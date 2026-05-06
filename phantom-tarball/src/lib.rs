//! Tarball-vs-git divergence detector.
//!
//! Given two archives — typically `git archive --format=tar.gz <tag>` for the
//! upstream tag, and the corresponding release tarball published on
//! GitHub/SourceForge/etc. — extract their file inventories and report any
//! file that is **added** in the release-only side, **modified** between the
//! two, or **removed** from the release.
//!
//! The XZ Utils backdoor (CVE-2024-3094) was hidden by exactly this
//! divergence: malicious build glue in `m4/build-to-host.m4` shipped only in
//! the release tarball and was never present in git.

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use phantom_core::{Finding, Location, Severity};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tar::Archive;

const DETECTOR: &str = "tarball-divergence";

/// Maximum number of bytes inspected for content red flags. Build-system files
/// are tiny in practice; a 256 KiB cap guards against accidentally pulling a
/// huge release artifact into memory.
const CONTENT_SCAN_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct Entry {
    pub size: u64,
    pub sha256: [u8; 32],
    /// Content of build-system or otherwise interesting files, capped at
    /// `CONTENT_SCAN_BYTES`. `None` for files we don't scan.
    pub head: Option<Vec<u8>>,
}

pub type Index = BTreeMap<String, Entry>;

pub fn index(tar_gz: &Path) -> Result<Index> {
    let file = File::open(tar_gz).with_context(|| format!("opening {}", tar_gz.display()))?;
    let buf = BufReader::new(file);
    let gz = GzDecoder::new(buf);
    let mut archive = Archive::new(gz);

    let mut raw = Index::new();
    for entry in archive.entries().context("reading tar entries")? {
        let mut entry = entry.context("reading tar entry header")?;
        let header = entry.header();
        if !matches!(
            header.entry_type(),
            tar::EntryType::Regular | tar::EntryType::Continuous
        ) {
            continue;
        }
        let raw_path = entry.path().context("decoding tar entry path")?;
        let key = raw_path
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();

        // Decide whether to keep file content for later red-flag scanning.
        let keep_content = wants_content_scan(&key);

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        let mut head: Option<Vec<u8>> = if keep_content {
            Some(Vec::with_capacity(8192))
        } else {
            None
        };
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            if let Some(h) = &mut head {
                let remaining = CONTENT_SCAN_BYTES.saturating_sub(h.len());
                if remaining > 0 {
                    let take = remaining.min(n);
                    h.extend_from_slice(&buf[..take]);
                }
            }
            total += n as u64;
        }
        let digest: [u8; 32] = hasher.finalize().into();

        raw.insert(
            key,
            Entry {
                size: total,
                sha256: digest,
                head,
            },
        );
    }
    Ok(strip_common_top_dir(raw))
}

/// We keep file content for build-system files where an injected obfuscation
/// payload would have a clear blast radius. We *exclude* a small set of large
/// autotools-generated scripts that legitimately contain shell-trick patterns
/// (configure, config.guess, libtool.m4 itself, ...) — scanning those produces
/// confident false positives. The XZ payload sat in a small allowlisted
/// gettext macro (`build-to-host.m4`), which is exactly what this scan still
/// covers.
fn wants_content_scan(path: &str) -> bool {
    if is_obfuscation_scan_excluded(path) {
        return false;
    }
    is_build_system_path(path) || is_known_dist_artifact(path)
}

fn is_obfuscation_scan_excluded(path: &str) -> bool {
    let bn = basename(path);
    matches!(
        bn,
        "configure"
            | "config.guess"
            | "config.sub"
            | "config.rpath"
            | "ltmain.sh"
            | "libtool.m4"
            | "aclocal.m4"
            | "depcomp"
            | "compile"
            | "install-sh"
            | "missing"
    )
}

/// If every entry shares the same first path component (e.g. `xz-5.6.1/...`),
/// strip it. Otherwise return the index unchanged. This lets release tarballs
/// (which typically have a versioned top dir) be compared with `git archive`
/// output (which by default has no top dir).
fn strip_common_top_dir(index: Index) -> Index {
    if index.is_empty() {
        return index;
    }
    let mut common: Option<&str> = None;
    for path in index.keys() {
        let top = match path.split_once('/') {
            Some((t, _)) => t,
            None => return index, // a top-level file means no common dir to strip
        };
        match common {
            None => common = Some(top),
            Some(c) if c == top => {}
            Some(_) => return index,
        }
    }
    let Some(top) = common else {
        return index;
    };
    let prefix_len = top.len() + 1; // include trailing '/'
    index
        .into_iter()
        .map(|(k, v)| (k[prefix_len..].to_string(), v))
        .collect()
}

/// Origin of the artifacts being compared. Lets `tarball-diff` widen its
/// allowlist with files that the publishing pipeline of each ecosystem is
/// known to add or rewrite (e.g. `Cargo.toml` is rewritten by `cargo publish`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    GitHub,
    Npm,
    PyPI,
    Crates,
}

/// Comparison mode for `diff()`.
///
/// - **`GitVsRelease`** (default): the source side is a `git archive` of the
///   tagged commit; *every* file divergence is suspicious because git is
///   supposed to match the tag exactly. This is the original tarball-diff
///   semantics that catches the XZ Utils CVE-2024-3094 pattern.
///
/// - **`ReleaseVsRelease`**: the source side is an *older release* of the
///   same package, the target is a *newer release*. Source-code changes are
///   expected (that is what a new release means). Build-system changes are
///   the highest-confidence indicator of an injected payload, exactly as in
///   the XZ case (v5.4.x clean → v5.6.0 backdoored). Use this mode to audit
///   a version bump before consuming an upstream release in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    GitVsRelease,
    ReleaseVsRelease,
}

#[derive(Debug, Clone, Copy)]
pub struct DiffOptions {
    /// If true, files present in the source side but missing from the target
    /// side are reported (Low). Defaults to false to keep the report focused
    /// on attacker-introduced additions and modifications.
    pub report_missing: bool,
    /// When set, expands the dist-artifact allowlist with files known to be
    /// added or rewritten by that ecosystem's publishing pipeline.
    pub ecosystem: Option<Ecosystem>,
    /// Comparison mode (see `DiffMode`).
    pub mode: DiffMode,
    /// In `ReleaseVsRelease` mode, whether to surface modifications/additions
    /// of regular source code files (`.c`, `.rs`, `.py`, …) as `Info`
    /// findings. Off by default — those changes are expected on a version
    /// bump and only add noise. Set to `true` for a full release audit.
    pub include_source_changes: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            report_missing: false,
            ecosystem: None,
            mode: DiffMode::GitVsRelease,
            include_source_changes: false,
        }
    }
}

/// Diff two archives.
///
/// `source` is the *known-good* / *baseline* archive: a `git archive` of the
/// tagged commit (mode = `GitVsRelease`), or an older release of the same
/// package (mode = `ReleaseVsRelease`).
///
/// `target` is the archive being audited.
///
/// The function name keeps `git_archive` and `release_tarball` for API
/// stability, but the parameters are interpreted as `(source, target)`.
pub fn diff(git_archive: &Path, release_tarball: &Path, opts: DiffOptions) -> Result<Vec<Finding>> {
    let source_label = match opts.mode {
        DiffMode::GitVsRelease => "indexing git archive",
        DiffMode::ReleaseVsRelease => "indexing baseline release",
    };
    let target_label = match opts.mode {
        DiffMode::GitVsRelease => "indexing release tarball",
        DiffMode::ReleaseVsRelease => "indexing target release",
    };
    let source_idx = index(git_archive).context(source_label)?;
    let target_idx = index(release_tarball).context(target_label)?;

    let mut findings = Vec::new();

    let added_rule = match opts.mode {
        DiffMode::GitVsRelease => "release-only-file",
        DiffMode::ReleaseVsRelease => "added-in-target-release",
    };
    let modified_rule = match opts.mode {
        DiffMode::GitVsRelease => "modified-in-release",
        DiffMode::ReleaseVsRelease => "modified-between-releases",
    };
    let added_origin_tag = match opts.mode {
        DiffMode::GitVsRelease => "release-only",
        DiffMode::ReleaseVsRelease => "added-in-target",
    };
    let added_title_prefix = match opts.mode {
        DiffMode::GitVsRelease => "File present in release but absent from git",
        DiffMode::ReleaseVsRelease => "File added in target release (absent from baseline)",
    };
    let modified_title_prefix = match opts.mode {
        DiffMode::GitVsRelease => "File differs between git and release",
        DiffMode::ReleaseVsRelease => "File differs between baseline and target release",
    };

    for (path, target_entry) in &target_idx {
        match source_idx.get(path) {
            None => {
                if let Some(severity) =
                    classify_added(path, opts.ecosystem, opts.mode, opts.include_source_changes)
                {
                    findings.push(Finding {
                        detector: DETECTOR.into(),
                        rule: added_rule.into(),
                        severity,
                        title: format!("{}: `{}`", added_title_prefix, path),
                        description: describe_added(path, opts.ecosystem, opts.mode),
                        locations: vec![Location::path(path.clone())],
                        evidence: json!({
                            "size": target_entry.size,
                            "sha256": hex(&target_entry.sha256),
                            "mode": match opts.mode {
                                DiffMode::GitVsRelease => "git-vs-release",
                                DiffMode::ReleaseVsRelease => "release-vs-release",
                            },
                        }),
                    });
                }
                // Content-level red-flag scan runs regardless of whether the
                // file's existence finding was suppressed: an obfuscated
                // payload inside an allowlisted gettext macro must surface
                // even if the macro itself is Info or skipped.
                if let Some(content) = &target_entry.head {
                    findings.extend(scan_content_redflags(path, content, added_origin_tag));
                }
            }
            Some(source_entry) => {
                if source_entry.sha256 != target_entry.sha256 {
                    if let Some(severity) = classify_modified(
                        path,
                        opts.ecosystem,
                        opts.mode,
                        opts.include_source_changes,
                    ) {
                        findings.push(Finding {
                            detector: DETECTOR.into(),
                            rule: modified_rule.into(),
                            severity,
                            title: format!("{}: `{}`", modified_title_prefix, path),
                            description: describe_modified(path, opts.ecosystem, opts.mode),
                            locations: vec![Location::path(path.clone())],
                            evidence: json!({
                                "source_sha256": hex(&source_entry.sha256),
                                "target_sha256": hex(&target_entry.sha256),
                                "source_size": source_entry.size,
                                "target_size": target_entry.size,
                                "mode": match opts.mode {
                                    DiffMode::GitVsRelease => "git-vs-release",
                                    DiffMode::ReleaseVsRelease => "release-vs-release",
                                },
                            }),
                        });
                    }
                    if let Some(content) = &target_entry.head {
                        findings.extend(scan_content_redflags(path, content, "modified"));
                    }
                }
            }
        }
    }

    if opts.report_missing {
        let (missing_rule, missing_title_prefix, missing_description) = match opts.mode {
            DiffMode::GitVsRelease => (
                "missing-in-release",
                "File in git absent from release",
                "Present in git at the tagged commit but missing from the release tarball. \
                 Often benign (intentionally excluded), but worth noting if security-relevant.",
            ),
            DiffMode::ReleaseVsRelease => (
                "removed-in-target-release",
                "File present in baseline but removed from target release",
                "Present in the baseline release but missing from the target release. \
                 Often benign (deprecated / refactored away), but worth noting if security-relevant.",
            ),
        };
        for (path, source_entry) in &source_idx {
            if !target_idx.contains_key(path) {
                findings.push(Finding {
                    detector: DETECTOR.into(),
                    rule: missing_rule.into(),
                    severity: Severity::Low,
                    title: format!("{}: `{}`", missing_title_prefix, path),
                    description: missing_description.into(),
                    locations: vec![Location::path(path.clone())],
                    evidence: json!({
                        "source_sha256": hex(&source_entry.sha256),
                        "source_size": source_entry.size,
                    }),
                });
            }
        }
    }

    Ok(findings)
}

/// Cheap regex-free content scanner for shell-obfuscation tells in build-system
/// files. Each find is a HIGH finding; the goal is to catch the kind of
/// payload XZ Utils embedded in `m4/build-to-host.m4` even when the file is on
/// the gettext allowlist.
fn scan_content_redflags(path: &str, content: &[u8], origin: &str) -> Vec<Finding> {
    let mut hits: Vec<&'static str> = vec![];
    let text = match std::str::from_utf8(content) {
        Ok(s) => s,
        Err(_) => return vec![], // binary-ish: skip in v0.x
    };

    let lc = text.to_ascii_lowercase();
    if lc.contains("eval ") && (lc.contains("| tr ") || lc.contains("|tr ")) {
        hits.push("eval-piped-through-tr");
    }
    if lc.contains("xxd -r") || lc.contains("xxd -p") {
        hits.push("xxd-hex-deobfuscation");
    }
    if lc.contains("base64 -d") || lc.contains("base64 --decode") {
        hits.push("base64-decode-shell");
    }
    // long base64-like runs (>= 200 contiguous chars from the b64 alphabet)
    if has_long_base64_run(text, 200) {
        hits.push("long-base64-string");
    }
    // long hex-like runs (>= 200 contiguous hex chars)
    if has_long_hex_run(text, 200) {
        hits.push("long-hex-string");
    }
    if lc.contains("printf '\\x") || lc.contains("printf \"\\x") {
        hits.push("printf-hex-escape-chain");
    }

    if hits.is_empty() {
        return vec![];
    }

    vec![Finding {
        detector: DETECTOR.into(),
        rule: "build-file-obfuscation".into(),
        severity: Severity::High,
        title: format!("Obfuscation patterns in build-system file: `{}`", path),
        description: format!(
            "Content of `{}` contains shell-obfuscation patterns ({}) typical of staged payloads. \
             Patterns matched: {}. \
             Even an allowlisted gettext/libtool macro can be carrier; manually inspect the content.",
            path, origin, hits.join(", ")
        ),
        locations: vec![Location::path(path.to_string())],
        evidence: json!({
            "patterns": hits,
            "origin": origin,
        }),
    }]
}

fn has_long_base64_run(s: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for b in s.bytes() {
        let is_b64 = b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
        if is_b64 {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn has_long_hex_run(s: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for b in s.bytes() {
        let is_hex = matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F');
        if is_hex {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Files where an attacker can inject code that runs at **build, install, CI,
/// or dev-environment startup**. A modification of any of these between two
/// archives is the highest-impact attack surface and triggers the strongest
/// severity in `classify_modified` / `classify_added`.
///
/// Coverage is intentionally broad across ecosystems: Python `setup.py` and
/// Ruby `extconf.rb` are as dangerous as `build.rs` — every one of them runs
/// arbitrary code at install time.
fn is_build_system_path(path: &str) -> bool {
    let bn = basename(path);

    // ─── Autotools (autoconf / automake / libtool) ──────────────────────────
    if matches!(bn, "configure.ac" | "configure.in") {
        return true;
    }
    if bn.ends_with(".m4") || bn.ends_with(".am") {
        return true;
    }
    if path.starts_with("m4/") || path.contains("/m4/") {
        return true;
    }

    // ─── Make and variants ──────────────────────────────────────────────────
    if matches!(bn, "Makefile" | "GNUmakefile" | "BSDmakefile" | "makefile") {
        return true;
    }
    if bn.ends_with("/Makefile") || bn.ends_with("/GNUmakefile") {
        return true;
    }
    if bn.ends_with(".mk") || bn.ends_with(".mak") {
        return true;
    }

    // ─── CMake ──────────────────────────────────────────────────────────────
    if bn == "CMakeLists.txt" || bn.ends_with(".cmake") {
        return true;
    }

    // ─── Meson ──────────────────────────────────────────────────────────────
    if matches!(bn, "meson.build" | "meson_options.txt" | "meson.options") {
        return true;
    }

    // ─── Rust ───────────────────────────────────────────────────────────────
    if bn == "build.rs" {
        return true;
    }
    // Rust toolchain / cargo config — pin a malicious toolchain or redirect
    // crate registries.
    if matches!(bn, "rust-toolchain.toml" | "rust-toolchain") {
        return true;
    }
    if path == ".cargo/config.toml"
        || path == ".cargo/config"
        || path.ends_with("/.cargo/config.toml")
        || path.ends_with("/.cargo/config")
    {
        return true;
    }

    // ─── Python ─────────────────────────────────────────────────────────────
    // setup.py runs arbitrary Python at install time; pyproject.toml drives
    // the build backend (which can pull arbitrary deps).
    if matches!(
        bn,
        "setup.py" | "pyproject.toml" | "MANIFEST.in" | "conftest.py" | "tox.ini" | "noxfile.py"
    ) {
        return true;
    }

    // ─── Ruby ───────────────────────────────────────────────────────────────
    // Rakefile + extconf.rb both run Ruby; *.gemspec evaluates Ruby in `gem build`.
    if matches!(bn, "Rakefile" | "rakefile" | "Gemfile" | "Gemfile.lock" | "extconf.rb") {
        return true;
    }
    if bn.ends_with(".gemspec") {
        return true;
    }

    // ─── Node native modules / package config ──────────────────────────────
    // node-gyp builds native extensions from `binding.gyp`.
    if bn == "binding.gyp" || bn.ends_with(".gyp") || bn.ends_with(".gypi") {
        return true;
    }
    // npm/yarn registry redirects.
    if matches!(bn, ".npmrc" | ".yarnrc" | ".yarnrc.yml" | ".pnpm-workspace.yaml") {
        return true;
    }

    // ─── Java: Gradle, Maven ───────────────────────────────────────────────
    if matches!(
        bn,
        "build.gradle"
            | "build.gradle.kts"
            | "settings.gradle"
            | "settings.gradle.kts"
            | "gradle.properties"
            | "pom.xml"
    ) {
        return true;
    }
    if path.contains("gradle/wrapper/gradle-wrapper") {
        return true;
    }

    // ─── Bazel / Buck ──────────────────────────────────────────────────────
    if matches!(
        bn,
        "BUILD"
            | "BUILD.bazel"
            | "WORKSPACE"
            | "WORKSPACE.bazel"
            | "MODULE.bazel"
            | ".bazelrc"
            | ".bazelversion"
            | "BUCK"
    ) {
        return true;
    }
    if bn.ends_with(".bzl") || bn.ends_with(".bazel") {
        return true;
    }

    // ─── Containers ────────────────────────────────────────────────────────
    if bn == "Dockerfile"
        || bn == "Containerfile"
        || bn.ends_with("/Dockerfile")
        || bn.ends_with(".dockerfile")
    {
        return true;
    }
    if matches!(
        bn,
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
    ) {
        return true;
    }
    // Dev containers run code on every contributor's machine.
    if path.starts_with(".devcontainer/") || path.contains("/.devcontainer/") {
        return true;
    }
    if bn == ".gitpod.yml" || bn == ".gitpod.Dockerfile" {
        return true;
    }

    // ─── CI / build pipelines (any platform) ───────────────────────────────
    if path.starts_with(".github/workflows/") || path.contains("/.github/workflows/") {
        return true;
    }
    if path.starts_with(".github/actions/") || path.contains("/.github/actions/") {
        return true;
    }
    if path == ".gitlab-ci.yml" || path.ends_with("/.gitlab-ci.yml") {
        return true;
    }
    if path == ".circleci/config.yml" || path.ends_with("/.circleci/config.yml") {
        return true;
    }
    if matches!(
        bn,
        ".travis.yml"
            | "Jenkinsfile"
            | "azure-pipelines.yml"
            | "azure-pipelines.yaml"
            | "bitbucket-pipelines.yml"
            | ".drone.yml"
            | "appveyor.yml"
            | ".appveyor.yml"
            | "cloudbuild.yaml"
            | "cloudbuild.yml"
            | "buildspec.yml"
            | "buildspec.yaml"
    ) {
        return true;
    }

    // ─── Pre-commit / git hooks ────────────────────────────────────────────
    if matches!(bn, ".pre-commit-config.yaml" | ".pre-commit-config.yml" | ".pre-commit-hooks.yaml") {
        return true;
    }
    if path.starts_with(".husky/") || path.contains("/.husky/") {
        return true;
    }

    // ─── Just / Task / SCons / xmake ───────────────────────────────────────
    if matches!(bn, "Justfile" | "justfile" | "Taskfile.yml" | "Taskfile.yaml" | "xmake.lua") {
        return true;
    }
    if matches!(bn, "SConstruct" | "SConscript") {
        return true;
    }

    // ─── pip / Python toolchain ────────────────────────────────────────────
    if matches!(bn, "pip.conf" | "pip.ini") {
        return true;
    }

    // ─── OS packaging (rare in upstream tarballs but high-impact) ──────────
    if path == "debian/rules" || path.ends_with("/debian/rules") {
        return true;
    }
    if path == "debian/control" || path.ends_with("/debian/control") {
        return true;
    }
    if bn.ends_with(".spec") && !path.starts_with("test/") && !path.starts_with("tests/") {
        // RPM .spec — but exclude test fixtures named *.spec
        return true;
    }
    if bn == "PKGBUILD" {
        return true;
    }

    false
}

/// Files that the publishing pipeline of `eco` is known to **add** to a
/// release tarball relative to the source git tree. Expected, not an attack
/// indicator on its own.
fn is_ecosystem_release_only_artifact(path: &str, eco: Option<Ecosystem>) -> bool {
    let bn = basename(path);
    match eco {
        Some(Ecosystem::Crates) => matches!(
            bn,
            ".cargo_vcs_info.json" | "Cargo.toml.orig" | "Cargo.lock"
        ),
        Some(Ecosystem::PyPI) => {
            // PyPI sdist conventionally adds PKG-INFO and a *.egg-info/ tree.
            if bn == "PKG-INFO" || bn == "setup.cfg" {
                return true;
            }
            if path.contains(".egg-info/") {
                return true;
            }
            false
        }
        Some(Ecosystem::Npm) => {
            // npm tarball adds a package/ wrapping (which top-dir-strip
            // already removes) and may include a generated `package.json`
            // (handled in `is_ecosystem_modified_artifact`).
            // Some projects ship a generated LICENSE / README only at publish.
            false
        }
        Some(Ecosystem::GitHub) | None => false,
    }
}

/// Files that the publishing pipeline of `eco` is known to **rewrite** in the
/// release relative to source. A modification of these files is expected, not
/// an attack indicator on its own.
fn is_ecosystem_modified_artifact(path: &str, eco: Option<Ecosystem>) -> bool {
    let bn = basename(path);
    match eco {
        Some(Ecosystem::Crates) => {
            // `cargo publish` rewrites Cargo.toml (path deps removed, version
            // requirements expanded, [workspace] stripped, …).
            matches!(bn, "Cargo.toml")
        }
        Some(Ecosystem::Npm) => {
            // `npm publish` (and lifecycle scripts like `prepublishOnly`)
            // can rewrite package.json. Same for package-lock.json shipped
            // in tarballs.
            matches!(bn, "package.json" | "package-lock.json")
        }
        Some(Ecosystem::PyPI) => matches!(bn, "PKG-INFO" | "setup.cfg"),
        Some(Ecosystem::GitHub) | None => false,
    }
}

/// Files that autoreconf / autotools / libtool / gettext / automake imports
/// into a release dist by design. Their presence in a release tarball without
/// being in git is **expected**, not an attack indicator on its own.
/// Severity for "release-only" of these files is downgraded to Info; the
/// content-level red-flag scanner remains active so an obfuscated payload
/// inside an otherwise allowlisted file (the XZ pattern) still surfaces.
fn is_known_dist_artifact(path: &str) -> bool {
    let bn = basename(path);

    // Autotools/libtool root-level helpers.
    if matches!(
        bn,
        "configure"
            | "Makefile.in"
            | "config.h.in"
            | "aclocal.m4"
            | "ltmain.sh"
            | "depcomp"
            | "compile"
            | "install-sh"
            | "missing"
            | "config.guess"
            | "config.sub"
            | "config.rpath"
            | "INSTALL"
            | "test-driver"
            | "ar-lib"
            | "py-compile"
            | "ABOUT-NLS"
            | "mkinstalldirs"
    ) {
        return true;
    }

    // Auto-generated translation artifacts under po/ or po4a/.
    if path.starts_with("po/") || path.starts_with("po4a/") {
        if bn.ends_with(".gmo") || bn.ends_with(".mo") {
            return true;
        }
        if matches!(
            bn,
            "stamp-po"
                | "Makefile.in.in"
                | "remove-potcdate.sin"
                | "Rules-quot"
                | "boldquot.sed"
                | "en@boldquot.header"
                | "en@quot.header"
                | "insert-header.sin"
                | "quot.sed"
                | "Makevars.template"
        ) {
            return true;
        }
        if bn == "POTFILES" || bn.ends_with(".pot") {
            return true;
        }
        // Translated man pages produced by po4a from .po sources.
        if path.starts_with("po4a/man/") {
            return true;
        }
    }

    // build-aux/* helpers (some autotools projects use this dir for the same
    // helpers listed above).
    if path.starts_with("build-aux/") || path.contains("/build-aux/") {
        return true;
    }

    // Standard gettext / libtool / automake m4 macros bundled at autoreconf.
    if path.starts_with("m4/") || path.contains("/m4/") {
        if matches!(
            bn,
            // gettext
            "gettext.m4"
                | "host-cpu-c-abi.m4"
                | "iconv.m4"
                | "intlmacosx.m4"
                | "intl.m4"
                | "intldir.m4"
                | "intmax_t.m4"
                | "lib-ld.m4"
                | "lib-link.m4"
                | "lib-prefix.m4"
                | "longlong.m4"
                | "nls.m4"
                | "po.m4"
                | "printf-posix.m4"
                | "progtest.m4"
                | "size_max.m4"
                | "stdint_h.m4"
                | "uintmax_t.m4"
                | "ulonglong.m4"
                | "visibility.m4"
                | "wchar_t.m4"
                | "wint_t.m4"
                | "build-to-host.m4"
                | "extern-inline.m4"
                | "fcntl-o.m4"
                | "stdint.m4"
                | "threadlib.m4"
                // libtool
                | "libtool.m4"
                | "ltoptions.m4"
                | "ltsugar.m4"
                | "ltversion.m4"
                | "lt~obsolete.m4"
                | "argz.m4"
                // posix shell / common autoconf-archive
                | "ax_pthread.m4"
                | "ax_check_compile_flag.m4"
                | "ax_check_link_flag.m4"
        ) {
            return true;
        }
    }

    false
}

fn is_release_doc(path: &str) -> bool {
    let bn = basename(path).to_ascii_uppercase();
    matches!(
        bn.as_str(),
        "AUTHORS" | "CHANGELOG" | "CHANGES" | "NEWS" | "THANKS" | "MANIFEST"
    )
}

/// Classify a file that exists on the target side but not on the source side.
/// Returns `None` to indicate the finding should be suppressed (e.g. an
/// ordinary new source file in `ReleaseVsRelease` mode without
/// `include_source_changes`).
fn classify_added(
    path: &str,
    eco: Option<Ecosystem>,
    mode: DiffMode,
    include_source: bool,
) -> Option<Severity> {
    // 1. Known publishing-pipeline artifacts are always Info regardless of mode.
    if is_ecosystem_release_only_artifact(path, eco) {
        return Some(Severity::Info);
    }
    if is_known_dist_artifact(path) {
        return Some(Severity::Info);
    }
    if is_release_doc(path) {
        return Some(Severity::Info);
    }
    // 2. Build-system files outside the autotools/gettext allowlist —
    //    suspicious in *both* modes. An attacker can introduce a malicious
    //    `m4/something.m4` either between git and release, or between two
    //    consecutive releases.
    if is_build_system_path(path) {
        return Some(Severity::High);
    }
    // 3. Generated docs are usually benign release-only.
    if path.starts_with("doc/") || path.contains("/doc/api/") || path.contains("/_static/") {
        return Some(Severity::Low);
    }
    // 4. Everything else: ordinary file additions.
    match mode {
        DiffMode::GitVsRelease => Some(Severity::Medium),
        DiffMode::ReleaseVsRelease => {
            if include_source {
                Some(Severity::Info)
            } else {
                None
            }
        }
    }
}

/// Classify a file that differs between source and target archives. Returns
/// `None` to suppress the finding entirely.
///
/// Ordering of the dispositions matters:
///   1. Release docs (CHANGELOG / AUTHORS …) — Info, frequently regenerated.
///   2. Ecosystem rewrites (Cargo.toml / package.json …) — Info, expected.
///   3. Standard dist artifacts (autotools-generated `configure`, gettext m4,
///      libtool m4, …) — **Info**, expected to differ between two releases
///      (autoreconf with a different toolchain version) and between git and
///      release. **The content-scan pass still runs**, so an obfuscated
///      payload inside one of these allowlisted files (the XZ Utils CVE
///      pattern) surfaces as a separate HIGH finding.
///   4. Custom (non-allowlisted) build-system files (`configure.ac`,
///      `*.am`, `m4/custom-*.m4`, GitHub workflows) — **P0** in both modes.
///      A custom build file modified between releases or between git and
///      release is the highest-confidence indicator of a tampered artifact.
///   5. Ordinary source/docs/data — HIGH in `GitVsRelease`, suppressed (or
///      Info with `--include-source-changes`) in `ReleaseVsRelease`.
fn classify_modified(
    path: &str,
    eco: Option<Ecosystem>,
    mode: DiffMode,
    include_source: bool,
) -> Option<Severity> {
    if is_release_doc(path) {
        return Some(Severity::Info);
    }
    if is_ecosystem_modified_artifact(path, eco) {
        return Some(Severity::Info);
    }
    if is_known_dist_artifact(path) {
        return Some(Severity::Info);
    }
    if is_build_system_path(path) {
        // In GvR, git must match the tag byte-for-byte: any divergence is the
        // smoking gun (P0).
        // In RvR, hand-written build sources (`configure.ac`, `*.am`,
        // `CMakeLists.txt`, `build.rs`, `.github/workflows/*`, custom
        // `m4/*.m4`) routinely change on a version bump. Demote to HIGH —
        // a review-blocker, but not a "drop-everything" P0. The content-scan
        // pass independently surfaces a HIGH finding for obfuscation
        // patterns regardless of mode, so the actual XZ smoking gun is not
        // lost.
        return Some(match mode {
            DiffMode::GitVsRelease => Severity::P0,
            DiffMode::ReleaseVsRelease => Severity::High,
        });
    }
    match mode {
        DiffMode::GitVsRelease => Some(Severity::High),
        DiffMode::ReleaseVsRelease => {
            if include_source {
                Some(Severity::Info)
            } else {
                None
            }
        }
    }
}

fn describe_added(path: &str, eco: Option<Ecosystem>, mode: DiffMode) -> String {
    let (here, there) = mode_labels(mode);
    if is_ecosystem_release_only_artifact(path, eco) {
        let eco_name = match eco {
            Some(Ecosystem::Crates) => "cargo publish",
            Some(Ecosystem::PyPI) => "PyPI sdist",
            Some(Ecosystem::Npm) => "npm publish",
            _ => "the publish pipeline",
        };
        format!(
            "`{}` is a file added by {} to every release. Expected; not an attack indicator on its own.",
            path, eco_name
        )
    } else if is_known_dist_artifact(path) {
        format!(
            "`{}` is a standard autotools / gettext / libtool / automake artifact bundled by `autoreconf` at release time. \
             Its presence in the {} without being in the {} is normal. \
             A separate content scan still flags shell-obfuscation patterns inside the file — the XZ Utils backdoor (CVE-2024-3094) was hidden in exactly such an allowlisted file.",
            path, there, here
        )
    } else if is_build_system_path(path) {
        format!(
            "`{}` is a build-system file present in the {} but absent from the {}, AND outside the standard autotools/gettext/libtool allowlist. \
             This is highly suspicious: a custom build script that ships only in the {} has no review path. \
             Reproduce from source or treat the {} as untrusted.",
            path, there, here, there, there
        )
    } else if is_release_doc(path) {
        format!(
            "`{}` is a release-time document (AUTHORS/CHANGELOG/etc.). Usually benign.",
            path
        )
    } else if path.starts_with("doc/") || path.contains("/_static/") {
        format!(
            "`{}` looks like generated documentation. Usually benign; not source-tracked.",
            path
        )
    } else {
        match mode {
            DiffMode::GitVsRelease => format!(
                "`{}` is in the release tarball but not in git at the corresponding tag. \
                 Investigate whether it was generated reproducibly from a tracked source, or injected.",
                path
            ),
            DiffMode::ReleaseVsRelease => format!(
                "`{}` is a new file introduced in the {}, not present in the {}. \
                 Likely a legitimate new feature; surfaced here because `--include-source-changes` is set.",
                path, there, here
            ),
        }
    }
}

fn describe_modified(path: &str, eco: Option<Ecosystem>, mode: DiffMode) -> String {
    let (here, there) = mode_labels(mode);
    if is_ecosystem_modified_artifact(path, eco) {
        let eco_name = match eco {
            Some(Ecosystem::Crates) => "cargo publish",
            Some(Ecosystem::Npm) => "npm publish (or a `prepublishOnly` script)",
            Some(Ecosystem::PyPI) => "the PyPI sdist build",
            _ => "the publish pipeline",
        };
        format!(
            "`{}` is rewritten by {} on every release. Expected; not an attack indicator on its own. \
             A content-level scan still flags shell-obfuscation patterns inside the file.",
            path, eco_name
        )
    } else if is_build_system_path(path) {
        match mode {
            DiffMode::GitVsRelease => format!(
                "`{}` differs between git and the release tarball. Build-system divergence is the highest-confidence indicator \
                 of a tampered release: an attacker can ship code that is never visible to git-based review (XZ Utils CVE-2024-3094). \
                 Diff the two versions byte-for-byte before trusting the release.",
                path
            ),
            DiffMode::ReleaseVsRelease => format!(
                "`{}` differs between the {} and the {}. \
                 Build-system divergence between two consecutive releases is the canonical XZ-style smoking gun \
                 (the v5.4.x → v5.6.0 transition introduced the malicious `m4/build-to-host.m4`). \
                 Diff the two versions byte-for-byte before trusting the upgrade.",
                path, here, there
            ),
        }
    } else if is_known_dist_artifact(path) {
        format!("`{}` is autogenerated and differs between sources. Check it was produced by a deterministic tool run.", path)
    } else {
        match mode {
            DiffMode::GitVsRelease => format!(
                "`{}` content differs between git and the release tarball. Source-tracked file should match its tagged version.",
                path
            ),
            DiffMode::ReleaseVsRelease => format!(
                "`{}` content changed between the {} and the {}. \
                 Source-code drift between releases is expected; surfaced here because `--include-source-changes` is set.",
                path, here, there
            ),
        }
    }
}

/// Returns `(source_label, target_label)` for the current diff mode — used to
/// frame finding messages accurately.
fn mode_labels(mode: DiffMode) -> (&'static str, &'static str) {
    match mode {
        DiffMode::GitVsRelease => ("git tree", "release tarball"),
        DiffMode::ReleaseVsRelease => ("baseline release", "target release"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test helpers — all GvR-mode classifications use these to keep the call
    // site short. RvR-mode calls are spelled out explicitly.
    fn ca(path: &str, eco: Option<Ecosystem>) -> Option<Severity> {
        classify_added(path, eco, DiffMode::GitVsRelease, false)
    }
    fn cm(path: &str, eco: Option<Ecosystem>) -> Option<Severity> {
        classify_modified(path, eco, DiffMode::GitVsRelease, false)
    }

    #[test]
    fn classify_xz_pattern() {
        // Allowlisted gettext m4 added-only is Info (expected at release time);
        // the *content scan* is what flags it when the payload is hidden.
        assert_eq!(ca("m4/build-to-host.m4", None), Some(Severity::Info));
        // Unknown m4 file release-only is High (no allowlist hit, suspicious).
        assert_eq!(ca("m4/custom-glue.m4", None), Some(Severity::High));
        // Modified ALLOWLISTED gettext m4 is Info — autoreconf regenerates
        // these on every release with whatever gettext version the maintainer
        // has installed. The content-scan pass independently surfaces a HIGH
        // finding when the file contains shell-obfuscation patterns (the XZ
        // payload pattern). This avoids false-positive P0s on every clean
        // release pair while still catching tampered allowlisted files.
        assert_eq!(cm("m4/build-to-host.m4", None), Some(Severity::Info));
        assert_eq!(cm("m4/gettext.m4", None), Some(Severity::Info));
        // Modified UNKNOWN custom build files (outside the allowlist) in
        // GvR mode is P0 — git tag must match the source byte-for-byte.
        assert_eq!(cm("m4/custom-glue.m4", None), Some(Severity::P0));
        assert_eq!(cm("configure.ac", None), Some(Severity::P0));
        assert_eq!(
            cm(".github/workflows/release.yml", None),
            Some(Severity::P0)
        );
        // Standard dist artifacts in release-only are Info.
        assert_eq!(ca("configure", None), Some(Severity::Info));
        assert_eq!(ca("aclocal.m4", None), Some(Severity::Info));
        assert_eq!(ca("AUTHORS", None), Some(Severity::Info));
        assert_eq!(ca("po/fr.gmo", None), Some(Severity::Info));
        assert_eq!(ca("build-aux/install-sh", None), Some(Severity::Info));
    }

    #[test]
    fn ecosystem_allowlist_crates() {
        assert_eq!(
            ca(".cargo_vcs_info.json", Some(Ecosystem::Crates)),
            Some(Severity::Info)
        );
        assert_eq!(
            ca("Cargo.toml.orig", Some(Ecosystem::Crates)),
            Some(Severity::Info)
        );
        assert_eq!(
            ca("Cargo.lock", Some(Ecosystem::Crates)),
            Some(Severity::Info)
        );
        assert_eq!(
            cm("Cargo.toml", Some(Ecosystem::Crates)),
            Some(Severity::Info)
        );
        // Without an ecosystem hint in GvR, modified Cargo.toml is HIGH (no info).
        assert_eq!(cm("Cargo.toml", None), Some(Severity::High));
    }

    #[test]
    fn ecosystem_allowlist_npm() {
        assert_eq!(
            cm("package.json", Some(Ecosystem::Npm)),
            Some(Severity::Info)
        );
        assert_eq!(cm("package.json", None), Some(Severity::High));
    }

    #[test]
    fn ecosystem_allowlist_pypi() {
        assert_eq!(ca("PKG-INFO", Some(Ecosystem::PyPI)), Some(Severity::Info));
        assert_eq!(
            ca("foo.egg-info/PKG-INFO", Some(Ecosystem::PyPI)),
            Some(Severity::Info)
        );
        assert_eq!(ca("PKG-INFO", None), Some(Severity::Medium)); // unknown otherwise
    }

    // ─── ReleaseVsRelease mode ─────────────────────────────────────────────

    #[test]
    fn rvr_suppresses_ordinary_source_changes() {
        // Without --include-source-changes, modifications to source code
        // between two releases produce no finding (legitimate version bump).
        let m = classify_modified("src/main.c", None, DiffMode::ReleaseVsRelease, false);
        assert_eq!(m, None);
        let a = classify_added("src/new_module.c", None, DiffMode::ReleaseVsRelease, false);
        assert_eq!(a, None);
    }

    #[test]
    fn rvr_with_include_source_emits_info() {
        let m = classify_modified("src/main.c", None, DiffMode::ReleaseVsRelease, true);
        assert_eq!(m, Some(Severity::Info));
        let a = classify_added("src/new.rs", None, DiffMode::ReleaseVsRelease, true);
        assert_eq!(a, Some(Severity::Info));
    }

    #[test]
    fn rvr_custom_build_files_are_high_not_p0() {
        // Hand-written build files routinely change between releases (a
        // maintainer adds a build option, refactors a Makefile.am, …). HIGH
        // signals "review required" without firing P0 on every legit version
        // bump. The content-scan pass independently surfaces HIGH on
        // obfuscation patterns, so a backdoored build file produces 2 HIGH
        // findings (modification + obfuscation) — clear enough.
        for path in [
            "configure.ac",
            "Makefile.am",
            "src/lib/Makefile.am",
            "CMakeLists.txt",
            "build.rs",
            "m4/custom-glue.m4",
            ".github/workflows/release.yml",
        ] {
            assert_eq!(
                classify_modified(path, None, DiffMode::ReleaseVsRelease, false),
                Some(Severity::High),
                "RvR-mode classify_modified for {} should be HIGH",
                path
            );
            // Same file in GvR mode is P0 — the smoking gun is unchanged
            // when comparing against git.
            assert_eq!(
                classify_modified(path, None, DiffMode::GitVsRelease, false),
                Some(Severity::P0),
                "GvR-mode classify_modified for {} should be P0",
                path
            );
        }
    }

    #[test]
    fn rvr_allowlisted_m4_modifications_are_info_not_p0() {
        // Critical: between two consecutive releases, every gettext / libtool
        // / automake m4 file legitimately changes when the maintainer bumps
        // the toolchain. Without this demotion, every release pair would
        // produce 20+ P0 false positives.
        // The content-scan pass still produces a separate HIGH finding when
        // such an allowlisted file contains obfuscation patterns (the XZ
        // pattern), so the smoking gun for backdoored allowlisted files is
        // still surfaced.
        for path in [
            "m4/build-to-host.m4",
            "m4/gettext.m4",
            "m4/iconv.m4",
            "m4/libtool.m4",
            "m4/ltversion.m4",
            "configure",
            "aclocal.m4",
            "build-aux/ltmain.sh",
            "Makefile.in",
        ] {
            assert_eq!(
                classify_modified(path, None, DiffMode::ReleaseVsRelease, false),
                Some(Severity::Info),
                "expected Info for modification of {}",
                path
            );
        }
    }

    #[test]
    fn rvr_keeps_unknown_m4_at_high() {
        // A custom m4 macro newly added in the target release that's not on
        // the allowlist is HIGH in both modes.
        let a = classify_added("m4/custom-glue.m4", None, DiffMode::ReleaseVsRelease, false);
        assert_eq!(a, Some(Severity::High));
    }

    #[test]
    fn rvr_keeps_ecosystem_allowlists() {
        // Ecosystem rewrites stay Info regardless of mode.
        assert_eq!(
            classify_modified(
                "Cargo.toml",
                Some(Ecosystem::Crates),
                DiffMode::ReleaseVsRelease,
                false
            ),
            Some(Severity::Info)
        );
        assert_eq!(
            classify_modified(
                "package.json",
                Some(Ecosystem::Npm),
                DiffMode::ReleaseVsRelease,
                false
            ),
            Some(Severity::Info)
        );
    }

    // ─── Build-system path coverage across ecosystems ──────────────────────

    #[test]
    fn build_system_python() {
        for p in [
            "setup.py",
            "pyproject.toml",
            "MANIFEST.in",
            "conftest.py",
            "tests/conftest.py",
            "tox.ini",
            "noxfile.py",
            "pip.conf",
            "pip.ini",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_ruby() {
        for p in [
            "Rakefile",
            "rakefile",
            "Gemfile",
            "Gemfile.lock",
            "ext/foo/extconf.rb",
            "extconf.rb",
            "mygem.gemspec",
            "lib/mygem.gemspec",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_node_native_and_registry() {
        for p in [
            "binding.gyp",
            "src/foo.gyp",
            "common.gypi",
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
            ".pnpm-workspace.yaml",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_containers_and_devcontainer() {
        for p in [
            "Dockerfile",
            "docker/Dockerfile",
            "alpine.dockerfile",
            "Containerfile",
            "docker-compose.yml",
            "compose.yaml",
            ".devcontainer/devcontainer.json",
            ".devcontainer/Dockerfile",
            "subdir/.devcontainer/setup.sh",
            ".gitpod.yml",
            ".gitpod.Dockerfile",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_meson_bazel_buck() {
        for p in [
            "meson.build",
            "meson_options.txt",
            "BUILD",
            "BUILD.bazel",
            "WORKSPACE",
            "WORKSPACE.bazel",
            "MODULE.bazel",
            ".bazelrc",
            ".bazelversion",
            "BUCK",
            "tools/rules.bzl",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_jvm() {
        for p in [
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradle.properties",
            "gradle/wrapper/gradle-wrapper.jar",
            "gradle/wrapper/gradle-wrapper.properties",
            "pom.xml",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_make_variants() {
        for p in [
            "Makefile",
            "GNUmakefile",
            "BSDmakefile",
            "src/Makefile",
            "common.mk",
            "rules.mak",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_ci_other_than_github() {
        for p in [
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            ".travis.yml",
            "Jenkinsfile",
            "azure-pipelines.yml",
            "azure-pipelines.yaml",
            "bitbucket-pipelines.yml",
            ".drone.yml",
            "appveyor.yml",
            ".appveyor.yml",
            "cloudbuild.yaml",
            "buildspec.yml",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_rust_toolchain_pinning() {
        for p in [
            "rust-toolchain.toml",
            "rust-toolchain",
            ".cargo/config.toml",
            ".cargo/config",
            "subdir/.cargo/config.toml",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_pre_commit_and_husky() {
        for p in [
            ".pre-commit-config.yaml",
            ".pre-commit-config.yml",
            ".pre-commit-hooks.yaml",
            ".husky/pre-commit",
            "subdir/.husky/post-merge",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_os_packaging() {
        for p in [
            "debian/rules",
            "debian/control",
            "myapp.spec",
            "rpm/myapp.spec",
            "PKGBUILD",
        ] {
            assert!(is_build_system_path(p), "expected build-system: {}", p);
        }
    }

    #[test]
    fn build_system_negatives() {
        // Things that look adjacent but should NOT match:
        for p in [
            "src/main.c",
            "src/lib.rs",
            "README.md",
            "tests/integration_test.py",
            "docs/index.html",
            "package.json",       // ecosystem-allowlisted, not build-system path
            "Cargo.toml",         // ecosystem-allowlisted
            "setup.cfg",          // ecosystem-allowlisted (pypi)
            "tests/foo.spec",     // .spec inside tests/ is intentionally excluded
            "configure",          // is in is_known_dist_artifact instead
        ] {
            assert!(!is_build_system_path(p), "expected NOT build-system: {}", p);
        }
    }

    #[test]
    fn obfuscation_detection() {
        let xz_like = b"gl_localedir_config='eval $cmd | tr -d \"\\r\" | sh'";
        let findings = scan_content_redflags("m4/build-to-host.m4", xz_like, "release-only");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);

        let benign = b"AC_DEFUN([gl_BUILD_TO_HOST], [\n  AC_REQUIRE([AC_CANONICAL_HOST])\n])\n";
        assert!(scan_content_redflags("m4/build-to-host.m4", benign, "release-only").is_empty());
    }

    #[test]
    fn long_b64_run() {
        let mut s = String::new();
        s.push_str("garbage = ");
        for _ in 0..210 {
            s.push('A');
        }
        assert!(has_long_base64_run(&s, 200));
        assert!(!has_long_base64_run("AAAA", 200));
    }

    fn entry(sha: u8) -> Entry {
        let mut s = [0u8; 32];
        s[0] = sha;
        Entry {
            size: 1,
            sha256: s,
            head: None,
        }
    }

    #[test]
    fn strip_common_when_shared() {
        let mut idx = Index::new();
        idx.insert("xz-5.6.1/src/main.c".into(), entry(1));
        idx.insert("xz-5.6.1/README".into(), entry(2));
        let stripped = strip_common_top_dir(idx);
        assert!(stripped.contains_key("src/main.c"));
        assert!(stripped.contains_key("README"));
    }

    #[test]
    fn no_strip_when_root_file() {
        let mut idx = Index::new();
        idx.insert("src/main.c".into(), entry(1));
        idx.insert("README".into(), entry(2));
        let stripped = strip_common_top_dir(idx);
        assert!(stripped.contains_key("src/main.c"));
        assert!(stripped.contains_key("README"));
    }

    #[test]
    fn no_strip_when_disagree() {
        let mut idx = Index::new();
        idx.insert("a/foo".into(), entry(1));
        idx.insert("b/bar".into(), entry(2));
        let stripped = strip_common_top_dir(idx);
        assert!(stripped.contains_key("a/foo"));
        assert!(stripped.contains_key("b/bar"));
    }
}
