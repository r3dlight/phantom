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
        if !matches!(header.entry_type(), tar::EntryType::Regular | tar::EntryType::Continuous) {
            continue;
        }
        let raw_path = entry.path().context("decoding tar entry path")?;
        let key = raw_path.to_string_lossy().trim_start_matches("./").to_string();

        // Decide whether to keep file content for later red-flag scanning.
        let keep_content = wants_content_scan(&key);

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        let mut total = 0u64;
        let mut head: Option<Vec<u8>> = if keep_content { Some(Vec::with_capacity(8192)) } else { None };
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 { break; }
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

        raw.insert(key, Entry { size: total, sha256: digest, head });
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
    let Some(top) = common else { return index; };
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

#[derive(Debug, Clone, Copy)]
pub struct DiffOptions {
    /// If true, files in git but missing from release are reported (Low).
    /// Defaults to false to keep the report focused on attacker-introduced
    /// divergence.
    pub report_missing: bool,
    /// When set, expands the dist-artifact allowlist with files known to be
    /// added or rewritten by that ecosystem's publishing pipeline.
    pub ecosystem: Option<Ecosystem>,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            report_missing: false,
            ecosystem: None,
        }
    }
}

pub fn diff(git_archive: &Path, release_tarball: &Path, opts: DiffOptions) -> Result<Vec<Finding>> {
    let git = index(git_archive).context("indexing git archive")?;
    let rel = index(release_tarball).context("indexing release tarball")?;

    let mut findings = Vec::new();

    for (path, rel_entry) in &rel {
        match git.get(path) {
            None => {
                let severity = classify_added(path, opts.ecosystem);
                findings.push(Finding {
                    detector: DETECTOR.into(),
                    rule: "release-only-file".into(),
                    severity,
                    title: format!("File present in release but absent from git: `{}`", path),
                    description: describe_added(path, opts.ecosystem).into(),
                    locations: vec![Location::path(path.clone())],
                    evidence: json!({
                        "size": rel_entry.size,
                        "sha256": hex(&rel_entry.sha256),
                    }),
                });

                // Content-level red flags: even when the file is "expected"
                // (allowlisted gettext/libtool macro), inspect its content for
                // obfuscation patterns. The XZ Utils build-to-host.m4 was
                // exactly an allowlisted file with malicious content.
                if let Some(content) = &rel_entry.head {
                    findings.extend(scan_content_redflags(path, content, "release-only"));
                }
            }
            Some(git_entry) => {
                if git_entry.sha256 != rel_entry.sha256 {
                    let severity = classify_modified(path, opts.ecosystem);
                    findings.push(Finding {
                        detector: DETECTOR.into(),
                        rule: "modified-in-release".into(),
                        severity,
                        title: format!("File differs between git and release: `{}`", path),
                        description: describe_modified(path, opts.ecosystem).into(),
                        locations: vec![Location::path(path.clone())],
                        evidence: json!({
                            "git_sha256": hex(&git_entry.sha256),
                            "release_sha256": hex(&rel_entry.sha256),
                            "git_size": git_entry.size,
                            "release_size": rel_entry.size,
                        }),
                    });
                    if let Some(content) = &rel_entry.head {
                        findings.extend(scan_content_redflags(path, content, "modified"));
                    }
                }
            }
        }
    }

    if opts.report_missing {
        for (path, git_entry) in &git {
            if !rel.contains_key(path) {
                findings.push(Finding {
                    detector: DETECTOR.into(),
                    rule: "missing-in-release".into(),
                    severity: Severity::Low,
                    title: format!("File in git absent from release: `{}`", path),
                    description: "Present in git at the tagged commit but missing from the release tarball. \
                                  Often benign (intentionally excluded), but worth noting if security-relevant.".into(),
                    locations: vec![Location::path(path.clone())],
                    evidence: json!({
                        "git_sha256": hex(&git_entry.sha256),
                        "git_size": git_entry.size,
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
            if run >= min_len { return true; }
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
            if run >= min_len { return true; }
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

fn is_build_system_path(path: &str) -> bool {
    let bn = basename(path);
    if bn == "configure.ac" || bn == "configure.in" { return true; }
    if bn.ends_with(".m4") || bn.ends_with(".am") { return true; }
    if path.starts_with("m4/") || path.contains("/m4/") { return true; }
    if bn == "build.rs" { return true; }
    if bn == "CMakeLists.txt" || bn.ends_with(".cmake") { return true; }
    if bn == "Makefile" || bn.ends_with("/Makefile") { return true; }
    if path.starts_with(".github/workflows/") { return true; }
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
        if matches!(bn, "stamp-po" | "Makefile.in.in" | "remove-potcdate.sin" | "Rules-quot" | "boldquot.sed" | "en@boldquot.header" | "en@quot.header" | "insert-header.sin" | "quot.sed" | "Makevars.template") {
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
    matches!(bn.as_str(), "AUTHORS" | "CHANGELOG" | "CHANGES" | "NEWS" | "THANKS" | "MANIFEST")
}

/// Classify a release-only file. Build-system files in `m4/` that are NOT in
/// the standard autotools/gettext/libtool allowlist are the highest-signal
/// release-only finding (HIGH); known dist artifacts demote to Info.
fn classify_added(path: &str, eco: Option<Ecosystem>) -> Severity {
    if is_ecosystem_release_only_artifact(path, eco) {
        return Severity::Info;
    }
    if is_known_dist_artifact(path) {
        return Severity::Info;
    }
    if is_release_doc(path) {
        return Severity::Info;
    }
    if is_build_system_path(path) {
        // unknown build-system file, release-only → highly suspicious
        return Severity::High;
    }
    // Doxygen / sphinx generated docs are commonly release-only.
    if path.starts_with("doc/") || path.contains("/doc/api/") || path.contains("/_static/") {
        return Severity::Low;
    }
    Severity::Medium
}

/// Modified between git and release: build-system divergence stays P0 (the XZ
/// smoking gun). Allowlisted dist artifacts that differ are Medium (could be
/// non-deterministic regeneration; could be tampered). Release docs (ChangeLog
/// etc.) are Info — frequently regenerated from git log.
fn classify_modified(path: &str, eco: Option<Ecosystem>) -> Severity {
    if is_release_doc(path) {
        return Severity::Info;
    }
    // Ecosystem-specific rewrites (Cargo.toml under crates.io, package.json
    // under npm, …) are expected and demoted to Info — but the content-scan
    // pass still runs so an obfuscated payload inside one of them surfaces.
    if is_ecosystem_modified_artifact(path, eco) {
        return Severity::Info;
    }
    if is_build_system_path(path) {
        return Severity::P0;
    }
    if is_known_dist_artifact(path) {
        return Severity::Medium;
    }
    Severity::High
}


fn describe_added(path: &str, eco: Option<Ecosystem>) -> String {
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
             Its presence in the release tarball without being in git is normal. \
             A separate content scan still flags shell-obfuscation patterns inside the file — the XZ Utils backdoor (CVE-2024-3094) was hidden in exactly such an allowlisted file.",
            path
        )
    } else if is_build_system_path(path) {
        format!(
            "`{}` is a build-system file present in the release tarball but absent from git AND outside the standard autotools/gettext/libtool allowlist. \
             This is highly suspicious: a custom build script that ships only in the released artifact has no review path. \
             Reproduce from source or treat the release as untrusted.",
            path
        )
    } else if is_release_doc(path) {
        format!("`{}` is a release-time document (AUTHORS/CHANGELOG/etc.). Usually benign.", path)
    } else if path.starts_with("doc/") || path.contains("/_static/") {
        format!("`{}` looks like generated documentation. Usually benign; not source-tracked.", path)
    } else {
        format!(
            "`{}` is in the release tarball but not in git at the corresponding tag. \
             Investigate whether it was generated reproducibly from a tracked source, or injected.",
            path
        )
    }
}

fn describe_modified(path: &str, eco: Option<Ecosystem>) -> String {
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
        format!(
            "`{}` differs between git and the release tarball. Build-system divergence is the highest-confidence indicator \
             of a tampered release: an attacker can ship code that is never visible to git-based review (XZ Utils CVE-2024-3094). \
             Diff the two versions byte-for-byte before trusting the release.",
            path
        )
    } else if is_known_dist_artifact(path) {
        format!("`{}` is autogenerated and differs between sources. Check it was produced by a deterministic tool run.", path)
    } else {
        format!("`{}` content differs between git and the release tarball. Source-tracked file should match its tagged version.", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_xz_pattern() {
        // Allowlisted gettext m4 added-only is Info (expected at release time);
        // the *content scan* is what flags it when the payload is hidden.
        assert_eq!(classify_added("m4/build-to-host.m4", None), Severity::Info);
        // Unknown m4 file release-only is High (no allowlist hit, suspicious).
        assert_eq!(classify_added("m4/custom-glue.m4", None), Severity::High);
        // Modified build-system file remains the smoking gun.
        assert_eq!(classify_modified("m4/build-to-host.m4", None), Severity::P0);
        assert_eq!(classify_modified("m4/gettext.m4", None), Severity::P0);
        // Standard dist artifacts in release-only are Info.
        assert_eq!(classify_added("configure", None), Severity::Info);
        assert_eq!(classify_added("aclocal.m4", None), Severity::Info);
        assert_eq!(classify_added("AUTHORS", None), Severity::Info);
        assert_eq!(classify_added("po/fr.gmo", None), Severity::Info);
        assert_eq!(classify_added("build-aux/install-sh", None), Severity::Info);
    }

    #[test]
    fn ecosystem_allowlist_crates() {
        // crates.io always adds these:
        assert_eq!(classify_added(".cargo_vcs_info.json", Some(Ecosystem::Crates)), Severity::Info);
        assert_eq!(classify_added("Cargo.toml.orig", Some(Ecosystem::Crates)), Severity::Info);
        assert_eq!(classify_added("Cargo.lock", Some(Ecosystem::Crates)), Severity::Info);
        // Cargo.toml is rewritten by `cargo publish` — modification is expected:
        assert_eq!(classify_modified("Cargo.toml", Some(Ecosystem::Crates)), Severity::Info);
        // Without an ecosystem hint, modified Cargo.toml is HIGH (no info).
        assert_eq!(classify_modified("Cargo.toml", None), Severity::High);
    }

    #[test]
    fn ecosystem_allowlist_npm() {
        assert_eq!(classify_modified("package.json", Some(Ecosystem::Npm)), Severity::Info);
        assert_eq!(classify_modified("package.json", None), Severity::High);
    }

    #[test]
    fn ecosystem_allowlist_pypi() {
        assert_eq!(classify_added("PKG-INFO", Some(Ecosystem::PyPI)), Severity::Info);
        assert_eq!(classify_added("foo.egg-info/PKG-INFO", Some(Ecosystem::PyPI)), Severity::Info);
        assert_eq!(classify_added("PKG-INFO", None), Severity::Medium); // unknown otherwise
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
        for _ in 0..210 { s.push('A'); }
        assert!(has_long_base64_run(&s, 200));
        assert!(!has_long_base64_run("AAAA", 200));
    }

    fn entry(sha: u8) -> Entry {
        let mut s = [0u8; 32];
        s[0] = sha;
        Entry { size: 1, sha256: s, head: None }
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
