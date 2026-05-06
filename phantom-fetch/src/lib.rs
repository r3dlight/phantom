//! Multi-ecosystem release downloader for `phantom tarball-diff`.
//!
//! Supported spec shapes:
//!
//! ```text
//! owner/repo[@tag]            (default scheme = github)
//! github:owner/repo[@tag]
//! gh:owner/repo[@tag]
//! npm:package[@version]
//! pypi:package[@version]
//! crates:package[@version]
//! ```
//!
//! For every ecosystem we download the released artifact (tarball / sdist /
//! `.crate`) and **best-effort** also fetch the matching git source archive,
//! by reading the registry's `repository` URL and trying common tag patterns
//! (`v<ver>`, `<ver>`, `<pkg>-<ver>`). When auto-resolution fails the caller
//! must supply `--git-archive` manually.
//!
//! Honours `GITHUB_TOKEN` for higher rate limits on the GitHub paths but
//! never requires it. Cache layout: `$XDG_CACHE_HOME/phantom/<scheme>/...`.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::fs::{self, File};
use std::io::copy;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

const USER_AGENT: &str = concat!("phantom-fetch/", env!("CARGO_PKG_VERSION"));

// ─── Spec parsing ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageSpec {
    GitHub {
        owner: String,
        repo: String,
        tag: Option<String>,
    },
    Npm {
        package: String,
        version: Option<String>,
    },
    PyPI {
        package: String,
        version: Option<String>,
    },
    Crates {
        package: String,
        version: Option<String>,
    },
}

impl FromStr for PackageSpec {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let (scheme, rest) = match s.split_once(':') {
            Some((sch, r)) if matches!(sch, "github" | "gh" | "npm" | "pypi" | "crates") => {
                (sch, r)
            }
            _ => ("github", s),
        };

        // Split off `@version`. npm scoped names start with `@scope/...` so
        // we must look for the *last* `@` and ensure the right-hand side
        // does not contain `/` (which would mean we ate the scope).
        let (name, version) = match rest.rsplit_once('@') {
            Some((n, v)) if !n.is_empty() && !v.is_empty() && !v.contains('/') => {
                (n, Some(v.to_string()))
            }
            _ => (rest, None),
        };

        match scheme {
            "github" | "gh" => {
                let (owner, repo) = name
                    .split_once('/')
                    .ok_or_else(|| anyhow!("expected `owner/repo[@tag]`, got `{}`", s))?;
                if owner.is_empty() || repo.is_empty() {
                    bail!("invalid github spec: `{}`", s);
                }
                Ok(PackageSpec::GitHub {
                    owner: owner.into(),
                    repo: repo.into(),
                    tag: version,
                })
            }
            "npm" => {
                if name.is_empty() {
                    bail!("missing npm package name in `{}`", s);
                }
                Ok(PackageSpec::Npm {
                    package: name.into(),
                    version,
                })
            }
            "pypi" => {
                if name.is_empty() {
                    bail!("missing pypi package name in `{}`", s);
                }
                Ok(PackageSpec::PyPI {
                    package: name.into(),
                    version,
                })
            }
            "crates" => {
                if name.is_empty() {
                    bail!("missing crate name in `{}`", s);
                }
                Ok(PackageSpec::Crates {
                    package: name.into(),
                    version,
                })
            }
            _ => bail!("unknown ecosystem `{}` in `{}`", scheme, s),
        }
    }
}

/// Compatibility shim: previously `--release` only accepted GitHub specs.
#[derive(Debug, Clone)]
pub struct ReleaseSpec {
    pub owner: String,
    pub repo: String,
    pub tag: Option<String>,
}

impl FromStr for ReleaseSpec {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.parse::<PackageSpec>()? {
            PackageSpec::GitHub { owner, repo, tag } => Ok(Self { owner, repo, tag }),
            _ => bail!("expected a github spec; for npm/pypi/crates use `phantom_fetch::download(PackageSpec…)`"),
        }
    }
}

// ─── Common helpers ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct DownloadedRelease {
    /// Human-readable label used in reports (`github://owner/repo@v1.2.3`,
    /// `npm:lodash@4.17.21`, …).
    pub spec_label: String,
    pub resolved_version: String,
    /// Source archive (typically a GitHub-auto-generated tarball at the
    /// matching tag). `None` when the registry metadata didn't point at a
    /// resolvable git source — caller must then supply `--git-archive`
    /// manually.
    pub source_archive: Option<PathBuf>,
    /// Released artifacts (tarball / sdist / `.crate`).
    pub release_assets: Vec<PathBuf>,
}

pub fn cache_root() -> Result<PathBuf> {
    let base = dirs::cache_dir().ok_or_else(|| anyhow!("no XDG cache directory available"))?;
    Ok(base.join("phantom"))
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(120))
        .user_agent(USER_AGENT)
        .build()
}

fn github_auth_header() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|t| format!("Bearer {}", t))
}

fn api_get(agent: &ureq::Agent, url: &str, github_auth: bool) -> Result<ureq::Response> {
    let mut req = agent.get(url).set("Accept", "application/json");
    if github_auth {
        if let Some(auth) = github_auth_header() {
            req = req.set("Authorization", &auth);
        }
    }
    let resp = req.call().with_context(|| format!("GET {}", url))?;
    Ok(resp)
}

fn download_to(agent: &ureq::Agent, url: &str, dest: &Path, github_auth: bool) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut req = agent.get(url);
    if github_auth {
        if let Some(auth) = github_auth_header() {
            req = req.set("Authorization", &auth);
        }
    }
    let resp = req.call().with_context(|| format!("GET {}", url))?;
    let mut reader = resp.into_reader();
    let tmp = dest.with_extension("download.tmp");
    {
        let mut file = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        copy(&mut reader, &mut file).context("downloading body")?;
        file.sync_all().ok();
    }
    fs::rename(&tmp, dest).with_context(|| format!("finalizing {}", dest.display()))?;
    Ok(())
}

fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn is_tar_gz(name: &str) -> bool {
    let lc = name.to_ascii_lowercase();
    lc.ends_with(".tar.gz") || lc.ends_with(".tgz")
}

/// Parse an upstream `repository.url` (npm / PyPI / crates.io conventions)
/// and return `(owner, repo)` if it points at a GitHub repo. Recognises:
/// `https://github.com/...`, `git+https://github.com/...`,
/// `git://github.com/...`, `git@github.com:...`, with optional `.git`
/// suffix.
fn parse_github_url(url: &str) -> Option<(String, String)> {
    let url = url
        .trim()
        .trim_start_matches("git+")
        .trim_start_matches("ssh://")
        .trim_start_matches("git://");
    let after = if let Some(a) = url.strip_prefix("https://github.com/") {
        a
    } else if let Some(a) = url.strip_prefix("http://github.com/") {
        a
    } else if let Some(a) = url.strip_prefix("github.com/") {
        a
    } else if let Some(a) = url.strip_prefix("git@github.com:") {
        a
    } else {
        return None;
    };
    let (owner, rest) = after.split_once('/')?;
    let repo = rest
        .split(|c: char| c == '/' || c == '#' || c == '?')
        .next()?
        .trim_end_matches(".git");
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

/// Best-effort fetch of a `git archive`-equivalent tarball for `version`
/// from the GitHub repo at `(owner, repo)`. Tries the patterns in order;
/// returns the first that succeeds.
fn try_fetch_github_source(
    agent: &ureq::Agent,
    owner: &str,
    repo: &str,
    version: &str,
    extra_tag_patterns: &[String],
    cache_dir: &Path,
) -> Option<PathBuf> {
    let mut patterns: Vec<String> = vec![format!("v{}", version), version.to_string()];
    patterns.extend(extra_tag_patterns.iter().cloned());

    for tag in &patterns {
        let dest = cache_dir.join(format!("source-{}.tar.gz", sanitize_name(tag)));
        if dest.exists() {
            return Some(dest);
        }
        let url = format!(
            "https://github.com/{}/{}/archive/refs/tags/{}.tar.gz",
            owner, repo, tag
        );
        if download_to(agent, &url, &dest, true).is_ok() {
            return Some(dest);
        }
    }
    None
}

// ─── Dispatch ────────────────────────────────────────────────────────────────

pub fn download(spec: &PackageSpec) -> Result<DownloadedRelease> {
    match spec {
        PackageSpec::GitHub { owner, repo, tag } => download_github(owner, repo, tag.as_deref()),
        PackageSpec::Npm { package, version } => download_npm(package, version.as_deref()),
        PackageSpec::PyPI { package, version } => download_pypi(package, version.as_deref()),
        PackageSpec::Crates { package, version } => download_crates(package, version.as_deref()),
    }
}

/// Pick a release asset most likely to be the canonical "source release
/// tarball". For GitHub, prefers the shortest filename containing the repo
/// name. For npm / PyPI / crates, the released artifact is unique and is the
/// only entry — return it directly.
pub fn pick_canonical_asset(rel: &DownloadedRelease) -> Option<&Path> {
    if rel.release_assets.len() == 1 {
        return rel.release_assets.first().map(|p| p.as_path());
    }
    rel.release_assets
        .iter()
        .min_by_key(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(str::len)
                .unwrap_or(usize::MAX)
        })
        .map(|p| p.as_path())
        .or_else(|| rel.release_assets.first().map(|p| p.as_path()))
}

// ─── GitHub ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GhReleaseInfo {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GhAssetInfo>,
}

#[derive(Debug, Deserialize)]
struct GhAssetInfo {
    name: String,
    browser_download_url: String,
}

fn download_github(owner: &str, repo: &str, tag: Option<&str>) -> Result<DownloadedRelease> {
    let agent = agent();
    let url = match tag {
        Some(t) => format!(
            "https://api.github.com/repos/{}/{}/releases/tags/{}",
            owner, repo, t
        ),
        None => format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            owner, repo
        ),
    };
    let resp = api_get(&agent, &url, true)
        .with_context(|| format!("fetching GitHub release info for {}/{}", owner, repo))?;
    let info: GhReleaseInfo = resp.into_json().context("parsing release JSON")?;
    let resolved_version = info.tag_name.clone();

    let cache = cache_root()?
        .join("github")
        .join(owner)
        .join(repo)
        .join(&resolved_version);
    fs::create_dir_all(&cache)?;

    let source_url = format!(
        "https://github.com/{}/{}/archive/refs/tags/{}.tar.gz",
        owner, repo, resolved_version
    );
    let source_archive = cache.join(format!(
        "source-{}.tar.gz",
        sanitize_name(&resolved_version)
    ));
    if !source_archive.exists() {
        download_to(&agent, &source_url, &source_archive, true)
            .with_context(|| format!("downloading source archive for {}", resolved_version))?;
    }

    let mut release_assets = vec![];
    for a in &info.assets {
        if !is_tar_gz(&a.name) {
            continue;
        }
        let dest = cache.join(&a.name);
        if !dest.exists() {
            download_to(&agent, &a.browser_download_url, &dest, true)
                .with_context(|| format!("downloading asset {}", a.name))?;
        }
        release_assets.push(dest);
    }

    Ok(DownloadedRelease {
        spec_label: format!("github://{}/{}@{}", owner, repo, resolved_version),
        resolved_version,
        source_archive: Some(source_archive),
        release_assets,
    })
}

// ─── npm ────────────────────────────────────────────────────────────────────

fn download_npm(package: &str, version: Option<&str>) -> Result<DownloadedRelease> {
    let agent = agent();

    // Resolve version (latest tag if not specified).
    let resolved = match version {
        Some(v) => v.to_string(),
        None => {
            let url = format!("https://registry.npmjs.org/{}", url_path_encode(package));
            let resp = api_get(&agent, &url, false)
                .with_context(|| format!("fetching npm package metadata for {}", package))?;
            let info: Value = resp.into_json().context("parsing npm metadata")?;
            info["dist-tags"]["latest"]
                .as_str()
                .ok_or_else(|| anyhow!("npm package `{}` has no `dist-tags.latest`", package))?
                .to_string()
        }
    };

    let url = format!(
        "https://registry.npmjs.org/{}/{}",
        url_path_encode(package),
        resolved
    );
    let resp = api_get(&agent, &url, false)
        .with_context(|| format!("fetching npm version metadata for {}@{}", package, resolved))?;
    let info: Value = resp.into_json().context("parsing npm version metadata")?;

    let tarball_url = info["dist"]["tarball"]
        .as_str()
        .ok_or_else(|| anyhow!("no `dist.tarball` for {}@{}", package, resolved))?
        .to_string();

    // npm allows several shapes for repository: a string, or an object with
    // `url` field. `repository.url` may be `git+https://...`, plain URL, etc.
    let repo_url = info["repository"]
        .as_str()
        .or_else(|| info["repository"]["url"].as_str())
        .map(String::from);

    let cache = cache_root()?
        .join("npm")
        .join(sanitize_name(package))
        .join(&resolved);
    fs::create_dir_all(&cache)?;

    let release_filename = format!(
        "{}-{}.tgz",
        sanitize_name(package),
        sanitize_name(&resolved)
    );
    let release_path = cache.join(&release_filename);
    if !release_path.exists() {
        download_to(&agent, &tarball_url, &release_path, false)
            .with_context(|| format!("downloading npm tarball for {}@{}", package, resolved))?;
    }

    let source_archive =
        repo_url
            .as_deref()
            .and_then(parse_github_url)
            .and_then(|(owner, repo)| {
                // npm-specific tag patterns: many projects tag `v<version>`,
                // some lerna monorepos tag `<package>@<version>`.
                let extra = vec![
                    format!("{}@{}", package, resolved),
                    format!("{}-v{}", package, resolved),
                ];
                try_fetch_github_source(&agent, &owner, &repo, &resolved, &extra, &cache)
            });

    Ok(DownloadedRelease {
        spec_label: format!("npm:{}@{}", package, resolved),
        resolved_version: resolved,
        source_archive,
        release_assets: vec![release_path],
    })
}

fn url_path_encode(s: &str) -> String {
    // npm scoped packages have a `/` in the name (`@scope/pkg`) which must
    // be percent-encoded when inserted into the URL path between segments.
    s.replace('/', "%2F")
}

// ─── PyPI ───────────────────────────────────────────────────────────────────

fn download_pypi(package: &str, version: Option<&str>) -> Result<DownloadedRelease> {
    let agent = agent();
    let path_part = match version {
        Some(v) => format!("{}/{}", package, v),
        None => package.to_string(),
    };
    let url = format!("https://pypi.org/pypi/{}/json", path_part);
    let resp = api_get(&agent, &url, false)
        .with_context(|| format!("fetching PyPI metadata for {}", path_part))?;
    let info: Value = resp.into_json().context("parsing PyPI metadata")?;

    let resolved = info["info"]["version"]
        .as_str()
        .ok_or_else(|| anyhow!("no version for PyPI package {}", package))?
        .to_string();

    // Find sdist URL from the `urls` array (the JSON returned by `/pypi/pkg/ver/json`
    // has urls for every release artifact for *that version*; for the no-version
    // form the urls are for the latest release).
    let urls = info["urls"]
        .as_array()
        .ok_or_else(|| anyhow!("no urls array in PyPI metadata for {}", package))?;
    let sdist = urls
        .iter()
        .find(|u| u["packagetype"].as_str() == Some("sdist"))
        .ok_or_else(|| {
            anyhow!(
                "no sdist artifact for PyPI {}@{}; only wheels published",
                package,
                resolved
            )
        })?;
    let sdist_url = sdist["url"]
        .as_str()
        .ok_or_else(|| anyhow!("malformed sdist url"))?
        .to_string();
    let filename = sdist["filename"]
        .as_str()
        .unwrap_or("sdist.tar.gz")
        .to_string();

    let cache = cache_root()?
        .join("pypi")
        .join(sanitize_name(package))
        .join(&resolved);
    fs::create_dir_all(&cache)?;

    let release_path = cache.join(&filename);
    if !release_path.exists() {
        download_to(&agent, &sdist_url, &release_path, false)
            .with_context(|| format!("downloading PyPI sdist for {}@{}", package, resolved))?;
    }

    // Source repo is typically in info.project_urls or info.home_page.
    let repo_url = (|| -> Option<String> {
        if let Some(map) = info["info"]["project_urls"].as_object() {
            for key in &[
                "Source",
                "Source Code",
                "Repository",
                "Homepage",
                "GitHub",
                "Code",
            ] {
                if let Some(v) = map.get(*key).and_then(|v| v.as_str()) {
                    return Some(v.into());
                }
            }
            for v in map.values() {
                if let Some(s) = v.as_str() {
                    if s.contains("github.com/") {
                        return Some(s.into());
                    }
                }
            }
        }
        info["info"]["home_page"].as_str().map(String::from)
    })();

    let source_archive =
        repo_url
            .as_deref()
            .and_then(parse_github_url)
            .and_then(|(owner, repo)| {
                let extra = vec![
                    format!("{}-{}", package, resolved),
                    format!("release-{}", resolved),
                ];
                try_fetch_github_source(&agent, &owner, &repo, &resolved, &extra, &cache)
            });

    Ok(DownloadedRelease {
        spec_label: format!("pypi:{}@{}", package, resolved),
        resolved_version: resolved,
        source_archive,
        release_assets: vec![release_path],
    })
}

// ─── crates.io ──────────────────────────────────────────────────────────────

fn download_crates(package: &str, version: Option<&str>) -> Result<DownloadedRelease> {
    let agent = agent();

    // Top-level metadata exposes max_stable_version + repository.
    let url = format!("https://crates.io/api/v1/crates/{}", package);
    let resp = api_get(&agent, &url, false)
        .with_context(|| format!("fetching crates.io metadata for {}", package))?;
    let info: Value = resp.into_json().context("parsing crates.io metadata")?;

    let resolved = match version {
        Some(v) => v.to_string(),
        None => info["crate"]["max_stable_version"]
            .as_str()
            .or_else(|| info["crate"]["max_version"].as_str())
            .ok_or_else(|| anyhow!("no version for crate {}", package))?
            .to_string(),
    };

    let download_url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        package, resolved
    );

    let cache = cache_root()?
        .join("crates")
        .join(sanitize_name(package))
        .join(&resolved);
    fs::create_dir_all(&cache)?;

    // Crate files are gzipped tar archives with a `.crate` extension.
    let release_filename = format!(
        "{}-{}.crate",
        sanitize_name(package),
        sanitize_name(&resolved)
    );
    let release_path = cache.join(&release_filename);
    if !release_path.exists() {
        download_to(&agent, &download_url, &release_path, false)
            .with_context(|| format!("downloading crate {}@{}", package, resolved))?;
    }

    let repo_url = info["crate"]["repository"].as_str().map(String::from);

    let source_archive =
        repo_url
            .as_deref()
            .and_then(parse_github_url)
            .and_then(|(owner, repo)| {
                // crates.io workspaces sometimes tag `<crate>-v<ver>` or
                // `<crate>-<ver>` to disambiguate among workspace members.
                let extra = vec![
                    format!("{}-v{}", package, resolved),
                    format!("{}-{}", package, resolved),
                ];
                try_fetch_github_source(&agent, &owner, &repo, &resolved, &extra, &cache)
            });

    Ok(DownloadedRelease {
        spec_label: format!("crates:{}@{}", package, resolved),
        resolved_version: resolved,
        source_archive,
        release_assets: vec![release_path],
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_github_default() {
        let s: PackageSpec = "tukaani-project/xz@v5.4.7".parse().unwrap();
        assert_eq!(
            s,
            PackageSpec::GitHub {
                owner: "tukaani-project".into(),
                repo: "xz".into(),
                tag: Some("v5.4.7".into()),
            }
        );
    }

    #[test]
    fn parse_github_explicit_scheme() {
        let s: PackageSpec = "github:owner/repo".parse().unwrap();
        assert!(matches!(s, PackageSpec::GitHub { tag: None, .. }));
        let s2: PackageSpec = "gh:owner/repo@v1".parse().unwrap();
        assert!(matches!(s2, PackageSpec::GitHub { tag: Some(_), .. }));
    }

    #[test]
    fn parse_npm_simple() {
        let s: PackageSpec = "npm:lodash@4.17.21".parse().unwrap();
        assert_eq!(
            s,
            PackageSpec::Npm {
                package: "lodash".into(),
                version: Some("4.17.21".into()),
            }
        );
    }

    #[test]
    fn parse_npm_scoped() {
        let s: PackageSpec = "npm:@types/node@20.0.0".parse().unwrap();
        assert_eq!(
            s,
            PackageSpec::Npm {
                package: "@types/node".into(),
                version: Some("20.0.0".into()),
            }
        );
    }

    #[test]
    fn parse_npm_scoped_no_version() {
        let s: PackageSpec = "npm:@types/node".parse().unwrap();
        assert_eq!(
            s,
            PackageSpec::Npm {
                package: "@types/node".into(),
                version: None,
            }
        );
    }

    #[test]
    fn parse_pypi() {
        let s: PackageSpec = "pypi:requests@2.31.0".parse().unwrap();
        assert_eq!(
            s,
            PackageSpec::PyPI {
                package: "requests".into(),
                version: Some("2.31.0".into()),
            }
        );
    }

    #[test]
    fn parse_crates() {
        let s: PackageSpec = "crates:serde@1.0.193".parse().unwrap();
        assert_eq!(
            s,
            PackageSpec::Crates {
                package: "serde".into(),
                version: Some("1.0.193".into()),
            }
        );
    }

    #[test]
    fn parse_invalid() {
        assert!("nope".parse::<PackageSpec>().is_err());
        assert!("npm:".parse::<PackageSpec>().is_err());
        assert!("unknown:foo@bar".parse::<PackageSpec>().is_err());
    }

    #[test]
    fn release_spec_only_accepts_github() {
        let r: ReleaseSpec = "owner/repo@v1".parse().unwrap();
        assert_eq!(r.repo, "repo");
        assert!("npm:foo".parse::<ReleaseSpec>().is_err());
    }

    #[test]
    fn parse_github_url_variants() {
        assert_eq!(
            parse_github_url("https://github.com/owner/repo"),
            Some(("owner".into(), "repo".into()))
        );
        assert_eq!(
            parse_github_url("https://github.com/owner/repo.git"),
            Some(("owner".into(), "repo".into()))
        );
        assert_eq!(
            parse_github_url("git+https://github.com/owner/repo.git"),
            Some(("owner".into(), "repo".into()))
        );
        assert_eq!(
            parse_github_url("git@github.com:owner/repo.git"),
            Some(("owner".into(), "repo".into()))
        );
        assert_eq!(
            parse_github_url("https://github.com/owner/repo/issues#42"),
            Some(("owner".into(), "repo".into()))
        );
        assert_eq!(parse_github_url("https://gitlab.com/foo/bar"), None);
        assert_eq!(parse_github_url("not a url"), None);
    }

    #[test]
    fn sanitize_strips_separators() {
        assert_eq!(sanitize_name("v5.6.1"), "v5.6.1");
        assert_eq!(sanitize_name("a/b\\c"), "a_b_c");
    }

    #[test]
    fn detects_tar_gz() {
        assert!(is_tar_gz("xz-5.6.1.tar.gz"));
        assert!(is_tar_gz("FOO.TGZ"));
        assert!(!is_tar_gz("xz.zip"));
    }
}
