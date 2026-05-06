//! Indirect prompt-injection scanner.
//!
//! Walks a repository and applies the shared `phantom-rules` content rules to
//! every file an AI agent is likely to ingest as context: READMEs, docs,
//! CHANGELOG/NEWS/CONTRIBUTING, issue and PR templates, GitHub discussion
//! templates, and Markdown/text/RST/AsciiDoc files.
//!
//! Code source files are intentionally **not** scanned here — comment-aware
//! parsing per language is planned in a later iteration; running these regexes
//! on raw source gives noisy false positives.

use phantom_core::{Finding, Location};
use phantom_rules::content_rules;
use serde_json::json;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const DETECTOR: &str = "promptinjection";

const TEXT_EXTENSIONS: &[&str] = &["md", "markdown", "rst", "adoc", "txt", "mdx"];

/// File basenames (case-insensitive, may have an extension after them) that
/// agents commonly read for project context.
const TEXT_BASENAMES: &[&str] = &[
    "readme",
    "changelog",
    "changes",
    "news",
    "contributing",
    "authors",
    "governance",
    "code_of_conduct",
    "code-of-conduct",
    "security",
    "support",
    "maintainers",
    "roadmap",
    "history",
];

/// Files explicitly excluded — pure license / notice text whose archaic phrasing
/// reliably trips the rules with no security value.
const EXCLUDED_BASENAMES: &[&str] = &[
    "license",
    "licence",
    "copying",
    "copying.lib",
    "notice",
];

const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".cache",
    "vendor",
];

fn is_target_file(rel: &Path) -> bool {
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else { return false; };
    let name_lc = name.to_ascii_lowercase();

    let stem_lc = name_lc.split('.').next().unwrap_or("");
    if EXCLUDED_BASENAMES.iter().any(|b| b == &stem_lc) {
        return false;
    }

    if let Some(ext) = rel.extension().and_then(|e| e.to_str()) {
        if TEXT_EXTENSIONS.iter().any(|t| t.eq_ignore_ascii_case(ext)) {
            return true;
        }
    }

    if TEXT_BASENAMES.iter().any(|b| b == &stem_lc) {
        return true;
    }

    // GitHub special template paths (e.g. ISSUE_TEMPLATE may contain extensionless files).
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    if rel_str.contains(".github/ISSUE_TEMPLATE/")
        || rel_str.contains(".github/PULL_REQUEST_TEMPLATE")
        || rel_str.contains(".github/DISCUSSION_TEMPLATE/")
    {
        return true;
    }

    false
}

/// Recursively scan `root` for indirect prompt-injection patterns in
/// text-likely files. `ignore` skips any subtree whose relative path is
/// prefixed by one of its entries (component-aware).
pub fn scan(root: &Path, ignore: &[PathBuf]) -> std::io::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let rules = content_rules().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    })?;

    let walker = WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        if SKIPPED_DIRS.iter().any(|d| d == &name.as_ref()) {
            return false;
        }
        let rel = e.path().strip_prefix(root).unwrap_or(e.path());
        !ignore.iter().any(|p| rel.starts_with(p))
    });

    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel: PathBuf = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        if !is_target_file(&rel) {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        for rule in rules {
            for m in rule.matches_all_views(&content) {
                let via_suffix = if m.via == "raw" {
                    String::new()
                } else {
                    format!(" (via {})", m.via)
                };
                let description = if m.via == "raw" {
                    m.description.to_string()
                } else {
                    format!(
                        "{} Caught after normalisation layer `{}` — the payload was obfuscated in the source.",
                        m.description, m.via
                    )
                };
                findings.push(Finding {
                    detector: DETECTOR.into(),
                    rule: m.rule_id.into(),
                    severity: m.severity,
                    title: format!("{}: `{}`{}", m.rule_id, rel.display(), via_suffix),
                    description,
                    locations: vec![Location {
                        path: path.display().to_string(),
                        line: Some(m.line),
                        excerpt: Some(m.excerpt),
                    }],
                    evidence: json!({ "column": m.column, "via": m.via }),
                });
            }
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn target_classification() {
        assert!(is_target_file(Path::new("README.md")));
        assert!(is_target_file(Path::new("docs/intro.md")));
        assert!(is_target_file(Path::new("CHANGELOG")));
        assert!(is_target_file(Path::new(".github/ISSUE_TEMPLATE/bug.yml")));
        assert!(!is_target_file(Path::new("LICENSE")));
        assert!(!is_target_file(Path::new("LICENSE.md")));
        assert!(!is_target_file(Path::new("src/lib.rs")));
    }
}
