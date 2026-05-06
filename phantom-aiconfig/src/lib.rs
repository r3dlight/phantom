//! AI-tooling config detector.
//!
//! Inventories the AI-agent configuration files in a project (CLAUDE.md,
//! AGENTS.md, .cursorrules, .mcp.json, .claude/settings.json, ...) and applies:
//! 1. The shared `phantom-rules` content rules (prompt-injection, hardcoded
//!    trust, permission bypass, invisible Unicode, ...).
//! 2. Structural checks specific to MCP server entries (shell-as-entrypoint,
//!    network-fetch-on-launch, sandbox-disabled, ...).
//!
//! AI-immune by construction: signals come from the file contents, not from
//! who authored a commit.

use phantom_core::{Finding, Location, Severity};
use phantom_rules::content_rules;
use serde_json::json;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const DETECTOR: &str = "aiconfig";

/// (suffix, rule_id, kind)
const PATH_PATTERNS: &[(&str, &str, &str)] = &[
    ("CLAUDE.md", "ai-instructions-file", "claude-instructions"),
    ("AGENTS.md", "ai-instructions-file", "agent-instructions"),
    (".cursorrules", "ai-instructions-file", "cursor-rules"),
    (".cursor/rules", "ai-instructions-file", "cursor-rules-dir"),
    (".windsurfrules", "ai-instructions-file", "windsurf-rules"),
    (".aider.conf.yml", "ai-instructions-file", "aider-config"),
    (".github/copilot-instructions.md", "ai-instructions-file", "copilot-instructions"),
    (".mcp.json", "mcp-config", "mcp-project"),
    ("mcp.json", "mcp-config", "mcp-generic"),
    ("claude_desktop_config.json", "mcp-config", "claude-desktop"),
    (".claude/settings.json", "agent-settings", "claude-settings"),
    (".claude/settings.local.json", "agent-settings", "claude-settings-local"),
];

/// Returns true when `rel` is inside any of the `ignore` prefix subtrees.
/// Component-aware: `Path::starts_with` requires whole-component matches.
pub(crate) fn is_ignored(rel: &Path, ignore: &[PathBuf]) -> bool {
    ignore.iter().any(|p| rel.starts_with(p))
}

fn relpath_endswith(rel: &str, suffix: &str) -> bool {
    if rel == suffix {
        return true;
    }
    if let Some(stripped) = rel.strip_suffix(suffix) {
        return stripped.is_empty() || stripped.ends_with('/');
    }
    false
}

fn match_path(rel: &str) -> Option<(&'static str, &'static str)> {
    for (suffix, rule, kind) in PATH_PATTERNS {
        if relpath_endswith(rel, suffix) {
            return Some((rule, kind));
        }
    }
    None
}

/// MCP server entries with broad capabilities are flagged separately because
/// installing an MCP server is the moral equivalent of granting `postinstall`
/// script powers to the project's tooling.
fn flag_mcp_servers(path: &Path, content: &str) -> Vec<Finding> {
    let mut findings = vec![];
    let json_value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    let servers = json_value.get("mcpServers").or_else(|| json_value.get("servers"));
    let Some(serde_json::Value::Object(map)) = servers else {
        return findings;
    };

    for (name, cfg) in map {
        let command = cfg.get("command").and_then(|v| v.as_str()).unwrap_or("");
        let args: Vec<String> = cfg
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str()).map(String::from).collect())
            .unwrap_or_default();
        let env_keys: Vec<String> = cfg
            .get("env")
            .and_then(|v| v.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let url = cfg.get("url").and_then(|v| v.as_str()).map(String::from);
        let transport = cfg
            .get("transport")
            .and_then(|v| v.as_str())
            .map(String::from);

        let mut concerns: Vec<&'static str> = vec![];
        let lc = command.to_ascii_lowercase();
        let basename_lc = lc.rsplit('/').next().unwrap_or(&lc).to_string();
        if matches!(basename_lc.as_str(), "sh" | "bash" | "zsh" | "ksh" | "dash" | "ash" | "fish") {
            concerns.push("shell-as-entrypoint");
        }
        if matches!(basename_lc.as_str(), "curl" | "wget") {
            concerns.push("network-fetch-on-launch");
        }
        if args.iter().any(|a| a.starts_with("http://") || a.starts_with("https://")) {
            concerns.push("network-url-as-arg");
        }
        if args.iter().any(|a| a.contains("--allow-all") || a.contains("--no-sandbox") || a.contains("--insecure")) {
            concerns.push("sandbox-or-tls-disabled");
        }
        if args.iter().any(|a| a.contains("| bash") || a.contains("|sh") || a.contains("| sh")) {
            concerns.push("piped-curl-bash");
        }
        if let Some(u) = &url {
            if u.starts_with("http://") {
                concerns.push("plaintext-http-transport");
            }
        }

        let severity = if !concerns.is_empty() {
            Severity::High
        } else if transport.as_deref() == Some("http") || url.is_some() {
            Severity::Medium
        } else {
            Severity::Medium
        };

        findings.push(Finding {
            detector: DETECTOR.into(),
            rule: "mcp-server-entry".into(),
            severity,
            title: format!("MCP server `{}` declared", name),
            description: format!(
                "MCP servers granted to a project apply to anyone running the project's agent. \
                 Treat this as installing a binary with shell access. \
                 Concerns: {}",
                if concerns.is_empty() {
                    "none beyond the install itself".to_string()
                } else {
                    concerns.join(", ")
                }
            ),
            locations: vec![Location::path(path.display().to_string())],
            evidence: json!({
                "name": name,
                "command": command,
                "args": args,
                "env_keys": env_keys,
                "url": url,
                "transport": transport,
                "concerns": concerns,
            }),
        });
    }

    findings
}

/// Recursively scan `root` for AI-agent configuration files.
///
/// `ignore` holds path prefixes (relative to `root`) whose subtrees are
/// skipped entirely — comparison is path-component aware (`examples` does
/// **not** match `examplesextra`).
pub fn scan(root: &Path, ignore: &[PathBuf]) -> std::io::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let rules = content_rules().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    })?;

    let walker = WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        if matches!(
            name.as_ref(),
            ".git" | "target" | "node_modules" | "dist" | "build" | ".next"
        ) {
            return false;
        }
        let rel = e.path().strip_prefix(root).unwrap_or(e.path());
        !is_ignored(rel, ignore)
    });

    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel: PathBuf = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let Some((path_rule, kind)) = match_path(&rel_str) else { continue; };

        let path_display = path.display().to_string();

        findings.push(Finding {
            detector: DETECTOR.into(),
            rule: path_rule.into(),
            severity: Severity::Info,
            title: format!("AI tooling config present: `{}`", rel_str),
            description: format!(
                "Detected `{}` ({}). Inventoried for review; further checks below.",
                rel_str, kind
            ),
            locations: vec![Location::path(path_display.clone())],
            evidence: json!({ "kind": kind }),
        });

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
                    title: format!("{}: `{}`{}", m.rule_id, rel_str, via_suffix),
                    description,
                    locations: vec![Location {
                        path: path_display.clone(),
                        line: Some(m.line),
                        excerpt: Some(m.excerpt),
                    }],
                    evidence: json!({ "kind": kind, "column": m.column, "via": m.via }),
                });
            }
        }

        if matches!(kind, "mcp-project" | "mcp-generic" | "claude-desktop") {
            findings.extend(flag_mcp_servers(path, &content));
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relpath_match_basic() {
        assert!(relpath_endswith("CLAUDE.md", "CLAUDE.md"));
        assert!(relpath_endswith("docs/CLAUDE.md", "CLAUDE.md"));
        assert!(!relpath_endswith("FAKECLAUDE.md", "CLAUDE.md"));
        assert!(relpath_endswith(".claude/settings.json", ".claude/settings.json"));
        assert!(relpath_endswith("nested/.claude/settings.json", ".claude/settings.json"));
    }

    #[test]
    fn ignore_is_component_aware() {
        let ignore = vec![PathBuf::from("examples")];
        assert!(is_ignored(Path::new("examples/CLAUDE.md"), &ignore));
        assert!(is_ignored(Path::new("examples"), &ignore));
        assert!(!is_ignored(Path::new("src/main.rs"), &ignore));
        // crucial: "examplesextra" must NOT match "examples"
        assert!(!is_ignored(Path::new("examplesextra/foo"), &ignore));
    }

    #[test]
    fn ignore_multiple_prefixes() {
        let ignore = vec![PathBuf::from("examples"), PathBuf::from("tests/fixtures")];
        assert!(is_ignored(Path::new("examples/x"), &ignore));
        assert!(is_ignored(Path::new("tests/fixtures/y"), &ignore));
        assert!(!is_ignored(Path::new("tests/unit/z"), &ignore));
    }

    #[test]
    fn ignore_empty_keeps_everything() {
        let ignore: Vec<PathBuf> = vec![];
        assert!(!is_ignored(Path::new("anything"), &ignore));
    }
}
