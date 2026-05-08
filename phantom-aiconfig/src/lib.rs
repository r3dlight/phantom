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

/// How a path is matched against an AI-tooling config pattern.
#[derive(Debug, Clone, Copy)]
enum Match {
    /// The relative path ends with this suffix at a path-component boundary.
    /// `Suffix("CLAUDE.md")` matches `CLAUDE.md`, `docs/CLAUDE.md` but not
    /// `FAKECLAUDE.md`.
    Suffix(&'static str),
    /// The relative path is exactly this directory, or any file beneath it.
    /// `InDir(".cursor/rules/")` matches `.cursor/rules/python.mdc`,
    /// `.cursor/rules/security.mdc`, `nested/.cursor/rules/foo.mdc`.
    InDir(&'static str),
}

/// Patterns are ordered from most specific to most generic. The first
/// matching pattern wins. `kind` is a stable identifier for downstream
/// classification (e.g. MCP vs general instructions).
///
/// Every entry below corresponds to a project-level configuration file or
/// directory documented by its tool's official docs (no speculative
/// patterns — verified on each tool's documentation site as of 2026-05).
const PATH_PATTERNS: &[(Match, &str, &str)] = &[
    // ─── Claude Code / Anthropic ────────────────────────────────────────────
    (
        Match::Suffix("CLAUDE.md"),
        "ai-instructions-file",
        "claude-instructions",
    ),
    (
        Match::Suffix(".claude/settings.json"),
        "agent-settings",
        "claude-settings",
    ),
    (
        Match::Suffix(".claude/settings.local.json"),
        "agent-settings",
        "claude-settings-local",
    ),
    (
        Match::Suffix("claude_desktop_config.json"),
        "mcp-config",
        "claude-desktop",
    ),
    (Match::InDir(".claude/"), "agent-settings", "claude-dir"),
    // ─── Generic AGENTS.md ──────────────────────────────────────────────────
    // Read by OpenAI Codex CLI, Cursor, Aider, Grok CLI (with Codex-style
    // hierarchical merging), and others.
    (
        Match::Suffix("AGENTS.md"),
        "ai-instructions-file",
        "agent-instructions",
    ),
    (
        Match::Suffix("AGENTS.override.md"),
        "ai-instructions-file",
        "agent-instructions-override",
    ),
    // ─── Cursor (legacy single-file + modern multi-file rules) ─────────────
    (
        Match::Suffix(".cursorrules"),
        "ai-instructions-file",
        "cursor-rules",
    ),
    (
        Match::Suffix(".cursorignore"),
        "agent-settings",
        "cursor-ignore",
    ),
    (
        Match::InDir(".cursor/rules/"),
        "ai-instructions-file",
        "cursor-rule-file",
    ),
    (Match::InDir(".cursor/"), "agent-settings", "cursor-dir"),
    // ─── Windsurf (Codeium's IDE) ──────────────────────────────────────────
    (
        Match::Suffix(".windsurfrules"),
        "ai-instructions-file",
        "windsurf-rules",
    ),
    (Match::InDir(".windsurf/"), "agent-settings", "windsurf-dir"),
    // ─── Aider ─────────────────────────────────────────────────────────────
    (
        Match::Suffix(".aider.conf.yml"),
        "ai-instructions-file",
        "aider-config",
    ),
    (
        Match::Suffix(".aiderignore"),
        "agent-settings",
        "aider-ignore",
    ),
    // ─── GitHub Copilot ────────────────────────────────────────────────────
    (
        Match::Suffix(".github/copilot-instructions.md"),
        "ai-instructions-file",
        "copilot-instructions",
    ),
    // ─── Continue.dev ──────────────────────────────────────────────────────
    (
        Match::Suffix(".continuerules"),
        "ai-instructions-file",
        "continue-rules",
    ),
    (
        Match::Suffix(".continue/config.json"),
        "agent-settings",
        "continue-config",
    ),
    (
        Match::Suffix(".continue/config.yaml"),
        "agent-settings",
        "continue-config",
    ),
    (
        Match::Suffix(".continue/config.yml"),
        "agent-settings",
        "continue-config",
    ),
    (Match::InDir(".continue/"), "agent-settings", "continue-dir"),
    // ─── Cline / Roo Code ──────────────────────────────────────────────────
    (
        Match::Suffix(".clinerules"),
        "ai-instructions-file",
        "cline-rules",
    ),
    (
        Match::Suffix(".roomodes"),
        "ai-instructions-file",
        "roo-modes",
    ),
    (Match::InDir(".roo/"), "agent-settings", "roo-dir"),
    // ─── Google: Gemini CLI + Project IDX (Gemini Code Assist) ─────────────
    // Gemini CLI's project-level instructions live in GEMINI.md (the
    // CLAUDE.md equivalent) plus .gemini/settings.json for project settings.
    (
        Match::Suffix("GEMINI.md"),
        "ai-instructions-file",
        "gemini-instructions",
    ),
    (
        Match::Suffix(".gemini/settings.json"),
        "agent-settings",
        "gemini-settings",
    ),
    (Match::InDir(".gemini/"), "agent-settings", "gemini-dir"),
    // Project IDX (Google's cloud IDE, paired with Gemini Code Assist).
    (
        Match::Suffix(".idx/airules.md"),
        "ai-instructions-file",
        "project-idx-rules",
    ),
    (
        Match::Suffix(".idx/dev.nix"),
        "agent-settings",
        "project-idx-dev",
    ),
    (Match::InDir(".idx/"), "agent-settings", "project-idx-dir"),
    // ─── Zed editor (built-in AI assistant) ────────────────────────────────
    (
        Match::Suffix(".zed/settings.json"),
        "agent-settings",
        "zed-settings",
    ),
    (Match::InDir(".zed/"), "agent-settings", "zed-dir"),
    // ─── OpenHands ─────────────────────────────────────────────────────────
    (
        Match::Suffix(".openhands_instructions"),
        "ai-instructions-file",
        "openhands-instructions",
    ),
    (
        Match::Suffix(".openhands/setup.sh"),
        "agent-settings",
        "openhands-setup",
    ),
    (
        Match::InDir(".openhands/"),
        "agent-settings",
        "openhands-dir",
    ),
    // ─── Goose (Block / Agentic AI Foundation) ─────────────────────────────
    (
        Match::Suffix(".goosehints"),
        "ai-instructions-file",
        "goose-hints",
    ),
    (
        Match::Suffix(".goosehints.md"),
        "ai-instructions-file",
        "goose-hints",
    ),
    (Match::InDir(".goose/"), "agent-settings", "goose-dir"),
    // ─── Codeium (classic, pre-Windsurf) ───────────────────────────────────
    (
        Match::Suffix(".codeium/instructions.md"),
        "ai-instructions-file",
        "codeium-instructions",
    ),
    (Match::InDir(".codeium/"), "agent-settings", "codeium-dir"),
    // ─── Amazon Q Developer ────────────────────────────────────────────────
    // Project rules are markdown files under .amazonq/rules/. Every .md
    // there is loaded as project context.
    (Match::InDir(".amazonq/"), "agent-settings", "amazon-q-dir"),
    (
        Match::InDir(".aws/amazonq/"),
        "agent-settings",
        "amazon-q-aws-dir",
    ),
    // ─── JetBrains AI Assistant (IntelliJ family + Fleet) ──────────────────
    // Project rules live under .aiassistant/rules/*.md.
    (
        Match::InDir(".aiassistant/rules/"),
        "ai-instructions-file",
        "jetbrains-ai-rules",
    ),
    (
        Match::InDir(".aiassistant/"),
        "agent-settings",
        "jetbrains-ai-dir",
    ),
    // ─── Plandex ───────────────────────────────────────────────────────────
    (Match::InDir(".plandex/"), "agent-settings", "plandex-dir"),
    // ─── Devin (Cognition) ─────────────────────────────────────────────────
    // Project skills live under .devin/skills/<name>/SKILL.md, plus
    // .devin/wiki.json for DeepWiki documentation.
    (
        Match::Suffix(".devin/wiki.json"),
        "agent-settings",
        "devin-wiki",
    ),
    (
        Match::InDir(".devin/skills/"),
        "ai-instructions-file",
        "devin-skill",
    ),
    (Match::InDir(".devin/"), "agent-settings", "devin-dir"),
    // ─── xAI Grok CLI ──────────────────────────────────────────────────────
    // Grok CLI's primary config is AGENTS.md (already covered above).
    // .grok/ is the project-level scratch dir (generated-media etc.); we
    // still flag it for inventory.
    (Match::InDir(".grok/"), "agent-settings", "grok-dir"),
    // ─── Mentat ────────────────────────────────────────────────────────────
    (
        Match::Suffix(".mentatconfig.json"),
        "agent-settings",
        "mentat-config",
    ),
    // ─── OpenCode (multi-model meta-agent) ─────────────────────────────────
    (
        Match::Suffix(".opencode.json"),
        "agent-settings",
        "opencode-config",
    ),
    // ─── MCP — common configs across hosts ─────────────────────────────────
    (Match::Suffix(".mcp.json"), "mcp-config", "mcp-project"),
    (Match::Suffix("mcp.json"), "mcp-config", "mcp-generic"),
    (Match::InDir(".mcp/"), "mcp-config", "mcp-dir"),
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

/// True iff `rel` is exactly the directory `prefix` (with or without a
/// trailing slash) **or** any path beneath it. Path-component aware:
/// `prefix=".cursor/rules/"` matches `.cursor/rules/foo.mdc` and
/// `nested/.cursor/rules/bar.mdc` but **not** `.cursor/rulesextra/foo`.
fn relpath_under_dir(rel: &str, prefix: &str) -> bool {
    let prefix_no_slash = prefix.trim_end_matches('/');
    if rel == prefix_no_slash || rel == prefix {
        return true;
    }
    // Direct subtree at root.
    let with_slash = format!("{}/", prefix_no_slash);
    if rel.starts_with(&with_slash) {
        return true;
    }
    // Subtree nested under any parent dir (e.g. `subdir/.cursor/rules/foo.mdc`).
    if let Some(idx) = rel.find(&format!("/{}", with_slash)) {
        return idx + 1 < rel.len(); // there is something after the prefix
    }
    false
}

fn match_path(rel: &str) -> Option<(&'static str, &'static str)> {
    for (matcher, rule, kind) in PATH_PATTERNS {
        let hit = match matcher {
            Match::Suffix(s) => relpath_endswith(rel, s),
            Match::InDir(p) => relpath_under_dir(rel, p),
        };
        if hit {
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

    let servers = json_value
        .get("mcpServers")
        .or_else(|| json_value.get("servers"));
    let Some(serde_json::Value::Object(map)) = servers else {
        return findings;
    };

    for (name, cfg) in map {
        let command = cfg.get("command").and_then(|v| v.as_str()).unwrap_or("");
        let args: Vec<String> = cfg
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .map(String::from)
                    .collect()
            })
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
        if matches!(
            basename_lc.as_str(),
            "sh" | "bash" | "zsh" | "ksh" | "dash" | "ash" | "fish"
        ) {
            concerns.push("shell-as-entrypoint");
        }
        if matches!(basename_lc.as_str(), "curl" | "wget") {
            concerns.push("network-fetch-on-launch");
        }
        if args
            .iter()
            .any(|a| a.starts_with("http://") || a.starts_with("https://"))
        {
            concerns.push("network-url-as-arg");
        }
        if args.iter().any(|a| {
            a.contains("--allow-all") || a.contains("--no-sandbox") || a.contains("--insecure")
        }) {
            concerns.push("sandbox-or-tls-disabled");
        }
        if args
            .iter()
            .any(|a| a.contains("| bash") || a.contains("|sh") || a.contains("| sh"))
        {
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
    let rules = content_rules()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
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
        let Some((path_rule, kind)) = match_path(&rel_str) else {
            continue;
        };

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
        assert!(relpath_endswith(
            ".claude/settings.json",
            ".claude/settings.json"
        ));
        assert!(relpath_endswith(
            "nested/.claude/settings.json",
            ".claude/settings.json"
        ));
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

    #[test]
    fn relpath_under_dir_basic() {
        assert!(relpath_under_dir(".cursor/rules", ".cursor/rules/"));
        assert!(relpath_under_dir(".cursor/rules/", ".cursor/rules/"));
        assert!(relpath_under_dir(
            ".cursor/rules/python.mdc",
            ".cursor/rules/"
        ));
        assert!(relpath_under_dir(
            ".cursor/rules/security/auth.mdc",
            ".cursor/rules/"
        ));
        // Component-aware: `.cursor/rulesextra/foo` must NOT match `.cursor/rules/`.
        assert!(!relpath_under_dir(
            ".cursor/rulesextra/foo",
            ".cursor/rules/"
        ));
        // Nested under a parent directory.
        assert!(relpath_under_dir(
            "subproject/.cursor/rules/foo.mdc",
            ".cursor/rules/"
        ));
        // Sibling but unrelated path.
        assert!(!relpath_under_dir("src/main.rs", ".cursor/rules/"));
        // Dir prefix ending without trailing slash also matches.
        assert!(relpath_under_dir(".devin/wiki.json", ".devin/"));
    }

    fn assert_matches(path: &str, expected_kind: &str) {
        match match_path(path) {
            Some((_, kind)) => assert_eq!(
                kind, expected_kind,
                "path {} matched but with kind {}, expected {}",
                path, kind, expected_kind
            ),
            None => panic!(
                "path {} did not match any pattern (expected kind {})",
                path, expected_kind
            ),
        }
    }

    fn assert_no_match(path: &str) {
        if let Some((_, kind)) = match_path(path) {
            panic!("path {} unexpectedly matched (kind = {})", path, kind);
        }
    }

    #[test]
    fn matches_claude_family() {
        assert_matches("CLAUDE.md", "claude-instructions");
        assert_matches("docs/CLAUDE.md", "claude-instructions");
        assert_matches(".claude/settings.json", "claude-settings");
        assert_matches(".claude/settings.local.json", "claude-settings-local");
        assert_matches("claude_desktop_config.json", "claude-desktop");
        assert_matches(".claude/hooks/pre-tool.sh", "claude-dir");
    }

    #[test]
    fn matches_agents_md_family() {
        assert_matches("AGENTS.md", "agent-instructions");
        assert_matches("subdir/AGENTS.md", "agent-instructions");
        assert_matches("AGENTS.override.md", "agent-instructions-override");
    }

    #[test]
    fn matches_cursor_modern_multi_rule_files() {
        // The big miss this session — Cursor's modern format is
        // .cursor/rules/*.mdc, with possibly nested subdirs.
        assert_matches(".cursor/rules/python.mdc", "cursor-rule-file");
        assert_matches(".cursor/rules/security/auth.mdc", "cursor-rule-file");
        assert_matches(".cursorrules", "cursor-rules");
        assert_matches(".cursorignore", "cursor-ignore");
    }

    #[test]
    fn matches_continue() {
        assert_matches(".continuerules", "continue-rules");
        assert_matches(".continue/config.json", "continue-config");
        assert_matches(".continue/config.yaml", "continue-config");
        assert_matches(".continue/config.yml", "continue-config");
        assert_matches(".continue/some-other-file", "continue-dir");
    }

    #[test]
    fn matches_cline_and_roo() {
        assert_matches(".clinerules", "cline-rules");
        assert_matches(".roomodes", "roo-modes");
        assert_matches(".roo/config.json", "roo-dir");
    }

    #[test]
    fn matches_gemini_and_idx() {
        // Gemini CLI: GEMINI.md is the CLAUDE.md equivalent.
        assert_matches("GEMINI.md", "gemini-instructions");
        assert_matches("subproject/GEMINI.md", "gemini-instructions");
        assert_matches(".gemini/settings.json", "gemini-settings");
        assert_matches(".gemini/extensions/foo", "gemini-dir");
        // Project IDX (Google Cloud paired with Gemini Code Assist).
        assert_matches(".idx/airules.md", "project-idx-rules");
        assert_matches(".idx/dev.nix", "project-idx-dev");
    }

    #[test]
    fn matches_jetbrains_ai_assistant() {
        assert_matches(".aiassistant/rules/security.md", "jetbrains-ai-rules");
        assert_matches(".aiassistant/rules/coding-style.md", "jetbrains-ai-rules");
        assert_matches(".aiassistant/some-other-file", "jetbrains-ai-dir");
    }

    #[test]
    fn matches_devin() {
        assert_matches(".devin/skills/lint/SKILL.md", "devin-skill");
        assert_matches(".devin/wiki.json", "devin-wiki");
        assert_matches(".devin/other.json", "devin-dir");
    }

    #[test]
    fn matches_openhands_goose_codeium() {
        assert_matches(".openhands_instructions", "openhands-instructions");
        assert_matches(".openhands/setup.sh", "openhands-setup");
        assert_matches(".openhands/anything-else.txt", "openhands-dir");
        assert_matches(".goosehints", "goose-hints");
        assert_matches(".goosehints.md", "goose-hints");
        assert_matches(".codeium/instructions.md", "codeium-instructions");
    }

    #[test]
    fn matches_amazon_q_zed_plandex() {
        assert_matches(".amazonq/rules/coding-style.md", "amazon-q-dir");
        assert_matches(".aws/amazonq/some-config", "amazon-q-aws-dir");
        assert_matches(".zed/settings.json", "zed-settings");
        assert_matches(".plandex/config.json", "plandex-dir");
    }

    #[test]
    fn matches_grok_opencode() {
        // Grok CLI primarily uses AGENTS.md (already tested); .grok/ is
        // documented as a project-level scratch dir.
        assert_matches(".grok/generated-media/img.png", "grok-dir");
        assert_matches(".opencode.json", "opencode-config");
    }

    #[test]
    fn matches_windsurf_aider() {
        assert_matches(".windsurfrules", "windsurf-rules");
        assert_matches(".windsurf/some-config", "windsurf-dir");
        assert_matches(".aider.conf.yml", "aider-config");
        assert_matches(".aiderignore", "aider-ignore");
    }

    #[test]
    fn matches_mcp_family() {
        assert_matches(".mcp.json", "mcp-project");
        assert_matches("mcp.json", "mcp-generic");
        assert_matches("subproject/.mcp.json", "mcp-project");
        assert_matches(".mcp/servers.json", "mcp-dir");
    }

    #[test]
    fn matches_negatives() {
        // Adjacent paths that should NOT match — guard against false positives.
        assert_no_match("src/main.rs");
        assert_no_match("README.md");
        assert_no_match("Cargo.toml");
        assert_no_match("package.json");
        assert_no_match(".gitignore");
        assert_no_match(".github/workflows/ci.yml"); // not an AI config
                                                     // Lookalikes that must not falsely match prefix-style entries.
        assert_no_match(".cursor-fakerules"); // not .cursor/rules
        assert_no_match(".devinfra/config"); // not .devin/
        assert_no_match("AGENTSx.md"); // not AGENTS.md
        assert_no_match("GEMINIx.md"); // not GEMINI.md
        assert_no_match(".geminix/something"); // not .gemini/
    }
}
