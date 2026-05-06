use console::{style, Term};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    P0,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::P0 => "P0",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    /// Fixed-width 6-char badge text used by the pretty printer so columns line
    /// up regardless of severity.
    fn badge_text(self) -> &'static str {
        match self {
            Severity::P0 => "  P0  ",
            Severity::High => " HIGH ",
            Severity::Medium => " MED  ",
            Severity::Low => " LOW  ",
            Severity::Info => " INFO ",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
}

impl Location {
    pub fn path(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line: None,
            excerpt: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub detector: String,
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub locations: Vec<Location>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub p0: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut s = Self::default();
        for f in findings {
            match f.severity {
                Severity::P0 => s.p0 += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
        }
        s
    }

    pub fn max_severity(&self) -> Option<Severity> {
        if self.p0 > 0 {
            Some(Severity::P0)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else if self.info > 0 {
            Some(Severity::Info)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

/// Rendering options for the terminal-pretty format.
#[derive(Debug, Clone, Copy)]
pub struct PrettyOptions {
    /// Hard wrap width for descriptions. Capped to a sensible range internally.
    pub width: usize,
    /// Whether to emit ANSI escape sequences.
    pub color: bool,
    /// Hide INFO findings (still counted in the summary). Useful for compact mode.
    pub hide_info: bool,
}

impl PrettyOptions {
    /// Inspect the controlling terminal and return reasonable defaults.
    /// Honours `NO_COLOR` and `CLICOLOR_FORCE` via the `console` crate.
    pub fn from_terminal() -> Self {
        let term = Term::stdout();
        let cols = term.size().1 as usize;
        let width = if cols == 0 { 100 } else { cols.clamp(60, 120) };
        Self {
            width,
            color: console::colors_enabled(),
            hide_info: false,
        }
    }
}

impl Default for PrettyOptions {
    fn default() -> Self {
        Self {
            width: 100,
            color: false,
            hide_info: false,
        }
    }
}

impl Report {
    pub fn new(target: Option<String>, mut findings: Vec<Finding>) -> Self {
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.rule.cmp(&b.rule))
                .then_with(|| {
                    a.locations
                        .first()
                        .map(|l| l.path.as_str())
                        .unwrap_or("")
                        .cmp(b.locations.first().map(|l| l.path.as_str()).unwrap_or(""))
                })
        });
        let summary = Summary::from_findings(&findings);
        Self {
            tool: "phantom".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            target,
            summary,
            findings,
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Phantom report\n\n");
        if let Some(t) = &self.target {
            out.push_str(&format!("**Target:** `{}`\n\n", t));
        }
        out.push_str(&format!(
            "**Findings:** P0={} HIGH={} MEDIUM={} LOW={} INFO={}\n\n",
            self.summary.p0,
            self.summary.high,
            self.summary.medium,
            self.summary.low,
            self.summary.info
        ));

        if self.findings.is_empty() {
            out.push_str("_No findings._\n");
            return out;
        }

        for f in &self.findings {
            out.push_str(&format!("## [{}] {}\n", f.severity, f.title));
            out.push_str(&format!("`{}` / `{}`\n\n", f.detector, f.rule));
            out.push_str(&f.description);
            out.push_str("\n\n");
            if !f.locations.is_empty() {
                out.push_str("**Locations:**\n");
                for loc in &f.locations {
                    match (loc.line, &loc.excerpt) {
                        (Some(line), Some(ex)) => {
                            out.push_str(&format!("- `{}:{}` — `{}`\n", loc.path, line, ex));
                        }
                        (Some(line), None) => {
                            out.push_str(&format!("- `{}:{}`\n", loc.path, line));
                        }
                        (None, Some(ex)) => {
                            out.push_str(&format!("- `{}` — `{}`\n", loc.path, ex));
                        }
                        (None, None) => {
                            out.push_str(&format!("- `{}`\n", loc.path));
                        }
                    }
                }
                out.push('\n');
            }
        }

        out
    }

    /// Render the report as SARIF 2.1.0 (Static Analysis Results Interchange
    /// Format). The output is consumable by GitHub Code Scanning, GitLab SAST
    /// reports, and most other SAST aggregators.
    ///
    /// The mapping is:
    /// - Phantom rule id → SARIF `reportingDescriptor` keyed by
    ///   `<detector>/<rule>` (deduplicated across the report).
    /// - Phantom severity → SARIF `level` (`P0`/`HIGH` → `error`,
    ///   `MEDIUM` → `warning`, `LOW`/`INFO` → `note`). The original phantom
    ///   severity label is preserved verbatim under
    ///   `result.properties["phantom-severity"]`.
    /// - Phantom location → SARIF `physicalLocation` (path, line, snippet).
    ///   Findings without a physical location surface as result-only entries.
    pub fn to_sarif(&self) -> serde_json::Value {
        use serde_json::{json, Map, Value};
        use std::collections::BTreeMap;

        // Deduplicate rules by `<detector>/<rule>`, preserving first-seen order.
        let mut rule_index: BTreeMap<String, usize> = BTreeMap::new();
        let mut rules: Vec<Value> = Vec::new();

        for f in &self.findings {
            let id = format!("{}/{}", f.detector, f.rule);
            if rule_index.contains_key(&id) {
                continue;
            }
            rule_index.insert(id.clone(), rules.len());
            rules.push(json!({
                "id": id,
                "name": f.rule,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(f.severity),
                },
                "helpUri": "https://github.com/r3dlight/phantom",
                "properties": {
                    "phantom-detector": f.detector,
                    "phantom-severity": f.severity.label(),
                    "tags": ["security", "supply-chain", &f.detector],
                }
            }));
        }

        let mut results: Vec<Value> = Vec::with_capacity(self.findings.len());
        for f in &self.findings {
            let id = format!("{}/{}", f.detector, f.rule);
            let idx = rule_index.get(&id).copied().unwrap_or(0);

            let mut locations_json: Vec<Value> = Vec::new();
            for loc in &f.locations {
                let mut region = Map::new();
                if let Some(line) = loc.line {
                    region.insert("startLine".into(), json!(line));
                }
                if let Some(ex) = &loc.excerpt {
                    region.insert("snippet".into(), json!({ "text": ex }));
                }
                let mut physical = Map::new();
                physical.insert(
                    "artifactLocation".into(),
                    json!({ "uri": loc.path, "uriBaseId": "%SRCROOT%" }),
                );
                if !region.is_empty() {
                    physical.insert("region".into(), Value::Object(region));
                }
                locations_json.push(json!({ "physicalLocation": Value::Object(physical) }));
            }

            // SARIF result.message is the user-facing one-liner; the longer
            // description goes on the rule + here as a property for clients
            // that surface it.
            let mut result = json!({
                "ruleId": id,
                "ruleIndex": idx,
                "level": severity_to_sarif_level(f.severity),
                "message": { "text": f.title },
                "properties": {
                    "phantom-severity": f.severity.label(),
                    "phantom-detector": f.detector,
                    "phantom-description": f.description,
                }
            });
            if !locations_json.is_empty() {
                result["locations"] = Value::Array(locations_json);
            }
            results.push(result);
        }

        let mut run = json!({
            "tool": {
                "driver": {
                    "name": "phantom",
                    "version": self.version,
                    "semanticVersion": self.version,
                    "informationUri": "https://github.com/r3dlight/phantom",
                    "rules": rules,
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
            "originalUriBaseIds": {
                "%SRCROOT%": { "uri": "file:///" }
            }
        });
        if let Some(t) = &self.target {
            run["properties"] = json!({ "phantom-target": t });
        }

        json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [run],
        })
    }

    pub fn to_pretty(&self, opts: &PrettyOptions) -> String {
        let mut out = String::new();
        let width = opts.width.clamp(60, 200);

        // ─── header ────────────────────────────────────────────────────────
        let name = format!("phantom v{}", self.version);
        let name_styled = style_str(&name, opts.color, Sty::Bold);
        let target_str = self.target.as_deref().unwrap_or("");
        if target_str.is_empty() {
            out.push_str(&format!("  {}\n", name_styled));
        } else {
            out.push_str(&format!(
                "  {}  {}  {}\n",
                name_styled,
                style_str("·", opts.color, Sty::Dim),
                target_str
            ));
        }
        out.push_str(&format!(
            "  {}\n",
            style_str(&"─".repeat(width.saturating_sub(2)), opts.color, Sty::Dim)
        ));

        // ─── summary ────────────────────────────────────────────────────────
        let s = &self.summary;
        let counts = [
            (s.p0, Severity::P0),
            (s.high, Severity::High),
            (s.medium, Severity::Medium),
            (s.low, Severity::Low),
            (s.info, Severity::Info),
        ];
        let total: usize = counts.iter().map(|(n, _)| *n).sum();
        if total == 0 {
            out.push_str(&format!(
                "  {}  {}\n",
                style_str("  OK  ", opts.color, Sty::OnGreen),
                style_str("no findings", opts.color, Sty::Bold)
            ));
        } else {
            let mut parts = vec![];
            for (n, sev) in counts {
                if n == 0 {
                    continue;
                }
                let badge = severity_badge(sev, opts.color);
                parts.push(format!("{} {}", badge, n));
            }
            out.push_str(&format!("  {}\n", parts.join("   ")));
        }
        out.push_str(&format!(
            "  {}\n",
            style_str(&"─".repeat(width.saturating_sub(2)), opts.color, Sty::Dim)
        ));
        out.push('\n');

        // ─── findings ───────────────────────────────────────────────────────
        let visible: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| !(opts.hide_info && f.severity == Severity::Info))
            .collect();

        if visible.is_empty() {
            return out;
        }

        for (i, f) in visible.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            render_finding(&mut out, f, width, opts.color);
        }

        out
    }
}

fn severity_to_sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::P0 | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

// ─── pretty helpers ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Sty {
    Bold,
    Dim,
    Cyan,
    Yellow,
    OnRed,
    OnGreen,
    OnYellow,
}

fn style_str(s: &str, color: bool, sty: Sty) -> String {
    if !color {
        return s.to_string();
    }
    match sty {
        Sty::Bold => style(s).bold().to_string(),
        Sty::Dim => style(s).dim().to_string(),
        Sty::Cyan => style(s).cyan().to_string(),
        Sty::Yellow => style(s).yellow().to_string(),
        Sty::OnRed => style(s).white().on_red().bold().to_string(),
        Sty::OnGreen => style(s).black().on_green().bold().to_string(),
        Sty::OnYellow => style(s).black().on_yellow().bold().to_string(),
    }
}

fn severity_badge(sev: Severity, color: bool) -> String {
    let text = sev.badge_text();
    if !color {
        return format!("[{}]", text);
    }
    match sev {
        Severity::P0 => style_str(text, color, Sty::OnRed),
        Severity::High => style_str(text, color, Sty::OnYellow),
        Severity::Medium => style_str(text, color, Sty::Yellow),
        Severity::Low => style_str(text, color, Sty::Cyan),
        Severity::Info => style_str(text, color, Sty::Dim),
    }
}

fn render_finding(out: &mut String, f: &Finding, width: usize, color: bool) {
    let badge = severity_badge(f.severity, color);
    let title = style_str(&f.title, color, Sty::Bold);
    out.push_str(&format!("  {}  {}\n", badge, title));

    let qualifier = format!("{} · {}", f.detector, f.rule);
    out.push_str(&format!(
        "          {}\n",
        style_str(&qualifier, color, Sty::Dim)
    ));

    // Description, hard-wrapped to terminal width.
    let desc_width = width.saturating_sub(10);
    for line in wrap_words(&f.description, desc_width).lines() {
        out.push_str(&format!("          {}\n", line));
    }

    for loc in &f.locations {
        let location = match loc.line {
            Some(l) => format!("{}:{}", loc.path, l),
            None => loc.path.clone(),
        };
        out.push_str(&format!(
            "          {} {}\n",
            style_str("↳", color, Sty::Cyan),
            style_str(&location, color, Sty::Cyan)
        ));
        if let Some(ex) = &loc.excerpt {
            // Visible-character truncation that doesn't blow up on multi-byte chars.
            let max = desc_width.saturating_sub(2);
            let truncated: String = ex.chars().take(max).collect();
            let render_excerpt: String = truncated
                .chars()
                .map(|c| if c.is_control() && c != '\t' { '·' } else { c })
                .collect();
            out.push_str(&format!(
                "            {}\n",
                style_str(&render_excerpt, color, Sty::Dim)
            ));
        }
    }
}

/// Greedy word-wrap. Counts characters (not display width — close enough for
/// typical reports without pulling in `unicode-width`).
fn wrap_words(s: &str, width: usize) -> String {
    if width == 0 {
        return s.to_string();
    }
    let mut out = String::new();
    let mut line_len = 0;
    for word in s.split_whitespace() {
        let word_len = word.chars().count();
        if line_len > 0 && line_len + 1 + word_len > width {
            out.push('\n');
            line_len = 0;
        } else if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += word_len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity, rule: &str, desc: &str) -> Finding {
        Finding {
            detector: "test".into(),
            rule: rule.into(),
            severity: sev,
            title: format!("{}: example", rule),
            description: desc.into(),
            locations: vec![Location {
                path: "src/lib.rs".into(),
                line: Some(42),
                excerpt: Some("the offending line".into()),
            }],
            evidence: serde_json::Value::Null,
        }
    }

    #[test]
    fn pretty_no_color_is_ansi_free() {
        let report = Report::new(
            Some("./.".into()),
            vec![finding(Severity::High, "h-rule", "A wrapped description.")],
        );
        let opts = PrettyOptions {
            width: 80,
            color: false,
            hide_info: false,
        };
        let out = report.to_pretty(&opts);
        assert!(!out.contains('\u{1b}'), "no ANSI escapes when color=false");
        assert!(out.contains("h-rule"));
        assert!(out.contains("src/lib.rs:42"));
    }

    #[test]
    fn pretty_clean_report_says_no_findings() {
        let report = Report::new(Some("/r".into()), vec![]);
        let out = report.to_pretty(&PrettyOptions {
            width: 80,
            color: false,
            hide_info: false,
        });
        assert!(out.contains("no findings"));
    }

    #[test]
    fn wrap_words_basic() {
        assert_eq!(wrap_words("one two three four", 8), "one two\nthree\nfour");
    }

    fn sample_finding(sev: Severity, detector: &str, rule: &str, line: Option<u32>) -> Finding {
        Finding {
            detector: detector.into(),
            rule: rule.into(),
            severity: sev,
            title: format!("{}: example", rule),
            description: "Description text.".into(),
            locations: vec![Location {
                path: "src/x.rs".into(),
                line,
                excerpt: line.map(|_| "line content".into()),
            }],
            evidence: serde_json::Value::Null,
        }
    }

    #[test]
    fn sarif_envelope() {
        let r = Report::new(Some(".".into()), vec![]);
        let s = r.to_sarif();
        assert_eq!(s["version"], "2.1.0");
        assert!(s["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0"));
        let driver = &s["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "phantom");
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn sarif_severity_levels() {
        let r = Report::new(
            None,
            vec![
                sample_finding(Severity::P0, "d", "p0", Some(1)),
                sample_finding(Severity::High, "d", "h", Some(2)),
                sample_finding(Severity::Medium, "d", "m", Some(3)),
                sample_finding(Severity::Low, "d", "l", Some(4)),
                sample_finding(Severity::Info, "d", "i", Some(5)),
            ],
        );
        let s = r.to_sarif();
        let levels: Vec<&str> = s["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        // Findings are sorted by descending severity in `Report::new`.
        assert_eq!(levels, vec!["error", "error", "warning", "note", "note"]);
    }

    #[test]
    fn sarif_dedupes_rules_across_findings() {
        let r = Report::new(
            None,
            vec![
                sample_finding(Severity::High, "aiconfig", "rule-x", Some(1)),
                sample_finding(Severity::High, "aiconfig", "rule-x", Some(2)),
                sample_finding(Severity::High, "aiconfig", "rule-y", Some(3)),
                sample_finding(Severity::High, "tarball", "rule-x", Some(4)),
            ],
        );
        let s = r.to_sarif();
        let rules = s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        // Three unique (detector, rule) pairs: aiconfig/rule-x, aiconfig/rule-y, tarball/rule-x.
        assert_eq!(rules.len(), 3);
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"aiconfig/rule-x"));
        assert!(ids.contains(&"aiconfig/rule-y"));
        assert!(ids.contains(&"tarball/rule-x"));
    }

    #[test]
    fn sarif_location_carries_line_and_snippet() {
        let r = Report::new(
            None,
            vec![sample_finding(Severity::High, "d", "r", Some(42))],
        );
        let s = r.to_sarif();
        let result = &s["runs"][0]["results"][0];
        let phys = &result["locations"][0]["physicalLocation"];
        assert_eq!(phys["artifactLocation"]["uri"], "src/x.rs");
        assert_eq!(phys["artifactLocation"]["uriBaseId"], "%SRCROOT%");
        assert_eq!(phys["region"]["startLine"], 42);
        assert_eq!(phys["region"]["snippet"]["text"], "line content");
    }

    #[test]
    fn sarif_finding_without_location_omits_locations_field() {
        let mut f = sample_finding(Severity::Info, "d", "no-loc", None);
        f.locations = vec![];
        let r = Report::new(None, vec![f]);
        let s = r.to_sarif();
        let result = &s["runs"][0]["results"][0];
        assert!(
            result.get("locations").is_none(),
            "no locations array when empty"
        );
        // SARIF still requires ruleId/level/message to be present.
        assert_eq!(result["ruleId"], "d/no-loc");
        assert_eq!(result["level"], "note");
    }
}
