//! Repository history snapshot + behavioural signals.
//!
//! Shells out to `git log` to enumerate every non-merge commit reachable from
//! all refs, persists them to a SQLite database, and computes per-contributor
//! aggregates. v0.x exposes one behavioural signal — **build-system
//! attraction**: the fraction of a contributor's commits that touch
//! `configure.ac`, `*.m4`, `*.am`, `build.rs`, `CMakeLists.txt`, `Makefile`, or
//! a GitHub Actions workflow. The XZ Utils attacker (JiaT75) had a
//! disproportionate share of commits in `m4/` and the build glue. Calibration
//! per project (planned) will refine the threshold.
//!
//! In the AI-assisted era this remains useful: an agent does not gravitate to
//! build-system files on its own, so the signal is largely AI-immune.

use anyhow::{anyhow, bail, Context, Result};
use phantom_core::{Finding, Location, Severity};
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const DETECTOR: &str = "snapshot";

const RECORD_SEP: &str = ">>>SHA<<<";

/// Floor applied to MAD when computing z-scores so that a tightly-clustered
/// distribution does not turn small absolute deviations into spurious huge
/// outliers. Expressed in raw build-attraction units (0.02 = 2 percentage
/// points).
const MAD_FLOOR: f64 = 0.02;

/// Below this MAD value the distribution is considered degenerate (essentially
/// every eligible contributor has the same build-attraction), and relative
/// scoring is skipped in favour of the absolute fallback.
const MIN_MAD_FOR_RELATIVE: f64 = 1e-9;

/// Minimum eligible-contributor count under which Auto mode falls back to
/// absolute scoring. Below 3 there is not enough sample to estimate a useful
/// median + MAD.
const MIN_ELIGIBLE_FOR_RELATIVE: usize = 3;

#[derive(Debug, Clone)]
pub struct CommitRecord {
    pub sha: String,
    pub author_name: String,
    pub author_email: String,
    pub committer_email: String,
    pub iso_time: String,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContributorStats {
    pub author_email: String,
    pub author_name: String,
    pub n_commits: u64,
    pub n_build_commits: u64,
    /// Commits where every touched file is a build-system file. A high ratio of
    /// build-only commits to build-touching commits is structurally different
    /// from a maintainer who fixes build issues alongside code changes.
    pub n_build_only_commits: u64,
    pub build_attraction: f64,
    /// `n_build_only_commits / n_build_commits`, or 0.0 when `n_build_commits == 0`.
    pub build_only_ratio: f64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotReport {
    pub repo: String,
    pub db_path: String,
    pub total_commits: u64,
    pub total_contributors: usize,
    pub contributors: Vec<ContributorStats>,
}

/// Strategy used to convert per-contributor build-attraction into severity.
///
/// * `Auto` (default) prefers the relative regime: a contributor is judged
///   against the rest of *this* repository's distribution. It silently falls
///   back to the absolute regime when the distribution is too small or too
///   uniform to compute a meaningful median + MAD.
/// * `Relative` forces the relative regime (still falls back when MAD is zero,
///   to avoid dividing by zero).
/// * `Absolute` reproduces the v0.1 behaviour: contributors are flagged purely
///   on the `medium_attraction_pct` / `high_attraction_pct` thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScoringMode {
    #[default]
    Auto,
    Relative,
    Absolute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Regime {
    Relative,
    Absolute,
}

impl Regime {
    fn as_str(self) -> &'static str {
        match self {
            Regime::Relative => "relative",
            Regime::Absolute => "absolute",
        }
    }
}

pub struct Options {
    /// Where to write the SQLite database. Defaults to `<repo>/.phantom/snapshot.db`.
    pub db_path: Option<PathBuf>,
    /// Minimum number of commits before a contributor's build-attraction is
    /// reported as a finding (suppresses noise from drive-by contributors).
    pub min_commits_for_finding: u64,
    /// Build-attraction thresholds for finding severities (used in Absolute
    /// mode and as fallback when relative scoring is unavailable).
    pub medium_attraction_pct: f64,
    pub high_attraction_pct: f64,
    /// Shape filter: minimum `build_only_ratio` for a contributor to surface as
    /// a finding. A maintainer who routinely mixes code with build-system
    /// changes will sit below this threshold; a contributor whose
    /// build-touching commits are predominantly build-only sits above it. The
    /// default (0.6) was chosen to suppress legitimate build-system maintainers
    /// while preserving the JiaT75-style profile.
    pub min_build_only_ratio: f64,

    /// Scoring strategy. See [`ScoringMode`].
    pub mode: ScoringMode,
    /// In the relative regime, the absolute build-attraction below which a
    /// contributor is never flagged regardless of z-score. Avoids surfacing
    /// "outliers" in repos where everyone has near-zero build-attraction.
    pub relative_attraction_floor: f64,
    /// In the relative regime, z-score above which a contributor is flagged
    /// Medium (1 MAD-unit = MAD, floored at `MAD_FLOOR` to avoid explosions on
    /// near-uniform distributions).
    pub medium_z: f64,
    /// In the relative regime, z-score above which a contributor is flagged High.
    pub high_z: f64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            db_path: None,
            min_commits_for_finding: 10,
            medium_attraction_pct: 0.25,
            high_attraction_pct: 0.50,
            min_build_only_ratio: 0.6,
            mode: ScoringMode::Auto,
            relative_attraction_floor: 0.15,
            medium_z: 3.0,
            high_z: 5.0,
        }
    }
}

/// Ingest the repo's history into SQLite and return a summary report.
pub fn snapshot(repo: &Path, opts: Options) -> Result<SnapshotReport> {
    if !repo.join(".git").exists() && !repo.join("HEAD").exists() {
        bail!("`{}` does not look like a git repository", repo.display());
    }

    let db_path = opts
        .db_path
        .clone()
        .unwrap_or_else(|| repo.join(".phantom").join("snapshot.db"));
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    if db_path.exists() {
        std::fs::remove_file(&db_path).context("removing previous snapshot db")?;
    }

    let conn = Connection::open(&db_path)
        .with_context(|| format!("opening sqlite at {}", db_path.display()))?;
    init_schema(&conn)?;

    let commits = run_git_log(repo)?;

    let tx = conn.unchecked_transaction()?;
    {
        let mut insert_commit = tx.prepare(
            "INSERT INTO commits(sha, author_name, author_email, committer_email, iso_time, n_files, n_build_files)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )?;
        let mut insert_file =
            tx.prepare("INSERT INTO commit_files(sha, path, is_build) VALUES (?, ?, ?)")?;
        for c in &commits {
            let n_files = c.files.len() as i64;
            let n_build = c.files.iter().filter(|p| is_build_system_path(p)).count() as i64;
            insert_commit.execute(params![
                c.sha,
                c.author_name,
                c.author_email,
                c.committer_email,
                c.iso_time,
                n_files,
                n_build,
            ])?;
            for p in &c.files {
                insert_file.execute(params![c.sha, p, is_build_system_path(p) as i64])?;
            }
        }
    }
    tx.commit()?;

    let contributors = aggregate_contributors(&conn)?;
    Ok(SnapshotReport {
        repo: repo.display().to_string(),
        db_path: db_path.display().to_string(),
        total_commits: commits.len() as u64,
        total_contributors: contributors.len(),
        contributors,
    })
}

/// Convert a snapshot report into Phantom findings using the supplied
/// threshold options.
pub fn findings_from_report(report: &SnapshotReport, opts: &Options) -> Vec<Finding> {
    let eligible: Vec<&ContributorStats> = report
        .contributors
        .iter()
        .filter(|c| c.n_commits >= opts.min_commits_for_finding)
        .collect();

    let (median_attr, mad_attr) = compute_distribution(&eligible);
    let regime = pick_regime(opts.mode, eligible.len(), mad_attr);

    let mut out = vec![summary_finding(
        report,
        opts,
        regime,
        eligible.len(),
        median_attr,
        mad_attr,
    )];

    for c in &eligible {
        // Shape filter applies in both regimes: a contributor whose
        // build-touching commits are mostly *mixed* with code is structurally
        // indistinguishable from a routine build maintainer. Suppress them to
        // cut the dominant noise class. The JiaT75 profile has a much higher
        // build-only ratio.
        if c.n_build_commits > 0 && c.build_only_ratio < opts.min_build_only_ratio {
            continue;
        }
        let classification = match regime {
            Regime::Relative => classify_relative(c.build_attraction, median_attr, mad_attr, opts),
            Regime::Absolute => classify_absolute(c.build_attraction, opts),
        };
        let Some(severity) = classification else {
            continue;
        };
        out.push(make_attraction_finding(
            report,
            c,
            severity,
            regime,
            median_attr,
            mad_attr,
            opts,
        ));
    }

    out
}

fn summary_finding(
    report: &SnapshotReport,
    opts: &Options,
    regime: Regime,
    eligible_count: usize,
    median_attr: f64,
    mad_attr: f64,
) -> Finding {
    let regime_blurb = match regime {
        Regime::Relative => format!(
            "Regime: relative — eligible-distribution median {:.1}%, MAD {:.1}%. \
             Contributors flagged at z >= {:.1} (Medium) or z >= {:.1} (High), \
             with absolute attraction floor of {:.0}%.",
            median_attr * 100.0,
            mad_attr * 100.0,
            opts.medium_z,
            opts.high_z,
            opts.relative_attraction_floor * 100.0,
        ),
        Regime::Absolute => format!(
            "Regime: absolute — Medium >= {:.0}%, High >= {:.0}% build-attraction. \
             Relative scoring requires >= {} eligible contributors with non-uniform \
             attraction; this run did not qualify (or was forced absolute).",
            opts.medium_attraction_pct * 100.0,
            opts.high_attraction_pct * 100.0,
            MIN_ELIGIBLE_FOR_RELATIVE,
        ),
    };

    let mut evidence = json!({
        "total_commits": report.total_commits,
        "total_contributors": report.total_contributors,
        "eligible_contributors": eligible_count,
        "min_commits_for_finding": opts.min_commits_for_finding,
        "min_build_only_ratio": opts.min_build_only_ratio,
        "regime": regime.as_str(),
        "db_path": report.db_path,
    });
    let evidence_obj = evidence
        .as_object_mut()
        .expect("json! always returns object");
    match regime {
        Regime::Relative => {
            evidence_obj.insert("median_attraction".into(), json!(median_attr));
            evidence_obj.insert("mad_attraction".into(), json!(mad_attr));
            evidence_obj.insert("medium_z".into(), json!(opts.medium_z));
            evidence_obj.insert("high_z".into(), json!(opts.high_z));
            evidence_obj.insert(
                "relative_attraction_floor".into(),
                json!(opts.relative_attraction_floor),
            );
        }
        Regime::Absolute => {
            evidence_obj.insert(
                "medium_attraction_pct".into(),
                json!(opts.medium_attraction_pct),
            );
            evidence_obj.insert(
                "high_attraction_pct".into(),
                json!(opts.high_attraction_pct),
            );
        }
    }

    Finding {
        detector: DETECTOR.into(),
        rule: "snapshot-summary".into(),
        severity: Severity::Info,
        title: format!("Repository snapshot of `{}`", report.repo),
        description: format!(
            "{} commits across {} contributors ({} eligible at >= {} commits each). \
             SQLite database stored at `{}`. {}",
            report.total_commits,
            report.total_contributors,
            eligible_count,
            opts.min_commits_for_finding,
            report.db_path,
            regime_blurb,
        ),
        locations: vec![Location::path(report.repo.clone())],
        evidence,
    }
}

fn make_attraction_finding(
    report: &SnapshotReport,
    c: &ContributorStats,
    severity: Severity,
    regime: Regime,
    median_attr: f64,
    mad_attr: f64,
    opts: &Options,
) -> Finding {
    let regime_blurb = match regime {
        Regime::Relative => {
            let z = z_score(c.build_attraction, median_attr, mad_attr);
            format!(
                "Within this repo's eligible distribution (median {:.1}%, MAD {:.1}%) \
                 this contributor sits {:.1} MAD-units above the median.",
                median_attr * 100.0,
                mad_attr * 100.0,
                z,
            )
        }
        Regime::Absolute => format!(
            "Build-attraction {:.1}% crosses the absolute threshold (Medium {:.0}%, High {:.0}%).",
            c.build_attraction * 100.0,
            opts.medium_attraction_pct * 100.0,
            opts.high_attraction_pct * 100.0,
        ),
    };

    let mut evidence = json!({
        "author_email": c.author_email,
        "author_name": c.author_name,
        "n_commits": c.n_commits,
        "n_build_commits": c.n_build_commits,
        "n_build_only_commits": c.n_build_only_commits,
        "build_attraction": c.build_attraction,
        "build_only_ratio": c.build_only_ratio,
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "regime": regime.as_str(),
    });
    if regime == Regime::Relative {
        let evidence_obj = evidence
            .as_object_mut()
            .expect("json! always returns object");
        evidence_obj.insert("median_attraction".into(), json!(median_attr));
        evidence_obj.insert("mad_attraction".into(), json!(mad_attr));
        evidence_obj.insert(
            "z_score".into(),
            json!(z_score(c.build_attraction, median_attr, mad_attr)),
        );
    }

    Finding {
        detector: DETECTOR.into(),
        rule: "build-system-attraction".into(),
        severity,
        title: format!(
            "{} ({}) — build-attraction {:.0}% over {} commits ({} build-only)",
            c.author_email,
            c.author_name,
            c.build_attraction * 100.0,
            c.n_commits,
            c.n_build_only_commits,
        ),
        description: format!(
            "Of {} commits authored by `{}`, {} touched build-system files \
             (configure.ac, *.m4, build.rs, CMakeLists.txt, GitHub Actions, ...) \
             and {} of those were *build-only* (touched no other files). \
             {} \
             The XZ Utils attacker (JiaT75) had a disproportionate share of build-system commits \
             prior to introducing the backdoor. \
             This is one signal, not a verdict — manual review required.",
            c.n_commits, c.author_email, c.n_build_commits, c.n_build_only_commits, regime_blurb,
        ),
        locations: vec![Location::path(report.repo.clone())],
        evidence,
    }
}

/// Median of a slice of finite f64 values. Returns 0.0 for an empty input.
/// NaN / infinite inputs are filtered before sorting.
fn median(xs: &[f64]) -> f64 {
    let mut sorted: Vec<f64> = xs.iter().copied().filter(|x| x.is_finite()).collect();
    if sorted.is_empty() {
        return 0.0;
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    // Note on lint: `n % 2 == 1` (odd-arm) is used rather than `n % 2 == 0`
    // (even-arm) so that clippy's `manual_is_multiple_of` does not trigger.
    // `usize::is_multiple_of` is only stable from Rust 1.87, while the
    // workspace MSRV is 1.75.
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        0.5 * (sorted[n / 2 - 1] + sorted[n / 2])
    }
}

/// Median + MAD of `build_attraction` over the supplied eligible contributors.
fn compute_distribution(eligible: &[&ContributorStats]) -> (f64, f64) {
    let xs: Vec<f64> = eligible.iter().map(|c| c.build_attraction).collect();
    let med = median(&xs);
    let dev: Vec<f64> = xs.iter().map(|x| (x - med).abs()).collect();
    let mad = median(&dev);
    (med, mad)
}

fn pick_regime(mode: ScoringMode, eligible_count: usize, mad: f64) -> Regime {
    match mode {
        ScoringMode::Absolute => Regime::Absolute,
        ScoringMode::Relative => {
            if mad > MIN_MAD_FOR_RELATIVE {
                Regime::Relative
            } else {
                Regime::Absolute
            }
        }
        ScoringMode::Auto => {
            if eligible_count >= MIN_ELIGIBLE_FOR_RELATIVE && mad > MIN_MAD_FOR_RELATIVE {
                Regime::Relative
            } else {
                Regime::Absolute
            }
        }
    }
}

fn z_score(attraction: f64, median_attr: f64, mad: f64) -> f64 {
    (attraction - median_attr) / mad.max(MAD_FLOOR)
}

fn classify_relative(
    attraction: f64,
    median_attr: f64,
    mad: f64,
    opts: &Options,
) -> Option<Severity> {
    if attraction < opts.relative_attraction_floor {
        return None;
    }
    let z = z_score(attraction, median_attr, mad);
    if z >= opts.high_z {
        Some(Severity::High)
    } else if z >= opts.medium_z {
        Some(Severity::Medium)
    } else {
        None
    }
}

fn classify_absolute(attraction: f64, opts: &Options) -> Option<Severity> {
    if attraction >= opts.high_attraction_pct {
        Some(Severity::High)
    } else if attraction >= opts.medium_attraction_pct {
        Some(Severity::Medium)
    } else {
        None
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE commits (
            sha TEXT PRIMARY KEY,
            author_name TEXT NOT NULL,
            author_email TEXT NOT NULL,
            committer_email TEXT NOT NULL,
            iso_time TEXT NOT NULL,
            n_files INTEGER NOT NULL,
            n_build_files INTEGER NOT NULL
        );
        CREATE TABLE commit_files (
            sha TEXT NOT NULL REFERENCES commits(sha),
            path TEXT NOT NULL,
            is_build INTEGER NOT NULL
        );
        CREATE INDEX idx_commit_files_sha ON commit_files(sha);
        CREATE INDEX idx_commits_email ON commits(author_email);
        "#,
    )?;
    Ok(())
}

fn run_git_log(repo: &Path) -> Result<Vec<CommitRecord>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "log",
            "--all",
            "--no-merges",
            "--pretty=format:>>>SHA<<<%H|%an|%ae|%cE|%aI",
            "--name-only",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("invoking git log")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("git log failed: {}", stderr.trim());
    }
    let stdout = String::from_utf8(out.stdout).context("git log produced non-UTF8")?;
    parse_git_log(&stdout)
}

fn parse_git_log(s: &str) -> Result<Vec<CommitRecord>> {
    let mut commits: Vec<CommitRecord> = Vec::new();
    let mut current: Option<CommitRecord> = None;

    for raw_line in s.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix(RECORD_SEP) {
            if let Some(c) = current.take() {
                commits.push(c);
            }
            let mut parts = rest.splitn(5, '|');
            let sha = parts
                .next()
                .ok_or_else(|| anyhow!("missing sha in {}", line))?
                .to_string();
            let author_name = parts.next().unwrap_or("").to_string();
            let author_email = parts.next().unwrap_or("").to_string();
            let committer_email = parts.next().unwrap_or("").to_string();
            let iso_time = parts.next().unwrap_or("").to_string();
            current = Some(CommitRecord {
                sha,
                author_name,
                author_email,
                committer_email,
                iso_time,
                files: vec![],
            });
        } else if line.is_empty() {
            // file-list separator inside a commit; ignore
        } else if let Some(c) = current.as_mut() {
            c.files.push(line.to_string());
        }
        // lines before the first record header are dropped
    }
    if let Some(c) = current.take() {
        commits.push(c);
    }
    Ok(commits)
}

fn aggregate_contributors(conn: &Connection) -> Result<Vec<ContributorStats>> {
    // Sort order rationale: a drive-by contributor with `1/1 = 100 %` build-attraction
    // used to top the list, drowning the actually-suspicious cases. Order by absolute
    // build-commit volume first ("how much of the build did this person actually
    // touch?"), then break ties by attraction ratio.
    //
    // `n_build_only_commits` counts commits where every touched file is a build
    // file (`n_build_files = n_files`, with `n_build_files > 0` to exclude empty
    // commits). It is derived from existing columns; no schema migration needed.
    let mut stmt = conn.prepare(
        r#"
        SELECT
            author_email,
            MAX(author_name) AS author_name,
            COUNT(*) AS n_commits,
            SUM(CASE WHEN n_build_files > 0 THEN 1 ELSE 0 END) AS n_build_commits,
            SUM(CASE WHEN n_build_files > 0 AND n_build_files = n_files THEN 1 ELSE 0 END)
                AS n_build_only_commits,
            MIN(iso_time) AS first_seen,
            MAX(iso_time) AS last_seen
        FROM commits
        GROUP BY author_email
        ORDER BY SUM(CASE WHEN n_build_files > 0 THEN 1 ELSE 0 END) DESC,
                 1.0 * SUM(CASE WHEN n_build_files > 0 THEN 1 ELSE 0 END) / COUNT(*) DESC,
                 author_email ASC
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        let n_commits: i64 = row.get(2)?;
        let n_build: i64 = row.get(3)?;
        let n_build_only: i64 = row.get(4)?;
        let attraction = if n_commits <= 0 {
            0.0
        } else {
            n_build as f64 / n_commits as f64
        };
        let build_only_ratio = if n_build <= 0 {
            0.0
        } else {
            n_build_only as f64 / n_build as f64
        };
        Ok(ContributorStats {
            author_email: row.get(0)?,
            author_name: row.get(1)?,
            n_commits: n_commits.max(0) as u64,
            n_build_commits: n_build.max(0) as u64,
            n_build_only_commits: n_build_only.max(0) as u64,
            build_attraction: attraction,
            build_only_ratio,
            first_seen: row.get(5)?,
            last_seen: row.get(6)?,
        })
    })?;
    let mut out = vec![];
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Mirror of `phantom_tarball::is_build_system_path`. Duplicated in v0.x to
/// keep the dependency graph shallow; will be lifted to a shared util once a
/// third detector needs it.
pub fn is_build_system_path(path: &str) -> bool {
    let bn = path.rsplit('/').next().unwrap_or(path);
    if bn == "configure.ac" || bn == "configure.in" {
        return true;
    }
    if bn.ends_with(".m4") || bn.ends_with(".am") {
        return true;
    }
    if path.starts_with("m4/") || path.contains("/m4/") {
        return true;
    }
    if bn == "build.rs" {
        return true;
    }
    if bn == "CMakeLists.txt" || bn.ends_with(".cmake") {
        return true;
    }
    if bn == "Makefile" || bn.ends_with("/Makefile") {
        return true;
    }
    if path.starts_with(".github/workflows/") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_two_commits() {
        let sample = "\
>>>SHA<<<abc123|Alice|alice@x|alice@x|2024-01-01T00:00:00+00:00
src/foo.c
src/bar.c

>>>SHA<<<def456|Bob|bob@y|bob@y|2024-02-01T00:00:00+00:00
configure.ac
m4/foo.m4
";
        let parsed = parse_git_log(sample).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].sha, "abc123");
        assert_eq!(parsed[0].files, vec!["src/foo.c", "src/bar.c"]);
        assert_eq!(parsed[1].author_email, "bob@y");
        assert_eq!(parsed[1].files, vec!["configure.ac", "m4/foo.m4"]);
    }

    #[test]
    fn build_paths() {
        assert!(is_build_system_path("configure.ac"));
        assert!(is_build_system_path("m4/build-to-host.m4"));
        assert!(is_build_system_path("CMakeLists.txt"));
        assert!(is_build_system_path("build.rs"));
        assert!(is_build_system_path(".github/workflows/ci.yml"));
        assert!(!is_build_system_path("src/main.c"));
    }

    /// Insert N commits with the given (n_files, n_build_files) tuple for `email`.
    fn insert_synthetic_commits(
        conn: &Connection,
        email: &str,
        name: &str,
        commits: &[(i64, i64)],
    ) {
        let mut stmt = conn
            .prepare(
                "INSERT INTO commits(sha, author_name, author_email, committer_email, \
                 iso_time, n_files, n_build_files) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .unwrap();
        for (i, (n_files, n_build)) in commits.iter().enumerate() {
            let sha = format!("{}-{:04}", email, i);
            stmt.execute(params![
                sha,
                name,
                email,
                email,
                "2024-01-01T00:00:00+00:00",
                n_files,
                n_build,
            ])
            .unwrap();
        }
    }

    #[test]
    fn aggregate_orders_by_absolute_build_volume_not_ratio() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        // alice: 1 commit, 1 build → ratio 100 % but volume 1 (drive-by)
        insert_synthetic_commits(&conn, "alice@x", "Alice", &[(2, 1)]);
        // bob: 5 commits, 2 build → ratio 40 %, volume 2
        insert_synthetic_commits(
            &conn,
            "bob@x",
            "Bob",
            &[(3, 1), (3, 1), (4, 0), (5, 0), (2, 0)],
        );
        // carol: 30 commits, 10 build → ratio 33 %, volume 10 (real build maintainer)
        let mut carol_commits = vec![(2, 1); 10];
        carol_commits.extend(vec![(2, 0); 20]);
        insert_synthetic_commits(&conn, "carol@x", "Carol", &carol_commits);

        let stats = aggregate_contributors(&conn).unwrap();
        let emails: Vec<&str> = stats.iter().map(|c| c.author_email.as_str()).collect();
        assert_eq!(
            emails,
            vec!["carol@x", "bob@x", "alice@x"],
            "expected sort: highest absolute build-commit volume first, then ratio, \
             then email; got {:?}",
            emails
        );
    }

    #[test]
    fn aggregate_computes_build_only_ratio() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        // attacker_profile: 20 commits total, 10 touch build files. Of those 10,
        // 9 are build-only (n_files == n_build_files), 1 mixes a code file.
        // Expected: n_build_commits=10, n_build_only_commits=9, ratio=0.9.
        let mut attacker = vec![(1, 1); 9]; // 9 build-only commits
        attacker.push((3, 1)); // 1 mixed build+code commit
        attacker.extend(vec![(2, 0); 10]); // 10 pure-code commits
        insert_synthetic_commits(&conn, "attacker@x", "Attacker", &attacker);

        // maintainer_profile: 20 commits, 10 touch build files, but 8 of those
        // are *mixed* with code (n_files=4, n_build=1). Only 2 are build-only.
        // Expected: n_build_commits=10, n_build_only_commits=2, ratio=0.2.
        let mut maintainer = vec![(1, 1); 2]; // 2 build-only
        maintainer.extend(vec![(4, 1); 8]); // 8 mixed
        maintainer.extend(vec![(2, 0); 10]); // 10 pure-code
        insert_synthetic_commits(&conn, "maintainer@x", "Maintainer", &maintainer);

        // bystander: zero build commits — must yield ratio = 0.0, not NaN.
        insert_synthetic_commits(&conn, "bystander@x", "Bystander", &[(2, 0); 5]);

        let stats = aggregate_contributors(&conn).unwrap();
        let by_email: std::collections::HashMap<_, _> =
            stats.iter().map(|c| (c.author_email.as_str(), c)).collect();

        let attacker = by_email["attacker@x"];
        assert_eq!(attacker.n_build_commits, 10);
        assert_eq!(attacker.n_build_only_commits, 9);
        assert!((attacker.build_only_ratio - 0.9).abs() < 1e-9);

        let maintainer = by_email["maintainer@x"];
        assert_eq!(maintainer.n_build_commits, 10);
        assert_eq!(maintainer.n_build_only_commits, 2);
        assert!((maintainer.build_only_ratio - 0.2).abs() < 1e-9);

        let bystander = by_email["bystander@x"];
        assert_eq!(bystander.n_build_commits, 0);
        assert_eq!(bystander.n_build_only_commits, 0);
        assert_eq!(
            bystander.build_only_ratio, 0.0,
            "ratio must be 0.0 (not NaN) when there are no build commits"
        );
    }

    fn make_contributor(
        email: &str,
        n_commits: u64,
        n_build: u64,
        n_build_only: u64,
    ) -> ContributorStats {
        let attraction = if n_commits == 0 {
            0.0
        } else {
            n_build as f64 / n_commits as f64
        };
        let build_only_ratio = if n_build == 0 {
            0.0
        } else {
            n_build_only as f64 / n_build as f64
        };
        ContributorStats {
            author_email: email.into(),
            author_name: email.into(),
            n_commits,
            n_build_commits: n_build,
            n_build_only_commits: n_build_only,
            build_attraction: attraction,
            build_only_ratio,
            first_seen: "2024-01-01T00:00:00+00:00".into(),
            last_seen: "2024-12-31T00:00:00+00:00".into(),
        }
    }

    fn make_report(contributors: Vec<ContributorStats>) -> SnapshotReport {
        SnapshotReport {
            repo: "/tmp/repo".into(),
            db_path: "/tmp/repo/.phantom/snapshot.db".into(),
            total_commits: contributors.iter().map(|c| c.n_commits).sum(),
            total_contributors: contributors.len(),
            contributors,
        }
    }

    #[test]
    fn shape_filter_suppresses_mixed_build_maintainer() {
        // Both contributors cross the 50 % HIGH absolute threshold. The
        // attacker has a 0.9 build-only ratio (passes filter); the legitimate
        // maintainer has a 0.2 ratio (suppressed).
        let report = make_report(vec![
            make_contributor("attacker@x", 30, 18, 16), // 60 % attraction, ratio 16/18 = 0.89
            make_contributor("maintainer@x", 30, 18, 4), // 60 % attraction, ratio 4/18 = 0.22
        ]);
        let opts = Options::default(); // min_build_only_ratio = 0.6
        let findings = findings_from_report(&report, &opts);

        let attraction_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.rule == "build-system-attraction")
            .collect();
        assert_eq!(
            attraction_findings.len(),
            1,
            "expected only the high-build-only-ratio contributor to surface; got {:?}",
            attraction_findings
                .iter()
                .map(|f| &f.title)
                .collect::<Vec<_>>()
        );
        assert!(
            attraction_findings[0].title.contains("attacker@x"),
            "expected attacker to surface, got `{}`",
            attraction_findings[0].title
        );
    }

    #[test]
    fn shape_filter_off_when_threshold_zero() {
        // With min_build_only_ratio = 0.0, both contributors must surface.
        let report = make_report(vec![
            make_contributor("attacker@x", 30, 18, 16),
            make_contributor("maintainer@x", 30, 18, 4),
        ]);
        let opts = Options {
            min_build_only_ratio: 0.0,
            ..Options::default()
        };
        let findings = findings_from_report(&report, &opts);
        let n = findings
            .iter()
            .filter(|f| f.rule == "build-system-attraction")
            .count();
        assert_eq!(n, 2);
    }

    #[test]
    fn median_handles_basic_lists() {
        assert_eq!(median(&[]), 0.0, "empty -> 0.0");
        assert_eq!(median(&[7.0]), 7.0, "singleton");
        assert_eq!(median(&[1.0, 2.0]), 1.5, "two values");
        assert_eq!(median(&[5.0, 1.0, 3.0]), 3.0, "odd, unsorted");
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5, "even, unsorted");
        // NaN must be filtered before computation, not poison the result.
        assert_eq!(median(&[f64::NAN, 2.0, 4.0]), 3.0, "NaN filtered");
        assert_eq!(
            median(&[f64::INFINITY, f64::NAN, f64::NEG_INFINITY]),
            0.0,
            "all non-finite -> 0.0"
        );
    }

    #[test]
    fn pick_regime_force_modes_are_honored() {
        assert_eq!(
            pick_regime(ScoringMode::Absolute, 100, 0.5),
            Regime::Absolute,
            "Absolute is sticky regardless of distribution"
        );
        assert_eq!(
            pick_regime(ScoringMode::Relative, 1, 0.5),
            Regime::Relative,
            "Relative does not require eligible-count threshold when forced"
        );
        assert_eq!(
            pick_regime(ScoringMode::Relative, 100, 0.0),
            Regime::Absolute,
            "Relative falls back to Absolute when MAD is zero (avoids /0)"
        );
    }

    #[test]
    fn pick_regime_auto_falls_back_when_distribution_unusable() {
        assert_eq!(
            pick_regime(ScoringMode::Auto, 2, 0.5),
            Regime::Absolute,
            "Auto needs >= 3 eligible contributors"
        );
        assert_eq!(
            pick_regime(ScoringMode::Auto, 10, 0.0),
            Regime::Absolute,
            "Auto falls back when MAD is zero"
        );
        assert_eq!(
            pick_regime(ScoringMode::Auto, 10, 1e-12),
            Regime::Absolute,
            "Auto falls back when MAD is below numerical floor"
        );
        assert_eq!(
            pick_regime(ScoringMode::Auto, 10, 0.05),
            Regime::Relative,
            "Auto picks Relative when distribution is usable"
        );
    }

    #[test]
    fn classify_relative_below_floor_never_fires() {
        let opts = Options::default(); // floor = 0.15
                                       // Even with z=10 (massive outlier), absolute attraction below the floor
                                       // must not surface. This is the safety valve for repos where everyone has
                                       // near-zero build-attraction.
        let s = classify_relative(0.10, /*median*/ 0.0, /*mad*/ 0.01, &opts);
        assert!(
            s.is_none(),
            "below-floor outlier must not fire, got {:?}",
            s
        );
    }

    #[test]
    fn classify_relative_thresholds_at_z() {
        let opts = Options::default(); // medium_z=3, high_z=5, floor=0.15
                                       // median=0.05, MAD=0.05 (above MAD_FLOOR), so z = (x - 0.05) / 0.05.
                                       // x=0.20 -> z=3.0 -> Medium; x=0.30 -> z=5.0 -> High.
        assert_eq!(
            classify_relative(0.20, 0.05, 0.05, &opts),
            Some(Severity::Medium)
        );
        assert_eq!(
            classify_relative(0.30, 0.05, 0.05, &opts),
            Some(Severity::High)
        );
        // Just below medium_z must not fire.
        assert!(classify_relative(0.19, 0.05, 0.05, &opts).is_none());
    }

    #[test]
    fn classify_relative_floors_tiny_mad() {
        // MAD = 0.001 should be floored to MAD_FLOOR = 0.02 to avoid spurious
        // huge z-scores on a near-uniform distribution.
        // Without flooring: z = (0.20 - 0.05) / 0.001 = 150 (massive outlier).
        // With flooring:    z = (0.20 - 0.05) / 0.02  = 7.5 (still High, but
        // a real outlier — the floor protects against degenerate cases, not
        // legitimate signal).
        let opts = Options::default();
        let s = classify_relative(0.20, 0.05, 0.001, &opts);
        assert_eq!(s, Some(Severity::High));
    }

    #[test]
    fn findings_relative_mode_picks_outlier_over_baseline() {
        // 5 contributors, all eligible. Four sit around 5–8 % build-attraction
        // (a normal repo); one sits at 35 % with a clean build-only profile —
        // a JiaT75-style shape. The relative regime must pick the outlier; the
        // legacy absolute regime (50 % HIGH bar) would have missed this.
        let report = make_report(vec![
            make_contributor("alice@x", 100, 5, 5), // 5 %, 5/5 = 100 % build-only
            make_contributor("bob@x", 100, 6, 5),   // 6 %
            make_contributor("carol@x", 100, 7, 5), // 7 %
            make_contributor("dave@x", 100, 8, 5),  // 8 %
            make_contributor("attacker@x", 100, 35, 32), // 35 %, ratio 32/35 = 0.91
        ]);
        let opts = Options::default(); // Auto mode
        let findings = findings_from_report(&report, &opts);

        let summary = findings
            .iter()
            .find(|f| f.rule == "snapshot-summary")
            .expect("summary must always be present");
        assert_eq!(
            summary.evidence.get("regime").and_then(|v| v.as_str()),
            Some("relative"),
            "expected relative regime, got {:?}",
            summary.evidence.get("regime")
        );

        let attraction: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.rule == "build-system-attraction")
            .collect();
        assert_eq!(
            attraction.len(),
            1,
            "only the attacker should surface; got {:?}",
            attraction.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        assert!(attraction[0].title.contains("attacker@x"));
        assert_eq!(attraction[0].severity, Severity::High);
    }

    #[test]
    fn findings_auto_mode_falls_back_to_absolute_with_few_contributors() {
        // 2 eligible contributors → Auto must fall back to Absolute. With the
        // legacy thresholds, a 60 % attraction crosses HIGH.
        let report = make_report(vec![
            make_contributor("attacker@x", 30, 18, 16), // ratio 16/18 = 0.89
            make_contributor("other@x", 30, 5, 5),
        ]);
        let opts = Options::default();
        let findings = findings_from_report(&report, &opts);
        let summary = findings
            .iter()
            .find(|f| f.rule == "snapshot-summary")
            .unwrap();
        assert_eq!(
            summary.evidence.get("regime").and_then(|v| v.as_str()),
            Some("absolute"),
        );

        let attraction: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.rule == "build-system-attraction")
            .collect();
        assert_eq!(attraction.len(), 1);
        assert!(attraction[0].title.contains("attacker@x"));
    }

    #[test]
    fn findings_force_absolute_reproduces_legacy_behavior() {
        // 5 contributors → Auto would pick Relative. ScoringMode::Absolute must
        // override and use the legacy thresholds. Same input as the relative
        // outlier test, but with a single contributor at 60 % to trip the
        // absolute HIGH bar.
        let report = make_report(vec![
            make_contributor("alice@x", 100, 5, 5),
            make_contributor("bob@x", 100, 6, 5),
            make_contributor("carol@x", 100, 7, 5),
            make_contributor("dave@x", 100, 8, 5),
            make_contributor("legacy@x", 100, 60, 55), // 60 %, ratio 55/60 = 0.92
        ]);
        let opts = Options {
            mode: ScoringMode::Absolute,
            ..Options::default()
        };
        let findings = findings_from_report(&report, &opts);
        let summary = findings
            .iter()
            .find(|f| f.rule == "snapshot-summary")
            .unwrap();
        assert_eq!(
            summary.evidence.get("regime").and_then(|v| v.as_str()),
            Some("absolute"),
        );

        let attraction: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.rule == "build-system-attraction")
            .collect();
        assert_eq!(
            attraction.len(),
            1,
            "only the contributor crossing the absolute HIGH bar should surface"
        );
        assert!(attraction[0].title.contains("legacy@x"));
        assert_eq!(attraction[0].severity, Severity::High);
    }
}
