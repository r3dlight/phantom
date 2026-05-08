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
    pub build_attraction: f64,
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

pub struct Options {
    /// Where to write the SQLite database. Defaults to `<repo>/.phantom/snapshot.db`.
    pub db_path: Option<PathBuf>,
    /// Minimum number of commits before a contributor's build-attraction is
    /// reported as a finding (suppresses noise from drive-by contributors).
    pub min_commits_for_finding: u64,
    /// Build-attraction thresholds for finding severities.
    pub medium_attraction_pct: f64,
    pub high_attraction_pct: f64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            db_path: None,
            min_commits_for_finding: 10,
            medium_attraction_pct: 0.25,
            high_attraction_pct: 0.50,
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
    let mut out = vec![Finding {
        detector: DETECTOR.into(),
        rule: "snapshot-summary".into(),
        severity: Severity::Info,
        title: format!("Repository snapshot of `{}`", report.repo),
        description: format!(
            "{} commits across {} contributors. SQLite database stored at `{}`.",
            report.total_commits, report.total_contributors, report.db_path
        ),
        locations: vec![Location::path(report.repo.clone())],
        evidence: json!({
            "total_commits": report.total_commits,
            "total_contributors": report.total_contributors,
            "db_path": report.db_path,
        }),
    }];

    for c in &report.contributors {
        if c.n_commits < opts.min_commits_for_finding {
            continue;
        }
        let severity = if c.build_attraction >= opts.high_attraction_pct {
            Severity::High
        } else if c.build_attraction >= opts.medium_attraction_pct {
            Severity::Medium
        } else {
            continue;
        };
        out.push(Finding {
            detector: DETECTOR.into(),
            rule: "build-system-attraction".into(),
            severity,
            title: format!(
                "{} ({}) — build-attraction {:.0}% over {} commits",
                c.author_email,
                c.author_name,
                c.build_attraction * 100.0,
                c.n_commits
            ),
            description: format!(
                "Of {} commits authored by `{}`, {} touched build-system files \
                 (configure.ac, *.m4, build.rs, CMakeLists.txt, GitHub Actions, ...). \
                 The XZ Utils attacker (JiaT75) had a disproportionate share of build-system commits \
                 prior to introducing the backdoor. \
                 This is one signal, not a verdict — a corporate maintainer of the build system would also score high.",
                c.n_commits, c.author_email, c.n_build_commits
            ),
            locations: vec![Location::path(report.repo.clone())],
            evidence: json!({
                "author_email": c.author_email,
                "author_name": c.author_name,
                "n_commits": c.n_commits,
                "n_build_commits": c.n_build_commits,
                "build_attraction": c.build_attraction,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
            }),
        });
    }

    out
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
    let mut stmt = conn.prepare(
        r#"
        SELECT
            author_email,
            MAX(author_name) AS author_name,
            COUNT(*) AS n_commits,
            SUM(CASE WHEN n_build_files > 0 THEN 1 ELSE 0 END) AS n_build_commits,
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
        let attraction = if n_commits == 0 {
            0.0
        } else {
            n_build as f64 / n_commits as f64
        };
        Ok(ContributorStats {
            author_email: row.get(0)?,
            author_name: row.get(1)?,
            n_commits: n_commits.max(0) as u64,
            n_build_commits: n_build.max(0) as u64,
            build_attraction: attraction,
            first_seen: row.get(4)?,
            last_seen: row.get(5)?,
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
}
