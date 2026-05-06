use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use phantom_core::{PrettyOptions, Report, Severity};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "phantom",
    version,
    about = "Forensic auditor for OSS contributions in the AI era",
    long_about = "Phantom inspects supply-chain risk vectors that survive \
                  AI-assisted development: tarball/git divergence, agent-config \
                  injection, and (in future releases) intent-based diff signals."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format. `auto` picks `pretty` when stdout is a TTY, `markdown` otherwise.
    #[arg(long, value_enum, default_value_t = Output::Auto, global = true)]
    format: Output,

    /// Hide INFO findings in pretty/markdown output (they remain in the summary and JSON).
    #[arg(long, global = true)]
    hide_info: bool,

    /// Exit non-zero if any finding meets or exceeds this severity.
    #[arg(long, value_enum, default_value_t = SeverityArg::High, global = true)]
    fail_on: SeverityArg,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Auto,
    Pretty,
    Json,
    Markdown,
    /// SARIF 2.1.0, consumable by GitHub Code Scanning, GitLab SAST, etc.
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    P0,
    Never,
}

impl SeverityArg {
    fn as_severity(self) -> Option<Severity> {
        match self {
            SeverityArg::Info => Some(Severity::Info),
            SeverityArg::Low => Some(Severity::Low),
            SeverityArg::Medium => Some(Severity::Medium),
            SeverityArg::High => Some(Severity::High),
            SeverityArg::P0 => Some(Severity::P0),
            SeverityArg::Never => None,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Audit a directory for AI tooling configs (CLAUDE.md, .mcp.json, .claude/settings.json,
    /// ...) and flag prompt-injection / permission-bypass / hardcoded-trust patterns.
    Aiconfig {
        /// Directory to scan (defaults to current dir).
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Skip files whose path (relative to the scan root) starts with this prefix.
        /// Repeatable. Path-component aware: `examples` matches `examples/foo` but not `examplesextra`.
        #[arg(long, value_name = "PREFIX")]
        ignore: Vec<PathBuf>,
    },
    /// Scan a repository for indirect prompt-injection patterns in text-likely
    /// files (READMEs, docs, CHANGELOG/NEWS, issue and PR templates).
    Promptinjection {
        /// Directory to scan (defaults to current dir).
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Skip files whose path (relative to the scan root) starts with this prefix.
        /// Repeatable. Path-component aware.
        #[arg(long, value_name = "PREFIX")]
        ignore: Vec<PathBuf>,
    },
    /// Ingest a git repository's history into SQLite and report behavioural
    /// signals (build-system attraction per contributor, ...).
    Snapshot {
        /// Path to the git repository.
        repo: PathBuf,
        /// Override the SQLite output path (defaults to `<repo>/.phantom/snapshot.db`).
        #[arg(long)]
        db: Option<PathBuf>,
        /// Minimum commits before a contributor's build-attraction surfaces as a finding.
        #[arg(long, default_value_t = 10)]
        min_commits: u64,
        /// Build-attraction percentage at which a contributor flags as Medium.
        #[arg(long, default_value_t = 0.25)]
        medium_attraction: f64,
        /// Build-attraction percentage at which a contributor flags as High.
        #[arg(long, default_value_t = 0.50)]
        high_attraction: f64,
    },
    /// Audit MCP server configurations declared in a config file (`.mcp.json`,
    /// `claude_desktop_config.json`). Optionally spawns a server live to enumerate
    /// its tools/resources/prompts and classify them by risk.
    McpAudit {
        /// Path to the MCP config file.
        config: PathBuf,
        /// Spawn a server and run a live JSON-RPC handshake. ⚠ runs untrusted code.
        #[arg(long, requires = "server")]
        live: bool,
        /// Server name to spawn (must exist in the config).
        #[arg(long)]
        server: Option<String>,
        /// Maximum seconds to wait for the server's responses.
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
    },
    /// Diff a `git archive` output against a release tarball, OR diff two
    /// releases of the same package. Flags divergent files. The XZ Utils
    /// backdoor (CVE-2024-3094) is the canonical instance of this attack.
    ///
    /// Modes
    ///   git-vs-release      (default)    source = git archive at the tag
    ///   release-vs-release               source = an earlier release of the same package
    ///
    /// Invocation shapes
    ///   1. Local archives, git-vs-release:
    ///        --git-archive A.tar.gz --release-tarball B.tar.gz
    ///   2. Auto-fetch from a registry, git-vs-release:
    ///        --release <SPEC>                                 (GitHub / npm / PyPI / crates.io)
    ///   3. Auto-fetch release, override git source:
    ///        --release <SPEC> --git-archive A.tar.gz
    ///   4. Auto-fetch both sides, release-vs-release:
    ///        --baseline <OLDER_SPEC> --release <NEWER_SPEC>
    ///   5. Local archives, release-vs-release:
    ///        --baseline-tarball A.tar.gz --release-tarball B.tar.gz
    ///
    /// Spec syntax for --release / --baseline:
    ///   owner/repo[@tag]            (default scheme = github)
    ///   github:owner/repo[@tag]
    ///   npm:package[@version]
    ///   pypi:package[@version]
    ///   crates:package[@version]
    TarballDiff {
        /// Source side: a `git archive --format=tar.gz <tag>` output (or any
        /// tarball representing the source). Required when neither --release
        /// nor --baseline is used; can also override the auto-resolved git
        /// source paired with --release.
        #[arg(long)]
        git_archive: Option<PathBuf>,
        /// Source side: an earlier release tarball. Triggers
        /// release-vs-release mode and is mutually exclusive with --git-archive
        /// and --baseline.
        #[arg(
            long,
            conflicts_with_all = ["git_archive", "baseline"]
        )]
        baseline_tarball: Option<PathBuf>,
        /// Target side: the published release tarball.
        #[arg(long)]
        release_tarball: Option<PathBuf>,
        /// Target side: auto-fetch from a registry. See spec syntax above.
        /// Honours `GITHUB_TOKEN` for GitHub paths.
        #[arg(long, value_name = "SPEC", conflicts_with = "release_tarball")]
        release: Option<String>,
        /// Source side: auto-fetch an earlier release from a registry. Triggers
        /// release-vs-release mode. Same spec syntax as --release.
        #[arg(
            long,
            value_name = "OLDER_SPEC",
            conflicts_with_all = ["git_archive", "baseline_tarball"],
            requires = "release"
        )]
        baseline: Option<String>,
        /// Also report files present on the source side but missing from the
        /// target side (Low). Off by default to keep reports focused on
        /// attacker-introduced additions and modifications.
        #[arg(long)]
        report_missing: bool,
        /// In release-vs-release mode, surface ordinary source-code
        /// modifications/additions as Info findings (off by default — those
        /// changes are expected on a version bump and only add noise).
        /// Has no effect in git-vs-release mode.
        #[arg(long)]
        include_source_changes: bool,
    },
}

fn ecosystem_for(spec: &phantom_fetch::PackageSpec) -> phantom_tarball::Ecosystem {
    match spec {
        phantom_fetch::PackageSpec::GitHub { .. } => phantom_tarball::Ecosystem::GitHub,
        phantom_fetch::PackageSpec::Npm { .. } => phantom_tarball::Ecosystem::Npm,
        phantom_fetch::PackageSpec::PyPI { .. } => phantom_tarball::Ecosystem::PyPI,
        phantom_fetch::PackageSpec::Crates { .. } => phantom_tarball::Ecosystem::Crates,
    }
}

/// Two specs reference the same package iff they are in the same ecosystem
/// and identify the same name (GitHub: `owner/repo`; npm/PyPI/crates:
/// package name). Versions are allowed to differ — that's the whole point of
/// release-vs-release.
fn same_ecosystem_and_package(
    a: &phantom_fetch::PackageSpec,
    b: &phantom_fetch::PackageSpec,
) -> bool {
    use phantom_fetch::PackageSpec::*;
    match (a, b) {
        (GitHub { owner: o1, repo: r1, .. }, GitHub { owner: o2, repo: r2, .. }) => {
            o1 == o2 && r1 == r2
        }
        (Npm { package: p1, .. }, Npm { package: p2, .. }) => p1 == p2,
        (PyPI { package: p1, .. }, PyPI { package: p2, .. }) => p1 == p2,
        (Crates { package: p1, .. }, Crates { package: p2, .. }) => p1 == p2,
        _ => false,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("phantom: error: {:#}", e);
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let (target, findings) = match &cli.command {
        Commands::Aiconfig { path, ignore } => {
            let findings = phantom_aiconfig::scan(path, ignore)?;
            (Some(path.display().to_string()), findings)
        }
        Commands::Promptinjection { path, ignore } => {
            let findings = phantom_promptinjection::scan(path, ignore)?;
            (Some(path.display().to_string()), findings)
        }
        Commands::Snapshot { repo, db, min_commits, medium_attraction, high_attraction } => {
            let opts = phantom_snapshot::Options {
                db_path: db.clone(),
                min_commits_for_finding: *min_commits,
                medium_attraction_pct: *medium_attraction,
                high_attraction_pct: *high_attraction,
            };
            let report = phantom_snapshot::snapshot(repo, phantom_snapshot::Options {
                db_path: opts.db_path.clone(),
                ..phantom_snapshot::Options::default()
            })?;
            // Re-run with the user's thresholds for findings:
            let opts_for_findings = phantom_snapshot::Options {
                db_path: None,
                min_commits_for_finding: *min_commits,
                medium_attraction_pct: *medium_attraction,
                high_attraction_pct: *high_attraction,
            };
            let findings = phantom_snapshot::findings_from_report(&report, &opts_for_findings);
            (Some(repo.display().to_string()), findings)
        }
        Commands::McpAudit { config, live, server, timeout_secs } => {
            let mut findings = phantom_mcp::audit_config(config)?;
            if *live {
                let server_name = server.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--live requires --server <NAME>")
                })?;
                eprintln!(
                    "phantom: warning: --live spawns `{}` from `{}`; \
                     this executes the configured MCP server, which by definition is \
                     the code you are trying to evaluate. Run inside a sandbox.",
                    server_name,
                    config.display()
                );
                let spec = phantom_mcp::McpServerSpec::from_config(config, server_name)?;
                let live_findings = phantom_mcp::audit_live(
                    &spec,
                    std::time::Duration::from_secs(*timeout_secs),
                )?;
                findings.extend(live_findings);
            }
            let label = format!(
                "{}{}",
                config.display(),
                if *live {
                    format!(" (+live: {})", server.as_deref().unwrap_or(""))
                } else {
                    String::new()
                }
            );
            (Some(label), findings)
        }
        Commands::TarballDiff {
            git_archive,
            baseline_tarball,
            release_tarball,
            release,
            baseline,
            report_missing,
            include_source_changes,
        } => {
            let mut opts = phantom_tarball::DiffOptions {
                report_missing: *report_missing,
                ecosystem: None,
                mode: phantom_tarball::DiffMode::GitVsRelease,
                include_source_changes: *include_source_changes,
            };

            // Resolve `(source_path, target_path, label, mode)`. Five shapes
            // from the help text — see clap definition for the exclusivity
            // constraints that cut down the cases we have to handle here.
            let (source_path, target_path, label) = match (
                git_archive.as_ref(),
                baseline_tarball.as_ref(),
                release_tarball.as_ref(),
                release.as_ref(),
                baseline.as_ref(),
            ) {
                // (1) git-vs-release, fully local.
                (Some(g), None, Some(r), None, None) => {
                    let label = format!("git={} ↔ release={}", g.display(), r.display());
                    (g.clone(), r.clone(), label)
                }
                // (5) release-vs-release, fully local.
                (None, Some(b), Some(r), None, None) => {
                    opts.mode = phantom_tarball::DiffMode::ReleaseVsRelease;
                    let label = format!(
                        "baseline={} ↔ release={}",
                        b.display(),
                        r.display()
                    );
                    (b.clone(), r.clone(), label)
                }
                // (4) release-vs-release, both auto-fetched.
                (None, None, None, Some(rel_spec), Some(base_spec)) => {
                    opts.mode = phantom_tarball::DiffMode::ReleaseVsRelease;
                    let baseline_pkg: phantom_fetch::PackageSpec = base_spec.parse()?;
                    let target_pkg: phantom_fetch::PackageSpec = rel_spec.parse()?;
                    if !same_ecosystem_and_package(&baseline_pkg, &target_pkg) {
                        anyhow::bail!(
                            "--baseline and --release must reference the same package in the same ecosystem"
                        );
                    }
                    let ecosystem = ecosystem_for(&target_pkg);
                    opts.ecosystem = Some(ecosystem);

                    let baseline_dl = phantom_fetch::download(&baseline_pkg)?;
                    let baseline_archive = phantom_fetch::pick_canonical_asset(&baseline_dl)
                        .ok_or_else(|| anyhow::anyhow!(
                            "baseline `{}` has no archive asset to compare",
                            baseline_dl.spec_label
                        ))?
                        .to_path_buf();

                    let target_dl = phantom_fetch::download(&target_pkg)?;
                    let target_archive = phantom_fetch::pick_canonical_asset(&target_dl)
                        .ok_or_else(|| anyhow::anyhow!(
                            "target release `{}` has no archive asset to compare",
                            target_dl.spec_label
                        ))?
                        .to_path_buf();

                    let label = format!(
                        "{}  ↔  {}",
                        baseline_dl.spec_label, target_dl.spec_label
                    );
                    (baseline_archive, target_archive, label)
                }
                // (2)/(3) git-vs-release, auto-fetched target with optional
                // --git-archive override.
                (override_git, None, None, Some(spec_str), None) => {
                    let spec: phantom_fetch::PackageSpec = spec_str.parse()?;
                    let ecosystem = ecosystem_for(&spec);
                    opts.ecosystem = Some(ecosystem);

                    let downloaded = phantom_fetch::download(&spec)?;
                    let target_archive = phantom_fetch::pick_canonical_asset(&downloaded)
                        .ok_or_else(|| anyhow::anyhow!(
                            "release `{}` has no archive asset to diff against",
                            downloaded.spec_label
                        ))?
                        .to_path_buf();
                    let source_archive = match override_git {
                        Some(g) => g.clone(),
                        None => downloaded.source_archive.clone().ok_or_else(|| {
                            anyhow::anyhow!(
                                "could not auto-resolve a git source for `{}`. \
                                 The registry's repository URL didn't point at a recognisable GitHub repo, \
                                 or no matching tag was found. \
                                 Re-run with `--git-archive <PATH>` providing a `git archive --format=tar.gz` \
                                 of the upstream commit, or use `--baseline <OLDER_SPEC>` to compare against \
                                 an earlier release of the same package instead.",
                                downloaded.spec_label
                            )
                        })?,
                    };
                    let label = format!(
                        "{} (source ↔ {})",
                        downloaded.spec_label,
                        target_archive.file_name().and_then(|n| n.to_str()).unwrap_or("?")
                    );
                    (source_archive, target_archive, label)
                }
                _ => anyhow::bail!(
                    "invalid combination of flags. Pick one:\n\
                     \n\
                     git-vs-release (default mode):\n  \
                       --git-archive A.tar.gz --release-tarball B.tar.gz\n  \
                       --release <SPEC>\n  \
                       --release <SPEC> --git-archive A.tar.gz\n\
                     \n\
                     release-vs-release:\n  \
                       --baseline-tarball A.tar.gz --release-tarball B.tar.gz\n  \
                       --baseline <OLDER_SPEC> --release <NEWER_SPEC>\n\
                     \n\
                     SPEC examples: `owner/repo@tag`, `npm:lodash@4.17.21`, \
                     `pypi:requests@2.31.0`, `crates:serde@1.0.193`."
                ),
            };
            let findings = phantom_tarball::diff(&source_path, &target_path, opts)?;
            (Some(label), findings)
        }
    };

    let report = Report::new(target, findings);

    enum Resolved {
        Pretty,
        Json,
        Markdown,
        Sarif,
    }
    let resolved_format = match cli.format {
        Output::Auto => {
            if std::io::stdout().is_terminal() {
                Resolved::Pretty
            } else {
                Resolved::Markdown
            }
        }
        Output::Pretty => Resolved::Pretty,
        Output::Json => Resolved::Json,
        Output::Markdown => Resolved::Markdown,
        Output::Sarif => Resolved::Sarif,
    };

    match resolved_format {
        Resolved::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Resolved::Markdown => {
            print!("{}", report.to_markdown());
        }
        Resolved::Pretty => {
            let mut opts = PrettyOptions::from_terminal();
            opts.hide_info = cli.hide_info;
            print!("{}", report.to_pretty(&opts));
        }
        Resolved::Sarif => {
            println!("{}", serde_json::to_string_pretty(&report.to_sarif())?);
        }
    }

    let code = match (cli.fail_on.as_severity(), report.summary.max_severity()) {
        (Some(threshold), Some(max)) if max >= threshold => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    };
    Ok(code)
}
