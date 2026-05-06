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
    /// Diff a `git archive` output against a release tarball; flag divergent files.
    /// The XZ Utils backdoor (CVE-2024-3094) is the canonical instance of this attack.
    ///
    /// Three invocation shapes are supported:
    ///   1. Both archives provided locally:        --git-archive A.tar.gz --release-tarball B.tar.gz
    ///   2. Auto-fetch from a registry:            --release <SPEC>      (GitHub / npm / PyPI / crates.io)
    ///   3. Auto-fetch the release, override git:  --release <SPEC>      --git-archive A.tar.gz
    ///
    /// Spec syntax for `--release`:
    ///   owner/repo[@tag]            (default scheme = github)
    ///   github:owner/repo[@tag]
    ///   npm:package[@version]
    ///   pypi:package[@version]
    ///   crates:package[@version]
    TarballDiff {
        /// Path to `git archive --format=tar.gz <tag>` output (or any tarball
        /// representing the source side). Required when `--release` is absent
        /// or when overriding the auto-resolved git source.
        #[arg(long)]
        git_archive: Option<PathBuf>,
        /// Path to the published release tarball.
        #[arg(long, requires = "git_archive", conflicts_with = "release")]
        release_tarball: Option<PathBuf>,
        /// Auto-fetch from a registry. See command help for spec syntax.
        /// Honours `GITHUB_TOKEN` for the GitHub paths.
        #[arg(long, value_name = "SPEC")]
        release: Option<String>,
        /// Also report files in git that are absent from the release.
        #[arg(long)]
        report_missing: bool,
    },
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
        Commands::TarballDiff { git_archive, release_tarball, release, report_missing } => {
            let mut opts = phantom_tarball::DiffOptions {
                report_missing: *report_missing,
                ecosystem: None,
            };
            let (git_path, release_path, label) = match (git_archive, release_tarball, release) {
                // Fully local: both archives provided.
                (Some(g), Some(r), None) => {
                    let label = format!("git={} ↔ release={}", g.display(), r.display());
                    (g.clone(), r.clone(), label)
                }
                // Auto-fetch from registry, optionally with --git-archive override.
                (override_git, None, Some(spec_str)) => {
                    let spec: phantom_fetch::PackageSpec = spec_str.parse()?;
                    // Map the spec to an ecosystem hint so tarball-diff can
                    // widen its allowlist appropriately.
                    let ecosystem = match &spec {
                        phantom_fetch::PackageSpec::GitHub { .. } => phantom_tarball::Ecosystem::GitHub,
                        phantom_fetch::PackageSpec::Npm { .. } => phantom_tarball::Ecosystem::Npm,
                        phantom_fetch::PackageSpec::PyPI { .. } => phantom_tarball::Ecosystem::PyPI,
                        phantom_fetch::PackageSpec::Crates { .. } => phantom_tarball::Ecosystem::Crates,
                    };
                    let downloaded = phantom_fetch::download(&spec)?;
                    let canonical = phantom_fetch::pick_canonical_asset(&downloaded)
                        .ok_or_else(|| anyhow::anyhow!(
                            "release `{}` has no archive asset to diff against",
                            downloaded.spec_label
                        ))?
                        .to_path_buf();
                    let git_side = match override_git {
                        Some(g) => g.clone(),
                        None => downloaded.source_archive.clone().ok_or_else(|| {
                            anyhow::anyhow!(
                                "could not auto-resolve a git source for `{}`. \
                                 The registry's repository URL didn't point at a recognisable GitHub repo, \
                                 or no matching tag was found. \
                                 Re-run with `--git-archive <PATH>` providing a `git archive --format=tar.gz` of the upstream commit.",
                                downloaded.spec_label
                            )
                        })?,
                    };
                    let label = format!(
                        "{} (source ↔ {})",
                        downloaded.spec_label,
                        canonical.file_name().and_then(|n| n.to_str()).unwrap_or("?")
                    );
                    opts.ecosystem = Some(ecosystem);
                    (git_side, canonical, label)
                }
                _ => anyhow::bail!(
                    "supply either --git-archive + --release-tarball, or --release <SPEC>. \
                     SPEC examples: `owner/repo@tag`, `npm:lodash@4.17.21`, `pypi:requests@2.31.0`, `crates:serde@1.0.193`."
                ),
            };
            let findings = phantom_tarball::diff(&git_path, &release_path, opts)?;
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
