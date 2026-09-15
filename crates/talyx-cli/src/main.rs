//! talyx-cli — v0 entry point.
//!
//! `talyx scan`   — discover, statically scan, and score every artifact
//!                        visible to a supported agent. Read-only.
//! `talyx status` — short protection summary. Read-only.
//! `talyx init`   — scan, cache decisions, AND rewrite MCP server
//!                        configs to route through the enforcement shim
//!                        (BUILD_PLAN.md §5a). The only command that writes
//!                        anything — see init.rs.
//! `talyx allow <id>` — manually approve a flagged artifact.
//! `talyx why <id>`   — show the full reasoning behind a cached decision.
//! `talyx activate <key>` — bind a paid license to this machine.
//! `talyx license status|deactivate` — inspect / release the license.
//!
//! `scan` and `status` are free (evaluation). `init` requires a valid
//! license — see license.rs for the full rationale, including why the
//! enforcement shim itself is deliberately never gated.

mod init;
mod license;
mod pipeline;
mod sarif;
mod sessions;

use talyx_core::{Decision, ProtectionLevel, RiskBand};
use talyx_risk::RiskEngine;
use clap::{Parser, Subcommand, ValueEnum};
use pipeline::{collect, ScannedArtifact};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "talyx",
    version,
    about = "Cross-agent security scanner for AI coding agent artifacts (MCP servers, skills, plugins, hooks)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover, scan, and score every artifact visible to a supported agent. Read-only.
    Scan {
        /// Project root to scan (in addition to user-level/global config).
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Onboarding preset — see BUILD_PLAN.md §6.
        #[arg(long, value_enum, default_value = "balanced")]
        level: ProtectionLevelArg,
        /// Fetch and statically scan the actual code behind a
        /// registry-resolved MCP server (`npx <pkg>`, `uvx <pkg>`) instead
        /// of scoring it on declared evidence only. Off by default: this
        /// makes a real outbound HTTPS call to the npm/PyPI registry for
        /// each one found, which every other artifact this tool scores
        /// never needs.
        #[arg(long)]
        fetch_registry: bool,
        /// Output format for stdout. `sarif` emits a SARIF 2.1.0 log for
        /// GitHub code scanning / CI security dashboards.
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormatArg,
        /// Also write a SARIF 2.1.0 log to this path (independent of
        /// `--format`, so you can keep the human-readable table on stdout
        /// and still hand CI a file to upload).
        #[arg(long)]
        sarif_file: Option<PathBuf>,
        /// Exit non-zero when the scan finds something: 2 if any artifact
        /// is BLOCK/QUARANTINE, 1 if any is ASK, 0 otherwise. Off by
        /// default so `scan` stays a read-only report; turn it on to gate
        /// a CI job.
        #[arg(long)]
        exit_code: bool,
    },
    /// Short protection summary (agents detected, artifact counts). Read-only.
    Status {
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
    /// Scan, cache decisions, and route MCP servers through the enforcement
    /// shim — the only command that modifies an agent's config file(s)
    /// (with a one-time backup before the first rewrite).
    Init {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long, value_enum, default_value = "balanced")]
        level: ProtectionLevelArg,
        /// Override the decision store location (defaults to
        /// ~/.talyx/decisions.json, or $TALYX_STORE if set).
        #[arg(long)]
        store: Option<PathBuf>,
        /// Also rewrite MCP server configs found OUTSIDE this project
        /// (e.g. a user-level ~/.claude.json). Off by default: `init` only
        /// touches configs inside --project unless you explicitly ask for
        /// more, because a user-level config affects every project on the
        /// machine, not just this one.
        #[arg(long)]
        include_user_config: bool,
        /// Fetch and statically scan the actual code behind a
        /// registry-resolved MCP server before scoring/enforcing it — see
        /// `scan --fetch-registry`'s help for why this is opt-in.
        #[arg(long)]
        fetch_registry: bool,
        /// Route each approved MCP server through the Talyx stdio
        /// proxy (ADR 0001): the shim stays between the agent and the
        /// server for the session and inspects the JSON-RPC traffic, on
        /// top of the launch-time scan. `TALYX_NO_PROXY=1` disables
        /// it for a single launch without re-running init.
        #[arg(long)]
        live: bool,
    },
    /// Manually approve an artifact flagged ASK/BLOCK (by id, from `scan`/`why`).
    Allow {
        artifact_id: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Show the full reasoning behind a cached decision.
    Why {
        artifact_id: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Activate a paid license on this machine (required for `init`).
    Activate {
        /// The license key from your purchase email (a UUID, e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
        key: String,
    },
    /// Inspect or release this machine's license.
    License {
        #[command(subcommand)]
        action: LicenseAction,
    },
    /// Work with the live-proxy guardrails file (see `talyx init --live`).
    Guardrails {
        #[command(subcommand)]
        action: GuardrailsAction,
    },
    /// Inspect Talyx's known-bad advisory feed (identity matches for
    /// publicly-disclosed malicious or vulnerable MCP artifacts).
    Advisories {
        #[command(subcommand)]
        action: AdvisoriesAction,
    },
}

#[derive(Subcommand)]
enum LicenseAction {
    /// Show license status, machines used, and expiry (lifetime keys never expire).
    Status,
    /// Release this machine's activation slot so it can be used elsewhere.
    Deactivate,
}

#[derive(Subcommand)]
enum GuardrailsAction {
    /// Validate the guardrails file (default: the one the proxy would load).
    Check {
        /// Path to a specific guardrails file to check.
        path: Option<PathBuf>,
    },
    /// List the rules the proxy would load, one line each.
    List {
        path: Option<PathBuf>,
    },
    /// Print a commented starter guardrails file to stdout.
    Example,
}

#[derive(Subcommand)]
enum AdvisoriesAction {
    /// List every advisory in the active feed.
    List,
    /// Check a package name (and optional version) against the feed.
    Check {
        /// Package name, e.g. `postmark-mcp`.
        package: String,
        /// Version to check, e.g. `1.0.17`. Omit to check the whole line.
        #[arg(long)]
        version: Option<String>,
        /// Registry the package lives in: `npm` (default) or `pypi`.
        #[arg(long, default_value = "npm")]
        registry: String,
    },
    /// Download a newer feed over HTTPS and replace the local override
    /// (`~/.talyx/advisories.json` or `$TALYX_ADVISORIES`). The bundled
    /// feed is never touched; a fetch or validation failure leaves any
    /// existing file untouched.
    Refresh {
        /// Feed URL. Defaults to `$TALYX_ADVISORIES_URL`, else the
        /// `advisories.json` asset of the latest release of
        /// `$TALYX_REPO` (defaults to `rynald0cst0ltziam/talyx`).
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum ProtectionLevelArg {
    Quiet,
    Balanced,
    Strict,
}

#[derive(ValueEnum, Clone, Copy, PartialEq)]
enum OutputFormatArg {
    Text,
    Sarif,
}

impl From<ProtectionLevelArg> for ProtectionLevel {
    fn from(v: ProtectionLevelArg) -> Self {
        match v {
            ProtectionLevelArg::Quiet => ProtectionLevel::Quiet,
            ProtectionLevelArg::Balanced => ProtectionLevel::Balanced,
            ProtectionLevelArg::Strict => ProtectionLevel::Strict,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            project,
            level,
            fetch_registry,
            format,
            sarif_file,
            exit_code,
        } => run_scan(&project, level.into(), fetch_registry, format, sarif_file, exit_code),
        Command::Status { project } => run_status(&project),
        Command::Init {
            project,
            level,
            store,
            include_user_config,
            fetch_registry,
            live,
        } => {
            let code = license::gate("init");
            if code != 0 {
                std::process::exit(code);
            }
            init::run_init(
                &project,
                level.into(),
                store,
                include_user_config,
                fetch_registry,
                live,
            )
        }
        Command::Allow { artifact_id, store } => init::run_allow(&artifact_id, store),
        Command::Why { artifact_id, store } => init::run_why(&artifact_id, store),
        Command::Activate { key } => std::process::exit(license::run_activate(&key)),
        Command::License { action } => std::process::exit(match action {
            LicenseAction::Status => license::run_status(),
            LicenseAction::Deactivate => license::run_deactivate(),
        }),
        Command::Guardrails { action } => std::process::exit(run_guardrails(action)),
        Command::Advisories { action } => std::process::exit(run_advisories(action)),
    }
}

fn run_advisories(action: AdvisoriesAction) -> i32 {
    use talyx_core::ArtifactSource;

    if let AdvisoriesAction::Refresh { url } = action {
        return run_advisories_refresh(url);
    }

    let feed = talyx_advisories::Advisories::load(pipeline::advisories_file().as_deref());

    match action {
        AdvisoriesAction::Refresh { .. } => unreachable!(),
        AdvisoriesAction::List => {
            println!("{} advisory(ies) — source: {}", feed.len(), feed.source);
            for adv in feed.iter() {
                println!(
                    "\n  {}  [{}]  {}\n    {}\n    published {}",
                    adv.id, adv.severity, adv.title, adv.detail, adv.published
                );
                for r in &adv.references {
                    println!("    {r}");
                }
            }
            0
        }
        AdvisoriesAction::Check {
            package,
            version,
            registry,
        } => {
            let source = ArtifactSource::Registry {
                name: package.clone(),
                registry: registry.clone(),
            };
            let spec = match &version {
                Some(v) => format!("{registry}:{package}@{v}"),
                None => format!("{registry}:{package}"),
            };
            let hits = feed.check(&source, None, None, version.as_deref());
            if hits.is_empty() {
                println!("No advisory matches {spec}.");
                0
            } else {
                for f in &hits {
                    println!("MATCH  [{:?}]  {}", f.capability, f.evidence);
                }
                1
            }
        }
    }
}

fn run_advisories_refresh(url: Option<String>) -> i32 {
    let explicit = url.is_some() || std::env::var_os("TALYX_ADVISORIES_URL").is_some();
    let url = url
        .or_else(|| std::env::var("TALYX_ADVISORIES_URL").ok())
        .unwrap_or_else(|| {
            let repo =
                std::env::var("TALYX_REPO")
                    .unwrap_or_else(|_| "rynald0cst0ltziam/talyx".to_string());
            format!("https://github.com/{repo}/releases/latest/download/advisories.json")
        });

    let Some(dest) = pipeline::advisories_file() else {
        eprintln!("talyx: no home directory — can't resolve where to write the feed.");
        eprintln!("Set $TALYX_ADVISORIES to an explicit path and retry.");
        return 1;
    };

    println!("Fetching {url}");
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .user_agent(concat!("talyx/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(agent);

    let text = match agent.get(&url).call() {
        Ok(mut resp) => match resp
            .body_mut()
            .with_config()
            .limit(4 * 1024 * 1024)
            .read_to_string()
        {
            Ok(t) => t,
            Err(e) => {
                eprintln!("talyx: failed to read the feed response: {e}");
                return 1;
            }
        },
        Err(ureq::Error::StatusCode(404)) => {
            eprintln!("talyx: {url} returned 404.");
            if !explicit {
                eprintln!(
                    "No published feed yet — `$TALYX_REPO` is still the placeholder until a real repo + release exists (same as the install scripts). Pass --url or set $TALYX_ADVISORIES_URL to fetch from elsewhere."
                );
            }
            return 1;
        }
        Err(e) => {
            eprintln!("talyx: could not fetch {url}: {e}");
            return 1;
        }
    };

    let count = match talyx_advisories::Advisories::validate(&text) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("talyx: the downloaded feed is not valid — {e}");
            eprintln!("The local feed was left unchanged.");
            return 1;
        }
    };

    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("talyx: could not create {}: {e}", parent.display());
            return 1;
        }
    }
    if let Err(e) = std::fs::write(&dest, &text) {
        eprintln!("talyx: could not write {}: {e}", dest.display());
        return 1;
    }

    println!(
        "Wrote {count} advisory(ies) to {} — `talyx scan`/`init` will use it from now on.",
        dest.display()
    );
    println!("Delete that file to fall back to the feed bundled in the binary.");
    0
}

fn run_guardrails(action: GuardrailsAction) -> i32 {
    use talyx_mcp_proxy::guardrails::{default_paths, Guardrails};

    if let GuardrailsAction::Example = action {
        print!("{}", Guardrails::EXAMPLE);
        return 0;
    }

    let (explicit, want_list) = match &action {
        GuardrailsAction::Check { path } => (path.clone(), false),
        GuardrailsAction::List { path } => (path.clone(), true),
        GuardrailsAction::Example => unreachable!(),
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let candidates = match explicit {
        Some(p) => vec![p],
        None => default_paths(&cwd),
    };

    match Guardrails::load(&candidates) {
        Ok(None) => {
            println!(
                "No guardrails file found. Looked at:\n{}\n\nRun `talyx guardrails example > ~/.talyx/guardrails.yaml` to start one.",
                candidates
                    .iter()
                    .map(|p| format!("  {}", p.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            0
        }
        Ok(Some(g)) => {
            println!("{} rule(s), valid — {}", g.rule_count(), g.source);
            if want_list {
                for line in g.describe() {
                    println!("  {line}");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("guardrails file is invalid:\n  {e}");
            1
        }
    }
}

fn resolve_root(project: &Path) -> PathBuf {
    project.canonicalize().unwrap_or_else(|_| project.to_path_buf())
}

fn run_scan(
    project: &Path,
    level: ProtectionLevel,
    fetch_registry: bool,
    format: OutputFormatArg,
    sarif_file: Option<PathBuf>,
    exit_code: bool,
) {
    let project_root = resolve_root(project);
    let engine = RiskEngine::new();
    let scanned = collect(&project_root, &engine, level, fetch_registry);

    // SARIF is emitted even for an empty scan (a valid log with zero
    // results is what a CI step expects), and before the text report so a
    // panic in rendering can't lose it.
    if let Some(path) = &sarif_file {
        write_sarif_file(&scanned, &project_root, path);
    }
    if format == OutputFormatArg::Sarif {
        let log = sarif::build(&scanned, &project_root);
        println!("{}", serde_json::to_string_pretty(&log).unwrap());
        if exit_code {
            std::process::exit(sarif::exit_code(&scanned));
        }
        return;
    }

    if scanned.is_empty() {
        println!(
            "No agent artifacts found under {} (and no recognized agent config in the home directory).",
            project_root.display()
        );
        if exit_code {
            std::process::exit(0);
        }
        return;
    }

    println!(
        "{:<12} {:<11} {:<30} {:<9} {:<10} LOCATION",
        "AGENT", "KIND", "NAME", "RISK", "DECISION"
    );
    for s in &scanned {
        println!(
            "{:<12} {:<11} {:<30} {:<9} {:<10} {}",
            s.agent_name,
            s.artifact.kind.to_string(),
            truncate(&sanitize_for_display(&s.artifact.name), 30),
            s.band.to_string(),
            s.decision.to_string(),
            sanitize_for_display(&s.location),
        );
    }

    let critical = scanned.iter().filter(|s| s.band == RiskBand::Critical).count();
    let high = scanned.iter().filter(|s| s.band == RiskBand::High).count();

    println!();
    println!(
        "{} artifact(s) scanned — {} critical, {} high.",
        scanned.len(),
        critical,
        high
    );
    println!("(read-only — run `talyx init` to also cache decisions and enable enforcement)");

    pipeline::print_registry_fetch_summary(&scanned, fetch_registry);

    let flagged: Vec<&ScannedArtifact> = scanned
        .iter()
        .filter(|s| matches!(s.decision, Decision::Ask | Decision::Block | Decision::Quarantine))
        .collect();

    if !flagged.is_empty() {
        println!("\nWhy these were flagged:");
        for s in flagged {
            println!(
                "\n--- {} ({}) via {} — {} => {} [id: {}] ---",
                sanitize_for_display(&s.artifact.name),
                s.artifact.kind,
                s.agent_name,
                s.band,
                s.decision,
                sanitize_for_display(&s.artifact.id)
            );
            for r in &s.breakdown.static_evidence_reasons {
                println!("  {r}");
            }
            for r in &s.breakdown.reputation_reasons {
                println!("  {r}");
            }
            for r in &s.breakdown.context_reasons {
                println!("  {r}");
            }
        }
    }

    if exit_code {
        std::process::exit(sarif::exit_code(&scanned));
    }
}

fn write_sarif_file(scanned: &[ScannedArtifact], project_root: &Path, path: &Path) {
    let log = sarif::build(scanned, project_root);
    match serde_json::to_string_pretty(&log) {
        Ok(text) => {
            if let Err(e) = std::fs::write(path, text) {
                eprintln!("talyx: failed to write SARIF file {}: {e}", path.display());
            } else {
                eprintln!("talyx: wrote SARIF report to {}", path.display());
            }
        }
        Err(e) => eprintln!("talyx: failed to serialize SARIF: {e}"),
    }
}

fn run_status(project: &Path) {
    let project_root = resolve_root(project);
    let engine = RiskEngine::new();
    let scanned = collect(&project_root, &engine, ProtectionLevel::Balanced, false);

    println!("Talyx\n");

    let mut agent_names: Vec<&str> = scanned.iter().map(|s| s.agent_name).collect();
    agent_names.sort_unstable();
    agent_names.dedup();

    if agent_names.is_empty() {
        println!("No supported agent detected under {}.", project_root.display());
        return;
    }

    println!("Agents detected:");
    for name in &agent_names {
        println!("  {name} \u{2713}");
    }

    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for s in &scanned {
        *counts.entry(s.artifact.kind.to_string()).or_insert(0) += 1;
    }

    println!("\nArtifacts: {}", scanned.len());
    for (kind, count) in &counts {
        println!("  {kind}: {count}");
    }

    let critical = scanned.iter().filter(|s| s.band == RiskBand::Critical).count();
    let blocked = scanned.iter().filter(|s| s.decision == Decision::Block).count();
    println!("\nCritical risk: {critical}    Blocked (Balanced preset): {blocked}");

    let rewritable = scanned.iter().filter(|s| s.launch.is_some() && s.config_source.is_some()).count();
    if rewritable > 0 {
        println!(
            "\nProtection: \u{25cf} Static scan cached in-memory only — run `talyx init` to route {rewritable} MCP server(s) through enforcement."
        );
    } else {
        println!("\nProtection: \u{25cf} Active (static scan only — enforcement not applicable to what was found here)");
    }

    print_recent_proxy_findings();
}

/// Summarise what the live MCP proxy (`init --live`) has caught recently.
/// Silent when the proxy isn't in use / nothing was flagged.
fn print_recent_proxy_findings() {
    let findings = sessions::recent(5);
    if findings.is_empty() {
        return;
    }
    let mut by_action: std::collections::BTreeMap<String, usize> = Default::default();
    for f in &findings {
        *by_action.entry(f.action.clone()).or_insert(0) += 1;
    }
    let breakdown: Vec<String> = by_action.iter().map(|(k, n)| format!("{n} {k}")).collect();
    println!(
        "\nLive proxy: {} finding(s) in recent sessions ({}).",
        findings.len(),
        breakdown.join(", ")
    );
    for f in findings.iter().take(3) {
        println!(
            "  {} — {} on {} ({})",
            f.action, f.capability, f.method, f.artifact
        );
    }
}

/// Replaces control characters with U+FFFD before printing anything
/// derived from an artifact's name/path/id to a terminal. Found live, not
/// hypothetically: a real, malformed Codex config.toml on this machine
/// parsed an ambiguous `\b` escape (see codex.rs's
/// repair_unescaped_backslashes doc comment) into a literal backspace
/// character, which then visibly corrupted the printed path (a character
/// appeared to vanish mid-string). More generally, an artifact's
/// name/path/id is exactly the kind of attacker-influenced content a
/// security tool must never print raw — control or ANSI-escape sequences
/// in a name could otherwise manipulate the terminal display in
/// misleading ways. `talyx why`'s underlying data (the decision
/// store) keeps the real string; this only affects what hits the screen.
pub(crate) fn sanitize_for_display(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}\u{2026}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_a_literal_backspace() {
        // Regression test for the exact live failure: a real Codex
        // config.toml's ambiguous `\b` escape (codex.rs's
        // repair_unescaped_backslashes) parsed into an actual backspace
        // character, which then visibly corrupted a printed path.
        let corrupted = "Bastion-AI\u{8}bastion.exe";
        let sanitized = sanitize_for_display(corrupted);
        assert!(!sanitized.contains('\u{8}'));
        assert!(sanitized.contains("Bastion-AI"));
        assert!(sanitized.contains("bastion.exe"));
    }

    #[test]
    fn sanitize_leaves_ordinary_text_unchanged() {
        assert_eq!(sanitize_for_display("normal-name_123.js"), "normal-name_123.js");
    }
}
