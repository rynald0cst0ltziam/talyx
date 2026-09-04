//! agentguard-cli — v0 entry point.
//!
//! `agentguard scan`   — discover, statically scan, and score every artifact
//!                        visible to a supported agent. Read-only.
//! `agentguard status` — short protection summary. Read-only.
//! `agentguard init`   — scan, cache decisions, AND rewrite MCP server
//!                        configs to route through the enforcement shim
//!                        (BUILD_PLAN.md §5a). The only command that writes
//!                        anything — see init.rs.
//! `agentguard allow <id>` — manually approve a flagged artifact.
//! `agentguard why <id>`   — show the full reasoning behind a cached decision.

mod init;
mod pipeline;

use agentguard_core::{Decision, ProtectionLevel, RiskBand};
use agentguard_risk::RiskEngine;
use clap::{Parser, Subcommand, ValueEnum};
use pipeline::{collect, ScannedArtifact};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "agentguard",
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
        /// ~/.agentguard/decisions.json, or $AGENTGUARD_STORE if set).
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
}

#[derive(ValueEnum, Clone, Copy)]
enum ProtectionLevelArg {
    Quiet,
    Balanced,
    Strict,
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
        Command::Scan { project, level, fetch_registry } => run_scan(&project, level.into(), fetch_registry),
        Command::Status { project } => run_status(&project),
        Command::Init {
            project,
            level,
            store,
            include_user_config,
            fetch_registry,
        } => init::run_init(&project, level.into(), store, include_user_config, fetch_registry),
        Command::Allow { artifact_id, store } => init::run_allow(&artifact_id, store),
        Command::Why { artifact_id, store } => init::run_why(&artifact_id, store),
    }
}

fn resolve_root(project: &Path) -> PathBuf {
    project.canonicalize().unwrap_or_else(|_| project.to_path_buf())
}

fn run_scan(project: &Path, level: ProtectionLevel, fetch_registry: bool) {
    let project_root = resolve_root(project);
    let engine = RiskEngine::new();
    let scanned = collect(&project_root, &engine, level, fetch_registry);

    if scanned.is_empty() {
        println!(
            "No agent artifacts found under {} (and no recognized agent config in the home directory).",
            project_root.display()
        );
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
    println!("(read-only — run `agentguard init` to also cache decisions and enable enforcement)");

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
}

fn run_status(project: &Path) {
    let project_root = resolve_root(project);
    let engine = RiskEngine::new();
    let scanned = collect(&project_root, &engine, ProtectionLevel::Balanced, false);

    println!("AgentGuard\n");

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
            "\nProtection: \u{25cf} Static scan cached in-memory only — run `agentguard init` to route {rewritable} MCP server(s) through enforcement."
        );
    } else {
        println!("\nProtection: \u{25cf} Active (static scan only — enforcement not applicable to what was found here)");
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
/// misleading ways. `agentguard why`'s underlying data (the decision
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
