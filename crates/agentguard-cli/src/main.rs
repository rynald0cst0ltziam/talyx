//! agentguard-cli — v0 entry point.
//!
//! `agentguard scan`  — discover, statically scan, and score every artifact
//!                       visible to a supported agent under a project root.
//! `agentguard status` — short summary, matching the BUILD_PLAN.md §14 UX mock.
//!
//! This is deliberately the whole pipeline end to end (adapters → scanner →
//! risk engine → decision), wired at the smallest useful scope, per
//! BUILD_PLAN.md §16 step 4: "fastest path to a demoable 'here's everything
//! installed and its risk' CLI output." Enforcement (§5) is not implemented
//! yet — this prints decisions, it doesn't act on them.

use agentguard_adapters::{all_adapters, DiscoveredArtifact};
use agentguard_core::{Artifact, Decision, ProtectionLevel, RiskBand, ScoreBreakdown};
use agentguard_risk::RiskEngine;
use clap::{Parser, Subcommand, ValueEnum};
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
    /// Discover, scan, and score every artifact visible to a supported agent.
    Scan {
        /// Project root to scan (in addition to user-level/global config).
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Onboarding preset — see BUILD_PLAN.md §6.
        #[arg(long, value_enum, default_value = "balanced")]
        level: ProtectionLevelArg,
    },
    /// Short protection summary (agents detected, artifact counts).
    Status {
        #[arg(long, default_value = ".")]
        project: PathBuf,
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

struct ScannedArtifact {
    agent_name: &'static str,
    artifact: Artifact,
    breakdown: ScoreBreakdown,
    band: RiskBand,
    decision: Decision,
    location: String,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { project, level } => run_scan(&project, level.into()),
        Command::Status { project } => run_status(&project),
    }
}

fn resolve_root(project: &Path) -> PathBuf {
    project.canonicalize().unwrap_or_else(|_| project.to_path_buf())
}

/// Runs discovery + static scan + risk scoring for every detected adapter.
/// Shared by both subcommands so `scan` and `status` never drift apart on
/// what counts as "found."
fn collect(project_root: &Path, engine: &RiskEngine, level: ProtectionLevel) -> Vec<ScannedArtifact> {
    let mut out = Vec::new();

    for adapter in all_adapters() {
        if !adapter.detect(project_root) {
            continue;
        }
        for discovered in adapter.discover(project_root) {
            let DiscoveredArtifact {
                mut artifact,
                scan_root,
                display_location,
            } = discovered;

            if let Some(root) = &scan_root {
                if root.is_dir() {
                    let result = agentguard_scanner::scan_dir(root);
                    artifact.capabilities.extend(result.findings);
                    let pkg_json = root.join("package.json");
                    if pkg_json.exists() {
                        artifact
                            .capabilities
                            .extend(agentguard_scanner::scan_package_json(&pkg_json));
                    }
                } else if root.is_file() {
                    if let Ok(findings) = agentguard_scanner::scan_file(root) {
                        artifact.capabilities.extend(findings);
                    }
                }
            }

            let breakdown = engine.score(&artifact);
            let band = breakdown.band();
            let decision = level.decision_for(band);

            out.push(ScannedArtifact {
                agent_name: adapter.agent_name(),
                artifact,
                breakdown,
                band,
                decision,
                location: display_location,
            });
        }
    }

    // Worst risk first — that's what a human should see first.
    out.sort_by(|a, b| b.band.cmp(&a.band));
    out
}

fn run_scan(project: &Path, level: ProtectionLevel) {
    let project_root = resolve_root(project);
    let engine = RiskEngine::new();
    let scanned = collect(&project_root, &engine, level);

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
            truncate(&s.artifact.name, 30),
            s.band.to_string(),
            s.decision.to_string(),
            s.location,
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

    let flagged: Vec<&ScannedArtifact> = scanned
        .iter()
        .filter(|s| matches!(s.decision, Decision::Ask | Decision::Block | Decision::Quarantine))
        .collect();

    if !flagged.is_empty() {
        println!("\nWhy these were flagged:");
        for s in flagged {
            println!(
                "\n--- {} ({}) via {} — {} => {} ---",
                s.artifact.name, s.artifact.kind, s.agent_name, s.band, s.decision
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
    let scanned = collect(&project_root, &engine, ProtectionLevel::Balanced);

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
    println!(
        "\nCritical risk: {critical}    Blocked (Balanced preset): {blocked}"
    );
    println!("\nProtection: \u{25cf} Active (static scan only — enforcement not yet wired, see BUILD_PLAN.md \u{a7}5)");
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}\u{2026}")
    }
}
