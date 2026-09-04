//! The shared discovery -> scan -> score pipeline used by every subcommand.
//! Kept in one place so `scan`, `status`, and `init` never drift apart on
//! what counts as "found" or how it's scored.

use agentguard_adapters::{all_adapters, ConfigSource, DiscoveredArtifact, LaunchCommand};
use agentguard_core::{Artifact, ArtifactKind, Decision, ProtectionLevel, RiskBand, ScoreBreakdown};
use agentguard_risk::RiskEngine;
use std::path::Path;

pub struct ScannedArtifact {
    pub agent_name: &'static str,
    pub artifact: Artifact,
    pub breakdown: ScoreBreakdown,
    pub band: RiskBand,
    pub decision: Decision,
    pub location: String,
    /// Present only for artifacts with a single fixed launch command
    /// (currently: MCP servers) — see agentguard-adapters' doc comment on
    /// `DiscoveredArtifact`.
    pub launch: Option<LaunchCommand>,
    pub config_source: Option<ConfigSource>,
}

/// Runs discovery + static scan + risk scoring for every detected adapter.
/// Read-only: never writes the decision store or touches any agent config
/// on disk. `init` (in init.rs) is the only place that mutates anything.
pub fn collect(
    project_root: &Path,
    engine: &RiskEngine,
    level: ProtectionLevel,
) -> Vec<ScannedArtifact> {
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
                launch,
                config_source,
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
                // Feeds drift detection (init.rs) — None for artifacts with
                // no scan_root (e.g. an unresolved registry package),
                // which is a real, documented limitation: those can't be
                // drift-checked until BUILD_PLAN.md §7's ecosystem scan
                // gives us something to hash.
                artifact.content_hash = agentguard_scanner::hash_path(root);
            }

            // Hooks have no scan_root (their "content" is a config value,
            // not a file) but their command is still inspectable text —
            // scan it the same way a script's contents get scanned, so
            // hook risk scoring reflects what the hook actually does
            // instead of always landing on the flat declared baseline
            // (Hook + ExecuteShell) regardless of content. Also hashed
            // here for the same reason a script file is hashed: without
            // it, drift detection (init.rs) has no baseline to compare a
            // changed hook command against.
            if artifact.kind == ArtifactKind::Hook {
                if let Some(l) = &launch {
                    artifact.capabilities.extend(agentguard_scanner::scan_shell_command(
                        &l.command,
                        &display_location,
                    ));
                    artifact.content_hash = Some(agentguard_scanner::hash_text(&l.command));
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
                launch,
                config_source,
            });
        }
    }

    // Worst risk first — that's what a human should see first.
    out.sort_by(|a, b| b.band.cmp(&a.band));
    out
}
