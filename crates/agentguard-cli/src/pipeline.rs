//! The shared discovery -> scan -> score pipeline used by every subcommand.
//! Kept in one place so `scan`, `status`, and `init` never drift apart on
//! what counts as "found" or how it's scored.

use agentguard_adapters::{all_adapters, ConfigSource, DiscoveredArtifact, LaunchCommand};
use agentguard_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, Decision,
    ProtectionLevel, RiskBand, ScoreBreakdown,
};
use agentguard_risk::RiskEngine;
use std::path::{Path, PathBuf};

/// Location of an optional refreshed advisory feed. `AGENTGUARD_ADVISORIES`
/// overrides, else `~/.agentguard/advisories.json`. `None` (no home dir) or
/// a missing/invalid file falls back to the feed embedded in the binary —
/// see `agentguard_advisories::Advisories::load`.
pub(crate) fn advisories_file() -> Option<PathBuf> {
    std::env::var_os("AGENTGUARD_ADVISORIES")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".agentguard").join("advisories.json")))
}

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
    /// The original config entry for a remote MCP server (see
    /// agentguard-adapters' `DiscoveredArtifact::raw_config_entry` doc
    /// comment) — carried through so `init.rs` can snapshot it into the
    /// decision store for `agentguard allow` to restore from later.
    pub raw_config_entry: Option<serde_json::Value>,
    /// The directory (or file) this artifact was statically scanned from —
    /// carried through so `init.rs` can quarantine (move out of Claude
    /// Code's `.claude/skills/` tree) a Skill artifact whose decision
    /// doesn't allow it to load. `None` for artifacts with no local
    /// content (e.g. a remote MCP server).
    pub scan_root: Option<PathBuf>,
    /// Set only for an `ArtifactSource::Registry` artifact when
    /// `fetch_registry` was requested for this `collect()` call — `None`
    /// for every other artifact kind, and also `None` for a registry
    /// artifact when fetching wasn't requested at all (today's default:
    /// declared-evidence-only scoring, exactly as before this existed).
    pub registry_fetch: Option<RegistryFetchOutcome>,
}

#[derive(Debug, Clone)]
pub enum RegistryFetchOutcome {
    Fetched { resolved_version: String },
    Failed { error: String },
}

/// Runs discovery + static scan + risk scoring for every detected adapter.
/// Read-only on disk in the sense that matters for this product's safety
/// boundary: never writes the decision store or touches any agent CONFIG
/// file. `init` (in init.rs) is the only place that does that. `collect`
/// itself DOES make outbound network calls, but only when `fetch_registry`
/// is true — see `maybe_fetch_registry_package`'s doc comment for why
/// that's opt-in rather than automatic.
pub fn collect(
    project_root: &Path,
    engine: &RiskEngine,
    level: ProtectionLevel,
    fetch_registry: bool,
) -> Vec<ScannedArtifact> {
    let mut out = Vec::new();
    let advisories =
        agentguard_advisories::Advisories::load(advisories_file().as_deref());

    for adapter in all_adapters() {
        if !adapter.detect(project_root) {
            continue;
        }
        for discovered in adapter.discover(project_root) {
            let DiscoveredArtifact {
                mut artifact,
                mut scan_root,
                display_location,
                launch,
                config_source,
                raw_config_entry,
            } = discovered;

            let registry_fetch = if fetch_registry {
                maybe_fetch_registry_package(&artifact.source, &mut scan_root)
            } else {
                None
            };

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

            // Known-bad advisory feed — matched by identity (package
            // name+version, publisher, remote host, repo owner), before
            // scoring so the risk engine's KnownMalicious/KnownAdvisory
            // rules apply.
            artifact.capabilities.extend(advisories.check(
                &artifact.source,
                artifact.publisher.name.as_deref(),
                artifact.publisher.repo_url.as_deref(),
                artifact.version.as_deref(),
            ));

            let breakdown = engine.score(&artifact);
            let band = breakdown.band();
            let decision = advisory_floor(&artifact.capabilities, level.decision_for(band));

            out.push(ScannedArtifact {
                agent_name: adapter.agent_name(),
                artifact,
                breakdown,
                band,
                decision,
                location: display_location,
                launch,
                config_source,
                raw_config_entry,
                scan_root,
                registry_fetch,
            });
        }
    }

    // Cross-artifact pass: MCP tool shadowing / server-name impersonation.
    // Has to run after every server is discovered and scored (it needs
    // each one's reputation verdict), so it's a post-pass that re-scores
    // just the affected artifacts.
    apply_tool_shadowing(&mut out, engine, level);

    // Worst risk first — that's what a human should see first.
    out.sort_by_key(|s| std::cmp::Reverse(s.band));
    out
}

/// Flags an MCP server whose NAME would let it intercept the agent's tool
/// calls — sharing a name with a trusted server, or impersonating /
/// typosquatting a well-known one (`filesystem`, `github`, ...). See
/// `agentguard_scanner::shadowing`. Adds a `ToolShadowing` capability
/// finding and re-scores the artifact.
fn apply_tool_shadowing(
    out: &mut [ScannedArtifact],
    engine: &RiskEngine,
    level: ProtectionLevel,
) {
    let mcp_indices: Vec<usize> = out
        .iter()
        .enumerate()
        .filter(|(_, s)| s.artifact.kind == ArtifactKind::McpServer)
        .map(|(i, _)| i)
        .collect();
    if mcp_indices.is_empty() {
        return;
    }

    let findings = {
        let refs: Vec<agentguard_scanner::shadowing::ServerRef> = mcp_indices
            .iter()
            .map(|&i| agentguard_scanner::shadowing::ServerRef {
                name: &out[i].artifact.name,
                source: &out[i].artifact.source,
                trusted: out[i].breakdown.reputation_discount > 0,
            })
            .collect();
        agentguard_scanner::shadowing::detect_shadowing(&refs)
    };

    for (ref_idx, mut finding) in findings {
        let out_idx = mcp_indices[ref_idx];
        let s = &mut out[out_idx];
        // Give the finding a location now that we know the config file.
        finding.location = Some(s.location.clone());
        let evidence = finding.evidence.clone();
        s.artifact.capabilities.push(finding);
        let mut breakdown = engine.score(&s.artifact);
        breakdown.static_evidence_reasons.push(evidence);
        s.breakdown = breakdown;
        s.band = s.breakdown.band();
        s.decision = advisory_floor(&s.artifact.capabilities, level.decision_for(s.band));
    }
}

/// The advisory feed floors a decision by *identity*, not only by score: a
/// confirmed-malicious match (`KnownMalicious`) always BLOCKs, and a
/// bounded-advisory match (`KnownAdvisory` — a fixed CVE, a "review before
/// use") is never softer than ASK, whatever the protection level's band
/// mapping would otherwise say.
fn advisory_floor(caps: &[CapabilityFinding], decision: Decision) -> Decision {
    let has = |c: Capability| caps.iter().any(|f| f.capability == c);
    if has(Capability::KnownMalicious) {
        Decision::Block
    } else if has(Capability::KnownAdvisory) && matches!(decision, Decision::Allow | Decision::AllowLog) {
        Decision::Ask
    } else {
        decision
    }
}

/// Fetches and extracts a registry-resolved artifact's actual code so it
/// gets the same static analysis any local script does, instead of
/// declared-evidence-only scoring. A no-op for every source except
/// `ArtifactSource::Registry`.
///
/// **Why this is opt-in** (only called when `collect`'s `fetch_registry`
/// is true): every other artifact this product scores comes entirely
/// from what's already on disk — `scan`/`init` have been network-free
/// until this existed. Fetching a package means a real outbound HTTPS
/// call to the npm or PyPI registry at scan time, which changes that, so
/// it stays behind an explicit flag rather than becoming silent default
/// behavior a CI pipeline or air-gapped environment could be surprised by.
fn maybe_fetch_registry_package(
    source: &ArtifactSource,
    scan_root: &mut Option<PathBuf>,
) -> Option<RegistryFetchOutcome> {
    if !matches!(source, ArtifactSource::Registry { .. }) {
        return None;
    }
    let cache_dir = agentguard_registry::resolve_cache_dir();
    match agentguard_registry::fetch_and_extract(source, &cache_dir) {
        Ok(fetched) => {
            *scan_root = Some(fetched.extracted_dir);
            Some(RegistryFetchOutcome::Fetched { resolved_version: fetched.resolved_version })
        }
        Err(e) => Some(RegistryFetchOutcome::Failed { error: e.to_string() }),
    }
}

/// Shared by `scan` and `init`'s output — reports how many
/// registry-resolved artifacts were found and, when `fetch_registry` was
/// on, what happened to each fetch attempt.
pub fn print_registry_fetch_summary(scanned: &[ScannedArtifact], fetch_registry: bool) {
    let registry_count = scanned
        .iter()
        .filter(|s| matches!(s.artifact.source, ArtifactSource::Registry { .. }))
        .count();
    if registry_count == 0 {
        return;
    }
    if !fetch_registry {
        println!(
            "\n{registry_count} registry-resolved MCP server(s) found (npx/uvx) — scored on declared evidence only."
        );
        println!("Re-run with --fetch-registry to statically scan their actual code.");
        return;
    }

    let fetched: Vec<(&ScannedArtifact, &str)> = scanned
        .iter()
        .filter_map(|s| match &s.registry_fetch {
            Some(RegistryFetchOutcome::Fetched { resolved_version }) => Some((s, resolved_version.as_str())),
            _ => None,
        })
        .collect();
    let failed: Vec<(&ScannedArtifact, &str)> = scanned
        .iter()
        .filter_map(|s| match &s.registry_fetch {
            Some(RegistryFetchOutcome::Failed { error }) => Some((s, error.as_str())),
            _ => None,
        })
        .collect();

    if !fetched.is_empty() {
        println!("\n{} registry package(s) fetched and statically scanned:", fetched.len());
        for (s, version) in &fetched {
            println!(
                "  {}@{} — {} ({})",
                crate::sanitize_for_display(&s.artifact.name),
                crate::sanitize_for_display(version),
                s.band,
                s.decision,
            );
        }
    }
    if !failed.is_empty() {
        println!(
            "{} registry package(s) could not be fetched (declared-evidence-only scoring used instead):",
            failed.len()
        );
        for (s, error) in failed {
            println!("  {} — {error}", crate::sanitize_for_display(&s.artifact.name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::EvidenceBasis;

    fn cap(c: Capability) -> CapabilityFinding {
        CapabilityFinding {
            capability: c,
            basis: EvidenceBasis::Declared,
            evidence: "test".to_string(),
            location: None,
        }
    }

    #[test]
    fn advisory_floor_forces_block_and_ask_by_identity() {
        // KnownMalicious -> BLOCK, whatever the band mapping said.
        assert_eq!(
            advisory_floor(&[cap(Capability::KnownMalicious)], Decision::Allow),
            Decision::Block
        );
        // KnownAdvisory lifts a soft decision to ASK...
        assert_eq!(
            advisory_floor(&[cap(Capability::KnownAdvisory)], Decision::AllowLog),
            Decision::Ask
        );
        // ...but never softens an already-harder one.
        assert_eq!(
            advisory_floor(&[cap(Capability::KnownAdvisory)], Decision::Block),
            Decision::Block
        );
        // No advisory capability -> unchanged.
        assert_eq!(
            advisory_floor(&[cap(Capability::NetworkExternal)], Decision::AllowLog),
            Decision::AllowLog
        );
    }
}
