//! agentguard-risk
//!
//! Implements the scoring formula from BUILD_PLAN.md §4:
//! `riskScore = staticEvidence (capped) - reputationDiscount + contextModifier`
//! followed by band mapping (core::RiskBand) and policy mapping
//! (core::ProtectionLevel::decision_for). Every contributing term is
//! recorded in the returned ScoreBreakdown — nothing here should ever
//! surface a bare number to a user without this trail attached (that's the
//! "View why" requirement from the original product spec).
//!
//! v0 trust seed is embedded from data/trust_seed.json — a small, honestly
//! incomplete stand-in for the pre-launch ecosystem scan described in
//! BUILD_PLAN.md §7. Do not treat the discounts here as tuned; they exist to
//! prove the mechanism, not as a finished reputation dataset.

use agentguard_core::{Artifact, ArtifactKind, Capability, RiskBand, ScoreBreakdown};
use serde::Deserialize;

const TRUST_SEED_JSON: &str = include_str!("../../../data/trust_seed.json");

#[derive(Debug, Deserialize)]
struct TrustSeedFile {
    publishers: Vec<TrustEntry>,
}

#[derive(Debug, Deserialize)]
struct TrustEntry {
    #[serde(rename = "match")]
    matcher: String,
    discount: i32,
    #[allow(dead_code)]
    note: String,
}

pub struct RiskEngine {
    trust: Vec<TrustEntry>,
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskEngine {
    pub fn new() -> Self {
        let parsed: TrustSeedFile =
            serde_json::from_str(TRUST_SEED_JSON).expect("embedded trust_seed.json is valid");
        Self {
            trust: parsed.publishers,
        }
    }

    pub fn score(&self, artifact: &Artifact) -> ScoreBreakdown {
        let caps = artifact.capability_set();

        let (static_evidence, static_evidence_reasons) = self.static_evidence(&caps);
        let (reputation_discount, reputation_reasons) = self.reputation_discount(artifact);
        let (context_modifier, context_reasons) = self.context_modifier(artifact, &caps);

        ScoreBreakdown {
            static_evidence,
            static_evidence_reasons,
            reputation_discount,
            reputation_reasons,
            context_modifier,
            context_reasons,
            policy_override: None,
        }
    }

    /// BUILD_PLAN.md §4 "Static evidence — capped, not additive to infinity".
    fn static_evidence(
        &self,
        caps: &std::collections::BTreeSet<Capability>,
    ) -> (i32, Vec<String>) {
        let mut capped = 0;
        let mut reasons = Vec::new();

        if caps.iter().any(|c| c.is_process_execution()) {
            capped += 10;
            reasons.push("executes shell commands / spawns processes (+10)".to_string());
        }
        if caps.iter().any(|c| c.is_secret_access()) {
            capped += 25;
            reasons.push("accesses credentials or secret material (+25)".to_string());
        }
        if caps.contains(&Capability::NetworkExternal) || caps.contains(&Capability::NetworkUnrestricted)
        {
            capped += 15;
            reasons.push("makes external network calls (+15)".to_string());
        }
        if caps.contains(&Capability::WriteHome) {
            capped += 20;
            reasons.push("writes outside the workspace (+20)".to_string());
        }
        let capped = capped.min(40);
        if capped == 40 {
            reasons.push("(capped at 40 — combination of the above is common for legitimate dev tools; reputation is what separates them, not raw capability count)".to_string());
        }

        let mut extra = 0;
        if caps.contains(&Capability::InstallPackage) {
            extra += 20;
            reasons.push("installs/downloads packages at runtime (+20)".to_string());
        }

        // The canonical exfiltration pattern — reading raw secret material
        // (an SSH key, stored OS/browser credentials) combined with any
        // outbound network capability. Deliberately NOT part of the capped
        // sum above: unlike an API key being sent to its own service, there
        // is no ordinary workflow where this combination is expected, so it
        // should never be softened by the "this is normal for a dev tool"
        // cap. See Capability::is_raw_secret_material's doc comment for why
        // this exists as its own rule.
        let has_network = caps.contains(&Capability::NetworkExternal)
            || caps.contains(&Capability::NetworkUnrestricted)
            || caps.contains(&Capability::NetworkLocal);
        if caps.iter().any(|c| c.is_raw_secret_material()) && has_network {
            extra += 40;
            reasons.push(
                "reads raw secret material (SSH keys / stored credentials / browser data) AND has network access — the canonical exfiltration pattern (+40, not subject to the cap above)"
                    .to_string(),
            );
        }

        (capped + extra, reasons)
    }

    /// BUILD_PLAN.md §4 "Reputation discount". Cold start (first-seen,
    /// unverified) is neutral — 0, not a penalty — per BUILD_PLAN.md §5
    /// ("cold start is neutral, not guilty").
    fn reputation_discount(&self, artifact: &Artifact) -> (i32, Vec<String>) {
        if artifact.publisher.verified {
            return (
                30,
                vec!["publisher identity is verified (-30)".to_string()],
            );
        }
        if let Some(name) = &artifact.publisher.name {
            let name_lower = name.to_lowercase();
            for entry in &self.trust {
                if name_lower.contains(&entry.matcher) {
                    return (
                        entry.discount,
                        vec![format!(
                            "publisher matches trust-seed entry '{}' (-{})",
                            entry.matcher, entry.discount
                        )],
                    );
                }
            }
        }
        (
            0,
            vec!["first-seen artifact, no reputation history yet (neutral — no discount, no penalty)".to_string()],
        )
    }

    /// BUILD_PLAN.md §4 "Context modifiers" — v0 implements the clearest
    /// case (archetype A4 in THREAT_MODEL.md: capability creep relative to
    /// declared artifact kind). Richer category-vs-capability matching is
    /// future work once artifacts carry a declared purpose/category field.
    fn context_modifier(
        &self,
        artifact: &Artifact,
        caps: &std::collections::BTreeSet<Capability>,
    ) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut reasons = Vec::new();

        if artifact.kind == ArtifactKind::Skill {
            if caps.iter().any(|c| c.is_secret_access()) {
                score += 20;
                reasons.push(
                    "a Skill (typically prompt/markdown-only) requests secret-access capabilities — unusual for this artifact kind (+20)"
                        .to_string(),
                );
            }
            if caps.contains(&Capability::ExecuteShell) {
                score += 10;
                reasons.push(
                    "a Skill requests shell execution — unusual for this artifact kind (+10)"
                        .to_string(),
                );
            }
        }

        (score, reasons)
    }
}

pub fn band_for(breakdown: &ScoreBreakdown) -> RiskBand {
    breakdown.band()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::{
        ArtifactSource, CapabilityFinding, Decision, EvidenceBasis, ProtectionLevel,
        PublisherIdentity,
    };
    use std::collections::BTreeSet;

    fn artifact_with(
        kind: ArtifactKind,
        publisher_name: Option<&str>,
        verified: bool,
        caps: &[Capability],
    ) -> Artifact {
        let source = ArtifactSource::LocalPath("test".to_string());
        Artifact {
            id: Artifact::compute_id(kind, "test-artifact", &source),
            kind,
            name: "test-artifact".to_string(),
            version: Some("1.0.0".to_string()),
            publisher: PublisherIdentity {
                name: publisher_name.map(|s| s.to_string()),
                repo_url: None,
                verified,
            },
            source,
            content_hash: None,
            capabilities: caps
                .iter()
                .map(|c| CapabilityFinding {
                    capability: *c,
                    basis: EvidenceBasis::Inferred,
                    evidence: "test".to_string(),
                    location: None,
                })
                .collect(),
            discovered_by: BTreeSet::new(),
        }
    }

    #[test]
    fn known_verified_publisher_scores_low_despite_broad_capabilities() {
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::McpServer,
            Some("github"),
            false,
            &[
                Capability::ExecuteShell,
                Capability::NetworkExternal,
                Capability::ApiKeys,
            ],
        );
        let breakdown = engine.score(&artifact);
        // 10 (shell) + 25 (secret) + 15 (network) = 50, capped at 40 per
        // BUILD_PLAN.md §4, minus the trust-seed discount for "github" (35)
        // => 5, LOW. This is the exact scenario the original plan's
        // uncapped/no-reputation scoring got wrong (flagged the official
        // GitHub MCP as HIGH).
        assert_eq!(breakdown.static_evidence, 40);
        assert_eq!(breakdown.reputation_discount, 35);
        assert_eq!(breakdown.total(), 5);
        assert_eq!(breakdown.band(), RiskBand::Low);
    }

    #[test]
    fn unknown_publisher_same_capabilities_scores_higher() {
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::McpServer,
            Some("totally-random-repo-42"),
            false,
            &[
                Capability::ExecuteShell,
                Capability::NetworkExternal,
                Capability::ApiKeys,
            ],
        );
        let breakdown = engine.score(&artifact);
        // Same capped evidence (40), but no reputation match => no discount.
        // Notably higher than the verified-publisher case above, despite
        // identical capabilities — that gap is the whole point of §4.
        assert_eq!(breakdown.static_evidence, 40);
        assert_eq!(breakdown.reputation_discount, 0);
        assert_eq!(breakdown.total(), 40);
        assert_eq!(breakdown.band(), RiskBand::Medium);
    }

    #[test]
    fn skill_requesting_ssh_keys_is_flagged_by_context_modifier() {
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::Skill,
            None,
            false,
            &[Capability::SshKeys, Capability::NetworkExternal],
        );
        let breakdown = engine.score(&artifact);
        // 25 (secret, capped-trio) + 15 (network, capped-trio) = 40, plus
        // +40 uncapped for the raw-secret-material + network exfiltration
        // pattern (SshKeys qualifies), plus +20 context (a Skill wanting
        // secrets) = 100 -> CRITICAL. Under the Balanced preset this is an
        // automatic BLOCK, matching the product's "critical activity: 0
        // interactions" principle for exactly this shape of artifact.
        assert_eq!(breakdown.total(), 100);
        assert_eq!(breakdown.band(), RiskBand::Critical);
        assert_eq!(
            ProtectionLevel::Balanced.decision_for(breakdown.band()),
            Decision::Block
        );
    }

    #[test]
    fn ssh_key_exfiltration_pattern_is_auto_blocked_even_on_first_sight() {
        // The flagship scenario from BUILD_PLAN.md §12 / THREAT_MODEL.md
        // archetype A1: an unverified, never-before-seen artifact that
        // reads an SSH private key and makes an external network call.
        // This must land at CRITICAL/BLOCK with zero reputation history —
        // waiting for "enough sightings" defeats the point for a
        // credential-exfiltration payload, which by definition is often
        // seen for the first time on the machine it's attacking.
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::McpServer,
            None,
            false,
            &[
                Capability::ExecuteShell,
                Capability::SpawnProcess,
                Capability::ReadSsh,
                Capability::NetworkExternal,
                Capability::EnvironmentVariables,
            ],
        );
        let breakdown = engine.score(&artifact);
        assert_eq!(breakdown.band(), RiskBand::Critical);
        assert_eq!(
            ProtectionLevel::Balanced.decision_for(breakdown.band()),
            Decision::Block
        );
    }

    #[test]
    fn cold_start_is_neutral_not_penalized() {
        let engine = RiskEngine::new();
        let artifact = artifact_with(ArtifactKind::McpServer, None, false, &[]);
        let breakdown = engine.score(&artifact);
        assert_eq!(breakdown.reputation_discount, 0);
        assert_eq!(breakdown.total(), 0);
        assert_eq!(breakdown.band(), RiskBand::Low);
    }
}
