//! talyx-risk
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

use talyx_core::{Artifact, ArtifactKind, Capability, RiskBand, ScoreBreakdown};
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
        let (mut reputation_discount, mut reputation_reasons) = self.reputation_discount(artifact);
        let (context_modifier, context_reasons) = self.context_modifier(artifact, &caps);

        // A publisher/package named in the known-bad feed as *confirmed
        // malicious* gets no reputation discount — a verified identity or a
        // trust-seeded vendor being in that feed means the account or
        // package is compromised, which is exactly when past reputation
        // stops being evidence of safety. Keeps a trusted-but-malicious
        // match decisively in Critical rather than letting -30 pull it into
        // High.
        if caps.contains(&Capability::KnownMalicious) && reputation_discount != 0 {
            reputation_discount = 0;
            reputation_reasons = vec![
                "reputation discount suppressed — this identity is named in the known-bad advisory feed as confirmed malicious (compromised account / package)".to_string(),
            ];
        }

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

        // Named in the known-bad advisory feed — matched by identity, not
        // heuristics. A confirmed in-the-wild malicious package/publisher
        // is decisive on its own; a bounded advisory (a fixed CVE, a
        // "review before use") forces at least ASK.
        if caps.contains(&Capability::KnownMalicious) {
            extra += 100;
            reasons.push(
                "matches a Talyx advisory for a confirmed malicious artifact (package / publisher / host named in the known-bad feed) — +100, forces BLOCK"
                    .to_string(),
            );
        } else if caps.contains(&Capability::KnownAdvisory) {
            extra += 30;
            reasons.push(
                "matches a Talyx advisory for a disclosed issue (e.g. a vulnerability fixed in a later version) — +30, forces review"
                    .to_string(),
            );
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

        // Content-influence findings — a prompt-layer attack in the
        // artifact's own text (a skill's SKILL.md, an agent-instruction
        // file, later an MCP tool description), detected by
        // talyx-scanner's content analysis rather than its code
        // heuristics. Scored OUTSIDE the capped OS-capability trio above:
        // that cap exists because "shell + network + writes files" is
        // normal for a legitimate dev tool and reputation is what
        // separates them — none of that reasoning applies to hidden text
        // or an instruction to ignore the system prompt, which has no
        // benign form. See Capability::is_content_influence and
        // THREAT_MODEL.md.
        if caps.contains(&Capability::HiddenInstructions) {
            extra += 45;
            reasons.push(
                "contains text hidden from a human reviewer (zero-width / bidirectional-override / Unicode-tag characters, or invisible HTML) — no legitimate reason for an instruction file to hide content (+45)"
                    .to_string(),
            );
        }
        if caps.contains(&Capability::DataExfiltrationText) {
            extra += 45;
            reasons.push(
                "instruction text directs the agent to send local secret material or context to an external destination — data-exfiltration directive (+45)"
                    .to_string(),
            );
        }
        if caps.contains(&Capability::PromptInjection) {
            extra += 30;
            reasons.push(
                "contains instruction-override / role-manipulation phrasing (\"ignore previous instructions\", \"do not tell the user\", spoofed role tags) — prompt-injection pattern (+30)"
                    .to_string(),
            );
        }
        if caps.contains(&Capability::EncodedPayload) {
            extra += 25;
            reasons.push(
                "embeds an encoded (base64 / hex / backslash-escape) payload that decodes to instructions, a URL, or shell content (+25)"
                    .to_string(),
            );
        }
        if caps.contains(&Capability::ToolShadowing) {
            extra += 30;
            reasons.push(
                "shares a name with, impersonates, or typosquats a well-known / trusted name (an MCP server, or a system command a plugin binary shadows on PATH) — a tool call or command invocation could be routed to it (+30)"
                    .to_string(),
            );
        }
        // Hidden text carrying an actual manipulation/exfiltration payload
        // is the canonical prompt-injection-via-skill shape — push it
        // unambiguously into CRITICAL rather than leaving it at the
        // High/Critical boundary.
        if caps.contains(&Capability::HiddenInstructions)
            && (caps.contains(&Capability::PromptInjection)
                || caps.contains(&Capability::DataExfiltrationText))
        {
            extra += 25;
            reasons.push(
                "hidden text AND an instruction-manipulation / exfiltration payload together — the canonical prompt-injection-via-instruction-file pattern (+25)"
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
                // Exact match, not substring. A substring match here would
                // be typosquat-exploitable: "linear" as a matcher would
                // also match a publisher name like
                // "totally-fake-linear-stealer" and grant it the same
                // reputation discount as the real thing. Publisher names
                // are already normalized to a specific identity (an npm
                // scope, a git host owner, or a registrable domain — see
                // talyx-adapters' guess_publisher/
                // extract_git_host_owner/host_registrable_domain), so
                // exact-matching against that normalized value is both
                // safer and sufficient.
                if name_lower == entry.matcher.to_lowercase() {
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
    use talyx_core::{
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
            Some("modelcontextprotocol"),
            false,
            &[
                Capability::ExecuteShell,
                Capability::NetworkExternal,
                Capability::ApiKeys,
            ],
        );
        let breakdown = engine.score(&artifact);
        // 10 (shell) + 25 (secret) + 15 (network) = 50, capped at 40 per
        // BUILD_PLAN.md §4, minus the trust-seed discount for the verified
        // "modelcontextprotocol" npm scope (30) => 10, LOW. This is the
        // exact scenario the original plan's uncapped/no-reputation
        // scoring got wrong (flagged an official reference MCP server as
        // HIGH).
        assert_eq!(breakdown.static_evidence, 40);
        assert_eq!(breakdown.reputation_discount, 30);
        assert_eq!(breakdown.total(), 10);
        assert_eq!(breakdown.band(), RiskBand::Low);
    }

    #[test]
    fn newly_seeded_vendors_score_low_and_their_lookalikes_do_not() {
        // Regression test for the 2026-09-05 trust-seed expansion (Slack,
        // HubSpot, Supabase, Neon, X, AWS) -- proves the entries actually
        // load from data/trust_seed.json and discount correctly, and that
        // a domain merely resembling one of them gets nothing. `api.aws`
        // is the interesting case: it's the registrable-domain heuristic's
        // output for AWS's real region-scoped host
        // (aws-mcp.us-east-1.api.aws), not a generic two-label domain like
        // stripe.com -- worth locking in since a future refactor of
        // host_registrable_domain could silently break this specific
        // trust anchor without an obvious test failure elsewhere.
        let engine = RiskEngine::new();
        for verified_publisher in ["slack.com", "hubspot.com", "supabase.com", "neon.tech", "x.com", "api.aws"] {
            let artifact = artifact_with(
                ArtifactKind::McpServer,
                Some(verified_publisher),
                false,
                &[Capability::NetworkExternal, Capability::ApiKeys],
            );
            let breakdown = engine.score(&artifact);
            assert_eq!(
                breakdown.reputation_discount, 30,
                "{verified_publisher} should get the full verified-vendor discount"
            );
            assert_eq!(breakdown.band(), RiskBand::Low, "{verified_publisher} should score LOW");
        }

        // Simulates the publisher talyx-adapters' host_registrable_domain
        // would actually derive for a lookalike host like
        // "aws-mcp.us-east-1.api-aws.example.com" (last two dot-labels:
        // "example.com", NOT "api.aws" -- the hyphen means it's a
        // different label, not a subdomain of the real thing).
        let lookalike = artifact_with(
            ArtifactKind::McpServer,
            Some("example.com"),
            false,
            &[Capability::NetworkExternal, Capability::ApiKeys],
        );
        let breakdown = engine.score(&lookalike);
        assert_eq!(breakdown.reputation_discount, 0);
        assert_eq!(breakdown.band(), RiskBand::Medium);
    }

    #[test]
    fn reputation_match_is_exact_not_substring() {
        // A publisher name that merely CONTAINS a trusted matcher must not
        // get the discount -- otherwise "totally-fake-linear-app-stealer"
        // would ride on "linear.app"'s reputation. Security-relevant fix,
        // not a style preference: see reputation_discount's doc comment.
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::McpServer,
            Some("totally-fake-linear.app-stealer"),
            false,
            &[Capability::ExecuteShell, Capability::NetworkExternal],
        );
        let breakdown = engine.score(&artifact);
        assert_eq!(
            breakdown.reputation_discount, 0,
            "a publisher name containing a trusted matcher as a substring must not match"
        );
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
    fn skill_with_hidden_instructions_and_injection_is_critical_block() {
        // The Phase-1 content-scanner shape: a skill whose SKILL.md hides
        // an "ignore previous instructions" payload in zero-width / Unicode
        // -tag characters. HiddenInstructions (+45) + PromptInjection (+30)
        // + the together-bonus (+25) = 100 -> CRITICAL -> BLOCK on every
        // preset. No OS capability required — this is a pure prompt-layer
        // attack.
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::Skill,
            None,
            false,
            &[Capability::HiddenInstructions, Capability::PromptInjection],
        );
        let breakdown = engine.score(&artifact);
        assert_eq!(breakdown.total(), 100);
        assert_eq!(breakdown.band(), RiskBand::Critical);
        assert_eq!(
            ProtectionLevel::Balanced.decision_for(breakdown.band()),
            Decision::Block
        );
    }

    #[test]
    fn agent_instruction_file_with_exfiltration_directive_is_high_or_critical() {
        // A poisoned `.cursorrules` / GEMINI.md committed to a shared repo:
        // prose telling the agent to send ~/.aws/credentials to an external
        // URL. DataExfiltrationText alone is +45 -> MEDIUM; with the
        // PromptInjection phrasing that usually accompanies it, +75 -> HIGH
        // -> BLOCK under Strict, ASK under Balanced.
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::AgentConfig,
            None,
            false,
            &[Capability::DataExfiltrationText, Capability::PromptInjection],
        );
        let breakdown = engine.score(&artifact);
        assert!(breakdown.total() >= 50, "got {}", breakdown.total());
        assert!(breakdown.band() >= RiskBand::High);
    }

    #[test]
    fn encoded_payload_alone_is_medium_not_critical() {
        // A base64 blob that decodes to something suspicious is a signal,
        // not a conviction on its own (+25 -> LOW/MEDIUM boundary). It
        // should not auto-BLOCK without corroboration.
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::Skill,
            None,
            false,
            &[Capability::EncodedPayload],
        );
        let breakdown = engine.score(&artifact);
        assert_eq!(breakdown.total(), 25);
        assert_eq!(breakdown.band(), RiskBand::Medium);
    }

    #[test]
    fn tool_shadowing_lifts_an_otherwise_low_mcp_server_to_medium() {
        // An unverified MCP server whose name shadows / impersonates a
        // trusted one (STATUS.md #44). +30, in the content-influence
        // group — enough to surface it for review, not enough to
        // auto-block a possibly-legit dual config.
        let engine = RiskEngine::new();
        let artifact = artifact_with(
            ArtifactKind::McpServer,
            None,
            false,
            &[Capability::SpawnProcess, Capability::ToolShadowing],
        );
        let breakdown = engine.score(&artifact);
        assert_eq!(breakdown.total(), 40); // 10 (spawn) + 30 (shadowing)
        assert_eq!(breakdown.band(), RiskBand::Medium);
    }

    #[test]
    fn benign_skill_with_no_content_findings_stays_low() {
        let engine = RiskEngine::new();
        let artifact = artifact_with(ArtifactKind::Skill, None, false, &[]);
        let breakdown = engine.score(&artifact);
        assert_eq!(breakdown.band(), RiskBand::Low);
    }

    #[test]
    fn advisory_feed_capabilities_drive_the_score() {
        let engine = RiskEngine::new();

        // A confirmed-malicious identity match is decisive on its own —
        // +100 pushes any artifact past the Critical threshold (80).
        let malicious =
            artifact_with(ArtifactKind::McpServer, None, false, &[Capability::KnownMalicious]);
        let b = engine.score(&malicious);
        assert!(b.total() >= 100);
        assert_eq!(b.band(), RiskBand::Critical);

        // A bounded advisory adds +30 without being decisive by itself.
        let advisory =
            artifact_with(ArtifactKind::McpServer, None, false, &[Capability::KnownAdvisory]);
        let b = engine.score(&advisory);
        assert_eq!(b.total(), 30);
        assert_eq!(b.band(), RiskBand::Medium);

        // Even a trust-seeded publisher can't discount a malicious match
        // below Critical.
        let trusted_but_malicious = artifact_with(
            ArtifactKind::McpServer,
            Some("modelcontextprotocol"),
            false,
            &[Capability::KnownMalicious],
        );
        assert_eq!(engine.score(&trusted_but_malicious).band(), RiskBand::Critical);
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
