//! SARIF 2.1.0 output for `talyx scan --format sarif`.
//!
//! SARIF (Static Analysis Results Interchange Format) is the format GitHub
//! code scanning, Azure DevOps, and most CI security dashboards ingest —
//! emitting it lets Talyx gate a pull request the same way a linter
//! or SAST tool does, without any Talyx-hosted service. The document
//! is built with `serde_json::json!` rather than typed structs: the schema
//! is broad, only a small, stable subset is used here, and the shape is
//! easier to review against the spec inline.
//!
//! Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//! Validator: https://sarifweb.azurewebsites.net/Validation

use crate::pipeline::ScannedArtifact;
use talyx_core::{ArtifactKind, Decision};
use serde_json::{json, Value};
use std::path::Path;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
// Consistent with the install scripts' default `TALYX_REPO`
// until a real repository exists.
const INFO_URI: &str = "https://github.com/rynald0cst0ltziam/talyx";

/// Build the full SARIF log for a scan result. `project_root` is used to
/// emit repository-relative `uri`s (what GitHub needs to annotate a PR);
/// anything outside it (a user-scope `~/.claude.json`) falls back to an
/// absolute `file://` URI.
pub fn build(scanned: &[ScannedArtifact], project_root: &Path) -> Value {
    let results: Vec<Value> = scanned
        .iter()
        .filter_map(|s| result_for(s, project_root))
        .collect();

    let mut kinds_present: Vec<ArtifactKind> = scanned
        .iter()
        .filter(|s| level_for(s.decision).is_some())
        .map(|s| s.artifact.kind)
        .collect();
    kinds_present.sort_by_key(|k| kind_slug(*k));
    kinds_present.dedup();
    let rules: Vec<Value> = kinds_present.iter().map(|k| rule_for(*k)).collect();

    json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Talyx",
                    "informationUri": INFO_URI,
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
        }]
    })
}

/// SARIF severity for a decision. `None` = don't emit a result for this
/// artifact (it was allowed outright).
fn level_for(decision: Decision) -> Option<&'static str> {
    match decision {
        Decision::Block | Decision::Quarantine => Some("error"),
        Decision::Ask => Some("warning"),
        Decision::AllowLog => Some("note"),
        Decision::Allow => None,
    }
}

fn kind_slug(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::McpServer => "mcp-server",
        ArtifactKind::Skill => "skill",
        ArtifactKind::Plugin => "plugin",
        ArtifactKind::Hook => "hook",
        ArtifactKind::AgentConfig => "agent-config",
        ArtifactKind::Script => "script",
        ArtifactKind::Dependency => "dependency",
        ArtifactKind::Executable => "executable",
    }
}

fn rule_for(kind: ArtifactKind) -> Value {
    let (name, short, full) = match kind {
        ArtifactKind::McpServer => (
            "RiskyMcpServer",
            "An MCP server was scored above the allowed risk threshold",
            "Talyx statically analyzed this MCP server's launch command / package / remote endpoint and its declared and inferred capabilities scored above the active protection level's threshold. Review the message for the specific evidence (secret access, outbound network, process execution, reputation).",
        ),
        ArtifactKind::Skill => (
            "RiskySkill",
            "A skill was scored above the allowed risk threshold",
            "Talyx analyzed this skill's bundled code and its SKILL.md / instruction text (prompt-injection phrasing, hidden Unicode, encoded payloads, exfiltration directives). A skill's markdown is injected directly into the agent's context, so instruction-manipulation content in it is treated as high severity.",
        ),
        ArtifactKind::Hook => (
            "RiskyHook",
            "An agent hook's command was scored above the allowed risk threshold",
            "Talyx analyzed this hook's shell command. Hooks execute automatically on agent events, so a command touching secret material or making outbound network calls is high severity.",
        ),
        ArtifactKind::AgentConfig => (
            "RiskyAgentInstructionFile",
            "An agent-instruction file contains prompt-injection or hidden content",
            "Talyx content-scanned this agent-instruction file (.cursorrules / GEMINI.md / AGENTS.md / ...). Its text is fed straight into the agent's context; instruction-override phrasing, text hidden from a human reviewer, or an exfiltration directive here is a supply-chain risk (e.g. a poisoned file committed to a shared repository).",
        ),
        _ => (
            "RiskyArtifact",
            "An agent artifact was scored above the allowed risk threshold",
            "Talyx statically analyzed this artifact and it scored above the active protection level's threshold. See the message for the specific evidence.",
        ),
    };
    json!({
        "id": format!("talyx/{}", kind_slug(kind)),
        "name": name,
        "shortDescription": { "text": short },
        "fullDescription": { "text": full },
        "helpUri": format!("{INFO_URI}/blob/main/THREAT_MODEL.md"),
        "defaultConfiguration": { "level": "warning" },
    })
}

fn result_for(s: &ScannedArtifact, project_root: &Path) -> Option<Value> {
    let level = level_for(s.decision)?;

    let reasons: Vec<&str> = s
        .breakdown
        .static_evidence_reasons
        .iter()
        .chain(s.breakdown.reputation_reasons.iter())
        .chain(s.breakdown.context_reasons.iter())
        .map(|r| r.as_str())
        .collect();
    let message = format!(
        "{} risk ({}) — {} \"{}\" via {}. {}",
        s.band,
        s.decision,
        s.artifact.kind,
        crate::sanitize_for_display(&s.artifact.name),
        s.agent_name,
        reasons.join("; ")
    );

    // Primary location: the most specific finding location if any finding
    // carries a "path:line", otherwise the artifact's own file/dir.
    let finding_locs: Vec<(String, Option<i64>)> = s
        .artifact
        .capabilities
        .iter()
        .filter_map(|f| f.location.as_deref())
        .filter_map(parse_path_line)
        .collect();

    let primary_uri;
    let primary_line;
    if let Some((p, line)) = finding_locs.first() {
        primary_uri = to_uri(Path::new(p), project_root);
        primary_line = *line;
    } else {
        primary_uri = to_uri(&artifact_path(s), project_root);
        primary_line = None;
    }

    let mut physical = json!({ "artifactLocation": { "uri": primary_uri } });
    if let Some(line) = primary_line {
        physical["region"] = json!({ "startLine": line.max(1) });
    }
    let locations = json!([{ "physicalLocation": physical }]);

    let related: Vec<Value> = finding_locs
        .iter()
        .skip(1)
        .map(|(p, line)| {
            let mut phys = json!({ "artifactLocation": { "uri": to_uri(Path::new(p), project_root) } });
            if let Some(l) = line {
                phys["region"] = json!({ "startLine": (*l).max(1) });
            }
            json!({ "physicalLocation": phys })
        })
        .collect();

    let mut result = json!({
        "ruleId": format!("talyx/{}", kind_slug(s.artifact.kind)),
        "level": level,
        "message": { "text": message },
        "locations": locations,
        "partialFingerprints": { "talyxArtifactId/v1": s.artifact.id },
        "properties": {
            "riskScore": s.breakdown.total(),
            "band": s.band.to_string(),
            "decision": s.decision.to_string(),
            "agent": s.agent_name,
        }
    });
    if !related.is_empty() {
        result["relatedLocations"] = Value::Array(related);
    }
    Some(result)
}

fn artifact_path(s: &ScannedArtifact) -> std::path::PathBuf {
    if let Some(cs) = &s.config_source {
        return cs.path.clone();
    }
    if let Some(root) = &s.scan_root {
        return root.clone();
    }
    // `location` can be "<path> (via node)" for a wrapped launch — take the
    // part before the parenthetical.
    let raw = s.location.split(" (via ").next().unwrap_or(&s.location);
    std::path::PathBuf::from(raw)
}

fn parse_path_line(loc: &str) -> Option<(String, Option<i64>)> {
    // "C:\path\file.md:12" or "/path/file.md:12" or "settings.json" (no line).
    // Split on the LAST ':' only if what follows is all digits.
    if let Some(idx) = loc.rfind(':') {
        let (path, rest) = loc.split_at(idx);
        let rest = &rest[1..];
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) && path.len() > 1 {
            return Some((path.to_string(), rest.parse().ok()));
        }
    }
    Some((loc.to_string(), None))
}

/// Repo-relative forward-slash URI when `path` is under `project_root`,
/// else an absolute `file://` URI. Strips Windows' `\\?\` extended-length
/// prefix so the two sides compare.
fn to_uri(path: &Path, project_root: &Path) -> String {
    fn strip_verbatim(s: &str) -> &str {
        s.strip_prefix(r"\\?\").unwrap_or(s)
    }
    let p = strip_verbatim(&path.to_string_lossy()).replace('\\', "/");
    let root = strip_verbatim(&project_root.to_string_lossy()).replace('\\', "/");
    let root_trimmed = root.trim_end_matches('/');

    if let Some(rel) = p.strip_prefix(root_trimmed) {
        let rel = rel.trim_start_matches('/');
        if !rel.is_empty() {
            return rel.to_string();
        }
    }
    if p.starts_with('/') {
        format!("file://{p}")
    } else {
        format!("file:///{p}")
    }
}

/// Exit code for `--exit-code`: 2 if anything is BLOCK/QUARANTINE, 1 if
/// anything is ASK, 0 otherwise. Mirrors how `grep`/`shellcheck` signal
/// "found something" to CI without the run itself being an error.
pub fn exit_code(scanned: &[ScannedArtifact]) -> i32 {
    let mut code = 0;
    for s in scanned {
        match s.decision {
            Decision::Block | Decision::Quarantine => return 2,
            Decision::Ask => code = 1,
            _ => {}
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use talyx_core::{
        Artifact, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis, PublisherIdentity,
        RiskBand, ScoreBreakdown,
    };
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn scanned(kind: ArtifactKind, name: &str, decision: Decision, band: RiskBand, loc: &str, findings: Vec<CapabilityFinding>) -> ScannedArtifact {
        let source = ArtifactSource::LocalPath(loc.to_string());
        ScannedArtifact {
            agent_name: "claude-code",
            artifact: Artifact {
                id: Artifact::compute_id(kind, name, &source),
                kind,
                name: name.to_string(),
                version: None,
                publisher: PublisherIdentity::default(),
                source,
                content_hash: None,
                capabilities: findings,
                discovered_by: BTreeSet::new(),
            },
            breakdown: ScoreBreakdown {
                static_evidence: 80,
                static_evidence_reasons: vec!["reads raw secret material AND has network access (+40)".into()],
                ..Default::default()
            },
            band,
            decision,
            location: loc.to_string(),
            launch: None,
            config_source: None,
            raw_config_entry: None,
            scan_root: Some(PathBuf::from(loc)),
            registry_fetch: None,
        }
    }

    #[test]
    fn produces_valid_top_level_shape() {
        let root = PathBuf::from("/repo");
        let items = vec![scanned(
            ArtifactKind::Skill,
            "evil",
            Decision::Block,
            RiskBand::Critical,
            "/repo/.claude/skills/evil",
            vec![CapabilityFinding {
                capability: Capability::HiddenInstructions,
                basis: EvidenceBasis::Inferred,
                evidence: "hidden text".into(),
                location: Some("/repo/.claude/skills/evil/SKILL.md:9".into()),
            }],
        )];
        let log = build(&items, &root);
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "Talyx");
        assert_eq!(run["results"].as_array().unwrap().len(), 1);
        let r = &run["results"][0];
        assert_eq!(r["level"], "error");
        assert_eq!(r["ruleId"], "talyx/skill");
        assert_eq!(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".claude/skills/evil/SKILL.md"
        );
        assert_eq!(r["locations"][0]["physicalLocation"]["region"]["startLine"], 9);
        // rule catalog carries the one kind that appeared
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "talyx/skill");
    }

    #[test]
    fn allowed_artifacts_produce_no_results() {
        let root = PathBuf::from("/repo");
        let items = vec![scanned(
            ArtifactKind::McpServer,
            "fine",
            Decision::Allow,
            RiskBand::Low,
            "/repo/.mcp.json",
            vec![],
        )];
        let log = build(&items, &root);
        assert!(log["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(log["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn out_of_tree_path_becomes_file_uri() {
        let root = PathBuf::from("/repo");
        let items = vec![scanned(
            ArtifactKind::McpServer,
            "user-scope",
            Decision::Ask,
            RiskBand::Medium,
            "/home/user/.claude.json",
            vec![],
        )];
        let log = build(&items, &root);
        let uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(uri.starts_with("file://"), "{uri}");
    }

    #[test]
    fn exit_code_reflects_worst_decision() {
        let block = scanned(ArtifactKind::Hook, "h", Decision::Block, RiskBand::Critical, "/repo/x", vec![]);
        let ask = scanned(ArtifactKind::Hook, "h", Decision::Ask, RiskBand::Medium, "/repo/x", vec![]);
        let allow = scanned(ArtifactKind::Hook, "h", Decision::Allow, RiskBand::Low, "/repo/x", vec![]);
        assert_eq!(exit_code(&[block]), 2);
        assert_eq!(exit_code(&[ask]), 1);
        assert_eq!(exit_code(&[allow]), 0);
        assert_eq!(exit_code(&[]), 0);
    }

    #[test]
    fn parse_path_line_handles_windows_and_plain() {
        assert_eq!(
            parse_path_line(r"C:\a\b.md:12"),
            Some((r"C:\a\b.md".to_string(), Some(12)))
        );
        assert_eq!(
            parse_path_line("/a/b.md:7"),
            Some(("/a/b.md".to_string(), Some(7)))
        );
        assert_eq!(
            parse_path_line("settings.json"),
            Some(("settings.json".to_string(), None))
        );
    }
}
