//! Unknown Agent Mode — BUILD_PLAN.md §14/§33 (kept from the original
//! product spec: "we protect your environment even if we don't know the
//! agent yet"). v0 implements the honest floor of that promise: recognize
//! the generic fingerprints most agent CLIs leave behind (a rules/config
//! file, a skills directory) even without a dedicated adapter, and surface
//! that something is present rather than staying silent.
//!
//! There's no *enforcement* point for an agent Talyx doesn't
//! understand (nothing to rewrite, no shim to route through), so this mode
//! stays discovery-first — its job is that `talyx status` can say
//! "found signs of an unrecognized agent" instead of "found nothing." But
//! a generic marker that is a single instruction FILE (`AGENTS.md`,
//! `.clinerules`, `.github/copilot-instructions.md`, ...) IS content-
//! scanned now: its prose feeds the same prompt-injection / hidden-Unicode
//! / encoded-payload analysis a skill's SKILL.md does (talyx-scanner's
//! content.rs), because a poisoned instruction file is a real risk whether
//! or not we recognize the agent that reads it. Directory markers stay
//! visibility-only.

use crate::{AgentAdapter, DiscoveredArtifact};
use talyx_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use std::collections::BTreeSet;
use std::path::Path;

/// Filenames/directories that, in practice, mean "some AI coding agent
/// configures itself here" even when we don't have a dedicated adapter for
/// that agent. Extend this list opportunistically — it's cheap to maintain
/// and each entry improves the "we see you" floor for a new ecosystem.
/// Remove an entry the moment a dedicated adapter picks it up (as
/// `.cursorrules` did when cursor.rs landed) — otherwise it gets reported
/// twice, once by the real adapter and once here, which looked like a bug
/// (and would have been confusing) the first time this was actually run.
const GENERIC_MARKERS: &[&str] = &[
    ".clinerules",
    ".continuerules",
    ".zedrules",
    ".mcprules",
    "AGENTS.md",
    "CONVENTIONS.md",
    ".goose",
    ".opencode",
    ".openhands",
    ".devin",
    ".github/copilot-instructions.md",
];

pub struct UnknownAgentAdapter;

impl AgentAdapter for UnknownAgentAdapter {
    fn agent_id(&self) -> &'static str {
        "unknown-agent"
    }

    fn agent_name(&self) -> &'static str {
        "Unrecognized agent"
    }

    /// Always report as "present" — this adapter's job is to run
    /// unconditionally after the named adapters and report only markers
    /// none of them already claimed, not to gate itself behind detection.
    fn detect(&self, _project_root: &Path) -> bool {
        true
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        for marker in GENERIC_MARKERS {
            let path = project_root.join(marker);
            if path.exists() {
                let source = ArtifactSource::LocalPath(path.display().to_string());
                let mut discovered_by = BTreeSet::new();
                discovered_by.insert("unknown-agent".to_string());
                let artifact = Artifact {
                    id: Artifact::compute_id(ArtifactKind::AgentConfig, marker, &source),
                    kind: ArtifactKind::AgentConfig,
                    name: (*marker).to_string(),
                    version: None,
                    publisher: PublisherIdentity::default(),
                    source,
                    content_hash: None,
                    capabilities: vec![],
                    discovered_by,
                };
                let scan_root = path.is_file().then(|| path.clone());
                out.push(DiscoveredArtifact {
                    display_location: path.display().to_string(),
                    scan_root,
                    artifact,
                    launch: None,
                    config_source: None,
                    raw_config_entry: None,
                });
            }
        }
        out
    }
}
