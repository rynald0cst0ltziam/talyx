//! agentguard-adapters
//!
//! Per-agent discovery — BUILD_PLAN.md §9/§32. Each adapter implements
//! `AgentAdapter` and translates one agent ecosystem's on-disk config into
//! the common `Artifact` model from agentguard-core. Adapters only discover;
//! they never decide or enforce (that's agentguard-risk and the future
//! shim/daemon — see BUILD_PLAN.md §5). Keeping that boundary is what lets
//! adding a new agent stay an adapter-sized change instead of a rewrite.

pub mod claude_code;
pub mod unknown;

use agentguard_core::Artifact;
use std::path::{Path, PathBuf};

/// One artifact found by an adapter, plus enough to hand it to the scanner.
#[derive(Debug, Clone)]
pub struct DiscoveredArtifact {
    pub artifact: Artifact,
    /// A file or directory the scanner can run static analysis against.
    /// `None` when the artifact is only known by reference (e.g. an
    /// unresolved registry package we haven't fetched locally) — the risk
    /// engine still scores it, just on declared evidence alone.
    pub scan_root: Option<PathBuf>,
    /// Human-readable location for CLI/UI display even when scan_root is None.
    pub display_location: String,
}

pub trait AgentAdapter {
    /// Stable identifier stored in Artifact.discovered_by, e.g. "claude-code".
    fn agent_id(&self) -> &'static str;
    /// Human-readable name for UI, e.g. "Claude Code".
    fn agent_name(&self) -> &'static str;
    /// Cheap signal check: does this machine/project show signs of this agent?
    fn detect(&self, project_root: &Path) -> bool;
    /// Full discovery pass: enumerate MCP servers, skills, plugins, hooks,
    /// and configs this adapter knows how to find, at both project and user scope.
    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact>;
}

/// The adapters wired into this build. Order doesn't matter — the CLI runs
/// `detect` on each and only calls `discover` on matches, so adding a new
/// Tier-1/2 agent is exactly one line here plus its own module.
pub fn all_adapters() -> Vec<Box<dyn AgentAdapter>> {
    vec![
        Box::new(claude_code::ClaudeCodeAdapter),
        Box::new(unknown::UnknownAgentAdapter),
    ]
}
