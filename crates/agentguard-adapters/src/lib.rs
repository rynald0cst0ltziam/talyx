//! agentguard-adapters
//!
//! Per-agent discovery — BUILD_PLAN.md §9/§32. Each adapter implements
//! `AgentAdapter` and translates one agent ecosystem's on-disk config into
//! the common `Artifact` model from agentguard-core. Adapters only discover;
//! they never decide or enforce (that's agentguard-risk and the future
//! shim/daemon — see BUILD_PLAN.md §5). Keeping that boundary is what lets
//! adding a new agent stay an adapter-sized change instead of a rewrite.

pub mod claude_code;
pub mod cursor;
mod mcp_config;
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
    /// The original (command, args) this artifact is launched with, when it
    /// has a single fixed launch command (currently: MCP servers). This is
    /// what `agentguard init` needs to rewrite a config entry to route
    /// through the enforcement shim while preserving the real launch.
    /// `None` for artifacts with no single subprocess launch (skills,
    /// unresolved registry packages, config-file fingerprints).
    pub launch: Option<LaunchCommand>,
    /// Where this artifact's launch is declared, and enough to find and
    /// rewrite that exact entry again. `None` when not rewritable — either
    /// there's no `launch` at all, or the adapter doesn't yet support
    /// rewriting this config shape (see `ConfigSourceKind`'s doc comment).
    pub config_source: Option<ConfigSource>,
}

#[derive(Debug, Clone)]
pub struct LaunchCommand {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ConfigSource {
    pub path: PathBuf,
    pub kind: ConfigSourceKind,
    /// The key identifying this entry within the config (e.g. the
    /// `mcpServers` object key) — enough for the rewriter to find and
    /// replace just this one entry, leaving the rest of the file untouched.
    pub entry_key: String,
}

/// The config shapes `agentguard init` knows how to rewrite. Deliberately
/// an enum, not a trait/callback, so the rewrite logic stays centralized
/// and auditable in one place (agentguard-cli) rather than scattered across
/// adapters — a config rewriter is a much more sensitive piece of code than
/// a discovery-only adapter, and it's worth the extra friction of adding a
/// variant here + a match arm in the CLI for each new rewritable shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSourceKind {
    /// A `{ "mcpServers": { "<entry_key>": { command, args, env } } }` file
    /// — `.mcp.json` (project scope) or `~/.claude.json` (user scope) as of
    /// this writing. See claude_code.rs's module doc comment for the same
    /// caveat about this shape changing across Claude Code versions.
    ClaudeCodeMcpServersJson,
    /// Same `mcpServers` JSON shape as above, but Cursor's own config
    /// files — `.cursor/mcp.json` (project scope) or `~/.cursor/mcp.json`
    /// (user scope) as of this writing. Kept as a distinct variant even
    /// though the shape is identical today: the two configs are physically
    /// separate files that could diverge in format over time, and treating
    /// them as one thing here would undo the "adding a variant forces a
    /// deliberate decision" property this enum exists for.
    CursorMcpJson,
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
        Box::new(cursor::CursorAdapter),
        Box::new(unknown::UnknownAgentAdapter),
    ]
}
