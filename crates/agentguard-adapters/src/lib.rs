//! agentguard-adapters
//!
//! Per-agent discovery — BUILD_PLAN.md §9/§32. Each adapter implements
//! `AgentAdapter` and translates one agent ecosystem's on-disk config into
//! the common `Artifact` model from agentguard-core. Adapters only discover;
//! they never decide or enforce (that's agentguard-risk and the future
//! shim/daemon — see BUILD_PLAN.md §5). Keeping that boundary is what lets
//! adding a new agent stay an adapter-sized change instead of a rewrite.

pub mod antigravity;
pub mod claude_code;
pub mod codex;
pub mod cursor;
pub mod gemini_cli;
pub mod github_copilot_cli;
mod hooks_config;
mod mcp_config;
pub mod unknown;
pub mod vscode_copilot;
pub mod windsurf;

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
    /// The complete original config entry (the JSON object / TOML table
    /// for this one server), captured as `serde_json::Value` regardless of
    /// source format — `toml::Value` round-trips through it cleanly via
    /// `serde_json::to_value`. Only populated for remote (`ArtifactSource::
    /// RemoteUrl`) MCP servers, which have no local process for the shim to
    /// wrap: enforcement for those means removing the entry from the
    /// config entirely when blocked, and this snapshot is what `agentguard
    /// allow` restores from — a removed entry is invisible to future
    /// discovery, so without a saved copy there'd be nothing to restore
    /// once the config no longer contains it.
    pub raw_config_entry: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchCommand {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A Claude Code `settings.json` hooks entry — nested under
    /// `hooks.<EventName>[].hooks[].command`, a single shell-command
    /// STRING (not an argv array; Claude Code's own docs show shell
    /// variable expansion like `$CLAUDE_PROJECT_DIR` inside it, confirming
    /// it runs through a real shell, unlike an MCP server's `command` +
    /// `args`). `entry_key` for this kind is `"hook-<index>"`, the same
    /// stable traversal-order index used to build the artifact id in
    /// claude_code.rs's `parse_hooks` — the rewrite step in
    /// agentguard-cli's init.rs walks the tree in that identical order to
    /// find the matching occurrence, since there's no flat map key to
    /// look up the way there is for `mcpServers`.
    ClaudeCodeHooksJson,
    /// A Codex CLI `[mcp_servers.<entry_key>]` table in `config.toml` —
    /// `.codex/config.toml` (project scope, trusted projects only) or
    /// `~/.codex/config.toml` (user scope) as of this writing. TOML, not
    /// JSON — a structurally different file format from the other three
    /// variants (verified against OpenAI's own docs), so it gets its own
    /// parser (codex.rs) rather than reusing mcp_config.rs, even though
    /// the underlying command/args/env concept per server is the same.
    CodexMcpServersToml,
    /// Same `mcpServers` JSON shape again, but Windsurf's own config file
    /// — `~/.codeium/windsurf/mcp_config.json`, user scope ONLY. Verified
    /// 2026-09-05 against Windsurf's own docs (docs.windsurf.com/windsurf/
    /// cascade/mcp, which as of this writing redirects to
    /// docs.devin.ai/desktop/cascade/mcp — Windsurf was acquired by
    /// Cognition/Devin; the config path and JSON shape are unchanged by
    /// the rebrand, confirmed directly, not assumed): unlike Claude Code/
    /// Cursor/Codex, Windsurf does NOT support a project-scoped copy —
    /// every server is configured globally, so `windsurf.rs` never looks
    /// for a `.windsurf/mcp_config.json` project file at all, on purpose.
    WindsurfMcpJson,
    /// Same `mcpServers` JSON shape again, but Google Antigravity's config
    /// files — `~/.gemini/config/mcp_config.json` (user/global scope) or
    /// `.agents/mcp_config.json` (project scope) as of this writing.
    /// Verified 2026-09-05 against antigravity.google/docs/mcp/. Distinct
    /// from Gemini CLI's own config (a different tool, different path,
    /// not covered by this adapter) despite sharing the `~/.gemini/`
    /// directory name — worth calling out since guessing the two were
    /// the same thing would have been an easy, wrong assumption.
    AntigravityMcpJson,
    /// Same `mcpServers` JSON shape again, but Gemini CLI's own
    /// `settings.json` — `.gemini/settings.json` (project scope) or
    /// `~/.gemini/settings.json` (user scope) as of this writing.
    /// Verified 2026-09-05 against google-gemini/gemini-cli's own docs
    /// (github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-
    /// server.md). `settings.json` carries other Gemini CLI settings
    /// alongside `mcpServers` — irrelevant here, since parsing only ever
    /// looks at that one key. Distinct from Antigravity's config despite
    /// sharing a `~/.gemini/` parent directory — see
    /// `AntigravityMcpJson`'s doc comment.
    GeminiCliSettingsJson,
    /// GitHub Copilot CLI's own config — `.mcp.json` (project root) is
    /// deliberately NOT covered by this variant: verified 2026-09-05 that
    /// `docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/
    /// add-mcp-servers` documents Copilot CLI reading the SAME `.mcp.json`
    /// Claude Code's adapter already discovers (`ClaudeCodeMcpServersJson`
    /// above) — adding a second path check for the identical file would
    /// double-report every entry in it (the same class of bug this
    /// codebase already found and fixed once for `.cursorrules`). This
    /// variant covers only `.github/mcp.json`, Copilot CLI's OTHER,
    /// non-shared config location, same `{ "mcpServers": {...} }` shape.
    GitHubCopilotCliMcpJson,
    /// VS Code's Copilot Chat extension — `.vscode/mcp.json`, workspace
    /// scope. Verified 2026-09-05 against code.visualstudio.com/docs/
    /// agents/reference/mcp-configuration: the top-level key is
    /// `"servers"`, NOT `"mcpServers"` — a genuinely different key name
    /// from every other variant here, not just a different file path
    /// (see `parse_mcp_servers_json`'s `top_level_key` parameter, added
    /// specifically to support this without forking the parser).
    VsCodeCopilotMcpJson,
    /// A Codex CLI hooks file — `.codex/hooks.json` (project scope) or
    /// `~/.codex/hooks.json` (user scope) as of this writing. Verified
    /// 2026-09-05 directly against OpenAI's own docs
    /// (learn.chatgpt.com/docs/hooks) via two independent fetches: the
    /// JSON shape is `{"hooks": {"PreToolUse": [{"matcher": ..., "hooks":
    /// [{"type": "command", "command": ...}]}]}}` — identical in structure
    /// to `ClaudeCodeHooksJson` (a `command` shell-string nested the same
    /// way, PascalCase event names, an optional top-level `description`
    /// field that's irrelevant here), so this variant reuses the same
    /// shared discovery/rewrite logic (`hooks_config.rs`) parameterized by
    /// this kind rather than a second copy of it. `entry_key` is
    /// `"hook-<index>"`, same traversal-order convention as
    /// `ClaudeCodeHooksJson`.
    CodexHooksJson,
    /// Antigravity's own hooks file — `.agents/hooks.json` (project scope)
    /// or `~/.gemini/config/hooks.json` (user scope) as of this writing.
    /// Verified 2026-09-05 via two independent, mutually-agreeing fetches
    /// (antigravity.google/docs/hooks and .../docs/ide/hooks — cross-
    /// checked deliberately after Windsurf's equivalent claim did NOT
    /// survive the same scrutiny, see STATUS.md's retraction note). The
    /// shape is genuinely different from `ClaudeCodeHooksJson`/
    /// `CodexHooksJson`, not just a new file path: there's no top-level
    /// `"hooks"` wrapper key at all — the root object IS the map, keyed by
    /// an arbitrary hook NAME, e.g. `{"my-hook": {"PreToolUse": [...]}}`.
    /// Each hook name may also carry a top-level `"enabled": false` to
    /// disable it without deleting it (defaults true) — a real semantic
    /// this codebase's discovery/rewrite must respect (a disabled hook
    /// never runs, so treating it as live risk would be a false positive,
    /// not caution). See `hooks_config.rs`'s `parse_hooks_value` (the root-
    /// extraction step is agent-specific; the per-entry walk is shared)
    /// and `init.rs`'s `rewrite_hooks`, both parameterized by an optional
    /// wrapper key for exactly this reason.
    AntigravityHooksJson,
    /// Gemini CLI's hooks — INLINE in the same `.gemini/settings.json` /
    /// `~/.gemini/settings.json` files already used for `mcpServers`
    /// (`GeminiCliSettingsJson`), under a sibling top-level `"hooks"` key.
    /// Verified 2026-09-05 directly against the real source, not docs
    /// prose (a docs-summary claim from earlier this session that Gemini
    /// CLI shares Claude Code's exact `PreToolUse`/`PostToolUse`/`Stop`/
    /// `UserPromptSubmit` event taxonomy did NOT hold up: the real event
    /// names, straight from `packages/core/src/hooks/types.ts`'s
    /// `HookEventName` enum, are `BeforeTool`/`AfterTool`/`BeforeAgent`/
    /// `AfterAgent`/`SessionStart`/`SessionEnd`/`PreCompress`/
    /// `BeforeModel`/`AfterModel`/`BeforeToolSelection`/`Notification` —
    /// genuinely different names, even though the wrapper shape itself
    /// (`{"hooks": {"<EventName>": [{"matcher": ..., "hooks": [{"type":
    /// "command", "command": ...}]}]}}`) is identical to Claude Code/
    /// Codex, confirmed via `packages/cli/src/config/config.ts`'s
    /// `hooks: settings.hooks || {}` and a real example file,
    /// `packages/cli/src/commands/extensions/examples/hooks/hooks/
    /// hooks.json`). Since the wrapper shape matches, this reuses
    /// `hooks_config.rs`'s `Some("hooks")` path unmodified — only the
    /// event names differ, and this codebase's command-discovery walk
    /// never inspects event names at all. One real, honestly-scoped
    /// limitation: Gemini CLI also supports disabling a hook by name via a
    /// SEPARATE, sibling `settings.hooksConfig.disabled: string[]` list
    /// (confirmed in the same `config.ts`) — unlike Antigravity's inline
    /// per-hook `"enabled"` field, this lives outside the `"hooks"`
    /// subtree entirely and is NOT currently cross-referenced, so a hook
    /// disabled only via that list is still discovered/enforced as if
    /// live. Documented, not silently assumed correct.
    GeminiCliHooksJson,
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
        Box::new(codex::CodexAdapter),
        Box::new(windsurf::WindsurfAdapter),
        Box::new(antigravity::AntigravityAdapter),
        Box::new(gemini_cli::GeminiCliAdapter),
        Box::new(github_copilot_cli::GitHubCopilotCliAdapter),
        Box::new(vscode_copilot::VsCodeCopilotAdapter),
        Box::new(unknown::UnknownAgentAdapter),
    ]
}
