//! agentguard-adapters
//!
//! Per-agent discovery — BUILD_PLAN.md §9/§32. Each adapter implements
//! `AgentAdapter` and translates one agent ecosystem's on-disk config into
//! the common `Artifact` model from agentguard-core. Adapters only discover;
//! they never decide or enforce (that's agentguard-risk and the future
//! shim/daemon — see BUILD_PLAN.md §5). Keeping that boundary is what lets
//! adding a new agent stay an adapter-sized change instead of a rewrite.

pub mod aider;
pub mod amazon_q;
pub mod amp;
pub mod antigravity;
pub mod claude_code;
pub mod claude_desktop;
pub mod cline;
pub mod cody;
pub mod codex;
pub mod continue_dev;
pub mod cursor;
pub mod devin_cli;
pub mod gemini_cli;
pub mod github_copilot_cli;
pub mod goose;
mod hooks_config;
pub mod jetbrains;
pub mod kiro;
mod mcp_config;
pub mod opencode;
pub mod openclaw;
pub mod roo_code;
pub mod tabnine;
pub mod unknown;
pub mod vscode_copilot;
pub mod windsurf;
pub mod zed;

use agentguard_core::Artifact;
use std::path::{Path, PathBuf};

/// Field names, in a fixed order, that carry a shell-command STRING inside
/// one hook definition object across every agent this codebase enforces
/// hooks for. `"command"` is the cross-platform field Claude Code/Codex/
/// Antigravity/Gemini CLI all use; `"bash"`/`"powershell"` are GitHub
/// Copilot CLI's OS-specific alternatives (see `ConfigSourceKind::
/// GitHubCopilotCliHooksJson`'s doc comment for the citation). Exported at
/// the crate root — rather than kept private inside `hooks_config.rs` —
/// specifically so agentguard-cli's `init.rs` rewrite path can iterate the
/// exact same field list discovery used, with no risk of the two drifting
/// apart.
pub const HOOK_COMMAND_FIELDS: [&str; 3] = ["command", "bash", "powershell"];

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
    /// GitHub Copilot CLI's standalone hook files — `.github/hooks/*.json`
    /// (project scope, any number of files, glob-matched — NOT one fixed
    /// filename like every other agent) and `~/.copilot/hooks/*.json`
    /// (user scope; `%USERPROFILE%\.copilot\hooks\` on Windows, or
    /// `$COPILOT_HOME/hooks/` if that env var is set). Verified 2026-09-05
    /// against the real, live docs.github.com/en/copilot/reference/
    /// hooks-reference page (fetched and grepped directly, not summarized
    /// — after two other agents' docs-summary claims failed to hold up
    /// earlier this session): each file wraps as `{"version": 1, "hooks":
    /// {"<camelCase-event>": [...]}}` — same `"hooks"`-wrapper shape as
    /// Claude Code/Codex/Gemini CLI. Two real differences from every other
    /// hook-enforced agent so far: (1) the shell-command field in the
    /// docs' own examples is `"bash"` (Unix) or `"powershell"` (Windows),
    /// not `"command"` — a cross-platform `"command"` field is also
    /// accepted, per the docs, but isn't what the canonical examples show,
    /// so `hooks_config.rs`'s `collect_command_strings` was extended to
    /// recognize all three field names, not just `"command"`; (2)
    /// discovery is a directory of files, not one fixed path, so this
    /// adapter enumerates and parses each `*.json` file independently
    /// (each file's own artifact indexing already resets to 0, and
    /// `init.rs`'s `by_config` grouping is keyed by exact file path, so no
    /// entry_key collision is possible across files). Copilot CLI's docs
    /// also confirm it independently reads Claude Code's own `.claude/
    /// settings.json`/`.claude/settings.local.json` for cross-tool hook
    /// compatibility — deliberately NOT re-checked by this adapter, same
    /// non-duplication principle already applied to the shared `.mcp.json`
    /// (see `GitHubCopilotCliMcpJson`'s doc comment), and an inline
    /// `"hooks"` field inside `.github/copilot/settings.json`/
    /// `~/.copilot/settings.json` is a third, real location this v1
    /// deliberately does not cover yet — the standalone-file mechanism is
    /// the primary, most concretely documented one.
    GitHubCopilotCliHooksJson,
    /// Claude Desktop's own `claude_desktop_config.json` — DISTINCT from
    /// Claude Code (a separate product: a chat-only desktop app, no coding-
    /// agent tool-execution loop, no hooks/skills mechanism). Verified
    /// 2026-09-05 against multiple independent sources agreeing on the
    /// same three OS-specific paths: `~/Library/Application Support/
    /// Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\
    /// claude_desktop_config.json` (Windows), `~/.config/Claude/
    /// claude_desktop_config.json` (Linux) — i.e. `dirs::config_dir()`,
    /// NOT `dirs::home_dir()` like every other agent covered so far (the
    /// first one that isn't a plain home-relative dot-directory). User-
    /// scope only — Claude Desktop has no per-project concept. Same `{
    /// "mcpServers": {...} }` shape as Claude Code/Cursor. A known,
    /// documented limitation carried over from the primary source: on
    /// Windows MSIX installs, the app may read from a different location
    /// inside the MSIX virtualized filesystem than this path — not
    /// resolved further here, matching this codebase's "record real,
    /// honest limitations" discipline.
    ClaudeDesktopMcpJson,
    /// OpenClaw's `~/.openclaw/openclaw.json` — verified 2026-09-05
    /// against docs.openclaw.ai/tools/mcp. Genuinely different nesting
    /// from every other agent: servers sit under `mcp.servers` (TWO levels
    /// deep — `{"mcp": {"servers": {"<name>": {...}}}}`), not a flat
    /// top-level `mcpServers` key, so this doesn't reuse
    /// `parse_mcp_servers_json`'s single-key lookup — `openclaw.rs`
    /// navigates the two levels itself, then hands the inner map straight
    /// to the same shared `parse_server_map` every other agent uses. Each
    /// server entry can carry a `"transport"` field (`"stdio"`, `"sse"`,
    /// `"streamable-http"`) and its own `"enabled"` boolean, inverted from
    /// Kiro's `"disabled"` (see `KiroMcpJson`'s doc comment) -- `openclaw.rs`
    /// checks for `"enabled": false` itself before handing entries to the
    /// shared parser, since `parse_server_map`'s own check looks for the
    /// opposite field name. OpenClaw itself has some gateway/router characteristics
    /// (per-agent server routing, a scoped config editor) but ships its
    /// own CLI end users install directly, matching Snyk agent-scan's own
    /// classification of it as a scannable agent, not purely an
    /// enterprise-deployed gateway.
    OpenClawJson,
    /// Sourcegraph Amp's settings files — `~/.config/amp/settings.json`
    /// (user scope) and `.amp/settings.json` (project/workspace scope).
    /// Verified 2026-09-05 against ampcode.com/docs/customize/mcp: the
    /// top-level key is LITERALLY the dotted string `"amp.mcpServers"`
    /// (VS-Code-settings-style flat key, not a nested `{"amp": {...}}`
    /// object) — reuses `parse_mcp_servers_json`'s existing `top_level_key`
    /// parameter unmodified, the same mechanism already proven for VS
    /// Code Copilot's `"servers"` key. A real, documented trust
    /// distinction from Amp's own docs: servers in the WORKSPACE file
    /// (`.amp/settings.json`) require explicit approval before running;
    /// servers in the GLOBAL file do not — noted here, not enforced
    /// differently by this adapter (same as Codex's analogous "trusted
    /// projects only" caveat, which this codebase's adapters document but
    /// don't independently re-implement). A separate `.amp/mcp.json` file
    /// for bundling servers with skills is mentioned in Amp's docs without
    /// a confirmed JSON shape — deliberately not covered, not guessed at.
    AmpMcpJson,
    /// Kiro's `.kiro/settings/mcp.json` (project scope) and
    /// `~/.kiro/settings/mcp.json` (user scope) — verified 2026-09-05
    /// against kiro.dev/docs/mcp/. Standard `{"mcpServers": {"<name>": {
    /// command, args, env, disabled }}}` shape, identical in structure to
    /// Claude Code/Cursor — the closest fit yet to the already-proven
    /// shape, zero new parsing logic needed beyond the shared `"disabled"`
    /// skip in `mcp_config.rs`'s `parse_server_map` (added specifically
    /// because Kiro's own example config includes `"disabled": false`
    /// inline).
    KiroMcpJson,
    /// Amazon Q Developer CLI — TWO real, distinct MCP surfaces, both
    /// verified 2026-09-05 directly against AWS's own docs and the
    /// aws/amazon-q-developer-cli GitHub repo's `agent-format.md`: (1) the
    /// "legacy" fixed-path files, `~/.aws/amazonq/mcp.json` (global) and
    /// `.amazonq/mcp.json` (workspace) — AWS's own docs call these
    /// "legacy" but they remain a real, currently-functional config
    /// surface, not removed; (2) the newer named "custom agent" files,
    /// each an arbitrarily-NAMED `*.json` file (the filename becomes the
    /// agent's name) inside `~/.aws/amazonq/cli-agents/` (CLI) or
    /// `~/.aws/amazonq/agents/` (IDE) — same `"mcpServers"` field, nested
    /// inside a larger per-agent config object alongside unrelated
    /// fields. Both surfaces use the identical `{"mcpServers": {"<name>":
    /// {command, args, env, timeout}}}` shape for the servers themselves,
    /// so `amazon_q.rs` handles the "arbitrary filename" surface the same
    /// way `github_copilot_cli.rs` handles Copilot CLI's own glob-of-files
    /// hooks directory — enumerate `*.json`, parse each independently.
    AmazonQMcpJson,
    /// Continue.dev — JSON-only, PARTIAL coverage, deliberately: `.continue/
    /// mcpServers/*.json` (project) and `~/.continue/mcpServers/*.json`
    /// (user), a glob of files exactly like Amazon Q's/Copilot CLI's own
    /// pattern, standard `{"mcpServers": {...}}` shape when a file in that
    /// directory happens to be JSON (Continue's own docs explicitly permit
    /// dropping in "JSON MCP configuration from another tool" here
    /// unchanged). Verified 2026-09-05 against docs.continue.dev/
    /// customize/deep-dives/mcp: Continue's NATIVE, preferred format is
    /// actually YAML (`config.yaml`'s own `mcpServers` key is a LIST of
    /// `{name, command, args}` objects, not a name-keyed map — a
    /// genuinely different shape from every other agent this codebase
    /// covers) and `.continue/mcpServers/*.yaml`/`*.yml` files use the
    /// same list shape. Neither YAML surface is covered by this variant —
    /// would need a YAML parsing dependency this workspace doesn't have
    /// yet, plus a bespoke list-shaped (not map-shaped) parser — scoped as
    /// a deliberate, documented follow-up rather than guessed at or
    /// silently skipped without a record.
    ContinueMcpJson,
    /// Devin CLI's own MCP config — a SEPARATE product from Windsurf/Devin
    /// Desktop/Cascade (the IDE `WindsurfMcpJson` targets), confirmed via
    /// two independent sources agreeing (2026-09-05): docs.devin.ai/cli/
    /// extensibility/configuration directly, and cross-validated against
    /// Warden-AI's own real, working registration code
    /// (rynald0cst0ltziam/Warden-AI's `src/cli/register.ts`), which
    /// registers into these exact paths under the label "Devin CLI" as a
    /// target distinct from its own separate "Windsurf/Devin" entry.
    /// Project scope: `.devin/config.json`. User scope: `~/.config/devin/
    /// config.json` (macOS/Linux) or `%APPDATA%\devin\config.json`
    /// (Windows), with `mcp_config.json` as a confirmed legacy/alternative
    /// filename at the same user-scope directory. Standard `{"mcpServers":
    /// {...}}` shape, reusing mcp_config.rs.
    DevinCliMcpJson,
    /// Devin CLI's USER-scope hooks — nested under a `"hooks"` key INSIDE
    /// `~/.config/devin/config.json` (the same file already read for MCP
    /// servers under `DevinCliMcpJson`), WITH a wrapper — the same
    /// convention as Claude Code/Codex/Gemini CLI. Kept as its own variant
    /// distinct from the project-scope file (`DevinCliProjectHooksJson`)
    /// specifically because that file uses the OPPOSITE convention (no
    /// wrapper) — one `ConfigSourceKind` must always mean one consistent
    /// rewrite shape, so two genuinely different shapes for "Devin CLI
    /// hooks" get two variants, not one overloaded by which file it came
    /// from.
    DevinCliHooksJson,
    /// Devin CLI's PROJECT-scope hooks — the standalone `.devin/
    /// hooks.v1.json` file. Verified 2026-09-05 directly against
    /// docs.devin.ai/cli/extensibility/hooks/overview AND independently
    /// confirmed by reading Warden-AI's own real, in-repo
    /// `.devin/hooks.v1.json` file (a working product's actual config, not
    /// docs prose): the root object IS the event map directly, e.g.
    /// `{"PreToolUse": [{"matcher": ..., "hooks": [{"type": "command",
    /// "command": ...}]}]}}` — NO `"hooks"` wrapper key, same shape family
    /// as `AntigravityHooksJson`. See `DevinCliHooksJson`'s doc comment
    /// for why the user-scope file needs a separate variant instead.
    DevinCliProjectHooksJson,
    /// Cline (a VS Code extension, `saoudrizwan.claude-dev`) — verified
    /// 2026-09-05 by cross-referencing Warden-AI's own real registration
    /// code, which embeds this exact, specific VS Code extension id in a
    /// `globalStorage` path (not a generic guessed location — a real
    /// extension id is not something to guess by accident, unlike the
    /// batch of unverified `~/.config/<name>/mcp.json`-shaped entries the
    /// same file also lists for several other tools, which this codebase
    /// does NOT build on without independent per-product verification;
    /// one of those, Claude Desktop's path, was directly checked and
    /// found WRONG). Path: `<VS Code globalStorage>/saoudrizwan.claude-dev/
    /// settings/cline_mcp_settings.json`, OS-specific base per VS Code's
    /// own convention (`%APPDATA%\Code\User\globalStorage` on Windows,
    /// `~/Library/Application Support/Code/User/globalStorage` on macOS,
    /// `~/.config/Code/User/globalStorage` on Linux). Standard `{
    /// "mcpServers": {...}}` shape.
    ClineMcpJson,
    /// Roo Code — "the same architecture as Cline, a different VS Code
    /// extension id" per Warden-AI's own code comment, confirmed the same
    /// way as `ClineMcpJson`: `rooveterinaryinc.roo-cline` in the
    /// identical `globalStorage` path shape, same `cline_mcp_settings.json`
    /// filename, same `{"mcpServers": {...}}` shape.
    RooCodeMcpJson,
    /// Zed editor — verified 2026-09-05 directly against zed.dev/docs/
    /// assistant/model-context-protocol. Zed calls MCP servers "context
    /// servers"; the top-level key is `"context_servers"`, NOT
    /// `"mcpServers"` and NOT `"mcp_servers"` either — Warden-AI's own
    /// registration code guessed the latter, and this direct fetch of
    /// Zed's own docs shows neither guess was right, reinforcing why this
    /// codebase doesn't build on that file's unverified batch without
    /// independently checking (see `RooCodeMcpJson`'s doc comment).
    /// Otherwise the per-server shape is the familiar one (`command`/
    /// `args`/`env` for local, `url`/`headers` for remote), so this
    /// reuses `parse_mcp_servers_json` unmodified via its `top_level_key`
    /// parameter — the same mechanism already proven for VS Code
    /// Copilot's `"servers"` and Amp's `"amp.mcpServers"`. Settings path
    /// is `dirs::config_dir()`-based (the second agent after Claude
    /// Desktop confirmed to use each OS's proper special config folder,
    /// not a plain home-relative dot-directory): `~/Library/Application
    /// Support/Zed/settings.json` (macOS), `~/.config/zed/settings.json`
    /// (Linux), `%APPDATA%\Zed\settings.json` (Windows).
    ZedMcpJson,
    /// JetBrains AI Assistant / Junie — verified 2026-09-05 directly
    /// against junie.jetbrains.com/docs/junie-plugin-mcp-settings.html
    /// and junie-cli-mcp-configuration.html. Path: `.junie/mcp/mcp.json`
    /// (project scope) and `~/.junie/mcp/mcp.json` (user/global scope) —
    /// a completely different, more specific path than Warden-AI's own
    /// generic, unverified guess (`~/AppData/Roaming/JetBrains/mcp.json`
    /// or platform equivalent) for the same product, a second concrete
    /// case (after Claude Desktop) proving that file's unverified batch
    /// shouldn't be trusted without independent checking. Standard `{
    /// "mcpServers": {...}}` shape, reusing mcp_config.rs unmodified.
    JetBrainsMcpJson,
    /// opencode — verified 2026-09-05 against opencode.ai's own docs
    /// (open-code.ai/en/docs/config, /docs/mcp-servers) and independently
    /// cross-validated by Snyk's `agent-scan` also listing "OpenCode" in
    /// its own supported-agent set (see STATUS.md #31's competitive
    /// research). Config: `opencode.json` (project root) or
    /// `~/.config/opencode/opencode.json` (user/global) — servers sit
    /// under a `"mcp"` key, ONE level of nesting (`{"mcp": {"<name>": {
    /// "type": "local"|"remote", "command"|"url": ...}}}}`), not a flat
    /// top-level `mcpServers` map. Doesn't reuse `parse_mcp_servers_json`'s
    /// single-key lookup for this reason — `opencode.rs` navigates the
    /// one level itself, then hands the inner map to the same shared
    /// `parse_server_map` every other agent uses, the same pattern
    /// already proven for OpenClaw's (two-level) nesting. A `.jsonc`
    /// variant (JSON with comments) is also documented but not handled --
    /// `serde_json` doesn't parse comments, and this hasn't been
    /// special-cased; a `.jsonc` file with real comments in it will fail
    /// to parse and be silently skipped, same as any malformed JSON file
    /// elsewhere in this codebase.
    OpenCodeMcpJson,
    /// Tabnine — verified 2026-09-05 against docs.tabnine.com's own MCP
    /// setup docs. Path: `.tabnine/mcp_servers.json` (project scope) and
    /// `~/.tabnine/mcp_servers.json` (user scope). Standard `{
    /// "mcpServers": {...}}` shape, reusing mcp_config.rs unmodified.
    TabnineMcpJson,
    /// Sourcegraph Cody — verified 2026-09-05 via search results quoting
    /// a complete, consistent example (cross-checked across independent
    /// pages, since a direct fetch of Sourcegraph's own docs page 403'd).
    /// Top-level key is the dotted string `"cody.mcpServers"` — same
    /// VS-Code-settings convention as Amp's `"amp.mcpServers"` and Cline/
    /// Roo Code's extension-scoped settings — but Cody's lives in VS
    /// Code's OWN general settings file, not a dedicated one: `.vscode/
    /// settings.json` (project/workspace scope) or `<VS Code User dir>/
    /// settings.json` (global scope, sibling to the `globalStorage`
    /// directory `ClineMcpJson`/`RooCodeMcpJson` use). Deliberately a
    /// DIFFERENT file from VS Code Copilot's own `.vscode/mcp.json`
    /// (`VsCodeCopilotMcpJson`) — no double-reporting risk, confirmed one
    /// notable detail while researching this: VS Code's native Copilot
    /// integration is "the only major client" using `"servers"` as its
    /// root key instead of an `mcpServers`-family name, per the same
    /// source. Reuses `parse_mcp_servers_json` via `top_level_key`, the
    /// same mechanism already proven for Amp/VS Code Copilot/Zed.
    CodyMcpJson,
    /// Goose (Block's AI agent) — verified 2026-09-05 against multiple
    /// independent sources agreeing: `~/.config/goose/config.yaml`, user
    /// scope, real YAML (not JSON) but a name-keyed MAP under
    /// `mcpServers:` — the SAME shape every JSON-based agent uses,
    /// serialized differently, unlike Continue.dev's genuinely
    /// LIST-shaped `mcpServers` in YAML (see `ContinueMcpJson`'s doc
    /// comment). Parsed via `serde_saphyr::from_str::<serde_json::
    /// Value>()` (see this crate's `Cargo.toml` for why that YAML crate
    /// was chosen over the deprecated `serde_yaml`/unsound `serde_yml`)
    /// directly into the same `Value` shared parsers already operate on
    /// -- `parse_server_map` is reused completely unmodified, the first
    /// YAML-native agent that needed zero shape-specific transform code.
    /// Discovery/scoring only, like `OpenClawJson`/`OpenCodeMcpJson` --
    /// NOT for a nesting reason this time, but because `init.rs`'s JSON
    /// rewrite path parses a config file with `serde_json::from_str`,
    /// which fails outright on a real YAML file. Writing a rewritten
    /// config back out would need YAML re-serialization too, a real
    /// separate mechanism this codebase doesn't have yet -- caught before
    /// it could ship as a silent rewrite failure by tracing through what
    /// `rewrite_config_json` actually does to the file, not assuming a
    /// `ConfigSourceKind` with a `top_level_key` is automatically
    /// rewritable.
    GooseMcpJson,
    /// Continue.dev's YAML surfaces specifically -- `config.yaml` and the
    /// `.continue/mcpServers/*.yaml`/`*.yml` bundle files (see
    /// `ContinueMcpJson`'s doc comment for the JSON-glob variant this is
    /// deliberately kept separate from). Same rewrite limitation as
    /// `GooseMcpJson` -- discovery/scoring only. Kept as its OWN variant
    /// rather than folded into `ContinueMcpJson` for the same reason
    /// Devin CLI's two hook shapes needed separate kinds: `ContinueMcpJson`
    /// artifacts from the JSON glob path ARE safely rewritable (real JSON
    /// files, the existing mechanism works), so merging the two would
    /// make one `ConfigSourceKind` mean two different things depending on
    /// which physical file an artifact happened to come from -- exactly
    /// the bug shape already caught and fixed once this session.
    ContinueYamlMcpJson,
    /// Aider -- verified 2026-09-05 against aider.chat's own docs
    /// (aider.chat/docs/config/aider_conf.html) and a real example file
    /// referenced from a third-party MCP server's own docs. Config:
    /// `.aider.conf.yml`, checked in the user's home directory, the git
    /// repo root, and the current directory (Aider's own docs say all
    /// three are loaded, in that order, with later ones taking priority
    /// for Aider's own runtime -- for discovery purposes this codebase
    /// checks all of them independently rather than picking a "winner").
    /// Real YAML, top-level key `"mcp-server"` (hyphenated, genuinely
    /// different from every other agent's `mcpServers`/`context_servers`/
    /// `cody.mcpServers`/etc.), and LIST-shaped like Continue.dev's own
    /// native format, not a name-keyed map -- reuses the same
    /// `list_to_server_map` conversion. Discovery/scoring only, same
    /// reason as `GooseMcpJson`/`ContinueYamlMcpJson`: `init.rs`'s JSON
    /// rewrite path can't parse or write real YAML.
    AiderMcpJson,
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
        Box::new(claude_desktop::ClaudeDesktopAdapter),
        Box::new(cursor::CursorAdapter),
        Box::new(codex::CodexAdapter),
        Box::new(windsurf::WindsurfAdapter),
        Box::new(antigravity::AntigravityAdapter),
        Box::new(gemini_cli::GeminiCliAdapter),
        Box::new(github_copilot_cli::GitHubCopilotCliAdapter),
        Box::new(vscode_copilot::VsCodeCopilotAdapter),
        Box::new(amazon_q::AmazonQAdapter),
        Box::new(amp::AmpAdapter),
        Box::new(kiro::KiroAdapter),
        Box::new(openclaw::OpenClawAdapter),
        Box::new(continue_dev::ContinueDevAdapter),
        Box::new(devin_cli::DevinCliAdapter),
        Box::new(cline::ClineAdapter),
        Box::new(roo_code::RooCodeAdapter),
        Box::new(zed::ZedAdapter),
        Box::new(jetbrains::JetBrainsAdapter),
        Box::new(opencode::OpenCodeAdapter),
        Box::new(tabnine::TabnineAdapter),
        Box::new(cody::CodyAdapter),
        Box::new(goose::GooseAdapter),
        Box::new(aider::AiderAdapter),
        Box::new(unknown::UnknownAgentAdapter),
    ]
}
