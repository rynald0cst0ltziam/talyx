//! GitHub Copilot CLI adapter — same locked v0 scope as Cursor/Windsurf/
//! Antigravity/Gemini CLI (BUILD_PLAN.md §0): discovery + config-gating
//! only, no hook-level enforcement claim (no hooks mechanism documented
//! for Copilot CLI as of this writing).
//!
//! Config paths — verified 2026-09-05 against docs.github.com/en/
//! copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers: Copilot
//! CLI reads MCP servers from `.mcp.json` in the project root OR
//! `.github/mcp.json`, both `{ "mcpServers": {...} }` shape (as of a June
//! 2026 change — it no longer reads `.vscode/mcp.json`, which is VS
//! Code's own separate config with a different top-level key; see
//! `vscode_copilot.rs`).
//!
//! **Deliberately does NOT check `.mcp.json`** — that exact file is
//! already discovered by `claude_code.rs`'s adapter (Claude Code reads
//! the identical path). Checking it again here would report every entry
//! in a shared `.mcp.json` twice, once per adapter — the same class of
//! bug this codebase already found and fixed once for `.cursorrules`
//! duplicating between Cursor's adapter and Unknown Agent Mode's generic
//! marker list. This adapter only ever looks at `.github/mcp.json`,
//! Copilot CLI's other, non-shared location. A project using ONLY
//! Copilot CLI's `.mcp.json` (not `.github/mcp.json`) still gets that
//! entry discovered — just attributed to Claude Code's adapter rather
//! than this one, a real but honestly-documented attribution gap, not a
//! missed detection.
//!
//! Hooks — verified 2026-09-05 directly against the live docs.github.com/
//! en/copilot/reference/hooks-reference page (fetched and grepped
//! directly, not summarized): `.github/hooks/*.json` (project scope) and
//! `~/.copilot/hooks/*.json` (user scope; `$COPILOT_HOME/hooks/*.json` if
//! that env var is set) — see `ConfigSourceKind::
//! GitHubCopilotCliHooksJson`'s doc comment for the full citation,
//! including the real `"bash"`/`"powershell"` command-field difference and
//! the deliberately-not-yet-covered inline-`.github/copilot/settings.json`
//! hooks location. Same `.claude/settings.json` non-duplication principle
//! as this module's MCP-server discovery applies here too — Copilot CLI's
//! own docs confirm it separately reads Claude Code's hook files for
//! cross-tool compatibility, so this adapter deliberately never looks at
//! `.claude/` at all.

use crate::hooks_config::parse_hooks_json;
use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

/// Enumerates every `*.json` file directly inside `dir` (GitHub Copilot
/// CLI's hooks directories are a glob of files, not one fixed filename —
/// see this module's doc comment) and parses each independently. Sorted
/// for deterministic output; each file gets its own 0-based `hook-<i>`
/// indexing (see `ConfigSourceKind::GitHubCopilotCliHooksJson`'s doc
/// comment for why that's safe — `init.rs`'s rewrite grouping is keyed by
/// exact file path, so there's no cross-file index collision to worry
/// about).
fn parse_hooks_dir(dir: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut json_files: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    json_files.sort();
    for path in json_files {
        out.extend(parse_hooks_json(
            &path,
            ConfigSourceKind::GitHubCopilotCliHooksJson,
            "github-copilot-cli",
        ));
    }
    out
}

pub struct GitHubCopilotCliAdapter;

impl AgentAdapter for GitHubCopilotCliAdapter {
    fn agent_id(&self) -> &'static str {
        "github-copilot-cli"
    }

    fn agent_name(&self) -> &'static str {
        "GitHub Copilot CLI"
    }

    fn detect(&self, project_root: &Path) -> bool {
        // A project with hooks but no MCP servers (or vice versa) must
        // still be detected -- found live: a fixture with only
        // .github/hooks/*.json and no .github/mcp.json was silently never
        // scanned at all, since discover() is only ever called after
        // detect() returns true (see agentguard-cli's pipeline.rs).
        project_root.join(".github").join("mcp.json").exists()
            || project_root.join(".github").join("hooks").exists()
            || dirs::home_dir()
                .map(|h| h.join(".copilot").join("hooks").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = parse_mcp_servers_json(
            &project_root.join(".github").join("mcp.json"),
            project_root,
            ConfigSourceKind::GitHubCopilotCliMcpJson,
            "mcpServers",
            "github-copilot-cli",
            "GitHub Copilot CLI",
        );

        out.extend(parse_hooks_dir(&project_root.join(".github").join("hooks")));
        if let Some(h) = dirs::home_dir() {
            out.extend(parse_hooks_dir(&h.join(".copilot").join("hooks")));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::ArtifactKind;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-copilot-cli-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn discovers_github_mcp_json() {
        let dir = unique_temp_dir("discover");
        let github_dir = dir.join(".github");
        std::fs::create_dir_all(&github_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(github_dir.join("mcp.json"), serde_json::to_string_pretty(&config).unwrap())
            .unwrap();

        assert!(GitHubCopilotCliAdapter.detect(&dir));
        let discovered = GitHubCopilotCliAdapter.discover(&dir);
        let mcp_entries: Vec<_> =
            discovered.iter().filter(|d| d.artifact.kind == ArtifactKind::McpServer).collect();
        assert_eq!(mcp_entries.len(), 1);
        assert_eq!(mcp_entries[0].artifact.name, "example");
        assert!(mcp_entries[0].artifact.discovered_by.contains("github-copilot-cli"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_a_project_with_only_hooks_and_no_mcp_json() {
        // Regression test for a real bug found live: detect() only
        // checked .github/mcp.json, so a project with only
        // .github/hooks/*.json was never scanned at all (discover() is
        // only called after detect() returns true).
        let dir = unique_temp_dir("detect-hooks-only");
        std::fs::create_dir_all(dir.join(".github").join("hooks")).unwrap();

        assert!(GitHubCopilotCliAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_hooks_from_multiple_files_in_the_hooks_directory() {
        // Copilot CLI's hooks directory is a glob of *.json files, not one
        // fixed filename -- two separate files here must both surface,
        // each keeping its own independent hook-<i> indexing.
        let dir = unique_temp_dir("hooks-multi");
        let hooks_dir = dir.join(".github").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        std::fs::write(
            hooks_dir.join("a.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "hooks": { "preToolUse": [ { "type": "command", "bash": "./scripts/a.sh" } ] }
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            hooks_dir.join("b.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "hooks": { "postToolUse": [ { "type": "command", "command": "./scripts/b.sh" } ] }
            }))
            .unwrap(),
        )
        .unwrap();

        let discovered = GitHubCopilotCliAdapter.discover(&dir);
        let hooks: Vec<_> = discovered.iter().filter(|d| d.artifact.kind == ArtifactKind::Hook).collect();
        assert_eq!(hooks.len(), 2);
        let commands: Vec<_> = hooks.iter().map(|d| d.launch.as_ref().unwrap().command.as_str()).collect();
        assert!(commands.contains(&"./scripts/a.sh"));
        assert!(commands.contains(&"./scripts/b.sh"));
        for h in &hooks {
            assert!(h.artifact.discovered_by.contains("github-copilot-cli"));
            assert_eq!(
                h.config_source.as_ref().unwrap().kind,
                ConfigSourceKind::GitHubCopilotCliHooksJson
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recognizes_the_bash_field_not_just_command() {
        // The docs' own canonical examples use "bash", not "command" -- a
        // adapter that only recognized "command" would silently discover
        // nothing from the shape most real-world files actually use.
        let dir = unique_temp_dir("hooks-bash-field");
        let hooks_dir = dir.join(".github").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        std::fs::write(
            hooks_dir.join("hooks.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "hooks": {
                    "preToolUse": [ { "type": "command", "bash": "./scripts/log-tool.sh" } ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let discovered = GitHubCopilotCliAdapter.discover(&dir);
        let hooks: Vec<_> = discovered.iter().filter(|d| d.artifact.kind == ArtifactKind::Hook).collect();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].launch.as_ref().unwrap().command, "./scripts/log-tool.sh");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_discover_a_bare_project_root_mcp_json() {
        // Regression test for the deliberate scope decision in this
        // module's doc comment: a bare .mcp.json (Claude Code's file,
        // which Copilot CLI also reads per its own docs) must NOT be
        // picked up here too, or every entry in it would be reported
        // twice.
        let dir = unique_temp_dir("no-duplicate");
        std::fs::create_dir_all(&dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(dir.join(".mcp.json"), serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = GitHubCopilotCliAdapter.discover(&dir);
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
