//! Claude Code adapter — the only Tier-1 adapter with full enforcement
//! planned (BUILD_PLAN.md §0, §5b: `PreToolUse` hooks are a real
//! interception point). MCP server discovery delegates to mcp_config.rs
//! (shared with the Cursor adapter — same JSON shape); this file owns
//! what's specific to Claude Code: hooks and skills discovery, and its
//! own config file locations.
//!
//! Config file locations below are the documented/common ones as of this
//! writing. Claude Code's config layout has changed before and will change
//! again — treat `detect`/`discover` returning nothing as "check these
//! paths are still current," not as "no agent present," and keep this file
//! as the single place those paths live so a version bump is a local edit,
//! not a hunt through the codebase (this is the adapter-maintenance
//! treadmill called out in BUILD_PLAN.md's audit notes).

use crate::hooks_config::parse_hooks_json;
use crate::mcp_config::{parse_mcp_servers_json, parse_server_map};
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use talyx_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub struct ClaudeCodeAdapter;

impl AgentAdapter for ClaudeCodeAdapter {
    fn agent_id(&self) -> &'static str {
        "claude-code"
    }

    fn agent_name(&self) -> &'static str {
        "Claude Code"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".mcp.json").exists()
            || project_root.join(".claude").exists()
            || home
                .as_ref()
                .map(|h| h.join(".claude.json").exists())
                .unwrap_or(false)
            || home
                .as_ref()
                .map(|h| h.join(".claude").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        // MCP servers — project scope (.mcp.json) and user scope
        // (~/.claude.json). Both sit directly in their own base dir, so
        // base_dir == the config's own parent for each.
        out.extend(parse_mcp_servers_json(
            &project_root.join(".mcp.json"),
            project_root,
            ConfigSourceKind::ClaudeCodeMcpServersJson,
            "mcpServers",
            "claude-code",
            "Claude Code",
        ));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers_json(
                &h.join(".claude.json"),
                h,
                ConfigSourceKind::ClaudeCodeMcpServersJson,
                "mcpServers",
                "claude-code",
                "Claude Code",
            ));
            // LOCAL scope — verified 2026-09-05 directly against
            // code.claude.com/docs/en/mcp: "Local scope is the default"
            // for `claude mcp add` (i.e. whenever a user doesn't pass
            // --scope), and it is NOT stored at ~/.claude.json's top
            // level like User scope is -- it nests under
            // `projects["<absolute-project-path>"].mcpServers`. A real,
            // previously-unhandled gap: since local is the default
            // scope, this was very plausibly the single most common way
            // an individual Claude Code user's MCP servers are actually
            // stored, and none of them were being discovered at all.
            out.extend(parse_local_scope_mcp_servers(&h.join(".claude.json"), project_root));
        }

        // Hooks — project settings.json + settings.local.json, and user
        // settings.json. settings.local.json (project-scope, gitignored by
        // convention) was a real, previously-unhandled gap — confirmed
        // 2026-09-05 directly against code.claude.com/docs/en/hooks's own
        // "Hook locations" table, which lists it as a distinct, real
        // location alongside settings.json, not a variant of it. Found
        // while investigating VS Code Copilot's hooks (which read this
        // same file directly, per its own docs) — fixing it here closes
        // the gap for Claude Code itself AND, since VS Code just parses
        // Claude Code's file format from Claude Code's own paths, means no
        // separate VS-Code-specific adapter code is needed for this
        // location at all (see STATUS.md's write-up).
        out.extend(parse_hooks_json(
            &project_root.join(".claude").join("settings.json"),
            ConfigSourceKind::ClaudeCodeHooksJson,
            "claude-code",
        ));
        out.extend(parse_hooks_json(
            &project_root.join(".claude").join("settings.local.json"),
            ConfigSourceKind::ClaudeCodeHooksJson,
            "claude-code",
        ));
        if let Some(h) = &home {
            out.extend(parse_hooks_json(
                &h.join(".claude").join("settings.json"),
                ConfigSourceKind::ClaudeCodeHooksJson,
                "claude-code",
            ));
        }

        // Skills — project and user skills directories.
        out.extend(discover_skills(&project_root.join(".claude").join("skills")));
        if let Some(h) = &home {
            out.extend(discover_skills(&h.join(".claude").join("skills")));
        }

        // Plugins — a whole second artifact surface (MCP servers, hooks,
        // skills, agents, LSP servers, monitors), only for plugins listed
        // in `enabledPlugins`. See `claude_code_plugins.rs`.
        out.extend(crate::claude_code_plugins::discover_plugins(project_root, home.as_deref()));

        out
    }
}

/// Parses `~/.claude.json`'s LOCAL-scope MCP servers for `project_root`
/// specifically — nested under `projects["<key>"].mcpServers`, where
/// `<key>` is the absolute project path AS CLAUDE CODE ITSELF WROTE IT,
/// not necessarily byte-identical to `project_root`'s own string form.
///
/// Verified empirically against a real `~/.claude.json` on the dev
/// machine, not just the docs: the SAME logical project appeared under
/// TWO different key spellings for the same directory
/// (`C:\Users\...\pop.lol` and `C:/Users/...\pop.lol` — backslash vs
/// forward-slash), evidently written at different times by different
/// invocation contexts. A plain string-equality lookup would have missed
/// one of them. `project_root` reaching this adapter is also typically
/// `Path::canonicalize()`'d upstream, which on Windows prepends the
/// `\\?\` extended-length prefix (`\\?\C:\...`) that Claude Code's own
/// keys never carry — so every key in `projects` is compared via
/// `paths_match_loosely` (strip that prefix, normalize separators, and
/// compare case-insensitively on Windows / case-sensitively elsewhere)
/// rather than a single exact-match attempt.
fn parse_local_scope_mcp_servers(claude_json_path: &Path, project_root: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = fs::read_to_string(claude_json_path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let Some(projects) = json.get("projects").and_then(|p| p.as_object()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (key, entry) in projects {
        if !paths_match_loosely(Path::new(key), project_root) {
            continue;
        }
        let Some(servers) = entry.get("mcpServers").and_then(|v| v.as_object()) else {
            continue;
        };
        out.extend(parse_server_map(
            servers,
            claude_json_path,
            project_root,
            ConfigSourceKind::ClaudeCodeMcpServersJson,
            "claude-code",
            "Claude Code",
        ));
    }
    out
}

/// Whether `a` and `b` plausibly refer to the same directory, tolerating
/// the real-world path-spelling differences found empirically (see
/// `parse_local_scope_mcp_servers`'s doc comment): a `\\?\` extended-
/// length prefix present on one side and not the other, `\` vs `/`
/// separators, and Windows' case-insensitive filesystem. Deliberately a
/// string-level comparison, not `Path::canonicalize()` on both sides —
/// canonicalizing `a` (a JSON value from `~/.claude.json`, which could
/// name a project that's been moved, renamed, or deleted since) would
/// fail or resolve to nothing for exactly the entries most worth still
/// matching against (an old/moved project's cached MCP server config is
/// still real, unmanaged risk sitting in that file either way).
fn paths_match_loosely(a: &Path, b: &Path) -> bool {
    fn normalize(p: &Path) -> String {
        let s = p.to_string_lossy();
        let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
        let forward_slashes = stripped.replace('\\', "/");
        let trimmed = forward_slashes.trim_end_matches('/');
        if cfg!(windows) {
            trimmed.to_lowercase()
        } else {
            trimmed.to_string()
        }
    }
    normalize(a) == normalize(b)
}

fn discovered_by_set() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("claude-code".to_string());
    s
}

/// Every subdirectory of `dir` containing a `SKILL.md` is treated as a
/// skill artifact. Its capabilities aren't populated here — the CLI hands
/// `scan_root` to talyx-scanner for that.
fn discover_skills(dir: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join("SKILL.md").exists() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("skill")
                .to_string();
            let source = ArtifactSource::LocalPath(path.display().to_string());
            let artifact = Artifact {
                id: Artifact::compute_id(ArtifactKind::Skill, &name, &source),
                kind: ArtifactKind::Skill,
                name: name.clone(),
                version: None,
                publisher: PublisherIdentity::default(),
                source,
                content_hash: None,
                capabilities: vec![],
                discovered_by: discovered_by_set(),
            };
            out.push(DiscoveredArtifact {
                display_location: path.display().to_string(),
                scan_root: Some(path),
                artifact,
                launch: None,
                config_source: None,
                raw_config_entry: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "talyx-claude-code-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn paths_match_loosely_tolerates_separator_and_prefix_differences() {
        // Reproduces the exact real-world discrepancy found empirically
        // in a live ~/.claude.json: the same project appeared under both
        // a backslash and a forward-slash key.
        assert!(paths_match_loosely(
            Path::new(r"C:\Users\Hubby\Desktop\pop.lol"),
            Path::new("C:/Users/Hubby/Desktop/pop.lol"),
        ));
        // Windows' \\?\ extended-length prefix, as Path::canonicalize()
        // adds, must not prevent a match against a key that never had it.
        assert!(paths_match_loosely(
            Path::new(r"\\?\C:\Users\Hubby\Desktop\pop.lol"),
            Path::new(r"C:\Users\Hubby\Desktop\pop.lol"),
        ));
        // Genuinely different directories must not match.
        assert!(!paths_match_loosely(
            Path::new(r"C:\Users\Hubby\Desktop\pop.lol"),
            Path::new(r"C:\Users\Hubby\Desktop\other-project"),
        ));
    }

    #[test]
    fn parse_local_scope_mcp_servers_finds_the_project_regardless_of_key_spelling() {
        let dir = unique_temp_dir("local-scope");
        std::fs::create_dir_all(&dir).unwrap();
        let claude_json_path = dir.join("claude.json");

        // The project_root this test passes in uses forward slashes (as
        // Path::display() would on a Unix-style path); the stored key
        // uses backslashes -- reproducing the mismatch found live,
        // proving the lookup survives it either direction.
        let project_key = dir.display().to_string();
        let config = serde_json::json!({
            "projects": {
                project_key.replace('/', "\\"): {
                    "mcpServers": {
                        "local-example": { "command": "some-binary", "args": [] }
                    }
                }
            }
        });
        std::fs::write(&claude_json_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_local_scope_mcp_servers(&claude_json_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "local-example");
        assert!(discovered[0].artifact.discovered_by.contains("claude-code"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_local_scope_mcp_servers_ignores_other_projects() {
        let dir = unique_temp_dir("local-scope-other");
        std::fs::create_dir_all(&dir).unwrap();
        let claude_json_path = dir.join("claude.json");

        let config = serde_json::json!({
            "projects": {
                "C:\\Users\\Hubby\\Desktop\\some-other-project": {
                    "mcpServers": {
                        "not-this-one": { "command": "some-binary", "args": [] }
                    }
                }
            }
        });
        std::fs::write(&claude_json_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_local_scope_mcp_servers(&claude_json_path, &dir);
        assert!(discovered.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    // Hook parsing (parse_hooks_json), its shim-unwrap logic, and the
    // command-hashing scheme now live in hooks_config.rs, shared with
    // Codex — see that module's own tests for that coverage.

    #[test]
    fn discovers_hooks_from_settings_local_json_even_without_settings_json() {
        // Regression test for a real gap found while investigating VS Code
        // Copilot's hooks (which read .claude/settings.local.json
        // directly, per its own docs) -- Claude Code's own docs confirm
        // this is a distinct, real project-scope hook location (gitignored
        // by convention), not a variant of settings.json, and it was never
        // discovered before this fix.
        let dir = unique_temp_dir("settings-local-hooks");
        let claude_dir = dir.join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [ { "type": "command", "command": "./scripts/local-only.sh" } ] }
                ]
            }
        });
        std::fs::write(
            claude_dir.join("settings.local.json"),
            serde_json::to_string_pretty(&hooks).unwrap(),
        )
        .unwrap();

        let discovered = ClaudeCodeAdapter.discover(&dir);
        let hooks_found: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::Hook)
            .filter(|d| {
                d.config_source
                    .as_ref()
                    .map(|cs| cs.path.starts_with(&dir))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(hooks_found.len(), 1);
        assert_eq!(hooks_found[0].launch.as_ref().unwrap().command, "./scripts/local-only.sh");

        std::fs::remove_dir_all(&dir).ok();
    }
}
