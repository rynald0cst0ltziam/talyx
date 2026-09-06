//! OpenHands adapter. Verified 2026-09-05 against docs.openhands.dev's
//! own MCP settings page and independent config-location sources.
//! Config: `./config.toml` (project/current directory) or
//! `~/.openhands/config.toml` (user).
//!
//! A genuinely different TOML shape from Codex's `[mcp_servers.<name>]`:
//! `[mcp]` has `stdio_servers` (an array of inline tables, each with
//! `name`/`command`/`args`/`env` -- the only one this adapter covers),
//! `sse_servers`, and `shttp_servers` (remote; each array element is
//! either a bare URL string or `{url, api_key, timeout}`, with NO name
//! field at all -- deliberately not covered here, see
//! `ConfigSourceKind::OpenHandsMcpToml`'s doc comment for why that's a
//! genuinely different problem, not a quick extension).
//!
//! `stdio_servers` converts through the same `list_to_server_map` pattern
//! Continue.dev/Aider use, via a TOML->JSON `Value` bridge (the same
//! conversion already proven in `codex.rs`'s `raw_config_entry` capture).

use crate::mcp_config::{list_to_server_map, parse_server_map};
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::Path;

pub struct OpenHandsAdapter;

impl AgentAdapter for OpenHandsAdapter {
    fn agent_id(&self) -> &'static str {
        "openhands"
    }

    fn agent_name(&self) -> &'static str {
        "OpenHands"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join("config.toml").exists()
            || home.as_ref().map(|h| h.join(".openhands").join("config.toml").exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_openhands_config(&project_root.join("config.toml"), project_root));
        if let Some(h) = &home {
            out.extend(parse_openhands_config(&h.join(".openhands").join("config.toml"), h));
        }

        out
    }
}

fn parse_openhands_config(path: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    // Lenient parse (strict first, then a backslash-repair retry) — the
    // same real-world Windows breakage `codex.rs` handles: a raw path
    // pasted into a TOML basic string without escaping its backslashes
    // (`"C:\Users\..."`, `\U` is an invalid escape). Found via a fixture,
    // 2026-09-06 (STATUS.md 5e).
    let Some(root) = crate::codex::parse_toml_leniently(&text) else {
        return Vec::new();
    };
    let Some(stdio_servers) = root.get("mcp").and_then(|m| m.get("stdio_servers")).and_then(|s| s.as_array())
    else {
        return Vec::new();
    };
    let list: Vec<serde_json::Value> =
        stdio_servers.iter().filter_map(|entry| serde_json::to_value(entry).ok()).collect();
    let servers = list_to_server_map(&list);
    parse_server_map(&servers, path, base_dir, ConfigSourceKind::OpenHandsMcpToml, "openhands", "OpenHands")
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
            "agentguard-openhands-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_config() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), "").unwrap();

        assert!(OpenHandsAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_stdio_servers_from_the_array_of_inline_tables() {
        let dir = unique_temp_dir("discover");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.toml"),
            r#"
[mcp]
stdio_servers = [
    {name="fetch", command="uvx", args=["mcp-server-fetch"]},
    {name="filesystem", command="npx", args=["@modelcontextprotocol/server-filesystem", "/"], env={DEBUG="true"}}
]
"#,
        )
        .unwrap();

        let discovered = OpenHandsAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 2);
        let names: Vec<_> = mcp.iter().map(|d| d.artifact.name.as_str()).collect();
        assert!(names.contains(&"fetch"));
        assert!(names.contains(&"filesystem"));
        assert!(mcp.iter().all(|d| d.artifact.discovered_by.contains("openhands")));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recovers_a_config_with_unescaped_windows_paths() {
        // STATUS.md 5e: a real Windows config.toml often has a raw path in
        // a basic string (`"C:\Users\..."`) -- `\U` is an invalid TOML
        // escape, so strict `toml::from_str` fails and the whole file
        // (and every server in it) was silently skipped. Lenient parse
        // (shared with codex.rs) recovers it.
        let dir = unique_temp_dir("winpath");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.toml"),
            "[mcp]\nstdio_servers = [\n  { name = \"fs\", command = \"node\", args = [\"C:\\Users\\dev\\mcp\\server.js\"] },\n]\n",
        )
        .unwrap();

        let discovered = OpenHandsAdapter.discover(&dir);
        let mcp: Vec<_> = discovered
            .iter()
            .filter(|d| d.config_source.as_ref().map(|cs| cs.path.starts_with(&dir)).unwrap_or(false))
            .collect();
        assert_eq!(mcp.len(), 1, "the server must be discovered despite the unescaped path");
        assert_eq!(mcp[0].artifact.name, "fs");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ignores_shttp_and_sse_servers_not_yet_supported() {
        // Documents the real, deliberate gap: unnamed remote array
        // entries aren't parsed at all -- this test exists so a future
        // change to support them updates this assertion deliberately.
        let dir = unique_temp_dir("remote-gap");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.toml"),
            r#"
[mcp]
shttp_servers = ["https://api.example.com/mcp/shttp"]
sse_servers = ["http://example.com:8080/mcp"]
"#,
        )
        .unwrap();

        let discovered = OpenHandsAdapter.discover(&dir);
        assert!(discovered.iter().all(|d| d.artifact.kind != ArtifactKind::McpServer));

        std::fs::remove_dir_all(&dir).ok();
    }
}
