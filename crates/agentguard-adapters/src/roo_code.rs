//! Roo Code adapter -- "the same architecture as Cline, a different VS
//! Code extension id" per Warden-AI's own registration code (see
//! cline.rs's module doc comment for the full verification citation).
//! Extension id `rooveterinaryinc.roo-cline`, same `globalStorage` path
//! shape as Cline, same `cline_mcp_settings.json` filename (Roo Code is a
//! fork of Cline and kept its config format), same `{"mcpServers": {...}}`
//! shape.

use crate::cline::vs_code_global_storage_dir;
use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use std::path::{Path, PathBuf};

const EXTENSION_ID: &str = "rooveterinaryinc.roo-cline";
const SETTINGS_FILENAME: &str = "cline_mcp_settings.json";

pub struct RooCodeAdapter;

impl AgentAdapter for RooCodeAdapter {
    fn agent_id(&self) -> &'static str {
        "roo-code"
    }

    fn agent_name(&self) -> &'static str {
        "Roo Code"
    }

    fn detect(&self, _project_root: &Path) -> bool {
        settings_path().map(|p| p.exists()).unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let Some(path) = settings_path() else {
            return Vec::new();
        };
        parse_mcp_servers_json(
            &path,
            project_root,
            ConfigSourceKind::RooCodeMcpJson,
            "mcpServers",
            "roo-code",
            "Roo Code",
        )
    }
}

fn settings_path() -> Option<PathBuf> {
    Some(vs_code_global_storage_dir()?.join(EXTENSION_ID).join("settings").join(SETTINGS_FILENAME))
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
            "agentguard-roo-code-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn parses_the_shared_mcp_servers_shape_directly() {
        let dir = unique_temp_dir("parse");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cline_mcp_settings.json");
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(
            &path,
            &dir,
            ConfigSourceKind::RooCodeMcpJson,
            "mcpServers",
            "roo-code",
            "Roo Code",
        );
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "example");
        assert!(discovered[0].artifact.discovered_by.contains("roo-code"));
        assert_eq!(discovered[0].artifact.kind, ArtifactKind::McpServer);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn settings_path_includes_the_real_extension_id_and_differs_from_cline() {
        let path = settings_path().expect("home dir should resolve on a real OS");
        assert!(path.to_string_lossy().contains("rooveterinaryinc.roo-cline"));
        assert!(!path.to_string_lossy().contains("saoudrizwan.claude-dev"));
    }
}
