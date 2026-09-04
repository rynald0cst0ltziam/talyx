//! Claude Code adapter — the only Tier-1 adapter with full enforcement
//! planned (BUILD_PLAN.md §0, §5b: `PreToolUse` hooks are a real
//! interception point). MCP server discovery here also populates `launch`
//! and `config_source`, which `agentguard init` (in agentguard-cli) uses to
//! rewrite `.mcp.json`/`.claude.json` entries through the enforcement shim
//! (§5a) — that's the config-rewrite mechanism actually being enforced;
//! hook integration (§5b) is separate and not yet built.
//!
//! Config file locations below are the documented/common ones as of this
//! writing. Claude Code's config layout has changed before and will change
//! again — treat `detect`/`discover` returning nothing as "check these
//! paths are still current," not as "no agent present," and keep this file
//! as the single place those paths live so a version bump is a local edit,
//! not a hunt through the codebase (this is the adapter-maintenance
//! treadmill called out in BUILD_PLAN.md's audit notes).

use crate::{AgentAdapter, ConfigSource, ConfigSourceKind, DiscoveredArtifact, LaunchCommand};
use agentguard_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
    PublisherIdentity,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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

        // MCP servers — project scope (.mcp.json) and user scope (~/.claude.json).
        out.extend(parse_mcp_servers(&project_root.join(".mcp.json")));
        if let Some(h) = &home {
            out.extend(parse_mcp_servers(&h.join(".claude.json")));
        }

        // Hooks — project and user settings.json.
        out.extend(parse_hooks(
            &project_root.join(".claude").join("settings.json"),
        ));
        if let Some(h) = &home {
            out.extend(parse_hooks(&h.join(".claude").join("settings.json")));
        }

        // Skills — project and user skills directories.
        out.extend(discover_skills(&project_root.join(".claude").join("skills")));
        if let Some(h) = &home {
            out.extend(discover_skills(&h.join(".claude").join("skills")));
        }

        out
    }
}

fn discovered_by_set() -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    s.insert("claude-code".to_string());
    s
}

/// Parse a Claude Code-style `{ "mcpServers": { name: { command, args, env } } }`
/// config file. Used for both `.mcp.json` (project scope) and `.claude.json`
/// (user scope) — both use this same shape as of this writing.
fn parse_mcp_servers(path: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return out;
    };
    let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) else {
        return out;
    };
    // Relative script paths in the config are conventionally relative to
    // the config file's own directory, not the current process's working
    // directory — resolve against that, not `std::env::current_dir()`.
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));

    for (name, cfg) in servers {
        let raw_command = cfg.get("command").and_then(|c| c.as_str()).unwrap_or("");
        let raw_args: Vec<String> = cfg
            .get("args")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let has_env = cfg
            .get("env")
            .and_then(|e| e.as_object())
            .map(|o| !o.is_empty())
            .unwrap_or(false);

        // See through a config entry already routed through
        // agentguard-shim (from a previous `agentguard init`) back to the
        // real underlying command. Without this, every scan after the
        // first `init` would classify/scan the shim BINARY itself instead
        // of the artifact it wraps — permanently blinding drift detection
        // and re-scoring the moment protection is turned on. Found by
        // actually re-running `init` twice against a live fixture, not by
        // inspection: the second run silently stopped detecting a
        // capability change that the first run's baseline should have
        // caught a diff against.
        let (command, args) = match unwrap_shim_invocation(raw_command, &raw_args) {
            Some((real_command, real_args)) => (real_command, real_args),
            None => (raw_command.to_string(), raw_args),
        };

        let (source, scan_root, display_location) = classify_command(&command, &args, base_dir);

        let mut capabilities = vec![CapabilityFinding {
            capability: Capability::SpawnProcess,
            basis: EvidenceBasis::Declared,
            evidence: "launched as a subprocess by Claude Code's MCP config".to_string(),
            location: Some(path.display().to_string()),
        }];
        if has_env {
            capabilities.push(CapabilityFinding {
                capability: Capability::EnvironmentVariables,
                basis: EvidenceBasis::Declared,
                evidence: "MCP config supplies environment variables to this server".to_string(),
                location: Some(path.display().to_string()),
            });
        }

        let artifact = Artifact {
            id: Artifact::compute_id(ArtifactKind::McpServer, name, &source),
            kind: ArtifactKind::McpServer,
            name: name.clone(),
            version: None,
            publisher: guess_publisher(&source),
            source,
            content_hash: None,
            capabilities,
            discovered_by: discovered_by_set(),
        };

        out.push(DiscoveredArtifact {
            artifact,
            scan_root,
            display_location,
            launch: Some(LaunchCommand {
                command: command.to_string(),
                args,
            }),
            config_source: Some(ConfigSource {
                path: path.to_path_buf(),
                kind: ConfigSourceKind::ClaudeCodeMcpServersJson,
                entry_key: name.clone(),
            }),
        });
    }

    out
}

/// If `command`/`args` match agentguard-shim's own invocation convention
/// (`<artifact-id> -- <real-command> [real-args...]` — see
/// agentguard-shim/src/main.rs's module doc comment, the single owner of
/// this contract besides here), returns the real underlying command and
/// args. Matched on the shim binary's filename AND the `--`-separator
/// shape together, not either alone, to avoid false-unwrapping a
/// legitimate server that happens to pass `--` as a real argument for its
/// own reasons.
fn unwrap_shim_invocation(command: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    let looks_like_shim = Path::new(command)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("agentguard-shim"))
        .unwrap_or(false);
    if !looks_like_shim {
        return None;
    }
    // Shape is [artifact_id, "--", real_command, ...real_args] — need at
    // least 3 elements to have a real command to unwrap to.
    if args.len() < 3 || args[1] != "--" {
        return None;
    }
    Some((args[2].clone(), args[3..].to_vec()))
}

/// Best-effort classification of an MCP server's launch command into a
/// source we can reason about. Deliberately conservative: anything we can't
/// confidently classify falls through to a bare LocalPath with no scan_root
/// rather than guessing — an artifact with thin evidence lands with fewer
/// findings, which is a weaker signal, not a wrong one.
fn classify_command(
    command: &str,
    args: &[String],
    base_dir: &Path,
) -> (ArtifactSource, Option<PathBuf>, String) {
    /// Resolve a possibly-relative path against `base_dir` (the config
    /// file's own directory) rather than the process's current directory.
    fn resolve(base_dir: &Path, candidate: &str) -> PathBuf {
        let p = Path::new(candidate);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            base_dir.join(p)
        }
    }

    let runner = Path::new(command)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
        .to_lowercase();

    if matches!(runner.as_str(), "npx" | "npm" | "pnpm" | "yarn" | "bunx") {
        if let Some(pkg) = args.iter().find(|a| !a.starts_with('-')) {
            let source = ArtifactSource::Registry {
                name: pkg.clone(),
                registry: "npm".to_string(),
            };
            return (source, None, format!("npm:{pkg} (via {command})"));
        }
    }
    if matches!(runner.as_str(), "uvx" | "pipx" | "pip" | "uv") {
        if let Some(pkg) = args.iter().find(|a| !a.starts_with('-')) {
            let source = ArtifactSource::Registry {
                name: pkg.clone(),
                registry: "pypi".to_string(),
            };
            return (source, None, format!("pypi:{pkg} (via {command})"));
        }
    }

    // A generic language runtime with a script path argument — e.g.
    // `"command": "node", "args": ["./mcp-servers/foo/index.js"]`. This is
    // the most common real-world MCP server launch shape; the scannable
    // target is the script argument, not the runtime binary itself.
    if matches!(
        runner.as_str(),
        "node" | "python" | "python3" | "bun" | "deno" | "ts-node"
    ) {
        if let Some(script) = args.iter().find(|a| !a.starts_with('-')) {
            let resolved = resolve(base_dir, script);
            if resolved.is_file() {
                return (
                    ArtifactSource::LocalPath(script.clone()),
                    Some(resolved),
                    format!("{script} (via {command})"),
                );
            }
        }
    }

    // Looks like a local script/binary path rather than a package runner.
    let looks_like_path = command.contains('/') || command.contains('\\');
    if looks_like_path {
        let resolved = resolve(base_dir, command);
        let scan_root = if resolved.is_file() || resolved.is_dir() {
            Some(resolved)
        } else {
            None
        };
        return (
            ArtifactSource::LocalPath(command.to_string()),
            scan_root,
            command.to_string(),
        );
    }

    // Bare command name (e.g. a globally-installed binary) — treat as an
    // executable we can identify but not statically scan.
    (
        ArtifactSource::LocalPath(command.to_string()),
        None,
        command.to_string(),
    )
}

fn guess_publisher(source: &ArtifactSource) -> PublisherIdentity {
    match source {
        ArtifactSource::Registry { name, .. } => {
            // Scoped npm packages (@org/pkg) name the org explicitly; use
            // that as the publisher guess. Never set `verified` here —
            // verification is an explicit step (BUILD_PLAN.md §7), not an
            // inference from a package name.
            let guessed = if let Some(stripped) = name.strip_prefix('@') {
                stripped.split('/').next().unwrap_or(name).to_string()
            } else {
                name.clone()
            };
            PublisherIdentity {
                name: Some(guessed),
                repo_url: None,
                verified: false,
            }
        }
        ArtifactSource::GitUrl(url) => PublisherIdentity {
            name: Some(url.clone()),
            repo_url: Some(url.clone()),
            verified: false,
        },
        ArtifactSource::LocalPath(_) => PublisherIdentity::default(),
    }
}

/// Recursively pull every `"command"` string found under a JSON `hooks`
/// subtree. Deliberately schema-loose rather than modeling Claude Code's
/// exact hook config shape field-by-field — that shape has changed before,
/// and "find every command hooks would run" degrades gracefully across
/// schema versions where a strict struct would just fail to parse.
fn parse_hooks(path: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return out;
    };
    let Some(hooks_val) = json.get("hooks") else {
        return out;
    };

    let mut commands = Vec::new();
    collect_command_strings(hooks_val, &mut commands);

    for (i, cmd) in commands.into_iter().enumerate() {
        let source = ArtifactSource::LocalPath(cmd.clone());
        let artifact = Artifact {
            id: Artifact::compute_id(ArtifactKind::Hook, &format!("hook-{i}-{cmd}"), &source),
            kind: ArtifactKind::Hook,
            name: cmd.clone(),
            version: None,
            publisher: PublisherIdentity::default(),
            source,
            content_hash: None,
            capabilities: vec![
                CapabilityFinding {
                    capability: Capability::Hook,
                    basis: EvidenceBasis::Declared,
                    evidence: "registered in Claude Code's hooks config".to_string(),
                    location: Some(path.display().to_string()),
                },
                CapabilityFinding {
                    capability: Capability::ExecuteShell,
                    basis: EvidenceBasis::Declared,
                    evidence: "hooks run a shell command on agent lifecycle events".to_string(),
                    location: Some(path.display().to_string()),
                },
            ],
            discovered_by: discovered_by_set(),
        };
        out.push(DiscoveredArtifact {
            artifact,
            scan_root: None,
            display_location: cmd,
            // Hooks are technically rewritable the same way MCP servers
            // are (single fixed command), but config-rewrite support for
            // them is out of v0 scope — see BUILD_PLAN.md's scope notes.
            // Caching a decision for a hook (via `agentguard init`) still
            // works; nothing currently enforces it.
            launch: None,
            config_source: None,
        });
    }

    out
}

fn collect_command_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get("command") {
                out.push(s.clone());
            }
            for v in map.values() {
                collect_command_strings(v, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_command_strings(item, out);
            }
        }
        _ => {}
    }
}

/// Every subdirectory of `dir` containing a `SKILL.md` is treated as a
/// skill artifact. Its capabilities aren't populated here — the CLI hands
/// `scan_root` to agentguard-scanner for that.
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
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwraps_a_shim_invocation() {
        let args = vec![
            "MCP server:foo:local:./x.js".to_string(),
            "--".to_string(),
            "node".to_string(),
            "./x.js".to_string(),
        ];
        let result = unwrap_shim_invocation("/some/path/agentguard-shim.exe", &args);
        assert_eq!(
            result,
            Some(("node".to_string(), vec!["./x.js".to_string()]))
        );
    }

    #[test]
    fn does_not_unwrap_an_unrelated_command_with_a_bare_double_dash() {
        // A real server that happens to pass `--` as one of its own args
        // must NOT be misidentified as an already-wrapped shim entry.
        let args = vec!["--".to_string(), "--verbose".to_string()];
        assert_eq!(unwrap_shim_invocation("some-real-mcp-server", &args), None);
    }

    #[test]
    fn does_not_unwrap_when_shim_named_binary_lacks_the_expected_arg_shape() {
        let args = vec!["only-one-arg".to_string()];
        assert_eq!(
            unwrap_shim_invocation("/path/agentguard-shim.exe", &args),
            None
        );
    }

    #[test]
    fn parse_mcp_servers_sees_through_an_already_wrapped_entry() {
        // Regression test for the exact bug found via a live fixture: once
        // `agentguard init` rewrites a config entry to launch through the
        // shim, a later scan must still classify/scan the REAL underlying
        // script, not the shim binary itself — otherwise every scan after
        // the first `init` is permanently blind to the artifact's actual
        // content.
        let dir = std::env::temp_dir().join(format!(
            "agentguard-claude-code-test-{}-{}",
            std::process::id(),
            UniqueTestId::next()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("index.js");
        std::fs::write(&script, "console.log('hi');").unwrap();

        let config_path = dir.join(".mcp.json");
        let shim_path = dir.join("agentguard-shim.exe");
        let config = serde_json::json!({
            "mcpServers": {
                "already-wrapped": {
                    "command": shim_path.to_string_lossy(),
                    "args": [
                        "MCP server:already-wrapped:local:index.js",
                        "--",
                        "node",
                        "index.js"
                    ]
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers(&config_path);
        assert_eq!(discovered.len(), 1);
        let d = &discovered[0];
        // scan_root should point at the real script next to the config,
        // NOT at the shim binary.
        assert_eq!(d.scan_root.as_deref(), Some(script.as_path()));
        let launch = d.launch.as_ref().unwrap();
        assert_eq!(launch.command, "node");
        assert_eq!(launch.args, vec!["index.js".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    struct UniqueTestId;
    impl UniqueTestId {
        fn next() -> u64 {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::Relaxed)
        }
    }
}
