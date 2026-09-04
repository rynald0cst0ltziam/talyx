//! Shared MCP-server config parsing. The `{ "mcpServers": { name: {
//! command, args, env } } }` JSON shape is used identically by Claude Code
//! (`.mcp.json` project-scope / `~/.claude.json` user-scope) and Cursor
//! (`.cursor/mcp.json` project-scope / `~/.cursor/mcp.json` user-scope) as
//! of this writing, so the parsing/classification/shim-unwrap logic lives
//! here once instead of duplicated per adapter. If an agent's config shape
//! ever diverges from this one, that adapter should stop calling this and
//! own its own parser — don't bend this one into covering two shapes.

use crate::{ConfigSource, ConfigSourceKind, DiscoveredArtifact, LaunchCommand};
use agentguard_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
    PublisherIdentity,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Parses one `mcpServers`-shaped config file into `DiscoveredArtifact`s.
/// `kind` tags the resulting `ConfigSource` for the rewrite step in
/// agentguard-cli's init.rs; `agent_id`/`agent_display_name` go into
/// `discovered_by` and the capability evidence text respectively.
///
/// `base_dir` is where relative script paths in the config resolve
/// against — deliberately an explicit parameter, NOT derived from
/// `path.parent()`: that coincidentally equals the project root for
/// Claude Code's `.mcp.json` (which sits directly in it) but is WRONG for
/// Cursor's `.cursor/mcp.json` (one directory deeper — relative paths
/// there are still relative to the project root, not to `.cursor/`).
/// Found via a live fixture: a Cursor-scoped malicious server's script
/// silently failed to resolve and fell back to declared-evidence-only
/// scoring instead of being statically scanned at all.
pub(crate) fn parse_mcp_servers_json(
    path: &Path,
    base_dir: &Path,
    kind: ConfigSourceKind,
    agent_id: &str,
    agent_display_name: &str,
) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return out;
    };
    let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) else {
        return out;
    };

    for (name, cfg) in servers {
        // Remote MCP server — `{ "type": "http" | "sse", "url": "...",
        // "headers": {...} }` instead of a local `command`/`args`. This is
        // an increasingly common shape (Notion, Linear, Sentry, and other
        // vendors ship this way rather than an npm package) that the
        // original version of this parser didn't recognize at all —
        // every remote entry was silently dropped. No local content to
        // scan or hash; the URL's host is the reputation-relevant
        // identity, and there's nothing here for `agentguard init` to
        // route through the shim (there's no local process to wrap).
        if let Some(url) = cfg.get("url").and_then(|u| u.as_str()) {
            out.push(remote_mcp_artifact(name, url, cfg, path, agent_id, agent_display_name));
            continue;
        }

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
        // real underlying command — see `unwrap_shim_invocation`'s doc
        // comment for why this matters (a live-fixture-found bug).
        let (command, args) = match unwrap_shim_invocation(raw_command, &raw_args) {
            Some((real_command, real_args)) => (real_command, real_args),
            None => (raw_command.to_string(), raw_args),
        };

        let (source, scan_root, display_location) = classify_command(&command, &args, base_dir);

        let mut capabilities = vec![CapabilityFinding {
            capability: Capability::SpawnProcess,
            basis: EvidenceBasis::Declared,
            evidence: format!("launched as a subprocess by {agent_display_name}'s MCP config"),
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

        let mut discovered_by = BTreeSet::new();
        discovered_by.insert(agent_id.to_string());

        let artifact = Artifact {
            id: Artifact::compute_id(ArtifactKind::McpServer, name, &source),
            kind: ArtifactKind::McpServer,
            name: name.clone(),
            version: None,
            publisher: guess_publisher(&source),
            source,
            content_hash: None,
            capabilities,
            discovered_by,
        };

        out.push(DiscoveredArtifact {
            artifact,
            scan_root,
            display_location,
            launch: Some(LaunchCommand {
                command: command.clone(),
                args,
            }),
            config_source: Some(ConfigSource {
                path: path.to_path_buf(),
                kind,
                entry_key: name.clone(),
            }),
        });
    }

    out
}

/// Builds a `DiscoveredArtifact` for a remote (HTTP/SSE) MCP server entry.
/// No `scan_root` (nothing local to hash or statically scan) and no
/// `launch`/`config_source` (the shim wraps a local subprocess launch;
/// there's no local process here to wrap — gating a remote network
/// service is a different enforcement problem, out of v0 scope).
fn remote_mcp_artifact(
    name: &str,
    url: &str,
    cfg: &Value,
    path: &Path,
    agent_id: &str,
    agent_display_name: &str,
) -> DiscoveredArtifact {
    let source = ArtifactSource::RemoteUrl(url.to_string());

    let mut capabilities = vec![CapabilityFinding {
        capability: Capability::NetworkExternal,
        basis: EvidenceBasis::Declared,
        evidence: format!("remote MCP server declared by {agent_display_name}'s config (reached over HTTP/SSE, not launched locally)"),
        location: Some(path.display().to_string()),
    }];
    // Headers that look like they carry a credential (Authorization,
    // X-Api-Key, etc.) are a declared signal this server involves a
    // secret/token, same spirit as the local-command path's env-var check.
    let has_auth_header = cfg
        .get("headers")
        .and_then(|h| h.as_object())
        .map(|headers| {
            headers.keys().any(|k| {
                let kl = k.to_lowercase();
                kl.contains("auth") || kl.contains("token") || kl.contains("key")
            })
        })
        .unwrap_or(false);
    if has_auth_header {
        capabilities.push(CapabilityFinding {
            capability: Capability::ApiKeys,
            basis: EvidenceBasis::Declared,
            evidence: "config supplies an authorization/token header for this remote server".to_string(),
            location: Some(path.display().to_string()),
        });
    }

    let mut discovered_by = BTreeSet::new();
    discovered_by.insert(agent_id.to_string());

    let artifact = Artifact {
        id: Artifact::compute_id(ArtifactKind::McpServer, name, &source),
        kind: ArtifactKind::McpServer,
        name: name.to_string(),
        version: None,
        publisher: guess_publisher(&source),
        source,
        content_hash: None,
        capabilities,
        discovered_by,
    };

    DiscoveredArtifact {
        display_location: url.to_string(),
        scan_root: None,
        artifact,
        launch: None,
        config_source: None,
    }
}

/// Naive registrable-domain extraction: strips scheme/port/path and takes
/// the last two dot-separated labels (`mcp.notion.com` -> `notion.com`).
/// Doesn't handle multi-part public suffixes (`.co.uk` etc.) correctly —
/// acceptable for v0 matching against a small, manually-verified trust
/// seed where every entry is checked against this exact logic, but not a
/// substitute for a real public-suffix-list-aware parser if this needs to
/// be precise at scale later.
fn host_registrable_domain(url: &str) -> Option<String> {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?; // strip a port, if present
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() >= 2 {
        Some(format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]))
    } else if !host.is_empty() {
        Some(host.to_string())
    } else {
        None
    }
}

/// If `command`/`args` match agentguard-shim's own invocation convention
/// (`<artifact-id> -- <real-command> [real-args...]` — see
/// agentguard-shim/src/main.rs's module doc comment, the single owner of
/// this contract besides here), returns the real underlying command and
/// args. Matched on the shim binary's filename AND the `--`-separator
/// shape together, not either alone, to avoid false-unwrapping a
/// legitimate server that happens to pass `--` as a real argument for its
/// own reasons.
///
/// Found via a live fixture, not by inspection: without this, once
/// `agentguard init` rewrites a config entry to launch through the shim,
/// every later scan would classify/scan the shim BINARY itself instead of
/// the artifact it wraps — permanently blinding drift detection and
/// re-scoring the moment protection is turned on.
pub(crate) fn unwrap_shim_invocation(command: &str, args: &[String]) -> Option<(String, Vec<String>)> {
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
pub(crate) fn classify_command(
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

pub(crate) fn guess_publisher(source: &ArtifactSource) -> PublisherIdentity {
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
        ArtifactSource::GitUrl(url) => {
            // github.com/<owner>/<repo> (and gitlab.com, bitbucket.org)
            // name the owner/org explicitly, same spirit as the npm-scope
            // case above — extract it so this is exact-matchable against
            // a trust-seed entry, instead of leaving the whole URL as the
            // "name" (which would never exact-match a short org name).
            let guessed = extract_git_host_owner(url);
            PublisherIdentity {
                name: guessed.or_else(|| Some(url.clone())),
                repo_url: Some(url.clone()),
                verified: false,
            }
        }
        ArtifactSource::RemoteUrl(url) => PublisherIdentity {
            // The registrable domain is the reputation-relevant identity
            // for a remote MCP server — see host_registrable_domain's doc
            // comment for the (deliberately simple) extraction logic.
            name: host_registrable_domain(url),
            repo_url: None,
            verified: false,
        },
        ArtifactSource::LocalPath(_) => PublisherIdentity::default(),
    }
}

/// Extracts `<owner>` from a `https://github.com/<owner>/<repo>`-shaped URL
/// (and the gitlab.com/bitbucket.org equivalents) — `None` for anything
/// else, which falls back to using the full URL as the publisher name.
fn extract_git_host_owner(url: &str) -> Option<String> {
    const KNOWN_HOSTS: &[&str] = &["github.com/", "gitlab.com/", "bitbucket.org/"];
    for host in KNOWN_HOSTS {
        if let Some(idx) = url.find(host) {
            let rest = &url[idx + host.len()..];
            if let Some(owner) = rest.split('/').next() {
                if !owner.is_empty() {
                    return Some(owner.to_string());
                }
            }
        }
    }
    None
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
    fn host_registrable_domain_strips_subdomain_scheme_and_path() {
        assert_eq!(
            host_registrable_domain("https://mcp.notion.com/mcp"),
            Some("notion.com".to_string())
        );
        assert_eq!(
            host_registrable_domain("https://mcp.linear.app/mcp/readonly"),
            Some("linear.app".to_string())
        );
        assert_eq!(
            host_registrable_domain("https://mcp.sentry.dev/mcp/org/project"),
            Some("sentry.dev".to_string())
        );
    }

    #[test]
    fn extract_git_host_owner_pulls_the_github_org() {
        assert_eq!(
            extract_git_host_owner("https://github.com/github/github-mcp-server"),
            Some("github".to_string())
        );
        assert_eq!(extract_git_host_owner("https://example.com/not-a-git-host"), None);
    }

    #[test]
    fn discovers_a_remote_http_mcp_server_entry() {
        // Regression test for a real gap: the original parser only
        // recognized `{ "command": ..., "args": ... }` and silently
        // dropped every `{ "type": "http", "url": ... }` remote entry --
        // an increasingly common shape (Notion, Linear, Sentry and others
        // ship this way instead of an npm package).
        let dir = unique_temp_dir("remote-mcp");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        let config = serde_json::json!({
            "mcpServers": {
                "linear": {
                    "type": "http",
                    "url": "https://mcp.linear.app/mcp",
                    "headers": { "Authorization": "Bearer example" }
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(
            &config_path,
            &dir,
            ConfigSourceKind::ClaudeCodeMcpServersJson,
            "claude-code",
            "Claude Code",
        );
        assert_eq!(discovered.len(), 1);
        let d = &discovered[0];
        assert_eq!(d.scan_root, None);
        assert_eq!(d.launch, None, "a remote server has no local process to wrap");
        assert_eq!(d.config_source, None, "a remote server isn't rewritable via the shim");
        assert_eq!(d.artifact.publisher.name.as_deref(), Some("linear.app"));
        let caps: Vec<_> = d.artifact.capabilities.iter().map(|c| c.capability).collect();
        assert!(caps.contains(&Capability::NetworkExternal));
        assert!(
            caps.contains(&Capability::ApiKeys),
            "an Authorization header should be picked up as a declared credential signal"
        );

        std::fs::remove_dir_all(&dir).ok();
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

    fn unique_temp_dir(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "agentguard-mcp-config-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn sees_through_an_already_wrapped_entry() {
        // Regression test for the exact bug found via a live fixture: once
        // `agentguard init` rewrites a config entry to launch through the
        // shim, a later scan must still classify/scan the REAL underlying
        // script, not the shim binary itself.
        let dir = unique_temp_dir("wrapped");
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

        let discovered = parse_mcp_servers_json(
            &config_path,
            &dir,
            ConfigSourceKind::ClaudeCodeMcpServersJson,
            "claude-code",
            "Claude Code",
        );
        assert_eq!(discovered.len(), 1);
        let d = &discovered[0];
        assert_eq!(d.scan_root.as_deref(), Some(script.as_path()));
        let launch = d.launch.as_ref().unwrap();
        assert_eq!(launch.command, "node");
        assert_eq!(launch.args, vec!["index.js".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tags_discovered_artifacts_with_the_given_agent_and_kind() {
        let dir = unique_temp_dir("tagging");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(
            &config_path,
            &dir,
            ConfigSourceKind::CursorMcpJson,
            "cursor",
            "Cursor",
        );
        assert_eq!(discovered.len(), 1);
        assert!(discovered[0].artifact.discovered_by.contains("cursor"));
        assert_eq!(
            discovered[0].config_source.as_ref().unwrap().kind,
            ConfigSourceKind::CursorMcpJson
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_relative_scripts_against_base_dir_not_the_configs_own_directory() {
        // Regression test for a real bug: Cursor's config lives at
        // `.cursor/mcp.json`, one directory deeper than the project root,
        // but a relative script path in it is still relative to the
        // project root, not to `.cursor/`. Reproduces that exact layout.
        let project_root = unique_temp_dir("nested-config-root");
        let config_dir = project_root.join(".cursor");
        std::fs::create_dir_all(&config_dir).unwrap();
        let script = project_root.join("server.js");
        std::fs::write(&script, "console.log('hi');").unwrap();

        let config_path = config_dir.join("mcp.json");
        let config = serde_json::json!({
            "mcpServers": {
                "nested": { "command": "node", "args": ["server.js"] }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        // Passing project_root (not config_path.parent(), which would be
        // config_dir) is the fix under test.
        let discovered = parse_mcp_servers_json(
            &config_path,
            &project_root,
            ConfigSourceKind::CursorMcpJson,
            "cursor",
            "Cursor",
        );
        assert_eq!(discovered.len(), 1);
        assert_eq!(
            discovered[0].scan_root.as_deref(),
            Some(script.as_path()),
            "relative script path should resolve against base_dir (project root), not the config file's own directory"
        );

        std::fs::remove_dir_all(&project_root).ok();
    }
}
