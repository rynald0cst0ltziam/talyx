//! Shared MCP-server config parsing. The `{ "mcpServers": { name: {
//! command, args, env } } }` JSON shape is used identically by Claude Code
//! (`.mcp.json` project-scope / `~/.claude.json` user-scope) and Cursor
//! (`.cursor/mcp.json` project-scope / `~/.cursor/mcp.json` user-scope) as
//! of this writing, so the parsing/classification/shim-unwrap logic lives
//! here once instead of duplicated per adapter. If an agent's config shape
//! ever diverges from this one, that adapter should stop calling this and
//! own its own parser — don't bend this one into covering two shapes.

use crate::{ConfigSource, ConfigSourceKind, DiscoveredArtifact, LaunchCommand};
use talyx_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
    PublisherIdentity,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Parses one `mcpServers`-shaped config file into `DiscoveredArtifact`s.
/// `kind` tags the resulting `ConfigSource` for the rewrite step in
/// talyx-cli's init.rs; `agent_id`/`agent_display_name` go into
/// `discovered_by` and the capability evidence text respectively.
///
/// `top_level_key` is the JSON key the server map sits under — `
/// "mcpServers"` for every agent covered so far except VS Code's Copilot
/// Chat extension, which documents `"servers"` instead (verified against
/// code.visualstudio.com/docs/agents/reference/mcp-configuration, not
/// assumed identical to every other tool just because the per-server
/// shape underneath is the same). Kept as an explicit parameter rather
/// than hardcoding `"mcpServers"` so a genuinely different top-level key
/// is a deliberate choice at each call site, not a silent assumption.
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
    top_level_key: &str,
    agent_id: &str,
    agent_display_name: &str,
) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let Some(servers) = json.get(top_level_key).and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    parse_server_map(servers, path, base_dir, kind, agent_id, agent_display_name)
}

/// YAML counterpart of `parse_mcp_servers_json` — same contract, same
/// shared `parse_server_map` underneath, just parsed with `serde_saphyr`
/// (see this crate's `Cargo.toml` for why that crate, not the deprecated
/// `serde_yaml`) into the identical `serde_json::Value` the JSON path
/// produces. Exists as its own function (not a branch inside the JSON
/// one) so a YAML-specific parse failure is handled the same
/// fail-empty-not-panic way, and so callers are explicit about which
/// format they're reading rather than the function guessing from a file
/// extension.
pub(crate) fn parse_mcp_servers_yaml(
    path: &Path,
    base_dir: &Path,
    kind: ConfigSourceKind,
    top_level_key: &str,
    agent_id: &str,
    agent_display_name: &str,
) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_saphyr::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let Some(servers) = json.get(top_level_key).and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    parse_server_map(servers, path, base_dir, kind, agent_id, agent_display_name)
}

/// Warp's `~/.warp/.mcp.json`: the servers are a flat map at the JSON
/// root (`{ "github": {...}, "sentry": {...} }`), per Warp's own CLI
/// docs' example — NOT wrapped in `mcpServers`. Checks for an `mcpServers`
/// wrapper first (some Warp versions / hand-edits use it), then falls
/// back to the root object when its values look like server configs
/// (have a `command` or `url`).
pub(crate) fn parse_mcp_servers_json_root_or_wrapped(
    path: &Path,
    base_dir: &Path,
    kind: ConfigSourceKind,
    agent_id: &str,
    agent_display_name: &str,
) -> Vec<DiscoveredArtifact> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let servers = json
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .or_else(|| {
            json.as_object().filter(|m| {
                m.values()
                    .any(|v| v.get("command").is_some() || v.get("url").is_some())
            })
        });
    let Some(servers) = servers else {
        return Vec::new();
    };
    parse_server_map(servers, path, base_dir, kind, agent_id, agent_display_name)
}

/// Converts a LIST-shaped `mcpServers` (`[{name, command, args}, ...]` --
/// Continue.dev's and Aider's own YAML convention, genuinely different
/// from every other agent's name-keyed MAP) into the map `parse_server_map`
/// expects, keyed by each entry's `"name"` field. An entry missing `name`
/// is skipped -- there's no key to file it under, and both agents' own
/// docs treat `name` as required.
pub(crate) fn list_to_server_map(list: &[Value]) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for entry in list {
        let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        out.insert(name.to_string(), entry.clone());
    }
    out
}

/// The per-server parsing loop shared by every caller that has already
/// located its `{ name: { command/args/env | url/serverUrl/httpUrl } }`
/// map, however it got there — a flat top-level key
/// (`parse_mcp_servers_json`) or a nested, dynamically-keyed path (Claude
/// Code's LOCAL-scope servers, nested under `projects["<absolute-project-
/// path>"].mcpServers` inside `~/.claude.json` — see `claude_code.rs`'s
/// `parse_local_scope_mcp_servers`). Split out so both paths share
/// identical remote-detection, command-classification, and capability
/// logic instead of drifting apart if duplicated.
pub(crate) fn parse_server_map(
    servers: &serde_json::Map<String, Value>,
    path: &Path,
    base_dir: &Path,
    kind: ConfigSourceKind,
    agent_id: &str,
    agent_display_name: &str,
) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    for (name, cfg) in servers {
        // A server marked "disabled": true never runs -- Kiro's and
        // OpenClaw's own docs confirm this per-server flag (verified
        // 2026-09-05), and surfacing a disabled entry as live risk would
        // be a false positive, same principle as hooks_config.rs's
        // "enabled": false skip for hooks. Harmless for every other agent,
        // which doesn't populate this field.
        if matches!(cfg.get("disabled"), Some(Value::Bool(true))) {
            continue;
        }

        // Remote MCP server — `{ "type": "http" | "sse", "url": "...",
        // "headers": {...} }` instead of a local `command`/`args`. This is
        // an increasingly common shape (Notion, Linear, Sentry, and other
        // vendors ship this way rather than an npm package) that the
        // original version of this parser didn't recognize at all —
        // every remote entry was silently dropped. No local content to
        // scan or hash, and no `launch` (no local process for the shim to
        // wrap) — but `config_source` IS populated: enforcement for a
        // remote entry means talyx-cli's init.rs including/excluding
        // it from the config outright, which still needs to know where
        // to find it.
        //
        // `url` is Claude Code/Cursor's field name; `serverUrl` is
        // Windsurf's (which also accepts `url`) and Antigravity's (which
        // documents ONLY `serverUrl`, not `url`); Gemini CLI splits
        // remote transport into `url` (SSE) and `httpUrl` (HTTP
        // streaming) — a third, distinct field name, not an alias for
        // either of the other two. Verified directly against each
        // vendor's own docs before adding any of these, not assumed to
        // be interchangeable. Checking all three here, in the shared
        // parser, means every caller gets all of them for free; harmless
        // for Claude Code/Cursor, which never populate `serverUrl` or
        // `httpUrl` at all.
        if let Some(url) = cfg
            .get("url")
            .or_else(|| cfg.get("serverUrl"))
            .or_else(|| cfg.get("httpUrl"))
            .and_then(|u| u.as_str())
        {
            out.push(remote_mcp_artifact(name, url, cfg, path, kind, agent_id, agent_display_name));
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
        // talyx-shim (from a previous `talyx init`) back to the
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
            raw_config_entry: None,
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
    kind: ConfigSourceKind,
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
    // `headers` is Claude Code / Cursor / most agents' field; Continue.dev
    // nests the same thing under `requestOptions.headers` (verified against
    // its own docs) — check both.
    let header_has_auth = |h: Option<&Value>| {
        h.and_then(|h| h.as_object())
            .map(|headers| {
                headers.keys().any(|k| {
                    let kl = k.to_lowercase();
                    kl.contains("auth") || kl.contains("token") || kl.contains("key")
                })
            })
            .unwrap_or(false)
    };
    let has_auth_header = header_has_auth(cfg.get("headers"))
        || header_has_auth(cfg.get("requestOptions").and_then(|r| r.get("headers")));
    // Some configs (OpenHands' `sse_servers` / `shttp_servers`, a few
    // others) carry the credential as a top-level `api_key` / `apiKey` /
    // `token` field rather than a header.
    let has_auth_field = cfg
        .as_object()
        .map(|o| {
            o.keys().any(|k| {
                let kl = k.to_lowercase();
                kl == "api_key" || kl == "apikey" || kl == "token" || kl == "authorization"
            })
        })
        .unwrap_or(false);
    if has_auth_header || has_auth_field {
        capabilities.push(CapabilityFinding {
            capability: Capability::ApiKeys,
            basis: EvidenceBasis::Declared,
            evidence: "config supplies an authorization token / API key for this remote server".to_string(),
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
        config_source: Some(ConfigSource {
            path: path.to_path_buf(),
            kind,
            entry_key: name.to_string(),
        }),
        raw_config_entry: serde_json::to_value(cfg).ok(),
    }
}

/// Naive registrable-domain extraction: strips scheme/port/path and takes
/// the last two dot-separated labels (`mcp.notion.com` -> `notion.com`).
/// Doesn't handle multi-part public suffixes (`.co.uk` etc.) correctly —
/// acceptable for v0 matching against a small, manually-verified trust
/// seed where every entry is checked against this exact logic, but not a
/// substitute for a real public-suffix-list-aware parser if this needs to
/// be precise at scale later.
/// Extracts the registrable domain (eTLD+1) from a URL's host, e.g.
/// `https://aws-mcp.us-east-1.api.aws/mcp` -> `api.aws`,
/// `https://foo.co.uk/mcp` -> `foo.co.uk`. Backed by the `psl` crate's
/// compiled-in copy of Mozilla's Public Suffix List (no network access,
/// deterministic, updated with each `psl` release) rather than a "last
/// two dot-labels" guess — a naive guess is wrong for any multi-label
/// public suffix (`.co.uk`, `.com.au`, and hundreds more), which would
/// have made `evil.co.uk` and a real `foo.co.uk` compare equal under
/// this codebase's exact-match reputation lookup (talyx-risk's
/// `reputation_discount`). Verified empirically against every domain in
/// `data/trust_seed.json` plus `foo.co.uk`/`evil.co.uk` before switching
/// to this — every existing seed entry round-trips to the identical
/// string, and the `.co.uk` case, previously indistinguishable, now
/// correctly separates.
fn host_registrable_domain(url: &str) -> Option<String> {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?; // strip a port, if present
    psl::domain_str(host).map(|d| d.to_string())
}

/// If `command`/`args` match talyx-shim's own invocation convention
/// (`<artifact-id> -- <real-command> [real-args...]` — see
/// talyx-shim/src/main.rs's module doc comment, the single owner of
/// this contract besides here), returns the real underlying command and
/// args. Matched on the shim binary's filename AND the `--`-separator
/// shape together, not either alone, to avoid false-unwrapping a
/// legitimate server that happens to pass `--` as a real argument for its
/// own reasons.
///
/// Found via a live fixture, not by inspection: without this, once
/// `talyx init` rewrites a config entry to launch through the shim,
/// every later scan would classify/scan the shim BINARY itself instead of
/// the artifact it wraps — permanently blinding drift detection and
/// re-scoring the moment protection is turned on.
pub(crate) fn unwrap_shim_invocation(command: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    let looks_like_shim = Path::new(command)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("talyx-shim"))
        .unwrap_or(false);
    if !looks_like_shim {
        return None;
    }
    // Shape is [artifact_id, ("--proxy")?, "--", real_command, ...real_args].
    // Skip an optional `--proxy` flag (written by `talyx init --live`)
    // before the `--` separator.
    let after_id = &args[1..];
    let rest = match after_id.first().map(String::as_str) {
        Some("--proxy") => &after_id[1..],
        _ => after_id,
    };
    // need [ "--", real_command, ...] — at least 2 elements after the id/flag
    if rest.len() < 2 || rest[0] != "--" {
        return None;
    }
    Some((rest[1].clone(), rest[2..].to_vec()))
}

/// For `<runner> <subcommand> [flags] <package>` shapes (`npm exec`,
/// `pnpm dlx`, `yarn dlx`, `pipx run`) — the subcommand word must be the
/// FIRST argument (not just present anywhere in `args`), and the package
/// spec is the first non-flag argument after it.
fn package_after_subcommand(args: &[String], subcommands: &[&str]) -> Option<String> {
    let first = args.first()?;
    if !subcommands.contains(&first.as_str()) {
        return None;
    }
    args[1..].iter().find(|a| !a.starts_with('-')).cloned()
}

/// `uv tool run [--from <pkg-spec>] <command> [args...]` — both
/// `--from <pkg>` and `--from=<pkg>` forms accepted.
fn uv_tool_run_package(args: &[String]) -> Option<String> {
    if args.first().map(String::as_str) != Some("tool") || args.get(1).map(String::as_str) != Some("run") {
        return None;
    }
    let rest = &args[2..];
    for (i, a) in rest.iter().enumerate() {
        if let Some(v) = a.strip_prefix("--from=") {
            return Some(v.to_string());
        }
        if a == "--from" {
            return rest.get(i + 1).cloned();
        }
    }
    rest.iter().find(|a| !a.starts_with('-')).cloned()
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

    // Direct-pass-through ad-hoc runners: the package spec IS the first
    // non-flag argument, no subcommand word involved -- genuinely how
    // npx/bunx/uvx work. Deliberately NOT "npm"/"pnpm"/"yarn"/"pipx"/"uv"
    // here even though they can also launch an ad-hoc package -- those
    // require a specific subcommand word first (`npm exec`, `pnpm dlx`,
    // `uv tool run`, ...), and treating "the first non-flag arg" as the
    // package name for THOSE would silently misclassify the subcommand
    // word itself as the package (e.g. `uv tool run --from black==24.1.0
    // black` would have produced a package named "tool"). Found live
    // while verifying this against uv's own docs, not from an actual
    // fixture failure -- fixed before it ever shipped classifying
    // anything wrong, by requiring the exact subcommand shape below
    // instead of guessing from "any non-flag argument."
    if matches!(runner.as_str(), "npx" | "bunx") {
        if let Some(pkg) = args.iter().find(|a| !a.starts_with('-')) {
            let source = ArtifactSource::Registry {
                name: pkg.clone(),
                registry: "npm".to_string(),
            };
            return (source, None, format!("npm:{pkg} (via {command})"));
        }
    }
    if runner == "uvx" {
        if let Some(pkg) = args.iter().find(|a| !a.starts_with('-')) {
            let source = ArtifactSource::Registry {
                name: pkg.clone(),
                registry: "pypi".to_string(),
            };
            return (source, None, format!("pypi:{pkg} (via {command})"));
        }
    }

    // Subcommand-style ad-hoc runners: `npm exec <pkg>` / `npm x <pkg>`,
    // `pnpm dlx <pkg>`, `yarn dlx <pkg>`, `pipx run <pkg>`. The
    // subcommand word must be the FIRST argument, and the package spec
    // is the first non-flag argument after it -- matching this file's
    // own stated design principle (fall through to no classification
    // rather than guess) when the shape isn't exactly this.
    if matches!(runner.as_str(), "npm" | "pnpm" | "yarn") {
        if let Some(pkg) = package_after_subcommand(args, &["exec", "dlx", "x"]) {
            let source = ArtifactSource::Registry { name: pkg.clone(), registry: "npm".to_string() };
            return (source, None, format!("npm:{pkg} (via {command} exec)"));
        }
    }
    if runner == "pipx" {
        if let Some(pkg) = package_after_subcommand(args, &["run"]) {
            let source = ArtifactSource::Registry { name: pkg.clone(), registry: "pypi".to_string() };
            return (source, None, format!("pypi:{pkg} (via pipx run)"));
        }
    }
    // `uv tool run [--from <pkg-spec>] <command> [args...]` -- verified
    // against uv's own docs (docs.astral.sh/uv/concepts/tools/, 2026-09-
    // 05): with --from, that value IS the package spec (may itself carry
    // ==version, handled by talyx-registry's parse_package_spec);
    // without it, uv resolves the package from the command name, so the
    // command name doubles as the package name.
    if runner == "uv" {
        if let Some(pkg) = uv_tool_run_package(args) {
            let display = format!("pypi:{pkg} (via uv tool run)");
            let source = ArtifactSource::Registry { name: pkg, registry: "pypi".to_string() };
            return (source, None, display);
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
        let result = unwrap_shim_invocation("/some/path/talyx-shim.exe", &args);
        assert_eq!(
            result,
            Some(("node".to_string(), vec!["./x.js".to_string()]))
        );
    }

    fn strs(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classify_command_recognizes_direct_npx_and_uvx() {
        let base = Path::new(".");
        let (source, _, _) = classify_command("npx", &strs(&["-y", "left-pad"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "left-pad".to_string(), registry: "npm".to_string() }
        );
        let (source, _, _) = classify_command("uvx", &strs(&["black"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "black".to_string(), registry: "pypi".to_string() }
        );
    }

    #[test]
    fn classify_command_does_not_misclassify_npm_install_as_a_package_named_install() {
        // Regression test for a real bug caught before it ever shipped:
        // the original version of this function took "the first non-flag
        // argument" as the package name for EVERY npm-family/uv-family
        // runner, which for a subcommand shape like `npm install <pkg>`
        // or `uv tool run --from <pkg> <cmd>` would silently treat the
        // subcommand word itself ("install", "tool") as the package name.
        // `npm install` isn't even an ad-hoc-run shape (it doesn't launch
        // anything), so this must fall through to no classification at
        // all, matching classify_command's own stated "don't guess"
        // design principle.
        let base = Path::new(".");
        let (source, scan_root, _) = classify_command("npm", &strs(&["install", "left-pad"]), base);
        assert!(!matches!(source, ArtifactSource::Registry { .. }));
        assert_eq!(scan_root, None);
    }

    #[test]
    fn classify_command_recognizes_npm_exec_pnpm_dlx_and_pipx_run() {
        let base = Path::new(".");
        let (source, _, _) = classify_command("npm", &strs(&["exec", "-y", "left-pad"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "left-pad".to_string(), registry: "npm".to_string() }
        );
        let (source, _, _) = classify_command("pnpm", &strs(&["dlx", "left-pad"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "left-pad".to_string(), registry: "npm".to_string() }
        );
        let (source, _, _) = classify_command("pipx", &strs(&["run", "black"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "black".to_string(), registry: "pypi".to_string() }
        );
    }

    #[test]
    fn classify_command_recognizes_uv_tool_run_with_and_without_from() {
        let base = Path::new(".");
        // Without --from: the command name doubles as the package name
        // (verified against uv's own docs).
        let (source, _, _) = classify_command("uv", &strs(&["tool", "run", "black"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "black".to_string(), registry: "pypi".to_string() }
        );
        // With --from: that value is the package spec, NOT the trailing
        // command -- this is exactly the shape that used to misclassify
        // "tool" as the package name.
        let (source, _, _) =
            classify_command("uv", &strs(&["tool", "run", "--from", "black==24.1.0", "blackd"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "black==24.1.0".to_string(), registry: "pypi".to_string() }
        );
        // --from=value form too.
        let (source, _, _) =
            classify_command("uv", &strs(&["tool", "run", "--from=black==24.1.0", "blackd"]), base);
        assert_eq!(
            source,
            ArtifactSource::Registry { name: "black==24.1.0".to_string(), registry: "pypi".to_string() }
        );
    }

    #[test]
    fn classify_command_does_not_classify_bare_uv_or_pip_without_a_recognized_subcommand() {
        // "uv" and "pip" alone (not "uv tool run" or a recognized ad-hoc
        // shape) are not ad-hoc package runners -- `pip install X` and a
        // bare `uv sync` don't launch anything either. Falls through to
        // no classification, same principle as the npm-install case.
        let base = Path::new(".");
        let (source, _, _) = classify_command("pip", &strs(&["install", "requests"]), base);
        assert!(!matches!(source, ArtifactSource::Registry { .. }));
        let (source, _, _) = classify_command("uv", &strs(&["sync"]), base);
        assert!(!matches!(source, ArtifactSource::Registry { .. }));
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
    fn host_registrable_domain_handles_multi_label_public_suffixes() {
        // Regression test for a real, previously-documented gap: a naive
        // "last two dot-labels" heuristic can't tell a multi-label public
        // suffix (.co.uk, .com.au, ...) from an ordinary two-label domain,
        // so it would extract "co.uk" as the registrable domain for BOTH
        // of these -- making them compare equal under the exact-match
        // reputation lookup in talyx-risk. Now backed by the `psl`
        // crate's compiled Mozilla Public Suffix List, they correctly
        // separate.
        assert_eq!(
            host_registrable_domain("https://mcp.foo.co.uk/mcp"),
            Some("foo.co.uk".to_string())
        );
        assert_eq!(
            host_registrable_domain("https://mcp.evil.co.uk/mcp"),
            Some("evil.co.uk".to_string())
        );
        assert_ne!(
            host_registrable_domain("https://mcp.foo.co.uk/mcp"),
            host_registrable_domain("https://mcp.evil.co.uk/mcp"),
        );
    }

    #[test]
    fn host_registrable_domain_handles_the_seeded_aws_region_scoped_host() {
        // api.aws is a real trust_seed.json entry (BUILD_PLAN.md §7's
        // AWS MCP Server entry) precisely because `aws` is a real,
        // Amazon-restricted ICANN TLD -- the public suffix list treats it
        // as a suffix, so the registrable domain of any
        // "<anything>.api.aws" host is "api.aws", not "aws" alone and not
        // the full region-qualified hostname.
        assert_eq!(
            host_registrable_domain("https://aws-mcp.us-east-1.api.aws/mcp"),
            Some("api.aws".to_string())
        );
        assert_eq!(
            host_registrable_domain("https://aws-mcp.eu-central-1.api.aws/mcp"),
            Some("api.aws".to_string())
        );
        // A domain that merely CONTAINS "api-aws" (hyphen, not a
        // subdomain of api.aws) must NOT collapse to the same registrable
        // domain -- it's an ordinary .com suffix.
        assert_eq!(
            host_registrable_domain("https://aws-mcp.us-east-1.api-aws.example.com/mcp"),
            Some("example.com".to_string())
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
            "mcpServers",
            "claude-code",
            "Claude Code",
        );
        assert_eq!(discovered.len(), 1);
        let d = &discovered[0];
        assert_eq!(d.scan_root, None);
        assert_eq!(d.launch, None, "a remote server has no local process to wrap");
        // Not None: there's no shim to route a remote server through (no
        // local process to wrap), but the entry is still block-or-remove
        // enforceable at the config-file level, and that path needs
        // exactly the same "where is this entry, what's its key" info a
        // local artifact's config_source carries.
        assert_eq!(
            d.config_source,
            Some(ConfigSource {
                path: config_path.clone(),
                kind: ConfigSourceKind::ClaudeCodeMcpServersJson,
                entry_key: "linear".to_string(),
            }),
            "a remote server's config_source is still populated -- init.rs uses it to remove/restore the entry"
        );
        assert_eq!(
            d.raw_config_entry,
            Some(config["mcpServers"]["linear"].clone()),
            "the original entry must be snapshotted so `talyx allow` can restore it later"
        );
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
    fn picks_up_an_auth_header_nested_under_request_options() {
        // Continue.dev's YAML puts a remote server's headers under
        // `requestOptions.headers`, not the top-level `headers` key every
        // other agent uses (STATUS.md 5f).
        let dir = unique_temp_dir("request-options-headers");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        let config = serde_json::json!({
            "mcpServers": {
                "notion": {
                    "url": "https://mcp.notion.com/mcp",
                    "requestOptions": { "headers": { "Authorization": "Bearer x" } }
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(
            &config_path,
            &dir,
            ConfigSourceKind::ContinueYamlMcpJson,
            "mcpServers",
            "continue-dev",
            "Continue.dev",
        );
        assert_eq!(discovered.len(), 1);
        let caps: Vec<_> = discovered[0]
            .artifact
            .capabilities
            .iter()
            .map(|c| c.capability)
            .collect();
        assert!(
            caps.contains(&Capability::ApiKeys),
            "an Authorization header under requestOptions.headers should still count"
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
            unwrap_shim_invocation("/path/talyx-shim.exe", &args),
            None
        );
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "talyx-mcp-config-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn sees_through_an_already_wrapped_entry() {
        // Regression test for the exact bug found via a live fixture: once
        // `talyx init` rewrites a config entry to launch through the
        // shim, a later scan must still classify/scan the REAL underlying
        // script, not the shim binary itself.
        let dir = unique_temp_dir("wrapped");
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("index.js");
        std::fs::write(&script, "console.log('hi');").unwrap();

        let config_path = dir.join(".mcp.json");
        let shim_path = dir.join("talyx-shim.exe");
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
            "mcpServers",
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
            "mcpServers",
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
    fn skips_a_server_marked_disabled_true() {
        let dir = unique_temp_dir("disabled-server");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("mcp.json");
        let config = serde_json::json!({
            "mcpServers": {
                "live": { "command": "some-binary", "args": [] },
                "turned-off": { "command": "some-binary", "args": [], "disabled": true }
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let discovered = parse_mcp_servers_json(
            &config_path,
            &dir,
            ConfigSourceKind::ClaudeCodeMcpServersJson,
            "mcpServers",
            "claude-code",
            "Claude Code",
        );
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "live");

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
            "mcpServers",
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
