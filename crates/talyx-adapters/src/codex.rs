//! Codex CLI adapter — discovery + config-gating. MCP server config lives
//! in `config.toml` (verified against OpenAI's own docs,
//! learn.chatgpt.com/docs/extend/mcp) — TOML, not the `mcpServers` JSON
//! shape Claude Code/Cursor use, so this doesn't reuse mcp_config.rs's
//! parser, though it does reuse its command/args classification and
//! publisher-guessing logic (same underlying concept once parsed: a name
//! mapped to a command+args or a remote url).
//!
//! Paths: `.codex/config.toml` (project scope, trusted projects only) or
//! `~/.codex/config.toml` (user scope) as of this writing — same "treat
//! empty discovery as a path check, not absence" caveat as the other
//! adapters.
//!
//! Codex also has a real, confirmed `PreToolUse`-equivalent hook mechanism
//! (`.codex/hooks.json` / `~/.codex/hooks.json`, verified 2026-09-05 —
//! see `ConfigSourceKind::CodexHooksJson`'s doc comment), the same shape
//! as Claude Code's, so hook discovery/enforcement is now shared with
//! Claude Code via `hooks_config.rs` rather than a second implementation.
//!
//! Local stdio servers: `[mcp_servers.<id>]` with `command`, `args`, `env`
//! (a nested table), `env_vars` (an array of host env var NAMES to
//! forward). Remote servers: `url`, `bearer_token_env_var`,
//! `http_headers`, `env_http_headers` — deliberately different field names
//! from Claude Code/Cursor's `headers` object (Codex's design keeps actual
//! secret values out of the config file, referencing an env var name
//! instead — noted, not modeled further here).

use crate::hooks_config::parse_hooks_json;
use crate::mcp_config::{classify_command, guess_publisher, unwrap_shim_invocation};
use crate::{AgentAdapter, ConfigSource, ConfigSourceKind, DiscoveredArtifact, LaunchCommand};
use talyx_core::{
    Artifact, ArtifactKind, ArtifactSource, Capability, CapabilityFinding, EvidenceBasis,
};
use std::collections::BTreeSet;
use std::path::Path;
use toml::Value;

pub struct CodexAdapter;

impl AgentAdapter for CodexAdapter {
    fn agent_id(&self) -> &'static str {
        "codex"
    }

    fn agent_name(&self) -> &'static str {
        "Codex"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".codex").join("config.toml").exists()
            || home
                .as_ref()
                .map(|h| h.join(".codex").join("config.toml").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        out.extend(parse_codex_mcp_servers(
            &project_root.join(".codex").join("config.toml"),
            project_root,
        ));
        if let Some(h) = &home {
            out.extend(parse_codex_mcp_servers(
                &h.join(".codex").join("config.toml"),
                h,
            ));
        }

        // Hooks — verified 2026-09-05 directly against OpenAI's own docs
        // (learn.chatgpt.com/docs/hooks, two independent fetches): a
        // standalone `.codex/hooks.json` (project scope) / `~/.codex/
        // hooks.json` (user scope), same `{"hooks": {...}}` JSON shape as
        // Claude Code's settings.json hooks tree — see
        // `ConfigSourceKind::CodexHooksJson`'s doc comment. Codex's docs
        // also mention inline `[hooks]` TOML tables in config.toml as an
        // alternative location; deliberately not covered here yet (a
        // second, differently-shaped parse path), same "don't build what
        // hasn't been verified" discipline as everything else in this pass.
        out.extend(parse_hooks_json(
            &project_root.join(".codex").join("hooks.json"),
            ConfigSourceKind::CodexHooksJson,
            "codex",
        ));
        if let Some(h) = &home {
            out.extend(parse_hooks_json(
                &h.join(".codex").join("hooks.json"),
                ConfigSourceKind::CodexHooksJson,
                "codex",
            ));
        }

        out
    }
}

/// Parses strictly first; on failure, retries after repairing the single
/// most common real-world breakage on Windows: a raw path pasted into a
/// TOML basic (double-quoted) string without escaping its backslashes
/// (`"C:\Users\..."`) — TOML's escape rules reject that (`\U` is only
/// valid followed by 8 hex digits), so `\U`sers fails to parse. Confirmed
/// on a live, real, in-use `~/.codex/config.toml` on the dev machine, not
/// a contrived case — this is not hypothetical hardening. The repair
/// applies globally (not scoped to strings), which would be wrong inside a
/// TOML *literal* (single-quoted) string where backslash has no special
/// meaning — but literal strings can never cause the specific "invalid
/// escape" failure this fallback is triggered by, so in practice this only
/// ever fires for exactly the case it's meant to fix. Only kept if the
/// repaired text ALSO parses successfully; can't make a truly-invalid file
/// worse than the "return nothing" baseline it would have gotten anyway.
///
/// Residual limitation: a string whose ONLY backslashes are `\b`/`\f`/`\n`/
/// `\r`/`\t` (e.g. a bare `"\bin"` with nothing else) is still ambiguous —
/// there's no proof it's a path rather than a control escape, so it's left
/// alone. But the common real case (`"C:\Users\bin\thing.exe"`, `"C:\temp\
/// x"`) is now recovered: the moment the string contains one backslash that
/// *cannot* be any TOML escape (`\U` not followed by hex, `\H`, `\ `, a
/// trailing `\`, …), the whole string is treated as an unescaped path and
/// every backslash in it is doubled — including the otherwise-ambiguous
/// ones. See `repair_unescaped_backslashes`.
pub fn parse_toml_leniently(text: &str) -> Option<Value> {
    if let Ok(v) = toml::from_str::<Value>(text) {
        return Some(v);
    }
    let repaired = repair_unescaped_backslashes(text);
    toml::from_str::<Value>(&repaired).ok()
}

/// True when the document contains a real TOML comment.
///
/// Enforcement rewrites this file by re-serializing a parsed `toml::Value`,
/// which cannot carry comments — so rewriting a commented config silently
/// deletes the user's own notes from their own file. The rewrite path
/// checks this and refuses instead, the same call already made for JSONC
/// configs: scanning still works, only the rewrite declines.
///
/// `#` inside a string is not a comment, and getting that wrong would be
/// worse than not checking at all — it would block enforcement for
/// perfectly ordinary configs (`args = ["--tag=#build"]`, a Windows path,
/// a URL fragment). All four TOML string forms are tracked.
pub fn toml_has_comments(text: &str) -> bool {
    let b = text.as_bytes();
    let mut i = 0usize;

    while i < b.len() {
        // Multi-line forms first — their delimiters start with the same
        // byte as the single-line ones.
        if b[i..].starts_with(b"\"\"\"") {
            i += 3;
            while i < b.len() && !b[i..].starts_with(b"\"\"\"") {
                // A backslash escapes the next byte in a basic string.
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 3;
            continue;
        }
        if b[i..].starts_with(b"'''") {
            i += 3;
            while i < b.len() && !b[i..].starts_with(b"'''") {
                i += 1;
            }
            i += 3;
            continue;
        }
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'\'' => {
                // Literal string: no escapes at all, ends at the next quote.
                i += 1;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                i += 1;
            }
            b'#' => return true,
            _ => i += 1,
        }
    }
    false
}

/// True if `chars` contains a backslash that cannot begin any TOML escape
/// sequence (`\U`/`\u` without the required hex digits, `\` before a letter
/// that isn't an escape designator, `\` before a space or digit, a trailing
/// `\`). Such a backslash is proof the string was written without escaping
/// any of them — a raw filesystem path pasted into a basic string.
fn has_unambiguous_raw_backslash(chars: &[char]) -> bool {
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '\\' {
            i += 1;
            continue;
        }
        match chars.get(i + 1).copied() {
            None => return true, // trailing backslash
            // A valid `\\` pair — skip BOTH so the second isn't re-examined
            // against the character after it.
            Some('\\') => i += 2,
            // Valid on their own, OR the ambiguous control escapes: not, by
            // themselves, proof of anything.
            Some('"' | 'n' | 't' | 'r' | 'b' | 'f') => i += 2,
            Some('u') => {
                let ok = chars
                    .get(i + 2..i + 6)
                    .map(|h| h.iter().all(|c| c.is_ascii_hexdigit()))
                    .unwrap_or(false);
                if ok {
                    i += 6;
                } else {
                    return true;
                }
            }
            Some('U') => {
                let ok = chars
                    .get(i + 2..i + 10)
                    .map(|h| h.iter().all(|c| c.is_ascii_hexdigit()))
                    .unwrap_or(false);
                if ok {
                    i += 10;
                } else {
                    return true;
                }
            }
            // `\S`, `\D`, `\ `, `\1`, … — cannot be an escape.
            Some(_) => return true,
        }
    }
    false
}

fn repair_unescaped_backslashes(text: &str) -> String {
    // If the string contains a backslash that can't be any TOML escape, it
    // was written without escaping backslashes at all — so double every
    // backslash, including `\b \f \n \r \t`, which in that file are path
    // components (`\bin`, `\temp`), not control characters. Without that
    // proof, fall through to the conservative per-escape pass below, which
    // leaves a lone `\b` alone rather than guessing.
    let chars: Vec<char> = text.chars().collect();
    if has_unambiguous_raw_backslash(&chars) {
        return text.replace('\\', "\\\\");
    }

    // Index-based rather than a char-by-char peekable iterator: telling a
    // genuinely-valid `\u`/`\U` escape apart from a raw backslash that
    // merely happens to be followed by 'u'/'U' (e.g. the "U" in "Users")
    // requires looking ahead 4 or 8 characters to check they're actually
    // hex digits — found via a real test failure, not by inspection: an
    // earlier version of this function only checked the single next
    // character, so it treated `\Users` as "already an escape" (since 'U'
    // is a valid escape *designator*) and left it broken, which is exactly
    // the bug this whole function exists to fix.
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let next = chars.get(i + 1).copied();
        let is_valid_escape = match next {
            Some('\\' | '"' | 'n' | 't' | 'r' | 'b' | 'f') => true,
            Some('u') => chars
                .get(i + 2..i + 6)
                .map(|hex| hex.iter().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or(false),
            Some('U') => chars
                .get(i + 2..i + 10)
                .map(|hex| hex.iter().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or(false),
            _ => false,
        };
        if is_valid_escape {
            // Consume BOTH characters of the pair. Critical: if this were
            // only 1, the second backslash of an already-valid `\\` would
            // get re-examined next iteration as if it were a fresh,
            // unrelated backslash — found via a real failing test, not by
            // inspection, when an earlier version of this function
            // corrupted already-correctly-escaped backslash pairs.
            out.push('\\');
            out.push(next.unwrap());
            i += 2;
        } else {
            out.push_str("\\\\"); // not a real escape — needs one now
            i += 1; // only the raw backslash; re-examine what follows normally
        }
    }
    out
}

fn parse_codex_mcp_servers(path: &Path, base_dir: &Path) -> Vec<DiscoveredArtifact> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let Some(root) = parse_toml_leniently(&text) else {
        return out;
    };
    let Some(servers) = root.get("mcp_servers").and_then(|v| v.as_table()) else {
        return out;
    };

    for (name, cfg) in servers {
        let Some(table) = cfg.as_table() else {
            continue;
        };

        if let Some(url) = table.get("url").and_then(|v| v.as_str()) {
            out.push(remote_codex_artifact(name, url, table, path));
            continue;
        }

        let Some(raw_command) = table.get("command").and_then(|v| v.as_str()) else {
            continue; // neither url nor command — not a shape we understand
        };
        let raw_args: Vec<String> = table
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let has_env = table
            .get("env")
            .and_then(|v| v.as_table())
            .map(|t| !t.is_empty())
            .unwrap_or(false)
            || table
                .get("env_vars")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);

        let (command, args) = match unwrap_shim_invocation(raw_command, &raw_args) {
            Some((real_command, real_args)) => (real_command, real_args),
            None => (raw_command.to_string(), raw_args),
        };

        let (source, scan_root, display_location) = classify_command(&command, &args, base_dir);

        let mut capabilities = vec![CapabilityFinding {
            capability: Capability::SpawnProcess,
            basis: EvidenceBasis::Declared,
            evidence: "launched as a subprocess by Codex's MCP config".to_string(),
            location: Some(path.display().to_string()),
        }];
        if has_env {
            capabilities.push(CapabilityFinding {
                capability: Capability::EnvironmentVariables,
                basis: EvidenceBasis::Declared,
                evidence: "MCP config supplies or forwards environment variables to this server"
                    .to_string(),
                location: Some(path.display().to_string()),
            });
        }

        let mut discovered_by = BTreeSet::new();
        discovered_by.insert("codex".to_string());

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
                kind: ConfigSourceKind::CodexMcpServersToml,
                entry_key: name.clone(),
            }),
            raw_config_entry: None,
        });
    }

    out
}

fn remote_codex_artifact(
    name: &str,
    url: &str,
    table: &toml::Table,
    path: &Path,
) -> DiscoveredArtifact {
    let source = ArtifactSource::RemoteUrl(url.to_string());

    let mut capabilities = vec![CapabilityFinding {
        capability: Capability::NetworkExternal,
        basis: EvidenceBasis::Declared,
        evidence: "remote MCP server declared by Codex's config (reached over HTTP, not launched locally)".to_string(),
        location: Some(path.display().to_string()),
    }];
    let has_auth = table.contains_key("bearer_token_env_var")
        || table
            .get("http_headers")
            .and_then(|v| v.as_table())
            .map(|t| !t.is_empty())
            .unwrap_or(false)
        || table
            .get("env_http_headers")
            .and_then(|v| v.as_table())
            .map(|t| !t.is_empty())
            .unwrap_or(false);
    if has_auth {
        capabilities.push(CapabilityFinding {
            capability: Capability::ApiKeys,
            basis: EvidenceBasis::Declared,
            evidence: "config supplies a bearer token or auth header for this remote server"
                .to_string(),
            location: Some(path.display().to_string()),
        });
    }

    let mut discovered_by = BTreeSet::new();
    discovered_by.insert("codex".to_string());

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
            kind: ConfigSourceKind::CodexMcpServersToml,
            entry_key: name.to_string(),
        }),
        raw_config_entry: serde_json::to_value(table).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_comments_are_detected() {
        assert!(toml_has_comments("# leading note\n[mcp_servers.a]\n"));
        assert!(toml_has_comments("[mcp_servers.a]\ncommand = \"node\" # trailing\n"));
        assert!(!toml_has_comments("[mcp_servers.a]\ncommand = \"node\"\n"));
        assert!(!toml_has_comments(""));
    }

    #[test]
    fn a_hash_inside_a_string_is_not_a_comment() {
        // Getting this wrong would block enforcement on ordinary configs
        // that merely contain a `#` in an argument, a path or a URL.
        assert!(!toml_has_comments(r#"args = ["--tag=#build"]"#));
        assert!(!toml_has_comments(r#"url = "https://x.test/a#frag""#));
        assert!(!toml_has_comments(r#"p = 'C:\lit#eral\path'"#));
        assert!(!toml_has_comments("s = \"\"\"multi\n#not a comment\nline\"\"\""));
        assert!(!toml_has_comments("s = '''lit\n#also not\n'''"));
        // An escaped quote must not end the string early and expose the
        // following `#` as a comment.
        assert!(!toml_has_comments(r#"s = "he said \"hi\" #inside""#));
        // ...but a real comment after a string still counts.
        assert!(toml_has_comments(r#"s = "value" # real comment"#));
    }

    #[test]
    fn repair_doubles_a_raw_unescaped_backslash() {
        let repaired = repair_unescaped_backslashes(r"C:\Users\Desktop\App.exe");
        assert_eq!(repaired, r"C:\\Users\\Desktop\\App.exe");
        // And the repaired text must actually parse as a valid TOML string.
        let wrapped = format!("x = \"{repaired}\"");
        assert!(toml::from_str::<Value>(&wrapped).is_ok());
    }

    #[test]
    fn repair_recovers_a_path_component_that_looks_like_a_named_escape() {
        // `\bastion.exe` on its own is a syntactically valid TOML escape
        // (backspace + "astion.exe"), so in isolation it's ambiguous. But
        // this string ALSO has `\Users` — `\U` not followed by 8 hex digits,
        // which cannot be an escape — proving the whole thing is an
        // unescaped Windows path. So every backslash is doubled, `\b`
        // included, and the path round-trips intact instead of picking up a
        // stray backspace control character (the real `~/.codex/config.toml`
        // bastion-proxy case on the dev machine).
        assert_eq!(
            repair_unescaped_backslashes(r"C:\Users\bastion.exe"),
            r"C:\\Users\\bastion.exe"
        );
        let wrapped = format!("x = \"{}\"", repair_unescaped_backslashes(r"C:\Users\bastion.exe"));
        let parsed: Value = toml::from_str(&wrapped).unwrap();
        assert_eq!(parsed["x"].as_str().unwrap(), r"C:\Users\bastion.exe");
    }

    #[test]
    fn repair_leaves_a_truly_isolated_control_escape_alone() {
        // The residual limitation, stated honestly: with no other backslash
        // to prove intent, `\bin` could genuinely be a backspace escape, so
        // it is left untouched rather than guessed at.
        assert_eq!(repair_unescaped_backslashes(r"\bin"), r"\bin");
    }

    #[test]
    fn repair_leaves_already_valid_double_backslashes_unchanged() {
        let already_escaped = r"C:\\Users\\bastion.exe";
        assert_eq!(repair_unescaped_backslashes(already_escaped), already_escaped);
    }

    #[test]
    fn repair_leaves_valid_named_escapes_unchanged() {
        assert_eq!(repair_unescaped_backslashes(r"line one\nline two"), r"line one\nline two");
    }

    #[test]
    fn repair_leaves_a_genuine_valid_unicode_escape_unchanged() {
        assert_eq!(repair_unescaped_backslashes(r"\u0041"), r"\u0041");
        assert_eq!(repair_unescaped_backslashes(r"\U0001F600"), r"\U0001F600");
    }

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "talyx-codex-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn parses_a_well_formed_local_server() {
        let dir = unique_temp_dir("wellformed");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]

[mcp_servers.context7.env]
MY_ENV_VAR = "value"
"#,
        )
        .unwrap();

        let discovered = parse_codex_mcp_servers(&config_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "context7");
        assert!(discovered[0].artifact.discovered_by.contains("codex"));
        let caps: Vec<_> = discovered[0]
            .artifact
            .capabilities
            .iter()
            .map(|c| c.capability)
            .collect();
        assert!(caps.contains(&Capability::EnvironmentVariables));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_a_remote_server_with_auth_header() {
        let dir = unique_temp_dir("remote");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[mcp_servers.figma]
url = "https://mcp.figma.com/mcp"
bearer_token_env_var = "FIGMA_OAUTH_TOKEN"
"#,
        )
        .unwrap();

        let discovered = parse_codex_mcp_servers(&config_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].scan_root, None);
        assert_eq!(discovered[0].launch, None);
        let caps: Vec<_> = discovered[0]
            .artifact
            .capabilities
            .iter()
            .map(|c| c.capability)
            .collect();
        assert!(caps.contains(&Capability::NetworkExternal));
        assert!(caps.contains(&Capability::ApiKeys));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recovers_from_unescaped_windows_paths() {
        // Regression test for the exact real-world breakage found on this
        // dev machine's actual ~/.codex/config.toml (written by another
        // tool): raw backslashes in a double-quoted string make it
        // invalid TOML per strict parsing (confirmed with a throwaway
        // parse before writing this fix), but the file is real and in use.
        let dir = unique_temp_dir("badescape");
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[mcp_servers.bastion]
command = "C:\Users\Hubby\Desktop\Bastion-AI\bastion.exe"
args = ["proxy", "--", "C:\\Users\\Hubby\\Desktop\\Bastion-AI\\bastion.exe", "mcp"]
"#,
        )
        .unwrap();

        // Confirm strict parsing genuinely fails first (otherwise this
        // test wouldn't be exercising the repair path at all).
        assert!(std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|t| toml::from_str::<Value>(&t).ok())
            .is_none());

        let discovered = parse_codex_mcp_servers(&config_path, &dir);
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].artifact.name, "bastion");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_project_scope_config() {
        let dir = unique_temp_dir("detect");
        let codex_dir = dir.join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();
        std::fs::write(codex_dir.join("config.toml"), "[mcp_servers.x]\ncommand = \"y\"\n").unwrap();

        assert!(CodexAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_finds_project_scope_hooks_json() {
        let dir = unique_temp_dir("hooks");
        let codex_dir = dir.join(".codex");
        std::fs::create_dir_all(&codex_dir).unwrap();
        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [ { "type": "command", "command": "./scripts/audit-log.sh" } ] }
                ]
            }
        });
        std::fs::write(codex_dir.join("hooks.json"), serde_json::to_string_pretty(&hooks).unwrap())
            .unwrap();

        let discovered = CodexAdapter.discover(&dir);
        let hook = discovered
            .iter()
            .find(|d| d.artifact.kind == ArtifactKind::Hook)
            .expect("hook should be discovered");
        assert_eq!(hook.launch.as_ref().unwrap().command, "./scripts/audit-log.sh");
        assert!(hook.artifact.discovered_by.contains("codex"));
        assert_eq!(
            hook.config_source.as_ref().unwrap().kind,
            ConfigSourceKind::CodexHooksJson
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
