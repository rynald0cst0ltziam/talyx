//! agentguard-shim — BUILD_PLAN.md §5a, the config-time enforcement
//! mechanism. `agentguard init` rewrites an agent's config so an MCP
//! server or hook entry launches through this binary instead of directly:
//! the shim looks up the cached decision for that artifact and either
//! launches the real command (transparently, inheriting stdio) or refuses
//! and explains why.
//!
//! Deliberately tiny and dependency-light (no clap, no scanner/risk crates)
//! — this runs on the hot path of every gated process launch, so startup
//! cost matters (BUILD_PLAN.md §9's p99 perf budget), and it must not need
//! network or a running daemon to make a decision: it only reads the local
//! decision cache written by `agentguard scan`/`init`.
//!
//! Invocation contract (owned entirely by this binary + the config
//! rewriter in agentguard-cli — not a public API, both sides are this repo):
//!
//!   agentguard-shim <artifact-id> [--proxy] -- <real-command> [real-args...]
//!     Argv mode — an MCP server's `command`/`args` are a real argv array,
//!     exec'd directly (no shell involved). With `--proxy` (written by
//!     `agentguard init --live`), the real command is run through the
//!     `agentguard-mcp-proxy` stdio pass-through instead of `exec`'d, so
//!     the session's JSON-RPC traffic can be inspected — see ADR 0001.
//!     `AGENTGUARD_NO_PROXY=1` forces the plain `exec` path regardless (a
//!     hard kill switch); `AGENTGUARD_PROXY_LEVEL=quiet|balanced|strict`
//!     sets the proxy's inspection level (default `balanced`).
//!
//!   agentguard-shim <artifact-id> --shell
//!     Shell mode — a Claude Code hook's `command` is a single shell-syntax
//!     STRING (its own docs show `$CLAUDE_PROJECT_DIR`-style shell
//!     variable expansion inside it, confirming it runs through a real
//!     shell, not direct exec). Deliberately does NOT take the command as
//!     an argv element the way argv mode does: this whole invocation line
//!     is itself embedded in the agent's config and re-parsed by ITS OWN
//!     shell when the hook fires, so any shell metacharacter in the real
//!     command (a pipe, a redirect) would be interpreted by that OUTER
//!     shell before this binary ever runs — found live, not hypothetically:
//!     a fixture hook command containing `|` caused cmd.exe to split the
//!     rewritten line into a pipeline and execute later stages directly,
//!     completely bypassing a BLOCK decision. Instead, this mode looks up
//!     `DecisionRecord.shell_command` — the real command, which only ever
//!     travels through the local store, never through a re-parsed string —
//!     and only after the decision below is confirmed ALLOW. Hooks are
//!     never proxied — they aren't MCP servers.

use agentguard_core::Decision;
use agentguard_mcp_proxy::{PolicyLevel, ProxyConfig};
use agentguard_store::DecisionStore;
use std::env;
use std::process::{Command, ExitStatus};

/// Exit code used for every "we deliberately did not launch the real
/// command" outcome (unscanned, ask-pending, blocked). Distinct from 127
/// (real command failed to launch) and from the real command's own exit
/// codes, which we forward verbatim on the allowed path.
const EXIT_REFUSED: i32 = 1;
const EXIT_USAGE: i32 = 64; // matches BSD sysexits.h EX_USAGE, a reasonable convention to borrow
const EXIT_LAUNCH_FAILED: i32 = 127;

enum LaunchMode {
    Argv {
        command: String,
        args: Vec<String>,
        /// `--proxy` was present — run the real command through the MCP
        /// stdio proxy rather than a bare exec (unless `AGENTGUARD_NO_PROXY`).
        proxy: bool,
    },
    /// The real command isn't known yet at parse time — see this file's
    /// module doc comment. Resolved from the decision record after ALLOW.
    Shell,
}

fn usage_error(msg: &str) -> ! {
    eprintln!("agentguard-shim: {msg}");
    eprintln!("usage: agentguard-shim <artifact-id> [--proxy] -- <real-command> [real-args...]");
    eprintln!("       agentguard-shim <artifact-id> --shell");
    std::process::exit(EXIT_USAGE);
}

/// Parses argv (after the binary name) into an artifact id + launch mode.
fn parse_args(args: &[String]) -> (&str, LaunchMode) {
    if args.is_empty() {
        usage_error("missing artifact id");
    }
    let artifact_id = args[0].as_str();

    if args.get(1).map(String::as_str) == Some("--shell") {
        if args.len() != 2 {
            usage_error("'--shell' takes no further arguments — the real command comes from the decision store, not argv");
        }
        return (artifact_id, LaunchMode::Shell);
    }

    let Some(sep) = args.iter().position(|a| a == "--") else {
        usage_error("missing '--' separator between artifact id and the real command");
    };
    if sep == 0 {
        usage_error("missing artifact id before '--'");
    }

    // Flags between the id and `--`. Only `--proxy` is defined.
    let mut proxy = false;
    for flag in &args[1..sep] {
        match flag.as_str() {
            "--proxy" => proxy = true,
            other => usage_error(&format!("unknown flag before '--': {other}")),
        }
    }

    let real: &[String] = &args[sep + 1..];
    let Some((real_command, real_args)) = real.split_first() else {
        usage_error("no real command given after '--'");
    };
    (
        artifact_id,
        LaunchMode::Argv {
            command: real_command.clone(),
            args: real_args.to_vec(),
            proxy,
        },
    )
}

/// Launches the real command, inheriting stdio by default — MCP servers
/// speak JSON-RPC over stdin/stdout and hooks may read a JSON payload from
/// stdin, so that channel must pass through untouched either way for the
/// wrapping to be transparent to the agent. `shell_command` is only
/// consulted for `LaunchMode::Shell`, resolved by the caller from the
/// decision record.
///
/// In `--proxy` argv mode (and without the `AGENTGUARD_NO_PROXY` kill
/// switch) the real command is run through `agentguard-mcp-proxy` instead:
/// same transparent stdio, but the JSON-RPC stream passes through the
/// proxy for inspection (ADR 0001). `AGENTGUARD_PROXY_LOG` optionally
/// names a JSONL transcript file.
fn launch(
    mode: &LaunchMode,
    artifact_id: &str,
    shell_command: Option<&str>,
) -> std::io::Result<ExitStatus> {
    match mode {
        LaunchMode::Argv {
            command,
            args,
            proxy,
        } => {
            let kill_switch = env::var("AGENTGUARD_NO_PROXY").as_deref() == Ok("1");
            if *proxy && !kill_switch {
                let mut cfg = ProxyConfig::new(artifact_id);
                cfg.log_path = env::var_os("AGENTGUARD_PROXY_LOG").map(Into::into);
                // The proxy's inspection level. Defaults to `balanced`
                // (ADR 0001); `AGENTGUARD_PROXY_LEVEL` overrides it for a
                // single launch without re-running `init`.
                cfg.level = Some(match env::var("AGENTGUARD_PROXY_LEVEL").as_deref() {
                    Ok("quiet") => PolicyLevel::Quiet,
                    Ok("strict") => PolicyLevel::Strict,
                    _ => PolicyLevel::Balanced,
                });
                cfg.sessions_dir = env::var_os("AGENTGUARD_SESSIONS_DIR").map(Into::into);
                agentguard_mcp_proxy::run(command, args, cfg)
            } else {
                Command::new(command).args(args).status()
            }
        }
        LaunchMode::Shell => {
            let shell_command = shell_command.expect("caller guarantees Some for LaunchMode::Shell");
            #[cfg(target_os = "windows")]
            {
                Command::new("cmd").args(["/C", shell_command]).status()
            }
            #[cfg(not(target_os = "windows"))]
            {
                Command::new("sh").args(["-c", shell_command]).status()
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (artifact_id, mode) = parse_args(&args);

    let store = DecisionStore::resolve();
    let record = store.get(artifact_id);

    let Some(record) = record else {
        eprintln!(
            "AgentGuard: '{artifact_id}' has never been scanned — refusing to launch it (fail-closed by design)."
        );
        eprintln!("Run `agentguard scan` or `agentguard init` to evaluate it, then retry.");
        std::process::exit(EXIT_REFUSED);
    };

    match record.effective_decision() {
        Decision::Allow | Decision::AllowLog => {
            // Falls through to launch below.
        }
        Decision::Ask => {
            eprintln!(
                "AgentGuard: '{}' is flagged {} and needs approval before it can run.",
                record.name, record.band
            );
            eprintln!(
                "Run `agentguard allow {artifact_id}` if you trust this, or `agentguard why {artifact_id}` to see the full reasoning."
            );
            std::process::exit(EXIT_REFUSED);
        }
        Decision::Block | Decision::Quarantine => {
            eprintln!(
                "AgentGuard blocked '{}' — risk: {} (score {}).",
                record.name, record.band, record.total_score
            );
            eprintln!(
                "Run `agentguard why {artifact_id}` to see the full reasoning, or `agentguard allow {artifact_id}` to override."
            );
            std::process::exit(EXIT_REFUSED);
        }
    }

    if matches!(mode, LaunchMode::Shell) && record.shell_command.is_none() {
        eprintln!(
            "agentguard-shim: '{artifact_id}' is in shell mode but the decision store has no shell_command for it."
        );
        eprintln!("This shouldn't happen from a normal `agentguard init` run — try re-running init.");
        std::process::exit(EXIT_REFUSED);
    }

    match launch(&mode, artifact_id, record.shell_command.as_deref()) {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => {
            let target = match &mode {
                LaunchMode::Argv { command, .. } => command.clone(),
                LaunchMode::Shell => record.shell_command.clone().unwrap_or_default(),
            };
            eprintln!("agentguard-shim: failed to launch '{target}': {e}");
            std::process::exit(EXIT_LAUNCH_FAILED);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_argv_mode() {
        let args: Vec<String> = ["id-1", "--", "node", "server.js", "--port", "3000"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (id, mode) = parse_args(&args);
        assert_eq!(id, "id-1");
        match mode {
            LaunchMode::Argv {
                command,
                args,
                proxy,
            } => {
                assert_eq!(command, "node");
                assert_eq!(args, vec!["server.js", "--port", "3000"]);
                assert!(!proxy);
            }
            LaunchMode::Shell => panic!("expected argv mode"),
        }
    }

    #[test]
    fn parses_proxy_flag_before_the_separator() {
        let args: Vec<String> = ["id-1", "--proxy", "--", "node", "s.js"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (id, mode) = parse_args(&args);
        assert_eq!(id, "id-1");
        match mode {
            LaunchMode::Argv {
                command,
                args,
                proxy,
            } => {
                assert_eq!(command, "node");
                assert_eq!(args, vec!["s.js"]);
                assert!(proxy);
            }
            LaunchMode::Shell => panic!("expected argv mode"),
        }
    }

    #[test]
    fn parses_shell_mode() {
        let args: Vec<String> = ["id-2", "--shell"].iter().map(|s| s.to_string()).collect();
        let (id, mode) = parse_args(&args);
        assert_eq!(id, "id-2");
        assert!(matches!(mode, LaunchMode::Shell));
    }
}
