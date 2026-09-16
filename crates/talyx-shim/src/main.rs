//! talyx-shim — BUILD_PLAN.md §5a, the config-time enforcement
//! mechanism. `talyx init` rewrites an agent's config so an MCP
//! server or hook entry launches through this binary instead of directly:
//! the shim looks up the cached decision for that artifact and either
//! launches the real command (transparently, inheriting stdio) or refuses
//! and explains why.
//!
//! Deliberately tiny and dependency-light (no clap, no scanner/risk crates)
//! — this runs on the hot path of every gated process launch, so startup
//! cost matters (BUILD_PLAN.md §9's p99 perf budget), and it must not need
//! network or a running daemon to make a decision: it only reads the local
//! decision cache written by `talyx scan`/`init`.
//!
//! Invocation contract (owned entirely by this binary + the config
//! rewriter in talyx-cli — not a public API, both sides are this repo):
//!
//!   talyx-shim <artifact-id> [--proxy] -- <real-command> [real-args...]
//!     Argv mode — an MCP server's `command`/`args` are a real argv array,
//!     exec'd directly (no shell involved). With `--proxy` (written by
//!     `talyx init --live`), the real command is run through the
//!     `talyx-mcp-proxy` stdio pass-through instead of `exec`'d, so
//!     the session's JSON-RPC traffic can be inspected — see ADR 0001.
//!     `TALYX_NO_PROXY=1` forces the plain `exec` path regardless (a
//!     hard kill switch); `TALYX_PROXY_LEVEL=quiet|balanced|strict`
//!     sets the proxy's inspection level (default `balanced`).
//!
//!   talyx-shim <artifact-id> --shell
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

use talyx_core::Decision;
use talyx_mcp_proxy::{PolicyLevel, ProxyConfig};
use talyx_store::DecisionStore;
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
        /// stdio proxy rather than a bare exec (unless `TALYX_NO_PROXY`).
        proxy: bool,
    },
    /// The real command isn't known yet at parse time — see this file's
    /// module doc comment. Resolved from the decision record after ALLOW.
    Shell,
}

/// Reads an env var only in debug/test builds; a RELEASE build always
/// gets `None`, as if the var were never set. An MCP config's `env`
/// block sets environment variables for the process the agent launches
/// — and that process *is the shim* — so honoring a security-relevant
/// var from the environment in a real (release) build would let a
/// config edit weaken enforcement for that one launch (disable the live
/// proxy, downgrade its inspection level, ...) without touching the
/// decision store at all. Kept for debug/test builds because the test
/// suite and local demo fixtures rely on these to control a single
/// launch without a full `talyx init` re-run (2026-09-15 review, C2).
fn debug_only_env(key: &str) -> Option<String> {
    #[cfg(debug_assertions)]
    {
        env::var(key).ok()
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = key;
        None
    }
}

/// Known code-execution-via-environment injection points (`LD_PRELOAD`
/// and its platform equivalents, plus per-interpreter startup-file/
/// options vars) — stripped from THIS process's environment before it
/// execs the real command, so a config edit that adds one of these to
/// the `env` block the agent sets for the shim can't smuggle arbitrary
/// code into an otherwise-unmodified, approved binary purely via
/// environment (2026-09-15 review, C2's "env keys" fix note). This is a
/// denylist, not a pinned allowlist of declared keys, deliberately: the
/// shim's child inherits the FULL ambient environment (PATH, HOME, ...)
/// by default, and the vast majority of that is normal OS/user
/// environment the real command needs, not something the MCP config's
/// small `env: {...}` override ever sets.
const DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
    "BASH_ENV",
    "ENV",
    "GCONV_PATH",
];

fn strip_dangerous_env_vars() {
    for key in DANGEROUS_ENV_VARS {
        env::remove_var(key);
    }
}

/// Whether `command`/`args` — what the shim is actually about to launch
/// in argv mode — is exactly what was approved at scan time. `false`
/// whenever there's no `approved_launch` at all (an older record from
/// before this field existed, or a record type that never set it) —
/// fail closed rather than treat "we don't know" as "fine".
fn launch_matches_approved(approved: Option<&talyx_store::ApprovedLaunch>, command: &str, args: &[String]) -> bool {
    approved.is_some_and(|a| a.command == command && a.args == args)
}

fn usage_error(msg: &str) -> ! {
    eprintln!("talyx-shim: {msg}");
    eprintln!("usage: talyx-shim <artifact-id> [--proxy] -- <real-command> [real-args...]");
    eprintln!("       talyx-shim <artifact-id> --shell");
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
/// In `--proxy` argv mode (and without the `TALYX_NO_PROXY` kill
/// switch) the real command is run through `talyx-mcp-proxy` instead:
/// same transparent stdio, but the JSON-RPC stream passes through the
/// proxy for inspection (ADR 0001). `TALYX_PROXY_LOG` optionally
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
            let kill_switch = debug_only_env("TALYX_NO_PROXY").as_deref() == Some("1");
            if *proxy && !kill_switch {
                let mut cfg = ProxyConfig::new(artifact_id);
                cfg.log_path = env::var_os("TALYX_PROXY_LOG").map(Into::into);
                // The proxy's inspection level. Defaults to `balanced`
                // (ADR 0001); `TALYX_PROXY_LEVEL` overrides it for a
                // single launch without re-running `init` — debug/test
                // builds only, same as `TALYX_NO_PROXY` above (see
                // `debug_only_env`'s doc comment).
                cfg.level = Some(match debug_only_env("TALYX_PROXY_LEVEL").as_deref() {
                    Some("quiet") => PolicyLevel::Quiet,
                    Some("strict") => PolicyLevel::Strict,
                    _ => PolicyLevel::Balanced,
                });
                cfg.sessions_dir = env::var_os("TALYX_SESSIONS_DIR").map(Into::into);
                talyx_mcp_proxy::run(command, args, cfg)
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
            "Talyx: '{artifact_id}' has never been scanned — refusing to launch it (fail-closed by design)."
        );
        eprintln!("Run `talyx scan` or `talyx init` to evaluate it, then retry.");
        std::process::exit(EXIT_REFUSED);
    };

    match record.effective_decision() {
        Decision::Allow | Decision::AllowLog => {
            // Falls through to launch below.
        }
        Decision::Ask => {
            eprintln!(
                "Talyx: '{}' is flagged {} and needs approval before it can run.",
                record.name, record.band
            );
            eprintln!(
                "Run `talyx allow {artifact_id}` if you trust this, or `talyx why {artifact_id}` to see the full reasoning."
            );
            std::process::exit(EXIT_REFUSED);
        }
        Decision::Block | Decision::Quarantine => {
            eprintln!(
                "Talyx blocked '{}' — risk: {} (score {}).",
                record.name, record.band, record.total_score
            );
            eprintln!(
                "Run `talyx why {artifact_id}` to see the full reasoning, or `talyx allow {artifact_id}` to override."
            );
            std::process::exit(EXIT_REFUSED);
        }
    }

    if matches!(mode, LaunchMode::Shell) && record.shell_command.is_none() {
        eprintln!(
            "talyx-shim: '{artifact_id}' is in shell mode but the decision store has no shell_command for it."
        );
        eprintln!("This shouldn't happen from a normal `talyx init` run — try re-running init.");
        std::process::exit(EXIT_REFUSED);
    }

    // The shim used to authorize purely by artifact id, then exec
    // whatever argv followed `--` — nothing tied the approval to what
    // actually runs. A config edit that kept the same already-approved
    // id but swapped in a different command (or different args) was
    // silently executed. Now it must match exactly what was approved at
    // scan time (2026-09-15 review, finding C2 — PoC'd live).
    if let LaunchMode::Argv { command, args, .. } = &mode {
        if !launch_matches_approved(record.approved_launch.as_ref(), command, args) {
            eprintln!(
                "talyx-shim: the launch command for '{artifact_id}' doesn't match what was approved — config changed since approval."
            );
            eprintln!("Run `talyx init` to re-evaluate it, then retry.");
            std::process::exit(EXIT_REFUSED);
        }
    }

    strip_dangerous_env_vars();

    match launch(&mode, artifact_id, record.shell_command.as_deref()) {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => {
            let target = match &mode {
                LaunchMode::Argv { command, .. } => command.clone(),
                LaunchMode::Shell => record.shell_command.clone().unwrap_or_default(),
            };
            eprintln!("talyx-shim: failed to launch '{target}': {e}");
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

    // --- C2 (2026-09-15 review): approval must be tied to the actual
    // command that runs, not just the artifact id -------------------

    #[test]
    fn launch_matches_approved_accepts_the_exact_approved_argv() {
        let approved = talyx_store::ApprovedLaunch {
            command: "node".to_string(),
            args: vec!["server.js".to_string()],
        };
        assert!(launch_matches_approved(
            Some(&approved),
            "node",
            &["server.js".to_string()]
        ));
    }

    #[test]
    fn launch_matches_approved_rejects_a_swapped_command() {
        // The exact PoC from the review: same already-approved artifact
        // id, but the config now points it at a different real command.
        let approved = talyx_store::ApprovedLaunch {
            command: "node".to_string(),
            args: vec!["server.js".to_string()],
        };
        assert!(!launch_matches_approved(
            Some(&approved),
            "cmd",
            &["/c".to_string(), "echo".to_string(), "ARBITRARY-COMMAND-EXECUTED".to_string()]
        ));
    }

    #[test]
    fn launch_matches_approved_rejects_a_swapped_arg() {
        let approved = talyx_store::ApprovedLaunch {
            command: "node".to_string(),
            args: vec!["server.js".to_string()],
        };
        assert!(!launch_matches_approved(
            Some(&approved),
            "node",
            &["server.js".to_string(), "--extra-flag".to_string()]
        ));
    }

    #[test]
    fn launch_matches_approved_rejects_when_nothing_was_ever_approved() {
        // An older record from before `approved_launch` existed, or any
        // record type that never sets it — fail closed, not "assume ok".
        assert!(!launch_matches_approved(None, "node", &["server.js".to_string()]));
    }

    #[test]
    fn strip_dangerous_env_vars_removes_every_listed_var() {
        for key in DANGEROUS_ENV_VARS {
            env::set_var(key, "poisoned");
        }
        strip_dangerous_env_vars();
        for key in DANGEROUS_ENV_VARS {
            assert!(env::var(key).is_err(), "{key} was not stripped");
        }
    }
}
