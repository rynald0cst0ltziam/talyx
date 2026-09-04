//! agentguard-shim — BUILD_PLAN.md §5a, the config-time enforcement
//! mechanism. `agentguard init` rewrites an agent's MCP config so a server
//! entry launches through this binary instead of directly: the shim looks
//! up the cached decision for that artifact and either execs the real
//! command (transparently, inheriting stdio so the wrapped MCP server's
//! JSON-RPC channel is untouched) or refuses to launch it and explains why.
//!
//! Deliberately tiny and dependency-light (no clap, no scanner/risk crates)
//! — this runs on the hot path of every gated process launch, so startup
//! cost matters (BUILD_PLAN.md §9's p99 perf budget), and it must not need
//! network or a running daemon to make a decision: it only reads the local
//! decision cache written by `agentguard scan`/`init`.
//!
//! Invocation contract (owned entirely by this binary + the config
//! rewriter in agentguard-cli — not a public API, both sides are this repo):
//!   agentguard-shim <artifact-id> -- <real-command> [real-args...]

use agentguard_core::Decision;
use agentguard_store::DecisionStore;
use std::env;
use std::path::PathBuf;
use std::process::Command;

/// Exit code used for every "we deliberately did not launch the real
/// command" outcome (unscanned, ask-pending, blocked). Distinct from 127
/// (real command failed to launch) and from the real command's own exit
/// codes, which we forward verbatim on the allowed path.
const EXIT_REFUSED: i32 = 1;
const EXIT_USAGE: i32 = 64; // matches BSD sysexits.h EX_USAGE, a reasonable convention to borrow
const EXIT_SOFTWARE: i32 = 70; // EX_SOFTWARE
const EXIT_LAUNCH_FAILED: i32 = 127;

fn open_store() -> DecisionStore {
    // AGENTGUARD_STORE lets tests and demo/fixture runs point the shim at
    // an isolated store instead of the real machine-wide
    // ~/.agentguard/decisions.json — never set this for a real install.
    if let Ok(path) = env::var("AGENTGUARD_STORE") {
        DecisionStore::open_at(PathBuf::from(path))
    } else {
        match DecisionStore::open_default() {
            Ok(store) => store,
            Err(e) => {
                eprintln!("agentguard-shim: cannot determine decision store location: {e}");
                std::process::exit(EXIT_SOFTWARE);
            }
        }
    }
}

fn usage_error(msg: &str) -> ! {
    eprintln!("agentguard-shim: {msg}");
    eprintln!("usage: agentguard-shim <artifact-id> -- <real-command> [real-args...]");
    std::process::exit(EXIT_USAGE);
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let Some(sep) = args.iter().position(|a| a == "--") else {
        usage_error("missing '--' separator between artifact id and the real command");
    };
    if sep == 0 {
        usage_error("missing artifact id before '--'");
    }
    let artifact_id = &args[0];
    let real: &[String] = &args[sep + 1..];
    let Some((real_command, real_args)) = real.split_first() else {
        usage_error("no real command given after '--'");
    };

    let store = open_store();
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
            // Falls through to exec below.
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

    // Allowed. Exec the real command, inheriting stdio by default — MCP
    // servers speak JSON-RPC over stdin/stdout, so that channel must pass
    // through untouched for the wrapping to be transparent to the agent.
    match Command::new(real_command).args(real_args).status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("agentguard-shim: failed to launch '{real_command}': {e}");
            std::process::exit(EXIT_LAUNCH_FAILED);
        }
    }
}
