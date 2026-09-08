//! End-to-end enforcement proof — the automated version of the
//! "shim-proven end to end" claims made throughout STATUS.md.
//!
//! Builds the real `talyx` + `talyx-shim` binaries, runs `talyx init`
//! against a fixture project that configures one known-malicious MCP server
//! (matched by the advisory feed) and one benign one, then invokes
//! `talyx-shim` exactly as the rewritten config would and asserts:
//!
//!   * the malicious server is BLOCKed — the shim refuses to launch it (exit 1)
//!   * the benign server runs — the shim execs it transparently (exit 0)
//!   * `talyx init` wrote a byte-exact `.talyx-backup` of the original config
//!   * `talyx allow` overrides a BLOCK in the decision store
//!
//! No network and nothing dangerous is ever executed: the malicious entry
//! is `npx -y postmark-mcp@1.0.17`, which the advisory feed matches by
//! identity (offline) and the shim refuses before `npx` is ever spawned.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TALYX: &str = env!("CARGO_BIN_EXE_talyx");

/// `talyx-shim(.exe)` sits next to the `talyx` binary once built. It is
/// not a dependency of this crate, so build it on demand — that keeps the
/// test working under `cargo test -p talyx-cli` as well as `--workspace`.
fn shim_bin() -> PathBuf {
    let path = Path::new(TALYX)
        .with_file_name(format!("talyx-shim{}", std::env::consts::EXE_SUFFIX));
    if !path.exists() {
        let ok = Command::new(env!("CARGO"))
            .args(["build", "-p", "talyx-shim"])
            .status()
            .expect("run `cargo build -p talyx-shim`")
            .success();
        assert!(ok, "failed to build talyx-shim");
    }
    assert!(path.exists(), "talyx-shim not found at {}", path.display());
    path
}

/// A self-cleaning scratch directory (no `tempfile` dev-dependency — the
/// workspace convention is a pid-namespaced dir under the system temp dir).
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "talyx-e2e-{}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            tag
        ));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The benign server's real launch command, per platform — always present,
/// prints a marker, exits 0.
fn benign_cmd() -> (&'static str, Vec<&'static str>) {
    if cfg!(windows) {
        ("cmd", vec!["/c", "echo", "benign-ok"])
    } else {
        ("sh", vec!["-c", "echo benign-ok"])
    }
}

fn run(cmd: &mut Command) -> Output {
    let out = cmd.output().expect("spawn");
    eprintln!(
        "$ {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}\n--- exit: {:?}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        out.status.code()
    );
    out
}

#[test]
fn init_blocks_a_known_bad_server_and_runs_a_benign_one() {
    let shim = shim_bin();
    let scratch = Scratch::new("enforce");
    let proj = scratch.path();
    let store = proj.join("store.json");

    let (bcmd, bargs) = benign_cmd();
    let original = serde_json::json!({
        "mcpServers": {
            "known-bad": { "command": "npx", "args": ["-y", "postmark-mcp@1.0.17"] },
            "benign":    { "command": bcmd, "args": bargs },
        }
    });
    let mcp_json = proj.join(".mcp.json");
    let original_text = serde_json::to_string_pretty(&original).unwrap();
    fs::write(&mcp_json, &original_text).unwrap();

    // ── talyx init ───────────────────────────────────────────────────────
    let out = run(Command::new(TALYX)
        .args(["init", "--project"])
        .arg(proj)
        .arg("--store")
        .arg(&store)
        .env("TALYX_DEV", "1"));
    assert!(out.status.success(), "`talyx init` failed");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        report.contains("1 critical") && report.contains("1 blocked"),
        "init should report exactly the one known-bad server as critical/blocked:\n{report}"
    );

    // ── the config was rewritten to route through the shim ───────────────
    let rewritten: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&mcp_json).unwrap()).unwrap();
    let servers = rewritten["mcpServers"].as_object().unwrap();

    let shim_str = shim.display().to_string();
    let invocation = |name: &str| -> (String, Vec<String>) {
        let e = &servers[name];
        let cmd = e["command"].as_str().unwrap().to_string();
        let args: Vec<String> = e["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(cmd, shim_str, "{name} not routed through the shim");
        (cmd, args)
    };
    let (_, bad_args) = invocation("known-bad");
    let (_, benign_args) = invocation("benign");

    // args = [<artifact-id>, "--", <original command>, <original args...>]
    let bad_id = bad_args[0].clone();
    let benign_id = benign_args[0].clone();
    assert_eq!(bad_args[1], "--");
    assert_eq!(&bad_args[2..], &["npx", "-y", "postmark-mcp@1.0.17"]);
    assert_eq!(benign_args[1], "--");
    assert_eq!(benign_args[2], bcmd);

    // ── the original config was backed up byte-for-byte ──────────────────
    let backup = proj.join(".mcp.json.talyx-backup");
    assert!(backup.exists(), "no .talyx-backup written");
    assert_eq!(
        fs::read_to_string(&backup).unwrap(),
        original_text,
        ".talyx-backup is not a faithful copy of the original"
    );

    // ── the shim REFUSES the known-bad server ────────────────────────────
    let out = run(Command::new(&shim)
        .arg(&bad_id)
        .arg("--")
        .args(["npx", "-y", "postmark-mcp@1.0.17"])
        .env("TALYX_STORE", &store));
    assert_eq!(out.status.code(), Some(1), "shim should refuse a BLOCK with exit 1");
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(err.contains("blocked") && err.contains("known-bad"), "unexpected refusal message: {err}");

    // ── the shim RUNS the benign server, transparently ───────────────────
    let mut c = Command::new(&shim);
    c.arg(&benign_id).arg("--").arg(bcmd).args(&bargs).env("TALYX_STORE", &store);
    let out = run(&mut c);
    assert!(out.status.success(), "shim should exec an ALLOW server");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("benign-ok"),
        "the benign command's own output did not pass through"
    );

    // ── `talyx allow` overrides the BLOCK ────────────────────────────────
    let out = run(Command::new(TALYX)
        .arg("allow")
        .arg(&bad_id)
        .arg("--store")
        .arg(&store));
    assert!(out.status.success(), "`talyx allow` failed");
    assert!(
        String::from_utf8_lossy(&out.stdout).to_lowercase().contains("approved"),
        "allow did not confirm the approval"
    );

    // and the store now reflects it (`talyx why` reads the same record the
    // shim would) — we do NOT re-run the shim for the known-bad entry,
    // since an override would exec the real `npx`.
    let out = run(Command::new(TALYX)
        .arg("why")
        .arg(&bad_id)
        .arg("--store")
        .arg(&store));
    assert!(out.status.success());
    let why = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        why.contains("approv") || why.contains("override") || why.contains("allow"),
        "`talyx why` does not show the manual approval:\n{why}"
    );
}
