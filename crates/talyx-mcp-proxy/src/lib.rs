//! `talyx-mcp-proxy` — the transparent stdio pass-through the
//! enforcement shim can run instead of a bare `exec` (ADR 0001).
//!
//! **Phase A (this crate today): transparent only.** It spawns the real
//! MCP server, shuttles every newline-delimited JSON-RPC message between
//! the agent and the server byte-for-byte, classifies each message for an
//! optional JSONL transcript, and reaps the child. It applies **no
//! policy** — that is Phase B. The point of shipping the transparent layer
//! first is to prove it is faithful and cheap against every real MCP
//! server before any inspection logic sits on the hot path.
//!
//! Design invariants (see ADR 0001):
//!  - Never drops or reorders bytes; forwards each message before doing
//!    anything else with it.
//!  - `stderr` is inherited untouched — servers log there.
//!  - No async runtime: two blocking pump threads over two unidirectional
//!    streams.
//!  - Fail-open: any internal error in a pump stops *that direction*
//!    cleanly rather than tearing the process down; the child's own exit
//!    status is what `run` returns.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub mod guardrails;
pub mod message;
mod policy;

use message::{Direction, Rpc};
pub use policy::PolicyLevel;
use policy::{Action, SessionPolicy};

/// Messages larger than this are forwarded but not parsed/inspected — a
/// single JSON-RPC message this big is anomalous, and buffering an
/// unbounded amount to inspect it would be its own denial of service.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// How the proxy should behave for one session.
pub struct ProxyConfig {
    /// Artifact id of the server being proxied — recorded in the transcript.
    pub artifact_id: String,
    /// If set, every message is appended to this file as one JSON object
    /// per line (a debugging aid; off by default).
    pub log_path: Option<PathBuf>,
    /// Per-message inspection cap. Defaults to [`DEFAULT_MAX_MESSAGE_BYTES`].
    pub max_message_bytes: usize,
    /// When set, the handshake responses (`initialize`, `tools/list`,
    /// `resources/list`, `prompts/list`) are scanned for instruction-text
    /// attacks and handled per the level (ADR 0001 Phase B). `None` =
    /// transparent pass-through only (Phase A behaviour).
    pub level: Option<PolicyLevel>,
    /// Directory for the session findings log. Defaults to
    /// `~/.talyx/sessions/`. Overridden in tests so they never touch
    /// the real one.
    pub sessions_dir: Option<PathBuf>,
    /// File for the trust-on-first-use tool baseline. Defaults to a
    /// `tool_baselines.json` next to the decision store. Overridden in
    /// tests.
    pub baseline_path: Option<PathBuf>,
    /// Explicit guardrails file. When `None`, the standard candidates are
    /// tried: `$TALYX_GUARDRAILS`, `<project_dir>/.talyx/
    /// guardrails.yaml`, `~/.talyx/guardrails.yaml`.
    pub guardrails_path: Option<PathBuf>,
    /// Project directory, for resolving `.talyx/guardrails.yaml`.
    /// Defaults to the current directory.
    pub project_dir: PathBuf,
}

impl ProxyConfig {
    pub fn new(artifact_id: impl Into<String>) -> Self {
        ProxyConfig {
            artifact_id: artifact_id.into(),
            log_path: None,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            level: None,
            sessions_dir: None,
            baseline_path: None,
            guardrails_path: None,
            project_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

/// Spawn `command args…` as the real MCP server and proxy the running
/// process's own stdio (the agent's pipe) to it for the life of the
/// session. `stderr` is inherited; `stdin`/`stdout` are piped through.
pub fn run(command: &str, args: &[String], config: ProxyConfig) -> io::Result<ExitStatus> {
    run_with(command, args, config, io::stdin(), io::stdout())
}

/// [`run`], but with the client side of the connection injected — used by
/// tests to drive a full session over in-process pipes. `client_in` is
/// what the agent sends; `client_out` is what the agent receives.
pub fn run_with<CR, CW>(
    command: &str,
    args: &[String],
    config: ProxyConfig,
    client_in: CR,
    client_out: CW,
) -> io::Result<ExitStatus>
where
    CR: Read + Send + 'static,
    CW: Write + Send + 'static,
{
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let child_stdin = child.stdin.take().expect("stdin was piped");
    let child_stdout = child.stdout.take().expect("stdout was piped");

    let logger = Arc::new(Logger::open(config.log_path.as_deref(), &config.artifact_id));
    let cap = config.max_message_bytes;
    let policy = config.level.map(|lvl| {
        Arc::new(SessionPolicy::new(
            config.artifact_id.clone(),
            lvl,
            config.sessions_dir.clone(),
            config.baseline_path.clone(),
            config.guardrails_path.clone(),
            &config.project_dir,
        ))
    });

    let to_server: SharedWriter = Arc::new(Mutex::new(Box::new(child_stdin)));
    let to_client: SharedWriter = Arc::new(Mutex::new(Box::new(client_out)));

    // The first pump to finish ends the session. A clean EOF lets the
    // other side wind down gracefully (the server exits when its stdin
    // closes); a policy teardown kills the child immediately.
    let (done_tx, done_rx) = std::sync::mpsc::channel::<PumpEnd>();

    // client (agent) -> server; can `Reply` a synthesised error to the
    // client (a guardrail that blocks a request).
    let l1 = Arc::clone(&logger);
    let p1 = policy.clone();
    let c2s_fwd = Arc::clone(&to_server);
    let c2s_reply = Arc::clone(&to_client);
    let done1 = done_tx.clone();
    let c2s = thread::spawn(move || {
        let end = pump(
            BufReader::new(client_in),
            &c2s_fwd,
            Some(&c2s_reply),
            Direction::ClientToServer,
            &l1,
            p1.as_deref(),
            cap,
        );
        let _ = done1.send(end);
    });
    drop(to_server);

    // server -> client (agent)
    let l2 = Arc::clone(&logger);
    let p2 = policy.clone();
    let s2c_fwd = Arc::clone(&to_client);
    let s2c = thread::spawn(move || {
        let end = pump(
            BufReader::new(child_stdout),
            &s2c_fwd,
            None,
            Direction::ServerToClient,
            &l2,
            p2.as_deref(),
            cap,
        );
        let _ = done_tx.send(end);
    });
    drop(to_client);

    // Wait for the first pump to finish.
    if let Ok(PumpEnd::Teardown) = done_rx.recv() {
        let _ = child.kill(); // a policy stop — end the session now
    }
    let status = child.wait()?;

    // The child's stdio is closed now, so both pumps unblock. Join s2c;
    // detach c2s (it may still be parked on the client's stdin, which
    // `process::exit` in the shim tears down).
    let _ = s2c.join();
    drop(c2s);

    logger.flush();
    Ok(status)
}

/// Why a pump loop returned.
#[derive(Clone, Copy, PartialEq)]
enum PumpEnd {
    /// EOF on the source, or the far side of a write is gone.
    Eof,
    /// A policy `*AndStop` action — the session must end.
    Teardown,
}

/// A message this size or smaller is parsed and shown to the policy
/// *before* forwarding (a handshake response — `tools/list` etc. — is
/// always well under this). A larger message (a big `tools/call` result:
/// file contents, command output) is forwarded first and only classified
/// for the transcript afterwards, so the policy never adds latency to the
/// bulk traffic. Handshake-response inspection that matters is unaffected.
const INSPECT_CAP: usize = 256 * 1024;

/// Shuttle newline-delimited messages from `src` to `dst`.
///
/// Small messages (≤ [`INSPECT_CAP`]) are parsed and — when a `policy` is
/// set (Phase B) — shown to it *before* forwarding, so a flagged handshake
/// response can be replaced with a JSON-RPC error (or replaced then the
/// session stopped) before the agent sees it. Everything else is forwarded
/// verbatim first and classified for the transcript afterwards. Returns on
/// EOF, a `dst` write error, or a policy stop.
type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;

fn write_locked(w: &SharedWriter, bytes: &[u8]) -> bool {
    match w.lock() {
        Ok(mut g) => g.write_all(bytes).and_then(|()| g.flush()).is_ok(),
        Err(_) => false,
    }
}

fn pump<R: BufRead>(
    mut src: R,
    forward: &SharedWriter,
    reply: Option<&SharedWriter>,
    dir: Direction,
    logger: &Logger,
    policy: Option<&SessionPolicy>,
    cap: usize,
) -> PumpEnd {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    loop {
        buf.clear();
        let n = loop {
            match src.read_until(b'\n', &mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return PumpEnd::Eof, // upstream broke
            }
        };
        if n == 0 {
            return PumpEnd::Eof;
        }

        // Too big to inspect (a large tool result, or over the hard cap):
        // forward first, classify after — the policy never sees it.
        if buf.len() > INSPECT_CAP.min(cap) {
            if !write_locked(forward, &buf) {
                return PumpEnd::Eof;
            }
            if buf.len() > cap {
                logger.record_note(dir, "oversized", buf.len());
            } else {
                match serde_json::from_slice::<serde_json::Value>(trim_newline(&buf)) {
                    Ok(v) => logger.record(dir, &Rpc::classify(&v), buf.len()),
                    Err(_) => logger.record_note(dir, "unparsed", buf.len()),
                }
            }
            continue;
        }

        // Small: parse, let the policy see it, then forward its verdict.
        let action = match serde_json::from_slice::<serde_json::Value>(trim_newline(&buf)) {
            Ok(v) => {
                logger.record(dir, &Rpc::classify(&v), buf.len());
                match policy {
                    Some(p) => p.inspect(dir, &v),
                    None => Action::Forward,
                }
            }
            Err(_) => {
                logger.record_note(dir, "unparsed", buf.len());
                Action::Forward
            }
        };

        let (target, out, stop): (&SharedWriter, &[u8], bool) = match &action {
            Action::Forward => (forward, &buf, false),
            Action::Replace(r) => (forward, r, false),
            Action::ReplaceAndStop(r) => (forward, r, true),
            // No upstream writer (s2c) → a `Reply` becomes a stop.
            Action::Reply(r) => (reply.unwrap_or(forward), r, reply.is_none()),
            Action::ReplyAndStop(r) => (reply.unwrap_or(forward), r, true),
        };
        if !write_locked(target, out) {
            return PumpEnd::Eof; // that endpoint gone
        }
        if stop {
            return PumpEnd::Teardown;
        }
    }
}

fn trim_newline(b: &[u8]) -> &[u8] {
    let b = b.strip_suffix(b"\n").unwrap_or(b);
    b.strip_suffix(b"\r").unwrap_or(b)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The optional JSONL transcript writer. A no-op when no `log_path` was
/// given. Guarded by a mutex so the two pump threads never interleave a
/// half-written line.
struct Logger {
    out: Option<Mutex<io::BufWriter<std::fs::File>>>,
    artifact_id: String,
}

impl Logger {
    fn open(path: Option<&std::path::Path>, artifact_id: &str) -> Self {
        let out = path.and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
                .map(|f| Mutex::new(io::BufWriter::new(f)))
        });
        Logger {
            out,
            artifact_id: artifact_id.to_string(),
        }
    }

    fn write_line(&self, v: &serde_json::Value) {
        let Some(m) = &self.out else { return };
        if let Ok(mut w) = m.lock() {
            let _ = writeln!(w, "{v}");
            let _ = w.flush();
        }
    }

    fn record(&self, dir: Direction, rpc: &Rpc, bytes: usize) {
        if self.out.is_none() {
            return;
        }
        let mut obj = serde_json::Map::new();
        obj.insert("ts_ms".into(), now_ms().into());
        obj.insert("artifact".into(), self.artifact_id.as_str().into());
        obj.insert("dir".into(), dir.tag().into());
        obj.insert("kind".into(), rpc.kind().into());
        if let Some(method) = rpc.method() {
            obj.insert("method".into(), method.into());
        }
        if let Some(id) = rpc.id() {
            obj.insert("id".into(), id.clone());
        }
        obj.insert("bytes".into(), bytes.into());
        self.write_line(&serde_json::Value::Object(obj));
    }

    fn record_note(&self, dir: Direction, note: &str, bytes: usize) {
        if self.out.is_none() {
            return;
        }
        self.write_line(&serde_json::json!({
            "ts_ms": now_ms(),
            "artifact": self.artifact_id,
            "dir": dir.tag(),
            "kind": note,
            "bytes": bytes,
        }));
    }

    fn flush(&self) {
        if let Some(m) = &self.out {
            if let Ok(mut w) = m.lock() {
                let _ = w.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A `Write` backed by a shared `Vec` so a test can read what the pump
    /// wrote after handing the pump a `SharedWriter`.
    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn shared_writer() -> (SharedWriter, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let w: SharedWriter = Arc::new(Mutex::new(Box::new(SharedBuf(buf.clone()))));
        (w, buf)
    }

    fn run_pump(input: &str, cap: usize) -> (Vec<u8>, Vec<String>) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let tmp = std::env::temp_dir().join(format!(
            "talyx-proxy-pumptest-{}-{}.jsonl",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let logger = Logger::open(Some(&tmp), "test-artifact");
        let (dst, bytes) = shared_writer();
        pump(
            Cursor::new(input.as_bytes().to_vec()),
            &dst,
            None,
            Direction::ClientToServer,
            &logger,
            None,
            cap,
        );
        logger.flush();
        let log = std::fs::read_to_string(&tmp).unwrap_or_default();
        let _ = std::fs::remove_file(&tmp);
        let out = bytes.lock().unwrap().clone();
        (out, log.lines().map(String::from).collect())
    }

    #[test]
    fn forwards_every_byte_unchanged() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n\
                     {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
                     {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
        let (out, _log) = run_pump(input, DEFAULT_MAX_MESSAGE_BYTES);
        assert_eq!(out, input.as_bytes());
    }

    #[test]
    fn classifies_each_message_in_the_transcript() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n\
                     {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\
                     {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n";
        let (_out, log) = run_pump(input, DEFAULT_MAX_MESSAGE_BYTES);
        assert_eq!(log.len(), 3);
        assert!(log[0].contains("\"kind\":\"request\"") && log[0].contains("\"method\":\"tools/list\""));
        assert!(log[1].contains("\"kind\":\"response\""));
        assert!(log[2].contains("\"kind\":\"notification\""));
    }

    #[test]
    fn a_non_json_line_is_forwarded_and_marked_unparsed() {
        let input = "starting server on port 3000...\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
        let (out, log) = run_pump(input, DEFAULT_MAX_MESSAGE_BYTES);
        assert_eq!(out, input.as_bytes());
        assert!(log[0].contains("\"kind\":\"unparsed\""));
        assert!(log[1].contains("\"kind\":\"response\""));
    }

    #[test]
    fn an_oversized_message_is_forwarded_and_marked_not_inspected() {
        let big = "x".repeat(2048);
        let input = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{big}\"}}\n");
        let (out, log) = run_pump(&input, 512);
        assert_eq!(out, input.as_bytes());
        assert!(log[0].contains("\"kind\":\"oversized\""));
    }

    #[test]
    fn a_final_line_without_a_newline_is_still_forwarded() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
        let (out, _log) = run_pump(input, DEFAULT_MAX_MESSAGE_BYTES);
        assert_eq!(out, input.as_bytes());
    }

    #[test]
    fn stops_cleanly_when_the_destination_closes() {
        // A writer that accepts one write then errors — the pump must
        // return, not spin.
        struct OneShot(bool);
        impl Write for OneShot {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
                } else {
                    self.0 = true;
                    Ok(b.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let logger = Logger::open(None, "t");
        let input = "a\nb\nc\nd\n";
        let dst: SharedWriter = Arc::new(Mutex::new(Box::new(OneShot(false))));
        pump(
            Cursor::new(input.as_bytes().to_vec()),
            &dst,
            None,
            Direction::ServerToClient,
            &logger,
            None,
            DEFAULT_MAX_MESSAGE_BYTES,
        );
        // reaching here (no hang, no panic) is the assertion
    }
}
