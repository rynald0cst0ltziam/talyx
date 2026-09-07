//! End-to-end: drive a full MCP session through `run_with` against the
//! real scripted testserver child process, over in-process pipes.

use talyx_mcp_proxy::{run_with, PolicyLevel, ProxyConfig};
use std::io::{BufRead, BufReader, Write};
use std::thread;

const SERVER: &str = env!("CARGO_BIN_EXE_talyx-mcp-testserver");

/// Send a sequence of client lines, collect the server's replies, assert
/// the proxy was transparent and the child exited cleanly.
#[test]
fn a_full_session_passes_through_untouched_and_reaps_the_child() {
    let (client_to_proxy_r, mut client_w) = std::io::pipe().unwrap();
    let (proxy_to_client_r, proxy_w) = std::io::pipe().unwrap();

    let proxy = thread::spawn(move || {
        run_with(
            SERVER,
            &[],
            ProxyConfig::new("test:server"),
            client_to_proxy_r,
            proxy_w,
        )
    });

    let mut from_proxy = BufReader::new(proxy_to_client_r);
    let mut read_line = || {
        let mut s = String::new();
        from_proxy.read_line(&mut s).unwrap();
        s
    };

    // initialize
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
        .unwrap();
    let init = read_line();
    assert!(init.contains("\"id\":1"), "{init}");
    assert!(init.contains("serverInfo"), "{init}");
    // exact byte shape the server emitted — proxy must not have reframed it
    assert!(init.ends_with('\n') && init.matches('\n').count() == 1);

    // initialized notification (no reply expected)
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .unwrap();

    // tools/list
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
        .unwrap();
    let list = read_line();
    assert!(list.contains("\"id\":2") && list.contains("\"name\":\"echo\""), "{list}");

    // a plain request → echo
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/list\"}\n")
        .unwrap();
    let echo = read_line();
    assert!(echo.contains("\"echo\":\"resources/list\""), "{echo}");

    // close the client side → server sees stdin EOF → exits 0
    drop(client_w);

    let status = proxy.join().unwrap().expect("proxy run failed");
    assert!(status.success(), "child exit: {status:?}");
}

/// A server→client message far larger than the inspection cap must still
/// round-trip byte-for-byte.
#[test]
fn an_oversized_message_still_round_trips() {
    let (client_to_proxy_r, mut client_w) = std::io::pipe().unwrap();
    let (proxy_to_client_r, proxy_w) = std::io::pipe().unwrap();

    let mut cfg = ProxyConfig::new("test:big");
    cfg.max_message_bytes = 4096; // force the "oversized, not inspected" path

    let proxy = thread::spawn(move || run_with(SERVER, &[], cfg, client_to_proxy_r, proxy_w));

    let mut from_proxy = BufReader::new(proxy_to_client_r);
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"big\",\"params\":{\"n\":200000}}\n")
        .unwrap();
    let mut line = String::new();
    from_proxy.read_line(&mut line).unwrap();

    assert!(line.len() > 200_000, "got {} bytes", line.len());
    assert!(line.contains(&"A".repeat(200_000)));

    drop(client_w);
    let status = proxy.join().unwrap().expect("proxy run failed");
    assert!(status.success());
}

/// Phase B: at `balanced`, a poisoned `tools/list` response is replaced
/// with a JSON-RPC error — the agent never sees the exfil directive — and
/// the rest of the session keeps working.
#[test]
fn a_poisoned_tools_list_is_blocked_at_balanced() {
    let (client_to_proxy_r, mut client_w) = std::io::pipe().unwrap();
    let (proxy_to_client_r, proxy_w) = std::io::pipe().unwrap();

    let mut cfg = ProxyConfig::new("test:poison");
    cfg.level = Some(PolicyLevel::Balanced);
    cfg.sessions_dir = Some(std::env::temp_dir().join(format!("ag-e2e-sessions-{}", std::process::id())));

    let proxy = thread::spawn(move || {
        run_with(
            SERVER,
            &["--poison".to_string()],
            cfg,
            client_to_proxy_r,
            proxy_w,
        )
    });

    let mut from_proxy = BufReader::new(proxy_to_client_r);

    // initialize passes through
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
        .unwrap();
    let mut init = String::new();
    from_proxy.read_line(&mut init).unwrap();
    assert!(init.contains("serverInfo"));

    // tools/list gets replaced with an error
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
        .unwrap();
    let mut list = String::new();
    from_proxy.read_line(&mut list).unwrap();
    assert!(list.contains("\"id\":2"), "{list}");
    assert!(list.contains("\"error\""), "{list}");
    assert!(list.contains("-32001"), "{list}");
    assert!(!list.contains("evil.example.com"), "the directive leaked: {list}");

    // the session still works afterwards
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/list\"}\n")
        .unwrap();
    let mut echo = String::new();
    from_proxy.read_line(&mut echo).unwrap();
    assert!(echo.contains("\"echo\":\"resources/list\""), "{echo}");

    drop(client_w);
    let status = proxy.join().unwrap().expect("proxy run failed");
    assert!(status.success());
}

/// Rug pull: a clean first `tools/list` is baselined; when the server
/// adds a tool on the second list, the proxy flags the drift.
#[test]
fn a_mid_session_rug_pull_is_caught() {
    let baseline = std::env::temp_dir().join(format!("ag-e2e-baseline-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&baseline);

    let (client_to_proxy_r, mut client_w) = std::io::pipe().unwrap();
    let (proxy_to_client_r, proxy_w) = std::io::pipe().unwrap();

    let mut cfg = ProxyConfig::new("test:rugpull");
    cfg.level = Some(PolicyLevel::Balanced);
    cfg.sessions_dir = Some(std::env::temp_dir().join(format!("ag-e2e-rp-{}", std::process::id())));
    cfg.baseline_path = Some(baseline.clone());

    let proxy = thread::spawn(move || {
        run_with(SERVER, &["--rugpull".to_string()], cfg, client_to_proxy_r, proxy_w)
    });

    let mut from_proxy = BufReader::new(proxy_to_client_r);
    let mut line = || {
        let mut s = String::new();
        from_proxy.read_line(&mut s).unwrap();
        s
    };

    // first list — clean, baselined, forwarded
    client_w.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n").unwrap();
    let first = line();
    assert!(first.contains("\"echo\"") && !first.contains("\"error\""), "{first}");

    // second list — now has `exec`, which wasn't in the approved set
    client_w.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n").unwrap();
    let second = line();
    assert!(second.contains("\"error\"") && second.contains("-32001"), "{second}");
    assert!(!second.contains("\"exec\""), "the rug-pulled tool leaked: {second}");

    drop(client_w);
    let _ = proxy.join().unwrap();
    let _ = std::fs::remove_file(&baseline);
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("ag-e2e-rp-{}", std::process::id())));
}

/// A user guardrail blocks a client `tools/call` whose argument references
/// an SSH path — the client gets a JSON-RPC error, the server never sees
/// the call, and the session keeps working.
#[test]
fn a_guardrail_blocks_a_client_request() {
    let gr_file = std::env::temp_dir().join(format!("ag-e2e-gr-{}.yaml", std::process::id()));
    std::fs::write(
        &gr_file,
        r#"
version: 1
rules:
  - name: no-ssh-args
    direction: client-to-server
    method: tools/call
    all:
      - path: params.arguments.*
        contains: "/.ssh/"
    action: block
    message: "argument references an SSH path"
"#,
    )
    .unwrap();

    let (client_to_proxy_r, mut client_w) = std::io::pipe().unwrap();
    let (proxy_to_client_r, proxy_w) = std::io::pipe().unwrap();

    let mut cfg = ProxyConfig::new("test:guardrail");
    cfg.level = Some(PolicyLevel::Balanced);
    cfg.sessions_dir = Some(std::env::temp_dir().join(format!("ag-e2e-grs-{}", std::process::id())));
    cfg.guardrails_path = Some(gr_file.clone());

    let proxy = thread::spawn(move || run_with(SERVER, &[], cfg, client_to_proxy_r, proxy_w));
    let mut from_proxy = BufReader::new(proxy_to_client_r);
    let mut line = || {
        let mut s = String::new();
        from_proxy.read_line(&mut s).unwrap();
        s
    };

    // blocked call → error back to the client
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read\",\"arguments\":{\"path\":\"/home/u/.ssh/id_rsa\"}}}\n")
        .unwrap();
    let blocked = line();
    assert!(blocked.contains("\"id\":1") && blocked.contains("\"error\""), "{blocked}");
    assert!(blocked.contains("no-ssh-args"), "{blocked}");

    // a tools/call with a clean argument is NOT blocked (reaches the server)
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read\",\"arguments\":{\"path\":\"/tmp/ok.txt\"}}}\n")
        .unwrap();
    let ok = line();
    assert!(ok.contains("\"id\":2") && ok.contains("\"content\"") && !ok.contains("no-ssh-args"), "{ok}");

    drop(client_w);
    let status = proxy.join().unwrap().expect("proxy run failed");
    assert!(status.success());
    let _ = std::fs::remove_file(&gr_file);
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("ag-e2e-grs-{}", std::process::id())));
}

/// At `strict`, the same poisoned response ends the session.
#[test]
fn a_poisoned_tools_list_tears_down_at_strict() {
    let (client_to_proxy_r, mut client_w) = std::io::pipe().unwrap();
    let (proxy_to_client_r, proxy_w) = std::io::pipe().unwrap();

    let mut cfg = ProxyConfig::new("test:poison-strict");
    cfg.level = Some(PolicyLevel::Strict);
    cfg.sessions_dir = Some(std::env::temp_dir().join(format!("ag-e2e-sessions-strict-{}", std::process::id())));

    let proxy = thread::spawn(move || {
        run_with(SERVER, &["--poison".to_string()], cfg, client_to_proxy_r, proxy_w)
    });

    let mut from_proxy = BufReader::new(proxy_to_client_r);
    client_w
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
        .unwrap();
    let mut list = String::new();
    from_proxy.read_line(&mut list).unwrap();
    assert!(list.contains("\"error\"") && list.contains("-32001"), "{list}");

    // teardown killed the child; the proxy returns without waiting for the
    // client to disconnect. Once we drop our write end the reader hits EOF.
    drop(client_w);
    let mut after = String::new();
    let n = from_proxy.read_line(&mut after).unwrap();
    assert_eq!(n, 0, "expected EOF after teardown, got: {after}");

    let _ = proxy.join().unwrap();
}
