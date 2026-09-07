//! End-to-end: drive a full MCP session through `run_with` against the
//! real scripted testserver child process, over in-process pipes.

use agentguard_mcp_proxy::{run_with, ProxyConfig};
use std::io::{BufRead, BufReader, Write};
use std::thread;

const SERVER: &str = env!("CARGO_BIN_EXE_agentguard-mcp-testserver");

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
