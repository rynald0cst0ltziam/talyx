//! JSONC-tolerant config parsing.
//!
//! Several of the agents this crate supports document their config as
//! JSON but actually accept **JSONC** — JSON with `//` / `/* */` comments
//! and trailing commas. VS Code's `mcp.json` and `settings.json` and
//! Zed's settings are the ones that matter most; VS Code ships comments
//! in its own default files, so a user's real config very often has them.
//!
//! `serde_json` rejects all of that, and every adapter's parse site did
//! the same thing on failure: return no artifacts, silently. The result
//! was a one-character bypass of the entire product — adding `//` to a
//! config made every server in it invisible to discovery, and therefore
//! to scanning and enforcement, with nothing printed to say so.
//! Reproduced directly: the same malicious server was found in a clean
//! file and absent once a comment and a trailing comma were added.
//!
//! So: parse strictly first (the common case, and exact), fall back to
//! stripping comments/trailing commas, and if it still won't parse, say
//! so out loud. A config Talyx cannot read is a gap in its coverage, and
//! the user is the only one who can close it — silence is the one
//! response that guarantees they never will.

use serde_json::Value;
use std::path::Path;

/// Parses a config that is JSON or JSONC. Returns `None` only when the
/// text is not recoverable as either, after warning on stderr.
pub(crate) fn parse_json_config(path: &Path, text: &str) -> Option<Value> {
    // Exact parse first: no rewriting of input in the overwhelmingly
    // common case, so a plain-JSON file can never be misread by the
    // stripper below.
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Some(v);
    }

    let stripped = strip_jsonc(text);
    match serde_json::from_str::<Value>(&stripped) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!(
                "talyx: {} could not be parsed as JSON or JSONC ({e}) — NOTHING IN THIS FILE WAS SCANNED. Fix the syntax and re-run, or this config's servers, hooks and skills stay invisible to Talyx.",
                path.display()
            );
            None
        }
    }
}

/// True when the text only parses after JSONC stripping — i.e. it really
/// does contain comments or trailing commas. Used by the enforcement
/// side, which re-serializes through `serde_json` and would silently
/// delete every comment in the user's file if it rewrote one of these.
pub fn needs_jsonc(text: &str) -> bool {
    serde_json::from_str::<Value>(text).is_err()
        && serde_json::from_str::<Value>(&strip_jsonc(text)).is_ok()
}

/// Replaces `//` and `/* */` comments with spaces and drops trailing
/// commas, leaving everything else — including byte offsets of the
/// surviving content — untouched.
///
/// Comments are blanked rather than removed so error positions reported
/// by `serde_json` still line up with the original file. String literals
/// are tracked properly (with escapes), because `"https://example.com"`
/// and `"a,}"` must survive intact — naive comment stripping corrupts
/// every URL in a config file.
fn strip_jsonc(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());

    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];

        if in_string {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if b == b'"' {
            in_string = true;
            out.push(b);
            i += 1;
            continue;
        }

        if b == b'/' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'/' => {
                    // Line comment: blank to end of line, keeping the
                    // newline so line numbers are preserved.
                    while i < bytes.len() && bytes[i] != b'\n' {
                        out.push(b' ');
                        i += 1;
                    }
                    continue;
                }
                b'*' => {
                    // Block comment: blank through the terminator,
                    // preserving any newlines inside it.
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    while i < bytes.len() {
                        if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                            out.push(b' ');
                            out.push(b' ');
                            i += 2;
                            break;
                        }
                        out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                        i += 1;
                    }
                    continue;
                }
                _ => {}
            }
        }

        out.push(b);
        i += 1;
    }

    // Trailing commas: a `,` whose next non-whitespace character closes
    // the object/array it sits in. Done as a second pass over the
    // comment-free text so a `,` inside a comment can't be considered.
    let mut result = out;
    let len = result.len();
    let mut in_string = false;
    let mut escaped = false;
    for idx in 0..len {
        let b = result[idx];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        if b == b'"' {
            in_string = true;
            continue;
        }
        if b != b',' {
            continue;
        }
        let mut j = idx + 1;
        while j < len && result[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < len && (result[j] == b'}' || result[j] == b']') {
            result[idx] = b' ';
        }
    }

    String::from_utf8_lossy(&result).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_json_parses_unchanged() {
        let v = parse_json_config(Path::new("t.json"), r#"{"a":1}"#).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn a_line_comment_no_longer_hides_the_whole_config() {
        // The PoC from the review, in miniature: one `//` used to make
        // every server in the file invisible to discovery.
        let text = r#"{
  // the comment that used to defeat Talyx entirely
  "mcpServers": {
    "evil": { "command": "node", "args": ["evil.js"] }
  }
}"#;
        let v = parse_json_config(Path::new("mcp.json"), text).unwrap();
        assert_eq!(v["mcpServers"]["evil"]["command"], "node");
    }

    #[test]
    fn block_comments_and_trailing_commas_are_handled() {
        let text = r#"{
  /* a block
     comment */
  "servers": {
    "a": { "command": "x", },
  },
}"#;
        let v = parse_json_config(Path::new("settings.json"), text).unwrap();
        assert_eq!(v["servers"]["a"]["command"], "x");
    }

    #[test]
    fn urls_and_comment_like_strings_survive() {
        // The failure mode of naive comment stripping: every https:// URL
        // in the file gets truncated, and a server silently loses its
        // endpoint.
        let text = r#"{
  "servers": {
    "remote": { "url": "https://example.com/mcp", "note": "a,} not a trailing comma" }
  } // real comment
}"#;
        let v = parse_json_config(Path::new("mcp.json"), text).unwrap();
        assert_eq!(v["servers"]["remote"]["url"], "https://example.com/mcp");
        assert_eq!(v["servers"]["remote"]["note"], "a,} not a trailing comma");
    }

    #[test]
    fn an_escaped_quote_inside_a_string_does_not_break_tracking() {
        let text = r#"{ "a": "he said \"hi\" // not a comment", "b": 2 }"#;
        let v = parse_json_config(Path::new("t.json"), text).unwrap();
        assert_eq!(v["a"], r#"he said "hi" // not a comment"#);
        assert_eq!(v["b"], 2);
    }

    #[test]
    fn genuinely_broken_json_returns_none() {
        assert!(parse_json_config(Path::new("t.json"), "{ this is not json at all").is_none());
    }

    #[test]
    fn needs_jsonc_only_flags_files_that_really_use_it() {
        assert!(!needs_jsonc(r#"{"a":1}"#));
        assert!(needs_jsonc("{\n // c\n \"a\":1}"));
        assert!(needs_jsonc(r#"{"a":1,}"#));
        // Unparseable either way is not "needs jsonc" — it's just broken.
        assert!(!needs_jsonc("{ broken"));
    }
}
