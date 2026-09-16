//! Guardrails — user-authored rules the live proxy enforces on every
//! JSON-RPC message, in addition to the built-in detectors (ADR 0001).
//!
//! A rule matches a message by direction, method, and one or more path
//! conditions, and takes an action: `allow` (forward it and skip the
//! built-in scan), `warn` (log, keep checking), `redact` (replace the
//! matched strings with a marker), or `block` (the message never reaches
//! its peer — a JSON-RPC error goes back to the sender instead).
//!
//! The file is `~/.talyx/guardrails.yaml`,
//! `<project>/.talyx/guardrails.yaml`, or `$TALYX_GUARDRAILS`.
//! It is parsed to a `serde_json::Value` and validated field by field so
//! a typo names the offending rule, not a serde line number.
//!
//! ```yaml
//! version: 1
//! rules:
//!   - name: block-ssh-key-args
//!     direction: client-to-server
//!     method: tools/call
//!     all:
//!       - path: params.arguments.*
//!         contains: "/.ssh/"
//!     action: block
//!     message: "tool call argument references an SSH path"
//!
//!   - name: strip-api-keys-from-results
//!     direction: server-to-client
//!     method: tools/call
//!     any:
//!       - { path: "result.content[*].text", regex: "sk-[A-Za-z0-9]{20,}" }
//!       - { path: "result.content[*].text", regex: "ghp_[A-Za-z0-9]{36}" }
//!     action: redact
//! ```

use crate::message::{Direction, Rpc};
use regex::Regex;
use serde_json::Value;
use std::path::Path;

pub(crate) const REDACTION: &str = "[Talyx guardrail: removed]";

/// The outcome of running every rule against one message.
pub(crate) enum GuardrailOutcome {
    /// No rule matched — the built-in detectors still run.
    None,
    /// An `allow` rule matched — forward as-is, skip the built-in scan.
    Allow { rule: String },
    /// A `warn` rule matched — logged; the built-in detectors still run.
    Warn { rule: String, message: String },
    /// A `redact` rule matched — forward this rewritten message instead.
    Redact { rule: String, message: String, rewritten: Value },
    /// A `block` rule matched — the message must not reach its peer.
    Block { rule: String, message: String },
}

#[derive(Clone, Copy, PartialEq)]
enum DirFilter {
    Any,
    ClientToServer,
    ServerToClient,
}

impl DirFilter {
    fn matches(self, d: Direction) -> bool {
        match self {
            DirFilter::Any => true,
            DirFilter::ClientToServer => d == Direction::ClientToServer,
            DirFilter::ServerToClient => d == Direction::ServerToClient,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum RuleAction {
    Allow,
    Warn,
    Redact,
    Block,
}

enum Op {
    Equals(Value),
    Contains(String),
    NotContains(String),
    Regex(Regex),
    Glob(String),
    Exists,
    NotExists,
    In(Vec<Value>),
    Gt(f64),
    Lt(f64),
}

struct Condition {
    path: String,
    op: Op,
}

struct Rule {
    name: String,
    direction: DirFilter,
    /// Exact method, or a `foo/*` glob, or `None` for any.
    method: Option<String>,
    /// `true` = every condition must match, `false` = any condition.
    require_all: bool,
    conditions: Vec<Condition>,
    action: RuleAction,
    message: Option<String>,
}

pub struct Guardrails {
    rules: Vec<Rule>,
    pub source: String,
}

impl Guardrails {
    /// Load and validate the first guardrails file that exists among the
    /// candidates. Returns `Ok(None)` when none exist.
    pub fn load(candidates: &[std::path::PathBuf]) -> Result<Option<Guardrails>, String> {
        for path in candidates {
            if path.is_file() {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                let g = Guardrails::parse(&text)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                return Ok(Some(Guardrails {
                    source: path.display().to_string(),
                    ..g
                }));
            }
        }
        Ok(None)
    }

    /// Parse + validate from YAML text.
    pub fn parse(text: &str) -> Result<Guardrails, String> {
        let root: Value = serde_saphyr::from_str(text)
            .map_err(|e| format!("not valid YAML: {e}"))?;
        let obj = root.as_object().ok_or("top level must be a mapping")?;

        if let Some(v) = obj.get("version") {
            if v.as_u64() != Some(1) {
                return Err(format!("unsupported version {v} (expected 1)"));
            }
        }

        let rules_v = obj
            .get("rules")
            .and_then(Value::as_array)
            .ok_or("missing `rules:` list")?;

        let mut rules = Vec::with_capacity(rules_v.len());
        for (i, rv) in rules_v.iter().enumerate() {
            rules.push(parse_rule(rv).map_err(|e| format!("rule {} ({e})", i + 1))?);
        }
        Ok(Guardrails {
            rules,
            source: "<inline>".to_string(),
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// One human-readable line per rule, for `talyx guardrails list`.
    pub fn describe(&self) -> Vec<String> {
        self.rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let dir = match r.direction {
                    DirFilter::Any => "any",
                    DirFilter::ClientToServer => "client→server",
                    DirFilter::ServerToClient => "server→client",
                };
                let method = r.method.as_deref().unwrap_or("*");
                let act = match r.action {
                    RuleAction::Allow => "allow",
                    RuleAction::Warn => "warn",
                    RuleAction::Redact => "redact",
                    RuleAction::Block => "block",
                };
                let join = if r.require_all { "all" } else { "any" };
                format!(
                    "{}. {}  [{dir} · {method} · {join}-of-{} · {act}]",
                    i + 1,
                    r.name,
                    r.conditions.len()
                )
            })
            .collect()
    }

    /// A commented starter file — `talyx guardrails example`.
    pub const EXAMPLE: &'static str = include_str!("guardrails.example.yaml");

    /// Run every rule against `msg`. `method` is the JSON-RPC method — for
    /// a response, the caller resolves it from the request/response id
    /// correlation, since the response message itself carries no `method`.
    /// The first `block`/`redact`/`allow` is decisive; `warn` rules are
    /// collected and reported but do not stop evaluation.
    pub(crate) fn evaluate(
        &self,
        dir: Direction,
        method: Option<&str>,
        msg: &Value,
    ) -> GuardrailOutcome {
        let method = method
            .map(str::to_string)
            .or_else(|| Rpc::classify(msg).method().map(str::to_string));
        let mut warned: Option<(String, String)> = None;

        for rule in &self.rules {
            if !rule.direction.matches(dir) {
                continue;
            }
            if let Some(want) = &rule.method {
                let Some(m) = &method else { continue };
                if !method_matches(want, m) {
                    continue;
                }
            }
            if !rule.matches(msg) {
                continue;
            }

            let message = rule
                .message
                .clone()
                .unwrap_or_else(|| format!("matched guardrail `{}`", rule.name));
            match rule.action {
                RuleAction::Allow => return GuardrailOutcome::Allow { rule: rule.name.clone() },
                RuleAction::Block => {
                    return GuardrailOutcome::Block { rule: rule.name.clone(), message }
                }
                RuleAction::Redact => {
                    let mut rewritten = msg.clone();
                    redact_matches(&mut rewritten, &rule.conditions);
                    return GuardrailOutcome::Redact {
                        rule: rule.name.clone(),
                        message,
                        rewritten,
                    };
                }
                RuleAction::Warn => {
                    warned.get_or_insert((rule.name.clone(), message));
                }
            }
        }

        match warned {
            Some((rule, message)) => GuardrailOutcome::Warn { rule, message },
            None => GuardrailOutcome::None,
        }
    }
}

impl Rule {
    fn matches(&self, msg: &Value) -> bool {
        if self.conditions.is_empty() {
            return true;
        }
        if self.require_all {
            self.conditions.iter().all(|c| condition_matches(c, msg))
        } else {
            self.conditions.iter().any(|c| condition_matches(c, msg))
        }
    }
}

fn method_matches(pattern: &str, method: &str) -> bool {
    match pattern.strip_suffix("/*") {
        Some(prefix) => method == prefix || method.starts_with(&format!("{prefix}/")),
        None => pattern == method,
    }
}

fn condition_matches(cond: &Condition, msg: &Value) -> bool {
    let values = json_path(msg, &cond.path);
    match &cond.op {
        Op::Exists => !values.is_empty(),
        Op::NotExists => values.is_empty(),
        Op::Equals(want) => values.contains(&want),
        Op::In(set) => values.iter().any(|v| set.iter().any(|s| s == *v)),
        Op::Contains(needle) => values
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains(needle.as_str()))),
        Op::NotContains(needle) => !values
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains(needle.as_str()))),
        Op::Regex(re) => values
            .iter()
            .any(|v| v.as_str().is_some_and(|s| re.is_match(s))),
        Op::Glob(g) => values
            .iter()
            .any(|v| v.as_str().is_some_and(|s| glob_match(g, s))),
        Op::Gt(n) => values.iter().any(|v| v.as_f64().is_some_and(|x| x > *n)),
        Op::Lt(n) => values.iter().any(|v| v.as_f64().is_some_and(|x| x < *n)),
    }
}

/// Replace every string value the (string-matching) conditions hit with
/// the redaction marker, in place.
fn redact_matches(msg: &mut Value, conditions: &[Condition]) {
    for cond in conditions {
        let is_string_op = matches!(
            cond.op,
            Op::Contains(_) | Op::Regex(_) | Op::Glob(_) | Op::Equals(_) | Op::In(_)
        );
        if !is_string_op {
            continue;
        }
        json_path_mut(msg, &cond.path, &mut |v| {
            let hit = match &cond.op {
                Op::Contains(n) => v.as_str().is_some_and(|s| s.contains(n.as_str())),
                Op::Regex(re) => v.as_str().is_some_and(|s| re.is_match(s)),
                Op::Glob(g) => v.as_str().is_some_and(|s| glob_match(g, s)),
                Op::Equals(w) => v == w,
                Op::In(set) => set.iter().any(|s| s == v),
                _ => false,
            };
            if hit {
                *v = Value::String(REDACTION.to_string());
            }
        });
    }
}

/// Resolve a dotted path with `*` (any key) and `[*]` (any array element)
/// wildcards to the set of matching values. `a.b`, `a.*.c`,
/// `result.content[*].text`.
fn json_path<'a>(root: &'a Value, path: &str) -> Vec<&'a Value> {
    let mut cur: Vec<&Value> = vec![root];
    for seg in split_path(path) {
        let mut next = Vec::new();
        for v in cur {
            match seg {
                Seg::Key(k) => {
                    if let Some(x) = v.get(k) {
                        next.push(x);
                    }
                }
                Seg::AnyKey => {
                    if let Some(o) = v.as_object() {
                        next.extend(o.values());
                    }
                }
                Seg::Index(i) => {
                    if let Some(x) = v.as_array().and_then(|a| a.get(i)) {
                        next.push(x);
                    }
                }
                Seg::AnyIndex => {
                    if let Some(a) = v.as_array() {
                        next.extend(a.iter());
                    }
                }
            }
        }
        cur = next;
        if cur.is_empty() {
            break;
        }
    }
    cur
}

fn json_path_mut(root: &mut Value, path: &str, f: &mut dyn FnMut(&mut Value)) {
    fn walk(v: &mut Value, segs: &[Seg], f: &mut dyn FnMut(&mut Value)) {
        let Some((seg, rest)) = segs.split_first() else {
            f(v);
            return;
        };
        match seg {
            Seg::Key(k) => {
                if let Some(x) = v.get_mut(*k) {
                    walk(x, rest, f);
                }
            }
            Seg::AnyKey => {
                if let Some(o) = v.as_object_mut() {
                    for x in o.values_mut() {
                        walk(x, rest, f);
                    }
                }
            }
            Seg::Index(i) => {
                if let Some(x) = v.as_array_mut().and_then(|a| a.get_mut(*i)) {
                    walk(x, rest, f);
                }
            }
            Seg::AnyIndex => {
                if let Some(a) = v.as_array_mut() {
                    for x in a.iter_mut() {
                        walk(x, rest, f);
                    }
                }
            }
        }
    }
    let segs: Vec<Seg> = split_path(path).collect();
    walk(root, &segs, f);
}

#[derive(Clone)]
enum Seg<'a> {
    Key(&'a str),
    AnyKey,
    Index(usize),
    AnyIndex,
}

fn split_path(path: &str) -> impl Iterator<Item = Seg<'_>> {
    path.split('.').flat_map(|part| {
        let mut segs = Vec::new();
        let (name, brackets) = match part.split_once('[') {
            Some((n, b)) => (n, Some(b)),
            None => (part, None),
        };
        if name == "*" {
            segs.push(Seg::AnyKey);
        } else if !name.is_empty() {
            segs.push(Seg::Key(name));
        }
        if let Some(b) = brackets {
            for idx in b.split('[') {
                let idx = idx.trim_end_matches(']');
                if idx == "*" {
                    segs.push(Seg::AnyIndex);
                } else if let Ok(n) = idx.parse::<usize>() {
                    segs.push(Seg::Index(n));
                }
            }
        }
        segs
    })
}

/// `*` matches any run of characters, `?` one character. Anchored.
fn glob_match(pat: &str, s: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => m(&p[1..], s) || (!s.is_empty() && m(p, &s[1..])),
            Some(b'?') => !s.is_empty() && m(&p[1..], &s[1..]),
            Some(&c) => s.first() == Some(&c) && m(&p[1..], &s[1..]),
        }
    }
    m(pat.as_bytes(), s.as_bytes())
}

// ── validation ────────────────────────────────────────────────

fn parse_rule(v: &Value) -> Result<Rule, String> {
    let obj = v.as_object().ok_or("is not a mapping")?;
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or("missing `name`")?
        .to_string();

    let direction = match obj.get("direction").and_then(Value::as_str) {
        None | Some("any") => DirFilter::Any,
        Some("client-to-server") | Some("request") => DirFilter::ClientToServer,
        Some("server-to-client") | Some("response") => DirFilter::ServerToClient,
        Some(d) => return Err(format!("unknown direction `{d}`")),
    };

    let method = obj.get("method").and_then(Value::as_str).map(str::to_string);

    let action = match obj.get("action").and_then(Value::as_str) {
        Some("allow") => RuleAction::Allow,
        Some("warn") => RuleAction::Warn,
        Some("redact") => RuleAction::Redact,
        Some("block") => RuleAction::Block,
        Some(a) => return Err(format!("unknown action `{a}`")),
        None => return Err("missing `action`".to_string()),
    };

    let (require_all, raw_conditions) = match (obj.get("all"), obj.get("any"), obj.get("match")) {
        (Some(a), None, None) => (true, a),
        (None, Some(a), None) => (false, a),
        (None, None, Some(a)) => (true, a),
        (None, None, None) => (true, &Value::Array(vec![])),
        _ => return Err("use exactly one of `all:` / `any:` / `match:`".to_string()),
    };
    let cond_list = raw_conditions
        .as_array()
        .ok_or("`all`/`any`/`match` must be a list")?;
    let conditions = cond_list
        .iter()
        .map(parse_condition)
        .collect::<Result<Vec<_>, _>>()?;

    if action == RuleAction::Redact && conditions.is_empty() {
        return Err("a `redact` rule needs at least one condition".to_string());
    }

    Ok(Rule {
        name,
        direction,
        method,
        require_all,
        conditions,
        action,
        message: obj.get("message").and_then(Value::as_str).map(str::to_string),
    })
}

fn parse_condition(v: &Value) -> Result<Condition, String> {
    let obj = v.as_object().ok_or("condition is not a mapping")?;
    let path = obj
        .get("path")
        .and_then(Value::as_str)
        .ok_or("condition missing `path`")?
        .to_string();

    let mut found: Option<Op> = None;
    let mut set = |op: Op| -> Result<(), String> {
        if found.is_some() {
            return Err("condition has more than one operator".to_string());
        }
        found = Some(op);
        Ok(())
    };

    for (k, val) in obj {
        match k.as_str() {
            "path" => {}
            "equals" => set(Op::Equals(val.clone()))?,
            "contains" => set(Op::Contains(str_val(val, "contains")?))?,
            "not_contains" => set(Op::NotContains(str_val(val, "not_contains")?))?,
            "regex" => {
                let pat = str_val(val, "regex")?;
                let re = Regex::new(&pat).map_err(|e| format!("bad regex: {e}"))?;
                set(Op::Regex(re))?;
            }
            "glob" => set(Op::Glob(str_val(val, "glob")?))?,
            "exists" => set(if val.as_bool() == Some(false) {
                Op::NotExists
            } else {
                Op::Exists
            })?,
            "in" => set(Op::In(
                val.as_array().ok_or("`in` must be a list")?.clone(),
            ))?,
            "gt" => set(Op::Gt(val.as_f64().ok_or("`gt` must be a number")?))?,
            "lt" => set(Op::Lt(val.as_f64().ok_or("`lt` must be a number")?))?,
            other => return Err(format!("unknown condition key `{other}`")),
        }
    }

    Ok(Condition {
        path,
        op: found.ok_or("condition has no operator (contains / regex / equals / …)")?,
    })
}

fn str_val(v: &Value, key: &str) -> Result<String, String> {
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("`{key}` must be a string"))
}

/// Default candidate paths for the guardrails file.
pub fn default_paths(cwd: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = crate::debug_only_env("TALYX_GUARDRAILS") {
        out.push(std::path::PathBuf::from(p));
    }
    out.push(cwd.join(".talyx").join("guardrails.yaml"));
    if let Some(h) = dirs::home_dir() {
        out.push(h.join(".talyx").join("guardrails.yaml"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn g(yaml: &str) -> Guardrails {
        Guardrails::parse(yaml).unwrap()
    }

    #[test]
    fn json_path_resolves_wildcards() {
        let v = json!({"result":{"content":[{"text":"a"},{"text":"b"},{"other":1}]}});
        let hits = json_path(&v, "result.content[*].text");
        assert_eq!(hits, vec![&json!("a"), &json!("b")]);
    }

    #[test]
    fn glob_and_method_matching() {
        assert!(glob_match("*.exe", "foo.exe"));
        assert!(!glob_match("*.exe", "foo.exed"));
        assert!(method_matches("tools/*", "tools/call"));
        assert!(method_matches("tools/*", "tools"));
        assert!(!method_matches("tools/*", "resources/list"));
        assert!(method_matches("initialize", "initialize"));
    }

    #[test]
    fn a_block_rule_on_a_request_arg() {
        let gr = g(r#"
version: 1
rules:
  - name: no-ssh
    direction: client-to-server
    method: tools/call
    all:
      - path: params.arguments.*
        contains: "/.ssh/"
    action: block
    message: "ssh path"
"#);
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"read","arguments":{"path":"/home/u/.ssh/id_rsa"}}});
        match gr.evaluate(Direction::ClientToServer, None, &msg) {
            GuardrailOutcome::Block { rule, message } => {
                assert_eq!(rule, "no-ssh");
                assert_eq!(message, "ssh path");
            }
            _ => panic!("expected Block"),
        }
        // wrong direction → no match
        assert!(matches!(
            gr.evaluate(Direction::ServerToClient, None, &msg),
            GuardrailOutcome::None
        ));
    }

    #[test]
    fn a_redact_rule_rewrites_the_matched_strings() {
        let gr = g(r#"
version: 1
rules:
  - name: strip-keys
    direction: server-to-client
    method: tools/call
    any:
      - { path: "result.content[*].text", regex: "sk-[A-Za-z0-9]{10,}" }
    action: redact
"#);
        let msg = json!({"jsonrpc":"2.0","id":1,"result":{"content":[
            {"type":"text","text":"here is the key sk-ABCDEFGHIJKLMNOP"},
            {"type":"text","text":"nothing here"}
        ]}});
        match gr.evaluate(Direction::ServerToClient, Some("tools/call"), &msg) {
            GuardrailOutcome::Redact { rewritten, .. } => {
                let blocks = rewritten["result"]["content"].as_array().unwrap();
                assert_eq!(blocks[0]["text"], json!(REDACTION));
                assert_eq!(blocks[1]["text"], json!("nothing here"));
            }
            _ => panic!("expected Redact"),
        }
    }

    #[test]
    fn allow_short_circuits() {
        let gr = g(r#"
version: 1
rules:
  - name: trust-internal
    method: tools/list
    all:
      - path: result.tools[*].name
        glob: "internal_*"
    action: allow
"#);
        let msg = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"internal_search"}]}});
        assert!(matches!(
            gr.evaluate(Direction::ServerToClient, Some("tools/list"), &msg),
            GuardrailOutcome::Allow { .. }
        ));
    }

    #[test]
    fn warn_does_not_short_circuit_but_is_reported() {
        let gr = g(r#"
version: 1
rules:
  - name: note-writes
    method: tools/call
    any:
      - { path: params.name, contains: "write" }
    action: warn
"#);
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file"}});
        assert!(matches!(
            gr.evaluate(Direction::ClientToServer, None, &msg),
            GuardrailOutcome::Warn { .. }
        ));
    }

    fn parse_err(yaml: &str) -> String {
        match Guardrails::parse(yaml) {
            Err(e) => e,
            Ok(_) => panic!("expected a parse error"),
        }
    }

    #[test]
    fn validation_names_the_bad_rule() {
        let err = parse_err(
            "version: 1\nrules:\n  - name: ok\n    action: warn\n  - name: bad\n    action: blcok\n",
        );
        assert!(err.contains("rule 2") && err.contains("blcok"), "{err}");
    }

    #[test]
    fn empty_or_missing_rules_is_an_error_but_empty_list_is_ok() {
        assert!(Guardrails::parse("version: 1\n").is_err());
        assert_eq!(g("version: 1\nrules: []\n").rule_count(), 0);
    }
}
