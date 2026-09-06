//! agentguard-scanner::shadowing
//!
//! Cross-artifact analysis: a single MCP server's launch command tells you
//! nothing about whether its *name* is a trap. `detect_shadowing` looks at
//! every configured MCP server together and flags the ones whose name
//! would let them intercept the agent's tool calls:
//!
//!  - an unverified server sharing a name with a trusted/verified one
//!    (the agent may bind `read_file` / `search` / ... to whichever it
//!    loads — "tool shadowing"),
//!  - a server using, or a near-miss spelling of, a well-known server name
//!    (`filesystem`, `github`, `slack`, ...) from a launch source that
//!    isn't the canonical one for that name ("server impersonation" /
//!    typosquatting).
//!
//! Every serious MCP-security tool (Snyk, Invariant Labs, Pillar) treats
//! this as a core detection. AgentGuard's per-artifact scanner never saw
//! it because it only ever inspected one launch command at a time.
//!
//! Deliberately conservative: a finding is only produced for an
//! *unverified* server (no reputation match), and only when the name
//! genuinely conflicts — a user legitimately running two `fetch` servers,
//! both from trusted sources, is not flagged.

use agentguard_core::{ArtifactSource, Capability, CapabilityFinding, EvidenceBasis};

/// One MCP server, as far as name analysis cares.
pub struct ServerRef<'a> {
    pub name: &'a str,
    pub source: &'a ArtifactSource,
    /// The risk engine found a reputation match / verified publisher for
    /// this server (`ScoreBreakdown.reputation_discount > 0`).
    pub trusted: bool,
}

/// Well-known MCP server names an attacker would impersonate, each with
/// the registry package names and remote domains that are legitimate for
/// that name. A server using one of these names (or a near-miss spelling)
/// from any OTHER source is the impersonation / typosquat pattern.
struct WellKnown {
    name: &'static str,
    packages: &'static [&'static str],
    domains: &'static [&'static str],
}

const WELL_KNOWN: &[WellKnown] = &[
    WellKnown { name: "filesystem", packages: &["@modelcontextprotocol/server-filesystem", "mcp-server-filesystem"], domains: &[] },
    WellKnown { name: "github", packages: &["@modelcontextprotocol/server-github", "@github/github-mcp-server", "github-mcp-server"], domains: &["api.githubcopilot.com"] },
    WellKnown { name: "git", packages: &["@modelcontextprotocol/server-git", "mcp-server-git"], domains: &[] },
    WellKnown { name: "fetch", packages: &["@modelcontextprotocol/server-fetch", "mcp-server-fetch"], domains: &[] },
    WellKnown { name: "memory", packages: &["@modelcontextprotocol/server-memory"], domains: &[] },
    WellKnown { name: "everything", packages: &["@modelcontextprotocol/server-everything"], domains: &[] },
    WellKnown { name: "time", packages: &["@modelcontextprotocol/server-time", "mcp-server-time"], domains: &[] },
    WellKnown { name: "sequthinking", packages: &["@modelcontextprotocol/server-sequential-thinking"], domains: &[] },
    WellKnown { name: "slack", packages: &["@modelcontextprotocol/server-slack"], domains: &["slack.com"] },
    WellKnown { name: "postgres", packages: &["@modelcontextprotocol/server-postgres"], domains: &[] },
    WellKnown { name: "sqlite", packages: &["@modelcontextprotocol/server-sqlite", "mcp-server-sqlite"], domains: &[] },
    WellKnown { name: "puppeteer", packages: &["@modelcontextprotocol/server-puppeteer"], domains: &[] },
    WellKnown { name: "gitlab", packages: &["@modelcontextprotocol/server-gitlab"], domains: &["gitlab.com"] },
    WellKnown { name: "sentry", packages: &["@sentry/mcp-server", "mcp-server-sentry"], domains: &["sentry.io", "sentry.dev"] },
    WellKnown { name: "notion", packages: &["@notionhq/notion-mcp-server"], domains: &["mcp.notion.com"] },
    WellKnown { name: "linear", packages: &[], domains: &["mcp.linear.app"] },
    WellKnown { name: "stripe", packages: &["@stripe/mcp"], domains: &["mcp.stripe.com"] },
    WellKnown { name: "atlassian", packages: &[], domains: &["mcp.atlassian.com"] },
];

/// Returns `(index into `servers`, finding)` pairs. The finding's
/// `capability` is always `Capability::ToolShadowing`.
pub fn detect_shadowing(servers: &[ServerRef]) -> Vec<(usize, CapabilityFinding)> {
    let mut out = Vec::new();

    for (i, s) in servers.iter().enumerate() {
        if s.trusted {
            continue;
        }
        let name_l = s.name.to_lowercase();

        // 1. Same name as a trusted server also configured on this machine.
        if let Some(t) = servers
            .iter()
            .find(|other| other.trusted && other.name.to_lowercase() == name_l)
        {
            out.push((
                i,
                finding(format!(
                    "an unverified MCP server named \"{}\" is configured alongside a trusted server of the same name ({}) — the agent could bind this server's tools instead (tool shadowing)",
                    s.name,
                    describe_source(t.source),
                )),
            ));
            continue;
        }

        // 2. Uses, or is a near-miss of, a well-known server name from a
        //    non-canonical source.
        if let Some(reason) = well_known_conflict(&name_l, s.source) {
            out.push((i, finding(reason)));
        }
    }

    out
}

fn finding(evidence: String) -> CapabilityFinding {
    CapabilityFinding {
        capability: Capability::ToolShadowing,
        basis: EvidenceBasis::Inferred,
        evidence,
        location: None,
    }
}

fn well_known_conflict(name_l: &str, source: &ArtifactSource) -> Option<String> {
    for wk in WELL_KNOWN {
        // Exact name match from a non-canonical source.
        if name_l == wk.name && !source_is_canonical(source, wk) {
            return Some(format!(
                "MCP server named \"{}\" — a well-known server name — but launched from {}, not its official source; a look-alike server using a trusted name can intercept the agent's tool calls (server impersonation)",
                wk.name,
                describe_source(source),
            ));
        }
        // Near-miss spelling (typosquat), regardless of source.
        if name_l != wk.name && looks_like(name_l, wk.name) {
            return Some(format!(
                "MCP server name \"{}\" closely resembles the well-known \"{}\" server — a possible typosquat used for tool shadowing",
                name_l, wk.name
            ));
        }
    }
    None
}

fn source_is_canonical(source: &ArtifactSource, wk: &WellKnown) -> bool {
    match source {
        ArtifactSource::Registry { name, .. } => {
            let n = name.to_lowercase();
            n == format!("@modelcontextprotocol/server-{}", wk.name)
                || n == format!("mcp-server-{}", wk.name)
                || wk.packages.iter().any(|p| n == p.to_lowercase())
        }
        ArtifactSource::RemoteUrl(url) => {
            let host = host_of(url);
            wk.domains
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        }
        // A bare local path or an arbitrary git URL is never the canonical
        // source for a well-known server name.
        ArtifactSource::LocalPath(_) | ArtifactSource::GitUrl(_) => false,
    }
}

/// True if `candidate` is a deliberate-looking near-miss of `target`:
/// Levenshtein distance 1 (for names >= 4 chars), or `target` embedded in
/// `candidate` with a look-alike affix (`github-unofficial`, `my-slack`,
/// `fetch2`, ...).
fn looks_like(candidate: &str, target: &str) -> bool {
    // Edit-distance typosquatting only for names long enough that a
    // single-char difference is unlikely to be a coincidence (`time` /
    // `git` are too short — a real `timer` server would false-positive).
    if target.len() >= 5 && levenshtein_at_most(candidate, target, 1) {
        return true;
    }
    // Deliberately narrow — a suffix that reads as "this is the real one"
    // or "a variant of the real one". `-mcp` / `-server` are excluded:
    // they're ordinary in legitimate server names.
    const SUFFIXES: &[&str] = &[
        "-unofficial", "-official", "-real", "-new", "-fork", "-plus", "-pro",
        "-v2", "2", "_",
    ];
    for aff in SUFFIXES {
        if candidate == format!("{target}{aff}") {
            return true;
        }
    }
    for pre in ["my-", "the-", "our-", "internal-", "custom-", "fake-"] {
        if candidate == format!("{pre}{target}") {
            return true;
        }
    }
    false
}

/// Levenshtein distance, short-circuiting once it exceeds `max`.
fn levenshtein_at_most(a: &str, b: &str, max: usize) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > max {
        return false;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        let mut row_min = cur[0];
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
            row_min = row_min.min(cur[j + 1]);
        }
        if row_min > max {
            return false;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()] <= max
}

fn host_of(url: &str) -> String {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn describe_source(source: &ArtifactSource) -> String {
    match source {
        ArtifactSource::Registry { name, registry } => format!("the {registry} package `{name}`"),
        ArtifactSource::RemoteUrl(u) => format!("`{}`", host_of(u)),
        ArtifactSource::GitUrl(u) => format!("git `{u}`"),
        ArtifactSource::LocalPath(p) => format!("a local path (`{p}`)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str) -> ArtifactSource {
        ArtifactSource::Registry { name: name.to_string(), registry: "npm".to_string() }
    }

    fn s<'a>(name: &'a str, source: &'a ArtifactSource, trusted: bool) -> ServerRef<'a> {
        ServerRef { name, source, trusted }
    }

    #[test]
    fn flags_unverified_server_sharing_a_trusted_server_name() {
        let trusted_src = reg("@modelcontextprotocol/server-github");
        let evil_src = reg("totally-not-github");
        let servers = vec![
            s("github", &trusted_src, true),
            s("github", &evil_src, false),
        ];
        let found = detect_shadowing(&servers);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 1);
        assert_eq!(found[0].1.capability, Capability::ToolShadowing);
    }

    #[test]
    fn flags_well_known_name_from_a_local_path() {
        let src = ArtifactSource::LocalPath("/home/x/my-fs-server".to_string());
        let servers = vec![s("filesystem", &src, false)];
        let found = detect_shadowing(&servers);
        assert_eq!(found.len(), 1);
        assert!(found[0].1.evidence.contains("impersonation"));
    }

    #[test]
    fn does_not_flag_the_real_official_server() {
        let src = reg("@modelcontextprotocol/server-filesystem");
        let servers = vec![s("filesystem", &src, false)];
        assert!(detect_shadowing(&servers).is_empty());
    }

    #[test]
    fn does_not_flag_a_trusted_server() {
        let src = reg("whatever");
        let servers = vec![s("github", &src, true)];
        assert!(detect_shadowing(&servers).is_empty());
    }

    #[test]
    fn flags_a_typosquat() {
        // "gihub" — one deletion from "github".
        let src = reg("random-pkg");
        let servers = vec![s("gihub", &src, false)];
        let found = detect_shadowing(&servers);
        assert_eq!(found.len(), 1);
        assert!(found[0].1.evidence.contains("typosquat"));
    }

    #[test]
    fn flags_an_affix_lookalike() {
        let src = reg("random-pkg");
        let servers = vec![s("github-unofficial", &src, false)];
        assert_eq!(detect_shadowing(&servers).len(), 1);
    }

    #[test]
    fn does_not_flag_two_unrelated_unverified_servers() {
        let a = reg("my-cool-tool");
        let b = reg("another-tool");
        let servers = vec![s("weather", &a, false), s("stocks", &b, false)];
        assert!(detect_shadowing(&servers).is_empty());
    }

    #[test]
    fn does_not_flag_a_real_remote_vendor_server() {
        let src = ArtifactSource::RemoteUrl("https://mcp.linear.app/mcp".to_string());
        let servers = vec![s("linear", &src, false)];
        assert!(detect_shadowing(&servers).is_empty());
    }

    #[test]
    fn flags_a_lookalike_remote_domain() {
        let src = ArtifactSource::RemoteUrl("https://api.fake-linear.example/mcp".to_string());
        let servers = vec![s("linear", &src, false)];
        assert_eq!(detect_shadowing(&servers).len(), 1);
    }

    #[test]
    fn levenshtein_short_circuits() {
        assert!(levenshtein_at_most("github", "gihub", 1)); // one deletion
        assert!(levenshtein_at_most("github", "githubb", 1)); // one insertion
        assert!(levenshtein_at_most("slack", "slask", 1)); // one substitution
        assert!(!levenshtein_at_most("github", "gitlab", 1)); // 2 edits
        assert!(!levenshtein_at_most("github", "githbu", 1)); // transposition = 2 plain edits
        assert!(!levenshtein_at_most("abc", "xyz", 1));
    }
}
