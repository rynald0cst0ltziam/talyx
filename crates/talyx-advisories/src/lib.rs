//! talyx-advisories — the known-bad feed (BUILD_PLAN.md §7, the
//! "known-bad" half).
//!
//! A small, hand-curated, publicly-sourced list of malicious or
//! vulnerable MCP artifacts, matched by **identity** — a package
//! name+version, a publisher, a remote host, a git-repo owner, or a name
//! pattern — not by heuristics. `data/advisories.json` is embedded so it
//! works offline; a newer copy can be dropped in at
//! `~/.talyx/advisories.json` (see [`load`]).
//!
//! A `malicious` match yields `Capability::KnownMalicious` (the risk
//! engine forces BLOCK); an `advisory` match yields
//! `Capability::KnownAdvisory` (forces review).

use talyx_core::{ArtifactSource, Capability, CapabilityFinding, EvidenceBasis};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

const EMBEDDED: &str = include_str!("../../../data/advisories.json");

#[derive(Deserialize)]
struct Feed {
    #[serde(default)]
    version: u32,
    advisories: Vec<Advisory>,
}

#[derive(Deserialize, Clone)]
pub struct Advisory {
    pub id: String,
    pub title: String,
    /// `"malicious"` or `"advisory"`.
    pub severity: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub published: String,
    #[serde(rename = "match")]
    matchers: Vec<Matcher>,
}

#[derive(Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Matcher {
    /// An npm package. `min_affected` (>=), `max_affected` (<=), or an
    /// explicit `affected` list; omit all three to match any version.
    Npm {
        name: String,
        #[serde(default)]
        min_affected: Option<String>,
        #[serde(default)]
        max_affected: Option<String>,
        #[serde(default)]
        affected: Vec<String>,
        #[serde(default)]
        fixed: Option<String>,
    },
    /// A PyPI package (same fields as `npm`).
    Pypi {
        name: String,
        #[serde(default)]
        min_affected: Option<String>,
        #[serde(default)]
        max_affected: Option<String>,
        #[serde(default)]
        affected: Vec<String>,
        #[serde(default)]
        fixed: Option<String>,
    },
    NpmPublisher {
        value: String,
    },
    NpmNameRegex {
        value: String,
    },
    /// A remote MCP server's registrable host.
    UrlHost {
        value: String,
    },
    /// A source repo owner (+ optional repo name).
    GitHostOwner {
        value: String,
        #[serde(default)]
        repo: Option<String>,
    },
}

/// The registry of advisories, loaded once.
pub struct Advisories {
    list: Vec<Advisory>,
    pub source: &'static str,
}

static EMBEDDED_ADVISORIES: Lazy<Advisories> = Lazy::new(|| {
    let feed: Feed =
        serde_json::from_str(EMBEDDED).expect("embedded data/advisories.json is valid");
    debug_assert_eq!(feed.version, 1);
    Advisories {
        list: feed.advisories,
        source: "embedded",
    }
});

impl Advisories {
    /// The embedded feed (always available, offline).
    pub fn embedded() -> &'static Advisories {
        &EMBEDDED_ADVISORIES
    }

    /// Load `~/.talyx/advisories.json` if present and valid, else the
    /// embedded feed. Used by `talyx scan`/`init`.
    pub fn load(path: Option<&Path>) -> Advisories {
        let embedded = || Advisories {
            list: EMBEDDED_ADVISORIES.list.clone(),
            source: "embedded",
        };
        let Some(path) = path else {
            return embedded();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            // No override file at that path — the common case, not an error.
            return embedded();
        };
        match serde_json::from_str::<Feed>(&text) {
            Ok(feed) if feed.version == 1 => Advisories {
                list: feed.advisories,
                source: "~/.talyx/advisories.json",
            },
            _ => Advisories {
                list: EMBEDDED_ADVISORIES.list.clone(),
                source: "embedded (override file present but invalid)",
            },
        }
    }

    /// Strictly parse + sanity-check a candidate feed (used by
    /// `talyx advisories refresh` before it overwrites the local file).
    /// Enforces the same curation rules `data/advisories.json` documents:
    /// `version == 1`, non-empty, and every advisory has a well-formed id,
    /// a `malicious`/`advisory` severity, at least one `references` URL,
    /// and at least one matcher. Returns the advisory count on success.
    pub fn validate(text: &str) -> Result<usize, String> {
        let feed: Feed = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
        if feed.version != 1 {
            return Err(format!("unsupported feed version {} (expected 1)", feed.version));
        }
        if feed.advisories.is_empty() {
            return Err("feed contains no advisories".to_string());
        }
        for adv in &feed.advisories {
            if adv.id.trim().is_empty() {
                return Err("an advisory has an empty id".to_string());
            }
            if adv.severity != "malicious" && adv.severity != "advisory" {
                return Err(format!(
                    "advisory {} has severity {:?} (expected \"malicious\" or \"advisory\")",
                    adv.id, adv.severity
                ));
            }
            if adv.references.iter().all(|r| r.trim().is_empty()) {
                return Err(format!("advisory {} has no reference URL", adv.id));
            }
            if adv.matchers.is_empty() {
                return Err(format!("advisory {} has no matchers", adv.id));
            }
        }
        Ok(feed.advisories.len())
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Advisory> {
        self.list.iter()
    }

    /// Check one artifact's identity against every advisory. Returns the
    /// capability finding(s) to attach — one per matching advisory.
    pub fn check(
        &self,
        source: &ArtifactSource,
        publisher: Option<&str>,
        repo_url: Option<&str>,
        version: Option<&str>,
    ) -> Vec<CapabilityFinding> {
        let mut out = Vec::new();
        for adv in &self.list {
            if adv
                .matchers
                .iter()
                .any(|m| matcher_hits(m, source, publisher, repo_url, version))
            {
                let cap = if adv.severity == "malicious" {
                    Capability::KnownMalicious
                } else {
                    Capability::KnownAdvisory
                };
                let refs = adv
                    .references
                    .first()
                    .map(|r| format!(" (see {r})"))
                    .unwrap_or_default();
                out.push(CapabilityFinding {
                    capability: cap,
                    basis: EvidenceBasis::Declared,
                    evidence: format!("advisory {}: {}{}", adv.id, adv.title, refs),
                    location: None,
                });
            }
        }
        out
    }
}

fn matcher_hits(
    m: &Matcher,
    source: &ArtifactSource,
    publisher: Option<&str>,
    repo_url: Option<&str>,
    version: Option<&str>,
) -> bool {
    match m {
        Matcher::Npm {
            name,
            min_affected,
            max_affected,
            affected,
            fixed,
        }
        | Matcher::Pypi {
            name,
            min_affected,
            max_affected,
            affected,
            fixed,
        } => {
            let want_registry = matches!(m, Matcher::Npm { .. }).then_some("npm");
            let want_registry = want_registry.or(matches!(m, Matcher::Pypi { .. }).then_some("pypi"));
            let ArtifactSource::Registry {
                name: pkg,
                registry,
            } = source
            else {
                return false;
            };
            // `pkg` is the raw spec from the config (`npx -y foo@1.2.3`,
            // `uvx black==24.1.0`) — split off any inline version so the
            // bare name can match and the pin feeds the range check.
            let (pkg_name, inline_ver) = split_spec(pkg, registry);
            if Some(registry.as_str()) != want_registry || pkg_name != name {
                return false;
            }
            let effective = version.or(inline_ver);
            version_in_range(effective, min_affected, max_affected, affected, fixed)
        }
        Matcher::NpmPublisher { value } => publisher.is_some_and(|p| p.eq_ignore_ascii_case(value)),
        Matcher::NpmNameRegex { value } => {
            let ArtifactSource::Registry { name, registry } = source else {
                return false;
            };
            let (bare, _) = split_spec(name, registry);
            registry == "npm" && compiled(value).is_match(bare)
        }
        Matcher::UrlHost { value } => match source {
            ArtifactSource::RemoteUrl(url) => host_of(url)
                .is_some_and(|h| h == value.as_str() || h.ends_with(&format!(".{value}"))),
            _ => false,
        },
        Matcher::GitHostOwner { value, repo } => {
            let url = match source {
                ArtifactSource::GitUrl(u) => Some(u.as_str()),
                _ => repo_url,
            };
            let Some(url) = url else { return false };
            let lower = url.to_lowercase();
            let owner_hit = lower.contains(&format!("/{}/", value.to_lowercase()))
                || lower.contains(&format!("/{}", value.to_lowercase()));
            match repo {
                Some(r) => owner_hit && lower.contains(&r.to_lowercase()),
                None => owner_hit,
            }
        }
    }
}

/// Conservative: when the artifact's version is unknown, a range-bounded
/// advisory still matches (better a false ASK than a missed malicious
/// package), UNLESS an explicit `fixed` version is given AND we can tell
/// the pinned version is at or above it.
fn version_in_range(
    version: Option<&str>,
    min: &Option<String>,
    max: &Option<String>,
    affected: &[String],
    fixed: &Option<String>,
) -> bool {
    if min.is_none() && max.is_none() && affected.is_empty() && fixed.is_none() {
        return true; // whole package is bad, any version
    }
    let Some(v) = version else {
        // unknown version — err toward flagging
        return true;
    };
    if !affected.is_empty() {
        return affected.iter().any(|a| a == v);
    }
    if let Some(f) = fixed {
        if cmp_semver(v, f) != std::cmp::Ordering::Less {
            return false; // at or above the fix
        }
    }
    if let Some(lo) = min {
        if cmp_semver(v, lo) == std::cmp::Ordering::Less {
            return false;
        }
    }
    if let Some(hi) = max {
        if cmp_semver(v, hi) == std::cmp::Ordering::Greater {
            return false;
        }
    }
    true
}

/// Numeric dotted-version compare. Non-numeric / pre-release suffixes on a
/// component compare as lower (`1.0.0-rc` < `1.0.0`); good enough for the
/// simple ranges these advisories use.
fn cmp_semver(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| -> Vec<i64> {
        s.split(['.', '-', '+'])
            .map(|p| p.parse::<i64>().unwrap_or(-1))
            .collect()
    };
    parts(a).cmp(&parts(b))
}

/// Split a registry spec into (bare name, exact pinned version). Handles
/// npm `name@1.2.3` / `@scope/name@1.2.3` / `name@latest` and PyPI
/// `name==1.2.3` / `name>=1.0`. A dist-tag or non-`==` constraint yields
/// `None` for the version (so the conservative "unknown version flags"
/// path in `version_in_range` still applies).
fn split_spec<'a>(spec: &'a str, registry: &str) -> (&'a str, Option<&'a str>) {
    if registry == "pypi" {
        for sep in ["==", ">=", "<=", "~=", "!=", ">", "<"] {
            if let Some((name, ver)) = spec.split_once(sep) {
                let ver = (sep == "==" && !ver.is_empty()).then_some(ver);
                return (name.trim(), ver);
            }
        }
        return (spec, None);
    }
    // npm: the version delimiter is the LAST '@' that isn't the leading
    // scope marker.
    let at = if let Some(rest) = spec.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        spec.find('@')
    };
    match at {
        Some(i) => {
            let ver = &spec[i + 1..];
            let numericish = ver
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false);
            (&spec[..i], numericish.then_some(ver))
        }
        None => (spec, None),
    }
}

fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()?
        .split('@')
        .next_back()?
        .split(':')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn compiled(pat: &str) -> &'static Regex {
    static CACHE: Lazy<std::sync::Mutex<std::collections::HashMap<String, &'static Regex>>> =
        Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut c = CACHE.lock().unwrap();
    if let Some(re) = c.get(pat) {
        return re;
    }
    let re: &'static Regex = Box::leak(Box::new(
        Regex::new(pat).unwrap_or_else(|_| Regex::new("$^").unwrap()),
    ));
    c.insert(pat.to_string(), re);
    re
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str, registry: &str) -> ArtifactSource {
        ArtifactSource::Registry {
            name: name.to_string(),
            registry: registry.to_string(),
        }
    }

    #[test]
    fn embedded_feed_parses_and_is_nonempty() {
        let a = Advisories::embedded();
        assert!(a.len() >= 4);
        assert!(a.iter().all(|adv| !adv.references.is_empty()));
        assert!(a
            .iter()
            .all(|adv| adv.severity == "malicious" || adv.severity == "advisory"));
    }

    #[test]
    fn validate_accepts_the_embedded_feed_and_rejects_malformed_ones() {
        assert!(Advisories::validate(EMBEDDED).unwrap() >= 4);

        assert!(Advisories::validate("not json").is_err());
        assert!(Advisories::validate(r#"{"version":2,"advisories":[]}"#).is_err());
        assert!(Advisories::validate(r#"{"version":1,"advisories":[]}"#)
            .unwrap_err()
            .contains("no advisories"));

        // an advisory missing its references URL is rejected
        let no_ref = r#"{"version":1,"advisories":[
            {"id":"X-1","title":"t","severity":"malicious","references":[],
             "match":[{"type":"npm_publisher","value":"x"}]}]}"#;
        assert!(Advisories::validate(no_ref).unwrap_err().contains("reference"));

        // a bad severity is rejected
        let bad_sev = r#"{"version":1,"advisories":[
            {"id":"X-1","title":"t","severity":"scary","references":["https://x"],
             "match":[{"type":"npm_publisher","value":"x"}]}]}"#;
        assert!(Advisories::validate(bad_sev).unwrap_err().contains("severity"));
    }

    #[test]
    fn postmark_mcp_is_flagged_malicious_from_the_affected_version_on() {
        let a = Advisories::embedded();
        let bad = a.check(&reg("postmark-mcp", "npm"), None, None, Some("1.0.17"));
        assert!(bad.iter().any(|f| f.capability == Capability::KnownMalicious));
        // an earlier version isn't in range
        let ok = a.check(&reg("postmark-mcp", "npm"), None, None, Some("1.0.9"));
        assert!(ok.is_empty());
        // another package from the same publisher is flagged for REVIEW
        // (advisory), not auto-blocked as malicious — pattern-based matches
        // never force a block.
        let by_pub = a.check(&reg("something-else", "npm"), Some("phanpak"), None, None);
        assert!(by_pub.iter().any(|f| f.capability == Capability::KnownAdvisory));
        assert!(!by_pub.iter().any(|f| f.capability == Capability::KnownMalicious));
    }

    #[test]
    fn mcp_remote_advisory_clears_once_you_are_on_the_fixed_version() {
        let a = Advisories::embedded();
        assert!(!a
            .check(&reg("mcp-remote", "npm"), None, None, Some("0.1.10"))
            .is_empty());
        assert!(a
            .check(&reg("mcp-remote", "npm"), None, None, Some("0.1.16"))
            .is_empty());
        assert!(a
            .check(&reg("mcp-remote", "npm"), None, None, Some("0.2.0"))
            .is_empty());
    }

    #[test]
    fn typosquat_name_pattern_matches() {
        let a = Advisories::embedded();
        assert!(!a
            .check(&reg("github-mcp-unofficial", "npm"), None, None, None)
            .is_empty());
        assert!(a
            .check(&reg("my-legit-tool", "npm"), None, None, None)
            .is_empty());
    }

    #[test]
    fn inline_version_spec_from_a_config_is_split_and_range_checked() {
        let a = Advisories::embedded();
        // `npx -y postmark-mcp@1.0.17` -> source name carries the spec
        assert!(!a
            .check(&reg("postmark-mcp@1.0.17", "npm"), None, None, None)
            .is_empty());
        // fixed version of mcp-remote, inline
        assert!(a
            .check(&reg("mcp-remote@0.1.16", "npm"), None, None, None)
            .is_empty());
        // a dist-tag isn't a version -> conservative flag still applies
        assert!(!a
            .check(&reg("mcp-remote@latest", "npm"), None, None, None)
            .is_empty());
        // typosquat regex still matches when a version is appended
        assert!(!a
            .check(&reg("github-mcp-unofficial@2.0.0", "npm"), None, None, None)
            .is_empty());
    }

    #[test]
    fn unknown_version_errs_toward_flagging_but_not_past_a_fix() {
        let a = Advisories::embedded();
        // postmark-mcp: no fixed version -> unknown version flags
        assert!(!a
            .check(&reg("postmark-mcp", "npm"), None, None, None)
            .is_empty());
    }
}
