//! agentguard-registry
//!
//! Fetches and extracts the actual code behind a registry-resolved MCP
//! server (`npx <pkg>`, `uvx <pkg>`, etc — `agentguard_core::ArtifactSource
//! ::Registry`) so `agentguard-scanner` can run the same static analysis
//! on it that a local script already gets, instead of falling back to
//! declared-evidence-only scoring. Closes the gap tracked in STATUS.md's
//! "Known limitations": "Registry-resolved MCP servers ... get scored on
//! declared evidence only — no static analysis of their actual code."
//!
//! **Opt-in, not automatic.** Fetching means a real outbound network call
//! to the npm/PyPI registry at scan time — a genuine change to this
//! product's trust boundary (every other artifact kind is scored purely
//! from what's already on disk). `agentguard scan`/`init` only do this
//! when the caller explicitly passes `--fetch-registry`; without it, a
//! registry-sourced artifact keeps today's behavior exactly. See
//! `agentguard-cli`'s `pipeline.rs` for where that flag is threaded
//! through.
//!
//! **Integrity, not blind trust.** Every downloaded archive is checked
//! against the checksum the registry's own metadata declares for it
//! (npm: `dist.integrity` (SRI, sha512) preferred, falling back to
//! `dist.shasum` (sha1); PyPI: `digests.sha256`) before extraction —
//! refuses to extract, rather than silently skipping the check, if
//! neither registry supplies one for a given file (verified live against
//! both registries: real responses always include at least one).
//!
//! **Cache, not re-fetch-every-scan.** Extracted content is cached at
//! `~/.agentguard/registry-cache/<registry>/<name>/<version>/content/`,
//! keyed on the version the registry actually resolved a spec to —
//! never on an unresolved tag like `"latest"` — so a later scan of the
//! same pinned or re-resolved version reuses it instead of re-downloading.

mod cache;
mod extract;
mod http;
mod npm;
mod pypi;

use agentguard_core::ArtifactSource;
use std::path::PathBuf;

pub use cache::resolve_cache_dir;

type Agent = ureq::Agent;

#[derive(Debug)]
pub enum RegistryError {
    /// The package name doesn't exist in the registry (HTTP 404), or a
    /// PyPI release has neither an sdist nor a wheel to fetch.
    NotFound { name: String, registry: String },
    /// A `registry` value on `ArtifactSource::Registry` this module
    /// doesn't know how to fetch from. Only `"npm"` and `"pypi"` are
    /// implemented (the only two `agentguard-adapters`' `classify_command`
    /// currently produces) — matched explicitly rather than falling
    /// through, so a future third registry source forces a deliberate
    /// decision here instead of a silent no-op.
    UnsupportedRegistry(String),
    /// A network-level failure: DNS, connection, timeout, non-2xx status
    /// other than 404, or a response that didn't parse as the JSON shape
    /// expected.
    Network(String),
    /// The downloaded archive's hash didn't match what the registry's own
    /// metadata declared for it (or neither registry supplied a checksum
    /// at all) — refused rather than extracted, since this is exactly the
    /// kind of integrity failure a security tool cannot shrug off.
    ChecksumMismatch { expected: String, actual: String },
    /// The archive didn't extract cleanly (corrupt, unsupported, or an
    /// entry the extractor's own path-traversal protection rejected).
    Extraction(String),
    Io(std::io::Error),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::NotFound { name, registry } => {
                write!(f, "'{name}' not found in the {registry} registry")
            }
            RegistryError::UnsupportedRegistry(r) => write!(f, "unsupported registry '{r}'"),
            RegistryError::Network(msg) => write!(f, "network error: {msg}"),
            RegistryError::ChecksumMismatch { expected, actual } => write!(
                f,
                "checksum mismatch (expected {expected}, got {actual}) -- refusing to extract unverified content"
            ),
            RegistryError::Extraction(msg) => write!(f, "extraction failed: {msg}"),
            RegistryError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for RegistryError {}

pub struct FetchedPackage {
    /// The directory the package's extracted content lives in — hand this
    /// straight to `agentguard_scanner::scan_dir` the same way any other
    /// artifact's `scan_root` is used.
    pub extracted_dir: PathBuf,
    /// The concrete version the registry resolved the spec to (e.g.
    /// `"1.4.2"` even if the config said `npx foo` with no version at
    /// all) — worth surfacing to the caller for display/logging, even
    /// though it's not otherwise load-bearing here (drift detection still
    /// runs on `agentguard_scanner::hash_path(extracted_dir)`, identical
    /// to every other local artifact, not on this version string).
    pub resolved_version: String,
}

/// Splits a package spec that may carry an inline version — `npx`/`uvx`
/// allow `pkg@version` (verified against uv's own docs for the `@`
/// syntax; it's also long-standing, well-known npm/npx behavior), and
/// pip-family tools use `pkg==version`. A bare scope marker (`@scope/
/// name` with no version) must NOT be split on its leading `@` — only a
/// LATER `@` (or an `==`) counts as a version separator.
fn parse_package_spec(spec: &str) -> (String, Option<String>) {
    if let Some(idx) = spec.find("==") {
        let (name, version) = spec.split_at(idx);
        return (name.to_string(), Some(version[2..].to_string()));
    }
    if let Some(idx) = spec.rfind('@') {
        if idx > 0 {
            let (name, version) = spec.split_at(idx);
            return (name.to_string(), Some(version[1..].to_string()));
        }
    }
    (spec.to_string(), None)
}

/// Fetches and extracts the package a `Registry` artifact source names,
/// using (and populating) the cache at `cache_dir`. `source` must be
/// `ArtifactSource::Registry` — any other variant is a caller error, not
/// a runtime condition this function needs to handle gracefully, since
/// every call site already knows which artifacts are registry-sourced
/// before calling this.
pub fn fetch_and_extract(source: &ArtifactSource, cache_dir: &std::path::Path) -> Result<FetchedPackage, RegistryError> {
    let ArtifactSource::Registry { name, registry } = source else {
        return Err(RegistryError::UnsupportedRegistry(format!(
            "fetch_and_extract called with a non-Registry source: {source:?}"
        )));
    };
    let (package_name, version_spec) = parse_package_spec(name);
    let agent = http::new_agent();

    match registry.as_str() {
        "npm" => fetch_npm(&agent, &package_name, version_spec.as_deref(), cache_dir),
        "pypi" => fetch_pypi(&agent, &package_name, version_spec.as_deref(), cache_dir),
        other => Err(RegistryError::UnsupportedRegistry(other.to_string())),
    }
}

fn fetch_npm(
    agent: &Agent,
    package_name: &str,
    version_spec: Option<&str>,
    cache_dir: &std::path::Path,
) -> Result<FetchedPackage, RegistryError> {
    // Two network round-trips even for a pinned version (metadata, then
    // the tarball) are unavoidable if we want the resolved version before
    // computing the cache key -- but for an ALREADY-cached version, this
    // still means a metadata fetch every time just to learn the version
    // number to check the cache with. Acceptable in v0: a metadata fetch
    // is small and fast, and getting this wrong (skipping it) would mean
    // trusting a caller-supplied version string as authoritative without
    // ever confirming it against the registry, which is worse.
    if let Some(pinned) = version_spec {
        let package_dir = cache::package_dir(cache_dir, "npm", package_name, pinned);
        if cache::is_complete(&package_dir) {
            return Ok(FetchedPackage {
                extracted_dir: cache::content_dir(&package_dir),
                resolved_version: pinned.to_string(),
            });
        }
    }

    let fetched = npm::fetch(agent, package_name, version_spec)?;
    let package_dir = cache::package_dir(cache_dir, "npm", package_name, &fetched.resolved_version);
    if cache::is_complete(&package_dir) {
        return Ok(FetchedPackage {
            extracted_dir: cache::content_dir(&package_dir),
            resolved_version: fetched.resolved_version,
        });
    }

    let content_dir = cache::content_dir(&package_dir);
    extract::extract_tar_gz(&fetched.bytes, &content_dir)?;
    extract::write_archive(&fetched.bytes, &package_dir.join("archive.tgz")).ok(); // best-effort, not load-bearing
    cache::mark_complete(&package_dir).map_err(RegistryError::Io)?;

    Ok(FetchedPackage {
        extracted_dir: content_dir,
        resolved_version: fetched.resolved_version,
    })
}

fn fetch_pypi(
    agent: &Agent,
    package_name: &str,
    version_spec: Option<&str>,
    cache_dir: &std::path::Path,
) -> Result<FetchedPackage, RegistryError> {
    if let Some(pinned) = version_spec {
        let package_dir = cache::package_dir(cache_dir, "pypi", package_name, pinned);
        if cache::is_complete(&package_dir) {
            return Ok(FetchedPackage {
                extracted_dir: cache::content_dir(&package_dir),
                resolved_version: pinned.to_string(),
            });
        }
    }

    let fetched = pypi::fetch(agent, package_name, version_spec)?;
    let (resolved_version, bytes, is_wheel) = match fetched {
        pypi::FetchedArchive::Sdist { resolved_version, bytes } => (resolved_version, bytes, false),
        pypi::FetchedArchive::Wheel { resolved_version, bytes } => (resolved_version, bytes, true),
    };

    let package_dir = cache::package_dir(cache_dir, "pypi", package_name, &resolved_version);
    if cache::is_complete(&package_dir) {
        return Ok(FetchedPackage {
            extracted_dir: cache::content_dir(&package_dir),
            resolved_version,
        });
    }

    let content_dir = cache::content_dir(&package_dir);
    if is_wheel {
        extract::extract_zip(&bytes, &content_dir)?;
        extract::write_archive(&bytes, &package_dir.join("archive.whl")).ok();
    } else {
        extract::extract_tar_gz(&bytes, &content_dir)?;
        extract::write_archive(&bytes, &package_dir.join("archive.tar.gz")).ok();
    }
    cache::mark_complete(&package_dir).map_err(RegistryError::Io)?;

    Ok(FetchedPackage { extracted_dir: content_dir, resolved_version })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_package_name_with_no_version() {
        assert_eq!(
            parse_package_spec("@modelcontextprotocol/server-filesystem"),
            ("@modelcontextprotocol/server-filesystem".to_string(), None)
        );
        assert_eq!(parse_package_spec("some-package"), ("some-package".to_string(), None));
    }

    #[test]
    fn parses_an_npm_style_pinned_scoped_package() {
        assert_eq!(
            parse_package_spec("@modelcontextprotocol/server-filesystem@1.2.3"),
            ("@modelcontextprotocol/server-filesystem".to_string(), Some("1.2.3".to_string()))
        );
    }

    #[test]
    fn parses_an_npm_style_pinned_unscoped_package() {
        assert_eq!(
            parse_package_spec("left-pad@1.3.0"),
            ("left-pad".to_string(), Some("1.3.0".to_string()))
        );
    }

    #[test]
    fn parses_a_pip_style_pinned_package() {
        assert_eq!(
            parse_package_spec("black==24.1.0"),
            ("black".to_string(), Some("24.1.0".to_string()))
        );
    }
}
