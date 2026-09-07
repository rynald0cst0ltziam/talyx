//! Where fetched-and-extracted package content lives on disk. Cached by
//! `(registry, name, resolved version)` — never by an unresolved spec like
//! `"latest"`, so a stale extraction is never silently reused across a real
//! version change (the version is always resolved from the registry's own
//! metadata BEFORE the cache path is computed — see `npm.rs`/`pypi.rs`).

use std::path::{Path, PathBuf};

/// `$TALYX_REGISTRY_CACHE` env var if set, else
/// `~/.talyx/registry-cache` — same resolution shape as
/// `talyx-store`'s `DecisionStore::resolve` (env var override, then a
/// home-relative default), so a demo/test can point this at an isolated
/// directory the same way it already does for the decision store.
pub fn resolve_cache_dir() -> PathBuf {
    if let Ok(path) = std::env::var("TALYX_REGISTRY_CACHE") {
        return PathBuf::from(path);
    }
    dirs::home_dir()
        .map(|h| h.join(".talyx").join("registry-cache"))
        .unwrap_or_else(|| PathBuf::from(".talyx-registry-cache"))
}

/// Filesystem-safe directory name for a package name that may contain
/// characters a path segment can't (npm scoped packages contain `/`, e.g.
/// `@modelcontextprotocol/server-filesystem`). Deliberately conservative:
/// anything outside `[A-Za-z0-9._-]` becomes `_`, so two different names
/// could theoretically collide on their sanitized form — acceptable here
/// because the cache is keyed on `(registry, sanitized name, version)`
/// together, not identity-critical (a collision just means one entry's
/// cache gets reused/overwritten for another, which at worst forces a
/// re-fetch, never a wrong *scoring* result, since the artifact id used
/// everywhere else in this codebase is `Artifact::compute_id`, computed
/// from the real unsanitized name).
fn sanitize_path_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The directory this `(registry, name, version)` extracts into. Does not
/// create it — callers create it as part of extraction, and check
/// `is_complete` first to decide whether to skip fetching entirely.
pub fn package_dir(cache_dir: &Path, registry: &str, name: &str, version: &str) -> PathBuf {
    cache_dir
        .join(sanitize_path_segment(registry))
        .join(sanitize_path_segment(name))
        .join(sanitize_path_segment(version))
}

/// A marker file written only after a full, successful fetch+extract —
/// its presence is what `is_complete` checks, so a prior run that crashed
/// or was killed mid-extraction (partial content on disk) is correctly
/// treated as incomplete and re-fetched, never trusted as-is.
fn complete_marker(package_dir: &Path) -> PathBuf {
    package_dir.join(".talyx-fetch-complete")
}

pub fn is_complete(package_dir: &Path) -> bool {
    complete_marker(package_dir).is_file()
}

pub fn mark_complete(package_dir: &Path) -> std::io::Result<()> {
    std::fs::write(complete_marker(package_dir), b"")
}

/// The subdirectory extracted archive content lands in, inside a package's
/// cache directory — kept separate from the raw archive file
/// (`write_archive`'s target) and the completion marker, so `scan_root`
/// can point at exactly the extracted tree with nothing else mixed in.
pub fn content_dir(package_dir: &Path) -> PathBuf {
    package_dir.join("content")
}
