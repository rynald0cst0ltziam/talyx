//! npm registry client — verified live against the real registry
//! (`https://registry.npmjs.org/@modelcontextprotocol/server-filesystem/
//! latest`) before writing this, not built from memory of the API shape.
//! `GET /<package>/<version-or-tag>` returns that one version's metadata
//! directly (not the full multi-version package document), including
//! `version`, `dist.tarball`, `dist.shasum` (sha1, always present), and
//! `dist.integrity` (an SRI string, `sha512-<base64>`, present on modern
//! packages) — this module prefers `integrity` when present since sha512
//! is the stronger check, falling back to `shasum` only when it's absent.

use crate::{Agent, RegistryError};
use base64::Engine;
use serde::Deserialize;
use sha2::Digest;

#[derive(Debug, Deserialize)]
struct NpmVersionDoc {
    version: String,
    dist: NpmDist,
}

#[derive(Debug, Deserialize)]
struct NpmDist {
    tarball: String,
    shasum: Option<String>,
    integrity: Option<String>,
}

pub(crate) struct FetchedTarball {
    pub resolved_version: String,
    pub bytes: Vec<u8>,
}

/// `version_spec` is `None` for "whatever `latest` currently is" or
/// `Some("1.2.3")` for a pinned version parsed from e.g. `pkg@1.2.3` —
/// npm's registry accepts a dist-tag (`latest`) or an exact version in
/// the same URL position, so this doesn't need two different endpoints.
pub(crate) fn fetch(
    agent: &Agent,
    package_name: &str,
    version_spec: Option<&str>,
) -> Result<FetchedTarball, RegistryError> {
    let tag_or_version = version_spec.unwrap_or("latest");
    // Scoped package names (`@scope/name`) contain a `/`, which is a
    // legitimate path separator here, not something to percent-encode --
    // confirmed live against the real registry before relying on this.
    let meta_url = format!("https://registry.npmjs.org/{package_name}/{tag_or_version}");

    let mut response = agent
        .get(&meta_url)
        .call()
        .map_err(|e| classify_request_error(e, package_name, "npm"))?;
    let doc: NpmVersionDoc = response
        .body_mut()
        .read_json()
        .map_err(|e| RegistryError::Network(format!("malformed npm registry response for {package_name}: {e}")))?;

    let tarball_bytes = crate::http::download(agent, &doc.dist.tarball)?;

    verify_npm_integrity(&tarball_bytes, &doc.dist)?;

    Ok(FetchedTarball {
        resolved_version: doc.version,
        bytes: tarball_bytes,
    })
}

fn verify_npm_integrity(bytes: &[u8], dist: &NpmDist) -> Result<(), RegistryError> {
    if let Some(integrity) = &dist.integrity {
        let Some((algo, b64_digest)) = integrity.split_once('-') else {
            return Err(RegistryError::ChecksumMismatch {
                expected: integrity.clone(),
                actual: "(malformed integrity string -- no '-' separator)".to_string(),
            });
        };
        let expected = base64::engine::general_purpose::STANDARD
            .decode(b64_digest)
            .map_err(|e| RegistryError::ChecksumMismatch {
                expected: integrity.clone(),
                actual: format!("(integrity base64 didn't decode: {e})"),
            })?;
        let actual = match algo {
            "sha512" => sha2::Sha512::digest(bytes).to_vec(),
            "sha256" => sha2::Sha256::digest(bytes).to_vec(),
            // An algorithm this module doesn't implement is not a reason
            // to skip verification silently -- fall through to shasum
            // instead of pretending integrity passed.
            _ => return verify_npm_shasum(bytes, dist),
        };
        if actual != expected {
            return Err(RegistryError::ChecksumMismatch {
                expected: integrity.clone(),
                actual: format!("{algo}-{}", base64::engine::general_purpose::STANDARD.encode(&actual)),
            });
        }
        return Ok(());
    }
    verify_npm_shasum(bytes, dist)
}

fn verify_npm_shasum(bytes: &[u8], dist: &NpmDist) -> Result<(), RegistryError> {
    let Some(expected_hex) = &dist.shasum else {
        // Neither integrity nor shasum present -- every real npm registry
        // response has at least shasum, so treat this as a malformed
        // response rather than silently accepting unverified content.
        return Err(RegistryError::ChecksumMismatch {
            expected: "(none provided by registry)".to_string(),
            actual: "(cannot verify -- refusing to extract unverified content)".to_string(),
        });
    };
    let actual = sha1::Sha1::digest(bytes);
    let actual_hex = hex_encode(&actual);
    if &actual_hex != expected_hex {
        return Err(RegistryError::ChecksumMismatch {
            expected: expected_hex.clone(),
            actual: actual_hex,
        });
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn classify_request_error(e: ureq::Error, name: &str, registry: &str) -> RegistryError {
    if let ureq::Error::StatusCode(404) = e {
        RegistryError::NotFound {
            name: name.to_string(),
            registry: registry.to_string(),
        }
    } else {
        RegistryError::Network(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dist(shasum: Option<&str>, integrity: Option<&str>) -> NpmDist {
        NpmDist {
            tarball: "https://example.invalid/pkg.tgz".to_string(),
            shasum: shasum.map(str::to_string),
            integrity: integrity.map(str::to_string),
        }
    }

    #[test]
    fn accepts_content_matching_its_declared_shasum() {
        let bytes = b"hello world";
        let sha1_hex = hex_encode(&sha1::Sha1::digest(bytes));
        let d = dist(Some(&sha1_hex), None);
        assert!(verify_npm_integrity(bytes, &d).is_ok());
    }

    #[test]
    fn rejects_content_not_matching_its_declared_shasum() {
        let bytes = b"hello world";
        let d = dist(Some("0000000000000000000000000000000000000a"), None);
        let err = verify_npm_integrity(bytes, &d).unwrap_err();
        assert!(matches!(err, RegistryError::ChecksumMismatch { .. }));
    }

    #[test]
    fn accepts_content_matching_its_declared_sha512_integrity() {
        let bytes = b"hello world";
        let digest = sha2::Sha512::digest(bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        let integrity = format!("sha512-{b64}");
        let d = dist(None, Some(&integrity));
        assert!(verify_npm_integrity(bytes, &d).is_ok());
    }

    #[test]
    fn rejects_content_not_matching_its_declared_sha512_integrity() {
        let bytes = b"hello world";
        let wrong_digest = sha2::Sha512::digest(b"something else entirely");
        let b64 = base64::engine::general_purpose::STANDARD.encode(wrong_digest);
        let integrity = format!("sha512-{b64}");
        let d = dist(None, Some(&integrity));
        let err = verify_npm_integrity(bytes, &d).unwrap_err();
        assert!(matches!(err, RegistryError::ChecksumMismatch { .. }));
    }

    #[test]
    fn refuses_to_extract_when_the_registry_supplied_no_checksum_at_all() {
        // A malformed/unusual registry response, not something this
        // module should ever silently treat as "verification passed."
        let bytes = b"hello world";
        let d = dist(None, None);
        let err = verify_npm_integrity(bytes, &d).unwrap_err();
        assert!(matches!(err, RegistryError::ChecksumMismatch { .. }));
    }

    #[test]
    fn prefers_integrity_over_shasum_when_both_are_present_and_integrity_wins_a_conflict() {
        // If integrity and shasum ever disagreed (shouldn't happen with a
        // real registry, but this locks in which one wins rather than
        // leaving it to whichever branch happens to run first): a valid
        // integrity hash is trusted even if a bogus shasum is also
        // present, since sha512 is the stronger, preferred check.
        let bytes = b"hello world";
        let digest = sha2::Sha512::digest(bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        let integrity = format!("sha512-{b64}");
        let d = dist(Some("0000000000000000000000000000000000000a"), Some(&integrity));
        assert!(verify_npm_integrity(bytes, &d).is_ok());
    }
}
