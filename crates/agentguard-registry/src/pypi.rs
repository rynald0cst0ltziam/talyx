//! PyPI JSON API client — verified live against the real API
//! (`https://pypi.org/pypi/requests/json` and `.../requests/2.31.0/json`)
//! before writing this. `GET /pypi/<package>/json` resolves the current
//! release; `GET /pypi/<package>/<version>/json` resolves a pinned one —
//! both return `info.version` and a `urls` array of that release's files,
//! each with `packagetype` (`"sdist"` or `"bdist_wheel"`), `filename`,
//! `url`, and `digests.sha256`.

use crate::{Agent, RegistryError};
use serde::Deserialize;
use sha2::Digest;

#[derive(Debug, Deserialize)]
struct PypiReleaseDoc {
    info: PypiInfo,
    urls: Vec<PypiFile>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    version: String,
}

#[derive(Debug, Deserialize)]
struct PypiFile {
    packagetype: String,
    url: String,
    digests: PypiDigests,
}

#[derive(Debug, Deserialize)]
struct PypiDigests {
    sha256: Option<String>,
}

pub(crate) enum FetchedArchive {
    /// A source distribution (`.tar.gz`) — preferred when available since
    /// it's the actual source, not a pre-built artifact.
    Sdist { resolved_version: String, bytes: Vec<u8> },
    /// A wheel (`.whl`, a zip) — used only when no sdist is published for
    /// this release (real and common: many packages ship wheel-only).
    Wheel { resolved_version: String, bytes: Vec<u8> },
}

pub(crate) fn fetch(
    agent: &Agent,
    package_name: &str,
    version_spec: Option<&str>,
) -> Result<FetchedArchive, RegistryError> {
    let meta_url = match version_spec {
        Some(v) => format!("https://pypi.org/pypi/{package_name}/{v}/json"),
        None => format!("https://pypi.org/pypi/{package_name}/json"),
    };

    let mut response = agent
        .get(&meta_url)
        .call()
        .map_err(|e| classify_request_error(e, package_name))?;
    let doc: PypiReleaseDoc = response.body_mut().read_json().map_err(|e| {
        RegistryError::Network(format!("malformed PyPI response for {package_name}: {e}"))
    })?;

    let sdist = doc.urls.iter().find(|f| f.packagetype == "sdist");
    let is_sdist = sdist.is_some();
    let wheel = doc.urls.iter().find(|f| f.packagetype == "bdist_wheel");
    let Some(file) = sdist.or(wheel) else {
        return Err(RegistryError::NotFound {
            name: package_name.to_string(),
            registry: "pypi".to_string(),
        });
    };

    let bytes = crate::http::download(agent, &file.url)?;
    verify_pypi_sha256(&bytes, file)?;

    Ok(if is_sdist {
        FetchedArchive::Sdist { resolved_version: doc.info.version, bytes }
    } else {
        FetchedArchive::Wheel { resolved_version: doc.info.version, bytes }
    })
}

fn verify_pypi_sha256(bytes: &[u8], file: &PypiFile) -> Result<(), RegistryError> {
    let Some(expected) = &file.digests.sha256 else {
        return Err(RegistryError::ChecksumMismatch {
            expected: "(none provided by PyPI)".to_string(),
            actual: "(cannot verify -- refusing to extract unverified content)".to_string(),
        });
    };
    let actual = sha2::Sha256::digest(bytes);
    let actual_hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();
    if &actual_hex != expected {
        return Err(RegistryError::ChecksumMismatch {
            expected: expected.clone(),
            actual: actual_hex,
        });
    }
    Ok(())
}

fn classify_request_error(e: ureq::Error, name: &str) -> RegistryError {
    if let ureq::Error::StatusCode(404) = e {
        RegistryError::NotFound {
            name: name.to_string(),
            registry: "pypi".to_string(),
        }
    } else {
        RegistryError::Network(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(packagetype: &str, sha256: Option<&str>) -> PypiFile {
        PypiFile {
            packagetype: packagetype.to_string(),
            url: "https://example.invalid/pkg.tar.gz".to_string(),
            digests: PypiDigests { sha256: sha256.map(str::to_string) },
        }
    }

    #[test]
    fn accepts_content_matching_its_declared_sha256() {
        let bytes = b"hello world";
        let hex: String = sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
        let f = file("sdist", Some(&hex));
        assert!(verify_pypi_sha256(bytes, &f).is_ok());
    }

    #[test]
    fn rejects_content_not_matching_its_declared_sha256() {
        let bytes = b"hello world";
        let f = file("sdist", Some("0".repeat(64).as_str()));
        let err = verify_pypi_sha256(bytes, &f).unwrap_err();
        assert!(matches!(err, RegistryError::ChecksumMismatch { .. }));
    }

    #[test]
    fn refuses_to_extract_when_pypi_supplied_no_sha256() {
        let bytes = b"hello world";
        let f = file("sdist", None);
        let err = verify_pypi_sha256(bytes, &f).unwrap_err();
        assert!(matches!(err, RegistryError::ChecksumMismatch { .. }));
    }
}
