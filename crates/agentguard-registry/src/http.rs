//! Shared HTTP plumbing — one configured `ureq::Agent` (timeouts set, see
//! `new_agent`) used by both the npm and PyPI clients.

use crate::RegistryError;
use std::time::Duration;

/// A tarball/wheel this large would be unusual for an MCP-server-shaped
/// package (these are typically tens of KB to a few MB) — set generously
/// above that so a legitimately large package doesn't fail, while still
/// bounding memory use against a compromised or misbehaving registry
/// response. ureq's own default (10MB, see `Body::read_to_vec`'s doc
/// comment) was judged too tight for this specifically; this raises it
/// rather than removing the bound entirely.
const MAX_DOWNLOAD_BYTES: u64 = 200 * 1024 * 1024;

/// Every request (metadata lookup and archive download) gets this same
/// global timeout — long enough for a slow connection, short enough that
/// a hung registry can't block `agentguard scan`/`init` indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn new_agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .user_agent(concat!("agentguard/", env!("CARGO_PKG_VERSION")))
        .build();
    ureq::Agent::new_with_config(config)
}

pub(crate) fn download(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, RegistryError> {
    let mut response = agent
        .get(url)
        .call()
        .map_err(|e| RegistryError::Network(format!("downloading {url}: {e}")))?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD_BYTES)
        .read_to_vec()
        .map_err(|e| RegistryError::Network(format!("reading response body from {url}: {e}")))
}
