//! License activation + verification for the paid commands.
//!
//! Talyx is a paid tool. `scan` and `status` run unlicensed so a
//! security team can evaluate it; `init` (which activates enforcement)
//! requires a valid license.
//!
//! Deliberately NOT gated: `talyx-shim` itself. The shim is invoked
//! by the agent, not the user — blocking it when a license lapses would
//! break a running agent mid-session, which is a worse outcome than a
//! lapsed license. A lapsed license means you can't re-run `init` or add
//! new servers, not that your machine stops working.
//!
//! ## How verification works
//!
//! Activation calls Lemon Squeezy's public License API
//! (<https://docs.lemonsqueezy.com/api/license-api>) once to bind the key
//! to this machine, then caches the result in `~/.talyx/license.json`.
//! After that:
//!   - within 7 days of the last check → trust the cache, no network call
//!   - older → try a live `validate`; on success refresh the cache
//!   - live check fails (offline) → keep working for 30 days total, then
//!     ask the user to reconnect. No hard remote kill switch.
//!
//! CI: set `TALYX_LICENSE_KEY` in the job env. That path does a
//! validate-only check (no activation slot consumed per run).
//!
//! Local development against a debug build: `TALYX_DEV=1` skips the
//! gate. Release binaries — what customers install — ignore that flag
//! entirely, so it can't be used to bypass licensing in the wild.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const API_BASE: &str = "https://api.lemonsqueezy.com/v1/licenses";
const TRUST_CACHE_SECS: u64 = 7 * 24 * 60 * 60;
const OFFLINE_GRACE_SECS: u64 = 30 * 24 * 60 * 60;
const REQUEST_TIMEOUT_SECS: u64 = 20;

// The Lemon Squeezy store/product/variant a license key must belong to.
// Lemon Squeezy's License API is public and unauthenticated: `validate`
// and `activate` will happily accept a key from ANY product in ANY store
// on Lemon Squeezy, not just this one. Their own guide says exactly this:
// "You should verify that the store_id, product_id and/or variant_id from
// this response match the IDs of your Lemon Squeezy product. If you don't
// do this, someone using a license key from another Lemon Squeezy product
// could use it to get access to your product." Without this check, any
// $1 purchase anywhere on Lemon Squeezy would unlock `talyx init`.
// https://docs.lemonsqueezy.com/guides/tutorials/license-keys
const ALLOWED_STORE_ID: u64 = 463533;
const ALLOWED_PRODUCT_ID: u64 = 1364213;
const ALLOWED_VARIANT_ID: u64 = 2130722;

/// Does an activate/validate response's `meta` block identify a key
/// bought for exactly this product? Checked on every response that
/// carries a `meta` object — a missing/mismatched field fails closed
/// (`unwrap_or_default()` on a `u64` compare against a real id never
/// accidentally matches).
fn identity_matches(body: &Value) -> bool {
    field_u64(body, &["meta", "store_id"]) == Some(ALLOWED_STORE_ID)
        && field_u64(body, &["meta", "product_id"]) == Some(ALLOWED_PRODUCT_ID)
        && field_u64(body, &["meta", "variant_id"]) == Some(ALLOWED_VARIANT_ID)
}

/// Persisted at `~/.talyx/license.json` after a successful activation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    pub key: String,
    pub instance_id: String,
    pub instance_name: String,
    /// Lemon Squeezy `license_key.status`: `active`, `inactive`, `expired`,
    /// `disabled`.
    pub status: String,
    #[serde(default)]
    pub activation_limit: Option<u64>,
    #[serde(default)]
    pub activation_usage: Option<u64>,
    /// Raw `expires_at` string from Lemon Squeezy (null for perpetual /
    /// non-expiring keys). Stored verbatim for display; not parsed.
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub customer_email: Option<String>,
    /// Unix seconds of the last successful activate/validate. Drives the
    /// trust-cache window and the offline grace period.
    pub last_verified_epoch: u64,
}

#[derive(Debug)]
pub enum LicenseError {
    /// No license on this machine and none in the environment.
    NotActivated,
    /// Lemon Squeezy said the key is not usable (expired / disabled / not
    /// found / activation limit reached). Carries the server's message.
    Rejected(String),
    /// Couldn't reach Lemon Squeezy and there's no cache within the grace
    /// window to fall back on.
    Unreachable(String),
    /// Local file / IO problem.
    Io(String),
}

impl std::fmt::Display for LicenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseError::NotActivated => write!(
                f,
                "no active license on this machine.\n  Buy one at https://gettalyx.dev/pricing, then run:\n    talyx activate <YOUR-KEY>\n  In CI, set TALYX_LICENSE_KEY instead."
            ),
            LicenseError::Rejected(m) => write!(f, "license rejected by Lemon Squeezy: {m}"),
            LicenseError::Unreachable(m) => write!(
                f,
                "couldn't verify your license and the offline grace period has expired: {m}\n  Reconnect to the internet and run `talyx license status` once."
            ),
            LicenseError::Io(m) => write!(f, "{m}"),
        }
    }
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `~/.talyx/license.json`, or `$TALYX_LICENSE_FILE` if set
/// (tests, and unusual home-directory layouts).
pub fn license_path() -> Result<PathBuf, LicenseError> {
    if let Ok(p) = std::env::var("TALYX_LICENSE_FILE") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| LicenseError::Io("can't locate your home directory".into()))?;
    Ok(home.join(".talyx").join("license.json"))
}

fn read_license() -> Option<LicenseFile> {
    let path = license_path().ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_license(lic: &LicenseFile) -> Result<(), LicenseError> {
    let path = license_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| LicenseError::Io(format!("creating {}: {e}", parent.display())))?;
    }
    let json = serde_json::to_string_pretty(lic)
        .map_err(|e| LicenseError::Io(format!("serializing license: {e}")))?;
    std::fs::write(&path, json)
        .map_err(|e| LicenseError::Io(format!("writing {}: {e}", path.display())))?;
    Ok(())
}

fn default_instance_name() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string());
    format!("{host} ({})", std::env::consts::OS)
}

// ── HTTP ──────────────────────────────────────────────────────────────

fn agent() -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS)))
        .user_agent(concat!("talyx/", env!("CARGO_PKG_VERSION")))
        .build();
    ureq::Agent::new_with_config(config)
}

/// POST `form` to `{API_BASE}/{endpoint}` and return the parsed JSON body.
/// Lemon Squeezy returns HTTP 400 with a JSON `{ "error": "..." }` body
/// for a bad/expired/exhausted key — that's a `Rejected`, not a transport
/// failure, so 4xx bodies are still read and surfaced.
fn post(endpoint: &str, form: &[(&str, &str)]) -> Result<Value, LicenseError> {
    let url = format!("{API_BASE}/{endpoint}");
    let result = agent().post(&url).header("Accept", "application/json").send_form(form.to_vec());

    let mut response = match result {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(code)) if code == 400 || code == 404 || code == 422 => {
            return Err(LicenseError::Rejected(format!(
                "the license key was not accepted (HTTP {code})"
            )));
        }
        Err(e) => return Err(LicenseError::Unreachable(format!("{url}: {e}"))),
    };

    response
        .body_mut()
        .read_json::<Value>()
        .map_err(|e| LicenseError::Unreachable(format!("malformed response from {url}: {e}")))
}

fn field_str(v: &Value, path: &[&str]) -> Option<String> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_str().map(String::from)
}

fn field_u64(v: &Value, path: &[&str]) -> Option<u64> {
    let mut cur = v;
    for k in path {
        cur = cur.get(k)?;
    }
    cur.as_u64()
}

fn cache_from_response(key: &str, body: &Value, prev_instance: Option<&LicenseFile>) -> LicenseFile {
    let instance_id = field_str(body, &["instance", "id"])
        .or_else(|| prev_instance.map(|p| p.instance_id.clone()))
        .unwrap_or_default();
    let instance_name = field_str(body, &["instance", "name"])
        .or_else(|| prev_instance.map(|p| p.instance_name.clone()))
        .unwrap_or_else(default_instance_name);
    LicenseFile {
        key: key.to_string(),
        instance_id,
        instance_name,
        status: field_str(body, &["license_key", "status"]).unwrap_or_else(|| "active".into()),
        activation_limit: field_u64(body, &["license_key", "activation_limit"]),
        activation_usage: field_u64(body, &["license_key", "activation_usage"]),
        expires_at: field_str(body, &["license_key", "expires_at"]),
        customer_email: field_str(body, &["meta", "customer_email"]),
        last_verified_epoch: now_epoch(),
    }
}

/// Lemon Squeezy `license_key.status` → usable right now?
fn status_ok(status: &str) -> bool {
    // `inactive` is the state of a freshly-issued key that has never been
    // activated; after activate it becomes `active`. Treat both as OK so a
    // validate call right after activate doesn't spuriously fail.
    matches!(status, "active" | "inactive")
}

// ── public commands ───────────────────────────────────────────────────

/// `talyx activate <key>`
pub fn run_activate(key: &str) -> i32 {
    let key = key.trim();
    if key.is_empty() {
        eprintln!("talyx: activate needs a license key");
        return 2;
    }

    if let Some(existing) = read_license() {
        if existing.key == key {
            println!("This machine is already activated with that key.");
            return 0;
        }
        let old_prefix = existing.key.chars().take(8).collect::<String>();
        println!(
            "Replacing the license already on this machine ({old_prefix}…). The old one keeps its activation slot — run `talyx license deactivate` first if you meant to free it."
        );
    }

    // Pre-flight check: `validate` with no `instance_id` checks the key's
    // identity WITHOUT creating an instance / consuming an activation
    // slot (Lemon Squeezy's own docs: "If no instance_id is provided...
    // instance will be null" — no activation happens). Reject a
    // wrong-product key here so it never touches the real `activate`
    // call and never spends a slot the customer would then have to
    // manually free.
    match post("validate", &[("license_key", key)]) {
        Ok(body) => {
            let valid = body.get("valid").and_then(Value::as_bool).unwrap_or(false);
            if valid && !identity_matches(&body) {
                eprintln!("talyx: this license key is valid, but it isn't for Talyx.");
                eprintln!("  Buy one at https://gettalyx.dev/pricing.");
                return 1;
            }
            // An invalid/unrecognized key at this stage is left to the
            // real `activate` call below, which gives the more specific
            // Lemon Squeezy error message for that case.
        }
        Err(LicenseError::Unreachable(m)) => {
            eprintln!("talyx: {m}");
            return 1;
        }
        Err(_) => {} // fall through to activate, which will surface the real error
    }

    let instance_name = default_instance_name();
    println!("Activating with Lemon Squeezy as \"{instance_name}\"…");

    let body = match post(
        "activate",
        &[("license_key", key), ("instance_name", &instance_name)],
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("talyx: {e}");
            return 1;
        }
    };

    let activated = body.get("activated").and_then(Value::as_bool).unwrap_or(false);
    if !activated {
        let msg = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Lemon Squeezy did not activate the key");
        eprintln!("talyx: {msg}");
        return 1;
    }

    // Belt-and-suspenders: re-check identity on the activate response
    // itself. The slot is already spent at this point (there's no way to
    // avoid that for a key that races past the validate pre-check with
    // a state change in between), but this still refuses to cache or
    // use a foreign identity — see `require_licensed`'s decisive checks.
    if !identity_matches(&body) {
        eprintln!("talyx: this license key isn't for Talyx — activation refused.");
        eprintln!("  Run `talyx license deactivate` if you want to free the slot this just used.");
        return 1;
    }

    let lic = cache_from_response(key, &body, None);
    if let Err(e) = write_license(&lic) {
        eprintln!("talyx: activated, but couldn't save the license file: {e}");
        return 1;
    }

    println!("Activated.");
    print_summary(&lic, None);
    println!("\nRun  talyx init --project ~  to enable enforcement.");
    0
}

/// `talyx license deactivate`
pub fn run_deactivate() -> i32 {
    let Some(lic) = read_license() else {
        eprintln!("talyx: no license on this machine to deactivate");
        return 1;
    };

    match post(
        "deactivate",
        &[("license_key", &lic.key), ("instance_id", &lic.instance_id)],
    ) {
        Ok(body) => {
            let ok = body.get("deactivated").and_then(Value::as_bool).unwrap_or(false);
            if !ok {
                let msg = body.get("error").and_then(Value::as_str).unwrap_or("unknown error");
                eprintln!("talyx: Lemon Squeezy did not deactivate this machine: {msg}");
                eprintln!("  The local license file is left in place. Retry when online.");
                return 1;
            }
        }
        Err(LicenseError::Unreachable(m)) => {
            eprintln!("talyx: couldn't reach Lemon Squeezy to release the activation slot: {m}");
            eprintln!("  The local license file is left in place. Retry when online.");
            return 1;
        }
        Err(e) => {
            eprintln!("talyx: {e}");
            return 1;
        }
    }

    if let Ok(path) = license_path() {
        let _ = std::fs::remove_file(path);
    }
    println!("Deactivated this machine and freed its activation slot.");
    0
}

/// `talyx license status`
pub fn run_status() -> i32 {
    let Some(mut lic) = read_license() else {
        println!("Not activated on this machine.");
        println!("  Buy: https://gettalyx.dev/pricing");
        println!("  Then: talyx activate <YOUR-KEY>");
        return 0;
    };

    // Best-effort live refresh; never fatal for a status read.
    match post(
        "validate",
        &[("license_key", &lic.key), ("instance_id", &lic.instance_id)],
    ) {
        Ok(body) => {
            let valid = body.get("valid").and_then(Value::as_bool).unwrap_or(false);
            let status = field_str(&body, &["license_key", "status"]).unwrap_or_default();
            if valid && status_ok(&status) && !identity_matches(&body) {
                print_summary(&lic, Some("this key isn't for Talyx — rejecting it"));
                return 1;
            } else if valid && status_ok(&status) {
                lic = cache_from_response(&lic.key, &body, Some(&lic));
                let _ = write_license(&lic);
                print_summary(&lic, Some("verified just now"));
            } else {
                let msg = body.get("error").and_then(Value::as_str).unwrap_or("not valid");
                lic.status = if status.is_empty() { lic.status.clone() } else { status };
                print_summary(&lic, Some(&format!("Lemon Squeezy says: {msg}")));
                return 1;
            }
        }
        Err(LicenseError::Unreachable(_)) => {
            let age = now_epoch().saturating_sub(lic.last_verified_epoch);
            let remaining = OFFLINE_GRACE_SECS.saturating_sub(age) / 86_400;
            print_summary(
                &lic,
                Some(&format!("offline — {remaining} day(s) of grace left before re-verification is required")),
            );
        }
        Err(e) => {
            print_summary(&lic, Some(&format!("{e}")));
            return 1;
        }
    }
    0
}

fn print_summary(lic: &LicenseFile, note: Option<&str>) {
    let n = lic.key.chars().count();
    let key_tail: String = lic.key.chars().skip(n.saturating_sub(4)).collect();
    println!("  License   ****-{key_tail}   status: {}", lic.status);
    if let (Some(u), Some(l)) = (lic.activation_usage, lic.activation_limit) {
        println!("  Machines  {u} of {l} activated");
    }
    println!("  Instance  {}", lic.instance_name);
    match &lic.expires_at {
        Some(e) => println!("  Expires   {e}"),
        None => println!("  Expires   never (lifetime license)"),
    }
    if let Some(email) = &lic.customer_email {
        println!("  Licensed  {email}");
    }
    if let Some(n) = note {
        println!("  Note      {n}");
    }
}

// ── the gate ──────────────────────────────────────────────────────────

/// Called by `main` before a paid command runs. Returns `Ok` to proceed.
/// Prints nothing on success unless a warning is warranted.
pub fn require_licensed(feature: &str) -> Result<(), LicenseError> {
    // Dev bypass — debug builds only. `cfg!(debug_assertions)` is false in
    // the release binaries customers install, so this branch compiles to
    // `false && ...` there and cannot be used to bypass licensing.
    if cfg!(debug_assertions) && std::env::var("TALYX_DEV").as_deref() == Ok("1") {
        eprintln!("talyx: TALYX_DEV=1 — skipping license check (debug build only)");
        return Ok(());
    }

    // CI path: a key in the environment → validate-only, no activation slot.
    if let Ok(env_key) = std::env::var("TALYX_LICENSE_KEY") {
        let env_key = env_key.trim();
        if !env_key.is_empty() {
            return require_via_env_key(env_key);
        }
    }

    let Some(lic) = read_license() else {
        return Err(LicenseError::NotActivated);
    };

    let age = now_epoch().saturating_sub(lic.last_verified_epoch);

    // Fresh enough — trust the cache, no network call.
    if age <= TRUST_CACHE_SECS {
        return gate_on_cached_status(&lic);
    }

    // Stale — try a live validate.
    match post(
        "validate",
        &[("license_key", &lic.key), ("instance_id", &lic.instance_id)],
    ) {
        Ok(body) => {
            let valid = body.get("valid").and_then(Value::as_bool).unwrap_or(false);
            let status = field_str(&body, &["license_key", "status"]).unwrap_or_default();
            if valid && status_ok(&status) && !identity_matches(&body) {
                Err(LicenseError::Rejected("this license key isn't for Talyx".to_string()))
            } else if valid && status_ok(&status) {
                let refreshed = cache_from_response(&lic.key, &body, Some(&lic));
                let _ = write_license(&refreshed);
                Ok(())
            } else {
                let msg = body
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("license is no longer valid")
                    .to_string();
                Err(LicenseError::Rejected(msg))
            }
        }
        Err(LicenseError::Unreachable(m)) => {
            if age <= OFFLINE_GRACE_SECS {
                let remaining = (OFFLINE_GRACE_SECS - age) / 86_400;
                eprintln!(
                    "talyx: couldn't verify your license (offline). {remaining} day(s) of grace left; continuing with `{feature}`."
                );
                Ok(())
            } else {
                Err(LicenseError::Unreachable(m))
            }
        }
        Err(e) => Err(e),
    }
}

fn gate_on_cached_status(lic: &LicenseFile) -> Result<(), LicenseError> {
    if status_ok(&lic.status) {
        Ok(())
    } else {
        Err(LicenseError::Rejected(format!(
            "cached license status is `{}` — run `talyx license status` while online",
            lic.status
        )))
    }
}

fn require_via_env_key(key: &str) -> Result<(), LicenseError> {
    match post("validate", &[("license_key", key)]) {
        Ok(body) => {
            let valid = body.get("valid").and_then(Value::as_bool).unwrap_or(false);
            let status = field_str(&body, &["license_key", "status"]).unwrap_or_default();
            if valid && status_ok(&status) && !identity_matches(&body) {
                Err(LicenseError::Rejected("TALYX_LICENSE_KEY isn't a Talyx license".to_string()))
            } else if valid && status_ok(&status) {
                Ok(())
            } else {
                let msg = body
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("TALYX_LICENSE_KEY is not valid")
                    .to_string();
                Err(LicenseError::Rejected(msg))
            }
        }
        Err(e) => Err(e),
    }
}

/// Convenience for `main`: run the gate, print the error, return an exit
/// code (0 = proceed, non-zero = stop).
pub fn gate(feature: &str) -> i32 {
    match require_licensed(feature) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(io::stderr(), "talyx: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // These tests mutate process-global env vars (TALYX_LICENSE_FILE
    // etc.), so they must not run concurrently with each other.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestEnv {
        _guard: MutexGuard<'static, ()>,
    }
    impl Drop for TestEnv {
        fn drop(&mut self) {
            std::env::remove_var("TALYX_LICENSE_FILE");
            std::env::remove_var("TALYX_LICENSE_KEY");
            std::env::remove_var("TALYX_DEV");
        }
    }

    fn with_temp_license_file(name: &str) -> (PathBuf, TestEnv) {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Start from a known-clean env every time.
        std::env::remove_var("TALYX_LICENSE_KEY");
        std::env::remove_var("TALYX_DEV");
        let dir = std::env::temp_dir().join(format!(
            "talyx-license-test-{}-{}",
            std::process::id(),
            name
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("license.json");
        let _ = std::fs::remove_file(&path);
        std::env::set_var("TALYX_LICENSE_FILE", &path);
        (path, TestEnv { _guard: guard })
    }

    fn sample(status: &str, verified_epoch: u64) -> LicenseFile {
        LicenseFile {
            key: "TLX-TEST-KEY-1234".into(),
            instance_id: "inst-1".into(),
            instance_name: "test-host".into(),
            status: status.into(),
            activation_limit: Some(3),
            activation_usage: Some(1),
            expires_at: None,
            customer_email: Some("buyer@example.com".into()),
            last_verified_epoch: verified_epoch,
        }
    }

    #[test]
    fn round_trips_the_license_file() {
        let (_path, _g) = with_temp_license_file("roundtrip");
        let lic = sample("active", now_epoch());
        write_license(&lic).unwrap();
        let back = read_license().expect("should read back");
        assert_eq!(back.key, lic.key);
        assert_eq!(back.instance_id, "inst-1");
        assert_eq!(back.status, "active");
    }

    #[test]
    fn missing_file_is_not_activated() {
        let (_path, _g) = with_temp_license_file("missing");
        assert!(matches!(require_licensed("init"), Err(LicenseError::NotActivated)));
    }

    #[test]
    fn fresh_active_cache_passes_without_network() {
        let (_path, _g) = with_temp_license_file("freshcache");
        write_license(&sample("active", now_epoch())).unwrap();
        // TRUST_CACHE_SECS window → no HTTP call, must return Ok.
        assert!(require_licensed("init").is_ok());
    }

    #[test]
    fn fresh_disabled_cache_is_rejected_without_network() {
        let (_path, _g) = with_temp_license_file("disabledcache");
        write_license(&sample("disabled", now_epoch())).unwrap();
        assert!(matches!(require_licensed("init"), Err(LicenseError::Rejected(_))));
    }

    #[test]
    fn status_ok_matches_lemonsqueezy_states() {
        assert!(status_ok("active"));
        assert!(status_ok("inactive"));
        assert!(!status_ok("expired"));
        assert!(!status_ok("disabled"));
    }

    #[test]
    fn parses_a_real_shaped_activate_response() {
        let body = serde_json::json!({
            "activated": true,
            "error": null,
            "license_key": {
                "id": 1, "status": "active", "key": "TLX-XXXX",
                "activation_limit": 3, "activation_usage": 1,
                "created_at": "2026-01-01T00:00:00.000000Z", "expires_at": null
            },
            "instance": { "id": "abc-123", "name": "laptop", "created_at": "2026-01-01T00:00:00.000000Z" },
            "meta": { "customer_email": "buyer@example.com", "variant_name": "Developer" }
        });
        let lic = cache_from_response("TLX-XXXX", &body, None);
        assert_eq!(lic.instance_id, "abc-123");
        assert_eq!(lic.instance_name, "laptop");
        assert_eq!(lic.status, "active");
        assert_eq!(lic.activation_limit, Some(3));
        assert_eq!(lic.customer_email.as_deref(), Some("buyer@example.com"));
    }

    #[test]
    fn identity_matches_the_pinned_talyx_ids() {
        let body = serde_json::json!({
            "valid": true,
            "meta": {
                "store_id": 463533, "product_id": 1364213, "variant_id": 2130722,
                "customer_email": "buyer@example.com"
            }
        });
        assert!(identity_matches(&body));
    }

    #[test]
    fn identity_rejects_a_key_from_a_different_lemon_squeezy_product() {
        // The exact scenario the License API's public/unauthenticated
        // design allows: a real, valid, active key -- just not for Talyx.
        let body = serde_json::json!({
            "valid": true,
            "license_key": { "status": "active" },
            "meta": {
                "store_id": 999999, "product_id": 1364213, "variant_id": 2130722
            }
        });
        assert!(!identity_matches(&body));
    }

    #[test]
    fn identity_rejects_a_response_with_no_meta_at_all() {
        let body = serde_json::json!({ "valid": true });
        assert!(!identity_matches(&body));
    }

    #[test]
    fn dev_bypass_is_debug_only() {
        // In `cargo test` (debug), TALYX_DEV=1 short-circuits.
        // This asserts the wiring, not a production guarantee — release
        // builds compile the `cfg!(debug_assertions)` guard to false.
        let (_path, _g) = with_temp_license_file("devbypass");
        std::env::set_var("TALYX_DEV", "1");
        let r = require_licensed("init");
        std::env::remove_var("TALYX_DEV");
        if cfg!(debug_assertions) {
            assert!(r.is_ok());
        }
    }
}
