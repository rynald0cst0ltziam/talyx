//! agentguard-store
//!
//! The local decision cache — BUILD_PLAN.md §6: "cache the decision keyed
//! on (artifact hash, policy version) and only re-evaluate on hash change,
//! policy change, or new incident data." Records are keyed on artifact id;
//! `content_hash`/`capability_snapshot` on each record are the baseline
//! `agentguard init`'s drift check (§8, in agentguard-cli's init.rs)
//! compares the next scan against. This crate is deliberately
//! small and dependency-light because both `agentguard-cli` (writer, at
//! `init`/`scan` time) and `agentguard-shim` (reader, at every gated
//! process launch — must be fast and must not depend on the scanner/risk
//! crates) link it.
//!
//! Storage is a single JSON file at `~/.agentguard/decisions.json`. That's
//! a deliberate v0 choice, not an oversight: it's human-inspectable,
//! diffable, needs no database dependency, and the file sizes involved
//! (tens to low thousands of artifacts on a single dev machine) don't need
//! anything heavier. Revisit if/when this needs to be shared across a
//! daemon and many concurrent shim invocations without a race.
//!
//! **Known v0 limitation, not yet fixed:** there is no file locking.
//! `load`/`save` is read-whole-file, mutate in memory, write-whole-file —
//! two concurrent writers (e.g. two `agentguard init` runs, or `init`
//! racing a future daemon) can lose one writer's update. The shim only
//! reads, so this doesn't affect the enforcement path itself, but
//! concurrent `agentguard scan`/`init`/`allow` invocations are not
//! currently safe. A test in this file caught the same class of race
//! (parallel test threads colliding on one temp file) — see `temp_store`'s
//! comment. Fix before this store is written by more than one process at a
//! time in practice (e.g. once a daemon exists).

use agentguard_core::{Capability, Decision, ProtectionLevel, RiskBand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub artifact_id: String,
    pub name: String,
    pub band: RiskBand,
    pub decision: Decision,
    pub total_score: i32,
    pub protection_level: ProtectionLevel,
    pub scanned_at_unix: u64,
    /// Flattened evidence/reputation/context reasons from the
    /// `ScoreBreakdown` that produced this record — stored so `agentguard
    /// why <id>` can show the full reasoning without re-scanning. Never
    /// surface `total_score`/`band` to a user without these attached.
    #[serde(default)]
    pub reasons: Vec<String>,
    /// Content hash from the scan that produced this record (see
    /// agentguard-scanner's `hash_path`) — `None` for artifacts that
    /// couldn't be hashed (no local content, e.g. an unresolved registry
    /// package). This is the baseline `agentguard init`'s drift check
    /// compares the next scan against — BUILD_PLAN.md §8.
    #[serde(default)]
    pub content_hash: Option<String>,
    /// The artifact's distinct capability set at scan time (sorted,
    /// deduped — not the full evidence list, which lives in `reasons`).
    /// Compared against the next scan's capability set when `content_hash`
    /// changes, to tell "content changed but does the same things" apart
    /// from "content changed AND now does something new and dangerous."
    #[serde(default)]
    pub capability_snapshot: Vec<Capability>,
    /// The real shell command for a hook (`ConfigSourceKind::
    /// ClaudeCodeHooksJson`) artifact — `None` for anything else. Exists
    /// because the wrapped config entry `agentguard init` writes for a
    /// hook deliberately does NOT contain this text: a hook's `command` is
    /// a shell-syntax string that Claude Code itself re-parses through a
    /// real shell when the hook fires, so embedding the original command
    /// (which may contain pipes, redirects, etc.) directly in that
    /// rewritten string would let the OUTER shell interpret those
    /// metacharacters before agentguard-shim ever runs — found live, not
    /// hypothetically: a fixture hook command containing `|` caused
    /// cmd.exe to split the rewritten line into a pipeline and run later
    /// stages directly, bypassing the shim's block entirely. The shim
    /// instead looks up the real command from here (this store, never
    /// re-parsed by a shell) after deciding ALLOW.
    #[serde(default)]
    pub shell_command: Option<String>,
    /// Set only by an explicit human action (`agentguard allow <id>`),
    /// never inferred. The shim treats an approved record as ALLOW
    /// regardless of what the engine's own decision says, which is the
    /// whole point of the ASK flow — the engine flags it once, a human
    /// decides, and that decision sticks until the artifact changes.
    pub manually_approved: bool,
    /// The complete original config entry for a remote MCP server (see
    /// agentguard-adapters' `DiscoveredArtifact::raw_config_entry`),
    /// snapshotted here at scan time so a later `agentguard allow <id>`
    /// can restore it. Remote servers have no local process for the shim
    /// to wrap, so `agentguard init` enforces a BLOCK/unapproved-ASK
    /// remote entry by removing it from the live config outright — but a
    /// removed entry is invisible to future discovery (there's nothing
    /// left on disk to re-scan), so without this snapshot there would be
    /// no way to bring it back once approved. `None` for every other
    /// artifact kind.
    #[serde(default)]
    pub remote_entry_snapshot: Option<serde_json::Value>,
    /// The config file this record's remote entry lives in (or was
    /// removed from), paired with `remote_entry_snapshot` /
    /// `config_entry_key` — `agentguard allow` reopens exactly this file
    /// rather than re-running discovery. `None` for non-remote artifacts.
    #[serde(default)]
    pub config_path: Option<PathBuf>,
    /// The key this remote entry is (or was) stored under in
    /// `config_path` (e.g. the `mcpServers` object key, or the Codex TOML
    /// `[mcp_servers.<key>]` table name) — `None` for non-remote
    /// artifacts.
    #[serde(default)]
    pub config_entry_key: Option<String>,
    /// Where a Skill artifact's directory originally lived (its
    /// `scan_root` at scan time). A Skill has no `PreToolUse`-style
    /// interception point at all — Claude Code's own hooks reference
    /// (verified 2026-09-05 against code.claude.com/docs/en/hooks) lists
    /// no hook event that fires on skill invocation, and skill content
    /// loads by direct context injection, never as a tool call a
    /// `PreToolUse` matcher could see. So enforcement means physically
    /// moving the skill's directory out of `.claude/skills/` (the same
    /// "there's nothing else to intercept, so change what's on disk"
    /// logic as remote MCP entry removal) rather than gating a launch or
    /// a config entry. `None` for every non-Skill artifact.
    #[serde(default)]
    pub quarantine_original_path: Option<PathBuf>,
    /// Where a quarantined Skill's directory currently sits, if
    /// `agentguard init` has moved it out of `.claude/skills/`
    /// (BLOCK/QUARANTINE, or an unapproved ASK). `None` when the skill is
    /// at its original location — either never quarantined, or already
    /// restored by `agentguard allow`. `agentguard allow` moves the
    /// directory from here back to `quarantine_original_path` and clears
    /// this field.
    #[serde(default)]
    pub quarantine_current_path: Option<PathBuf>,
}

impl DecisionRecord {
    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// What the shim should actually do, folding in manual approval.
    pub fn effective_decision(&self) -> Decision {
        if self.manually_approved {
            Decision::Allow
        } else {
            self.decision
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    records: BTreeMap<String, DecisionRecord>,
}

pub struct DecisionStore {
    path: PathBuf,
}

impl DecisionStore {
    /// `~/.agentguard/decisions.json`. Directory and file are created on
    /// first write, not on open — opening never has a side effect.
    pub fn open_default() -> io::Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no home directory found"))?;
        Ok(Self {
            path: home.join(".agentguard").join("decisions.json"),
        })
    }

    /// For tests and for pointing the shim/CLI at an isolated store (e.g.
    /// `AGENTGUARD_STORE` env var during demo/fixture runs) instead of the
    /// real machine-wide one.
    pub fn open_at(path: PathBuf) -> Self {
        Self { path }
    }

    /// `$AGENTGUARD_STORE` env var if set, else `open_default()`, falling
    /// back to a store in the current directory on the (very rare) case
    /// `open_default()` can't determine a home directory — resolving a
    /// store location should never itself be a hard failure for a
    /// read-only lookup. This is the single shared resolution policy
    /// every caller that just wants "the store" (as opposed to explicit
    /// control, like the CLI's `--store` flag) should use, rather than
    /// each reimplementing the same env-var-then-default logic.
    pub fn resolve() -> Self {
        if let Ok(path) = std::env::var("AGENTGUARD_STORE") {
            return Self::open_at(PathBuf::from(path));
        }
        Self::open_default().unwrap_or_else(|_| Self::open_at(PathBuf::from(".agentguard-decisions.json")))
    }

    fn load(&self) -> StoreFile {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn save(&self, file: &StoreFile) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&self.path, text)
    }

    pub fn get(&self, artifact_id: &str) -> Option<DecisionRecord> {
        self.load().records.get(artifact_id).cloned()
    }

    pub fn upsert(&self, record: DecisionRecord) -> io::Result<()> {
        let mut file = self.load();
        file.records.insert(record.artifact_id.clone(), record);
        self.save(&file)
    }

    /// `agentguard allow <id>`. Returns `false` if the artifact has never
    /// been scanned (nothing to approve) — the caller should tell the user
    /// to run a scan first rather than silently creating a phantom record.
    pub fn approve(&self, artifact_id: &str) -> io::Result<bool> {
        let mut file = self.load();
        match file.records.get_mut(artifact_id) {
            Some(record) => {
                record.manually_approved = true;
                self.save(&file)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn all(&self) -> Vec<DecisionRecord> {
        self.load().records.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> DecisionStore {
        // A unique path per call, not per second: `cargo test` runs these
        // in parallel threads within one process, so process::id() +
        // now_unix() (1s resolution) can collide and race on the same
        // file. Caught by an actual flaky test run, not by inspection.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mut path = std::env::temp_dir();
        path.push(format!(
            "agentguard-store-test-{}-{}.json",
            std::process::id(),
            n
        ));
        DecisionStore::open_at(path)
    }

    #[test]
    fn round_trips_a_record() {
        let store = temp_store();
        let record = DecisionRecord {
            artifact_id: "mcp-server:test:local:foo".to_string(),
            name: "foo".to_string(),
            band: RiskBand::High,
            decision: Decision::Ask,
            total_score: 60,
            protection_level: ProtectionLevel::Balanced,
            scanned_at_unix: DecisionRecord::now_unix(),
            reasons: vec!["test evidence".to_string()],
            content_hash: Some("abc123".to_string()),
            capability_snapshot: vec![Capability::NetworkExternal],
            shell_command: None,
            manually_approved: false,
            remote_entry_snapshot: None,
            config_path: None,
            config_entry_key: None,
            quarantine_original_path: None,
            quarantine_current_path: None,
        };
        store.upsert(record.clone()).unwrap();

        let fetched = store.get(&record.artifact_id).unwrap();
        assert_eq!(fetched.decision, Decision::Ask);
        assert_eq!(fetched.effective_decision(), Decision::Ask);
    }

    #[test]
    fn approval_overrides_effective_decision_but_not_stored_decision() {
        let store = temp_store();
        let id = "mcp-server:test:local:bar".to_string();
        store
            .upsert(DecisionRecord {
                artifact_id: id.clone(),
                name: "bar".to_string(),
                band: RiskBand::High,
                decision: Decision::Ask,
                total_score: 55,
                protection_level: ProtectionLevel::Balanced,
                scanned_at_unix: DecisionRecord::now_unix(),
                reasons: vec![],
                content_hash: None,
                capability_snapshot: vec![],
                shell_command: None,
                manually_approved: false,
                remote_entry_snapshot: None,
                config_path: None,
                config_entry_key: None,
                quarantine_original_path: None,
                quarantine_current_path: None,
            })
            .unwrap();

        let approved = store.approve(&id).unwrap();
        assert!(approved);

        let fetched = store.get(&id).unwrap();
        assert_eq!(fetched.decision, Decision::Ask); // engine's verdict preserved
        assert_eq!(fetched.effective_decision(), Decision::Allow); // but now allowed
    }

    #[test]
    fn approving_unknown_artifact_returns_false() {
        let store = temp_store();
        assert!(!store.approve("does-not-exist").unwrap());
    }
}
