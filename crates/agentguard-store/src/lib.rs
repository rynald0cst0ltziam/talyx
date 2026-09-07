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
//! daemon and many concurrent shim invocations at a scale where a single
//! flat file itself becomes the bottleneck.
//!
//! **Concurrency**: every read and write takes a real OS-level advisory
//! lock on the store file itself (`std::fs::File`'s native `lock`/
//! `lock_shared`/`unlock` — stable since Rust 1.89, `flock(2)` on Unix /
//! `LockFileEx` on Windows under the hood; no external crate needed) for
//! the full duration of that read or read-modify-write cycle. Writers
//! (`upsert`/`approve`) take an exclusive lock; readers (`get`/`all`)
//! take a shared lock, so concurrent reads don't block each other but a
//! writer excludes everyone else, including other writers, for as long
//! as it holds the lock. This closes a real, previously-documented gap:
//! two concurrent `agentguard init` runs (or `init` racing `allow`) used
//! to silently lose one writer's update under a naive
//! read-whole-file/write-whole-file pattern, proven by a regression test
//! in this file (`concurrent_writers_do_not_lose_updates`) that spawns
//! real OS threads hammering one store concurrently and asserts every
//! single write survived.

use agentguard_core::{Capability, Decision, ProtectionLevel, RiskBand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
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
    /// The JSON key PATH the server map sits under in `config_path` —
    /// `["mcpServers"]` for most JSON agents, `["servers"]` for VS Code's
    /// Copilot Chat extension, `["mcp", "servers"]` for OpenClaw,
    /// `["mcp"]` for opencode / Crush; `None` for a TOML config (Codex) or
    /// a non-remote artifact. This crate stays deliberately unaware of
    /// `agentguard-adapters`' `ConfigSourceKind` enum (kept
    /// dependency-light — see this module's doc comment), so the actual
    /// path is captured here as plain data at scan time instead, letting
    /// `agentguard allow`'s restore path insert a remote entry back under
    /// the correct nested key without re-deriving it. (Renamed from
    /// `config_top_level_key: Option<String>`; an older record missing
    /// this field deserializes to `None` and the restore path falls back
    /// to `["mcpServers"]`. The old string field is simply ignored if
    /// present — serde drops unknown fields.)
    #[serde(default)]
    pub config_key_path: Option<Vec<String>>,
    /// Whether the removed remote entry was an element of a LIST (keyed by
    /// its own `name` field — Continue.dev's / Aider's YAML `mcpServers`)
    /// rather than a value in a name-keyed MAP (every other agent). The
    /// restore path appends to the list vs. inserts at the map key.
    /// `false` for a map (the default, and correct for every JSON agent).
    #[serde(default)]
    pub config_entry_is_list_element: bool,
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

    /// Opens the store file read-only and holds a shared lock (`fs4`) for
    /// the duration of the read, so a reader never observes a writer's
    /// in-progress truncate-then-rewrite. A missing file is a normal,
    /// silent "no records yet" — not an error — since `open_default`
    /// deliberately never creates the file just by being opened.
    fn read_locked(&self) -> io::Result<StoreFile> {
        let mut f = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StoreFile::default()),
            Err(e) => return Err(e),
        };
        f.lock_shared()?;
        let mut text = String::new();
        f.read_to_string(&mut text)?;
        // An empty file (e.g. a writer created it but hasn't written yet —
        // can't happen with this module's own writers, which always hold
        // the lock across create+write, but a foreign process truncating
        // the file some other way is not this store's problem to detect)
        // parses as "no records" rather than a hard error.
        if text.trim().is_empty() {
            return Ok(StoreFile::default());
        }
        serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Opens (creating if needed) the store file, holds an EXCLUSIVE lock
    /// across the full read-modify-write cycle, and rewrites the file
    /// in-place (seek to start, write, truncate to the new length) through
    /// the same locked handle — never a separate `std::fs::write` call,
    /// which would open its own handle and defeat the lock. The exclusive
    /// lock excludes every other reader and writer (this process or any
    /// other) for the whole cycle, which is what actually closes the
    /// lost-update race a naive load-then-save split has: two concurrent
    /// callers of this method serialize completely, so the second one to
    /// acquire the lock always mutates the FIRST one's already-persisted
    /// state, never a stale in-memory copy.
    fn with_exclusive_lock<T>(&self, f: impl FnOnce(&mut StoreFile) -> T) -> io::Result<T> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut handle = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;
        handle.lock()?;

        let mut text = String::new();
        handle.read_to_string(&mut text)?;
        let mut store = if text.trim().is_empty() {
            StoreFile::default()
        } else {
            serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        };

        let result = f(&mut store);

        let serialized = serde_json::to_string_pretty(&store)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        handle.seek(SeekFrom::Start(0))?;
        handle.write_all(serialized.as_bytes())?;
        handle.set_len(serialized.len() as u64)?;
        handle.flush()?;

        // The exclusive lock releases when `handle` drops at the end of
        // this scope (both flock and LockFileEx release on handle close);
        // no explicit unlock needed, and none would be safe to skip here
        // anyway since every early-return above is a `?` that already
        // propagates before this point is reached.
        Ok(result)
    }

    pub fn get(&self, artifact_id: &str) -> Option<DecisionRecord> {
        self.read_locked()
            .unwrap_or_default()
            .records
            .get(artifact_id)
            .cloned()
    }

    pub fn upsert(&self, record: DecisionRecord) -> io::Result<()> {
        self.with_exclusive_lock(|store| {
            store.records.insert(record.artifact_id.clone(), record);
        })
    }

    /// `agentguard allow <id>`. Returns `false` if the artifact has never
    /// been scanned (nothing to approve) — the caller should tell the user
    /// to run a scan first rather than silently creating a phantom record.
    pub fn approve(&self, artifact_id: &str) -> io::Result<bool> {
        self.with_exclusive_lock(|store| match store.records.get_mut(artifact_id) {
            Some(record) => {
                record.manually_approved = true;
                true
            }
            None => false,
        })
    }

    pub fn all(&self) -> Vec<DecisionRecord> {
        self.read_locked().unwrap_or_default().records.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store_path() -> PathBuf {
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
        path
    }

    fn temp_store() -> DecisionStore {
        DecisionStore::open_at(temp_store_path())
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
            config_key_path: None,
            config_entry_is_list_element: false,
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
            config_key_path: None,
            config_entry_is_list_element: false,
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

    fn minimal_record(artifact_id: &str) -> DecisionRecord {
        DecisionRecord {
            artifact_id: artifact_id.to_string(),
            name: artifact_id.to_string(),
            band: RiskBand::Low,
            decision: Decision::Allow,
            total_score: 0,
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
            config_key_path: None,
            config_entry_is_list_element: false,
            quarantine_original_path: None,
            quarantine_current_path: None,
        }
    }

    /// Proves the fix for the previously-documented "no file locking, two
    /// concurrent writers can lose one writer's update" gap. Real OS
    /// threads (not just async tasks in one executor) hammer ONE store
    /// file concurrently, each writing its own distinct artifact id --
    /// under the old read-whole-file/mutate/write-whole-file pattern with
    /// no lock, this reliably lost updates (two writers both loading the
    /// same stale snapshot, the second one's write clobbering the
    /// first's). If every one of these survives, the exclusive lock in
    /// `with_exclusive_lock` is doing its job: each writer's
    /// read-modify-write cycle is fully serialized against every other
    /// writer, not just fast enough to usually not collide.
    #[test]
    fn concurrent_writers_do_not_lose_updates() {
        let path = temp_store_path();
        const WRITER_THREADS: usize = 16;

        let handles: Vec<_> = (0..WRITER_THREADS)
            .map(|i| {
                let store = DecisionStore::open_at(path.clone());
                std::thread::spawn(move || {
                    let id = format!("artifact-{i}");
                    store.upsert(minimal_record(&id)).unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let store = DecisionStore::open_at(path.clone());
        let all = store.all();
        assert_eq!(
            all.len(),
            WRITER_THREADS,
            "every concurrent writer's record must survive -- fewer than {WRITER_THREADS} means an update was lost to a race"
        );
        for i in 0..WRITER_THREADS {
            assert!(
                store.get(&format!("artifact-{i}")).is_some(),
                "artifact-{i}'s write was lost"
            );
        }

        std::fs::remove_file(&path).ok();
    }

    /// Same race, but for `approve` specifically (a read-modify-write on
    /// an EXISTING record, not an insert) -- a different code path than
    /// `upsert`, worth its own proof since the two share `with_exclusive_
    /// lock` but call it with different closures.
    #[test]
    fn concurrent_approvals_of_different_records_all_land() {
        let path = temp_store_path();
        const RECORD_COUNT: usize = 16;

        let seed_store = DecisionStore::open_at(path.clone());
        for i in 0..RECORD_COUNT {
            seed_store.upsert(minimal_record(&format!("artifact-{i}"))).unwrap();
        }

        let handles: Vec<_> = (0..RECORD_COUNT)
            .map(|i| {
                let store = DecisionStore::open_at(path.clone());
                std::thread::spawn(move || {
                    assert!(store.approve(&format!("artifact-{i}")).unwrap());
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let store = DecisionStore::open_at(path.clone());
        for i in 0..RECORD_COUNT {
            let record = store.get(&format!("artifact-{i}")).unwrap();
            assert!(
                record.manually_approved,
                "artifact-{i}'s approval was lost to a race"
            );
        }

        std::fs::remove_file(&path).ok();
    }
}
