//! Durable posture history — "what changed since last scan" (TASKS.md 3.4,
//! PRODUCT_MODEL §5 "Activity").
//!
//! A compact JSONL append-log (one [`Snapshot`] per line) at
//! `~/.talyx/history.jsonl` (`TALYX_HISTORY` overrides in debug/test
//! builds, same pattern and rationale as the decision store's
//! `TALYX_STORE`). Snapshots are keyed by `scope` so a diff only ever
//! compares a project against its own past, never against another project
//! or the whole machine.
//!
//! `talyx init` records a snapshot on every run (its natural capture
//! point); `talyx report` reads the latest prior snapshot to show what
//! changed, and records one itself only when asked with `--record`, so a
//! plain `report` stays free of side effects for CI piping.

use crate::report::Row;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use talyx_core::{Decision, RiskBand};

/// One artifact's state within a snapshot.
#[derive(Serialize, Deserialize, Clone)]
pub struct ArtifactState {
    pub decision: Decision,
    pub band: RiskBand,
    pub score: i32,
    #[serde(default)]
    pub approved: bool,
}

/// A point-in-time posture snapshot for one scope.
#[derive(Serialize, Deserialize, Clone)]
pub struct Snapshot {
    pub generated_at_unix: u64,
    pub scope: String,
    pub artifacts: BTreeMap<String, ArtifactState>,
}

impl Snapshot {
    /// Build a snapshot from report rows (their effective decisions).
    pub fn from_rows(scope: String, generated_at_unix: u64, rows: &[Row]) -> Snapshot {
        let artifacts = rows
            .iter()
            .map(|r| {
                (
                    r.id.clone(),
                    ArtifactState {
                        decision: r.effective_decision,
                        band: r.band,
                        score: r.score,
                        approved: r.approved,
                    },
                )
            })
            .collect();
        Snapshot {
            generated_at_unix,
            scope,
            artifacts,
        }
    }
}

/// A flagged decision needs a human — not plainly allowed.
fn is_flagged(d: Decision) -> bool {
    matches!(d, Decision::Ask | Decision::Block | Decision::Quarantine)
}

/// The transitions between two snapshots (PRODUCT_MODEL §5 "Activity").
pub struct Diff {
    pub since_unix: u64,
    pub newly_flagged: Vec<String>,
    pub resolved: Vec<String>,
    pub newly_approved: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// (id, old score, new score) for artifacts whose score rose.
    pub score_increased: Vec<(String, i32, i32)>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.newly_flagged.is_empty()
            && self.resolved.is_empty()
            && self.newly_approved.is_empty()
            && self.added.is_empty()
            && self.removed.is_empty()
            && self.score_increased.is_empty()
    }
}

/// Compare a previous snapshot against the current one.
pub fn diff(prev: &Snapshot, cur: &Snapshot) -> Diff {
    let mut d = Diff {
        since_unix: prev.generated_at_unix,
        newly_flagged: Vec::new(),
        resolved: Vec::new(),
        newly_approved: Vec::new(),
        added: Vec::new(),
        removed: Vec::new(),
        score_increased: Vec::new(),
    };
    for (id, cur_state) in &cur.artifacts {
        match prev.artifacts.get(id) {
            None => d.added.push(id.clone()),
            Some(prev_state) => {
                if !is_flagged(prev_state.decision) && is_flagged(cur_state.decision) {
                    d.newly_flagged.push(id.clone());
                }
                if is_flagged(prev_state.decision) && !is_flagged(cur_state.decision) {
                    d.resolved.push(id.clone());
                }
                if !prev_state.approved && cur_state.approved {
                    d.newly_approved.push(id.clone());
                }
                if cur_state.score > prev_state.score {
                    d.score_increased
                        .push((id.clone(), prev_state.score, cur_state.score));
                }
            }
        }
    }
    for id in prev.artifacts.keys() {
        if !cur.artifacts.contains_key(id) {
            d.removed.push(id.clone());
        }
    }
    d
}

/// `~/.talyx/history.jsonl`, or `$TALYX_HISTORY` in debug/test builds.
pub fn history_path() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Ok(p) = std::env::var("TALYX_HISTORY") {
        return Some(PathBuf::from(p));
    }
    dirs::home_dir().map(|h| h.join(".talyx").join("history.jsonl"))
}

/// How many snapshots to keep per file. Bounds unbounded growth while
/// leaving plenty of history for change tracking.
const MAX_SNAPSHOTS: usize = 200;

/// Append a snapshot to the default history file (best-effort; returns the
/// error so the caller can warn without failing the surrounding command).
pub fn record(snapshot: &Snapshot) -> io::Result<()> {
    let path = history_path()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no home directory for history"))?;
    append_at(&path, snapshot)
}

/// The most recent snapshot for `scope` in the default history file.
pub fn latest(scope: &str) -> Option<Snapshot> {
    latest_at(&history_path()?, scope)
}

pub fn append_at(path: &Path, snapshot: &Snapshot) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(snapshot)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")?;
    drop(f);
    prune(path);
    Ok(())
}

/// Keeps only the newest `MAX_SNAPSHOTS` lines. Best-effort: any IO problem
/// leaves the file as-is rather than risking the history that was just
/// written.
fn prune(path: &Path) {
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    let lines: Vec<String> = io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .collect();
    if lines.len() <= MAX_SNAPSHOTS {
        return;
    }
    let keep = &lines[lines.len() - MAX_SNAPSHOTS..];
    let tmp = path.with_extension("jsonl.tmp");
    if std::fs::write(&tmp, format!("{}\n", keep.join("\n"))).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

pub fn latest_at(path: &Path, scope: &str) -> Option<Snapshot> {
    let file = std::fs::File::open(path).ok()?;
    io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str::<Snapshot>(&l).ok())
        .filter(|s| s.scope == scope)
        .max_by_key(|s| s.generated_at_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(decision: Decision, score: i32, approved: bool) -> ArtifactState {
        ArtifactState { decision, band: RiskBand::Low, score, approved }
    }

    fn snap(ts: u64, scope: &str, entries: &[(&str, ArtifactState)]) -> Snapshot {
        Snapshot {
            generated_at_unix: ts,
            scope: scope.to_string(),
            artifacts: entries.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        }
    }

    #[test]
    fn diff_detects_every_transition() {
        let prev = snap(
            100,
            "proj",
            &[
                ("stays-allowed", state(Decision::Allow, 0, false)),
                ("gets-flagged", state(Decision::Allow, 10, false)),
                ("gets-resolved", state(Decision::Block, 90, false)),
                ("gets-approved", state(Decision::Ask, 60, false)),
                ("disappears", state(Decision::Allow, 0, false)),
                ("worse", state(Decision::Ask, 40, false)),
            ],
        );
        let cur = snap(
            200,
            "proj",
            &[
                ("stays-allowed", state(Decision::Allow, 0, false)),
                ("gets-flagged", state(Decision::Block, 85, false)),
                ("gets-resolved", state(Decision::Allow, 0, false)),
                ("gets-approved", state(Decision::Ask, 60, true)),
                ("worse", state(Decision::Ask, 70, false)),
                ("brand-new", state(Decision::Ask, 50, false)),
            ],
        );
        let d = diff(&prev, &cur);
        assert_eq!(d.since_unix, 100);
        assert_eq!(d.newly_flagged, vec!["gets-flagged"]);
        assert_eq!(d.resolved, vec!["gets-resolved"]);
        assert_eq!(d.newly_approved, vec!["gets-approved"]);
        assert_eq!(d.added, vec!["brand-new"]);
        assert_eq!(d.removed, vec!["disappears"]);
        // both gets-flagged (10->85) and worse (40->70) rose
        assert!(d.score_increased.iter().any(|(id, o, n)| id == "worse" && *o == 40 && *n == 70));
        assert!(!d.is_empty());
    }

    #[test]
    fn append_and_latest_round_trip_by_scope() {
        let dir = std::env::temp_dir().join(format!("talyx-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.jsonl");
        let _ = std::fs::remove_file(&path);

        append_at(&path, &snap(100, "proj-a", &[("x", state(Decision::Allow, 0, false))])).unwrap();
        append_at(&path, &snap(300, "proj-a", &[("x", state(Decision::Block, 90, false))])).unwrap();
        append_at(&path, &snap(200, "proj-b", &[("y", state(Decision::Ask, 50, false))])).unwrap();

        let latest_a = latest_at(&path, "proj-a").unwrap();
        assert_eq!(latest_a.generated_at_unix, 300); // newest for the scope
        assert_eq!(latest_a.artifacts.get("x").unwrap().decision, Decision::Block);

        let latest_b = latest_at(&path, "proj-b").unwrap();
        assert_eq!(latest_b.generated_at_unix, 200);
        assert!(latest_at(&path, "proj-c").is_none());

        std::fs::remove_file(&path).ok();
    }
}
