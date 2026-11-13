//! Reader for the live proxy's findings log
//! (`~/.talyx/sessions/<date>-<pid>.jsonl`, `TALYX_SESSIONS_DIR`
//! overrides). Written by `talyx-mcp-proxy`; surfaced by
//! `talyx status` and `talyx why`.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// One line from a session log.
pub struct Finding {
    pub ts_ms: u64,
    pub artifact: String,
    pub method: String,
    pub action: String,
    pub capability: String,
    pub evidence: String,
}

/// Aggregated view of a set of findings — the data behind `talyx sessions`
/// (TASKS.md 2.4: one understandable summary of recent live-proxy activity,
/// with a durable machine-readable form via `--json`).
pub struct Summary {
    pub total: usize,
    pub by_action: BTreeMap<String, usize>,
    pub by_capability: BTreeMap<String, usize>,
    pub by_artifact: BTreeMap<String, usize>,
    /// Newest / oldest finding timestamps (ms since epoch), 0 when empty.
    pub newest_ts_ms: u64,
    pub oldest_ts_ms: u64,
}

/// Tallies findings by action, capability, and artifact, and records the
/// time window they span.
pub fn summarize(findings: &[Finding]) -> Summary {
    let mut by_action = BTreeMap::new();
    let mut by_capability = BTreeMap::new();
    let mut by_artifact = BTreeMap::new();
    let mut newest = 0u64;
    let mut oldest = u64::MAX;
    for f in findings {
        if !f.action.is_empty() {
            *by_action.entry(f.action.clone()).or_insert(0) += 1;
        }
        if !f.capability.is_empty() {
            *by_capability.entry(f.capability.clone()).or_insert(0) += 1;
        }
        if !f.artifact.is_empty() {
            *by_artifact.entry(f.artifact.clone()).or_insert(0) += 1;
        }
        newest = newest.max(f.ts_ms);
        oldest = oldest.min(f.ts_ms);
    }
    Summary {
        total: findings.len(),
        by_action,
        by_capability,
        by_artifact,
        newest_ts_ms: newest,
        oldest_ts_ms: if findings.is_empty() { 0 } else { oldest },
    }
}

fn sessions_dir() -> Option<PathBuf> {
    std::env::var_os("TALYX_SESSIONS_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".talyx").join("sessions")))
}

/// Findings from the most recent `max_files` session logs, newest file
/// first, newest finding first within a file.
pub fn recent(max_files: usize) -> Vec<Finding> {
    let Some(dir) = sessions_dir() else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("jsonl"))
        .collect();
    files.sort_by_key(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    let mut out = Vec::new();
    for path in files.iter().rev().take(max_files) {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().rev() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(Finding {
                ts_ms: v.get("ts_ms").and_then(|x| x.as_u64()).unwrap_or(0),
                artifact: s("artifact"),
                method: s("method"),
                action: s("action"),
                capability: s("capability"),
                evidence: s("evidence"),
            });
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.ts_ms)); // newest first
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(ts: u64, artifact: &str, action: &str, capability: &str) -> Finding {
        Finding {
            ts_ms: ts,
            artifact: artifact.to_string(),
            method: "tools/call".to_string(),
            action: action.to_string(),
            capability: capability.to_string(),
            evidence: String::new(),
        }
    }

    #[test]
    fn summarize_tallies_and_bounds_the_window() {
        let findings = vec![
            finding(300, "srv-a", "block", "secret_access"),
            finding(100, "srv-b", "allow", "network_external"),
            finding(200, "srv-a", "block", "network_external"),
        ];
        let s = summarize(&findings);
        assert_eq!(s.total, 3);
        assert_eq!(s.by_action.get("block"), Some(&2));
        assert_eq!(s.by_action.get("allow"), Some(&1));
        assert_eq!(s.by_capability.get("network_external"), Some(&2));
        assert_eq!(s.by_artifact.get("srv-a"), Some(&2));
        assert_eq!(s.newest_ts_ms, 300);
        assert_eq!(s.oldest_ts_ms, 100);
    }

    #[test]
    fn summarize_handles_empty() {
        let s = summarize(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.newest_ts_ms, 0);
        assert_eq!(s.oldest_ts_ms, 0);
        assert!(s.by_action.is_empty());
    }
}
