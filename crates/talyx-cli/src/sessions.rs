//! Reader for the live proxy's findings log
//! (`~/.talyx/sessions/<date>-<pid>.jsonl`, `TALYX_SESSIONS_DIR`
//! overrides). Written by `talyx-mcp-proxy`; surfaced by
//! `talyx status` and `talyx why`.

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
