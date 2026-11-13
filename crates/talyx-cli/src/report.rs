//! `talyx report` — the canonical posture / analytics model
//! (PRODUCT_MODEL.md §5, TASKS.md 3.1–3.3).
//!
//! One structure, built once from a fresh scan + the decision store +
//! recent session findings, rendered to text / JSON / CSV / Markdown from
//! the same data so every surface reports identical numbers. Metrics are
//! computed from a lightweight [`Row`] list (one per artifact) rather than
//! straight off `ScannedArtifact`, so the arithmetic is unit-testable
//! without constructing a whole scan.

use crate::pipeline::ScannedArtifact;
use crate::sessions;
use std::collections::BTreeMap;
use talyx_core::{Decision, RiskBand};
use talyx_store::DecisionStore;

/// One artifact's line in the report — the atomic unit every metric is
/// derived from. `effective_decision` already folds in manual approval
/// (what actually happens), while `scan_decision` is the engine's verdict.
pub struct Row {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub agent: String,
    pub band: RiskBand,
    pub score: i32,
    pub scan_decision: Decision,
    pub effective_decision: Decision,
    pub approved: bool,
    pub capabilities: Vec<String>,
    /// A one-line "why" for the top-risk list (first static-evidence reason).
    pub reason: String,
    /// Whether this artifact is routed (or routable) through the shim.
    pub rewritable: bool,
}

/// Current state counts across all artifacts (PRODUCT_MODEL §5 "Posture").
pub struct Posture {
    pub total: usize,
    pub allowed: usize,
    pub logged: usize,
    pub in_review: usize,
    pub blocked: usize,
    pub quarantined: usize,
    pub approved: usize,
    pub by_band: BTreeMap<String, usize>,
    pub by_kind: BTreeMap<String, usize>,
    /// Capability tallies across artifacts that are NOT plainly allowed —
    /// the "top attack classes" of TASKS 3.2.
    pub top_capabilities: BTreeMap<String, usize>,
    /// allowed+logged : blocked+quarantined. `None` when nothing is
    /// blocked (the ratio would be undefined / infinite).
    pub allow_block_ratio: Option<f64>,
}

/// Artifacts currently routed through the shim, by agent (PRODUCT_MODEL §5
/// "Enforcement").
pub struct Enforcement {
    pub rewritable: usize,
    pub by_agent: BTreeMap<String, usize>,
}

/// One high-band artifact with its one-line reason (PRODUCT_MODEL §5
/// "Top risk").
pub struct TopRisk {
    pub id: String,
    pub name: String,
    pub band: RiskBand,
    pub score: i32,
    pub reason: String,
}

pub struct Report {
    pub generated_at_unix: u64,
    pub scope: String,
    pub posture: Posture,
    pub enforcement: Enforcement,
    pub session_findings: sessions::Summary,
    pub top_risk: Vec<TopRisk>,
    pub rows: Vec<Row>,
}

/// Builds the rows for a scan, cross-referencing the decision store so the
/// effective decision and approval state reflect what the shim would
/// actually do, not just the engine's fresh verdict.
pub fn rows_from_scan(scanned: &[ScannedArtifact], store: &DecisionStore) -> Vec<Row> {
    scanned
        .iter()
        .map(|s| {
            let record = store.get(&s.artifact.id);
            let approved = record.as_ref().map(|r| r.manually_approved).unwrap_or(false);
            let effective = if approved { Decision::Allow } else { s.decision };
            let reason = s
                .breakdown
                .static_evidence_reasons
                .first()
                .or_else(|| s.breakdown.context_reasons.first())
                .cloned()
                .unwrap_or_else(|| format!("{} risk", s.band));
            Row {
                id: s.artifact.id.clone(),
                name: s.artifact.name.clone(),
                kind: s.artifact.kind.to_string(),
                agent: s.agent_name.to_string(),
                band: s.band,
                score: s.breakdown.total(),
                scan_decision: s.decision,
                effective_decision: effective,
                approved,
                capabilities: s.artifact.capability_set().iter().map(|c| c.to_string()).collect(),
                reason,
                rewritable: s.config_source.is_some(),
            }
        })
        .collect()
}

/// Posture metrics from the rows — pure arithmetic, unit-tested directly.
pub fn posture_from_rows(rows: &[Row]) -> Posture {
    let mut p = Posture {
        total: rows.len(),
        allowed: 0,
        logged: 0,
        in_review: 0,
        blocked: 0,
        quarantined: 0,
        approved: 0,
        by_band: BTreeMap::new(),
        by_kind: BTreeMap::new(),
        top_capabilities: BTreeMap::new(),
        allow_block_ratio: None,
    };
    for r in rows {
        match r.effective_decision {
            Decision::Allow => p.allowed += 1,
            Decision::AllowLog => p.logged += 1,
            Decision::Ask => p.in_review += 1,
            Decision::Block => p.blocked += 1,
            Decision::Quarantine => p.quarantined += 1,
        }
        if r.approved {
            p.approved += 1;
        }
        *p.by_band.entry(r.band.to_string()).or_insert(0) += 1;
        *p.by_kind.entry(r.kind.clone()).or_insert(0) += 1;
        // "Attack classes": capabilities of anything not plainly allowed.
        if !matches!(r.effective_decision, Decision::Allow | Decision::AllowLog) {
            for c in &r.capabilities {
                *p.top_capabilities.entry(c.clone()).or_insert(0) += 1;
            }
        }
    }
    let stopped = p.blocked + p.quarantined;
    if stopped > 0 {
        p.allow_block_ratio = Some((p.allowed + p.logged) as f64 / stopped as f64);
    }
    p
}

/// Enforcement metrics — rewritable artifacts, by agent.
pub fn enforcement_from_rows(rows: &[Row]) -> Enforcement {
    let mut by_agent = BTreeMap::new();
    let mut rewritable = 0;
    for r in rows.iter().filter(|r| r.rewritable) {
        rewritable += 1;
        *by_agent.entry(r.agent.clone()).or_insert(0) += 1;
    }
    Enforcement { rewritable, by_agent }
}

/// The `n` highest-scoring artifacts that aren't plainly allowed, worst
/// first (ties broken by id for determinism).
pub fn top_risk_from_rows(rows: &[Row], n: usize) -> Vec<TopRisk> {
    let mut risky: Vec<&Row> = rows
        .iter()
        .filter(|r| !matches!(r.effective_decision, Decision::Allow | Decision::AllowLog))
        .collect();
    risky.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    risky
        .into_iter()
        .take(n)
        .map(|r| TopRisk {
            id: r.id.clone(),
            name: r.name.clone(),
            band: r.band,
            score: r.score,
            reason: r.reason.clone(),
        })
        .collect()
}

impl Report {
    /// Assemble the whole report from a scan, the store, and the live-proxy
    /// session findings.
    pub fn generate(
        scope: String,
        scanned: &[ScannedArtifact],
        store: &DecisionStore,
        session_limit: usize,
    ) -> Report {
        let rows = rows_from_scan(scanned, store);
        let posture = posture_from_rows(&rows);
        let enforcement = enforcement_from_rows(&rows);
        let top_risk = top_risk_from_rows(&rows, 10);
        let session_findings = sessions::summarize(&sessions::recent(session_limit));
        Report {
            generated_at_unix: talyx_store::DecisionRecord::now_unix(),
            scope,
            posture,
            enforcement,
            session_findings,
            top_risk,
            rows,
        }
    }

    /// The machine-readable form — the schema every export shares.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "generated_at_unix": self.generated_at_unix,
            "scope": self.scope,
            "posture": {
                "total": self.posture.total,
                "allowed": self.posture.allowed,
                "logged": self.posture.logged,
                "in_review": self.posture.in_review,
                "blocked": self.posture.blocked,
                "quarantined": self.posture.quarantined,
                "approved": self.posture.approved,
                "by_band": self.posture.by_band,
                "by_kind": self.posture.by_kind,
                "top_capabilities": self.posture.top_capabilities,
                "allow_block_ratio": self.posture.allow_block_ratio,
            },
            "enforcement": {
                "rewritable": self.enforcement.rewritable,
                "by_agent": self.enforcement.by_agent,
            },
            "session_findings": {
                "total": self.session_findings.total,
                "by_action": self.session_findings.by_action,
                "by_capability": self.session_findings.by_capability,
                "newest_ts_ms": self.session_findings.newest_ts_ms,
                "oldest_ts_ms": self.session_findings.oldest_ts_ms,
            },
            "top_risk": self.top_risk.iter().map(|t| serde_json::json!({
                "id": t.id,
                "name": t.name,
                "band": t.band.to_string(),
                "score": t.score,
                "reason": t.reason,
            })).collect::<Vec<_>>(),
        })
    }

    /// The full artifact inventory as CSV (TASKS 3.3) — stable header,
    /// every field sanitized and escaped so an attacker-influenced name
    /// can't break the row structure or inject terminal control sequences.
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "id,name,kind,agent,band,score,scan_decision,effective_decision,approved,capabilities\n",
        );
        for r in &self.rows {
            let fields = [
                r.id.clone(),
                r.name.clone(),
                r.kind.clone(),
                r.agent.clone(),
                r.band.to_string(),
                r.score.to_string(),
                r.scan_decision.to_string(),
                r.effective_decision.to_string(),
                r.approved.to_string(),
                r.capabilities.join("|"),
            ];
            let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        }
        out
    }

    /// A shareable Markdown summary (TASKS 3.3) — the executive snapshot,
    /// not the full inventory.
    pub fn to_markdown(&self) -> String {
        let p = &self.posture;
        let mut m = String::new();
        m.push_str("# Talyx security report\n\n");
        m.push_str(&format!(
            "- **Scope:** {}\n- **Generated:** {}\n\n",
            crate::sanitize_for_display(&self.scope),
            crate::init::format_unix(self.generated_at_unix),
        ));
        m.push_str("## Posture\n\n");
        m.push_str(&format!("- Total artifacts: {}\n", p.total));
        m.push_str(&format!(
            "- Allowed: {} (logged: {}), In review: {}, Blocked: {}, Quarantined: {}\n",
            p.allowed, p.logged, p.in_review, p.blocked, p.quarantined,
        ));
        m.push_str(&format!("- Manually approved: {}\n", p.approved));
        if let Some(ratio) = p.allow_block_ratio {
            m.push_str(&format!("- Allow/block ratio: {ratio:.2}\n"));
        }
        m.push_str(&format!(
            "- Enforcement: {} rewritable artifact(s) across {} agent(s)\n",
            self.enforcement.rewritable,
            self.enforcement.by_agent.len(),
        ));
        if self.session_findings.total > 0 {
            m.push_str(&format!(
                "- Live-proxy findings: {}\n",
                self.session_findings.total
            ));
        }
        if !self.top_risk.is_empty() {
            m.push_str("\n## Top risk\n\n");
            for t in &self.top_risk {
                m.push_str(&format!(
                    "- **{}** ({}, score {}) — {}\n",
                    crate::sanitize_for_display(&t.name),
                    t.band,
                    t.score,
                    crate::sanitize_for_display(&t.reason),
                ));
            }
        }
        m
    }
}

/// Quotes a CSV field when it contains a comma, quote, or newline, doubling
/// embedded quotes per RFC 4180. Control characters are replaced first (via
/// the shared display sanitizer) so nothing attacker-authored reaches a
/// spreadsheet or terminal raw.
fn csv_field(s: &str) -> String {
    let safe = crate::sanitize_for_display(s);
    if safe.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", safe.replace('"', "\"\""))
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, band: RiskBand, score: i32, decision: Decision, approved: bool, caps: &[&str]) -> Row {
        let effective = if approved { Decision::Allow } else { decision };
        Row {
            id: id.to_string(),
            name: id.to_string(),
            kind: "MCP server".to_string(),
            agent: "codex".to_string(),
            band,
            score,
            scan_decision: decision,
            effective_decision: effective,
            approved,
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            reason: "test reason".to_string(),
            rewritable: true,
        }
    }

    #[test]
    fn posture_counts_by_effective_decision() {
        let rows = vec![
            row("a", RiskBand::Low, 0, Decision::Allow, false, &[]),
            row("b", RiskBand::High, 60, Decision::Ask, false, &["network_external"]),
            // Approved block -> counts as allowed, and its caps are NOT
            // tallied as attack classes (it's trusted now).
            row("c", RiskBand::Critical, 80, Decision::Block, true, &["secret_access"]),
            row("d", RiskBand::Critical, 85, Decision::Block, false, &["secret_access", "network_external"]),
        ];
        let p = posture_from_rows(&rows);
        assert_eq!(p.total, 4);
        assert_eq!(p.allowed, 2); // a + approved c
        assert_eq!(p.in_review, 1); // b
        assert_eq!(p.blocked, 1); // d
        assert_eq!(p.approved, 1); // c
        assert_eq!(p.top_capabilities.get("network_external"), Some(&2)); // b + d
        assert_eq!(p.top_capabilities.get("secret_access"), Some(&1)); // d only (c approved)
        // allow/block ratio: (2 allowed) / (1 blocked) = 2.0
        assert_eq!(p.allow_block_ratio, Some(2.0));
    }

    #[test]
    fn allow_block_ratio_is_none_when_nothing_blocked() {
        let rows = vec![row("a", RiskBand::Low, 0, Decision::Allow, false, &[])];
        assert_eq!(posture_from_rows(&rows).allow_block_ratio, None);
    }

    #[test]
    fn top_risk_is_worst_first_and_excludes_allowed() {
        let rows = vec![
            row("a", RiskBand::Low, 0, Decision::Allow, false, &[]),
            row("b", RiskBand::High, 60, Decision::Ask, false, &[]),
            row("c", RiskBand::Critical, 90, Decision::Block, false, &[]),
            row("approved", RiskBand::Critical, 95, Decision::Block, true, &[]),
        ];
        let top = top_risk_from_rows(&rows, 10);
        assert_eq!(top.len(), 2); // allowed + approved excluded
        assert_eq!(top[0].id, "c"); // highest score first
        assert_eq!(top[1].id, "b");
    }
}
