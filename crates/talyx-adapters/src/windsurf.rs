//! Windsurf/Devin Desktop adapter. "Windsurf" was rebranded to "Devin
//! Desktop" on 2026-06-02 (Cognition, which also makes Devin, acquired
//! Windsurf in 2025) — shipped as an automatic over-the-air update, no
//! reinstall, no new install path. This module is kept under its
//! original "windsurf" name/agent id rather than renamed, since that's
//! still the literal path component and is how the product is
//! referenced across this codebase's trust seed/tests; "Devin Desktop"
//! is the current product name for anyone searching for it.
//!
//! **Hooks: confirmed absent, not a hedge.** An earlier note in this
//! codebase's history claimed Devin Desktop's hooks use "the same format
//! as Claude Code hooks" — that did not survive re-verification and was
//! retracted. Re-verified again 2026-09-13, this time exhaustively rather
//! than by spot-check: fetched `docs.devin.ai/desktop/devin-desktop-faq`
//! (the FAQ page Cognition maintains specifically for this rebrand) and
//! searched its full rendered text for the substring "hook" — zero
//! matches. The same page's own migration table (quoted below) documents
//! every extensibility surface the product has: rules, workflows, skills,
//! plans, MCP servers, extensions. No hooks entry exists in that table
//! either. Cascade/Devin Local has no hook mechanism; this isn't a gap,
//! it's a narrower surface than Claude Code or even Cursor.
//!
//! **MCP config path — trust the machine over the doc.** The FAQ page
//! states the config lives at `~/.codeium/mcp_config.json`. Direct
//! inspection of a real, actively-used installation shows that path does
//! NOT exist, while `~/.codeium/windsurf/mcp_config.json` does (real
//! content, real mtime). The FAQ is wrong, out of date, or describes a
//! rollout state not yet reached — the path this adapter has always used
//! is the one actually in use. Left unchanged. User scope ONLY, no
//! project-scoped equivalent (confirmed directly, not assumed). Same
//! `{ "mcpServers": { "<name>": { command, args, env } } }` shape,
//! reusing mcp_config.rs — the remote-server field is documented as
//! accepting either `url` or `serverUrl`, both handled by the shared
//! parser already.
//!
//! **Rules, workflows, skills — the FAQ's own migration table**, quoted
//! verbatim from the live page (2026-09-13):
//!
//! ```text
//! .windsurfrules (root file)  -> .devin/rules/ (directory)  Project rules (single-file legacy format)
//! .windsurf/rules/            -> .devin/rules/              Project rules
//! .windsurf/workflows/        -> .devin/workflows/          Workflows
//! .windsurf/skills/           -> .devin/skills/             Skills
//! .windsurf/plans/            -> .devin/plans/              Plans
//! ```
//! "The application already supports `.devin/` as the primary workspace
//! directory and falls back to `.windsurf/` for backward compatibility."
//! Directory-based rules are individual `.md` files with YAML frontmatter
//! activation triggers (always-on, model-decision, glob-based, manual);
//! `.devin/rules/` "is the preferred location and takes precedence" over
//! `.windsurf/rules/`. This adapter scans BOTH directories unconditionally
//! rather than encoding that precedence — a scanner's job is not to miss
//! content because a newer path shadows it, and precedence rules are
//! exactly the kind of vendor claim that's already been wrong once here
//! (see the MCP path note above).
//!
//! The legacy single-file `.windsurfrules` is still fingerprinted (FAQ:
//! "the legacy `.windsurfrules` file at your workspace root is still
//! read"). A `.devin/rules` FILE (not directory) is also scanned
//! defensively if one is found on disk, even though the FAQ says no such
//! single-file equivalent exists ("There is no `.devinrules` single-file
//! equivalent") — the same reasoning as the MCP path: don't let an
//! unverified vendor claim be the reason a real file on disk goes
//! unscanned.
//!
//! **Skills format** cross-checked against `docs.devin.ai`'s CLI skills
//! reference (`cli/extensibility/skills/creating-skills`), since the FAQ
//! table names the directory but not the file shape: `<skills-dir>/<name
//! (the invocation id)>/SKILL.md`, optional YAML frontmatter + prompt
//! body — identical to every other agent's SKILL.md convention already
//! handled in this crate. Confirmed for real (not just documented): this
//! machine's `~/.codeium/windsurf/skills/` is real and populated with
//! this exact `<name>/SKILL.md` shape, which is also the FAQ's stated
//! "Global skills" location — so that user-scope directory is discovered
//! here too.
//!
//! **Deliberately NOT built, documented as known gaps rather than
//! silently claimed as covered:**
//! - `.devin/plans/` / `.windsurf/plans/` — task/session tracking
//!   artifacts, not confirmed to carry agent-directing prose the way
//!   rules/workflows do; lower security relevance.
//! - Global workflows (`~/.codeium/windsurf/global_workflows/` per the
//!   FAQ) — that exact path does NOT exist on a real, actively-used
//!   installation; instead an unexplained, undocumented
//!   `~/.codeium/windsurf/windsurf/workflows/` was found with real
//!   content. Unlike the MCP path and the global-skills path, this one
//!   isn't corroborated by a second signal (docs *and* reality agree on
//!   MCP and global-skills paths; here they disagree and the real path's
//!   purpose is unconfirmed — could be a workspace-keyed cache, not a
//!   stable global location). Not built on a single unconfirmed
//!   observation.
//! - Enterprise system-level paths (`/Library/Application
//!   Support/Devin/`, `C:\ProgramData\Devin\`, `/etc/devin/`) —
//!   admin-deployed, machine-wide; out of scope for this local-first
//!   per-project/per-user tool.

use crate::mcp_config::parse_mcp_servers_json;
use crate::{AgentAdapter, ConfigSourceKind, DiscoveredArtifact};
use talyx_core::{Artifact, ArtifactKind, ArtifactSource, PublisherIdentity};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub struct WindsurfAdapter;

impl AgentAdapter for WindsurfAdapter {
    fn agent_id(&self) -> &'static str {
        "windsurf"
    }

    fn agent_name(&self) -> &'static str {
        "Windsurf"
    }

    fn detect(&self, project_root: &Path) -> bool {
        let home = dirs::home_dir();
        project_root.join(".windsurfrules").exists()
            || project_root.join(".windsurf").exists()
            || project_root.join(".devin").exists()
            || home
                .as_ref()
                .map(|h| h.join(".codeium").join("windsurf").exists())
                .unwrap_or(false)
    }

    fn discover(&self, project_root: &Path) -> Vec<DiscoveredArtifact> {
        let mut out = Vec::new();
        let home = dirs::home_dir();

        // User-scope only — see this module's doc comment for why there's
        // no project-scope equivalent to also check.
        if let Some(h) = &home {
            let windsurf_home = h.join(".codeium").join("windsurf");
            out.extend(parse_mcp_servers_json(
                &windsurf_home.join("mcp_config.json"),
                h,
                ConfigSourceKind::WindsurfMcpJson,
                "mcpServers",
                "windsurf",
                "Windsurf",
            ));
            out.extend(discover_skills_dir(
                &windsurf_home.join("skills"),
                "global-skills",
            ));
        }

        let rules_path = project_root.join(".windsurfrules");
        if rules_path.exists() {
            out.push(fingerprint(&rules_path, ".windsurfrules", ArtifactKind::AgentConfig));
        }

        // Defensive: a `.devin/rules` FILE isn't a documented format (the
        // directory below is), but don't let that stop us from scanning a
        // real file if one exists — see module doc comment.
        let devin_rules_file = project_root.join(".devin").join("rules");
        if devin_rules_file.is_file() {
            out.push(fingerprint(&devin_rules_file, ".devin/rules", ArtifactKind::AgentConfig));
        }

        // Directory-based rules: `.devin/rules/` preferred, `.windsurf/rules/`
        // fallback — both scanned unconditionally, see module doc comment.
        out.extend(discover_markdown_dir(
            &project_root.join(".devin").join("rules"),
            "devin/rules",
        ));
        out.extend(discover_markdown_dir(
            &project_root.join(".windsurf").join("rules"),
            "windsurf/rules",
        ));

        out.extend(discover_markdown_dir(
            &project_root.join(".devin").join("workflows"),
            "devin/workflows",
        ));
        out.extend(discover_markdown_dir(
            &project_root.join(".windsurf").join("workflows"),
            "windsurf/workflows",
        ));

        out.extend(discover_skills_dir(
            &project_root.join(".devin").join("skills"),
            "devin/skills",
        ));
        out.extend(discover_skills_dir(
            &project_root.join(".windsurf").join("skills"),
            "windsurf/skills",
        ));

        out
    }
}

/// Every loose `.md` file directly under `dir` — used for `rules/` and
/// `workflows/` directories, both individually-content-scanned
/// instruction files with no shared wrapper format.
fn discover_markdown_dir(dir: &Path, label: &str) -> Vec<DiscoveredArtifact> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rule.md");
        out.push(fingerprint(
            &path,
            &format!("{label}/{name}"),
            ArtifactKind::AgentConfig,
        ));
    }
    out
}

/// Every `<dir>/<name>/SKILL.md` subdirectory — see module doc comment
/// for the format citation.
fn discover_skills_dir(dir: &Path, label: &str) -> Vec<DiscoveredArtifact> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let skill_dir = entry.path();
        if !skill_dir.is_dir() || !skill_dir.join("SKILL.md").is_file() {
            continue;
        }
        let name = skill_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("skill");
        out.push(fingerprint(
            &skill_dir,
            &format!("{label}/{name}"),
            ArtifactKind::Skill,
        ));
    }
    out
}

fn fingerprint(path: &Path, marker: &str, kind: ArtifactKind) -> DiscoveredArtifact {
    let source = ArtifactSource::LocalPath(path.display().to_string());
    let mut discovered_by = BTreeSet::new();
    discovered_by.insert("windsurf".to_string());
    let artifact = Artifact {
        id: Artifact::compute_id(kind, marker, &source),
        kind,
        name: marker.to_string(),
        version: None,
        publisher: PublisherIdentity::default(),
        source,
        content_hash: None,
        capabilities: vec![],
        discovered_by,
    };
    DiscoveredArtifact {
        display_location: path.display().to_string(),
        // Content-scanned as an instruction file (AgentConfig) or a
        // skill (Skill) — see cursor.rs's config_fingerprint /
        // antigravity.rs's plugin_skill_fingerprint for the rationale.
        scan_root: Some(path.to_path_buf()),
        artifact,
        launch: None,
        config_source: None,
        raw_config_entry: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "talyx-windsurf-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    #[test]
    fn detects_project_scope_windsurfrules() {
        let dir = unique_temp_dir("detect");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".windsurfrules"), "be helpful").unwrap();

        assert!(WindsurfAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_never_looks_for_a_project_scope_mcp_config() {
        // The defining difference from Cursor/Claude Code: no
        // .windsurf/mcp_config.json project-scope file exists in
        // Windsurf's own design, so writing one here must have zero
        // effect on discovery -- proves this adapter doesn't accidentally
        // grow a project-scope path some future edit might add by
        // copy-pasting Cursor's shape without checking.
        let dir = unique_temp_dir("no-project-scope");
        let windsurf_dir = dir.join(".windsurf");
        std::fs::create_dir_all(&windsurf_dir).unwrap();
        let config = serde_json::json!({
            "mcpServers": { "example": { "command": "some-binary", "args": [] } }
        });
        std::fs::write(
            windsurf_dir.join("mcp_config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let discovered = WindsurfAdapter.discover(&dir);
        let project_scoped: Vec<_> = discovered
            .iter()
            .filter(|d| d.artifact.kind == ArtifactKind::McpServer)
            .filter(|d| {
                d.config_source
                    .as_ref()
                    .map(|cs| cs.path.starts_with(&dir))
                    .unwrap_or(false)
            })
            .collect();
        assert!(project_scoped.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_project_scope_dot_devin_directory() {
        let dir = unique_temp_dir("detect-devin");
        std::fs::create_dir_all(dir.join(".devin")).unwrap();

        assert!(WindsurfAdapter.detect(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_devin_rules_directory_and_falls_back_to_windsurf_rules() {
        let dir = unique_temp_dir("rules-dirs");
        std::fs::create_dir_all(dir.join(".devin").join("rules")).unwrap();
        std::fs::create_dir_all(dir.join(".windsurf").join("rules")).unwrap();
        std::fs::write(
            dir.join(".devin").join("rules").join("style.md"),
            "Always use tabs.",
        )
        .unwrap();
        std::fs::write(
            dir.join(".windsurf").join("rules").join("legacy.md"),
            "Legacy rule content.",
        )
        .unwrap();

        let discovered = WindsurfAdapter.discover(&dir);
        assert!(discovered
            .iter()
            .any(|d| d.artifact.kind == ArtifactKind::AgentConfig
                && d.artifact.name == "devin/rules/style.md"));
        assert!(discovered
            .iter()
            .any(|d| d.artifact.kind == ArtifactKind::AgentConfig
                && d.artifact.name == "windsurf/rules/legacy.md"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_dot_devin_rules_file_defensively_even_though_undocumented() {
        let dir = unique_temp_dir("rules-file");
        std::fs::create_dir_all(dir.join(".devin")).unwrap();
        std::fs::write(dir.join(".devin").join("rules"), "single-file rules content").unwrap();

        let discovered = WindsurfAdapter.discover(&dir);
        let found = discovered
            .iter()
            .find(|d| d.artifact.kind == ArtifactKind::AgentConfig && d.artifact.name == ".devin/rules");
        assert!(found.is_some());
        assert_eq!(found.unwrap().scan_root.as_deref(), Some(dir.join(".devin").join("rules").as_path()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_workflows_from_both_devin_and_windsurf_directories() {
        let dir = unique_temp_dir("workflows");
        std::fs::create_dir_all(dir.join(".devin").join("workflows")).unwrap();
        std::fs::create_dir_all(dir.join(".windsurf").join("workflows")).unwrap();
        std::fs::write(
            dir.join(".devin").join("workflows").join("review.md"),
            "---\nauto_execution_mode: 0\n---\nReview the code.",
        )
        .unwrap();
        std::fs::write(
            dir.join(".windsurf").join("workflows").join("deploy.md"),
            "Deploy the app.",
        )
        .unwrap();

        let discovered = WindsurfAdapter.discover(&dir);
        assert!(discovered
            .iter()
            .any(|d| d.artifact.kind == ArtifactKind::AgentConfig
                && d.artifact.name == "devin/workflows/review.md"));
        assert!(discovered
            .iter()
            .any(|d| d.artifact.kind == ArtifactKind::AgentConfig
                && d.artifact.name == "windsurf/workflows/deploy.md"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_a_project_scope_skill_as_skill_kind_with_directory_scan_root() {
        let dir = unique_temp_dir("project-skill");
        let skill_dir = dir.join(".devin").join("skills").join("shady-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: shady-skill\n---\nDo something.",
        )
        .unwrap();

        let discovered = WindsurfAdapter.discover(&dir);
        let found = discovered
            .iter()
            .find(|d| d.artifact.kind == ArtifactKind::Skill && d.artifact.name == "devin/skills/shady-skill");
        assert!(found.is_some());
        assert_eq!(found.unwrap().scan_root.as_deref(), Some(skill_dir.as_path()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_directory_without_skill_md_is_not_treated_as_a_skill() {
        let dir = unique_temp_dir("not-a-skill");
        std::fs::create_dir_all(dir.join(".devin").join("skills").join("just-a-folder")).unwrap();
        std::fs::write(
            dir.join(".devin")
                .join("skills")
                .join("just-a-folder")
                .join("notes.txt"),
            "not a skill",
        )
        .unwrap();

        // Filtered to this test's own temp dir: the real dev machine this
        // suite runs on has a genuinely populated
        // ~/.codeium/windsurf/skills/ (see module doc comment), which
        // discover() also scans since dirs::home_dir() can't be mocked
        // here -- an unscoped assertion would spuriously fail on it.
        let discovered = WindsurfAdapter.discover(&dir);
        assert!(!discovered.iter().any(|d| d.artifact.kind == ArtifactKind::Skill
            && d.scan_root.as_ref().map(|p| p.starts_with(&dir)).unwrap_or(false)));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discovers_global_skills_under_the_codeium_windsurf_directory() {
        // Can't redirect dirs::home_dir() in a unit test, so this proves
        // the helper function's own filtering logic (SKILL.md required,
        // non-skill entries ignored) rather than the home-dir wiring --
        // the wiring itself is exercised for real on a machine that has
        // ~/.codeium/windsurf/skills/ populated (confirmed during this
        // adapter's research).
        let dir = unique_temp_dir("global-skills-helper");
        let skills_root = dir.join("skills");
        std::fs::create_dir_all(skills_root.join("arkcli-doctor")).unwrap();
        std::fs::write(
            skills_root.join("arkcli-doctor").join("SKILL.md"),
            "---\nname: arkcli-doctor\n---\nDiagnose.",
        )
        .unwrap();
        std::fs::write(skills_root.join(".arkcli-managed-skills.json"), "{}").unwrap();

        let found = discover_skills_dir(&skills_root, "global-skills");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].artifact.name, "global-skills/arkcli-doctor");
        assert_eq!(found[0].artifact.kind, ArtifactKind::Skill);

        std::fs::remove_dir_all(&dir).ok();
    }
}
