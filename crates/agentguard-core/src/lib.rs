//! agentguard-core
//!
//! Shared domain model for AgentGuard. Every adapter, scanner, and the risk
//! engine speak in these types — this crate has no I/O and no dependency on
//! any specific agent ecosystem. See BUILD_PLAN.md §3-6 for the design this
//! implements.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// The capability taxonomy. This is the common language every agent
/// ecosystem gets translated into — see BUILD_PLAN.md §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    // Filesystem
    ReadWorkspace,
    WriteWorkspace,
    ReadHome,
    WriteHome,
    ReadSsh,
    ReadCredentials,
    ReadBrowserData,
    ReadSystem,
    // Process
    ExecuteShell,
    SpawnProcess,
    ExecuteBinary,
    InstallPackage,
    // Network
    NetworkLocal,
    NetworkExternal,
    NetworkRestricted,
    NetworkUnrestricted,
    // Secrets
    EnvironmentVariables,
    SshKeys,
    CloudCredentials,
    ApiKeys,
    TokenStores,
    // Persistence
    Startup,
    Cron,
    Hook,
    ShellProfile,
    BackgroundProcess,
}

impl Capability {
    /// Capabilities that touch credential/secret material directly. Used by
    /// the risk engine as a distinct, heavily-weighted category regardless
    /// of which specific variant matched. This is deliberately broad — it
    /// includes API keys and tokens, which routinely flow through
    /// legitimate integrations (an MCP server sending its own bearer token
    /// to its own API is normal). For the narrower, much higher-signal
    /// case, see `is_raw_secret_material`.
    pub fn is_secret_access(self) -> bool {
        matches!(
            self,
            Capability::ReadSsh
                | Capability::ReadCredentials
                | Capability::ReadBrowserData
                | Capability::SshKeys
                | Capability::CloudCredentials
                | Capability::ApiKeys
                | Capability::TokenStores
        )
    }

    /// The narrow subset of `is_secret_access` that has essentially no
    /// legitimate reason to co-occur with outbound network access: raw SSH
    /// key material, stored OS/browser credentials. Unlike an API key
    /// (expected to be sent to its own service), there is no ordinary MCP
    /// server / skill workflow that reads an SSH private key or a browser's
    /// cookie store and then makes a network call. The risk engine treats
    /// this combination as the canonical exfiltration pattern — see
    /// BUILD_PLAN.md §4 and THREAT_MODEL.md archetype A1 — and does not
    /// let the general evidence cap soften it. This distinction exists
    /// because a v0 build of the risk engine, tested against a synthetic
    /// SSH-exfiltration fixture, initially scored it MEDIUM instead of
    /// CRITICAL: the broad `is_secret_access` category was capped together
    /// with shell/network/write-outside-workspace evidence on the
    /// assumption that combination is "normal for a dev tool," which is
    /// true for API keys but not for raw key material.
    pub fn is_raw_secret_material(self) -> bool {
        matches!(
            self,
            Capability::ReadSsh
                | Capability::SshKeys
                | Capability::ReadCredentials
                | Capability::ReadBrowserData
        )
    }

    pub fn is_persistence(self) -> bool {
        matches!(
            self,
            Capability::Startup
                | Capability::Cron
                | Capability::Hook
                | Capability::ShellProfile
                | Capability::BackgroundProcess
        )
    }

    pub fn is_process_execution(self) -> bool {
        matches!(
            self,
            Capability::ExecuteShell
                | Capability::SpawnProcess
                | Capability::ExecuteBinary
                | Capability::InstallPackage
        )
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// How a capability was determined to apply to an artifact. Surfaced to the
/// user explicitly — declared, inferred, and inherited findings carry very
/// different confidence and should never be presented identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceBasis {
    /// The artifact's own manifest/config declares this capability.
    Declared,
    /// Static analysis of source found code patterns implying this capability.
    Inferred,
    /// A dependency of this artifact has this capability; the artifact
    /// inherits it transitively even if its own code never invokes it.
    Inherited,
}

/// One piece of evidence that an artifact has a given capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityFinding {
    pub capability: Capability,
    pub basis: EvidenceBasis,
    /// Free-text, human-readable evidence: a matched import, a file path
    /// pattern, a manifest field. Never the raw contents of a secret, only
    /// the fact that a sensitive pattern matched — see BUILD_PLAN.md §11.
    pub evidence: String,
    /// Source location, when known: "path:line".
    pub location: Option<String>,
}

/// What kind of thing an artifact is, in the agent-agnostic model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    McpServer,
    Skill,
    Plugin,
    Hook,
    AgentConfig,
    Script,
    Dependency,
    Executable,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ArtifactKind::McpServer => "MCP server",
            ArtifactKind::Skill => "Skill",
            ArtifactKind::Plugin => "Plugin",
            ArtifactKind::Hook => "Hook",
            ArtifactKind::AgentConfig => "Agent config",
            ArtifactKind::Script => "Script",
            ArtifactKind::Dependency => "Dependency",
            ArtifactKind::Executable => "Executable",
        };
        write!(f, "{s}")
    }
}

/// Where an artifact was found / declared. Kept separate from identity so
/// the same logical artifact discovered via two agents dedupes cleanly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactSource {
    LocalPath(String),
    GitUrl(String),
    Registry { name: String, registry: String },
}

/// Publisher/repo identity used by the reputation discount in the risk
/// engine (BUILD_PLAN.md §4, §7). `verified` is only ever set by an explicit
/// verification step (org verification, signed release, npm provenance) —
/// never inferred.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublisherIdentity {
    pub name: Option<String>,
    pub repo_url: Option<String>,
    pub verified: bool,
}

/// The normalized representation of anything AgentGuard can reason about —
/// an MCP server, a skill, a plugin, a hook, etc. See BUILD_PLAN.md §3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Stable id: derived from (kind, name, source) — see `Artifact::compute_id`.
    pub id: String,
    pub kind: ArtifactKind,
    pub name: String,
    pub version: Option<String>,
    pub publisher: PublisherIdentity,
    pub source: ArtifactSource,
    /// SHA-256 of the artifact's content (file, or directory manifest hash
    /// for multi-file artifacts). None only if hashing hasn't run yet.
    pub content_hash: Option<String>,
    pub capabilities: Vec<CapabilityFinding>,
    /// Which agent(s) reference this artifact (e.g. "claude-code").
    pub discovered_by: BTreeSet<String>,
}

impl Artifact {
    pub fn compute_id(kind: ArtifactKind, name: &str, source: &ArtifactSource) -> String {
        let source_key = match source {
            ArtifactSource::LocalPath(p) => format!("local:{p}"),
            ArtifactSource::GitUrl(u) => format!("git:{u}"),
            ArtifactSource::Registry { name, registry } => format!("reg:{registry}:{name}"),
        };
        format!("{kind}:{name}:{source_key}")
    }

    /// Distinct capability set, deduped, sorted.
    pub fn capability_set(&self) -> BTreeSet<Capability> {
        self.capabilities.iter().map(|f| f.capability).collect()
    }
}

/// Final decision the policy engine renders for an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    AllowLog,
    Ask,
    Block,
    Quarantine,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Decision::Allow => "ALLOW",
            Decision::AllowLog => "ALLOW+LOG",
            Decision::Ask => "ASK",
            Decision::Block => "BLOCK",
            Decision::Quarantine => "QUARANTINE",
        };
        write!(f, "{s}")
    }
}

/// Coarse risk band the numeric score maps to before policy is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskBand {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskBand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RiskBand::Low => "LOW",
            RiskBand::Medium => "MEDIUM",
            RiskBand::High => "HIGH",
            RiskBand::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

impl RiskBand {
    /// Thresholds from BUILD_PLAN.md §4/§6. A score is inclusive-lower-bound
    /// banded; tune these against the eval corpus (§13), not by feel.
    pub fn from_score(score: i32) -> RiskBand {
        match score {
            i32::MIN..=24 => RiskBand::Low,
            25..=49 => RiskBand::Medium,
            50..=79 => RiskBand::High,
            _ => RiskBand::Critical,
        }
    }
}

/// One of the three onboarding presets from BUILD_PLAN.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionLevel {
    Quiet,
    Balanced,
    Strict,
}

impl ProtectionLevel {
    pub fn decision_for(self, band: RiskBand) -> Decision {
        use Decision::*;
        use ProtectionLevel::*;
        use RiskBand::*;
        match (self, band) {
            (Quiet, Low) => Allow,
            (Quiet, Medium) => Allow,
            (Quiet, High) => Ask,
            (Quiet, Critical) => Block,

            (Balanced, Low) => Allow,
            (Balanced, Medium) => AllowLog,
            (Balanced, High) => Ask,
            (Balanced, Critical) => Block,

            (Strict, Low) => Allow,
            (Strict, Medium) => Ask,
            (Strict, High) => Block,
            (Strict, Critical) => Block,
        }
    }
}

impl Default for ProtectionLevel {
    fn default() -> Self {
        ProtectionLevel::Balanced
    }
}

/// A transparent, inspectable breakdown of how a score was reached — this is
/// what a "View why" click in the UI renders. Never render a bare number
/// without this.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub static_evidence: i32,
    pub static_evidence_reasons: Vec<String>,
    pub reputation_discount: i32,
    pub reputation_reasons: Vec<String>,
    pub context_modifier: i32,
    pub context_reasons: Vec<String>,
    pub policy_override: Option<Decision>,
}

impl ScoreBreakdown {
    pub fn total(&self) -> i32 {
        (self.static_evidence - self.reputation_discount + self.context_modifier).max(0)
    }

    pub fn band(&self) -> RiskBand {
        RiskBand::from_score(self.total())
    }
}
