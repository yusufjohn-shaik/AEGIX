//! Canonical data models and deterministic Tri-Factor math for `cyberguard-risk`.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// Fine-grained static reachability classification for dependencies and code locations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityStatus {
    /// Target crate/symbol is directly invoked along a verified BFS call path from an entrypoint.
    VerifiedReachable,
    /// Target crate/file is imported or used in non-test production source files.
    ImportedInSource,
    /// Target is declared in normal `[dependencies]` (or proc-macro) without direct src token match.
    DirectDeclared,
    /// Target is declared in `[build-dependencies]` (`build.rs` / `*-sys` executed at compile time).
    BuildDependency,
    /// Target is an indirect dependency reachable via an active non-dev parent dependency edge.
    TransitiveReachable,
    /// Target exists solely in `[dev-dependencies]`, `tests/`, `benches/`, `examples/`, or `#[cfg(test)]`.
    DevOrTestOnly,
    /// Target is orphaned in `Cargo.lock` or disconnected from all production entrypoints.
    Unreachable,
    /// Non-Rust / non-Cargo finding where Rust call-graph analysis is not applicable (conservative 1.0).
    NotApplicable,
}

impl ReachabilityStatus {
    /// Deterministic reachability multiplier in `[0.0, 1.0]`.
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::VerifiedReachable => 1.00,
            Self::ImportedInSource => 0.85,
            Self::DirectDeclared => 0.70,
            Self::BuildDependency => 0.60,
            Self::TransitiveReachable => 0.50,
            Self::DevOrTestOnly => 0.10,
            Self::Unreachable => 0.00,
            Self::NotApplicable => 1.00,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifiedReachable => "verified_reachable",
            Self::ImportedInSource => "imported_in_source",
            Self::DirectDeclared => "direct_declared",
            Self::BuildDependency => "build_dependency",
            Self::TransitiveReachable => "transitive_reachable",
            Self::DevOrTestOnly => "dev_or_test_only",
            Self::Unreachable => "unreachable",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Calibrated remediation priority tier preventing EPSS multiplicative suppression of critical reachable CVEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Critical,
    High,
    Medium,
    Low,
    Suppressed,
}

impl RiskTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Suppressed => "suppressed",
        }
    }
}

/// Provenance of the CVSS/EPSS inputs used for scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreSource {
    SarifProperty,
    AdvisoryDb,
    ExternalEpssDb,
    CweHeuristic,
    SeverityDefault,
}

impl ScoreSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SarifProperty => "sarif_property",
            Self::AdvisoryDb => "advisory_db",
            Self::ExternalEpssDb => "external_epss_db",
            Self::CweHeuristic => "cwe_heuristic",
            Self::SeverityDefault => "severity_default",
        }
    }
}

/// Provenance of Cargo workspace dependency graph resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataSource {
    CargoMetadata,
    PureRustFallback,
    NotApplicable,
}

/// Sanitizes non-finite floats (`NaN`, `+/-inf`) before bounded clamping.
pub fn sanitize_clamped(val: f64, min: f64, max: f64, fallback: f64) -> f64 {
    if val.is_finite() {
        val.clamp(min, max)
    } else {
        fallback.clamp(min, max)
    }
}

/// Computes deterministic integer basis points (`0..=1000`) and 2-decimal Tri-Factor score (`0.00..=10.00`)
/// matching `cyberguard_core::sarif::SarifResult::with_tri_factor`.
pub fn compute_tri_factor_bps(
    cvss: f64,
    epss: f64,
    reachability: f64,
) -> (f64, f64, f64, u32, f64) {
    let c = sanitize_clamped(cvss, 0.0, 10.0, 0.0);
    let e = sanitize_clamped(epss, 0.0, 1.0, 0.0);
    let r = sanitize_clamped(reachability, 0.0, 1.0, 0.0);

    let raw_bps = (c * e * r * 100.0).round();
    let score_bps = if raw_bps.is_finite() && raw_bps >= 0.0 {
        (raw_bps as u32).min(1000)
    } else {
        0
    };
    let tri_factor_score = f64::from(score_bps) / 100.0;
    (c, e, r, score_bps, tri_factor_score)
}

/// Classifies a finding into a `RiskTier` using integer basis points plus a High-CVSS Reachability Safety Floor.
pub fn classify_risk_tier(
    cvss: f64,
    epss: f64,
    reachability: f64,
    score_bps: u32,
    status: ReachabilityStatus,
) -> RiskTier {
    if status == ReachabilityStatus::Unreachable
        || (status == ReachabilityStatus::DevOrTestOnly && score_bps < 10)
    {
        return RiskTier::Suppressed;
    }

    if score_bps >= 600 || (cvss >= 9.0 && reachability >= 0.85 && epss >= 0.10) {
        RiskTier::Critical
    } else if score_bps >= 250 || (cvss >= 7.0 && reachability >= 0.70) {
        RiskTier::High
    } else if score_bps >= 50 || (cvss >= 4.0 && reachability >= 0.50) {
        RiskTier::Medium
    } else {
        RiskTier::Low
    }
}

/// Detailed mathematical breakdown for a single prioritized finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriFactorBreakdown {
    pub cvss: f64,
    pub epss: f64,
    pub reachability: f64,
    pub tri_factor_score: f64,
    pub score_bps: u32,
    pub status: ReachabilityStatus,
    pub tier: RiskTier,
    pub score_source: ScoreSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_trace: Vec<String>,
    pub evidence: String,
}

/// Unified security finding enriched with Tri-Factor scoring and reachability evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrioritizedFinding {
    pub id: String,
    pub rule_id: String,
    pub package_or_target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub summary: String,
    pub breakdown: TriFactorBreakdown,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
}

/// Complete Tri-Factor prioritization report across a workspace or SARIF bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskPrioritizationReport {
    pub target_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_source: Option<MetadataSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub workspace_packages: usize,
    pub analyzed_nodes: usize,
    pub total_findings: usize,
    pub suppressed_count: usize,
    pub suppressed_unreachable: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings: Vec<PrioritizedFinding>,
}

impl RiskPrioritizationReport {
    /// Recomputes summary tier counts cleanly from `self.findings`.
    pub fn recompute_counts(&mut self) {
        self.total_findings = self.findings.len();
        self.suppressed_count = 0;
        self.suppressed_unreachable = 0;
        self.critical_count = 0;
        self.high_count = 0;
        self.medium_count = 0;
        self.low_count = 0;

        for f in &self.findings {
            match f.breakdown.tier {
                RiskTier::Critical => self.critical_count += 1,
                RiskTier::High => self.high_count += 1,
                RiskTier::Medium => self.medium_count += 1,
                RiskTier::Low => self.low_count += 1,
                RiskTier::Suppressed => {
                    self.suppressed_count += 1;
                    if f.breakdown.status == ReachabilityStatus::Unreachable {
                        self.suppressed_unreachable += 1;
                    }
                }
            }
        }
    }
}

/// Configuration options controlling Tri-Factor prioritization execution.
#[derive(Debug, Clone)]
pub struct RiskScanOptions {
    pub min_score: f64,
    pub show_suppressed: bool,
    pub use_cargo_metadata: bool,
    pub external_epss_db: Option<PathBuf>,
}

impl Default for RiskScanOptions {
    fn default() -> Self {
        Self {
            min_score: 0.0,
            show_suppressed: false,
            use_cargo_metadata: true,
            external_epss_db: None,
        }
    }
}

/// Resolved Cargo dependency classification within the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyScope {
    NormalDirect,
    BuildDirect,
    DevDirect,
    NormalTransitive,
    BuildTransitive,
    DevTransitive,
    Orphaned,
}

/// Entrypoint source target descriptor inside a workspace crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceTargetRoot {
    pub crate_name: String,
    pub crate_ident: String,
    pub is_library: bool,
    pub is_proc_macro: bool,
    pub src_path: PathBuf,
    pub manifest_dir: PathBuf,
}

/// Normalized dependency package metadata extracted from `cargo metadata` or fallback manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyNode {
    pub name: String,
    pub normalized_ident: String,
    pub version: String,
    pub is_workspace_member: bool,
    pub is_proc_macro: bool,
    pub scope: DependencyScope,
    /// All Rust import identifiers (package ident + any `[dependencies]` `rename` aliases).
    pub import_idents: BTreeSet<String>,
    /// Parent packages in the dependency graph pointing to this package.
    pub depended_by: BTreeSet<String>,
}

/// Complete resolved dependency graph for a Rust Cargo project or workspace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceDependencyGraph {
    pub workspace_root: PathBuf,
    pub metadata_source: Option<MetadataSource>,
    pub warnings: Vec<String>,
    pub target_roots: Vec<WorkspaceTargetRoot>,
    pub packages: BTreeMap<String, DependencyNode>,
}
