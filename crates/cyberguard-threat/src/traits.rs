//! Trait definitions establishing contracts for Threat Modeling and ATT&CK Mapping.

#![deny(unsafe_code)]

use crate::error::ThreatError;
use crate::models::{MitreTactic, MitreTechnique, StrideCategory, ThreatFinding, ThreatReport};
use async_trait::async_trait;
use cyberguard_core::sarif::SarifLog;
use std::io::Read;
use std::path::Path;

/// Primary orchestrator trait for Threat Modeling and Matrix generation.
#[async_trait]
pub trait ThreatScanner: Send + Sync {
    /// Ingests pre-parsed threat findings and evaluates matrices, STRIDE, and scores.
    async fn scan_findings(&self, findings: &[ThreatFinding]) -> Result<ThreatReport, ThreatError>;

    /// Ingests and parses a raw SARIF v2.1.0 JSON string.
    async fn scan_sarif(&self, sarif_json: &str) -> Result<ThreatReport, ThreatError>;

    /// Ingests a pre-parsed SARIF log structure.
    async fn scan_sarif_log(&self, sarif: &SarifLog) -> Result<ThreatReport, ThreatError>;

    /// Ingests findings or SARIF data from a generic stream reader (e.g. STDIN or memory buffer).
    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
    ) -> Result<ThreatReport, ThreatError>;

    /// Scans a SARIF log or report file on the local filesystem.
    async fn scan_file(&self, path: &Path) -> Result<ThreatReport, ThreatError>;
}

/// Static and dynamic mapper for MITRE ATT&CK Tactics and Techniques.
pub trait AttackMapper: Send + Sync {
    /// Maps a finding's rule ID and CWE identifiers to ATT&CK tactics and technique IDs.
    fn map_finding_to_techniques(
        &self,
        rule_id: &str,
        cwes: &[u32],
    ) -> (Vec<MitreTactic>, Vec<String>);

    /// Retrieves detailed technique metadata by technique ID (e.g., "T1190").
    fn get_technique_details(&self, technique_id: &str) -> Option<MitreTechnique>;

    /// Returns all supported techniques in this mapper's catalog.
    fn all_techniques(&self) -> &[MitreTechnique];

    /// Returns all techniques belonging to a specific tactic.
    fn techniques_for_tactic(&self, tactic: MitreTactic) -> Vec<&MitreTechnique>;
}

/// Classifier for STRIDE Threat Modeling categories.
pub trait StrideClassifier: Send + Sync {
    /// Classifies a finding into STRIDE categories based on rule identifiers and CWEs.
    fn classify_finding(&self, rule_id: &str, cwes: &[u32]) -> Vec<StrideCategory>;

    /// Maps a security property violation name to a STRIDE category.
    fn classify_by_violation(&self, property: &str) -> Option<StrideCategory>;

    /// Returns human-readable description and remediation guidance for a STRIDE category.
    fn get_stride_guidance(&self, category: StrideCategory) -> &'static str;
}
