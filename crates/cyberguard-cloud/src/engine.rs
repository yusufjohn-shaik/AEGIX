//! CloudEngine facade orchestrating multi-cloud parsing, CSPM auditing,
//! CIEM auditing, and OASIS SARIF v2.1.0 telemetry export.

use crate::ciem::DefaultCiemAuditor;
use crate::cspm::DefaultCspmAuditor;
use crate::error::CloudError;
use crate::models::{CloudAuditReport, CloudConfig};
use crate::parser::CloudParser;
use crate::traits::{CiemAuditor, CloudScanner, CspmAuditor};
use async_trait::async_trait;
use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{SarifLog, SarifResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

pub struct CloudEngine {
    cspm_auditor: Box<dyn CspmAuditor>,
    ciem_auditor: Box<dyn CiemAuditor>,
}

impl Default for CloudEngine {
    fn default() -> Self {
        Self {
            cspm_auditor: Box::new(DefaultCspmAuditor),
            ciem_auditor: Box::new(DefaultCiemAuditor),
        }
    }
}

#[async_trait]
impl CloudScanner for CloudEngine {
    async fn scan(&self, config: &CloudConfig) -> Result<CloudAuditReport, CloudError> {
        let mut findings = Vec::new();
        findings.extend(self.cspm_auditor.audit_posture(&config.resources)?);
        findings.extend(
            self.ciem_auditor
                .audit_entitlements(&config.policies, &config.resources)?,
        );

        Ok(CloudAuditReport {
            provider: config.detected_provider,
            total_resources_evaluated: config.resources.len(),
            total_policies_evaluated: config.policies.len(),
            findings,
        })
    }

    async fn scan_file(&self, path: &Path) -> Result<CloudAuditReport, CloudError> {
        let config = CloudParser::parse_path(path)?;
        self.scan(&config).await
    }
}

impl CloudEngine {
    /// Computes deterministic SHA-256 location fingerprint for a finding.
    pub fn compute_fingerprint(finding: &crate::models::CloudFinding) -> String {
        let mut hasher = Sha256::new();
        hasher.update(finding.rule_id.as_bytes());
        hasher.update(finding.resource_id.as_bytes());
        hasher.update(finding.configuration_path.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Generates a new baseline snapshot from an audit report.
    pub fn generate_baseline(
        &self,
        report: &CloudAuditReport,
        target_path: &Path,
    ) -> AegixBaseline {
        let sarif = self.to_sarif(report, target_path, None);
        AegixBaseline::from_sarif(&sarif)
    }

    /// Filters findings in an audit report against a baseline snapshot.
    pub fn filter_baseline(
        report: &CloudAuditReport,
        baseline: &AegixBaseline,
    ) -> CloudAuditReport {
        let filtered_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| {
                !baseline
                    .fingerprints
                    .contains(&Self::compute_fingerprint(f))
            })
            .cloned()
            .collect();

        CloudAuditReport {
            provider: report.provider,
            total_resources_evaluated: report.total_resources_evaluated,
            total_policies_evaluated: report.total_policies_evaluated,
            findings: filtered_findings,
        }
    }

    /// Formats audit findings into OASIS SARIF v2.1.0 telemetry with SHA-256 location
    /// fingerprints and applies Aegix baseline suppression.
    pub fn to_sarif(
        &self,
        report: &CloudAuditReport,
        target_path: &Path,
        baseline: Option<&AegixBaseline>,
    ) -> SarifLog {
        let mut log = SarifLog::new("Aegix Cloud Posture Engine", env!("CARGO_PKG_VERSION"));

        for finding in &report.findings {
            let fingerprint = Self::compute_fingerprint(finding);

            // Check baseline snapshot suppression
            if let Some(base) = baseline {
                if base.fingerprints.contains(&fingerprint) {
                    continue;
                }
            }

            let mut sarif_result =
                SarifResult::new(&finding.rule_id, finding.severity, &finding.description);
            sarif_result.confidence = Some(finding.confidence);
            sarif_result.add_location(
                target_path.to_string_lossy().to_string(),
                1,
                Some(1),
                None,
                None,
            );

            let mut fp_map = HashMap::new();
            fp_map.insert("sha256/v1".to_string(), fingerprint.clone());
            fp_map.insert("logicalLocationTokenHash/v1".to_string(), fingerprint);
            sarif_result.partial_fingerprints = Some(fp_map);

            log.add_result(sarif_result);
        }

        log
    }

    /// Formats audit findings into a clean, human-readable terminal output.
    pub fn format_terminal(&self, report: &CloudAuditReport) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "\n☁️  AEGIX CLOUD SECURITY & IAM POSTURE AUDIT ({})\n",
            report.provider
        ));
        out.push_str(&format!(
            "Evaluated: {} resources, {} policies | Findings: {}\n",
            report.total_resources_evaluated,
            report.total_policies_evaluated,
            report.findings.len()
        ));
        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );

        if report.findings.is_empty() {
            out.push_str(
                "✅ No cloud security misconfigurations or excessive entitlements detected!\n",
            );
        } else {
            for f in &report.findings {
                out.push_str(&format!("[{:?}] {} - {}\n", f.severity, f.rule_id, f.title));
                out.push_str(&format!(
                    "  Resource: {} ({})\n",
                    f.resource_id, f.configuration_path
                ));
                out.push_str(&format!("  Details:  {}\n", f.description));
                out.push_str(&format!("  Remedy:   {}\n\n", f.remediation));
            }
        }
        out
    }
}
