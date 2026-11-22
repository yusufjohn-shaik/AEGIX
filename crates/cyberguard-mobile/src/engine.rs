use crate::android::DefaultAndroidAuditor;
use crate::error::MobileError;
use crate::ios::DefaultIosAuditor;
use crate::models::{MobileDocument, MobileFinding, MobileReport};
use crate::parser::MobileParser;
use crate::traits::{AndroidAuditor, IosAuditor, MobileScanner};
use async_trait::async_trait;
use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{SarifLog, SarifResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

/// Primary orchestrator engine for Mobile Security Static Analysis.
pub struct MobileEngine {
    pub baseline: Option<AegixBaseline>,
    pub release_mode: bool,
    pub android_auditor: Box<dyn AndroidAuditor>,
    pub ios_auditor: Box<dyn IosAuditor>,
}

impl Default for MobileEngine {
    fn default() -> Self {
        Self::new(false)
    }
}

impl MobileEngine {
    pub fn new(release_mode: bool) -> Self {
        Self {
            baseline: None,
            release_mode,
            android_auditor: Box::new(DefaultAndroidAuditor::new(release_mode)),
            ios_auditor: Box::new(DefaultIosAuditor::new(release_mode)),
        }
    }

    pub fn with_baseline(mut self, baseline: AegixBaseline) -> Self {
        self.baseline = Some(baseline);
        self
    }

    pub fn with_android_auditor(mut self, auditor: Box<dyn AndroidAuditor>) -> Self {
        self.android_auditor = auditor;
        self
    }

    pub fn with_ios_auditor(mut self, auditor: Box<dyn IosAuditor>) -> Self {
        self.ios_auditor = auditor;
        self
    }

    /// Generates an Aegix baseline snapshot from a mobile security report.
    pub fn generate_baseline(&self, report: &MobileReport, _target_path: &Path) -> AegixBaseline {
        let sarif = self.to_sarif(report).unwrap_or_else(|_| {
            SarifLog::new("Aegix Mobile Security Engine", env!("CARGO_PKG_VERSION"))
        });
        AegixBaseline::from_sarif(&sarif)
    }

    /// Filters findings in a mobile security report against an Aegix baseline snapshot.
    pub fn filter_baseline(report: &MobileReport, baseline: &AegixBaseline) -> MobileReport {
        let mut filtered = report.clone();
        let initial_count = filtered.findings.len();
        filtered
            .findings
            .retain(|f| !baseline.fingerprints.contains(&f.fingerprint));
        filtered.suppressed_findings_count = initial_count.saturating_sub(filtered.findings.len());
        filtered
    }

    /// Evaluates findings and applies baseline suppression if configured.
    fn evaluate_findings(
        &self,
        raw_findings: Vec<MobileFinding>,
        target_path: String,
        docs_count: usize,
        components_count: usize,
    ) -> MobileReport {
        let mut final_findings = Vec::new();
        let mut suppressed_count = 0;

        for finding in raw_findings {
            let is_suppressed = self
                .baseline
                .as_ref()
                .map(|b| b.fingerprints.contains(&finding.fingerprint))
                .unwrap_or(false);

            if is_suppressed {
                suppressed_count += 1;
            } else {
                final_findings.push(finding);
            }
        }

        MobileReport {
            target_path,
            total_documents_scanned: docs_count,
            total_components_evaluated: components_count,
            findings: final_findings,
            suppressed_findings_count: suppressed_count,
        }
    }

    /// Exports findings to OASIS SARIF v2.1.0 telemetry.
    pub fn to_sarif(&self, report: &MobileReport) -> Result<SarifLog, MobileError> {
        let mut sarif_log = SarifLog::new(
            "Aegix Mobile Security Static Analysis Engine",
            env!("CARGO_PKG_VERSION"),
        );

        for finding in &report.findings {
            let mut sarif_result = SarifResult::new(
                &finding.rule_id,
                finding.severity,
                format!(
                    "{}: {} Remediation: {}",
                    finding.title, finding.description, finding.remediation
                ),
            );

            sarif_result.confidence = Some(finding.confidence);
            sarif_result.add_location(
                finding.file_path.clone(),
                finding.line,
                Some(finding.column),
                Some(finding.line),
                Some(finding.column + 10),
            );

            let mut hasher = Sha256::new();
            hasher.update(finding.rule_id.as_bytes());
            hasher.update(b":");
            hasher.update(finding.file_path.as_bytes());
            hasher.update(b":");
            hasher.update(finding.location_path.as_bytes());
            hasher.update(b":");
            hasher.update(finding.description.as_bytes());
            let loc_hash = format!("{:x}", hasher.finalize());

            let mut fp_map = HashMap::new();
            fp_map.insert("logicalLocationTokenHash/v1".to_string(), loc_hash);
            fp_map.insert("sha256/v1".to_string(), finding.fingerprint.clone());
            sarif_result.partial_fingerprints = Some(fp_map);

            sarif_log.runs[0].results.push(sarif_result);
        }

        Ok(sarif_log)
    }
}

#[async_trait]
impl MobileScanner for MobileEngine {
    async fn scan(&self, documents: &[MobileDocument]) -> Result<MobileReport, MobileError> {
        let mut all_findings = Vec::new();
        let mut total_components = 0;

        for doc in documents {
            if let Some(manifest) = &doc.android_manifest {
                total_components += manifest.application.components.len();
                let findings = self.android_auditor.audit_manifest(
                    manifest,
                    &doc.file_path,
                    &doc.raw_content,
                )?;
                all_findings.extend(findings);
            }

            if let Some(net_cfg) = &doc.android_network_config {
                let findings = self.android_auditor.audit_network_config(
                    net_cfg,
                    &doc.file_path,
                    &doc.raw_content,
                )?;
                all_findings.extend(findings);
            }

            if let Some(plist) = &doc.ios_plist {
                total_components += plist.url_types.len() + plist.privacy_usage_descriptions.len();
                let findings =
                    self.ios_auditor
                        .audit_plist(plist, &doc.file_path, &doc.raw_content)?;
                all_findings.extend(findings);
            }

            if let Some(ent) = &doc.ios_entitlements {
                total_components += ent.keychain_access_groups.len();
                let findings =
                    self.ios_auditor
                        .audit_entitlements(ent, &doc.file_path, &doc.raw_content)?;
                all_findings.extend(findings);
            }
        }

        Ok(self.evaluate_findings(
            all_findings,
            "in-memory".to_string(),
            documents.len(),
            total_components,
        ))
    }

    async fn scan_file(&self, path: &Path) -> Result<MobileReport, MobileError> {
        let docs = MobileParser::parse_file(path)?;
        let mut report = self.scan(&docs).await?;
        report.target_path = path.to_string_lossy().to_string();
        Ok(report)
    }

    async fn scan_directory(&self, dir_path: &Path) -> Result<MobileReport, MobileError> {
        let mut all_docs = Vec::new();

        for entry in WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let p = entry.path();
            let file_name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            let is_candidate = file_name.ends_with(".apk")
                || file_name.ends_with(".ipa")
                || file_name == "androidmanifest.xml"
                || file_name.ends_with("network_security_config.xml")
                || file_name == "info.plist"
                || file_name.ends_with(".entitlements");

            if is_candidate {
                match MobileParser::parse_file(p) {
                    Ok(docs) => all_docs.extend(docs),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse mobile artifact at '{}': {}",
                            p.display(),
                            e
                        );
                    }
                }
            }
        }

        let mut report = self.scan(&all_docs).await?;
        report.target_path = dir_path.to_string_lossy().to_string();
        Ok(report)
    }

    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<MobileReport, MobileError> {
        let docs = MobileParser::parse_reader(reader, path_hint)?;
        let mut report = self.scan(&docs).await?;
        report.target_path = path_hint.to_string_lossy().to_string();
        Ok(report)
    }
}
