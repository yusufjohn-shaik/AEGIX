use crate::error::IacError;
use crate::k8s::DefaultK8sAuditor;
use crate::models::{IacDocument, IacReport, IacResource};
use crate::parser::IacParser;
use crate::terraform::DefaultTerraformAuditor;
use crate::traits::{IacScanner, K8sAuditor, TerraformAuditor};
use async_trait::async_trait;
use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

/// Main facade coordinating parsing, Kubernetes audits, and Terraform audits.
pub struct IacEngine {
    k8s_auditor: Box<dyn K8sAuditor>,
    terraform_auditor: Box<dyn TerraformAuditor>,
}

impl Default for IacEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl IacEngine {
    pub fn new() -> Self {
        Self {
            k8s_auditor: Box::new(DefaultK8sAuditor),
            terraform_auditor: Box::new(DefaultTerraformAuditor),
        }
    }

    pub fn with_auditors(k8s: Box<dyn K8sAuditor>, terraform: Box<dyn TerraformAuditor>) -> Self {
        Self {
            k8s_auditor: k8s,
            terraform_auditor: terraform,
        }
    }

    /// Evaluates in-memory pre-parsed documents.
    pub fn evaluate_documents(&self, documents: &[IacDocument]) -> Result<IacReport, IacError> {
        let mut findings = Vec::new();
        let mut total_resources = 0;

        for doc in documents {
            let mut k8s_manifests = Vec::new();
            let mut tf_resources = Vec::new();
            let mut tf_variables = Vec::new();
            let mut tf_locals = Vec::new();

            for res in &doc.resources {
                total_resources += 1;
                match res {
                    IacResource::Kubernetes(m) => k8s_manifests.push(m.as_ref()),
                    IacResource::Terraform(r) => tf_resources.push(r.as_ref().clone()),
                    IacResource::TerraformVariable(v) => tf_variables.push(v.clone()),
                    IacResource::TerraformLocal(l) => tf_locals.push(l.clone()),
                }
            }

            // Audit Kubernetes
            for manifest in k8s_manifests {
                let f =
                    self.k8s_auditor
                        .audit_manifest(manifest, &doc.file_path, &doc.raw_content)?;
                findings.extend(f);
            }

            // Audit Terraform
            if !tf_resources.is_empty() || !tf_variables.is_empty() || !tf_locals.is_empty() {
                let f = self.terraform_auditor.audit_terraform(
                    &tf_resources,
                    &tf_variables,
                    &tf_locals,
                    &doc.file_path,
                    &doc.raw_content,
                )?;
                findings.extend(f);
            }
        }

        Ok(IacReport {
            target_path: String::new(),
            total_documents_scanned: documents.len(),
            total_resources_evaluated: total_resources,
            findings,
            suppressed_findings_count: 0,
        })
    }

    /// Generates an Aegix baseline snapshot from an IaC audit report.
    pub fn generate_baseline(&self, report: &IacReport, target_path: &Path) -> AegixBaseline {
        let sarif = self.to_sarif(report, target_path, None);
        AegixBaseline::from_sarif(&sarif)
    }

    /// Filters findings in an IaC report against an Aegix baseline snapshot.
    pub fn filter_baseline(report: &IacReport, baseline: &AegixBaseline) -> IacReport {
        let mut filtered = report.clone();
        let initial_count = filtered.findings.len();
        filtered
            .findings
            .retain(|f| !baseline.fingerprints.contains(&f.fingerprint));
        filtered.suppressed_findings_count = initial_count.saturating_sub(filtered.findings.len());
        filtered
    }

    /// Exports findings to standardized OASIS SARIF v2.1.0 format with baseline suppression.
    pub fn to_sarif(
        &self,
        report: &IacReport,
        _target_path: &Path,
        baseline: Option<&AegixBaseline>,
    ) -> SarifLog {
        let mut log = SarifLog::new("Aegix IaC Security Engine", env!("CARGO_PKG_VERSION"));

        for finding in &report.findings {
            // Baseline suppression check
            if let Some(base) = baseline {
                if base.fingerprints.contains(&finding.fingerprint) {
                    continue;
                }
            }

            let mut sarif_result = SarifResult::new(
                &finding.rule_id,
                finding.severity,
                format!(
                    "{} Remediation: {}",
                    finding.description, finding.remediation
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

            let mut fp_map = HashMap::new();
            fp_map.insert("sha256/v1".to_string(), finding.fingerprint.clone());
            fp_map.insert(
                "logicalLocationTokenHash/v1".to_string(),
                finding.fingerprint.clone(),
            );
            sarif_result.partial_fingerprints = Some(fp_map);

            log.add_result(sarif_result);
        }

        log
    }

    /// Formats findings into human-readable terminal output.
    pub fn format_terminal(&self, report: &IacReport) -> String {
        let mut out = String::new();
        out.push_str(
            "================================================================================\n",
        );
        out.push_str(
            "                         AEGIX IAC SECURITY ENGINE                              \n",
        );
        out.push_str(
            "================================================================================\n\n",
        );

        out.push_str(&format!(
            "Target Path:                {}\n",
            report.target_path
        ));
        out.push_str(&format!(
            "Total Documents Scanned:    {}\n",
            report.total_documents_scanned
        ));
        out.push_str(&format!(
            "Total Resources Evaluated:  {}\n",
            report.total_resources_evaluated
        ));
        out.push_str(&format!(
            "Active Security Findings:   {}\n",
            report.findings.len()
        ));
        if report.suppressed_findings_count > 0 {
            out.push_str(&format!(
                "Suppressed via Baseline:    {}\n",
                report.suppressed_findings_count
            ));
        }
        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );

        if report.findings.is_empty() {
            out.push_str(
                "\n✅ Clean scan! Zero Infrastructure as Code misconfigurations detected.\n",
            );
            return out;
        }

        for (idx, f) in report.findings.iter().enumerate() {
            let sev_str = match f.severity {
                SarifLevel::Error => "🔴 CRITICAL/ERROR",
                SarifLevel::Warning => "🟡 WARNING",
                SarifLevel::Note => "🔵 NOTE",
                SarifLevel::None => "⚪ NONE",
            };

            out.push_str(&format!(
                "\n[{}] {} - {} (CWE-{})\n",
                idx + 1,
                sev_str,
                f.rule_id,
                f.cwe
            ));
            out.push_str(&format!("     Title:        {}\n", f.title));
            out.push_str(&format!(
                "     Resource:     {} ({})\n",
                f.resource_id, f.resource_type
            ));
            out.push_str(&format!(
                "     Location:     {}:{}:{}\n",
                f.file_path, f.line, f.column
            ));
            out.push_str(&format!("     Path:         {}\n", f.configuration_path));
            out.push_str(&format!("     Description:  {}\n", f.description));
            out.push_str(&format!("     Remediation:  {}\n", f.remediation));
            out.push_str(&format!("     Fingerprint:  {}\n", f.fingerprint));
        }

        out.push_str(
            "\n================================================================================\n",
        );
        out
    }
}

#[async_trait]
impl IacScanner for IacEngine {
    async fn scan(&self, documents: &[IacDocument]) -> Result<IacReport, IacError> {
        self.evaluate_documents(documents)
    }

    async fn scan_file(&self, path: &Path) -> Result<IacReport, IacError> {
        let mut all_docs = Vec::new();
        let target_str = path.display().to_string();

        if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let is_iac = ext == "yaml" || ext == "yml" || ext == "json" || ext == "tf";
                    if is_iac {
                        if let Ok(docs) = IacParser::parse_file(p) {
                            all_docs.extend(docs);
                        }
                    }
                }
            }
        } else {
            let docs = IacParser::parse_file(path)?;
            all_docs.extend(docs);
        }

        let mut report = self.evaluate_documents(&all_docs)?;
        report.target_path = target_str;
        Ok(report)
    }

    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<IacReport, IacError> {
        let mut content = String::new();
        reader.read_to_string(&mut content)?;

        if content.len() > crate::parser::MAX_IAC_FILE_SIZE {
            return Err(IacError::FileSizeLimitExceeded {
                size: content.len(),
                max_allowed: crate::parser::MAX_IAC_FILE_SIZE,
            });
        }

        let docs = IacParser::parse_str(&content, path_hint)?;
        let mut report = self.evaluate_documents(&docs)?;
        report.target_path = path_hint.display().to_string();
        Ok(report)
    }
}
