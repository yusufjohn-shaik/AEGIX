use crate::error::PipelineError;
use crate::models::{PipelineDocument, PipelineFinding, PipelineReport};
use crate::parser::PipelineParser;
use crate::slsa::DefaultSlsaAuditor;
use crate::traits::{PipelineScanner, SlsaAuditor, WorkflowAuditor};
use crate::workflow::DefaultWorkflowAuditor;
use async_trait::async_trait;
use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{SarifLog, SarifResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

pub struct PipelineEngine {
    baseline: Option<AegixBaseline>,
    trusted_builders: Vec<String>,
    expected_source_repo: Option<String>,
    workflow_auditor: Box<dyn WorkflowAuditor>,
    slsa_auditor: Box<dyn SlsaAuditor>,
}

impl Default for PipelineEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineEngine {
    pub fn new() -> Self {
        Self {
            baseline: None,
            trusted_builders: Vec::new(),
            expected_source_repo: None,
            workflow_auditor: Box::new(DefaultWorkflowAuditor),
            slsa_auditor: Box::new(DefaultSlsaAuditor),
        }
    }

    pub fn with_baseline(mut self, baseline: AegixBaseline) -> Self {
        self.baseline = Some(baseline);
        self
    }

    pub fn with_trusted_builder(mut self, builder: impl Into<String>) -> Self {
        self.trusted_builders.push(builder.into());
        self
    }

    pub fn with_expected_source_repo(mut self, repo: impl Into<String>) -> Self {
        self.expected_source_repo = Some(repo.into());
        self
    }

    /// Generates an Aegix baseline snapshot from a pipeline report.
    pub fn generate_baseline(&self, report: &PipelineReport, _target_path: &Path) -> AegixBaseline {
        let sarif = self.to_sarif(report).unwrap_or_else(|_| {
            SarifLog::new("Aegix Pipeline Security Engine", env!("CARGO_PKG_VERSION"))
        });
        AegixBaseline::from_sarif(&sarif)
    }

    /// Filters findings in a pipeline report against an Aegix baseline snapshot.
    pub fn filter_baseline(report: &PipelineReport, baseline: &AegixBaseline) -> PipelineReport {
        let mut filtered = report.clone();
        let initial_count = filtered.findings.len();
        filtered
            .findings
            .retain(|f| !baseline.fingerprints.contains(&f.fingerprint));
        filtered.suppressed_findings_count = initial_count.saturating_sub(filtered.findings.len());
        filtered
    }

    /// Evaluates findings and applies baseline suppression.
    fn evaluate_findings(
        &self,
        raw_findings: Vec<PipelineFinding>,
        target_path: String,
        docs_count: usize,
        jobs_count: usize,
        steps_count: usize,
    ) -> PipelineReport {
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

        PipelineReport {
            target_path,
            total_documents_scanned: docs_count,
            total_jobs_evaluated: jobs_count,
            total_steps_evaluated: steps_count,
            findings: final_findings,
            suppressed_findings_count: suppressed_count,
        }
    }

    /// Exports findings to OASIS SARIF v2.1.0 telemetry.
    pub fn to_sarif(&self, report: &PipelineReport) -> Result<SarifLog, PipelineError> {
        let mut sarif_log = SarifLog::new(
            "Aegix CI/CD Pipeline Security Engine",
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
            hasher.update(finding.file_path.as_bytes());
            hasher.update(finding.location_path.as_bytes());
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

    /// Computes SHA-256 cryptographic digest of a file.
    pub fn compute_file_sha256(path: &Path) -> Result<String, std::io::Error> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }
}

#[async_trait]
impl PipelineScanner for PipelineEngine {
    async fn scan(&self, documents: &[PipelineDocument]) -> Result<PipelineReport, PipelineError> {
        let mut all_findings = Vec::new();
        let mut total_jobs = 0;
        let mut total_steps = 0;

        for doc in documents {
            if let Some(workflow) = &doc.workflow {
                total_jobs += workflow.jobs.len();
                for job in workflow.jobs.values() {
                    total_steps += job.steps.len();
                }

                let findings = self.workflow_auditor.audit_workflow(
                    workflow,
                    &doc.file_path,
                    &doc.raw_content,
                )?;
                all_findings.extend(findings);
            }

            if let Some(slsa) = &doc.slsa {
                let findings = self.slsa_auditor.audit_slsa(
                    slsa,
                    &doc.file_path,
                    &doc.raw_content,
                    None,
                    &self.trusted_builders,
                    self.expected_source_repo.as_deref(),
                )?;
                all_findings.extend(findings);
            }
        }

        Ok(self.evaluate_findings(
            all_findings,
            "in-memory".to_string(),
            documents.len(),
            total_jobs,
            total_steps,
        ))
    }

    async fn scan_file(
        &self,
        path: &Path,
        artifact_path: Option<&Path>,
    ) -> Result<PipelineReport, PipelineError> {
        let doc = PipelineParser::parse_file(path)?;
        let mut all_findings = Vec::new();
        let mut total_jobs = 0;
        let mut total_steps = 0;

        if let Some(workflow) = &doc.workflow {
            total_jobs += workflow.jobs.len();
            for job in workflow.jobs.values() {
                total_steps += job.steps.len();
            }

            let findings =
                self.workflow_auditor
                    .audit_workflow(workflow, &doc.file_path, &doc.raw_content)?;
            all_findings.extend(findings);
        }

        if let Some(slsa) = &doc.slsa {
            let artifact_digest = if let Some(ap) = artifact_path {
                Some(Self::compute_file_sha256(ap)?)
            } else {
                // Sibling binary auto-discovery: check if subject file exists in same directory
                let mut found_digest = None;
                if let Some(parent) = path.parent() {
                    for subj in &slsa.subject {
                        let candidate = parent.join(&subj.name);
                        if candidate.is_file() {
                            if let Ok(d) = Self::compute_file_sha256(&candidate) {
                                found_digest = Some(d);
                                break;
                            }
                        }
                    }
                }
                found_digest
            };

            let findings = self.slsa_auditor.audit_slsa(
                slsa,
                &doc.file_path,
                &doc.raw_content,
                artifact_digest.as_deref(),
                &self.trusted_builders,
                self.expected_source_repo.as_deref(),
            )?;
            all_findings.extend(findings);
        }

        Ok(self.evaluate_findings(
            all_findings,
            path.display().to_string(),
            1,
            total_jobs,
            total_steps,
        ))
    }

    async fn scan_directory(&self, dir_path: &Path) -> Result<PipelineReport, PipelineError> {
        let mut all_findings = Vec::new();
        let mut docs_scanned = 0;
        let mut total_jobs = 0;
        let mut total_steps = 0;

        for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            if ext == "yaml" || ext == "yml" || ext == "json" {
                if let Ok(doc) = PipelineParser::parse_file(path) {
                    docs_scanned += 1;
                    if let Some(workflow) = &doc.workflow {
                        total_jobs += workflow.jobs.len();
                        for job in workflow.jobs.values() {
                            total_steps += job.steps.len();
                        }
                        if let Ok(f) = self.workflow_auditor.audit_workflow(
                            workflow,
                            &doc.file_path,
                            &doc.raw_content,
                        ) {
                            all_findings.extend(f);
                        }
                    }

                    if let Some(slsa) = &doc.slsa {
                        if let Ok(f) = self.slsa_auditor.audit_slsa(
                            slsa,
                            &doc.file_path,
                            &doc.raw_content,
                            None,
                            &self.trusted_builders,
                            self.expected_source_repo.as_deref(),
                        ) {
                            all_findings.extend(f);
                        }
                    }
                }
            }
        }

        Ok(self.evaluate_findings(
            all_findings,
            dir_path.display().to_string(),
            docs_scanned,
            total_jobs,
            total_steps,
        ))
    }

    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<PipelineReport, PipelineError> {
        let mut content = String::new();
        reader.read_to_string(&mut content)?;

        if content.len() > crate::parser::MAX_PIPELINE_FILE_SIZE {
            return Err(PipelineError::FileSizeLimitExceeded {
                size: content.len(),
                max_allowed: crate::parser::MAX_PIPELINE_FILE_SIZE,
            });
        }

        let doc = PipelineParser::parse_str(&content, path_hint)?;
        self.scan(&[doc]).await
    }
}
