//! ThreatEngine facade and orchestrator implementing ThreatScanner.

#![deny(unsafe_code)]

use crate::catalog::StaticThreatCatalog;
use crate::error::ThreatError;
use crate::mapper::ThreatMapper;
use crate::models::{MitreMatrixDomain, ThreatFinding, ThreatReport};
use crate::navigator::NavigatorGenerator;
use crate::scorer::ThreatScorer;
use crate::traits::ThreatScanner;
use async_trait::async_trait;
use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{
    ArtifactLocation, Driver, Location, Message, PhysicalLocation, Region, ReportingDescriptor,
    Run, SarifLog, SarifResult, Tool,
};
use serde_json::json;
use std::io::Read;
use std::path::Path;

/// ThreatEngine manages multi-source telemetry ingestion, baseline suppression,
/// threat matrix computation, and report generation.
#[derive(Clone)]
pub struct ThreatEngine {
    catalog: StaticThreatCatalog,
    scorer: ThreatScorer,
    domain: MitreMatrixDomain,
    baseline: Option<AegixBaseline>,
    layer_name: String,
}

impl Default for ThreatEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatEngine {
    /// Constructs a new ThreatEngine with default Enterprise ATT&CK settings.
    pub fn new() -> Self {
        Self {
            catalog: StaticThreatCatalog::new(),
            scorer: ThreatScorer::default(),
            domain: MitreMatrixDomain::EnterpriseAttack,
            baseline: None,
            layer_name: "Aegix Security Threat Matrix".to_string(),
        }
    }

    /// Sets the target MITRE ATT&CK Matrix Domain.
    pub fn with_domain(mut self, domain: MitreMatrixDomain) -> Self {
        self.domain = domain;
        self
    }

    /// Configures an AegixBaseline for finding suppression.
    pub fn with_baseline(mut self, baseline: AegixBaseline) -> Self {
        self.baseline = Some(baseline);
        self
    }

    /// Sets the exported Navigator layer name.
    pub fn with_layer_name(mut self, name: impl Into<String>) -> Self {
        self.layer_name = name.into();
        self
    }

    /// Configures the saturation tuning constant alpha.
    pub fn with_alpha(mut self, alpha: f64) -> Self {
        self.scorer = ThreatScorer::new(alpha);
        self
    }

    /// Access reference to the static catalog.
    pub fn catalog(&self) -> &StaticThreatCatalog {
        &self.catalog
    }

    /// Exports findings and matrix properties back into an enriched SARIF v2.1.0 log.
    pub fn export_sarif_report(&self, report: &ThreatReport) -> Result<SarifLog, ThreatError> {
        let mut results = Vec::new();
        let mut rules = Vec::new();

        for finding in &report.findings {
            let mut props = json!({
                "mitreTactics": finding.tactics.iter().map(|t| t.slug()).collect::<Vec<_>>(),
                "mitreTechniques": finding.techniques,
                "strideCategories": finding.stride_categories.iter().map(|s| s.title()).collect::<Vec<_>>(),
                "remediation": finding.remediation,
                "fingerprint": finding.fingerprint,
            });

            if let Some(cvss) = finding.cvss_score {
                props["cvss"] = json!(cvss);
            }
            if let Some(tf) = finding.tri_factor_score {
                props["triFactorScore"] = json!(tf);
            }

            let locations = if let Some(path) = &finding.file_path {
                vec![Location {
                    physical_location: Some(PhysicalLocation {
                        artifact_location: ArtifactLocation { uri: path.clone() },
                        region: finding.line.map(|l| Region {
                            start_line: l,
                            start_column: None,
                            end_line: None,
                            end_column: None,
                        }),
                    }),
                }]
            } else {
                Vec::new()
            };

            let mut sarif_result = SarifResult::new(
                finding.source_rule_id.clone(),
                finding.severity,
                finding.description.clone(),
            );
            sarif_result.confidence = Some(finding.confidence);
            sarif_result.locations = locations;
            sarif_result.properties = Some(props);

            results.push(sarif_result);

            rules.push(ReportingDescriptor {
                id: finding.source_rule_id.clone(),
                name: Some(finding.title.clone()),
                short_description: Message {
                    text: finding.description.clone(),
                },
                full_description: None,
                help_uri: None,
            });
        }

        rules.sort_by(|a, b| a.id.cmp(&b.id));
        rules.dedup_by(|a, b| a.id == b.id);

        let run = Run {
            tool: Tool {
                driver: Driver {
                    name: "aegix-threat".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/yusufjohn-shaik/AEGIX".to_string(),
                    rules,
                },
            },
            results,
        };

        Ok(SarifLog {
            version: "2.1.0".to_string(),
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            runs: vec![run],
        })
    }
}

#[async_trait]
impl ThreatScanner for ThreatEngine {
    async fn scan_findings(&self, findings: &[ThreatFinding]) -> Result<ThreatReport, ThreatError> {
        let stride_counts = ThreatScorer::count_by_stride(findings);
        let tactic_counts = ThreatScorer::count_by_tactic(findings);
        let technique_counts = ThreatScorer::count_by_technique(findings);

        let generator = NavigatorGenerator::new(self.scorer);
        let navigator_layer = generator.generate_layer(&self.layer_name, self.domain, findings);

        Ok(ThreatReport {
            domain: self.domain,
            generated_at: chrono::Utc::now(),
            total_findings: findings.len(),
            findings: findings.to_vec(),
            stride_counts,
            tactic_counts,
            technique_counts,
            navigator_layer,
            suppressed_count: 0,
        })
    }

    async fn scan_sarif_log(&self, sarif: &SarifLog) -> Result<ThreatReport, ThreatError> {
        let mut log = sarif.clone();
        let mut suppressed_count = 0;

        if let Some(baseline) = &self.baseline {
            suppressed_count = baseline.filter_sarif(&mut log);
        }

        let mapper = ThreatMapper::new(&self.catalog, &self.catalog);
        let mut findings = Vec::new();

        for run in &log.runs {
            for res in &run.results {
                findings.push(mapper.map_sarif_result(res));
            }
        }

        let mut report = self.scan_findings(&findings).await?;
        report.suppressed_count = suppressed_count;
        Ok(report)
    }

    async fn scan_sarif(&self, sarif_json: &str) -> Result<ThreatReport, ThreatError> {
        let log: SarifLog = serde_json::from_str(sarif_json).map_err(|e| {
            ThreatError::SarifParse(format!("Failed to parse SARIF v2.1.0 JSON: {}", e))
        })?;
        self.scan_sarif_log(&log).await
    }

    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
    ) -> Result<ThreatReport, ThreatError> {
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        self.scan_sarif(&buf).await
    }

    async fn scan_file(&self, path: &Path) -> Result<ThreatReport, ThreatError> {
        let content = std::fs::read_to_string(path)?;
        self.scan_sarif(&content).await
    }
}
