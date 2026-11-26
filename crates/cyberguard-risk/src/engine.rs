//! Main `RiskEngine` orchestrating Cargo graph analysis, multi-engine scanning, and Tri-Factor prioritization.

#![deny(unsafe_code)]

use crate::call_graph::RustCallGraphAnalyzer;
use crate::cargo_graph::CargoDependencyGraphBuilder;
use crate::epss::EpssCatalog;
use crate::error::RiskError;
use crate::models::{PrioritizedFinding, RiskPrioritizationReport, RiskScanOptions};
use crate::scorer::TriFactorScorer;
use crate::traits::{DependencyGraphBuilder, ReachabilityAnalyzer, RiskPrioritizer};
use async_trait::async_trait;
use cyberguard_core::sarif::SarifLog;
use cyberguard_sast::{NativeRuleEngine, SastAnalyzer, ScanContext};
use cyberguard_sca::{ScaAnalyzer, ScaEngine};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct RiskEngine {
    graph_builder: CargoDependencyGraphBuilder,
    call_analyzer: RustCallGraphAnalyzer,
    scorer: TriFactorScorer,
}

impl RiskEngine {
    pub fn new() -> Self {
        Self {
            graph_builder: CargoDependencyGraphBuilder::new(),
            call_analyzer: RustCallGraphAnalyzer::new(),
            scorer: TriFactorScorer::new(),
        }
    }

    fn load_catalog(options: &RiskScanOptions) -> Result<EpssCatalog, RiskError> {
        let mut catalog = EpssCatalog::embedded();
        if let Some(ref db_path) = options.external_epss_db {
            catalog.load_external_json(db_path)?;
        }
        Ok(catalog)
    }

    fn finalize_report(
        mut report: RiskPrioritizationReport,
        options: &RiskScanOptions,
    ) -> RiskPrioritizationReport {
        // Deterministic sort: descending basis points, descending CVSS, ascending ID
        report.findings.sort_by(|a, b| {
            b.breakdown
                .score_bps
                .cmp(&a.breakdown.score_bps)
                .then_with(|| b.breakdown.cvss.total_cmp(&a.breakdown.cvss))
                .then_with(|| a.id.cmp(&b.id))
        });

        // Compute full counts BEFORE display filtering
        report.recompute_counts();

        // Filter output list according to display flags
        let min_bps = if options.min_score.is_finite() && options.min_score > 0.0 {
            (options.min_score * 100.0).round() as u32
        } else {
            0
        };

        report.findings.retain(|f| {
            if !options.show_suppressed && f.breakdown.tier == crate::models::RiskTier::Suppressed {
                return false;
            }
            f.breakdown.score_bps >= min_bps
        });

        report
    }
}

#[async_trait]
impl RiskPrioritizer for RiskEngine {
    async fn prioritize_path(
        &self,
        target: &Path,
        options: &RiskScanOptions,
    ) -> Result<RiskPrioritizationReport, RiskError> {
        if !target.exists() {
            return Err(RiskError::InvalidTarget(target.to_path_buf()));
        }

        let catalog = Self::load_catalog(options)?;
        let dep_graph = self
            .graph_builder
            .build(target, options.use_cargo_metadata)
            .await?;
        let reach_index = self.call_analyzer.analyze(&dep_graph, target)?;

        let mut report = RiskPrioritizationReport {
            target_path: target.to_path_buf(),
            metadata_source: dep_graph.metadata_source,
            warnings: dep_graph.warnings.clone(),
            workspace_packages: dep_graph.packages.len(),
            analyzed_nodes: reach_index.analyzed_functions,
            ..Default::default()
        };

        let mut seen_ids: BTreeSet<String> = BTreeSet::new();

        // 1. Run SCA dependency audit cleanly
        let sca_engine = ScaEngine::new();
        if let Ok(sca_report) = sca_engine.scan(target).await {
            let lock_hint = sca_report
                .lockfiles_scanned
                .first()
                .map(|p| p.to_string_lossy().to_string());
            for sca_finding in &sca_report.findings {
                let prioritized =
                    self.scorer
                        .score_sca_finding(sca_finding, &reach_index, lock_hint.as_deref());
                if seen_ids.insert(prioritized.id.clone()) {
                    report.findings.push(prioritized);
                }
            }
        }

        // 2. Run native SAST scan cleanly
        let sast_engine = NativeRuleEngine::default();
        let ctx = ScanContext::new(target);
        if let Ok(sast_results) = sast_engine.analyze(&ctx).await {
            for res in &sast_results {
                let prioritized = self.scorer.score_sarif_result(
                    "cyberguard-sast",
                    res,
                    &reach_index,
                    &dep_graph,
                    &catalog,
                );
                if seen_ids.insert(prioritized.id.clone()) {
                    report.findings.push(prioritized);
                }
            }
        }

        Ok(Self::finalize_report(report, options))
    }

    async fn prioritize_sarif(
        &self,
        target: &Path,
        sarif: &SarifLog,
        options: &RiskScanOptions,
    ) -> Result<RiskPrioritizationReport, RiskError> {
        let catalog = Self::load_catalog(options)?;
        let dep_graph = if target.exists() {
            self.graph_builder
                .build(target, options.use_cargo_metadata)
                .await?
        } else {
            Default::default()
        };

        let reach_index = if target.exists() && !dep_graph.packages.is_empty() {
            self.call_analyzer.analyze(&dep_graph, target)?
        } else {
            Default::default()
        };

        let mut report = RiskPrioritizationReport {
            target_path: target.to_path_buf(),
            metadata_source: dep_graph.metadata_source,
            warnings: dep_graph.warnings.clone(),
            workspace_packages: dep_graph.packages.len(),
            analyzed_nodes: reach_index.analyzed_functions,
            ..Default::default()
        };

        let mut findings: Vec<PrioritizedFinding> = Vec::new();
        for run in &sarif.runs {
            let tool_name = &run.tool.driver.name;
            for result in &run.results {
                findings.push(self.scorer.score_sarif_result(
                    tool_name,
                    result,
                    &reach_index,
                    &dep_graph,
                    &catalog,
                ));
            }
        }

        report.findings = findings;
        Ok(Self::finalize_report(report, options))
    }
}
