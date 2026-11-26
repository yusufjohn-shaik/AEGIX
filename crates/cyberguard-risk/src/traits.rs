//! Core trait contracts for Cargo graph building, reachability tracing, scoring, and export.

#![deny(unsafe_code)]

use crate::error::RiskError;
use crate::models::{
    ReachabilityStatus, RiskPrioritizationReport, RiskScanOptions, WorkspaceDependencyGraph,
};
use async_trait::async_trait;
use cyberguard_core::sarif::SarifLog;
use std::collections::BTreeMap;
use std::path::Path;

/// Result of static Rust call-graph analysis across workspace targets.
#[derive(Debug, Clone, Default)]
pub struct RustReachabilityIndex {
    /// Total function/symbol nodes discovered in workspace `.rs` files.
    pub analyzed_functions: usize,
    /// Per-dependency crate name -> (status, shortest deterministic call trace, evidence string).
    pub crate_reachability: BTreeMap<String, (ReachabilityStatus, Vec<String>, String)>,
    /// Per workspace relative file path -> list of `(start_line, end_line, fn_qual_name, is_test_scope, trace_from_entrypoint)`.
    pub function_spans: BTreeMap<String, Vec<FunctionReachabilitySpan>>,
}

/// Line span and entrypoint-reachability summary for a single Rust function.
#[derive(Debug, Clone)]
pub struct FunctionReachabilitySpan {
    pub start_line: usize,
    pub end_line: usize,
    pub qual_name: String,
    pub is_test_scope: bool,
    pub entrypoint_trace: Option<Vec<String>>,
}

#[async_trait]
pub trait DependencyGraphBuilder: Send + Sync {
    async fn build(
        &self,
        target: &Path,
        use_cargo_metadata: bool,
    ) -> Result<WorkspaceDependencyGraph, RiskError>;
}

pub trait ReachabilityAnalyzer: Send + Sync {
    fn analyze(
        &self,
        dep_graph: &WorkspaceDependencyGraph,
        target: &Path,
    ) -> Result<RustReachabilityIndex, RiskError>;
}

#[async_trait]
pub trait RiskPrioritizer: Send + Sync {
    async fn prioritize_path(
        &self,
        target: &Path,
        options: &RiskScanOptions,
    ) -> Result<RiskPrioritizationReport, RiskError>;

    async fn prioritize_sarif(
        &self,
        target: &Path,
        sarif: &SarifLog,
        options: &RiskScanOptions,
    ) -> Result<RiskPrioritizationReport, RiskError>;
}

pub trait RiskExporter: Send + Sync {
    fn export(&self, report: &RiskPrioritizationReport) -> Result<String, RiskError>;
}
