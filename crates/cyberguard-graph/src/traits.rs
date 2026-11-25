//! Trait definitions establishing contracts for ingestion, correlation, traversal, and export.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{AttackGraph, AttackPath, ChokePoint};
use cyberguard_core::sarif::SarifLog;

/// Ingestion contract for parsing external scanner findings into graph nodes.
pub trait TelemetryIngester: Send + Sync {
    /// Ingests a SARIF log, creating nodes in the target graph. Returns count of created nodes.
    fn ingest_sarif(&self, graph: &mut AttackGraph, sarif: &SarifLog) -> Result<usize, GraphError>;
}

/// Correlation contract for inferring multi-hop exploit edges.
pub trait GraphCorrelator: Send + Sync {
    /// Evaluates existing nodes and synthesizes directed exploit edges. Returns count of created edges.
    fn correlate(&self, graph: &mut AttackGraph) -> Result<usize, GraphError>;
}

/// Traversal contract for discovering exploit paths from entrypoints to impacts.
pub trait PathFinder: Send + Sync {
    /// Finds all simple attack paths subject to depth, budget, and risk constraints.
    fn find_paths(
        &self,
        graph: &AttackGraph,
        max_depth: usize,
        max_paths: usize,
        min_risk: f64,
    ) -> Result<Vec<AttackPath>, GraphError>;
}

/// Analysis contract for computing choke-point cut-vertices.
pub trait ChokePointAnalyzer: Send + Sync {
    /// Computes high-leverage choke points whose remediation breaks maximum high-risk paths.
    fn analyze_choke_points(
        &self,
        graph: &AttackGraph,
        paths: &[AttackPath],
    ) -> Result<Vec<ChokePoint>, GraphError>;
}

/// Export contract for rendering graph topologies and exploit paths.
pub trait GraphExporter: Send + Sync {
    /// Formats the graph, paths, and choke points into a target representation.
    fn export(
        &self,
        graph: &AttackGraph,
        paths: &[AttackPath],
        choke_points: &[ChokePoint],
    ) -> Result<String, GraphError>;
}
