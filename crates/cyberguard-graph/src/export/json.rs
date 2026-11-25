//! Full structured JSON exporter for the Attack Graph and discovered exploit paths.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{AttackGraph, AttackPath, ChokePoint};
use crate::traits::GraphExporter;
use serde::{Deserialize, Serialize};

/// Envelope for full graph analysis serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphAnalysisReport {
    pub graph: AttackGraph,
    pub paths: Vec<AttackPath>,
    pub choke_points: Vec<ChokePoint>,
    pub summary: GraphSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub discovered_paths: usize,
    pub max_path_risk: f64,
    pub top_choke_point: Option<String>,
}

/// Structured JSON exporter.
#[derive(Debug, Default, Clone)]
pub struct JsonExporter;

impl JsonExporter {
    pub fn new() -> Self {
        Self
    }
}

impl GraphExporter for JsonExporter {
    fn export(
        &self,
        graph: &AttackGraph,
        paths: &[AttackPath],
        choke_points: &[ChokePoint],
    ) -> Result<String, GraphError> {
        let max_risk = paths
            .iter()
            .map(|p| p.path_risk)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0);

        let report = GraphAnalysisReport {
            graph: graph.clone(),
            paths: paths.to_vec(),
            choke_points: choke_points.to_vec(),
            summary: GraphSummary {
                total_nodes: graph.node_count(),
                total_edges: graph.edge_count(),
                discovered_paths: paths.len(),
                max_path_risk: max_risk,
                top_choke_point: choke_points.first().map(|cp| cp.node_label.clone()),
            },
        };

        serde_json::to_string_pretty(&report).map_err(GraphError::Json)
    }
}
