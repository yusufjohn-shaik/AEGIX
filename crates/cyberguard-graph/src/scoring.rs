//! Path risk scoring formulas and Choke-Point cut-vertex analyzer.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{AttackGraph, AttackNode, AttackPath, ChokePoint, NodeId, NodeKind};
use crate::traits::ChokePointAnalyzer;
use std::collections::{BTreeMap, BTreeSet};

/// Calculates the compounding path risk according to the Aegix risk model:
///
/// PathRisk(p) = ImpactScore * (product(Risk(v))^(1/len)) * (gamma^(len - 1)) * 10.0
///
/// where Risk(v) in [0.1, 1.0], gamma = 0.95 (friction per hop), and output in [0.0, 100.0].
pub fn calculate_path_risk(nodes: &[&AttackNode]) -> f64 {
    if nodes.is_empty() {
        return 0.0;
    }

    let len = nodes.len();
    let gamma = 0.95_f64;

    // Geometric mean of node risk scores, floored at 0.1
    let mut log_sum = 0.0;
    for node in nodes {
        let r = node.risk_score.clamp(0.1, 1.0);
        log_sum += r.ln();
    }
    let geom_mean = (log_sum / (len as f64)).exp();

    // Attenuation discount per additional hop
    let attenuation = gamma.powi((len.saturating_sub(1)) as i32);

    // Terminal impact score scaled to [1.0, 10.0]
    let last_node = nodes[len - 1];
    let impact_score = last_node.risk_score.clamp(0.1, 1.0) * 10.0;

    // Compounding path risk scaled to [0.0, 100.0]
    let raw_score = impact_score * geom_mean * attenuation * 10.0;
    let clamped = raw_score.clamp(0.0, 100.0);
    (clamped * 10.0).round() / 10.0
}

/// Standard choke point cut-vertex analyzer.
#[derive(Debug, Default, Clone)]
pub struct StandardChokePointAnalyzer;

impl StandardChokePointAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Generates contextual remediation advice based on node type and properties.
    pub fn generate_remediation_guidance(node: &AttackNode) -> String {
        match node.kind {
            NodeKind::Vulnerability => {
                format!(
                    "Remediate vulnerability '{}' to eliminate downstream exploit paths.",
                    node.label
                )
            }
            NodeKind::Secret => {
                format!(
                    "Revoke and rotate compromised credential '{}' immediately.",
                    node.label
                )
            }
            NodeKind::Service => {
                format!(
                    "Apply network micro-segmentation and authentication to service '{}'.",
                    node.label
                )
            }
            NodeKind::Privilege => {
                format!(
                    "Strip excessive administrative entitlements and enforce least privilege for '{}'.",
                    node.label
                )
            }
            NodeKind::Asset => {
                format!(
                    "Isolate asset '{}' in private subnet and enforce strict ACLs.",
                    node.label
                )
            }
            NodeKind::Entrypoint => {
                format!(
                    "Restrict public exposure of entrypoint '{}' using WAF or VPN.",
                    node.label
                )
            }
            NodeKind::Impact => {
                format!("Harden defenses against terminal impact '{}'.", node.label)
            }
        }
    }
}

impl ChokePointAnalyzer for StandardChokePointAnalyzer {
    fn analyze_choke_points(
        &self,
        graph: &AttackGraph,
        paths: &[AttackPath],
    ) -> Result<Vec<ChokePoint>, GraphError> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }

        // Map intermediate nodes to paths that traverse them
        // Intermediate nodes: nodes that are neither the entrypoint nor the impact of that path
        let mut node_to_paths: BTreeMap<NodeId, BTreeSet<String>> = BTreeMap::new();
        let mut node_to_score: BTreeMap<NodeId, f64> = BTreeMap::new();

        for path in paths {
            if path.node_ids.len() <= 2 {
                // If path is only entrypoint -> impact, both are endpoints
                continue;
            }

            // Exclude entrypoint (index 0) and terminal impact (index len - 1)
            for node_id in &path.node_ids[1..path.node_ids.len() - 1] {
                node_to_paths
                    .entry(node_id.clone())
                    .or_default()
                    .insert(path.id.clone());

                let score_entry = node_to_score.entry(node_id.clone()).or_insert(0.0);
                *score_entry += path.path_risk;
            }
        }

        let mut choke_points = Vec::new();

        for (node_id, blocked_paths_set) in node_to_paths {
            if let Some(node) = graph.get_node(&node_id) {
                let choke_score = node_to_score.get(&node_id).copied().unwrap_or(0.0);
                let rounded_score = (choke_score * 10.0).round() / 10.0;
                let blocked_path_ids: Vec<String> = blocked_paths_set.into_iter().collect();
                let paths_blocked_count = blocked_path_ids.len();
                let guidance = Self::generate_remediation_guidance(node);

                choke_points.push(ChokePoint {
                    node_id: node_id.clone(),
                    node_label: node.label.clone(),
                    node_kind: node.kind,
                    choke_score: rounded_score,
                    paths_blocked_count,
                    blocked_path_ids,
                    remediation_guidance: guidance,
                });
            }
        }

        // Sort descending by paths_blocked_count, then by choke_score
        choke_points.sort_by(|a, b| {
            b.paths_blocked_count
                .cmp(&a.paths_blocked_count)
                .then_with(|| {
                    b.choke_score
                        .partial_cmp(&a.choke_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        Ok(choke_points)
    }
}
