//! Cycle-safe bounded depth-first search path traversal engine.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{AttackGraph, AttackNode, AttackPath, EdgeKind, NodeId, NodeKind};
use crate::scoring::calculate_path_risk;
use crate::traits::PathFinder;
use std::collections::BTreeSet;

/// Standard cycle-safe bounded DFS pathfinder.
#[derive(Debug, Default, Clone)]
pub struct StandardPathFinder;

impl StandardPathFinder {
    pub fn new() -> Self {
        Self
    }

    #[allow(clippy::too_many_arguments)]
    fn dfs(
        &self,
        current_id: &NodeId,
        current_path: &mut Vec<NodeId>,
        current_edges: &mut Vec<EdgeKind>,
        visited: &mut BTreeSet<NodeId>,
        results: &mut Vec<AttackPath>,
        graph: &AttackGraph,
        max_depth: usize,
        max_paths: usize,
        min_risk: f64,
    ) {
        if results.len() >= max_paths {
            return;
        }

        if current_path.len() > max_depth {
            return;
        }

        let current_node = match graph.get_node(current_id) {
            Some(n) => n,
            None => return,
        };

        let is_terminal = current_node.kind == NodeKind::Impact
            || (current_node.kind == NodeKind::Asset && graph.out_edges(current_id).is_empty());

        if is_terminal && current_path.len() >= 2 {
            // Resolve node references for risk calculation
            let node_refs: Option<Vec<&AttackNode>> =
                current_path.iter().map(|id| graph.get_node(id)).collect();

            if let Some(nodes) = node_refs {
                let path_risk = calculate_path_risk(&nodes);
                if path_risk >= min_risk {
                    let path = AttackPath {
                        id: format!("path-{}", results.len() + 1),
                        node_ids: current_path.clone(),
                        edge_kinds: current_edges.clone(),
                        path_risk,
                        entrypoint_id: current_path[0].clone(),
                        impact_id: current_path
                            .last()
                            .cloned()
                            .unwrap_or_else(|| current_id.clone()),
                        hop_count: current_path.len().saturating_sub(1),
                    };
                    results.push(path);
                }
            }

            // Do not traverse beyond terminal impact node
            if current_node.kind == NodeKind::Impact {
                return;
            }
        }

        for edge in graph.out_edges(current_id) {
            if results.len() >= max_paths {
                return;
            }

            let next_id = &edge.target;

            // Cycle prevention check
            if !visited.contains(next_id) {
                visited.insert(next_id.clone());
                current_path.push(next_id.clone());
                current_edges.push(edge.kind);

                self.dfs(
                    next_id,
                    current_path,
                    current_edges,
                    visited,
                    results,
                    graph,
                    max_depth,
                    max_paths,
                    min_risk,
                );

                current_edges.pop();
                current_path.pop();
                visited.remove(next_id);
            }
        }
    }
}

impl PathFinder for StandardPathFinder {
    fn find_paths(
        &self,
        graph: &AttackGraph,
        max_depth: usize,
        max_paths: usize,
        min_risk: f64,
    ) -> Result<Vec<AttackPath>, GraphError> {
        let mut results = Vec::new();

        // Identify starting entrypoints
        let mut start_nodes: Vec<NodeId> = graph
            .entrypoints()
            .into_iter()
            .map(|n| n.id.clone())
            .collect();

        // Fallback: if no Entrypoints explicitly labeled, pick roots (in-degree == 0, excluding Impact)
        if start_nodes.is_empty() {
            let mut non_roots = BTreeSet::new();
            for edges in graph.adjacency.values() {
                for edge in edges {
                    non_roots.insert(edge.target.clone());
                }
            }

            for node in graph.nodes.values() {
                if !non_roots.contains(&node.id) && node.kind != NodeKind::Impact {
                    start_nodes.push(node.id.clone());
                }
            }
        }

        for start_id in start_nodes {
            if results.len() >= max_paths {
                break;
            }

            let mut current_path = vec![start_id.clone()];
            let mut current_edges = Vec::new();
            let mut visited = BTreeSet::new();
            visited.insert(start_id.clone());

            self.dfs(
                &start_id,
                &mut current_path,
                &mut current_edges,
                &mut visited,
                &mut results,
                graph,
                max_depth,
                max_paths,
                min_risk,
            );
        }

        // Sort paths descending by compounding risk score
        results.sort_by(|a, b| {
            b.path_risk
                .partial_cmp(&a.path_risk)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Re-index path IDs sequentially
        for (idx, path) in results.iter_mut().enumerate() {
            path.id = format!("path-{}", idx + 1);
        }

        Ok(results)
    }
}
