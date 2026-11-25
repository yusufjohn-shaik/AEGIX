//! Mermaid flowchart exporter for GitHub PR comments and Markdown documentation.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{AttackGraph, AttackPath, ChokePoint, NodeId, NodeKind};
use crate::traits::GraphExporter;
use std::collections::BTreeSet;
use std::fmt::Write;

/// Mermaid flowchart exporter rendering GitHub-compatible DAG diagrams.
#[derive(Debug, Default, Clone)]
pub struct MermaidExporter;

impl MermaidExporter {
    pub fn new() -> Self {
        Self
    }

    /// Sanitizes node identifier into safe Mermaid ASCII format.
    fn sanitize_id(id: &NodeId) -> String {
        id.0.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }

    /// Sanitizes text for display inside Mermaid node labels.
    fn sanitize_text(text: &str) -> String {
        text.replace('"', "'")
            .replace('\n', " ")
            .chars()
            .take(60)
            .collect()
    }
}

impl GraphExporter for MermaidExporter {
    fn export(
        &self,
        graph: &AttackGraph,
        paths: &[AttackPath],
        choke_points: &[ChokePoint],
    ) -> Result<String, GraphError> {
        let mut out = String::new();

        writeln!(out, "```mermaid")?;
        writeln!(out, "flowchart LR")?;

        // Collect all nodes participating in discovered paths (or all nodes if no paths)
        let mut relevant_nodes = BTreeSet::new();
        if !paths.is_empty() {
            for path in paths {
                for id in &path.node_ids {
                    relevant_nodes.insert(id.clone());
                }
            }
        } else {
            for id in graph.nodes.keys() {
                relevant_nodes.insert(id.clone());
            }
        }

        // Output node definitions
        for node_id in &relevant_nodes {
            if let Some(node) = graph.get_node(node_id) {
                let safe_id = Self::sanitize_id(node_id);
                let safe_label = Self::sanitize_text(&node.label);
                let kind_tag = match node.kind {
                    NodeKind::Entrypoint => "🌐 Entrypoint",
                    NodeKind::Service => "⚙️ Service",
                    NodeKind::Vulnerability => "⚠️ Vuln",
                    NodeKind::Secret => "🔑 Secret",
                    NodeKind::Asset => "📦 Asset",
                    NodeKind::Privilege => "🛡️ Privilege",
                    NodeKind::Impact => "💥 Impact",
                };

                writeln!(
                    out,
                    "    {}[\"<b>{}</b><br/>{}\"]",
                    safe_id, kind_tag, safe_label
                )?;
            }
        }

        writeln!(out)?;

        // Output edges
        let mut emitted_edges = BTreeSet::new();
        if !paths.is_empty() {
            for path in paths {
                for i in 0..path.node_ids.len().saturating_sub(1) {
                    let from_id = &path.node_ids[i];
                    let to_id = &path.node_ids[i + 1];
                    let edge_key = (from_id.clone(), to_id.clone());

                    if !emitted_edges.contains(&edge_key) {
                        emitted_edges.insert(edge_key);
                        let edge_kind = path
                            .edge_kinds
                            .get(i)
                            .map(|k| k.as_str())
                            .unwrap_or("traverses");
                        let safe_from = Self::sanitize_id(from_id);
                        let safe_to = Self::sanitize_id(to_id);
                        writeln!(out, "    {} -->|{}| {}", safe_from, edge_kind, safe_to)?;
                    }
                }
            }
        } else {
            for (from_id, edges) in &graph.adjacency {
                for edge in edges {
                    let safe_from = Self::sanitize_id(from_id);
                    let safe_to = Self::sanitize_id(&edge.target);
                    writeln!(
                        out,
                        "    {} -->|{}| {}",
                        safe_from,
                        edge.kind.as_str(),
                        safe_to
                    )?;
                }
            }
        }

        // Highlight Choke Points with styling
        if !choke_points.is_empty() {
            writeln!(out)?;
            for cp in choke_points.iter().take(3) {
                let safe_id = Self::sanitize_id(&cp.node_id);
                writeln!(
                    out,
                    "    style {} fill:#ffebee,stroke:#c62828,stroke-width:3px",
                    safe_id
                )?;
            }
        }

        writeln!(out, "```")?;
        Ok(out)
    }
}
