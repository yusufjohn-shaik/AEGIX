//! ANSI and plain text terminal tree exporter for exploit paths and choke points.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{AttackGraph, AttackPath, ChokePoint};
use crate::traits::GraphExporter;
use std::fmt::Write;

/// ANSI terminal tree exporter.
#[derive(Debug, Default, Clone)]
pub struct TerminalExporter {
    pub use_colors: bool,
}

impl TerminalExporter {
    pub fn new(use_colors: bool) -> Self {
        Self { use_colors }
    }

    fn color(&self, code: &str, text: &str) -> String {
        if self.use_colors {
            format!("{}{}\x1b[0m", code, text)
        } else {
            text.to_string()
        }
    }
}

impl GraphExporter for TerminalExporter {
    fn export(
        &self,
        graph: &AttackGraph,
        paths: &[AttackPath],
        choke_points: &[ChokePoint],
    ) -> Result<String, GraphError> {
        let mut out = String::new();

        let bold = "\x1b[1m";
        let red = "\x1b[31;1m";
        let yellow = "\x1b[33;1m";
        let green = "\x1b[32;1m";
        let cyan = "\x1b[36;1m";
        let magenta = "\x1b[35;1m";
        let gray = "\x1b[90m";

        writeln!(
            out,
            "{}",
            self.color(
                bold,
                "=========================================================="
            )
        )?;
        writeln!(
            out,
            "{}",
            self.color(
                bold,
                "              AEGIX ATTACK PATH ENGINE                    "
            )
        )?;
        writeln!(
            out,
            "{}",
            self.color(
                bold,
                "=========================================================="
            )
        )?;
        writeln!(
            out,
            "Graph Topology: {} nodes | {} edges | {} discovered exploit chains\n",
            self.color(cyan, &graph.node_count().to_string()),
            self.color(cyan, &graph.edge_count().to_string()),
            self.color(
                if paths.is_empty() { green } else { red },
                &paths.len().to_string()
            )
        )?;

        if paths.is_empty() {
            writeln!(
                out,
                "{}",
                self.color(
                    green,
                    "No viable multi-hop attack paths reaching critical impact were identified."
                )
            )?;
        } else {
            writeln!(out, "{}", self.color(bold, "Discovered Exploit Chains:"))?;
            for (idx, path) in paths.iter().enumerate() {
                let risk_color = if path.path_risk >= 70.0 {
                    red
                } else if path.path_risk >= 40.0 {
                    yellow
                } else {
                    cyan
                };

                let risk_label = if path.path_risk >= 70.0 {
                    "CRITICAL"
                } else if path.path_risk >= 40.0 {
                    "HIGH"
                } else {
                    "MEDIUM"
                };

                writeln!(
                    out,
                    "\n[{}] Risk: {}/100 ({}) | {} Hops",
                    self.color(bold, &format!("Path #{}", idx + 1)),
                    self.color(risk_color, &format!("{:.1}", path.path_risk)),
                    self.color(risk_color, risk_label),
                    path.hop_count
                )?;

                for (hop_idx, node_id) in path.node_ids.iter().enumerate() {
                    let node = graph.get_node(node_id);
                    let label = node.map(|n| n.label.as_str()).unwrap_or("Unknown Node");
                    let kind_str = node
                        .map(|n| format!("[{:?}]", n.kind))
                        .unwrap_or_else(|| "[Node]".to_string());

                    let loc_str = if let Some(n) = node {
                        if let Some(ref loc) = n.location {
                            if let Some(ref url) = loc.url_or_route {
                                format!(" ({})", url)
                            } else if let Some(ref file) = loc.file_path {
                                format!(" ({}:{})", file, loc.line_number.unwrap_or(0))
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };

                    if hop_idx == 0 {
                        writeln!(
                            out,
                            "  {} {}{}",
                            self.color(cyan, &kind_str),
                            label,
                            self.color(gray, &loc_str)
                        )?;
                    } else {
                        let indent = "  ".repeat(hop_idx + 1);
                        let edge_kind = path
                            .edge_kinds
                            .get(hop_idx - 1)
                            .map(|k| k.as_str())
                            .unwrap_or("traverses");

                        let node_color = if hop_idx == path.node_ids.len() - 1 {
                            red
                        } else {
                            magenta
                        };

                        writeln!(
                            out,
                            "{}└─[{}]─> {} {}{}",
                            indent,
                            self.color(yellow, edge_kind),
                            self.color(node_color, &kind_str),
                            label,
                            self.color(gray, &loc_str)
                        )?;
                    }
                }
            }
        }

        if !choke_points.is_empty() {
            writeln!(
                out,
                "\n{}",
                self.color(
                    bold,
                    "=========================================================="
                )
            )?;
            writeln!(
                out,
                "{}",
                self.color(
                    bold,
                    "       HIGH-LEVERAGE REMEDIATION CHOKE POINTS             "
                )
            )?;
            writeln!(
                out,
                "{}",
                self.color(
                    bold,
                    "=========================================================="
                )
            )?;

            for (idx, cp) in choke_points.iter().enumerate() {
                writeln!(
                    out,
                    "\n{}. {} {}",
                    idx + 1,
                    self.color(cyan, &format!("[{:?}]", cp.node_kind)),
                    self.color(bold, &cp.node_label)
                )?;
                writeln!(
                    out,
                    "   Blocks: {} exploit paths | Cumulative Choke Score: {}",
                    self.color(red, &cp.paths_blocked_count.to_string()),
                    self.color(yellow, &format!("{:.1}", cp.choke_score))
                )?;
                writeln!(
                    out,
                    "   Guidance: {}",
                    self.color(green, &cp.remediation_guidance)
                )?;
            }
        }

        writeln!(out)?;
        Ok(out)
    }
}
