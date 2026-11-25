//! SARIF v2.1.0 exporter with multi-step `codeFlow` execution path representations.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{AttackGraph, AttackPath, ChokePoint};
use crate::traits::GraphExporter;
use cyberguard_core::sarif::{
    ArtifactLocation, CodeFlow, Location, Message, PhysicalLocation, Region, ReportingDescriptor,
    SarifLevel, SarifLog, SarifResult, ThreadFlow, ThreadFlowLocation,
};

/// SARIF v2.1.0 codeFlow exporter.
#[derive(Debug, Default, Clone)]
pub struct SarifExporter;

impl SarifExporter {
    pub fn new() -> Self {
        Self
    }
}

impl GraphExporter for SarifExporter {
    fn export(
        &self,
        graph: &AttackGraph,
        paths: &[AttackPath],
        _choke_points: &[ChokePoint],
    ) -> Result<String, GraphError> {
        let mut sarif = SarifLog::new("cyberguard-graph", env!("CARGO_PKG_VERSION"));

        // Register Attack Path rule in driver
        sarif.add_rule(ReportingDescriptor {
            id: "PATH-EXPLOIT-CHAIN".to_string(),
            name: Some("MultiHopExploitPath".to_string()),
            short_description: Message {
                text: "Multi-hop correlated attack path connecting entrypoint to critical impact."
                    .to_string(),
            },
            full_description: Some(Message {
                text: "Aegix Attack Path Engine discovered an actionable multi-hop chain spanning perimeter entrypoints, exploitable vulnerabilities, leaked credentials, and privileged cloud assets.".to_string(),
            }),
            help_uri: Some("https://github.com/yusufjohn-shaik/AEGIX/blob/main/docs/attack-paths.md".to_string()),
        });

        for path in paths {
            let level = if path.path_risk >= 70.0 {
                SarifLevel::Error
            } else if path.path_risk >= 40.0 {
                SarifLevel::Warning
            } else {
                SarifLevel::Note
            };

            let ep_node = graph.get_node(&path.entrypoint_id);
            let imp_node = graph.get_node(&path.impact_id);

            let ep_label = ep_node.map(|n| n.label.as_str()).unwrap_or("Entrypoint");
            let imp_label = imp_node
                .map(|n| n.label.as_str())
                .unwrap_or("Terminal Impact");

            let mut result = SarifResult::new(
                "PATH-EXPLOIT-CHAIN",
                level,
                format!(
                    "Exploit chain from '{}' to '{}' (compounding path risk: {:.1}/100, {} hops)",
                    ep_label, imp_label, path.path_risk, path.hop_count
                ),
            );

            // Build ThreadFlow locations representing each step
            let mut thread_locations = Vec::new();
            for (step_idx, node_id) in path.node_ids.iter().enumerate() {
                let node = graph.get_node(node_id);
                let (uri, start_line) = if let Some(n) = node {
                    if let Some(ref loc) = n.location {
                        if let Some(ref url) = loc.url_or_route {
                            (url.clone(), 1)
                        } else if let Some(ref file) = loc.file_path {
                            (file.clone(), loc.line_number.unwrap_or(1))
                        } else {
                            (format!("graph://node/{}", node_id.0), 1)
                        }
                    } else {
                        (format!("graph://node/{}", node_id.0), 1)
                    }
                } else {
                    (format!("graph://node/{}", node_id.0), 1)
                };

                let step_loc = Location {
                    physical_location: Some(PhysicalLocation {
                        artifact_location: ArtifactLocation { uri: uri.clone() },
                        region: Some(Region {
                            start_line,
                            start_column: Some(1),
                            end_line: Some(start_line),
                            end_column: None,
                        }),
                    }),
                };

                let importance = if step_idx == 0 || step_idx == path.node_ids.len() - 1 {
                    "essential".to_string()
                } else {
                    "important".to_string()
                };

                thread_locations.push(ThreadFlowLocation {
                    location: step_loc,
                    step: Some(step_idx + 1),
                    importance: Some(importance),
                });
            }

            // Primary result location set to terminal impact (or entrypoint)
            if let Some(first_thread_loc) = thread_locations.last() {
                result.locations.push(first_thread_loc.location.clone());
            }

            let code_flow = CodeFlow {
                message: Some(Message {
                    text: format!("Attack path execution flow {}", path.id),
                }),
                thread_flows: vec![ThreadFlow {
                    message: Some(Message {
                        text: "Attacker exploitation trace".to_string(),
                    }),
                    locations: thread_locations,
                }],
            };

            result.add_code_flow(code_flow);

            let mut props = serde_json::Map::new();
            props.insert("path_id".to_string(), serde_json::json!(path.id));
            props.insert("path_risk".to_string(), serde_json::json!(path.path_risk));
            props.insert("hop_count".to_string(), serde_json::json!(path.hop_count));
            props.insert("node_ids".to_string(), serde_json::json!(path.node_ids));
            result.properties = Some(serde_json::Value::Object(props));

            sarif.add_result(result);
        }

        serde_json::to_string_pretty(&sarif).map_err(GraphError::Json)
    }
}
