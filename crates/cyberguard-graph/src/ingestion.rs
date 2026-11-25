//! Telemetry ingestion implementation for SARIF v2.1.0 and ATT&CK Threat Findings.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{compute_node_id, AttackGraph, AttackNode, NodeKind, NodeLocation};
use crate::traits::TelemetryIngester;
use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use cyberguard_threat::models::ThreatFinding;

/// Standard telemetry ingester for Aegix security findings.
#[derive(Debug, Default, Clone)]
pub struct StandardTelemetryIngester;

impl StandardTelemetryIngester {
    pub fn new() -> Self {
        Self
    }

    /// Helper to convert a single SARIF result into an AttackNode.
    pub fn sarif_result_to_node(&self, tool_name: &str, result: &SarifResult) -> AttackNode {
        let rule_id = &result.rule_id;
        let rule_lower = rule_id.to_lowercase();
        let tool_lower = tool_name.to_lowercase();
        let message_lower = result.message.text.to_lowercase();

        // Extract physical/logical location if present
        let mut file_path = None;
        let mut line_number = None;
        let mut url_or_route = None;

        if let Some(loc) = result.locations.first() {
            if let Some(ref phys) = loc.physical_location {
                let uri = &phys.artifact_location.uri;
                if uri.starts_with("http://")
                    || uri.starts_with("https://")
                    || uri.starts_with("net://")
                {
                    url_or_route = Some(uri.clone());
                } else {
                    file_path = Some(uri.clone());
                }

                if let Some(ref reg) = phys.region {
                    line_number = Some(reg.start_line);
                }
            }
        }

        // Determine NodeKind based on tool, rule, and message semantics
        let kind = if tool_lower.contains("net")
            || rule_lower.starts_with("net-")
            || url_or_route.is_some()
            || message_lower.contains("open port")
            || message_lower.contains("public endpoint")
        {
            NodeKind::Entrypoint
        } else if tool_lower.contains("secret")
            || rule_lower.starts_with("sec-")
            || rule_lower.starts_with("secret-")
            || message_lower.contains("leaked secret")
            || message_lower.contains("api key")
            || message_lower.contains("private key")
            || message_lower.contains("credentials")
        {
            NodeKind::Secret
        } else if tool_lower.contains("cloud")
            || tool_lower.contains("iac")
            || tool_lower.contains("ciem")
        {
            if message_lower.contains("privilege")
                || message_lower.contains("escalat")
                || message_lower.contains("admin")
                || message_lower.contains("iam role")
            {
                NodeKind::Privilege
            } else {
                NodeKind::Asset
            }
        } else if message_lower.contains("exfiltration")
            || message_lower.contains("ransomware")
            || message_lower.contains("system takeover")
        {
            NodeKind::Impact
        } else {
            NodeKind::Vulnerability
        };

        // Compute normalized risk score (0.0 .. 1.0)
        let risk_score = if let Some(serde_json::Value::Object(ref props)) = result.properties {
            if let Some(serde_json::Value::Number(ref num)) = props.get("triFactorScore") {
                num.as_f64().map(|s| (s / 100.0).clamp(0.0, 1.0))
            } else if let Some(serde_json::Value::Number(ref num)) = props.get("cvss") {
                num.as_f64().map(|s| (s / 10.0).clamp(0.0, 1.0))
            } else {
                None
            }
        } else {
            None
        }
        .unwrap_or(match result.level {
            SarifLevel::Error => 0.85,
            SarifLevel::Warning => 0.55,
            SarifLevel::Note => 0.25,
            SarifLevel::None => 0.10,
        });

        // Compute deterministic identifier seed
        let loc_seed = if let Some(ref url) = url_or_route {
            url.clone()
        } else if let Some(ref path) = file_path {
            format!("{}:{}", path, line_number.unwrap_or(0))
        } else {
            result.fingerprint()
        };

        let node_id = compute_node_id(kind, tool_name, &format!("{}:{}", rule_id, loc_seed));
        let label = format!("{}: {}", rule_id, result.message.text);
        let description = result.message.text.clone();

        let mut node = AttackNode::new(node_id, kind, label, description, risk_score, tool_name);

        if file_path.is_some() || line_number.is_some() || url_or_route.is_some() {
            node = node.with_location(NodeLocation {
                file_path,
                line_number,
                url_or_route,
                target_asset: None,
            });
        }

        node = node.with_metadata("rule_id", serde_json::json!(rule_id));
        node = node.with_metadata("level", serde_json::json!(format!("{:?}", result.level)));

        if let Some(ref props) = result.properties {
            node = node.with_metadata("properties", props.clone());
        }

        node
    }

    /// Ingests an array of ATT&CK Threat Findings into the graph.
    pub fn ingest_threat_findings(
        &self,
        graph: &mut AttackGraph,
        findings: &[ThreatFinding],
    ) -> Result<usize, GraphError> {
        let mut added = 0;
        for finding in findings {
            let mut kind = NodeKind::Vulnerability;

            for tactic in &finding.tactics {
                match tactic {
                    cyberguard_threat::models::MitreTactic::InitialAccess
                    | cyberguard_threat::models::MitreTactic::Reconnaissance => {
                        kind = NodeKind::Entrypoint;
                        break;
                    }
                    cyberguard_threat::models::MitreTactic::Impact => {
                        kind = NodeKind::Impact;
                        break;
                    }
                    cyberguard_threat::models::MitreTactic::PrivilegeEscalation => {
                        kind = NodeKind::Privilege;
                        break;
                    }
                    cyberguard_threat::models::MitreTactic::CredentialAccess => {
                        kind = NodeKind::Secret;
                        break;
                    }
                    _ => {}
                }
            }

            let risk_score = if let Some(tri) = finding.tri_factor_score {
                (tri / 100.0).clamp(0.0, 1.0)
            } else if let Some(cvss) = finding.cvss_score {
                (cvss / 10.0).clamp(0.0, 1.0)
            } else {
                match finding.severity {
                    SarifLevel::Error => 0.85,
                    SarifLevel::Warning => 0.55,
                    SarifLevel::Note => 0.25,
                    SarifLevel::None => 0.10,
                }
            };

            let loc_seed = finding
                .file_path
                .as_ref()
                .map(|p| format!("{}:{}", p, finding.line.unwrap_or(0)))
                .unwrap_or_else(|| finding.id.clone());

            let node_id = compute_node_id(
                kind,
                "cyberguard-threat",
                &format!("{}:{}", finding.source_rule_id, loc_seed),
            );
            let mut node = AttackNode::new(
                node_id,
                kind,
                &finding.title,
                &finding.description,
                risk_score,
                "cyberguard-threat",
            );

            if finding.file_path.is_some() || finding.line.is_some() {
                node = node.with_location(NodeLocation {
                    file_path: finding.file_path.clone(),
                    line_number: finding.line,
                    url_or_route: None,
                    target_asset: None,
                });
            }

            node = node.with_metadata("tactics", serde_json::json!(finding.tactics));
            node = node.with_metadata("techniques", serde_json::json!(finding.techniques));
            node = node.with_metadata("stride", serde_json::json!(finding.stride_categories));

            graph.add_node(node);
            added += 1;
        }

        Ok(added)
    }
}

impl TelemetryIngester for StandardTelemetryIngester {
    fn ingest_sarif(&self, graph: &mut AttackGraph, sarif: &SarifLog) -> Result<usize, GraphError> {
        let mut count = 0;
        for run in &sarif.runs {
            let tool_name = &run.tool.driver.name;
            for result in &run.results {
                let node = self.sarif_result_to_node(tool_name, result);
                graph.add_node(node);
                count += 1;
            }
        }
        Ok(count)
    }
}
