//! Deterministic 5-Tier Correlation Engine linking telemetry findings into multi-hop exploit graphs.

#![deny(unsafe_code)]

use crate::error::GraphError;
use crate::models::{
    compute_node_id, AttackEdge, AttackGraph, AttackNode, EdgeKind, NodeId, NodeKind,
};
use crate::traits::GraphCorrelator;

/// Standard correlation engine implementing Aegix's 5-tier correlation rules.
#[derive(Debug, Default, Clone)]
pub struct StandardGraphCorrelator;

impl StandardGraphCorrelator {
    pub fn new() -> Self {
        Self
    }

    /// Adds an edge if an equivalent edge (same target and kind) does not already exist.
    fn add_edge_if_missing(
        graph: &mut AttackGraph,
        source: &NodeId,
        target: &NodeId,
        kind: EdgeKind,
        label: impl Into<String>,
        evidence: Option<String>,
    ) -> bool {
        let exists = graph
            .out_edges(source)
            .iter()
            .any(|e| e.target == *target && e.kind == kind);

        if !exists {
            let mut edge = AttackEdge::new(target.clone(), kind, label);
            if let Some(ev) = evidence {
                edge = edge.with_evidence(ev);
            }
            graph.add_edge(source.clone(), edge);
            true
        } else {
            false
        }
    }

    /// Rule 1: Link Entrypoint nodes to Service nodes via `Exposes`.
    pub fn apply_rule_1_entrypoint_to_service(graph: &mut AttackGraph) -> usize {
        let entrypoints: Vec<NodeId> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Entrypoint)
            .map(|n| n.id.clone())
            .collect();

        if entrypoints.is_empty() {
            return 0;
        }

        let mut services: Vec<NodeId> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Service)
            .map(|n| n.id.clone())
            .collect();

        // Synthesize default service if none declared
        if services.is_empty() {
            let default_service_id =
                compute_node_id(NodeKind::Service, "cyberguard-graph", "service:backend-app");
            let service_node = AttackNode::new(
                default_service_id.clone(),
                NodeKind::Service,
                "Service: Core Application Backend",
                "Internal application service or API server exposed by network entrypoints.",
                0.50,
                "cyberguard-graph",
            );
            graph.add_node(service_node);
            services.push(default_service_id);
        }

        let mut edge_count = 0;
        for ep in &entrypoints {
            for svc in &services {
                if Self::add_edge_if_missing(
                    graph,
                    ep,
                    svc,
                    EdgeKind::Exposes,
                    "Exposes application service",
                    Some("Public entrypoint routes traffic to backend service".to_string()),
                ) {
                    edge_count += 1;
                }
            }
        }

        edge_count
    }

    /// Rule 2: Link Service nodes to Vulnerability nodes via `AllowsExploit`.
    pub fn apply_rule_2_service_to_vulnerability(graph: &mut AttackGraph) -> usize {
        let services: Vec<NodeId> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Service)
            .map(|n| n.id.clone())
            .collect();

        let vulnerabilities: Vec<(NodeId, String)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Vulnerability)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect();

        let mut edge_count = 0;
        for svc in &services {
            for (vuln_id, label) in &vulnerabilities {
                if Self::add_edge_if_missing(
                    graph,
                    svc,
                    vuln_id,
                    EdgeKind::AllowsExploit,
                    "Allows exploitation of vulnerability",
                    Some(format!("Service hosts vulnerable component: {}", label)),
                ) {
                    edge_count += 1;
                }
            }
        }

        edge_count
    }

    /// Rule 3: Link Vulnerability nodes to Secret nodes via `LeadsToCredential`.
    pub fn apply_rule_3_vulnerability_to_secret(graph: &mut AttackGraph) -> usize {
        let secrets: Vec<(NodeId, String)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Secret)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect();

        if secrets.is_empty() {
            return 0;
        }

        let vulnerabilities: Vec<(NodeId, String, bool)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Vulnerability)
            .map(|n| {
                let text = format!("{} {}", n.label, n.description).to_lowercase();
                let is_credential_leaker = text.contains("sqli")
                    || text.contains("sql injection")
                    || text.contains("rce")
                    || text.contains("remote code")
                    || text.contains("command injection")
                    || text.contains("cmdi")
                    || text.contains("ssrf")
                    || text.contains("traversal")
                    || text.contains("lfi")
                    || text.contains("arbitrary file")
                    || text.contains("deserialization")
                    || n.risk_score >= 0.70;
                (n.id.clone(), n.label.clone(), is_credential_leaker)
            })
            .collect();

        let mut edge_count = 0;
        for (vuln_id, vuln_label, is_leaker) in &vulnerabilities {
            if *is_leaker {
                for (sec_id, sec_label) in &secrets {
                    if Self::add_edge_if_missing(
                        graph,
                        vuln_id,
                        sec_id,
                        EdgeKind::LeadsToCredential,
                        "Leads to credential disclosure",
                        Some(format!(
                            "Exploitation of {} allows extraction of secret {}",
                            vuln_label, sec_label
                        )),
                    ) {
                        edge_count += 1;
                    }
                }
            }
        }

        edge_count
    }

    /// Rule 4: Link Secret nodes to Cloud Asset / Infrastructure nodes via `GrantsAccess`.
    pub fn apply_rule_4_secret_to_asset(graph: &mut AttackGraph) -> usize {
        let secrets: Vec<(NodeId, String)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Secret)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect();

        if secrets.is_empty() {
            return 0;
        }

        let mut assets: Vec<(NodeId, String)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Asset)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect();

        // Synthesize target asset if none exists
        if assets.is_empty() {
            let asset_id = compute_node_id(
                NodeKind::Asset,
                "cyberguard-graph",
                "asset:cloud-data-store",
            );
            let asset_node = AttackNode::new(
                asset_id.clone(),
                NodeKind::Asset,
                "Asset: Production Cloud Infrastructure & Database",
                "Internal cloud data stores, S3 buckets, and production databases protected by credentials.",
                0.80,
                "cyberguard-graph",
            );
            graph.add_node(asset_node);
            assets.push((
                asset_id,
                "Asset: Production Cloud Infrastructure & Database".to_string(),
            ));
        }

        let mut edge_count = 0;
        for (sec_id, sec_label) in &secrets {
            for (asset_id, asset_label) in &assets {
                if Self::add_edge_if_missing(
                    graph,
                    sec_id,
                    asset_id,
                    EdgeKind::GrantsAccess,
                    "Grants access to internal asset",
                    Some(format!(
                        "Compromised credential {} authorizes access to {}",
                        sec_label, asset_label
                    )),
                ) {
                    edge_count += 1;
                }
            }
        }

        edge_count
    }

    /// Rule 5: Link Asset / Privilege nodes to terminal Impact nodes via `EscalatesTo` / `ResultsIn`.
    pub fn apply_rule_5_privilege_to_impact(graph: &mut AttackGraph) -> usize {
        let privileges: Vec<(NodeId, String)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Privilege)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect();

        let assets: Vec<(NodeId, String)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Asset)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect();

        let mut impacts: Vec<(NodeId, String)> = graph
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::Impact)
            .map(|n| (n.id.clone(), n.label.clone()))
            .collect();

        // Synthesize terminal impact if none exists
        if impacts.is_empty() {
            let impact_id = compute_node_id(
                NodeKind::Impact,
                "cyberguard-graph",
                "impact:data-exfiltration",
            );
            let impact_node = AttackNode::new(
                impact_id.clone(),
                NodeKind::Impact,
                "Impact: Exfiltration of Sensitive Production Data",
                "Unauthorized exfiltration of sensitive production customer data and administrative takeover.",
                0.95,
                "cyberguard-graph",
            );
            graph.add_node(impact_node);
            impacts.push((
                impact_id,
                "Impact: Exfiltration of Sensitive Production Data".to_string(),
            ));
        }

        let mut edge_count = 0;

        // If privileges exist, connect assets -> privileges if appropriate
        for (asset_id, asset_label) in &assets {
            for (priv_id, priv_label) in &privileges {
                if Self::add_edge_if_missing(
                    graph,
                    asset_id,
                    priv_id,
                    EdgeKind::EscalatesTo,
                    "Escalates privilege",
                    Some(format!(
                        "Access to {} enables privilege escalation via {}",
                        asset_label, priv_label
                    )),
                ) {
                    edge_count += 1;
                }
            }
        }

        // Connect privileges to terminal impacts
        if !privileges.is_empty() {
            for (priv_id, priv_label) in &privileges {
                for (impact_id, impact_label) in &impacts {
                    if Self::add_edge_if_missing(
                        graph,
                        priv_id,
                        impact_id,
                        EdgeKind::ResultsIn,
                        "Results in critical impact",
                        Some(format!(
                            "Administrative capability {} results in {}",
                            priv_label, impact_label
                        )),
                    ) {
                        edge_count += 1;
                    }
                }
            }
        } else {
            // If no privileges, connect assets directly to impacts
            for (asset_id, asset_label) in &assets {
                for (impact_id, impact_label) in &impacts {
                    if Self::add_edge_if_missing(
                        graph,
                        asset_id,
                        impact_id,
                        EdgeKind::ResultsIn,
                        "Results in critical impact",
                        Some(format!(
                            "Compromised asset {} results in {}",
                            asset_label, impact_label
                        )),
                    ) {
                        edge_count += 1;
                    }
                }
            }
        }

        edge_count
    }
}

impl GraphCorrelator for StandardGraphCorrelator {
    fn correlate(&self, graph: &mut AttackGraph) -> Result<usize, GraphError> {
        let mut total_edges = 0;
        total_edges += Self::apply_rule_1_entrypoint_to_service(graph);
        total_edges += Self::apply_rule_2_service_to_vulnerability(graph);
        total_edges += Self::apply_rule_3_vulnerability_to_secret(graph);
        total_edges += Self::apply_rule_4_secret_to_asset(graph);
        total_edges += Self::apply_rule_5_privilege_to_impact(graph);
        Ok(total_edges)
    }
}
