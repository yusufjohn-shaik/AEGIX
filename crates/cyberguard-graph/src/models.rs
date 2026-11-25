//! Canonical data models for the Attack Path Graph, nodes, edges, and choke points.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Deterministic unique identifier for a graph node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&NodeId> for NodeId {
    fn from(id: &NodeId) -> Self {
        id.clone()
    }
}

/// Computes a deterministic SHA-256 node ID based on kind, engine, and location/identifier.
pub fn compute_node_id(kind: NodeKind, source_engine: &str, identifier: &str) -> NodeId {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(source_engine.as_bytes());
    hasher.update(b":");
    hasher.update(identifier.as_bytes());
    let hash = hasher.finalize();
    let hex_str: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    NodeId(format!("{}-{}", kind.as_str(), &hex_str[..16]))
}

/// High-level categorization of attack graph nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// Public IP, exposed port, DNS host, or unauthenticated route.
    Entrypoint,
    /// Internal service, microservice, or web application container.
    Service,
    /// Software vulnerability (SAST, SCA, DAST, or API flaw).
    Vulnerability,
    /// Leaked secret, private key, or credential.
    Secret,
    /// Sensitive internal asset, database, cloud bucket, or host node.
    Asset,
    /// Administrative entitlement, IAM role, or root capability.
    Privilege,
    /// Terminal security impact (Data Exfiltration, Ransomware, Takeover).
    Impact,
}

impl NodeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Entrypoint => "entrypoint",
            Self::Service => "service",
            Self::Vulnerability => "vulnerability",
            Self::Secret => "secret",
            Self::Asset => "asset",
            Self::Privilege => "privilege",
            Self::Impact => "impact",
        }
    }
}

/// Physical and logical location metadata for a graph node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_or_route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_asset: Option<String>,
}

/// A discrete node in the attack graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub label: String,
    pub description: String,
    /// Normalized risk score in range [0.0, 1.0].
    pub risk_score: f64,
    pub source_engine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<NodeLocation>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl AttackNode {
    pub fn new(
        id: impl Into<NodeId>,
        kind: NodeKind,
        label: impl Into<String>,
        description: impl Into<String>,
        risk_score: f64,
        source_engine: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            label: label.into(),
            description: description.into(),
            risk_score: risk_score.clamp(0.0, 1.0),
            source_engine: source_engine.into(),
            location: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_location(mut self, location: NodeLocation) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Categorization of directed exploit edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// An entrypoint exposes an internal service or API endpoint.
    Exposes,
    /// An exposed service contains an exploitable vulnerability.
    AllowsExploit,
    /// A code execution or traversal vulnerability leads to a leaked credential.
    LeadsToCredential,
    /// A credential grants access to an internal asset or cloud resource.
    GrantsAccess,
    /// An asset or credential permits IAM/root privilege escalation.
    EscalatesTo,
    /// An escalation or critical vulnerability results in terminal impact.
    ResultsIn,
}

impl EdgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exposes => "exposes",
            Self::AllowsExploit => "allows_exploit",
            Self::LeadsToCredential => "leads_to_credential",
            Self::GrantsAccess => "grants_access",
            Self::EscalatesTo => "escalates_to",
            Self::ResultsIn => "results_in",
        }
    }
}

/// A directed edge linking two nodes in the attack graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackEdge {
    pub target: NodeId,
    pub kind: EdgeKind,
    pub label: String,
    pub weight: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl AttackEdge {
    pub fn new(target: impl Into<NodeId>, kind: EdgeKind, label: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            kind,
            label: label.into(),
            weight: 1.0,
            evidence: None,
        }
    }

    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

/// Primary in-memory Attack Graph structure.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackGraph {
    pub nodes: BTreeMap<NodeId, AttackNode>,
    pub adjacency: BTreeMap<NodeId, Vec<AttackEdge>>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: AttackNode) -> NodeId {
        let id = node.id.clone();
        self.nodes.insert(id.clone(), node);
        self.adjacency.entry(id.clone()).or_default();
        id
    }

    pub fn add_edge(&mut self, source: impl Into<NodeId>, edge: AttackEdge) {
        let source_id = source.into();
        self.adjacency.entry(source_id).or_default().push(edge);
    }

    pub fn get_node(&self, id: &NodeId) -> Option<&AttackNode> {
        self.nodes.get(id)
    }

    pub fn out_edges(&self, id: &NodeId) -> &[AttackEdge] {
        self.adjacency.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.adjacency.values().map(|v| v.len()).sum()
    }

    pub fn entrypoints(&self) -> Vec<&AttackNode> {
        self.nodes
            .values()
            .filter(|n| n.kind == NodeKind::Entrypoint)
            .collect()
    }

    pub fn impacts(&self) -> Vec<&AttackNode> {
        self.nodes
            .values()
            .filter(|n| n.kind == NodeKind::Impact)
            .collect()
    }
}

/// A discovered multi-hop exploit path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub node_ids: Vec<NodeId>,
    pub edge_kinds: Vec<EdgeKind>,
    pub path_risk: f64,
    pub entrypoint_id: NodeId,
    pub impact_id: NodeId,
    pub hop_count: usize,
}

/// A high-leverage choke point in the attack graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChokePoint {
    pub node_id: NodeId,
    pub node_label: String,
    pub node_kind: NodeKind,
    pub choke_score: f64,
    pub paths_blocked_count: usize,
    pub blocked_path_ids: Vec<String>,
    pub remediation_guidance: String,
}
