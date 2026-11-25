//! Unit tests for Attack Graph data models, node ID hashing, and graph topology.

#![deny(unsafe_code)]

use cyberguard_graph::models::*;

#[test]
fn test_deterministic_node_id_hashing() {
    let id1 = compute_node_id(
        NodeKind::Vulnerability,
        "cyberguard-sast",
        "src/auth.rs:42:CG-SQLI-001",
    );
    let id2 = compute_node_id(
        NodeKind::Vulnerability,
        "cyberguard-sast",
        "src/auth.rs:42:CG-SQLI-001",
    );
    let id3 = compute_node_id(
        NodeKind::Vulnerability,
        "cyberguard-sast",
        "src/auth.rs:43:CG-SQLI-001",
    );
    let id4 = compute_node_id(
        NodeKind::Secret,
        "cyberguard-secret",
        "src/auth.rs:42:CG-SQLI-001",
    );

    assert_eq!(
        id1, id2,
        "Identical node parameters must yield identical SHA-256 node IDs"
    );
    assert_ne!(id1, id3, "Different locations must yield distinct node IDs");
    assert_ne!(
        id1, id4,
        "Different node kinds must yield distinct node IDs"
    );
    assert!(id1.0.starts_with("vulnerability-"));
    assert!(id4.0.starts_with("secret-"));
}

#[test]
fn test_attack_graph_mutation_and_query() {
    let mut graph = AttackGraph::new();

    let ep = AttackNode::new(
        "ep-1",
        NodeKind::Entrypoint,
        "Public Gateway",
        "HTTPS on 0.0.0.0:443",
        0.7,
        "cyberguard-net",
    );
    let svc = AttackNode::new(
        "svc-1",
        NodeKind::Service,
        "Auth Microservice",
        "Rust Web Service",
        0.3,
        "cyberguard-api",
    );
    let vuln = AttackNode::new(
        "vuln-1",
        NodeKind::Vulnerability,
        "SQL Injection",
        "CWE-89 in /login",
        0.95,
        "cyberguard-sast",
    );
    let imp = AttackNode::new(
        "imp-1",
        NodeKind::Impact,
        "Customer DB Exfiltration",
        "Sensitive customer records dumped",
        1.0,
        "cyberguard-threat",
    );

    let ep_id = graph.add_node(ep);
    let svc_id = graph.add_node(svc);
    let vuln_id = graph.add_node(vuln);
    let imp_id = graph.add_node(imp);

    assert_eq!(graph.node_count(), 4);
    assert_eq!(graph.entrypoints().len(), 1);
    assert_eq!(graph.impacts().len(), 1);

    graph.add_edge(
        &ep_id,
        AttackEdge::new(&svc_id, EdgeKind::Exposes, "Routes public traffic"),
    );
    graph.add_edge(
        &svc_id,
        AttackEdge::new(&vuln_id, EdgeKind::AllowsExploit, "Flaw in login handler"),
    );
    graph.add_edge(
        &vuln_id,
        AttackEdge::new(&imp_id, EdgeKind::ResultsIn, "Dumps SQL table"),
    );

    assert_eq!(graph.edge_count(), 3);
    assert_eq!(graph.out_edges(&ep_id).len(), 1);
    assert_eq!(graph.out_edges(&svc_id).len(), 1);
    assert_eq!(graph.out_edges(&vuln_id).len(), 1);
    assert_eq!(graph.out_edges(&imp_id).len(), 0);
}

#[test]
fn test_serde_roundtrip() {
    let mut graph = AttackGraph::new();
    let n1 = AttackNode::new("n1", NodeKind::Entrypoint, "Entry", "Test", 0.5, "test");
    graph.add_node(n1);

    let serialized = serde_json::to_string(&graph).expect("serialize graph");
    let deserialized: AttackGraph = serde_json::from_str(&serialized).expect("deserialize graph");

    assert_eq!(graph, deserialized);
}
