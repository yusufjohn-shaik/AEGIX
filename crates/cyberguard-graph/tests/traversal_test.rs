use cyberguard_graph::{
    calculate_path_risk, AttackEdge, AttackGraph, AttackNode, ChokePointAnalyzer, EdgeKind, NodeId,
    NodeKind, PathFinder, StandardChokePointAnalyzer, StandardPathFinder,
};

#[test]
fn test_cycle_avoidance() {
    let mut graph = AttackGraph::new();

    let ep = AttackNode::new(
        "n-ep",
        NodeKind::Entrypoint,
        "Public Port",
        "Open port 80",
        0.6,
        "test",
    );
    let b = AttackNode::new(
        "n-b",
        NodeKind::Vulnerability,
        "Vuln B",
        "Flaw B",
        0.7,
        "test",
    );
    let c = AttackNode::new(
        "n-c",
        NodeKind::Vulnerability,
        "Vuln C",
        "Flaw C",
        0.8,
        "test",
    );
    let imp = AttackNode::new(
        "n-imp",
        NodeKind::Impact,
        "Impact Node",
        "Critical Data Exfil",
        0.95,
        "test",
    );

    graph.add_node(ep);
    graph.add_node(b);
    graph.add_node(c);
    graph.add_node(imp);

    // Create cycle: EP -> B -> C -> B (cycle between B and C)
    // and C -> Imp
    graph.add_edge("n-ep", AttackEdge::new("n-b", EdgeKind::Exposes, "link"));
    graph.add_edge(
        "n-b",
        AttackEdge::new("n-c", EdgeKind::AllowsExploit, "link"),
    );
    graph.add_edge(
        "n-c",
        AttackEdge::new("n-b", EdgeKind::AllowsExploit, "cycle-edge"),
    );
    graph.add_edge("n-c", AttackEdge::new("n-imp", EdgeKind::ResultsIn, "link"));

    let path_finder = StandardPathFinder::new();
    let paths = path_finder
        .find_paths(&graph, 10, 100, 0.0)
        .expect("traversal succeeds despite cycle");

    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0].node_ids,
        vec![
            NodeId::from("n-ep"),
            NodeId::from("n-b"),
            NodeId::from("n-c"),
            NodeId::from("n-imp")
        ]
    );
}

#[test]
fn test_path_depth_limiting() {
    let mut graph = AttackGraph::new();

    let ep = AttackNode::new("n-0", NodeKind::Entrypoint, "EP", "Start", 0.5, "test");
    graph.add_node(ep);

    for i in 1..=10 {
        let kind = if i == 10 {
            NodeKind::Impact
        } else {
            NodeKind::Vulnerability
        };
        let node = AttackNode::new(
            format!("n-{}", i),
            kind,
            format!("Node {}", i),
            "Step",
            0.6,
            "test",
        );
        graph.add_node(node);
        graph.add_edge(
            format!("n-{}", i - 1),
            AttackEdge::new(format!("n-{}", i), EdgeKind::AllowsExploit, "step"),
        );
    }

    let path_finder = StandardPathFinder::new();

    // With depth limit 5, a 10-hop path cannot reach terminal node
    let paths_short = path_finder
        .find_paths(&graph, 5, 100, 0.0)
        .expect("traversal succeeds");
    assert_eq!(paths_short.len(), 0);

    // With depth limit 12, the path reaches the terminal node
    let paths_long = path_finder
        .find_paths(&graph, 12, 100, 0.0)
        .expect("traversal succeeds");
    assert_eq!(paths_long.len(), 1);
    assert_eq!(paths_long[0].hop_count, 10);
}

#[test]
fn test_diamond_graph_choke_point_analysis() {
    let mut graph = AttackGraph::new();

    let ep = AttackNode::new(
        "ep-1",
        NodeKind::Entrypoint,
        "Public Gateway",
        "Internet ingress",
        0.5,
        "test",
    );
    let v1 = AttackNode::new(
        "v-1",
        NodeKind::Vulnerability,
        "SSRF in Webhook",
        "SSRF",
        0.8,
        "test",
    );
    let v2 = AttackNode::new(
        "v-2",
        NodeKind::Vulnerability,
        "SQLi in Login",
        "SQLi",
        0.9,
        "test",
    );
    let choke = AttackNode::new(
        "choke-secret",
        NodeKind::Secret,
        "Production AWS Credentials",
        "Leaked root key",
        0.95,
        "test",
    );
    let asset = AttackNode::new(
        "asset-db",
        NodeKind::Asset,
        "Primary RDS Database",
        "Customer DB",
        0.9,
        "test",
    );
    let impact = AttackNode::new(
        "impact-exfil",
        NodeKind::Impact,
        "Full Customer PII Breach",
        "Breach",
        1.0,
        "test",
    );

    graph.add_node(ep);
    graph.add_node(v1);
    graph.add_node(v2);
    graph.add_node(choke);
    graph.add_node(asset);
    graph.add_node(impact);

    // Path 1: ep -> v1 -> choke -> asset -> impact
    graph.add_edge("ep-1", AttackEdge::new("v-1", EdgeKind::Exposes, "route 1"));
    graph.add_edge(
        "v-1",
        AttackEdge::new("choke-secret", EdgeKind::LeadsToCredential, "leak 1"),
    );

    // Path 2: ep -> v2 -> choke -> asset -> impact
    graph.add_edge("ep-1", AttackEdge::new("v-2", EdgeKind::Exposes, "route 2"));
    graph.add_edge(
        "v-2",
        AttackEdge::new("choke-secret", EdgeKind::LeadsToCredential, "leak 2"),
    );

    // Common segment: choke -> asset -> impact
    graph.add_edge(
        "choke-secret",
        AttackEdge::new("asset-db", EdgeKind::GrantsAccess, "auth"),
    );
    graph.add_edge(
        "asset-db",
        AttackEdge::new("impact-exfil", EdgeKind::ResultsIn, "exfil"),
    );

    let path_finder = StandardPathFinder::new();
    let paths = path_finder.find_paths(&graph, 10, 100, 0.0).unwrap();
    assert_eq!(paths.len(), 2);

    let analyzer = StandardChokePointAnalyzer::new();
    let choke_points = analyzer.analyze_choke_points(&graph, &paths).unwrap();

    assert!(!choke_points.is_empty());
    // Both choke-secret and asset-db block 2 paths
    let top = &choke_points[0];
    assert_eq!(top.paths_blocked_count, 2);
    assert!(top.choke_score > 0.0);
    assert!(top.node_id == NodeId::from("choke-secret") || top.node_id == NodeId::from("asset-db"));
}

#[test]
fn test_compounding_path_risk_formula() {
    let n1 = AttackNode::new("n1", NodeKind::Entrypoint, "EP", "", 0.5, "test");
    let n2 = AttackNode::new("n2", NodeKind::Vulnerability, "V", "", 0.8, "test");
    let n3 = AttackNode::new("n3", NodeKind::Impact, "I", "", 0.95, "test");

    let risk = calculate_path_risk(&[&n1, &n2, &n3]);
    assert!(risk > 0.0 && risk <= 100.0);

    // Single node check
    let single_risk = calculate_path_risk(&[&n3]);
    assert!(single_risk > 0.0 && single_risk <= 100.0);
}
