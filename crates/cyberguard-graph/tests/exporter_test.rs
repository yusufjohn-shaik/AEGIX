use cyberguard_graph::{
    AttackEdge, AttackGraph, AttackNode, ChokePointAnalyzer, EdgeKind, GraphExporter, JsonExporter,
    MermaidExporter, NodeKind, PathFinder, SarifExporter, StandardChokePointAnalyzer,
    StandardPathFinder, TerminalExporter,
};

fn create_sample_graph() -> (
    AttackGraph,
    Vec<cyberguard_graph::AttackPath>,
    Vec<cyberguard_graph::ChokePoint>,
) {
    let mut graph = AttackGraph::new();

    let ep = AttackNode::new(
        "ep-1",
        NodeKind::Entrypoint,
        "Port 443 HTTPS",
        "Public Gateway",
        0.6,
        "net",
    );
    let svc = AttackNode::new(
        "svc-1",
        NodeKind::Service,
        "Auth Service",
        "Core Auth",
        0.5,
        "graph",
    );
    let vuln = AttackNode::new(
        "vuln-1",
        NodeKind::Vulnerability,
        "CVE-2024-SQLI",
        "SQL Injection",
        0.9,
        "sast",
    );
    let sec = AttackNode::new(
        "sec-1",
        NodeKind::Secret,
        "AWS_ACCESS_KEY",
        "Leaked AWS key",
        0.95,
        "secret",
    );
    let asset = AttackNode::new(
        "asset-1",
        NodeKind::Asset,
        "Prod S3 Bucket",
        "Customer Data",
        0.9,
        "cloud",
    );
    let imp = AttackNode::new(
        "imp-1",
        NodeKind::Impact,
        "Customer PII Breach",
        "Data exfiltration",
        1.0,
        "graph",
    );

    graph.add_node(ep);
    graph.add_node(svc);
    graph.add_node(vuln);
    graph.add_node(sec);
    graph.add_node(asset);
    graph.add_node(imp);

    graph.add_edge(
        "ep-1",
        AttackEdge::new("svc-1", EdgeKind::Exposes, "exposes"),
    );
    graph.add_edge(
        "svc-1",
        AttackEdge::new("vuln-1", EdgeKind::AllowsExploit, "allows"),
    );
    graph.add_edge(
        "vuln-1",
        AttackEdge::new("sec-1", EdgeKind::LeadsToCredential, "leads"),
    );
    graph.add_edge(
        "sec-1",
        AttackEdge::new("asset-1", EdgeKind::GrantsAccess, "grants"),
    );
    graph.add_edge(
        "asset-1",
        AttackEdge::new("imp-1", EdgeKind::ResultsIn, "results"),
    );

    let pf = StandardPathFinder::new();
    let paths = pf.find_paths(&graph, 10, 100, 0.0).unwrap();

    let ca = StandardChokePointAnalyzer::new();
    let choke_points = ca.analyze_choke_points(&graph, &paths).unwrap();

    (graph, paths, choke_points)
}

#[test]
fn test_terminal_exporter() {
    let (graph, paths, choke_points) = create_sample_graph();
    let exporter = TerminalExporter::new(false);
    let output = exporter
        .export(&graph, &paths, &choke_points)
        .expect("terminal export succeeds");

    assert!(output.contains("AEGIX ATTACK PATH ENGINE"));
    assert!(output.contains("Discovered Exploit Chains:"));
    assert!(output.contains("HIGH-LEVERAGE REMEDIATION CHOKE POINTS"));
    assert!(output.contains("Customer PII Breach"));
}

#[test]
fn test_mermaid_exporter() {
    let (graph, paths, choke_points) = create_sample_graph();
    let exporter = MermaidExporter::new();
    let output = exporter
        .export(&graph, &paths, &choke_points)
        .expect("mermaid export succeeds");

    assert!(output.starts_with("```mermaid\nflowchart LR"));
    assert!(output.contains("-->|exposes|"));
    assert!(output.contains("-->|results_in|"));
    assert!(output.ends_with("```\n"));
}

#[test]
fn test_json_exporter() {
    let (graph, paths, choke_points) = create_sample_graph();
    let exporter = JsonExporter::new();
    let output = exporter
        .export(&graph, &paths, &choke_points)
        .expect("json export succeeds");

    let val: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
    assert!(val.get("graph").is_some());
    assert!(val.get("paths").is_some());
    assert!(val.get("choke_points").is_some());
    assert!(val.get("summary").is_some());
}

#[test]
fn test_sarif_code_flow_exporter() {
    let (graph, paths, choke_points) = create_sample_graph();
    let exporter = SarifExporter::new();
    let output = exporter
        .export(&graph, &paths, &choke_points)
        .expect("sarif export succeeds");

    let sarif: cyberguard_core::sarif::SarifLog =
        serde_json::from_str(&output).expect("valid SARIF v2.1.0");
    assert_eq!(sarif.runs.len(), 1);
    let run = &sarif.runs[0];
    assert_eq!(run.tool.driver.name, "cyberguard-graph");
    assert_eq!(run.results.len(), 1);

    let res = &run.results[0];
    assert_eq!(res.rule_id, "PATH-EXPLOIT-CHAIN");
    assert_eq!(res.code_flows.len(), 1);
    assert_eq!(res.code_flows[0].thread_flows.len(), 1);
    assert_eq!(res.code_flows[0].thread_flows[0].locations.len(), 6);
}
