use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use cyberguard_graph::{
    AttackGraph, EdgeKind, GraphCorrelator, NodeKind, StandardGraphCorrelator,
    StandardTelemetryIngester, TelemetryIngester,
};

#[test]
fn test_sarif_telemetry_ingestion() {
    let ingester = StandardTelemetryIngester::new();
    let mut graph = AttackGraph::new();

    let mut sarif = SarifLog::new("cyberguard-sast", "0.9.0");
    let mut r1 = SarifResult::new(
        "SAST-SQLI-001",
        SarifLevel::Error,
        "SQL Injection vulnerability in user login",
    );
    r1.add_location("src/auth.rs", 42, Some(5), Some(42), Some(20));
    r1.with_tri_factor(9.8, 0.95, 0.90);

    let mut r2 = SarifResult::new(
        "SEC-AWS-KEY-001",
        SarifLevel::Error,
        "Leaked AWS Access Key in configuration",
    );
    r2.add_location("config/prod.env", 12, None, None, None);

    sarif.add_result(r1);
    sarif.add_result(r2);

    let count = ingester
        .ingest_sarif(&mut graph, &sarif)
        .expect("ingestion succeeds");
    assert_eq!(count, 2);
    assert_eq!(graph.node_count(), 2);

    let kinds: Vec<NodeKind> = graph.nodes.values().map(|n| n.kind).collect();
    assert!(kinds.contains(&NodeKind::Vulnerability));
    assert!(kinds.contains(&NodeKind::Secret));
}

#[test]
fn test_five_tier_correlation_engine() {
    let ingester = StandardTelemetryIngester::new();
    let correlator = StandardGraphCorrelator::new();
    let mut graph = AttackGraph::new();

    // 1. Entrypoint: Public API / Open Port
    let mut net_sarif = SarifLog::new("cyberguard-net", "0.9.0");
    let mut net_res = SarifResult::new(
        "NET-PORT-443",
        SarifLevel::Warning,
        "Public HTTPS endpoint exposed",
    );
    net_res.add_location("https://api.example.com", 1, None, None, None);
    net_sarif.add_result(net_res);

    // 2. Vulnerability: SQLi
    let mut sast_sarif = SarifLog::new("cyberguard-sast", "0.9.0");
    let mut sast_res = SarifResult::new(
        "SAST-SQLI-01",
        SarifLevel::Error,
        "Critical SQL Injection flaw in query handler",
    );
    sast_res.add_location("src/db.rs", 15, None, None, None);
    sast_res.with_tri_factor(9.5, 0.9, 0.9);
    sast_sarif.add_result(sast_res);

    // 3. Secret: AWS Secret Key
    let mut sec_sarif = SarifLog::new("cyberguard-secret", "0.9.0");
    let mut sec_res = SarifResult::new(
        "SEC-AWS-001",
        SarifLevel::Error,
        "Hardcoded AWS secret access key",
    );
    sec_res.add_location("config/secrets.env", 5, None, None, None);
    sec_sarif.add_result(sec_res);

    ingester.ingest_sarif(&mut graph, &net_sarif).unwrap();
    ingester.ingest_sarif(&mut graph, &sast_sarif).unwrap();
    ingester.ingest_sarif(&mut graph, &sec_sarif).unwrap();

    let edges_created = correlator
        .correlate(&mut graph)
        .expect("correlate succeeds");
    assert!(edges_created > 0);

    // Verify all 5 layers are linked
    // Entrypoint -> Service (Exposes)
    let ep = graph
        .entrypoints()
        .into_iter()
        .next()
        .expect("entrypoint exists");
    let ep_edges = graph.out_edges(&ep.id);
    assert!(ep_edges.iter().any(|e| e.kind == EdgeKind::Exposes));

    // Service -> Vulnerability (AllowsExploit)
    let svc_id = &ep_edges
        .iter()
        .find(|e| e.kind == EdgeKind::Exposes)
        .unwrap()
        .target;
    let svc_edges = graph.out_edges(svc_id);
    assert!(svc_edges.iter().any(|e| e.kind == EdgeKind::AllowsExploit));

    // Vulnerability -> Secret (LeadsToCredential)
    let vuln_id = &svc_edges
        .iter()
        .find(|e| e.kind == EdgeKind::AllowsExploit)
        .unwrap()
        .target;
    let vuln_edges = graph.out_edges(vuln_id);
    assert!(vuln_edges
        .iter()
        .any(|e| e.kind == EdgeKind::LeadsToCredential));

    // Secret -> Asset (GrantsAccess)
    let sec_id = &vuln_edges
        .iter()
        .find(|e| e.kind == EdgeKind::LeadsToCredential)
        .unwrap()
        .target;
    let sec_edges = graph.out_edges(sec_id);
    assert!(sec_edges.iter().any(|e| e.kind == EdgeKind::GrantsAccess));

    // Asset -> Impact (ResultsIn)
    let asset_id = &sec_edges
        .iter()
        .find(|e| e.kind == EdgeKind::GrantsAccess)
        .unwrap()
        .target;
    let asset_edges = graph.out_edges(asset_id);
    assert!(asset_edges.iter().any(|e| e.kind == EdgeKind::ResultsIn));
}
