use cyberguard_net::models::{PortStatus, SecurityScope};
use cyberguard_net::nmap::parse_grepable_nmap;
use cyberguard_net::scope::ScopeGate;
use cyberguard_net::traits::NetworkScanner;
use cyberguard_net::NetworkEngine;
use tokio::net::TcpListener;

#[test]
fn test_parse_grepable_nmap_output() {
    let sample_og = "Host: 192.168.1.50 (test.corp)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/tcp//http//nginx 1.24.0/, 3306/closed/tcp//mysql///\tIgnored State: filtered (97)";
    let findings = parse_grepable_nmap(sample_og, "test.corp");

    assert_eq!(findings.len(), 3);

    let ssh = findings.iter().find(|f| f.port == 22).unwrap();
    assert_eq!(ssh.status, PortStatus::Open);
    assert_eq!(ssh.service, "ssh");
    assert_eq!(ssh.banner.as_deref(), Some("OpenSSH 8.9p1"));

    let mysql = findings.iter().find(|f| f.port == 3306).unwrap();
    assert_eq!(mysql.status, PortStatus::Closed);
    assert_eq!(mysql.service, "mysql");
}

#[tokio::test]
async fn test_network_engine_full_scan_and_sarif() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    let scope = SecurityScope {
        engagement_id: "ENG-ENGINE-TEST".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["127.0.0.1/32".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec!["localhost".to_string()],
        authorized_ports: vec![port],
        signature: None,
    };

    let gate = ScopeGate::new(scope);
    let engine = NetworkEngine::new(gate);

    let report = engine
        .scan("127.0.0.1", &[port])
        .await
        .expect("Scan executes successfully");

    assert_eq!(report.engagement_id.as_deref(), Some("ENG-ENGINE-TEST"));
    assert_eq!(report.scanned_ports, 1);
    assert_eq!(report.open_ports, 1);

    // Verify SARIF output
    let sarif = report.sarif.expect("SARIF report must be populated");
    assert!(!sarif.runs.is_empty());
    let run = &sarif.runs[0];
    assert_eq!(run.tool.driver.name, "CyberGuard Network Recon Engine");
    assert!(!run.results.is_empty());

    let result = &run.results[0];
    assert_eq!(result.rule_id, "CG-NET-PORT-OPEN");
    assert!(result
        .partial_fingerprints
        .as_ref()
        .unwrap()
        .contains_key("deterministicSha256"));
}
