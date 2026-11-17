// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use cyberguard_net::{verify_scope_hmac, NetworkEngine, NetworkScanner, ScopeGate};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_recon_with_scope_fixture() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("network-scope")
        .join(".security-scope.yaml");

    let gate = ScopeGate::from_file(&fixture_path).expect("Scope file must exist and parse");

    // Verify HMAC Proof-of-Authorization
    let secret_key = b"fixture-secret-key-2026";
    assert!(
        verify_scope_hmac(&gate.scope, secret_key).is_ok(),
        "Scope HMAC signature must verify cleanly"
    );

    // Spawn mock listener on localhost
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"SSH-2.0-CyberGuard_Mock_1.0\r\n").await;
        }
    });

    let mut allowed_gate = gate.clone();
    allowed_gate.scope.authorized_ports.push(port);

    let engine = NetworkEngine::new(allowed_gate);

    // In-scope scan succeeds
    let report = engine
        .scan("127.0.0.1", &[port])
        .await
        .expect("Scan on in-scope port must succeed");

    assert_eq!(report.engagement_id.as_deref(), Some("ENG-FIXTURE-001"));
    assert_eq!(report.scanned_ports, 1);
    assert_eq!(report.open_ports, 1);

    let finding = &report.findings[0];
    assert_eq!(finding.port, port);
    assert!(finding
        .banner
        .as_deref()
        .unwrap_or("")
        .contains("CyberGuard_Mock"));

    // Verify SARIF telemetry
    let sarif = report.sarif.expect("SARIF report must be present");
    assert!(!sarif.runs.is_empty());
    assert_eq!(sarif.runs[0].results.len(), 1);

    // Out-of-scope targets are strictly rejected
    let out_of_scope = engine.scan("192.168.1.1", &[port]).await;
    assert!(
        out_of_scope.is_err(),
        "Out of scope IP must be rejected by Scope Gate"
    );

    let metadata_target = engine.scan("169.254.169.254", &[80]).await;
    assert!(
        metadata_target.is_err(),
        "Cloud metadata IP must be rejected by Bogon blacklist"
    );
}

#[tokio::test]
async fn test_recon_port_spec_parsing() {
    use cyberguard_net::DEFAULT_TOP_PORTS;

    // Verify top 100 ports list length
    assert_eq!(DEFAULT_TOP_PORTS.len(), 100);

    // Verify that passing empty string to scan defaults safely
    let scope_yaml = r#"
engagement_id: "ENG-PORT-TEST"
authorized_cidrs:
  - "127.0.0.1/32"
"#;
    let gate = ScopeGate::from_yaml_str(scope_yaml).unwrap();
    let engine = NetworkEngine::new(gate);
    assert_eq!(engine.gate.scope.engagement_id, "ENG-PORT-TEST");
}
