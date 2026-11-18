// Copyright 2026 Aegix / CyberGuard Authors.
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

use cyberguard_api::{ApiConfig, ApiEngine, ApiScanner};
use cyberguard_core::baseline::AegixBaseline;
use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TEST_API_SPEC: &str = r#"
openapi: 3.0.0
info:
  title: Integration Test API
  version: 1.0.0
servers:
  - url: http://insecure.example.com
paths:
  /api/v1/users:
    get:
      summary: Get all users
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                role:
                  type: string
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: integer
                  password:
                    type: string
"#;

#[tokio::test]
async fn test_api_engine_static_and_sarif_export() {
    let temp_dir = std::env::temp_dir().join("aegix_api_test");
    fs::create_dir_all(&temp_dir).unwrap();
    let spec_path = temp_dir.join("openapi.yaml");
    fs::write(&spec_path, TEST_API_SPEC).unwrap();

    let config = ApiConfig {
        spec_path: spec_path.clone(),
        target: None,
        fuzz: false,
        allow_destructive: false,
        dry_run: false,
        scope_path: None,
        scope_key: None,
        max_rps: 25,
        timeout_ms: 5000,
        headers: vec![],
        insecure: false,
        schemathesis: false,
        baseline_path: None,
        format: "sarif".to_string(),
    };

    let engine = ApiEngine::new();
    let report = engine
        .scan(&config)
        .await
        .expect("Static API audit should succeed");

    assert_eq!(report.operations_count, 2);
    assert!(!report.findings.is_empty());

    // Generate SARIF
    let sarif = engine.generate_sarif(&report);
    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);
    let run = &sarif.runs[0];
    assert_eq!(run.tool.driver.name, "Aegix-API");
    assert!(!run.results.is_empty());

    // Verify rules present
    let rule_ids: Vec<&str> = run.results.iter().map(|r| r.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"CG-API-001"));
    assert!(rule_ids.contains(&"CG-API-002"));
    assert!(rule_ids.contains(&"CG-API-004"));
    assert!(rule_ids.contains(&"CG-API-006"));

    // Cleanup
    let _ = fs::remove_file(&spec_path);
}

#[tokio::test]
async fn test_api_engine_baseline_snapshot_suppression() {
    let temp_dir = std::env::temp_dir().join("aegix_api_baseline_test");
    fs::create_dir_all(&temp_dir).unwrap();
    let spec_path = temp_dir.join("openapi_baseline.yaml");
    let baseline_path = temp_dir.join("api_baseline.json");
    fs::write(&spec_path, TEST_API_SPEC).unwrap();

    let engine = ApiEngine::new();

    // 1. First run without baseline
    let config = ApiConfig {
        spec_path: spec_path.clone(),
        target: None,
        fuzz: false,
        allow_destructive: false,
        dry_run: false,
        scope_path: None,
        scope_key: None,
        max_rps: 25,
        timeout_ms: 5000,
        headers: vec![],
        insecure: false,
        schemathesis: false,
        baseline_path: None,
        format: "terminal".to_string(),
    };

    let report_initial = engine.scan(&config).await.unwrap();
    let initial_count = report_initial.findings.len();
    assert!(initial_count > 0);

    // Save baseline from SARIF log
    let sarif_log = engine.generate_sarif(&report_initial);
    let baseline = AegixBaseline::from_sarif(&sarif_log);
    baseline.save_to_path(&baseline_path).unwrap();

    // 2. Second run with baseline attached -> all known findings must be suppressed!
    let mut config_with_baseline = config.clone();
    config_with_baseline.baseline_path = Some(baseline_path.clone());

    let report_suppressed = engine.scan(&config_with_baseline).await.unwrap();
    assert_eq!(
        report_suppressed.findings.len(),
        0,
        "All findings should be suppressed by baseline snapshot"
    );

    // Cleanup
    let _ = fs::remove_file(&spec_path);
    let _ = fs::remove_file(&baseline_path);
}

#[tokio::test]
async fn test_api_cli_active_fuzzing_with_mock_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await.unwrap_or(0);
                    let body = r#"{"result": "ok"}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let spec_content = r#"
openapi: 3.0.0
info:
  title: Mock Server Test
  version: 1.0.0
paths:
  /ping:
    get:
      summary: Ping endpoint
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
      security:
        - bearerAuth: []
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
"#;

    let temp_dir = std::env::temp_dir().join("aegix_fuzz_cli_test");
    fs::create_dir_all(&temp_dir).unwrap();
    let spec_path = temp_dir.join("spec.yaml");
    fs::write(&spec_path, spec_content).unwrap();

    let config = ApiConfig {
        spec_path: spec_path.clone(),
        target: Some(format!("http://127.0.0.1:{}", port)),
        fuzz: true,
        allow_destructive: false,
        dry_run: false,
        scope_path: None,
        scope_key: None,
        max_rps: 50,
        timeout_ms: 2000,
        headers: vec!["Authorization: Bearer token123".to_string()],
        insecure: true,
        schemathesis: false,
        baseline_path: None,
        format: "terminal".to_string(),
    };

    let engine = ApiEngine::new();
    let report = engine
        .scan(&config)
        .await
        .expect("Fuzzing run against mock server should succeed");

    assert_eq!(report.fuzzed_endpoints, 1);
    assert!(report.fuzzer_requests_sent > 0);
    // Healthy 200 OK responses -> 0 fuzzer crashes
    assert_eq!(report.fuzzer_errors_found, 0);

    // Cleanup
    let _ = fs::remove_file(&spec_path);
}
