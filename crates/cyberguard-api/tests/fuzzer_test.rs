use cyberguard_api::fuzzer::DefaultApiFuzzer;
use cyberguard_api::models::ApiConfig;
use cyberguard_api::parser::parse_spec_str;
use cyberguard_api::traits::ApiFuzzer;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_fuzzer_server_crash_500_detection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    // If request contains boundary mutation i64::MAX or null byte, simulate crash 500
                    if req.contains("9223372036854775807")
                        || req.contains("%00")
                        || req.contains("0")
                    {
                        let body = "Traceback (most recent call last):\n  File 'app.py', line 42, in get_item\nZeroDivisionError: division by zero";
                        let response = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let body = r#"{"status": "ok"}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                });
            }
        }
    });

    let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Mock Crash Target
  version: 1.0.0
paths:
  /items/{id}:
    get:
      summary: Retrieve item by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;

    let spec = parse_spec_str(spec_yaml, None).unwrap();
    let config = ApiConfig {
        spec_path: PathBuf::from("mock_crash.yaml"),
        target: Some(format!("http://127.0.0.1:{}", port)),
        fuzz: true,
        allow_destructive: false,
        dry_run: false,
        scope_path: None,
        scope_key: None,
        max_rps: 100,
        timeout_ms: 2000,
        headers: vec!["Authorization: Bearer test_token".to_string()],
        insecure: true,
        schemathesis: false,
        baseline_path: None,
        format: "terminal".to_string(),
    };

    let fuzzer = DefaultApiFuzzer::new();
    let findings = fuzzer
        .fuzz(&spec, &config)
        .await
        .expect("Fuzz run should complete");

    // Must detect CG-API-008: Unhandled Server Exception / 500 Crash
    let crash_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-008")
        .collect();
    assert!(
        !crash_findings.is_empty(),
        "Fuzzer must detect simulated 500 error and stack trace"
    );
    assert_eq!(crash_findings[0].cwe, 703);
}

#[tokio::test]
async fn test_fuzzer_response_schema_contract_drift_detection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await.unwrap_or(0);

                    // Return 200 OK with non-JSON HTML when spec promised application/json
                    let body = "<html><body><h1>Maintenance Gateway Page</h1></body></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Drift Target
  version: 1.0.0
paths:
  /data:
    get:
      summary: Get data
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
"#;

    let spec = parse_spec_str(spec_yaml, None).unwrap();
    let config = ApiConfig {
        spec_path: PathBuf::from("mock_drift.yaml"),
        target: Some(format!("http://127.0.0.1:{}", port)),
        fuzz: true,
        allow_destructive: false,
        dry_run: false,
        scope_path: None,
        scope_key: None,
        max_rps: 100,
        timeout_ms: 2000,
        headers: vec![],
        insecure: true,
        schemathesis: false,
        baseline_path: None,
        format: "terminal".to_string(),
    };

    let fuzzer = DefaultApiFuzzer::new();
    let findings = fuzzer
        .fuzz(&spec, &config)
        .await
        .expect("Fuzz run should complete");

    // Must detect CG-API-009: Response Schema Contract Drift
    let drift_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "CG-API-009")
        .collect();
    assert!(
        !drift_findings.is_empty(),
        "Fuzzer must detect response schema contract drift"
    );
}
