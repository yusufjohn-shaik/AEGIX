use cyberguard_dast::engine::DastEngine;
use cyberguard_dast::models::DastTarget;
use cyberguard_dast::traits::DastScanner;
use cyberguard_net::models::SecurityScope;
use cyberguard_net::ScopeGate;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn test_dast_engine_end_to_end_scan_and_sarif() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET / ") {
                        // Root URL missing HSTS, CSP, X-Frame-Options
                        let body = "Welcome to Vulnerable Web App";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nX-Powered-By: PHP/7.4.3\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if req.contains("GET /.env") {
                        let body = "APP_KEY=base64:abcd1234efgh5678\nDB_PASS=admin\n";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                });
            }
        }
    });

    let target_url = Url::parse(&format!("http://127.0.0.1:{}", port)).unwrap();
    let target = DastTarget::new(target_url);

    let scope = ScopeGate::new(SecurityScope {
        engagement_id: "test-engine".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["127.0.0.1/32".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec![],
        authorized_ports: vec![],
        signature: None,
    });

    let engine = DastEngine::new().with_timeout_ms(2000);
    let report = engine.scan(&target, &scope).await.unwrap();

    assert!(report.tested_endpoints_count > 0);
    assert!(!report.findings.is_empty());

    // Check that SARIF was generated with deterministic fingerprints
    let sarif = &report.sarif_log;
    assert_eq!(sarif.runs.len(), 1);
    let run = &sarif.runs[0];
    assert!(!run.results.is_empty());

    for r in &run.results {
        assert!(r.partial_fingerprints.is_some());
        let fps = r.partial_fingerprints.as_ref().unwrap();
        assert!(fps.contains_key("deterministicSha256"));
    }
}
