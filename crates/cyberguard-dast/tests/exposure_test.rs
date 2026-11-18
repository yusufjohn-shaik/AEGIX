use cyberguard_dast::checks::exposure::*;
use cyberguard_dast::client::DastClient;
use cyberguard_dast::models::DastTarget;
use cyberguard_net::models::SecurityScope;
use cyberguard_net::ScopeGate;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use url::Url;

#[tokio::test]
async fn test_spa_soft_404_rejected_and_true_env_detected() {
    // Start mock server responding to /.env with real config and other endpoints with SPA HTML
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if req.contains("GET /.env") {
                        let body = "DATABASE_URL=postgres://user:pass@db:5432/prod\nAPI_KEY=sk_live_123456789\n";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if req.contains("GET /.git/HEAD") {
                        // Return SPA fallback HTML with HTTP 200 (Soft 404)
                        let body = "<!DOCTYPE html><html><body><div id=\"root\">SPA Root</div></body></html>";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

    let base_url = Url::parse(&format!("http://127.0.0.1:{}", port)).unwrap();
    let target = DastTarget::new(base_url.clone());
    let client = DastClient::new(&target, 2000).unwrap();

    let scope = ScopeGate::new(SecurityScope {
        engagement_id: "test-exposure".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["127.0.0.1/32".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec![],
        authorized_ports: vec![],
        signature: None,
    });

    let semaphore = Arc::new(Semaphore::new(5));
    let findings = check_sensitive_exposures(&client, &base_url, &scope, semaphore)
        .await
        .unwrap();

    // 1. The real /.env MUST be flagged as CG-DAST-EXPO-ENV
    let env_finding = findings.iter().find(|f| f.id == "CG-DAST-EXPO-ENV");
    assert!(env_finding.is_some(), "Expected real .env to be flagged");

    // 2. The SPA soft-404 /.git/HEAD MUST NOT be flagged as CG-DAST-EXPO-GIT
    let git_finding = findings.iter().find(|f| f.id == "CG-DAST-EXPO-GIT");
    assert!(
        git_finding.is_none(),
        "SPA soft-404 HTML response must not be flagged as exposed .git"
    );
}
