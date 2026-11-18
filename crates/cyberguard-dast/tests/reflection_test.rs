use cyberguard_dast::checks::reflection::check_active_reflection;
use cyberguard_dast::client::DastClient;
use cyberguard_dast::models::DastTarget;
use cyberguard_net::models::SecurityScope;
use cyberguard_net::ScopeGate;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn test_active_xss_reflection_unescaped_detection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    if let Some(pos) = req.find("GET /search?") {
                        let query_part = &req[pos + 12..];
                        let query_str = query_part.split_whitespace().next().unwrap_or("");
                        let mut reflected = String::new();
                        for (k, v) in url::form_urlencoded::parse(query_str.as_bytes()) {
                            if k == "q" {
                                reflected = v.into_owned();
                                break;
                            }
                        }
                        let body = format!(
                            "<html><body><h1>Search Results for: {}</h1></body></html>",
                            reflected
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                        return;
                    }

                    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello World\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let base_url = Url::parse(&format!("http://127.0.0.1:{}/search", port)).unwrap();
    let target = DastTarget::new(base_url.clone());
    let client = DastClient::new(&target, 2000).unwrap();

    let scope = ScopeGate::new(SecurityScope {
        engagement_id: "test-refl".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["127.0.0.1/32".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec![],
        authorized_ports: vec![],
        signature: None,
    });

    let findings = check_active_reflection(&client, &base_url, &scope)
        .await
        .unwrap();

    let xss_finding = findings.iter().find(|f| f.id == "CG-DAST-REFL-HTML");
    assert!(
        xss_finding.is_some(),
        "Expected unescaped reflection to be flagged as CG-DAST-REFL-HTML"
    );
}
