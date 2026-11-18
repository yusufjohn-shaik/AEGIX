use cyberguard_dast::client::DastClient;
use cyberguard_dast::error::DastError;
use cyberguard_dast::models::DastTarget;
use cyberguard_net::models::SecurityScope;
use cyberguard_net::ScopeGate;
use reqwest::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn test_redirect_to_cloud_metadata_blocked() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    // Return 302 Found redirecting to AWS IMDS metadata IP
                    let response = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nConnection: close\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let target_url = Url::parse(&format!("http://127.0.0.1:{}/vuln-redirect", port)).unwrap();
    let target = DastTarget::new(target_url.clone());
    let client = DastClient::new(&target, 2000).unwrap();

    let scope = ScopeGate::new(SecurityScope {
        engagement_id: "test-redirect".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["127.0.0.1/32".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec![],
        authorized_ports: vec![],
        signature: None,
    });

    let res = client
        .send_request(Method::GET, &target_url, None, &scope)
        .await;

    assert!(
        res.is_err(),
        "Expected redirect to 169.254.169.254 to be rejected"
    );
    match res.unwrap_err() {
        DastError::ScopeViolation(msg) => {
            assert!(
                msg.contains("169.254.169.254")
                    || msg.contains("not authorized")
                    || msg.contains("Bogon"),
                "Expected scope violation mentioning target IP or bogon, got: {}",
                msg
            );
        }
        DastError::SsrfBlocked(ip) => {
            assert_eq!(ip.to_string(), "169.254.169.254");
        }
        other => panic!("Unexpected error variant: {:?}", other),
    }
}

#[tokio::test]
async fn test_infinite_redirect_loop_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let p = port;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    // Infinite redirect loop back to self
                    let response = format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/loop\r\nConnection: close\r\n\r\n",
                        p
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let target_url = Url::parse(&format!("http://127.0.0.1:{}/loop", port)).unwrap();
    let target = DastTarget::new(target_url.clone());
    let client = DastClient::new(&target, 2000).unwrap();

    let scope = ScopeGate::new(SecurityScope {
        engagement_id: "test-loop".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["127.0.0.1/32".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec![],
        authorized_ports: vec![],
        signature: None,
    });

    let res = client
        .send_request(Method::GET, &target_url, None, &scope)
        .await;

    assert!(res.is_err());
    match res.unwrap_err() {
        DastError::RedirectLimitExceeded { max_hops } => {
            assert_eq!(max_hops, 5);
        }
        other => panic!("Expected RedirectLimitExceeded, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_redirect_to_unauthorized_domain_blocked() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    // Return 302 Found redirecting to an unauthorized domain
                    let response = "HTTP/1.1 302 Found\r\nLocation: http://unauthorized-external-domain.example/steal\r\nConnection: close\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    let target_url =
        Url::parse(&format!("http://127.0.0.1:{}/redirect-out-of-scope", port)).unwrap();
    let target = DastTarget::new(target_url.clone());
    let client = DastClient::new(&target, 2000).unwrap();

    let scope = ScopeGate::new(SecurityScope {
        engagement_id: "test-domain-boundary".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["127.0.0.1/32".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec!["authorized-app.example".to_string()],
        authorized_ports: vec![],
        signature: None,
    });

    let res = client
        .send_request(Method::GET, &target_url, None, &scope)
        .await;

    assert!(
        res.is_err(),
        "Expected redirect to out-of-scope domain to be blocked"
    );
    match res.unwrap_err() {
        DastError::ScopeViolation(msg) => {
            assert!(
                msg.contains("unauthorized-external-domain.example")
                    || msg.contains("not authorized"),
                "Expected scope violation message for unauthorized domain, got: {}",
                msg
            );
        }
        other => panic!("Expected ScopeViolation, got: {:?}", other),
    }
}
