use cyberguard_net::models::{PinnedTarget, PortStatus};
use cyberguard_net::scanner::{probe_banner, sanitize_banner, TcpScanner};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_sanitize_banner_strips_ansi_and_control_chars() {
    let dirty = b"\x1b[31;1mCompromised Host\x1b[0m\x00\x07\x08 SSH-2.0-OpenSSH\r\n";
    let clean = sanitize_banner(dirty);
    assert_eq!(clean, "Compromised Host SSH-2.0-OpenSSH\r\n");
}

#[tokio::test]
async fn test_tcp_scanner_detects_open_and_closed_ports() {
    // 1. Bind an ephemeral mock TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let open_port = local_addr.port();
    let closed_port = open_port + 1; // Unbound port

    // Accept connections in background task
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.write_all(b"SSH-2.0-TestSSH_1.0\r\n").await;
        }
    });

    let target = PinnedTarget::new("localhost", local_addr.ip(), open_port);
    let scanner = TcpScanner {
        concurrency: 10,
        timeout: Duration::from_millis(500),
    };

    let findings = scanner
        .scan_ports(&target, &[open_port, closed_port])
        .await
        .expect("Scan succeeds");

    assert_eq!(findings.len(), 2);

    let open_finding = findings.iter().find(|f| f.port == open_port).unwrap();
    assert_eq!(open_finding.status, PortStatus::Open);

    let closed_finding = findings.iter().find(|f| f.port == closed_port).unwrap();
    assert!(
        closed_finding.status == PortStatus::Closed
            || closed_finding.status == PortStatus::Filtered
    );
}

#[tokio::test]
async fn test_probe_banner_passive_service() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream
                .write_all(b"220 mail.example.org ESMTP Postfix\r\n")
                .await;
        }
    });

    let target = PinnedTarget::new("mail.example.org", addr.ip(), addr.port());
    let banner = probe_banner(&target, Duration::from_millis(500))
        .await
        .expect("Banner returned");

    assert!(banner.contains("220 mail.example.org ESMTP Postfix"));
}

#[tokio::test]
async fn test_probe_banner_active_http() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 128];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nServer: TestHTTP/1.0\r\n\r\n")
                .await;
        }
    });

    // Designate port 80 or 8080 or pass active probe
    let target = PinnedTarget::new("web.internal", addr.ip(), 80);
    // Directly target the ephemeral socket addr
    let mut http_target = target.clone();
    http_target.port = addr.port();

    let banner = probe_banner(&http_target, Duration::from_millis(500))
        .await
        .expect("HTTP banner returned");

    assert!(banner.contains("HTTP/1.1") || banner.contains("TestHTTP"));
}
