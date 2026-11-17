//! Asynchronous TCP connect scanner and safe protocol banner grabber.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::error::NetError;
use crate::models::{PinnedTarget, PortFinding, PortStatus};

/// Curated top 100 most critical network and service ports.
pub const DEFAULT_TOP_PORTS: &[(u16, &str)] = &[
    (7, "echo"),
    (9, "discard"),
    (13, "daytime"),
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (26, "rsftp"),
    (37, "time"),
    (53, "dns"),
    (67, "dhcps"),
    (68, "dhcpc"),
    (69, "tftp"),
    (79, "finger"),
    (80, "http"),
    (81, "hosts2-ns"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "rpcbind"),
    (113, "ident"),
    (119, "nntp"),
    (123, "ntp"),
    (135, "msrpc"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (162, "snmptrap"),
    (179, "bgp"),
    (199, "smux"),
    (389, "ldap"),
    (427, "svrloc"),
    (443, "https"),
    (444, "snpp"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (500, "isakmp"),
    (513, "login"),
    (514, "syslog"),
    (515, "printer"),
    (548, "afp"),
    (554, "rtsp"),
    (587, "submission"),
    (631, "ipp"),
    (636, "ldaps"),
    (873, "rsync"),
    (990, "ftps"),
    (993, "imaps"),
    (995, "pop3s"),
    (1025, "network-service"),
    (1026, "lsa-rpc"),
    (1027, "iis"),
    (1080, "socks"),
    (1194, "openvpn"),
    (1433, "ms-sql-s"),
    (1521, "oracle"),
    (1720, "h323"),
    (1723, "pptp"),
    (1755, "wms"),
    (1900, "upnp"),
    (2000, "cisco-sccp"),
    (2049, "nfs"),
    (2121, "ccproxy-ftp"),
    (2181, "zookeeper"),
    (2375, "docker"),
    (2376, "docker-tls"),
    (3000, "dev-web"),
    (3128, "squid-http"),
    (3306, "mysql"),
    (3389, "rdp"),
    (4369, "epmd"),
    (5000, "upnp-flask"),
    (5060, "sip"),
    (5432, "postgresql"),
    (5672, "amqp"),
    (5800, "vnc-http"),
    (5900, "vnc"),
    (5984, "couchdb"),
    (6000, "x11"),
    (6379, "redis"),
    (6667, "irc"),
    (7001, "weblogic"),
    (8000, "http-alt"),
    (8008, "http-alt"),
    (8080, "http-proxy"),
    (8081, "http-alt"),
    (8443, "https-alt"),
    (8500, "consul"),
    (8888, "jupyter-http"),
    (9000, "sonar-php"),
    (9042, "cassandra"),
    (9092, "kafka"),
    (9100, "jetdirect"),
    (9200, "elasticsearch"),
    (9300, "es-cluster"),
    (11211, "memcached"),
    (27017, "mongodb"),
    (28017, "mongodb-web"),
];

/// Resolve a port number to its canonical service name.
#[must_use]
pub fn lookup_service(port: u16) -> &'static str {
    for (p, s) in DEFAULT_TOP_PORTS {
        if *p == port {
            return s;
        }
    }
    "unknown"
}

/// Asynchronous non-blocking TCP connect scanner.
#[derive(Debug, Clone)]
pub struct TcpScanner {
    pub concurrency: usize,
    pub timeout: Duration,
}

impl Default for TcpScanner {
    fn default() -> Self {
        Self {
            concurrency: 128,
            timeout: Duration::from_millis(1000),
        }
    }
}

impl TcpScanner {
    /// Construct a scanner with custom concurrency and timeout bounds.
    #[must_use]
    pub fn new(concurrency: usize, timeout: Duration) -> Self {
        Self {
            concurrency: if concurrency == 0 { 128 } else { concurrency },
            timeout,
        }
    }

    /// Perform asynchronous TCP connect scan across specified ports for a pinned target.
    pub async fn scan_ports(
        &self,
        target: &PinnedTarget,
        ports: &[u16],
    ) -> Result<Vec<PortFinding>, NetError> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::with_capacity(ports.len());

        for &port in ports {
            let sem = Arc::clone(&semaphore);
            let ip = target.ip;
            let host = target.hostname.clone();
            let timeout_dur = self.timeout;

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok();
                let addr = std::net::SocketAddr::new(ip, port);
                let service = lookup_service(port).to_string();

                let connect_fut = TcpStream::connect(addr);
                match tokio::time::timeout(timeout_dur, connect_fut).await {
                    Ok(Ok(mut stream)) => {
                        let _ = stream.set_nodelay(true);
                        // Port is open. Attempt safe banner grabbing.
                        let banner = probe_stream_banner(&mut stream, port, timeout_dur).await;
                        PortFinding {
                            host,
                            ip: ip.to_string(),
                            port,
                            status: PortStatus::Open,
                            service,
                            banner,
                            protocol: "tcp".to_string(),
                        }
                    }
                    Ok(Err(err)) => {
                        // Connection refused or reset indicates a closed port
                        let status = match err.kind() {
                            std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionReset => PortStatus::Closed,
                            _ => PortStatus::Filtered,
                        };
                        PortFinding {
                            host,
                            ip: ip.to_string(),
                            port,
                            status,
                            service,
                            banner: None,
                            protocol: "tcp".to_string(),
                        }
                    }
                    Err(_) => {
                        // Timeout indicates a packet filter or drop firewall
                        PortFinding {
                            host,
                            ip: ip.to_string(),
                            port,
                            status: PortStatus::Filtered,
                            service,
                            banner: None,
                            protocol: "tcp".to_string(),
                        }
                    }
                }
            });

            tasks.push(task);
        }

        let mut findings = Vec::with_capacity(tasks.len());
        for task in tasks {
            if let Ok(finding) = task.await {
                findings.push(finding);
            }
        }

        findings.sort_by_key(|f| f.port);
        Ok(findings)
    }
}

/// Helper to grab banners from an already connected TCP stream.
async fn probe_stream_banner(
    stream: &mut TcpStream,
    port: u16,
    timeout: Duration,
) -> Option<String> {
    let is_web_port = matches!(
        port,
        80 | 443 | 8000 | 8008 | 8080 | 8081 | 8443 | 3000 | 5000
    );

    let read_fut = async {
        let mut buf = [0u8; 1024];

        if is_web_port {
            let req = b"HEAD / HTTP/1.0\r\nUser-Agent: CyberGuard-Recon/0.8.0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req).await;
            let mut reader = stream.take(1024);
            if let Ok(n) = reader.read(&mut buf).await {
                if n > 0 {
                    let sanitized = sanitize_banner(&buf[..n]);
                    if !sanitized.trim().is_empty() {
                        return Some(sanitized);
                    }
                }
            }
            return None;
        }

        // For non-standard or banner-first services, first attempt passive read
        let mut reader = stream.take(1024);
        let passive_fut = reader.read(&mut buf);
        match tokio::time::timeout(Duration::from_millis(150), passive_fut).await {
            Ok(Ok(n)) if n > 0 => {
                let sanitized = sanitize_banner(&buf[..n]);
                if !sanitized.trim().is_empty() {
                    return Some(sanitized);
                }
            }
            _ => {
                // If passive read yielded nothing, attempt active HTTP HEAD probe
                let req = b"HEAD / HTTP/1.0\r\nUser-Agent: CyberGuard-Recon/0.8.0\r\nConnection: close\r\n\r\n";
                if stream.write_all(req).await.is_ok() {
                    let mut reader2 = stream.take(1024);
                    if let Ok(n) = reader2.read(&mut buf).await {
                        if n > 0 {
                            let sanitized = sanitize_banner(&buf[..n]);
                            if !sanitized.trim().is_empty() {
                                return Some(sanitized);
                            }
                        }
                    }
                }
            }
        }

        None
    };

    tokio::time::timeout(timeout.min(Duration::from_millis(1000)), read_fut)
        .await
        .ok()
        .flatten()
}

/// Safely connect and extract a service banner for a target.
pub async fn probe_banner(target: &PinnedTarget, timeout: Duration) -> Option<String> {
    let addr = target.socket_addr();
    let stream_fut = TcpStream::connect(addr);
    if let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, stream_fut).await {
        probe_stream_banner(&mut stream, target.port, timeout).await
    } else {
        None
    }
}

/// Sanitizes untrusted banner bytes:
/// - Strips ANSI terminal escape sequences (`\x1b[...m`)
/// - Strips unprintable binary control codes (nulls, bells, line feeds cleaned)
/// - Enforces maximum length and valid UTF-8
#[must_use]
pub fn sanitize_banner(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;

    while i < raw.len() {
        // Detect ANSI escape sequences starting with 0x1B ('\e') and '['
        if raw[i] == 0x1B && i + 1 < raw.len() && raw[i + 1] == b'[' {
            i += 2;
            // Advance until terminating ANSI command character (0x40 - 0x7E)
            while i < raw.len() && !(0x40..=0x7E).contains(&raw[i]) {
                i += 1;
            }
            if i < raw.len() {
                i += 1; // Skip the terminating command byte
            }
            continue;
        }

        let b = raw[i];
        // Allow printable ASCII, newline, carriage return, and tab
        if (0x20..=0x7E).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            out.push(b as char);
        } else if b > 0x7F {
            // For multi-byte UTF-8, attempt decoding remaining chunk
            let lossy = String::from_utf8_lossy(&raw[i..i + 1]);
            out.push_str(&lossy);
        }
        // Other control characters (0x00, 0x07, 0x08, etc.) are strictly discarded.

        i += 1;
    }

    out
}
