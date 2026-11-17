//! Core Network Reconnaissance Engine orchestrating scope gating and scanning.

use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use std::time::Instant;

use crate::error::NetError;
use crate::models::{NetworkAuditReport, PinnedTarget, PortFinding, PortStatus};
use crate::nmap::run_supervised_nmap;
use crate::scanner::{TcpScanner, DEFAULT_TOP_PORTS};
use crate::scope::ScopeGate;
use crate::traits::NetworkScanner;
use async_trait::async_trait;

/// Network reconnaissance engine combining scope security with native and supervised scanning.
pub struct NetworkEngine {
    pub gate: ScopeGate,
    pub scanner: TcpScanner,
    pub use_nmap: bool,
}

impl NetworkEngine {
    /// Create a new NetworkEngine with the provided ScopeGate.
    #[must_use]
    pub fn new(gate: ScopeGate) -> Self {
        Self {
            gate,
            scanner: TcpScanner::default(),
            use_nmap: false,
        }
    }

    /// Configure scanner concurrency.
    #[must_use]
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.scanner.concurrency = concurrency;
        self
    }

    /// Configure probe timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.scanner.timeout = timeout;
        self
    }

    /// Toggle external supervised Nmap scanning.
    #[must_use]
    pub fn with_nmap(mut self, use_nmap: bool) -> Self {
        self.use_nmap = use_nmap;
        self
    }

    /// Convert network reconnaissance findings into an OASIS SARIF v2.1.0 telemetry log.
    #[must_use]
    pub fn generate_sarif(
        &self,
        target: &str,
        pinned_ip: &str,
        findings: &[PortFinding],
    ) -> SarifLog {
        let mut sarif = SarifLog::new("CyberGuard Network Recon Engine", "0.8.0");

        for finding in findings {
            if finding.status != PortStatus::Open {
                continue;
            }

            let is_unencrypted = matches!(finding.port, 21 | 23 | 80 | 110 | 143 | 514);
            let (rule_id, level) = if is_unencrypted {
                ("CG-NET-UNENCRYPTED-SERVICE", SarifLevel::Warning)
            } else {
                ("CG-NET-PORT-OPEN", SarifLevel::Note)
            };

            let mut msg = format!(
                "Open port {} ({}) detected on {} ({}) via {}",
                finding.port, finding.service, target, pinned_ip, finding.protocol
            );
            if let Some(ref banner) = finding.banner {
                msg.push_str(&format!(". Service banner: {banner}"));
            }

            let mut result = SarifResult::new(rule_id, level, msg);
            result.add_location(
                format!("net://{}:{}", target, finding.port),
                usize::from(finding.port),
                None,
                None,
                None,
            );
            result.compute_deterministic_fingerprint();
            if let Some(ref mut map) = result.partial_fingerprints {
                if let Some(hash) = map.get("logicalLocationTokenHash/v1").cloned() {
                    map.insert("deterministicSha256".to_string(), hash);
                }
            }
            sarif.add_result(result);
        }

        sarif
    }
}

#[async_trait]
impl NetworkScanner for NetworkEngine {
    async fn validate_scope(&self, target: &str, port: u16) -> Result<PinnedTarget, NetError> {
        self.gate.validate_target(target, port)
    }

    async fn scan(&self, target: &str, ports: &[u16]) -> Result<NetworkAuditReport, NetError> {
        let start_time = Instant::now();

        // 1. Determine effective ports
        let effective_ports: Vec<u16> = if ports.is_empty() {
            DEFAULT_TOP_PORTS.iter().map(|(p, _)| *p).collect()
        } else {
            ports.to_vec()
        };

        let first_port = effective_ports.first().copied().unwrap_or(80);

        // 2. Validate target through Scope Gate and acquire DNS-pinned target
        let pinned_target = self.gate.validate_target(target, first_port)?;

        // 3. Execute scan (supervised Nmap or pure-Rust async connect scanner)
        let findings = if self.use_nmap {
            run_supervised_nmap(&pinned_target, &effective_ports).await?
        } else {
            self.scanner
                .scan_ports(&pinned_target, &effective_ports)
                .await?
        };

        let open_ports = findings
            .iter()
            .filter(|f| f.status == PortStatus::Open)
            .count();

        let duration_ms = start_time.elapsed().as_millis() as u64;

        // 4. Generate SARIF telemetry
        let sarif = self.generate_sarif(target, &pinned_target.ip.to_string(), &findings);

        Ok(NetworkAuditReport {
            engagement_id: Some(self.gate.scope.engagement_id.clone()),
            target: target.to_string(),
            pinned_ip: pinned_target.ip.to_string(),
            scanned_ports: effective_ports.len(),
            open_ports,
            findings,
            violations: Vec::new(),
            duration_ms,
            sarif: Some(sarif),
        })
    }
}
