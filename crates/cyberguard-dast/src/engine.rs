use crate::checks::{check_active_reflection, check_security_headers, check_sensitive_exposures};
use crate::client::{DastClient, DEFAULT_TIMEOUT_MS};
use crate::error::DastError;
use crate::models::{DastAuditReport, DastFinding, DastTarget, FindingSeverity};
use crate::nuclei::run_supervised_nuclei;
use crate::rules::{evaluate_rules, get_embedded_rules};
use crate::traits::DastScanner;
use async_trait::async_trait;
use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use cyberguard_net::ScopeGate;
use reqwest::Method;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct DastEngine {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub max_rps: u32,
    pub use_nuclei: bool,
}

impl Default for DastEngine {
    fn default() -> Self {
        Self {
            concurrency: 10,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_rps: 25,
            use_nuclei: false,
        }
    }
}

impl DastEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    #[must_use]
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    #[must_use]
    pub fn with_max_rps(mut self, max_rps: u32) -> Self {
        self.max_rps = max_rps;
        self
    }

    #[must_use]
    pub fn with_nuclei(mut self, use_nuclei: bool) -> Self {
        self.use_nuclei = use_nuclei;
        self
    }

    #[must_use]
    pub fn generate_sarif(&self, target_url: &str, findings: &[DastFinding]) -> SarifLog {
        let mut sarif = SarifLog::new("CyberGuard DAST Engine", "0.9.0");

        for finding in findings {
            let level = match finding.severity {
                FindingSeverity::Critical | FindingSeverity::High => SarifLevel::Error,
                FindingSeverity::Medium => SarifLevel::Warning,
                FindingSeverity::Low | FindingSeverity::Info => SarifLevel::Note,
            };

            let msg = format!(
                "{}: {}. Evidence: {}",
                finding.title, finding.description, finding.evidence
            );
            let mut result = SarifResult::new(&finding.id, level, msg);

            let loc_uri = format!("{}{}", target_url.trim_end_matches('/'), finding.endpoint);
            result.add_location(loc_uri, 1, None, None, None);
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
impl DastScanner for DastEngine {
    async fn scan(
        &self,
        target: &DastTarget,
        scope: &ScopeGate,
    ) -> Result<DastAuditReport, DastError> {
        let client = DastClient::new(target, self.timeout_ms)?;
        let mut findings = Vec::new();
        let mut tested_count = 0;

        // Phase 1: Baseline Request & Security Header Check
        let is_https = target.url.scheme() == "https";
        let baseline_res = client
            .send_request(Method::GET, &target.url, Some(&target.headers), scope)
            .await;

        match baseline_res {
            Ok((_status, headers, _body)) => {
                tested_count += 1;
                let header_findings = check_security_headers(&headers, is_https, target.url.path());
                findings.extend(header_findings);
            }
            Err(e) => return Err(e),
        }

        // Phase 2: Sensitive Endpoint Discovery
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let exposure_findings =
            check_sensitive_exposures(&client, &target.url, scope, semaphore.clone()).await?;
        tested_count += 5; // 5 sensitive paths probed
        findings.extend(exposure_findings);

        // Phase 3: Active Parameter Reflection Probes
        let reflection_findings = check_active_reflection(&client, &target.url, scope).await?;
        tested_count += 6; // parameters tested
        findings.extend(reflection_findings);

        // Phase 4: Declarative Rules Evaluation
        let embedded_rules = get_embedded_rules();
        tested_count += embedded_rules.len();
        let rule_findings = evaluate_rules(&client, &target.url, &embedded_rules, scope).await?;
        findings.extend(rule_findings);

        // Optional External Supervised Nuclei Runner
        if self.use_nuclei {
            if let Ok(nuclei_findings) =
                run_supervised_nuclei(&target.url, self.timeout_ms / 1000).await
            {
                tested_count += nuclei_findings.len();
                findings.extend(nuclei_findings);
            }
        }

        // Phase 5: SARIF Synthesis
        let sarif_log = self.generate_sarif(target.url.as_str(), &findings);

        Ok(DastAuditReport {
            target: target.url.to_string(),
            tested_endpoints_count: tested_count,
            findings,
            sarif_log,
        })
    }
}
