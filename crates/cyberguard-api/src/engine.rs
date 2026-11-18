//! ApiEngine facade coordinating parsing, linting, fuzzing, baseline suppression, and SARIF export.

use crate::error::ApiError;
use crate::fuzzer::DefaultApiFuzzer;
use crate::linter::DefaultApiLinter;
use crate::models::{ApiAuditReport, ApiConfig, ApiSpec};
use crate::parser::parse_spec_file;
use crate::schemathesis::SchemathesisRunner;
use crate::traits::{ApiFuzzer, ApiLinter, ApiScanner};
use async_trait::async_trait;
use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{Message, ReportingDescriptor, SarifLog, SarifResult};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;

/// High-performance API security analysis and contract fuzzing engine.
#[derive(Clone)]
pub struct ApiEngine {
    linter: Arc<dyn ApiLinter>,
    fuzzer: Arc<dyn ApiFuzzer>,
}

impl Default for ApiEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiEngine {
    /// Create a new ApiEngine with standard linter and boundary fuzzer.
    pub fn new() -> Self {
        Self {
            linter: Arc::new(DefaultApiLinter::new()),
            fuzzer: Arc::new(DefaultApiFuzzer::new()),
        }
    }

    /// Convert an ApiAuditReport into OASIS SARIF v2.1.0 telemetry.
    pub fn generate_sarif(&self, report: &ApiAuditReport) -> SarifLog {
        let mut log = SarifLog::new("Aegix-API", "0.9.0");

        // Register rules catalog
        self.register_rules(&mut log);

        for finding in &report.findings {
            let mut result = SarifResult::new(
                &finding.rule_id,
                finding.severity,
                format!("{}: {}", finding.title, finding.description),
            );

            result.add_location(
                &report.spec_path,
                finding.line_hint.unwrap_or(1),
                Some(1),
                None,
                None,
            );

            result.set_confidence(finding.confidence);

            let mut props = serde_json::Map::new();
            props.insert(
                "jsonPointer".to_string(),
                serde_json::json!(finding.json_pointer),
            );
            props.insert("cwe".to_string(), serde_json::json!(finding.cwe));
            props.insert(
                "remediation".to_string(),
                serde_json::json!(finding.remediation),
            );
            if let Some(ref m) = finding.method {
                props.insert("httpMethod".to_string(), serde_json::json!(m));
            }
            props.insert("apiPath".to_string(), serde_json::json!(finding.path));
            result.properties = Some(serde_json::Value::Object(props));

            result.compute_deterministic_fingerprint();
            log.add_result(result);
        }

        log
    }

    fn register_rules(&self, log: &mut SarifLog) {
        let rules = [
            (
                "CG-API-001",
                "Missing Operation Security",
                "API operation has no security requirement or overrides global auth.",
                306,
            ),
            (
                "CG-API-002",
                "Insecure Plaintext Server URL",
                "Server URL specifies unencrypted http:// transport.",
                319,
            ),
            (
                "CG-API-003",
                "Unauthenticated Direct Object Access (BOLA / IDOR)",
                "Path parameter exposes object ID without authentication.",
                639,
            ),
            (
                "CG-API-004",
                "Mass Assignment Vulnerability in Request Schema",
                "Request schema allows client-controlled administrative fields.",
                915,
            ),
            (
                "CG-API-005",
                "Unbounded Collection Pagination",
                "Collection GET operation lacks pagination query parameters.",
                20,
            ),
            (
                "CG-API-006",
                "Excessive Sensitive Data Exposure in Response",
                "Response schema exposes sensitive attributes.",
                200,
            ),
            (
                "CG-API-007",
                "Missing Authentication on Administrative Endpoint",
                "Privileged administrative route lacks authentication.",
                285,
            ),
            (
                "CG-API-008",
                "Unhandled Server Exception / 500 Crash",
                "Fuzz payload caused unhandled 500/502/503/504 or stack trace.",
                703,
            ),
            (
                "CG-API-009",
                "Response Schema Contract Drift",
                "Live 2xx response payload violates declared response schema.",
                703,
            ),
        ];

        for (id, name, desc, cwe) in rules {
            log.add_rule(ReportingDescriptor {
                id: id.to_string(),
                name: Some(name.to_string()),
                short_description: Message {
                    text: desc.to_string(),
                },
                full_description: Some(Message {
                    text: format!("{} (CWE-{})", desc, cwe),
                }),
                help_uri: Some(format!(
                    "https://cwe.mitre.org/data/definitions/{}.html",
                    cwe
                )),
            });
        }
    }
}

#[async_trait]
impl ApiScanner for ApiEngine {
    async fn scan(&self, config: &ApiConfig) -> Result<ApiAuditReport, ApiError> {
        info!("Ingesting API specification from: {:?}", config.spec_path);
        let spec: ApiSpec = parse_spec_file(&config.spec_path)?;

        let spec_path_str = config.spec_path.to_string_lossy().to_string();
        let mut findings = self.linter.lint(&spec, &spec_path_str);
        let mut fuzzed_endpoints = 0;
        let mut fuzzer_requests_sent = 0;
        let mut fuzzer_errors_found = 0;

        // Active contract fuzzing
        if config.fuzz {
            info!("Executing active contract boundary mutation fuzzing...");
            let fuzzer_findings = self.fuzzer.fuzz(&spec, config).await?;
            fuzzed_endpoints = spec.operations.len();
            fuzzer_requests_sent = fuzzed_endpoints * 9;
            fuzzer_errors_found = fuzzer_findings.len();
            findings.extend(fuzzer_findings);
        }

        // Optional external Schemathesis supervision
        if config.schemathesis {
            info!("Executing supervised Schemathesis property-based runner...");
            let st_findings = SchemathesisRunner::run(config).await?;
            findings.extend(st_findings);
        }

        // Filter against baseline snapshot if configured
        if let Some(ref baseline_path) = config.baseline_path {
            if baseline_path.exists() {
                if let Ok(baseline) = AegixBaseline::load_from_path(baseline_path) {
                    info!(
                        "Filtering API findings against baseline snapshot ({} known items)...",
                        baseline.fingerprints.len()
                    );
                    findings.retain(|f| {
                        // Compute fingerprint for finding
                        let mut hasher = sha2::Sha256::default();
                        use sha2::Digest;
                        hasher.update(f.rule_id.as_bytes());
                        hasher.update(spec_path_str.as_bytes());
                        hasher.update(f.line_hint.unwrap_or(1).to_string().as_bytes());
                        let hash_hex = format!("{:x}", hasher.finalize());
                        !baseline.contains(&hash_hex)
                    });
                }
            }
        }

        // Deduplicate findings by rule_id + path + method
        let mut seen = HashSet::new();
        findings.retain(|f| {
            let key = format!("{}:{}:{:?}", f.rule_id, f.path, f.method);
            seen.insert(key)
        });

        Ok(ApiAuditReport {
            spec_path: spec_path_str,
            spec_version: spec.version,
            operations_count: spec.operations.len(),
            findings,
            fuzzed_endpoints,
            fuzzer_requests_sent,
            fuzzer_errors_found,
        })
    }
}
