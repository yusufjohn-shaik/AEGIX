//! Deterministic negative contract prober and boundary mutation fuzzer.

use crate::error::ApiError;
use crate::models::{ApiConfig, ApiFinding, ApiSpec, Operation, ParamLocation, Parameter};
use crate::traits::ApiFuzzer;
use async_trait::async_trait;
use cyberguard_core::sarif::{Confidence, SarifLevel};
use cyberguard_dast::client::DastClient;
use cyberguard_dast::models::DastTarget;
use cyberguard_net::{ScopeGate, SecurityScope};
use reqwest::header::RETRY_AFTER;
use reqwest::Method;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

/// Default deterministic negative boundary prober.
#[derive(Debug, Default, Clone)]
pub struct DefaultApiFuzzer;

impl DefaultApiFuzzer {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ApiFuzzer for DefaultApiFuzzer {
    async fn fuzz(&self, spec: &ApiSpec, config: &ApiConfig) -> Result<Vec<ApiFinding>, ApiError> {
        let target_str = match &config.target {
            Some(t) => t.as_str(),
            None => {
                // If not in CLI config, try first server from spec
                if let Some(first_server) = spec.servers.first() {
                    first_server.as_str()
                } else {
                    return Err(ApiError::TargetUrlRequired);
                }
            }
        };

        let base_url = Url::parse(target_str)
            .map_err(|e| ApiError::InvalidTargetUrl(format!("{}: {}", target_str, e)))?;

        // Initialize ScopeGate
        let scope_gate = if let Some(ref scope_path) = config.scope_path {
            ScopeGate::from_file(scope_path).map_err(|e| {
                ApiError::ScopeViolation(format!("Failed to load scope file: {}", e))
            })?
        } else {
            // Ephemeral scope gate for target host
            let host = base_url
                .host_str()
                .ok_or_else(|| ApiError::InvalidTargetUrl("Target URL has no host".to_string()))?;
            let is_ip = IpAddr::from_str(host).is_ok();
            let ephemeral_scope = SecurityScope {
                engagement_id: "ephemeral-api-fuzz".to_string(),
                valid_from: None,
                valid_until: None,
                authorized_cidrs: if is_ip {
                    if host.contains(':') {
                        vec![format!("{}/128", host)]
                    } else {
                        vec![format!("{}/32", host)]
                    }
                } else if host.eq_ignore_ascii_case("localhost") {
                    vec!["127.0.0.1/32".to_string(), "::1/128".to_string()]
                } else {
                    vec![]
                },
                excluded_cidrs: vec![],
                authorized_domains: if !is_ip {
                    vec![host.to_string()]
                } else {
                    vec![]
                },
                authorized_ports: vec![],
                signature: None,
            };
            ScopeGate::new(ephemeral_scope)
        };

        // Construct DastTarget
        let mut dast_target = DastTarget::new(base_url.clone()).with_insecure(config.insecure);
        for h in &config.headers {
            if let Some((k, v)) = h.split_once(':') {
                dast_target = dast_target.with_header(k.trim(), v.trim());
            }
        }

        let client = DastClient::new(&dast_target, config.timeout_ms)?;
        let mut findings = Vec::new();

        // Calculate probe delay from max_rps (default 25 RPS -> 40ms)
        let rate_delay = if config.max_rps > 0 {
            Duration::from_millis(1000 / config.max_rps as u64)
        } else {
            Duration::from_millis(40)
        };

        info!(
            "Starting API contract fuzzing against {} (max_rps: {}, safe_methods_only: {})",
            base_url, config.max_rps, !config.allow_destructive
        );

        for op in &spec.operations {
            let is_safe_method = matches!(op.method.as_str(), "GET" | "HEAD" | "OPTIONS");
            if !is_safe_method && !config.allow_destructive {
                debug!(
                    "Skipping state-changing operation '{} {}' (requires --allow-destructive)",
                    op.method, op.path
                );
                continue;
            }

            if config.dry_run {
                info!(
                    "[DRY-RUN] Planned fuzzing probes for operation: {} {}",
                    op.method, op.path
                );
                continue;
            }

            // Probe mutations for this operation
            fuzz_operation(
                &client,
                &base_url,
                &scope_gate,
                op,
                &dast_target.headers,
                rate_delay,
                &mut findings,
            )
            .await?;
        }

        Ok(findings)
    }
}

async fn fuzz_operation(
    client: &DastClient,
    base_url: &Url,
    scope: &ScopeGate,
    op: &Operation,
    headers: &HashMap<String, String>,
    delay: Duration,
    findings: &mut Vec<ApiFinding>,
) -> Result<(), ApiError> {
    let method = match Method::from_str(&op.method) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    // Candidate parameter mutations
    let mutations = generate_boundary_mutations();

    // 1. Path parameters
    let path_params: Vec<&Parameter> = op
        .parameters
        .iter()
        .filter(|p| p.location == ParamLocation::Path)
        .collect();

    // 2. Query parameters
    let query_params: Vec<&Parameter> = op
        .parameters
        .iter()
        .filter(|p| p.location == ParamLocation::Query)
        .collect();

    // Cap total probes per endpoint to 15 to stay safe and responsive
    let mut probe_count = 0;
    const MAX_PROBES_PER_ENDPOINT: usize = 15;
    let placeholder_re = regex::Regex::new(r"\{[^}]+\}").expect("Valid static regex for URL placeholders");

    for (mut_name, mut_val) in &mutations {
        if probe_count >= MAX_PROBES_PER_ENDPOINT {
            break;
        }

        // Build target path with mutations
        let mut target_path = op.path.clone();
        for param in &path_params {
            let token = format!("{{{}}}", param.name);
            let encoded_mut = urlencoding_encode(mut_val);
            target_path = target_path.replace(&token, &encoded_mut);
        }

        // Replace any remaining unresolved path tokens with safe fallback "1"
        if target_path.contains('{') && target_path.contains('}') {
            target_path = placeholder_re.replace_all(&target_path, "1").to_string();
        }

        // Build query string
        let mut query_pairs = Vec::new();
        for (i, param) in query_params.iter().enumerate() {
            let val = if i == 0 { mut_val.as_str() } else { "default" };
            query_pairs.push((param.name.as_str(), val));
        }

        let mut probe_url = match base_url.join(target_path.trim_start_matches('/')) {
            Ok(u) => u,
            Err(_) => continue,
        };

        if !query_pairs.is_empty() {
            let mut q_str = String::new();
            for (k, v) in query_pairs {
                if !q_str.is_empty() {
                    q_str.push('&');
                }
                q_str.push_str(&urlencoding_encode(k));
                q_str.push('=');
                q_str.push_str(&urlencoding_encode(v));
            }
            probe_url.set_query(Some(&q_str));
        }

        // Prepare body for destructive methods if schema exists
        let body_payload = if op.request_body.is_some() && method != Method::GET {
            Some(format!(r#"{{"fuzz_test_prop": "{}"}}"#, mut_val).into_bytes())
        } else {
            None
        };

        // Execute request with rate delay
        tokio::time::sleep(delay).await;
        probe_count += 1;

        let res = client
            .send_request_with_body(
                method.clone(),
                &probe_url,
                Some(headers),
                body_payload,
                scope,
            )
            .await;

        match res {
            Ok((status, resp_headers, body_bytes)) => {
                // Adaptive 429 backoff
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    let backoff_secs = resp_headers
                        .get(RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(2);
                    warn!(
                        "Target returned 429 Too Many Requests; backing off for {}s",
                        backoff_secs
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    continue;
                }

                let body_str = String::from_utf8_lossy(&body_bytes);

                // Anomaly check 1: Status 500, 502, 503, 504 (Server Crash / Exception)
                let is_5xx = status.is_server_error();
                let has_stack_trace = detect_stack_trace(&body_str);

                if is_5xx || has_stack_trace {
                    let evidence = if has_stack_trace {
                        format!("Runtime stack trace detected in body (status {})", status)
                    } else {
                        format!("HTTP status {} Server Error received", status)
                    };

                    findings.push(ApiFinding {
                        rule_id: "CG-API-008".to_string(),
                        title: "Unhandled Server Exception / 500 Crash".to_string(),
                        description: format!(
                            "Probe mutation '{}' against '{} {}' caused an unhandled server error: {}. Mutation value: '{}'",
                            mut_name, op.method, probe_url.path(), evidence, mut_val
                        ),
                        severity: SarifLevel::Error,
                        confidence: Confidence::High,
                        cwe: 703,
                        path: op.path.clone(),
                        method: Some(op.method.clone()),
                        line_hint: Some(1),
                        json_pointer: format!("/paths/~1{}/{}", op.path.replace('/', "~1"), op.method.to_ascii_lowercase()),
                        remediation: "Implement defensive input validation and robust error handlers to catch unexpected input boundaries without throwing 500 exceptions."
                            .to_string(),
                    });
                    // Only flag one crash finding per endpoint mutation run to avoid flood
                    break;
                }

                // Anomaly check 2: Contract Drift on 2xx responses (CG-API-009)
                if status.is_success() {
                    if let Some(drift_finding) =
                        check_response_contract_drift(op, &status, &body_str)
                    {
                        findings.push(drift_finding);
                        break;
                    }
                }
            }
            Err(e) => {
                debug!("Probe error on {} {}: {}", op.method, probe_url, e);
            }
        }
    }

    Ok(())
}

fn generate_boundary_mutations() -> Vec<(&'static str, String)> {
    vec![
        // Integer boundary mutations
        ("int_zero", "0".to_string()),
        ("int_negative_one", "-1".to_string()),
        ("int_i64_max", "9223372036854775807".to_string()),
        ("int_i64_min", "-9223372036854775808".to_string()),
        // String / injection boundaries
        ("null_byte", "\0".to_string()),
        ("path_traversal", "../../../../etc/passwd".to_string()),
        ("format_string", "%s%p%x%n".to_string()),
        ("type_anomaly_alpha", "NaN".to_string()),
        ("oversized_buffer", "A".repeat(1024)),
    ]
}

fn detect_stack_trace(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("traceback (most recent call last)")
        || lower.contains("exception in thread")
        || lower.contains("at java.")
        || lower.contains("at org.springframework.")
        || lower.contains("panic at")
        || lower.contains("fatal error:")
        || lower.contains("uncaught exception")
        || lower.contains("referenceerror:")
        || lower.contains("typeerror:")
        || lower.contains("system.nullreferenceexception")
}

fn check_response_contract_drift(
    op: &Operation,
    status: &reqwest::StatusCode,
    body: &str,
) -> Option<ApiFinding> {
    let code_str = status.as_u16().to_string();
    let resp_def = op.responses.get(&code_str)?;

    // If spec specifies application/json schema, check if response is valid JSON
    if let Some(expected_schema) = resp_def.content_types.get("application/json") {
        if let Ok(json_val) = serde_json::from_str::<Value>(body) {
            // Check top-level type conformance
            if let Some(ref expected_type) = expected_schema.schema_type {
                let matches_type = match expected_type.as_str() {
                    "object" => json_val.is_object(),
                    "array" => json_val.is_array(),
                    "string" => json_val.is_string(),
                    "integer" | "number" => json_val.is_number(),
                    "boolean" => json_val.is_boolean(),
                    _ => true,
                };

                if !matches_type {
                    return Some(ApiFinding {
                        rule_id: "CG-API-009".to_string(),
                        title: "Response Schema Contract Drift".to_string(),
                        description: format!(
                            "Endpoint '{} {}' returned status {} with payload violating declared schema type (expected '{}').",
                            op.method, op.path, status, expected_type
                        ),
                        severity: SarifLevel::Warning,
                        confidence: Confidence::Medium,
                        cwe: 703,
                        path: op.path.clone(),
                        method: Some(op.method.clone()),
                        line_hint: Some(1),
                        json_pointer: format!(
                            "/paths/~1{}/{}/responses/{}/content/application~1json/schema",
                            op.path.replace('/', "~1"),
                            op.method.to_ascii_lowercase(),
                            code_str
                        ),
                        remediation: "Align backend API response structure with the OpenAPI contract specification."
                            .to_string(),
                    });
                }
            }
        } else if !body.trim().is_empty() {
            // Body was expected to be application/json, but isn't valid JSON
            return Some(ApiFinding {
                rule_id: "CG-API-009".to_string(),
                title: "Response Schema Contract Drift".to_string(),
                description: format!(
                    "Endpoint '{} {}' returned status {} with invalid non-JSON payload when application/json was contractually promised.",
                    op.method, op.path, status
                ),
                severity: SarifLevel::Warning,
                confidence: Confidence::Medium,
                cwe: 703,
                path: op.path.clone(),
                method: Some(op.method.clone()),
                line_hint: Some(1),
                json_pointer: format!(
                    "/paths/~1{}/{}/responses/{}",
                    op.path.replace('/', "~1"),
                    op.method.to_ascii_lowercase(),
                    code_str
                ),
                remediation: "Return valid JSON payloads matching Content-Type header declarations."
                    .to_string(),
            });
        }
    }

    None
}

fn urlencoding_encode(s: &str) -> String {
    let mut encoded = String::new();
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            || byte == b'.'
            || byte == b'~'
        {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}
