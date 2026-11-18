//! Supervised execution of Schemathesis CLI property-based fuzzing via cyberguard-proc.

use crate::error::ApiError;
use crate::models::{ApiConfig, ApiFinding};
use cyberguard_core::sarif::{Confidence, SarifLevel};
use cyberguard_proc::{execute_process, ProcessOptions};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Supervised Schemathesis property-based fuzzing runner.
pub struct SchemathesisRunner;

impl SchemathesisRunner {
    /// Execute Schemathesis against target if the CLI tool is installed.
    pub async fn run(config: &ApiConfig) -> Result<Vec<ApiFinding>, ApiError> {
        let target = match &config.target {
            Some(t) => t,
            None => return Err(ApiError::TargetUrlRequired),
        };

        let mut args = vec![
            "run".to_string(),
            config.spec_path.to_string_lossy().to_string(),
            "--url".to_string(),
            target.clone(),
            "--checks".to_string(),
            "all".to_string(),
            "--hypothesis-max-examples".to_string(),
            "50".to_string(),
        ];

        for h in &config.headers {
            args.push("--header".to_string());
            args.push(h.clone());
        }

        if config.insecure {
            args.push("--validate-schema=false".to_string());
        }

        info!(
            "Invoking supervised Schemathesis runner: schemathesis {:?}",
            args
        );

        let options = ProcessOptions::new("schemathesis", args)
            .with_timeout(Duration::from_secs(120))
            .with_max_output(10 * 1024 * 1024);

        let output = match execute_process(options).await {
            Ok(out) => out,
            Err(e) => {
                warn!("Schemathesis execution could not be started: {}", e);
                return Ok(Vec::new());
            }
        };

        let stdout = &output.stdout;
        let stderr = &output.stderr;
        debug!(
            "Schemathesis exit code: {:?}, stdout lines: {}",
            output.exit_code,
            stdout.lines().count()
        );

        let findings = parse_schemathesis_output(stdout, stderr, config);
        Ok(findings)
    }
}

fn parse_schemathesis_output(stdout: &str, _stderr: &str, config: &ApiConfig) -> Vec<ApiFinding> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains("FAILED") || trimmed.contains("FAILURE") {
            if trimmed.contains("500") || trimmed.contains("Server error") {
                findings.push(ApiFinding {
                    rule_id: "CG-API-008".to_string(),
                    title: "Schemathesis: Server 500 Crash Under Property-Based Fuzzing".to_string(),
                    description: format!(
                        "Schemathesis property-based fuzzing triggered unhandled server crash: {}",
                        trimmed
                    ),
                    severity: SarifLevel::Error,
                    confidence: Confidence::High,
                    cwe: 703,
                    path: config.spec_path.to_string_lossy().to_string(),
                    method: None,
                    line_hint: Some(1),
                    json_pointer: "/paths".to_string(),
                    remediation: "Review server logs for the failing payload and enforce defensive validation."
                        .to_string(),
                });
            } else if trimmed.contains("schema") || trimmed.contains("conformance") {
                findings.push(ApiFinding {
                    rule_id: "CG-API-009".to_string(),
                    title: "Schemathesis: Response Schema Drift Detected".to_string(),
                    description: format!(
                        "Schemathesis detected live response schema violation: {}",
                        trimmed
                    ),
                    severity: SarifLevel::Warning,
                    confidence: Confidence::High,
                    cwe: 703,
                    path: config.spec_path.to_string_lossy().to_string(),
                    method: None,
                    line_hint: Some(1),
                    json_pointer: "/paths".to_string(),
                    remediation:
                        "Update the OpenAPI response schema or fix backend response serialization."
                            .to_string(),
                });
            }
        }
    }

    findings
}
