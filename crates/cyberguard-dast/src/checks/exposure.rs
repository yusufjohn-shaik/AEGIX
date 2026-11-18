use crate::client::DastClient;
use crate::error::DastError;
use crate::models::{DastFinding, FindingSeverity};
use cyberguard_net::ScopeGate;
use reqwest::Method;
use std::sync::Arc;
use tokio::sync::Semaphore;
use url::Url;

struct SensitivePath {
    path: &'static str,
    id: &'static str,
    title: &'static str,
    severity: FindingSeverity,
    description: &'static str,
    remediation: &'static str,
    validator: fn(&[u8]) -> bool,
}

fn validate_git(body: &[u8]) -> bool {
    let s = String::from_utf8_lossy(body);
    s.starts_with("ref: refs/")
}

fn validate_env(body: &[u8]) -> bool {
    let s = String::from_utf8_lossy(body);
    let s_lower = s.to_lowercase();
    if s_lower.contains("<html") || s_lower.contains("<!doctype") {
        return false;
    }
    s.lines().any(|line| {
        let trimmed = line.trim();
        if let Some((k, _)) = trimmed.split_once('=') {
            !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        } else {
            false
        }
    })
}

fn validate_actuator_health(body: &[u8]) -> bool {
    let s = String::from_utf8_lossy(body);
    s.contains("\"status\":")
}

fn validate_actuator_env(body: &[u8]) -> bool {
    let s = String::from_utf8_lossy(body);
    s.contains("\"propertySources\"")
}

fn validate_api_spec(body: &[u8]) -> bool {
    let s = String::from_utf8_lossy(body);
    s.contains("\"swagger\":") || s.contains("\"openapi\":")
}

const SENSITIVE_PATHS: &[SensitivePath] = &[
    SensitivePath {
        path: "/.git/HEAD",
        id: "CG-DAST-EXPO-GIT",
        title: "Exposed Git Repository Metadata (/.git/HEAD)",
        severity: FindingSeverity::High,
        description: "The .git repository directory is publicly accessible, allowing attackers to download source code and version history.",
        remediation: "Restrict web server access to all hidden files and directories starting with a dot (e.g., /.git).",
        validator: validate_git,
    },
    SensitivePath {
        path: "/.env",
        id: "CG-DAST-EXPO-ENV",
        title: "Exposed Environment Configuration File (/.env)",
        severity: FindingSeverity::Critical,
        description: "The .env configuration file is publicly accessible, leaking production database credentials, API keys, and secret tokens.",
        remediation: "Move the .env file outside the web document root and configure your web server to deny access to .env files.",
        validator: validate_env,
    },
    SensitivePath {
        path: "/actuator/health",
        id: "CG-DAST-EXPO-ACTUATOR",
        title: "Exposed Spring Boot Actuator Health Endpoint",
        severity: FindingSeverity::Medium,
        description: "Spring Boot Actuator /health endpoint is exposed without authentication.",
        remediation: "Secure all Spring Boot Actuator endpoints using Spring Security or bind management endpoints to internal interfaces.",
        validator: validate_actuator_health,
    },
    SensitivePath {
        path: "/actuator/env",
        id: "CG-DAST-EXPO-ACTUATOR",
        title: "Exposed Spring Boot Actuator Environment Configuration",
        severity: FindingSeverity::Critical,
        description: "Spring Boot Actuator /env endpoint exposes environment variables and configuration properties.",
        remediation: "Disable or strictly authenticate the management.endpoints.web.exposure.include configuration.",
        validator: validate_actuator_env,
    },
    SensitivePath {
        path: "/swagger.json",
        id: "CG-DAST-EXPO-SWAGGER",
        title: "Exposed Swagger / OpenAPI Specification",
        severity: FindingSeverity::Info,
        description: "The OpenAPI/Swagger API schema is publicly accessible, disclosing all internal API routes and schemas.",
        remediation: "Restrict public access to API documentation endpoints in production environments.",
        validator: validate_api_spec,
    },
];

pub async fn check_sensitive_exposures(
    client: &DastClient,
    base_url: &Url,
    scope: &ScopeGate,
    semaphore: Arc<Semaphore>,
) -> Result<Vec<DastFinding>, DastError> {
    let mut findings = Vec::new();

    for check in SENSITIVE_PATHS {
        let _permit = semaphore
            .acquire()
            .await
            .map_err(|e| DastError::Subprocess(format!("Semaphore acquisition failed: {}", e)))?;

        let probe_url = match base_url.join(check.path) {
            Ok(u) => u,
            Err(_) => continue,
        };

        if let Ok((status, _headers, body)) = client
            .send_request(Method::GET, &probe_url, None, scope)
            .await
        {
            if status.is_success() && (check.validator)(&body) {
                let snippet = String::from_utf8_lossy(&body);
                findings.push(DastFinding::new(
                    check.id,
                    check.title,
                    check.description,
                    check.severity,
                    probe_url.path(),
                    format!("HTTP {} OK with signature: {}", status, snippet),
                    check.remediation,
                ));
            }
        }
    }

    Ok(findings)
}
