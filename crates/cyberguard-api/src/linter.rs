//! Static contract security auditor implementing OWASP API Security Top 10 rules.

use crate::models::{ApiFinding, ApiSpec, Operation, ParamLocation, SchemaNode};
use crate::traits::ApiLinter;
use cyberguard_core::sarif::{Confidence, SarifLevel};
use std::collections::HashSet;

/// Default static contract linter for API specifications.
#[derive(Debug, Default, Clone)]
pub struct DefaultApiLinter;

impl DefaultApiLinter {
    pub fn new() -> Self {
        Self
    }
}

impl ApiLinter for DefaultApiLinter {
    fn lint(&self, spec: &ApiSpec, spec_path: &str) -> Vec<ApiFinding> {
        let mut findings = Vec::new();

        // Rule CG-API-002: Insecure Plaintext Server URL (Spec-level check)
        check_insecure_server_urls(spec, &mut findings);

        // Operation-level rules
        for op in &spec.operations {
            check_missing_operation_security(op, &mut findings);
            check_unauthenticated_object_id_access(op, &mut findings);
            check_mass_assignment(op, &mut findings);
            check_unbounded_pagination(op, &mut findings);
            check_excessive_data_exposure(op, &mut findings);
            check_admin_route_security(op, &mut findings);
        }

        // Fill line hint / path if needed
        for finding in &mut findings {
            if finding.path.is_empty() {
                finding.path = spec_path.to_string();
            }
        }

        findings
    }
}

/// Rule CG-API-002: Insecure Plaintext Server URL (CWE-319, API8:2023)
fn check_insecure_server_urls(spec: &ApiSpec, findings: &mut Vec<ApiFinding>) {
    for (idx, server) in spec.servers.iter().enumerate() {
        let lower = server.to_ascii_lowercase();
        if lower.starts_with("http://") {
            // Exemption: loopback / local development addresses
            let host_part = lower.trim_start_matches("http://");
            let is_loopback = host_part.starts_with("localhost")
                || host_part.starts_with("127.0.0.1")
                || host_part.starts_with("[::1]")
                || host_part.starts_with("0.0.0.0");

            if !is_loopback {
                findings.push(ApiFinding {
                    rule_id: "CG-API-002".to_string(),
                    title: "Insecure Plaintext Server URL".to_string(),
                    description: format!(
                        "API server URL '{}' specifies insecure plaintext HTTP transport. Production APIs must enforce TLS encryption.",
                        server
                    ),
                    severity: SarifLevel::Error,
                    confidence: Confidence::High,
                    cwe: 319,
                    path: String::new(),
                    method: None,
                    line_hint: Some(1),
                    json_pointer: format!("/servers/{}", idx),
                    remediation: "Upgrade server URL scheme from 'http://' to 'https://' and enforce HSTS."
                        .to_string(),
                });
            }
        }
    }
}

/// Rule CG-API-001: Missing Operation Security (CWE-306, API2:2023)
fn check_missing_operation_security(op: &Operation, findings: &mut Vec<ApiFinding>) {
    // Exempt public endpoints
    if op.is_public_exempt {
        return;
    }

    if op.security.is_empty() {
        findings.push(ApiFinding {
            rule_id: "CG-API-001".to_string(),
            title: "Missing Operation Security Requirement".to_string(),
            description: format!(
                "Operation '{} {}' defines no authentication or authorization security requirements. Any anonymous caller can invoke this endpoint.",
                op.method, op.path
            ),
            severity: SarifLevel::Error,
            confidence: Confidence::High,
            cwe: 306,
            path: op.path.clone(),
            method: Some(op.method.clone()),
            line_hint: Some(1),
            json_pointer: format!("/paths/~1{}/{}/security", escape_pointer(&op.path), op.method.to_ascii_lowercase()),
            remediation: "Declare explicit authentication security schemes (e.g. bearerAuth, apiKey, oauth2) in the operation definition."
                .to_string(),
        });
    }
}

/// Rule CG-API-003: Unauthenticated Object ID Access (CWE-639, API1:2023)
fn check_unauthenticated_object_id_access(op: &Operation, findings: &mut Vec<ApiFinding>) {
    // Only flag if operation has no security and is NOT an exempted public route
    if !op.security.is_empty() || op.is_public_exempt {
        return;
    }

    let has_id_param = op.parameters.iter().any(|p| {
        if p.location == ParamLocation::Path {
            let n = p.name.to_ascii_lowercase();
            n == "id" || n.ends_with("_id") || n.ends_with("id") || n.contains("uuid")
        } else {
            false
        }
    });

    if has_id_param {
        findings.push(ApiFinding {
            rule_id: "CG-API-003".to_string(),
            title: "Unauthenticated Direct Object Access (BOLA / IDOR Risk)".to_string(),
            description: format!(
                "Operation '{} {}' accepts direct object identifiers in path parameters without enforcing authentication requirements, facilitating unauthorized ID enumeration.",
                op.method, op.path
            ),
            severity: SarifLevel::Warning,
            confidence: Confidence::Medium,
            cwe: 639,
            path: op.path.clone(),
            method: Some(op.method.clone()),
            line_hint: Some(1),
            json_pointer: format!("/paths/~1{}/{}", escape_pointer(&op.path), op.method.to_ascii_lowercase()),
            remediation: "Enforce authentication and verify the requesting identity owns the referenced object resource before handling requests."
                .to_string(),
        });
    }
}

/// Rule CG-API-004: Mass Assignment in Request Body (CWE-915, API3:2023)
fn check_mass_assignment(op: &Operation, findings: &mut Vec<ApiFinding>) {
    // Admin routes legitimately update administrative fields
    if op.is_admin_route {
        return;
    }

    let body = match &op.request_body {
        Some(b) => b,
        None => return,
    };

    let sensitive_keys: HashSet<&'static str> = [
        "role",
        "roles",
        "isadmin",
        "is_admin",
        "admin",
        "permissions",
        "balance",
        "credit",
        "verified",
        "is_verified",
        "superuser",
    ]
    .into_iter()
    .collect();

    for (content_type, schema) in &body.content_types {
        let mut flagged_props = Vec::new();
        find_sensitive_properties(schema, &sensitive_keys, false, &mut flagged_props);

        if !flagged_props.is_empty() {
            findings.push(ApiFinding {
                rule_id: "CG-API-004".to_string(),
                title: "Mass Assignment Vulnerability in Request Schema".to_string(),
                description: format!(
                    "Operation '{} {}' ({}) accepts client-controlled administrative properties ({}) in request body schema without readOnly protection.",
                    op.method,
                    op.path,
                    content_type,
                    flagged_props.join(", ")
                ),
                severity: SarifLevel::Warning,
                confidence: Confidence::Medium,
                cwe: 915,
                path: op.path.clone(),
                method: Some(op.method.clone()),
                line_hint: Some(1),
                json_pointer: format!(
                    "/paths/~1{}/{}/requestBody/content/{}/schema",
                    escape_pointer(&op.path),
                    op.method.to_ascii_lowercase(),
                    content_type
                ),
                remediation: "Mark privileged administrative fields as 'readOnly: true' or separate public client DTOs from internal administrative entities."
                    .to_string(),
            });
        }
    }
}

/// Rule CG-API-005: Unbounded Collection Pagination (CWE-20, API4:2023)
fn check_unbounded_pagination(op: &Operation, findings: &mut Vec<ApiFinding>) {
    if op.method != "GET" || op.is_public_exempt {
        return;
    }

    // Check if 2xx response returns an array
    let returns_array = op.responses.iter().any(|(code, resp)| {
        if code.starts_with('2') {
            resp.content_types.values().any(|schema| {
                schema.schema_type.as_deref() == Some("array")
                    || schema
                        .properties
                        .values()
                        .any(|p| p.schema_type.as_deref() == Some("array"))
            })
        } else {
            false
        }
    });

    if !returns_array {
        return;
    }

    // Check if query parameters include pagination controls
    let pagination_params: HashSet<&'static str> = [
        "limit",
        "offset",
        "page",
        "pagesize",
        "page_size",
        "per_page",
        "cursor",
        "size",
        "count",
    ]
    .into_iter()
    .collect();

    let has_pagination = op.parameters.iter().any(|p| {
        p.location == ParamLocation::Query
            && pagination_params.contains(p.name.to_ascii_lowercase().as_str())
    });

    if !has_pagination {
        findings.push(ApiFinding {
            rule_id: "CG-API-005".to_string(),
            title: "Unbounded Collection Pagination (Denial of Service Risk)".to_string(),
            description: format!(
                "GET operation '{}' returns a collection/array without defining pagination query parameters (e.g. 'limit', 'page', 'cursor'). Callers can trigger memory exhaustion by querying unbounded record sets.",
                op.path
            ),
            severity: SarifLevel::Warning,
            confidence: Confidence::Medium,
            cwe: 20,
            path: op.path.clone(),
            method: Some(op.method.clone()),
            line_hint: Some(1),
            json_pointer: format!("/paths/~1{}/get/parameters", escape_pointer(&op.path)),
            remediation: "Add mandatory pagination controls (e.g., 'limit', 'page', or 'cursor') with an enforced maximum page size."
                .to_string(),
        });
    }
}

/// Rule CG-API-006: Excessive Data Exposure in Response (CWE-200, API3:2023)
fn check_excessive_data_exposure(op: &Operation, findings: &mut Vec<ApiFinding>) {
    let sensitive_keys: HashSet<&'static str> = [
        "password",
        "passwd",
        "secret",
        "token",
        "private_key",
        "api_key",
        "ssn",
        "credential",
        "hash",
    ]
    .into_iter()
    .collect();

    for (code, resp) in &op.responses {
        if code.starts_with('2') {
            for (content_type, schema) in &resp.content_types {
                let mut flagged_props = Vec::new();
                find_sensitive_properties(schema, &sensitive_keys, true, &mut flagged_props);

                if !flagged_props.is_empty() {
                    findings.push(ApiFinding {
                        rule_id: "CG-API-006".to_string(),
                        title: "Excessive Sensitive Data Exposure in Response".to_string(),
                        description: format!(
                            "Response {} of '{} {}' ({}) exposes sensitive attributes ({}) without 'writeOnly: true' suppression.",
                            code,
                            op.method,
                            op.path,
                            content_type,
                            flagged_props.join(", ")
                        ),
                        severity: SarifLevel::Warning,
                        confidence: Confidence::High,
                        cwe: 200,
                        path: op.path.clone(),
                        method: Some(op.method.clone()),
                        line_hint: Some(1),
                        json_pointer: format!(
                            "/paths/~1{}/{}/responses/{}/content/{}/schema",
                            escape_pointer(&op.path),
                            op.method.to_ascii_lowercase(),
                            code,
                            content_type
                        ),
                        remediation: "Remove sensitive fields from API response schemas or annotate them with 'writeOnly: true'."
                            .to_string(),
                    });
                }
            }
        }
    }
}

/// Rule CG-API-007: Missing Admin Route Authentication (CWE-285, API5:2023)
fn check_admin_route_security(op: &Operation, findings: &mut Vec<ApiFinding>) {
    if op.is_admin_route && op.security.is_empty() {
        findings.push(ApiFinding {
            rule_id: "CG-API-007".to_string(),
            title: "Missing Authentication on Administrative Endpoint (BFLA Risk)".to_string(),
            description: format!(
                "Privileged administrative route '{} {}' lacks authentication and access control requirements. Anonymous users can invoke administrative functions.",
                op.method, op.path
            ),
            severity: SarifLevel::Error,
            confidence: Confidence::High,
            cwe: 285,
            path: op.path.clone(),
            method: Some(op.method.clone()),
            line_hint: Some(1),
            json_pointer: format!("/paths/~1{}/{}/security", escape_pointer(&op.path), op.method.to_ascii_lowercase()),
            remediation: "Restrict administrative and internal endpoints with strict role-based access control and mutual authentication."
                .to_string(),
        });
    }
}

fn find_sensitive_properties(
    schema: &SchemaNode,
    sensitive_keys: &HashSet<&'static str>,
    is_response: bool,
    flagged: &mut Vec<String>,
) {
    for (prop_name, prop_schema) in &schema.properties {
        let lower = prop_name.to_ascii_lowercase();
        let matches = sensitive_keys.iter().any(|k| lower.contains(k));

        if matches {
            if is_response {
                // In responses, exempt if write_only is true
                if !prop_schema.write_only {
                    flagged.push(prop_name.clone());
                }
            } else {
                // In request bodies, exempt if read_only is true
                if !prop_schema.read_only {
                    flagged.push(prop_name.clone());
                }
            }
        }

        // Recurse into child properties
        find_sensitive_properties(prop_schema, sensitive_keys, is_response, flagged);
    }

    if let Some(items) = &schema.items {
        find_sensitive_properties(items, sensitive_keys, is_response, flagged);
    }
}

fn escape_pointer(path: &str) -> String {
    path.trim_start_matches('/')
        .replace('/', "~1")
        .replace('~', "~0")
}
