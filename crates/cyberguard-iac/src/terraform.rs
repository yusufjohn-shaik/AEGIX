use crate::error::IacError;
use crate::models::{IacFinding, IacRuleId, TerraformLocal, TerraformResource, TerraformVariable};
use crate::parser::IacParser;
use crate::traits::TerraformAuditor;
use cyberguard_secret::mask_secret;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct DefaultTerraformAuditor;

pub const SENSITIVE_MANAGEMENT_PORTS: &[i32] = &[
    22,    // SSH
    3389,  // RDP
    3306,  // MySQL
    5432,  // PostgreSQL
    1433,  // MS SQL
    27017, // MongoDB
    6379,  // Redis
];

pub const SECRET_IDENTIFIERS: &[&str] = &[
    "password",
    "secret",
    "api_key",
    "apikey",
    "token",
    "private_key",
    "db_pass",
    "credential",
];

impl TerraformAuditor for DefaultTerraformAuditor {
    fn audit_terraform(
        &self,
        resources: &[TerraformResource],
        variables: &[TerraformVariable],
        locals: &[TerraformLocal],
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<IacFinding>, IacError> {
        let mut findings = Vec::new();

        // Index standalone S3 encryption configurations to avoid false positives on modern S3
        let standalone_encryption_buckets: Vec<String> = resources
            .iter()
            .filter(|r| r.resource_type == "aws_s3_bucket_server_side_encryption_configuration")
            .filter_map(|r| {
                r.properties
                    .get("bucket")
                    .and_then(|v| v.as_str())
                    .map(|s| {
                        s.trim_start_matches("aws_s3_bucket.")
                            .trim_end_matches(".id")
                            .trim_end_matches(".bucket")
                            .to_string()
                    })
            })
            .collect();

        // --------------------------------------------------------------------
        // CG-IAC-007: Unrestricted Ingress Security Group
        // --------------------------------------------------------------------
        for res in resources {
            if res.resource_type == "aws_security_group"
                || res.resource_type == "aws_security_group_rule"
                || res.resource_type == "aws_vpc_security_group_ingress_rule"
            {
                // Check standalone or inline ingress rules
                let mut ingress_rules: Vec<HashMap<String, serde_json::Value>> = Vec::new();

                // Inline ingress block inside aws_security_group
                if let Some(ingress_val) = res.properties.get("ingress") {
                    match ingress_val {
                        serde_json::Value::Array(arr) => {
                            for item in arr {
                                if let Some(obj) = item.as_object() {
                                    ingress_rules.push(obj.clone().into_iter().collect());
                                }
                            }
                        }
                        serde_json::Value::Object(obj) => {
                            ingress_rules.push(obj.clone().into_iter().collect());
                        }
                        _ => {}
                    }
                }

                // Standalone rule or direct properties
                if res.resource_type == "aws_security_group_rule"
                    || res.resource_type == "aws_vpc_security_group_ingress_rule"
                {
                    let rule_type = res
                        .properties
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("ingress");
                    if rule_type == "ingress" {
                        ingress_rules.push(res.properties.clone());
                    }
                }

                for rule in ingress_rules {
                    let mut is_public = false;
                    if let Some(cidrs) = rule.get("cidr_blocks").and_then(|v| v.as_array()) {
                        is_public = cidrs
                            .iter()
                            .any(|c| c.as_str() == Some("0.0.0.0/0") || c.as_str() == Some("::/0"));
                    }
                    if let Some(cidr_single) = rule.get("cidr_ipv4").and_then(|v| v.as_str()) {
                        if cidr_single == "0.0.0.0/0" {
                            is_public = true;
                        }
                    }
                    if let Some(cidr_v6) = rule.get("cidr_ipv6").and_then(|v| v.as_str()) {
                        if cidr_v6 == "::/0" {
                            is_public = true;
                        }
                    }

                    if is_public {
                        let from_port = rule
                            .get("from_port")
                            .and_then(|v| v.as_i64())
                            .map(|p| p as i32);
                        let to_port = rule
                            .get("to_port")
                            .and_then(|v| v.as_i64())
                            .map(|p| p as i32);
                        let protocol = rule
                            .get("protocol")
                            .or_else(|| rule.get("ip_protocol"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        let is_wildcard_protocol = protocol == "-1" || protocol == "all";

                        for &target_port in SENSITIVE_MANAGEMENT_PORTS {
                            let exposed = is_wildcard_protocol
                                || match (from_port, to_port) {
                                    (Some(from), Some(to)) => {
                                        (from <= target_port && to >= target_port)
                                            || (from == 0 && to == 0)
                                    }
                                    _ => false,
                                };

                            if exposed {
                                let (line, col) =
                                    IacParser::calculate_line_hint(raw_content, "0.0.0.0/0");
                                findings.push(Self::build_finding(
                                    IacRuleId::CgIac007,
                                    file_path,
                                    &res.resource_name,
                                    &res.resource_type,
                                    line,
                                    col,
                                    format!("{}.ingress.cidr_blocks", res.resource_name),
                                    format!(
                                        "Security group '{}' allows unrestricted ingress (0.0.0.0/0) to sensitive port {}.",
                                        res.resource_name, target_port
                                    ),
                                    "Restrict ingress CIDR blocks to specific trusted corporate subnets or bastions.".to_string(),
                                ));
                                break;
                            }
                        }
                    }
                }
            }

            // ----------------------------------------------------------------
            // CG-IAC-008: Unencrypted Cloud Storage Bucket
            // ----------------------------------------------------------------
            if res.resource_type == "aws_s3_bucket" {
                let has_inline_encryption = res
                    .properties
                    .contains_key("server_side_encryption_configuration");
                let has_standalone_encryption = standalone_encryption_buckets
                    .iter()
                    .any(|b| b == &res.resource_name);

                if !has_inline_encryption && !has_standalone_encryption {
                    let (line, col) =
                        IacParser::calculate_line_hint(raw_content, &res.resource_name);
                    findings.push(Self::build_finding(
                        IacRuleId::CgIac008,
                        file_path,
                        &res.resource_name,
                        &res.resource_type,
                        line,
                        col,
                        format!("{}.server_side_encryption_configuration", res.resource_name),
                        format!(
                            "S3 Bucket '{}' omits explicit server-side encryption configuration (SSE-KMS).",
                            res.resource_name
                        ),
                        "Configure 'aws_s3_bucket_server_side_encryption_configuration' with SSE-KMS or AES256.".to_string(),
                    ));
                }
            }

            // ----------------------------------------------------------------
            // CG-IAC-010: Missing Audit / Access Logging
            // ----------------------------------------------------------------
            if res.resource_type == "aws_s3_bucket" {
                let has_logging = res.properties.contains_key("logging");
                if !has_logging {
                    let (line, col) =
                        IacParser::calculate_line_hint(raw_content, &res.resource_name);
                    findings.push(Self::build_finding(
                        IacRuleId::CgIac010,
                        file_path,
                        &res.resource_name,
                        &res.resource_type,
                        line,
                        col,
                        format!("{}.logging", res.resource_name),
                        format!(
                            "S3 Bucket '{}' omits access logging configuration.",
                            res.resource_name
                        ),
                        "Define access logging target bucket via 'logging' block or 'aws_s3_bucket_logging' resource.".to_string(),
                    ));
                }
            }
        }

        // --------------------------------------------------------------------
        // CG-IAC-009: Plaintext Sensitive Secret in IaC
        // --------------------------------------------------------------------
        for var in variables {
            let lower_name = var.name.to_ascii_lowercase();
            let is_sensitive_ident = SECRET_IDENTIFIERS
                .iter()
                .any(|&sec| lower_name.contains(sec));

            if is_sensitive_ident {
                if let Some(ref def_val) = var.default_value {
                    let val_str = match def_val {
                        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.as_str()),
                        _ => None,
                    };

                    if let Some(secret_text) = val_str {
                        let masked = mask_secret(secret_text);
                        let (line, col) = IacParser::calculate_line_hint(raw_content, &var.name);
                        findings.push(Self::build_finding(
                            IacRuleId::CgIac009,
                            file_path,
                            &var.name,
                            "variable",
                            line,
                            col,
                            format!("variable.{}.default", var.name),
                            format!(
                                "Variable '{}' contains a hardcoded plaintext secret default ('{}').",
                                var.name, masked
                            ),
                            "Remove secret default from IaC and inject credentials dynamically via secrets manager or environment.".to_string(),
                        ));
                    }
                }
            }
        }

        for local in locals {
            let lower_name = local.name.to_ascii_lowercase();
            let is_sensitive_ident = SECRET_IDENTIFIERS
                .iter()
                .any(|&sec| lower_name.contains(sec));

            if is_sensitive_ident {
                if let Some(secret_text) = local.value.as_str() {
                    if !secret_text.trim().is_empty() {
                        let masked = mask_secret(secret_text);
                        let (line, col) = IacParser::calculate_line_hint(raw_content, &local.name);
                        findings.push(Self::build_finding(
                            IacRuleId::CgIac009,
                            file_path,
                            &local.name,
                            "locals",
                            line,
                            col,
                            format!("locals.{}", local.name),
                            format!(
                                "Local '{}' contains a hardcoded plaintext secret value ('{}').",
                                local.name, masked
                            ),
                            "Avoid storing secrets in Terraform locals; retrieve values from AWS Secrets Manager or Vault.".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(findings)
    }
}

impl DefaultTerraformAuditor {
    #[allow(clippy::too_many_arguments)]
    fn build_finding(
        rule: IacRuleId,
        file_path: &str,
        resource_id: &str,
        resource_type: &str,
        line: usize,
        column: usize,
        config_path: impl Into<String>,
        description: String,
        remediation: String,
    ) -> IacFinding {
        let config_path_str = config_path.into();
        let mut hasher = Sha256::new();
        hasher.update(rule.as_str().as_bytes());
        hasher.update(file_path.as_bytes());
        hasher.update(resource_id.as_bytes());
        hasher.update(config_path_str.as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize());

        IacFinding {
            rule_id: rule.as_str().to_string(),
            title: rule.title().to_string(),
            description,
            severity: rule.severity(),
            confidence: rule.confidence(),
            cwe: rule.cwe(),
            file_path: file_path.to_string(),
            resource_id: resource_id.to_string(),
            resource_type: resource_type.to_string(),
            line,
            column,
            configuration_path: config_path_str,
            remediation,
            fingerprint,
        }
    }
}
