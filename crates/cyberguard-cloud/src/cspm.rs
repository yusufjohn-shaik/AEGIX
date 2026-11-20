//! Cloud Security Posture Management (CSPM) auditor.
//!
//! Statically evaluates cloud resources for public storage exposures, unencrypted
//! data assets, overly permissive network security groups, and public IAM members.

use crate::error::CloudError;
use crate::models::{
    CloudFinding, CloudProvider, CloudResource, CloudResourceType, RuleAction, RuleDirection,
    SecurityGroupRule, StatementEffect,
};
use crate::traits::CspmAuditor;
use cyberguard_core::sarif::{Confidence, SarifLevel};

pub struct DefaultCspmAuditor;

pub const SENSITIVE_MANAGEMENT_PORTS: &[i32] = &[
    22,    // SSH
    3389,  // RDP
    3306,  // MySQL
    5432,  // PostgreSQL
    1433,  // MS SQL
    27017, // MongoDB
    6379,  // Redis
];

impl CspmAuditor for DefaultCspmAuditor {
    fn audit_posture(&self, resources: &[CloudResource]) -> Result<Vec<CloudFinding>, CloudError> {
        let mut findings = Vec::new();

        for res in resources {
            // 1. Storage Bucket Audits (CG-CLOUD-003, CG-CLOUD-004)
            if res.resource_type == CloudResourceType::StorageBucket {
                // CG-CLOUD-004: Unencrypted Cloud Storage at Rest
                let is_encrypted = res
                    .server_side_encryption
                    .as_ref()
                    .map(|e| e.enabled)
                    .unwrap_or(false);

                if !is_encrypted {
                    findings.push(CloudFinding {
                        rule_id: "CG-CLOUD-004".to_string(),
                        title: "Unencrypted Cloud Storage Bucket at Rest".to_string(),
                        description: format!(
                            "Storage bucket '{}' does not mandate default server-side encryption.",
                            res.name
                        ),
                        severity: SarifLevel::Warning,
                        confidence: Confidence::High,
                        cwe: 311,
                        provider: res.provider,
                        resource_id: res.id.clone(),
                        configuration_path: "/ServerSideEncryptionConfiguration".to_string(),
                        remediation: "Enable server-side encryption with AWS KMS (aws:kms) or AES256 customer-managed/provider-managed keys.".to_string(),
                    });
                }

                // CG-CLOUD-003: Public Unauthenticated Storage Bucket Policy
                for policy in &res.associated_policies {
                    for statement in &policy.statements {
                        if statement.effect == StatementEffect::Allow {
                            if let Some(ref principal) = statement.principal {
                                if principal.is_public_wildcard()
                                    && !statement.has_restricting_conditions()
                                {
                                    findings.push(CloudFinding {
                                        rule_id: "CG-CLOUD-003".to_string(),
                                        title: "Public Unauthenticated Storage Bucket Exposure".to_string(),
                                        description: format!(
                                            "Storage bucket '{}' policy grants public anonymous access (Principal: *) without conditional constraints.",
                                            res.name
                                        ),
                                        severity: SarifLevel::Error,
                                        confidence: Confidence::High,
                                        cwe: 284,
                                        provider: res.provider,
                                        resource_id: res.id.clone(),
                                        configuration_path: "/Statement/Principal".to_string(),
                                        remediation: "Remove public wildcard Principal and enable S3 Block Public Access at bucket and account levels.".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // 2. AWS Security Group Audits (CG-CLOUD-005)
            if res.resource_type == CloudResourceType::SecurityGroup {
                for rule in &res.security_rules {
                    if rule.direction == RuleDirection::Inbound && rule.action == RuleAction::Allow
                    {
                        let is_public =
                            rule.cidr_blocks.iter().any(|c| {
                                c == "0.0.0.0/0" || c == "0.0.0.0/1" || c == "128.0.0.0/1"
                            }) || rule.ipv6_cidr_blocks.iter().any(|c| c == "::/0");

                        if is_public {
                            for &port in SENSITIVE_MANAGEMENT_PORTS {
                                if Self::rule_covers_port(rule, port) {
                                    findings.push(CloudFinding {
                                        rule_id: "CG-CLOUD-005".to_string(),
                                        title: "Security Group Exposes Sensitive Port to the Internet".to_string(),
                                        description: format!(
                                            "Security group '{}' allows unrestricted inbound traffic (0.0.0.0/0) to sensitive port {}.",
                                            res.name, port
                                        ),
                                        severity: SarifLevel::Error,
                                        confidence: Confidence::High,
                                        cwe: 284,
                                        provider: res.provider,
                                        resource_id: res.id.clone(),
                                        configuration_path: format!("/IpPermissions/FromPort-{}", port),
                                        remediation: "Restrict ingress CIDRs to authorized corporate subnets or bastion host IP addresses.".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // 3. Azure NSG Audits (CG-CLOUD-009)
            if res.resource_type == CloudResourceType::NetworkSecurityGroup {
                for rule in &res.security_rules {
                    if rule.direction == RuleDirection::Inbound && rule.action == RuleAction::Allow
                    {
                        let is_public = rule.cidr_blocks.iter().any(|c| {
                            c == "*"
                                || c.eq_ignore_ascii_case("Internet")
                                || c == "0.0.0.0/0"
                                || c == "0.0.0.0/1"
                                || c == "128.0.0.0/1"
                        });

                        if is_public {
                            for &port in &[22, 3389, 3306, 5432] {
                                if Self::rule_covers_port(rule, port) {
                                    findings.push(CloudFinding {
                                        rule_id: "CG-CLOUD-009".to_string(),
                                        title: "Azure NSG Inbound Any to Management Port".to_string(),
                                        description: format!(
                                            "Azure Network Security Group allows inbound Internet traffic to management port {}.",
                                            port
                                        ),
                                        severity: SarifLevel::Error,
                                        confidence: Confidence::High,
                                        cwe: 284,
                                        provider: CloudProvider::Azure,
                                        resource_id: res.id.clone(),
                                        configuration_path: format!(
                                            "/securityRules/{}",
                                            rule.rule_id.as_deref().unwrap_or("rule")
                                        ),
                                        remediation: "Restrict sourceAddressPrefix in NSG rule from 'Internet' to specific administrative IP ranges or Azure Bastion.".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // 4. GCP Public Member Bindings (CG-CLOUD-007)
            if res.provider == CloudProvider::Gcp {
                if let Some(bindings) = res
                    .raw_properties
                    .get("bindings")
                    .and_then(|v| v.as_array())
                {
                    for b in bindings {
                        if let Some(members) = b.get("members").and_then(|v| v.as_array()) {
                            let has_public_member = members.iter().any(|m| {
                                m.as_str()
                                    .map(|s| s == "allUsers" || s == "allAuthenticatedUsers")
                                    .unwrap_or(false)
                            });

                            if has_public_member {
                                let role =
                                    b.get("role").and_then(|v| v.as_str()).unwrap_or("unknown");
                                findings.push(CloudFinding {
                                    rule_id: "CG-CLOUD-007".to_string(),
                                    title: "GCP Public IAM Member Exposure".to_string(),
                                    description: format!(
                                        "GCP IAM policy binds public member ('allUsers' or 'allAuthenticatedUsers') to role '{}'.",
                                        role
                                    ),
                                    severity: SarifLevel::Error,
                                    confidence: Confidence::High,
                                    cwe: 284,
                                    provider: CloudProvider::Gcp,
                                    resource_id: res.id.clone(),
                                    configuration_path: "/bindings/members".to_string(),
                                    remediation: "Remove 'allUsers' and 'allAuthenticatedUsers' bindings and grant access exclusively to designated corporate identities.".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}

impl DefaultCspmAuditor {
    /// Checks whether a security group rule covers a given port.
    pub fn rule_covers_port(rule: &SecurityGroupRule, port: i32) -> bool {
        match (rule.from_port, rule.to_port) {
            (Some(from), Some(to)) => {
                if from == -1 || to == -1 {
                    true
                } else {
                    port >= from && port <= to
                }
            }
            (Some(from), None) => from == -1 || port == from,
            (None, Some(to)) => to == -1 || port == to,
            (None, None) => rule.protocol == "*" || rule.protocol == "-1",
        }
    }
}
