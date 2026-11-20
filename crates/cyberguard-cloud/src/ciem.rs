//! Cloud Infrastructure Entitlement Management (CIEM) auditor.
//!
//! Audits multi-cloud identities, permissions, and role assignments against
//! CIS Benchmarks and OWASP Cloud Top 10 rules.

use crate::error::CloudError;
use crate::models::{
    CloudFinding, CloudProvider, CloudResource, CloudResourceType, IamPolicy, StatementEffect,
};
use crate::traits::CiemAuditor;
use cyberguard_core::sarif::{Confidence, SarifLevel};

pub struct DefaultCiemAuditor;

/// Rhino Security Labs Privilege Escalation Action Matrix
pub const PRIVILEGE_ESCALATION_TUPLES: &[(&[&str], &str)] = &[
    // PassRole combined with compute execution engines
    (&["iam:PassRole"], "ec2:RunInstances"),
    (&["iam:PassRole"], "lambda:CreateFunction"),
    (&["iam:PassRole"], "glue:CreateDevEndpoint"),
    (&["iam:PassRole"], "cloudformation:CreateStack"),
    (&["iam:PassRole"], "datapipeline:CreatePipeline"),
    (&["iam:PassRole"], "codebuild:CreateProject"),
    // Direct policy modifications
    (&["iam:CreatePolicyVersion"], ""),
    (&["iam:SetDefaultPolicyVersion"], ""),
    (&["iam:AttachUserPolicy"], ""),
    (&["iam:AttachGroupPolicy"], ""),
    (&["iam:AttachRolePolicy"], ""),
    (&["iam:PutUserPolicy"], ""),
    (&["iam:PutGroupPolicy"], ""),
    (&["iam:PutRolePolicy"], ""),
    // Group and role membership alteration
    (&["iam:AddUserToGroup"], ""),
    (&["iam:UpdateAssumeRolePolicy"], ""),
    // Credential generation / password reset
    (&["iam:CreateAccessKey"], ""),
    (&["iam:CreateLoginProfile"], ""),
    (&["iam:UpdateLoginProfile"], ""),
];

impl CiemAuditor for DefaultCiemAuditor {
    fn audit_entitlements(
        &self,
        policies: &[IamPolicy],
        resources: &[CloudResource],
    ) -> Result<Vec<CloudFinding>, CloudError> {
        let mut findings = Vec::new();

        // 1. Audit AWS IAM Policies
        for policy in policies {
            for statement in &policy.statements {
                if statement.effect != StatementEffect::Allow {
                    continue;
                }

                // CG-CLOUD-001: AWS IAM Full Administrative Wildcard
                if statement.allows_action("*") && statement.allows_wildcard_resource() {
                    // Calibrated Exemption: Skip if restricting conditions are present
                    if !statement.has_restricting_conditions() {
                        findings.push(CloudFinding {
                            rule_id: "CG-CLOUD-001".to_string(),
                            title: "AWS IAM Policy Full Administrative Wildcard Granted".to_string(),
                            description: format!(
                                "IAM policy '{}' grants unrestricted administrative access (Action: *, Resource: *) without restricting condition keys.",
                                policy.policy_name.as_deref().unwrap_or("inline")
                            ),
                            severity: SarifLevel::Error,
                            confidence: Confidence::High,
                            cwe: 732,
                            provider: CloudProvider::Aws,
                            resource_id: policy.policy_name.clone().unwrap_or_else(|| "iam-policy".to_string()),
                            configuration_path: "/Statement/Action".to_string(),
                            remediation: "Scope permissions to the least privilege required. Replace Action: '*' with specific API operations and restrict Resource ARNs.".to_string(),
                        });
                    }
                }

                // CG-CLOUD-002: AWS IAM Dangerous Privilege Escalation Paths
                for (actions, companion) in PRIVILEGE_ESCALATION_TUPLES {
                    let has_primary = actions.iter().any(|act| statement.allows_action(act));
                    let has_companion = companion.is_empty() || statement.allows_action(companion);

                    if has_primary && has_companion {
                        findings.push(CloudFinding {
                            rule_id: "CG-CLOUD-002".to_string(),
                            title: "AWS IAM Privilege Escalation Vector Detected".to_string(),
                            description: format!(
                                "IAM policy grants known privilege escalation capability ({:?} combined with '{}').",
                                actions, companion
                            ),
                            severity: SarifLevel::Error,
                            confidence: Confidence::High,
                            cwe: 269,
                            provider: CloudProvider::Aws,
                            resource_id: policy.policy_name.clone().unwrap_or_else(|| "iam-policy".to_string()),
                            configuration_path: "/Statement/Action".to_string(),
                            remediation: "Restrict iam:PassRole and policy creation permissions to dedicated administrative roles, and apply explicit condition constraints.".to_string(),
                        });
                        break; // One escalation alert per statement
                    }
                }
            }
        }

        // 2. Audit GCP IAM Bindings (CG-CLOUD-006: Primitive Owner/Editor Role)
        for resource in resources {
            if resource.provider == CloudProvider::Gcp {
                if let Some(bindings) = resource
                    .raw_properties
                    .get("bindings")
                    .and_then(|v| v.as_array())
                {
                    for b in bindings {
                        if let Some(role) = b.get("role").and_then(|v| v.as_str()) {
                            if role == "roles/owner" || role == "roles/editor" {
                                findings.push(CloudFinding {
                                    rule_id: "CG-CLOUD-006".to_string(),
                                    title: "GCP Over-Privileged Primitive Role Assigned".to_string(),
                                    description: format!(
                                        "GCP IAM binding assigns legacy primitive role '{}' with excessive blast radius.",
                                        role
                                    ),
                                    severity: SarifLevel::Error,
                                    confidence: Confidence::High,
                                    cwe: 732,
                                    provider: CloudProvider::Gcp,
                                    resource_id: resource.id.clone(),
                                    configuration_path: "/bindings/role".to_string(),
                                    remediation: "Replace primitive roles/owner and roles/editor with targeted predefined IAM roles matching the least privilege principle.".to_string(),
                                });
                            }
                        }
                    }
                }
            }

            // 3. Audit Azure RBAC Role Assignments (CG-CLOUD-008: Permissive RBAC Owner)
            if resource.provider == CloudProvider::Azure
                && resource.resource_type == CloudResourceType::AzureRoleAssignment
            {
                let role_def = resource
                    .raw_properties
                    .get("roleDefinitionName")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&resource.name);
                if role_def.eq_ignore_ascii_case("Owner")
                    || role_def.eq_ignore_ascii_case("Contributor")
                {
                    let scope = resource
                        .raw_properties
                        .get("scope")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if scope.starts_with("/subscriptions/") && !scope.contains("/resourceGroups/") {
                        findings.push(CloudFinding {
                            rule_id: "CG-CLOUD-008".to_string(),
                            title: "Azure Permissive Subscription-Level RBAC Assignment".to_string(),
                            description: format!(
                                "Azure role assignment grants excessive role '{}' at the broad subscription scope.",
                                role_def
                            ),
                            severity: SarifLevel::Error,
                            confidence: Confidence::High,
                            cwe: 732,
                            provider: CloudProvider::Azure,
                            resource_id: resource.id.clone(),
                            configuration_path: "/roleDefinitionName".to_string(),
                            remediation: "Scope Azure role assignments to specific Resource Groups or Resources instead of broad subscription or management group scopes.".to_string(),
                        });
                    }
                }
            }

            // 4. Audit Account Credential Report (CG-CLOUD-010: Root Account Missing MFA)
            if resource.id == "aws-account-summary" {
                let mfa_enabled = resource
                    .raw_properties
                    .get("AccountMFAEnabled")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1);
                let access_keys_present = resource
                    .raw_properties
                    .get("AccountAccessKeysPresent")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);

                if mfa_enabled == 0 || access_keys_present > 0 {
                    findings.push(CloudFinding {
                        rule_id: "CG-CLOUD-010".to_string(),
                        title: "Root or Privileged Account Missing MFA or Active Access Keys".to_string(),
                        description: "AWS account summary indicates that root MFA is disabled or active root access keys exist.".to_string(),
                        severity: SarifLevel::Warning,
                        confidence: Confidence::Medium,
                        cwe: 308,
                        provider: CloudProvider::Aws,
                        resource_id: resource.id.clone(),
                        configuration_path: "/AccountMFAEnabled".to_string(),
                        remediation: "Enable hardware/virtual MFA on the root account and delete all active root access keys immediately.".to_string(),
                    });
                }
            }
        }

        Ok(findings)
    }
}
