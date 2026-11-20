//! Canonical Intermediate Representation (IR), polymorphic deserializers, and finding models.

use cyberguard_core::sarif::{Confidence, SarifLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cloud service provider identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    Generic,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Gcp => write!(f, "GCP"),
            Self::Azure => write!(f, "Azure"),
            Self::Generic => write!(f, "Generic"),
        }
    }
}

/// Robust polymorphic deserializer handling scalar String or Vec<String>.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
}

impl StringOrVec {
    /// Returns all values as a unified vector of string slices.
    pub fn as_slice_strings(&self) -> Vec<&str> {
        match self {
            Self::Single(s) => vec![s.as_str()],
            Self::Multiple(vec) => vec.iter().map(|s| s.as_str()).collect(),
        }
    }

    /// Checks if any item matches the target string (case-insensitive for actions).
    pub fn contains_ignore_ascii_case(&self, target: &str) -> bool {
        match self {
            Self::Single(s) => s.eq_ignore_ascii_case(target),
            Self::Multiple(vec) => vec.iter().any(|s| s.eq_ignore_ascii_case(target)),
        }
    }

    /// Checks if any item matches the wildcard pattern or exact string.
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        self.as_slice_strings().iter().any(|val| {
            if *val == "*" || *val == pattern {
                true
            } else if let Some(prefix) = val.strip_suffix('*') {
                pattern.starts_with(prefix)
            } else {
                false
            }
        })
    }
}

/// Representation of AWS IAM Principal duality (Wildcard "*" vs. Structured Object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Principal {
    Wildcard(String),
    Structured(HashMap<String, StringOrVec>),
}

impl Principal {
    /// Returns true if the principal grants anonymous public access ("*").
    pub fn is_public_wildcard(&self) -> bool {
        match self {
            Self::Wildcard(s) => s == "*",
            Self::Structured(map) => map.iter().any(|(k, v)| {
                k == "*"
                    || v.as_slice_strings()
                        .iter()
                        .any(|p| *p == "*" || *p == "arn:aws:iam::*:root")
            }),
        }
    }
}

/// Statement Effect (Allow or Deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatementEffect {
    Allow,
    Deny,
}

/// Canonical IAM Policy Statement IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    #[serde(default)]
    pub sid: Option<String>,
    pub effect: StatementEffect,
    #[serde(default)]
    pub principal: Option<Principal>,
    #[serde(default)]
    pub action: Option<StringOrVec>,
    #[serde(default)]
    pub not_action: Option<StringOrVec>,
    #[serde(default)]
    pub resource: Option<StringOrVec>,
    #[serde(default)]
    pub not_resource: Option<StringOrVec>,
    #[serde(default)]
    pub condition: Option<HashMap<String, serde_json::Value>>,
}

impl Statement {
    /// Checks whether this statement grants the specified action.
    pub fn allows_action(&self, target_action: &str) -> bool {
        if self.effect != StatementEffect::Allow {
            return false;
        }
        if let Some(ref action) = self.action {
            action.matches_pattern(target_action)
        } else {
            false
        }
    }

    /// Checks whether this statement targets the wildcard resource ("*").
    pub fn allows_wildcard_resource(&self) -> bool {
        if self.effect != StatementEffect::Allow {
            return false;
        }
        if let Some(ref res) = self.resource {
            res.as_slice_strings().contains(&"*")
        } else {
            false
        }
    }

    /// Checks whether the statement contains conditions constraining access.
    pub fn has_restricting_conditions(&self) -> bool {
        if let Some(ref cond) = self.condition {
            !cond.is_empty()
        } else {
            false
        }
    }
}

/// Canonical IAM Policy IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicy {
    pub provider: CloudProvider,
    pub policy_id: Option<String>,
    pub policy_name: Option<String>,
    pub statements: Vec<Statement>,
    pub attached_roles: Vec<String>,
    pub raw_json: Option<serde_json::Value>,
}

/// Security Group and NSG Ingress/Egress Rule IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroupRule {
    pub rule_id: Option<String>,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub protocol: String, // tcp, udp, icmp, *
    pub from_port: Option<i32>,
    pub to_port: Option<i32>,
    pub cidr_blocks: Vec<String>,
    pub ipv6_cidr_blocks: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Canonical Cloud Resource Types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudResourceType {
    StorageBucket,
    SecurityGroup,
    NetworkSecurityGroup,
    IamRole,
    IcpBinding,
    AzureRoleAssignment,
    Generic,
}

/// Canonical Cloud Resource Representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResource {
    pub provider: CloudProvider,
    pub resource_type: CloudResourceType,
    pub id: String,
    pub name: String,
    pub tags: HashMap<String, String>,
    pub server_side_encryption: Option<ServerSideEncryption>,
    pub security_rules: Vec<SecurityGroupRule>,
    pub associated_policies: Vec<IamPolicy>,
    pub raw_properties: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSideEncryption {
    pub enabled: bool,
    pub algorithm: Option<String>,
    pub kms_key_id: Option<String>,
}

/// Unified Ingestion Output Configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConfig {
    pub detected_provider: CloudProvider,
    pub resources: Vec<CloudResource>,
    pub policies: Vec<IamPolicy>,
}

/// Cloud Vulnerability Finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudFinding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: SarifLevel,
    pub confidence: Confidence,
    pub cwe: u32,
    pub provider: CloudProvider,
    pub resource_id: String,
    pub configuration_path: String,
    pub remediation: String,
}

/// Final Audit Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAuditReport {
    pub provider: CloudProvider,
    pub total_resources_evaluated: usize,
    pub total_policies_evaluated: usize,
    pub findings: Vec<CloudFinding>,
}
