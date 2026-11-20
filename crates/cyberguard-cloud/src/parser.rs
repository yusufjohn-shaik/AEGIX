//! Multi-cloud static configuration and policy ingestion parser.

use crate::error::CloudError;
use crate::models::{
    CloudConfig, CloudProvider, CloudResource, CloudResourceType, IamPolicy, RuleAction,
    RuleDirection, SecurityGroupRule, ServerSideEncryption, Statement,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

/// Maximum allowable configuration file size for static analysis (10 MB).
pub const MAX_CONFIG_FILE_SIZE: usize = 10 * 1024 * 1024;

pub struct CloudParser;

impl CloudParser {
    /// Ingests a file or directory from disk. If a directory is given, recursively
    /// traverses and ingests all .json, .yaml, and .yml files.
    pub fn parse_path(path: &Path) -> Result<CloudConfig, CloudError> {
        if path == Path::new("-") {
            let mut content = String::new();
            std::io::stdin().read_to_string(&mut content)?;
            return Self::parse_str(&content, Path::new("stdin.json"));
        }

        if path.is_dir() {
            Self::parse_dir(path)
        } else {
            Self::parse_file(path)
        }
    }

    /// Recursively traverses a directory and aggregates all parsed cloud configs.
    pub fn parse_dir(dir: &Path) -> Result<CloudConfig, CloudError> {
        let mut aggregated_resources = Vec::new();
        let mut aggregated_policies = Vec::new();
        let mut primary_provider = CloudProvider::Generic;

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .flatten()
        {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    let ext_lower = ext.to_ascii_lowercase();
                    if ext_lower == "json" || ext_lower == "yaml" || ext_lower == "yml" {
                        if let Ok(config) = Self::parse_file(p) {
                            if primary_provider == CloudProvider::Generic
                                && config.detected_provider != CloudProvider::Generic
                            {
                                primary_provider = config.detected_provider;
                            }
                            aggregated_resources.extend(config.resources);
                            aggregated_policies.extend(config.policies);
                        }
                    }
                }
            }
        }

        Ok(CloudConfig {
            detected_provider: primary_provider,
            resources: aggregated_resources,
            policies: aggregated_policies,
        })
    }

    /// Ingests a single configuration file from disk.
    pub fn parse_file(path: &Path) -> Result<CloudConfig, CloudError> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        if size > MAX_CONFIG_FILE_SIZE {
            return Err(CloudError::FileSizeLimitExceeded {
                size,
                max_allowed: MAX_CONFIG_FILE_SIZE,
            });
        }

        let mut content = String::with_capacity(size);
        file.read_to_string(&mut content)?;
        Self::parse_str(&content, path)
    }

    /// Ingests raw JSON or YAML content with a path hint for naming.
    pub fn parse_str(content: &str, path_hint: &Path) -> Result<CloudConfig, CloudError> {
        let value: serde_json::Value = if let Ok(val) = serde_json::from_str(content) {
            val
        } else {
            serde_yaml::from_str(content)?
        };

        Self::normalize_value(value, path_hint)
    }

    /// Auto-detects cloud provider schema and normalizes to canonical CloudConfig IR.
    pub fn normalize_value(
        value: serde_json::Value,
        path_hint: &Path,
    ) -> Result<CloudConfig, CloudError> {
        // Handle array of objects (e.g. `az role assignment list` or list of security groups)
        if let Some(arr) = value.as_array() {
            let mut resources = Vec::new();
            let mut policies = Vec::new();
            let mut provider = CloudProvider::Generic;

            for item in arr {
                if let Ok(sub_cfg) = Self::normalize_value(item.clone(), path_hint) {
                    if provider == CloudProvider::Generic
                        && sub_cfg.detected_provider != CloudProvider::Generic
                    {
                        provider = sub_cfg.detected_provider;
                    }
                    resources.extend(sub_cfg.resources);
                    policies.extend(sub_cfg.policies);
                }
            }

            return Ok(CloudConfig {
                detected_provider: provider,
                resources,
                policies,
            });
        }

        let obj = value.as_object().ok_or_else(|| {
            CloudError::UnrecognizedProvider(
                "Top-level document must be a JSON object or array".to_string(),
            )
        })?;

        // 1. AWS IAM Policy (Contains "Statement" array or object)
        if obj.contains_key("Statement") {
            let statements: Vec<Statement> =
                if let Some(arr) = obj.get("Statement").and_then(|s| s.as_array()) {
                    serde_json::from_value(serde_json::Value::Array(arr.clone()))?
                } else if let Some(single) = obj.get("Statement") {
                    vec![serde_json::from_value(single.clone())?]
                } else {
                    Vec::new()
                };

            let policy = IamPolicy {
                provider: CloudProvider::Aws,
                policy_id: obj
                    .get("Id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                policy_name: path_hint
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string()),
                statements,
                attached_roles: Vec::new(),
                raw_json: Some(value.clone()),
            };

            return Ok(CloudConfig {
                detected_provider: CloudProvider::Aws,
                resources: Vec::new(),
                policies: vec![policy],
            });
        }

        // 2. AWS Security Group (Contains "IpPermissions" or "SecurityGroups")
        if obj.contains_key("IpPermissions") || obj.contains_key("SecurityGroups") {
            let rules = Self::extract_aws_sg_rules(obj);
            let resource = CloudResource {
                provider: CloudProvider::Aws,
                resource_type: CloudResourceType::SecurityGroup,
                id: obj
                    .get("GroupId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("sg-default")
                    .to_string(),
                name: obj
                    .get("GroupName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("security-group")
                    .to_string(),
                tags: HashMap::new(),
                server_side_encryption: None,
                security_rules: rules,
                associated_policies: Vec::new(),
                raw_properties: value.clone(),
            };

            return Ok(CloudConfig {
                detected_provider: CloudProvider::Aws,
                resources: vec![resource],
                policies: Vec::new(),
            });
        }

        // 3. GCP IAM Policy (Contains "bindings" array with "role" and "members")
        if obj.contains_key("bindings") {
            let resource = CloudResource {
                provider: CloudProvider::Gcp,
                resource_type: CloudResourceType::IcpBinding,
                id: path_hint
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "gcp-iam".to_string()),
                name: "GCP Project IAM Policy".to_string(),
                tags: HashMap::new(),
                server_side_encryption: None,
                security_rules: Vec::new(),
                associated_policies: Vec::new(),
                raw_properties: value.clone(),
            };

            return Ok(CloudConfig {
                detected_provider: CloudProvider::Gcp,
                resources: vec![resource],
                policies: Vec::new(),
            });
        }

        // 4. Azure RBAC Role Assignment (Contains "roleDefinitionName" or "roleDefinitionId" and "principalId")
        if obj.contains_key("roleDefinitionName")
            || (obj.contains_key("roleDefinitionId") && obj.contains_key("principalId"))
        {
            let role_name = obj
                .get("roleDefinitionName")
                .and_then(|v| v.as_str())
                .unwrap_or("Owner");
            let resource = CloudResource {
                provider: CloudProvider::Azure,
                resource_type: CloudResourceType::AzureRoleAssignment,
                id: obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("azure-rbac")
                    .to_string(),
                name: role_name.to_string(),
                tags: HashMap::new(),
                server_side_encryption: None,
                security_rules: Vec::new(),
                associated_policies: Vec::new(),
                raw_properties: value.clone(),
            };

            return Ok(CloudConfig {
                detected_provider: CloudProvider::Azure,
                resources: vec![resource],
                policies: Vec::new(),
            });
        }

        // 5. Azure NSG (Contains "securityRules" or "defaultSecurityRules")
        if obj.contains_key("securityRules")
            || obj.contains_key("defaultSecurityRules")
            || (obj.contains_key("properties") && obj["properties"].get("securityRules").is_some())
        {
            let rules = Self::extract_azure_nsg_rules(obj);
            let resource = CloudResource {
                provider: CloudProvider::Azure,
                resource_type: CloudResourceType::NetworkSecurityGroup,
                id: obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("nsg-default")
                    .to_string(),
                name: obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("azure-nsg")
                    .to_string(),
                tags: HashMap::new(),
                server_side_encryption: None,
                security_rules: rules,
                associated_policies: Vec::new(),
                raw_properties: value.clone(),
            };

            return Ok(CloudConfig {
                detected_provider: CloudProvider::Azure,
                resources: vec![resource],
                policies: Vec::new(),
            });
        }

        // 6. Cloud Storage Bucket Configuration (S3 / GCS / Azure Blob)
        if obj.contains_key("BucketName")
            || obj.contains_key("bucket_policy")
            || obj.contains_key("ServerSideEncryptionConfiguration")
        {
            let has_sse = obj.contains_key("ServerSideEncryptionConfiguration");
            let mut policies = Vec::new();

            if let Some(policy_val) = obj.get("bucket_policy") {
                if let Ok(statements) =
                    serde_json::from_value::<Vec<Statement>>(policy_val["Statement"].clone())
                {
                    policies.push(IamPolicy {
                        provider: CloudProvider::Aws,
                        policy_id: None,
                        policy_name: Some("BucketPolicy".to_string()),
                        statements,
                        attached_roles: Vec::new(),
                        raw_json: Some(policy_val.clone()),
                    });
                }
            }

            let bucket_name = obj
                .get("BucketName")
                .and_then(|v| v.as_str())
                .unwrap_or("storage-bucket");
            let resource = CloudResource {
                provider: CloudProvider::Aws,
                resource_type: CloudResourceType::StorageBucket,
                id: bucket_name.to_string(),
                name: bucket_name.to_string(),
                tags: HashMap::new(),
                server_side_encryption: Some(ServerSideEncryption {
                    enabled: has_sse,
                    algorithm: None,
                    kms_key_id: None,
                }),
                security_rules: Vec::new(),
                associated_policies: policies.clone(),
                raw_properties: value.clone(),
            };

            return Ok(CloudConfig {
                detected_provider: CloudProvider::Aws,
                resources: vec![resource],
                policies,
            });
        }

        // 7. Credential Summary / Account Report (AWS Account Summary or Root Credential Report)
        if obj.contains_key("AccountMFAEnabled") || obj.contains_key("AccountAccessKeysPresent") {
            let resource = CloudResource {
                provider: CloudProvider::Aws,
                resource_type: CloudResourceType::Generic,
                id: "aws-account-summary".to_string(),
                name: "AWS Account Credential Summary".to_string(),
                tags: HashMap::new(),
                server_side_encryption: None,
                security_rules: Vec::new(),
                associated_policies: Vec::new(),
                raw_properties: value.clone(),
            };

            return Ok(CloudConfig {
                detected_provider: CloudProvider::Aws,
                resources: vec![resource],
                policies: Vec::new(),
            });
        }

        Err(CloudError::UnrecognizedProvider(
            path_hint.display().to_string(),
        ))
    }

    fn extract_aws_sg_rules(
        obj: &serde_json::Map<String, serde_json::Value>,
    ) -> Vec<SecurityGroupRule> {
        let mut rules = Vec::new();
        if let Some(perms) = obj.get("IpPermissions").and_then(|v| v.as_array()) {
            for perm in perms {
                let from_port = perm
                    .get("FromPort")
                    .and_then(|v| v.as_i64())
                    .map(|p| p as i32);
                let to_port = perm
                    .get("ToPort")
                    .and_then(|v| v.as_i64())
                    .map(|p| p as i32);
                let protocol = perm
                    .get("IpProtocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tcp")
                    .to_string();

                let mut cidr_blocks = Vec::new();
                if let Some(ranges) = perm.get("IpRanges").and_then(|v| v.as_array()) {
                    for r in ranges {
                        if let Some(cidr) = r.get("CidrIp").and_then(|v| v.as_str()) {
                            cidr_blocks.push(cidr.to_string());
                        }
                    }
                }

                let mut ipv6_cidr_blocks = Vec::new();
                if let Some(ranges) = perm.get("Ipv6Ranges").and_then(|v| v.as_array()) {
                    for r in ranges {
                        if let Some(cidr) = r.get("CidrIpv6").and_then(|v| v.as_str()) {
                            ipv6_cidr_blocks.push(cidr.to_string());
                        }
                    }
                }

                rules.push(SecurityGroupRule {
                    rule_id: None,
                    direction: RuleDirection::Inbound,
                    action: RuleAction::Allow,
                    protocol,
                    from_port,
                    to_port,
                    cidr_blocks,
                    ipv6_cidr_blocks,
                    description: None,
                });
            }
        }
        rules
    }

    fn extract_azure_nsg_rules(
        obj: &serde_json::Map<String, serde_json::Value>,
    ) -> Vec<SecurityGroupRule> {
        let mut rules = Vec::new();
        let raw_rules = obj
            .get("securityRules")
            .or_else(|| obj.get("defaultSecurityRules"))
            .or_else(|| obj.get("properties").and_then(|p| p.get("securityRules")))
            .and_then(|v| v.as_array());

        if let Some(rule_arr) = raw_rules {
            for r in rule_arr {
                let props = r.get("properties").unwrap_or(r);
                let access = props
                    .get("access")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Allow");
                let direction = props
                    .get("direction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Inbound");
                let protocol = props
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string();

                // Check both singular and plural port fields
                let mut port_ranges = Vec::new();
                if let Some(singular) = props.get("destinationPortRange").and_then(|v| v.as_str()) {
                    port_ranges.push(singular.to_string());
                }
                if let Some(plural) = props
                    .get("destinationPortRanges")
                    .and_then(|v| v.as_array())
                {
                    for p in plural {
                        if let Some(ps) = p.as_str() {
                            port_ranges.push(ps.to_string());
                        }
                    }
                }
                if port_ranges.is_empty() {
                    port_ranges.push("*".to_string());
                }

                // Check both singular and plural source prefix fields
                let mut cidr_blocks = Vec::new();
                if let Some(source) = props.get("sourceAddressPrefix").and_then(|v| v.as_str()) {
                    cidr_blocks.push(source.to_string());
                }
                if let Some(sources) = props
                    .get("sourceAddressPrefixes")
                    .and_then(|v| v.as_array())
                {
                    for s in sources {
                        if let Some(ss) = s.as_str() {
                            cidr_blocks.push(ss.to_string());
                        }
                    }
                }

                for port_str in port_ranges {
                    let (from_port, to_port) = Self::parse_port_range(&port_str);
                    rules.push(SecurityGroupRule {
                        rule_id: r
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        direction: if direction.eq_ignore_ascii_case("Inbound") {
                            RuleDirection::Inbound
                        } else {
                            RuleDirection::Outbound
                        },
                        action: if access.eq_ignore_ascii_case("Allow") {
                            RuleAction::Allow
                        } else {
                            RuleAction::Deny
                        },
                        protocol: protocol.clone(),
                        from_port,
                        to_port,
                        cidr_blocks: cidr_blocks.clone(),
                        ipv6_cidr_blocks: Vec::new(),
                        description: None,
                    });
                }
            }
        }
        rules
    }

    /// Parses numeric port string, port range (e.g. "20-25"), or wildcard ("*", "-1").
    pub fn parse_port_range(port_str: &str) -> (Option<i32>, Option<i32>) {
        let trimmed = port_str.trim();
        if trimmed == "*" || trimmed == "-1" {
            (Some(1), Some(65535))
        } else if let Some((start, end)) = trimmed.split_once('-') {
            (
                start.trim().parse::<i32>().ok(),
                end.trim().parse::<i32>().ok(),
            )
        } else if let Ok(port) = trimmed.parse::<i32>() {
            if port == -1 {
                (Some(1), Some(65535))
            } else {
                (Some(port), Some(port))
            }
        } else {
            (None, None)
        }
    }
}
