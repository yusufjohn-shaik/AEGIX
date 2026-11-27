//! MCP Resources Catalog providing read-only contextual references.

#![deny(unsafe_code)]

use crate::error::McpError;
use crate::protocol::{ReadResourceResult, Resource, ResourceContents};
use crate::traits::ResourceProvider;
use async_trait::async_trait;
use cyberguard_threat::catalog::StaticThreatCatalog;
use cyberguard_threat::models::MitreTactic;
use cyberguard_threat::traits::AttackMapper;
use serde_json::json;

pub const URI_RULES: &str = "aegix://rules";
pub const URI_ATTACK_MATRIX: &str = "aegix://attack-matrix";
pub const URI_SYSTEM_STATUS: &str = "aegix://system-status";

/// Aegix contextual resource provider.
#[derive(Clone, Default)]
pub struct AegixResourceCatalog;

impl AegixResourceCatalog {
    pub fn new() -> Self {
        Self
    }

    fn generate_rules_resource() -> String {
        let rules = json!({
            "version": "1.0.0",
            "engines": [
                {
                    "name": "SAST",
                    "rules": [
                        { "id": "CG-SQLI-001", "name": "SQL Injection", "severity": "Error", "cwe": "CWE-89" },
                        { "id": "CG-CMDI-001", "name": "Command Injection", "severity": "Error", "cwe": "CWE-78" },
                        { "id": "CG-SECR-001", "name": "Hardcoded Secret", "severity": "Error", "cwe": "CWE-798" },
                        { "id": "CG-PATH-001", "name": "Path Traversal", "severity": "Warning", "cwe": "CWE-22" },
                        { "id": "CG-SSRF-001", "name": "SSRF", "severity": "Error", "cwe": "CWE-918" },
                        { "id": "CG-XSS-001", "name": "Cross-Site Scripting", "severity": "Error", "cwe": "CWE-79" }
                    ]
                },
                {
                    "name": "Secrets",
                    "rules": [
                        { "id": "CG-SEC-AWS-001", "name": "AWS Access Key", "severity": "Error", "provider": "AWS" },
                        { "id": "CG-SEC-GITHUB-001", "name": "GitHub PAT", "severity": "Error", "provider": "GitHub" },
                        { "id": "CG-SEC-OPENAI-001", "name": "OpenAI API Key", "severity": "Error", "provider": "OpenAI" },
                        { "id": "CG-SEC-STRIPE-001", "name": "Stripe Live Key", "severity": "Error", "provider": "Stripe" }
                    ]
                },
                {
                    "name": "IaC",
                    "rules": [
                        { "id": "IAC-K8S-001", "name": "Privileged Container Escalation", "severity": "Error", "benchmark": "CIS K8s 5.2.1" },
                        { "id": "IAC-K8S-002", "name": "Missing Resource Limits", "severity": "Warning", "benchmark": "CIS K8s 5.7.1" },
                        { "id": "IAC-TF-001", "name": "Public S3 Bucket", "severity": "Error", "benchmark": "CIS AWS 2.1.5" }
                    ]
                },
                {
                    "name": "Pipeline",
                    "rules": [
                        { "id": "PIPELINE-GHA-001", "name": "Untrusted Script Injection", "severity": "Error", "standard": "OWASP CI/CD SEC-1" },
                        { "id": "PIPELINE-GHA-002", "name": "Overly Permissive Token", "severity": "Error", "standard": "OWASP CI/CD SEC-2" }
                    ]
                },
                {
                    "name": "Mobile",
                    "rules": [
                        { "id": "MOB-ANDR-001", "name": "Cleartext HTTP Traffic", "severity": "Error", "standard": "OWASP Mobile M3" },
                        { "id": "MOB-ANDR-002", "name": "Debuggable In Production", "severity": "Error", "standard": "OWASP Mobile M1" }
                    ]
                },
                {
                    "name": "Container",
                    "rules": [
                        { "id": "CG-DOCKER-001", "name": "Container Runs As Root", "severity": "Warning", "benchmark": "CIS Docker 4.1" },
                        { "id": "CG-DOCKER-002", "name": "Unpinned Image Tag", "severity": "Warning", "benchmark": "CIS Docker 4.2" }
                    ]
                }
            ]
        });
        serde_json::to_string_pretty(&rules).unwrap_or_default()
    }

    fn generate_attack_matrix_resource() -> String {
        let all_tactics = [
            MitreTactic::Reconnaissance,
            MitreTactic::ResourceDevelopment,
            MitreTactic::InitialAccess,
            MitreTactic::Execution,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
            MitreTactic::DefenseEvasion,
            MitreTactic::CredentialAccess,
            MitreTactic::Discovery,
            MitreTactic::LateralMovement,
            MitreTactic::Collection,
            MitreTactic::CommandAndControl,
            MitreTactic::Exfiltration,
            MitreTactic::Impact,
        ];

        let tactics: Vec<serde_json::Value> = all_tactics
            .iter()
            .map(|t| {
                json!({
                    "id": t.id(),
                    "name": t.title(),
                    "slug": t.slug(),
                })
            })
            .collect();

        let catalog = StaticThreatCatalog::new();
        let techniques: Vec<serde_json::Value> = catalog
            .all_techniques()
            .iter()
            .map(|tech| {
                json!({
                    "id": tech.id,
                    "name": tech.name,
                    "tactics": tech.tactics.iter().map(|tac| tac.slug()).collect::<Vec<_>>(),
                    "description": tech.description,
                    "url": tech.url,
                })
            })
            .collect();

        let matrix = json!({
            "version": "1.0.0",
            "framework": "MITRE ATT&CK Enterprise Matrix v14.1 & STRIDE Taxonomy",
            "tacticsCount": tactics.len(),
            "techniquesCount": techniques.len(),
            "tactics": tactics,
            "techniques": techniques,
        });

        serde_json::to_string_pretty(&matrix).unwrap_or_default()
    }

    fn generate_system_status_resource() -> String {
        let status = json!({
            "product": "Aegix Autonomous Security Platform",
            "version": env!("CARGO_PKG_VERSION"),
            "mcpProtocolVersion": crate::protocol::MCP_PROTOCOL_VERSION,
            "architecture": std::env::consts::ARCH,
            "os": std::env::consts::OS,
            "airGappedOffline": true,
            "runtimeNetworkCalls": 0,
            "activeEngines": [
                "cyberguard-sast",
                "cyberguard-secret",
                "cyberguard-sca",
                "cyberguard-iac",
                "cyberguard-pipeline",
                "cyberguard-mobile",
                "cyberguard-container",
                "cyberguard-threat",
                "cyberguard-graph",
                "cyberguard-risk",
                "cyberguard-fix",
                "cyberguard-ui",
                "cyberguard-core"
            ]
        });
        serde_json::to_string_pretty(&status).unwrap_or_default()
    }
}

#[async_trait]
impl ResourceProvider for AegixResourceCatalog {
    fn list_resources(&self) -> Vec<Resource> {
        vec![
            Resource {
                uri: URI_RULES.to_string(),
                name: "Aegix Security Rules Catalog".to_string(),
                description: Some(
                    "Complete index of Aegix detection signatures across SAST, Secrets, IaC, CI/CD, Container, and Mobile with severity and CWE mappings.".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: URI_ATTACK_MATRIX.to_string(),
                name: "MITRE ATT&CK Enterprise Matrix & STRIDE Taxonomy".to_string(),
                description: Some(
                    "Static reference taxonomy of MITRE ATT&CK tactics, techniques, platforms, and STRIDE security property mappings.".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: URI_SYSTEM_STATUS.to_string(),
                name: "Aegix MCP Server & Scanner Status".to_string(),
                description: Some(
                    "Server version, platform environment, air-gapped offline status, and active security engine capabilities.".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
        ]
    }

    async fn read_resource(&self, uri: &str) -> Result<ReadResourceResult, McpError> {
        let text = match uri {
            URI_RULES => Self::generate_rules_resource(),
            URI_ATTACK_MATRIX => Self::generate_attack_matrix_resource(),
            URI_SYSTEM_STATUS => Self::generate_system_status_resource(),
            unknown => return Err(McpError::ResourceNotFound(unknown.to_string())),
        };

        Ok(ReadResourceResult {
            contents: vec![ResourceContents {
                uri: uri.to_string(),
                mime_type: Some("application/json".to_string()),
                text,
            }],
        })
    }
}
