//! MCP Prompt Templates Catalog guiding AI agents through security audits, code fixing, and threat modeling.

#![deny(unsafe_code)]

use crate::error::McpError;
use crate::protocol::{GetPromptResult, Prompt, PromptArgument, PromptMessage, ToolContent};
use crate::traits::PromptProvider;
use async_trait::async_trait;
use std::collections::HashMap;

pub const PROMPT_SECURITY_AUDIT: &str = "security_audit";
pub const PROMPT_FIX_VULNERABILITY: &str = "fix_vulnerability";
pub const PROMPT_THREAT_MODEL_REVIEW: &str = "threat_model_review";

/// Aegix structured prompt template provider.
#[derive(Clone, Default)]
pub struct AegixPromptCatalog;

impl AegixPromptCatalog {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PromptProvider for AegixPromptCatalog {
    fn list_prompts(&self) -> Vec<Prompt> {
        vec![
            Prompt {
                name: PROMPT_SECURITY_AUDIT.to_string(),
                description: Some(
                    "Instructs the AI agent to conduct a comprehensive security assessment across code, secrets, dependencies, IaC, and CI/CD pipelines, prioritizing findings by risk.".to_string(),
                ),
                arguments: Some(vec![
                    PromptArgument {
                        name: "path".to_string(),
                        description: Some("Target repository or directory path to audit (defaults to '.')".to_string()),
                        required: Some(false),
                    },
                    PromptArgument {
                        name: "focus".to_string(),
                        description: Some("Optional focus area (e.g. 'all', 'sast', 'secrets', 'iac', 'pipeline', 'mobile')".to_string()),
                        required: Some(false),
                    },
                ]),
            },
            Prompt {
                name: PROMPT_FIX_VULNERABILITY.to_string(),
                description: Some(
                    "Directs the AI agent to analyze a specific Aegix security alert and synthesize an AST-preserving, surgical code fix.".to_string(),
                ),
                arguments: Some(vec![
                    PromptArgument {
                        name: "rule_id".to_string(),
                        description: Some("Aegix rule ID (e.g. CG-SQLI-001, CG-SEC-AWS-001, IAC-K8S-001)".to_string()),
                        required: Some(true),
                    },
                    PromptArgument {
                        name: "file_path".to_string(),
                        description: Some("Path to the source file containing the finding".to_string()),
                        required: Some(true),
                    },
                    PromptArgument {
                        name: "line_number".to_string(),
                        description: Some("Line number of the identified vulnerability".to_string()),
                        required: Some(false),
                    },
                ]),
            },
            Prompt {
                name: PROMPT_THREAT_MODEL_REVIEW.to_string(),
                description: Some(
                    "Guides the AI agent through an architectural threat modeling review based on STRIDE categories and MITRE ATT&CK Enterprise Matrix mapping.".to_string(),
                ),
                arguments: Some(vec![
                    PromptArgument {
                        name: "path".to_string(),
                        description: Some("Target project directory or SARIF report path (defaults to '.')".to_string()),
                        required: Some(false),
                    },
                    PromptArgument {
                        name: "domain".to_string(),
                        description: Some("MITRE ATT&CK domain (enterprise, cloud, mobile, container)".to_string()),
                        required: Some(false),
                    },
                ]),
            },
        ]
    }

    async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<HashMap<String, String>>,
    ) -> Result<GetPromptResult, McpError> {
        let args = arguments.unwrap_or_default();

        match name {
            PROMPT_SECURITY_AUDIT => {
                let path = args.get("path").map(|s| s.as_str()).unwrap_or(".");
                let focus = args.get("focus").map(|s| s.as_str()).unwrap_or("all");

                let tool_call = if focus == "all" {
                    format!("`aegix_scan(path: \"{}\")`", path)
                } else {
                    format!("`aegix_{}(path: \"{}\")`", focus, path)
                };

                let prompt_text = format!(
                    "Please perform a complete security audit on target '{}' with focus on '{}'.\n\n\
                    1. Execute the Aegix MCP tool: {}\n\
                    2. Categorize all discovered findings by severity (Critical, High, Medium, Low).\n\
                    3. For any unfamiliar or complex rule IDs, call `aegix_explain(rule_id: ...)` to inspect the vulnerability mechanism.\n\
                    4. Synthesize a prioritized remediation action plan with secure code examples.",
                    path, focus, tool_call
                );

                Ok(GetPromptResult {
                    description: Some("Comprehensive repository security audit".to_string()),
                    messages: vec![PromptMessage {
                        role: "user".to_string(),
                        content: ToolContent::Text { text: prompt_text },
                    }],
                })
            }
            PROMPT_FIX_VULNERABILITY => {
                let rule_id = args.get("rule_id").ok_or_else(|| {
                    McpError::InvalidParams("Missing required argument 'rule_id'".to_string())
                })?;
                let file_path = args.get("file_path").ok_or_else(|| {
                    McpError::InvalidParams("Missing required argument 'file_path'".to_string())
                })?;
                let line_str = args
                    .get("line_number")
                    .map(|l| format!(" around line {}", l))
                    .unwrap_or_default();

                let prompt_text = format!(
                    "Please inspect and resolve the security flaw '{}' identified in `{}`{}.\n\n\
                    1. Query `aegix_explain(rule_id: \"{}\")` for rule details, CWE classification, and recommended secure patterns.\n\
                    2. Read the source file at `{}`.\n\
                    3. Formulate a syntax-preserving, minimal code patch that resolves the issue without altering external behavior.\n\
                    4. Present the before/after diff and explain how the patch mitigates the exploit vector.",
                    rule_id, file_path, line_str, rule_id, file_path
                );

                Ok(GetPromptResult {
                    description: Some("Autonomous vulnerability code patch synthesis".to_string()),
                    messages: vec![PromptMessage {
                        role: "user".to_string(),
                        content: ToolContent::Text { text: prompt_text },
                    }],
                })
            }
            PROMPT_THREAT_MODEL_REVIEW => {
                let path = args.get("path").map(|s| s.as_str()).unwrap_or(".");
                let domain = args
                    .get("domain")
                    .map(|s| s.as_str())
                    .unwrap_or("enterprise");

                let prompt_text = format!(
                    "Please perform an architectural threat model evaluation for target '{}' under the MITRE ATT&CK '{}' domain.\n\n\
                    1. Execute `aegix_threat(path: \"{}\", domain: \"{}\")` to compute the ATT&CK Matrix and STRIDE profile.\n\
                    2. Review the STRIDE categorization (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).\n\
                    3. Highlight active attack techniques and mapped CVE/CWE relationships.\n\
                    4. Formulate architectural defense-in-depth mitigations for the highest-scoring threats.",
                    path, domain, path, domain
                );

                Ok(GetPromptResult {
                    description: Some(
                        "Architectural STRIDE & MITRE ATT&CK threat evaluation".to_string(),
                    ),
                    messages: vec![PromptMessage {
                        role: "user".to_string(),
                        content: ToolContent::Text { text: prompt_text },
                    }],
                })
            }
            unknown => Err(McpError::PromptNotFound(unknown.to_string())),
        }
    }
}
