//! Canonical MCP tool schemas for Aegix security intelligence and remediation.

#![deny(unsafe_code)]

use crate::protocol::Tool;
use serde_json::json;

/// Returns the comprehensive list of tools exposed by the Aegix MCP server.
pub fn get_tool_catalog() -> Vec<Tool> {
    vec![
        Tool {
            name: "aegix_scan".to_string(),
            description: Some(
                "Performs comprehensive multi-engine vulnerability scanning across source code (SAST), leaked secrets, SCA dependencies, IaC, CI/CD pipelines, and container definitions.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target directory or file path to scan (defaults to current directory '.')"
                    },
                    "baseline": {
                        "type": "string",
                        "description": "Optional path to a baseline snapshot file (.json) to suppress known findings"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_sast".to_string(),
            description: Some(
                "Static Application Security Testing (SAST) for source code vulnerabilities (SQL injection, command injection, path traversal, SSRF, XSS, insecure deserialization).".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target directory or source code file to analyze"
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Minimum severity threshold (e.g. error, warning, note)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_secrets".to_string(),
            description: Some(
                "High-precision scanner detecting leaked API tokens (AWS, GitHub, OpenAI, Stripe, Slack), private keys, and high-entropy credentials with automatic masking.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target directory or file to inspect for leaked secrets"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_sca".to_string(),
            description: Some(
                "Software Composition Analysis (SCA) detecting known vulnerable dependencies and CVEs in lockfiles (Cargo.lock, package-lock.json).".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target project directory or lockfile path"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_iac".to_string(),
            description: Some(
                "Audits Infrastructure as Code (Kubernetes YAML/JSON, Helm templates, Terraform definitions) against CIS benchmarks and NSA/CISA hardening guidelines.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target directory or manifest file (.yaml, .json, .tf)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_pipeline".to_string(),
            description: Some(
                "Audits CI/CD pipeline workflows (GitHub Actions, GitLab CI) and SLSA provenance attestations against OWASP Top 10 CI/CD security risks.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target directory (.github/workflows) or pipeline definition file"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_mobile".to_string(),
            description: Some(
                "Audits mobile application packages and manifests (Android AndroidManifest.xml, APK, iOS Info.plist, IPA) for security misconfigurations and dangerous permissions.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target directory, manifest file, or APK/IPA archive"
                    },
                    "release": {
                        "type": "boolean",
                        "description": "Whether to enforce strict release build security checks (default: false)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_threat".to_string(),
            description: Some(
                "Automated threat modeling, STRIDE classification, and MITRE ATT&CK Matrix mapping from project findings or SARIF reports.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target project directory or SARIF report file to evaluate"
                    },
                    "domain": {
                        "type": "string",
                        "description": "MITRE ATT&CK Matrix domain (enterprise, cloud, mobile, container; default: enterprise)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of findings to return in output (default: 50)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_explain".to_string(),
            description: Some(
                "Provides in-depth technical explanation, vulnerability impact analysis, CWE references, and syntax-preserving remediation guidance for an Aegix rule ID.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Aegix rule identifier (e.g. CG-SQLI-001, CG-SEC-AWS-001, IAC-K8S-001, PIPELINE-GHA-001, MOB-ANDR-001, CG-DOCKER-001)"
                    }
                },
                "required": ["rule_id"]
            }),
        },
    ]
}
