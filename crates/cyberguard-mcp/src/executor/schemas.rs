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
            name: "aegix_graph".to_string(),
            description: Some(
                "Multi-layer Attack Path Engine synthesizing findings across entrypoints, vulnerabilities, secrets, and cloud assets into exploit chains and remediation choke points.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target project directory or SARIF report file to construct the attack graph"
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum traversal depth (hop count) for path discovery (default: 10)"
                    },
                    "min_risk": {
                        "type": "number",
                        "description": "Minimum path risk score threshold to report (default: 0.0)"
                    },
                    "format": {
                        "type": "string",
                        "description": "Output representation: 'markdown', 'mermaid', 'json', or 'sarif' (default: 'markdown')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of exploit paths to return (default: 10)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_risk".to_string(),
            description: Some(
                "Tri-Factor Prioritizer (CVSS x EPSS x Reachability) computing static Rust call-graph reachability from Cargo workspaces and prioritizing multi-engine SARIF telemetry.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target Cargo workspace/project directory or SARIF report file"
                    },
                    "min_score": {
                        "type": "number",
                        "description": "Minimum Tri-Factor score threshold to return (0.0 to 10.0, default: 0.0)"
                    },
                    "show_suppressed": {
                        "type": "boolean",
                        "description": "Include unreachable/suppressed findings in output (default: false)"
                    },
                    "no_cargo_metadata": {
                        "type": "boolean",
                        "description": "Skip spawning `cargo metadata` and use pure-Rust Cargo.toml/Cargo.lock fallback (default: false)"
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format: 'markdown' or 'json' (default: 'markdown')"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of prioritized findings to return (default: 50)"
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
        Tool {
            name: "aegix_fix".to_string(),
            description: Some(
                "Deterministic AST & Autonomous Remediation: synthesizes surgical patches, POSIX unified diffs, and eradication unit tests for SQLi, Command Injection, Path Traversal, and Leaked Secrets across Python, JS/TS, Go, and Rust.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target project directory or source code file to remediate (defaults to current directory '.')"
                    },
                    "sarif_path": {
                        "type": "string",
                        "description": "Optional path to a SARIF report file containing findings to remediate"
                    },
                    "auto_apply": {
                        "type": "boolean",
                        "description": "Whether to atomically apply surgical patches to source files on disk (default: false, dry-run only)"
                    },
                    "rules": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional list of rule IDs to filter remediation (e.g. ['CG-SQLI-001', 'CG-CMDI-001'])"
                    },
                    "generate_tests": {
                        "type": "boolean",
                        "description": "Whether to generate autonomous eradication regression unit tests (default: true)"
                    }
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "aegix_report".to_string(),
            description: Some(
                "Executive Security Reporting & Metrics Aggregation: computes overall Security Posture Score (0-100), severity breakdowns, compliance scorecards (OWASP, CIS, MITRE ATT&CK), and renders executive HTML/print or JSON reports.".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Target project directory or SARIF file to evaluate (defaults to current directory '.')"
                    },
                    "sarif_path": {
                        "type": "string",
                        "description": "Optional path to a SARIF report file containing findings to aggregate"
                    },
                    "format": {
                        "type": "string",
                        "description": "Output representation: 'summary', 'html', or 'json' (default: 'summary')"
                    }
                },
                "required": ["path"]
            }),
        },
    ]
}
