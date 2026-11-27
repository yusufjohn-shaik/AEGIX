//! In-process facade bridging Aegix security scanning engines to MCP tools.

#![deny(unsafe_code)]

use crate::error::McpError;
use crate::executor::schemas::get_tool_catalog;
use crate::protocol::{CallToolResult, Tool};
use crate::traits::ToolExecutor;
use async_trait::async_trait;
use cyberguard_container::{ContainerAuditReport, ContainerEngine, ContainerScanner};
use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use cyberguard_fix::{FixEngine, FixScanOptions, RemediationEngine};
use cyberguard_graph::{
    AttackGraph, ChokePointAnalyzer, GraphCorrelator, GraphExporter, JsonExporter, MermaidExporter,
    PathFinder, SarifExporter, StandardChokePointAnalyzer, StandardGraphCorrelator,
    StandardPathFinder, StandardTelemetryIngester, TelemetryIngester, TerminalExporter,
};
use cyberguard_iac::traits::IacScanner;
use cyberguard_iac::IacEngine;
use cyberguard_mobile::traits::MobileScanner;
use cyberguard_mobile::MobileEngine;
use cyberguard_pipeline::traits::PipelineScanner;
use cyberguard_pipeline::PipelineEngine;
use cyberguard_risk::{
    JsonExporter as RiskJsonExporter, RiskEngine, RiskExporter, RiskPrioritizer, RiskScanOptions,
    TerminalExporter as RiskTerminalExporter,
};
use cyberguard_sast::{NativeRuleEngine, SastAnalyzer, ScanContext};
use cyberguard_sca::{ScaAnalyzer, ScaEngine};
use cyberguard_secret::{SecretEngine, SecretScanner};
use cyberguard_threat::traits::ThreatScanner;
use cyberguard_threat::{MitreMatrixDomain, ThreatEngine, ThreatReportFormatter};
use cyberguard_ui::{
    DashboardRenderer, DefaultHtmlReportGenerator, DefaultMetricsAggregator,
    DefaultTerminalDashboard, ReportAggregator, ReportGenerator,
};
use std::path::{Path, PathBuf};

/// Default finding limit to protect LLM context windows.
pub const DEFAULT_FINDINGS_LIMIT: usize = 50;

/// Aegix in-process multi-engine facade executing MCP tool calls.
#[derive(Clone, Default)]
pub struct AegixEngineFacade;

impl AegixEngineFacade {
    pub fn new() -> Self {
        Self
    }

    /// Extract an optional integer limit argument, defaulting to `DEFAULT_FINDINGS_LIMIT`.
    fn extract_limit(args: &Option<serde_json::Map<String, serde_json::Value>>) -> usize {
        args.as_ref()
            .and_then(|m| m.get("limit"))
            .and_then(|v| v.as_u64())
            .map(|u| u as usize)
            .unwrap_or(DEFAULT_FINDINGS_LIMIT)
    }

    /// Extract a required string path argument.
    fn extract_path(
        args: &Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<PathBuf, CallToolResult> {
        let path_str = args
            .as_ref()
            .and_then(|m| m.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or(".");

        let path = PathBuf::from(path_str);
        if !path.exists() {
            return Err(CallToolResult::failure(format!(
                "Target path '{}' does not exist on local filesystem.",
                path_str
            )));
        }
        Ok(path)
    }

    /// Format a collection of SarifResults into structured Markdown telemetry.
    fn format_sarif_results(results: &[SarifResult], target_path: &str, limit: usize) -> String {
        let total = results.len();
        if total == 0 {
            return format!(
                "✅ **No security vulnerabilities detected** in target: `{}`\n",
                target_path
            );
        }

        let errors = results
            .iter()
            .filter(|r| r.level == SarifLevel::Error)
            .count();
        let warnings = results
            .iter()
            .filter(|r| r.level == SarifLevel::Warning)
            .count();
        let notes = results
            .iter()
            .filter(|r| r.level == SarifLevel::Note || r.level == SarifLevel::None)
            .count();

        let mut out = String::new();
        out.push_str(&format!("### 🛡️ Aegix Scan Report: `{}`\n\n", target_path));
        out.push_str(&format!(
            "**Total Findings:** {} (🔴 Errors: {}, 🟡 Warnings: {}, 🔵 Notes/Info: {})\n\n",
            total, errors, warnings, notes
        ));
        out.push_str("| # | Severity | Rule ID | Location | Message |\n");
        out.push_str("|---|----------|---------|----------|---------|\n");

        let slice = if results.len() > limit {
            &results[..limit]
        } else {
            results
        };

        for (idx, res) in slice.iter().enumerate() {
            let sev_tag = match res.level {
                SarifLevel::Error => "🔴 Error",
                SarifLevel::Warning => "🟡 Warning",
                SarifLevel::Note => "🔵 Note",
                SarifLevel::None => "⚪ Info",
            };

            let loc_str = res
                .locations
                .first()
                .and_then(|l| {
                    l.physical_location.as_ref().map(|p| {
                        if let Some(r) = &p.region {
                            format!("{}:{}", p.artifact_location.uri, r.start_line)
                        } else {
                            p.artifact_location.uri.clone()
                        }
                    })
                })
                .unwrap_or_else(|| "-".to_string());

            let clean_msg = res.message.text.replace('|', "\\|").replace('\n', " ");
            out.push_str(&format!(
                "| {} | {} | `{}` | `{}` | {} |\n",
                idx + 1,
                sev_tag,
                res.rule_id,
                loc_str,
                clean_msg
            ));
        }

        if total > limit {
            out.push_str(&format!(
                "\n*⚠️ Notice: Displaying first {} of {} findings to protect context window. Specify `\"limit\": {}` to view all.*",
                limit, total, total
            ));
        }

        out
    }

    /// Execute multi-engine scan across SAST, Secrets, SCA, IaC, Pipeline, Container.
    async fn run_aegix_scan(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let limit = Self::extract_limit(&args);
        let path_str = path.to_string_lossy().to_string();

        let mut all_findings = Vec::new();

        // 1. SAST
        let sast_engine = NativeRuleEngine::default();
        let ctx = ScanContext::new(&path);
        if let Ok(findings) = sast_engine.analyze(&ctx).await {
            all_findings.extend(findings);
        }

        // 2. Secrets
        let secret_engine = SecretEngine::default();
        if let Ok(raw_secrets) = secret_engine.scan_path(&path).await {
            all_findings.extend(secret_engine.to_sarif(&raw_secrets));
        }

        // 3. SCA (Dependencies)
        let sca_engine = ScaEngine::new();
        if let Ok(report) = sca_engine.scan(&path).await {
            let sarif = sca_engine.to_sarif_log(&report);
            for run in sarif.runs {
                all_findings.extend(run.results);
            }
        }

        // 4. IaC (Kubernetes & Terraform)
        let iac_engine = IacEngine::new();
        if let Ok(report) = iac_engine.scan_file(&path).await {
            let sarif = iac_engine.to_sarif(&report, &path, None);
            for run in sarif.runs {
                all_findings.extend(run.results);
            }
        }

        // 5. CI/CD Pipelines
        let pipeline_engine = PipelineEngine::new();
        let pipe_res = if path.is_dir() {
            pipeline_engine.scan_directory(&path).await
        } else {
            pipeline_engine.scan_file(&path, None).await
        };
        if let Ok(report) = pipe_res {
            if let Ok(sarif) = pipeline_engine.to_sarif(&report) {
                for run in sarif.runs {
                    all_findings.extend(run.results);
                }
            }
        }

        // 6. Mobile manifests
        let mobile_engine = MobileEngine::new(false);
        let mob_res = if path.is_dir() {
            mobile_engine.scan_directory(&path).await
        } else {
            mobile_engine.scan_file(&path).await
        };
        if let Ok(report) = mob_res {
            if let Ok(sarif) = mobile_engine.to_sarif(&report) {
                for run in sarif.runs {
                    all_findings.extend(run.results);
                }
            }
        }

        // 7. Containers (Dockerfiles)
        let container_engine = ContainerEngine::new();
        if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if ContainerEngine::is_dockerfile(name) {
                if let Ok(df_findings) = container_engine.scan_dockerfile(&path).await {
                    let report = ContainerAuditReport {
                        dockerfile_findings: df_findings,
                        packages: Vec::new(),
                    };
                    all_findings.extend(container_engine.to_sarif(&report));
                }
            }
        }

        // Apply baseline filtering if provided
        let baseline_path = args
            .as_ref()
            .and_then(|m| m.get("baseline"))
            .and_then(|v| v.as_str());

        let mut suppressed = 0;
        if let Some(base_str) = baseline_path {
            let base_file = Path::new(base_str);
            if base_file.exists() {
                if let Ok(baseline) = AegixBaseline::load_from_path(base_file) {
                    suppressed = baseline.filter_results(&mut all_findings);
                }
            }
        }

        let mut text = Self::format_sarif_results(&all_findings, &path_str, limit);
        if suppressed > 0 {
            text.push_str(&format!(
                "\n*🛡️ Baseline suppression: {} known finding(s) filtered out.*",
                suppressed
            ));
        }

        CallToolResult::success(text)
    }

    /// Execute SAST engine.
    async fn run_aegix_sast(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let limit = Self::extract_limit(&args);
        let min_sev = args
            .as_ref()
            .and_then(|m| m.get("min_severity"))
            .and_then(|v| v.as_str());

        let sast_engine = NativeRuleEngine::default();
        let mut ctx = ScanContext::new(&path);
        if let Some(sev) = min_sev {
            ctx = ctx.with_min_severity(Some(sev.to_string()));
        }

        match sast_engine.analyze(&ctx).await {
            Ok(findings) => {
                let text = Self::format_sarif_results(&findings, &path.to_string_lossy(), limit);
                CallToolResult::success(text)
            }
            Err(e) => CallToolResult::failure(format!("SAST analysis failed: {}", e)),
        }
    }

    /// Execute Secrets engine.
    async fn run_aegix_secrets(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let limit = Self::extract_limit(&args);

        let secret_engine = SecretEngine::default();
        match secret_engine.scan_path(&path).await {
            Ok(raw_secrets) => {
                let findings = secret_engine.to_sarif(&raw_secrets);
                let text = Self::format_sarif_results(&findings, &path.to_string_lossy(), limit);
                CallToolResult::success(text)
            }
            Err(e) => CallToolResult::failure(format!("Secret detection failed: {}", e)),
        }
    }

    /// Execute SCA engine.
    async fn run_aegix_sca(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let limit = Self::extract_limit(&args);

        let sca_engine = ScaEngine::new();
        match sca_engine.scan(&path).await {
            Ok(report) => {
                let sarif = sca_engine.to_sarif_log(&report);
                let findings: Vec<SarifResult> =
                    sarif.runs.into_iter().flat_map(|r| r.results).collect();
                let text = Self::format_sarif_results(&findings, &path.to_string_lossy(), limit);
                CallToolResult::success(text)
            }
            Err(e) => CallToolResult::failure(format!("SCA analysis failed: {}", e)),
        }
    }

    /// Execute IaC engine.
    async fn run_aegix_iac(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let limit = Self::extract_limit(&args);

        let iac_engine = IacEngine::new();
        match iac_engine.scan_file(&path).await {
            Ok(report) => {
                let sarif = iac_engine.to_sarif(&report, &path, None);
                let findings: Vec<SarifResult> =
                    sarif.runs.into_iter().flat_map(|r| r.results).collect();
                let text = Self::format_sarif_results(&findings, &path.to_string_lossy(), limit);
                CallToolResult::success(text)
            }
            Err(e) => CallToolResult::failure(format!("IaC analysis failed: {}", e)),
        }
    }

    /// Execute Pipeline engine.
    async fn run_aegix_pipeline(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let limit = Self::extract_limit(&args);

        let pipeline_engine = PipelineEngine::new();
        let pipe_res = if path.is_dir() {
            pipeline_engine.scan_directory(&path).await
        } else {
            pipeline_engine.scan_file(&path, None).await
        };

        match pipe_res {
            Ok(report) => match pipeline_engine.to_sarif(&report) {
                Ok(sarif) => {
                    let findings: Vec<SarifResult> =
                        sarif.runs.into_iter().flat_map(|r| r.results).collect();
                    let text =
                        Self::format_sarif_results(&findings, &path.to_string_lossy(), limit);
                    CallToolResult::success(text)
                }
                Err(e) => {
                    CallToolResult::failure(format!("Pipeline SARIF conversion failed: {}", e))
                }
            },
            Err(e) => CallToolResult::failure(format!("Pipeline analysis failed: {}", e)),
        }
    }

    /// Execute Mobile engine.
    async fn run_aegix_mobile(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let limit = Self::extract_limit(&args);
        let release = args
            .as_ref()
            .and_then(|m| m.get("release"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mobile_engine = MobileEngine::new(release);
        let mob_res = if path.is_dir() {
            mobile_engine.scan_directory(&path).await
        } else {
            mobile_engine.scan_file(&path).await
        };

        match mob_res {
            Ok(report) => match mobile_engine.to_sarif(&report) {
                Ok(sarif) => {
                    let findings: Vec<SarifResult> =
                        sarif.runs.into_iter().flat_map(|r| r.results).collect();
                    let text =
                        Self::format_sarif_results(&findings, &path.to_string_lossy(), limit);
                    CallToolResult::success(text)
                }
                Err(e) => CallToolResult::failure(format!("Mobile SARIF conversion failed: {}", e)),
            },
            Err(e) => CallToolResult::failure(format!("Mobile audit failed: {}", e)),
        }
    }

    /// Execute Threat Modeling engine.
    async fn run_aegix_threat(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };
        let domain_str = args
            .as_ref()
            .and_then(|m| m.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("enterprise");

        let domain = MitreMatrixDomain::from_str_loose(domain_str)
            .unwrap_or(MitreMatrixDomain::EnterpriseAttack);

        let engine = ThreatEngine::new().with_domain(domain);

        let report_res = if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "json" || ext == "sarif" {
                engine.scan_file(&path).await
            } else {
                let sast_engine = NativeRuleEngine::default();
                let ctx = ScanContext::new(&path);
                let findings = sast_engine.analyze(&ctx).await.unwrap_or_default();
                let mut sarif_log =
                    SarifLog::new("Aegix Threat Evaluation", env!("CARGO_PKG_VERSION"));
                for f in findings {
                    sarif_log.add_result(f);
                }
                engine.scan_sarif_log(&sarif_log).await
            }
        } else {
            // Scan directory with SAST & Secrets to build a combined SARIF log
            let sast_engine = NativeRuleEngine::default();
            let ctx = ScanContext::new(&path);
            let mut findings = sast_engine.analyze(&ctx).await.unwrap_or_default();

            let secret_engine = SecretEngine::default();
            if let Ok(raw_secrets) = secret_engine.scan_path(&path).await {
                findings.extend(secret_engine.to_sarif(&raw_secrets));
            }

            let mut sarif_log = SarifLog::new("Aegix Threat Evaluation", env!("CARGO_PKG_VERSION"));
            for f in findings {
                sarif_log.add_result(f);
            }
            engine.scan_sarif_log(&sarif_log).await
        };

        match report_res {
            Ok(report) => {
                let terminal_view =
                    ThreatReportFormatter::render_terminal(&report, engine.catalog());
                CallToolResult::success(terminal_view)
            }
            Err(e) => CallToolResult::failure(format!("Threat modeling failed: {}", e)),
        }
    }

    /// Explain rule ID with security details and remediation advice.
    fn run_aegix_explain(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let rule_id = match args
            .as_ref()
            .and_then(|m| m.get("rule_id"))
            .and_then(|v| v.as_str())
        {
            Some(r) => r.trim(),
            None => {
                return CallToolResult::failure("Missing required argument 'rule_id'.".to_string())
            }
        };

        let explanation = match rule_id {
            "CG-SQLI-001" => {
                r#"## Rule Explanation: CG-SQLI-001
**Name:** SQL Injection via Unsanitized Formatting  
**Severity:** 🔴 Error (High Impact)  
**Standard:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)

### Vulnerability Mechanism
Untrusted user inputs are formatted or concatenated directly into SQL command strings (e.g. `SELECT * FROM users WHERE id = ` + user_input). An attacker can inject quotes or SQL syntax (`' OR '1'='1`) to bypass authentication, dump sensitive database tables, or execute remote commands.

### Remediation Guidance
Always use parameterized queries, prepared statements, or ORMs that bind query parameters separately from the SQL statement grammar:
```rust
// Secure Parameterized Query:
sqlx::query!("SELECT * FROM users WHERE id = $1", user_id).fetch_one(&pool).await?;
```
"#
            }
            "CG-CMDI-001" => {
                r#"## Rule Explanation: CG-CMDI-001
**Name:** OS Command Injection via Shell Invocation  
**Severity:** 🔴 Error (Critical Impact)  
**Standard:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)

### Vulnerability Mechanism
User-supplied data is concatenated into arguments passed to a system shell (`system()`, `popen()`, `exec()`, `sh -c`). Attackers inject shell metacharacters (`;`, `&`, `|`, `$()`, backticks) to execute arbitrary commands with the privileges of the running application.

### Remediation Guidance
Avoid invoking raw shells. Pass arguments as discrete string vectors directly to the process execution API:
```rust
// Secure Executable Invocation:
std::process::Command::new("/usr/bin/git")
    .args(["checkout", &branch_name])
    .output()?;
```
"#
            }
            "CG-SECR-001" => {
                r#"## Rule Explanation: CG-SECR-001
**Name:** Hardcoded Cryptographic Secret or API Token  
**Severity:** 🔴 Error (High Impact)  
**Standard:** CWE-798 (Use of Hard-coded Credentials)

### Vulnerability Mechanism
Private keys, AWS tokens, GitHub PATs, database passwords, or cryptographic secrets are committed directly in source code. Any party with read access to the repository can extract and abuse these credentials.

### Remediation Guidance
1. Immediately revoke and rotate the exposed secret.
2. Load credentials at runtime from environment variables or a secure vault (e.g. HashiCorp Vault, AWS Secrets Manager).
"#
            }
            "CG-PATH-001" => {
                r#"## Rule Explanation: CG-PATH-001
**Name:** Path Traversal via Unvalidated Relative Path Sequence  
**Severity:** 🟡 Warning (Medium Impact)  
**Standard:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

### Vulnerability Mechanism
The application constructs filesystem paths using unvalidated user input containing `../` or `..\` sequences, allowing attackers to access files outside the intended root directory.

### Remediation Guidance
Canonicalize the requested path using `std::fs::canonicalize` and verify that the resolved path starts with the allowed base directory:
```rust
let resolved = target_dir.join(user_path).canonicalize()?;
if !resolved.starts_with(&target_dir) {
    return Err("Access Denied: Path Traversal Detected");
}
```
"#
            }
            "CG-SSRF-001" => {
                r#"## Rule Explanation: CG-SSRF-001
**Name:** Server-Side Request Forgery via Dynamic URL Formulation  
**Severity:** 🔴 Error (High Impact)  
**Standard:** CWE-918 (Server-Side Request Forgery)

### Vulnerability Mechanism
The backend issues outbound network requests to URLs supplied or influenced by users without validating destination IP addresses. Attackers exploit this to target internal infrastructure (e.g. AWS IMDS `169.254.169.254` or private VPC services).

### Remediation Guidance
Validate URLs against an allowlist of trusted domains and enforce DNS resolution checks that reject private/loopback IP address ranges (RFC 1918).
"#
            }
            "CG-XSS-001" => {
                r#"## Rule Explanation: CG-XSS-001
**Name:** Cross-Site Scripting via Unsanitized DOM Insertion  
**Severity:** 🔴 Error (High Impact)  
**Standard:** CWE-79 (Improper Neutralization of Input During Web Page Generation)

### Vulnerability Mechanism
Unsanitized user data is inserted into HTML or DOM sinks (`innerHTML`, `dangerouslySetInnerHTML`), allowing attackers to execute arbitrary JavaScript in victim browsers.

### Remediation Guidance
Use safe DOM text assignment (`textContent`) or sanitize HTML with an audited library like DOMPurify before rendering.
"#
            }
            "IAC-K8S-001" => {
                r#"## Rule Explanation: IAC-K8S-001
**Name:** Privileged Container Escalation Allowed  
**Severity:** 🔴 Error (Critical Impact)  
**Standard:** CIS Kubernetes Benchmark 5.2.1

### Vulnerability Mechanism
Container is configured with `securityContext.privileged: true`. Privileged containers share host root capabilities and can easily escape container confinement to compromise the host node.

### Remediation Guidance
Set `privileged: false` and explicitly drop all unused Linux capabilities (`drop: ["ALL"]`).
"#
            }
            "PIPELINE-GHA-001" => {
                r#"## Rule Explanation: PIPELINE-GHA-001
**Name:** Script Injection via Untrusted Pull Request Context  
**Severity:** 🔴 Error (Critical Impact)  
**Standard:** OWASP CI/CD Top 10 - CICD-SEC-1

### Vulnerability Mechanism
Inline `run:` shell commands embed untrusted GitHub context values (such as `${{ github.event.pull_request.title }}`). An attacker opening a pull request with backticks or semicolons can execute arbitrary commands in the CI runner.

### Remediation Guidance
Pass context variables into the action environment rather than formatting them into the script body:
```yaml
- name: Echo PR Title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```
"#
            }
            "MOB-ANDR-001" => {
                r#"## Rule Explanation: MOB-ANDR-001
**Name:** Cleartext HTTP Traffic Permitted  
**Severity:** 🔴 Error (High Impact)  
**Standard:** OWASP Mobile Top 10 - M3 (Insecure Communication)

### Vulnerability Mechanism
The application configures `android:usesCleartextTraffic="true"` or permits insecure HTTP in `network_security_config.xml`, exposing network traffic to man-in-the-middle interception.

### Remediation Guidance
Set `android:usesCleartextTraffic="false"` and enforce TLS 1.3 across all network communication.
"#
            }
            "CG-DOCKER-001" => {
                r#"## Rule Explanation: CG-DOCKER-001
**Name:** Container Runs as Root  
**Severity:** 🟡 Warning (Medium Impact)  
**Standard:** CIS Docker Benchmark 4.1

### Vulnerability Mechanism
Dockerfile lacks a `USER` instruction, causing container processes to run as root (`UID 0`). If a vulnerability occurs, attackers obtain root privileges inside the container.

### Remediation Guidance
Create and switch to a non-privileged user before executing application binaries:
```dockerfile
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
```
"#
            }
            other => {
                return CallToolResult::success(format!(
                    "## Rule Information: {}\n\n*Rule ID '{}' is a recognized Aegix detection signature.* For detailed remediation templates or automated code fixes, run `aegix fix` or inspect the SARIF telemetry output.",
                    other, other
                ));
            }
        };

        CallToolResult::success(explanation.to_string())
    }

    /// Execute the Attack Path Engine over project findings or SARIF reports.
    async fn run_aegix_graph(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };

        let max_depth = args
            .as_ref()
            .and_then(|m| m.get("max_depth"))
            .and_then(|v| v.as_u64())
            .map(|u| u as usize)
            .unwrap_or(10);

        let min_risk = args
            .as_ref()
            .and_then(|m| m.get("min_risk"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let limit = args
            .as_ref()
            .and_then(|m| m.get("limit"))
            .and_then(|v| v.as_u64())
            .map(|u| u as usize)
            .unwrap_or(10);

        let format_choice = args
            .as_ref()
            .and_then(|m| m.get("format"))
            .and_then(|v| v.as_str())
            .unwrap_or("markdown");

        let mut graph = AttackGraph::new();
        let ingester = StandardTelemetryIngester::new();

        // If target is a SARIF/JSON file, load directly
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(sarif) = serde_json::from_str::<SarifLog>(&content) {
                    let _ = ingester.ingest_sarif(&mut graph, &sarif);
                }
            }
        }

        // If graph is empty (e.g. scanning a directory), gather findings via multi-engine scan
        if graph.node_count() == 0 {
            let mut sarif_log = SarifLog::new("aegix-mcp", "0.9.0");

            let sast_engine = NativeRuleEngine::default();
            let ctx = ScanContext::new(&path);
            if let Ok(findings) = sast_engine.analyze(&ctx).await {
                for f in findings {
                    sarif_log.add_result(f);
                }
            }

            let secret_engine = SecretEngine::default();
            if let Ok(raw_secrets) = secret_engine.scan_path(&path).await {
                for s in secret_engine.to_sarif(&raw_secrets) {
                    sarif_log.add_result(s);
                }
            }

            let _ = ingester.ingest_sarif(&mut graph, &sarif_log);
        }

        let correlator = StandardGraphCorrelator::new();
        if let Err(e) = correlator.correlate(&mut graph) {
            return CallToolResult::failure(format!("Correlation error: {}", e));
        }

        let path_finder = StandardPathFinder::new();
        let paths = match path_finder.find_paths(&graph, max_depth, limit, min_risk) {
            Ok(p) => p,
            Err(e) => return CallToolResult::failure(format!("Traversal error: {}", e)),
        };

        let analyzer = StandardChokePointAnalyzer::new();
        let choke_points = match analyzer.analyze_choke_points(&graph, &paths) {
            Ok(cp) => cp,
            Err(e) => return CallToolResult::failure(format!("Choke-point analysis error: {}", e)),
        };

        match format_choice {
            "mermaid" => {
                let exporter = MermaidExporter::new();
                match exporter.export(&graph, &paths, &choke_points) {
                    Ok(rendered) => CallToolResult::success(rendered),
                    Err(e) => CallToolResult::failure(format!("Mermaid export error: {}", e)),
                }
            }
            "json" => {
                let exporter = JsonExporter::new();
                match exporter.export(&graph, &paths, &choke_points) {
                    Ok(rendered) => CallToolResult::success(rendered),
                    Err(e) => CallToolResult::failure(format!("JSON export error: {}", e)),
                }
            }
            "sarif" => {
                let exporter = SarifExporter::new();
                match exporter.export(&graph, &paths, &choke_points) {
                    Ok(rendered) => CallToolResult::success(rendered),
                    Err(e) => CallToolResult::failure(format!("SARIF export error: {}", e)),
                }
            }
            _ => {
                let exporter = TerminalExporter::new(false);
                match exporter.export(&graph, &paths, &choke_points) {
                    Ok(rendered) => CallToolResult::success(rendered),
                    Err(e) => CallToolResult::failure(format!("Export error: {}", e)),
                }
            }
        }
    }

    /// Execute the Tri-Factor Prioritizer (`cyberguard-risk`) on a workspace or SARIF file.
    async fn run_aegix_risk(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };

        // Confine relative traversal and verify canonical path
        let canonical = match std::fs::canonicalize(&path) {
            Ok(c) => c,
            Err(e) => {
                return CallToolResult::failure(format!(
                    "Failed to resolve target path '{}': {}",
                    path.display(),
                    e
                ))
            }
        };

        let min_score = args
            .as_ref()
            .and_then(|m| m.get("min_score"))
            .and_then(|v| v.as_f64())
            .filter(|v| v.is_finite())
            .unwrap_or(0.0);

        let show_suppressed = args
            .as_ref()
            .and_then(|m| m.get("show_suppressed"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let no_cargo_metadata = args
            .as_ref()
            .and_then(|m| m.get("no_cargo_metadata"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let limit = Self::extract_limit(&args);
        let format_choice = args
            .as_ref()
            .and_then(|m| m.get("format"))
            .and_then(|v| v.as_str())
            .unwrap_or("markdown");

        let options = RiskScanOptions {
            min_score,
            show_suppressed,
            use_cargo_metadata: !no_cargo_metadata,
            external_epss_db: None,
        };

        let engine = RiskEngine::new();
        let report_res = if canonical.is_file()
            && canonical
                .extension()
                .is_some_and(|ext| ext == "json" || ext == "sarif")
        {
            match std::fs::read_to_string(&canonical) {
                Ok(content) => match serde_json::from_str::<SarifLog>(&content) {
                    Ok(sarif) => {
                        let parent = canonical.parent().unwrap_or(&canonical);
                        engine.prioritize_sarif(parent, &sarif, &options).await
                    }
                    Err(e) => {
                        return CallToolResult::failure(format!("Malformed SARIF file: {}", e))
                    }
                },
                Err(e) => {
                    return CallToolResult::failure(format!("Failed to read SARIF file: {}", e))
                }
            }
        } else {
            engine.prioritize_path(&canonical, &options).await
        };

        let mut report = match report_res {
            Ok(r) => r,
            Err(e) => return CallToolResult::failure(format!("Tri-Factor analysis failed: {}", e)),
        };

        if report.findings.len() > limit {
            report.findings.truncate(limit);
        }

        if format_choice == "json" {
            let exporter = RiskJsonExporter::new();
            match exporter.export(&report) {
                Ok(rendered) => CallToolResult::success(rendered),
                Err(e) => CallToolResult::failure(format!("JSON export error: {}", e)),
            }
        } else {
            let exporter = RiskTerminalExporter::new(false);
            match exporter.export(&report) {
                Ok(rendered) => CallToolResult::success(rendered),
                Err(e) => CallToolResult::failure(format!("Terminal export error: {}", e)),
            }
        }
    }

    /// Execute the Deterministic AST & Autonomous Remediation Engine (`cyberguard-fix`).
    async fn run_aegix_fix(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };

        let canonical = match std::fs::canonicalize(&path) {
            Ok(c) => c,
            Err(e) => {
                return CallToolResult::failure(format!(
                    "Failed to resolve target path '{}': {}",
                    path.display(),
                    e
                ))
            }
        };

        let auto_apply = args
            .as_ref()
            .and_then(|m| m.get("auto_apply"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let generate_tests = args
            .as_ref()
            .and_then(|m| m.get("generate_tests"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let rules_filter = args
            .as_ref()
            .and_then(|m| m.get("rules"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|val| val.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            });

        let sarif_path = args
            .as_ref()
            .and_then(|m| m.get("sarif_path"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        let options = FixScanOptions {
            sarif_path: sarif_path.clone(),
            rules_filter,
            language_override: None,
            generate_tests,
            max_file_size: 10 * 1024 * 1024,
        };

        let engine = FixEngine::new();
        let plan_res = if let Some(ref sp) = sarif_path {
            match std::fs::read_to_string(sp) {
                Ok(content) => match serde_json::from_str::<SarifLog>(&content) {
                    Ok(sarif) => engine.plan_sarif(&canonical, &sarif, &options).await,
                    Err(e) => {
                        return CallToolResult::failure(format!("Malformed SARIF file: {}", e))
                    }
                },
                Err(e) => {
                    return CallToolResult::failure(format!("Failed to read SARIF file: {}", e))
                }
            }
        } else {
            engine.plan_path(&canonical, &options).await
        };

        let plan = match plan_res {
            Ok(p) => p,
            Err(e) => {
                return CallToolResult::failure(format!("Remediation planning failed: {}", e))
            }
        };

        let mut out = String::new();
        out.push_str(&format!(
            "### 🛠️ Aegix AST Remediation Report: `{}`\n\n",
            canonical.display()
        ));
        out.push_str(&format!(
            "- **Vulnerabilities Detected:** {}\n- **Surgical Patches Planned:** {}\n- **Unfixable Findings:** {}\n- **Eradication Tests Planned:** {}\n\n",
            plan.total_vulnerabilities_detected,
            plan.patches.len(),
            plan.unfixable_count,
            plan.tests.len()
        ));

        if plan.patches.is_empty() {
            out.push_str("✅ **No remediable vulnerabilities detected or no patches required.**\n");
            return CallToolResult::success(out);
        }

        if auto_apply {
            match engine.apply_plan(&plan).await {
                Ok(res) => {
                    out.push_str(&format!(
                        "✨ **Successfully applied {} patch(es) across {} file(s)** in {}ms.\n\n",
                        res.applied_patches,
                        res.modified_files.len(),
                        res.duration_ms
                    ));
                    out.push_str("#### Modified Files\n");
                    for f in &res.modified_files {
                        out.push_str(&format!("- `{}`\n", f.display()));
                    }
                    if !res.written_test_files.is_empty() {
                        out.push_str("\n#### Generated Eradication Tests\n");
                        for t in &res.written_test_files {
                            out.push_str(&format!("- `{}`\n", t.display()));
                        }
                    }
                }
                Err(e) => {
                    return CallToolResult::failure(format!(
                        "Failed to apply surgical patches: {}",
                        e
                    ))
                }
            }
        } else {
            out.push_str("#### Proposed Unified Diffs (Dry-Run Preview)\n\n");
            for diff in &plan.diffs {
                out.push_str(&format!("```diff\n{}\n```\n\n", diff.raw_diff.trim()));
            }
            out.push_str("> 💡 *Dry-run mode active. Set `auto_apply: true` to atomically write these patches to disk.*\n");
        }

        CallToolResult::success(out)
    }

    /// Execute Executive Security Reporting & Metrics Aggregation (`cyberguard-ui`).
    async fn run_aegix_report(
        &self,
        args: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> CallToolResult {
        let path = match Self::extract_path(&args) {
            Ok(p) => p,
            Err(fail) => return fail,
        };

        let format_choice = args
            .as_ref()
            .and_then(|m| m.get("format"))
            .and_then(|v| v.as_str())
            .unwrap_or("summary");

        let sarif_path = args
            .as_ref()
            .and_then(|m| m.get("sarif_path"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from);

        let (sarif_log, target_str) = if let Some(ref sp) = sarif_path {
            match std::fs::read_to_string(sp) {
                Ok(content) => match serde_json::from_str::<SarifLog>(&content) {
                    Ok(sarif) => (sarif, sp.to_string_lossy().to_string()),
                    Err(e) => {
                        return CallToolResult::failure(format!("Malformed SARIF file: {}", e))
                    }
                },
                Err(e) => {
                    return CallToolResult::failure(format!("Failed to read SARIF file: {}", e))
                }
            }
        } else if path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext == "json" || ext == "sarif")
        {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<SarifLog>(&content) {
                    Ok(sarif) => (sarif, path.to_string_lossy().to_string()),
                    Err(e) => {
                        return CallToolResult::failure(format!("Malformed SARIF file: {}", e))
                    }
                },
                Err(e) => {
                    return CallToolResult::failure(format!("Failed to read SARIF file: {}", e))
                }
            }
        } else {
            let sast_engine = NativeRuleEngine::default();
            let ctx = ScanContext::new(&path);
            let sast_findings = sast_engine.analyze(&ctx).await.unwrap_or_default();

            let secret_engine = SecretEngine::default();
            let raw_secrets = secret_engine.scan_path(&path).await.unwrap_or_default();
            let secret_findings = secret_engine.to_sarif(&raw_secrets);

            let mut log = SarifLog::new("Aegix Engine", env!("CARGO_PKG_VERSION"));
            for f in sast_findings.into_iter().chain(secret_findings) {
                log.add_result(f);
            }
            (log, path.to_string_lossy().to_string())
        };

        let aggregator = DefaultMetricsAggregator::new();
        let report = match aggregator.aggregate_sarif(&sarif_log, &target_str) {
            Ok(r) => r,
            Err(e) => return CallToolResult::failure(format!("Aggregation failed: {}", e)),
        };

        match format_choice {
            "html" => {
                let generator = DefaultHtmlReportGenerator::new();
                match generator.generate_html(&report) {
                    Ok(html) => CallToolResult::success(html),
                    Err(e) => CallToolResult::failure(format!("HTML generation failed: {}", e)),
                }
            }
            "json" => match serde_json::to_string_pretty(&report) {
                Ok(json_str) => CallToolResult::success(json_str),
                Err(e) => CallToolResult::failure(format!("JSON serialization failed: {}", e)),
            },
            _ => {
                let dashboard = DefaultTerminalDashboard::new(false);
                match dashboard.render_dashboard(&report) {
                    Ok(rendered) => CallToolResult::success(rendered),
                    Err(e) => CallToolResult::failure(format!("Dashboard rendering failed: {}", e)),
                }
            }
        }
    }
}

#[async_trait]
impl ToolExecutor for AegixEngineFacade {
    fn list_tools(&self) -> Vec<Tool> {
        get_tool_catalog()
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<CallToolResult, McpError> {
        let result = match name {
            "aegix_scan" => self.run_aegix_scan(arguments).await,
            "aegix_sast" => self.run_aegix_sast(arguments).await,
            "aegix_secrets" => self.run_aegix_secrets(arguments).await,
            "aegix_sca" => self.run_aegix_sca(arguments).await,
            "aegix_iac" => self.run_aegix_iac(arguments).await,
            "aegix_pipeline" => self.run_aegix_pipeline(arguments).await,
            "aegix_mobile" => self.run_aegix_mobile(arguments).await,
            "aegix_threat" => self.run_aegix_threat(arguments).await,
            "aegix_graph" => self.run_aegix_graph(arguments).await,
            "aegix_risk" => self.run_aegix_risk(arguments).await,
            "aegix_fix" => self.run_aegix_fix(arguments).await,
            "aegix_report" => self.run_aegix_report(arguments).await,
            "aegix_explain" => self.run_aegix_explain(arguments),
            unknown => CallToolResult::failure(format!("Unknown Aegix tool: '{}'", unknown)),
        };

        Ok(result)
    }
}
