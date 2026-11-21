use crate::error::PipelineError;
use crate::models::{PipelineFinding, PipelineRuleId, WorkflowDefinition, WorkflowStep};
use crate::parser::PipelineParser;
use crate::traits::WorkflowAuditor;
use regex::Regex;
use sha2::{Digest, Sha256};

pub struct DefaultWorkflowAuditor;

impl WorkflowAuditor for DefaultWorkflowAuditor {
    fn audit_workflow(
        &self,
        workflow: &WorkflowDefinition,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<PipelineFinding>, PipelineError> {
        let mut findings = Vec::new();

        // --------------------------------------------------------------------
        // CG-PIPE-003: Excessive GITHUB_TOKEN Permissions (Top-level)
        // --------------------------------------------------------------------
        match &workflow.permissions {
            None => {
                let (line, col) = PipelineParser::calculate_line_hint(raw_content, "name:");
                findings.push(Self::build_finding(
                    PipelineRuleId::CgPipe003,
                    file_path,
                    line,
                    col,
                    "/permissions",
                    "Workflow omits top-level `permissions` block, defaulting to repository-wide permissions (potential write access).".to_string(),
                    "Add explicit `permissions: read-all` (or `permissions: {}`) at the top level of the workflow.".to_string(),
                ));
            }
            Some(perms) => {
                if perms.is_write_all() {
                    let (line, col) = PipelineParser::calculate_line_hint(raw_content, "write-all");
                    findings.push(Self::build_finding(
                        PipelineRuleId::CgPipe003,
                        file_path,
                        line,
                        col,
                        "/permissions",
                        "Workflow grants broad `permissions: write-all` at the top level, violating least privilege.".to_string(),
                        "Replace `permissions: write-all` with `permissions: read-all` and specify write permissions only on necessary jobs.".to_string(),
                    ));
                }
            }
        }

        // --------------------------------------------------------------------
        // CG-PIPE-004: Dangerous pull_request_target Trigger
        // --------------------------------------------------------------------
        let has_pr_target = workflow.on.contains_event("pull_request_target");

        // Inspect jobs and steps
        for (job_id, job) in &workflow.jobs {
            // Check job-level permissions
            if let Some(perms) = &job.permissions {
                if perms.is_write_all() {
                    let (line, col) =
                        PipelineParser::calculate_step_line_hint(raw_content, job_id, "write-all");
                    findings.push(Self::build_finding(
                        PipelineRuleId::CgPipe003,
                        file_path,
                        line,
                        col,
                        format!("/jobs/{}/permissions", job_id),
                        format!("Job '{}' defines broad `permissions: write-all`.", job_id),
                        "Grant only specific necessary scopes (e.g. `contents: read`) to this job."
                            .to_string(),
                    ));
                }
            }

            // ----------------------------------------------------------------
            // CG-PIPE-006: Insecure Self-Hosted Runner
            // ----------------------------------------------------------------
            if job.runs_on.is_self_hosted() {
                let is_untrusted_trigger = workflow.on.contains_event("pull_request")
                    || workflow.on.contains_event("pull_request_target")
                    || workflow.on.contains_event("issues")
                    || workflow.on.contains_event("issue_comment")
                    || workflow.on.contains_event("fork");

                let has_env_gate = job.environment.is_some();

                if is_untrusted_trigger || !has_env_gate {
                    let (line, col) = PipelineParser::calculate_step_line_hint(
                        raw_content,
                        job_id,
                        "self-hosted",
                    );
                    findings.push(Self::build_finding(
                        PipelineRuleId::CgPipe006,
                        file_path,
                        line,
                        col,
                        format!("/jobs/{}/runs-on", job_id),
                        format!(
                            "Job '{}' uses `runs-on: self-hosted` on workflows accessible to external triggers without environment approval.",
                            job_id
                        ),
                        "Do not run self-hosted runners on workflows triggered by PRs. Use ephemeral GitHub-hosted runners or require an environment protection rule.".to_string(),
                    ));
                }
            }

            for (step_idx, step) in job.steps.iter().enumerate() {
                let step_loc = format!("/jobs/{}/steps/{}", job_id, step_idx);

                // ------------------------------------------------------------
                // CG-PIPE-001: Unpinned 3rd-Party Action
                // ------------------------------------------------------------
                if let Some(uses) = &step.uses {
                    if !uses.starts_with("./") && !uses.starts_with("docker://") {
                        if let Some(at_pos) = uses.find('@') {
                            let version = &uses[at_pos + 1..];
                            let is_sha1 = version.len() == 40
                                && version.chars().all(|c| c.is_ascii_hexdigit());

                            if !is_sha1 {
                                let (line, col) = PipelineParser::calculate_step_line_hint(
                                    raw_content,
                                    job_id,
                                    uses,
                                );
                                findings.push(Self::build_finding(
                                    PipelineRuleId::CgPipe001,
                                    file_path,
                                    line,
                                    col,
                                    format!("{}/uses", step_loc),
                                    format!(
                                        "Action '{}' is pinned to mutable ref '{}' instead of an immutable 40-character commit SHA.",
                                        uses, version
                                    ),
                                    "Pin the action to an immutable commit hash (e.g. `actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b`).".to_string(),
                                ));
                            }
                        } else {
                            // Missing @ version tag entirely
                            let (line, col) =
                                PipelineParser::calculate_step_line_hint(raw_content, job_id, uses);
                            findings.push(Self::build_finding(
                                PipelineRuleId::CgPipe001,
                                file_path,
                                line,
                                col,
                                format!("{}/uses", step_loc),
                                format!(
                                    "Action '{}' has no version or commit SHA specified.",
                                    uses
                                ),
                                "Pin the action to an immutable 40-character commit SHA."
                                    .to_string(),
                            ));
                        }
                    }

                    // CG-PIPE-004 checkout check under pull_request_target
                    if has_pr_target && uses.contains("actions/checkout") {
                        if let Some(ref_val) = step.with.get("ref").and_then(|v| v.as_str()) {
                            let lower_ref = ref_val.to_ascii_lowercase();
                            if lower_ref.contains("github.event.pull_request.head.sha")
                                || lower_ref.contains("github.event.pull_request.head.ref")
                                || lower_ref.contains("github.head_ref")
                                || lower_ref.contains("pull_request.head")
                            {
                                let (line, col) = PipelineParser::calculate_step_line_hint(
                                    raw_content,
                                    job_id,
                                    "actions/checkout",
                                );
                                findings.push(Self::build_finding(
                                    PipelineRuleId::CgPipe004,
                                    file_path,
                                    line,
                                    col,
                                    format!("{}/with/ref", step_loc),
                                    "Workflow triggers on `pull_request_target` AND checks out untrusted PR head commit (critical RCE / secret leak risk).".to_string(),
                                    "Do not check out untrusted PR code in `pull_request_target`. Use `pull_request` trigger or a two-stage unprivileged workflow.".to_string(),
                                ));
                            }
                        }
                    }
                }

                // ------------------------------------------------------------
                // CG-PIPE-002: Script Injection via Untrusted Context
                // ------------------------------------------------------------
                if let Some(run_script) = &step.run {
                    if let Some(untrusted_expr) = Self::detect_script_injection(run_script) {
                        let (line, col) = PipelineParser::calculate_step_line_hint(
                            raw_content,
                            job_id,
                            &untrusted_expr,
                        );
                        findings.push(Self::build_finding(
                            PipelineRuleId::CgPipe002,
                            file_path,
                            line,
                            col,
                            format!("{}/run/untrusted_context", step_loc),
                            format!(
                                "Untrusted GitHub context '{}' is interpolated directly into a shell script (Script Injection vulnerability).",
                                untrusted_expr
                            ),
                            "Pass untrusted context into an environment variable (`env:`) and reference it as `\"$VAR\"` inside the script.".to_string(),
                        ));
                    }

                    // Also check for inline ${{ env.VAR }} expansion inside run: blocks
                    if let Some(inline_env) = Self::detect_inline_env_expansion(run_script) {
                        let (line, col) = PipelineParser::calculate_step_line_hint(
                            raw_content,
                            job_id,
                            &inline_env,
                        );
                        findings.push(Self::build_finding(
                            PipelineRuleId::CgPipe002,
                            file_path,
                            line,
                            col,
                            format!("{}/run/inline_env", step_loc),
                            format!(
                                "Inline expression '{}' expands prior to shell execution (Pre-Shell Interpolation risk).",
                                inline_env
                            ),
                            "Reference environment variables using standard shell syntax (e.g. `\"$VAR\"`) instead of `${{ env.VAR }}` in script bodies.".to_string(),
                        ));
                    }
                }

                // ------------------------------------------------------------
                // CG-PIPE-005: Plaintext Secret in Workflow
                // ------------------------------------------------------------
                Self::audit_step_secrets(
                    step,
                    &step_loc,
                    file_path,
                    raw_content,
                    job_id,
                    &mut findings,
                );
            }
        }

        Ok(findings)
    }
}

impl DefaultWorkflowAuditor {
    /// Detects dangerous interpolation of untrusted contexts in script bodies.
    /// Handles both dot notation (`github.event.issue.title`) and bracket notation (`github['event']['issue']['title']`).
    fn detect_script_injection(script: &str) -> Option<String> {
        let dangerous_patterns = [
            // Standard dot-notation
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.event.review_comment.body",
            "github.event.head_commit.message",
            "github.event.head_commit.author.email",
            "github.event.head_commit.author.name",
            "github.event.commits",
            "github.head_ref",
            "github.event.pull_request.head.ref",
            "github.event.client_payload",
            "github.event.pages",
            "github.event.discussion.title",
            "github.event.discussion.body",
        ];

        let lower_script = script.to_ascii_lowercase();

        for pat in dangerous_patterns {
            if lower_script.contains(pat) {
                return Some(pat.to_string());
            }
        }

        // Check bracket notation: github['event'] or github["event"]
        if lower_script.contains("github['event']") || lower_script.contains("github[\"event\"]") {
            return Some("github['event'] (bracket notation)".to_string());
        }

        None
    }

    /// Detects inline ${{ env.VAR }} expansion inside run script blocks.
    fn detect_inline_env_expansion(script: &str) -> Option<String> {
        let re = Regex::new(r#"(?i)\$\{\{\s*env\.[A-Za-z0-9_]+\s*\}\}"#).ok()?;
        if let Some(mat) = re.find(script) {
            return Some(mat.as_str().to_string());
        }
        None
    }

    /// Scans env and run blocks for hardcoded secrets.
    fn audit_step_secrets(
        step: &WorkflowStep,
        step_loc: &str,
        file_path: &str,
        raw_content: &str,
        job_id: &str,
        findings: &mut Vec<PipelineFinding>,
    ) {
        let secret_regexes = [
            ("GitHub Personal Access Token", r"ghp_[A-Za-z0-9_]{36}"),
            ("GitHub OAuth Token", r"gho_[A-Za-z0-9_]{36}"),
            (
                "AWS Access Key ID",
                r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            ),
            (
                "Slack Bot Token",
                r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
            ),
            (
                "Private Key Header",
                r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            ),
        ];

        // Check env vars
        for (k, v) in &step.env {
            if let Some(s) = v.as_str() {
                for (name, pattern) in secret_regexes {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(s) {
                            let (line, col) =
                                PipelineParser::calculate_step_line_hint(raw_content, job_id, k);
                            findings.push(Self::build_finding(
                                PipelineRuleId::CgPipe005,
                                file_path,
                                line,
                                col,
                                format!("{}/env/{}", step_loc, k),
                                format!(
                                    "Plaintext secret ({}) detected in step environment variable '{}': {}",
                                    name,
                                    k,
                                    Self::mask_secret(s)
                                ),
                                "Move sensitive tokens to GitHub Actions Secrets (`${{ secrets.NAME }}`) or an external secrets vault.".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // Check run scripts for inline secrets
        if let Some(run_script) = &step.run {
            for (name, pattern) in secret_regexes {
                if let Ok(re) = Regex::new(pattern) {
                    if let Some(mat) = re.find(run_script) {
                        let matched_str = mat.as_str();
                        let (line, col) = PipelineParser::calculate_step_line_hint(
                            raw_content,
                            job_id,
                            matched_str,
                        );
                        findings.push(Self::build_finding(
                            PipelineRuleId::CgPipe005,
                            file_path,
                            line,
                            col,
                            format!("{}/run", step_loc),
                            format!(
                                "Hardcoded secret ({}) detected inside step script: {}",
                                name,
                                Self::mask_secret(matched_str)
                            ),
                            "Remove hardcoded credentials from workflow run scripts and use secret injection.".to_string(),
                        ));
                    }
                }
            }
        }
    }

    pub fn mask_secret(secret: &str) -> String {
        if secret.len() <= 6 {
            "******".to_string()
        } else if secret.starts_with("ghp_") || secret.starts_with("gho_") {
            format!("{}***{}", &secret[..4], &secret[secret.len() - 3..])
        } else {
            format!("{}***{}", &secret[..3], &secret[secret.len() - 3..])
        }
    }

    fn build_finding(
        rule: PipelineRuleId,
        file_path: &str,
        line: usize,
        column: usize,
        location_path: impl Into<String>,
        description: String,
        remediation: String,
    ) -> PipelineFinding {
        let loc_str = location_path.into();
        let mut hasher = Sha256::new();
        hasher.update(rule.as_str().as_bytes());
        hasher.update(file_path.as_bytes());
        hasher.update(loc_str.as_bytes());
        hasher.update(description.as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize());

        PipelineFinding {
            rule_id: rule.as_str().to_string(),
            title: rule.title().to_string(),
            description,
            severity: rule.severity(),
            confidence: rule.confidence(),
            cwe: rule.cwe(),
            file_path: file_path.to_string(),
            line,
            column,
            location_path: loc_str,
            remediation,
            fingerprint,
        }
    }
}
