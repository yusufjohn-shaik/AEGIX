// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Static Dockerfile linting and security anti-pattern analysis.

use crate::error::ContainerError;
use crate::models::DockerfileFinding;
use cyberguard_core::SarifLevel;
use regex::Regex;

/// A parsed Dockerfile instruction with 1-based source line mapping.
#[derive(Clone, Debug)]
struct ParsedInstruction {
    line_number: usize,
    directive: String,
    args: String,
}

/// A stage in a multi-stage Dockerfile.
#[derive(Clone, Debug, Default)]
struct DockerfileStage {
    from_line: usize,
    base_image: String,
    user_instruction: Option<(usize, String)>,
    healthcheck_instruction: Option<usize>,
    instructions: Vec<ParsedInstruction>,
}

/// Static Dockerfile security linter.
#[derive(Clone, Debug)]
pub struct DockerfileLinter {
    curl_pipe_regex: Regex,
    sudo_regex: Regex,
    secret_env_regex: Regex,
}

impl Default for DockerfileLinter {
    fn default() -> Self {
        Self {
            curl_pipe_regex: Regex::new(r#"(?i)(?:curl|wget)\b[^|]*\|\s*(?:ba|da|z|k|a)?sh\b"#)
                .expect("Valid regex"),
            sudo_regex: Regex::new(r#"(?i)\bsudo\b"#).expect("Valid regex"),
            secret_env_regex: Regex::new(
                r#"(?i)(?:password|secret|token|api_key|apikey|private_key)\s*[:=]\s*\S+"#,
            )
            .expect("Valid regex"),
        }
    }
}

impl DockerfileLinter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses raw Dockerfile text into normalized instructions, handling multi-line continuations (`\`).
    fn parse_instructions(&self, content: &str) -> Vec<ParsedInstruction> {
        let mut instructions = Vec::new();
        let mut current_directive = String::new();
        let mut current_args = String::new();
        let mut current_line = 1;
        let mut in_continuation = false;

        for (idx, raw_line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = raw_line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let (line_part, continues) = if let Some(stripped) = trimmed.strip_suffix('\\') {
                (stripped.trim_end(), true)
            } else {
                (trimmed, false)
            };

            if in_continuation {
                if !current_args.is_empty() {
                    current_args.push(' ');
                }
                current_args.push_str(line_part);
                if !continues {
                    instructions.push(ParsedInstruction {
                        line_number: current_line,
                        directive: current_directive.clone(),
                        args: current_args.clone(),
                    });
                    in_continuation = false;
                    current_directive.clear();
                    current_args.clear();
                }
            } else {
                let mut parts = line_part.splitn(2, char::is_whitespace);
                if let Some(directive) = parts.next() {
                    let dir_upper = directive.to_uppercase();
                    let args = parts.next().unwrap_or("").trim().to_string();
                    if continues {
                        current_line = line_num;
                        current_directive = dir_upper;
                        current_args = args;
                        in_continuation = true;
                    } else {
                        instructions.push(ParsedInstruction {
                            line_number: line_num,
                            directive: dir_upper,
                            args,
                        });
                    }
                }
            }
        }

        if in_continuation && !current_directive.is_empty() {
            instructions.push(ParsedInstruction {
                line_number: current_line,
                directive: current_directive,
                args: current_args,
            });
        }

        instructions
    }

    /// Lints Dockerfile content against 8 core container security rules.
    pub fn lint(&self, content: &str) -> Result<Vec<DockerfileFinding>, ContainerError> {
        let instructions = self.parse_instructions(content);
        let mut findings = Vec::new();

        // 1. Organize instructions into stages
        let mut stages: Vec<DockerfileStage> = Vec::new();
        let mut current_stage = DockerfileStage::default();

        for inst in &instructions {
            if inst.directive == "FROM" {
                if current_stage.from_line != 0 {
                    stages.push(current_stage);
                    current_stage = DockerfileStage::default();
                }
                current_stage.from_line = inst.line_number;
                current_stage.base_image = inst.args.clone();
            } else if inst.directive == "USER" {
                current_stage.user_instruction = Some((inst.line_number, inst.args.clone()));
            } else if inst.directive == "HEALTHCHECK" {
                current_stage.healthcheck_instruction = Some(inst.line_number);
            }
            current_stage.instructions.push(inst.clone());
        }

        if current_stage.from_line != 0 {
            stages.push(current_stage);
        }

        let num_stages = stages.len();

        // 2. Evaluate stage-level and instruction-level rules
        for (stage_idx, stage) in stages.iter().enumerate() {
            let is_final_stage = stage_idx == num_stages.saturating_sub(1);

            // CG-CONT-002: Untagged Base Image
            let base_image_token = stage
                .base_image
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim();
            if !base_image_token.is_empty() && base_image_token != "scratch" {
                // If it doesn't contain a digest '@sha256:' and either lacks a tag or ends with ':latest'
                let is_digest = base_image_token.contains('@');
                let is_latest = base_image_token.ends_with(":latest");
                let has_tag = base_image_token.contains(':');

                if !is_digest && (!has_tag || is_latest) {
                    findings.push(DockerfileFinding {
                        rule_id: "CG-CONT-002".to_string(),
                        directive: "FROM".to_string(),
                        line_number: stage.from_line,
                        severity: SarifLevel::Warning,
                        message: format!(
                            "Base image '{}' is untagged or pinned to mutable 'latest'.",
                            base_image_token
                        ),
                        recommendation:
                            "Pin the base image to an immutable semantic version or digest."
                                .to_string(),
                    });
                }
            }

            // Rules specific to final deployment stage
            if is_final_stage {
                // CG-CONT-001: Root User Detection
                match &stage.user_instruction {
                    None => {
                        findings.push(DockerfileFinding {
                            rule_id: "CG-CONT-001".to_string(),
                            directive: "USER".to_string(),
                            line_number: stage.from_line,
                            severity: SarifLevel::Error,
                            message: "Container process runs as root (missing USER directive)."
                                .to_string(),
                            recommendation:
                                "Add a non-root USER instruction before executing runtime commands."
                                    .to_string(),
                        });
                    }
                    Some((line, user)) => {
                        let u_trimmed = user.trim().to_lowercase();
                        if u_trimmed == "root" || u_trimmed == "0" {
                            findings.push(DockerfileFinding {
                                rule_id: "CG-CONT-001".to_string(),
                                directive: "USER".to_string(),
                                line_number: *line,
                                severity: SarifLevel::Error,
                                message: "Explicit USER root instruction detected.".to_string(),
                                recommendation:
                                    "Specify a non-root user or unprivileged numeric UID."
                                        .to_string(),
                            });
                        }
                    }
                }

                // CG-CONT-005: Missing Healthcheck
                if stage.healthcheck_instruction.is_none() {
                    findings.push(DockerfileFinding {
                        rule_id: "CG-CONT-005".to_string(),
                        directive: "HEALTHCHECK".to_string(),
                        line_number: stage.from_line,
                        severity: SarifLevel::Note,
                        message: "Container image is missing a HEALTHCHECK instruction.".to_string(),
                        recommendation:
                            "Add a HEALTHCHECK instruction or ensure health is monitored externally."
                                .to_string(),
                    });
                }
            }

            // Instruction-level rules across all stages
            for inst in &stage.instructions {
                match inst.directive.as_str() {
                    "RUN" => {
                        // CG-CONT-003: Curl / Wget pipe to shell
                        if self.curl_pipe_regex.is_match(&inst.args) {
                            findings.push(DockerfileFinding {
                                rule_id: "CG-CONT-003".to_string(),
                                directive: "RUN".to_string(),
                                line_number: inst.line_number,
                                severity: SarifLevel::Error,
                                message: "Dangerous pipe from curl/wget to shell detected."
                                    .to_string(),
                                recommendation:
                                    "Download artifacts, verify their checksum or signature, and execute separately."
                                        .to_string(),
                            });
                        }

                        // CG-CONT-006: Sudo in container
                        if self.sudo_regex.is_match(&inst.args) {
                            findings.push(DockerfileFinding {
                                rule_id: "CG-CONT-006".to_string(),
                                directive: "RUN".to_string(),
                                line_number: inst.line_number,
                                severity: SarifLevel::Warning,
                                message: "Unnecessary use of sudo inside container build."
                                    .to_string(),
                                recommendation:
                                    "Execute setup steps during the root build stage or grant specific file permissions."
                                        .to_string(),
                            });
                        }

                        // CG-CONT-008: Apt-get without clean
                        if (inst.args.contains("apt-get install")
                            || inst.args.contains("apt install"))
                            && !inst.args.contains("/var/lib/apt/lists")
                        {
                            findings.push(DockerfileFinding {
                                rule_id: "CG-CONT-008".to_string(),
                                directive: "RUN".to_string(),
                                line_number: inst.line_number,
                                severity: SarifLevel::Warning,
                                message:
                                    "apt-get install without cleaning lists increases image size."
                                        .to_string(),
                                recommendation:
                                    "Append '&& rm -rf /var/lib/apt/lists/*' to the apt install layer."
                                        .to_string(),
                            });
                        }
                    }
                    "ENV" | "ARG" => {
                        // CG-CONT-004: Hardcoded secret in ENV / ARG
                        if self.secret_env_regex.is_match(&inst.args) {
                            findings.push(DockerfileFinding {
                                rule_id: "CG-CONT-004".to_string(),
                                directive: inst.directive.clone(),
                                line_number: inst.line_number,
                                severity: SarifLevel::Error,
                                message: format!(
                                    "Potential hardcoded secret or API credential in {} directive.",
                                    inst.directive
                                ),
                                recommendation:
                                    "Use BuildKit secret mounts ('RUN --mount=type=secret') rather than persistent variables."
                                        .to_string(),
                            });
                        }
                    }
                    "ADD" => {
                        // CG-CONT-007: ADD instead of COPY
                        let src = inst.args.split_whitespace().next().unwrap_or("");
                        let is_url = src.starts_with("http://") || src.starts_with("https://");
                        let is_archive = src.ends_with(".tar")
                            || src.ends_with(".tar.gz")
                            || src.ends_with(".tgz")
                            || src.ends_with(".tar.bz2")
                            || src.ends_with(".tar.xz")
                            || src.ends_with(".zip");

                        if !is_url && !is_archive {
                            findings.push(DockerfileFinding {
                                rule_id: "CG-CONT-007".to_string(),
                                directive: "ADD".to_string(),
                                line_number: inst.line_number,
                                severity: SarifLevel::Note,
                                message: "ADD used for local non-archive file transfer instead of COPY."
                                    .to_string(),
                                recommendation:
                                    "Use COPY instead of ADD unless tar auto-extraction is specifically intended."
                                        .to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        let suppressions = cyberguard_core::SuppressionMap::parse(content);
        findings.retain(|f| !suppressions.is_suppressed(f.line_number, &f.rule_id));

        Ok(findings)
    }
}
