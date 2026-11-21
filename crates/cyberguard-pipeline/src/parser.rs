use crate::error::PipelineError;
use crate::models::{
    DsseEnvelope, PipelineDocument, PipelineFormat, SlsaStatement, WorkflowDefinition,
};
use base64::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MAX_PIPELINE_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB ceiling

pub struct PipelineParser;

impl PipelineParser {
    pub fn parse_file(path: &Path) -> Result<PipelineDocument, PipelineError> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len() as usize;

        if size > MAX_PIPELINE_FILE_SIZE {
            return Err(PipelineError::FileSizeLimitExceeded {
                size,
                max_allowed: MAX_PIPELINE_FILE_SIZE,
            });
        }

        let mut content = String::with_capacity(size);
        file.read_to_string(&mut content)?;
        Self::parse_str(&content, path)
    }

    pub fn parse_str(content: &str, path_hint: &Path) -> Result<PipelineDocument, PipelineError> {
        let format = Self::detect_format(content, path_hint)?;
        match format {
            PipelineFormat::GitHubActions => {
                let workflow: WorkflowDefinition = serde_yaml::from_str(content)?;
                Ok(PipelineDocument {
                    format,
                    file_path: path_hint.display().to_string(),
                    workflow: Some(workflow),
                    slsa: None,
                    raw_content: content.to_string(),
                })
            }
            PipelineFormat::GitLabCi => {
                // GitLab CI definitions normalize into WorkflowDefinition
                let workflow: WorkflowDefinition = serde_yaml::from_str(content)?;
                Ok(PipelineDocument {
                    format,
                    file_path: path_hint.display().to_string(),
                    workflow: Some(workflow),
                    slsa: None,
                    raw_content: content.to_string(),
                })
            }
            PipelineFormat::SlsaProvenance => {
                let slsa = Self::parse_slsa_or_dsse(content)?;
                Ok(PipelineDocument {
                    format,
                    file_path: path_hint.display().to_string(),
                    workflow: None,
                    slsa: Some(slsa),
                    raw_content: content.to_string(),
                })
            }
        }
    }

    pub fn parse_slsa_or_dsse(content: &str) -> Result<SlsaStatement, PipelineError> {
        let trimmed = content.trim_start();
        // Check if this is a DSSE envelope wrapping an in-toto statement
        if let Ok(envelope) = serde_json::from_str::<DsseEnvelope>(trimmed) {
            if envelope.payload_type.contains("in-toto") || !envelope.payload.is_empty() {
                let decoded_bytes = BASE64_STANDARD.decode(envelope.payload.trim())?;
                let decoded_str = String::from_utf8_lossy(&decoded_bytes);
                if let Ok(stmt) = serde_json::from_str::<SlsaStatement>(&decoded_str) {
                    return Ok(stmt);
                }
            }
        }

        // Direct in-toto statement JSON
        let statement: SlsaStatement = serde_json::from_str(trimmed)?;
        Ok(statement)
    }

    pub fn detect_format(content: &str, path_hint: &Path) -> Result<PipelineFormat, PipelineError> {
        let file_name = path_hint
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if file_name == ".gitlab-ci.yml" || file_name.ends_with(".gitlab-ci.yaml") {
            return Ok(PipelineFormat::GitLabCi);
        }

        let trimmed = content.trim_start();
        if trimmed.starts_with('{')
            && (trimmed.contains("predicateType")
                || trimmed.contains("in-toto")
                || trimmed.contains("payloadType"))
        {
            return Ok(PipelineFormat::SlsaProvenance);
        }

        if path_hint.to_string_lossy().contains(".github/workflows")
            || trimmed.contains("jobs:")
            || trimmed.contains("on:")
        {
            return Ok(PipelineFormat::GitHubActions);
        }

        if trimmed.contains("stages:") || trimmed.contains("script:") {
            return Ok(PipelineFormat::GitLabCi);
        }

        // Fallback: try parsing JSON as SLSA, else YAML as GHA
        if Self::parse_slsa_or_dsse(content).is_ok() {
            return Ok(PipelineFormat::SlsaProvenance);
        }

        if serde_yaml::from_str::<WorkflowDefinition>(content).is_ok() {
            return Ok(PipelineFormat::GitHubActions);
        }

        Err(PipelineError::UnrecognizedFormat(
            path_hint.display().to_string(),
        ))
    }

    /// Finds 1-based line and column for token occurrence.
    pub fn calculate_line_hint(content: &str, token: &str) -> (usize, usize) {
        let lower_token = token.to_ascii_lowercase();
        for (i, line) in content.lines().enumerate() {
            if let Some(col) = line.find(token) {
                return (i + 1, col + 1);
            }
            if let Some(col) = line.to_ascii_lowercase().find(&lower_token) {
                return (i + 1, col + 1);
            }
        }
        (1, 1)
    }

    /// Finds 1-based line and column scoped within a specific job.
    pub fn calculate_step_line_hint(content: &str, job_id: &str, token: &str) -> (usize, usize) {
        let mut in_target_job = false;
        let job_key = format!("{}:", job_id);
        let lower_token = token.to_ascii_lowercase();

        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with(&job_key) {
                in_target_job = true;
                continue;
            }

            if in_target_job {
                // If a new top-level sibling block starts, exit job scope
                if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') {
                    in_target_job = false;
                    continue;
                }

                if let Some(col) = line.find(token) {
                    return (i + 1, col + 1);
                }
                if let Some(col) = line.to_ascii_lowercase().find(&lower_token) {
                    return (i + 1, col + 1);
                }
            }
        }

        Self::calculate_line_hint(content, token)
    }
}
