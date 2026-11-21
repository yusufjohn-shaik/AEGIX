use crate::error::PipelineError;
use crate::models::{
    PipelineDocument, PipelineFinding, PipelineReport, SlsaStatement, WorkflowDefinition,
};
use async_trait::async_trait;
use std::io::Read;
use std::path::Path;

/// Primary orchestrator trait for CI/CD Pipeline & SLSA static scanning.
#[async_trait]
pub trait PipelineScanner: Send + Sync {
    /// Evaluates pre-parsed pipeline documents in memory.
    async fn scan(&self, documents: &[PipelineDocument]) -> Result<PipelineReport, PipelineError>;

    /// Reads, parses, and evaluates a workflow or provenance file from the local filesystem.
    async fn scan_file(
        &self,
        path: &Path,
        artifact_path: Option<&Path>,
    ) -> Result<PipelineReport, PipelineError>;

    /// Traverses a directory recursively and evaluates all workflow and provenance files.
    async fn scan_directory(&self, dir_path: &Path) -> Result<PipelineReport, PipelineError>;

    /// Ingests and evaluates pipeline configuration from a generic reader stream (e.g. STDIN).
    async fn scan_reader(
        &self,
        reader: &mut (dyn Read + Send),
        path_hint: &Path,
    ) -> Result<PipelineReport, PipelineError>;
}

/// Static security auditor for CI/CD workflow definitions (GitHub Actions, GitLab CI).
pub trait WorkflowAuditor: Send + Sync {
    /// Audits a parsed workflow against rules CG-PIPE-001 through CG-PIPE-006.
    fn audit_workflow(
        &self,
        workflow: &WorkflowDefinition,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<PipelineFinding>, PipelineError>;
}

/// Static security auditor for SLSA provenance attestations.
pub trait SlsaAuditor: Send + Sync {
    /// Audits a parsed SLSA in-toto statement against rules CG-PIPE-007 through CG-PIPE-010.
    fn audit_slsa(
        &self,
        statement: &SlsaStatement,
        file_path: &str,
        raw_content: &str,
        target_artifact_digest: Option<&str>,
        trusted_builders: &[String],
        expected_source_repo: Option<&str>,
    ) -> Result<Vec<PipelineFinding>, PipelineError>;
}
