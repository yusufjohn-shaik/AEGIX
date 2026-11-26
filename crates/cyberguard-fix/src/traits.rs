use crate::error::FixError;
use crate::models::{
    EradicationTest, FixScanOptions, ParsedSourceFile, RemediationExecutionResult, RemediationPlan,
    SourceLanguage, SurgicalPatch, TaintFlowPath,
};
use async_trait::async_trait;
use cyberguard_core::sarif::SarifLog;
use std::path::Path;

pub trait AstParser: Send + Sync {
    fn parse(
        &self,
        path: &Path,
        content: &str,
        lang: SourceLanguage,
    ) -> Result<ParsedSourceFile, FixError>;
}

pub trait TaintAnalyzer: Send + Sync {
    fn analyze(&self, ast: &ParsedSourceFile) -> Result<Vec<TaintFlowPath>, FixError>;
}

pub trait PatchSynthesizer: Send + Sync {
    fn synthesize(
        &self,
        taint: &TaintFlowPath,
        ast: &ParsedSourceFile,
    ) -> Result<Option<SurgicalPatch>, FixError>;
}

pub trait TestGenerator: Send + Sync {
    fn generate_test(
        &self,
        patch: &SurgicalPatch,
        lang: SourceLanguage,
    ) -> Result<EradicationTest, FixError>;
}

#[async_trait]
pub trait RemediationEngine: Send + Sync {
    async fn plan_path(
        &self,
        target: &Path,
        options: &FixScanOptions,
    ) -> Result<RemediationPlan, FixError>;

    async fn plan_sarif(
        &self,
        target: &Path,
        sarif: &SarifLog,
        options: &FixScanOptions,
    ) -> Result<RemediationPlan, FixError>;

    async fn apply_plan(
        &self,
        plan: &RemediationPlan,
    ) -> Result<RemediationExecutionResult, FixError>;
}
