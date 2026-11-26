pub mod command;
pub mod path;
pub mod secret;
pub mod sql;

use crate::error::FixError;
use crate::models::{ParsedSourceFile, SurgicalPatch, TaintFlowPath, TaintSinkKind};
use crate::traits::PatchSynthesizer;

#[derive(Debug, Default, Clone)]
pub struct DefaultPatchSynthesizer;

impl DefaultPatchSynthesizer {
    pub fn new() -> Self {
        Self
    }
}

impl PatchSynthesizer for DefaultPatchSynthesizer {
    fn synthesize(
        &self,
        taint: &TaintFlowPath,
        ast: &ParsedSourceFile,
    ) -> Result<Option<SurgicalPatch>, FixError> {
        // If taint is already sanitized, no patch needed
        if taint.is_sanitized {
            return Ok(None);
        }

        match taint.sink_kind {
            TaintSinkKind::SqlExecution => sql::synthesize_sql_patch(taint, ast),
            TaintSinkKind::CommandExecution => command::synthesize_command_patch(taint, ast),
            TaintSinkKind::PathTraversal => path::synthesize_path_patch(taint, ast),
            TaintSinkKind::HardcodedSecret => secret::synthesize_secret_patch(taint, ast),
        }
    }
}
