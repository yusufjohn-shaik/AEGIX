//! Catalog providers for MCP Resources and Prompt Templates.

#![deny(unsafe_code)]

pub mod prompts;
pub mod resources;

pub use prompts::{
    AegixPromptCatalog, PROMPT_FIX_VULNERABILITY, PROMPT_SECURITY_AUDIT, PROMPT_THREAT_MODEL_REVIEW,
};
pub use resources::{AegixResourceCatalog, URI_ATTACK_MATRIX, URI_RULES, URI_SYSTEM_STATUS};
