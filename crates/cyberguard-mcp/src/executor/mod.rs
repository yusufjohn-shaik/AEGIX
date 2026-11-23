//! MCP Tool execution engine and schema definitions.

#![deny(unsafe_code)]

pub mod facade;
pub mod schemas;

pub use facade::{AegixEngineFacade, DEFAULT_FINDINGS_LIMIT};
pub use schemas::get_tool_catalog;
