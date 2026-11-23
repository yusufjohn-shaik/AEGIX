//! cyberguard-mcp: Model Context Protocol (MCP v2024-11-05) Server for Aegix.
//!
//! Provides a standard JSON-RPC 2.0 stdio server enabling Claude Code, Cursor,
//! Antigravity, and autonomous AI agents to execute security scans and query
//! threat intelligence.

#![deny(unsafe_code)]

pub mod error;
pub mod protocol;
pub mod traits;

pub use error::*;
pub use protocol::*;
pub use traits::*;
