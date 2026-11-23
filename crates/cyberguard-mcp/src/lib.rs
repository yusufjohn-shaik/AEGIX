//! cyberguard-mcp: Model Context Protocol (MCP v2024-11-05) Server for Aegix.
//!
//! Provides a standard JSON-RPC 2.0 stdio server enabling Claude Code, Cursor,
//! Antigravity, and autonomous AI agents to execute security scans and query
//! threat intelligence.

#![deny(unsafe_code)]

pub mod catalogs;
pub mod error;
pub mod executor;
pub mod protocol;
pub mod router;
pub mod server;
pub mod traits;
pub mod transport;

pub use catalogs::*;
pub use error::*;
pub use executor::*;
pub use protocol::*;
pub use router::*;
pub use server::*;
pub use traits::*;
pub use transport::*;
