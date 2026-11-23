//! Trait definitions establishing contracts for MCP transport, tools, resources, and prompts.

#![deny(unsafe_code)]

use crate::error::McpError;
use crate::protocol::*;
use async_trait::async_trait;
use std::collections::HashMap;

/// Low-level streaming transport for JSON-RPC 2.0 communication.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Read the next incoming JSON-RPC request frame. Returns `Ok(None)` upon EOF.
    async fn read_request(&mut self) -> Result<Option<JsonRpcRequest>, McpError>;

    /// Write an outgoing JSON-RPC response frame.
    async fn write_response(&mut self, response: &JsonRpcResponse) -> Result<(), McpError>;
}

/// Pluggable executor for Aegix security tools.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    /// Returns the schema catalogue of registered tools.
    fn list_tools(&self) -> Vec<Tool>;

    /// Executes a tool by name with arguments.
    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<CallToolResult, McpError>;
}

/// Provider for contextual reference resources (rules, threat catalog, status).
#[async_trait]
pub trait ResourceProvider: Send + Sync {
    /// Lists all available resources.
    fn list_resources(&self) -> Vec<Resource>;

    /// Reads content of a specific resource URI.
    async fn read_resource(&self, uri: &str) -> Result<ReadResourceResult, McpError>;
}

/// Catalog provider for structured prompt templates.
#[async_trait]
pub trait PromptProvider: Send + Sync {
    /// Lists all available prompts.
    fn list_prompts(&self) -> Vec<Prompt>;

    /// Retrieves an expanded prompt template with injected arguments.
    async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<HashMap<String, String>>,
    ) -> Result<GetPromptResult, McpError>;
}

/// Central JSON-RPC method router and protocol handler.
#[async_trait]
pub trait McpHandler: Send + Sync {
    /// Dispatches a request. Returns `None` if the incoming message was a notification.
    async fn handle_request(&self, request: JsonRpcRequest) -> Option<JsonRpcResponse>;
}
