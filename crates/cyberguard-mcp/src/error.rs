//! Strongly typed error taxonomy for MCP JSON-RPC 2.0 protocol and handlers.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standard JSON-RPC 2.0 and MCP protocol error codes.
pub const CODE_PARSE_ERROR: i32 = -32700;
pub const CODE_INVALID_REQUEST: i32 = -32600;
pub const CODE_METHOD_NOT_FOUND: i32 = -32601;
pub const CODE_INVALID_PARAMS: i32 = -32602;
pub const CODE_INTERNAL_ERROR: i32 = -32603;

pub const CODE_RESOURCE_NOT_FOUND: i32 = -32001;
pub const CODE_PROMPT_NOT_FOUND: i32 = -32002;
pub const CODE_TRANSPORT_ERROR: i32 = -32003;

#[derive(Error, Debug)]
pub enum McpError {
    #[error("JSON-RPC parse error: {0}")]
    ParseError(String),

    #[error("Invalid JSON-RPC request: {0}")]
    InvalidRequest(String),

    #[error("Method not found: '{0}'")]
    MethodNotFound(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Tool not found: '{0}'")]
    ToolNotFound(String),

    #[error("Resource not found: '{0}'")]
    ResourceNotFound(String),

    #[error("Prompt template not found: '{0}'")]
    PromptNotFound(String),

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Transport I/O error: {0}")]
    Transport(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl McpError {
    /// Returns the deterministic JSON-RPC 2.0 error code.
    pub fn error_code(&self) -> i32 {
        match self {
            Self::ParseError(_) => CODE_PARSE_ERROR,
            Self::InvalidRequest(_) => CODE_INVALID_REQUEST,
            Self::MethodNotFound(_) | Self::ToolNotFound(_) => CODE_METHOD_NOT_FOUND,
            Self::InvalidParams(_) => CODE_INVALID_PARAMS,
            Self::InternalError(_) | Self::Serialization(_) => CODE_INTERNAL_ERROR,
            Self::ResourceNotFound(_) => CODE_RESOURCE_NOT_FOUND,
            Self::PromptNotFound(_) => CODE_PROMPT_NOT_FOUND,
            Self::TransportError(_) | Self::Transport(_) => CODE_TRANSPORT_ERROR,
        }
    }
}

/// Strongly typed JSON-RPC 2.0 Error Object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new(CODE_PARSE_ERROR, message)
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(CODE_INVALID_REQUEST, message)
    }

    pub fn method_not_found(message: impl Into<String>) -> Self {
        Self::new(CODE_METHOD_NOT_FOUND, message)
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(CODE_INVALID_PARAMS, message)
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(CODE_INTERNAL_ERROR, message)
    }
}

impl From<McpError> for JsonRpcError {
    fn from(err: McpError) -> Self {
        Self {
            code: err.error_code(),
            message: err.to_string(),
            data: None,
        }
    }
}
