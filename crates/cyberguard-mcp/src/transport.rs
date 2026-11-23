//! Asynchronous streaming JSON-RPC 2.0 transport implementations for MCP.

#![deny(unsafe_code)]

use crate::error::McpError;
use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::traits::McpTransport;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024; // 8 MB

/// Generic transport implementation wrapping any async reader and writer.
pub struct GenericTransport<R, W> {
    reader: BufReader<R>,
    writer: W,
    max_frame_bytes: usize,
}

impl<R, W> GenericTransport<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send + Sync,
    W: tokio::io::AsyncWrite + Unpin + Send + Sync,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    pub fn with_max_frame_bytes(mut self, max: usize) -> Self {
        self.max_frame_bytes = max;
        self
    }
}

#[async_trait]
impl<R, W> McpTransport for GenericTransport<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send + Sync,
    W: tokio::io::AsyncWrite + Unpin + Send + Sync,
{
    async fn read_request(&mut self) -> Result<Option<JsonRpcRequest>, McpError> {
        loop {
            let mut line = String::new();
            let bytes_read =
                self.reader
                    .read_line(&mut line)
                    .await
                    .map_err(|e| match e.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            McpError::TransportError("EOF".to_string())
                        }
                        _ => McpError::TransportError(e.to_string()),
                    })?;

            if bytes_read == 0 {
                // Clean EOF on stream
                return Ok(None);
            }

            if bytes_read > self.max_frame_bytes {
                return Err(McpError::InvalidRequest(format!(
                    "Frame size ({} bytes) exceeded maximum allowed limit of {} bytes",
                    bytes_read, self.max_frame_bytes
                )));
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                // Skip empty newline frames
                continue;
            }

            let request: JsonRpcRequest = serde_json::from_str(trimmed).map_err(|e| {
                McpError::ParseError(format!("Malformed JSON-RPC request frame: {}", e))
            })?;

            return Ok(Some(request));
        }
    }

    async fn write_response(&mut self, response: &JsonRpcResponse) -> Result<(), McpError> {
        let mut serialized = serde_json::to_string(response)
            .map_err(|e| McpError::InternalError(format!("Serialization failure: {}", e)))?;
        serialized.push('\n');

        self.writer
            .write_all(serialized.as_bytes())
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::BrokenPipe => {
                    McpError::TransportError("Client closed pipe (Broken pipe)".to_string())
                }
                _ => McpError::TransportError(e.to_string()),
            })?;

        self.writer
            .flush()
            .await
            .map_err(|e| McpError::TransportError(e.to_string()))?;

        Ok(())
    }
}

/// Standard I/O (stdin/stdout) transport for production MCP server execution.
pub type StdioTransport = GenericTransport<tokio::io::Stdin, tokio::io::Stdout>;

impl StdioTransport {
    /// Creates a new StdioTransport connected to standard input and standard output.
    pub fn stdio() -> Self {
        GenericTransport::new(tokio::io::stdin(), tokio::io::stdout())
    }
}
