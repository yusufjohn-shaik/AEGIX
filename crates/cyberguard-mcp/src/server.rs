//! Main MCP server event loop and stdio runner.

#![deny(unsafe_code)]

use crate::error::{JsonRpcError, McpError};
use crate::protocol::JsonRpcResponse;
use crate::router::McpRouter;
use crate::traits::{McpHandler, McpTransport};
use crate::transport::StdioTransport;

/// Executes the main MCP JSON-RPC event loop over the provided transport and handler.
pub async fn run_server<T: McpTransport, H: McpHandler>(
    mut transport: T,
    handler: H,
) -> Result<(), McpError> {
    tracing::info!("Starting Aegix MCP server event loop");

    loop {
        match transport.read_request().await {
            Ok(Some(request)) => {
                let maybe_response = handler.handle_request(request).await;
                if let Some(response) = maybe_response {
                    transport.write_response(&response).await?;
                }
            }
            Ok(None) => {
                tracing::info!("Received clean EOF on transport; exiting event loop");
                break;
            }
            Err(McpError::ParseError(msg)) => {
                tracing::warn!("JSON-RPC parse error: {}", msg);
                let error_resp = JsonRpcResponse::error(None, JsonRpcError::parse_error(msg));
                transport.write_response(&error_resp).await?;
            }
            Err(McpError::TransportError(msg)) => {
                tracing::warn!("Transport disconnected ({}); stopping server", msg);
                break;
            }
            Err(e) => {
                tracing::error!("Unexpected MCP server error: {}", e);
                return Err(e);
            }
        }
    }

    tracing::info!("Aegix MCP server stopped gracefully");
    Ok(())
}

/// Convenience runner executing the standard Aegix MCP server over stdio.
pub async fn run_stdio_server() -> Result<(), McpError> {
    let transport = StdioTransport::stdio();
    let handler = McpRouter::default();
    run_server(transport, handler).await
}
