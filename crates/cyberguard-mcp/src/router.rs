//! Central JSON-RPC 2.0 message router and MCP protocol handler.

#![deny(unsafe_code)]

use crate::catalogs::{AegixPromptCatalog, AegixResourceCatalog};
use crate::error::JsonRpcError;
use crate::executor::AegixEngineFacade;
use crate::protocol::*;
use crate::traits::{McpHandler, PromptProvider, ResourceProvider, ToolExecutor};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// Core JSON-RPC 2.0 message router for Aegix MCP.
#[derive(Clone)]
pub struct McpRouter {
    tool_executor: Arc<dyn ToolExecutor>,
    resource_provider: Arc<dyn ResourceProvider>,
    prompt_provider: Arc<dyn PromptProvider>,
}

impl Default for McpRouter {
    fn default() -> Self {
        Self::new(
            Arc::new(AegixEngineFacade::new()),
            Arc::new(AegixResourceCatalog::new()),
            Arc::new(AegixPromptCatalog::new()),
        )
    }
}

impl McpRouter {
    /// Constructs a router with explicit providers.
    pub fn new(
        tool_executor: Arc<dyn ToolExecutor>,
        resource_provider: Arc<dyn ResourceProvider>,
        prompt_provider: Arc<dyn PromptProvider>,
    ) -> Self {
        Self {
            tool_executor,
            resource_provider,
            prompt_provider,
        }
    }

    /// Handles the MCP lifecycle `initialize` method.
    fn handle_initialize(&self, id: Option<RequestId>) -> JsonRpcResponse {
        let result = InitializeResult {
            protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities {
                tools: ToolsCapability { list_changed: false },
                resources: ResourcesCapability {
                    subscribe: false,
                    list_changed: false,
                },
                prompts: PromptsCapability { list_changed: false },
            },
            server_info: Implementation {
                name: "aegix-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "Aegix Autonomous Security Intelligence MCP Server. Provides static analysis, secret leak discovery, SCA, IaC auditing, CI/CD pipeline verification, and MITRE ATT&CK threat modeling.".to_string(),
            ),
        };

        JsonRpcResponse::success(id, json!(result))
    }

    /// Handles `tools/list`.
    fn handle_tools_list(&self, id: Option<RequestId>) -> JsonRpcResponse {
        let tools = self.tool_executor.list_tools();
        let result = ListToolsResult {
            tools,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, json!(result))
    }

    /// Handles `tools/call`.
    async fn handle_tools_call(
        &self,
        id: Option<RequestId>,
        params: Option<serde_json::Value>,
    ) -> JsonRpcResponse {
        let call_params: CallToolParams = match params {
            Some(v) => match serde_json::from_value(v) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params(format!("Invalid tools/call params: {}", e)),
                    );
                }
            },
            None => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("Missing params object for tools/call"),
                );
            }
        };

        match self
            .tool_executor
            .call_tool(&call_params.name, call_params.arguments)
            .await
        {
            Ok(tool_result) => JsonRpcResponse::success(id, json!(tool_result)),
            Err(e) => JsonRpcResponse::error(id, e.into()),
        }
    }

    /// Handles `resources/list`.
    fn handle_resources_list(&self, id: Option<RequestId>) -> JsonRpcResponse {
        let resources = self.resource_provider.list_resources();
        let result = ListResourcesResult {
            resources,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, json!(result))
    }

    /// Handles `resources/read`.
    async fn handle_resources_read(
        &self,
        id: Option<RequestId>,
        params: Option<serde_json::Value>,
    ) -> JsonRpcResponse {
        let read_params: ReadResourceParams = match params {
            Some(v) => match serde_json::from_value(v) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params(format!(
                            "Invalid resources/read params: {}",
                            e
                        )),
                    );
                }
            },
            None => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("Missing params object for resources/read"),
                );
            }
        };

        match self.resource_provider.read_resource(&read_params.uri).await {
            Ok(read_result) => JsonRpcResponse::success(id, json!(read_result)),
            Err(e) => JsonRpcResponse::error(id, e.into()),
        }
    }

    /// Handles `prompts/list`.
    fn handle_prompts_list(&self, id: Option<RequestId>) -> JsonRpcResponse {
        let prompts = self.prompt_provider.list_prompts();
        let result = ListPromptsResult {
            prompts,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, json!(result))
    }

    /// Handles `prompts/get`.
    async fn handle_prompts_get(
        &self,
        id: Option<RequestId>,
        params: Option<serde_json::Value>,
    ) -> JsonRpcResponse {
        let get_params: GetPromptParams = match params {
            Some(v) => match serde_json::from_value(v) {
                Ok(p) => p,
                Err(e) => {
                    return JsonRpcResponse::error(
                        id,
                        JsonRpcError::invalid_params(format!("Invalid prompts/get params: {}", e)),
                    );
                }
            },
            None => {
                return JsonRpcResponse::error(
                    id,
                    JsonRpcError::invalid_params("Missing params object for prompts/get"),
                );
            }
        };

        match self
            .prompt_provider
            .get_prompt(&get_params.name, get_params.arguments)
            .await
        {
            Ok(prompt_result) => JsonRpcResponse::success(id, json!(prompt_result)),
            Err(e) => JsonRpcResponse::error(id, e.into()),
        }
    }
}

#[async_trait]
impl McpHandler for McpRouter {
    async fn handle_request(&self, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let is_notif = request.is_notification();
        let method = request.method.as_str();

        // 1. Handle notifications (never return a response to client)
        if is_notif || method.starts_with("notifications/") {
            match method {
                "notifications/initialized" => {
                    tracing::info!("Client successfully acknowledged initialization");
                }
                "notifications/cancelled" => {
                    tracing::debug!("Received operation cancellation notification");
                }
                other => {
                    tracing::debug!("Unhandled notification received: '{}'", other);
                }
            }
            return None;
        }

        let id = request.id;

        // 2. Route standard requests
        let response = match method {
            "initialize" => self.handle_initialize(id),
            "ping" => JsonRpcResponse::success(id, json!({})),
            "tools/list" => self.handle_tools_list(id),
            "tools/call" => self.handle_tools_call(id, request.params).await,
            "resources/list" => self.handle_resources_list(id),
            "resources/read" => self.handle_resources_read(id, request.params).await,
            "prompts/list" => self.handle_prompts_list(id),
            "prompts/get" => self.handle_prompts_get(id, request.params).await,
            unknown => JsonRpcResponse::error(
                id,
                JsonRpcError::method_not_found(format!("Method not supported: '{}'", unknown)),
            ),
        };

        Some(response)
    }
}
