#![deny(unsafe_code)]

use cyberguard_mcp::error::{
    JsonRpcError, McpError, CODE_INVALID_PARAMS, CODE_METHOD_NOT_FOUND, CODE_PARSE_ERROR,
};
use cyberguard_mcp::protocol::{
    CallToolResult, Implementation, InitializeResult, JsonRpcRequest, JsonRpcResponse,
    PromptMessage, ReadResourceResult, RequestId, ResourceContents, ServerCapabilities,
    ToolContent, MCP_PROTOCOL_VERSION,
};
use serde_json::json;

#[test]
fn test_request_id_serde() {
    let int_id = RequestId::Int(42);
    let str_id = RequestId::String("abc-123".to_string());

    let json_int = serde_json::to_string(&int_id).unwrap();
    let json_str = serde_json::to_string(&str_id).unwrap();

    assert_eq!(json_int, "42");
    assert_eq!(json_str, "\"abc-123\"");

    let de_int: RequestId = serde_json::from_str("100").unwrap();
    let de_str: RequestId = serde_json::from_str("\"req-99\"").unwrap();

    assert_eq!(de_int, RequestId::Int(100));
    assert_eq!(de_str, RequestId::String("req-99".to_string()));
}

#[test]
fn test_jsonrpc_request_and_notification() {
    let req_json = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let req: JsonRpcRequest = serde_json::from_str(req_json).unwrap();
    assert_eq!(req.jsonrpc, "2.0");
    assert_eq!(req.id, Some(RequestId::Int(1)));
    assert_eq!(req.method, "initialize");
    assert!(!req.is_notification());

    let notif_json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let notif: JsonRpcRequest = serde_json::from_str(notif_json).unwrap();
    assert_eq!(notif.id, None);
    assert!(notif.is_notification());
}

#[test]
fn test_jsonrpc_response_success_and_error() {
    let resp = JsonRpcResponse::success(Some(RequestId::Int(1)), json!({"status": "ok"}));
    let resp_str = serde_json::to_string(&resp).unwrap();
    assert!(resp_str.contains("\"result\":{\"status\":\"ok\"}"));
    assert!(!resp_str.contains("\"error\""));

    let err_resp = JsonRpcResponse::error(
        Some(RequestId::String("req-err".to_string())),
        JsonRpcError {
            code: CODE_METHOD_NOT_FOUND,
            message: "Method not found".to_string(),
            data: None,
        },
    );
    let err_str = serde_json::to_string(&err_resp).unwrap();
    assert!(err_str.contains("\"code\":-32601"));
    assert!(err_str.contains("\"message\":\"Method not found\""));
    assert!(!err_str.contains("\"result\""));
}

#[test]
fn test_mcp_error_code_mapping() {
    assert_eq!(
        McpError::ParseError("invalid".into()).error_code(),
        CODE_PARSE_ERROR
    );
    assert_eq!(
        McpError::MethodNotFound("foo".into()).error_code(),
        CODE_METHOD_NOT_FOUND
    );
    assert_eq!(
        McpError::InvalidParams("bar".into()).error_code(),
        CODE_INVALID_PARAMS
    );

    let json_rpc_err: JsonRpcError = McpError::ParseError("syntax error".into()).into();
    assert_eq!(json_rpc_err.code, CODE_PARSE_ERROR);
    assert!(json_rpc_err.message.contains("syntax error"));
}

#[test]
fn test_initialize_result_serde() {
    let init = InitializeResult {
        protocol_version: MCP_PROTOCOL_VERSION.to_string(),
        capabilities: ServerCapabilities::default(),
        server_info: Implementation {
            name: "aegix-mcp".to_string(),
            version: "0.9.0".to_string(),
        },
        instructions: Some("Security scanner".to_string()),
    };

    let serialized = serde_json::to_string(&init).unwrap();
    assert!(serialized.contains("\"protocolVersion\":\"2024-11-05\""));
    assert!(serialized.contains("\"name\":\"aegix-mcp\""));

    let deserialized: InitializeResult = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.server_info.name, "aegix-mcp");
}

#[test]
fn test_call_tool_result_constructors() {
    let success = CallToolResult::success("scan results".to_string());
    assert!(!success.is_error);
    assert_eq!(success.content.len(), 1);
    match &success.content[0] {
        ToolContent::Text { text } => assert_eq!(text, "scan results"),
    }

    let fail = CallToolResult::failure("target not found".to_string());
    assert!(fail.is_error);
    match &fail.content[0] {
        ToolContent::Text { text } => assert_eq!(text, "target not found"),
    }
}

#[test]
fn test_resource_and_prompt_results_serde() {
    let res = ReadResourceResult {
        contents: vec![ResourceContents {
            uri: "aegix://system-status".to_string(),
            mime_type: Some("application/json".to_string()),
            text: "{\"status\":\"healthy\"}".to_string(),
        }],
    };
    let res_str = serde_json::to_string(&res).unwrap();
    assert!(res_str.contains("\"uri\":\"aegix://system-status\""));

    let prompt = cyberguard_mcp::protocol::GetPromptResult {
        description: Some("Security audit".to_string()),
        messages: vec![PromptMessage {
            role: "user".to_string(),
            content: ToolContent::Text {
                text: "Run aegix scan".to_string(),
            },
        }],
    };
    let prompt_str = serde_json::to_string(&prompt).unwrap();
    assert!(prompt_str.contains("\"role\":\"user\""));
}
