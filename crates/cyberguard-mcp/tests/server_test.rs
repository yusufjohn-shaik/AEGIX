//! End-to-end integration tests for Aegix MCP Server, JSON-RPC Router, and Transports.

#![deny(unsafe_code)]

use cyberguard_mcp::protocol::*;
use cyberguard_mcp::router::McpRouter;
use cyberguard_mcp::server::run_server;
use cyberguard_mcp::traits::McpHandler;
use cyberguard_mcp::transport::GenericTransport;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn test_router_initialize() {
    let router = McpRouter::default();
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Int(1)),
        method: "initialize".to_string(),
        params: Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        })),
    };

    let resp = router
        .handle_request(req)
        .await
        .expect("initialize produces response");
    assert_eq!(resp.id, Some(RequestId::Int(1)));
    assert!(resp.error.is_none());

    let res = resp.result.expect("result object");
    assert_eq!(res["protocolVersion"], "2024-11-05");
    assert_eq!(res["serverInfo"]["name"], "aegix-mcp");
}

#[tokio::test]
async fn test_router_notification_produces_none() {
    let router = McpRouter::default();
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: None,
        method: "notifications/initialized".to_string(),
        params: None,
    };

    let resp = router.handle_request(req).await;
    assert!(
        resp.is_none(),
        "Notifications must never produce a response"
    );
}

#[tokio::test]
async fn test_router_tools_list_and_call() {
    let router = McpRouter::default();

    // 1. tools/list
    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Int(2)),
        method: "tools/list".to_string(),
        params: None,
    };
    let list_resp = router.handle_request(list_req).await.expect("list tools");
    let tools_val = list_resp.result.expect("tools result");
    let tools = tools_val["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 10);

    // 2. tools/call
    let call_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::String("call-1".to_string())),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aegix_explain",
            "arguments": { "rule_id": "CG-CMDI-001" }
        })),
    };
    let call_resp = router.handle_request(call_req).await.expect("call tool");
    let call_res = call_resp.result.expect("call tool result");
    assert_eq!(call_res["isError"], false);
    let text = call_res["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("Command Injection"));
    assert!(text.contains("CWE-78"));
}

#[tokio::test]
async fn test_router_resources_list_and_read() {
    let router = McpRouter::default();

    // 1. resources/list
    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Int(3)),
        method: "resources/list".to_string(),
        params: None,
    };
    let list_resp = router
        .handle_request(list_req)
        .await
        .expect("list resources");
    let res_val = list_resp.result.expect("resources result");
    let resources = res_val["resources"].as_array().expect("resources array");
    assert_eq!(resources.len(), 3);

    // 2. resources/read
    let read_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Int(4)),
        method: "resources/read".to_string(),
        params: Some(json!({
            "uri": "aegix://system-status"
        })),
    };
    let read_resp = router
        .handle_request(read_req)
        .await
        .expect("read resource");
    let read_res = read_resp.result.expect("read result");
    let contents = read_res["contents"].as_array().expect("contents array");
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0]["uri"], "aegix://system-status");
}

#[tokio::test]
async fn test_router_prompts_list_and_get() {
    let router = McpRouter::default();

    // 1. prompts/list
    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Int(5)),
        method: "prompts/list".to_string(),
        params: None,
    };
    let list_resp = router.handle_request(list_req).await.expect("list prompts");
    let p_val = list_resp.result.expect("prompts result");
    let prompts = p_val["prompts"].as_array().expect("prompts array");
    assert_eq!(prompts.len(), 3);

    // 2. prompts/get
    let get_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Int(6)),
        method: "prompts/get".to_string(),
        params: Some(json!({
            "name": "security_audit",
            "arguments": { "path": ".", "focus": "all" }
        })),
    };
    let get_resp = router.handle_request(get_req).await.expect("get prompt");
    let get_res = get_resp.result.expect("get prompt result");
    let msgs = get_res["messages"].as_array().expect("messages");
    assert_eq!(msgs.len(), 1);
}

#[tokio::test]
async fn test_router_method_not_found() {
    let router = McpRouter::default();
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Int(99)),
        method: "non_existent_method".to_string(),
        params: None,
    };

    let resp = router.handle_request(req).await.expect("response");
    assert_eq!(resp.id, Some(RequestId::Int(99)));
    let err = resp.error.expect("error object");
    assert_eq!(err.code, -32601);
}

#[tokio::test]
async fn test_server_event_loop_duplex_e2e() {
    // Setup duplex channels:
    // client_tx -> server_rx (requests)
    // server_tx -> client_rx (responses)
    let (server_rx, mut client_tx) = tokio::io::duplex(64 * 1024);
    let (mut client_rx_raw, server_tx) = tokio::io::duplex(64 * 1024);

    let transport = GenericTransport::new(server_rx, server_tx);
    let router = McpRouter::default();

    // Spawn server in background task
    let server_handle = tokio::spawn(async move { run_server(transport, router).await });

    let mut client_rx = BufReader::new(&mut client_rx_raw);

    // 1. Send initialize request
    let init_frame = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "e2e-agent", "version": "1.0" }
        }
    })
    .to_string();
    client_tx
        .write_all(format!("{}\n", init_frame).as_bytes())
        .await
        .expect("write init");

    // Read initialize response
    let mut resp_line = String::new();
    client_rx
        .read_line(&mut resp_line)
        .await
        .expect("read init response");
    let init_resp: JsonRpcResponse =
        serde_json::from_str(resp_line.trim()).expect("parse init resp");
    assert_eq!(init_resp.id, Some(RequestId::Int(100)));
    assert!(init_resp.error.is_none());

    // 2. Send notification (no response should be written)
    let notif_frame = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })
    .to_string();
    client_tx
        .write_all(format!("{}\n", notif_frame).as_bytes())
        .await
        .expect("write notif");

    // 3. Send ping request
    let ping_frame = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "ping"
    })
    .to_string();
    client_tx
        .write_all(format!("{}\n", ping_frame).as_bytes())
        .await
        .expect("write ping");

    // Read ping response (verifies the notification produced 0 frames)
    resp_line.clear();
    client_rx
        .read_line(&mut resp_line)
        .await
        .expect("read ping response");
    let ping_resp: JsonRpcResponse =
        serde_json::from_str(resp_line.trim()).expect("parse ping resp");
    assert_eq!(ping_resp.id, Some(RequestId::Int(101)));
    assert_eq!(ping_resp.result, Some(json!({})));

    // 4. Send malformed JSON frame
    client_tx
        .write_all(b"{\"jsonrpc\": \"2.0\", MALFORMED\n")
        .await
        .expect("write malformed");
    resp_line.clear();
    client_rx
        .read_line(&mut resp_line)
        .await
        .expect("read parse error");
    let err_resp: JsonRpcResponse = serde_json::from_str(resp_line.trim()).expect("parse err resp");
    assert_eq!(err_resp.error.expect("parse error").code, -32700);

    // 5. Clean EOF: drop client_tx, server terminates gracefully
    drop(client_tx);
    let server_res = server_handle.await.expect("join server");
    assert!(server_res.is_ok(), "Server must exit cleanly on EOF");
}
