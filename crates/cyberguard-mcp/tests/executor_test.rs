//! Integration and unit tests for Aegix MCP Tool Schemas and Multi-Engine Facade.

#![deny(unsafe_code)]

use cyberguard_mcp::executor::AegixEngineFacade;
use cyberguard_mcp::protocol::ToolContent;
use cyberguard_mcp::traits::ToolExecutor;
use serde_json::json;
use std::fs;

#[tokio::test]
async fn test_list_tools_schema_catalog() {
    let facade = AegixEngineFacade::new();
    let tools = facade.list_tools();

    assert_eq!(tools.len(), 10);

    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(tool_names.contains(&"aegix_scan"));
    assert!(tool_names.contains(&"aegix_sast"));
    assert!(tool_names.contains(&"aegix_secrets"));
    assert!(tool_names.contains(&"aegix_sca"));
    assert!(tool_names.contains(&"aegix_iac"));
    assert!(tool_names.contains(&"aegix_pipeline"));
    assert!(tool_names.contains(&"aegix_mobile"));
    assert!(tool_names.contains(&"aegix_threat"));
    assert!(tool_names.contains(&"aegix_graph"));
    assert!(tool_names.contains(&"aegix_explain"));

    for tool in &tools {
        assert!(tool.description.is_some());
        assert_eq!(tool.input_schema["type"], "object");
        assert!(tool.input_schema.get("properties").is_some());
    }
}

#[tokio::test]
async fn test_call_tool_unknown_name() {
    let facade = AegixEngineFacade::new();
    let res = facade
        .call_tool("unknown_tool_xyz", None)
        .await
        .expect("facade call returns Ok");

    assert!(res.is_error);
    match &res.content[0] {
        ToolContent::Text { text } => assert!(text.contains("Unknown Aegix tool")),
    }
}

#[tokio::test]
async fn test_call_tool_nonexistent_path() {
    let facade = AegixEngineFacade::new();
    let args = json!({
        "path": "/path/does/not/exist/surely/123456"
    })
    .as_object()
    .cloned();

    let res = facade
        .call_tool("aegix_sast", args)
        .await
        .expect("facade call returns Ok");

    assert!(res.is_error);
    match &res.content[0] {
        ToolContent::Text { text } => {
            assert!(text.contains("does not exist"));
        }
    }
}

#[tokio::test]
async fn test_call_explain_rule() {
    let facade = AegixEngineFacade::new();

    // Valid rule ID
    let args = json!({ "rule_id": "CG-SQLI-001" }).as_object().cloned();
    let res = facade
        .call_tool("aegix_explain", args)
        .await
        .expect("call explain");
    assert!(!res.is_error);
    match &res.content[0] {
        ToolContent::Text { text } => {
            assert!(text.contains("SQL Injection"));
            assert!(text.contains("CWE-89"));
            assert!(text.contains("Remediation Guidance"));
        }
    }

    // Missing rule_id
    let res_missing = facade
        .call_tool("aegix_explain", None)
        .await
        .expect("call explain");
    assert!(res_missing.is_error);

    // Fallback rule
    let args_other = json!({ "rule_id": "CUSTOM-999" }).as_object().cloned();
    let res_other = facade
        .call_tool("aegix_explain", args_other)
        .await
        .expect("call explain");
    assert!(!res_other.is_error);
    match &res_other.content[0] {
        ToolContent::Text { text } => {
            assert!(text.contains("CUSTOM-999"));
        }
    }
}

#[tokio::test]
async fn test_call_sast_and_secrets_on_fixtures() {
    let facade = AegixEngineFacade::new();
    let temp_dir = std::env::temp_dir().join(format!("aegix_mcp_exec_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create test dir");

    // 1. Create a file with SQL injection and command injection
    let code_file = temp_dir.join("app.py");
    fs::write(
        &code_file,
        r#"
def handler(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    import os
    os.system("echo " + user_input)
"#,
    )
    .expect("write test file");

    // Test aegix_sast
    let args_sast = json!({
        "path": temp_dir.to_str().unwrap()
    })
    .as_object()
    .cloned();

    let res_sast = facade
        .call_tool("aegix_sast", args_sast)
        .await
        .expect("sast call");
    assert!(!res_sast.is_error);
    match &res_sast.content[0] {
        ToolContent::Text { text } => {
            assert!(text.contains("Aegix Scan Report"));
            assert!(text.contains("CG-SQLI-001") || text.contains("CG-CMDI-001"));
        }
    }

    // 2. Create a file with secret token
    let secret_file = temp_dir.join("keys.env");
    fs::write(
        &secret_file,
        "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .expect("write secret file");

    // Test aegix_secrets
    let args_sec = json!({
        "path": temp_dir.to_str().unwrap()
    })
    .as_object()
    .cloned();

    let res_sec = facade
        .call_tool("aegix_secrets", args_sec)
        .await
        .expect("secrets call");
    assert!(!res_sec.is_error);
    match &res_sec.content[0] {
        ToolContent::Text { text } => {
            assert!(text.contains("Aegix Scan Report"));
            assert!(text.contains("CG-SEC-GITHUB-001"));
        }
    }

    // 3. Test aegix_scan (multi-engine)
    let args_scan = json!({
        "path": temp_dir.to_str().unwrap()
    })
    .as_object()
    .cloned();

    let res_scan = facade
        .call_tool("aegix_scan", args_scan)
        .await
        .expect("scan call");
    assert!(!res_scan.is_error);
    match &res_scan.content[0] {
        ToolContent::Text { text } => {
            assert!(text.contains("Aegix Scan Report"));
            assert!(text.contains("CG-SQLI-001") || text.contains("CG-SEC-GITHUB-001"));
        }
    }

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}
