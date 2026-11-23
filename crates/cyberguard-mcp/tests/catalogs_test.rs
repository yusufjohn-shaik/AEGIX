//! Integration and unit tests for Aegix MCP Resources and Prompts Catalogs.

#![deny(unsafe_code)]

use cyberguard_mcp::catalogs::{
    AegixPromptCatalog, AegixResourceCatalog, PROMPT_FIX_VULNERABILITY, PROMPT_SECURITY_AUDIT,
    PROMPT_THREAT_MODEL_REVIEW, URI_ATTACK_MATRIX, URI_RULES, URI_SYSTEM_STATUS,
};
use cyberguard_mcp::error::McpError;
use cyberguard_mcp::protocol::ToolContent;
use cyberguard_mcp::traits::{PromptProvider, ResourceProvider};
use std::collections::HashMap;

#[tokio::test]
async fn test_list_resources() {
    let catalog = AegixResourceCatalog::new();
    let resources = catalog.list_resources();

    assert_eq!(resources.len(), 3);
    let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&URI_RULES));
    assert!(uris.contains(&URI_ATTACK_MATRIX));
    assert!(uris.contains(&URI_SYSTEM_STATUS));
}

#[tokio::test]
async fn test_read_resource_rules() {
    let catalog = AegixResourceCatalog::new();
    let res = catalog
        .read_resource(URI_RULES)
        .await
        .expect("read rules resource");

    assert_eq!(res.contents.len(), 1);
    assert_eq!(res.contents[0].uri, URI_RULES);
    assert_eq!(
        res.contents[0].mime_type.as_deref(),
        Some("application/json")
    );

    let json_val: serde_json::Value =
        serde_json::from_str(&res.contents[0].text).expect("valid json");
    assert!(json_val.get("engines").is_some());
    let engines = json_val["engines"].as_array().expect("engines array");
    assert!(!engines.is_empty());
}

#[tokio::test]
async fn test_read_resource_attack_matrix() {
    let catalog = AegixResourceCatalog::new();
    let res = catalog
        .read_resource(URI_ATTACK_MATRIX)
        .await
        .expect("read attack matrix");

    let json_val: serde_json::Value =
        serde_json::from_str(&res.contents[0].text).expect("valid json");
    assert!(json_val.get("tactics").is_some());
    assert!(json_val.get("techniques").is_some());
}

#[tokio::test]
async fn test_read_resource_system_status() {
    let catalog = AegixResourceCatalog::new();
    let res = catalog
        .read_resource(URI_SYSTEM_STATUS)
        .await
        .expect("read status");

    let json_val: serde_json::Value =
        serde_json::from_str(&res.contents[0].text).expect("valid json");
    assert_eq!(json_val["airGappedOffline"], true);
    assert_eq!(json_val["runtimeNetworkCalls"], 0);
    assert!(json_val["activeEngines"].is_array());
}

#[tokio::test]
async fn test_read_resource_unknown() {
    let catalog = AegixResourceCatalog::new();
    let err = catalog
        .read_resource("aegix://unknown-uri")
        .await
        .unwrap_err();

    match err {
        McpError::ResourceNotFound(uri) => assert_eq!(uri, "aegix://unknown-uri"),
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn test_list_prompts() {
    let catalog = AegixPromptCatalog::new();
    let prompts = catalog.list_prompts();

    assert_eq!(prompts.len(), 3);
    let names: Vec<&str> = prompts.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&PROMPT_SECURITY_AUDIT));
    assert!(names.contains(&PROMPT_FIX_VULNERABILITY));
    assert!(names.contains(&PROMPT_THREAT_MODEL_REVIEW));
}

#[tokio::test]
async fn test_get_prompt_security_audit() {
    let catalog = AegixPromptCatalog::new();

    let mut args = HashMap::new();
    args.insert("path".to_string(), "crates/cyberguard-core".to_string());
    args.insert("focus".to_string(), "sast".to_string());

    let res = catalog
        .get_prompt(PROMPT_SECURITY_AUDIT, Some(args))
        .await
        .expect("get prompt");

    assert_eq!(res.messages.len(), 1);
    match &res.messages[0].content {
        ToolContent::Text { text } => {
            assert!(text.contains("crates/cyberguard-core"));
            assert!(text.contains("aegix_sast"));
        }
    }
}

#[tokio::test]
async fn test_get_prompt_fix_vulnerability() {
    let catalog = AegixPromptCatalog::new();

    // Missing required args
    let err = catalog
        .get_prompt(PROMPT_FIX_VULNERABILITY, None)
        .await
        .unwrap_err();
    match err {
        McpError::InvalidParams(msg) => assert!(msg.contains("Missing required argument")),
        other => panic!("Unexpected error: {:?}", other),
    }

    // Valid args
    let mut args = HashMap::new();
    args.insert("rule_id".to_string(), "CG-SQLI-001".to_string());
    args.insert("file_path".to_string(), "src/db.rs".to_string());
    args.insert("line_number".to_string(), "42".to_string());

    let res = catalog
        .get_prompt(PROMPT_FIX_VULNERABILITY, Some(args))
        .await
        .expect("get prompt");

    match &res.messages[0].content {
        ToolContent::Text { text } => {
            assert!(text.contains("CG-SQLI-001"));
            assert!(text.contains("src/db.rs"));
            assert!(text.contains("line 42"));
        }
    }
}

#[tokio::test]
async fn test_get_prompt_threat_model_review() {
    let catalog = AegixPromptCatalog::new();

    let mut args = HashMap::new();
    args.insert("path".to_string(), "deploy/k8s".to_string());
    args.insert("domain".to_string(), "cloud".to_string());

    let res = catalog
        .get_prompt(PROMPT_THREAT_MODEL_REVIEW, Some(args))
        .await
        .expect("get prompt");

    match &res.messages[0].content {
        ToolContent::Text { text } => {
            assert!(text.contains("deploy/k8s"));
            assert!(text.contains("cloud"));
            assert!(text.contains("STRIDE"));
        }
    }
}

#[tokio::test]
async fn test_get_prompt_unknown() {
    let catalog = AegixPromptCatalog::new();
    let err = catalog
        .get_prompt("unknown_prompt_xyz", None)
        .await
        .unwrap_err();

    match err {
        McpError::PromptNotFound(name) => assert_eq!(name, "unknown_prompt_xyz"),
        other => panic!("Unexpected error: {:?}", other),
    }
}
