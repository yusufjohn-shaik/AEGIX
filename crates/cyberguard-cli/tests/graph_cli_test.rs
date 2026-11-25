//! Integration tests for `aegix trace` CLI subcommand and MCP `aegix_graph` tool.

#![deny(unsafe_code)]

use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use std::io::Write;
use std::process::{Command, Stdio};

fn get_temp_file(prefix: &str) -> std::path::PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{}-{}.json", prefix, now))
}

#[test]
fn test_aegix_trace_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("trace")
        .arg("--help")
        .output()
        .expect("Failed to execute aegix trace --help");

    assert!(output.status.success());
    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(help_text.contains("--input"));
    assert!(help_text.contains("--format"));
    assert!(help_text.contains("--output"));
    assert!(help_text.contains("--max-depth"));
    assert!(help_text.contains("--min-risk"));
    assert!(help_text.contains("--fail-on"));
    assert!(help_text.contains("--baseline"));
}

#[test]
fn test_aegix_trace_cli_json_export_with_input() {
    let sarif_path = get_temp_file("telemetry-json-test");

    let mut sarif = SarifLog::new("cyberguard-net", "0.9.0");

    let mut net_res = SarifResult::new(
        "NET-PORT-443",
        SarifLevel::Warning,
        "Public HTTPS entrypoint exposed",
    );
    net_res.add_location("https://api.example.com", 1, None, None, None);
    sarif.add_result(net_res);

    let mut sast_res = SarifResult::new(
        "SAST-SQLI-001",
        SarifLevel::Error,
        "Critical SQL injection vulnerability",
    );
    sast_res.add_location("src/api/auth.rs", 45, None, None, None);
    sast_res.with_tri_factor(9.5, 0.95, 0.9);
    sarif.add_result(sast_res);

    let mut sec_res = SarifResult::new(
        "SEC-AWS-KEY",
        SarifLevel::Error,
        "Hardcoded AWS production secret key",
    );
    sec_res.add_location("config/aws.env", 3, None, None, None);
    sec_res.with_tri_factor(9.0, 0.9, 0.9);
    sarif.add_result(sec_res);

    std::fs::write(&sarif_path, serde_json::to_string(&sarif).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("trace")
        .arg("--input")
        .arg(&sarif_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("Failed to execute aegix trace");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("output must be valid JSON");

    assert!(val.get("graph").is_some());
    assert!(val.get("paths").is_some());
    assert!(val.get("choke_points").is_some());
    assert!(val.get("summary").is_some());

    let summary = &val["summary"];
    assert!(summary["total_nodes"].as_u64().unwrap() >= 3);
    assert!(summary["discovered_paths"].as_u64().unwrap() >= 1);

    let _ = std::fs::remove_file(sarif_path);
}

#[test]
fn test_aegix_trace_cli_mermaid_format() {
    let sarif_path = get_temp_file("telemetry-mermaid-test");

    let mut sarif = SarifLog::new("cyberguard-net", "0.9.0");
    let net_res = SarifResult::new("NET-PORT-80", SarifLevel::Warning, "HTTP ingress port open");
    sarif.add_result(net_res);

    std::fs::write(&sarif_path, serde_json::to_string(&sarif).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("trace")
        .arg("--input")
        .arg(&sarif_path)
        .arg("--format")
        .arg("mermaid")
        .output()
        .expect("Failed to execute aegix trace");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("```mermaid\nflowchart LR"));

    let _ = std::fs::remove_file(sarif_path);
}

#[test]
fn test_aegix_mcp_lists_graph_tool() {
    use std::io::{BufRead, BufReader};

    let mut child = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn aegix mcp process");

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    // Initialize
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "cli-test", "version": "1.0.0" }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&init_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();

    // Tools/list
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    writeln!(stdin, "{}", serde_json::to_string(&tools_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let tools_resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

    let tools = tools_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    let has_graph = tools.iter().any(|t| t["name"] == "aegix_graph");
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        has_graph,
        "aegix_graph tool must be present in tools catalog"
    );
}
