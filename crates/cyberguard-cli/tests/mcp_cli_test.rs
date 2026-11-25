//! Integration test verifying `aegix mcp` subcommand wire protocol purity and stdio execution.

#![deny(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn test_aegix_mcp_cli_stdio_wire_purity() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn aegix mcp process");

    let mut stdin = child.stdin.take().expect("Failed to open child stdin");
    let stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut reader = BufReader::new(stdout);

    // 1. Send initialize request
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
    writeln!(stdin, "{}", serde_json::to_string(&init_req).unwrap()).expect("write init");
    stdin.flush().expect("flush stdin");

    // Read initialize response
    let mut line = String::new();
    reader.read_line(&mut line).expect("read line from stdout");
    let trimmed = line.trim();

    // Verify stdout wire purity: MUST start with '{' and be valid JSON
    assert!(
        trimmed.starts_with('{'),
        "Stdout polluted! First character must be '{{', got: '{}'",
        trimmed
    );
    let init_resp: serde_json::Value =
        serde_json::from_str(trimmed).expect("Stdout must be pure valid JSON");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "aegix-mcp");

    // 2. Send tools/list request
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    writeln!(stdin, "{}", serde_json::to_string(&tools_req).unwrap()).expect("write tools/list");
    stdin.flush().expect("flush stdin");

    line.clear();
    reader.read_line(&mut line).expect("read line from stdout");
    let tools_resp: serde_json::Value =
        serde_json::from_str(line.trim()).expect("Stdout must be pure valid JSON");
    assert_eq!(tools_resp["id"], 2);
    let tools = tools_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tools.len(), 10);

    // 3. Drop stdin to send clean EOF
    drop(stdin);

    // Process should terminate cleanly with exit code 0
    let status = child.wait().expect("wait for child process");
    assert!(
        status.success(),
        "aegix mcp process must exit with code 0 on EOF"
    );
}
