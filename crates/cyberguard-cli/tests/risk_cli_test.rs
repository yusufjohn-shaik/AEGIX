//! Integration tests for `aegix risk` CLI subcommand and `aegix_risk` MCP tool.

#![deny(unsafe_code)]

use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn get_temp_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{}-{}", prefix, nanos));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    dir
}

#[test]
fn test_aegix_risk_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("risk")
        .arg("--help")
        .output()
        .expect("Failed to execute aegix risk --help");

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--input"));
    assert!(help.contains("--format"));
    assert!(help.contains("--output"));
    assert!(help.contains("--min-score"));
    assert!(help.contains("--fail-on"));
    assert!(help.contains("--show-suppressed"));
    assert!(help.contains("--no-cargo-metadata"));
    assert!(help.contains("--epss-db"));
    assert!(help.contains("--baseline"));
    assert!(help.contains("--save-baseline"));
}

#[test]
fn test_aegix_risk_cli_exit_codes_and_json_export() {
    let dir = get_temp_dir("risk-cli-e2e");

    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"risk-demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nchrono = \"0.4.19\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"risk-demo\"\nversion = \"0.1.0\"\ndependencies = [\"chrono\"]\n\n[[package]]\nname = \"chrono\"\nversion = \"0.4.19\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src").join("main.rs"),
        "use chrono::NaiveDate;\nfn main() { let _ = NaiveDate::from_ymd_opt(2026, 1, 1); }\n",
    )
    .unwrap();

    // High-EPSS reachable SARIF triggers exit code 1 above default --fail-on 2.5
    let sarif_path = dir.join("findings.sarif.json");
    let mut sarif = SarifLog::new("cyberguard-sast", "0.9.0");
    let mut sqli = SarifResult::new("CG-SQLI-001", SarifLevel::Error, "SQL Injection in main");
    sqli.add_location("src/main.rs", 2, None, None, None);
    sqli.properties = Some(serde_json::json!({ "cwe": "CWE-89" }));
    sarif.add_result(sqli);
    std::fs::write(&sarif_path, serde_json::to_string(&sarif).unwrap()).unwrap();

    let breach_out = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("risk")
        .arg(&dir)
        .arg("--input")
        .arg(&sarif_path)
        .arg("--no-cargo-metadata")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run aegix risk");

    assert_eq!(breach_out.status.code(), Some(1));
    let json_val: serde_json::Value = serde_json::from_slice(&breach_out.stdout).unwrap();
    assert_eq!(json_val["critical_count"], 1);
    assert_eq!(
        json_val["findings"][0]["breakdown"]["tri_factor_score"],
        8.33
    );

    // High --fail-on threshold passes with exit code 0
    let pass_out = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("risk")
        .arg(&dir)
        .arg("--input")
        .arg(&sarif_path)
        .arg("--no-cargo-metadata")
        .arg("--fail-on")
        .arg("9.5")
        .arg("--format")
        .arg("sarif")
        .output()
        .expect("run aegix risk pass");
    assert_eq!(pass_out.status.code(), Some(0));

    // Malformed SARIF returns exit code 2 cleanly
    let bad_path = dir.join("bad.sarif.json");
    std::fs::write(&bad_path, "{ not valid sarif").unwrap();
    let err_out = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("risk")
        .arg("--input")
        .arg(&bad_path)
        .output()
        .expect("run aegix risk error");
    assert_eq!(err_out.status.code(), Some(2));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_aegix_mcp_exposes_and_executes_aegix_risk() {
    let dir = get_temp_dir("risk-mcp-e2e");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"mcp-demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aegix mcp");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "risk-test", "version": "1.0.0" }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&init_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();

    let call_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "aegix_risk",
            "arguments": {
                "path": dir.to_string_lossy(),
                "no_cargo_metadata": true,
                "format": "json"
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&call_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let body = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(body.contains("workspace_packages"));

    drop(stdin);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
