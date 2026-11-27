//! Integration tests for `aegix report` CLI subcommand.

#![deny(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_temp_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{}-{}", prefix, nanos));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_aegix_report_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("report")
        .arg("--help")
        .output()
        .expect("Failed to execute aegix report --help");

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--sarif"));
    assert!(help.contains("--html"));
    assert!(help.contains("--json"));
    assert!(help.contains("--no-terminal"));
}

#[test]
fn test_aegix_report_cli_html_and_json_export() {
    let dir = get_temp_dir("report-cli-e2e");
    let sample_file = dir.join("app.py");
    fs::write(
        &sample_file,
        "def query_user(db, uid):\n    return db.execute('SELECT * FROM users WHERE id = ' + uid)\n",
    )
    .unwrap();

    let html_out = dir.join("report.html");
    let json_out = dir.join("report.json");

    let output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("report")
        .arg("--html")
        .arg(&html_out)
        .arg("--json")
        .arg(&json_out)
        .arg(&sample_file)
        .output()
        .expect("Execute aegix report");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SECURITY POSTURE SCORE"));

    // Verify HTML report file
    assert!(html_out.exists());
    let html_content = fs::read_to_string(&html_out).unwrap();
    assert!(html_content.contains("<!DOCTYPE html>"));
    assert!(html_content.contains("Aegix Executive Security Report"));

    // Verify JSON report file
    assert!(json_out.exists());
    let json_content = fs::read_to_string(&json_out).unwrap();
    let json_val: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    assert!(json_val.get("posture").is_some());
    assert!(json_val.get("severities").is_some());

    // Cleanup
    let _ = fs::remove_dir_all(&dir);
}
