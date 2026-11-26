//! Integration tests for `aegix fix` CLI subcommand.

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
fn test_aegix_fix_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("fix")
        .arg("--help")
        .output()
        .expect("Failed to execute aegix fix --help");

    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--auto"));
    assert!(help.contains("--dry-run"));
    assert!(help.contains("--sarif"));
    assert!(help.contains("--rules"));
    assert!(help.contains("--lang"));
    assert!(help.contains("--output-diff"));
    assert!(help.contains("--write-tests"));
}

#[test]
fn test_aegix_fix_cli_dry_run_and_auto() {
    let dir = get_temp_dir("fix-cli-e2e");
    let vuln_file = dir.join("vuln.py");
    let original = "def get_user(db, user_id):\n    query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"\n    return db.execute(query)\n";
    fs::write(&vuln_file, original).unwrap();

    let diff_out = dir.join("patch.diff");

    // 1. Dry run
    let dry_run_output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("fix")
        .arg("--dry-run")
        .arg("--output-diff")
        .arg(&diff_out)
        .arg(&vuln_file)
        .output()
        .expect("Execute dry run");

    assert!(dry_run_output.status.success());
    let stdout = String::from_utf8_lossy(&dry_run_output.stdout);
    assert!(stdout.contains("Aegix AST & Autonomous Remediation Engine"));
    assert!(stdout.contains("Surgical Patches Synthesized: 1"));
    assert!(stdout.contains("Planned Unified Diffs"));

    // Verify original file unchanged
    let content_after_dry = fs::read_to_string(&vuln_file).unwrap();
    assert_eq!(content_after_dry, original);

    // Verify diff output file created
    assert!(diff_out.exists());
    let diff_text = fs::read_to_string(&diff_out).unwrap();
    assert!(diff_text.contains("---"));
    assert!(diff_text.contains("+++"));

    // 2. Auto apply
    let auto_output = Command::new(env!("CARGO_BIN_EXE_aegix"))
        .arg("fix")
        .arg("--auto")
        .arg(&vuln_file)
        .output()
        .expect("Execute auto fix");

    assert!(auto_output.status.success());
    let auto_stdout = String::from_utf8_lossy(&auto_output.stdout);
    assert!(auto_stdout.contains("Applied 1 patch(es)"));

    // Verify file modified on disk
    let content_after_auto = fs::read_to_string(&vuln_file).unwrap();
    assert_ne!(content_after_auto, original);

    // Cleanup
    let _ = fs::remove_dir_all(&dir);
}
