#![deny(unsafe_code)]

pub mod error;
pub mod models;
pub mod parser;
pub mod taint;
pub mod traits;

pub use error::FixError;
pub use models::*;
pub use parser::MultiLanguageAstParser;
pub use taint::DefaultTaintAnalyzer;
pub use traits::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_language_detection() {
        assert_eq!(
            SourceLanguage::from_extension("py"),
            Some(SourceLanguage::Python)
        );
        assert_eq!(
            SourceLanguage::from_extension("js"),
            Some(SourceLanguage::JavaScript)
        );
        assert_eq!(
            SourceLanguage::from_extension("ts"),
            Some(SourceLanguage::TypeScript)
        );
        assert_eq!(
            SourceLanguage::from_extension("go"),
            Some(SourceLanguage::Go)
        );
        assert_eq!(
            SourceLanguage::from_extension("rs"),
            Some(SourceLanguage::Rust)
        );
        assert_eq!(SourceLanguage::from_extension("txt"), None);
    }

    #[test]
    fn test_sarif_fix_conversion() {
        let patch = SurgicalPatch {
            id: "fix-1".to_string(),
            rule_id: "CG-SQLI-001".to_string(),
            category: PatchCategory::SqlParameterization,
            file_path: PathBuf::from("src/db.py"),
            target_line_start: 10,
            target_line_end: 11,
            original_content: "cursor.execute(f'SELECT {id}')".to_string(),
            replacement_content: "cursor.execute('SELECT %s', (id,))".to_string(),
            required_imports: vec![],
            explanation: "Parameterize SQL query".to_string(),
            confidence: 0.95,
        };

        let sarif_fix = cyberguard_core::sarif::Fix::from(&patch);
        assert_eq!(sarif_fix.description.text, "Parameterize SQL query");
        assert_eq!(sarif_fix.artifact_changes.len(), 1);
        let change = &sarif_fix.artifact_changes[0];
        assert_eq!(change.artifact_location.uri, "src/db.py");
        assert_eq!(change.replacements.len(), 1);
        assert_eq!(change.replacements[0].deleted_region.start_line, 10);
    }

    #[test]
    fn test_python_ast_parsing_and_taint() {
        let code = r#"
import sqlite3
import os

API_KEY = "sk_live_94819a8f4c19284ba71e"

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)

def ping_host(target):
    subprocess.run(f"ping -c 1 {target}", shell=True)
"#;
        let parser = MultiLanguageAstParser::new();
        let parsed = parser
            .parse(&PathBuf::from("app.py"), code, SourceLanguage::Python)
            .expect("parse python");

        assert_eq!(parsed.imports.len(), 2);
        assert_eq!(parsed.functions.len(), 2);
        assert_eq!(parsed.functions[0].name, "get_user");
        assert_eq!(parsed.functions[1].name, "ping_host");

        let analyzer = DefaultTaintAnalyzer::new();
        let flows = analyzer.analyze(&parsed).expect("analyze taint");

        assert!(flows.len() >= 3);
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::HardcodedSecret));
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::SqlExecution && !f.is_sanitized));
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::CommandExecution && !f.is_sanitized));
    }

    #[test]
    fn test_javascript_ast_parsing_and_taint() {
        let code = r#"
const child_process = require('child_process');
const db = require('./db');

const STRIPE_SECRET = "sk_test_51Mz0FakeTokenSecret";

function runQuery(userId) {
    const q = `SELECT * FROM accounts WHERE id = '${userId}'`;
    db.query(q);
}

function executeCmd(cmd) {
    child_process.exec(`cat ${cmd}`);
}
"#;
        let parser = MultiLanguageAstParser::new();
        let parsed = parser
            .parse(&PathBuf::from("app.js"), code, SourceLanguage::JavaScript)
            .expect("parse js");

        assert_eq!(parsed.imports.len(), 2);
        assert_eq!(parsed.functions.len(), 2);

        let analyzer = DefaultTaintAnalyzer::new();
        let flows = analyzer.analyze(&parsed).expect("analyze taint");

        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::HardcodedSecret));
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::SqlExecution));
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::CommandExecution));
    }

    #[test]
    fn test_go_ast_parsing_and_taint() {
        let code = r#"
package main

import (
    "database/sql"
    "os/exec"
)

func HandleUser(userInput string) {
    query := "SELECT * FROM users WHERE name = " + userInput
    db.Query(query)
}

func ExecScript(scriptPath string) {
    exec.Command("sh", "-c", scriptPath)
}
"#;
        let parser = MultiLanguageAstParser::new();
        let parsed = parser
            .parse(&PathBuf::from("main.go"), code, SourceLanguage::Go)
            .expect("parse go");

        assert_eq!(parsed.imports.len(), 2);
        assert_eq!(parsed.functions.len(), 2);

        let analyzer = DefaultTaintAnalyzer::new();
        let flows = analyzer.analyze(&parsed).expect("analyze taint");

        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::SqlExecution));
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::CommandExecution));
    }

    #[test]
    fn test_rust_ast_parsing_and_taint() {
        let code = r#"
use std::process::Command;
use std::fs::File;

pub fn read_file_untrusted(user_path: &str) {
    File::open(user_path).ok();
}

pub fn spawn_shell(cmd_arg: &str) {
    Command::new(cmd_arg);
}
"#;
        let parser = MultiLanguageAstParser::new();
        let parsed = parser
            .parse(&PathBuf::from("src/lib.rs"), code, SourceLanguage::Rust)
            .expect("parse rust");

        assert_eq!(parsed.imports.len(), 2);
        assert_eq!(parsed.functions.len(), 2);

        let analyzer = DefaultTaintAnalyzer::new();
        let flows = analyzer.analyze(&parsed).expect("analyze taint");

        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::PathTraversal));
        assert!(flows
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::CommandExecution));
    }
}
