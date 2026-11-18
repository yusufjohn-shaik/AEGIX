// Copyright 2026 Aegix Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use cyberguard_core::Confidence;
use cyberguard_sast::NativeRuleEngine;

#[test]
fn test_inline_suppression_preceding_line() {
    let engine = NativeRuleEngine::default();
    let code_suppressed = r#"
// aegix:ignore CG-SQLI-001
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
"#;
    let results = engine.scan_file_content("test.rs", code_suppressed);
    assert_eq!(
        results.len(),
        0,
        "Preceding line ignore comment should suppress SQLI finding"
    );

    let code_unsuppressed = r#"
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
"#;
    let results_unsuppressed = engine.scan_file_content("test.rs", code_unsuppressed);
    assert_eq!(results_unsuppressed.len(), 1);
    assert_eq!(results_unsuppressed[0].rule_id, "CG-SQLI-001");
    assert_eq!(results_unsuppressed[0].confidence, Some(Confidence::High));
}

#[test]
fn test_inline_suppression_same_line() {
    let engine = NativeRuleEngine::default();
    let code = r#"
let query = format!("SELECT * FROM users WHERE id = {}", user_id); // aegix:ignore CG-SQLI-001
"#;
    let results = engine.scan_file_content("test.rs", code);
    assert_eq!(
        results.len(),
        0,
        "Same line ignore comment should suppress SQLI finding"
    );
}

#[test]
fn test_inline_suppression_python_comment() {
    let engine = NativeRuleEngine::default();
    let code = r#"
# aegix:ignore CG-CMDI-001 -- Handled by sandbox
os.system(f"ping -c 1 {host}")
"#;
    let results = engine.scan_file_content("test.py", code);
    assert_eq!(
        results.len(),
        0,
        "Python hash comment with reasoning should suppress CMDI finding"
    );
}

#[test]
fn test_inline_suppression_blanket_all() {
    let engine = NativeRuleEngine::default();
    let code = r#"
// aegix:ignore
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
"#;
    let results = engine.scan_file_content("test.rs", code);
    assert_eq!(
        results.len(),
        0,
        "Blanket ignore should suppress all findings on target line"
    );
}

#[test]
fn test_inline_suppression_legacy_cyberguard_prefix() {
    let engine = NativeRuleEngine::default();
    let code = r#"
// cyberguard:ignore CG-SQLI-001
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
"#;
    let results = engine.scan_file_content("test.rs", code);
    assert_eq!(
        results.len(),
        0,
        "Legacy cyberguard:ignore directive should maintain backward compatibility"
    );
}

#[test]
fn test_inline_suppression_mismatched_rule_id_does_not_suppress() {
    let engine = NativeRuleEngine::default();
    let code = r#"
// aegix:ignore CG-CMDI-001
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
"#;
    let results = engine.scan_file_content("test.rs", code);
    assert_eq!(
        results.len(),
        1,
        "Ignoring CG-CMDI-001 should not suppress a CG-SQLI-001 finding"
    );
    assert_eq!(results[0].rule_id, "CG-SQLI-001");
}
