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

//! Inline comment suppression directives for false positive management.
//!
//! Developers can suppress specific security alerts by placing comments either on the exact line
//! of the finding or on the immediately preceding line:
//!
//! ```ignore
//! // aegix:ignore CG-SQLI-001
//! let query = format!("SELECT * FROM users WHERE id = {}", sanitized_id);
//! ```
//!
//! Or inline:
//! ```ignore
//! let query = format!("SELECT * FROM users WHERE id = {}", sanitized_id); // aegix:ignore CG-SQLI-001
//! ```
//!
//! Supported directive prefixes (case-insensitive):
//! - `aegix:ignore`
//! - `cyberguard:ignore` (backward compatibility)
//!
//! Comment syntax supported:
//! - `// aegix:ignore <RULE_ID> [reason]` (Rust, Go, C/C++, Java, JS/TS)
//! - `# aegix:ignore <RULE_ID> [reason]` (Python, Bash, YAML, Ruby)
//! - `/* aegix:ignore <RULE_ID> */` (CSS, C block comments)
//! - `<!-- aegix:ignore <RULE_ID> -->` (HTML, XML)

use std::collections::{HashMap, HashSet};

/// Maps file line numbers (1-based) to the set of suppressed rule IDs (or `*` for all rules).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuppressionMap {
    line_suppressions: HashMap<usize, HashSet<String>>,
}

impl SuppressionMap {
    /// Parse all inline suppression directives from the complete string content of a source file.
    pub fn parse(content: &str) -> Self {
        let mut map: HashMap<usize, HashSet<String>> = HashMap::new();

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1; // 1-based line number
            if let Some(rules) = parse_line_directive(line) {
                // The suppression applies to:
                // 1. The line containing the comment (e.g. inline comments)
                // 2. The next line (e.g. comments preceding the vulnerable code statement)
                for &target_line in &[line_num, line_num + 1] {
                    let entry = map.entry(target_line).or_default();
                    for rule in &rules {
                        entry.insert(rule.to_ascii_uppercase());
                    }
                }
            }
        }

        Self {
            line_suppressions: map,
        }
    }

    /// Check if a rule is suppressed on the given 1-based line number.
    pub fn is_suppressed(&self, line: usize, rule_id: &str) -> bool {
        if let Some(rules) = self.line_suppressions.get(&line) {
            if rules.contains("*") || rules.contains("ALL") {
                return true;
            }
            if rules.contains(&rule_id.to_ascii_uppercase()) {
                return true;
            }
        }
        false
    }

    /// Returns the total number of lines that have active suppressions.
    pub fn active_suppressed_lines(&self) -> usize {
        self.line_suppressions.len()
    }
}

/// Parse an inline suppression directive from a single line of text.
/// Returns `Some(vec![rules])` if directive is present.
fn parse_line_directive(line: &str) -> Option<Vec<String>> {
    let lower = line.to_ascii_lowercase();

    // Look for directive markers: aegix:ignore or cyberguard:ignore
    let (start_idx, len) = if let Some(idx) = lower.find("aegix:ignore") {
        (idx, "aegix:ignore".len())
    } else {
        let idx = lower.find("cyberguard:ignore")?;
        (idx, "cyberguard:ignore".len())
    };

    let prefix = &line[..start_idx];
    // Ensure the directive is preceded by a comment marker (//, #, /*, <!--) or line start whitespace
    let is_comment = prefix.contains("//")
        || prefix.contains('#')
        || prefix.contains("/*")
        || prefix.contains("<!--")
        || prefix.trim().is_empty();

    if !is_comment {
        return None;
    }

    let rest = &line[start_idx + len..];

    // Strip leading colons or equals, e.g. aegix:ignore: CG-SQLI-001 or aegix:ignore=CG-SQLI-001
    let trimmed = rest.trim_start_matches(|c: char| c == ':' || c == '=' || c.is_whitespace());

    // Strip trailing comment terminators like */ or -->
    let cleaned = trimmed
        .trim_end()
        .trim_end_matches("*/")
        .trim_end_matches("-->")
        .trim();

    if cleaned.is_empty() {
        return Some(vec!["*".to_string()]);
    }

    // Isolate rules from optional reasons/explanations
    // Delimiters for reason: "--", "//", "#", "reason:", "because:"
    let rules_part = if let Some(idx) = cleaned.find("--") {
        &cleaned[..idx]
    } else if let Some(idx) = cleaned.find("//") {
        &cleaned[..idx]
    } else if let Some(idx) = cleaned.find('#') {
        &cleaned[..idx]
    } else if let Some(idx) = cleaned.to_ascii_lowercase().find("reason:") {
        &cleaned[..idx]
    } else if let Some(idx) = cleaned.to_ascii_lowercase().find("because:") {
        &cleaned[..idx]
    } else {
        cleaned
    };

    // Split on commas, semicolons, or whitespace
    let mut rules = Vec::new();
    for token in rules_part.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let t = token.trim();
        if !t.is_empty() {
            rules.push(t.to_string());
        }
    }

    if rules.is_empty() {
        Some(vec!["*".to_string()])
    } else {
        Some(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preceding_line_suppression() {
        let code = r#"
// aegix:ignore CG-SQLI-001
let query = format!("SELECT * FROM users WHERE id = {}", id);
"#;
        let map = SuppressionMap::parse(code);
        // Line 2 has comment, line 3 has query
        assert!(map.is_suppressed(2, "CG-SQLI-001"));
        assert!(map.is_suppressed(3, "CG-SQLI-001"));
        assert!(!map.is_suppressed(3, "CG-CMDI-001"));
        assert!(!map.is_suppressed(4, "CG-SQLI-001"));
    }

    #[test]
    fn test_same_line_inline_suppression() {
        let code = r#"let query = format!("SELECT * FROM users WHERE id = {}", id); // aegix:ignore CG-SQLI-001"#;
        let map = SuppressionMap::parse(code);
        assert!(map.is_suppressed(1, "CG-SQLI-001"));
        assert!(!map.is_suppressed(1, "CG-CMDI-001"));
    }

    #[test]
    fn test_multiple_rules_and_reason() {
        let code = r#"# aegix:ignore CG-SQLI-001, CG-CMDI-001 -- Approved by security team"#;
        let map = SuppressionMap::parse(code);
        assert!(map.is_suppressed(1, "CG-SQLI-001"));
        assert!(map.is_suppressed(1, "CG-CMDI-001"));
        assert!(!map.is_suppressed(1, "CG-PATH-001"));
    }

    #[test]
    fn test_blanket_ignore_all() {
        let code = r#"// aegix:ignore"#;
        let map = SuppressionMap::parse(code);
        assert!(map.is_suppressed(1, "CG-SQLI-001"));
        assert!(map.is_suppressed(1, "ANY-RULE"));
    }

    #[test]
    fn test_cyberguard_ignore_backward_compatibility() {
        let code = r#"/* cyberguard:ignore CG-CRYP-001 */"#;
        let map = SuppressionMap::parse(code);
        assert!(map.is_suppressed(1, "CG-CRYP-001"));
    }
}
