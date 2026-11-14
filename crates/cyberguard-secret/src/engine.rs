// Copyright 2026 CyberGuard Authors.
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

//! Core secret detection scanning engine.

use crate::entropy::calculate_shannon_entropy;
use crate::error::SecretError;
use crate::masker::mask_secret;
use crate::models::{SecretFinding, SecretRule};
use crate::rules::default_rules;
use crate::traits::SecretScanner;
use async_trait::async_trait;
use cyberguard_core::SarifResult;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

const MAX_FILE_SIZE_BYTES: u64 = 16 * 1024 * 1024; // 16 MB max
const BINARY_CHECK_BYTES: usize = 1024;

/// High-performance Secret Detection Engine.
#[derive(Clone, Debug)]
pub struct SecretEngine {
    rules: Vec<SecretRule>,
}

impl Default for SecretEngine {
    fn default() -> Self {
        Self {
            rules: default_rules(),
        }
    }
}

impl SecretEngine {
    /// Creates a new secret engine with custom rules.
    pub fn new(rules: Vec<SecretRule>) -> Self {
        Self { rules }
    }

    /// Access the registered rules.
    pub fn rules(&self) -> &[SecretRule] {
        &self.rules
    }

    /// Checks if a file appears to be binary by inspecting initial bytes for null characters.
    fn is_binary_file(path: &Path) -> bool {
        if let Ok(mut f) = File::open(path) {
            let mut buffer = [0u8; BINARY_CHECK_BYTES];
            if let Ok(bytes_read) = f.read(&mut buffer) {
                return buffer[..bytes_read].contains(&0u8);
            }
        }
        false
    }

    /// Scans a single text file's contents for secret patterns and high entropy tokens.
    fn scan_file_content(&self, path: &Path, content: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_number = line_idx + 1;

            for rule in &self.rules {
                for caps in rule.pattern.captures_iter(line) {
                    let (secret_text, start_offset) = if let Some(m) = caps.get(1) {
                        (m.as_str(), m.start())
                    } else if let Some(m) = caps.get(0) {
                        (m.as_str(), m.start())
                    } else {
                        continue;
                    };

                    let entropy = calculate_shannon_entropy(secret_text);
                    if let Some(min_ent) = rule.min_entropy {
                        if entropy < min_ent {
                            continue;
                        }
                    }

                    let column_number = line[..start_offset].chars().count() + 1;
                    let masked_secret = mask_secret(secret_text);
                    let message = format!(
                        "Exposed {} credential detected ({}) with Shannon entropy {:.2}",
                        rule.provider, masked_secret, entropy
                    );

                    findings.push(SecretFinding {
                        rule_id: rule.id.clone(),
                        provider: rule.provider.clone(),
                        file_path: path.to_path_buf(),
                        line_number,
                        column_number,
                        masked_secret,
                        entropy,
                        severity: rule.severity,
                        message,
                    });
                }
            }
        }

        findings
    }
}

#[async_trait]
impl SecretScanner for SecretEngine {
    async fn scan_path(&self, target: &Path) -> Result<Vec<SecretFinding>, SecretError> {
        let mut findings = Vec::new();

        if !target.exists() {
            return Ok(findings);
        }

        if target.is_file() {
            if let Ok(metadata) = target.metadata() {
                if metadata.len() <= MAX_FILE_SIZE_BYTES && !Self::is_binary_file(target) {
                    if let Ok(content) = std::fs::read_to_string(target) {
                        findings.extend(self.scan_file_content(target, &content));
                    }
                }
            }
            return Ok(findings);
        }

        let walker = WalkDir::new(target)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                let file_name = entry.file_name().to_string_lossy();
                !(file_name == ".git"
                    || file_name == "node_modules"
                    || file_name == "target"
                    || file_name == ".svn"
                    || file_name == ".hg"
                    || file_name == ".cargo"
                    || file_name == "vendor")
            });

        for entry in walker.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.len() > MAX_FILE_SIZE_BYTES {
                        continue;
                    }
                }

                if Self::is_binary_file(path) {
                    continue;
                }

                if let Ok(content) = std::fs::read_to_string(path) {
                    findings.extend(self.scan_file_content(path, &content));
                }
            }
        }

        Ok(findings)
    }

    fn to_sarif(&self, findings: &[SecretFinding]) -> Vec<SarifResult> {
        findings
            .iter()
            .map(|f| {
                let mut res = SarifResult::new(&f.rule_id, f.severity, &f.message);
                res.add_location(
                    f.file_path.display().to_string(),
                    f.line_number,
                    Some(f.column_number),
                    Some(f.line_number),
                    Some(f.column_number + f.masked_secret.len()),
                );
                res.compute_deterministic_fingerprint();
                res
            })
            .collect()
    }
}
