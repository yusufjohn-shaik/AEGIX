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

//! Data models for secret detection rules and findings.

use cyberguard_core::SarifLevel;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Rule definition for detecting specific provider credentials or tokens.
#[derive(Clone, Debug)]
pub struct SecretRule {
    /// Unique rule identifier (e.g., `CG-SEC-AWS-001`).
    pub id: String,
    /// Target provider or service (e.g., `AWS`, `GitHub`).
    pub provider: String,
    /// Human-readable description.
    pub description: String,
    /// Compiled regular expression pattern.
    pub pattern: Regex,
    /// Optional minimum Shannon entropy threshold.
    pub min_entropy: Option<f64>,
    /// Severity level of the finding.
    pub severity: SarifLevel,
}

/// A specific finding of an exposed credential.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretFinding {
    /// ID of the rule that matched.
    pub rule_id: String,
    /// Provider name.
    pub provider: String,
    /// Relative or absolute path where the secret was detected.
    pub file_path: PathBuf,
    /// Line number (1-based).
    pub line_number: usize,
    /// Column number (1-based).
    pub column_number: usize,
    /// Redacted secret representation (e.g., `AKIA**************LE`).
    pub masked_secret: String,
    /// Calculated Shannon entropy score.
    pub entropy: f64,
    /// Severity level.
    pub severity: SarifLevel,
    /// Contextual explanation or remediation advisory.
    pub message: String,
}
