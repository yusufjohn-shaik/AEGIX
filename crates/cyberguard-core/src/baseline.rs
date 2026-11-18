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

//! Baseline snapshotting engine for suppressing legacy findings during progressive adoption.
//!
//! Existing codebases frequently contain hundreds of pre-existing alerts. The baseline engine
//! enables teams to capture existing findings into a versioned `.aegix-baseline.json` file.
//! Subsequent CI/CD runs filter against this baseline, allowing builds to pass while ensuring
//! that any *new* vulnerability regressions immediately trigger build failure.

use crate::sarif::{SarifLog, SarifResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Canonical snapshot of known/accepted security findings in a codebase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AegixBaseline {
    /// Baseline format schema version
    pub version: String,
    /// Tool version identifier that generated the baseline
    pub tool: String,
    /// ISO8601 UTC timestamp of baseline generation
    pub generated_at: String,
    /// Total count of unique findings captured in baseline
    pub total_findings: usize,
    /// Deterministically sorted set of SHA-256 finding fingerprints
    pub fingerprints: BTreeSet<String>,
    /// Human-readable list of captured findings for audit transparency
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<BaselineFindingEntry>,
}

/// Metadata entry for a single baseline finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineFindingEntry {
    pub rule_id: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Default for AegixBaseline {
    fn default() -> Self {
        Self::new()
    }
}

impl AegixBaseline {
    /// Create an empty baseline.
    pub fn new() -> Self {
        Self {
            version: "1.0.0".to_string(),
            tool: format!("Aegix v{}", env!("CARGO_PKG_VERSION")),
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_findings: 0,
            fingerprints: BTreeSet::new(),
            findings: Vec::new(),
        }
    }

    /// Construct a baseline snapshot from a slice of SarifResults.
    pub fn from_results(results: &[SarifResult]) -> Self {
        let mut fingerprints = BTreeSet::new();
        let mut findings = Vec::new();

        for res in results {
            let fp = res.fingerprint();
            fingerprints.insert(fp.clone());

            let loc_str = res.locations.first().and_then(|loc| {
                loc.physical_location.as_ref().map(|phys| {
                    if let Some(reg) = &phys.region {
                        format!("{}:{}", phys.artifact_location.uri, reg.start_line)
                    } else {
                        phys.artifact_location.uri.clone()
                    }
                })
            });

            findings.push(BaselineFindingEntry {
                rule_id: res.rule_id.clone(),
                fingerprint: fp,
                location: loc_str,
                message: Some(res.message.text.clone()),
            });
        }

        Self {
            version: "1.0.0".to_string(),
            tool: format!("Aegix v{}", env!("CARGO_PKG_VERSION")),
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_findings: fingerprints.len(),
            fingerprints,
            findings,
        }
    }

    /// Construct a baseline snapshot from a SarifLog.
    pub fn from_sarif(log: &SarifLog) -> Self {
        let results: Vec<SarifResult> = log.runs.iter().flat_map(|r| r.results.clone()).collect();
        Self::from_results(&results)
    }

    /// Returns true if the given fingerprint is tracked in this baseline.
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Filter out baseline findings from a vector of results in-place.
    /// Returns the number of findings suppressed by the baseline.
    pub fn filter_results(&self, results: &mut Vec<SarifResult>) -> usize {
        let original_len = results.len();
        results.retain(|r| !self.contains(&r.fingerprint()));
        original_len - results.len()
    }

    /// Filter out baseline findings from a SarifLog in-place.
    /// Returns the number of findings suppressed by the baseline.
    pub fn filter_sarif(&self, log: &mut SarifLog) -> usize {
        let mut suppressed = 0;
        for run in &mut log.runs {
            suppressed += self.filter_results(&mut run.results);
        }
        suppressed
    }

    /// Load baseline from a file path.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let baseline: Self = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(baseline)
    }

    /// Save baseline to a file path as indented JSON.
    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::SarifLevel;

    #[test]
    fn test_baseline_creation_and_filtering() {
        let mut r1 = SarifResult::new("CG-SQLI-001", SarifLevel::Error, "SQL Injection detected");
        r1.add_location("src/db.rs", 42, Some(5), Some(42), Some(30));

        let mut r2 = SarifResult::new("CG-CMDI-001", SarifLevel::Error, "Command Injection");
        r2.add_location("src/exec.rs", 10, Some(1), Some(10), Some(20));

        let baseline = AegixBaseline::from_results(&[r1.clone()]);
        assert_eq!(baseline.total_findings, 1);
        assert!(baseline.contains(&r1.fingerprint()));
        assert!(!baseline.contains(&r2.fingerprint()));

        let mut current_results = vec![r1.clone(), r2.clone()];
        let suppressed = baseline.filter_results(&mut current_results);

        assert_eq!(suppressed, 1);
        assert_eq!(current_results.len(), 1);
        assert_eq!(current_results[0].rule_id, "CG-CMDI-001");
    }

    #[test]
    fn test_baseline_serialization_roundtrip() {
        let mut r1 = SarifResult::new("CG-SQLI-001", SarifLevel::Error, "SQL Injection detected");
        r1.add_location("src/db.rs", 42, Some(5), Some(42), Some(30));

        let baseline = AegixBaseline::from_results(&[r1]);
        let serialized = serde_json::to_string(&baseline).expect("Serialize");
        let deserialized: AegixBaseline =
            serde_json::from_str(&serialized).expect("Deserialize baseline");

        assert_eq!(baseline.total_findings, deserialized.total_findings);
        assert_eq!(baseline.fingerprints, deserialized.fingerprints);
    }
}
