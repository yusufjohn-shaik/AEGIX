//! Asymptotic Logarithmic Saturation Scoring and Aggregation Engine.

#![deny(unsafe_code)]

use crate::models::{MitreTactic, StrideCategory, ThreatFinding};
use cyberguard_core::sarif::{Confidence, SarifLevel};
use std::collections::HashMap;

/// Tuning constant for logarithmic saturation.
pub const DEFAULT_SATURATION_ALPHA: f64 = 0.75;

/// ThreatScorer evaluates finding weights and aggregates techniques and STRIDE metrics.
pub struct ThreatScorer {
    alpha: f64,
}

impl Default for ThreatScorer {
    fn default() -> Self {
        Self::new(DEFAULT_SATURATION_ALPHA)
    }
}

impl ThreatScorer {
    pub fn new(alpha: f64) -> Self {
        Self { alpha }
    }

    /// Evaluates base severity for a finding (0.0 to 10.0 scale).
    pub fn base_severity(finding: &ThreatFinding) -> f64 {
        if let Some(tf) = finding.tri_factor_score {
            return tf.clamp(0.0, 10.0);
        }
        if let Some(cvss) = finding.cvss_score {
            return cvss.clamp(0.0, 10.0);
        }
        match finding.severity {
            SarifLevel::Error => 8.0,
            SarifLevel::Warning => 5.0,
            SarifLevel::Note => 2.0,
            SarifLevel::None => 1.0,
        }
    }

    /// Evaluates statistical weight for a finding.
    pub fn finding_weight(finding: &ThreatFinding) -> f64 {
        let sev_weight = match finding.severity {
            SarifLevel::Error => 1.0,
            SarifLevel::Warning => 0.6,
            SarifLevel::Note => 0.2,
            SarifLevel::None => 0.1,
        };

        let conf_weight = match finding.confidence {
            Confidence::High => 1.0,
            Confidence::Medium => 0.7,
            Confidence::Low => 0.4,
        };

        sev_weight * conf_weight
    }

    /// Calculates score for a technique given its associated findings.
    ///
    /// Score = min(10.0, max(BaseSeverity) + alpha * ln(1 + sum(Weight)))
    pub fn score_technique(&self, findings: &[&ThreatFinding]) -> f64 {
        if findings.is_empty() {
            return 0.0;
        }

        let max_base = findings
            .iter()
            .map(|f| Self::base_severity(f))
            .fold(0.0f64, f64::max);

        let sum_weight: f64 = findings.iter().map(|f| Self::finding_weight(f)).sum();

        let raw_score = max_base + self.alpha * (1.0 + sum_weight).ln();
        let clamped = raw_score.clamp(0.0, 10.0);

        // Round to 1 decimal place
        (clamped * 10.0).round() / 10.0
    }

    /// Aggregates technique scores across all findings.
    pub fn aggregate_technique_scores(&self, findings: &[ThreatFinding]) -> HashMap<String, f64> {
        let mut grouped: HashMap<String, Vec<&ThreatFinding>> = HashMap::new();

        for finding in findings {
            for tech_id in &finding.techniques {
                grouped.entry(tech_id.clone()).or_default().push(finding);
            }
        }

        let mut scores = HashMap::new();
        for (tech_id, tech_findings) in grouped {
            scores.insert(tech_id, self.score_technique(&tech_findings));
        }

        scores
    }

    /// Counts findings grouped by STRIDE category.
    pub fn count_by_stride(findings: &[ThreatFinding]) -> HashMap<StrideCategory, usize> {
        let mut counts = HashMap::new();
        for cat in StrideCategory::all() {
            counts.insert(*cat, 0);
        }

        for finding in findings {
            for cat in &finding.stride_categories {
                *counts.entry(*cat).or_insert(0) += 1;
            }
        }

        counts
    }

    /// Counts findings grouped by MITRE ATT&CK Tactic.
    pub fn count_by_tactic(findings: &[ThreatFinding]) -> HashMap<MitreTactic, usize> {
        let mut counts = HashMap::new();
        for tactic in MitreTactic::all() {
            counts.insert(*tactic, 0);
        }

        for finding in findings {
            for tactic in &finding.tactics {
                *counts.entry(*tactic).or_insert(0) += 1;
            }
        }

        counts
    }

    /// Counts findings grouped by ATT&CK Technique ID.
    pub fn count_by_technique(findings: &[ThreatFinding]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();

        for finding in findings {
            for tech in &finding.techniques {
                *counts.entry(tech.clone()).or_insert(0) += 1;
            }
        }

        counts
    }
}
