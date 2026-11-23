//! Threat finding mapping and enrichment engine.

#![deny(unsafe_code)]

use crate::models::{StrideCategory, ThreatFinding};
use crate::traits::{AttackMapper, StrideClassifier};
use cyberguard_core::sarif::{Confidence, SarifResult};
use regex::Regex;
use std::sync::OnceLock;

static CWE_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_cwe_regex() -> &'static Regex {
    CWE_REGEX.get_or_init(|| Regex::new(r"(?i)cwe[-_]?(\d+)").expect("Invalid CWE regex"))
}

/// Mapper that transforms SARIF results into enriched ThreatFindings.
pub struct ThreatMapper<'a> {
    attack_mapper: &'a (dyn AttackMapper + 'a),
    stride_classifier: &'a (dyn StrideClassifier + 'a),
}

impl<'a> ThreatMapper<'a> {
    pub fn new(
        attack_mapper: &'a (dyn AttackMapper + 'a),
        stride_classifier: &'a (dyn StrideClassifier + 'a),
    ) -> Self {
        Self {
            attack_mapper,
            stride_classifier,
        }
    }

    /// Maps a SARIF finding into a unified ThreatFinding.
    pub fn map_sarif_result(&self, result: &SarifResult) -> ThreatFinding {
        let mut cwe_ids = Vec::new();

        // 1. Extract CWE from rule ID and message
        let re = get_cwe_regex();
        for cap in re.captures_iter(&result.rule_id) {
            if let Some(m) = cap.get(1) {
                if let Ok(cwe) = m.as_str().parse::<u32>() {
                    cwe_ids.push(cwe);
                }
            }
        }
        for cap in re.captures_iter(&result.message.text) {
            if let Some(m) = cap.get(1) {
                if let Ok(cwe) = m.as_str().parse::<u32>() {
                    cwe_ids.push(cwe);
                }
            }
        }

        // 2. Extract CVSS, Tri-Factor, and CWEs from properties bag if available
        let mut cvss_score = None;
        let mut tri_factor_score = None;

        if let Some(props) = &result.properties {
            if let Some(c) = props.get("cvss").and_then(|v| v.as_f64()) {
                cvss_score = Some(c);
            }
            if let Some(tf) = props.get("triFactorScore").and_then(|v| v.as_f64()) {
                tri_factor_score = Some(tf);
            }
            if let Some(cwes_val) = props.get("cwes").and_then(|v| v.as_array()) {
                for c in cwes_val {
                    if let Some(n) = c.as_u64() {
                        cwe_ids.push(n as u32);
                    } else if let Some(s) = c.as_str() {
                        for cap in re.captures_iter(s) {
                            if let Some(m) = cap.get(1) {
                                if let Ok(parsed) = m.as_str().parse::<u32>() {
                                    cwe_ids.push(parsed);
                                }
                            }
                        }
                    }
                }
            }
        }

        cwe_ids.sort_unstable();
        cwe_ids.dedup();

        // 3. Map ATT&CK Tactics and Techniques
        let (tactics, techniques) = self
            .attack_mapper
            .map_finding_to_techniques(&result.rule_id, &cwe_ids);

        // 4. Classify STRIDE categories
        let stride_categories = self
            .stride_classifier
            .classify_finding(&result.rule_id, &cwe_ids);

        // 5. Extract location
        let mut file_path = None;
        let mut line = None;

        if let Some(loc) = result.locations.first() {
            if let Some(phys) = &loc.physical_location {
                file_path = Some(phys.artifact_location.uri.clone());
                if let Some(reg) = &phys.region {
                    line = Some(reg.start_line);
                }
            }
        }

        // 6. Formulate remediation advice
        let primary_stride = stride_categories
            .first()
            .copied()
            .unwrap_or(StrideCategory::InformationDisclosure);
        let remediation = self
            .stride_classifier
            .get_stride_guidance(primary_stride)
            .to_string();

        let fingerprint = result.fingerprint();
        let confidence = result.confidence.unwrap_or(Confidence::Medium);

        ThreatFinding {
            id: format!("TF-{}", &fingerprint[..12.min(fingerprint.len())]),
            source_rule_id: result.rule_id.clone(),
            title: result.rule_id.clone(),
            description: result.message.text.clone(),
            severity: result.level,
            confidence,
            tactics,
            techniques,
            stride_categories,
            cwe_ids,
            file_path,
            line,
            cvss_score,
            tri_factor_score,
            remediation,
            fingerprint,
        }
    }
}
