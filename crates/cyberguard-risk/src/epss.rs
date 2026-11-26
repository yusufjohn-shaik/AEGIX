//! Offline EPSS & CVSS intelligence lookup reusing `cyberguard-sca::VulnerabilityDatabase`.

#![deny(unsafe_code)]

use crate::error::RiskError;
use crate::models::{sanitize_clamped, ScoreSource};
use cyberguard_core::sarif::SarifLevel;
use cyberguard_sca::db::VulnerabilityDatabase;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryIntel {
    pub cvss: Option<f64>,
    pub epss: f64,
    pub fixed_version: Option<String>,
    pub cve: Option<String>,
}

/// Offline EPSS and CVSS intelligence catalog with external bundle override support.
#[derive(Debug, Clone)]
pub struct EpssCatalog {
    embedded_by_id: BTreeMap<String, AdvisoryIntel>,
    external_by_id: BTreeMap<String, AdvisoryIntel>,
}

impl Default for EpssCatalog {
    fn default() -> Self {
        Self::embedded()
    }
}

impl EpssCatalog {
    /// Constructs catalog directly from `cyberguard_sca::VulnerabilityDatabase::embedded()` without duplication.
    pub fn embedded() -> Self {
        let mut embedded_by_id = BTreeMap::new();
        let db = VulnerabilityDatabase::embedded();

        for adv in db.advisories() {
            let intel = AdvisoryIntel {
                cvss: Some(sanitize_clamped(adv.cvss, 0.0, 10.0, 5.0)),
                epss: sanitize_clamped(adv.epss, 0.0, 1.0, 0.35),
                fixed_version: adv.fixed_version.clone(),
                cve: adv.cve.clone(),
            };
            embedded_by_id.insert(adv.id.to_uppercase(), intel.clone());
            if let Some(ref cve) = adv.cve {
                embedded_by_id.insert(cve.to_uppercase(), intel);
            }
        }

        // Baseline Rust/Ecosystem CWE-aligned high-profile advisories supplemental index
        let supplemental = [
            ("CVE-2024-3094", 10.0, 0.97),
            ("CVE-2021-44228", 10.0, 0.98),
            ("CVE-2022-22965", 9.8, 0.97),
            ("CVE-2023-38545", 9.8, 0.89),
            ("RUSTSEC-2022-0090", 7.5, 0.14),
            ("RUSTSEC-2023-0071", 5.9, 0.18),
        ];
        for (id, cvss, epss) in supplemental {
            embedded_by_id
                .entry(id.to_string())
                .or_insert(AdvisoryIntel {
                    cvss: Some(cvss),
                    epss,
                    fixed_version: None,
                    cve: if id.starts_with("CVE-") {
                        Some(id.to_string())
                    } else {
                        None
                    },
                });
        }

        Self {
            embedded_by_id,
            external_by_id: BTreeMap::new(),
        }
    }

    /// Loads an optional offline JSON EPSS override map (`{ "CVE-2024-...": { "epss": 0.91, "cvss": 9.8 } }`).
    pub fn load_external_json(&mut self, path: &Path) -> Result<usize, RiskError> {
        let content = std::fs::read_to_string(path)?;
        let raw: BTreeMap<String, ExternalEpssRecord> = serde_json::from_str(&content)?;
        let mut count = 0;

        for (id, rec) in raw {
            let epss = sanitize_clamped(rec.epss, 0.0, 1.0, 0.35);
            let cvss = rec.cvss.map(|c| sanitize_clamped(c, 0.0, 10.0, 5.0));
            self.external_by_id.insert(
                id.trim().to_uppercase(),
                AdvisoryIntel {
                    cvss,
                    epss,
                    fixed_version: rec.fixed_version,
                    cve: None,
                },
            );
            count += 1;
        }
        Ok(count)
    }

    /// Resolves `(cvss, epss, score_source, fixed_version)` according to strict precedence:
    /// SARIF properties > External `--epss-db` > `VulnerabilityDatabase` > CWE Heuristic > `SarifLevel`.
    pub fn resolve(
        &self,
        rule_id: &str,
        cve_hint: Option<&str>,
        cwe_hint: Option<&str>,
        explicit_cvss: Option<f64>,
        explicit_epss: Option<f64>,
        level: SarifLevel,
    ) -> (f64, f64, ScoreSource, Option<String>) {
        let keys: Vec<String> = [Some(rule_id), cve_hint]
            .into_iter()
            .flatten()
            .map(|s| s.trim().to_uppercase())
            .collect();

        let ext_match = keys.iter().find_map(|k| self.external_by_id.get(k));
        let emb_match = keys.iter().find_map(|k| self.embedded_by_id.get(k));

        let fixed_version = ext_match
            .and_then(|m| m.fixed_version.clone())
            .or_else(|| emb_match.and_then(|m| m.fixed_version.clone()));

        let (default_cvss, default_epss) = match level {
            SarifLevel::Error => (7.5, 0.35),
            SarifLevel::Warning => (5.0, 0.15),
            SarifLevel::Note => (2.5, 0.05),
            SarifLevel::None => (0.0, 0.01),
        };

        // 1. Both CVSS and EPSS explicitly attached in SARIF properties
        if let (Some(c), Some(e)) = (explicit_cvss, explicit_epss) {
            if c.is_finite() && e.is_finite() {
                return (
                    sanitize_clamped(c, 0.0, 10.0, default_cvss),
                    sanitize_clamped(e, 0.0, 1.0, default_epss),
                    ScoreSource::SarifProperty,
                    fixed_version,
                );
            }
        }

        // 2. External offline EPSS bundle
        if let Some(ext) = ext_match {
            let cvss = explicit_cvss
                .filter(|v| v.is_finite())
                .or(ext.cvss)
                .or_else(|| emb_match.and_then(|m| m.cvss))
                .unwrap_or(default_cvss);
            return (
                sanitize_clamped(cvss, 0.0, 10.0, default_cvss),
                ext.epss,
                ScoreSource::ExternalEpssDb,
                fixed_version,
            );
        }

        // 3. Embedded VulnerabilityDatabase
        if let Some(emb) = emb_match {
            let cvss = explicit_cvss
                .filter(|v| v.is_finite())
                .or(emb.cvss)
                .unwrap_or(default_cvss);
            let epss = explicit_epss.filter(|v| v.is_finite()).unwrap_or(emb.epss);
            return (
                sanitize_clamped(cvss, 0.0, 10.0, default_cvss),
                sanitize_clamped(epss, 0.0, 1.0, default_epss),
                ScoreSource::AdvisoryDb,
                fixed_version,
            );
        }

        // 4. CWE heuristic priors for SAST / API / IaC findings
        if let Some((cwe_cvss, cwe_epss)) = cwe_hint.and_then(lookup_cwe_prior) {
            let cvss = explicit_cvss.filter(|v| v.is_finite()).unwrap_or(cwe_cvss);
            let epss = explicit_epss.filter(|v| v.is_finite()).unwrap_or(cwe_epss);
            return (
                sanitize_clamped(cvss, 0.0, 10.0, default_cvss),
                sanitize_clamped(epss, 0.0, 1.0, default_epss),
                ScoreSource::CweHeuristic,
                fixed_version,
            );
        }

        // 5. Fallback severity default (never 0.0 for Error/Warning)
        let cvss = explicit_cvss
            .filter(|v| v.is_finite())
            .unwrap_or(default_cvss);
        let epss = explicit_epss
            .filter(|v| v.is_finite())
            .unwrap_or(default_epss);
        let source = if explicit_cvss.is_some() && explicit_cvss.is_some_and(f64::is_finite) {
            ScoreSource::SarifProperty
        } else {
            ScoreSource::SeverityDefault
        };

        (
            sanitize_clamped(cvss, 0.0, 10.0, default_cvss),
            sanitize_clamped(epss, 0.0, 1.0, default_epss),
            source,
            fixed_version,
        )
    }

    pub fn lookup_fixed_version(&self, rule_id: &str) -> Option<String> {
        let key = rule_id.trim().to_uppercase();
        self.external_by_id
            .get(&key)
            .and_then(|m| m.fixed_version.clone())
            .or_else(|| {
                self.embedded_by_id
                    .get(&key)
                    .and_then(|m| m.fixed_version.clone())
            })
    }
}

#[derive(Debug, Deserialize)]
struct ExternalEpssRecord {
    epss: f64,
    #[serde(default)]
    cvss: Option<f64>,
    #[serde(default)]
    fixed_version: Option<String>,
}

fn lookup_cwe_prior(cwe: &str) -> Option<(f64, f64)> {
    let norm = cwe.trim().to_uppercase();
    let code = norm.strip_prefix("CWE-").unwrap_or(&norm);
    match code {
        "89" => Some((9.8, 0.85)),  // SQL Injection
        "78" => Some((9.8, 0.88)),  // OS Command Injection
        "94" => Some((9.8, 0.85)),  // Code Injection / RCE
        "502" => Some((9.8, 0.82)), // Insecure Deserialization
        "918" => Some((8.6, 0.72)), // SSRF
        "798" => Some((9.0, 0.75)), // Hardcoded Credentials
        "22" => Some((7.5, 0.65)),  // Path Traversal
        "79" => Some((6.1, 0.45)),  // Cross-Site Scripting (XSS)
        "327" => Some((5.9, 0.15)), // Broken Cryptography
        "250" => Some((7.8, 0.35)), // Execution with Unnecessary Privileges
        _ => None,
    }
}
