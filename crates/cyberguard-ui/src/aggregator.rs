//! Executive metrics aggregator ingesting SARIF v2.1.0 telemetry.

#![deny(unsafe_code)]

use crate::error::UiError;
use crate::models::{
    ComplianceCategory, EngineCount, ExecutiveFindingSummary, ExecutiveReport, PostureGrade,
    PostureScore, SeverityCount,
};
use crate::traits::ReportAggregator;
use chrono::Utc;
use cyberguard_core::sarif::{SarifLevel, SarifLog};
use std::collections::HashMap;

#[derive(Default, Clone)]
pub struct DefaultMetricsAggregator;

impl DefaultMetricsAggregator {
    pub fn new() -> Self {
        Self
    }

    fn classify_severity(rule_id: &str, level: &SarifLevel) -> &'static str {
        match level {
            SarifLevel::Error => {
                if rule_id.contains("SQLI")
                    || rule_id.contains("CMDI")
                    || rule_id.contains("SEC-AWS")
                    || rule_id.contains("SEC-OPENAI")
                    || rule_id.contains("SEC-STRIPE")
                {
                    "Critical"
                } else {
                    "High"
                }
            }
            SarifLevel::Warning => "Medium",
            SarifLevel::Note => "Low",
            SarifLevel::None => "Info",
        }
    }

    fn detect_engine(rule_id: &str, driver_name: &str) -> &'static str {
        if rule_id.starts_with("CG-SEC") {
            "Secrets"
        } else if rule_id.starts_with("IAC") {
            "IaC Security"
        } else if rule_id.starts_with("PIPELINE") {
            "CI/CD Pipeline"
        } else if rule_id.starts_with("MOB") {
            "Mobile App"
        } else if rule_id.starts_with("CG-DOCKER") || rule_id.starts_with("CG-CONT") {
            "Container"
        } else if rule_id.starts_with("API-") {
            "API Contract"
        } else if rule_id.starts_with("CG-") {
            "SAST"
        } else if !driver_name.is_empty() {
            "Security Engine"
        } else {
            "General"
        }
    }

    fn calculate_posture_score(severities: &SeverityCount) -> PostureScore {
        let penalty = (severities.critical * 25)
            + (severities.high * 10)
            + (severities.medium * 3)
            + severities.low;

        let score = if penalty >= 100 {
            0
        } else {
            (100 - penalty) as u32
        };

        let grade = match score {
            90..=100 => PostureGrade::A,
            75..=89 => PostureGrade::B,
            60..=74 => PostureGrade::C,
            40..=59 => PostureGrade::D,
            _ => PostureGrade::F,
        };

        PostureScore {
            score,
            grade,
            label: grade.as_str().to_string(),
        }
    }

    fn generate_compliance_scorecard(
        results_count: usize,
        severities: &SeverityCount,
    ) -> Vec<ComplianceCategory> {
        vec![
            ComplianceCategory {
                framework: "OWASP Top 10 (2021)".to_string(),
                requirement: "A03:2021 - Injection (SQLi, CMDI)".to_string(),
                status: if severities.critical == 0 {
                    "Passed".to_string()
                } else {
                    "Action Required".to_string()
                },
                finding_count: severities.critical,
            },
            ComplianceCategory {
                framework: "OWASP Top 10 (2021)".to_string(),
                requirement: "A07:2021 - Identification & Authentication Failures".to_string(),
                status: if severities.high == 0 {
                    "Passed".to_string()
                } else {
                    "Review Needed".to_string()
                },
                finding_count: severities.high,
            },
            ComplianceCategory {
                framework: "CIS Benchmarks".to_string(),
                requirement: "Hardening & Least Privilege Access".to_string(),
                status: if severities.medium <= 2 {
                    "Compliant".to_string()
                } else {
                    "Non-Compliant".to_string()
                },
                finding_count: severities.medium,
            },
            ComplianceCategory {
                framework: "MITRE ATT&CK".to_string(),
                requirement: "T1190 - Exploit Public-Facing Application".to_string(),
                status: if results_count == 0 {
                    "Clean".to_string()
                } else {
                    "Exposed".to_string()
                },
                finding_count: results_count,
            },
        ]
    }
}

impl ReportAggregator for DefaultMetricsAggregator {
    fn aggregate_sarif(
        &self,
        sarif: &SarifLog,
        target_name: &str,
    ) -> Result<ExecutiveReport, UiError> {
        let mut severities = SeverityCount::default();
        let mut engine_map: HashMap<String, usize> = HashMap::new();
        let mut top_findings = Vec::new();

        for run in &sarif.runs {
            let driver_name = run.tool.driver.name.as_str();

            for res in &run.results {
                let rule_id = res.rule_id.as_str();
                let severity_str = Self::classify_severity(rule_id, &res.level);

                match severity_str {
                    "Critical" => severities.critical += 1,
                    "High" => severities.high += 1,
                    "Medium" => severities.medium += 1,
                    "Low" => severities.low += 1,
                    _ => severities.info += 1,
                }

                let engine = Self::detect_engine(rule_id, driver_name);
                *engine_map.entry(engine.to_string()).or_insert(0) += 1;

                let (file_path, line) = if let Some(loc) = res.locations.first() {
                    if let Some(ref phys) = loc.physical_location {
                        let path = phys.artifact_location.uri.clone();
                        let line = phys.region.as_ref().map(|r| r.start_line).unwrap_or(1);
                        (path, line)
                    } else {
                        ("unknown".to_string(), 1)
                    }
                } else {
                    ("unknown".to_string(), 1)
                };

                let remediation = if rule_id.contains("SQLI") {
                    "Use parameterized queries or ORM binding".to_string()
                } else if rule_id.contains("CMDI") {
                    "Pass arguments as argv arrays without shell interpolation".to_string()
                } else if rule_id.contains("SEC-") {
                    "Revoke token immediately and extract to environment variable".to_string()
                } else {
                    "Apply input validation and follow defensive security practices".to_string()
                };

                if top_findings.len() < 25 {
                    top_findings.push(ExecutiveFindingSummary {
                        id: format!("FINDING-{:04}", top_findings.len() + 1),
                        rule_id: rule_id.to_string(),
                        engine: engine.to_string(),
                        severity: severity_str.to_string(),
                        file_path,
                        line,
                        title: res.message.text.clone(),
                        remediation,
                    });
                }
            }
        }

        let mut engine_breakdown: Vec<EngineCount> = engine_map
            .into_iter()
            .map(|(engine, count)| EngineCount { engine, count })
            .collect();
        engine_breakdown.sort_by_key(|a| std::cmp::Reverse(a.count));

        let total_findings = severities.total();
        let posture = Self::calculate_posture_score(&severities);
        let compliance = Self::generate_compliance_scorecard(total_findings, &severities);
        let attack_choke_points = if severities.critical > 0 {
            std::cmp::max(1, severities.critical / 2)
        } else {
            0
        };

        Ok(ExecutiveReport {
            title: format!("Aegix Executive Security Report - {}", target_name),
            target: target_name.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            posture,
            total_findings,
            severities,
            engine_breakdown,
            compliance,
            top_findings,
            attack_choke_points,
        })
    }
}
