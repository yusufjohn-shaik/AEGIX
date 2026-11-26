//! Enriched OASIS SARIF v2.1.0 exporter with Tri-Factor properties and CodeFlow call traces.

#![deny(unsafe_code)]

use crate::error::RiskError;
use crate::models::{RiskPrioritizationReport, RiskTier};
use crate::traits::RiskExporter;
use cyberguard_core::sarif::{
    ArtifactLocation, CodeFlow, Location, Message, PhysicalLocation, Region, ReportingDescriptor,
    SarifLevel, SarifLog, SarifResult, ThreadFlow, ThreadFlowLocation,
};
use std::collections::BTreeSet;

#[derive(Debug, Default, Clone)]
pub struct SarifExporter;

impl SarifExporter {
    pub fn new() -> Self {
        Self
    }
}

impl RiskExporter for SarifExporter {
    fn export(&self, report: &RiskPrioritizationReport) -> Result<String, RiskError> {
        let mut sarif = SarifLog::new("cyberguard-risk", env!("CARGO_PKG_VERSION"));
        let mut registered_rules: BTreeSet<String> = BTreeSet::new();

        for f in &report.findings {
            let level = match f.breakdown.tier {
                RiskTier::Critical | RiskTier::High => SarifLevel::Error,
                RiskTier::Medium => SarifLevel::Warning,
                RiskTier::Low | RiskTier::Suppressed => SarifLevel::Note,
            };

            let msg = format!(
                "{} [Tri-Factor: {:.2}, Reachability: {} ({:.2})]",
                f.summary,
                f.breakdown.tri_factor_score,
                f.breakdown.status.as_str(),
                f.breakdown.reachability
            );

            let mut res = SarifResult::new(&f.rule_id, level, msg);

            if let Some(ref file) = f.file_path {
                let line = f.line.unwrap_or(1);
                res.add_location(file, line, Some(1), Some(line), None);
            }

            // Attach baseline Tri-Factor property contract compatible with `to_ocsf`
            res.with_tri_factor(f.breakdown.cvss, f.breakdown.epss, f.breakdown.reachability);

            if let Some(serde_json::Value::Object(ref mut props)) = res.properties {
                props.insert(
                    "reachabilityStatus".to_string(),
                    serde_json::json!(f.breakdown.status.as_str()),
                );
                props.insert(
                    "riskTier".to_string(),
                    serde_json::json!(f.breakdown.tier.as_str()),
                );
                props.insert(
                    "scoreSource".to_string(),
                    serde_json::json!(f.breakdown.score_source.as_str()),
                );
                props.insert(
                    "callTrace".to_string(),
                    serde_json::json!(f.breakdown.call_trace),
                );
                props.insert(
                    "evidence".to_string(),
                    serde_json::json!(f.breakdown.evidence),
                );
                props.insert(
                    "package".to_string(),
                    serde_json::json!(f.package_or_target),
                );
                if let Some(ref v) = f.version {
                    props.insert("version".to_string(), serde_json::json!(v));
                }
                if let Some(ref fv) = f.fixed_version {
                    props.insert("fixedVersion".to_string(), serde_json::json!(fv));
                }
            }

            if !f.breakdown.call_trace.is_empty() {
                let mut thread_locs = Vec::with_capacity(f.breakdown.call_trace.len());
                let total_steps = f.breakdown.call_trace.len();

                for (idx, step_str) in f.breakdown.call_trace.iter().enumerate() {
                    let uri = if let Some((file_part, _fn_part)) = step_str.split_once("::") {
                        if file_part.ends_with(".rs") {
                            file_part.to_string()
                        } else {
                            format!("cargo://crate/{}", step_str.replace("::", "/"))
                        }
                    } else {
                        format!("cargo://symbol/{}", step_str)
                    };

                    let importance = if idx == 0 || idx + 1 == total_steps {
                        "essential"
                    } else {
                        "important"
                    };

                    thread_locs.push(ThreadFlowLocation {
                        location: Location {
                            physical_location: Some(PhysicalLocation {
                                artifact_location: ArtifactLocation { uri },
                                region: Some(Region {
                                    start_line: f.line.unwrap_or(1),
                                    start_column: Some(1),
                                    end_line: None,
                                    end_column: None,
                                }),
                            }),
                        },
                        step: Some(idx + 1),
                        importance: Some(importance.to_string()),
                    });
                }

                res.add_code_flow(CodeFlow {
                    message: Some(Message {
                        text: format!("Entrypoint call-graph trace for {}", f.rule_id),
                    }),
                    thread_flows: vec![ThreadFlow {
                        message: Some(Message {
                            text: "Static reachability path".to_string(),
                        }),
                        locations: thread_locs,
                    }],
                });
            }

            res.compute_deterministic_fingerprint();
            sarif.add_result(res);

            if registered_rules.insert(f.rule_id.clone()) {
                sarif.add_rule(ReportingDescriptor {
                    id: f.rule_id.clone(),
                    name: None,
                    short_description: Message {
                        text: f.summary.clone(),
                    },
                    full_description: Some(Message {
                        text: f.breakdown.evidence.clone(),
                    }),
                    help_uri: None,
                });
            }
        }

        serde_json::to_string_pretty(&sarif).map_err(RiskError::Json)
    }
}
