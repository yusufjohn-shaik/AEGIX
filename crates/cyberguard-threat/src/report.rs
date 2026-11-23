//! Threat report formatting and visualization engine (Terminal & JSON).

#![deny(unsafe_code)]

use crate::catalog::StaticThreatCatalog;
use crate::error::ThreatError;
use crate::models::{StrideCategory, ThreatReport};
use crate::traits::AttackMapper;

/// Formatter for terminal output and serialization.
pub struct ThreatReportFormatter;

impl ThreatReportFormatter {
    /// Formats the threat report into clean terminal output.
    pub fn render_terminal(report: &ThreatReport, catalog: &StaticThreatCatalog) -> String {
        let mut out = String::new();

        out.push_str(
            "================================================================================\n",
        );
        out.push_str(
            "                   AEGIX THREAT MODELING & ATT&CK MATRIX                        \n",
        );
        out.push_str(
            "================================================================================\n",
        );
        out.push_str(&format!(" Domain:            {}\n", report.domain.as_str()));
        out.push_str(&format!(
            " Generated At:      {}\n",
            report.generated_at.to_rfc3339()
        ));
        out.push_str(&format!(" Evaluated Findings: {}\n", report.total_findings));
        if report.suppressed_count > 0 {
            out.push_str(&format!(
                " Suppressed by Baseline: {}\n",
                report.suppressed_count
            ));
        }
        out.push('\n');

        // 1. STRIDE Threat Distribution
        out.push_str(
            "--- STRIDE THREAT PROPERTY PROFILE ---------------------------------------------\n",
        );
        out.push_str(
            format!(
                "{:<4} {:<24} {:<18} {:<8}\n",
                "Cat", "Threat Category", "Security Property", "Count"
            )
            .as_str(),
        );
        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );

        for cat in StrideCategory::all() {
            let count = report.stride_counts.get(cat).copied().unwrap_or(0);
            out.push_str(&format!(
                " [{}]  {:<24} {:<18} {:<8}\n",
                cat.letter(),
                cat.title(),
                cat.security_property(),
                count
            ));
        }
        out.push('\n');

        // 2. MITRE ATT&CK Matrix Techniques
        out.push_str(
            "--- MITRE ATT&CK TECHNIQUES DETECTED -------------------------------------------\n",
        );
        out.push_str(
            format!(
                "{:<8} {:<34} {:<20} {:<6} {:<6}\n",
                "ID", "Technique Name", "Tactic", "Count", "Score"
            )
            .as_str(),
        );
        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );

        if report.navigator_layer.techniques.is_empty() {
            out.push_str(" No MITRE ATT&CK techniques identified in ingested telemetry.\n");
        } else {
            for entry in &report.navigator_layer.techniques {
                let name = catalog
                    .get_technique_details(&entry.technique_id)
                    .map(|t| t.name)
                    .unwrap_or_else(|| "Unknown Technique".to_string());

                let score_str = entry
                    .score
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "-".to_string());

                let count_str = entry
                    .metadata
                    .iter()
                    .find(|m| m.name == "findingsCount")
                    .map(|m| m.value.as_str())
                    .unwrap_or("1");

                let name_truncated = if name.len() > 32 {
                    format!("{}...", &name[..29])
                } else {
                    name
                };

                out.push_str(&format!(
                    " {:<7} {:<34} {:<20} {:<6} {:<6}\n",
                    entry.technique_id, name_truncated, entry.tactic, count_str, score_str
                ));
            }
        }
        out.push_str(
            "================================================================================\n",
        );

        out
    }

    /// Serializes the ThreatReport into formatted JSON.
    pub fn to_json(report: &ThreatReport) -> Result<String, ThreatError> {
        serde_json::to_string_pretty(report).map_err(ThreatError::Json)
    }

    /// Serializes the MITRE ATT&CK Navigator Layer into formatted JSON.
    pub fn to_navigator_json(report: &ThreatReport) -> Result<String, ThreatError> {
        serde_json::to_string_pretty(&report.navigator_layer).map_err(ThreatError::Json)
    }
}
