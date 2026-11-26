//! Safe ANSI/plain terminal exporter with control-character stripping.

#![deny(unsafe_code)]

use crate::error::RiskError;
use crate::models::{RiskPrioritizationReport, RiskTier};
use crate::traits::RiskExporter;
use std::fmt::Write;

/// Strips ASCII/C1 control characters to prevent ANSI escape injection from untrusted SARIF or code strings.
pub fn sanitize_terminal_text(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            let code = c as u32;
            c == ' ' || (!(code < 0x20 || code == 0x7F || (0x80..=0x9F).contains(&code)))
        })
        .collect()
}

#[derive(Debug, Default, Clone)]
pub struct TerminalExporter {
    pub use_colors: bool,
}

impl TerminalExporter {
    pub fn new(use_colors: bool) -> Self {
        Self { use_colors }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.use_colors {
            format!("{}{}\x1b[0m", code, text)
        } else {
            text.to_string()
        }
    }
}

impl RiskExporter for TerminalExporter {
    fn export(&self, report: &RiskPrioritizationReport) -> Result<String, RiskError> {
        let mut out = String::new();
        let bold = "\x1b[1m";
        let red = "\x1b[31;1m";
        let yellow = "\x1b[33;1m";
        let cyan = "\x1b[36;1m";
        let green = "\x1b[32;1m";
        let gray = "\x1b[90m";

        writeln!(
            out,
            "{}",
            self.paint(
                bold,
                "=================================================================="
            )
        )?;
        writeln!(
            out,
            "{}",
            self.paint(
                bold,
                "           AEGIX TRI-FACTOR PRIORITIZER & REACHABILITY            "
            )
        )?;
        writeln!(
            out,
            "{}",
            self.paint(
                bold,
                "=================================================================="
            )
        )?;
        writeln!(
            out,
            "Target: {} | Packages: {} | Functions Analyzed: {}",
            sanitize_terminal_text(&report.target_path.display().to_string()),
            self.paint(cyan, &report.workspace_packages.to_string()),
            self.paint(cyan, &report.analyzed_nodes.to_string())
        )?;
        writeln!(
            out,
            "Totals: {} analyzed | {} Critical | {} High | {} Medium | {} Low | {} Suppressed ({} unreachable)\n",
            report.total_findings,
            self.paint(red, &report.critical_count.to_string()),
            self.paint(red, &report.high_count.to_string()),
            self.paint(yellow, &report.medium_count.to_string()),
            self.paint(cyan, &report.low_count.to_string()),
            self.paint(gray, &report.suppressed_count.to_string()),
            report.suppressed_unreachable
        )?;

        for warn in &report.warnings {
            writeln!(
                out,
                "{} {}",
                self.paint(yellow, "[WARN]"),
                sanitize_terminal_text(warn)
            )?;
        }
        if !report.warnings.is_empty() {
            writeln!(out)?;
        }

        if report.findings.is_empty() {
            writeln!(
                out,
                "{}",
                self.paint(
                    green,
                    "No prioritized actionable findings matched the selected filters."
                )
            )?;
            return Ok(out);
        }

        for (idx, f) in report.findings.iter().enumerate() {
            let (tier_label, tier_color) = match f.breakdown.tier {
                RiskTier::Critical => ("CRITICAL  ", red),
                RiskTier::High => ("HIGH      ", red),
                RiskTier::Medium => ("MEDIUM    ", yellow),
                RiskTier::Low => ("LOW       ", cyan),
                RiskTier::Suppressed => ("SUPPRESSED", gray),
            };

            let target_disp = match &f.version {
                Some(v) => format!(
                    "{}@{}",
                    sanitize_terminal_text(&f.package_or_target),
                    sanitize_terminal_text(v)
                ),
                None => sanitize_terminal_text(&f.package_or_target),
            };

            writeln!(
                out,
                "{}. [{}] {} | {} | Score: {}",
                idx + 1,
                self.paint(tier_color, tier_label),
                sanitize_terminal_text(&f.rule_id),
                target_disp,
                self.paint(
                    tier_color,
                    &format!("{:.2}/10", f.breakdown.tri_factor_score)
                )
            )?;
            writeln!(
                out,
                "   ├── CVSS: {:.1} | EPSS: {:.2} ({}) | Reachability: {:.2} [{}]",
                f.breakdown.cvss,
                f.breakdown.epss,
                f.breakdown.score_source.as_str(),
                f.breakdown.reachability,
                f.breakdown.status.as_str()
            )?;
            writeln!(out, "   ├── {}", sanitize_terminal_text(&f.summary))?;
            if !f.breakdown.call_trace.is_empty() {
                let sanitized_trace: Vec<String> = f
                    .breakdown
                    .call_trace
                    .iter()
                    .map(|s| sanitize_terminal_text(s))
                    .collect();
                writeln!(out, "   ├── Call Trace: {}", sanitized_trace.join(" -> "))?;
            }
            writeln!(
                out,
                "   └── Evidence: {}",
                sanitize_terminal_text(&f.breakdown.evidence)
            )?;
            if let Some(ref fixed) = f.fixed_version {
                writeln!(
                    out,
                    "   └── Remediation: Upgrade to {}",
                    self.paint(green, &sanitize_terminal_text(fixed))
                )?;
            }
        }

        Ok(out)
    }
}
