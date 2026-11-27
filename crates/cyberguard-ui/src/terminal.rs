//! High-impact ANSI terminal dashboard renderer and widgets for Aegix.

#![deny(unsafe_code)]

use crate::error::UiError;
use crate::models::{ExecutiveReport, PostureGrade};
use crate::traits::DashboardRenderer;

#[derive(Clone, Debug)]
pub struct DefaultTerminalDashboard {
    use_color: bool,
}

impl Default for DefaultTerminalDashboard {
    fn default() -> Self {
        Self::new(true)
    }
}

impl DefaultTerminalDashboard {
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    fn colorize(&self, text: &str, color_code: &str) -> String {
        if self.use_color {
            format!("\x1b[{}m{}\x1b[0m", color_code, text)
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        if self.use_color {
            format!("\x1b[1m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn render_gauge(&self, score: u32, grade: PostureGrade) -> String {
        let filled_blocks = (score as usize / 5).min(20);
        let empty_blocks = 20 - filled_blocks;

        let filled = "■".repeat(filled_blocks);
        let empty = "░".repeat(empty_blocks);

        let color = match grade {
            PostureGrade::A => "32", // Green
            PostureGrade::B => "32",
            PostureGrade::C => "33", // Yellow
            PostureGrade::D => "31", // Red
            PostureGrade::F => "31",
        };

        format!(
            "[{}{}] {}/100 ({})",
            self.colorize(&filled, color),
            self.colorize(&empty, "90"),
            score,
            grade.as_str()
        )
    }
}

impl DashboardRenderer for DefaultTerminalDashboard {
    fn render_dashboard(&self, report: &ExecutiveReport) -> Result<String, UiError> {
        let mut out = String::new();

        // Banner Header
        out.push_str(&self.colorize(
            "┌──────────────────────────────────────────────────────────────────────────────┐\n",
            "36",
        ));
        out.push_str(&format!(
            "│ {} │\n",
            self.bold(&format!("{:<76}", report.title))
        ));
        out.push_str(&format!(
            "│ Target: {:<68} │\n",
            self.colorize(&format!("{:<68}", report.target), "90")
        ));
        out.push_str(&self.colorize(
            "├──────────────────────────────────────────────────────────────────────────────┤\n",
            "36",
        ));

        // KPI Summary Cards
        out.push_str(
            "│  SECURITY POSTURE SCORE                                                      │\n",
        );
        out.push_str(&format!(
            "│  {:<83} │\n",
            self.render_gauge(report.posture.score, report.posture.grade)
        ));
        out.push_str(
            "│                                                                              │\n",
        );
        out.push_str(&format!(
            "│  Total Findings: {:<12} Critical: {:<12} Choke Points: {:<11} │\n",
            self.bold(&report.total_findings.to_string()),
            self.colorize(&report.severities.critical.to_string(), "31"),
            self.colorize(&report.attack_choke_points.to_string(), "33")
        ));
        out.push_str(&self.colorize(
            "├──────────────────────────────────────────────────────────────────────────────┤\n",
            "36",
        ));

        // Severity Breakdown
        out.push_str(
            "│  SEVERITY SPECTRUM                                                           │\n",
        );
        out.push_str(&format!(
            "│  Critical: {:<5} High: {:<5} Medium: {:<5} Low: {:<5} Info: {:<11} │\n",
            self.colorize(&report.severities.critical.to_string(), "31"),
            self.colorize(&report.severities.high.to_string(), "33"),
            self.colorize(&report.severities.medium.to_string(), "33"),
            self.colorize(&report.severities.low.to_string(), "34"),
            self.colorize(&report.severities.info.to_string(), "90")
        ));
        out.push_str(&self.colorize(
            "├──────────────────────────────────────────────────────────────────────────────┤\n",
            "36",
        ));

        // Compliance Status
        out.push_str(
            "│  REGULATORY COMPLIANCE SCORECARD                                             │\n",
        );
        for comp in &report.compliance {
            let status_tag = if comp.status == "Passed"
                || comp.status == "Compliant"
                || comp.status == "Clean"
            {
                self.colorize("[PASS]", "32")
            } else {
                self.colorize("[FAIL]", "31")
            };
            out.push_str(&format!(
                "│  {} {:<28} {:<38} │\n",
                status_tag, comp.framework, comp.requirement
            ));
        }
        out.push_str(&self.colorize(
            "├──────────────────────────────────────────────────────────────────────────────┤\n",
            "36",
        ));

        // Top Vulnerabilities
        out.push_str(
            "│  TOP IDENTIFIED VULNERABILITIES                                              │\n",
        );
        if report.top_findings.is_empty() {
            out.push_str("│  ✅ No security vulnerabilities detected in target.                          │\n");
        } else {
            for f in report.top_findings.iter().take(5) {
                let sev_badge = match f.severity.as_str() {
                    "Critical" => self.colorize("[CRIT]", "31"),
                    "High" => self.colorize("[HIGH]", "33"),
                    "Medium" => self.colorize("[MED ]", "33"),
                    _ => self.colorize("[LOW ]", "34"),
                };
                let loc = format!("{}:{}", f.file_path, f.line);
                out.push_str(&format!(
                    "│  {} {:<16} {:<24} {:<22} │\n",
                    sev_badge,
                    f.rule_id,
                    if f.title.len() > 24 {
                        &f.title[..24]
                    } else {
                        &f.title
                    },
                    if loc.len() > 22 { &loc[..22] } else { &loc }
                ));
            }
        }
        out.push_str(&self.colorize(
            "└──────────────────────────────────────────────────────────────────────────────┘\n",
            "36",
        ));

        Ok(out)
    }
}
