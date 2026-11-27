//! Public traits for metrics aggregation, report generation, and dashboard rendering.

#![deny(unsafe_code)]

use crate::error::UiError;
use crate::models::ExecutiveReport;
use cyberguard_core::sarif::SarifLog;

pub trait ReportAggregator {
    fn aggregate_sarif(
        &self,
        sarif: &SarifLog,
        target_name: &str,
    ) -> Result<ExecutiveReport, UiError>;
}

pub trait ReportGenerator {
    fn generate_html(&self, report: &ExecutiveReport) -> Result<String, UiError>;
}

pub trait DashboardRenderer {
    fn render_dashboard(&self, report: &ExecutiveReport) -> Result<String, UiError>;
}
