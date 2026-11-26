//! Pretty JSON exporter for Tri-Factor Prioritization reports.

#![deny(unsafe_code)]

use crate::error::RiskError;
use crate::models::RiskPrioritizationReport;
use crate::traits::RiskExporter;

#[derive(Debug, Default, Clone)]
pub struct JsonExporter;

impl JsonExporter {
    pub fn new() -> Self {
        Self
    }
}

impl RiskExporter for JsonExporter {
    fn export(&self, report: &RiskPrioritizationReport) -> Result<String, RiskError> {
        serde_json::to_string_pretty(report).map_err(RiskError::Json)
    }
}
