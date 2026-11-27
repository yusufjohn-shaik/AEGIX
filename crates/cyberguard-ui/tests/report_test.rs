//! Tests for `cyberguard-ui` executive metrics aggregator and HTML generator.

#![deny(unsafe_code)]

use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use cyberguard_ui::{
    DefaultHtmlReportGenerator, DefaultMetricsAggregator, ReportAggregator, ReportGenerator,
};

fn create_sample_sarif() -> SarifLog {
    let mut log = SarifLog::new("cyberguard-sast", "0.9.0");

    // 1. SQL Injection (Critical)
    let mut res1 = SarifResult::new(
        "CG-SQLI-001",
        SarifLevel::Error,
        "Unsanitized input concatenated into SQL query",
    );
    res1.add_location("src/db.rs", 42, Some(5), Some(42), None);
    log.add_result(res1);

    // 2. AWS Key (Critical)
    let mut res2 = SarifResult::new(
        "CG-SEC-AWS-001",
        SarifLevel::Error,
        "Plaintext AWS Secret Access Key",
    );
    res2.add_location("config/aws.env", 10, Some(1), Some(10), None);
    log.add_result(res2);

    log
}

#[test]
fn test_metrics_aggregation() {
    let sarif = create_sample_sarif();
    let aggregator = DefaultMetricsAggregator::new();
    let report = aggregator
        .aggregate_sarif(&sarif, "test-target")
        .expect("aggregation succeeds");

    assert_eq!(report.target, "test-target");
    assert_eq!(report.total_findings, 2);
    assert_eq!(report.severities.critical, 2);
    assert_eq!(report.severities.high, 0);
    // 100 - (2 * 25) = 50 -> Grade D
    assert_eq!(report.posture.score, 50);
    assert_eq!(report.posture.grade, cyberguard_ui::PostureGrade::D);
    assert!(report.engine_breakdown.iter().any(|e| e.engine == "SAST"));
    assert!(report
        .engine_breakdown
        .iter()
        .any(|e| e.engine == "Secrets"));
    assert_eq!(report.top_findings.len(), 2);
    assert_eq!(report.compliance.len(), 4);
}

#[test]
fn test_html_report_generation() {
    let sarif = create_sample_sarif();
    let aggregator = DefaultMetricsAggregator::new();
    let report = aggregator
        .aggregate_sarif(&sarif, "test-target")
        .expect("aggregation succeeds");

    let generator = DefaultHtmlReportGenerator::new();
    let html = generator
        .generate_html(&report)
        .expect("HTML generation succeeds");

    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Aegix Executive Security Report - test-target"));
    assert!(html.contains("Grade: D"));
    assert!(html.contains("posture-gauge"));
    assert!(html.contains("CG-SQLI-001"));
    assert!(html.contains("CG-SEC-AWS-001"));
    assert!(html.contains("@media print"));
    assert!(html.contains("OWASP Top 10"));
    assert!(html.contains("CIS Benchmarks"));
}
