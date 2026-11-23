#![deny(unsafe_code)]

use cyberguard_core::baseline::AegixBaseline;
use cyberguard_threat::engine::ThreatEngine;
use cyberguard_threat::models::{MitreMatrixDomain, MitreTactic, StrideCategory};
use cyberguard_threat::report::ThreatReportFormatter;
use cyberguard_threat::traits::ThreatScanner;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("threat")
        .join(name)
}

#[tokio::test]
async fn test_threat_cli_sarif_sql_injection_scan() {
    let fixture = fixture_path("sarif_sql_injection.json");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = ThreatEngine::new().with_domain(MitreMatrixDomain::EnterpriseAttack);
    let report = engine.scan_file(&fixture).await.unwrap();

    assert_eq!(report.total_findings, 1);
    assert_eq!(report.findings[0].source_rule_id, "CG-SAST-SQLI");
    assert!(report.findings[0]
        .tactics
        .contains(&MitreTactic::InitialAccess));
    assert!(report.findings[0].techniques.contains(&"T1190".to_string()));
    assert!(report.findings[0]
        .stride_categories
        .contains(&StrideCategory::Tampering));

    // Verify Navigator Layer
    assert_eq!(report.navigator_layer.domain, "enterprise-attack");
    let t1190_entry = report
        .navigator_layer
        .techniques
        .iter()
        .find(|t| t.technique_id == "T1190")
        .expect("T1190 must be present in Navigator layer");
    assert!(t1190_entry.score.unwrap_or(0.0) >= 6.6);
}

#[tokio::test]
async fn test_threat_cli_sarif_multi_domain_scan() {
    let fixture = fixture_path("sarif_multi_domain.json");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = ThreatEngine::new().with_domain(MitreMatrixDomain::EnterpriseAttack);
    let report = engine.scan_file(&fixture).await.unwrap();

    assert_eq!(report.total_findings, 3);

    // Assert STRIDE Category counts
    assert_eq!(
        report
            .stride_counts
            .get(&StrideCategory::InformationDisclosure),
        Some(&1)
    );
    assert_eq!(
        report
            .stride_counts
            .get(&StrideCategory::ElevationOfPrivilege),
        Some(&1)
    );
    assert_eq!(
        report.stride_counts.get(&StrideCategory::DenialOfService),
        Some(&1)
    );

    // Assert Techniques detected
    assert!(report.technique_counts.contains_key("T1552"));
    assert!(report.technique_counts.contains_key("T1499"));
    assert!(
        report.technique_counts.contains_key("T1611")
            || report.technique_counts.contains_key("T1068")
    );
}

#[tokio::test]
async fn test_threat_cli_terminal_and_navigator_export() {
    let fixture = fixture_path("sarif_multi_domain.json");
    let engine = ThreatEngine::new();
    let report = engine.scan_file(&fixture).await.unwrap();

    // Terminal render
    let term = ThreatReportFormatter::render_terminal(&report, engine.catalog());
    assert!(term.contains("AEGIX THREAT MODELING & ATT&CK MATRIX"));
    assert!(term.contains("STRIDE THREAT PROPERTY PROFILE"));
    assert!(term.contains("T1552"));
    assert!(term.contains("T1499"));

    // Navigator JSON export
    let nav_json = ThreatReportFormatter::to_navigator_json(&report).unwrap();
    assert!(nav_json.contains("\"attack\": \"14\""));
    assert!(nav_json.contains("\"navigator\": \"4.5\""));
    assert!(nav_json.contains("\"techniqueID\": \"T1552\""));
}

#[tokio::test]
async fn test_threat_cli_baseline_filtering() {
    let fixture = fixture_path("sarif_multi_domain.json");
    let initial_engine = ThreatEngine::new();
    let initial_report = initial_engine.scan_file(&fixture).await.unwrap();
    assert_eq!(initial_report.total_findings, 3);

    // Create baseline containing finding 0 (CG-SEC-001)
    let sarif_export = initial_engine.export_sarif_report(&initial_report).unwrap();
    let first_result = &sarif_export.runs[0].results[0];
    let baseline = AegixBaseline::from_results(std::slice::from_ref(first_result));

    // Scan with baseline suppression enabled
    let engine_with_baseline = ThreatEngine::new().with_baseline(baseline);
    let filtered_report = engine_with_baseline.scan_file(&fixture).await.unwrap();

    assert_eq!(filtered_report.suppressed_count, 1);
    assert_eq!(filtered_report.total_findings, 2);
}
