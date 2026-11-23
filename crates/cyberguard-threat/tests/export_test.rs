#![deny(unsafe_code)]

use cyberguard_core::sarif::{Confidence, SarifLevel, SarifResult};
use cyberguard_threat::catalog::StaticThreatCatalog;
use cyberguard_threat::mapper::ThreatMapper;
use cyberguard_threat::models::{MitreMatrixDomain, ThreatReport};
use cyberguard_threat::navigator::NavigatorGenerator;
use cyberguard_threat::report::ThreatReportFormatter;
use cyberguard_threat::scorer::ThreatScorer;
use serde_json::json;

#[test]
fn test_navigator_generator_schema_compliance() {
    let catalog = StaticThreatCatalog::new();
    let mapper = ThreatMapper::new(&catalog, &catalog);
    let generator = NavigatorGenerator::default();

    let mut r1 = SarifResult::new(
        "CG-SEC-001",
        SarifLevel::Error,
        "Leaked AWS Access Key in git history (CWE-798)",
    );
    r1.confidence = Some(Confidence::High);
    r1.properties = Some(json!({ "cvss": 9.0, "cwes": [798] }));

    let mut r2 = SarifResult::new(
        "CG-CONT-001",
        SarifLevel::Error,
        "Privileged container mode enabled in compose file (CWE-250)",
    );
    r2.confidence = Some(Confidence::High);
    r2.properties = Some(json!({ "cvss": 8.5, "cwes": [250] }));

    let f1 = mapper.map_sarif_result(&r1);
    let f2 = mapper.map_sarif_result(&r2);

    let findings = vec![f1, f2];

    let layer = generator.generate_layer(
        "Aegix Threat Matrix Layer",
        MitreMatrixDomain::EnterpriseAttack,
        &findings,
    );

    assert_eq!(layer.name, "Aegix Threat Matrix Layer");
    assert_eq!(layer.domain, "enterprise-attack");
    assert_eq!(layer.versions.attack, "14");
    assert_eq!(layer.versions.navigator, "4.5");
    assert!(!layer.techniques.is_empty());

    // Serialize to JSON and verify field presence
    let json_output = serde_json::to_string_pretty(&layer).expect("Failed to serialize layer");
    assert!(json_output.contains("\"techniqueID\": \"T1552\""));
    assert!(
        json_output.contains("\"techniqueID\": \"T1611\"")
            || json_output.contains("\"techniqueID\": \"T1068\"")
    );
    assert!(json_output.contains("\"score\": 9.0"));
    assert!(json_output.contains("\"name\": \"findingsCount\""));
    assert!(json_output.contains("\"value\": \"1\""));
    assert!(json_output.contains("\"platforms\""));
    // Verify static color is omitted so gradient interpolation is not overridden
    assert!(!json_output.contains("\"color\": \"#"));
}

#[test]
fn test_threat_report_terminal_and_json_formatting() {
    let catalog = StaticThreatCatalog::new();
    let mapper = ThreatMapper::new(&catalog, &catalog);
    let generator = NavigatorGenerator::default();

    let mut r1 = SarifResult::new("CG-API-003", SarifLevel::Warning, "Missing API rate limit");
    r1.properties = Some(json!({ "cvss": 5.3 }));

    let f1 = mapper.map_sarif_result(&r1);
    let findings = vec![f1];

    let stride_counts = ThreatScorer::count_by_stride(&findings);
    let tactic_counts = ThreatScorer::count_by_tactic(&findings);
    let technique_counts = ThreatScorer::count_by_technique(&findings);
    let navigator_layer = generator.generate_layer(
        "Aegix Security Report",
        MitreMatrixDomain::EnterpriseAttack,
        &findings,
    );

    let report = ThreatReport {
        domain: MitreMatrixDomain::EnterpriseAttack,
        generated_at: chrono::Utc::now(),
        total_findings: findings.len(),
        findings,
        stride_counts,
        tactic_counts,
        technique_counts,
        navigator_layer,
        suppressed_count: 0,
    };

    let terminal_str = ThreatReportFormatter::render_terminal(&report, &catalog);
    assert!(terminal_str.contains("AEGIX THREAT MODELING & ATT&CK MATRIX"));
    assert!(terminal_str.contains("STRIDE THREAT PROPERTY PROFILE"));
    assert!(terminal_str.contains("MITRE ATT&CK TECHNIQUES DETECTED"));

    let json_str = ThreatReportFormatter::to_json(&report).expect("Failed to render JSON");
    assert!(json_str.contains("\"domain\": \"enterprise-attack\""));
    assert!(json_str.contains("\"total_findings\": 1"));

    let nav_str =
        ThreatReportFormatter::to_navigator_json(&report).expect("Failed to render Navigator JSON");
    assert!(nav_str.contains("\"navigator\": \"4.5\""));
}
