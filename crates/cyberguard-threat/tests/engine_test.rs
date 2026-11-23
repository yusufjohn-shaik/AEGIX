#![deny(unsafe_code)]

use cyberguard_core::baseline::AegixBaseline;
use cyberguard_core::sarif::{Confidence, SarifLevel, SarifLog, SarifResult};
use cyberguard_threat::engine::ThreatEngine;
use cyberguard_threat::models::{MitreMatrixDomain, MitreTactic, StrideCategory};
use cyberguard_threat::traits::ThreatScanner;
use serde_json::json;
use std::io::Cursor;

#[tokio::test]
async fn test_threat_engine_scan_sarif_string() {
    let engine = ThreatEngine::new().with_domain(MitreMatrixDomain::EnterpriseAttack);

    let sarif_json = r#"{
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": { "name": "aegix-sast", "version": "0.9.0", "informationUri": "https://github.com", "rules": [] }
                },
                "results": [
                    {
                        "ruleId": "CG-SAST-SQLI",
                        "level": "error",
                        "message": { "text": "SQL Injection in User Login Handler" },
                        "properties": { "cvss": 8.8, "cwes": [89] }
                    },
                    {
                        "ruleId": "CG-SEC-001",
                        "level": "error",
                        "message": { "text": "Hardcoded AWS Access Key" },
                        "properties": { "cvss": 9.0, "cwes": [798] }
                    }
                ]
            }
        ]
    }"#;

    let report = engine
        .scan_sarif(sarif_json)
        .await
        .expect("Failed to scan SARIF");

    assert_eq!(report.domain, MitreMatrixDomain::EnterpriseAttack);
    assert_eq!(report.total_findings, 2);
    assert_eq!(report.suppressed_count, 0);

    // Verify STRIDE distribution
    assert_eq!(
        report.stride_counts.get(&StrideCategory::Tampering),
        Some(&1)
    );
    assert_eq!(
        report
            .stride_counts
            .get(&StrideCategory::InformationDisclosure),
        Some(&1)
    );

    // Verify ATT&CK tactics
    assert_eq!(
        report.tactic_counts.get(&MitreTactic::InitialAccess),
        Some(&1)
    );
    assert_eq!(
        report.tactic_counts.get(&MitreTactic::CredentialAccess),
        Some(&1)
    );

    // Verify Navigator layer
    assert_eq!(report.navigator_layer.domain, "enterprise-attack");
    assert!(!report.navigator_layer.techniques.is_empty());
}

#[tokio::test]
async fn test_threat_engine_with_baseline_suppression() {
    let mut r1 = SarifResult::new("CG-SEC-001", SarifLevel::Error, "Hardcoded AWS Key");
    r1.confidence = Some(Confidence::High);
    let mut r2 = SarifResult::new("CG-CONT-001", SarifLevel::Error, "Privileged Container");
    r2.confidence = Some(Confidence::High);

    // Create baseline containing r1 only
    let baseline = AegixBaseline::from_results(&[r1.clone()]);
    assert_eq!(baseline.total_findings, 1);

    let engine = ThreatEngine::new().with_baseline(baseline);

    let run = cyberguard_core::sarif::Run {
        tool: cyberguard_core::sarif::Tool {
            driver: cyberguard_core::sarif::Driver {
                name: "aegix-all".to_string(),
                version: "0.9.0".to_string(),
                information_uri: "https://github.com".to_string(),
                rules: Vec::new(),
            },
        },
        results: vec![r1, r2],
    };
    let log = SarifLog {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![run],
    };

    let report = engine
        .scan_sarif_log(&log)
        .await
        .expect("Failed to scan SARIF log");

    assert_eq!(report.suppressed_count, 1);
    assert_eq!(report.total_findings, 1);
    assert_eq!(report.findings[0].source_rule_id, "CG-CONT-001");
}

#[tokio::test]
async fn test_threat_engine_reader_and_sarif_export() {
    let engine = ThreatEngine::new();

    let sarif_json = r#"{
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": { "name": "aegix-api", "version": "0.9.0", "informationUri": "https://github.com", "rules": [] }
                },
                "results": [
                    {
                        "ruleId": "CG-API-003",
                        "level": "warning",
                        "message": { "text": "Unmetered API endpoint (CWE-400)" },
                        "properties": { "cvss": 5.3 }
                    }
                ]
            }
        ]
    }"#;

    let mut cursor = Cursor::new(sarif_json.as_bytes());
    let report = engine
        .scan_reader(&mut cursor)
        .await
        .expect("Failed to scan from reader");

    assert_eq!(report.total_findings, 1);

    // Export back to enriched SARIF
    let exported_sarif = engine
        .export_sarif_report(&report)
        .expect("Failed to export SARIF");
    assert_eq!(exported_sarif.runs.len(), 1);
    assert_eq!(exported_sarif.runs[0].results.len(), 1);

    let res = &exported_sarif.runs[0].results[0];
    let props = res
        .properties
        .as_ref()
        .expect("Missing properties in exported SARIF");
    assert!(props.get("mitreTechniques").is_some());
    assert!(props.get("strideCategories").is_some());
    assert_eq!(props.get("cvss"), Some(&json!(5.3)));
}
