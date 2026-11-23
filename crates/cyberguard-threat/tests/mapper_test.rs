#![deny(unsafe_code)]

use cyberguard_core::sarif::{
    ArtifactLocation, Confidence, Location, PhysicalLocation, Region, SarifLevel, SarifResult,
};
use cyberguard_threat::catalog::StaticThreatCatalog;
use cyberguard_threat::mapper::ThreatMapper;
use cyberguard_threat::models::{MitreTactic, StrideCategory};
use cyberguard_threat::scorer::ThreatScorer;
use serde_json::json;

#[test]
fn test_threat_mapper_sarif_enrichment() {
    let catalog = StaticThreatCatalog::new();
    let mapper = ThreatMapper::new(&catalog, &catalog);

    let mut result = SarifResult::new(
        "CG-SAST-SQLI",
        SarifLevel::Error,
        "Unsanitized user input passed directly to database query (CWE-89)",
    );
    result.confidence = Some(Confidence::High);
    result.locations = vec![Location {
        physical_location: Some(PhysicalLocation {
            artifact_location: ArtifactLocation {
                uri: "src/auth/login.rs".to_string(),
            },
            region: Some(Region {
                start_line: 42,
                start_column: Some(1),
                end_line: Some(42),
                end_column: Some(50),
            }),
        }),
    }];
    result.properties = Some(json!({
        "cvss": 8.8,
        "epss": 0.75,
        "reachability": 1.0,
        "triFactorScore": 6.6,
        "cwes": [89]
    }));

    let finding = mapper.map_sarif_result(&result);

    assert_eq!(finding.source_rule_id, "CG-SAST-SQLI");
    assert_eq!(finding.severity, SarifLevel::Error);
    assert_eq!(finding.confidence, Confidence::High);
    assert!(finding.tactics.contains(&MitreTactic::InitialAccess));
    assert!(finding.techniques.contains(&"T1190".to_string()));
    assert!(finding
        .stride_categories
        .contains(&StrideCategory::Tampering));
    assert_eq!(finding.file_path, Some("src/auth/login.rs".to_string()));
    assert_eq!(finding.line, Some(42));
    assert_eq!(finding.cvss_score, Some(8.8));
    assert_eq!(finding.tri_factor_score, Some(6.6));
    assert!(!finding.fingerprint.is_empty());
}

#[test]
fn test_threat_scorer_asymptotic_saturation() {
    let catalog = StaticThreatCatalog::new();
    let mapper = ThreatMapper::new(&catalog, &catalog);
    let scorer = ThreatScorer::default();

    let mut r1 = SarifResult::new("CG-SEC-001", SarifLevel::Error, "Leaked AWS Key");
    r1.confidence = Some(Confidence::High);
    r1.properties = Some(json!({ "cvss": 9.0 }));

    let f1 = mapper.map_sarif_result(&r1);

    // Single finding score should be >= base severity (9.0) and <= 10.0
    let score1 = scorer.score_technique(&[&f1]);
    assert!(score1 >= 9.0);
    assert!(score1 <= 10.0);

    // 10 accumulated findings should saturate smoothly without exceeding 10.0
    let ten_findings: Vec<&cyberguard_threat::models::ThreatFinding> = vec![&f1; 10];
    let score_saturated = scorer.score_technique(&ten_findings);
    assert_eq!(score_saturated, 10.0);
}

#[test]
fn test_scorer_aggregation() {
    let catalog = StaticThreatCatalog::new();
    let mapper = ThreatMapper::new(&catalog, &catalog);
    let scorer = ThreatScorer::default();

    let r1 = SarifResult::new("CG-SEC-001", SarifLevel::Error, "Leaked Key");
    let r2 = SarifResult::new("CG-API-003", SarifLevel::Warning, "Rate limit missing");

    let f1 = mapper.map_sarif_result(&r1);
    let f2 = mapper.map_sarif_result(&r2);

    let findings = vec![f1, f2];

    let stride_counts = ThreatScorer::count_by_stride(&findings);
    assert_eq!(
        stride_counts.get(&StrideCategory::InformationDisclosure),
        Some(&1)
    );
    assert_eq!(
        stride_counts.get(&StrideCategory::DenialOfService),
        Some(&1)
    );

    let tactic_counts = ThreatScorer::count_by_tactic(&findings);
    assert_eq!(tactic_counts.get(&MitreTactic::CredentialAccess), Some(&1));
    assert_eq!(tactic_counts.get(&MitreTactic::Impact), Some(&1));

    let tech_scores = scorer.aggregate_technique_scores(&findings);
    assert!(tech_scores.contains_key("T1552"));
    assert!(tech_scores.contains_key("T1499"));
}
