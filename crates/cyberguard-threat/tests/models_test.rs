#![deny(unsafe_code)]

use cyberguard_threat::error::ThreatError;
use cyberguard_threat::models::{
    AttackNavigatorLayer, MitreMatrixDomain, MitreTactic, NavigatorGradient,
    NavigatorMetadataEntry, NavigatorTechniqueEntry, NavigatorVersions, StrideCategory,
};

#[test]
fn test_matrix_domain_parsing() {
    assert_eq!(
        MitreMatrixDomain::from_str_loose("enterprise"),
        Some(MitreMatrixDomain::EnterpriseAttack)
    );
    assert_eq!(
        MitreMatrixDomain::from_str_loose("cloud-attack"),
        Some(MitreMatrixDomain::CloudAttack)
    );
    assert_eq!(
        MitreMatrixDomain::from_str_loose("mobile"),
        Some(MitreMatrixDomain::MobileAttack)
    );
    assert_eq!(
        MitreMatrixDomain::from_str_loose("containers"),
        Some(MitreMatrixDomain::ContainerAttack)
    );
    assert_eq!(MitreMatrixDomain::from_str_loose("invalid-domain"), None);
}

#[test]
fn test_all_14_tactics() {
    let tactics = MitreTactic::all();
    assert_eq!(tactics.len(), 14);

    for tactic in tactics {
        assert!(tactic.id().starts_with("TA"));
        assert!(!tactic.slug().is_empty());
        assert!(!tactic.title().is_empty());
        assert_eq!(MitreTactic::from_id_or_slug(tactic.id()), Some(*tactic));
        assert_eq!(MitreTactic::from_id_or_slug(tactic.slug()), Some(*tactic));
    }
}

#[test]
fn test_stride_categories() {
    let categories = StrideCategory::all();
    assert_eq!(categories.len(), 6);

    for cat in categories {
        let ch = cat.letter();
        assert_eq!(StrideCategory::from_letter(ch), Some(*cat));
        assert!(!cat.security_property().is_empty());
        assert!(!cat.title().is_empty());
    }
}

#[test]
fn test_navigator_layer_serde() {
    let layer = AttackNavigatorLayer {
        name: "Test Aegix Layer".to_string(),
        versions: NavigatorVersions::default(),
        domain: "enterprise-attack".to_string(),
        description: "Test description".to_string(),
        filters: None,
        gradient: NavigatorGradient::default(),
        layout: None,
        techniques: vec![NavigatorTechniqueEntry {
            technique_id: "T1190".to_string(),
            tactic: "initial-access".to_string(),
            score: Some(8.5),
            color: None,
            comment: Some("Test comment".to_string()),
            enabled: true,
            metadata: vec![NavigatorMetadataEntry {
                name: "findingsCount".to_string(),
                value: "1".to_string(),
            }],
        }],
    };

    let json_str = serde_json::to_string_pretty(&layer).expect("Failed to serialize layer");
    assert!(json_str.contains("\"techniqueID\": \"T1190\""));
    assert!(json_str.contains("\"tactic\": \"initial-access\""));
    assert!(json_str.contains("\"score\": 8.5"));

    let deserialized: AttackNavigatorLayer =
        serde_json::from_str(&json_str).expect("Failed to deserialize layer");
    assert_eq!(deserialized.name, "Test Aegix Layer");
    assert_eq!(deserialized.techniques.len(), 1);
    assert_eq!(deserialized.techniques[0].technique_id, "T1190");
}

#[test]
fn test_threat_error_display() {
    let err = ThreatError::SarifParse("Invalid JSON token".to_string());
    assert_eq!(
        err.to_string(),
        "SARIF v2.1.0 log deserialization error: Invalid JSON token"
    );

    let err = ThreatError::InvalidTactic("TA9999".to_string());
    assert_eq!(
        err.to_string(),
        "Unknown or malformed MITRE ATT&CK tactic identifier: 'TA9999'"
    );
}
