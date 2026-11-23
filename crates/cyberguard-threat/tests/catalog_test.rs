#![deny(unsafe_code)]

use cyberguard_threat::catalog::{score_to_gradient_color, StaticThreatCatalog};
use cyberguard_threat::models::{MitreTactic, StrideCategory};
use cyberguard_threat::traits::{AttackMapper, StrideClassifier};

#[test]
fn test_static_threat_catalog_techniques() {
    let catalog = StaticThreatCatalog::new();
    let all = catalog.all_techniques();
    assert!(!all.is_empty());

    let sqli = catalog.get_technique_details("T1190");
    assert!(sqli.is_some());
    let sqli = sqli.unwrap();
    assert_eq!(sqli.name, "Exploit Public-Facing Application");
    assert!(sqli.tactics.contains(&MitreTactic::InitialAccess));

    let creds = catalog.get_technique_details("T1552");
    assert!(creds.is_some());
    let creds = creds.unwrap();
    assert_eq!(creds.name, "Unsecured Credentials");
    assert!(creds.tactics.contains(&MitreTactic::CredentialAccess));
}

#[test]
fn test_rule_and_cwe_technique_mapping() {
    let catalog = StaticThreatCatalog::new();

    // 1. Secrets rule
    let (tactics, techniques) = catalog.map_finding_to_techniques("CG-SEC-001", &[]);
    assert!(tactics.contains(&MitreTactic::CredentialAccess));
    assert!(techniques.contains(&"T1552".to_string()));

    // 2. Container rule
    let (tactics, techniques) = catalog.map_finding_to_techniques("CG-CONT-001", &[]);
    assert!(tactics.contains(&MitreTactic::PrivilegeEscalation));
    assert!(techniques.contains(&"T1611".to_string()));

    // 3. CWE-89 (SQL Injection) fallback
    let (tactics, techniques) = catalog.map_finding_to_techniques("CUSTOM-RULE-1", &[89]);
    assert!(tactics.contains(&MitreTactic::InitialAccess));
    assert!(techniques.contains(&"T1190".to_string()));

    // 4. CWE-798 (Hardcoded Credentials) fallback
    let (tactics, techniques) = catalog.map_finding_to_techniques("CUSTOM-RULE-2", &[798]);
    assert!(tactics.contains(&MitreTactic::CredentialAccess));
    assert!(techniques.contains(&"T1552".to_string()));

    // 5. Pipeline rule
    let (tactics, techniques) = catalog.map_finding_to_techniques("CG-PIPE-001", &[]);
    assert!(tactics.contains(&MitreTactic::Execution));
    assert!(techniques.contains(&"T1059".to_string()));
}

#[test]
fn test_stride_classification() {
    let catalog = StaticThreatCatalog::new();

    // Spoofing via CWE-287
    let cats = catalog.classify_finding("CUSTOM-AUTH", &[287]);
    assert!(cats.contains(&StrideCategory::Spoofing));

    // Tampering via SQL injection
    let cats = catalog.classify_finding("CG-SAST-SQLI", &[89]);
    assert!(cats.contains(&StrideCategory::Tampering));

    // Information disclosure via secret leak
    let cats = catalog.classify_finding("CG-SEC-AWS-KEY", &[798]);
    assert!(cats.contains(&StrideCategory::InformationDisclosure));

    // Denial of Service via rate limit / ReDoS
    let cats = catalog.classify_finding("CG-API-003", &[400]);
    assert!(cats.contains(&StrideCategory::DenialOfService));

    // Elevation of privilege via container / CWE-250
    let cats = catalog.classify_finding("CG-CONT-001", &[250]);
    assert!(cats.contains(&StrideCategory::ElevationOfPrivilege));

    // Security property parsing
    assert_eq!(
        catalog.classify_by_violation("confidentiality"),
        Some(StrideCategory::InformationDisclosure)
    );
    assert_eq!(
        catalog.classify_by_violation("integrity"),
        Some(StrideCategory::Tampering)
    );
    assert_eq!(
        catalog.classify_by_violation("availability"),
        Some(StrideCategory::DenialOfService)
    );
}

#[test]
fn test_color_gradient_interpolation() {
    let min_val = 0.0;
    let max_val = 10.0;

    // Minimum score should be white (#ffffff)
    assert_eq!(score_to_gradient_color(0.0, min_val, max_val), "#ffffff");

    // Maximum score should be red (#e53935)
    assert_eq!(score_to_gradient_color(10.0, min_val, max_val), "#e53935");

    // Over maximum should clamp to #e53935
    assert_eq!(score_to_gradient_color(12.5, min_val, max_val), "#e53935");

    // Mid points should interpolate correctly
    let mid_color = score_to_gradient_color(5.0, min_val, max_val);
    assert!(mid_color.starts_with('#'));
    assert_eq!(mid_color.len(), 7);
}
