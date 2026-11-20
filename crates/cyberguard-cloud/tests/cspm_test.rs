use cyberguard_cloud::cspm::DefaultCspmAuditor;
use cyberguard_cloud::parser::CloudParser;
use cyberguard_cloud::traits::CspmAuditor;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("vulnerable-cloud")
        .join(name)
}

#[test]
fn test_cspm_public_storage_and_encryption() {
    let path = fixture_path("aws-s3-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse S3 fixture");

    let auditor = DefaultCspmAuditor;
    let findings = auditor
        .audit_posture(&config.resources)
        .expect("CSPM posture audit should succeed");

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CLOUD-003"),
        "Must detect CG-CLOUD-003 (Public Bucket Policy)"
    );
    assert!(
        rule_ids.contains(&"CG-CLOUD-004"),
        "Must detect CG-CLOUD-004 (Unencrypted Storage)"
    );
}

#[test]
fn test_cspm_security_group_open_ports() {
    let path = fixture_path("aws-sg-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse SG fixture");

    let auditor = DefaultCspmAuditor;
    let findings = auditor
        .audit_posture(&config.resources)
        .expect("CSPM posture audit should succeed");

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CLOUD-005"),
        "Must detect CG-CLOUD-005 (Open SG port)"
    );
    // Should flag port 22, 3389, and 5432
    assert!(findings.iter().any(|f| f.description.contains("22")));
    assert!(findings.iter().any(|f| f.description.contains("3389")));
    assert!(findings.iter().any(|f| f.description.contains("5432")));
}

#[test]
fn test_cspm_azure_nsg_open_ports() {
    let path = fixture_path("azure-nsg-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse Azure NSG fixture");

    let auditor = DefaultCspmAuditor;
    let findings = auditor
        .audit_posture(&config.resources)
        .expect("CSPM posture audit should succeed");

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CLOUD-009"),
        "Must detect CG-CLOUD-009 (Azure NSG open port)"
    );
    assert!(findings.iter().any(|f| f.description.contains("22")));
    assert!(findings.iter().any(|f| f.description.contains("3389")));
}

#[test]
fn test_cspm_gcp_public_member_exposure() {
    let path = fixture_path("gcp-iam-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse GCP fixture");

    let auditor = DefaultCspmAuditor;
    let findings = auditor
        .audit_posture(&config.resources)
        .expect("CSPM posture audit should succeed");

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CLOUD-007"),
        "Must detect CG-CLOUD-007 (GCP allUsers exposure)"
    );
}
