use cyberguard_cloud::ciem::DefaultCiemAuditor;
use cyberguard_cloud::models::{CloudProvider, CloudResource, CloudResourceType};
use cyberguard_cloud::parser::CloudParser;
use cyberguard_cloud::traits::CiemAuditor;
use std::collections::HashMap;
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
fn test_ciem_wildcard_admin_and_privilege_escalation() {
    let path = fixture_path("aws-iam-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse AWS IAM fixture");

    let auditor = DefaultCiemAuditor;
    let findings = auditor
        .audit_entitlements(&config.policies, &config.resources)
        .expect("CIEM audit should succeed");

    // Expect CG-CLOUD-001 (Wildcard) and CG-CLOUD-002 (Escalation)
    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CLOUD-001"),
        "Must detect CG-CLOUD-001"
    );
    assert!(
        rule_ids.contains(&"CG-CLOUD-002"),
        "Must detect CG-CLOUD-002"
    );
}

#[test]
fn test_ciem_safe_config_zero_findings() {
    let path = fixture_path("safe-cloud-config.json");
    let config = CloudParser::parse_file(&path).expect("Should parse safe cloud fixture");

    let auditor = DefaultCiemAuditor;
    let findings = auditor
        .audit_entitlements(&config.policies, &config.resources)
        .expect("CIEM audit should succeed");

    assert!(
        findings.is_empty(),
        "Safe configuration must yield 0 CIEM findings (true negative)"
    );
}

#[test]
fn test_ciem_gcp_primitive_role() {
    let path = fixture_path("gcp-iam-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse GCP fixture");

    let auditor = DefaultCiemAuditor;
    let findings = auditor
        .audit_entitlements(&config.policies, &config.resources)
        .expect("CIEM audit should succeed");

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CLOUD-006"),
        "Must detect GCP primitive role CG-CLOUD-006"
    );
}

#[test]
fn test_ciem_azure_subscription_owner_rbac() {
    let raw = serde_json::json!({
        "id": "/subscriptions/sub-001/providers/Microsoft.Authorization/roleAssignments/ra-123",
        "roleDefinitionName": "Owner",
        "scope": "/subscriptions/sub-001",
        "principalId": "sp-12345"
    });

    let resource = CloudResource {
        provider: CloudProvider::Azure,
        resource_type: CloudResourceType::AzureRoleAssignment,
        id: "ra-123".to_string(),
        name: "Owner".to_string(),
        tags: HashMap::new(),
        server_side_encryption: None,
        security_rules: Vec::new(),
        associated_policies: Vec::new(),
        raw_properties: raw,
    };

    let auditor = DefaultCiemAuditor;
    let findings = auditor
        .audit_entitlements(&[], &[resource])
        .expect("CIEM audit should succeed");

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CLOUD-008"),
        "Must detect Azure subscription Owner CG-CLOUD-008"
    );
}
