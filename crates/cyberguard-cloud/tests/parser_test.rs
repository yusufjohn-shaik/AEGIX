use cyberguard_cloud::models::{CloudProvider, CloudResourceType, StatementEffect};
use cyberguard_cloud::parser::CloudParser;
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
fn test_parse_aws_iam_polymorphic() {
    let path = fixture_path("aws-iam-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse AWS IAM policy fixture");

    assert_eq!(config.detected_provider, CloudProvider::Aws);
    assert_eq!(config.policies.len(), 1);
    let policy = &config.policies[0];
    assert_eq!(policy.statements.len(), 3);

    // First statement has single string Action: "*"
    let s0 = &policy.statements[0];
    assert_eq!(s0.effect, StatementEffect::Allow);
    assert!(s0.allows_action("*"));
    assert!(s0.allows_action("s3:GetObject"));
    assert!(s0.allows_wildcard_resource());

    // Second statement has array of actions
    let s1 = &policy.statements[1];
    assert!(s1.allows_action("iam:PassRole"));
    assert!(s1.allows_action("ec2:RunInstances"));
    assert!(!s1.allows_action("s3:GetObject"));

    // Third statement has single string Action: "iam:CreateAccessKey"
    let s2 = &policy.statements[2];
    assert!(s2.allows_action("iam:CreateAccessKey"));
}

#[test]
fn test_parse_aws_security_group_and_ports() {
    let path = fixture_path("aws-sg-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse AWS SG fixture");

    assert_eq!(config.detected_provider, CloudProvider::Aws);
    assert_eq!(config.resources.len(), 1);
    let sg = &config.resources[0];
    assert_eq!(sg.resource_type, CloudResourceType::SecurityGroup);
    assert_eq!(sg.security_rules.len(), 3);

    // Rule 0 has port 22 with 0.0.0.0/0
    assert_eq!(sg.security_rules[0].from_port, Some(22));
    assert_eq!(sg.security_rules[0].to_port, Some(22));
    assert!(sg.security_rules[0]
        .cidr_blocks
        .contains(&"0.0.0.0/0".to_string()));

    // Rule 1 has port 3389 with ::/0
    assert_eq!(sg.security_rules[1].from_port, Some(3389));
    assert_eq!(sg.security_rules[1].to_port, Some(3389));
    assert!(sg.security_rules[1]
        .ipv6_cidr_blocks
        .contains(&"::/0".to_string()));

    // Test port -1 parsing
    let (from, to) = CloudParser::parse_port_range("-1");
    assert_eq!(from, Some(1));
    assert_eq!(to, Some(65535));
}

#[test]
fn test_parse_gcp_iam_bindings() {
    let path = fixture_path("gcp-iam-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse GCP IAM fixture");

    assert_eq!(config.detected_provider, CloudProvider::Gcp);
    assert_eq!(config.resources.len(), 1);
    let res = &config.resources[0];
    assert_eq!(res.resource_type, CloudResourceType::IcpBinding);
}

#[test]
fn test_parse_azure_nsg_plural_ports() {
    let path = fixture_path("azure-nsg-vulnerable.json");
    let config = CloudParser::parse_file(&path).expect("Should parse Azure NSG fixture");

    assert_eq!(config.detected_provider, CloudProvider::Azure);
    assert_eq!(config.resources.len(), 1);
    let nsg = &config.resources[0];
    assert_eq!(nsg.resource_type, CloudResourceType::NetworkSecurityGroup);

    // Rules include 22, 3389, and 5432
    let ports: Vec<i32> = nsg
        .security_rules
        .iter()
        .filter_map(|r| r.from_port)
        .collect();
    assert!(ports.contains(&22));
    assert!(ports.contains(&3389));
    assert!(ports.contains(&5432));
}

#[test]
fn test_parse_directory_recursive() {
    let path = fixture_path("");
    let config = CloudParser::parse_dir(&path).expect("Should parse directory of fixtures");

    // Aggregates all resources and policies across fixtures
    assert!(config.resources.len() >= 4);
    assert!(config.policies.len() >= 2);
}
