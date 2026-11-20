use cyberguard_iac::models::{TerraformLocal, TerraformResource, TerraformVariable};
use cyberguard_iac::terraform::DefaultTerraformAuditor;
use cyberguard_iac::traits::TerraformAuditor;
use std::collections::HashMap;

#[test]
fn test_terraform_unrestricted_ingress_detection() {
    let mut props = HashMap::new();
    let ingress_rule = serde_json::json!({
        "from_port": 22,
        "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"]
    });
    props.insert(
        "ingress".to_string(),
        serde_json::Value::Array(vec![ingress_rule]),
    );

    let resources = vec![TerraformResource {
        resource_type: "aws_security_group".to_string(),
        resource_name: "open_ssh".to_string(),
        properties: props,
        line_start: 1,
        line_end: 10,
    }];

    let auditor = DefaultTerraformAuditor;
    let findings = auditor
        .audit_terraform(&resources, &[], &[], "main.tf", "0.0.0.0/0")
        .unwrap();

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-IAC-007"),
        "Expected CG-IAC-007 for open SSH"
    );
}

#[test]
fn test_terraform_unencrypted_s3_bucket() {
    let resources = vec![TerraformResource {
        resource_type: "aws_s3_bucket".to_string(),
        resource_name: "unencrypted_bucket".to_string(),
        properties: HashMap::new(),
        line_start: 1,
        line_end: 5,
    }];

    let auditor = DefaultTerraformAuditor;
    let findings = auditor
        .audit_terraform(&resources, &[], &[], "s3.tf", "unencrypted_bucket")
        .unwrap();

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-IAC-008"),
        "Expected CG-IAC-008 for unencrypted bucket"
    );
}

#[test]
fn test_terraform_standalone_s3_encryption_recognition() {
    let mut enc_props = HashMap::new();
    enc_props.insert(
        "bucket".to_string(),
        serde_json::Value::String("aws_s3_bucket.my_bucket.id".to_string()),
    );

    let resources = vec![
        TerraformResource {
            resource_type: "aws_s3_bucket".to_string(),
            resource_name: "my_bucket".to_string(),
            properties: HashMap::new(),
            line_start: 1,
            line_end: 3,
        },
        TerraformResource {
            resource_type: "aws_s3_bucket_server_side_encryption_configuration".to_string(),
            resource_name: "my_bucket_enc".to_string(),
            properties: enc_props,
            line_start: 4,
            line_end: 10,
        },
    ];

    let auditor = DefaultTerraformAuditor;
    let findings = auditor
        .audit_terraform(&resources, &[], &[], "s3.tf", "my_bucket")
        .unwrap();

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !rule_ids.contains(&"CG-IAC-008"),
        "Standalone encryption should satisfy CG-IAC-008"
    );
}

#[test]
fn test_terraform_hardcoded_secret_masking() {
    let variables = vec![TerraformVariable {
        name: "admin_password".to_string(),
        default_value: Some(serde_json::Value::String("supersecret123".to_string())),
        description: None,
        sensitive: None,
        line: 1,
    }];

    let locals = vec![TerraformLocal {
        name: "api_token".to_string(),
        value: serde_json::Value::String("ghp_secret_access_token_9988".to_string()),
        line: 5,
    }];

    let auditor = DefaultTerraformAuditor;
    let findings = auditor
        .audit_terraform(&[], &variables, &locals, "vars.tf", "admin_password")
        .unwrap();

    assert_eq!(findings.len(), 2);
    for f in &findings {
        assert_eq!(f.rule_id, "CG-IAC-009");
        // Ensure plaintext password is NOT revealed unmasked
        assert!(!f.description.contains("supersecret123"));
        assert!(!f.description.contains("ghp_secret_access_token_9988"));
        assert!(f.description.contains('*'));
    }
}
