use cyberguard_pipeline::models::PipelineRuleId;
use cyberguard_pipeline::parser::PipelineParser;
use cyberguard_pipeline::slsa::DefaultSlsaAuditor;
use cyberguard_pipeline::traits::SlsaAuditor;
use std::path::Path;

#[test]
fn test_slsa_valid_provenance_passes() {
    let fixture_path =
        Path::new("../../tests/fixtures/vulnerable-pipeline/slsa-valid-provenance.json");
    let doc = PipelineParser::parse_file(fixture_path).expect("Failed to parse SLSA fixture");
    let slsa = doc.slsa.expect("SLSA statement must be present");

    let auditor = DefaultSlsaAuditor;
    let trusted_builders =
        vec!["https://github.com/slsa-framework/slsa-github-generator".to_string()];
    let expected_repo = "https://github.com/yusufjohn-shaik/AEGIX";

    let findings = auditor
        .audit_slsa(
            &slsa,
            fixture_path.to_str().unwrap(),
            &doc.raw_content,
            None,
            &trusted_builders,
            Some(expected_repo),
        )
        .expect("Auditor failed");

    assert!(
        findings.is_empty(),
        "Valid SLSA attestation should have 0 findings, got: {:?}",
        findings
    );
}

#[test]
fn test_slsa_tampered_provenance_flags_violations() {
    let fixture_path =
        Path::new("../../tests/fixtures/vulnerable-pipeline/slsa-tampered-digest.json");
    let doc = PipelineParser::parse_file(fixture_path).expect("Failed to parse tampered fixture");
    let slsa = doc.slsa.expect("SLSA statement must be present");

    let auditor = DefaultSlsaAuditor;
    let trusted_builders =
        vec!["https://github.com/slsa-framework/slsa-github-generator".to_string()];
    let expected_repo = "https://github.com/yusufjohn-shaik/AEGIX";

    // Specify expected artifact digest that does not match the tampered zeros
    let findings = auditor
        .audit_slsa(
            &slsa,
            fixture_path.to_str().unwrap(),
            &doc.raw_content,
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            &trusted_builders,
            Some(expected_repo),
        )
        .expect("Auditor failed");

    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe008.as_str()),
        "Should flag CG-PIPE-008 (digest mismatch)"
    );
    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe009.as_str()),
        "Should flag CG-PIPE-009 (untrusted builder)"
    );
    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe010.as_str()),
        "Should flag CG-PIPE-010 (tampered materials)"
    );
}
