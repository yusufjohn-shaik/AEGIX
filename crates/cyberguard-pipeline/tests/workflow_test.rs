use cyberguard_pipeline::models::PipelineRuleId;
use cyberguard_pipeline::parser::PipelineParser;
use cyberguard_pipeline::traits::WorkflowAuditor;
use cyberguard_pipeline::workflow::DefaultWorkflowAuditor;
use std::path::Path;

#[test]
fn test_workflow_auditor_flags_vulnerabilities() {
    let fixture_path =
        Path::new("../../tests/fixtures/vulnerable-pipeline/gha-vulnerable-injection.yaml");
    let doc = PipelineParser::parse_file(fixture_path).expect("Failed to parse fixture");
    let workflow = doc.workflow.expect("Workflow must be present");

    let auditor = DefaultWorkflowAuditor;
    let findings = auditor
        .audit_workflow(&workflow, fixture_path.to_str().unwrap(), &doc.raw_content)
        .expect("Auditor failed");

    // Must find:
    // 1. CG-PIPE-001 (unpinned actions/checkout@v3)
    // 2. CG-PIPE-002 (script injection on github.event.issue.title and inline env expansion)
    // 3. CG-PIPE-003 (missing top-level perms and write-all job perms)
    // 4. CG-PIPE-004 (pull_request_target + untrusted checkout ref)
    // 5. CG-PIPE-005 (hardcoded GitHub PAT in env)
    // 6. CG-PIPE-006 (runs-on: self-hosted on PR workflow)
    let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();

    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe001.as_str()),
        "Should flag CG-PIPE-001 (unpinned action)"
    );
    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe002.as_str()),
        "Should flag CG-PIPE-002 (script injection)"
    );
    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe003.as_str()),
        "Should flag CG-PIPE-003 (excessive permissions)"
    );
    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe004.as_str()),
        "Should flag CG-PIPE-004 (pull_request_target checkout)"
    );
    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe005.as_str()),
        "Should flag CG-PIPE-005 (plaintext secret)"
    );
    assert!(
        rule_ids.contains(&PipelineRuleId::CgPipe006.as_str()),
        "Should flag CG-PIPE-006 (insecure self-hosted)"
    );

    // Secret must be masked
    let secret_finding = findings
        .iter()
        .find(|f| f.rule_id == PipelineRuleId::CgPipe005.as_str())
        .unwrap();
    assert!(
        secret_finding.description.contains("ghp_***999"),
        "Secret should be masked"
    );
}

#[test]
fn test_hardened_workflow_passes_clean() {
    let fixture_path = Path::new("../../tests/fixtures/vulnerable-pipeline/gha-safe-workflow.yaml");
    let doc = PipelineParser::parse_file(fixture_path).expect("Failed to parse hardened fixture");
    let workflow = doc.workflow.expect("Workflow must be present");

    let auditor = DefaultWorkflowAuditor;
    let findings = auditor
        .audit_workflow(&workflow, fixture_path.to_str().unwrap(), &doc.raw_content)
        .expect("Auditor failed");

    // A properly hardened workflow with 40-char SHA pinned actions, read-all perms, and shell variable expansion has 0 findings!
    assert!(
        findings.is_empty(),
        "Hardened workflow should have 0 findings, got: {:?}",
        findings
    );
}
