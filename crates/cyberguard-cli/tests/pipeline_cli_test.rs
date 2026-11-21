use cyberguard_pipeline::engine::PipelineEngine;
use cyberguard_pipeline::models::PipelineRuleId;
use cyberguard_pipeline::traits::PipelineScanner;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("vulnerable-pipeline")
        .join(name)
}

#[tokio::test]
async fn test_pipeline_cli_workflow_scan() {
    let fixture = fixture_path("gha-vulnerable-injection.yaml");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = PipelineEngine::new();
    let report = engine.scan_file(&fixture, None).await.unwrap();

    assert!(
        report.findings.len() >= 5,
        "Expected >= 5 findings for vulnerable workflow, found {}",
        report.findings.len()
    );

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe001.as_str()));
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe002.as_str()));
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe003.as_str()));
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe004.as_str()));
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe005.as_str()));
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe006.as_str()));
}

#[tokio::test]
async fn test_pipeline_cli_safe_workflow_scan() {
    let fixture = fixture_path("gha-safe-workflow.yaml");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = PipelineEngine::new();
    let report = engine.scan_file(&fixture, None).await.unwrap();

    assert_eq!(
        report.findings.len(),
        0,
        "Expected 0 findings on hardened workflow"
    );
}

#[tokio::test]
async fn test_pipeline_cli_slsa_scan() {
    let fixture = fixture_path("slsa-tampered-digest.json");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = PipelineEngine::new()
        .with_trusted_builder("https://github.com/slsa-framework/slsa-github-generator")
        .with_expected_source_repo("https://github.com/yusufjohn-shaik/AEGIX");

    let report = engine.scan_file(&fixture, None).await.unwrap();

    assert!(
        report.findings.len() >= 2,
        "Expected >= 2 findings for tampered SLSA, found {}",
        report.findings.len()
    );

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe009.as_str()));
    assert!(rule_ids.contains(&PipelineRuleId::CgPipe010.as_str()));
}

#[tokio::test]
async fn test_pipeline_cli_baseline_suppression() {
    let fixture = fixture_path("gha-vulnerable-injection.yaml");
    let engine = PipelineEngine::new();
    let report = engine.scan_file(&fixture, None).await.unwrap();

    assert!(!report.findings.is_empty());

    // Generate baseline snapshot
    let baseline = engine.generate_baseline(&report, &fixture);
    assert_eq!(baseline.fingerprints.len(), report.findings.len());

    // Filter using baseline
    let filtered = PipelineEngine::filter_baseline(&report, &baseline);
    assert_eq!(
        filtered.findings.len(),
        0,
        "All findings should be suppressed by baseline"
    );
    assert_eq!(filtered.suppressed_findings_count, report.findings.len());

    // SARIF export from baseline-filtered engine
    let suppressed_engine = PipelineEngine::new().with_baseline(baseline);
    let suppressed_report = suppressed_engine.scan_file(&fixture, None).await.unwrap();
    let sarif = suppressed_engine.to_sarif(&suppressed_report).unwrap();
    assert_eq!(
        sarif.runs[0].results.len(),
        0,
        "SARIF should contain 0 results after suppression"
    );
}
