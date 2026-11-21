use cyberguard_core::baseline::AegixBaseline;
use cyberguard_pipeline::engine::PipelineEngine;
use cyberguard_pipeline::traits::PipelineScanner;
use std::collections::BTreeSet;
use std::path::Path;

#[tokio::test]
async fn test_pipeline_engine_scan_and_sarif() {
    let fixture_path =
        Path::new("../../tests/fixtures/vulnerable-pipeline/gha-vulnerable-injection.yaml");
    let engine = PipelineEngine::new();

    let report = engine
        .scan_file(fixture_path, None)
        .await
        .expect("Scan file failed");

    assert!(
        !report.findings.is_empty(),
        "Vulnerable workflow must produce findings"
    );
    assert_eq!(report.suppressed_findings_count, 0);

    // Verify SARIF export
    let sarif = engine.to_sarif(&report).expect("Failed to export SARIF");
    assert_eq!(sarif.runs.len(), 1);
    assert_eq!(sarif.runs[0].results.len(), report.findings.len());

    // Verify partial fingerprints
    for res in &sarif.runs[0].results {
        let fps = res
            .partial_fingerprints
            .as_ref()
            .expect("Fingerprints should be present");
        assert!(fps.contains_key("logicalLocationTokenHash/v1"));
        assert!(fps.contains_key("sha256/v1"));
    }
}

#[tokio::test]
async fn test_pipeline_engine_baseline_suppression() {
    let fixture_path =
        Path::new("../../tests/fixtures/vulnerable-pipeline/gha-vulnerable-injection.yaml");
    let unsuppressed_engine = PipelineEngine::new();

    let unsuppressed_report = unsuppressed_engine
        .scan_file(fixture_path, None)
        .await
        .expect("Scan failed");

    assert!(!unsuppressed_report.findings.is_empty());
    let finding_to_suppress = &unsuppressed_report.findings[0];

    let mut baseline_fps = BTreeSet::new();
    baseline_fps.insert(finding_to_suppress.fingerprint.clone());

    let baseline = AegixBaseline {
        version: "1.0.0".to_string(),
        tool: "aegix-test".to_string(),
        generated_at: "2026-11-21T00:00:00Z".to_string(),
        total_findings: 1,
        fingerprints: baseline_fps,
        findings: Vec::new(),
    };

    let engine = PipelineEngine::new().with_baseline(baseline);
    let report = engine
        .scan_file(fixture_path, None)
        .await
        .expect("Scan with baseline failed");

    assert_eq!(report.suppressed_findings_count, 1);
    assert_eq!(
        report.findings.len(),
        unsuppressed_report.findings.len() - 1
    );
    assert!(!report
        .findings
        .iter()
        .any(|f| f.fingerprint == finding_to_suppress.fingerprint));
}
