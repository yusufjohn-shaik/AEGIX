use cyberguard_cloud::engine::CloudEngine;
use cyberguard_cloud::traits::CloudScanner;
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

#[tokio::test]
async fn test_cloud_engine_end_to_end_and_sarif() {
    let path = fixture_path("aws-iam-vulnerable.json");
    let engine = CloudEngine::default();
    let report = engine.scan_file(&path).await.expect("Scan should succeed");

    assert!(!report.findings.is_empty());
    assert_eq!(report.total_policies_evaluated, 1);

    // Export to SARIF
    let sarif = engine.to_sarif(&report, &path, None);
    assert_eq!(sarif.runs.len(), 1);
    assert!(!sarif.runs[0].results.is_empty());

    // Verify deterministic SHA-256 fingerprints exist in partialFingerprints
    for res in &sarif.runs[0].results {
        assert!(res.partial_fingerprints.is_some());
        let fps = res.partial_fingerprints.as_ref().unwrap();
        assert!(fps.contains_key("sha256/v1"));
    }
}

#[tokio::test]
async fn test_cloud_baseline_snapshot_lifecycle() {
    let path = fixture_path("aws-s3-vulnerable.json");
    let engine = CloudEngine::default();
    let report = engine.scan_file(&path).await.expect("Scan should succeed");

    // Generate baseline
    let baseline = engine.generate_baseline(&report, &path);
    assert_eq!(baseline.fingerprints.len(), report.findings.len());

    // Filter report against baseline -> should be 0 findings
    let filtered = CloudEngine::filter_baseline(&report, &baseline);
    assert_eq!(
        filtered.findings.len(),
        0,
        "All known baseline findings must be suppressed"
    );

    // SARIF export with baseline -> 0 results
    let sarif = engine.to_sarif(&report, &path, Some(&baseline));
    assert_eq!(sarif.runs[0].results.len(), 0);
}
