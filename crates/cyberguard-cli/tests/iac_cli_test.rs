use cyberguard_iac::engine::IacEngine;
use cyberguard_iac::traits::IacScanner;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("vulnerable-iac")
        .join(name)
}

#[tokio::test]
async fn test_iac_cli_k8s_scan() {
    let fixture = fixture_path("k8s-privileged-pod.yaml");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = IacEngine::new();
    let report = engine.scan_file(&fixture).await.unwrap();

    assert!(
        report.findings.len() >= 4,
        "Expected >= 4 findings for vulnerable pod, found {}",
        report.findings.len()
    );

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"CG-IAC-001"));
    assert!(rule_ids.contains(&"CG-IAC-003"));
}

#[tokio::test]
async fn test_iac_cli_k8s_safe_scan() {
    let fixture = fixture_path("k8s-safe-deployment.yaml");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = IacEngine::new();
    let report = engine.scan_file(&fixture).await.unwrap();

    assert_eq!(
        report.findings.len(),
        0,
        "Expected 0 findings on hardened deployment"
    );
}

#[tokio::test]
async fn test_iac_cli_terraform_scan() {
    let fixture = fixture_path("terraform-vulnerable.tf");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = IacEngine::new();
    let report = engine.scan_file(&fixture).await.unwrap();

    assert!(
        report.findings.len() >= 3,
        "Expected >= 3 findings for vulnerable terraform, found {}",
        report.findings.len()
    );

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"CG-IAC-007"));
    assert!(rule_ids.contains(&"CG-IAC-008"));
    assert!(rule_ids.contains(&"CG-IAC-009"));
}

#[tokio::test]
async fn test_iac_cli_baseline_suppression() {
    let fixture = fixture_path("terraform-vulnerable.tf");
    let engine = IacEngine::new();
    let report = engine.scan_file(&fixture).await.unwrap();

    assert!(!report.findings.is_empty());

    // Generate baseline snapshot
    let baseline = engine.generate_baseline(&report, &fixture);
    assert_eq!(baseline.fingerprints.len(), report.findings.len());

    // Filter using baseline
    let filtered = IacEngine::filter_baseline(&report, &baseline);
    assert_eq!(
        filtered.findings.len(),
        0,
        "All findings should be suppressed by baseline"
    );
    assert_eq!(filtered.suppressed_findings_count, report.findings.len());

    // SARIF export with baseline suppression
    let sarif = engine.to_sarif(&report, &fixture, Some(&baseline));
    assert_eq!(
        sarif.runs[0].results.len(),
        0,
        "SARIF should contain 0 results after suppression"
    );
}
