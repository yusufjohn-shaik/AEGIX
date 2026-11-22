use cyberguard_mobile::engine::MobileEngine;
use cyberguard_mobile::models::MobileRuleId;
use cyberguard_mobile::traits::MobileScanner;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("vulnerable-mobile")
        .join(name)
}

#[tokio::test]
async fn test_mobile_cli_android_vulnerable_scan() {
    let fixture = fixture_path("android-vulnerable-manifest.xml");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = MobileEngine::new(false);
    let report = engine.scan_file(&fixture).await.unwrap();

    assert!(
        report.findings.len() >= 6,
        "Expected >= 6 findings for vulnerable Android manifest, found {}",
        report.findings.len()
    );

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&MobileRuleId::CgMob001.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob002.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob003.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob004.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob005.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob010.as_str()));
}

#[tokio::test]
async fn test_mobile_cli_android_safe_scan() {
    let fixture = fixture_path("android-safe-manifest.xml");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = MobileEngine::new(false);
    let report = engine.scan_file(&fixture).await.unwrap();

    assert_eq!(
        report.findings.len(),
        0,
        "Expected 0 findings on hardened Android manifest"
    );
}

#[tokio::test]
async fn test_mobile_cli_ios_vulnerable_scan() {
    let fixture = fixture_path("ios-vulnerable-info.plist");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = MobileEngine::new(false);
    let report = engine.scan_file(&fixture).await.unwrap();

    assert!(
        report.findings.len() >= 5,
        "Expected >= 5 findings for vulnerable iOS Info.plist, found {}",
        report.findings.len()
    );

    let rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&MobileRuleId::CgMob006.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob007.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob008.as_str()));
    assert!(rule_ids.contains(&MobileRuleId::CgMob010.as_str()));
}

#[tokio::test]
async fn test_mobile_cli_ios_safe_scan() {
    let fixture = fixture_path("ios-safe-info.plist");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = MobileEngine::new(false);
    let report = engine.scan_file(&fixture).await.unwrap();

    assert_eq!(
        report.findings.len(),
        0,
        "Expected 0 findings on hardened iOS Info.plist"
    );
}

#[tokio::test]
async fn test_mobile_cli_ios_entitlements_scan() {
    let fixture = fixture_path("ios-vulnerable.entitlements");
    assert!(fixture.exists(), "Fixture must exist at {:?}", fixture);

    let engine = MobileEngine::new(false);
    let report = engine.scan_file(&fixture).await.unwrap();

    assert_eq!(report.findings.len(), 2);
    assert!(report
        .findings
        .iter()
        .all(|f| f.rule_id == MobileRuleId::CgMob009.as_str()));
}

#[tokio::test]
async fn test_mobile_cli_baseline_suppression() {
    let fixture = fixture_path("android-vulnerable-manifest.xml");
    let engine = MobileEngine::new(false);
    let initial_report = engine.scan_file(&fixture).await.unwrap();
    assert!(!initial_report.findings.is_empty());

    let baseline = engine.generate_baseline(&initial_report, &fixture);
    let suppressed_report = MobileEngine::filter_baseline(&initial_report, &baseline);

    assert_eq!(suppressed_report.findings.len(), 0);
    assert_eq!(
        suppressed_report.suppressed_findings_count,
        initial_report.findings.len()
    );
}
