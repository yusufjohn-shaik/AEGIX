use cyberguard_mobile::engine::MobileEngine;
use cyberguard_mobile::models::{MobileDocument, MobileFormat};
use cyberguard_mobile::parser::MobileParser;
use cyberguard_mobile::traits::MobileScanner;
use std::io::Cursor;
use std::path::Path;

#[tokio::test]
async fn test_mobile_engine_multi_platform_scan() {
    let android_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.multiplatform">
    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
        <activity android:name=".UnprotectedActivity" android:exported="true" />
    </application>
</manifest>"#;

    let ios_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.multiplatform</string>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>"#;

    let android_manifest =
        MobileParser::parse_android_manifest_xml(android_xml, "AndroidManifest.xml").unwrap();
    let ios_plist = MobileParser::parse_ios_plist(ios_xml.as_bytes(), "Info.plist").unwrap();

    let docs = vec![
        MobileDocument {
            format: MobileFormat::AndroidManifestXml,
            file_path: "AndroidManifest.xml".to_string(),
            android_manifest: Some(android_manifest),
            android_network_config: None,
            ios_plist: None,
            ios_entitlements: None,
            raw_content: android_xml.to_string(),
        },
        MobileDocument {
            format: MobileFormat::IosInfoPlist,
            file_path: "Info.plist".to_string(),
            android_manifest: None,
            android_network_config: None,
            ios_plist: Some(ios_plist),
            ios_entitlements: None,
            raw_content: ios_xml.to_string(),
        },
    ];

    let engine = MobileEngine::new(false);
    let report = engine.scan(&docs).await.expect("scan");

    assert_eq!(report.total_documents_scanned, 2);
    assert!(!report.findings.is_empty());

    // Both Android findings (CG-MOB-001, etc.) and iOS findings (CG-MOB-006) must be present
    assert!(report.findings.iter().any(|f| f.rule_id == "CG-MOB-001"));
    assert!(report.findings.iter().any(|f| f.rule_id == "CG-MOB-006"));

    // Test SARIF export
    let sarif = engine.to_sarif(&report).expect("to_sarif");
    assert_eq!(sarif.runs.len(), 1);
    assert_eq!(sarif.runs[0].results.len(), report.findings.len());

    // Test Baseline generation and filtering
    let baseline = engine.generate_baseline(&report, Path::new("."));
    assert_eq!(baseline.fingerprints.len(), report.findings.len());

    let filtered = MobileEngine::filter_baseline(&report, &baseline);
    assert_eq!(filtered.findings.len(), 0);
    assert_eq!(filtered.suppressed_findings_count, report.findings.len());
}

#[tokio::test]
async fn test_mobile_engine_scan_reader() {
    let android_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.stream">
    <application android:debuggable="true" />
</manifest>"#;

    let engine = MobileEngine::new(false);
    let mut cursor = Cursor::new(android_xml.as_bytes());
    let report = engine
        .scan_reader(&mut cursor, Path::new("AndroidManifest.xml"))
        .await
        .expect("scan_reader");

    assert_eq!(report.total_documents_scanned, 1);
    assert!(report.findings.iter().any(|f| f.rule_id == "CG-MOB-001"));
}
