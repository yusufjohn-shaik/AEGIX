use cyberguard_mobile::android::DefaultAndroidAuditor;
use cyberguard_mobile::models::MobileRuleId;
use cyberguard_mobile::parser::MobileParser;
use cyberguard_mobile::traits::AndroidAuditor;

#[test]
fn test_android_auditor_vulnerable_manifest() {
    // Construct dummy test API key dynamically to avoid triggering automated repository secret scanners
    let dummy_google_key = ["AIza", "SyA_exampleFakeGoogleApiKeyForTest1"].join("");
    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerableapp">

    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="30" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.READ_SMS" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:label="VulnerableApp">

        <!-- Exported activity missing permission -->
        <activity
            android:name=".InsecureActivity"
            android:exported="true" />

        <!-- Main Launcher (Legitimately Exported) -->
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Exported background service without permission -->
        <service
            android:name=".BackgroundSyncService"
            android:exported="true" />

        <!-- Hardcoded Secret in Meta-Data -->
        <meta-data
            android:name="google_api_key"
            android:value="{}" />

    </application>
</manifest>"#,
        dummy_google_key
    );

    let manifest =
        MobileParser::parse_android_manifest_xml(&xml, "AndroidManifest.xml").expect("parse");
    let auditor = DefaultAndroidAuditor::new(false);
    let findings = auditor
        .audit_manifest(&manifest, "AndroidManifest.xml", &xml)
        .expect("audit");

    // Check CG-MOB-001 (debuggable)
    assert!(findings
        .iter()
        .any(|f| f.rule_id == MobileRuleId::CgMob001.as_str()));

    // Check CG-MOB-002 (allowBackup)
    assert!(findings
        .iter()
        .any(|f| f.rule_id == MobileRuleId::CgMob002.as_str()));

    // Check CG-MOB-003 (usesCleartextTraffic)
    assert!(findings
        .iter()
        .any(|f| f.rule_id == MobileRuleId::CgMob003.as_str()));

    // Check CG-MOB-004 (exported activity and service, but NOT MainActivity)
    let exported_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == MobileRuleId::CgMob004.as_str())
        .collect();
    assert_eq!(exported_findings.len(), 2);
    assert!(exported_findings
        .iter()
        .any(|f| f.description.contains(".InsecureActivity")));
    assert!(exported_findings
        .iter()
        .any(|f| f.description.contains(".BackgroundSyncService")));
    assert!(!exported_findings
        .iter()
        .any(|f| f.description.contains(".MainActivity")));

    // Check CG-MOB-005 (SYSTEM_ALERT_WINDOW and READ_SMS)
    let perm_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == MobileRuleId::CgMob005.as_str())
        .collect();
    assert_eq!(perm_findings.len(), 2);
    assert!(perm_findings
        .iter()
        .any(|f| f.description.contains("SYSTEM_ALERT_WINDOW")));
    assert!(perm_findings
        .iter()
        .any(|f| f.description.contains("READ_SMS")));

    // Check CG-MOB-010 (Google API Key)
    let secret_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == MobileRuleId::CgMob010.as_str())
        .collect();
    assert_eq!(secret_findings.len(), 1);
    assert!(secret_findings[0].description.contains("AIza***est1"));
}

#[test]
fn test_android_auditor_safe_manifest() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.safeapp">

    <uses-sdk android:minSdkVersion="31" android:targetSdkVersion="34" />

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="false"
        android:debuggable="false"
        android:usesCleartextTraffic="false"
        android:label="SafeApp">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity
            android:name=".InternalActivity"
            android:exported="false" />

    </application>
</manifest>"#;

    let manifest =
        MobileParser::parse_android_manifest_xml(xml, "AndroidManifest.xml").expect("parse");
    let auditor = DefaultAndroidAuditor::new(false);
    let findings = auditor
        .audit_manifest(&manifest, "AndroidManifest.xml", xml)
        .expect("audit");

    assert_eq!(findings.len(), 0);
}

#[test]
fn test_android_network_security_config_audit() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">legacy.example.com</domain>
    </domain-config>
</network-security-config>"#;

    let cfg = MobileParser::parse_android_network_config(xml, "network_security_config.xml")
        .expect("parse");
    let auditor = DefaultAndroidAuditor::new(false);
    let findings = auditor
        .audit_network_config(&cfg, "network_security_config.xml", xml)
        .expect("audit");

    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .all(|f| f.rule_id == MobileRuleId::CgMob003.as_str()));
}
