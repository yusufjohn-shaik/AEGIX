use cyberguard_mobile::ios::DefaultIosAuditor;
use cyberguard_mobile::models::MobileRuleId;
use cyberguard_mobile::parser::MobileParser;
use cyberguard_mobile::traits::IosAuditor;

#[test]
fn test_ios_auditor_vulnerable_plist() {
    let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.vulnerableios</string>
    <key>CFBundleName</key>
    <string>VulnerableIOS</string>

    <!-- Insecure ATS Exceptions -->
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
        <key>NSExceptionDomains</key>
        <dict>
            <key>insecure.example.com</key>
            <dict>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <true/>
            </dict>
        </dict>
    </dict>

    <!-- Insecure URL Schemes -->
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>http</string>
                <string>a</string>
            </array>
        </dict>
    </array>

    <!-- Generic / Weak Privacy Strings -->
    <key>NSCameraUsageDescription</key>
    <string>Need camera</string>
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>TODO</string>

    <!-- Hardcoded Secret -->
    <key>AWS_KEY</key>
    <string>AKIAIOSFODNN7EXAMPLE</string>
</dict>
</plist>"#;

    let plist = MobileParser::parse_ios_plist(plist_xml.as_bytes(), "Info.plist").expect("parse");
    let auditor = DefaultIosAuditor::new(false);
    let findings = auditor
        .audit_plist(&plist, "Info.plist", plist_xml)
        .expect("audit");

    // CG-MOB-006: 2 findings (global arbitrary loads, domain exception for insecure.example.com)
    let ats_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == MobileRuleId::CgMob006.as_str())
        .collect();
    assert_eq!(ats_findings.len(), 2);
    assert!(ats_findings
        .iter()
        .any(|f| f.description.contains("globally disabled")));
    assert!(ats_findings
        .iter()
        .any(|f| f.description.contains("insecure.example.com")));

    // CG-MOB-007: 2 findings (http, short scheme "a")
    let url_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == MobileRuleId::CgMob007.as_str())
        .collect();
    assert_eq!(url_findings.len(), 2);

    // CG-MOB-008: 2 findings (Need camera, TODO)
    let privacy_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == MobileRuleId::CgMob008.as_str())
        .collect();
    assert_eq!(privacy_findings.len(), 2);

    // CG-MOB-010: AWS Key
    let secret_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == MobileRuleId::CgMob010.as_str())
        .collect();
    assert_eq!(secret_findings.len(), 1);
    assert!(secret_findings[0].description.contains("AKIA***MPLE"));
}

#[test]
fn test_ios_auditor_safe_plist() {
    let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.safeios</string>
    <key>CFBundleName</key>
    <string>SafeIOS</string>

    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>customscheme</string>
            </array>
        </dict>
    </array>

    <key>NSCameraUsageDescription</key>
    <string>Required for profile photo verification and document scanning.</string>
</dict>
</plist>"#;

    let plist = MobileParser::parse_ios_plist(plist_xml.as_bytes(), "Info.plist").expect("parse");
    let auditor = DefaultIosAuditor::new(false);
    let findings = auditor
        .audit_plist(&plist, "Info.plist", plist_xml)
        .expect("audit");

    assert_eq!(findings.len(), 0);
}

#[test]
fn test_ios_auditor_entitlements() {
    let ent_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
    <key>keychain-access-groups</key>
    <array>
        <string>*</string>
    </array>
</dict>
</plist>"#;

    let ent = MobileParser::parse_ios_entitlements(ent_xml.as_bytes(), "app.entitlements")
        .expect("parse");
    let auditor = DefaultIosAuditor::new(false);
    let findings = auditor
        .audit_entitlements(&ent, "app.entitlements", ent_xml)
        .expect("audit");

    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .all(|f| f.rule_id == MobileRuleId::CgMob009.as_str()));
    assert!(findings
        .iter()
        .any(|f| f.description.contains("get-task-allow")));
    assert!(findings
        .iter()
        .any(|f| f.description.contains("keychain access group")));
}
