use cyberguard_mobile::parser::MobileParser;

#[test]
fn test_parse_android_manifest_xml() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application
        android:name=".MainApplication"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service
            android:name=".ExportedService"
            android:exported="true" />
    </application>
</manifest>"#;

    let manifest =
        MobileParser::parse_android_manifest_xml(xml, "AndroidManifest.xml").expect("parse xml");
    assert_eq!(
        manifest.package_name.as_deref(),
        Some("com.example.testapp")
    );
    assert_eq!(manifest.min_sdk_version, Some(24));
    assert_eq!(manifest.target_sdk_version, Some(33));
    assert_eq!(manifest.permissions.len(), 2);
    assert_eq!(manifest.application.debuggable, Some(true));
    assert_eq!(manifest.application.allow_backup, Some(true));
    assert_eq!(manifest.application.uses_cleartext_traffic, Some(true));
    assert_eq!(manifest.application.components.len(), 2);

    let main_act = manifest
        .application
        .components
        .iter()
        .find(|c| c.name == ".MainActivity")
        .unwrap();
    assert_eq!(main_act.exported, Some(true));
    assert!(main_act.intent_filters[0].is_main_launcher());
}

#[test]
fn test_parse_android_network_config() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">insecure.example.com</domain>
        <domain includeSubdomains="false">legacy.example.com</domain>
    </domain-config>
</network-security-config>"#;

    let cfg =
        MobileParser::parse_android_network_config(xml, "res/xml/network_security_config.xml")
            .expect("parse net config");
    assert_eq!(cfg.base_config_cleartext_permitted, Some(false));
    assert_eq!(cfg.domain_configs.len(), 1);
    assert_eq!(
        cfg.domain_configs[0].cleartext_traffic_permitted,
        Some(true)
    );
    assert_eq!(cfg.domain_configs[0].domains.len(), 2);
}

#[test]
fn test_parse_ios_plist_xml() {
    let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.iosapp</string>
    <key>CFBundleName</key>
    <string>TestIOS</string>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
        <key>NSExceptionDomains</key>
        <dict>
            <key>api.example.com</key>
            <dict>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <true/>
                <key>NSIncludesSubdomains</key>
                <true/>
            </dict>
        </dict>
    </dict>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLName</key>
            <string>test-scheme</string>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>customscheme</string>
            </array>
        </dict>
    </array>
    <key>NSCameraUsageDescription</key>
    <string>Required to scan bar codes for inventory tracking.</string>
</dict>
</plist>"#;

    let plist =
        MobileParser::parse_ios_plist(plist_xml.as_bytes(), "Info.plist").expect("parse plist");
    assert_eq!(
        plist.bundle_identifier.as_deref(),
        Some("com.example.iosapp")
    );
    assert_eq!(plist.bundle_name.as_deref(), Some("TestIOS"));

    let ats = plist.app_transport_security.unwrap();
    assert_eq!(ats.allows_arbitrary_loads, Some(true));
    assert!(ats.exception_domains.contains_key("api.example.com"));

    assert_eq!(plist.url_types.len(), 1);
    assert_eq!(plist.url_types[0].schemes, vec!["customscheme".to_string()]);

    assert_eq!(
        plist
            .privacy_usage_descriptions
            .get("NSCameraUsageDescription")
            .map(|s| s.as_str()),
        Some("Required to scan bar codes for inventory tracking.")
    );
}

#[test]
fn test_parse_ios_entitlements() {
    let ent_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>get-task-allow</key>
    <true/>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.example.shared</string>
    </array>
</dict>
</plist>"#;

    let ent = MobileParser::parse_ios_entitlements(ent_xml.as_bytes(), "app.entitlements")
        .expect("parse entitlements");
    assert_eq!(ent.get_task_allow, Some(true));
    assert_eq!(ent.keychain_access_groups.len(), 1);
}

#[test]
fn test_streaming_zip_extraction() {
    // Construct a synthetic ZIP archive in memory
    // Local file 1: AndroidManifest.xml (stored)
    // Local file 2: classes.dex (stored, skipped)
    let manifest_content = b"<manifest package=\"com.test\"/>";
    let dex_content = b"DEX_BYTECODE_DUMMY_DATA";

    let mut zip_bytes = Vec::new();

    // File 1 header
    zip_bytes.extend_from_slice(b"PK\x03\x04");
    zip_bytes.extend_from_slice(&[20, 0]); // version
    zip_bytes.extend_from_slice(&[0, 0]); // flags
    zip_bytes.extend_from_slice(&[0, 0]); // compression = stored
    zip_bytes.extend_from_slice(&[0, 0, 0, 0]); // time, date
    zip_bytes.extend_from_slice(&[0, 0, 0, 0]); // crc
    zip_bytes.extend_from_slice(&(manifest_content.len() as u32).to_le_bytes()); // compressed size
    zip_bytes.extend_from_slice(&(manifest_content.len() as u32).to_le_bytes()); // uncompressed size
    let name1 = b"AndroidManifest.xml";
    zip_bytes.extend_from_slice(&(name1.len() as u16).to_le_bytes()); // name len
    zip_bytes.extend_from_slice(&[0, 0]); // extra len
    zip_bytes.extend_from_slice(name1);
    zip_bytes.extend_from_slice(manifest_content);

    // File 2 header (classes.dex)
    zip_bytes.extend_from_slice(b"PK\x03\x04");
    zip_bytes.extend_from_slice(&[20, 0]);
    zip_bytes.extend_from_slice(&[0, 0]);
    zip_bytes.extend_from_slice(&[0, 0]); // stored
    zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
    zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
    zip_bytes.extend_from_slice(&(dex_content.len() as u32).to_le_bytes());
    zip_bytes.extend_from_slice(&(dex_content.len() as u32).to_le_bytes());
    let name2 = b"classes.dex";
    zip_bytes.extend_from_slice(&(name2.len() as u16).to_le_bytes());
    zip_bytes.extend_from_slice(&[0, 0]);
    zip_bytes.extend_from_slice(name2);
    zip_bytes.extend_from_slice(dex_content);

    let mut cursor = std::io::Cursor::new(zip_bytes);
    let extracted =
        MobileParser::extract_targeted_zip_entries(&mut cursor, &["androidmanifest.xml"])
            .expect("extract zip");

    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].0, "AndroidManifest.xml");
    assert_eq!(extracted[0].1, manifest_content);
}
