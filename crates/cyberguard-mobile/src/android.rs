use crate::error::MobileError;
use crate::models::{AndroidManifest, AndroidNetworkSecurityConfig, MobileFinding, MobileRuleId};
use crate::traits::AndroidAuditor;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// High-risk / dangerous Android permissions catalog.
pub const DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
];

static AWS_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:AKIA[0-9A-Z]{16})"#).expect("valid regex"));

static GOOGLE_API_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"AIza[0-9A-Za-z\-_]{35}"#).expect("valid regex"));

static PRIVATE_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"-----BEGIN [A-Z ]+ PRIVATE KEY-----"#).expect("valid regex"));

static GENERIC_SECRET_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:secret|api_key|access_token|password|auth_token)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{24,})["']"#)
        .expect("valid regex")
});

/// Default static security auditor for Android packages and manifests.
#[derive(Debug, Default, Clone)]
pub struct DefaultAndroidAuditor {
    /// When release_mode is enabled, warning rules (like debuggable) are escalated or enforced.
    pub release_mode: bool,
}

impl DefaultAndroidAuditor {
    pub fn new(release_mode: bool) -> Self {
        Self { release_mode }
    }

    fn calculate_fingerprint(
        rule_id: &str,
        file_path: &str,
        location_path: &str,
        description: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(b":");
        hasher.update(file_path.as_bytes());
        hasher.update(b":");
        hasher.update(location_path.as_bytes());
        hasher.update(b":");
        hasher.update(description.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn mask_secret(secret: &str) -> String {
        if secret.len() <= 8 {
            "****".to_string()
        } else {
            format!("{}***{}", &secret[..4], &secret[secret.len() - 4..])
        }
    }
}

impl AndroidAuditor for DefaultAndroidAuditor {
    fn audit_manifest(
        &self,
        manifest: &AndroidManifest,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError> {
        let mut findings = Vec::new();

        // 1. CG-MOB-001: Insecure Debuggable Flag Enabled
        if manifest.application.debuggable == Some(true) {
            let rule = MobileRuleId::CgMob001;
            let location = "/manifest/application/@android:debuggable".to_string();
            let desc = "Android application has android:debuggable=\"true\" enabled, permitting runtime debugging, memory inspection, and reverse engineering.".to_string();
            let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
            findings.push(MobileFinding {
                rule_id: rule.as_str().to_string(),
                title: rule.title().to_string(),
                description: desc,
                severity: rule.severity(),
                confidence: rule.confidence(),
                cwe: rule.cwe(),
                file_path: file_path.to_string(),
                line: 1,
                column: 1,
                location_path: location,
                remediation: "Remove android:debuggable=\"true\" from <application> or set to \"false\" in release builds.".to_string(),
                fingerprint: fp,
            });
        }

        // 2. CG-MOB-002: Insecure Application Backup Enabled
        let target_sdk = manifest.target_sdk_version.unwrap_or(30);
        let explicit_backup = manifest.application.allow_backup;
        let has_backup_rules = manifest.application.full_backup_content.is_some()
            || manifest.application.data_extraction_rules.is_some();

        let backup_insecure = match explicit_backup {
            Some(true) => !has_backup_rules,
            None => target_sdk < 31 && !has_backup_rules,
            Some(false) => false,
        };

        if backup_insecure {
            let rule = MobileRuleId::CgMob002;
            let location = "/manifest/application/@android:allowBackup".to_string();
            let desc = "Application backup is enabled without restrictive data extraction rules, allowing app sandbox data extraction via adb backup.".to_string();
            let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
            findings.push(MobileFinding {
                rule_id: rule.as_str().to_string(),
                title: rule.title().to_string(),
                description: desc,
                severity: rule.severity(),
                confidence: rule.confidence(),
                cwe: rule.cwe(),
                file_path: file_path.to_string(),
                line: 1,
                column: 1,
                location_path: location,
                remediation: "Set android:allowBackup=\"false\" or configure restrictive android:dataExtractionRules / android:fullBackupContent.".to_string(),
                fingerprint: fp,
            });
        }

        // 3. CG-MOB-003: Cleartext HTTP Traffic Permitted (Manifest Level)
        if manifest.application.uses_cleartext_traffic == Some(true) {
            let rule = MobileRuleId::CgMob003;
            let location = "/manifest/application/@android:usesCleartextTraffic".to_string();
            let desc = "Cleartext HTTP traffic is explicitly permitted via android:usesCleartextTraffic=\"true\", exposing communications to MitM attacks.".to_string();
            let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
            findings.push(MobileFinding {
                rule_id: rule.as_str().to_string(),
                title: rule.title().to_string(),
                description: desc,
                severity: rule.severity(),
                confidence: rule.confidence(),
                cwe: rule.cwe(),
                file_path: file_path.to_string(),
                line: 1,
                column: 1,
                location_path: location,
                remediation: "Enforce TLS across all communications by setting android:usesCleartextTraffic=\"false\".".to_string(),
                fingerprint: fp,
            });
        }

        // 4. CG-MOB-004: Exported IPC Component Missing Permission
        for comp in &manifest.application.components {
            // Main launcher activity is legitimately exported for app entry
            let is_main_launcher = comp.intent_filters.iter().any(|f| f.is_main_launcher());
            if is_main_launcher {
                continue;
            }

            let is_exported = match comp.exported {
                Some(exp) => exp,
                None => !comp.intent_filters.is_empty() && target_sdk < 31,
            };

            if is_exported && comp.permission.is_none() {
                let rule = MobileRuleId::CgMob004;
                let c_type_str = comp.component_type.to_string();
                let location = format!(
                    "/manifest/application/{}[@android:name='{}']",
                    c_type_str, comp.name
                );
                let desc = format!(
                    "Component '{}' ({}) is exported without an authorizing permission, exposing internal IPC endpoints to unauthorized third-party apps.",
                    comp.name, c_type_str
                );
                let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
                findings.push(MobileFinding {
                    rule_id: rule.as_str().to_string(),
                    title: rule.title().to_string(),
                    description: desc,
                    severity: rule.severity(),
                    confidence: rule.confidence(),
                    cwe: rule.cwe(),
                    file_path: file_path.to_string(),
                    line: 1,
                    column: 1,
                    location_path: location,
                    remediation: format!(
                        "Set android:exported=\"false\" if '{}' is internal, or protect it with an authorizing android:permission.",
                        comp.name
                    ),
                    fingerprint: fp,
                });
            }
        }

        // 5. CG-MOB-005: Dangerous / Excessive Permissions Requested
        for perm in &manifest.uses_permissions {
            if DANGEROUS_PERMISSIONS.contains(&perm.name.as_str()) {
                let rule = MobileRuleId::CgMob005;
                let location = format!("/manifest/uses-permission[@android:name='{}']", perm.name);
                let desc = format!(
                    "High-risk Android permission '{}' requested. Excessive platform permissions expand the attack surface.",
                    perm.name
                );
                let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
                findings.push(MobileFinding {
                    rule_id: rule.as_str().to_string(),
                    title: rule.title().to_string(),
                    description: desc,
                    severity: rule.severity(),
                    confidence: rule.confidence(),
                    cwe: rule.cwe(),
                    file_path: file_path.to_string(),
                    line: 1,
                    column: 1,
                    location_path: location,
                    remediation: format!(
                        "Evaluate if permission '{}' is strictly required; replace with least-privilege APIs (e.g. Scoped Storage, Photo Picker).",
                        perm.name
                    ),
                    fingerprint: fp,
                });
            }
        }

        // 6. CG-MOB-010: Hardcoded Secrets in Android Manifest / Package
        self.scan_for_secrets(raw_content, file_path, &mut findings);

        Ok(findings)
    }

    fn audit_network_config(
        &self,
        config: &AndroidNetworkSecurityConfig,
        file_path: &str,
        _raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError> {
        let mut findings = Vec::new();

        // CG-MOB-003: Check base-config cleartext
        if config.base_config_cleartext_permitted == Some(true) {
            let rule = MobileRuleId::CgMob003;
            let location =
                "/network-security-config/base-config/@cleartextTrafficPermitted".to_string();
            let desc =
                "Global base-config allows cleartext HTTP traffic across all app network requests."
                    .to_string();
            let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
            findings.push(MobileFinding {
                rule_id: rule.as_str().to_string(),
                title: rule.title().to_string(),
                description: desc,
                severity: rule.severity(),
                confidence: rule.confidence(),
                cwe: rule.cwe(),
                file_path: file_path.to_string(),
                line: 1,
                column: 1,
                location_path: location,
                remediation:
                    "Set cleartextTrafficPermitted=\"false\" in <base-config> to mandate TLS."
                        .to_string(),
                fingerprint: fp,
            });
        }

        // CG-MOB-003: Check domain-config cleartext
        for d_cfg in &config.domain_configs {
            if d_cfg.cleartext_traffic_permitted == Some(true) {
                let rule = MobileRuleId::CgMob003;
                let domain_list = d_cfg.domains.join(", ");
                let location = format!(
                    "/network-security-config/domain-config[domain='{}']",
                    domain_list
                );
                let desc = format!(
                    "Domain configuration permits cleartext HTTP traffic to domains: [{}].",
                    domain_list
                );
                let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
                findings.push(MobileFinding {
                    rule_id: rule.as_str().to_string(),
                    title: rule.title().to_string(),
                    description: desc,
                    severity: rule.severity(),
                    confidence: rule.confidence(),
                    cwe: rule.cwe(),
                    file_path: file_path.to_string(),
                    line: 1,
                    column: 1,
                    location_path: location,
                    remediation:
                        "Enforce HTTPS/TLS endpoints and remove cleartext domain exceptions."
                            .to_string(),
                    fingerprint: fp,
                });
            }
        }

        Ok(findings)
    }
}

impl DefaultAndroidAuditor {
    fn scan_for_secrets(
        &self,
        raw_content: &str,
        file_path: &str,
        findings: &mut Vec<MobileFinding>,
    ) {
        let rule = MobileRuleId::CgMob010;

        // AWS Key check
        for m in AWS_KEY_REGEX.find_iter(raw_content) {
            let secret = m.as_str();
            let masked = Self::mask_secret(secret);
            let location = format!("/raw_content/match[@offset='{}']", m.start());
            let desc = format!("Hardcoded AWS Access Key identified: {}", masked);
            let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
            findings.push(MobileFinding {
                rule_id: rule.as_str().to_string(),
                title: rule.title().to_string(),
                description: desc,
                severity: rule.severity(),
                confidence: rule.confidence(),
                cwe: rule.cwe(),
                file_path: file_path.to_string(),
                line: 1,
                column: 1,
                location_path: location,
                remediation: "Extract AWS credentials from mobile code. Use federated STS tokens or backend API proxies.".to_string(),
                fingerprint: fp,
            });
        }

        // Google API Key check
        for m in GOOGLE_API_KEY_REGEX.find_iter(raw_content) {
            let secret = m.as_str();
            let masked = Self::mask_secret(secret);
            let location = format!("/raw_content/match[@offset='{}']", m.start());
            let desc = format!("Hardcoded Google API Key identified: {}", masked);
            let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
            findings.push(MobileFinding {
                rule_id: rule.as_str().to_string(),
                title: rule.title().to_string(),
                description: desc,
                severity: rule.severity(),
                confidence: rule.confidence(),
                cwe: rule.cwe(),
                file_path: file_path.to_string(),
                line: 1,
                column: 1,
                location_path: location,
                remediation: "Restrict Google API key in Google Cloud Console with Android package name and SHA-1 certificate fingerprint restrictions.".to_string(),
                fingerprint: fp,
            });
        }

        // Private Key check
        for m in PRIVATE_KEY_REGEX.find_iter(raw_content) {
            let location = format!("/raw_content/match[@offset='{}']", m.start());
            let desc = "Hardcoded Private Key block identified in mobile package.".to_string();
            let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
            findings.push(MobileFinding {
                rule_id: rule.as_str().to_string(),
                title: rule.title().to_string(),
                description: desc,
                severity: rule.severity(),
                confidence: rule.confidence(),
                cwe: rule.cwe(),
                file_path: file_path.to_string(),
                line: 1,
                column: 1,
                location_path: location,
                remediation:
                    "Never bundle private cryptographic keys in mobile application packages."
                        .to_string(),
                fingerprint: fp,
            });
        }

        // Generic secret pattern check
        for cap in GENERIC_SECRET_REGEX.captures_iter(raw_content) {
            if let Some(secret_match) = cap.get(1) {
                let val = secret_match.as_str();
                // Filter out URLs, namespaces, and standard schema indicators
                if val.starts_with("http") || val.contains("schemas.android.com") {
                    continue;
                }
                let masked = Self::mask_secret(val);
                let location = format!("/raw_content/match[@offset='{}']", secret_match.start());
                let desc = format!("High-entropy generic credential/token embedded: {}", masked);
                let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
                findings.push(MobileFinding {
                    rule_id: rule.as_str().to_string(),
                    title: rule.title().to_string(),
                    description: desc,
                    severity: rule.severity(),
                    confidence: rule.confidence(),
                    cwe: rule.cwe(),
                    file_path: file_path.to_string(),
                    line: 1,
                    column: 1,
                    location_path: location,
                    remediation: "Store sensitive keys on a secure backend server or inject dynamically via secure authentication sessions.".to_string(),
                    fingerprint: fp,
                });
            }
        }
    }
}
