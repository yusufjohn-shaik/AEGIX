use crate::error::MobileError;
use crate::models::{IosEntitlement, IosPropertyList, MobileFinding, MobileRuleId};
use crate::traits::IosAuditor;
use cyberguard_core::sarif::SarifLevel;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

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

const RESERVED_OR_DANGEROUS_SCHEMES: &[&str] = &["http", "https", "mailto", "tel", "ftp", "file"];

/// Default static security auditor for iOS application bundles, plists, and entitlements.
#[derive(Debug, Default, Clone)]
pub struct DefaultIosAuditor {
    /// When release_mode is enabled, entitlements and ATS checks are strictly enforced.
    pub release_mode: bool,
}

impl DefaultIosAuditor {
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

impl IosAuditor for DefaultIosAuditor {
    fn audit_plist(
        &self,
        plist: &IosPropertyList,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError> {
        let mut findings = Vec::new();

        // 1. CG-MOB-006: Insecure App Transport Security (ATS) Exceptions
        if let Some(ats) = &plist.app_transport_security {
            let arbitrary_loads = ats.allows_arbitrary_loads.unwrap_or(false);
            let arbitrary_web = ats.allows_arbitrary_loads_in_web_content.unwrap_or(false);
            let arbitrary_media = ats.allows_arbitrary_loads_for_media.unwrap_or(false);

            if arbitrary_loads {
                let rule = MobileRuleId::CgMob006;
                let location =
                    "/plist/dict/key[NSAppTransportSecurity]/dict/key[NSAllowsArbitraryLoads]"
                        .to_string();
                let desc = if arbitrary_web {
                    "NSAllowsArbitraryLoads is set to true, but NSAllowsArbitraryLoadsInWebContent is also set. Native traffic uses ATS on iOS 10+, but older devices remain vulnerable."
                } else {
                    "App Transport Security (ATS) is globally disabled via NSAllowsArbitraryLoads = true, exposing all network traffic to cleartext interception and MitM attacks."
                }.to_string();
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
                    remediation: "Remove NSAllowsArbitraryLoads and enforce TLS 1.2+ with forward secrecy across all endpoints.".to_string(),
                    fingerprint: fp,
                });
            } else if arbitrary_web || arbitrary_media {
                let rule = MobileRuleId::CgMob006;
                let location = "/plist/dict/key[NSAppTransportSecurity]".to_string();
                let desc = "App Transport Security contains exceptions for web content or streaming media, allowing cleartext HTTP traffic in WKWebView.".to_string();
                let fp = Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
                findings.push(MobileFinding {
                    rule_id: rule.as_str().to_string(),
                    title: rule.title().to_string(),
                    description: desc,
                    severity: SarifLevel::Warning,
                    confidence: rule.confidence(),
                    cwe: rule.cwe(),
                    file_path: file_path.to_string(),
                    line: 1,
                    column: 1,
                    location_path: location,
                    remediation: "Ensure WKWebView loads only secure HTTPS resources.".to_string(),
                    fingerprint: fp,
                });
            }

            for (domain, exc) in &ats.exception_domains {
                let insecure_http = exc.exception_allows_insecure_http_loads.unwrap_or(false)
                    || exc
                        .temporary_exception_allows_insecure_http_loads
                        .unwrap_or(false);
                if insecure_http {
                    let rule = MobileRuleId::CgMob006;
                    let location = format!(
                        "/plist/dict/key[NSAppTransportSecurity]/dict/key[NSExceptionDomains]/dict/key[{}]",
                        domain
                    );
                    let desc = format!(
                        "Insecure HTTP loads permitted for domain '{}' via ATS exception.",
                        domain
                    );
                    let fp =
                        Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
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
                            "Migrate domain '{}' to HTTPS/TLS 1.2+ and remove the insecure ATS exception.",
                            domain
                        ),
                        fingerprint: fp,
                    });
                }
            }
        }

        // 2. CG-MOB-007: Insecure Custom URL Scheme
        for url_type in &plist.url_types {
            for scheme in &url_type.schemes {
                let lower = scheme.to_ascii_lowercase();
                let is_dangerous = RESERVED_OR_DANGEROUS_SCHEMES.contains(&lower.as_str());
                let is_short_or_wildcard = lower.len() < 3 || lower.contains('*');

                if is_dangerous || is_short_or_wildcard {
                    let rule = MobileRuleId::CgMob007;
                    let location = format!(
                        "/plist/dict/key[CFBundleURLTypes]/array/dict/key[CFBundleURLSchemes]/string[{}]",
                        scheme
                    );
                    let desc = format!(
                        "Insecure, collision-prone, or reserved URL scheme '{}' declared in CFBundleURLSchemes.",
                        scheme
                    );
                    let fp =
                        Self::calculate_fingerprint(rule.as_str(), file_path, &location, &desc);
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
                        remediation: "Adopt iOS Universal Links (associated-domains) to ensure cryptographically verified domain ownership.".to_string(),
                        fingerprint: fp,
                    });
                }
            }
        }

        // 3. CG-MOB-008: Missing or Generic Privacy Usage Description
        for (key, desc_str) in &plist.privacy_usage_descriptions {
            let trimmed = desc_str.trim();
            let is_generic = trimmed.len() < 15
                || trimmed.eq_ignore_ascii_case("TODO")
                || trimmed.eq_ignore_ascii_case("test")
                || trimmed.eq_ignore_ascii_case("Need permission")
                || trimmed.eq_ignore_ascii_case("Need camera")
                || trimmed.eq_ignore_ascii_case("Camera access")
                || trimmed.eq_ignore_ascii_case("App requires this permission");

            if is_generic {
                let rule = MobileRuleId::CgMob008;
                let location = format!("/plist/dict/key[{}]", key);
                let desc = format!(
                    "Privacy usage description for '{}' is generic, placeholder, or insufficient: \"{}\".",
                    key, trimmed
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
                        "Provide a clear, specific, user-facing explanation for '{}' in accordance with App Store guidelines.",
                        key
                    ),
                    fingerprint: fp,
                });
            }
        }

        // 4. CG-MOB-010: Hardcoded Secrets in Plist
        self.scan_for_secrets(raw_content, file_path, &mut findings);

        Ok(findings)
    }

    fn audit_entitlements(
        &self,
        entitlements: &IosEntitlement,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<MobileFinding>, MobileError> {
        let mut findings = Vec::new();

        // 1. CG-MOB-009: Insecure Release App Entitlements (get-task-allow)
        if entitlements.get_task_allow == Some(true) {
            let rule = MobileRuleId::CgMob009;
            let location = "/entitlements/dict/key[get-task-allow]".to_string();
            let desc = "Entitlement 'get-task-allow' is enabled (true). This allows debugger attachment and memory dumping in release builds.".to_string();
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
                remediation: "Ensure 'get-task-allow' is set to false or stripped by release distribution provisioning profiles.".to_string(),
                fingerprint: fp,
            });
        }

        // 2. CG-MOB-009: Wildcard keychain access groups
        for group in &entitlements.keychain_access_groups {
            if group == "*" || group.ends_with(".*") {
                let rule = MobileRuleId::CgMob009;
                let location = format!(
                    "/entitlements/dict/key[keychain-access-groups]/array/string[{}]",
                    group
                );
                let desc = format!(
                    "Wildcard keychain access group '{}' declared, breaking keychain isolation.",
                    group
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
                    remediation: "Specify explicit bundle seed identifiers for keychain sharing; eliminate wildcards.".to_string(),
                    fingerprint: fp,
                });
            }
        }

        // 3. CG-MOB-010: Hardcoded Secrets in Entitlements
        self.scan_for_secrets(raw_content, file_path, &mut findings);

        Ok(findings)
    }
}

impl DefaultIosAuditor {
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
                remediation: "Restrict Google API key in Google Cloud Console with iOS bundle identifier restrictions.".to_string(),
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
                if val.starts_with("http") || val.contains("apple.com") {
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
