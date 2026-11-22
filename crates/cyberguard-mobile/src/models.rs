use cyberguard_core::sarif::{Confidence, SarifLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported mobile artifact and configuration formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileFormat {
    AndroidManifestXml,
    AndroidBinaryXml,
    AndroidNetworkSecurityConfig,
    AndroidApk,
    IosInfoPlist,
    IosEntitlements,
    IosIpa,
}

/// Strongly typed identifier for Mobile Security Engine rules (OWASP MASVS / Mobile Top 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MobileRuleId {
    CgMob001, // Insecure Debuggable Flag Enabled
    CgMob002, // Insecure Application Backup Enabled
    CgMob003, // Cleartext HTTP Traffic Permitted
    CgMob004, // Exported IPC Component Missing Permission
    CgMob005, // Dangerous / Excessive Permissions Requested
    CgMob006, // Insecure App Transport Security (ATS) Exceptions
    CgMob007, // Insecure Custom URL Scheme
    CgMob008, // Missing or Generic Privacy Usage Description
    CgMob009, // Insecure Release App Entitlements
    CgMob010, // Hardcoded Secrets in Mobile Package
}

impl MobileRuleId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CgMob001 => "CG-MOB-001",
            Self::CgMob002 => "CG-MOB-002",
            Self::CgMob003 => "CG-MOB-003",
            Self::CgMob004 => "CG-MOB-004",
            Self::CgMob005 => "CG-MOB-005",
            Self::CgMob006 => "CG-MOB-006",
            Self::CgMob007 => "CG-MOB-007",
            Self::CgMob008 => "CG-MOB-008",
            Self::CgMob009 => "CG-MOB-009",
            Self::CgMob010 => "CG-MOB-010",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::CgMob001 => "Insecure Debuggable Flag Enabled",
            Self::CgMob002 => "Insecure Application Backup Enabled",
            Self::CgMob003 => "Cleartext HTTP Traffic Permitted",
            Self::CgMob004 => "Exported IPC Component Missing Permission",
            Self::CgMob005 => "Dangerous / Excessive Permissions Requested",
            Self::CgMob006 => "Insecure App Transport Security (ATS) Exceptions",
            Self::CgMob007 => "Insecure Custom URL Scheme",
            Self::CgMob008 => "Missing or Generic Privacy Usage Description",
            Self::CgMob009 => "Insecure Release App Entitlements",
            Self::CgMob010 => "Hardcoded Secrets in Mobile Package",
        }
    }

    pub fn severity(&self) -> SarifLevel {
        match self {
            Self::CgMob004 | Self::CgMob009 => SarifLevel::Error,
            Self::CgMob001 | Self::CgMob003 | Self::CgMob006 | Self::CgMob010 => SarifLevel::Error,
            Self::CgMob002 | Self::CgMob005 | Self::CgMob007 | Self::CgMob008 => {
                SarifLevel::Warning
            }
        }
    }

    pub fn confidence(&self) -> Confidence {
        match self {
            Self::CgMob008 => Confidence::Medium,
            _ => Confidence::High,
        }
    }

    pub fn cwe(&self) -> u32 {
        match self {
            Self::CgMob001 => 215,
            Self::CgMob002 => 921,
            Self::CgMob003 | Self::CgMob006 => 319,
            Self::CgMob004 => 926,
            Self::CgMob005 | Self::CgMob009 => 250,
            Self::CgMob007 => 939,
            Self::CgMob008 => 359,
            Self::CgMob010 => 798,
        }
    }

    pub fn masvs_control(&self) -> &'static str {
        match self {
            Self::CgMob001 => {
                "MASVS-RESILIENCE-1: The app validates that it is running in a trusted environment"
            }
            Self::CgMob002 => {
                "MASVS-STORAGE-2: The app prevents leakage of sensitive data via platform backups"
            }
            Self::CgMob003 | Self::CgMob006 => {
                "MASVS-NETWORK-1: The app uses secure network communication (TLS 1.2+)"
            }
            Self::CgMob004 => {
                "MASVS-PLATFORM-1: The app securely configures IPC components and access controls"
            }
            Self::CgMob005 => "MASVS-PLATFORM-2: The app requests minimum platform permissions",
            Self::CgMob007 => {
                "MASVS-PLATFORM-1: The app validates inputs received via custom URL schemes"
            }
            Self::CgMob008 => {
                "MASVS-PLATFORM-3: The app provides clear, user-facing privacy usage justifications"
            }
            Self::CgMob009 => {
                "MASVS-RESILIENCE-1: Production app builds omit development/debugging entitlements"
            }
            Self::CgMob010 => {
                "MASVS-CRYPTO-1: The app does not embed hardcoded cryptographic secrets or API keys"
            }
        }
    }

    pub fn owasp_category(&self) -> &'static str {
        match self {
            Self::CgMob001 | Self::CgMob004 | Self::CgMob007 | Self::CgMob009 => {
                "OWASP M1: Improper Credential Usage & Platform Misconfigurations"
            }
            Self::CgMob002 => "OWASP M2: Insecure Data Storage",
            Self::CgMob003 | Self::CgMob006 => "OWASP M5: Insecure Communication",
            Self::CgMob005 | Self::CgMob008 => "OWASP M6: Inadequate Privacy Controls",
            Self::CgMob010 => "OWASP M9: Insecure Cryptography & Hardcoded Secrets",
        }
    }
}

/// Canonical representation of an individual Mobile security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileFinding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: SarifLevel,
    pub confidence: Confidence,
    pub cwe: u32,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub location_path: String,
    pub remediation: String,
    pub fingerprint: String,
}

/// Aggregated Mobile Security Audit Report.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MobileReport {
    pub target_path: String,
    pub total_documents_scanned: usize,
    pub total_components_evaluated: usize,
    pub findings: Vec<MobileFinding>,
    pub suppressed_findings_count: usize,
}

/// Intermediate Representation of a parsed mobile document or archive manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileDocument {
    pub format: MobileFormat,
    pub file_path: String,
    pub android_manifest: Option<AndroidManifest>,
    pub android_network_config: Option<AndroidNetworkSecurityConfig>,
    pub ios_plist: Option<IosPropertyList>,
    pub ios_entitlements: Option<IosEntitlement>,
    pub raw_content: String,
}

// ============================================================================
// Android Manifest & Network Security IR
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AndroidManifest {
    pub package_name: Option<String>,
    pub min_sdk_version: Option<u32>,
    pub target_sdk_version: Option<u32>,
    pub application: AndroidApplication,
    pub permissions: Vec<String>,
    pub uses_permissions: Vec<AndroidUsesPermission>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AndroidApplication {
    pub name: Option<String>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<String>,
    pub full_backup_content: Option<String>,
    pub data_extraction_rules: Option<String>,
    pub components: Vec<AndroidComponent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AndroidComponentType {
    Activity,
    Service,
    Receiver,
    Provider,
}

impl std::fmt::Display for AndroidComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Activity => write!(f, "activity"),
            Self::Service => write!(f, "service"),
            Self::Receiver => write!(f, "receiver"),
            Self::Provider => write!(f, "provider"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidComponent {
    pub component_type: AndroidComponentType,
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub intent_filters: Vec<AndroidIntentFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AndroidIntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_hosts: Vec<String>,
}

impl AndroidIntentFilter {
    pub fn is_main_launcher(&self) -> bool {
        self.actions
            .iter()
            .any(|a| a == "android.intent.action.MAIN")
            && self
                .categories
                .iter()
                .any(|c| c == "android.intent.category.LAUNCHER")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidUsesPermission {
    pub name: String,
    pub max_sdk_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AndroidNetworkSecurityConfig {
    pub base_config_cleartext_permitted: Option<bool>,
    pub domain_configs: Vec<AndroidDomainConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidDomainConfig {
    pub domains: Vec<String>,
    pub cleartext_traffic_permitted: Option<bool>,
    pub include_subdomains: bool,
}

// ============================================================================
// iOS Property List & Entitlements IR
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IosPropertyList {
    pub bundle_identifier: Option<String>,
    pub bundle_name: Option<String>,
    pub bundle_version: Option<String>,
    pub bundle_short_version_string: Option<String>,
    pub app_transport_security: Option<IosAppTransportSecurity>,
    pub url_types: Vec<IosUrlType>,
    pub privacy_usage_descriptions: HashMap<String, String>,
    pub raw_keys: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IosAppTransportSecurity {
    pub allows_arbitrary_loads: Option<bool>,
    pub allows_arbitrary_loads_for_media: Option<bool>,
    pub allows_arbitrary_loads_in_web_content: Option<bool>,
    pub allows_local_networking: Option<bool>,
    pub exception_domains: HashMap<String, IosAtsExceptionDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IosAtsExceptionDomain {
    pub includes_subdomains: Option<bool>,
    pub exception_allows_insecure_http_loads: Option<bool>,
    pub temporary_exception_allows_insecure_http_loads: Option<bool>,
    pub exception_minimum_tls_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IosUrlType {
    pub url_name: Option<String>,
    pub schemes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IosEntitlement {
    pub get_task_allow: Option<bool>,
    pub keychain_access_groups: Vec<String>,
    pub associated_domains: Vec<String>,
    pub app_sandbox: Option<bool>,
    pub raw_entitlements: HashMap<String, serde_json::Value>,
}
