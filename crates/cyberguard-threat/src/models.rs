//! Canonical data models for MITRE ATT&CK, STRIDE, and Navigator Layer v4.5 export.

#![deny(unsafe_code)]

use cyberguard_core::sarif::{Confidence, SarifLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported MITRE ATT&CK Matrix Domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MitreMatrixDomain {
    EnterpriseAttack,
    CloudAttack,
    MobileAttack,
    ContainerAttack,
}

impl MitreMatrixDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EnterpriseAttack => "enterprise-attack",
            Self::CloudAttack => "cloud-attack",
            Self::MobileAttack => "mobile-attack",
            Self::ContainerAttack => "container-attack",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().replace('_', "-").as_str() {
            "enterprise" | "enterprise-attack" => Some(Self::EnterpriseAttack),
            "cloud" | "cloud-attack" => Some(Self::CloudAttack),
            "mobile" | "mobile-attack" => Some(Self::MobileAttack),
            "container" | "containers" | "container-attack" => Some(Self::ContainerAttack),
            _ => None,
        }
    }
}

/// The 14 MITRE ATT&CK Enterprise Tactics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    /// Canonical ATT&CK Tactic Identifier (e.g. TA0001).
    pub fn id(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }

    /// Kebab-case slug used by MITRE ATT&CK Navigator Layer.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "reconnaissance",
            Self::ResourceDevelopment => "resource-development",
            Self::InitialAccess => "initial-access",
            Self::Execution => "execution",
            Self::Persistence => "persistence",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::DefenseEvasion => "defense-evasion",
            Self::CredentialAccess => "credential-access",
            Self::Discovery => "discovery",
            Self::LateralMovement => "lateral-movement",
            Self::Collection => "collection",
            Self::CommandAndControl => "command-and-control",
            Self::Exfiltration => "exfiltration",
            Self::Impact => "impact",
        }
    }

    /// Human-readable title.
    pub fn title(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::ResourceDevelopment => "Resource Development",
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command & Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }

    /// Resolve tactic from Tactic ID (e.g. TA0001) or slug (e.g. initial-access).
    pub fn from_id_or_slug(s: &str) -> Option<Self> {
        let normalized = s.trim().to_uppercase();
        match normalized.as_str() {
            "TA0043" => return Some(Self::Reconnaissance),
            "TA0042" => return Some(Self::ResourceDevelopment),
            "TA0001" => return Some(Self::InitialAccess),
            "TA0002" => return Some(Self::Execution),
            "TA0003" => return Some(Self::Persistence),
            "TA0004" => return Some(Self::PrivilegeEscalation),
            "TA0005" => return Some(Self::DefenseEvasion),
            "TA0006" => return Some(Self::CredentialAccess),
            "TA0007" => return Some(Self::Discovery),
            "TA0008" => return Some(Self::LateralMovement),
            "TA0009" => return Some(Self::Collection),
            "TA0011" => return Some(Self::CommandAndControl),
            "TA0010" => return Some(Self::Exfiltration),
            "TA0040" => return Some(Self::Impact),
            _ => {}
        }

        match s.trim().to_lowercase().replace(' ', "-").as_str() {
            "reconnaissance" => Some(Self::Reconnaissance),
            "resource-development" => Some(Self::ResourceDevelopment),
            "initial-access" => Some(Self::InitialAccess),
            "execution" => Some(Self::Execution),
            "persistence" => Some(Self::Persistence),
            "privilege-escalation" => Some(Self::PrivilegeEscalation),
            "defense-evasion" => Some(Self::DefenseEvasion),
            "credential-access" => Some(Self::CredentialAccess),
            "discovery" => Some(Self::Discovery),
            "lateral-movement" => Some(Self::LateralMovement),
            "collection" => Some(Self::Collection),
            "command-and-control" | "command-control" => Some(Self::CommandAndControl),
            "exfiltration" => Some(Self::Exfiltration),
            "impact" => Some(Self::Impact),
            _ => None,
        }
    }

    /// Returns a slice containing all 14 tactics.
    pub fn all() -> &'static [MitreTactic] {
        &[
            Self::Reconnaissance,
            Self::ResourceDevelopment,
            Self::InitialAccess,
            Self::Execution,
            Self::Persistence,
            Self::PrivilegeEscalation,
            Self::DefenseEvasion,
            Self::CredentialAccess,
            Self::Discovery,
            Self::LateralMovement,
            Self::Collection,
            Self::CommandAndControl,
            Self::Exfiltration,
            Self::Impact,
        ]
    }
}

/// Metadata representation for a MITRE ATT&CK Technique or Sub-technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactics: Vec<MitreTactic>,
    pub description: String,
    pub url: String,
    pub is_subtechnique: bool,
    pub parent_technique_id: Option<String>,
}

/// STRIDE Threat Classification Categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrideCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

impl StrideCategory {
    pub fn letter(&self) -> char {
        match self {
            Self::Spoofing => 'S',
            Self::Tampering => 'T',
            Self::Repudiation => 'R',
            Self::InformationDisclosure => 'I',
            Self::DenialOfService => 'D',
            Self::ElevationOfPrivilege => 'E',
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::Spoofing => "Spoofing",
            Self::Tampering => "Tampering",
            Self::Repudiation => "Repudiation",
            Self::InformationDisclosure => "Information Disclosure",
            Self::DenialOfService => "Denial of Service",
            Self::ElevationOfPrivilege => "Elevation of Privilege",
        }
    }

    pub fn security_property(&self) -> &'static str {
        match self {
            Self::Spoofing => "Authentication",
            Self::Tampering => "Integrity",
            Self::Repudiation => "Non-repudiation",
            Self::InformationDisclosure => "Confidentiality",
            Self::DenialOfService => "Availability",
            Self::ElevationOfPrivilege => "Authorization",
        }
    }

    pub fn from_letter(c: char) -> Option<Self> {
        match c.to_ascii_uppercase() {
            'S' => Some(Self::Spoofing),
            'T' => Some(Self::Tampering),
            'R' => Some(Self::Repudiation),
            'I' => Some(Self::InformationDisclosure),
            'D' => Some(Self::DenialOfService),
            'E' => Some(Self::ElevationOfPrivilege),
            _ => None,
        }
    }

    pub fn all() -> &'static [StrideCategory] {
        &[
            Self::Spoofing,
            Self::Tampering,
            Self::Repudiation,
            Self::InformationDisclosure,
            Self::DenialOfService,
            Self::ElevationOfPrivilege,
        ]
    }
}

/// Unified Threat Model Finding, correlating technical telemetry to TTPs and STRIDE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub id: String,
    pub source_rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: SarifLevel,
    pub confidence: Confidence,
    pub tactics: Vec<MitreTactic>,
    pub techniques: Vec<String>,
    pub stride_categories: Vec<StrideCategory>,
    pub cwe_ids: Vec<u32>,
    pub file_path: Option<String>,
    pub line: Option<usize>,
    pub cvss_score: Option<f64>,
    pub tri_factor_score: Option<f64>,
    pub remediation: String,
    pub fingerprint: String,
}

// ============================================================================
// MITRE ATT&CK Navigator Layer v4.5 / v5.0 Specification Models
// ============================================================================

/// Root JSON structure of a MITRE ATT&CK Navigator Layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackNavigatorLayer {
    pub name: String,
    pub versions: NavigatorVersions,
    pub domain: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<NavigatorFilters>,
    pub gradient: NavigatorGradient,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<NavigatorLayout>,
    pub techniques: Vec<NavigatorTechniqueEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatorVersions {
    pub attack: String,
    pub navigator: String,
    pub layer: String,
}

impl Default for NavigatorVersions {
    fn default() -> Self {
        Self {
            attack: "14".to_string(),
            navigator: "4.5".to_string(),
            layer: "4.5".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatorFilters {
    pub platforms: Vec<String>,
}

impl Default for NavigatorFilters {
    fn default() -> Self {
        Self {
            platforms: vec![
                "Linux".to_string(),
                "Windows".to_string(),
                "macOS".to_string(),
                "Containers".to_string(),
                "AWS".to_string(),
                "GCP".to_string(),
                "Azure".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatorLayout {
    pub layout: String,
    pub show_id: bool,
    pub show_name: bool,
    pub show_subtechniques: bool,
}

impl Default for NavigatorLayout {
    fn default() -> Self {
        Self {
            layout: "side".to_string(),
            show_id: false,
            show_name: true,
            show_subtechniques: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatorGradient {
    pub colors: Vec<String>,
    pub min_value: f64,
    pub max_value: f64,
}

impl Default for NavigatorGradient {
    fn default() -> Self {
        Self {
            colors: vec![
                "#ffffff".to_string(),
                "#ffe082".to_string(),
                "#ff8a65".to_string(),
                "#e53935".to_string(),
            ],
            min_value: 0.0,
            max_value: 10.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatorTechniqueEntry {
    #[serde(rename = "techniqueID")]
    pub technique_id: String,
    pub tactic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata: Vec<NavigatorMetadataEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatorMetadataEntry {
    pub name: String,
    pub value: String,
}

/// Aggregated Threat Modeling and ATT&CK Matrix Report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatReport {
    pub domain: MitreMatrixDomain,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub total_findings: usize,
    pub findings: Vec<ThreatFinding>,
    pub stride_counts: HashMap<StrideCategory, usize>,
    pub tactic_counts: HashMap<MitreTactic, usize>,
    pub technique_counts: HashMap<String, usize>,
    pub navigator_layer: AttackNavigatorLayer,
    pub suppressed_count: usize,
}
