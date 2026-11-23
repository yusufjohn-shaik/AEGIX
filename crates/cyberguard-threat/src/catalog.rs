//! Static Knowledge Base catalog providing deterministic ATT&CK and STRIDE mappings.

#![deny(unsafe_code)]

use crate::models::{MitreTactic, MitreTechnique, StrideCategory};
use crate::traits::{AttackMapper, StrideClassifier};
use std::collections::HashMap;

/// In-memory static catalog of MITRE ATT&CK techniques and STRIDE rules.
#[derive(Debug, Clone)]
pub struct StaticThreatCatalog {
    techniques: Vec<MitreTechnique>,
    technique_lookup: HashMap<String, MitreTechnique>,
}

impl Default for StaticThreatCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl StaticThreatCatalog {
    /// Constructs and initializes the full ATT&CK and STRIDE static catalog.
    pub fn new() -> Self {
        let techniques = vec![
            MitreTechnique {
                id: "T1190".to_string(),
                name: "Exploit Public-Facing Application".to_string(),
                tactics: vec![MitreTactic::InitialAccess],
                description: "Adversaries may attempt to exploit vulnerabilities in Internet-facing software.".to_string(),
                url: "https://attack.mitre.org/techniques/T1190".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1059".to_string(),
                name: "Command and Scripting Interpreter".to_string(),
                tactics: vec![MitreTactic::Execution],
                description: "Adversaries may abuse command and script interpreters to execute commands.".to_string(),
                url: "https://attack.mitre.org/techniques/T1059".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1078".to_string(),
                name: "Valid Accounts".to_string(),
                tactics: vec![
                    MitreTactic::DefenseEvasion,
                    MitreTactic::InitialAccess,
                    MitreTactic::Persistence,
                    MitreTactic::PrivilegeEscalation,
                ],
                description: "Adversaries may obtain and abuse credentials of existing accounts.".to_string(),
                url: "https://attack.mitre.org/techniques/T1078".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1552".to_string(),
                name: "Unsecured Credentials".to_string(),
                tactics: vec![MitreTactic::CredentialAccess],
                description: "Adversaries may search compromised systems for cleartext or hardcoded credentials.".to_string(),
                url: "https://attack.mitre.org/techniques/T1552".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1068".to_string(),
                name: "Exploitation for Privilege Escalation".to_string(),
                tactics: vec![MitreTactic::PrivilegeEscalation],
                description: "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.".to_string(),
                url: "https://attack.mitre.org/techniques/T1068".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1611".to_string(),
                name: "Escape to Host".to_string(),
                tactics: vec![MitreTactic::PrivilegeEscalation],
                description: "Adversaries may break out of containerized environments to gain access to the underlying host.".to_string(),
                url: "https://attack.mitre.org/techniques/T1611".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1046".to_string(),
                name: "Network Service Discovery".to_string(),
                tactics: vec![MitreTactic::Discovery],
                description: "Adversaries may attempt to get a listing of services running on hosts or network ports.".to_string(),
                url: "https://attack.mitre.org/techniques/T1046".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1562".to_string(),
                name: "Impair Defenses".to_string(),
                tactics: vec![MitreTactic::DefenseEvasion],
                description: "Adversaries may disable security software, logging, or configurations to evade detection.".to_string(),
                url: "https://attack.mitre.org/techniques/T1562".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1530".to_string(),
                name: "Data from Cloud Storage".to_string(),
                tactics: vec![MitreTactic::Collection],
                description: "Adversaries may access data stored in cloud storage buckets, blobs, or drives.".to_string(),
                url: "https://attack.mitre.org/techniques/T1530".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1499".to_string(),
                name: "Endpoint Denial of Service".to_string(),
                tactics: vec![MitreTactic::Impact],
                description: "Adversaries may perform endpoint DoS attacks that degrade or shut down application availability.".to_string(),
                url: "https://attack.mitre.org/techniques/T1499".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1020".to_string(),
                name: "Automated Exfiltration".to_string(),
                tactics: vec![MitreTactic::Exfiltration],
                description: "Adversaries may exfiltrate data through automated processing or egress connections.".to_string(),
                url: "https://attack.mitre.org/techniques/T1020".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1071".to_string(),
                name: "Application Layer Protocol".to_string(),
                tactics: vec![MitreTactic::CommandAndControl],
                description: "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to blend in.".to_string(),
                url: "https://attack.mitre.org/techniques/T1071".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1595".to_string(),
                name: "Active Scanning".to_string(),
                tactics: vec![MitreTactic::Reconnaissance],
                description: "Adversaries may execute active scans to gather information on IP ranges, ports, and vulnerabilities.".to_string(),
                url: "https://attack.mitre.org/techniques/T1595".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1583".to_string(),
                name: "Acquire Infrastructure".to_string(),
                tactics: vec![MitreTactic::ResourceDevelopment],
                description: "Adversaries may acquire domains, servers, or cloud registries to support targeted operations.".to_string(),
                url: "https://attack.mitre.org/techniques/T1583".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1195".to_string(),
                name: "Supply Chain Compromise".to_string(),
                tactics: vec![MitreTactic::InitialAccess],
                description: "Adversaries may manipulate products or delivery mechanisms prior to receipt by end consumers.".to_string(),
                url: "https://attack.mitre.org/techniques/T1195".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1407".to_string(),
                name: "Download New Code at Runtime".to_string(),
                tactics: vec![MitreTactic::Execution],
                description: "Adversaries may download and execute dynamic code at runtime to bypass store verification.".to_string(),
                url: "https://attack.mitre.org/techniques/T1407".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1409".to_string(),
                name: "Access Stored Application Data".to_string(),
                tactics: vec![MitreTactic::Collection],
                description: "Adversaries may harvest sensitive application data from unencrypted local storage or backups.".to_string(),
                url: "https://attack.mitre.org/techniques/T1409".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1526".to_string(),
                name: "Cloud Service Discovery".to_string(),
                tactics: vec![MitreTactic::Discovery],
                description: "Adversaries may enumerate cloud infrastructure, IAM permissions, and running instances.".to_string(),
                url: "https://attack.mitre.org/techniques/T1526".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1546".to_string(),
                name: "Event Triggered Execution".to_string(),
                tactics: vec![MitreTactic::Persistence, MitreTactic::PrivilegeEscalation],
                description: "Adversaries may establish persistence using system event handlers or webhooks.".to_string(),
                url: "https://attack.mitre.org/techniques/T1546".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
            MitreTechnique {
                id: "T1574".to_string(),
                name: "Hijack Execution Flow".to_string(),
                tactics: vec![
                    MitreTactic::Persistence,
                    MitreTactic::PrivilegeEscalation,
                    MitreTactic::DefenseEvasion,
                ],
                description: "Adversaries may hijack the execution flow by altering search paths or injected libraries.".to_string(),
                url: "https://attack.mitre.org/techniques/T1574".to_string(),
                is_subtechnique: false,
                parent_technique_id: None,
            },
        ];

        let mut lookup = HashMap::new();
        for t in &techniques {
            lookup.insert(t.id.clone(), t.clone());
        }

        Self {
            techniques,
            technique_lookup: lookup,
        }
    }
}

impl AttackMapper for StaticThreatCatalog {
    fn map_finding_to_techniques(
        &self,
        rule_id: &str,
        cwes: &[u32],
    ) -> (Vec<MitreTactic>, Vec<String>) {
        let mut tactics = Vec::new();
        let mut techniques = Vec::new();

        // 1. Direct rule prefix correlation
        if rule_id.starts_with("CG-SEC")
            || rule_id.starts_with("CG-SECRET")
            || rule_id == "CG-MOB-010"
        {
            tactics.push(MitreTactic::CredentialAccess);
            techniques.push("T1552".to_string());
        }
        if rule_id.starts_with("CG-NET") {
            tactics.push(MitreTactic::Reconnaissance);
            tactics.push(MitreTactic::Discovery);
            techniques.push("T1595".to_string());
            techniques.push("T1046".to_string());
        }
        if rule_id.starts_with("CG-CONT") {
            tactics.push(MitreTactic::PrivilegeEscalation);
            techniques.push("T1611".to_string());
            techniques.push("T1068".to_string());
        }
        if rule_id.starts_with("CG-CLOUD") {
            tactics.push(MitreTactic::DefenseEvasion);
            tactics.push(MitreTactic::Collection);
            tactics.push(MitreTactic::Discovery);
            techniques.push("T1562".to_string());
            techniques.push("T1530".to_string());
            techniques.push("T1526".to_string());
        }
        if rule_id.starts_with("CG-API") || rule_id.starts_with("CG-DAST") {
            tactics.push(MitreTactic::InitialAccess);
            techniques.push("T1190".to_string());
            if rule_id.contains("RATE") || rule_id.contains("DOS") || rule_id == "CG-API-003" {
                tactics.push(MitreTactic::Impact);
                techniques.push("T1499".to_string());
            }
        }
        if rule_id.starts_with("CG-PIPE") {
            tactics.push(MitreTactic::Execution);
            tactics.push(MitreTactic::CommandAndControl);
            techniques.push("T1059".to_string());
            techniques.push("T1071".to_string());
            if rule_id.contains("TRIGGER") || rule_id.contains("EVENT") {
                tactics.push(MitreTactic::Persistence);
                techniques.push("T1546".to_string());
            }
        }
        if rule_id.starts_with("CG-SCA") {
            tactics.push(MitreTactic::InitialAccess);
            techniques.push("T1195".to_string());
        }
        if rule_id.starts_with("CG-SAST") {
            if rule_id.contains("SQL") || rule_id.contains("INJ") || rule_id.contains("XSS") {
                tactics.push(MitreTactic::InitialAccess);
                techniques.push("T1190".to_string());
            }
            if rule_id.contains("CMD") || rule_id.contains("EXEC") {
                tactics.push(MitreTactic::Execution);
                techniques.push("T1059".to_string());
            }
        }
        if rule_id.starts_with("CG-MOB") {
            if rule_id == "CG-MOB-001" || rule_id == "CG-MOB-002" {
                tactics.push(MitreTactic::Execution);
                techniques.push("T1407".to_string());
            } else if rule_id == "CG-MOB-003" || rule_id == "CG-MOB-004" {
                tactics.push(MitreTactic::Collection);
                techniques.push("T1409".to_string());
            }
        }

        // 2. CWE mapping fallback and enrichment
        for &cwe in cwes {
            match cwe {
                798 | 522 | 312 => {
                    tactics.push(MitreTactic::CredentialAccess);
                    techniques.push("T1552".to_string());
                }
                89 | 79 | 434 | 926 => {
                    tactics.push(MitreTactic::InitialAccess);
                    techniques.push("T1190".to_string());
                }
                78 | 94 => {
                    tactics.push(MitreTactic::Execution);
                    techniques.push("T1059".to_string());
                }
                250 | 269 => {
                    tactics.push(MitreTactic::PrivilegeEscalation);
                    techniques.push("T1068".to_string());
                }
                287 | 306 => {
                    tactics.push(MitreTactic::InitialAccess);
                    techniques.push("T1078".to_string());
                }
                400 | 770 | 1333 => {
                    tactics.push(MitreTactic::Impact);
                    techniques.push("T1499".to_string());
                }
                778 => {
                    tactics.push(MitreTactic::DefenseEvasion);
                    techniques.push("T1562".to_string());
                }
                200 => {
                    tactics.push(MitreTactic::Collection);
                    techniques.push("T1530".to_string());
                }
                1388 | 1395 => {
                    tactics.push(MitreTactic::InitialAccess);
                    techniques.push("T1195".to_string());
                }
                _ => {}
            }
        }

        // Default fallback if no technique matched
        if techniques.is_empty() {
            tactics.push(MitreTactic::InitialAccess);
            techniques.push("T1190".to_string());
        }

        // Deduplicate tactics and techniques
        tactics.sort();
        tactics.dedup();
        techniques.sort();
        techniques.dedup();

        (tactics, techniques)
    }

    fn get_technique_details(&self, technique_id: &str) -> Option<MitreTechnique> {
        self.technique_lookup.get(technique_id).cloned()
    }

    fn all_techniques(&self) -> &[MitreTechnique] {
        &self.techniques
    }

    fn techniques_for_tactic(&self, tactic: MitreTactic) -> Vec<&MitreTechnique> {
        self.techniques
            .iter()
            .filter(|t| t.tactics.contains(&tactic))
            .collect()
    }
}

impl StrideClassifier for StaticThreatCatalog {
    fn classify_finding(&self, rule_id: &str, cwes: &[u32]) -> Vec<StrideCategory> {
        let mut categories = Vec::new();

        // 1. Rule ID Heuristics
        if rule_id.contains("AUTH") || rule_id == "CG-MOB-007" {
            categories.push(StrideCategory::Spoofing);
        }
        if rule_id.contains("INJ")
            || rule_id.contains("INTEGRITY")
            || rule_id.starts_with("CG-PIPE")
            || rule_id.starts_with("CG-SAST-SQL")
        {
            categories.push(StrideCategory::Tampering);
        }
        if rule_id.contains("LOG") || rule_id.contains("AUDIT") {
            categories.push(StrideCategory::Repudiation);
        }
        if rule_id.contains("SEC")
            || rule_id.contains("SECRET")
            || rule_id.contains("LEAK")
            || rule_id == "CG-MOB-003"
            || rule_id == "CG-MOB-010"
        {
            categories.push(StrideCategory::InformationDisclosure);
        }
        if rule_id.contains("DOS")
            || rule_id.contains("LIMIT")
            || rule_id.contains("RATE")
            || rule_id.contains("TIMEOUT")
            || rule_id == "CG-API-003"
        {
            categories.push(StrideCategory::DenialOfService);
        }
        if rule_id.contains("PRIV")
            || rule_id.contains("PERM")
            || rule_id.starts_with("CG-CONT")
            || rule_id == "CG-MOB-004"
            || rule_id == "CG-MOB-009"
        {
            categories.push(StrideCategory::ElevationOfPrivilege);
        }

        // 2. CWE Classification
        for &cwe in cwes {
            match cwe {
                287 | 306 | 939 => categories.push(StrideCategory::Spoofing),
                89 | 78 | 79 | 94 | 353 => categories.push(StrideCategory::Tampering),
                778 | 223 => categories.push(StrideCategory::Repudiation),
                200 | 312 | 319 | 522 | 798 => {
                    categories.push(StrideCategory::InformationDisclosure);
                }
                400 | 770 | 1333 => categories.push(StrideCategory::DenialOfService),
                250 | 269 | 926 => categories.push(StrideCategory::ElevationOfPrivilege),
                _ => {}
            }
        }

        // Default fallback if no category matched
        if categories.is_empty() {
            categories.push(StrideCategory::InformationDisclosure);
        }

        categories.sort();
        categories.dedup();
        categories
    }

    fn classify_by_violation(&self, property: &str) -> Option<StrideCategory> {
        match property.to_lowercase().as_str() {
            "authentication" => Some(StrideCategory::Spoofing),
            "integrity" => Some(StrideCategory::Tampering),
            "non-repudiation" | "nonrepudiation" => Some(StrideCategory::Repudiation),
            "confidentiality" => Some(StrideCategory::InformationDisclosure),
            "availability" => Some(StrideCategory::DenialOfService),
            "authorization" => Some(StrideCategory::ElevationOfPrivilege),
            _ => None,
        }
    }

    fn get_stride_guidance(&self, category: StrideCategory) -> &'static str {
        match category {
            StrideCategory::Spoofing => {
                "Implement robust mutual TLS, cryptographic signatures, or strong MFA authentication."
            }
            StrideCategory::Tampering => {
                "Validate input data, sign container images/artifacts, and employ immutable build steps."
            }
            StrideCategory::Repudiation => {
                "Enable centralized, tamper-evident audit logging with external timestamping."
            }
            StrideCategory::InformationDisclosure => {
                "Enforce end-to-end encryption, secret masking, and strict egress firewalls."
            }
            StrideCategory::DenialOfService => {
                "Enforce rate limiting, bounded streaming buffers, and algorithmic timeouts."
            }
            StrideCategory::ElevationOfPrivilege => {
                "Apply principle of least privilege, non-root users, and drop Linux capabilities."
            }
        }
    }
}

/// Helper function to interpolate a 4-stop hex color gradient for ATT&CK Navigator Layer.
/// Stops: 0.0 -> #ffffff, 3.33 -> #ffe082, 6.66 -> #ff8a65, 10.0 -> #e53935
pub fn score_to_gradient_color(score: f64, min_val: f64, max_val: f64) -> String {
    let clamped = score.clamp(min_val, max_val);
    let range = (max_val - min_val).max(0.001);
    let ratio = (clamped - min_val) / range; // 0.0 to 1.0

    // Gradient stops: (ratio, [R, G, B])
    let stops: &[(f64, [u8; 3])] = &[
        (0.00, [0xff, 0xff, 0xff]), // #ffffff
        (0.33, [0xff, 0xe0, 0x82]), // #ffe082
        (0.66, [0xff, 0x8a, 0x65]), // #ff8a65
        (1.00, [0xe5, 0x39, 0x35]), // #e53935
    ];

    if ratio <= stops[0].0 {
        return format!(
            "#{:02x}{:02x}{:02x}",
            stops[0].1[0], stops[0].1[1], stops[0].1[2]
        );
    }
    if ratio >= stops[3].0 {
        return format!(
            "#{:02x}{:02x}{:02x}",
            stops[3].1[0], stops[3].1[1], stops[3].1[2]
        );
    }

    for i in 0..stops.len() - 1 {
        let (r1, c1) = stops[i];
        let (r2, c2) = stops[i + 1];
        if ratio >= r1 && ratio <= r2 {
            let seg_ratio = (ratio - r1) / (r2 - r1);
            let r = (c1[0] as f64 + seg_ratio * (c2[0] as f64 - c1[0] as f64)).round() as u8;
            let g = (c1[1] as f64 + seg_ratio * (c2[1] as f64 - c1[1] as f64)).round() as u8;
            let b = (c1[2] as f64 + seg_ratio * (c2[2] as f64 - c1[2] as f64)).round() as u8;
            return format!("#{:02x}{:02x}{:02x}", r, g, b);
        }
    }

    "#e53935".to_string()
}
