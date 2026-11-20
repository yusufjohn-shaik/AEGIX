use cyberguard_core::sarif::{Confidence, SarifLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported Infrastructure as Code file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IacFormat {
    KubernetesYaml,
    KubernetesJson,
    TerraformHcl,
    TerraformJson,
    TerraformPlanJson,
}

/// Strongly typed identifier for IaC security rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IacRuleId {
    CgIac001, // Privileged Container Allowed
    CgIac002, // Container Allowed to Run as Root
    CgIac003, // Host Namespace Sharing (PID/IPC/Net)
    CgIac004, // Dangerous Linux Capabilities Added
    CgIac005, // Missing CPU / Memory Limits
    CgIac006, // Root Filesystem is Writable
    CgIac007, // Unrestricted Ingress Security Group
    CgIac008, // Unencrypted Cloud Storage Bucket
    CgIac009, // Plaintext Sensitive Secret in IaC
    CgIac010, // Missing Audit / Access Logging
}

impl IacRuleId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CgIac001 => "CG-IAC-001",
            Self::CgIac002 => "CG-IAC-002",
            Self::CgIac003 => "CG-IAC-003",
            Self::CgIac004 => "CG-IAC-004",
            Self::CgIac005 => "CG-IAC-005",
            Self::CgIac006 => "CG-IAC-006",
            Self::CgIac007 => "CG-IAC-007",
            Self::CgIac008 => "CG-IAC-008",
            Self::CgIac009 => "CG-IAC-009",
            Self::CgIac010 => "CG-IAC-010",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::CgIac001 => "Privileged Container Allowed",
            Self::CgIac002 => "Container Allowed to Run as Root",
            Self::CgIac003 => "Host Namespace Sharing (PID/IPC/Net)",
            Self::CgIac004 => "Dangerous Linux Capabilities Added",
            Self::CgIac005 => "Missing CPU / Memory Limits",
            Self::CgIac006 => "Root Filesystem is Writable",
            Self::CgIac007 => "Unrestricted Ingress Security Group",
            Self::CgIac008 => "Unencrypted Cloud Storage Bucket",
            Self::CgIac009 => "Plaintext Sensitive Secret in IaC",
            Self::CgIac010 => "Missing Audit / Access Logging",
        }
    }

    pub fn severity(&self) -> SarifLevel {
        match self {
            Self::CgIac001 | Self::CgIac003 => SarifLevel::Error, // Critical mapped to Error in SARIF
            Self::CgIac002 | Self::CgIac004 | Self::CgIac007 | Self::CgIac009 => SarifLevel::Error,
            Self::CgIac005 | Self::CgIac006 | Self::CgIac008 | Self::CgIac010 => {
                SarifLevel::Warning
            }
        }
    }

    pub fn confidence(&self) -> Confidence {
        match self {
            Self::CgIac010 => Confidence::Medium,
            _ => Confidence::High,
        }
    }

    pub fn cwe(&self) -> u32 {
        match self {
            Self::CgIac001 | Self::CgIac002 | Self::CgIac003 | Self::CgIac004 => 250,
            Self::CgIac005 => 770,
            Self::CgIac006 => 732,
            Self::CgIac007 => 284,
            Self::CgIac008 => 311,
            Self::CgIac009 => 798,
            Self::CgIac010 => 778,
        }
    }
}

/// Canonical representation of an individual IaC security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacFinding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: SarifLevel,
    pub confidence: Confidence,
    pub cwe: u32,
    pub file_path: String,
    pub resource_id: String,
    pub resource_type: String,
    pub line: usize,
    pub column: usize,
    pub configuration_path: String,
    pub remediation: String,
    pub fingerprint: String,
}

/// Final aggregated IaC Audit Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacReport {
    pub target_path: String,
    pub total_documents_scanned: usize,
    pub total_resources_evaluated: usize,
    pub findings: Vec<IacFinding>,
    pub suppressed_findings_count: usize,
}

/// Representation of a parsed single document within an IaC file stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacDocument {
    pub document_index: usize,
    pub format: IacFormat,
    pub file_path: String,
    pub resources: Vec<IacResource>,
    pub raw_content: String,
}

/// Canonical polymorphic IaC Resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum IacResource {
    Kubernetes(Box<K8sManifest>),
    Terraform(Box<TerraformResource>),
    TerraformVariable(TerraformVariable),
    TerraformLocal(TerraformLocal),
}

// ============================================================================
// Kubernetes Models & Deserializers
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sManifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    #[serde(default)]
    pub spec: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sObjectMeta {
    pub name: Option<String>,
    pub namespace: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

impl K8sManifest {
    /// Extracts canonical `K8sPodSpec` from Pods, Workload Controllers, and CronJobs.
    pub fn extract_pod_spec(&self) -> Option<K8sPodSpec> {
        let spec_val = self.spec.as_ref()?;

        match self.kind.as_str() {
            "Pod" => serde_json::from_value(spec_val.clone()).ok(),
            "Deployment"
            | "DaemonSet"
            | "StatefulSet"
            | "ReplicaSet"
            | "Job"
            | "ReplicationController" => spec_val
                .get("template")?
                .get("spec")
                .and_then(|s| serde_json::from_value(s.clone()).ok()),
            "CronJob" => spec_val
                .get("jobTemplate")?
                .get("spec")?
                .get("template")?
                .get("spec")
                .and_then(|s| serde_json::from_value(s.clone()).ok()),
            _ => None,
        }
    }

    /// Evaluates if workload belongs to recognized system infrastructure.
    pub fn is_system_workload(&self) -> bool {
        let ns = self.metadata.namespace.as_deref().unwrap_or("default");
        if ns == "kube-system" || ns == "kube-node-lease" {
            return true;
        }

        if let Some(name) = self.metadata.name.as_deref() {
            let lower = name.to_ascii_lowercase();
            if lower.contains("cilium")
                || lower.contains("calico")
                || lower.contains("kube-proxy")
                || lower.contains("aws-node")
                || lower.contains("flannel")
                || lower.contains("csi-")
            {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sPodSpec {
    #[serde(rename = "hostPID")]
    pub host_pid: Option<bool>,
    #[serde(rename = "hostIPC")]
    pub host_ipc: Option<bool>,
    #[serde(rename = "hostNetwork")]
    pub host_network: Option<bool>,
    #[serde(rename = "securityContext")]
    pub security_context: Option<K8sPodSecurityContext>,
    #[serde(default)]
    pub containers: Vec<K8sContainer>,
    #[serde(rename = "initContainers", default)]
    pub init_containers: Option<Vec<K8sContainer>>,
    #[serde(rename = "ephemeralContainers", default)]
    pub ephemeral_containers: Option<Vec<K8sContainer>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sPodSecurityContext {
    #[serde(rename = "runAsUser")]
    pub run_as_user: Option<i64>,
    #[serde(rename = "runAsGroup")]
    pub run_as_group: Option<i64>,
    #[serde(rename = "runAsNonRoot")]
    pub run_as_non_root: Option<bool>,
    #[serde(rename = "fsGroup")]
    pub fs_group: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sContainer {
    pub name: String,
    pub image: Option<String>,
    #[serde(rename = "securityContext")]
    pub security_context: Option<K8sContainerSecurityContext>,
    pub resources: Option<K8sResourceRequirements>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sContainerSecurityContext {
    pub privileged: Option<bool>,
    #[serde(rename = "runAsUser")]
    pub run_as_user: Option<i64>,
    #[serde(rename = "runAsGroup")]
    pub run_as_group: Option<i64>,
    #[serde(rename = "runAsNonRoot")]
    pub run_as_non_root: Option<bool>,
    #[serde(rename = "readOnlyRootFilesystem")]
    pub read_only_root_filesystem: Option<bool>,
    #[serde(rename = "allowPrivilegeEscalation")]
    pub allow_privilege_escalation: Option<bool>,
    pub capabilities: Option<K8sCapabilities>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sCapabilities {
    #[serde(default)]
    pub add: Option<Vec<String>>,
    #[serde(default)]
    pub drop: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sResourceRequirements {
    pub limits: Option<HashMap<String, serde_json::Value>>,
    pub requests: Option<HashMap<String, serde_json::Value>>,
}

// ============================================================================
// Terraform Models & Deserializers
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformResource {
    pub resource_type: String,
    pub resource_name: String,
    pub properties: HashMap<String, serde_json::Value>,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformVariable {
    pub name: String,
    pub default_value: Option<serde_json::Value>,
    pub description: Option<String>,
    pub sensitive: Option<bool>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformLocal {
    pub name: String,
    pub value: serde_json::Value,
    pub line: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TerraformSecurityGroupRule {
    pub from_port: Option<i32>,
    pub to_port: Option<i32>,
    pub protocol: Option<String>,
    #[serde(default)]
    pub cidr_blocks: Vec<String>,
    #[serde(default)]
    pub ipv6_cidr_blocks: Vec<String>,
    pub description: Option<String>,
}
