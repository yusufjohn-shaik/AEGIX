use cyberguard_core::sarif::{Confidence, SarifLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported CI/CD pipeline and attestation file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineFormat {
    GitHubActions,
    GitLabCi,
    SlsaProvenance,
}

/// Strongly typed identifier for CI/CD and SLSA security rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PipelineRuleId {
    CgPipe001, // Unpinned 3rd-Party Action
    CgPipe002, // Script Injection via Untrusted Context
    CgPipe003, // Excessive GITHUB_TOKEN Permissions
    CgPipe004, // Dangerous pull_request_target Trigger
    CgPipe005, // Plaintext Secret in Workflow
    CgPipe006, // Insecure Self-Hosted Runner
    CgPipe007, // Missing SLSA Provenance Attestation
    CgPipe008, // SLSA Artifact Digest Mismatch
    CgPipe009, // Untrusted SLSA Builder Identity
    CgPipe010, // Tampered Source Repository Materials
}

impl PipelineRuleId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CgPipe001 => "CG-PIPE-001",
            Self::CgPipe002 => "CG-PIPE-002",
            Self::CgPipe003 => "CG-PIPE-003",
            Self::CgPipe004 => "CG-PIPE-004",
            Self::CgPipe005 => "CG-PIPE-005",
            Self::CgPipe006 => "CG-PIPE-006",
            Self::CgPipe007 => "CG-PIPE-007",
            Self::CgPipe008 => "CG-PIPE-008",
            Self::CgPipe009 => "CG-PIPE-009",
            Self::CgPipe010 => "CG-PIPE-010",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::CgPipe001 => "Unpinned 3rd-Party Action",
            Self::CgPipe002 => "Script Injection via Untrusted Context",
            Self::CgPipe003 => "Excessive GITHUB_TOKEN Permissions",
            Self::CgPipe004 => "Dangerous pull_request_target Trigger",
            Self::CgPipe005 => "Plaintext Secret in Workflow",
            Self::CgPipe006 => "Insecure Self-Hosted Runner",
            Self::CgPipe007 => "Missing SLSA Provenance Attestation",
            Self::CgPipe008 => "SLSA Artifact Digest Mismatch",
            Self::CgPipe009 => "Untrusted SLSA Builder Identity",
            Self::CgPipe010 => "Tampered Source Repository Materials",
        }
    }

    pub fn severity(&self) -> SarifLevel {
        match self {
            Self::CgPipe002 | Self::CgPipe004 | Self::CgPipe008 => SarifLevel::Error, // Critical
            Self::CgPipe003 | Self::CgPipe005 | Self::CgPipe006 | Self::CgPipe009 => {
                SarifLevel::Error
            }
            Self::CgPipe001 | Self::CgPipe007 | Self::CgPipe010 => SarifLevel::Warning,
        }
    }

    pub fn confidence(&self) -> Confidence {
        match self {
            Self::CgPipe007 => Confidence::Medium,
            _ => Confidence::High,
        }
    }

    pub fn cwe(&self) -> u32 {
        match self {
            Self::CgPipe001 | Self::CgPipe004 => 829,
            Self::CgPipe002 => 78,
            Self::CgPipe003 => 250,
            Self::CgPipe005 => 798,
            Self::CgPipe006 => 668,
            Self::CgPipe007 => 345,
            Self::CgPipe008 => 353,
            Self::CgPipe009 => 290,
            Self::CgPipe010 => 346,
        }
    }

    pub fn cis_benchmark(&self) -> Option<&'static str> {
        match self {
            Self::CgPipe001 => Some("CIS Supply Chain 3.2"),
            Self::CgPipe003 => Some("CIS Supply Chain 3.1"),
            _ => None,
        }
    }

    pub fn owasp_category(&self) -> Option<&'static str> {
        match self {
            Self::CgPipe002 => Some("OWASP CI/CD-01: Insufficient Flow Control Mechanisms"),
            Self::CgPipe004 => Some("OWASP CI/CD-02: Unguarded Third-Party Services"),
            Self::CgPipe006 => Some("OWASP CI/CD-04: Poisoned Pipeline Execution (PPE)"),
            _ => None,
        }
    }
}

/// Canonical representation of an individual Pipeline security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineFinding {
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

/// Aggregated Pipeline Audit Report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineReport {
    pub target_path: String,
    pub total_documents_scanned: usize,
    pub total_jobs_evaluated: usize,
    pub total_steps_evaluated: usize,
    pub findings: Vec<PipelineFinding>,
    pub suppressed_findings_count: usize,
}

/// Parsed pipeline document IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDocument {
    pub format: PipelineFormat,
    pub file_path: String,
    pub workflow: Option<WorkflowDefinition>,
    pub slsa: Option<SlsaStatement>,
    pub raw_content: String,
}

// ============================================================================
// GitHub Actions & CI Workflow IR
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkflowDefinition {
    pub name: Option<String>,
    #[serde(alias = "true", default)]
    pub on: WorkflowTriggers,
    #[serde(default)]
    pub permissions: Option<WorkflowPermissions>,
    #[serde(default)]
    pub env: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub jobs: HashMap<String, WorkflowJob>,
}

/// Polymorphic representation of workflow triggers (`on:` block).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum WorkflowTriggers {
    #[default]
    None,
    Single(String),
    Multiple(Vec<String>),
    Detailed(HashMap<String, Option<serde_json::Value>>),
}

impl WorkflowTriggers {
    pub fn contains_event(&self, event_name: &str) -> bool {
        match self {
            Self::None => false,
            Self::Single(ev) => ev.eq_ignore_ascii_case(event_name),
            Self::Multiple(list) => list.iter().any(|e| e.eq_ignore_ascii_case(event_name)),
            Self::Detailed(map) => map.keys().any(|k| k.eq_ignore_ascii_case(event_name)),
        }
    }
}

/// Polymorphic representation of GitHub Actions permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkflowPermissions {
    Preset(String), // "read-all", "write-all"
    Scoped(HashMap<String, String>),
}

impl WorkflowPermissions {
    pub fn is_write_all(&self) -> bool {
        match self {
            Self::Preset(p) => p == "write-all",
            Self::Scoped(map) => map.values().any(|v| v == "write" || v == "write-all"),
        }
    }

    pub fn get_scope(&self, scope: &str) -> Option<&str> {
        match self {
            Self::Preset(p) => Some(p.as_str()),
            Self::Scoped(map) => map.get(scope).map(|s| s.as_str()),
        }
    }
}

/// Representation of a single workflow job.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkflowJob {
    pub name: Option<String>,
    #[serde(rename = "runs-on", default)]
    pub runs_on: RunsOn,
    #[serde(default)]
    pub permissions: Option<WorkflowPermissions>,
    #[serde(default)]
    pub environment: Option<serde_json::Value>,
    #[serde(default)]
    pub env: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub steps: Vec<WorkflowStep>,
}

/// Polymorphic runner allocation (`runs-on:`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RunsOn {
    Single(String),
    Multiple(Vec<String>),
}

impl Default for RunsOn {
    fn default() -> Self {
        Self::Single("ubuntu-latest".to_string())
    }
}

impl RunsOn {
    pub fn is_self_hosted(&self) -> bool {
        match self {
            Self::Single(s) => s.to_ascii_lowercase().contains("self-hosted"),
            Self::Multiple(list) => list
                .iter()
                .any(|s| s.to_ascii_lowercase().contains("self-hosted")),
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Self::Single(s) => s.clone(),
            Self::Multiple(list) => list.join(", "),
        }
    }
}

/// Representation of an individual workflow step.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkflowStep {
    pub id: Option<String>,
    pub name: Option<String>,
    pub uses: Option<String>,
    pub run: Option<String>,
    #[serde(default)]
    pub with: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub env: HashMap<String, serde_json::Value>,
    #[serde(rename = "working-directory")]
    pub working_directory: Option<String>,
    pub shell: Option<String>,
}

// ============================================================================
// DSSE (Dead Simple Signing Envelope) & SLSA In-toto Provenance Attestation IR
// ============================================================================

/// DSSE signing envelope wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    #[serde(default)]
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: Option<String>,
    pub sig: String,
}

/// In-toto statement envelope wrapping SLSA v0.2 / v1.0 predicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<SlsaSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SlsaPredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaSubject {
    pub name: String,
    pub digest: HashMap<String, String>,
}

/// Polymorphic SLSA Predicate supporting v0.2 and v1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SlsaPredicate {
    V10(SlsaV10Predicate),
    V02(SlsaV02Predicate),
    Raw(serde_json::Value),
}

impl SlsaPredicate {
    pub fn builder_id(&self) -> Option<&str> {
        match self {
            Self::V10(p) => Some(&p.run_details.builder.id),
            Self::V02(p) => Some(&p.builder.id),
            Self::Raw(v) => v
                .pointer("/runDetails/builder/id")
                .or_else(|| v.pointer("/builder/id"))
                .and_then(|val| val.as_str()),
        }
    }

    pub fn materials(&self) -> Vec<(String, HashMap<String, String>)> {
        match self {
            Self::V10(p) => p
                .build_definition
                .resolved_dependencies
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|d| d.uri.clone().map(|u| (u, d.digest.clone())))
                .collect(),
            Self::V02(p) => p
                .materials
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|m| (m.uri.clone(), m.digest.clone()))
                .collect(),
            Self::Raw(v) => {
                let mut results = Vec::new();
                if let Some(arr) = v.pointer("/materials").and_then(|m| m.as_array()) {
                    for item in arr {
                        if let Some(uri) = item.get("uri").and_then(|u| u.as_str()) {
                            let mut digests = HashMap::new();
                            if let Some(d_map) = item.get("digest").and_then(|d| d.as_object()) {
                                for (k, val) in d_map {
                                    if let Some(s) = val.as_str() {
                                        digests.insert(k.clone(), s.to_string());
                                    }
                                }
                            }
                            results.push((uri.to_string(), digests));
                        }
                    }
                }
                results
            }
        }
    }
}

// SLSA v0.2 Predicate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaV02Predicate {
    pub builder: SlsaV02Builder,
    #[serde(default)]
    pub recipe: Option<SlsaV02Recipe>,
    #[serde(default)]
    pub metadata: Option<SlsaV02Metadata>,
    #[serde(default)]
    pub materials: Option<Vec<SlsaV02Material>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaV02Builder {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlsaV02Recipe {
    #[serde(rename = "type")]
    pub recipe_type: Option<String>,
    #[serde(rename = "definedInMaterial")]
    pub defined_in_material: Option<i64>,
    #[serde(rename = "entryPoint")]
    pub entry_point: Option<String>,
    pub arguments: Option<serde_json::Value>,
    pub environment: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlsaV02Metadata {
    #[serde(rename = "buildInvocationId")]
    pub build_invocation_id: Option<String>,
    pub completeness: Option<serde_json::Value>,
    pub reproducible: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaV02Material {
    pub uri: String,
    #[serde(default)]
    pub digest: HashMap<String, String>,
}

// SLSA v1.0 Predicate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaV10Predicate {
    #[serde(rename = "buildDefinition")]
    pub build_definition: SlsaV10BuildDefinition,
    #[serde(rename = "runDetails")]
    pub run_details: SlsaV10RunDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaV10BuildDefinition {
    #[serde(rename = "buildType")]
    pub build_type: String,
    #[serde(rename = "externalParameters", default)]
    pub external_parameters: Option<serde_json::Value>,
    #[serde(rename = "internalParameters", default)]
    pub internal_parameters: Option<serde_json::Value>,
    #[serde(rename = "resolvedDependencies", default)]
    pub resolved_dependencies: Option<Vec<SlsaResourceDescriptor>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaV10RunDetails {
    pub builder: SlsaV10Builder,
    #[serde(default)]
    pub metadata: Option<SlsaV10Metadata>,
    #[serde(default)]
    pub byproducts: Option<Vec<SlsaResourceDescriptor>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaV10Builder {
    pub id: String,
    pub version: Option<String>,
    #[serde(rename = "builderDependencies", default)]
    pub builder_dependencies: Option<Vec<SlsaResourceDescriptor>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlsaV10Metadata {
    #[serde(rename = "invocationId")]
    pub invocation_id: Option<String>,
    #[serde(rename = "startedOn")]
    pub started_on: Option<String>,
    #[serde(rename = "finishedOn")]
    pub finished_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SlsaResourceDescriptor {
    pub uri: Option<String>,
    #[serde(default)]
    pub digest: HashMap<String, String>,
    pub name: Option<String>,
    #[serde(rename = "downloadLocation")]
    pub download_location: Option<String>,
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
}
