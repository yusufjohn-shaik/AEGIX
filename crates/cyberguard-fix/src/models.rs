use cyberguard_core::sarif::{ArtifactChange, ArtifactLocation, Fix, Message, Region, Replacement};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLanguage {
    Python,
    JavaScript,
    TypeScript,
    Go,
    Rust,
}

impl SourceLanguage {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_ascii_lowercase().as_str() {
            "py" => Some(Self::Python),
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "ts" | "tsx" | "mts" | "cts" => Some(Self::TypeScript),
            "go" => Some(Self::Go),
            "rs" => Some(Self::Rust),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Python => "Python",
            Self::JavaScript => "JavaScript",
            Self::TypeScript => "TypeScript",
            Self::Go => "Go",
            Self::Rust => "Rust",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstImport {
    pub module: String,
    pub alias: Option<String>,
    pub items: Vec<String>,
    pub line: usize,
    pub is_esm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstCallSite {
    pub callee: String,
    pub raw_args: Vec<String>,
    pub line: usize,
    pub indent: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstAssignment {
    pub variable: String,
    pub expression: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstFunction {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub parameters: Vec<String>,
    pub calls: Vec<AstCallSite>,
    pub assignments: Vec<AstAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSourceFile {
    pub file_path: PathBuf,
    pub language: SourceLanguage,
    pub lines: Vec<String>,
    pub imports: Vec<AstImport>,
    pub functions: Vec<AstFunction>,
    pub global_calls: Vec<AstCallSite>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSourceKind {
    HttpQueryParam,
    HttpRequestBody,
    HttpHeader,
    CliArgument,
    EnvironmentVariable,
    FileReadInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintSinkKind {
    SqlExecution,
    CommandExecution,
    PathTraversal,
    HardcodedSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanitizerKind {
    ParameterizedQuery,
    ShellQuoteOrArgArray,
    PathContainmentGuard,
    EnvironmentLookup,
    TypeCastIntegerOrBool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFlowPath {
    pub source_kind: TaintSourceKind,
    pub source_identifier: String,
    pub source_line: usize,
    pub propagators: Vec<String>,
    pub sink_kind: TaintSinkKind,
    pub sink_call: String,
    pub sink_line: usize,
    pub is_sanitized: bool,
    pub sanitizer_kind: Option<SanitizerKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchCategory {
    SqlParameterization,
    CommandArgvArray,
    PathContainmentGuard,
    EnvVarSecretExtraction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurgicalPatch {
    pub id: String,
    pub rule_id: String,
    pub category: PatchCategory,
    pub file_path: PathBuf,
    pub target_line_start: usize,
    pub target_line_end: usize,
    pub original_content: String,
    pub replacement_content: String,
    pub required_imports: Vec<String>,
    pub explanation: String,
    pub confidence: f64,
}

impl From<&SurgicalPatch> for Fix {
    fn from(patch: &SurgicalPatch) -> Self {
        Fix {
            description: Message {
                text: patch.explanation.clone(),
            },
            artifact_changes: vec![ArtifactChange {
                artifact_location: ArtifactLocation {
                    uri: patch.file_path.to_string_lossy().to_string(),
                },
                replacements: vec![Replacement {
                    deleted_region: Region {
                        start_line: patch.target_line_start,
                        start_column: Some(1),
                        end_line: Some(patch.target_line_end),
                        end_column: None,
                    },
                    inserted_content: Some(Message {
                        text: patch.replacement_content.clone(),
                    }),
                }],
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffChunk {
    pub old_start: usize,
    pub old_lines: usize,
    pub new_start: usize,
    pub new_lines: usize,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedDiff {
    pub file_path: PathBuf,
    pub original_header: String,
    pub modified_header: String,
    pub chunks: Vec<DiffChunk>,
    pub raw_diff: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EradicationTest {
    pub test_id: String,
    pub target_file: PathBuf,
    pub test_file_path: PathBuf,
    pub language: SourceLanguage,
    pub test_framework: String,
    pub test_code: String,
    pub benign_test_name: String,
    pub exploit_payload_test_name: String,
    pub execution_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub target_path: PathBuf,
    pub language: SourceLanguage,
    pub total_vulnerabilities_detected: usize,
    pub remediated_count: usize,
    pub unfixable_count: usize,
    pub patches: Vec<SurgicalPatch>,
    pub diffs: Vec<UnifiedDiff>,
    pub tests: Vec<EradicationTest>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationExecutionResult {
    pub applied_patches: usize,
    pub modified_files: Vec<PathBuf>,
    pub written_test_files: Vec<PathBuf>,
    pub failed_patches: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct FixScanOptions {
    pub sarif_path: Option<PathBuf>,
    pub rules_filter: Option<Vec<String>>,
    pub language_override: Option<SourceLanguage>,
    pub generate_tests: bool,
    pub max_file_size: u64,
}
