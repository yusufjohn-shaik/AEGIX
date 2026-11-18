//! Strongly typed Intermediate Representation (IR), AST models, findings, and configuration.

use cyberguard_core::sarif::{Confidence, SarifLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Specification format dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecVersion {
    OpenApi30,
    OpenApi31,
    Swagger2,
}

impl std::fmt::Display for SpecVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecVersion::OpenApi30 => write!(f, "OpenAPI 3.0"),
            SpecVersion::OpenApi31 => write!(f, "OpenAPI 3.1"),
            SpecVersion::Swagger2 => write!(f, "Swagger 2.0"),
        }
    }
}

/// Normalized canonical API Specification IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSpec {
    pub version: SpecVersion,
    pub title: String,
    pub spec_version: String,
    pub servers: Vec<String>,
    pub operations: Vec<Operation>,
    pub security_definitions: HashMap<String, SecurityScheme>,
}

/// Normalized API operation (e.g. GET /api/v1/users/{id}).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub method: String,
    pub path: String,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<RequestBody>,
    pub responses: HashMap<String, Response>,
    pub security: Vec<HashMap<String, Vec<String>>>,
    pub is_admin_route: bool,
    pub is_public_exempt: bool,
}

/// Parameter location in HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamLocation {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

/// Normalized operation parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: ParamLocation,
    pub required: bool,
    pub schema: Option<Box<SchemaNode>>,
}

/// Normalized request body definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub required: bool,
    pub content_types: HashMap<String, Box<SchemaNode>>,
}

/// Normalized response definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub description: String,
    pub content_types: HashMap<String, Box<SchemaNode>>,
}

/// Normalized security scheme definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScheme {
    pub scheme_type: String, // apiKey, http, oauth2, openIdConnect
    pub name: Option<String>,
    pub location: Option<String>,
    pub scheme: Option<String>, // bearer, basic
}

/// Normalized schema AST node with boundary properties and cycle tracking.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SchemaNode {
    pub schema_type: Option<String>,
    pub format: Option<String>,
    pub properties: HashMap<String, Box<SchemaNode>>,
    pub items: Option<Box<SchemaNode>>,
    pub required: Vec<String>,
    pub read_only: bool,
    pub write_only: bool,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub ref_path: Option<String>,
}

/// Standardized API security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFinding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: SarifLevel,
    pub confidence: Confidence,
    pub cwe: u32,
    pub path: String,
    pub method: Option<String>,
    pub line_hint: Option<usize>,
    pub json_pointer: String,
    pub remediation: String,
}

/// Complete report of API static audit and active fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAuditReport {
    pub spec_path: String,
    pub spec_version: SpecVersion,
    pub operations_count: usize,
    pub findings: Vec<ApiFinding>,
    pub fuzzed_endpoints: usize,
    pub fuzzer_requests_sent: usize,
    pub fuzzer_errors_found: usize,
}

/// Execution configuration for the API security engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub spec_path: PathBuf,
    pub target: Option<String>,
    pub fuzz: bool,
    pub allow_destructive: bool,
    pub dry_run: bool,
    pub scope_path: Option<PathBuf>,
    pub scope_key: Option<String>,
    pub max_rps: u32,
    pub timeout_ms: u64,
    pub headers: Vec<String>,
    pub insecure: bool,
    pub schemathesis: bool,
    pub baseline_path: Option<PathBuf>,
    pub format: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            spec_path: PathBuf::new(),
            target: None,
            fuzz: false,
            allow_destructive: false,
            dry_run: false,
            scope_path: None,
            scope_key: None,
            max_rps: 25,
            timeout_ms: 5000,
            headers: Vec::new(),
            insecure: false,
            schemathesis: false,
            baseline_path: None,
            format: "terminal".to_string(),
        }
    }
}
