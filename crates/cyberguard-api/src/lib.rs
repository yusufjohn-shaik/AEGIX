//! # CyberGuard / Aegix API Security & Contract Fuzzing Engine (`cyberguard-api`)
//!
//! Provides static contract auditing of OpenAPI 3.0, 3.1, and Swagger 2.0 specifications
//! against OWASP API Security Top 10 anti-patterns, active deterministic negative boundary
//! mutation probing, and supervised Schemathesis execution.

#![deny(unsafe_code)]

pub mod engine;
pub mod error;
pub mod fuzzer;
pub mod linter;
pub mod models;
pub mod parser;
pub mod schemathesis;
pub mod traits;

pub use engine::ApiEngine;
pub use error::ApiError;
pub use fuzzer::DefaultApiFuzzer;
pub use linter::DefaultApiLinter;
pub use models::{
    ApiAuditReport, ApiConfig, ApiFinding, ApiSpec, Operation, ParamLocation, Parameter,
    RequestBody, Response, SchemaNode, SecurityScheme, SpecVersion,
};
pub use parser::{parse_spec_file, parse_spec_str};
pub use schemathesis::SchemathesisRunner;
pub use traits::{ApiFuzzer, ApiLinter, ApiScanner};

/// Prelude containing commonly used traits and types.
pub mod prelude {
    pub use crate::engine::ApiEngine;
    pub use crate::error::ApiError;
    pub use crate::models::{ApiAuditReport, ApiConfig, ApiFinding, ApiSpec, SpecVersion};
    pub use crate::parser::{parse_spec_file, parse_spec_str};
    pub use crate::traits::{ApiFuzzer, ApiLinter, ApiScanner};
}
