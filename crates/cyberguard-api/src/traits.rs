//! Core trait definitions for the API Security & Spec Fuzzing engine.

use crate::error::ApiError;
use crate::models::{ApiAuditReport, ApiConfig, ApiFinding, ApiSpec};
use async_trait::async_trait;

/// Facade trait coordinating complete API specification audit and fuzzing.
#[async_trait]
pub trait ApiScanner: Send + Sync {
    /// Execute static audit and optional active fuzzing according to configuration.
    async fn scan(&self, config: &ApiConfig) -> Result<ApiAuditReport, ApiError>;
}

/// Static contract security linter trait (OWASP API Security Top 10).
pub trait ApiLinter: Send + Sync {
    /// Statically analyze normalized specification against security rules.
    fn lint(&self, spec: &ApiSpec, spec_path: &str) -> Vec<ApiFinding>;
}

/// Active contract mutation and boundary prober trait.
#[async_trait]
pub trait ApiFuzzer: Send + Sync {
    /// Execute boundary mutation fuzzing against target endpoints.
    async fn fuzz(&self, spec: &ApiSpec, config: &ApiConfig) -> Result<Vec<ApiFinding>, ApiError>;
}
