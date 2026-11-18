#![deny(unsafe_code)]

pub mod checks;
pub mod client;
pub mod engine;
pub mod error;
pub mod models;
pub mod nuclei;
pub mod rules;
pub mod traits;

pub use client::{DastClient, DEFAULT_TIMEOUT_MS, MAX_BODY_BYTES, MAX_REDIRECT_HOPS};
pub use engine::DastEngine;
pub use error::DastError;
pub use models::{
    DastAuditReport, DastFinding, DastPhase, DastRule, DastTarget, FindingSeverity, MatchCondition,
    MatchPart, RuleMatcher, RuleRequest,
};
pub use traits::DastScanner;
