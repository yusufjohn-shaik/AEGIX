// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(unsafe_code)]

//! # CyberGuard Secret Detection Engine
//!
//! High-precision, zero-runtime Secret and Credential Leakage Detection Engine.
//! Provides Shannon entropy analysis, multi-provider API token discovery,
//! automatic credential masking, and OASIS SARIF v2.1.0 telemetry.

pub mod engine;
pub mod entropy;
pub mod error;
pub mod masker;
pub mod models;
pub mod rules;
pub mod traits;

pub use engine::SecretEngine;
pub use entropy::{calculate_shannon_entropy, is_high_entropy};
pub use error::SecretError;
pub use masker::mask_secret;
pub use models::{SecretFinding, SecretRule};
pub use rules::default_rules;
pub use traits::SecretScanner;
