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

//! Error types for the secret detection engine.

use std::path::PathBuf;
use thiserror::Error;

/// Errors produced during secret analysis or rule matching.
#[derive(Error, Debug)]
pub enum SecretError {
    /// Filesystem or I/O error while reading target files.
    #[error("I/O error during secret scan: {0}")]
    Io(#[from] std::io::Error),

    /// Regular expression failure or invalid pattern syntax.
    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),

    /// Data parsing or structural decoding error.
    #[error("Parse error at {0}: {1}")]
    Parse(PathBuf, String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
