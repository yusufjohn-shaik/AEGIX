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

//! Error types for the container security engine.

use std::path::PathBuf;
use thiserror::Error;

/// Errors produced during container inspection, Dockerfile parsing, or tar processing.
#[derive(Error, Debug)]
pub enum ContainerError {
    /// Filesystem or I/O error while reading target files or image streams.
    #[error("I/O error during container scan: {0}")]
    Io(#[from] std::io::Error),

    /// Regular expression failure or invalid pattern syntax.
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    /// Parse error in Dockerfile or OCI manifest.
    #[error("Parse error at {0}: {1}")]
    Parse(PathBuf, String),

    /// Dangerous Zip-Slip or directory traversal path detected in tar archive.
    #[error("Zip-Slip security violation: entry '{0}' attempts directory traversal")]
    ZipSlipViolation(String),

    /// Decompression or tar archive corruption error.
    #[error("Archive error: {0}")]
    ArchiveError(String),

    /// Serialization / Deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
