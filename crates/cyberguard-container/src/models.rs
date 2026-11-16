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

//! Data models for container security findings, installed OS packages, and audit reports.

use cyberguard_core::SarifLevel;
use serde::{Deserialize, Serialize};

/// Security finding identified in a Dockerfile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerfileFinding {
    /// Rule identifier (e.g., `CG-CONT-001`).
    pub rule_id: String,
    /// Dockerfile instruction directive (e.g., `USER`, `FROM`, `RUN`).
    pub directive: String,
    /// 1-based line number where the issue was detected.
    pub line_number: usize,
    /// Severity level.
    pub severity: SarifLevel,
    /// Human-readable explanation.
    pub message: String,
    /// Recommended remediation guidance.
    pub recommendation: String,
}

/// An installed operating system package discovered within an image layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerPackage {
    /// Package name (e.g., `busybox`, `libssl3`).
    pub name: String,
    /// Installed package version (including epoch if applicable).
    pub version: String,
    /// System architecture (e.g., `x86_64`, `amd64`).
    pub architecture: Option<String>,
    /// Package manager type (`apk`, `dpkg`).
    pub package_manager: String,
    /// Origin source package (critical for Alpine CVE matching).
    pub origin: Option<String>,
    /// OCI Layer SHA identifier where package was introduced or updated.
    pub layer_id: Option<String>,
}

/// Aggregated container security audit report.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContainerAuditReport {
    /// All Dockerfile linting findings.
    pub dockerfile_findings: Vec<DockerfileFinding>,
    /// All installed operating system packages discovered in container layers.
    pub packages: Vec<ContainerPackage>,
}
