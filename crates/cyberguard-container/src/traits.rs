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

//! Core trait abstractions for container security scanning.

use crate::error::ContainerError;
use crate::models::{ContainerAuditReport, DockerfileFinding};
use async_trait::async_trait;
use cyberguard_core::SarifResult;
use std::path::Path;

/// Asynchronous container security scanner interface.
#[async_trait]
pub trait ContainerScanner: Send + Sync {
    /// Scan a single Dockerfile or directory containing Dockerfiles.
    async fn scan_dockerfile(&self, path: &Path) -> Result<Vec<DockerfileFinding>, ContainerError>;

    /// Scan an exported OCI / Docker image tarball archive.
    async fn scan_image_archive(&self, path: &Path)
        -> Result<ContainerAuditReport, ContainerError>;

    /// Convert container findings into standard OASIS SARIF v2.1.0 telemetry.
    fn to_sarif(&self, report: &ContainerAuditReport) -> Vec<SarifResult>;
}
