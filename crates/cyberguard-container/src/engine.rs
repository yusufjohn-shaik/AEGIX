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

//! Core container security scanning engine.

use crate::dockerfile::DockerfileLinter;
use crate::error::ContainerError;
use crate::models::{ContainerAuditReport, DockerfileFinding};
use crate::oci::OciInspector;
use crate::traits::ContainerScanner;
use async_trait::async_trait;
use cyberguard_core::SarifResult;
use std::fs::File;
use std::path::Path;
use walkdir::WalkDir;

/// Primary Container & OCI Security Engine.
#[derive(Clone, Debug, Default)]
pub struct ContainerEngine {
    linter: DockerfileLinter,
    inspector: OciInspector,
}

impl ContainerEngine {
    /// Creates a new ContainerEngine with default linter and inspector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Access the underlying Dockerfile linter.
    pub fn linter(&self) -> &DockerfileLinter {
        &self.linter
    }

    /// Access the underlying OCI inspector.
    pub fn inspector(&self) -> &OciInspector {
        &self.inspector
    }

    /// Helper to test if a file name matches standard Dockerfile naming conventions.
    pub fn is_dockerfile(name: &str) -> bool {
        name == "Dockerfile" || name.starts_with("Dockerfile.") || name.ends_with(".dockerfile")
    }
}

#[async_trait]
impl ContainerScanner for ContainerEngine {
    async fn scan_dockerfile(
        &self,
        target: &Path,
    ) -> Result<Vec<DockerfileFinding>, ContainerError> {
        let mut findings = Vec::new();

        if !target.exists() {
            return Ok(findings);
        }

        if target.is_file() {
            let content = std::fs::read_to_string(target)?;
            findings.extend(self.linter.lint(&content)?);
            return Ok(findings);
        }

        let walker = WalkDir::new(target)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                let name = entry.file_name().to_string_lossy();
                !(name == ".git"
                    || name == "node_modules"
                    || name == "target"
                    || name == ".svn"
                    || name == ".cargo"
                    || name == "vendor")
            });

        for entry in walker.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                if Self::is_dockerfile(&file_name) {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        findings.extend(self.linter.lint(&content)?);
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn scan_image_archive(
        &self,
        target: &Path,
    ) -> Result<ContainerAuditReport, ContainerError> {
        let file = File::open(target)?;
        let packages = self.inspector.inspect_tar_stream(file)?;

        Ok(ContainerAuditReport {
            dockerfile_findings: Vec::new(),
            packages,
        })
    }

    fn to_sarif(&self, report: &ContainerAuditReport) -> Vec<SarifResult> {
        report
            .dockerfile_findings
            .iter()
            .map(|f| {
                let msg = format!("{}: {}", f.message, f.recommendation);
                let mut res = SarifResult::new(&f.rule_id, f.severity, msg)
                    .with_confidence(cyberguard_core::Confidence::High);
                res.add_location(
                    "Dockerfile",
                    f.line_number,
                    Some(1),
                    Some(f.line_number),
                    None,
                );
                res.compute_deterministic_fingerprint();
                res
            })
            .collect()
    }
}
