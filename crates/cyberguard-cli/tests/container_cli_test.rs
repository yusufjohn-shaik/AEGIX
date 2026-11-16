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

use cyberguard_container::{ContainerAuditReport, ContainerEngine, ContainerScanner};
use std::path::PathBuf;

#[tokio::test]
async fn test_container_scan_fixture() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("vulnerable-container");

    let engine = ContainerEngine::new();
    let findings = engine
        .scan_dockerfile(&fixture_dir)
        .await
        .expect("Scan succeeds");

    assert!(
        findings.len() >= 5,
        "Expected at least 5 findings in vulnerable container fixture, found {}",
        findings.len()
    );

    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CONT-001"),
        "Must flag root user execution"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-002"),
        "Must flag untagged base image"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-003"),
        "Must flag curl to shell pipe"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-004"),
        "Must flag exposed secret in ENV"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-005"),
        "Must flag missing healthcheck"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-007"),
        "Must flag ADD instead of COPY"
    );

    let report = ContainerAuditReport {
        dockerfile_findings: findings,
        packages: Vec::new(),
    };

    let sarif = engine.to_sarif(&report);
    assert_eq!(sarif.len(), report.dockerfile_findings.len());
    for res in &sarif {
        assert!(res.partial_fingerprints.is_some());
    }
}
