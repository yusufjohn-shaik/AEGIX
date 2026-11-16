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
use std::fs;

#[tokio::test]
async fn test_container_engine_dockerfile_and_sarif() {
    let temp_dir = std::env::temp_dir().join(format!("cg_cont_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let df_path = temp_dir.join("Dockerfile");
    let content = r#"
FROM ubuntu
RUN apt-get update && apt-get install -y curl
USER root
CMD ["/bin/bash"]
"#;
    fs::write(&df_path, content).unwrap();

    let engine = ContainerEngine::new();
    let findings = engine
        .scan_dockerfile(&df_path)
        .await
        .expect("Scan succeeds");

    assert!(
        !findings.is_empty(),
        "Must detect findings in vulnerable Dockerfile"
    );

    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-CONT-001"),
        "Must detect explicit root user"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-002"),
        "Must detect untagged ubuntu base image"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-005"),
        "Must detect missing healthcheck"
    );
    assert!(
        rule_ids.contains(&"CG-CONT-008"),
        "Must detect apt-get without clean"
    );

    let report = ContainerAuditReport {
        dockerfile_findings: findings,
        packages: Vec::new(),
    };

    let sarif_results = engine.to_sarif(&report);
    assert_eq!(sarif_results.len(), report.dockerfile_findings.len());

    for r in &sarif_results {
        assert!(
            r.partial_fingerprints.is_some(),
            "SARIF result must have deterministic fingerprint"
        );
        let fps = r.partial_fingerprints.as_ref().unwrap();
        assert!(fps.contains_key("logicalLocationTokenHash/v1"));
    }

    let _ = fs::remove_dir_all(&temp_dir);
}
