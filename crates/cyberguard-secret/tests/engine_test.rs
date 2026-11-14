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

use cyberguard_secret::{SecretEngine, SecretScanner};
use std::fs;

#[tokio::test]
async fn test_secret_engine_scan_and_sarif() {
    let temp_dir = std::env::temp_dir().join(format!("cg_sec_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let clean_file = temp_dir.join("clean.rs");
    fs::write(&clean_file, "fn main() { println!(\"Hello World\"); }").unwrap();

    let stripe_dummy = ["sk", "live", "51Abcdefghijklmnopqrstuvw"].join("_");
    let secrets_file = temp_dir.join("secrets.env");
    let secrets_content = format!(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSTRIPE_SECRET={}\n",
        stripe_dummy
    );
    fs::write(&secrets_file, secrets_content).unwrap();

    let binary_file = temp_dir.join("test.bin");
    fs::write(&binary_file, b"ELF\x00\x01\x02\x00AKIAIOSFODNN7EXAMPLE").unwrap();

    let git_dir = temp_dir.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("config"), "AKIAIOSFODNN7EXAMPLE").unwrap();

    let engine = SecretEngine::default();
    let findings = engine.scan_path(&temp_dir).await.expect("Scan succeeds");

    assert_eq!(
        findings.len(),
        2,
        "Expected 2 findings, found {}",
        findings.len()
    );

    let aws_finding = findings
        .iter()
        .find(|f| f.rule_id == "CG-SEC-AWS-001")
        .unwrap();
    assert_eq!(aws_finding.provider, "AWS");
    assert_eq!(aws_finding.line_number, 1);
    assert_eq!(aws_finding.masked_secret, "AKIA**************LE");
    assert!(aws_finding.entropy > 3.0);

    let stripe_finding = findings
        .iter()
        .find(|f| f.rule_id == "CG-SEC-STRIPE-001")
        .unwrap();
    assert_eq!(stripe_finding.provider, "Stripe");
    assert_eq!(stripe_finding.line_number, 2);
    assert!(stripe_finding.masked_secret.starts_with("sk_l"));

    // Check SARIF conversion
    let sarif_results = engine.to_sarif(&findings);
    assert_eq!(sarif_results.len(), 2);
    for r in &sarif_results {
        assert!(r.partial_fingerprints.is_some());
        let fps = r.partial_fingerprints.as_ref().unwrap();
        assert!(fps.contains_key("logicalLocationTokenHash/v1"));
    }

    let _ = fs::remove_dir_all(&temp_dir);
}
