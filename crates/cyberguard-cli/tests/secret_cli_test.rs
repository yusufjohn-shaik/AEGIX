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
use std::path::PathBuf;

#[tokio::test]
async fn test_secret_scan_fixture() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("vulnerable-secrets");

    let engine = SecretEngine::default();
    let findings = engine.scan_path(&fixture_dir).await.expect("Scan succeeds");

    assert!(
        findings.len() >= 5,
        "Expected at least 5 secrets in fixture, found {}",
        findings.len()
    );

    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"CG-SEC-AWS-001"),
        "Must find AWS Access Key"
    );
    assert!(
        rule_ids.contains(&"CG-SEC-AWS-002"),
        "Must find AWS Secret Access Key"
    );
    assert!(
        rule_ids.contains(&"CG-SEC-GITHUB-001"),
        "Must find GitHub token"
    );
    assert!(
        rule_ids.contains(&"CG-SEC-GENERIC-001"),
        "Must find Generic API key"
    );
    assert!(
        rule_ids.contains(&"CG-SEC-OPENAI-001"),
        "Must find OpenAI key"
    );
    assert!(
        rule_ids.contains(&"CG-SEC-KEY-001"),
        "Must find RSA Private Key"
    );

    // Ensure all secrets are masked
    for f in &findings {
        assert!(
            f.masked_secret.contains('*') || f.rule_id == "CG-SEC-KEY-001",
            "Secret must be masked: {}",
            f.masked_secret
        );
        assert!(!f.masked_secret.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!f
            .masked_secret
            .contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }
}

#[tokio::test]
async fn test_secret_scan_dynamic_stripe_and_slack() {
    let temp_dir = std::env::temp_dir().join(format!("cg_sec_dyn_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let dummy_stripe = ["sk", "live", "51Abcdefghijklmnopqrstuvw"].join("_");
    let dummy_slack = [
        "xoxb",
        "123456789012",
        "1234567890123",
        "AbCdEfGhIjKlMnOpQrStUvWx",
    ]
    .join("-");

    std::fs::write(
        temp_dir.join("creds.env"),
        format!("STRIPE_KEY={}\nSLACK_TOKEN={}\n", dummy_stripe, dummy_slack),
    )
    .unwrap();

    let engine = SecretEngine::default();
    let findings = engine.scan_path(&temp_dir).await.expect("Scan succeeds");

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|f| f.rule_id == "CG-SEC-STRIPE-001"));
    assert!(findings.iter().any(|f| f.rule_id == "CG-SEC-SLACK-001"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}
