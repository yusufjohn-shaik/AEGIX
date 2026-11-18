// Copyright 2026 Aegix Authors.
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

use cyberguard_core::AegixBaseline;
use cyberguard_sast::{NativeRuleEngine, SastAnalyzer, ScanContext};
use std::fs;

#[tokio::test]
async fn test_baseline_snapshot_lifecycle_and_filtering() {
    let test_dir = std::env::temp_dir().join(format!("aegix_baseline_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&test_dir);

    // 1. Create initial codebase with 2 legacy security issues
    let sqli_file = test_dir.join("legacy_auth.py");
    fs::write(
        &sqli_file,
        r#"
def login(username, password):
    query = "SELECT * FROM users WHERE user = '" + username + "'"
    return db.execute(query)
"#,
    )
    .unwrap();

    let cmdi_file = test_dir.join("legacy_util.py");
    fs::write(
        &cmdi_file,
        r#"
import os
def ping(host):
    os.system("ping -c 1 " + host)
"#,
    )
    .unwrap();

    // 2. Perform initial scan
    let ctx = ScanContext::new(&test_dir);
    let engine = NativeRuleEngine::default();
    let initial_findings = engine.analyze(&ctx).await.unwrap();
    assert_eq!(initial_findings.len(), 2);

    // 3. Save baseline snapshot
    let baseline_path = test_dir.join(".aegix-baseline.json");
    let baseline = AegixBaseline::from_results(&initial_findings);
    baseline.save_to_path(&baseline_path).unwrap();

    assert!(baseline_path.exists());
    let loaded_baseline = AegixBaseline::load_from_path(&baseline_path).unwrap();
    assert_eq!(loaded_baseline.total_findings, 2);
    assert_eq!(loaded_baseline.fingerprints.len(), 2);

    // 4. Rescan with baseline active - legacy issues must be suppressed
    let mut second_scan_findings = engine.analyze(&ctx).await.unwrap();
    assert_eq!(second_scan_findings.len(), 2);

    let suppressed = loaded_baseline.filter_results(&mut second_scan_findings);
    assert_eq!(
        suppressed, 2,
        "Both legacy findings must be suppressed by baseline"
    );
    assert_eq!(
        second_scan_findings.len(),
        0,
        "Zero new regressions should be reported"
    );

    // 5. Introduce a NEW vulnerability regression
    let secret_file = test_dir.join("api_key.rs");
    fs::write(
        &secret_file,
        r#"
pub const GITHUB_TOKEN: &str = "ghp_123456789012345678901234567890123456";
"#,
    )
    .unwrap();

    // 6. Rescan with baseline active - ONLY the new regression should fail
    let mut third_scan_findings = engine.analyze(&ctx).await.unwrap();
    assert_eq!(
        third_scan_findings.len(),
        3,
        "Total 3 issues exist in codebase"
    );

    let suppressed = loaded_baseline.filter_results(&mut third_scan_findings);
    assert_eq!(suppressed, 2, "Legacy issues remain suppressed");
    assert_eq!(
        third_scan_findings.len(),
        1,
        "Exactly 1 new regression detected"
    );
    assert_eq!(third_scan_findings[0].rule_id, "CG-SECR-001");

    // 7. Cleanup
    let _ = fs::remove_dir_all(&test_dir);
}
