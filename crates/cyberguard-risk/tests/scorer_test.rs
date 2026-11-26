use cyberguard_core::sarif::{SarifLevel, SarifLog, SarifResult};
use cyberguard_risk::{
    EpssCatalog, ReachabilityStatus, RiskEngine, RiskPrioritizer, RiskScanOptions, RiskTier,
    ScoreSource,
};
use std::path::PathBuf;

fn temp_ws(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aegix-risk-scorer-{}-{}", name, nanos));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    dir
}

#[test]
fn test_epss_catalog_precedence_and_external_override() {
    let mut catalog = EpssCatalog::embedded();

    // Exact embedded RUSTSEC match (chrono)
    let (cvss, epss, src, fixed) = catalog.resolve(
        "RUSTSEC-2020-0071",
        None,
        None,
        None,
        None,
        SarifLevel::Error,
    );
    assert_eq!(cvss, 7.5);
    assert_eq!(epss, 0.12);
    assert_eq!(src, ScoreSource::AdvisoryDb);
    assert_eq!(fixed.as_deref(), Some("0.4.20"));

    // CWE heuristic fallback for SQLi
    let (sast_cvss, sast_epss, sast_src, _) = catalog.resolve(
        "CG-SQLI-001",
        None,
        Some("CWE-89"),
        None,
        None,
        SarifLevel::Error,
    );
    assert_eq!(sast_cvss, 9.8);
    assert_eq!(sast_epss, 0.85);
    assert_eq!(sast_src, ScoreSource::CweHeuristic);

    // External override JSON takes precedence over embedded DB
    let dir = temp_ws("epss-ext");
    let db_path = dir.join("epss.json");
    std::fs::write(
        &db_path,
        r#"{ "RUSTSEC-2020-0071": { "epss": 0.91, "cvss": 8.8, "fixed_version": "0.4.35" } }"#,
    )
    .unwrap();

    let loaded = catalog.load_external_json(&db_path).unwrap();
    assert_eq!(loaded, 1);

    let (ecvss, eepss, esrc, efixed) = catalog.resolve(
        "RUSTSEC-2020-0071",
        None,
        None,
        None,
        None,
        SarifLevel::Error,
    );
    assert_eq!(ecvss, 8.8);
    assert_eq!(eepss, 0.91);
    assert_eq!(esrc, ScoreSource::ExternalEpssDb);
    assert_eq!(efixed.as_deref(), Some("0.4.35"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_prioritize_sarif_fusion_with_sca_and_sast_and_graph() {
    let dir = temp_ws("fusion");

    let cargo_toml = r#"
[package]
name = "fusion-app"
version = "0.1.0"
edition = "2021"

[dependencies]
chrono = "0.4.19"
"#;

    let cargo_lock = r#"
version = 3

[[package]]
name = "fusion-app"
version = "0.1.0"
dependencies = ["chrono"]

[[package]]
name = "chrono"
version = "0.4.19"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.12.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    let main_rs = r#"
use chrono::NaiveDate;

fn main() {
    let _d = NaiveDate::from_ymd_opt(2026, 11, 26);
}
"#;

    std::fs::write(dir.join("Cargo.toml"), cargo_toml).unwrap();
    std::fs::write(dir.join("Cargo.lock"), cargo_lock).unwrap();
    std::fs::write(dir.join("src").join("main.rs"), main_rs).unwrap();

    // Simulate multi-engine SARIF log (SCA chrono + orphaned tokio + Rust SAST + Graph chain)
    let mut sarif = SarifLog::new("cyberguard-sca", "0.9.0");

    let mut r_chrono = SarifResult::new(
        "RUSTSEC-2020-0071",
        SarifLevel::Error,
        "Known vulnerability RUSTSEC-2020-0071 (CVE-2020-35873) in dependency chrono@0.4.19. Potential use-after-free.",
    );
    r_chrono.add_location("Cargo.lock", 1, None, None, None);
    sarif.add_result(r_chrono);

    let mut r_tokio_orphan = SarifResult::new(
        "RUSTSEC-2021-0145",
        SarifLevel::Error,
        "Known vulnerability RUSTSEC-2021-0145 in dependency tokio@1.12.0. Data race.",
    );
    r_tokio_orphan.add_location("Cargo.lock", 1, None, None, None);
    sarif.add_result(r_tokio_orphan);

    let mut r_sast = SarifResult::new(
        "CG-SQLI-001",
        SarifLevel::Error,
        "Raw SQL concatenation inside main handler",
    );
    r_sast.add_location("src/main.rs", 4, None, None, None);
    r_sast.properties = Some(serde_json::json!({ "cwe": "CWE-89" }));
    sarif.add_result(r_sast);

    let mut r_graph = SarifResult::new(
        "PATH-EXPLOIT-CHAIN",
        SarifLevel::Error,
        "Exploit chain from entrypoint to data exfil",
    );
    r_graph.properties = Some(serde_json::json!({ "path_risk": 88.0 }));
    sarif.add_result(r_graph);

    let engine = RiskEngine::new();
    let report = engine
        .prioritize_sarif(
            &dir,
            &sarif,
            &RiskScanOptions {
                min_score: 0.0,
                show_suppressed: true,
                use_cargo_metadata: false,
                external_epss_db: None,
            },
        )
        .await
        .expect("prioritization succeeds");

    assert_eq!(report.total_findings, 4);
    assert_eq!(report.suppressed_unreachable, 1);

    // Highest risk must be SAST inside main() with CWE-89 (9.8 * 0.85 * 1.0 = 8.33 -> Critical)
    let top = &report.findings[0];
    assert_eq!(top.rule_id, "CG-SQLI-001");
    assert_eq!(top.breakdown.status, ReachabilityStatus::VerifiedReachable);
    assert_eq!(top.breakdown.tier, RiskTier::Critical);
    assert_eq!(top.breakdown.tri_factor_score, 8.33);

    // chrono is verified reachable in main() -> not suppressed, High safety floor
    let chrono_f = report
        .findings
        .iter()
        .find(|f| f.package_or_target == "chrono")
        .unwrap();
    assert_eq!(
        chrono_f.breakdown.status,
        ReachabilityStatus::VerifiedReachable
    );
    assert_eq!(chrono_f.breakdown.tier, RiskTier::High);

    // Orphaned tokio is Unreachable -> Suppressed
    let tokio_f = report
        .findings
        .iter()
        .find(|f| f.package_or_target == "tokio")
        .unwrap();
    assert_eq!(tokio_f.breakdown.status, ReachabilityStatus::Unreachable);
    assert_eq!(tokio_f.breakdown.tier, RiskTier::Suppressed);

    // Graph chain path_risk 88.0 mapped to cvss 8.8, NotApplicable pass-through
    let graph_f = report
        .findings
        .iter()
        .find(|f| f.rule_id == "PATH-EXPLOIT-CHAIN")
        .unwrap();
    assert_eq!(graph_f.breakdown.cvss, 8.8);
    assert_eq!(graph_f.breakdown.status, ReachabilityStatus::NotApplicable);

    let _ = std::fs::remove_dir_all(&dir);
}
