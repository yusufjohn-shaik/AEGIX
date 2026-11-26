use cyberguard_core::sarif::{SarifLevel, SarifLog};
use cyberguard_risk::{
    sanitize_terminal_text, JsonExporter, MetadataSource, PrioritizedFinding, ReachabilityStatus,
    RiskExporter, RiskPrioritizationReport, RiskTier, SarifExporter, ScoreSource, TerminalExporter,
    TriFactorBreakdown,
};
use std::path::PathBuf;

fn sample_report() -> RiskPrioritizationReport {
    let mut report = RiskPrioritizationReport {
        target_path: PathBuf::from("/tmp/demo"),
        metadata_source: Some(MetadataSource::PureRustFallback),
        warnings: vec!["Demo fallback note\x1b[31mINJECTED".to_string()],
        workspace_packages: 12,
        analyzed_nodes: 8,
        findings: vec![PrioritizedFinding {
            id: "RUSTSEC-2020-0071:chrono@0.4.19".to_string(),
            rule_id: "RUSTSEC-2020-0071".to_string(),
            package_or_target: "chrono".to_string(),
            version: Some("0.4.19".to_string()),
            file_path: Some("Cargo.lock".to_string()),
            line: Some(1),
            summary: "Use-after-free in chrono\x1b[2J".to_string(),
            breakdown: TriFactorBreakdown {
                cvss: 7.5,
                epss: 0.12,
                reachability: 1.0,
                tri_factor_score: 0.90,
                score_bps: 90,
                status: ReachabilityStatus::VerifiedReachable,
                tier: RiskTier::High,
                score_source: ScoreSource::AdvisoryDb,
                call_trace: vec![
                    "src/main.rs::main".to_string(),
                    "chrono::NaiveDate::parse_from_str".to_string(),
                ],
                evidence: "Verified path".to_string(),
            },
            fixed_version: Some("0.4.20".to_string()),
        }],
        ..Default::default()
    };
    report.recompute_counts();
    report
}

#[test]
fn test_terminal_exporter_strips_control_escape_injection() {
    let report = sample_report();
    let cleaned = sanitize_terminal_text("bad\x1b[31mstring\x07!");
    assert!(!cleaned.contains('\x1b'));
    assert!(!cleaned.contains('\x07'));

    let exporter = TerminalExporter::new(false);
    let rendered = exporter.export(&report).expect("terminal export succeeds");
    assert!(rendered.contains("AEGIX TRI-FACTOR PRIORITIZER"));
    assert!(rendered.contains("chrono@0.4.19"));
    assert!(rendered.contains("src/main.rs::main -> chrono::NaiveDate::parse_from_str"));
    assert!(!rendered.contains('\x1b'));
}

#[test]
fn test_json_exporter_roundtrip() {
    let report = sample_report();
    let exporter = JsonExporter::new();
    let json_str = exporter.export(&report).expect("json export succeeds");

    let parsed: RiskPrioritizationReport = serde_json::from_str(&json_str).expect("valid JSON");
    assert_eq!(parsed.total_findings, 1);
    assert_eq!(parsed.high_count, 1);
    assert_eq!(parsed.findings[0].breakdown.score_bps, 90);
}

#[test]
fn test_sarif_exporter_properties_and_code_flows() {
    let report = sample_report();
    let exporter = SarifExporter::new();
    let sarif_str = exporter.export(&report).expect("sarif export succeeds");

    let sarif: SarifLog = serde_json::from_str(&sarif_str).expect("valid SARIF v2.1.0");
    assert_eq!(sarif.runs.len(), 1);
    let res = &sarif.runs[0].results[0];
    assert_eq!(res.rule_id, "RUSTSEC-2020-0071");
    assert_eq!(res.level, SarifLevel::Error);
    assert_eq!(res.code_flows.len(), 1);
    assert_eq!(res.code_flows[0].thread_flows[0].locations.len(), 2);

    let props = res.properties.as_ref().unwrap();
    assert_eq!(props["reachabilityStatus"], "verified_reachable");
    assert_eq!(props["riskTier"], "high");
    assert_eq!(props["triFactorScore"], 0.9);
    assert_eq!(props["fixedVersion"], "0.4.20");
}
