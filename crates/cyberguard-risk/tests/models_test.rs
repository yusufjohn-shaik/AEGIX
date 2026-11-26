use cyberguard_core::sarif::{SarifLevel, SarifResult};
use cyberguard_risk::{
    classify_risk_tier, compute_tri_factor_bps, PrioritizedFinding, ReachabilityStatus,
    RiskPrioritizationReport, RiskTier, ScoreSource, TriFactorBreakdown,
};
use std::path::PathBuf;

#[test]
fn test_tri_factor_parity_and_nan_sanitization() {
    // Parity check with SarifResult::with_tri_factor
    let mut res = SarifResult::new("RUSTSEC-2020-0071", SarifLevel::Error, "chrono flaw");
    res.with_tri_factor(7.5, 0.12, 1.0);
    let expected = res.to_ocsf("sca").vulnerabilities[0]
        .tri_factor_score
        .unwrap();

    let (c, e, r, bps, score) = compute_tri_factor_bps(7.5, 0.12, 1.0);
    assert_eq!(c, 7.5);
    assert_eq!(e, 0.12);
    assert_eq!(r, 1.0);
    assert_eq!(bps, 90);
    assert_eq!(score, expected);

    // NaN & Inf safety
    let (nc, ne, nr, nbps, nscore) = compute_tri_factor_bps(f64::NAN, f64::INFINITY, -5.0);
    assert_eq!(nc, 0.0);
    assert_eq!(ne, 0.0);
    assert_eq!(nr, 0.0);
    assert_eq!(nbps, 0);
    assert_eq!(nscore, 0.0);
}

#[test]
fn test_risk_tier_safety_floor_and_suppression() {
    // Unreachable must always be Suppressed even at CVSS 10.0, EPSS 0.99
    let (_, _, _, bps_unreach, _) = compute_tri_factor_bps(10.0, 0.99, 0.0);
    assert_eq!(
        classify_risk_tier(
            10.0,
            0.99,
            0.0,
            bps_unreach,
            ReachabilityStatus::Unreachable
        ),
        RiskTier::Suppressed
    );

    // Reachable Critical CVE with low EPSS (0.05) must NOT be suppressed; hits High safety floor
    let (_, _, _, bps_low_epss, _) = compute_tri_factor_bps(9.8, 0.05, 1.0);
    assert_eq!(
        classify_risk_tier(
            9.8,
            0.05,
            1.0,
            bps_low_epss,
            ReachabilityStatus::VerifiedReachable
        ),
        RiskTier::High
    );

    // Reachable High CVE (chrono 7.5 * 0.12 * 1.0 = 0.90) hits High safety floor instead of Low
    let (_, _, _, bps_chrono, _) = compute_tri_factor_bps(7.5, 0.12, 1.0);
    assert_eq!(
        classify_risk_tier(
            7.5,
            0.12,
            1.0,
            bps_chrono,
            ReachabilityStatus::VerifiedReachable
        ),
        RiskTier::High
    );

    // High EPSS + Reachable Critical hits Critical
    let (_, _, _, bps_crit, _) = compute_tri_factor_bps(9.8, 0.85, 1.0);
    assert_eq!(
        classify_risk_tier(
            9.8,
            0.85,
            1.0,
            bps_crit,
            ReachabilityStatus::VerifiedReachable
        ),
        RiskTier::Critical
    );

    // DevOrTestOnly with score < 0.10 gets Suppressed cleanly
    let (_, _, _, bps_dev_low, _) = compute_tri_factor_bps(4.0, 0.10, 0.10);
    assert_eq!(bps_dev_low, 4);
    assert_eq!(
        classify_risk_tier(
            4.0,
            0.10,
            0.10,
            bps_dev_low,
            ReachabilityStatus::DevOrTestOnly
        ),
        RiskTier::Suppressed
    );
}

#[test]
fn test_report_accounting_invariant() {
    let mut report = RiskPrioritizationReport {
        target_path: PathBuf::from("."),
        ..Default::default()
    };

    let make_finding = |id: &str, tier: RiskTier, status: ReachabilityStatus| PrioritizedFinding {
        id: id.to_string(),
        rule_id: "R1".to_string(),
        package_or_target: "pkg".to_string(),
        version: None,
        file_path: None,
        line: None,
        summary: "sum".to_string(),
        breakdown: TriFactorBreakdown {
            cvss: 7.0,
            epss: 0.5,
            reachability: status.multiplier(),
            tri_factor_score: 3.5,
            score_bps: 350,
            status,
            tier,
            score_source: ScoreSource::AdvisoryDb,
            call_trace: vec![],
            evidence: "ev".to_string(),
        },
        fixed_version: None,
    };

    report.findings.push(make_finding(
        "f1",
        RiskTier::Critical,
        ReachabilityStatus::VerifiedReachable,
    ));
    report.findings.push(make_finding(
        "f2",
        RiskTier::High,
        ReachabilityStatus::DirectDeclared,
    ));
    report.findings.push(make_finding(
        "f3",
        RiskTier::Suppressed,
        ReachabilityStatus::Unreachable,
    ));
    report.findings.push(make_finding(
        "f4",
        RiskTier::Suppressed,
        ReachabilityStatus::DevOrTestOnly,
    ));

    report.recompute_counts();
    assert_eq!(report.total_findings, 4);
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.high_count, 1);
    assert_eq!(report.suppressed_count, 2);
    assert_eq!(report.suppressed_unreachable, 1);
    assert_eq!(
        report.critical_count
            + report.high_count
            + report.medium_count
            + report.low_count
            + report.suppressed_count,
        report.total_findings
    );
}
