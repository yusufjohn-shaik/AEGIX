//! Tri-Factor scoring and SARIF/SCA reachability fusion helpers.

#![deny(unsafe_code)]

use crate::epss::EpssCatalog;
use crate::models::{
    classify_risk_tier, compute_tri_factor_bps, PrioritizedFinding, ReachabilityStatus,
    ScoreSource, TriFactorBreakdown, WorkspaceDependencyGraph,
};
use crate::traits::RustReachabilityIndex;
use cyberguard_core::sarif::SarifResult;
use cyberguard_sca::models::{Ecosystem, ScaFinding};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct TriFactorScorer {
    dep_msg_regex: Regex,
}

impl Default for TriFactorScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl TriFactorScorer {
    pub fn new() -> Self {
        // Matches ScaEngine::to_sarif_log format: "in dependency <name>@<version>."
        let dep_msg_regex =
            Regex::new(r"in dependency ([A-Za-z0-9_@./-]+)@([^\s.]+(?:\.[^\s.]+)*)")
                .expect("valid dependency regex");
        Self { dep_msg_regex }
    }

    /// Scores a native `ScaFinding` against the resolved Rust call-graph reachability index.
    pub fn score_sca_finding(
        &self,
        finding: &ScaFinding,
        index: &RustReachabilityIndex,
        lockfile_hint: Option<&str>,
    ) -> PrioritizedFinding {
        let pkg = &finding.package;
        let vuln = &finding.vulnerability;

        let (status, call_trace, evidence) = if pkg.ecosystem == Ecosystem::Cargo {
            if let Some((st, trace, ev)) = index.crate_reachability.get(&pkg.name) {
                (*st, trace.clone(), ev.clone())
            } else if pkg.is_direct {
                (
                    ReachabilityStatus::DirectDeclared,
                    Vec::new(),
                    format!("Direct Cargo dependency '{}' declared", pkg.name),
                )
            } else {
                (
                    ReachabilityStatus::TransitiveReachable,
                    Vec::new(),
                    format!("Transitive Cargo dependency '{}'", pkg.name),
                )
            }
        } else if pkg.is_direct {
            (
                ReachabilityStatus::VerifiedReachable,
                Vec::new(),
                format!(
                    "Direct {:?} dependency '{}' declared in lockfile",
                    pkg.ecosystem, pkg.name
                ),
            )
        } else {
            (
                ReachabilityStatus::TransitiveReachable,
                Vec::new(),
                format!(
                    "Transitive {:?} dependency '{}' declared in lockfile",
                    pkg.ecosystem, pkg.name
                ),
            )
        };

        let reachability = if pkg.ecosystem == Ecosystem::Cargo {
            status.multiplier()
        } else {
            finding.reachability
        };

        let (cvss, epss, r, score_bps, tri_factor_score) =
            compute_tri_factor_bps(vuln.cvss, vuln.epss, reachability);
        let tier = classify_risk_tier(cvss, epss, r, score_bps, status);

        let id = format!("{}:{}@{}", vuln.id, pkg.name, pkg.version);

        PrioritizedFinding {
            id,
            rule_id: vuln.id.clone(),
            package_or_target: pkg.name.clone(),
            version: Some(pkg.version.clone()),
            file_path: lockfile_hint.map(str::to_string),
            line: Some(1),
            summary: vuln.summary.clone(),
            breakdown: TriFactorBreakdown {
                cvss,
                epss,
                reachability: r,
                tri_factor_score,
                score_bps,
                status,
                tier,
                score_source: ScoreSource::AdvisoryDb,
                call_trace,
                evidence,
            },
            fixed_version: vuln.fixed_version.clone(),
        }
    }

    /// Scores and enriches any generic `SarifResult` from SAST, SCA, Graph, Secret, or Cloud tools.
    pub fn score_sarif_result(
        &self,
        tool_name: &str,
        result: &SarifResult,
        index: &RustReachabilityIndex,
        dep_graph: &WorkspaceDependencyGraph,
        catalog: &EpssCatalog,
    ) -> PrioritizedFinding {
        let props = result.properties.as_ref().and_then(|v| v.as_object());

        let prop_str = |key: &str| -> Option<String> {
            props
                .and_then(|m| m.get(key))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        let prop_f64 =
            |key: &str| -> Option<f64> { props.and_then(|m| m.get(key)).and_then(|v| v.as_f64()) };

        // Extract location
        let (file_path, line) = result
            .locations
            .first()
            .and_then(|l| l.physical_location.as_ref())
            .map(|phys| {
                (
                    Some(phys.artifact_location.uri.clone()),
                    phys.region.as_ref().map(|r| r.start_line),
                )
            })
            .unwrap_or((None, None));

        // Extract package & version (structured properties OR ScaEngine message regex fallback)
        let (mut pkg_name, mut version) = (
            prop_str("package").or_else(|| prop_str("packageName")),
            prop_str("version"),
        );
        if pkg_name.is_none() {
            if let Some(caps) = self.dep_msg_regex.captures(&result.message.text) {
                pkg_name = caps.get(1).map(|m| m.as_str().to_string());
                if version.is_none() {
                    version = caps
                        .get(2)
                        .map(|m| m.as_str().trim_end_matches('.').to_string());
                }
            }
        }

        let cve_hint = prop_str("cve");
        let cwe_hint = prop_str("cwe");

        // Handle cyberguard-graph `path_risk` (0..=100) mapping cleanly into CVSS (0..=10)
        let explicit_cvss = prop_f64("cvss")
            .or_else(|| prop_f64("path_risk").map(|pr| (pr / 10.0).clamp(0.0, 10.0)));
        let explicit_epss = prop_f64("epss");

        let (cvss, epss, score_source, cat_fixed) = catalog.resolve(
            &result.rule_id,
            cve_hint.as_deref(),
            cwe_hint.as_deref(),
            explicit_cvss,
            explicit_epss,
            result.level,
        );
        let fixed_version = prop_str("fixedVersion").or(cat_fixed);

        // Determine ReachabilityStatus across SCA vs Rust SAST vs non-Rust targets
        let (status, call_trace, evidence) = if let Some(ref pkg) = pkg_name {
            if let Some((st, trace, ev)) = index.crate_reachability.get(pkg) {
                (*st, trace.clone(), ev.clone())
            } else if let Some(node) = dep_graph.packages.get(pkg) {
                (
                    ReachabilityStatus::DirectDeclared,
                    Vec::new(),
                    format!(
                        "Cargo dependency '{}' v{} resolved",
                        node.name, node.version
                    ),
                )
            } else {
                // Non-Cargo package in SARIF (e.g. npm/PyPI) - preserve attached reachability or NotApplicable
                let attached = prop_f64("reachability");
                if let Some(r) = attached.filter(|v| v.is_finite()) {
                    let st = if r >= 0.99 {
                        ReachabilityStatus::VerifiedReachable
                    } else if r <= 0.01 {
                        ReachabilityStatus::Unreachable
                    } else {
                        ReachabilityStatus::TransitiveReachable
                    };
                    (
                        st,
                        Vec::new(),
                        format!(
                            "Non-Cargo dependency '{}' reachability ({:.2}) preserved from SARIF",
                            pkg, r
                        ),
                    )
                } else {
                    (
                        ReachabilityStatus::NotApplicable,
                        Vec::new(),
                        format!("Non-Cargo dependency '{}' (Rust reachability N/A)", pkg),
                    )
                }
            }
        } else if let Some(ref uri) = file_path {
            resolve_file_reachability(uri, line, index, dep_graph)
        } else {
            (
                ReachabilityStatus::NotApplicable,
                Vec::new(),
                format!(
                    "No local Rust file or Cargo dependency attached ({})",
                    tool_name
                ),
            )
        };

        let reachability = status.multiplier();
        let (c, e, r, score_bps, tri_factor_score) =
            compute_tri_factor_bps(cvss, epss, reachability);
        let tier = classify_risk_tier(c, e, r, score_bps, status);

        let package_or_target =
            pkg_name.unwrap_or_else(|| file_path.clone().unwrap_or_else(|| result.rule_id.clone()));

        let id = format!(
            "{}:{}:{}",
            result.rule_id,
            package_or_target,
            line.unwrap_or(1)
        );

        PrioritizedFinding {
            id,
            rule_id: result.rule_id.clone(),
            package_or_target,
            version,
            file_path,
            line,
            summary: result.message.text.clone(),
            breakdown: TriFactorBreakdown {
                cvss: c,
                epss: e,
                reachability: r,
                tri_factor_score,
                score_bps,
                status,
                tier,
                score_source,
                call_trace,
                evidence,
            },
            fixed_version,
        }
    }
}

fn resolve_file_reachability(
    uri: &str,
    line_opt: Option<usize>,
    index: &RustReachabilityIndex,
    dep_graph: &WorkspaceDependencyGraph,
) -> (ReachabilityStatus, Vec<String>, String) {
    let norm_uri = uri.replace('\\', "/");
    if !norm_uri.ends_with(".rs") {
        return (
            ReachabilityStatus::NotApplicable,
            Vec::new(),
            format!("Non-Rust file '{}' (conservative pass-through)", uri),
        );
    }

    // Match relative path against analyzed function spans
    let ws_prefix = dep_graph
        .workspace_root
        .to_string_lossy()
        .replace('\\', "/");
    let stripped = norm_uri
        .strip_prefix(&ws_prefix)
        .map(|s| s.trim_start_matches('/'))
        .unwrap_or(norm_uri.as_str());

    let target_line = line_opt.unwrap_or(1);

    if let Some(spans) = index.function_spans.get(stripped) {
        if let Some(span) = spans
            .iter()
            .find(|s| target_line >= s.start_line && target_line <= s.end_line)
        {
            if span.is_test_scope {
                return (
                    ReachabilityStatus::DevOrTestOnly,
                    Vec::new(),
                    format!(
                        "Finding at {}:{} resides inside #[cfg(test)] function '{}'",
                        stripped, target_line, span.qual_name
                    ),
                );
            }
            if let Some(ref trace) = span.entrypoint_trace {
                return (
                    ReachabilityStatus::VerifiedReachable,
                    trace.clone(),
                    format!(
                        "Verified entrypoint call path to finding at {}:{}",
                        stripped, target_line
                    ),
                );
            }
        }
    }

    let in_test_dir = stripped.starts_with("tests/")
        || stripped.contains("/tests/")
        || stripped.starts_with("benches/")
        || stripped.contains("/benches/")
        || stripped.starts_with("examples/")
        || stripped.contains("/examples/");

    if in_test_dir {
        (
            ReachabilityStatus::DevOrTestOnly,
            Vec::new(),
            format!("Finding located inside test/example file '{}'", stripped),
        )
    } else {
        (
            ReachabilityStatus::ImportedInSource,
            Vec::new(),
            format!("Finding in production Rust source file '{}'", stripped),
        )
    }
}
