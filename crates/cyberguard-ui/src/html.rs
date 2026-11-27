//! Self-contained executive HTML and printable PDF report generator.

#![deny(unsafe_code)]

use crate::error::UiError;
use crate::models::ExecutiveReport;
use crate::traits::ReportGenerator;

#[derive(Default, Clone)]
pub struct DefaultHtmlReportGenerator;

impl DefaultHtmlReportGenerator {
    pub fn new() -> Self {
        Self
    }

    fn render_svg_gauge(score: u32, color_hex: &str) -> String {
        let radius = 54.0;
        let circumference = 2.0 * std::f64::consts::PI * radius;
        let offset = circumference * (1.0 - (score as f64 / 100.0));

        format!(
            r##"<svg class="posture-gauge" viewBox="0 0 140 140">
  <circle cx="70" cy="70" r="{radius}" fill="none" stroke="#334155" stroke-width="12" />
  <circle cx="70" cy="70" r="{radius}" fill="none" stroke="{color_hex}" stroke-width="12"
          stroke-dasharray="{circumference:.2}" stroke-dashoffset="{offset:.2}"
          stroke-linecap="round" transform="rotate(-90 70 70)" />
  <text x="70" y="76" text-anchor="middle" font-size="28" font-weight="700" fill="#f8fafc">{score}</text>
  <text x="70" y="96" text-anchor="middle" font-size="12" fill="#94a3b8">/ 100</text>
</svg>"##
        )
    }

    fn render_severity_bars(report: &ExecutiveReport) -> String {
        let max_val = std::cmp::max(
            1,
            std::cmp::max(
                report.severities.critical,
                std::cmp::max(
                    report.severities.high,
                    std::cmp::max(report.severities.medium, report.severities.low),
                ),
            ),
        ) as f64;

        let crit_w = (report.severities.critical as f64 / max_val * 100.0).round();
        let high_w = (report.severities.high as f64 / max_val * 100.0).round();
        let med_w = (report.severities.medium as f64 / max_val * 100.0).round();
        let low_w = (report.severities.low as f64 / max_val * 100.0).round();

        format!(
            r#"<div class="bars-container">
  <div class="bar-row">
    <span class="bar-label crit">Critical ({})</span>
    <div class="bar-track"><div class="bar-fill crit" style="width: {}%;"></div></div>
  </div>
  <div class="bar-row">
    <span class="bar-label high">High ({})</span>
    <div class="bar-track"><div class="bar-fill high" style="width: {}%;"></div></div>
  </div>
  <div class="bar-row">
    <span class="bar-label med">Medium ({})</span>
    <div class="bar-track"><div class="bar-fill med" style="width: {}%;"></div></div>
  </div>
  <div class="bar-row">
    <span class="bar-label low">Low ({})</span>
    <div class="bar-track"><div class="bar-fill low" style="width: {}%;"></div></div>
  </div>
</div>"#,
            report.severities.critical,
            crit_w,
            report.severities.high,
            high_w,
            report.severities.medium,
            med_w,
            report.severities.low,
            low_w
        )
    }
}

impl ReportGenerator for DefaultHtmlReportGenerator {
    fn generate_html(&self, report: &ExecutiveReport) -> Result<String, UiError> {
        let gauge_svg =
            Self::render_svg_gauge(report.posture.score, report.posture.grade.color_hex());
        let bars_html = Self::render_severity_bars(report);

        let mut engine_tags = String::new();
        for ec in &report.engine_breakdown {
            engine_tags.push_str(&format!(
                r#"<span class="engine-badge">{}: <strong>{}</strong></span>"#,
                ec.engine, ec.count
            ));
        }

        let mut compliance_rows = String::new();
        for comp in &report.compliance {
            let status_class = if comp.status == "Passed"
                || comp.status == "Compliant"
                || comp.status == "Clean"
            {
                "status-pass"
            } else {
                "status-fail"
            };
            compliance_rows.push_str(&format!(
                r#"<tr>
  <td><strong>{}</strong></td>
  <td>{}</td>
  <td><span class="badge {}">{}</span></td>
  <td class="text-right">{} finding(s)</td>
</tr>"#,
                comp.framework, comp.requirement, status_class, comp.status, comp.finding_count
            ));
        }

        let mut findings_rows = String::new();
        if report.top_findings.is_empty() {
            findings_rows.push_str(
                r#"<tr><td colspan="6" class="text-center">✅ No security vulnerabilities detected in target.</td></tr>"#,
            );
        } else {
            for f in &report.top_findings {
                let sev_class = match f.severity.as_str() {
                    "Critical" => "sev-crit",
                    "High" => "sev-high",
                    "Medium" => "sev-med",
                    _ => "sev-low",
                };
                findings_rows.push_str(&format!(
                    r#"<tr>
  <td><code>{}</code></td>
  <td><span class="badge {}">{}</span></td>
  <td><strong>{}</strong></td>
  <td><code>{}:{}</code></td>
  <td>{}</td>
  <td><span class="remediation">{}</span></td>
</tr>"#,
                    f.rule_id,
                    sev_class,
                    f.severity,
                    f.title,
                    f.file_path,
                    f.line,
                    f.engine,
                    f.remediation
                ));
            }
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{}</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #151e2e;
      --border: #233149;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #3b82f6;
      --pass: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2.5rem 2rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }}
    h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; }}
    .meta {{ font-size: 0.875rem; color: var(--text-muted); margin-top: 0.25rem; }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.5rem;
    }}
    .card-title {{
      font-size: 0.8125rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
      font-weight: 600;
    }}
    .kpi-gauge-card {{
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .gauge-info h2 {{ font-size: 2rem; font-weight: 800; }}
    .gauge-info p {{ font-size: 0.875rem; color: var(--text-muted); }}
    .posture-gauge {{ width: 100px; height: 100px; }}
    .kpi-stat {{ font-size: 2.5rem; font-weight: 800; margin-bottom: 0.25rem; }}
    .bars-container {{ display: flex; flex-direction: column; gap: 0.5rem; }}
    .bar-row {{ display: flex; align-items: center; gap: 0.75rem; font-size: 0.8125rem; }}
    .bar-label {{ width: 95px; font-weight: 600; }}
    .bar-label.crit {{ color: var(--crit); }}
    .bar-label.high {{ color: var(--high); }}
    .bar-label.med {{ color: var(--med); }}
    .bar-label.low {{ color: var(--low); }}
    .bar-track {{ flex: 1; height: 8px; background: #233149; border-radius: 4px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 4px; }}
    .bar-fill.crit {{ background: var(--crit); }}
    .bar-fill.high {{ background: var(--high); }}
    .bar-fill.med {{ background: var(--med); }}
    .bar-fill.low {{ background: var(--low); }}
    .engines-bar {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 2rem; }}
    .engine-badge {{
      background: #1e293b;
      border: 1px solid var(--border);
      padding: 0.375rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.8125rem;
    }}
    h2.section-heading {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; color: #fff; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
      margin-bottom: 2.5rem;
    }}
    th, td {{
      padding: 0.875rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      background: #131c2d;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }}
    tr:hover td {{ background: #1a2538; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
    }}
    .sev-crit {{ background: rgba(239, 68, 68, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
    .sev-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .sev-med {{ background: rgba(234, 179, 8, 0.2); color: var(--med); border: 1px solid var(--med); }}
    .sev-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
    .status-pass {{ background: rgba(16, 185, 129, 0.2); color: var(--pass); border: 1px solid var(--pass); }}
    .status-fail {{ background: rgba(239, 68, 68, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
    .remediation {{ color: #38bdf8; font-size: 0.8125rem; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.8125rem; }}
    .text-right {{ text-align: right; }}
    .text-center {{ text-align: center; }}
    footer {{
      margin-top: 3rem;
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      font-size: 0.8125rem;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
    }}
    @media print {{
      body {{ background: #ffffff !important; color: #000000 !important; padding: 0; }}
      .card {{ background: #ffffff !important; border: 1px solid #ccc !important; }}
      th {{ background: #f0f0f0 !important; color: #333 !important; }}
      td {{ border-bottom: 1px solid #ddd !important; }}
      .badge {{ border: 1px solid #000 !important; color: #000 !important; background: transparent !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>{}</h1>
        <div class="meta">Target: <code>{}</code> &bull; Generated: {} &bull; Aegix Autonomous Security</div>
      </div>
      <div>
        <span class="badge" style="border: 1px solid #38bdf8; color: #38bdf8;">Executive Edition</span>
      </div>
    </header>

    <div class="kpi-grid">
      <div class="card kpi-gauge-card">
        <div class="gauge-info">
          <div class="card-title">Security Posture Score</div>
          <h2>Grade: {}</h2>
          <p>{}</p>
        </div>
        {}
      </div>

      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="kpi-stat">{}</div>
        <p class="meta">Across {} detection engines</p>
      </div>

      <div class="card">
        <div class="card-title">Attack Choke Points</div>
        <div class="kpi-stat" style="color: #f59e0b;">{}</div>
        <p class="meta">Remediation priority choke points</p>
      </div>

      <div class="card">
        <div class="card-title">Severity Spectrum</div>
        {}
      </div>
    </div>

    <h2 class="section-heading">Coverage Breakdown</h2>
    <div class="engines-bar">
      {}
    </div>

    <h2 class="section-heading">Regulatory & Compliance Scorecard</h2>
    <div class="card" style="padding: 0; overflow: hidden; margin-bottom: 2rem;">
      <table>
        <thead>
          <tr>
            <th>Framework</th>
            <th>Standard Requirement</th>
            <th>Compliance Status</th>
            <th class="text-right">Open Findings</th>
          </tr>
        </thead>
        <tbody>
          {}
        </tbody>
      </table>
    </div>

    <h2 class="section-heading">Prioritized Vulnerabilities & Remediation Plan</h2>
    <div class="card" style="padding: 0; overflow: hidden;">
      <table>
        <thead>
          <tr>
            <th>Rule ID</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Location</th>
            <th>Engine</th>
            <th>Remediation Directive</th>
          </tr>
        </thead>
        <tbody>
          {}
        </tbody>
      </table>
    </div>

    <footer>
      <div>Generated autonomously by <strong>Aegix Security Platform</strong> &bull; Air-Gapped High Assurance Engine</div>
      <div>Confidential &mdash; Internal Executive Briefing</div>
    </footer>
  </div>
</body>
</html>"#,
            report.title,
            report.title,
            report.target,
            report.generated_at,
            report.posture.grade.as_str().chars().next().unwrap_or('A'),
            report.posture.label,
            gauge_svg,
            report.total_findings,
            report.engine_breakdown.len(),
            report.attack_choke_points,
            bars_html,
            engine_tags,
            compliance_rows,
            findings_rows
        );

        Ok(html)
    }
}
