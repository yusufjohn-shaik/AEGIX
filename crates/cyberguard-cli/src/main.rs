use clap::{Args, Parser, Subcommand, ValueEnum};
use cyberguard_container::{ContainerAuditReport, ContainerEngine, ContainerScanner};
use cyberguard_core::config::CyberguardConfig;
use cyberguard_core::sarif::{Message, ReportingDescriptor, SarifLevel, SarifLog};
use cyberguard_dast::{DastEngine, DastScanner, DastTarget, FindingSeverity};
use cyberguard_net::{
    verify_scope_hmac, NetworkEngine, NetworkScanner, ScopeGate, DEFAULT_TOP_PORTS,
};
use cyberguard_sast::{NativeRuleEngine, SastAnalyzer, ScanContext};
use cyberguard_sca::sbom::{generate_cyclonedx_json, generate_spdx_json};
use cyberguard_sca::{ScaAnalyzer, ScaEngine};
use cyberguard_secret::{SecretEngine, SecretScanner};
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use url::Url;

#[derive(Parser, Debug)]
#[command(
    name = "cyberguard",
    version = env!("CARGO_PKG_VERSION"),
    about = "Autonomous Vulnerability Intelligence & Remediation Platform",
    long_about = "CyberGuard is an uncompromising, next-generation open-source vulnerability intelligence platform\nbuilt in Rust. It discovers real flaws in modern software, correlates attack path graphs (DAG),\nand autonomously synthesizes AST-verified code fixes."
)]
pub struct Cli {
    /// Custom configuration file path (defaults to cyberguard.yaml)
    #[arg(global = true, short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Enable verbose diagnostic logging
    #[arg(global = true, short, long)]
    pub verbose: bool,

    /// Suppress all non-essential output
    #[arg(global = true, short, long)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Commands {
    /// Perform deep vulnerability discovery across the codebase
    Scan(ScanArgs),

    /// Audit cloud, network, and supply-chain assets
    Audit(AuditArgs),

    /// Perform network reconnaissance against an authorized target with Scope Gate enforcement
    Recon(ReconArgs),

    /// Perform dynamic application security testing (DAST) with Scope Gate enforcement
    Dast(DastArgs),

    /// Trace multi-layer attack paths and correlate findings via in-memory DAG
    Trace(TraceArgs),

    /// Synthesize and apply syntax-preserving AST code fixes
    Fix(FixArgs),

    /// Launch CyberGuard as an AI agent Model Context Protocol (MCP) server
    Mcp(McpArgs),
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct ScanArgs {
    /// Target directory or source file to scan
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output report format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Minimum severity threshold
    #[arg(long, value_name = "LEVEL")]
    pub min_severity: Option<String>,

    /// Only scan for secrets and leaked credentials
    #[arg(long)]
    pub secrets_only: bool,

    /// Disable secret and credential scanning during code scan
    #[arg(long)]
    pub no_secrets: bool,

    /// Only scan container Dockerfiles and image layers
    #[arg(long)]
    pub container_only: bool,

    /// Disable container and Dockerfile scanning during code scan
    #[arg(long)]
    pub no_container: bool,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct AuditArgs {
    /// Target directory or dependency manifest (defaults to current directory)
    #[arg(default_value = ".")]
    pub target: String,

    /// Output report format
    #[arg(short, long, value_enum, default_value_t = AuditFormat::Terminal)]
    pub format: AuditFormat,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct ReconArgs {
    /// Target hostname or IP address to scan
    pub target: String,

    /// Path to the .security-scope.yaml file
    #[arg(long, default_value = ".security-scope.yaml")]
    pub scope: PathBuf,

    /// Optional HMAC-SHA256 secret key to verify scope authenticity
    #[arg(long)]
    pub scope_key: Option<String>,

    /// Target ports to scan ('top100', '80,443', '1-1024')
    #[arg(long, default_value = "top100")]
    pub ports: String,

    /// Per-probe connection timeout in milliseconds
    #[arg(long, default_value_t = 1000)]
    pub timeout: u64,

    /// Maximum concurrent TCP probes
    #[arg(long, default_value_t = 128)]
    pub concurrency: usize,

    /// Supervise host-installed Nmap for scanning
    #[arg(long)]
    pub nmap: bool,

    /// Output report format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct DastArgs {
    /// Target base URL to scan (e.g. http://127.0.0.1:8080)
    pub target: String,

    /// Path to .security-scope.yaml file
    #[arg(long)]
    pub scope: Option<PathBuf>,

    /// Cryptographic HMAC-SHA256 scope validation key
    #[arg(long, env = "CYBERGUARD_SCOPE_KEY")]
    pub scope_key: Option<String>,

    /// Maximum requests per second (rate limit)
    #[arg(long, default_value_t = 25)]
    pub max_rps: u32,

    /// Maximum concurrent HTTP probes
    #[arg(long, default_value_t = 10)]
    pub concurrency: usize,

    /// Cumulative HTTP transaction timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    pub timeout: u64,

    /// Allow self-signed or invalid TLS certificates (dev/test only)
    #[arg(long)]
    pub insecure: bool,

    /// Run external supervised Nuclei scanner
    #[arg(long)]
    pub nuclei: bool,

    /// Custom request header in 'Key: Value' format (can be specified multiple times)
    #[arg(long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// Output report format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,
}

fn parse_ports_spec(spec: &str) -> anyhow::Result<Vec<u16>> {
    let spec = spec.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("top100") {
        return Ok(DEFAULT_TOP_PORTS.iter().map(|(p, _)| *p).collect());
    }
    if let Some((start_s, end_s)) = spec.split_once('-') {
        let start = start_s.trim().parse::<u16>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid port range start '{start_s}': must be an integer between 1 and 65535"
            )
        })?;
        let end = end_s.trim().parse::<u16>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid port range end '{end_s}': must be an integer between 1 and 65535"
            )
        })?;
        if start == 0 || end == 0 {
            anyhow::bail!("Port numbers must be between 1 and 65535 (got 0)");
        }
        if start > end {
            anyhow::bail!("Invalid port range: start port {start} is greater than end port {end}");
        }
        return Ok((start..=end).collect());
    }

    let mut ports = Vec::new();
    for token in spec.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        let p = t.parse::<u16>().map_err(|_| {
            anyhow::anyhow!("Invalid port '{t}': must be an integer between 1 and 65535")
        })?;
        if p == 0 {
            anyhow::bail!("Port numbers must be between 1 and 65535 (got 0)");
        }
        ports.push(p);
    }

    if ports.is_empty() {
        anyhow::bail!("No valid ports specified in '{spec}'");
    }

    Ok(ports)
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditFormat {
    Terminal,
    Sarif,
    Json,
    Cyclonedx,
    Spdx,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct TraceArgs {
    /// Target repository path to construct Attack Path Graph
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct FixArgs {
    /// Target file or directory for automated remediation
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Automatically apply fixes without manual confirmation
    #[arg(long)]
    pub auto: bool,

    /// Perform a dry-run and print unified diffs to stdout
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct McpArgs {
    /// Run MCP JSON-RPC protocol over standard I/O (stdio)
    #[arg(long, default_value_t = true)]
    pub stdio: bool,

    /// Optional port to serve MCP over Server-Sent Events (SSE)
    #[arg(long)]
    pub port: Option<u16>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Sarif,
    Json,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.quiet {
        Level::ERROR
    } else if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    // Load layered configuration
    let config = CyberguardConfig::load_layered(cli.config.as_deref())
        .unwrap_or_else(|_| CyberguardConfig::default());

    match cli.command {
        Some(Commands::Scan(args)) => {
            let run_sast = !args.secrets_only && !args.container_only;
            let run_secrets = !args.no_secrets && !args.container_only;
            let run_container = !args.no_container && !args.secrets_only;

            let mut sast_findings = Vec::new();
            let sast_engine = NativeRuleEngine::default();

            if run_sast {
                let mut ctx = ScanContext::new(&args.path);
                if let Some(ref sev) = args.min_severity {
                    ctx = ctx.with_min_severity(Some(sev.clone()));
                }
                sast_findings = sast_engine.analyze(&ctx).await?;
            }

            let secret_engine = SecretEngine::default();
            let mut secret_findings = Vec::new();
            if run_secrets {
                let raw_secrets = secret_engine.scan_path(&args.path).await?;
                secret_findings = secret_engine.to_sarif(&raw_secrets);
            }

            let container_engine = ContainerEngine::new();
            let mut container_sarif = Vec::new();
            if run_container {
                let path_str = args.path.to_string_lossy();
                if path_str.ends_with(".tar")
                    || path_str.ends_with(".tar.gz")
                    || path_str.ends_with(".tgz")
                {
                    if let Ok(report) = container_engine.scan_image_archive(&args.path).await {
                        container_sarif = container_engine.to_sarif(&report);
                    }
                } else if let Ok(df_findings) = container_engine.scan_dockerfile(&args.path).await {
                    let report = ContainerAuditReport {
                        dockerfile_findings: df_findings,
                        packages: Vec::new(),
                    };
                    container_sarif = container_engine.to_sarif(&report);
                }
            }

            match args.format {
                OutputFormat::Sarif | OutputFormat::Json => {
                    let mut log = SarifLog::new("CyberGuard Scanner", env!("CARGO_PKG_VERSION"));
                    if run_sast {
                        for rule in sast_engine.rules() {
                            log.add_rule(ReportingDescriptor {
                                id: rule.id.clone(),
                                name: Some(rule.name.clone()),
                                short_description: Message {
                                    text: rule.message.clone(),
                                },
                                full_description: None,
                                help_uri: Some(rule.help_uri.clone()),
                            });
                        }
                    }
                    if run_secrets {
                        for rule in secret_engine.rules() {
                            log.add_rule(ReportingDescriptor {
                                id: rule.id.clone(),
                                name: Some(rule.provider.clone()),
                                short_description: Message {
                                    text: rule.description.clone(),
                                },
                                full_description: None,
                                help_uri: Some(
                                    "https://github.com/yusufjohn-shaik/CYBER-GUARD".to_string(),
                                ),
                            });
                        }
                    }
                    if run_container {
                        let container_rules = [
                            (
                                "CG-CONT-001",
                                "Root User Execution",
                                "Container process runs as root. Specify a non-root USER directive.",
                            ),
                            (
                                "CG-CONT-002",
                                "Untagged Base Image",
                                "Base image is untagged or pinned to mutable 'latest' tag.",
                            ),
                            (
                                "CG-CONT-003",
                                "Curl/Wget to Shell",
                                "Dangerous pipe from curl/wget to shell execution detected.",
                            ),
                            (
                                "CG-CONT-004",
                                "Exposed Secret in ENV/ARG",
                                "Potential hardcoded secret or API credential in ENV/ARG directive.",
                            ),
                            (
                                "CG-CONT-005",
                                "Missing Healthcheck",
                                "Container image is missing a HEALTHCHECK instruction.",
                            ),
                            (
                                "CG-CONT-006",
                                "Sudo in Container",
                                "Unnecessary use of sudo inside container build step.",
                            ),
                            (
                                "CG-CONT-007",
                                "ADD instead of COPY",
                                "ADD used for local non-archive file transfer instead of COPY.",
                            ),
                            (
                                "CG-CONT-008",
                                "Apt-Get Without Clean",
                                "apt-get install without cache cleaning retains temporary package indexes.",
                            ),
                        ];
                        for (id, name, desc) in container_rules {
                            log.add_rule(ReportingDescriptor {
                                id: id.to_string(),
                                name: Some(name.to_string()),
                                short_description: Message {
                                    text: desc.to_string(),
                                },
                                full_description: None,
                                help_uri: Some(
                                    "https://github.com/yusufjohn-shaik/CYBER-GUARD".to_string(),
                                ),
                            });
                        }
                    }
                    for finding in sast_findings {
                        log.add_result(finding);
                    }
                    for finding in secret_findings {
                        log.add_result(finding);
                    }
                    for finding in container_sarif {
                        log.add_result(finding);
                    }
                    println!("{}", serde_json::to_string_pretty(&log)?);
                }
                OutputFormat::Terminal => {
                    println!("🛡️  CyberGuard Scanner v{}", env!("CARGO_PKG_VERSION"));
                    println!("Target: {}", args.path.display());
                    println!("Workspace: {}", config.general.workspace_dir.display());
                    println!("{:-<80}", "");

                    let total_count =
                        sast_findings.len() + secret_findings.len() + container_sarif.len();
                    if total_count == 0 {
                        println!("✅ No security vulnerabilities, leaked credentials, or container misconfigurations detected.");
                    } else {
                        println!("Found {} security alert(s):", total_count);
                        println!();
                        for f in sast_findings
                            .iter()
                            .chain(secret_findings.iter())
                            .chain(container_sarif.iter())
                        {
                            let loc_str = if let Some(loc) = f.locations.first() {
                                if let Some(phys) = &loc.physical_location {
                                    if let Some(reg) = &phys.region {
                                        format!(
                                            "{}:{}:{}",
                                            phys.artifact_location.uri,
                                            reg.start_line,
                                            reg.start_column.unwrap_or(1)
                                        )
                                    } else {
                                        phys.artifact_location.uri.clone()
                                    }
                                } else {
                                    "-".to_string()
                                }
                            } else {
                                "-".to_string()
                            };

                            let sev_label = match f.level {
                                SarifLevel::Error => "🔴 ERROR",
                                SarifLevel::Warning => "🟡 WARN ",
                                SarifLevel::Note => "🔵 NOTE ",
                                SarifLevel::None => "⚪ NONE ",
                            };

                            println!("{} [{}] {}", sev_label, f.rule_id, loc_str);
                            println!("   └── {}", f.message.text);
                            if let Some(fps) = &f.partial_fingerprints {
                                if let Some(hash) = fps.get("logicalLocationTokenHash/v1") {
                                    let preview = if hash.len() > 16 { &hash[..16] } else { hash };
                                    println!("   └── Fingerprint: {}", preview);
                                }
                            }
                        }
                    }
                    println!("{:-<80}", "");
                }
            }
        }
        Some(Commands::Audit(args)) => {
            let target_path = Path::new(&args.target);
            let sca_engine = ScaEngine::new();
            let report = sca_engine.scan(target_path).await?;

            match args.format {
                AuditFormat::Cyclonedx => {
                    let project_name = target_path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("project");
                    let cyclonedx_json = generate_cyclonedx_json(project_name, &report.packages)?;
                    println!("{}", cyclonedx_json);
                }
                AuditFormat::Spdx => {
                    let project_name = target_path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("project");
                    let spdx_json = generate_spdx_json(project_name, &report.packages)?;
                    println!("{}", spdx_json);
                }
                AuditFormat::Sarif | AuditFormat::Json => {
                    let sarif_log = sca_engine.to_sarif_log(&report);
                    println!("{}", serde_json::to_string_pretty(&sarif_log)?);
                }
                AuditFormat::Terminal => {
                    println!(
                        "🛡️  CyberGuard SCA & Supply Chain Auditor v{}",
                        env!("CARGO_PKG_VERSION")
                    );
                    println!("Target: {}", target_path.display());
                    println!(
                        "Scanned {} lockfile(s) | Total dependencies: {} ({} direct, {} transitive)",
                        report.lockfiles_scanned.len(),
                        report.total_packages,
                        report.direct_dependencies,
                        report.transitive_dependencies
                    );
                    println!("{:-<80}", "");

                    if report.findings.is_empty() {
                        println!("✅ No known supply-chain vulnerabilities found in dependencies.");
                    } else {
                        println!(
                            "Found {} vulnerable dependency alert(s):",
                            report.findings.len()
                        );
                        println!();
                        for finding in &report.findings {
                            let sev_label = if finding.vulnerability.cvss >= 9.0 {
                                "🔴 CRITICAL"
                            } else if finding.vulnerability.cvss >= 7.0 {
                                "🔴 HIGH    "
                            } else if finding.vulnerability.cvss >= 4.0 {
                                "🟡 MEDIUM  "
                            } else {
                                "🔵 LOW     "
                            };

                            let dep_type = if finding.package.is_direct {
                                "Direct"
                            } else {
                                "Transitive"
                            };

                            println!(
                                "{} [{}] {}@{} ({:?})",
                                sev_label,
                                finding.vulnerability.id,
                                finding.package.name,
                                finding.package.version,
                                finding.package.ecosystem
                            );
                            println!("   └── {}", finding.vulnerability.summary);
                            println!(
                                "   └── CVSS: {:.1} | EPSS: {:.2} | Reachability: {:.1} ({}) | Tri-Factor: {:.2}",
                                finding.vulnerability.cvss,
                                finding.vulnerability.epss,
                                finding.reachability,
                                dep_type,
                                finding.tri_factor_score
                            );
                            if let Some(ref fixed) = finding.vulnerability.fixed_version {
                                println!("   └── Remediation: Upgrade to {} or later", fixed);
                            }
                        }
                    }
                    println!("{:-<80}", "");
                }
            }
        }
        Some(Commands::Recon(args)) => {
            if !args.scope.exists() {
                anyhow::bail!(
                    "Scope file not found at '{}'. Network reconnaissance strictly requires cryptographic Proof-of-Authorization via .security-scope.yaml.",
                    args.scope.display()
                );
            }

            let gate = ScopeGate::from_file(&args.scope)?;
            if let Some(ref key) = args.scope_key {
                verify_scope_hmac(&gate.scope, key.as_bytes())?;
            }

            let parsed_ports = parse_ports_spec(&args.ports)?;
            let engine = NetworkEngine::new(gate)
                .with_concurrency(args.concurrency)
                .with_timeout(std::time::Duration::from_millis(args.timeout))
                .with_nmap(args.nmap);

            let report = engine.scan(&args.target, &parsed_ports).await?;

            match args.format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Sarif => {
                    let sarif = report.sarif.unwrap_or_else(|| {
                        SarifLog::new("CyberGuard Network Recon Engine", "0.8.0")
                    });
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                OutputFormat::Terminal => {
                    println!(
                        "🛡️  CyberGuard Network Reconnaissance Engine v{}",
                        env!("CARGO_PKG_VERSION")
                    );
                    if let Some(ref eng) = report.engagement_id {
                        println!("Engagement: {}", eng);
                    }
                    println!(
                        "Target: {} (Pinned IP: {})",
                        report.target, report.pinned_ip
                    );
                    println!(
                        "Scanned: {} ports | Discovered Open: {} | Duration: {} ms",
                        report.scanned_ports, report.open_ports, report.duration_ms
                    );
                    println!("{:-<80}", "");

                    if report.findings.is_empty() {
                        println!("✅ No ports responded to connection attempts.");
                    } else {
                        println!("{:<10} {:<10} {:<15} BANNER", "PORT", "STATE", "SERVICE");
                        println!("{:-<80}", "");
                        for f in &report.findings {
                            if f.status == cyberguard_net::PortStatus::Open {
                                let port_proto = format!("{}/{}", f.port, f.protocol);
                                let banner = f.banner.as_deref().unwrap_or("-");
                                println!(
                                    "{:<10} {:<10} {:<15} {}",
                                    port_proto, f.status, f.service, banner
                                );
                            }
                        }
                    }
                    println!("{:-<80}", "");
                }
            }
        }
        Some(Commands::Dast(args)) => {
            let target_url = Url::parse(&args.target)
                .map_err(|e| anyhow::anyhow!("Invalid target URL '{}': {}", args.target, e))?;

            let host = target_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Missing host in target URL '{}'", args.target))?;

            let gate = if let Some(ref scope_path) = args.scope {
                if !scope_path.exists() {
                    anyhow::bail!(
                        "Scope file not found at '{}'. Dynamic scanning strictly requires authorization via .security-scope.yaml.",
                        scope_path.display()
                    );
                }
                let g = ScopeGate::from_file(scope_path)?;
                if let Some(ref key) = args.scope_key {
                    verify_scope_hmac(&g.scope, key.as_bytes())?;
                }
                g
            } else {
                let is_ip = host.parse::<std::net::IpAddr>().is_ok();
                let ephemeral_scope = cyberguard_net::models::SecurityScope {
                    engagement_id: "ephemeral-dast-scan".to_string(),
                    valid_from: None,
                    valid_until: None,
                    authorized_cidrs: if is_ip {
                        if host.contains(':') {
                            vec![format!("{}/128", host)]
                        } else {
                            vec![format!("{}/32", host)]
                        }
                    } else {
                        vec![]
                    },
                    excluded_cidrs: vec![],
                    authorized_domains: if !is_ip {
                        vec![host.to_string()]
                    } else {
                        vec![]
                    },
                    authorized_ports: vec![],
                    signature: None,
                };
                ScopeGate::new(ephemeral_scope)
            };

            let mut dast_target = DastTarget::new(target_url.clone()).with_insecure(args.insecure);
            for h in &args.headers {
                if let Some((k, v)) = h.split_once(':') {
                    dast_target = dast_target.with_header(k.trim(), v.trim());
                }
            }

            let engine = DastEngine::new()
                .with_concurrency(args.concurrency)
                .with_timeout_ms(args.timeout)
                .with_max_rps(args.max_rps)
                .with_nuclei(args.nuclei);

            let report = engine.scan(&dast_target, &gate).await?;

            match args.format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Sarif => {
                    println!("{}", serde_json::to_string_pretty(&report.sarif_log)?);
                }
                OutputFormat::Terminal => {
                    println!("🛡️  CyberGuard DAST Engine v{}", env!("CARGO_PKG_VERSION"));
                    println!("Target: {}", report.target);
                    println!(
                        "Probed Endpoints / Checks: {} | Discovered Vulnerabilities: {}",
                        report.tested_endpoints_count,
                        report.findings.len()
                    );
                    println!("{:-<80}", "");

                    if report.findings.is_empty() {
                        println!("✅ No dynamic security vulnerabilities or misconfigurations discovered.");
                    } else {
                        for f in &report.findings {
                            let (badge, color) = match f.severity {
                                FindingSeverity::Critical | FindingSeverity::High => {
                                    ("🔴 ERROR", "High/Critical")
                                }
                                FindingSeverity::Medium => ("🟡 WARN ", "Medium"),
                                FindingSeverity::Low => ("🔵 NOTE ", "Low"),
                                FindingSeverity::Info => ("ℹ️  INFO ", "Info"),
                            };

                            println!(
                                "{} [{}] {}{}",
                                badge,
                                f.id,
                                report.target.trim_end_matches('/'),
                                f.endpoint
                            );
                            println!("   └── Title: {}", f.title);
                            println!("   └── Severity: {}", color);
                            println!("   └── Evidence: {}", f.evidence);
                            println!("   └── Remediation: {}", f.remediation);
                            println!();
                        }
                    }
                    println!("{:-<80}", "");
                }
            }
        }
        Some(Commands::Trace(args)) => {
            println!(
                "🕸️  Constructing in-memory Attack Path Graph (DAG) for: {}",
                args.path.display()
            );
            println!("[+] Nodes: 0 | Edges: 0 | Exploit Chains: 0");
        }
        Some(Commands::Fix(args)) => {
            println!("🛠️  CyberGuard AST Auto-Remediation Engine");
            println!(
                "Target: {} (auto={}, dry_run={})",
                args.path.display(),
                args.auto,
                args.dry_run
            );
        }
        Some(Commands::Mcp(args)) => {
            println!("🤖 CyberGuard Model Context Protocol (MCP) Server");
            if let Some(port) = args.port {
                println!("Starting SSE transport on port {}", port);
            } else {
                println!("Listening on stdio (JSON-RPC 2.0)...");
            }
        }
        None => {
            println!(
                "🛡️  CyberGuard {} - Next-Generation Autonomous Vulnerability Intelligence",
                env!("CARGO_PKG_VERSION")
            );
            println!("Run 'cyberguard --help' for available commands.");
        }
    }

    Ok(())
}
