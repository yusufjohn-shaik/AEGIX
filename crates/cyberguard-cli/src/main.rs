#![deny(unsafe_code)]

use clap::{Args, Parser, Subcommand, ValueEnum};
use cyberguard_api::{ApiConfig, ApiEngine, ApiScanner};
use cyberguard_cloud::{CloudEngine, CloudScanner};
use cyberguard_container::{ContainerAuditReport, ContainerEngine, ContainerScanner};
use cyberguard_core::config::CyberguardConfig;
use cyberguard_core::sarif::{Message, ReportingDescriptor, SarifLevel, SarifLog, SarifResult};
use cyberguard_core::AegixBaseline;
use cyberguard_dast::{DastEngine, DastScanner, DastTarget, FindingSeverity};
use cyberguard_iac::{IacEngine, IacScanner};
use cyberguard_net::{
    verify_scope_hmac, NetworkEngine, NetworkScanner, ScopeGate, DEFAULT_TOP_PORTS,
};
use cyberguard_pipeline::{PipelineEngine, PipelineScanner};
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
    name = "aegix",
    version = env!("CARGO_PKG_VERSION"),
    about = "Autonomous Vulnerability Intelligence & Remediation Platform",
    long_about = "Aegix is a high-performance open-source vulnerability intelligence platform\nbuilt in pure Rust. It discovers flaws across modern stacks, correlates attack path graphs (DAG),\nand autonomously synthesizes AST-verified code fixes."
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

    /// Audit and fuzz API contracts (OpenAPI 3.0/3.1, Swagger 2.0)
    Api(ApiArgs),

    /// Audit multi-cloud infrastructure and IAM entitlements (CSPM & CIEM)
    Cloud(CloudArgs),

    /// Audit Infrastructure as Code (Kubernetes YAML/JSON, Helm, Terraform)
    Iac(IacArgs),

    /// Audit CI/CD pipelines (GitHub Actions, GitLab CI) and SLSA provenance attestations
    Pipeline(PipelineArgs),

    /// Audit mobile applications (Android APK, AndroidManifest.xml, iOS IPA, Info.plist, Entitlements)
    Mobile(MobileArgs),

    /// Threat modeling, STRIDE classification, and MITRE ATT&CK Matrix generation
    Threat(ThreatArgs),

    /// Trace multi-layer attack paths and correlate findings via in-memory DAG
    Trace(TraceArgs),

    /// Prioritize vulnerabilities via Tri-Factor score (CVSS x EPSS x Reachability) and Rust reachability
    Risk(RiskArgs),

    /// Synthesize and apply syntax-preserving AST code fixes
    Fix(FixArgs),

    /// Launch Aegix as an AI agent Model Context Protocol (MCP) server
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

    /// Save discovered findings as a new baseline snapshot file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,

    /// Filter findings against a baseline snapshot file, suppressing known alerts
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

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

#[derive(Args, Debug, PartialEq, Eq)]
pub struct ApiArgs {
    /// Path to OpenAPI/Swagger specification file (.yaml, .yml, .json)
    pub spec_path: PathBuf,

    /// Target base URL for live API contract fuzzing (e.g. https://api.example.com)
    #[arg(long, value_name = "URL")]
    pub target: Option<String>,

    /// Enable active contract boundary mutation fuzzing
    #[arg(long, default_value_t = false)]
    pub fuzz: bool,

    /// Allow fuzzing potentially destructive HTTP methods (POST, PUT, DELETE, PATCH)
    #[arg(long, default_value_t = false)]
    pub allow_destructive: bool,

    /// Dry run: plan and display planned fuzzer payloads without transmitting HTTP requests
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Path to ScopeGate authorization file or target scope definition
    #[arg(long, value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Scope authorization HMAC key for verified enterprise scans
    #[arg(long, value_name = "KEY", env = "CYBERGUARD_SCOPE_KEY")]
    pub scope_key: Option<String>,

    /// Maximum requests per second to avoid triggering live rate limits
    #[arg(long, default_value_t = 25)]
    pub max_rps: u32,

    /// HTTP request timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    pub timeout: u64,

    /// Custom HTTP header to inject (repeatable, e.g. -H "Authorization: Bearer token")
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// Allow insecure TLS connections (skip certificate verification)
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Execute Schemathesis property-based fuzzing via cyberguard-proc runner
    #[arg(long, default_value_t = false)]
    pub schemathesis: bool,

    /// Path to baseline snapshot file to suppress known issues
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Output report format: terminal, sarif, json
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct CloudArgs {
    /// Target cloud configuration file or directory to scan, or '-' for STDIN
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Optional cloud provider filter: aws, gcp, azure, auto
    #[arg(long, default_value = "auto")]
    pub provider: String,

    /// Output report format: terminal, sarif, json
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Optional output file to write the audit results
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Path to baseline snapshot file to filter known findings
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Save discovered findings as a new baseline snapshot file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct IacArgs {
    /// Target IaC file, directory to scan, or '-' for STDIN
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Output report format: terminal, sarif, json
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Optional output file to write the audit results
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Path to baseline snapshot file to filter known findings
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Save discovered findings as a new baseline snapshot file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct PipelineArgs {
    /// Target pipeline file, workflow, SLSA attestation, directory to scan, or '-' for STDIN
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Optional target artifact to verify against SLSA provenance subject digests
    #[arg(short, long, value_name = "ARTIFACT_FILE")]
    pub artifact: Option<PathBuf>,

    /// Output report format: terminal, sarif, json
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Optional output file to write the audit results
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Path to baseline snapshot file to filter known findings
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Save discovered findings as a new baseline snapshot file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,

    /// Trusted SLSA builder identities (multiple flags supported)
    #[arg(long, value_name = "BUILDER_URI")]
    pub trusted_builder: Vec<String>,

    /// Expected official source repository URL to verify in SLSA materials
    #[arg(long, value_name = "REPO_URL")]
    pub expected_repo: Option<String>,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct MobileArgs {
    /// Target mobile package (.apk, .ipa), manifest, plist, directory to scan, or '-' for STDIN
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Enforce release mode security checks (escalates debuggable flags to errors)
    #[arg(long, default_value_t = false)]
    pub release: bool,

    /// Output report format: terminal, sarif, json
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Optional output file to write the audit results
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Path to baseline snapshot file to filter known findings
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Save discovered findings as a new baseline snapshot file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreatOutputFormat {
    Terminal,
    Sarif,
    Json,
    Navigator,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct ThreatArgs {
    /// Path to SARIF v2.1.0 telemetry file or '-' for STDIN
    #[arg(default_value = "-")]
    pub input: PathBuf,

    /// Target MITRE ATT&CK Matrix Domain (enterprise, cloud, mobile, container)
    #[arg(short, long, default_value = "enterprise")]
    pub domain: String,

    /// Output report format: terminal, sarif, json, navigator
    #[arg(short, long, value_enum, default_value_t = ThreatOutputFormat::Terminal)]
    pub format: ThreatOutputFormat,

    /// Optional output file to write threat model or Navigator layer
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Path to baseline snapshot file to filter known findings
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Display MITRE ATT&CK terminal matrix only
    #[arg(long, default_value_t = false)]
    pub matrix: bool,

    /// Display STRIDE threat distribution cards only
    #[arg(long, default_value_t = false)]
    pub stride: bool,

    /// Layer name for the generated ATT&CK Navigator Layer
    #[arg(long, default_value = "Aegix Security Threat Matrix")]
    pub layer_name: String,
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

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceFormat {
    Terminal,
    Mermaid,
    Json,
    Sarif,
}

#[derive(Args, Debug, PartialEq)]
pub struct TraceArgs {
    /// Target repository path or SARIF file to construct Attack Path Graph
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Optional path to SARIF v2.1.0 telemetry file or '-' for STDIN
    #[arg(long, value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Output report format: terminal, mermaid, json, sarif
    #[arg(short, long, value_enum, default_value_t = TraceFormat::Terminal)]
    pub format: TraceFormat,

    /// Optional output file to write the results
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Maximum traversal depth (hop count)
    #[arg(long, default_value_t = 10)]
    pub max_depth: usize,

    /// Minimum path risk score threshold to report (0.0 to 100.0)
    #[arg(long, default_value_t = 0.0)]
    pub min_risk: f64,

    /// Compounding path risk threshold to trigger exit code 1
    #[arg(long, default_value_t = 70.0)]
    pub fail_on: f64,

    /// Path to baseline snapshot file to filter known findings
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Save discovered findings as a new baseline snapshot file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,
}

impl Eq for TraceArgs {}

#[derive(Args, Debug, PartialEq)]
pub struct RiskArgs {
    /// Target Cargo workspace directory or SARIF report file
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Optional path to SARIF v2.1.0 telemetry file or '-' for STDIN
    #[arg(long, value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Output report format: terminal, sarif, json
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Optional output file to write the prioritized results
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Minimum Tri-Factor score threshold to display (0.0 to 10.0)
    #[arg(long, default_value_t = 0.0)]
    pub min_score: f64,

    /// Minimum Tri-Factor score among non-suppressed findings to trigger exit code 1
    #[arg(long, default_value_t = 2.5)]
    pub fail_on: f64,

    /// Include unreachable/suppressed findings in output
    #[arg(long, default_value_t = false)]
    pub show_suppressed: bool,

    /// Skip spawning `cargo metadata` and use pure-Rust Cargo.toml/Cargo.lock fallback
    #[arg(long, default_value_t = false)]
    pub no_cargo_metadata: bool,

    /// Optional offline JSON EPSS database override file
    #[arg(long, value_name = "FILE")]
    pub epss_db: Option<PathBuf>,

    /// Path to baseline snapshot file to suppress known findings
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Save discovered findings as a new baseline snapshot file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,
}

impl Eq for RiskArgs {}

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
        .with_writer(std::io::stderr)
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

            let mut all_findings: Vec<SarifResult> = sast_findings
                .into_iter()
                .chain(secret_findings)
                .chain(container_sarif)
                .collect();

            // Save baseline snapshot if requested
            if let Some(ref save_path) = args.save_baseline {
                let baseline = AegixBaseline::from_results(&all_findings);
                baseline.save_to_path(save_path)?;
                if args.format == OutputFormat::Terminal {
                    println!(
                        "💾 Saved baseline snapshot with {} finding(s) to {}",
                        baseline.total_findings,
                        save_path.display()
                    );
                }
            }

            // Filter against baseline snapshot if requested
            let mut suppressed_count = 0;
            if let Some(ref baseline_path) = args.baseline {
                let baseline = AegixBaseline::load_from_path(baseline_path)?;
                suppressed_count = baseline.filter_results(&mut all_findings);
            }

            match args.format {
                OutputFormat::Sarif | OutputFormat::Json => {
                    let mut log = SarifLog::new("Aegix Scanner", env!("CARGO_PKG_VERSION"));
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
                                    "https://github.com/yusufjohn-shaik/AEGIX".to_string(),
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
                                    "https://github.com/yusufjohn-shaik/AEGIX".to_string(),
                                ),
                            });
                        }
                    }
                    for finding in all_findings {
                        log.add_result(finding);
                    }
                    println!("{}", serde_json::to_string_pretty(&log)?);
                }
                OutputFormat::Terminal => {
                    println!("🛡️  Aegix Scanner v{}", env!("CARGO_PKG_VERSION"));
                    println!("Target: {}", args.path.display());
                    println!("Workspace: {}", config.general.workspace_dir.display());
                    if args.baseline.is_some() && suppressed_count > 0 {
                        println!(
                            "ℹ️  Baseline active: {} pre-existing finding(s) suppressed.",
                            suppressed_count
                        );
                    }
                    println!("{:-<80}", "");

                    if all_findings.is_empty() {
                        if suppressed_count > 0 {
                            println!(
                                "✅ No new security vulnerabilities or regressions detected ({} suppressed by baseline).",
                                suppressed_count
                            );
                        } else {
                            println!("✅ No security vulnerabilities, leaked credentials, or container misconfigurations detected.");
                        }
                    } else {
                        println!("Found {} security alert(s):", all_findings.len());
                        println!();
                        for f in &all_findings {
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
                            if let Some(conf) = f.confidence {
                                println!("   └── Confidence: {}", conf);
                            }
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
                        "🛡️  Aegix SCA & Supply Chain Auditor v{}",
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
                        SarifLog::new("Aegix Network Recon Engine", env!("CARGO_PKG_VERSION"))
                    });
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                OutputFormat::Terminal => {
                    println!(
                        "🛡️  Aegix Network Reconnaissance Engine v{}",
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
            let normalized_target = if !args.target.contains("://") {
                format!("http://{}", args.target)
            } else {
                args.target.clone()
            };
            let target_url = Url::parse(&normalized_target)
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
                    } else if host.eq_ignore_ascii_case("localhost") {
                        vec!["127.0.0.1/32".to_string(), "::1/128".to_string()]
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
                    println!("🛡️  Aegix DAST Engine v{}", env!("CARGO_PKG_VERSION"));
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
        Some(Commands::Api(args)) => {
            let api_config = ApiConfig {
                spec_path: args.spec_path.clone(),
                target: args.target.clone(),
                fuzz: args.fuzz,
                allow_destructive: args.allow_destructive,
                dry_run: args.dry_run,
                scope_path: args.scope.clone(),
                scope_key: args.scope_key.clone(),
                max_rps: args.max_rps,
                timeout_ms: args.timeout,
                headers: args.headers.clone(),
                insecure: args.insecure,
                schemathesis: args.schemathesis,
                baseline_path: args.baseline.clone(),
                format: format!("{:?}", args.format).to_lowercase(),
            };

            let engine = ApiEngine::new();
            let report = engine.scan(&api_config).await?;

            match args.format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Sarif => {
                    let sarif = engine.generate_sarif(&report);
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                }
                OutputFormat::Terminal => {
                    println!(
                        "🛡️  Aegix API Security Engine v{}",
                        env!("CARGO_PKG_VERSION")
                    );
                    println!("Specification: {}", report.spec_path);
                    println!("Dialect: {}", report.spec_version);
                    println!(
                        "Audited Endpoints: {} | Findings Discovered: {}",
                        report.operations_count,
                        report.findings.len()
                    );
                    if report.fuzzed_endpoints > 0 {
                        println!(
                            "Fuzzed Endpoints: {} | Probes Sent: {} | Crash/Drift Findings: {}",
                            report.fuzzed_endpoints,
                            report.fuzzer_requests_sent,
                            report.fuzzer_errors_found
                        );
                    }
                    println!("{:-<80}", "");

                    if report.findings.is_empty() {
                        println!("✅ No API contract security vulnerabilities or anti-patterns detected.");
                    } else {
                        for f in &report.findings {
                            let (badge, color) = match f.severity {
                                SarifLevel::Error => ("🔴 ERROR", "High/Critical"),
                                SarifLevel::Warning => ("🟡 WARN ", "Medium"),
                                SarifLevel::Note => ("🔵 NOTE ", "Low"),
                                SarifLevel::None => ("ℹ️  INFO ", "Info"),
                            };
                            if let Some(ref m) = f.method {
                                println!("{} [{}] {} {}", badge, f.rule_id, m, f.path);
                            } else {
                                println!("{} [{}] {}", badge, f.rule_id, f.path);
                            }
                            println!("   └── Title: {}", f.title);
                            println!("   └── Severity: {}", color);
                            println!("   └── Confidence: {:?}", f.confidence);
                            println!("   └── Location: {}", f.json_pointer);
                            println!("   └── Description: {}", f.description);
                            println!("   └── Remediation: {}", f.remediation);
                            println!();
                        }
                    }
                    println!("{:-<80}", "");
                }
            }
        }
        Some(Commands::Cloud(args)) => {
            let engine = CloudEngine::default();
            let config = cyberguard_cloud::parser::CloudParser::parse_path(&args.target)?;
            let report = engine.scan(&config).await?;

            // Handle save baseline if requested
            if let Some(ref save_path) = args.save_baseline {
                let baseline = engine.generate_baseline(&report, &args.target);
                baseline.save_to_path(save_path)?;
                println!(
                    "Saved {} findings to baseline snapshot '{}'",
                    report.findings.len(),
                    save_path.display()
                );
            }

            // Load baseline for suppression if requested
            let baseline_opt = if let Some(ref base_path) = args.baseline {
                Some(cyberguard_core::baseline::AegixBaseline::load_from_path(
                    base_path,
                )?)
            } else {
                None
            };

            let output_str = match args.format {
                OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Sarif => {
                    let sarif = engine.to_sarif(&report, &args.target, baseline_opt.as_ref());
                    serde_json::to_string_pretty(&sarif)?
                }
                OutputFormat::Terminal => {
                    if let Some(ref base) = baseline_opt {
                        let filtered_report = CloudEngine::filter_baseline(&report, base);
                        engine.format_terminal(&filtered_report)
                    } else {
                        engine.format_terminal(&report)
                    }
                }
            };

            if let Some(ref out_path) = args.output {
                std::fs::write(out_path, &output_str)?;
                println!("Audit report written to {}", out_path.display());
            } else {
                print!("{}", output_str);
            }
        }
        Some(Commands::Iac(args)) => {
            let engine = IacEngine::new();
            let report = if args.target.to_string_lossy() == "-" {
                let mut stdin = std::io::stdin();
                engine
                    .scan_reader(&mut stdin, &PathBuf::from("stdin.yaml"))
                    .await?
            } else {
                engine.scan_file(&args.target).await?
            };

            // Handle save baseline if requested
            if let Some(ref save_path) = args.save_baseline {
                let baseline = engine.generate_baseline(&report, &args.target);
                baseline.save_to_path(save_path)?;
                println!(
                    "Saved {} findings to baseline snapshot '{}'",
                    report.findings.len(),
                    save_path.display()
                );
            }

            // Load baseline for suppression if requested
            let baseline_opt = if let Some(ref base_path) = args.baseline {
                Some(cyberguard_core::baseline::AegixBaseline::load_from_path(
                    base_path,
                )?)
            } else {
                None
            };

            let output_str = match args.format {
                OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Sarif => {
                    let sarif = engine.to_sarif(&report, &args.target, baseline_opt.as_ref());
                    serde_json::to_string_pretty(&sarif)?
                }
                OutputFormat::Terminal => {
                    if let Some(ref base) = baseline_opt {
                        let filtered_report = IacEngine::filter_baseline(&report, base);
                        engine.format_terminal(&filtered_report)
                    } else {
                        engine.format_terminal(&report)
                    }
                }
            };

            if let Some(ref out_path) = args.output {
                std::fs::write(out_path, &output_str)?;
                println!("Audit report written to {}", out_path.display());
            } else {
                print!("{}", output_str);
            }
        }
        Some(Commands::Pipeline(args)) => {
            let mut engine = PipelineEngine::new();

            for tb in &args.trusted_builder {
                engine = engine.with_trusted_builder(tb);
            }
            if let Some(ref repo) = args.expected_repo {
                engine = engine.with_expected_source_repo(repo);
            }

            // Load baseline for suppression if requested
            let baseline_opt = if let Some(ref base_path) = args.baseline {
                let base = cyberguard_core::baseline::AegixBaseline::load_from_path(base_path)?;
                engine = engine.with_baseline(base.clone());
                Some(base)
            } else {
                None
            };

            let report = if args.target.to_string_lossy() == "-" {
                let mut stdin = std::io::stdin();
                engine
                    .scan_reader(&mut stdin, &PathBuf::from("stdin.yaml"))
                    .await?
            } else if args.target.is_dir() {
                engine.scan_directory(&args.target).await?
            } else {
                engine
                    .scan_file(&args.target, args.artifact.as_deref())
                    .await?
            };

            // Handle save baseline if requested
            if let Some(ref save_path) = args.save_baseline {
                let baseline = engine.generate_baseline(&report, &args.target);
                baseline.save_to_path(save_path)?;
                println!(
                    "Saved {} findings to baseline snapshot '{}'",
                    report.findings.len(),
                    save_path.display()
                );
            }

            let output_str = match args.format {
                OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Sarif => {
                    let sarif = engine.to_sarif(&report)?;
                    serde_json::to_string_pretty(&sarif)?
                }
                OutputFormat::Terminal => {
                    if let Some(ref base) = baseline_opt {
                        let filtered_report = PipelineEngine::filter_baseline(&report, base);
                        format_pipeline_terminal(&filtered_report)
                    } else {
                        format_pipeline_terminal(&report)
                    }
                }
            };

            if let Some(ref out_path) = args.output {
                std::fs::write(out_path, &output_str)?;
                println!("Audit report written to {}", out_path.display());
            } else {
                print!("{}", output_str);
            }

            if !report.findings.is_empty() {
                std::process::exit(1);
            }
        }
        Some(Commands::Mobile(args)) => {
            use cyberguard_mobile::traits::MobileScanner;
            use cyberguard_mobile::MobileEngine;
            use std::io::Read;

            let baseline_opt = if let Some(ref base_path) = args.baseline {
                if base_path.exists() {
                    let file = std::fs::File::open(base_path)?;
                    let reader = std::io::BufReader::new(file);
                    let base: cyberguard_core::baseline::AegixBaseline =
                        serde_json::from_reader(reader)?;
                    Some(base)
                } else {
                    anyhow::bail!("Baseline file not found at: {}", base_path.display());
                }
            } else {
                None
            };

            let mut engine = MobileEngine::new(args.release);
            if let Some(ref base) = baseline_opt {
                engine = engine.with_baseline(base.clone());
            }

            let report = if args.target == Path::new("-") {
                let mut stdin = std::io::stdin();
                let mut buffer = Vec::new();
                stdin.read_to_end(&mut buffer)?;
                let mut cursor = std::io::Cursor::new(buffer);
                engine
                    .scan_reader(&mut cursor, Path::new("stdin-mobile.xml"))
                    .await?
            } else if args.target.is_file() {
                engine.scan_file(&args.target).await?
            } else if args.target.is_dir() {
                engine.scan_directory(&args.target).await?
            } else {
                anyhow::bail!("Target path not found: {}", args.target.display());
            };

            if let Some(ref save_path) = args.save_baseline {
                let new_baseline = engine.generate_baseline(&report, &args.target);
                let json_data = serde_json::to_string_pretty(&new_baseline)?;
                std::fs::write(save_path, json_data)?;
                println!(
                    "Saved {} findings to baseline snapshot '{}'",
                    report.findings.len(),
                    save_path.display()
                );
            }

            let output_str = match args.format {
                OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Sarif => {
                    let sarif = engine.to_sarif(&report)?;
                    serde_json::to_string_pretty(&sarif)?
                }
                OutputFormat::Terminal => {
                    if let Some(ref base) = baseline_opt {
                        let filtered_report = MobileEngine::filter_baseline(&report, base);
                        format_mobile_terminal(&filtered_report)
                    } else {
                        format_mobile_terminal(&report)
                    }
                }
            };

            if let Some(ref out_path) = args.output {
                std::fs::write(out_path, &output_str)?;
                println!("Audit report written to {}", out_path.display());
            } else {
                print!("{}", output_str);
            }

            if !report.findings.is_empty() {
                std::process::exit(1);
            }
        }
        Some(Commands::Threat(args)) => {
            use cyberguard_threat::models::MitreMatrixDomain;
            use cyberguard_threat::report::ThreatReportFormatter;
            use cyberguard_threat::traits::ThreatScanner;
            use cyberguard_threat::ThreatEngine;
            use std::io::Read;

            let baseline_opt = if let Some(ref base_path) = args.baseline {
                if base_path.exists() {
                    let file = std::fs::File::open(base_path)?;
                    let reader = std::io::BufReader::new(file);
                    let base: cyberguard_core::baseline::AegixBaseline =
                        serde_json::from_reader(reader)?;
                    Some(base)
                } else {
                    anyhow::bail!("Baseline file not found at: {}", base_path.display());
                }
            } else {
                None
            };

            let domain = MitreMatrixDomain::from_str_loose(&args.domain)
                .unwrap_or(MitreMatrixDomain::EnterpriseAttack);

            let mut engine = ThreatEngine::new()
                .with_domain(domain)
                .with_layer_name(args.layer_name);

            if let Some(base) = baseline_opt {
                engine = engine.with_baseline(base);
            }

            let report = if args.input == Path::new("-") {
                let mut stdin = std::io::stdin();
                let mut buffer = String::new();
                stdin.read_to_string(&mut buffer)?;
                engine.scan_sarif(&buffer).await?
            } else if args.input.is_file() {
                engine.scan_file(&args.input).await?
            } else {
                anyhow::bail!("Input SARIF file not found: {}", args.input.display());
            };

            let output_str = match args.format {
                ThreatOutputFormat::Json => ThreatReportFormatter::to_json(&report)?,
                ThreatOutputFormat::Navigator => ThreatReportFormatter::to_navigator_json(&report)?,
                ThreatOutputFormat::Sarif => {
                    let sarif = engine.export_sarif_report(&report)?;
                    serde_json::to_string_pretty(&sarif)?
                }
                ThreatOutputFormat::Terminal => {
                    ThreatReportFormatter::render_terminal(&report, engine.catalog())
                }
            };

            if let Some(ref out_path) = args.output {
                std::fs::write(out_path, &output_str)?;
                println!("Threat model report written to {}", out_path.display());
            } else {
                print!("{}", output_str);
            }

            if report.total_findings > 0 {
                std::process::exit(1);
            }
        }
        Some(Commands::Trace(args)) => {
            use cyberguard_graph::{
                AttackGraph, ChokePointAnalyzer, GraphCorrelator, GraphExporter, JsonExporter,
                MermaidExporter, PathFinder, SarifExporter, StandardChokePointAnalyzer,
                StandardGraphCorrelator, StandardPathFinder, StandardTelemetryIngester,
                TelemetryIngester, TerminalExporter,
            };
            use std::io::Read;

            let mut graph = AttackGraph::new();
            let ingester = StandardTelemetryIngester::new();

            // 1. Ingest input telemetry from file, STDIN, or automated directory scan
            let sarif_opt: Option<SarifLog> = if let Some(ref input_path) = args.input {
                let content = if input_path == Path::new("-") {
                    let mut stdin = std::io::stdin();
                    let mut buffer = String::new();
                    stdin.read_to_string(&mut buffer)?;
                    buffer
                } else if input_path.is_file() {
                    std::fs::read_to_string(input_path)?
                } else {
                    anyhow::bail!("Input SARIF file not found: {}", input_path.display());
                };
                Some(serde_json::from_str(&content)?)
            } else if args.path.is_file()
                && (args
                    .path
                    .extension()
                    .is_some_and(|ext| ext == "json" || ext == "sarif"))
            {
                let content = std::fs::read_to_string(&args.path)?;
                Some(serde_json::from_str(&content)?)
            } else {
                None
            };

            if let Some(ref sarif) = sarif_opt {
                ingester.ingest_sarif(&mut graph, sarif)?;
            } else {
                let mut sarif_log = SarifLog::new("aegix-trace", env!("CARGO_PKG_VERSION"));

                let sast_engine = NativeRuleEngine::default();
                let ctx = ScanContext::new(&args.path);
                if let Ok(findings) = sast_engine.analyze(&ctx).await {
                    for f in findings {
                        sarif_log.add_result(f);
                    }
                }

                let secret_engine = SecretEngine::default();
                if let Ok(raw_secrets) = secret_engine.scan_path(&args.path).await {
                    for s in secret_engine.to_sarif(&raw_secrets) {
                        sarif_log.add_result(s);
                    }
                }

                ingester.ingest_sarif(&mut graph, &sarif_log)?;
            }

            // 2. Correlate findings via 5-tier correlation engine
            let correlator = StandardGraphCorrelator::new();
            correlator.correlate(&mut graph)?;

            // 3. Cycle-safe bounded DFS path discovery
            let path_finder = StandardPathFinder::new();
            let mut paths = path_finder.find_paths(&graph, args.max_depth, 100, args.min_risk)?;

            // 4. Baseline filtering if provided
            if let Some(ref base_path) = args.baseline {
                if base_path.exists() {
                    let baseline = AegixBaseline::load_from_path(base_path)?;
                    paths.retain(|p| !baseline.contains(&format!("path:{}", p.id)));
                }
            }

            if let Some(ref save_path) = args.save_baseline {
                let mut base = AegixBaseline::new();
                for p in &paths {
                    let fp = format!("path:{}", p.id);
                    base.fingerprints.insert(fp.clone());
                    base.findings
                        .push(cyberguard_core::baseline::BaselineFindingEntry {
                            rule_id: "PATH-EXPLOIT-CHAIN".to_string(),
                            fingerprint: fp,
                            location: Some(format!("hops:{}", p.hop_count)),
                            message: Some(format!("Attack path risk {:.1}", p.path_risk)),
                        });
                }
                base.total_findings = base.fingerprints.len();
                base.save_to_path(save_path)?;
            }

            // 5. Choke-point cut-vertex ranking
            let analyzer = StandardChokePointAnalyzer::new();
            let choke_points = analyzer.analyze_choke_points(&graph, &paths)?;

            // 6. Export representation
            let output_str = match args.format {
                TraceFormat::Terminal => {
                    let exporter = TerminalExporter::new(args.output.is_none());
                    exporter.export(&graph, &paths, &choke_points)?
                }
                TraceFormat::Mermaid => {
                    let exporter = MermaidExporter::new();
                    exporter.export(&graph, &paths, &choke_points)?
                }
                TraceFormat::Json => {
                    let exporter = JsonExporter::new();
                    exporter.export(&graph, &paths, &choke_points)?
                }
                TraceFormat::Sarif => {
                    let exporter = SarifExporter::new();
                    exporter.export(&graph, &paths, &choke_points)?
                }
            };

            if let Some(ref out_path) = args.output {
                std::fs::write(out_path, &output_str)?;
                println!("Attack path report written to {}", out_path.display());
            } else {
                print!("{}", output_str);
            }

            // 7. Check fail_on threshold for exit code
            let max_risk = paths
                .iter()
                .map(|p| p.path_risk)
                .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or(0.0);

            if max_risk >= args.fail_on {
                std::process::exit(1);
            }
        }
        Some(Commands::Risk(args)) => {
            use cyberguard_core::baseline::BaselineFindingEntry;
            use cyberguard_risk::{
                JsonExporter as RiskJsonExporter, RiskEngine, RiskExporter, RiskPrioritizer,
                RiskScanOptions, RiskTier, SarifExporter as RiskSarifExporter,
                TerminalExporter as RiskTerminalExporter,
            };
            use std::io::Read;

            let options = RiskScanOptions {
                min_score: if args.min_score.is_finite() {
                    args.min_score
                } else {
                    0.0
                },
                show_suppressed: args.show_suppressed,
                use_cargo_metadata: !args.no_cargo_metadata,
                external_epss_db: args.epss_db.clone(),
            };

            let sarif_opt: Option<SarifLog> = if let Some(ref input_path) = args.input {
                let content = if input_path == Path::new("-") {
                    let mut stdin = std::io::stdin();
                    let mut buffer = String::new();
                    if let Err(e) = stdin.read_to_string(&mut buffer) {
                        eprintln!("Error reading STDIN telemetry: {}", e);
                        std::process::exit(2);
                    }
                    buffer
                } else if input_path.is_file() {
                    match std::fs::read_to_string(input_path) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Error reading SARIF file '{}': {}", input_path.display(), e);
                            std::process::exit(2);
                        }
                    }
                } else {
                    eprintln!("Input SARIF file not found: {}", input_path.display());
                    std::process::exit(2);
                };

                match serde_json::from_str(&content) {
                    Ok(log) => Some(log),
                    Err(e) => {
                        eprintln!("Malformed SARIF telemetry: {}", e);
                        std::process::exit(2);
                    }
                }
            } else if args.path.is_file()
                && args
                    .path
                    .extension()
                    .is_some_and(|ext| ext == "json" || ext == "sarif")
            {
                let content = match std::fs::read_to_string(&args.path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error reading SARIF file '{}': {}", args.path.display(), e);
                        std::process::exit(2);
                    }
                };
                match serde_json::from_str(&content) {
                    Ok(log) => Some(log),
                    Err(e) => {
                        eprintln!("Malformed SARIF telemetry: {}", e);
                        std::process::exit(2);
                    }
                }
            } else {
                None
            };

            let engine = RiskEngine::new();
            let report_res = if let Some(ref sarif) = sarif_opt {
                let target_root = if args.path.is_file() {
                    args.path.parent().unwrap_or(Path::new("."))
                } else {
                    args.path.as_path()
                };
                engine.prioritize_sarif(target_root, sarif, &options).await
            } else {
                engine.prioritize_path(&args.path, &options).await
            };

            let mut report = match report_res {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Tri-Factor risk analysis error: {}", e);
                    std::process::exit(2);
                }
            };

            if let Some(ref base_path) = args.baseline {
                if base_path.exists() {
                    match AegixBaseline::load_from_path(base_path) {
                        Ok(baseline) => {
                            report.findings.retain(|f| !baseline.contains(&f.id));
                            report.recompute_counts();
                        }
                        Err(e) => {
                            eprintln!("Error reading baseline '{}': {}", base_path.display(), e);
                            std::process::exit(2);
                        }
                    }
                }
            }

            if let Some(ref save_path) = args.save_baseline {
                let mut base = AegixBaseline::new();
                for f in &report.findings {
                    base.fingerprints.insert(f.id.clone());
                    base.findings.push(BaselineFindingEntry {
                        rule_id: f.rule_id.clone(),
                        fingerprint: f.id.clone(),
                        location: f.file_path.clone(),
                        message: Some(f.summary.clone()),
                    });
                }
                base.total_findings = base.fingerprints.len();
                if let Err(e) = base.save_to_path(save_path) {
                    eprintln!("Error writing baseline '{}': {}", save_path.display(), e);
                    std::process::exit(2);
                }
            }

            let output_res = match args.format {
                OutputFormat::Terminal => {
                    RiskTerminalExporter::new(args.output.is_none()).export(&report)
                }
                OutputFormat::Json => RiskJsonExporter::new().export(&report),
                OutputFormat::Sarif => RiskSarifExporter::new().export(&report),
            };

            let output_str = match output_res {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Risk report formatting error: {}", e);
                    std::process::exit(2);
                }
            };

            if let Some(ref out_path) = args.output {
                if let Err(e) = std::fs::write(out_path, &output_str) {
                    eprintln!("Error writing output file '{}': {}", out_path.display(), e);
                    std::process::exit(2);
                }
                println!("Tri-Factor risk report written to {}", out_path.display());
            } else {
                print!("{}", output_str);
            }

            let fail_on_bps = if args.fail_on.is_finite() && args.fail_on >= 0.0 {
                (args.fail_on * 100.0).round() as u32
            } else {
                u32::MAX
            };

            let breach = report
                .findings
                .iter()
                .filter(|f| f.breakdown.tier != RiskTier::Suppressed)
                .any(|f| f.breakdown.score_bps >= fail_on_bps);

            if breach {
                std::process::exit(1);
            }
        }
        Some(Commands::Fix(args)) => {
            println!("🛠️  Aegix AST Auto-Remediation Engine");
            println!(
                "Target: {} (auto={}, dry_run={})",
                args.path.display(),
                args.auto,
                args.dry_run
            );
        }
        Some(Commands::Mcp(args)) => {
            if let Some(port) = args.port {
                tracing::warn!(
                    "SSE transport on port {} is disabled in air-gapped mode; defaulting to stdio",
                    port
                );
            }
            cyberguard_mcp::server::run_stdio_server().await?;
        }
        None => {
            println!(
                "🛡️  Aegix {} - Next-Generation Autonomous Vulnerability Intelligence",
                env!("CARGO_PKG_VERSION")
            );
            println!("Run 'aegix --help' for available commands.");
        }
    }

    Ok(())
}

fn format_pipeline_terminal(report: &cyberguard_pipeline::PipelineReport) -> String {
    let mut out = String::new();
    out.push_str("\n🛡️  Aegix CI/CD Pipeline & SLSA Provenance Security Audit Report\n");
    out.push_str("======================================================================\n");
    out.push_str(&format!("Target:            {}\n", report.target_path));
    out.push_str(&format!(
        "Documents Scanned: {}\n",
        report.total_documents_scanned
    ));
    out.push_str(&format!(
        "Jobs Evaluated:    {}\n",
        report.total_jobs_evaluated
    ));
    out.push_str(&format!(
        "Steps Evaluated:   {}\n",
        report.total_steps_evaluated
    ));
    out.push_str(&format!(
        "Suppressed:        {}\n",
        report.suppressed_findings_count
    ));
    out.push_str(&format!("Active Findings:   {}\n", report.findings.len()));
    out.push_str("----------------------------------------------------------------------\n");

    if report.findings.is_empty() {
        out.push_str("✅ No pipeline security or SLSA provenance vulnerabilities discovered.\n\n");
        return out;
    }

    for (i, f) in report.findings.iter().enumerate() {
        out.push_str(&format!(
            "[{}] {} ({}) - {:?}\n",
            i + 1,
            f.rule_id,
            f.title,
            f.severity
        ));
        out.push_str(&format!(
            "    Location: {}:{}:{}\n",
            f.file_path, f.line, f.column
        ));
        out.push_str(&format!("    Scope:    {}\n", f.location_path));
        out.push_str(&format!("    Issue:    {}\n", f.description));
        out.push_str(&format!("    Fix:      {}\n\n", f.remediation));
    }
    out
}

fn format_mobile_terminal(report: &cyberguard_mobile::MobileReport) -> String {
    let mut out = String::new();
    out.push_str("\n📱  Aegix Mobile Application Security Audit Report\n");
    out.push_str("======================================================================\n");
    out.push_str(&format!("Target:                 {}\n", report.target_path));
    out.push_str(&format!(
        "Documents Scanned:      {}\n",
        report.total_documents_scanned
    ));
    out.push_str(&format!(
        "Components Evaluated:   {}\n",
        report.total_components_evaluated
    ));
    out.push_str(&format!(
        "Suppressed:             {}\n",
        report.suppressed_findings_count
    ));
    out.push_str(&format!(
        "Active Findings:        {}\n",
        report.findings.len()
    ));
    out.push_str("----------------------------------------------------------------------\n");

    if report.findings.is_empty() {
        out.push_str(
            "✅ No mobile security vulnerabilities or insecure configurations discovered.\n\n",
        );
        return out;
    }

    for (i, f) in report.findings.iter().enumerate() {
        out.push_str(&format!(
            "[{}] {} ({}) - {:?}\n",
            i + 1,
            f.rule_id,
            f.title,
            f.severity
        ));
        out.push_str(&format!(
            "    Location: {}:{}:{}\n",
            f.file_path, f.line, f.column
        ));
        out.push_str(&format!("    Scope:    {}\n", f.location_path));
        out.push_str(&format!("    Issue:    {}\n", f.description));
        out.push_str(&format!("    Fix:      {}\n\n", f.remediation));
    }
    out
}
