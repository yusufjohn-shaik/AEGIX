# 📋 Aegix Master TODO & Execution Backlog

This document is the permanent, exhaustive tracking log for all improvements, technical debts, roadmap milestones, and commercialization requirements for the **Aegix** platform.

---

## ⚡ BUCKET 1: WHAT WE HAVE TO DO NOW (During Modules 10–21)

These items address core credibility, developer adoption primitives, parser robustness, and roadmap execution. They must be implemented inline before or alongside the remaining modules.

### Phase 1.1: Immediate Credibility & Tone Correction (Completed ✅)
- [x] **README Tone Overhaul:** Rewrote `README.md` to remove marketing hyperbole (e.g. dropped *"#1 open-source security project"*, *"mathematically immune to ReDoS"*). Replaced with exact, measurable engineering claims (e.g. *"Linear-time non-backtracking DFA regular expression engine avoiding ReDoS worst-cases"*, *"Zero external runtime JVM/Python dependencies"*).
- [x] **Formal Threat Model (`SECURITY_MODEL.md`):** Published an honest, developer-first document defining:
  - Exact detection capabilities and boundaries.
  - Explicit **Non-Goals** (e.g., cannot detect complex business-logic authorization bypasses or cross-service semantic flaws without full runtime tracing).
  - Parser security and local execution boundaries.
- [x] **CI Dogfooding (`.github/workflows/dco_and_lint.yml`):** Run Aegix on itself in GitHub Actions CI:
  - Build `aegix` release binary.
  - Run `aegix scan .` (SAST) on the workspace itself and verify SARIF telemetry export.
- [x] **Project Renaming Decision & Refactor:** Migrated away from the generic/trademark-conflicted name *"CyberGuard"* to **Aegix** (`aegix`). Updated CLI binary target, Clap definitions, and integration tests.

### Phase 1.2: Core Adoption Primitives (In-Engine Mechanics - Completed ✅)
- [x] **Baseline File Support (`--baseline <FILE>`):**
  - Implemented `--save-baseline .aegix-baseline.json` and `--baseline .aegix-baseline.json`.
  - Suppresses pre-existing legacy findings so enterprise teams can adopt the scanner on legacy repositories without breaking CI builds.
- [x] **Inline Suppression Comments:**
  - Support code comments to suppress specific findings in code:
    - `# aegix:ignore <RULE_ID> [reason]` (Python, Bash, YAML, Dockerfile)
    - `// aegix:ignore <RULE_ID> [reason]` (Rust, Go, C/C++, JS/TS)
    - `/* aegix:ignore <RULE_ID> */` (CSS, C/Rust block comments)
    - `<!-- aegix:ignore <RULE_ID> -->` (HTML/XML)
    - Backward compatible with `cyberguard:ignore`.
- [x] **Confidence Ratings on Findings:**
  - Added typed confidence enum (`High`, `Medium`, `Low`) to every `SarifResult` / `Finding` alongside Severity and integrated into SARIF metadata and terminal reporting.

### Phase 1.3: Parser Rigor & Defensive Hardening
- [ ] **Parser Fuzz Testing (`cargo-fuzz` / libFuzzer):**
  - Setup `fuzz/` target to fuzz untrusted parsers against memory exhaustion, infinite loops, and panics:
    - `fuzz_cargo_lock`: Cargo.lock TOML dependency parser.
    - `fuzz_npm_lock`: package-lock.json v1/v2/v3 parser.
    - `fuzz_dockerfile`: Dockerfile directive parser.
    - `fuzz_oci_tar`: Tarball header extractor and path traversal / zip-slip prevention.
- [ ] **Paired Regression Test Fixtures:**
  - Ensure every security rule in SAST, Secret, Container, and DAST has paired **known-bad (true positive)** and **known-good (true negative)** test fixtures.

### Phase 1.4: Core Engine Upgrades (Modules 10–15)
- [x] **Module 10: API Security & Spec Fuzzing (`cyberguard-api` / `aegix-api`):** OpenAPI 3.0 / 3.1 & Swagger 2.0 contract validator and autonomous contract boundary mutation fuzzing engine.
- [x] **Module 11: Cloud Security (`aegix-cloud` / `cyberguard-cloud`):** AWS, GCP, Azure IAM and cloud security posture (CSPM/CIEM).
- [x] **Module 12: IaC Security (`aegix-iac` / `cyberguard-iac`):** Terraform, Kubernetes, Helm static security linters and posture evaluation.
- [x] **Module 13: CI/CD Pipeline & SLSA Provenance (`aegix-pipeline` / `cyberguard-pipeline`):** GitHub Actions & GitLab CI workflow auditor, DSSE envelope unwrapper, and SLSA v0.2/v1.0 provenance verifier.
- [x] **Module 14: Mobile Security (`aegix-mobile` / `cyberguard-mobile`):** Android APK (`AndroidManifest.xml`, `network_security_config.xml`) & iOS IPA (`Info.plist`, `*.entitlements`) static security auditor, AXML / binary plist ingestion, and MASVS/OWASP rules engine.
- [x] **Module 15: Threat Modeling & ATT&CK Matrix (`aegix-threat` / `cyberguard-threat`):** Automated MITRE ATT&CK Enterprise/Cloud/Mobile/Container matrix mapping, STRIDE classification, asymptotic saturation scoring, and ATT&CK Navigator v4.5/v5.0 layer export.
- [ ] **Live Vulnerability Advisory Sync:** Automated synchronization with live OSV.dev and GitHub Security Advisories.
- [ ] **Verified Secret Liveness Checks:** Optional safe active API verification (`--verify-secrets`) to test if discovered keys are active.

### Phase 1.5: The Autonomous Differentiators (Modules 16–19)
- [x] **Module 16: Model Context Protocol (MCP) Server (`aegix-mcp` / `cyberguard-mcp`):** Native JSON-RPC 2.0 stdio MCP server enabling Cursor, Claude Code, Antigravity, and AI coding agents to invoke scans, query rules and threat models, and receive AST fix prompts.
- [x] **Module 17: Attack Path Engine (`aegix-graph` / `cyberguard-graph`):** In-memory Directed Graph (DG) connecting external entrypoints $\to$ services $\to$ reachable vulnerabilities $\to$ leaked secrets $\to$ assets $\to$ privilege escalation $\to$ terminal impacts, compounding path risk scoring, cut-vertex choke point isolation, and multi-format exporters (Terminal, Mermaid, JSON, SARIF CodeFlow).
- [x] **Module 18: Tri-Factor Prioritizer (`aegix-risk` / `cyberguard-risk`):**
  - Implemented Cargo dependency graph resolution (`cargo metadata` with scrubbed host-RCE defenses + pure-Rust `Cargo.toml`/`Cargo.lock` fallback) and zero-dependency deterministic Rust source call-graph reachability (`VerifiedReachable` through `Unreachable`).
  - Computes basis-point mathematical risk $\text{Score} = \text{round}_2(\text{CVSS} \times \text{EPSS} \times \text{Reachability})$ with calibrated priority tiers, offline EPSS catalog integration, SARIF `codeFlows`, CLI (`aegix risk`), and MCP (`aegix_risk`) support.
- [ ] **Module 19: Tree-sitter AST & Autonomous Remediation (`aegix-fix`):**
  - Transition SAST from pure regex to Tree-sitter AST parsing for Python, JavaScript/TypeScript, and Go.
  - Implement intra-procedural taint tracking (Sources $\to$ Sanitizers $\to$ Sinks).
  - Apply surgical AST patches and auto-generate unit tests verifying eradication.

### Phase 1.6: Developer Interfaces (Modules 20–21)
- [ ] **Module 20: TUI Dashboard & Reporting (`aegix-ui`):** `ratatui` terminal interface and executive PDF/HTML report generators.
- [ ] **Module 21: Release Automation & Multi-Arch Packaging (`aegix-dist`):** Automated cross-compilation pipeline for static binaries.

---

## 🚀 BUCKET 2: WHAT WE HAVE TO DO AFTER 21 MODULES (Launch, Scale & Commercialize)

These items focus on packaging distribution, community building, empirical benchmarks, security hardening, and business model monetization once the full 21-module engine is verified.

### Phase 2.0: Post-21 Modules Security Audit Hardening & System Upgrades Sprint
Comprehensive security audit remediation and system-wide upgrades prioritized for execution immediately following the completion of Modules 1–21.

#### 1. Critical Audit Findings
- [ ] **DAST ScopeGate Bypass & Optional HMAC Verification (`cyberguard-cli`, `cyberguard-dast`, `cyberguard-net`, `cyberguard-api`):**
  - **Issue:** Despite stating "Dynamic scanning strictly requires authorization via `.security-scope.yaml`", when `--scope` is omitted in `Commands::Dast` (`cyberguard-cli/src/main.rs:997-1036`), `main.rs` synthesizes an ephemeral unsigned `SecurityScope` (signature: `None`) authorizing whatever target the caller passed. Furthermore, `verify_scope_hmac` (`cyberguard-cli/src/main.rs:924-926 & 1005-1007`) is only invoked if `--scope-key` is supplied; omitting `--scope-key` accepts unsigned or forged `.security-scope.yaml` files. `NetworkEngine::scan`, `DastEngine::scan`, and `DefaultApiFuzzer::fuzz` never verify scope signatures (`ApiConfig::scope_key` in `cyberguard-api/src/models.rs` is never read).
  - **Remediation Plan:** Require `--scope` and `--scope-key` (via env var or flag) by default, moving unauthenticated local scanning behind an explicit `--allow-localhost-unverified` flag; verify HMAC inside `ScopeGate` construction across all network engines.
- [ ] **External DAST/API Runners & PinnedResolver ScopeGate / SSRF Bypass (`cyberguard-dast`, `cyberguard-api`):**
  - **Issue:** `PinnedResolver::resolve` (`cyberguard-dast/src/client.rs:37-53`) falls back to live, unvalidated `tokio::net::lookup_host` whenever `pinned_hosts` misses, and `pinned_hosts` keys only by hostname (without port) under concurrent `RwLock` overwrites. Neither `run_supervised_nuclei` (`cyberguard-dast/src/nuclei.rs:27-49`) nor `SchemathesisRunner::run` (`cyberguard-api/src/schemathesis.rs:15-68`) enforces `ScopeGate`, bogon filtering, or pinned DNS, allowing DNS rebinding and redirect-based SSRF via subprocesses.
  - **Remediation Plan:** Return an explicit error on `PinnedResolver` cache miss; pass pinned IPs/Host headers or enforce network-namespace/proxy egress filtering for nuclei and schemathesis subprocess runners.
- [ ] **Scope Gate Bypass Bugs (`cyberguard-net`):**
  - **Issue:** Wildcard suffix match (`cyberguard-net/src/scope.rs:183-188`) via `d.strip_prefix("*.")` drops the leading dot, so `*.example.com` checks `host.ends_with("example.com")`, matching unrelated collision domains like `evilexample.com` (and `*.` matches all hosts). It is also case-sensitive. `is_bogon_or_metadata` (`cyberguard-net/src/cidr.rs:105-181`) omits RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`, including Alibaba metadata `100.100.100.200`), and IPv6 ULA (`fc00::/7` except `fd00:ec2::254`). In domain-only scopes (`authorized_cidrs` empty), `validate_ip` allows scanning any domain that resolves/redirects to internal RFC 1918/ULA IPs. `NetworkEngine::scan` (`cyberguard-net/src/engine.rs:120-132`) validates only `effective_ports.first()` and forwards all remaining ports unvalidated; `generate_scope_hmac` (`cyberguard-net/src/scope.rs:288-297`) also omits `authorized_ports`. Malformed CIDRs and invalid RFC 3339 timestamps are silently ignored (`cyberguard-net/src/scope.rs:24-33, 69-95, 169-178`); bracketed IPv6 hosts (`"[::1]"`) from `Url::host_str()` fail `IpAddr::from_str` and fall through to domain matching.
  - **Remediation Plan:** Fix wildcard matching to require boundary dot and ASCII case-insensitivity; expand bogon filter to cover RFC 1918, CGNAT, and IPv6 ULA; validate all requested ports in `NetworkEngine::scan`; include `authorized_ports` in HMAC digest; strip bracket delimiters for IPv6 parsing and fail closed on invalid CIDR/timestamps.
- [ ] **SLSA / DSSE Cryptographic Signature Verification Missing (`cyberguard-pipeline`):**
  - **Issue:** `PipelineParser::parse_slsa_or_dsse` (`cyberguard-pipeline/src/parser.rs:69-85`) decodes `DsseEnvelope.payload` and ignores `envelope.signatures` completely (no cryptographic verification, nor even a non-empty signature check). Any forged provenance JSON/DSSE envelope passes.
  - **Remediation Plan:** Enforce cryptographic signature verification (ECDSA/Ed25519) on DSSE envelopes using configured trusted public keys or certificates before accepting provenance assertions, or explicitly flag provenance parsing as unverified.

#### 2. High Audit Findings
- [ ] **OpenAPI `$ref` & SLSA Path Traversal / Arbitrary File Read (`cyberguard-api`, `cyberguard-pipeline`):**
  - **Issue:** In `cyberguard-api/src/parser.rs:654-667`, when `parse_spec_file` is given a bare filename (e.g., `spec.yaml`), `path.parent()` is `""`, `"".canonicalize()` fails, and `unwrap_or_else` leaves `canonical_dir = ""`. `canonical_target.starts_with("")` evaluates to true, bypassing the directory containment guard and allowing arbitrary local file reads via `$ref`. In `cyberguard-pipeline/src/engine.rs:244-258`, when `artifact_path` is `None`, `subj.name` is appended directly to `repo_path` without traversal checks; a malicious SLSA provenance file can read/hash files outside the repository.
  - **Remediation Plan:** Normalize and canonicalize base directories with a fallback to `current_dir()`; strictly enforce directory containment (`canonical_target.starts_with(&base_dir)`) and reject relative path traversal components (`..`) in `subj.name`.
- [ ] **Unbounded Parser Memory Allocations & Zip-Bomb / Decompression DoS (`cyberguard-mobile`, `cyberguard-container`, `cyberguard-mcp`, `cyberguard-pipeline`, `cyberguard-iac`, `cyberguard-cloud`, `cyberguard-threat`, `cyberguard-core`):**
  - **Issue:**
    - `cyberguard-mobile/src/parser.rs:323-345`: In `read_zip_entry_bytes`, reads `entry.compressed_size()` as `usize` directly into `Vec::with_capacity` without upper bounds; also loops over all entries into a `Vec<String>` without count limits (ZIP bomb / memory exhaustion).
    - `cyberguard-mobile/src/parser.rs:815`: In AXML parser, `chunk_size < 8` underflow in `chunk_size - 8` can cause panic / infinite loop.
    - Tar-slip in `cyberguard-container` (`layer.rs:45-80`): Custom tar header parser checks only `entry_path.starts_with("..") || entry_path.contains("/../")`, skipping `../` escapes via components like `foo/../../bar`, ignores tar symlink/hardlink linkname fields (bytes 157..257), PAX headers, and GNU LongName/LongLink.
    - MCP unbounded frame read (`cyberguard-mcp/src/transport.rs:48-69`): `read_line(&mut line).await` buffers an entire line in RAM before checking `bytes_read > self.max_frame_bytes`; exceeding the limit returns `InvalidRequest`, which terminates `run_server` instead of returning JSON-RPC `-32600`.
    - Unbounded stream/stdin readers: `cyberguard-pipeline`, `cyberguard-iac`, `cyberguard-cloud` (`"-"` stdin), `cyberguard-threat`, and `cyberguard-core/baseline.rs` call `read_to_string` without bounded `.take(...)` limits.
  - **Remediation Plan:** Enforce maximum allocation ceilings (e.g. 64 MB per file, max 10,000 ZIP entries); add underflow protection in AXML chunk decoding; enforce streaming decompressed byte limits in OCI tar/gzip processing; use `.take(MAX_LINE_BYTES)` on MCP stdio lines and stream readers; parse tar PAX and LongName headers.
- [ ] **Symlink Traversal & Size-Limit Bypass Across File Scanners (`cyberguard-sast`, `cyberguard-secret`, `cyberguard-sca`, `cyberguard-container`, `cyberguard-mcp`):**
  - **Issue:** `WalkDir::follow_links(false)` paired with `path.is_file()` (which follows symlinks) and `entry.metadata()` (which reads symlink's own size via lstat) in `cyberguard-sast/src/walker.rs:52-77` lets file symlinks bypass `max_file_size_bytes` and escape the target directory. Passing a file directly as `ctx.target_path` also skips size, extension, and exclusion checks. The same pattern appears in `cyberguard-secret`, `cyberguard-sca`, and `cyberguard-container` (the latter two have no file-size limit at all); `cyberguard-mcp` (`facade.rs`) accepts unconfined paths.
  - **Remediation Plan:** Use `symlink_metadata()` to reject symlinks escaping the repository root; apply size, binary check, and exclusion filters uniformly to direct file targets; confine MCP file operations to workspace roots.
- [ ] **Subprocess Supervisor Hardening Gaps (`cyberguard-proc`):**
  - **Issue:** `cyberguard-proc/src/supervisor.rs:12-50`:
    - Does not set `cmd.stdin(Stdio::null())` (dangerous if run alongside stdio MCP).
    - Missing `cmd.kill_on_drop(true)` (dropped futures orphan process groups).
    - Inherits full parent environment (can leak `CYBERGUARD_SCOPE_KEY` or tokens to external tools).
    - Casts `child.id()` with `id as i32` before `killpg`.
    - Uses `#[allow(unsafe_code)] unsafe { cmd.pre_exec(...) }` at L32-39, contradicting the blanket `#![deny(unsafe_code)]` statement in `SECURITY_MODEL.md:54`.
  - **Remediation Plan:** Ensure `stdin(Stdio::null())`, set `kill_on_drop(true)`, clear/sanitize process environment variables to a minimal safe allowlist (`PATH`, `HOME`, `LANG`), fix `killpg` PID casting, and audit/reconcile `pre_exec` unsafe code boundary.

#### 3. Medium Findings (Correctness, Scanner Soundness & Stubs)
- [ ] **SAST Line Numbers & Inline Suppressions (`cyberguard-sast`, `cyberguard-core`):**
  - **Issue:** In `cyberguard-sast/src/engine.rs:52-60`, `prefix.lines().count()` strips a trailing `\n`, reporting line - 1 whenever a match starts at column 1 of line >= 2 and misaligning `SuppressionMap::is_suppressed`. In `cyberguard-core/src/suppression.rs`, `parse_line_directive` matches `//` and `#` inside string literals/URLs and treats `// aegix:ignore -- reason` (without a rule ID) as wildcard `*` suppressing all rules.
  - **Remediation Plan:** Fix line count calculation to properly preserve trailing newlines; ensure suppression parsing only operates on actual comment tokens outside string literals; require explicit rule ID or `--all` flag.
- [ ] **Stubbed / Non-Functional Features Wiring:**
  - [ ] **MCP Port Binding (`cyberguard-cli`):** `aegix mcp --port` ignores `--port` and always runs stdio; implement TCP listener when `--port` is supplied.
  - [ ] **Config File Field Plumbing (`cyberguard-core`, `cyberguard-cli`):** `CyberguardConfig` errors are swallowed via `.unwrap_or_else(|_| CyberguardConfig::default())`, and most config fields (`timeout_seconds`, `max_output_bytes`, `log_level`, `reporting.*`) are unwired; propagate config errors and plumb all fields to engine runners.
  - [ ] **SCA Advisory Expansion & Lockfile Classification (`cyberguard-sca`):** `cyberguard-sca` ships only 6 hardcoded advisories (3 Cargo, 3 npm), has no PyPI parser, and misclassifies `is_direct` in both Cargo (`source.is_none()` marks all registry deps transitive) and npm (`node_modules/` count marks hoisted transitive deps direct). Expand embedded database and fix direct dependency heuristics.
  - [ ] **Container Layer Traversal (`cyberguard-container`):** `OciInspector` only reads top-level tar entries and does not traverse `manifest.json` / nested layer tarballs, returning 0 packages on real docker save / OCI archives; implement full manifest layer traversal.
  - [ ] **DAST Rate Limiting (`cyberguard-dast`):** Plumb `DastEngine::max_rps` to actively throttle HTTP request rates.
- [ ] **Parser & Rule Inaccuracies:**
  - [ ] **Schemathesis Flag Bug (`cyberguard-api`):** `cyberguard-api/src/schemathesis.rs`: `config.insecure` passes `--validate-schema=false` instead of disabling TLS verification, ignores `timeout_ms`, and passes `spec_path` without `--` / leading-dash guard.
  - [ ] **Mobile AXML & Privacy Descriptions (`cyberguard-mobile`):** `parse_axml_string_pool` consumes only one length prefix for UTF-8 strings (corrupting UTF-8 tags/attrs); `CG-MOB-008` never detects missing privacy descriptions; `release_mode` is unused.
  - [ ] **Cloud & IaC Rules Engine (`cyberguard-cloud`, `cyberguard-iac`):** AWS IAM checks are case-sensitive, ignore `NotAction`/`NotResource`/`Deny`, and miss cross-statement escalation pairs; HCL parser counts raw `{/}` inside strings/comments and breaks on multi-line lists, inline maps, and trailing comments.
  - [ ] **Secret Masking & Scanner Precision (`cyberguard-secret`):** `mask_secret` exposes up to 6 characters + exact length (4 prefix + 2 suffix), `CG-SEC-SLACK-001` rejects hyphens in multi-segment Slack tokens, and `scan_file_content` only scans single lines (leaving multi-line PEM bodies unmasked).
  - [ ] **Graph & Threat Modeling Alignment (`cyberguard-graph`, `cyberguard-threat`):** `StandardTelemetryIngester` expects `sec-`/`sast-`/`dast-` prefixes rather than `CG-*` rule IDs; `StandardGraphCorrelator` performs ungrounded Cartesian linking across unrelated nodes; `StandardPathFinder` truncates at `max_paths` in `BTreeMap` order before sorting by risk.
- [ ] **SARIF & Baseline Inconsistencies:**
  - [ ] **Deterministic Fingerprint Collisions (`cyberguard-core`):** `SarifResult::compute_deterministic_fingerprint` hashes `rule_id + uri + start_line` without delimiters or `start_column`, collapsing multiple findings on the same line (observed during `aegix scan .`, where `fuzzer.rs:325` emitted 4 alerts with identical fingerprint `e5251f56fe831dce`). Add delimiters and column coordinates.
  - [ ] **Baseline Filtering Parity Across Formats (`cyberguard-cli`):** `aegix cloud --format json` and `aegix iac --format json` bypass `--baseline` filtering, whereas sarif and terminal apply it; unify baseline filtering across all commands and output formats.

### Phase 2.1: Packaging & Universal Distribution
- [ ] **Multi-Architecture Release Binaries:**
  - Automated GitHub Releases for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin` (M1/M2/M3), and `x86_64-pc-windows-msvc`.
  - SHA-256 checksums (`SHA256SUMS.txt`) and Cosign signatures.
- [ ] **Package Manager Distribution:**
  - Publish CLI to crates.io (`cargo install <new-name>`).
  - Homebrew core formula (`brew install <new-name>`).
  - Official OCI Docker container on GitHub Packages (`ghcr.io`) and Docker Hub.
  - Official GitHub Marketplace Action (`uses: <new-name>/action@v1`).
- [ ] **IDE & Developer Tooling:**
  - Official VS Code extension with real-time inline SARIF diagnostics.
  - Pre-commit hook integration (`.pre-commit-hooks.yaml`).
  - Pull-request comment bot (concise Markdown tables for GitHub / GitLab / Bitbucket).

### Phase 2.2: Empirical Benchmarks & Academic Validation
- [ ] **Vulnerable Target Benchmarks:**
  - Run the platform against standard benchmarks: OWASP Juice Shop, DVWA, WebGoat, and benchmark repos.
- [ ] **Competitive Precision & Recall Whitepaper:**
  - Measure and publish head-to-head empirical metrics vs. Semgrep, Gitleaks, and Trivy:
    - Scan execution speed (wall-clock time across 100k LOC).
    - Peak memory footprint (RSS in MB).
    - Precision, Recall, and False Positive Rate (FPR).

### Phase 2.3: Community & OpenSSF Standards
- [ ] **30-Second Terminal Demo:** Clean asciinema / GIF recording showing installation, instant scan, vulnerability discovery, and SARIF output.
- [ ] **Documentation Portal:** Comprehensive documentation site with quickstarts, complete rule reference catalog, and CI/CD copy-paste workflows.
- [ ] **Rule Authoring Guide:** Step-by-step documentation on how community contributors can write and submit new YAML declarative rules.
- [ ] **Curated Community Backlog:** Create 20+ `good first issue` tickets for community rule authors.
- [ ] **OpenSSF Best Practices Badge & Scorecard:** Achieve passing $\to$ silver badge from the Linux Foundation Open Source Security Foundation.
- [ ] **Community Support Channels:** Setup project Discord and GitHub Discussions.

### Phase 2.4: Legal, Trademark & Brand Defensibility
- [ ] **Trademark Registration:** File trademark application for the new selected brand name in the US (USPTO), UK, and EU.
- [ ] **Corporate Entity Formation:** Incorporate legal entity (e.g. Delaware C-Corp) to hold intellectual property and manage commercial operations.
- [ ] **Independent 3rd-Party Security Audit:** Commission external audit of the scanner codebase, subprocess runners, and parsers before enterprise production rollouts.

### Phase 2.5: Commercial Strategy & Open-Core Monetization
- [ ] **Open-Core Licensing Boundary:**
  - **Free & Open-Source (Apache 2.0):** CLI scanner, all local scanning engines, MCP AI agent integration, SARIF/JSON outputs, local baseline files.
  - **Commercial Paid Tier (Enterprise SaaS / On-Premise Console):**
    - Centralized multi-repo web dashboard.
    - Single Sign-On (SAML / Okta / Azure AD).
    - Team-level Role-Based Access Control (RBAC).
    - Centralized compliance policy enforcement across orgs.
    - Historical trend analytics and compliance mapping reports.
- [ ] **Compliance Framework Cross-Walks:**
  - Map finding categories to regulatory standards (SOC 2 Type II CC7.1/CC7.2, ISO/IEC 27001 A.12.6, PCI-DSS v4.0 Requirement 6).
- [ ] **Customer Discovery Program:**
  - Conduct 20–30 structured interviews with AppSec leads, CISOs, and Platform/DevOps managers to validate pricing and enterprise features.
