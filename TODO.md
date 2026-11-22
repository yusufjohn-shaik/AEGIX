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
- [ ] **Module 15: Threat Modeling & ATT&CK Matrix (`aegix-threat`):** Automated MITRE ATT&CK mapping engine.
- [ ] **Live Vulnerability Advisory Sync:** Automated synchronization with live OSV.dev and GitHub Security Advisories.
- [ ] **Verified Secret Liveness Checks:** Optional safe active API verification (`--verify-secrets`) to test if discovered keys are active.

### Phase 1.5: The Autonomous Differentiators (Modules 16–19)
- [ ] **Module 16: Model Context Protocol (MCP) Server (`aegix-mcp`):** Native JSON-RPC MCP server enabling Cursor, Claude Code, Antigravity, and AI coding agents to invoke the scanner directly.
- [ ] **Module 17: Attack Path Engine (`aegix-graph`):** In-memory Directed Acyclic Graph (DAG) connecting external entrypoints $\to$ API routes $\to$ reachable CVEs $\to$ leaked secrets $\to$ cloud privilege escalation.
- [ ] **Module 18: Tri-Factor Prioritizer (`aegix-risk`):**
  - Implement real single-language reachability analysis (Rust call-graph via `cargo metadata` first).
  - Compute mathematical risk: $\text{Score} = \text{CVSS} \times \text{EPSS} \times \text{Reachability}$.
- [ ] **Module 19: Tree-sitter AST & Autonomous Remediation (`aegix-fix`):**
  - Transition SAST from pure regex to Tree-sitter AST parsing for Python, JavaScript/TypeScript, and Go.
  - Implement intra-procedural taint tracking (Sources $\to$ Sanitizers $\to$ Sinks).
  - Apply surgical AST patches and auto-generate unit tests verifying eradication.

### Phase 1.6: Developer Interfaces (Modules 20–21)
- [ ] **Module 20: TUI Dashboard & Reporting (`aegix-ui`):** `ratatui` terminal interface and executive PDF/HTML report generators.
- [ ] **Module 21: Release Automation & Multi-Arch Packaging (`aegix-dist`):** Automated cross-compilation pipeline for static binaries.

---

## 🚀 BUCKET 2: WHAT WE HAVE TO DO AFTER 21 MODULES (Launch, Scale & Commercialize)

These items focus on packaging distribution, community building, empirical benchmarks, and business model monetization once the full 21-module engine is verified.

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
