<div align="center">

# 🛡️ Aegix
### High-Performance Vulnerability Intelligence & Autonomous Security Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Rust Version](https://img.shields.io/badge/Rust-1.85%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![CI Status](https://img.shields.io/github/actions/workflow/status/yusufjohn-shaik/AEGIX/dco_and_lint.yml?branch=main&label=CI%20Quality%20Gate&style=flat-square)](https://github.com/yusufjohn-shaik/AEGIX/actions)
[![SARIF Standard](https://img.shields.io/badge/Standard-OASIS%20SARIF%20v2.1.0-orange.svg?style=flat-square)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![AI Agent Protocol](https://img.shields.io/badge/AI%20Protocol-Model%20Context%20Protocol%20(MCP)-8A2BE2.svg?style=flat-square)](https://modelcontextprotocol.io)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![DCO](https://img.shields.io/badge/DCO-Signed--off--by-green.svg?style=flat-square)](CONTRIBUTING.md)

<p align="center">
  <b>100% Pure Native Rust • Zero Runtime Dependencies • Linear-Time DFA Scanning • OASIS SARIF v2.1.0 Engine</b>
</p>

[Quickstart](#-quickstart) •
[Capability Matrix](#-capability-status-matrix) •
[Architecture](#-system-architecture) •
[Threat Model](SECURITY_MODEL.md) •
[Contributing](CONTRIBUTING.md)

</div>

---

## 📊 Capability Status Matrix

To maintain transparent, verifiable engineering credibility, here is what is live and verified with passing automated test suites versus what is actively being built on the roadmap:

| Capability | Module | Status | Deliverables & Interfaces |
| :--- | :--- | :---: | :--- |
| **Legal & Safe Harbor** | Module 01 | **LIVE ✅** | Apache 2.0, Statutory Safe Harbor, DCO Gate, OpenSSF Scorecard workflow |
| **CLI & Process Supervisor** | Module 02 | **LIVE ✅** | `aegix-cli`, POSIX process group sandboxing, 10 MB buffer bounds, Figment config |
| **Universal Security Bus** | Module 03 | **LIVE ✅** | `aegix-core`, OASIS SARIF v2.1.0, OCSF v1.3.0, BLAKE3 deterministic fingerprints |
| **In-Process SAST Engine** | Module 04 | **LIVE ✅** | `aegix-sast`, linear $O(n)$ regex scanner (SQLi, CMDi, Secrets, Path, Crypto), walker |
| **SCA & Supply Chain** | Module 05 | **LIVE ✅** | `aegix-sca`, Cargo/npm lockfile parsing, CycloneDX v1.5 & SPDX v2.3 SBOM, OSV advisory engine |
| **Secret Detection Engine** | Module 06 | **LIVE ✅** | `aegix-secret`, Shannon entropy analysis, multi-provider credentials detection (AWS, GitHub, Stripe, OpenAI, Slack, Keys), surgical masking |
| **Container & OCI Security** | Module 07 | **LIVE ✅** | `aegix-container`, static Dockerfile linter (8 rules), daemonless OCI/tar layer scanner, Alpine/Debian package discovery |
| **Network Recon & Scope Gate** | Module 08 | **LIVE ✅** | `aegix-net`, cryptographic Proof-of-Authorization, DNS TOCTOU-resistant PinnedTarget, async TCP scanner, safe banner grabber, supervised Nmap adapter |
| **DAST & Dynamic Security Engine** | Module 09 | **LIVE ✅** | `aegix-dast`, atomic IP-pinned redirect validation (SSRF/metadata immune), SPA soft-404 content signatures, security headers, context-aware reflection, declarative rules, supervised Nuclei |
| **API Security & Spec Fuzzing** | Module 10 | **IN PROGRESS 🔨** | OpenAPI 3.0 / Swagger schema contract validation and endpoint fuzzing |
| **MCP AI Agent Server** | Module 16 | **PLANNED 📋** | JSON-RPC Model Context Protocol server for Antigravity, Cursor, and Claude Code |
| **Attack Path Graph (DAG)** | Module 17 | **PLANNED 📋** | In-memory directed acyclic graph mapping multi-hop exploit chains |
| **AST Auto-Remediation** | Module 19 | **PLANNED 📋** | Tree-sitter AST syntax patcher and automated regression test generator |

---

## 🌟 Engineering Design Principles

Aegix is a vulnerability intelligence and autonomous remediation platform written in pure, safe Rust:

1. **Zero Runtime Dependencies:** No Python, JVM, or Node.js runtime required. Compiles to a single static, sandboxed binary.
2. **Linear-Time DFA Matching:** Uses non-backtracking regular expression automata (`regex` crate) with explicit DFA size limits to avoid ReDoS worst-case behavior.
3. **Fail-Closed Scope Gate:** Network and dynamic scanning engines strictly require pre-flight cryptographic Proof-of-Authorization (`.security-scope.yaml`) and enforce atomic IP pinning on every redirect hop to defeat DNS rebinding TOCTOU attacks.
4. **Universal SARIF v2.1.0 Data Bus:** Emits standard OASIS SARIF telemetry with deterministic BLAKE3 partial fingerprints (`logicalLocationTokenHash/v1`) to prevent duplicate alerts across commits and CI runs.
5. **AI Agent Native:** Built to expose tools to modern AI coding assistants via the Model Context Protocol (MCP).

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          AEGIX CLI & TUI INTERFACE                     │
│      aegix [scan | audit | recon | dast | trace | fix | mcp]           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│             INTELLIGENCE ENGINE & ATTACK SURFACE DISCOVERY             │
│   - Application Architecture & Endpoint Detector                       │
│   - Semantic Taint Analyzer (Sources ➔ Sanitizers ➔ Sinks)             │
│   - Modern API & Dynamic Security Validator                            │
│   - Universal SARIF v2.1.0 & OCSF Security Bus                         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│            CORRELATION ENGINE & ATTACK PATH GRAPH (DAG)                │
│   - In-Memory Graph Engine (Code ➔ Cloud ➔ Network ➔ Identity)         │
│   - Reachability Checker (Call Graph Call-Path Verifier)               │
│   - Tri-Factor Prioritizer: CVSS × EPSS (Threat Intel) × Reachability │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Prioritized, Verified Exploit Paths
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│         AUTONOMOUS REMEDIATION & MODEL CONTEXT PROTOCOL (MCP)          │
│   - Tree-sitter AST Patch Engine (Multi-language surgical fixes)       │
│   - Regression Test Synthesizer (Auto-generates unit tests)            │
│   - MCP Protocol Server (Bi-directional AI Pair Programmer Skill)      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart

### 1. Build from Source (Pure Rust)

```bash
git clone https://github.com/yusufjohn-shaik/AEGIX.git aegix
cd aegix
cargo build --release
```

### 2. Run the SAST Scanner on the Demo Fixture

Aegix includes a test fixture application so you can test vulnerability discovery immediately:

```bash
./target/release/aegix scan tests/fixtures/vulnerable-app
```

**Terminal Output:**
```text
🛡️  Aegix SAST Engine v0.9.0
Target: tests/fixtures/vulnerable-app
Workspace: .
--------------------------------------------------------------------------------
Found 5 vulnerability alert(s):

🔴 ERROR [CG-SQLI-001] tests/fixtures/vulnerable-app/app.py:9:14
   └── Potential SQL injection via raw string interpolation or concatenation.
   └── Fingerprint: 7685d4d6b246a416
🟡 WARN  [CG-CRYP-001] tests/fixtures/vulnerable-app/app.py:17:12
   └── Broken or cryptographically weak hashing algorithm (MD5/SHA1) detected.
   └── Fingerprint: 0aea6a26a7d94cf4
🔴 ERROR [CG-SECR-001] tests/fixtures/vulnerable-app/config.py:5:22
   └── Hardcoded cryptographic secret or API token detected in source code.
   └── Fingerprint: df1e1849a29a4d76
🔴 ERROR [CG-CMDI-001] tests/fixtures/vulnerable-app/handler.js:9:5
   └── Potential OS command injection via unescaped string in command invocation.
   └── Fingerprint: e582c30c13821add
🟡 WARN  [CG-PATH-001] tests/fixtures/vulnerable-app/handler.js:21:34
   └── Potential directory traversal via unvalidated relative path sequence.
   └── Fingerprint: 874987e8a2b5586e
--------------------------------------------------------------------------------
```

### 3. Export OASIS SARIF v2.1.0 Telemetry

Generate standard SARIF telemetry compatible with GitHub Code Scanning, DefectDojo, and VS Code SARIF viewers:

```bash
./target/release/aegix scan tests/fixtures/vulnerable-app --format sarif | jq .
```

### 4. Run Network Reconnaissance with Scope Gate Enforcement

Aegix includes an asynchronous network reconnaissance engine with mandatory Scope Gate enforcement (`.security-scope.yaml`), DNS TOCTOU protection, and bogon/metadata address blacklists:

```bash
./target/release/aegix recon 127.0.0.1 --scope tests/fixtures/network-scope/.security-scope.yaml --scope-key fixture-secret-key-2026 --ports 80,443,8080
```

### 5. Run Dynamic Application Security Testing (DAST)

Audit active web applications and APIs for security misconfigurations, sensitive endpoint exposures, and injection reflections with atomic IP-pinned redirect protection:

```bash
./target/release/aegix dast http://127.0.0.1:8080 --scope tests/fixtures/network-scope/.security-scope.yaml --scope-key fixture-secret-key-2026
```

---

## 🤝 Community & Contributing

Aegix is an open-source security engineering platform developed in the open.

- 💡 **Contribute:** See open issues labeled `good first issue` or propose an architectural enhancement.
- 🛡️ **Quality Standards:** Every contribution must be signed with a **Developer Certificate of Origin** (`git commit -s`) and include automated test verification.
- 📜 **Code of Conduct:** Read our [Contributor Covenant](CODE_OF_CONDUCT.md) and [Contributing Guidelines](CONTRIBUTING.md).

---

## ⚖️ Legal Safe Harbor & Ethical Research

Aegix is built **strictly for defensive security auditing, authorized vulnerability research, and continuous remediation**.

- Review our [Legal Safe Harbor Agreement](LEGAL_SAFE_HARBOR.md) covering safe-harbor protections under the US CFAA, UK Computer Misuse Act, and Indian IT Act.
- Vulnerabilities within Aegix should be reported privately via [GitHub Security Advisories](https://github.com/yusufjohn-shaik/AEGIX/security/advisories) as detailed in our [Security Policy](SECURITY.md).

---

## 📄 License

Aegix is open-source software licensed under the **[Apache License, Version 2.0](LICENSE)**.
