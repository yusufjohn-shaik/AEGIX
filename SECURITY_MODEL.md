# 🛡️ Aegix Threat Model & Security Boundaries

This document defines the formal threat model, operational scope, architectural boundaries, and explicit non-goals for the **Aegix** platform.

---

## 1. System Overview & Trust Assumptions

Aegix is an autonomous vulnerability intelligence and remediation tool designed to execute locally in developer workstations and continuous integration (CI/CD) pipelines.

### Trust Boundaries
1. **The Scanner Host:** The environment where Aegix executes (developer laptop, CI runner, container) is assumed to have an authentic, uncompromised operating system.
2. **Target Inputs (Untrusted):**
   - Source code repositories, lockfiles, and configuration files scanned by SAST/SCA/Secret engines are treated as **untrusted input**.
   - Dockerfiles and OCI container image layers are treated as **untrusted archives**.
   - Remote servers probed by Recon/DAST engines are treated as **potentially adversarial hosts**.
3. **Output Telemetry:** OASIS SARIF v2.1.0 and OCSF telemetry produced by Aegix is sanitized of terminal control sequences and ANSI escape codes before emission.

---

## 2. Detection Scope: What Aegix Catches

| Layer | Engine | Primary Detection Capabilities |
| :--- | :--- | :--- |
| **Code (SAST)** | `aegix-sast` | Direct string concatenation in SQL queries (`CG-SQLI-001`), unescaped OS command injection sinks (`CG-CMDI-001`), path traversal sequences (`CG-PATH-001`), weak hashing primitives (MD5/SHA-1 in security contexts, `CG-CRYP-001`), and hardcoded plaintext credentials (`CG-SECR-001`). |
| **Dependencies (SCA)** | `aegix-sca` | Known CVEs and GHSA advisories in parsed `Cargo.lock` and `package-lock.json` lockfiles; automated CycloneDX v1.5 and SPDX v2.3 Software Bill of Materials (SBOM) generation. |
| **Credentials** | `aegix-secret` | High-entropy tokens exceeding Shannon entropy thresholds (3.5+ for base64, 3.0+ for hex); multi-provider pattern matching (AWS AKIA/ABIA, GitHub ghp/ghs tokens, Stripe sk_live/rk_live keys, OpenAI sk- keys, Slack xoxb/xoxp tokens, PEM private keys). |
| **Containers (OCI)** | `aegix-container` | Dangerous Dockerfile directives (running as root user, unpinned `latest` base images, `curl \| sh` pipe-to-shell patterns, hardcoded secrets, `ADD` instead of `COPY`); daemonless OCI tar layer package auditing. |
| **Reconnaissance** | `aegix-net` | Authorized TCP port scanning with non-intrusive banner grabbing; cryptographic Proof-of-Authorization (`.security-scope.yaml`) boundary verification. |
| **Dynamic (DAST)** | `aegix-dast` | Protocol-aware security header audits (HSTS, CSP unsafe-inline/unsafe-eval, X-Frame-Options, X-Content-Type-Options nosniff, CORS wildcard + credentials); sensitive endpoint exposure (`/.env`, `/.git/HEAD`, Spring Actuator, Swagger); context-aware parameter reflection (unescaped HTML XSS injection). |

---

## 3. Explicit Non-Goals: What Aegix Does NOT Catch

To maintain transparent engineering integrity, the following areas are outside the scope of current Aegix detection engines:

1. **Complex Business Logic Flaws:**
   Aegix cannot detect domain-specific logic vulnerabilities (e.g., bypassing a multi-step checkout workflow or unauthorized manipulation of account balances) without formal business-logic specifications.
2. **Zero-Day Vulnerabilities in Dependencies:**
   The SCA engine matches dependencies against known vulnerability advisory catalogs (OSV, GitHub Advisories, NVD). Undisclosed zero-day vulnerabilities with no public advisory are not detected by SCA.
3. **Obfuscated or Packed Malware in Binaries:**
   Aegix static and container analysis is focused on software engineering configurations, source code, and package manager manifests. It is not an endpoint antivirus (AV) or behavioral sandboxing engine for packed executable malware.
4. **Multi-Service Distributed Race Conditions:**
   Aegix analyzes local source trees and active endpoints. Distributed race conditions spanning separate asynchronous microservices without shared code analysis are out of scope.

---

## 4. Defensive Rigor: Defending the Scanner Itself

A security scanner running with elevated repository access in CI must not become an attack vector. Aegix enforces defensive controls across all ingestion paths:

### 1. Memory Safety & Zero C-Bindings
- Entire workspace enforces `#![deny(unsafe_code)]` at compile time.
- All TLS communication uses pure Rust `rustls-tls` rather than legacy OpenSSL C-bindings.

### 2. Regular Expression DoS (ReDoS) Immunity
- All pattern matching uses the Rust `regex` crate, which compiles regular expressions into non-backtracking Deterministic Finite Automata (DFA).
- Evaluation runs in linear time $O(n)$ relative to input length, mathematically preventing algorithmic complexity exhaustion attacks.
- Compiled automata enforce strict 1 MB size limits (`size_limit(1024 * 1024)`).

### 3. DNS Rebinding TOCTOU & SSRF Protection
- **Pre-Flight Host Validation:** Targets and redirect hops are resolved and validated against the Scope Gate before any network connection is opened.
- **Bogon & Cloud Metadata Blacklist:** Private subnets (RFC 1918), link-local addresses, and cloud instance metadata services (`169.254.169.254`, IPv6 `[fd00:ec2::254]`) are strictly rejected.
- **Atomic IP Pinning (`PinnedResolver`):** HTTP requests are pinned to the exact IP validated during pre-flight resolution, defeating multi-A DNS rebinding attacks.

### 4. Decompression Bomb & Resource Exhaustion Defense
- **Streaming Response Reader:** HTTP response bodies are read chunk-by-chunk with a strict 2 MB ceiling (`MAX_BODY_BYTES`). If chunked compression bombs attempt to expand beyond 2 MB, the connection is aborted immediately.
- **Subprocess Buffer Bounds:** All supervised external tools executed via `cyberguard-proc` (e.g., Nmap, Nuclei) enforce hard 10 MB maximum stdout/stderr buffer limits and mandatory execution timeouts.
- **Archive Extraction Bounds:** Tarball readers validate paths against Zip-Slip path traversal attacks and reject entries referencing `..` or leading slashes.

---

## 5. Vulnerability Reporting

If you discover a security vulnerability within Aegix itself, please report it responsibly according to our [Security Policy](SECURITY.md) via private GitHub Security Advisories. Do not open public issues for zero-day vulnerabilities in this platform.
