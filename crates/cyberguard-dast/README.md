# `cyberguard-dast`

Dynamic Application Security Testing (DAST) Engine for the CyberGuard platform.

## Features
- **Mandatory Scope Gate Enforcement:** Directly integrated with `cyberguard-net::ScopeGate` to block out-of-scope probes, loopback, and cloud metadata (`169.254.169.254`).
- **DNS Rebinding & TOCTOU Immunity:** Strict manual redirect loop (`Policy::none()`) with atomic IP pinning on every redirect hop.
- **Decompression Bomb Protection:** Hard 2 MB response body ceiling (`take(2MB)`) and non-textual MIME type filtering.
- **Security Misconfiguration & Header Auditing:** Protocol-aware HSTS, CSP, X-Frame-Options, X-Content-Type-Options, CORS, and Server banner checks.
- **Sensitive Endpoint Discovery:** Probes critical exposure endpoints (`/.env`, `/.git/HEAD`, `/actuator/*`) with content-signature validation to eliminate SPA soft-404 false positives.
- **Context-Aware Active Reflection:** Probes candidate query parameters for unescaped HTML execution contexts (`<script>`, `"`, `'`).
- **Declarative YAML Rule Engine:** Linear-time regex evaluation with size limits.
- **Supervised External Nuclei Runner:** Optional execution via `cyberguard-proc` with `-no-interactsh` and asynchronous stream draining.
- **OASIS SARIF v2.1.0 Telemetry:** Deterministic SHA-256 location fingerprints via `cyberguard-core`.
