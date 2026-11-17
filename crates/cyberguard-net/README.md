# `cyberguard-net`

Network Reconnaissance & Cryptographic Scope Gate Engine for the CyberGuard platform.

## Features
- **Mandatory Scope Gate:** Strictly verifies target hostnames and IPs against `.security-scope.yaml` and bogon/cloud metadata blacklists before opening any sockets.
- **DNS Rebinding Prevention:** Eliminates TOCTOU through pre-resolved `PinnedTarget` socket binding.
- **Pure-Rust Async TCP Scanner:** High-throughput, non-blocking TCP connect probing with bounded `tokio::sync::Semaphore` concurrency and curated `DEFAULT_TOP_PORTS`.
- **Safe Banner Grabbing:** Protocol-aware active (HTTP HEAD) and passive banner extraction bounded to 1024 bytes with ANSI control-code sanitization.
- **External Nmap Supervision:** Supervised adapter via `cyberguard-proc` parsing grepable `-oG -` output without XML overhead.
- **OASIS SARIF v2.1.0 Telemetry:** Standard location fingerprints, rule IDs, and structured reporting.
