use crate::models::{DastFinding, FindingSeverity};
use reqwest::header::HeaderMap;

pub fn check_security_headers(
    headers: &HeaderMap,
    is_https: bool,
    endpoint: &str,
) -> Vec<DastFinding> {
    let mut findings = Vec::new();

    // 1. HSTS (Strict-Transport-Security) - evaluated only over HTTPS
    if is_https {
        if let Some(val) = headers.get("strict-transport-security") {
            let val_str = val.to_str().unwrap_or_default();
            if !val_str.contains("max-age") {
                findings.push(DastFinding::new(
                    "CG-DAST-HDR-HSTS",
                    "Invalid or Ineffective HSTS Header",
                    "The Strict-Transport-Security header is present but lacks a valid max-age directive.",
                    FindingSeverity::Low,
                    endpoint,
                    format!("Strict-Transport-Security: {}", val_str),
                    "Configure Strict-Transport-Security with a robust max-age directive (e.g., max-age=31536000; includeSubDomains).",
                ));
            }
        } else {
            findings.push(DastFinding::new(
                "CG-DAST-HDR-HSTS",
                "Missing HTTP Strict Transport Security (HSTS) Header",
                "The web server does not enforce HTTPS connections via the Strict-Transport-Security header.",
                FindingSeverity::Low,
                endpoint,
                "Strict-Transport-Security header missing",
                "Enforce HSTS by adding the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
            ));
        }
    }

    // 2. Content-Security-Policy (CSP)
    if let Some(csp_val) = headers.get("content-security-policy") {
        let csp_str = csp_val.to_str().unwrap_or_default();
        if csp_str.contains("'unsafe-inline'") || csp_str.contains("'unsafe-eval'") {
            findings.push(DastFinding::new(
                "CG-DAST-HDR-CSP-UNSAFE",
                "Insecure Content-Security-Policy Allows Unsafe Directives",
                "The Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval', undermining XSS defenses.",
                FindingSeverity::Medium,
                endpoint,
                format!("Content-Security-Policy: {}", csp_str),
                "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP; use cryptographic nonces or hashes.",
            ));
        }
    } else {
        findings.push(DastFinding::new(
            "CG-DAST-HDR-CSP",
            "Missing Content-Security-Policy (CSP) Header",
            "The web server does not send a Content-Security-Policy header, leaving the application vulnerable to cross-site scripting (XSS) and data injection.",
            FindingSeverity::Medium,
            endpoint,
            "Content-Security-Policy header missing",
            "Implement a strict Content-Security-Policy header restricting script and resource loading origins.",
        ));
    }

    // 3. X-Frame-Options (Clickjacking Protection)
    if let Some(xframe) = headers.get("x-frame-options") {
        let val_str = xframe.to_str().unwrap_or_default().to_uppercase();
        if val_str != "DENY" && val_str != "SAMEORIGIN" {
            findings.push(DastFinding::new(
                "CG-DAST-HDR-XFRAME",
                "Permissive or Deprecated X-Frame-Options Header",
                "The X-Frame-Options header is set to a non-standard or overly permissive value.",
                FindingSeverity::Medium,
                endpoint,
                format!("X-Frame-Options: {}", val_str),
                "Set X-Frame-Options to DENY or SAMEORIGIN, or configure frame-ancestors in CSP.",
            ));
        }
    } else if headers
        .get("content-security-policy")
        .map(|v| v.to_str().unwrap_or_default().contains("frame-ancestors"))
        .unwrap_or(false)
    {
        // frame-ancestors in CSP supersedes X-Frame-Options
    } else {
        findings.push(DastFinding::new(
            "CG-DAST-HDR-XFRAME",
            "Missing X-Frame-Options Header (Clickjacking Risk)",
            "The web application does not restrict embedding in iframes via X-Frame-Options or CSP frame-ancestors.",
            FindingSeverity::Medium,
            endpoint,
            "X-Frame-Options header missing",
            "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to protect against UI redressing/clickjacking.",
        ));
    }

    // 4. X-Content-Type-Options: nosniff
    if let Some(nosniff) = headers.get("x-content-type-options") {
        let val_str = nosniff.to_str().unwrap_or_default().to_lowercase();
        if val_str != "nosniff" {
            findings.push(DastFinding::new(
                "CG-DAST-HDR-NOSNIFF",
                "Invalid X-Content-Type-Options Header",
                "The X-Content-Type-Options header is present but not set to 'nosniff'.",
                FindingSeverity::Low,
                endpoint,
                format!("X-Content-Type-Options: {}", val_str),
                "Set 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
            ));
        }
    } else {
        findings.push(DastFinding::new(
            "CG-DAST-HDR-NOSNIFF",
            "Missing X-Content-Type-Options Header",
            "The web server does not send the 'X-Content-Type-Options: nosniff' header.",
            FindingSeverity::Low,
            endpoint,
            "X-Content-Type-Options header missing",
            "Add 'X-Content-Type-Options: nosniff' to HTTP responses.",
        ));
    }

    // 5. CORS Misconfiguration (Access-Control-Allow-Origin: * with credentials)
    if let (Some(origin), Some(creds)) = (
        headers.get("access-control-allow-origin"),
        headers.get("access-control-allow-credentials"),
    ) {
        let origin_str = origin.to_str().unwrap_or_default();
        let creds_str = creds.to_str().unwrap_or_default();
        if origin_str == "*" && creds_str == "true" {
            findings.push(DastFinding::new(
                "CG-DAST-HDR-CORS",
                "Insecure Cross-Origin Resource Sharing (CORS) Configuration",
                "Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is true, violating CORS standards and allowing credential leakage.",
                FindingSeverity::High,
                endpoint,
                "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                "Do not allow wildcard origins when credentials are supported. Whitelist trusted specific origins.",
            ));
        }
    }

    // 6. Information Leakage (Server / X-Powered-By)
    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or_default();
        if server_str.contains('/') {
            findings.push(DastFinding::new(
                "CG-DAST-HDR-BANNER",
                "Detailed Server Banner Information Leakage",
                "The Server header discloses precise software version numbers, aiding attacker reconnaissance.",
                FindingSeverity::Info,
                endpoint,
                format!("Server: {}", server_str),
                "Configure your web server to suppress or genericize the Server response header.",
            ));
        }
    }
    if let Some(powered_by) = headers.get("x-powered-by") {
        let val_str = powered_by.to_str().unwrap_or_default();
        findings.push(DastFinding::new(
            "CG-DAST-HDR-BANNER",
            "Technology Stack Disclosed via X-Powered-By",
            "The X-Powered-By header advertises underlying runtime technologies.",
            FindingSeverity::Info,
            endpoint,
            format!("X-Powered-By: {}", val_str),
            "Disable the X-Powered-By header in your application framework configuration.",
        ));
    }

    findings
}
