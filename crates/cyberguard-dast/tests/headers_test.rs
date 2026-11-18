use cyberguard_dast::checks::check_security_headers;
use reqwest::header::{HeaderMap, HeaderValue};

#[test]
fn test_hsts_evaluated_only_on_https() {
    let empty_headers = HeaderMap::new();

    // Over plain HTTP, missing HSTS must NOT trigger a finding
    let http_findings = check_security_headers(&empty_headers, false, "/");
    assert!(!http_findings.iter().any(|f| f.id == "CG-DAST-HDR-HSTS"));

    // Over HTTPS, missing HSTS MUST trigger a finding
    let https_findings = check_security_headers(&empty_headers, true, "/");
    assert!(https_findings.iter().any(|f| f.id == "CG-DAST-HDR-HSTS"));
}

#[test]
fn test_csp_unsafe_directives_detected() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'"),
    );

    let findings = check_security_headers(&headers, true, "/");
    let unsafe_csp = findings.iter().find(|f| f.id == "CG-DAST-HDR-CSP-UNSAFE");
    assert!(unsafe_csp.is_some());
}

#[test]
fn test_cors_wildcard_with_credentials_flagged() {
    let mut headers = HeaderMap::new();
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert(
        "access-control-allow-credentials",
        HeaderValue::from_static("true"),
    );

    let findings = check_security_headers(&headers, true, "/");
    let cors_finding = findings.iter().find(|f| f.id == "CG-DAST-HDR-CORS");
    assert!(cors_finding.is_some());
    assert_eq!(
        cors_finding.unwrap().severity,
        cyberguard_dast::FindingSeverity::High
    );
}

#[test]
fn test_clean_headers_produce_no_security_warnings() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );

    let findings = check_security_headers(&headers, true, "/");
    assert!(findings.is_empty());
}
