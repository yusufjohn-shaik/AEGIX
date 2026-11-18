use crate::client::DastClient;
use crate::error::DastError;
use crate::models::{DastFinding, FindingSeverity};
use cyberguard_net::ScopeGate;
use reqwest::header::CONTENT_TYPE;
use reqwest::Method;
use std::collections::HashSet;
use url::Url;

const CURATED_PARAMS: &[&str] = &["q", "search", "id", "redirect", "url", "next"];

pub async fn check_active_reflection(
    client: &DastClient,
    target_url: &Url,
    scope: &ScopeGate,
) -> Result<Vec<DastFinding>, DastError> {
    let mut findings = Vec::new();
    let mut params_to_test = HashSet::new();

    // 1. Collect query parameters already present on the URL
    for (k, _) in target_url.query_pairs() {
        params_to_test.insert(k.to_string());
    }

    // 2. If no parameters are present, fall back to the top curated parameters
    if params_to_test.is_empty() {
        for p in CURATED_PARAMS {
            params_to_test.insert(p.to_string());
        }
    }

    let nonce = "cg987a1";
    let probe_payload = format!("{}<script>alert(1)</script>", nonce);

    for param in params_to_test {
        let mut probe_url = target_url.clone();
        probe_url
            .query_pairs_mut()
            .clear()
            .append_pair(&param, &probe_payload);

        if let Ok((status, headers, body)) = client
            .send_request(Method::GET, &probe_url, None, scope)
            .await
        {
            if !status.is_success() {
                continue;
            }

            // Verify Content-Type is HTML
            let is_html = headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.contains("text/html") || ct.contains("application/xhtml+xml"))
                .unwrap_or(false);

            if !is_html {
                continue;
            }

            let body_str = String::from_utf8_lossy(&body);

            // True positive criteria: raw unencoded <script> payload appears in HTML body
            // and is NOT entity-encoded as &lt;script&gt;
            if body_str.contains(&probe_payload)
                && !body_str.contains(&format!("{}&lt;script&gt;alert(1)&lt;/script&gt;", nonce))
            {
                findings.push(DastFinding::new(
                    "CG-DAST-REFL-HTML",
                    "Unescaped Cross-Site Scripting (XSS) Parameter Reflection",
                    format!(
                        "Parameter '{}' reflects raw HTML metacharacters without contextual encoding.",
                        param
                    ),
                    FindingSeverity::High,
                    probe_url.path(),
                    format!("Reflected unescaped payload in parameter '{}': {}", param, probe_payload),
                    "Contextually HTML-encode user input or adopt a strict templating engine with auto-escaping enabled.",
                ));
            }
        }
    }

    Ok(findings)
}
