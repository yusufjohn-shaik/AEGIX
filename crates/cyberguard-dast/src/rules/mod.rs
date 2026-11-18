pub mod catalog;
pub mod matcher;

pub use catalog::get_embedded_rules;
pub use matcher::evaluate_matchers;

use crate::client::DastClient;
use crate::error::DastError;
use crate::models::{DastFinding, DastRule};
use cyberguard_net::ScopeGate;
use reqwest::Method;
use std::str::FromStr;
use url::Url;

pub async fn evaluate_rules(
    client: &DastClient,
    base_url: &Url,
    rules: &[DastRule],
    scope: &ScopeGate,
) -> Result<Vec<DastFinding>, DastError> {
    let mut findings = Vec::new();

    for rule in rules {
        let method = Method::from_str(&rule.request.method).unwrap_or(Method::GET);
        let probe_url = match base_url.join(&rule.request.path) {
            Ok(u) => u,
            Err(_) => continue,
        };

        if let Ok((status, headers, body)) = client
            .send_request(method, &probe_url, Some(&rule.request.headers), scope)
            .await
        {
            let matched = evaluate_matchers(
                &rule.matchers,
                rule.condition,
                status.as_u16(),
                &headers,
                &body,
            )?;

            if matched {
                findings.push(DastFinding::new(
                    &rule.id,
                    &rule.name,
                    format!("Declarative security rule '{}' matched on endpoint.", rule.name),
                    rule.severity,
                    probe_url.path(),
                    format!("HTTP {} OK with rule matcher criteria", status),
                    "Review and restrict public exposure of this administrative or internal interface.",
                ));
            }
        }
    }

    Ok(findings)
}
