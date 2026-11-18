use crate::error::DastError;
use crate::models::{DastFinding, FindingSeverity};
use cyberguard_proc::{execute_process, ProcessOptions};
use serde::Deserialize;
use std::time::Duration;
use url::Url;

#[derive(Debug, Deserialize)]
struct NucleiFinding {
    #[serde(rename = "template-id")]
    template_id: Option<String>,
    info: Option<NucleiInfo>,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
    #[serde(rename = "extracted-results")]
    extracted_results: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: Option<String>,
    severity: Option<String>,
    description: Option<String>,
    remediation: Option<String>,
}

pub async fn run_supervised_nuclei(
    target_url: &Url,
    timeout_secs: u64,
) -> Result<Vec<DastFinding>, DastError> {
    let url_str = target_url.to_string();
    let args = vec![
        "-u".to_string(),
        url_str,
        "-jsonl".to_string(),
        "-silent".to_string(),
        "-no-interactsh".to_string(),
        "-disable-update-check".to_string(),
        "-stats=false".to_string(),
    ];

    let options = ProcessOptions::new("nuclei", args)
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_max_output(10 * 1024 * 1024);

    let output = execute_process(options)
        .await
        .map_err(|e| DastError::Subprocess(format!("Failed to execute nuclei: {}", e)))?;

    let mut findings = Vec::new();

    for line in output.stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(item) = serde_json::from_str::<NucleiFinding>(trimmed) {
            let id = item
                .template_id
                .unwrap_or_else(|| "NUCLEI-UNKNOWN".to_string());
            let title = item
                .info
                .as_ref()
                .and_then(|i| i.name.clone())
                .unwrap_or_else(|| id.clone());
            let description = item
                .info
                .as_ref()
                .and_then(|i| i.description.clone())
                .unwrap_or_else(|| "Nuclei finding".to_string());
            let remediation = item
                .info
                .as_ref()
                .and_then(|i| i.remediation.clone())
                .unwrap_or_else(|| "Remediate according to template recommendation.".to_string());

            let severity = match item.info.as_ref().and_then(|i| i.severity.as_deref()) {
                Some("critical") => FindingSeverity::Critical,
                Some("high") => FindingSeverity::High,
                Some("medium") => FindingSeverity::Medium,
                Some("low") => FindingSeverity::Low,
                _ => FindingSeverity::Info,
            };

            let endpoint = item
                .matched_at
                .unwrap_or_else(|| target_url.path().to_string());
            let evidence = item
                .extracted_results
                .map(|r| r.join(", "))
                .unwrap_or_else(|| "Matched template criteria".to_string());

            findings.push(DastFinding::new(
                id,
                title,
                description,
                severity,
                endpoint,
                evidence,
                remediation,
            ));
        }
    }

    Ok(findings)
}
