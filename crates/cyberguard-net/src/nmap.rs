//! Supervised Nmap external process adapter.

use cyberguard_proc::{execute_process, ProcessOptions};
use std::time::Duration;

use crate::error::NetError;
use crate::models::{PinnedTarget, PortFinding, PortStatus};

/// Parses Nmap grepable (`-oG -`) output into structured `PortFinding` records.
#[must_use]
pub fn parse_grepable_nmap(output: &str, target_host: &str) -> Vec<PortFinding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with("Host:") || !line.contains("Ports:") {
            continue;
        }

        // Extract IP address from "Host: <ip> (<host>)"
        let ip = if let Some(rest) = line.strip_prefix("Host:") {
            rest.split_whitespace().next().unwrap_or("").to_string()
        } else {
            String::new()
        };

        // Extract Ports section: "\tPorts: ..."
        if let Some(ports_idx) = line.find("Ports:") {
            let ports_section = &line[ports_idx + 6..];
            // Stop if there is a following tab section like "\tIgnored State:"
            let ports_str = ports_section.split('\t').next().unwrap_or("").trim();

            for port_entry in ports_str.split(',') {
                let entry = port_entry.trim();
                let parts: Vec<&str> = entry.split('/').collect();
                if parts.len() >= 3 {
                    if let Ok(port_num) = parts[0].parse::<u16>() {
                        let status_str = parts[1].to_ascii_lowercase();
                        let status = match status_str.as_str() {
                            "open" => PortStatus::Open,
                            "closed" => PortStatus::Closed,
                            _ => PortStatus::Filtered,
                        };

                        let protocol = if !parts[2].is_empty() {
                            parts[2].to_string()
                        } else {
                            "tcp".to_string()
                        };

                        let service = if parts.len() > 4 && !parts[4].is_empty() {
                            parts[4].to_string()
                        } else {
                            "unknown".to_string()
                        };

                        let banner = if parts.len() > 6 && !parts[6].is_empty() {
                            Some(parts[6].trim().to_string())
                        } else {
                            None
                        };

                        findings.push(PortFinding {
                            host: target_host.to_string(),
                            ip: ip.clone(),
                            port: port_num,
                            status,
                            service,
                            banner,
                            protocol,
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Executes system `nmap` using `cyberguard-proc::execute_process`.
///
/// Security constraints:
/// - Connects exclusively to `target.ip` (pre-validated, never passes hostnames to prevent DNS TOCTOU).
/// - Restricts options to safe TCP connect scan flags: `-sT -Pn -p <ports> -oG - <ip>`.
pub async fn run_supervised_nmap(
    target: &PinnedTarget,
    ports: &[u16],
) -> Result<Vec<PortFinding>, NetError> {
    let ports_str = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let args = vec![
        "-sT".to_string(),
        "-Pn".to_string(),
        "-p".to_string(),
        ports_str,
        "-oG".to_string(),
        "-".to_string(),
        target.ip.to_string(),
    ];

    let options = ProcessOptions::new("nmap", args)
        .with_timeout(Duration::from_secs(60))
        .with_max_output(5 * 1024 * 1024);

    let output = execute_process(options).await?;

    if output.exit_code != Some(0) {
        return Err(NetError::Process(
            cyberguard_core::error::CyberguardError::Internal(format!(
                "nmap failed with exit code {:?}: {}",
                output.exit_code, output.stderr
            )),
        ));
    }

    Ok(parse_grepable_nmap(&output.stdout, &target.hostname))
}
