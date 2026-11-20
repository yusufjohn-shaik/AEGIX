use crate::error::IacError;
use crate::models::{IacFinding, IacRuleId, K8sManifest};
use crate::parser::IacParser;
use crate::traits::K8sAuditor;
use sha2::{Digest, Sha256};

pub struct DefaultK8sAuditor;

pub const DANGEROUS_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN",
    "CAP_SYS_ADMIN",
    "NET_ADMIN",
    "CAP_NET_ADMIN",
    "ALL",
    "SYS_PTRACE",
    "CAP_SYS_PTRACE",
    "SYS_RAWIO",
    "CAP_SYS_RAWIO",
    "DAC_OVERRIDE",
    "NET_RAW",
];

impl K8sAuditor for DefaultK8sAuditor {
    fn audit_manifest(
        &self,
        manifest: &K8sManifest,
        file_path: &str,
        raw_content: &str,
    ) -> Result<Vec<IacFinding>, IacError> {
        let mut findings = Vec::new();
        let pod_spec = match manifest.extract_pod_spec() {
            Some(spec) => spec,
            None => return Ok(findings),
        };

        let resource_name = manifest.metadata.name.as_deref().unwrap_or("unnamed");
        let is_system = manifest.is_system_workload();

        // --------------------------------------------------------------------
        // CG-IAC-003: Host Namespace Sharing (PID/IPC/Net)
        // --------------------------------------------------------------------
        let host_pid = pod_spec.host_pid.unwrap_or(false);
        let host_ipc = pod_spec.host_ipc.unwrap_or(false);
        let host_net = pod_spec.host_network.unwrap_or(false);

        if host_pid || host_ipc || (host_net && !is_system) {
            let (line, col) = if host_pid {
                IacParser::calculate_line_hint(raw_content, "hostPID")
            } else if host_ipc {
                IacParser::calculate_line_hint(raw_content, "hostIPC")
            } else {
                IacParser::calculate_line_hint(raw_content, "hostNetwork")
            };

            findings.push(Self::build_finding(
                IacRuleId::CgIac003,
                file_path,
                resource_name,
                &manifest.kind,
                line,
                col,
                "/spec/hostPID",
                format!(
                    "Workload '{}' shares host namespaces (hostPID: {}, hostIPC: {}, hostNetwork: {}), enabling host container escape.",
                    resource_name, host_pid, host_ipc, host_net
                ),
                "Remove hostPID, hostIPC, and hostNetwork settings or set them explicitly to false.".to_string(),
            ));
        }

        // Combine regular, init, and ephemeral containers
        let mut all_containers = pod_spec.containers.clone();
        if let Some(ref inits) = pod_spec.init_containers {
            all_containers.extend(inits.clone());
        }
        if let Some(ref ephem) = pod_spec.ephemeral_containers {
            all_containers.extend(ephem.clone());
        }

        for (idx, container) in all_containers.iter().enumerate() {
            let sec_ctx = container.security_context.as_ref();

            // ----------------------------------------------------------------
            // CG-IAC-001: Privileged Container Allowed
            // ----------------------------------------------------------------
            let is_privileged = sec_ctx.and_then(|s| s.privileged).unwrap_or(false);
            if is_privileged && !is_system {
                let (line, col) = IacParser::calculate_line_hint(raw_content, "privileged");
                findings.push(Self::build_finding(
                    IacRuleId::CgIac001,
                    file_path,
                    resource_name,
                    &manifest.kind,
                    line,
                    col,
                    format!("/spec/containers/{}/securityContext/privileged", idx),
                    format!(
                        "Container '{}' in workload '{}' runs in privileged mode, granting full root host access.",
                        container.name, resource_name
                    ),
                    "Set securityContext.privileged: false and rely on granular Linux capabilities.".to_string(),
                ));
            }

            // ----------------------------------------------------------------
            // CG-IAC-002: Container Allowed to Run as Root
            // ----------------------------------------------------------------
            let pod_run_as_user = pod_spec
                .security_context
                .as_ref()
                .and_then(|s| s.run_as_user);
            let pod_non_root = pod_spec
                .security_context
                .as_ref()
                .and_then(|s| s.run_as_non_root);
            let ctr_run_as_user = sec_ctx.and_then(|s| s.run_as_user);
            let ctr_non_root = sec_ctx.and_then(|s| s.run_as_non_root);

            let runs_as_root = ctr_run_as_user == Some(0)
                || (ctr_run_as_user.is_none() && pod_run_as_user == Some(0))
                || ctr_non_root == Some(false)
                || (ctr_non_root.is_none() && pod_non_root == Some(false))
                || (ctr_non_root.is_none()
                    && pod_non_root.is_none()
                    && ctr_run_as_user.is_none()
                    && pod_run_as_user.is_none());

            if runs_as_root && !is_system {
                let (line, col) = IacParser::calculate_line_hint(raw_content, "runAsNonRoot");
                let (final_line, final_col) = if line == 1 {
                    IacParser::calculate_line_hint(raw_content, &container.name)
                } else {
                    (line, col)
                };

                findings.push(Self::build_finding(
                    IacRuleId::CgIac002,
                    file_path,
                    resource_name,
                    &manifest.kind,
                    final_line,
                    final_col,
                    format!("/spec/containers/{}/securityContext/runAsNonRoot", idx),
                    format!(
                        "Container '{}' in workload '{}' is permitted to execute as root UID 0.",
                        container.name, resource_name
                    ),
                    "Enforce securityContext.runAsNonRoot: true and specify a non-zero runAsUser UID.".to_string(),
                ));
            }

            // ----------------------------------------------------------------
            // CG-IAC-004: Dangerous Linux Capabilities Added
            // ----------------------------------------------------------------
            if let Some(caps) = sec_ctx.and_then(|s| s.capabilities.as_ref()) {
                if let Some(ref adds) = caps.add {
                    for added in adds {
                        if DANGEROUS_CAPABILITIES
                            .iter()
                            .any(|&d| d.eq_ignore_ascii_case(added))
                        {
                            let (line, col) = IacParser::calculate_line_hint(raw_content, added);
                            findings.push(Self::build_finding(
                                IacRuleId::CgIac004,
                                file_path,
                                resource_name,
                                &manifest.kind,
                                line,
                                col,
                                format!("/spec/containers/{}/securityContext/capabilities/add", idx),
                                format!(
                                    "Container '{}' adds dangerous Linux capability '{}'.",
                                    container.name, added
                                ),
                                "Drop ALL capabilities with 'drop: [ALL]' and add only least-privilege capabilities.".to_string(),
                            ));
                            break;
                        }
                    }
                }
            }

            // ----------------------------------------------------------------
            // CG-IAC-005: Missing CPU / Memory Limits
            // ----------------------------------------------------------------
            let has_limits = container
                .resources
                .as_ref()
                .and_then(|r| r.limits.as_ref())
                .map(|l| l.contains_key("cpu") && l.contains_key("memory"))
                .unwrap_or(false);

            if !has_limits && !is_system {
                let (line, col) = IacParser::calculate_line_hint(raw_content, &container.name);
                findings.push(Self::build_finding(
                    IacRuleId::CgIac005,
                    file_path,
                    resource_name,
                    &manifest.kind,
                    line,
                    col,
                    format!("/spec/containers/{}/resources/limits", idx),
                    format!(
                        "Container '{}' omits deterministic CPU or Memory limits (DoS risk).",
                        container.name
                    ),
                    "Define resources.limits.cpu and resources.limits.memory for all production containers.".to_string(),
                ));
            }

            // ----------------------------------------------------------------
            // CG-IAC-006: Root Filesystem is Writable
            // ----------------------------------------------------------------
            let read_only_root = sec_ctx
                .and_then(|s| s.read_only_root_filesystem)
                .unwrap_or(false);
            if !read_only_root && !is_system {
                let (line, col) =
                    IacParser::calculate_line_hint(raw_content, "readOnlyRootFilesystem");
                let (final_line, final_col) = if line == 1 {
                    IacParser::calculate_line_hint(raw_content, &container.name)
                } else {
                    (line, col)
                };

                findings.push(Self::build_finding(
                    IacRuleId::CgIac006,
                    file_path,
                    resource_name,
                    &manifest.kind,
                    final_line,
                    final_col,
                    format!(
                        "/spec/containers/{}/securityContext/readOnlyRootFilesystem",
                        idx
                    ),
                    format!(
                        "Container '{}' has a writable root filesystem.",
                        container.name
                    ),
                    "Set securityContext.readOnlyRootFilesystem: true and mount writable state to temporary emptyDir volumes.".to_string(),
                ));
            }
        }

        Ok(findings)
    }
}

impl DefaultK8sAuditor {
    #[allow(clippy::too_many_arguments)]
    fn build_finding(
        rule: IacRuleId,
        file_path: &str,
        resource_id: &str,
        resource_type: &str,
        line: usize,
        column: usize,
        config_path: impl Into<String>,
        description: String,
        remediation: String,
    ) -> IacFinding {
        let config_path_str = config_path.into();
        let mut hasher = Sha256::new();
        hasher.update(rule.as_str().as_bytes());
        hasher.update(file_path.as_bytes());
        hasher.update(resource_id.as_bytes());
        hasher.update(config_path_str.as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize());

        IacFinding {
            rule_id: rule.as_str().to_string(),
            title: rule.title().to_string(),
            description,
            severity: rule.severity(),
            confidence: rule.confidence(),
            cwe: rule.cwe(),
            file_path: file_path.to_string(),
            resource_id: resource_id.to_string(),
            resource_type: resource_type.to_string(),
            line,
            column,
            configuration_path: config_path_str,
            remediation,
            fingerprint,
        }
    }
}
