//! Cryptographic Scope Gate and pre-flight DNS target pinning.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

use crate::cidr::{is_bogon_or_metadata, Cidr};
use crate::error::NetError;
use crate::models::{PinnedTarget, SecurityScope};

/// Scope Gate enforcing strict boundary validation before opening network sockets.
#[derive(Debug, Clone)]
pub struct ScopeGate {
    pub scope: SecurityScope,
    pub authorized_cidrs: Vec<Cidr>,
    pub excluded_cidrs: Vec<Cidr>,
}

impl ScopeGate {
    /// Construct a new ScopeGate from a declarative SecurityScope.
    pub fn new(scope: SecurityScope) -> Self {
        let authorized_cidrs = scope
            .authorized_cidrs
            .iter()
            .filter_map(|s| Cidr::parse(s).ok())
            .collect();
        let excluded_cidrs = scope
            .excluded_cidrs
            .iter()
            .filter_map(|s| Cidr::parse(s).ok())
            .collect();

        Self {
            scope,
            authorized_cidrs,
            excluded_cidrs,
        }
    }

    /// Load and parse a `.security-scope.yaml` configuration file from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, NetError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            NetError::ScopeParseError(format!("Failed to read {}: {e}", path.display()))
        })?;
        Self::from_str(&content)
    }

    /// Parse a `.security-scope.yaml` YAML string.
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, NetError> {
        let scope: SecurityScope = serde_yaml::from_str(yaml_str)
            .map_err(|e| NetError::ScopeParseError(format!("Invalid YAML syntax: {e}")))?;
        Ok(Self::new(scope))
    }
}

impl std::str::FromStr for ScopeGate {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_yaml_str(s)
    }
}

impl ScopeGate {
    /// Check scope time validity against the current UTC timestamp.
    pub fn check_expiration(&self) -> Result<(), NetError> {
        let now = Utc::now();

        if let Some(ref valid_until_str) = self.scope.valid_until {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(valid_until_str) {
                if now > valid_until {
                    return Err(NetError::ScopeExpired {
                        expired_at: valid_until_str.clone(),
                        now: now.to_rfc3339(),
                    });
                }
            }
        }

        if let Some(ref valid_from_str) = self.scope.valid_from {
            if let Ok(valid_from) = DateTime::parse_from_rfc3339(valid_from_str) {
                if now < valid_from {
                    return Err(NetError::ScopeNotYetValid {
                        valid_from: valid_from_str.clone(),
                        now: now.to_rfc3339(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate a raw IP address and port against scope rules.
    pub fn validate_ip(&self, ip: IpAddr, port: u16) -> Result<PinnedTarget, NetError> {
        self.check_expiration()?;

        // 0. Fail-closed: An empty scope with no CIDRs and no domains authorizes nothing
        if self.authorized_cidrs.is_empty() && self.scope.authorized_domains.is_empty() {
            return Err(NetError::ScopeViolation(format!(
                "Scope configuration for engagement '{}' defines zero authorized CIDRs or domains. All scanning is forbidden.",
                self.scope.engagement_id
            )));
        }

        // 1. Bogon & Metadata Check
        if let Some(bogon_reason) = is_bogon_or_metadata(ip) {
            let is_authorized_loopback =
                ip.is_loopback() && self.authorized_cidrs.iter().any(|c| c.contains(ip));

            if !is_authorized_loopback {
                return Err(NetError::BogonBlacklisted {
                    target: ip.to_string(),
                    ip,
                    reason: bogon_reason.to_string(),
                });
            }
        }

        // 2. Excluded CIDRs Check
        for excluded in &self.excluded_cidrs {
            if excluded.contains(ip) {
                return Err(NetError::ScopeViolation(format!(
                    "IP {ip} matches explicitly excluded CIDR range {:?}",
                    excluded
                )));
            }
        }

        // 3. Authorized CIDRs Check
        if !self.authorized_cidrs.is_empty() {
            let in_authorized = self.authorized_cidrs.iter().any(|c| c.contains(ip));
            if !in_authorized {
                return Err(NetError::ScopeViolation(format!(
                    "IP {ip} is not within any authorized CIDR range for engagement '{}'",
                    self.scope.engagement_id
                )));
            }
        }

        // 4. Authorized Ports Check
        if !self.scope.authorized_ports.is_empty() && !self.scope.authorized_ports.contains(&port) {
            return Err(NetError::ScopeViolation(format!(
                "Port {port} is not permitted by authorized_ports whitelist ({:?})",
                self.scope.authorized_ports
            )));
        }

        Ok(PinnedTarget::new(ip.to_string(), ip, port))
    }

    /// Validate a target (hostname or IP string) and resolve to a TOCTOU-safe PinnedTarget.
    ///
    /// Every resolved `A` and `AAAA` record is checked. If *any* address is out of scope or
    /// points to a bogon/cloud metadata service, the entire target is rejected immediately.
    pub fn validate_target(&self, target: &str, port: u16) -> Result<PinnedTarget, NetError> {
        let target = target.trim();

        // 0. Fail-closed check
        if self.authorized_cidrs.is_empty() && self.scope.authorized_domains.is_empty() {
            return Err(NetError::ScopeViolation(format!(
                "Scope configuration for engagement '{}' defines zero authorized CIDRs or domains. All scanning is forbidden.",
                self.scope.engagement_id
            )));
        }

        // Direct IP check
        if let Ok(ip) = IpAddr::from_str(target) {
            if self.authorized_cidrs.is_empty() {
                return Err(NetError::ScopeViolation(format!(
                    "Target '{target}' is an IP address, but engagement '{}' authorizes only domain names ({:?}) without CIDR whitelisting.",
                    self.scope.engagement_id, self.scope.authorized_domains
                )));
            }
            return self.validate_ip(ip, port);
        }

        self.check_expiration()?;

        // Domain whitelist check
        if !self.scope.authorized_domains.is_empty() {
            let domain_authorized = self.scope.authorized_domains.iter().any(|d| {
                if let Some(suffix) = d.strip_prefix("*.") {
                    target.ends_with(suffix) || target == suffix
                } else {
                    target.eq_ignore_ascii_case(d)
                }
            });

            if !domain_authorized {
                return Err(NetError::ScopeViolation(format!(
                    "Domain '{target}' is not in authorized_domains whitelist ({:?})",
                    self.scope.authorized_domains
                )));
            }
        }

        // One-time DNS resolution with strict validation on every returned IP
        let socket_str = format!("{target}:{port}");
        let addrs: Vec<std::net::SocketAddr> = socket_str
            .to_socket_addrs()
            .map_err(|e| NetError::DnsResolutionFailed {
                host: target.to_string(),
                reason: e.to_string(),
            })?
            .collect();

        if addrs.is_empty() {
            return Err(NetError::DnsResolutionFailed {
                host: target.to_string(),
                reason: "DNS resolution returned 0 IP records".to_string(),
            });
        }

        // Ensure ALL resolved IPs conform to the scope gate (prevent multi-A DNS rebinding)
        let mut first_valid_ip = None;
        for addr in &addrs {
            let ip = addr.ip();
            let _ = self.validate_ip(ip, port)?;
            if first_valid_ip.is_none() {
                first_valid_ip = Some(ip);
            }
        }

        let pinned_ip = first_valid_ip.expect("At least one address resolved");
        Ok(PinnedTarget::new(target, pinned_ip, port))
    }
}

/// Computes RFC 2104 compliant HMAC-SHA256 without external dependencies.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let res: [u8; 32] = outer.finalize().into();
    res
}

/// Generates a canonical hex HMAC-SHA256 signature for a `SecurityScope`.
#[must_use]
pub fn generate_scope_hmac(scope: &SecurityScope, secret_key: &[u8]) -> String {
    let canonical = format!(
        "{}:{}:{}:{}:{}:{}",
        scope.engagement_id,
        scope.valid_from.as_deref().unwrap_or(""),
        scope.valid_until.as_deref().unwrap_or(""),
        scope.authorized_cidrs.join(","),
        scope.excluded_cidrs.join(","),
        scope.authorized_domains.join(",")
    );

    let digest = hmac_sha256(secret_key, canonical.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

/// Verifies that a `SecurityScope` carries a valid HMAC-SHA256 signature.
pub fn verify_scope_hmac(scope: &SecurityScope, secret_key: &[u8]) -> Result<(), NetError> {
    let signature = scope
        .signature
        .as_deref()
        .ok_or(NetError::MissingSignature)?;
    let expected = generate_scope_hmac(scope, secret_key);

    if signature.eq_ignore_ascii_case(&expected) {
        Ok(())
    } else {
        Err(NetError::InvalidSignature {
            engagement_id: scope.engagement_id.clone(),
        })
    }
}
