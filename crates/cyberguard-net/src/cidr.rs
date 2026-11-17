//! IPv4/IPv6 CIDR representation and Bogon / Cloud Metadata detection.

use crate::error::NetError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// CIDR representation supporting IPv4 and IPv6 subnet ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cidr {
    V4 { network: Ipv4Addr, prefix: u8 },
    V6 { network: Ipv6Addr, prefix: u8 },
}

impl Cidr {
    /// Parse a CIDR notation string (e.g., `192.168.1.0/24` or `10.0.0.1` or `2001:db8::/32`).
    ///
    /// If no slash is present, the prefix defaults to 32 for IPv4 and 128 for IPv6.
    pub fn parse(s: &str) -> Result<Self, NetError> {
        let s = s.trim();
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let prefix: u8 = prefix_str.parse().map_err(|_| {
                NetError::InvalidTarget(format!("Invalid CIDR prefix length: {prefix_str}"))
            })?;

            if let Ok(ipv4) = Ipv4Addr::from_str(ip_str) {
                if prefix > 32 {
                    return Err(NetError::InvalidTarget(format!(
                        "IPv4 prefix length must be 0-32: {prefix}"
                    )));
                }
                Ok(Self::V4 {
                    network: ipv4,
                    prefix,
                })
            } else if let Ok(ipv6) = Ipv6Addr::from_str(ip_str) {
                if prefix > 128 {
                    return Err(NetError::InvalidTarget(format!(
                        "IPv6 prefix length must be 0-128: {prefix}"
                    )));
                }
                Ok(Self::V6 {
                    network: ipv6,
                    prefix,
                })
            } else {
                Err(NetError::InvalidTarget(format!(
                    "Invalid IP address in CIDR: {ip_str}"
                )))
            }
        } else if let Ok(ipv4) = Ipv4Addr::from_str(s) {
            Ok(Self::V4 {
                network: ipv4,
                prefix: 32,
            })
        } else if let Ok(ipv6) = Ipv6Addr::from_str(s) {
            Ok(Self::V6 {
                network: ipv6,
                prefix: 128,
            })
        } else {
            Err(NetError::InvalidTarget(format!(
                "Unrecognized CIDR format: {s}"
            )))
        }
    }

    /// Check if the given `IpAddr` is contained within this CIDR range.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        // Canonicalize IPv4-mapped or IPv4-compatible IPv6 addresses (e.g., ::ffff:192.168.1.1)
        let effective_ip = match ip {
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4() {
                    IpAddr::V4(v4)
                } else {
                    IpAddr::V6(v6)
                }
            }
            v4 => v4,
        };

        match (self, effective_ip) {
            (Self::V4 { network, prefix }, IpAddr::V4(target)) => {
                if *prefix == 0 {
                    return true;
                }
                let mask = !0u32 << (32 - *prefix);
                (u32::from(target) & mask) == (u32::from(*network) & mask)
            }
            (Self::V6 { network, prefix }, IpAddr::V6(target)) => {
                if *prefix == 0 {
                    return true;
                }
                let mask = !0u128 << (128 - *prefix);
                (u128::from(target) & mask) == (u128::from(*network) & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

/// Checks if an IP is a blacklisted bogon, cloud metadata endpoint, or unsafe address.
/// Returns the reason if blacklisted, or `None` if safe for public/authorized inspection.
#[must_use]
pub fn is_bogon_or_metadata(ip: IpAddr) -> Option<&'static str> {
    // Canonicalize IPv4-mapped or IPv4-compatible IPv6 addresses (e.g. ::ffff:169.254.169.254)
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4() {
            return is_bogon_or_metadata(IpAddr::V4(v4));
        }
    }

    match ip {
        IpAddr::V4(ipv4) => {
            let u = u32::from(ipv4);

            // 169.254.0.0/16 (Link Local & AWS/GCP Metadata 169.254.169.254)
            if (u & 0xFFFF_0000) == 0xA9FE_0000 {
                return Some("Link-Local / Cloud Instance Metadata Service (169.254.0.0/16)");
            }

            // 168.63.129.16/32 (Azure WireServer / Host Protected Channel)
            if u == 0xA83F_8110 {
                return Some("Azure WireServer Host Channel (168.63.129.16)");
            }

            // 127.0.0.0/8 (Loopback)
            if (u & 0xFF00_0000) == 0x7F00_0000 {
                return Some("Loopback range (127.0.0.0/8)");
            }

            // 0.0.0.0/8 (This host on this network)
            if (u & 0xFF00_0000) == 0 {
                return Some("Unspecified network range (0.0.0.0/8)");
            }

            // 224.0.0.0/4 (Multicast)
            if (u & 0xF000_0000) == 0xE000_0000 {
                return Some("Multicast range (224.0.0.0/4)");
            }

            // 255.255.255.255/32 (Broadcast)
            if u == 0xFFFF_FFFF {
                return Some("Limited Broadcast address (255.255.255.255)");
            }

            None
        }
        IpAddr::V6(ipv6) => {
            let u = u128::from(ipv6);

            // fe80::/10 (IPv6 Link-Local)
            if (u & 0xFFC0_0000_0000_0000_0000_0000_0000_0000)
                == 0xFE80_0000_0000_0000_0000_0000_0000_0000
            {
                return Some("IPv6 Link-Local address (fe80::/10)");
            }

            // AWS IMDSv6 (fd00:ec2::254)
            if ipv6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
                return Some("AWS IMDSv6 endpoint (fd00:ec2::254)");
            }

            // ::1/128 (IPv6 Loopback)
            if ipv6.is_loopback() {
                return Some("IPv6 Loopback address (::1)");
            }

            // ::/128 (IPv6 Unspecified)
            if ipv6.is_unspecified() {
                return Some("IPv6 Unspecified address (::)");
            }

            // ff00::/8 (IPv6 Multicast)
            if ipv6.is_multicast() {
                return Some("IPv6 Multicast range (ff00::/8)");
            }

            None
        }
    }
}
