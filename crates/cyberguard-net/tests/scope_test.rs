use cyberguard_net::cidr::{is_bogon_or_metadata, Cidr};
use cyberguard_net::error::NetError;
use cyberguard_net::models::SecurityScope;
use cyberguard_net::scope::{generate_scope_hmac, verify_scope_hmac, ScopeGate};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_ipv4_cidr_matching() {
    let cidr = Cidr::parse("192.168.1.0/24").expect("Valid CIDR");
    assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55))));
    assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));

    // Single IP without prefix assumes /32
    let single = Cidr::parse("10.0.0.5").expect("Valid single IP");
    assert!(single.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))));
    assert!(!single.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));
}

#[test]
fn test_ipv6_cidr_matching() {
    let cidr = Cidr::parse("2001:db8::/32").expect("Valid IPv6 CIDR");
    let in_scope: IpAddr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
    let out_scope: IpAddr = "2001:db9::1".parse().unwrap();

    assert!(cidr.contains(in_scope));
    assert!(!cidr.contains(out_scope));
}

#[test]
fn test_bogon_and_cloud_metadata_blacklist() {
    // AWS / GCP IMDS
    let imds: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(is_bogon_or_metadata(imds).is_some());

    // Azure WireServer
    let azure: IpAddr = "168.63.129.16".parse().unwrap();
    assert!(is_bogon_or_metadata(azure).is_some());

    // Loopback
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(is_bogon_or_metadata(loopback).is_some());

    let loopback_v6: IpAddr = "::1".parse().unwrap();
    assert!(is_bogon_or_metadata(loopback_v6).is_some());

    // Multicast & Broadcast
    let multicast: IpAddr = "224.0.0.1".parse().unwrap();
    assert!(is_bogon_or_metadata(multicast).is_some());

    let broadcast: IpAddr = "255.255.255.255".parse().unwrap();
    assert!(is_bogon_or_metadata(broadcast).is_some());

    // Legitimate public IP is not bogon
    let public_ip: IpAddr = "93.184.216.34".parse().unwrap();
    assert!(is_bogon_or_metadata(public_ip).is_none());
}

#[test]
fn test_scope_gate_validation_pass() {
    let scope = SecurityScope {
        engagement_id: "ENG-2026-001".to_string(),
        valid_from: Some("2026-01-01T00:00:00Z".to_string()),
        valid_until: Some("2028-12-31T23:59:59Z".to_string()),
        authorized_cidrs: vec!["93.184.216.0/24".to_string()],
        excluded_cidrs: vec!["93.184.216.50/32".to_string()],
        authorized_domains: vec!["example.com".to_string()],
        authorized_ports: vec![80, 443],
        signature: None,
    };

    let gate = ScopeGate::new(scope);

    // In-scope IP
    let target_ip: IpAddr = "93.184.216.34".parse().unwrap();
    let pinned = gate.validate_ip(target_ip, 80).expect("IP is authorized");
    assert_eq!(pinned.ip, target_ip);
    assert_eq!(pinned.port, 80);

    // Excluded IP should fail
    let excluded_ip: IpAddr = "93.184.216.50".parse().unwrap();
    assert!(matches!(
        gate.validate_ip(excluded_ip, 80),
        Err(NetError::ScopeViolation(_))
    ));

    // Out of scope IP should fail
    let unauth_ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(matches!(
        gate.validate_ip(unauth_ip, 80),
        Err(NetError::ScopeViolation(_))
    ));

    // Unauthorized port should fail
    assert!(matches!(
        gate.validate_ip(target_ip, 22),
        Err(NetError::ScopeViolation(_))
    ));
}

#[test]
fn test_scope_gate_expiration() {
    let expired_scope = SecurityScope {
        engagement_id: "ENG-EXPIRED".to_string(),
        valid_from: Some("2020-01-01T00:00:00Z".to_string()),
        valid_until: Some("2021-01-01T00:00:00Z".to_string()),
        authorized_cidrs: vec!["93.184.216.0/24".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec![],
        authorized_ports: vec![],
        signature: None,
    };

    let gate = ScopeGate::new(expired_scope);
    let target_ip: IpAddr = "93.184.216.34".parse().unwrap();
    let res = gate.validate_ip(target_ip, 80);
    assert!(matches!(res, Err(NetError::ScopeExpired { .. })));
}

#[test]
fn test_scope_gate_hmac_signature() {
    let mut scope = SecurityScope {
        engagement_id: "ENG-HMAC-TEST".to_string(),
        valid_from: None,
        valid_until: None,
        authorized_cidrs: vec!["198.51.100.0/24".to_string()],
        excluded_cidrs: vec![],
        authorized_domains: vec!["secure.corp".to_string()],
        authorized_ports: vec![443],
        signature: None,
    };

    let secret_key = "secret-engagement-key-2026";
    let sig = generate_scope_hmac(&scope, secret_key.as_bytes());
    scope.signature = Some(sig.clone());

    // Valid signature verifies
    assert!(verify_scope_hmac(&scope, secret_key.as_bytes()).is_ok());

    // Tampered CIDR fails signature check
    let mut tampered = scope.clone();
    tampered.authorized_cidrs.push("10.0.0.0/8".to_string());
    assert!(matches!(
        verify_scope_hmac(&tampered, secret_key.as_bytes()),
        Err(NetError::InvalidSignature { .. })
    ));
}

#[test]
fn test_scope_gate_yaml_parsing() {
    let yaml = r#"
engagement_id: "ENG-YAML-TEST"
valid_from: "2026-01-01T00:00:00Z"
valid_until: "2030-01-01T00:00:00Z"
authorized_cidrs:
  - "192.0.2.0/24"
excluded_cidrs:
  - "192.0.2.100/32"
authorized_domains:
  - "*.test.internal"
authorized_ports:
  - 80
  - 443
"#;

    let gate = ScopeGate::from_yaml_str(yaml).expect("Valid YAML scope");
    assert_eq!(gate.scope.engagement_id, "ENG-YAML-TEST");
    assert_eq!(gate.authorized_cidrs.len(), 1);
    assert_eq!(gate.excluded_cidrs.len(), 1);
    assert_eq!(gate.scope.authorized_ports, vec![80, 443]);

    let ok_ip: IpAddr = "192.0.2.5".parse().unwrap();
    let pinned = gate.validate_ip(ok_ip, 443).unwrap();
    assert_eq!(pinned.ip, ok_ip);
    assert_eq!(pinned.port, 443);

    let excluded: IpAddr = "192.0.2.100".parse().unwrap();
    assert!(gate.validate_ip(excluded, 443).is_err());
}
