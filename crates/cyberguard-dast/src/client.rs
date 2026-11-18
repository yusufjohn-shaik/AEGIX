use crate::error::DastError;
use crate::models::DastTarget;
use cyberguard_net::ScopeGate;
use reqwest::dns::{Addrs, Name, Resolve};
use reqwest::header::{HeaderMap, HeaderValue, LOCATION, USER_AGENT};
use reqwest::{Client, Method, Response, StatusCode};
use std::collections::HashMap;
use std::future::ready;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use url::Url;

pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MB
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;
pub const MAX_REDIRECT_HOPS: usize = 5;

#[derive(Clone, Default)]
pub struct PinnedResolver {
    pinned_hosts: Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>,
}

impl PinnedResolver {
    pub fn new() -> Self {
        Self {
            pinned_hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn pin(&self, host: &str, addrs: Vec<SocketAddr>) {
        if let Ok(mut lock) = self.pinned_hosts.write() {
            lock.insert(host.to_string(), addrs);
        }
    }
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> reqwest::dns::Resolving {
        let host = name.as_str();
        if let Ok(lock) = self.pinned_hosts.read() {
            if let Some(addrs) = lock.get(host) {
                let boxed: Addrs = Box::new(addrs.clone().into_iter());
                return Box::pin(ready(Ok(boxed)));
            }
        }

        let host_string = host.to_string();
        Box::pin(async move {
            let addrs = tokio::net::lookup_host(format!("{}:0", host_string)).await?;
            let boxed: Addrs = Box::new(addrs);
            Ok(boxed)
        })
    }
}

pub struct DastClient {
    client: Client,
    resolver: PinnedResolver,
    timeout: Duration,
}

impl DastClient {
    pub fn new(target: &DastTarget, timeout_ms: u64) -> Result<Self, DastError> {
        let resolver = PinnedResolver::new();
        let timeout = Duration::from_millis(timeout_ms);

        let mut builder = Client::builder()
            .dns_resolver(Arc::new(resolver.clone()))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .pool_max_idle_per_host(0);

        if target.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build()?;
        Ok(Self {
            client,
            resolver,
            timeout,
        })
    }

    pub async fn read_bounded_body(mut response: Response) -> Result<Vec<u8>, DastError> {
        if let Some(cl) = response.content_length() {
            if cl > MAX_BODY_BYTES as u64 {
                return Err(DastError::BodyTooLarge {
                    limit_bytes: MAX_BODY_BYTES,
                });
            }
        }

        let mut body = Vec::with_capacity(8192);
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(DastError::BodyTooLarge {
                    limit_bytes: MAX_BODY_BYTES,
                });
            }
            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }

    pub async fn send_request(
        &self,
        method: Method,
        url: &Url,
        headers: Option<&HashMap<String, String>>,
        scope: &ScopeGate,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), DastError> {
        let mut current_url = url.clone();
        let mut hops = 0;

        loop {
            if hops >= MAX_REDIRECT_HOPS {
                return Err(DastError::RedirectLimitExceeded {
                    max_hops: MAX_REDIRECT_HOPS,
                });
            }

            // Enforce scheme whitelist
            let scheme = current_url.scheme();
            if scheme != "http" && scheme != "https" {
                return Err(DastError::ScopeViolation(format!(
                    "Unsupported scheme in target URL: {}",
                    scheme
                )));
            }

            // Resolve and validate target host against ScopeGate and Bogon blacklist
            let host_str = current_url
                .host_str()
                .ok_or_else(|| DastError::InvalidUrl("Missing host in URL".to_string()))?;
            let port = current_url
                .port_or_known_default()
                .ok_or_else(|| DastError::InvalidUrl("Missing port in URL".to_string()))?;

            // Validate target host against ScopeGate (domain whitelist, direct IP rules, port, expiration)
            scope.validate_host(host_str, port).map_err(|e| {
                DastError::ScopeViolation(format!(
                    "Host {} is not authorized by scope gate: {}",
                    host_str, e
                ))
            })?;

            let addrs = tokio::net::lookup_host(format!("{}:{}", host_str, port))
                .await
                .map_err(|e| {
                    DastError::ScopeViolation(format!(
                        "DNS resolution failed for {}: {}",
                        host_str, e
                    ))
                })?;

            let mut validated_addrs = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                if let Err(e) = scope.validate_ip(ip, port) {
                    return Err(DastError::ScopeViolation(format!(
                        "IP {} for host {} is not authorized: {}",
                        ip, host_str, e
                    )));
                }
                validated_addrs.push(addr);
            }

            if validated_addrs.is_empty() {
                return Err(DastError::ScopeViolation(format!(
                    "No valid authorized IP resolved for {}",
                    host_str
                )));
            }

            // Pin the validated addresses to prevent DNS rebinding TOCTOU
            self.resolver.pin(host_str, validated_addrs);

            // Construct and send request
            let mut req_builder = self
                .client
                .request(method.clone(), current_url.as_str())
                .header(
                    USER_AGENT,
                    "CyberGuard-DAST/0.9.0 (Defensive Security Scanner; +https://github.com/yusufjohn-shaik/CYBER-GUARD)",
                );

            let is_same_origin = current_url.scheme() == url.scheme()
                && current_url.host_str() == url.host_str()
                && current_url.port_or_known_default() == url.port_or_known_default();

            if let Some(hdrs) = headers {
                for (k, v) in hdrs {
                    let k_lower = k.to_ascii_lowercase();
                    // Strip credentials across origins per RFC 9110
                    if !is_same_origin
                        && (k_lower == "authorization"
                            || k_lower == "cookie"
                            || k_lower == "proxy-authorization")
                    {
                        continue;
                    }
                    if let (Ok(name), Ok(val)) = (
                        reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                        HeaderValue::from_str(v),
                    ) {
                        req_builder = req_builder.header(name, val);
                    }
                }
            }

            let response = tokio::time::timeout(self.timeout, req_builder.send())
                .await
                .map_err(|_| DastError::Timeout {
                    duration_ms: self.timeout.as_millis() as u64,
                })??;

            let status = response.status();
            let resp_headers = response.headers().clone();

            // Handle redirects manually
            if status.is_redirection() {
                if let Some(loc) = resp_headers.get(LOCATION) {
                    let loc_str = loc.to_str().map_err(|_| {
                        DastError::InvalidUrl("Invalid Location header".to_string())
                    })?;
                    let next_url = current_url.join(loc_str).map_err(|e| {
                        DastError::InvalidUrl(format!("Failed to resolve redirect URL: {}", e))
                    })?;

                    current_url = next_url;
                    hops += 1;
                    continue;
                }
            }

            let body = Self::read_bounded_body(response).await?;
            return Ok((status, resp_headers, body));
        }
    }
}
