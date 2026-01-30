//! Network Guard (Egress Proxy) implementation.
//!
//! The Network Guard is the single outbound network path for connectors under
//! `strict`/`moderate` sandbox profiles. It enforces `NetworkConstraints` from
//! the connector manifest and provides credential injection without exposing
//! raw secrets to connector processes.

use std::net::IpAddr;

use fcp_manifest::NetworkConstraints;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

// ============================================================================
// Errors
// ============================================================================

/// Errors from the Network Guard.
#[derive(Debug, Error)]
pub enum EgressError {
    /// Request denied due to policy violation.
    #[error("egress denied: {reason}")]
    Denied { reason: String, code: DenyReason },

    /// Invalid request format.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// URL parsing failed.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Hostname canonicalization failed.
    #[error("hostname canonicalization failed: {0}")]
    CanonicalizationFailed(String),

    /// DNS resolution failed.
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    /// Credential not found or not authorized.
    #[error("credential error: {0}")]
    CredentialError(String),

    /// TLS verification failed.
    #[error("TLS verification failed: {0}")]
    TlsVerificationFailed(String),
}

/// Reason codes for denied requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Host not in allow list.
    HostNotAllowed,
    /// Port not in allow list.
    PortNotAllowed,
    /// IP literal used when denied.
    IpLiteralDenied,
    /// Localhost access denied.
    LocalhostDenied,
    /// Private range (RFC1918) access denied.
    PrivateRangeDenied,
    /// Tailnet range access denied.
    TailnetRangeDenied,
    /// Link-local range access denied.
    LinkLocalDenied,
    /// Custom CIDR deny rule matched.
    CidrDenyMatched,
    /// SNI mismatch.
    SniMismatch,
    /// SPKI pin mismatch.
    SpkiPinMismatch,
    /// Credential not authorized for this operation.
    CredentialNotAuthorized,
    /// Credential host binding does not allow the requested host.
    CredentialHostNotAllowed,
    /// Hostname not canonicalized.
    HostnameNotCanonical,
    /// Too many DNS responses.
    DnsMaxIpsExceeded,
    /// Max redirects exceeded.
    MaxRedirectsExceeded,
}

// ============================================================================
// Request Types
// ============================================================================

/// Egress request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EgressRequest {
    /// HTTP/HTTPS request.
    Http(EgressHttpRequest),
    /// Raw TCP connection (for non-HTTP protocols like postgres, redis).
    TcpConnect(EgressTcpConnectRequest),
}

/// HTTP egress request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressHttpRequest {
    /// Target URL (must be absolute).
    pub url: String,
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Request headers (Authorization headers will be stripped for logging).
    pub headers: Vec<HttpHeader>,
    /// Request body (optional).
    #[serde(default)]
    pub body: Option<Vec<u8>>,
    /// Credential ID for injection (optional).
    /// If provided, the guard will inject the credential into the request.
    #[serde(default)]
    pub credential_id: Option<String>,
}

/// HTTP header key-value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// TCP connect egress request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressTcpConnectRequest {
    /// Target hostname.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Whether to upgrade to TLS after connect.
    #[serde(default)]
    pub tls: bool,
    /// SNI hostname override (defaults to `host` if TLS enabled).
    #[serde(default)]
    pub sni_override: Option<String>,
    /// Credential ID for injection (optional).
    #[serde(default)]
    pub credential_id: Option<String>,
}

// ============================================================================
// Evaluation Result
// ============================================================================

/// Decision from the egress guard.
#[derive(Debug, Clone)]
pub struct EgressDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Canonical hostname (after IDNA2008 + lowercase).
    pub canonical_host: String,
    /// Resolved IP addresses (after DNS resolution).
    pub resolved_ips: Vec<IpAddr>,
    /// Port to connect to.
    pub port: u16,
    /// Whether TLS is required.
    pub tls_required: bool,
    /// Expected SNI (for TLS verification).
    pub expected_sni: Option<String>,
    /// SPKI pins to verify (if any).
    pub spki_pins: Vec<Vec<u8>>,
    /// Injected credential (if any, already applied to request).
    pub credential_injected: bool,
}

/// TCP authorization decision with optional connection auth bytes.
#[derive(Debug, Clone)]
pub struct EgressTcpDecision {
    pub decision: EgressDecision,
    pub tcp_auth: Option<Vec<u8>>,
}

// ============================================================================
// CIDR Defaults
// ============================================================================

/// Default CIDR ranges that are denied when `deny_localhost` is true.
const LOCALHOST_CIDRS: &[&str] = &[
    "127.0.0.0/8", // IPv4 loopback
    "::1/128",     // IPv6 loopback
    "0.0.0.0/8",   // This network (localhost-ish)
    "::/128",      // Unspecified address
];

/// Default CIDR ranges that are denied when `deny_private_ranges` is true (RFC1918 + RFC4193).
const PRIVATE_CIDRS: &[&str] = &[
    "10.0.0.0/8",     // RFC1918 Class A
    "172.16.0.0/12",  // RFC1918 Class B
    "192.168.0.0/16", // RFC1918 Class C
    "fc00::/7",       // IPv6 Unique Local Addresses (ULA)
];

/// Link-local ranges (always denied alongside private ranges).
const LINK_LOCAL_CIDRS: &[&str] = &[
    "169.254.0.0/16", // IPv4 link-local
    "fe80::/10",      // IPv6 link-local
];

/// Default CIDR ranges that are denied when `deny_tailnet_ranges` is true.
/// Tailscale uses CGNAT space (100.64.0.0/10) for its mesh network.
const TAILNET_CIDRS: &[&str] = &[
    "100.64.0.0/10", // CGNAT / Tailscale address space
];

// ============================================================================
// Hostname Canonicalization
// ============================================================================

/// Canonicalize a hostname according to FCP2 rules:
/// 1. Convert to lowercase
/// 2. Apply IDNA2008 (Punycode encoding for internationalized domains)
/// 3. Strip trailing dot
///
/// # Errors
///
/// Returns an error if the hostname is invalid or cannot be encoded.
pub fn canonicalize_hostname(hostname: &str) -> Result<String, EgressError> {
    if hostname.is_empty() {
        return Err(EgressError::CanonicalizationFailed(
            "hostname is empty".into(),
        ));
    }

    // Strip trailing dot (FQDN notation)
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);

    // Apply IDNA2008 encoding (handles Unicode → Punycode)
    let ascii_host = idna::domain_to_ascii(hostname)
        .map_err(|e| EgressError::CanonicalizationFailed(e.to_string()))?;

    // Lowercase (IDNA should already produce lowercase ASCII, but be explicit)
    let canonical = ascii_host.to_ascii_lowercase();

    if canonical.is_empty() {
        return Err(EgressError::CanonicalizationFailed(
            "canonicalized hostname is empty".into(),
        ));
    }

    Ok(canonical)
}

fn canonicalize_host_pattern(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return None;
    }

    let (wildcard, raw) = pattern
        .strip_prefix("*.")
        .map_or((false, pattern), |rest| (true, rest));

    let canonical = if raw.parse::<IpAddr>().is_ok() {
        raw.to_string()
    } else {
        canonicalize_hostname(raw).ok()?
    };

    if wildcard {
        Some(format!("*.{canonical}"))
    } else {
        Some(canonical)
    }
}

/// Check if a hostname is canonical (already in FCP2 canonical form).
#[must_use]
pub fn is_hostname_canonical(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.ends_with('.') {
        return false;
    }

    // Must be ASCII
    if !hostname.is_ascii() {
        return false;
    }

    // Must be lowercase
    if hostname.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }

    // Check if IDNA encoding is idempotent
    idna::domain_to_ascii(hostname).is_ok_and(|encoded| encoded == hostname)
}

// ============================================================================
// CIDR Checking
// ============================================================================

/// Check if an IP address is contained in any of the given CIDR ranges.
fn ip_in_any_cidr(ip: IpAddr, cidrs: &[IpNet]) -> bool {
    cidrs.iter().any(|net| net.contains(&ip))
}

/// Parse a list of CIDR strings into `IpNet` values.
fn parse_cidr_list(cidrs: &[&str]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|s| s.parse::<IpNet>().ok())
        .collect()
}

/// Check if an IP address is a localhost address.
#[must_use]
pub fn is_localhost(ip: IpAddr) -> bool {
    static LOCALHOST_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(LOCALHOST_CIDRS));
    ip_in_any_cidr(ip, &LOCALHOST_NETS)
}

/// Check if an IP address is in a private range (RFC1918/RFC4193).
#[must_use]
pub fn is_private_range(ip: IpAddr) -> bool {
    static PRIVATE_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(PRIVATE_CIDRS));
    ip_in_any_cidr(ip, &PRIVATE_NETS)
}

/// Check if an IP address is in a link-local range.
#[must_use]
pub fn is_link_local(ip: IpAddr) -> bool {
    static LINK_LOCAL_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(LINK_LOCAL_CIDRS));
    ip_in_any_cidr(ip, &LINK_LOCAL_NETS)
}

/// Check if an IP address is in the Tailnet range (CGNAT 100.64.0.0/10).
#[must_use]
pub fn is_tailnet_range(ip: IpAddr) -> bool {
    static TAILNET_NETS: std::sync::LazyLock<Vec<IpNet>> =
        std::sync::LazyLock::new(|| parse_cidr_list(TAILNET_CIDRS));
    ip_in_any_cidr(ip, &TAILNET_NETS)
}

// ============================================================================
// Egress Guard
// ============================================================================

/// The Network Guard evaluates egress requests against `NetworkConstraints`.
///
/// This is the core policy enforcement point for all outbound network access.
#[derive(Debug, Default)]
pub struct EgressGuard {
    // Future: DNS resolver configuration, connection pool, etc.
}

impl EgressGuard {
    /// Create a new egress guard.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// Evaluate an egress request against the given constraints.
    ///
    /// This performs all policy checks except actual DNS resolution and TLS
    /// verification (which happen at connection time).
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` if the request violates any constraint.
    pub fn evaluate(
        &self,
        request: &EgressRequest,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        match request {
            EgressRequest::Http(http) => self.evaluate_http(http, constraints),
            EgressRequest::TcpConnect(tcp) => self.evaluate_tcp(tcp, constraints),
        }
    }

    /// Evaluate an HTTP request and perform credential authorization/injection.
    ///
    /// This is the integrated "secretless egress" path: policy check + credential gating.
    ///
    /// # Errors
    /// Returns `EgressError::Denied` for policy or credential violations.
    pub fn authorize_http(
        &self,
        request: &mut EgressHttpRequest,
        constraints: &NetworkConstraints,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<EgressDecision, EgressError> {
        let mut decision = self.evaluate(&EgressRequest::Http(request.clone()), constraints)?;

        let Some(credential_id) = request.credential_id.as_deref() else {
            return Ok(decision);
        };

        let authorized = injector.is_authorized(credential_id, operation_id, credential_allow)?;
        if !authorized {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not authorized for operation `{operation_id}`"
                ),
                code: DenyReason::CredentialNotAuthorized,
            });
        }

        let host_allowed = injector.is_host_allowed(credential_id, &decision.canonical_host)?;
        if !host_allowed {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not allowed for host `{}`",
                    decision.canonical_host
                ),
                code: DenyReason::CredentialHostNotAllowed,
            });
        }

        injector.inject_http(credential_id, &mut request.headers)?;
        decision.credential_injected = true;

        Ok(decision)
    }

    /// Evaluate a TCP connect request and perform credential authorization.
    ///
    /// Returns optional auth bytes to send after connection establishment.
    pub fn authorize_tcp(
        &self,
        request: &EgressTcpConnectRequest,
        constraints: &NetworkConstraints,
        injector: &dyn CredentialInjector,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<EgressTcpDecision, EgressError> {
        let mut decision =
            self.evaluate(&EgressRequest::TcpConnect(request.clone()), constraints)?;

        let Some(credential_id) = request.credential_id.as_deref() else {
            return Ok(EgressTcpDecision {
                decision,
                tcp_auth: None,
            });
        };

        let authorized = injector.is_authorized(credential_id, operation_id, credential_allow)?;
        if !authorized {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not authorized for operation `{operation_id}`"
                ),
                code: DenyReason::CredentialNotAuthorized,
            });
        }

        let host_allowed = injector.is_host_allowed(credential_id, &decision.canonical_host)?;
        if !host_allowed {
            return Err(EgressError::Denied {
                reason: format!(
                    "credential `{credential_id}` not allowed for host `{}`",
                    decision.canonical_host
                ),
                code: DenyReason::CredentialHostNotAllowed,
            });
        }

        let tcp_auth = injector.get_tcp_auth(credential_id)?;
        if tcp_auth.is_some() {
            decision.credential_injected = true;
        }

        Ok(EgressTcpDecision { decision, tcp_auth })
    }

    /// Evaluate an HTTP request.
    fn evaluate_http(
        &self,
        request: &EgressHttpRequest,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        // Parse URL
        let url = url::Url::parse(&request.url)
            .map_err(|e| EgressError::InvalidUrl(format!("{}: {e}", request.url)))?;

        // Extract host
        let host = url
            .host_str()
            .ok_or_else(|| EgressError::InvalidUrl("URL has no host".into()))?;

        // Extract port (default based on scheme)
        let port = url.port_or_known_default().ok_or_else(|| {
            EgressError::InvalidUrl(format!(
                "cannot determine port for scheme: {}",
                url.scheme()
            ))
        })?;

        // Determine if TLS is required
        let tls_required = url.scheme() == "https";

        // Evaluate common constraints
        self.evaluate_host_port(host, port, tls_required, constraints)
    }

    /// Evaluate a TCP connect request.
    fn evaluate_tcp(
        &self,
        request: &EgressTcpConnectRequest,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        self.evaluate_host_port(&request.host, request.port, request.tls, constraints)
    }

    /// Core constraint evaluation for host:port.
    fn evaluate_host_port(
        &self,
        host: &str,
        port: u16,
        tls_required: bool,
        constraints: &NetworkConstraints,
    ) -> Result<EgressDecision, EgressError> {
        // Step 1: Check if host is an IP literal
        let is_ip_literal = host.parse::<IpAddr>().is_ok();
        if is_ip_literal && constraints.deny_ip_literals {
            warn!(host = %host, "IP literal denied");
            return Err(EgressError::Denied {
                reason: format!("IP literals are not allowed: {host}"),
                code: DenyReason::IpLiteralDenied,
            });
        }

        // Step 2: Canonicalize hostname
        let canonical_host = if is_ip_literal {
            host.to_string()
        } else {
            let canonical = canonicalize_hostname(host)?;
            if canonical != host {
                if constraints.require_host_canonicalization {
                    return Err(EgressError::Denied {
                        reason: format!("hostname not canonical: {host}"),
                        code: DenyReason::HostnameNotCanonical,
                    });
                }
                debug!(original = %host, canonical = %canonical, "hostname canonicalized");
            }
            canonical
        };

        // Step 3: Check host against allow list
        if !self.host_matches_allow_list(&canonical_host, is_ip_literal, constraints) {
            warn!(host = %canonical_host, "host not in allow list");
            return Err(EgressError::Denied {
                reason: format!("host not allowed: {canonical_host}"),
                code: DenyReason::HostNotAllowed,
            });
        }

        // Step 4: Check port against allow list
        if !constraints.port_allow.contains(&port) {
            warn!(port = %port, "port not in allow list");
            return Err(EgressError::Denied {
                reason: format!("port not allowed: {port}"),
                code: DenyReason::PortNotAllowed,
            });
        }

        // Step 5: If it's an IP literal, check CIDR constraints immediately
        if let Ok(ip) = canonical_host.parse::<IpAddr>() {
            self.check_ip_constraints(ip, constraints)?;
        }

        // Build decision
        let expected_sni = if tls_required && constraints.require_sni {
            Some(canonical_host.clone())
        } else {
            None
        };

        let spki_pins: Vec<Vec<u8>> = constraints
            .spki_pins
            .iter()
            .map(|b| b.as_bytes().to_vec())
            .collect();

        Ok(EgressDecision {
            allowed: true,
            canonical_host,
            resolved_ips: vec![], // Populated at DNS resolution time
            port,
            tls_required,
            expected_sni,
            spki_pins,
            credential_injected: false,
        })
    }

    /// Check if a host matches the allow list.
    #[allow(clippy::unused_self)] // Will use self for caching in future
    fn host_matches_allow_list(
        &self,
        host: &str,
        is_ip_literal: bool,
        constraints: &NetworkConstraints,
    ) -> bool {
        // Check explicit IP allow list
        if is_ip_literal {
            if let Ok(ip) = host.parse::<IpAddr>() {
                if constraints.ip_allow.contains(&ip) {
                    return true;
                }
            }
        }

        // Check hostname allow list
        for pattern in &constraints.host_allow {
            let Some(canonical_pattern) = canonicalize_host_pattern(pattern) else {
                continue;
            };
            if canonical_pattern.starts_with("*.") {
                // Wildcard match: *.example.com matches sub.example.com
                let suffix = &canonical_pattern[1..]; // ".example.com"
                if host.ends_with(suffix) && host.len() > suffix.len() {
                    // Ensure there's actually a subdomain (not just "example.com")
                    return true;
                }
            } else if canonical_pattern == host {
                return true;
            }
        }

        false
    }

    /// Check resolved IP against CIDR constraints.
    ///
    /// This is called after DNS resolution to verify the resolved IPs are allowed.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` if the IP matches any deny rule.
    pub fn check_ip_constraints(
        &self,
        ip: IpAddr,
        constraints: &NetworkConstraints,
    ) -> Result<(), EgressError> {
        // Check localhost
        if constraints.deny_localhost && is_localhost(ip) {
            return Err(EgressError::Denied {
                reason: format!("localhost access denied: {ip}"),
                code: DenyReason::LocalhostDenied,
            });
        }

        // Check private ranges (RFC1918)
        if constraints.deny_private_ranges && is_private_range(ip) {
            return Err(EgressError::Denied {
                reason: format!("private range access denied: {ip}"),
                code: DenyReason::PrivateRangeDenied,
            });
        }

        // Check link-local (always denied with private ranges)
        if constraints.deny_private_ranges && is_link_local(ip) {
            return Err(EgressError::Denied {
                reason: format!("link-local access denied: {ip}"),
                code: DenyReason::LinkLocalDenied,
            });
        }

        // Check tailnet ranges
        if constraints.deny_tailnet_ranges && is_tailnet_range(ip) {
            return Err(EgressError::Denied {
                reason: format!("tailnet range access denied: {ip}"),
                code: DenyReason::TailnetRangeDenied,
            });
        }

        // Check custom CIDR deny list
        for cidr_str in &constraints.cidr_deny {
            if let Ok(cidr) = cidr_str.parse::<IpNet>() {
                if cidr.contains(&ip) {
                    return Err(EgressError::Denied {
                        reason: format!("CIDR deny rule matched: {ip} in {cidr_str}"),
                        code: DenyReason::CidrDenyMatched,
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate resolved IPs from DNS resolution.
    ///
    /// Checks all resolved IPs against constraints and enforces `dns_max_ips`.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` if any IP violates constraints or too many IPs returned.
    pub fn validate_dns_resolution(
        &self,
        ips: &[IpAddr],
        constraints: &NetworkConstraints,
    ) -> Result<Vec<IpAddr>, EgressError> {
        if ips.len() > constraints.dns_max_ips as usize {
            return Err(EgressError::Denied {
                reason: format!(
                    "DNS returned {} IPs, max allowed is {}",
                    ips.len(),
                    constraints.dns_max_ips
                ),
                code: DenyReason::DnsMaxIpsExceeded,
            });
        }

        let mut allowed_ips = Vec::new();
        for ip in ips {
            self.check_ip_constraints(*ip, constraints)?;
            allowed_ips.push(*ip);
        }

        Ok(allowed_ips)
    }
}

// ============================================================================
// Credential Injection
// ============================================================================

/// Credential injection context for the Network Guard.
///
/// This trait defines the interface for credential backends. The Network Guard
/// uses this to inject credentials into requests without exposing raw secret
/// bytes to connector processes.
pub trait CredentialInjector: Send + Sync {
    /// Check if a credential is authorized for the given operation.
    ///
    /// # Errors
    ///
    /// Returns an error if credential lookup or authorization check fails.
    fn is_authorized(
        &self,
        credential_id: &str,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<bool, EgressError>;

    /// Check if a credential is allowed for the given destination host.
    ///
    /// Default: allow all hosts. Override when credentials are host-bound.
    fn is_host_allowed(&self, _credential_id: &str, _host: &str) -> Result<bool, EgressError> {
        Ok(true)
    }

    /// Inject a credential into an HTTP request.
    ///
    /// The injector should modify the headers in-place to add authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be retrieved or injected.
    fn inject_http(
        &self,
        credential_id: &str,
        headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError>;

    /// Get connection credentials for a TCP connection.
    ///
    /// Returns opaque bytes that should be sent after connection establishment
    /// (e.g., for database authentication).
    ///
    /// # Errors
    ///
    /// Returns an error if the credential cannot be retrieved.
    fn get_tcp_auth(&self, credential_id: &str) -> Result<Option<Vec<u8>>, EgressError>;
}

/// No-op credential injector for testing or when credentials are disabled.
#[derive(Debug, Default)]
pub struct NoOpCredentialInjector;

impl CredentialInjector for NoOpCredentialInjector {
    fn is_authorized(
        &self,
        _credential_id: &str,
        _operation_id: &str,
        _credential_allow: &[String],
    ) -> Result<bool, EgressError> {
        Ok(false)
    }

    fn inject_http(
        &self,
        credential_id: &str,
        _headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError> {
        Err(EgressError::CredentialError(format!(
            "credential injection not available: {credential_id}"
        )))
    }

    fn get_tcp_auth(&self, credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
        Err(EgressError::CredentialError(format!(
            "credential injection not available: {credential_id}"
        )))
    }
}

// ============================================================================
// TLS Verification
// ============================================================================

/// TLS verification hooks for the Network Guard.
pub trait TlsVerifier: Send + Sync {
    /// Verify SNI matches the expected hostname.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` with `SniMismatch` if names don't match.
    fn verify_sni(&self, actual_sni: &str, expected_sni: &str) -> Result<(), EgressError>;

    /// Verify SPKI pin matches one of the expected pins.
    ///
    /// # Errors
    ///
    /// Returns `EgressError::Denied` with `SpkiPinMismatch` if no pin matches.
    fn verify_spki(&self, cert_spki: &[u8], expected_pins: &[Vec<u8>]) -> Result<(), EgressError>;
}

/// Default TLS verifier implementation.
#[derive(Debug, Default)]
pub struct DefaultTlsVerifier;

impl TlsVerifier for DefaultTlsVerifier {
    fn verify_sni(&self, actual_sni: &str, expected_sni: &str) -> Result<(), EgressError> {
        if actual_sni != expected_sni {
            return Err(EgressError::Denied {
                reason: format!("SNI mismatch: expected `{expected_sni}`, got `{actual_sni}`"),
                code: DenyReason::SniMismatch,
            });
        }
        Ok(())
    }

    fn verify_spki(&self, cert_spki: &[u8], expected_pins: &[Vec<u8>]) -> Result<(), EgressError> {
        if expected_pins.is_empty() {
            return Ok(());
        }

        for pin in expected_pins {
            if cert_spki == pin.as_slice() {
                return Ok(());
            }
        }

        Err(EgressError::Denied {
            reason: "SPKI pin verification failed: no matching pin".into(),
            code: DenyReason::SpkiPinMismatch,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // Hostname Canonicalization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_canonicalize_lowercase() {
        assert_eq!(
            canonicalize_hostname("API.Example.COM").unwrap(),
            "api.example.com"
        );
    }

    #[test]
    fn test_canonicalize_trailing_dot() {
        assert_eq!(
            canonicalize_hostname("example.com.").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_canonicalize_idna() {
        // Internationalized domain name
        assert_eq!(
            canonicalize_hostname("münchen.example.com").unwrap(),
            "xn--mnchen-3ya.example.com"
        );
    }

    #[test]
    fn test_canonicalize_emoji_domain() {
        // Emoji domains get Punycode encoded
        let result = canonicalize_hostname("🏠.example.com");
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(canonical.starts_with("xn--"));
        assert!(canonical.ends_with(".example.com"));
    }

    #[test]
    fn test_canonicalize_empty() {
        assert!(canonicalize_hostname("").is_err());
    }

    #[test]
    fn test_is_hostname_canonical() {
        assert!(is_hostname_canonical("api.example.com"));
        assert!(!is_hostname_canonical("API.example.com"));
        assert!(!is_hostname_canonical("example.com."));
        assert!(!is_hostname_canonical("münchen.example.com"));
    }

    // ------------------------------------------------------------------------
    // CIDR Check Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_localhost_ipv4() {
        assert!(is_localhost("127.0.0.1".parse().unwrap()));
        assert!(is_localhost("127.0.0.2".parse().unwrap()));
        assert!(is_localhost("127.255.255.255".parse().unwrap()));
        assert!(!is_localhost("128.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_localhost_ipv6() {
        assert!(is_localhost("::1".parse().unwrap()));
        assert!(!is_localhost("::2".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range() {
        // RFC1918 ranges
        assert!(is_private_range("10.0.0.1".parse().unwrap()));
        assert!(is_private_range("10.255.255.255".parse().unwrap()));
        assert!(is_private_range("172.16.0.1".parse().unwrap()));
        assert!(is_private_range("172.31.255.255".parse().unwrap()));
        assert!(is_private_range("192.168.0.1".parse().unwrap()));
        assert!(is_private_range("192.168.255.255".parse().unwrap()));

        // Not private
        assert!(!is_private_range("8.8.8.8".parse().unwrap()));
        assert!(!is_private_range("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local() {
        assert!(is_link_local("169.254.0.1".parse().unwrap()));
        assert!(is_link_local("169.254.255.255".parse().unwrap()));
        assert!(!is_link_local("169.255.0.1".parse().unwrap()));

        // IPv6 link-local
        assert!(is_link_local("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_is_tailnet_range() {
        assert!(is_tailnet_range("100.64.0.1".parse().unwrap()));
        assert!(is_tailnet_range("100.127.255.255".parse().unwrap()));
        assert!(!is_tailnet_range("100.128.0.1".parse().unwrap()));
        assert!(!is_tailnet_range("100.63.255.255".parse().unwrap()));
    }

    // ------------------------------------------------------------------------
    // Egress Guard Tests
    // ------------------------------------------------------------------------

    fn test_constraints() -> NetworkConstraints {
        NetworkConstraints {
            host_allow: vec!["api.example.com".into(), "*.test.com".into()],
            port_allow: vec![443, 8443],
            ip_allow: vec![],
            cidr_deny: vec![],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        }
    }

    #[test]
    fn test_evaluate_allowed_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/v1/data".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
        assert_eq!(decision.port, 443);
        assert!(decision.tls_required);
    }

    #[test]
    fn test_evaluate_wildcard_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://sub.test.com:443/path".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "sub.test.com");
    }

    #[test]
    fn test_evaluate_denied_host() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://evil.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::HostNotAllowed);
        }
    }

    #[test]
    fn test_evaluate_denied_port() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com:9999/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PortNotAllowed);
        }
    }

    #[test]
    fn test_evaluate_ip_literal_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://93.184.216.34/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::IpLiteralDenied);
        }
    }

    #[test]
    fn test_check_ip_localhost_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("127.0.0.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LocalhostDenied);
        }
    }

    #[test]
    fn test_check_ip_private_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("192.168.1.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PrivateRangeDenied);
        }
    }

    #[test]
    fn test_check_ip_tailnet_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("100.100.100.100".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::TailnetRangeDenied);
        }
    }

    #[test]
    fn test_check_ip_public_allowed() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("8.8.8.8".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tcp_connect_evaluation() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 443,
            tls: true,
            sni_override: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
        assert!(decision.tls_required);
    }

    #[test]
    fn test_dns_max_ips_exceeded() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.dns_max_ips = 2;

        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];

        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::DnsMaxIpsExceeded);
        }
    }

    // ------------------------------------------------------------------------
    // TLS Verifier Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sni_verification() {
        let verifier = DefaultTlsVerifier;

        assert!(verifier.verify_sni("example.com", "example.com").is_ok());
        assert!(verifier.verify_sni("other.com", "example.com").is_err());
    }

    #[test]
    fn test_spki_verification() {
        let verifier = DefaultTlsVerifier;

        let pin1 = vec![1, 2, 3, 4];
        let pin2 = vec![5, 6, 7, 8];
        let allowed_pins = vec![pin1.clone(), pin2.clone()];

        assert!(verifier.verify_spki(&pin1, &allowed_pins).is_ok());
        assert!(verifier.verify_spki(&pin2, &allowed_pins).is_ok());
        assert!(verifier.verify_spki(&[9, 10], &allowed_pins).is_err());

        // Empty pins should pass
        assert!(verifier.verify_spki(&[1, 2], &[]).is_ok());
    }

    // ── New tests ──

    #[test]
    fn test_egress_error_display() {
        let e = EgressError::Denied {
            reason: "bad host".into(),
            code: DenyReason::HostNotAllowed,
        };
        assert!(e.to_string().contains("bad host"));

        let e = EgressError::InvalidRequest("malformed".into());
        assert!(e.to_string().contains("malformed"));

        let e = EgressError::InvalidUrl("no scheme".into());
        assert!(e.to_string().contains("no scheme"));

        let e = EgressError::CanonicalizationFailed("punycode".into());
        assert!(e.to_string().contains("punycode"));

        let e = EgressError::DnsResolutionFailed("NXDOMAIN".into());
        assert!(e.to_string().contains("NXDOMAIN"));

        let e = EgressError::CredentialError("not found".into());
        assert!(e.to_string().contains("not found"));

        let e = EgressError::TlsVerificationFailed("expired cert".into());
        assert!(e.to_string().contains("expired cert"));
    }

    #[test]
    fn test_deny_reason_serde_roundtrip() {
        let reasons = [
            DenyReason::HostNotAllowed,
            DenyReason::PortNotAllowed,
            DenyReason::IpLiteralDenied,
            DenyReason::LocalhostDenied,
            DenyReason::PrivateRangeDenied,
            DenyReason::TailnetRangeDenied,
            DenyReason::LinkLocalDenied,
            DenyReason::CidrDenyMatched,
            DenyReason::SniMismatch,
            DenyReason::SpkiPinMismatch,
            DenyReason::CredentialNotAuthorized,
            DenyReason::CredentialHostNotAllowed,
            DenyReason::HostnameNotCanonical,
            DenyReason::DnsMaxIpsExceeded,
            DenyReason::MaxRedirectsExceeded,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let roundtrip: DenyReason = serde_json::from_str(&json).unwrap();
            assert_eq!(roundtrip, reason);
        }
    }

    #[test]
    fn test_egress_request_http_serde() {
        let req = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/data".into(),
            method: "POST".into(),
            headers: vec![HttpHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            }],
            body: Some(b"{}".to_vec()),
            credential_id: Some("cred-1".into()),
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"http\""));
        let roundtrip: EgressRequest = serde_json::from_str(&json).unwrap();
        if let EgressRequest::Http(http) = roundtrip {
            assert_eq!(http.url, "https://api.example.com/data");
            assert_eq!(http.method, "POST");
            assert_eq!(http.headers.len(), 1);
            assert_eq!(http.credential_id, Some("cred-1".into()));
        } else {
            panic!("expected Http variant");
        }
    }

    #[test]
    fn test_egress_request_tcp_serde() {
        let req = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "db.example.com".into(),
            port: 5432,
            tls: true,
            sni_override: Some("db.example.com".into()),
            credential_id: None,
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"tcp_connect\""));
        let roundtrip: EgressRequest = serde_json::from_str(&json).unwrap();
        if let EgressRequest::TcpConnect(tcp) = roundtrip {
            assert_eq!(tcp.host, "db.example.com");
            assert_eq!(tcp.port, 5432);
            assert!(tcp.tls);
            assert_eq!(tcp.sni_override, Some("db.example.com".into()));
        } else {
            panic!("expected TcpConnect variant");
        }
    }

    #[test]
    fn test_egress_guard_default() {
        let guard = EgressGuard::default();
        // Just verify it can be constructed via Default
        let _ = format!("{guard:?}");
    }

    #[test]
    fn test_canonicalize_idempotent() {
        // Already canonical hostname should pass through unchanged
        let canonical = canonicalize_hostname("api.example.com").unwrap();
        let double = canonicalize_hostname(&canonical).unwrap();
        assert_eq!(canonical, double);
    }

    #[test]
    fn test_is_hostname_canonical_empty() {
        assert!(!is_hostname_canonical(""));
    }

    #[test]
    fn test_is_hostname_canonical_non_ascii() {
        assert!(!is_hostname_canonical("münchen.example.com"));
    }

    #[test]
    fn test_noop_credential_injector() {
        let injector = NoOpCredentialInjector;

        // is_authorized always returns false
        let result = injector
            .is_authorized("cred-1", "op-1", &["cred-1".into()])
            .unwrap();
        assert!(!result);

        // inject_http returns error
        let mut headers = vec![];
        let result = injector.inject_http("cred-1", &mut headers);
        assert!(result.is_err());

        // get_tcp_auth returns error
        let result = injector.get_tcp_auth("cred-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dns_resolution_valid() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn test_validate_dns_resolution_contains_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "127.0.0.1".parse().unwrap(), // localhost - denied
        ];
        let result = guard.validate_dns_resolution(&ips, &constraints);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_ip_link_local_denied() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let result = guard.check_ip_constraints("169.254.1.1".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::LinkLocalDenied);
        }
    }

    #[test]
    fn test_check_ip_custom_cidr_deny() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.cidr_deny = vec!["203.0.113.0/24".into()]; // TEST-NET-3

        let result = guard.check_ip_constraints("203.0.113.42".parse().unwrap(), &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::CidrDenyMatched);
        }

        // IP outside that CIDR should pass
        let result = guard.check_ip_constraints("203.0.114.1".parse().unwrap(), &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_evaluate_non_canonical_host_allowed_when_not_required() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.require_host_canonicalization = false;
        constraints.host_allow = vec!["api.example.com".into()];
        constraints.deny_ip_literals = false;

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://API.EXAMPLE.COM:443/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.canonical_host, "api.example.com");
    }

    #[test]
    fn test_evaluate_tcp_denied_port() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::TcpConnect(EgressTcpConnectRequest {
            host: "api.example.com".into(),
            port: 9999, // Not in port_allow
            tls: false,
            sni_override: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::PortNotAllowed);
        }
    }

    #[test]
    fn test_evaluate_sni_decision() {
        let guard = EgressGuard::new();
        let constraints = test_constraints(); // require_sni = true

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.tls_required);
        assert_eq!(decision.expected_sni, Some("api.example.com".into()));
    }

    #[test]
    fn test_evaluate_no_sni_when_not_required() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.require_sni = false;

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.tls_required);
        assert_eq!(decision.expected_sni, None);
    }

    #[test]
    fn test_evaluate_spki_pins_in_decision() {
        use fcp_manifest::Base64Bytes;
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.spki_pins = vec![
            Base64Bytes::try_from("base64:cGluMQ==".to_string()).unwrap(),
            Base64Bytes::try_from("base64:cGluMg==".to_string()).unwrap(),
        ];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://api.example.com/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert_eq!(decision.spki_pins.len(), 2);
    }

    #[test]
    fn test_evaluate_invalid_url() {
        let guard = EgressGuard::new();
        let constraints = test_constraints();

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "not-a-url".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(matches!(result, Err(EgressError::InvalidUrl(_))));
    }

    #[test]
    fn test_wildcard_does_not_match_bare_domain() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.host_allow = vec!["*.test.com".into()];
        constraints.deny_ip_literals = false;

        // Bare domain "test.com" should NOT match "*.test.com"
        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://test.com:443/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let result = guard.evaluate(&request, &constraints);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_literal_in_ip_allow() {
        let guard = EgressGuard::new();
        let mut constraints = test_constraints();
        constraints.deny_ip_literals = false;
        constraints.ip_allow = vec!["93.184.216.34".parse().unwrap()];
        constraints.port_allow = vec![443];

        let request = EgressRequest::Http(EgressHttpRequest {
            url: "https://93.184.216.34/".into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
            credential_id: None,
        });

        let decision = guard.evaluate(&request, &constraints).unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn test_is_localhost_unspecified() {
        assert!(is_localhost("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn test_is_private_range_ipv6_ula() {
        assert!(is_private_range("fd12:3456:789a::1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local_ipv6() {
        assert!(is_link_local("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_sni_verification_deny_code() {
        let verifier = DefaultTlsVerifier;
        let result = verifier.verify_sni("wrong.com", "expected.com");
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::SniMismatch);
        } else {
            panic!("expected Denied error");
        }
    }

    #[test]
    fn test_spki_verification_deny_code() {
        let verifier = DefaultTlsVerifier;
        let pins = vec![vec![1, 2, 3]];
        let result = verifier.verify_spki(&[4, 5, 6], &pins);
        if let Err(EgressError::Denied { code, .. }) = result {
            assert_eq!(code, DenyReason::SpkiPinMismatch);
        } else {
            panic!("expected Denied error");
        }
    }

    #[test]
    fn test_http_header_serde() {
        let header = HttpHeader {
            name: "Authorization".into(),
            value: "Bearer token".into(),
        };
        let json = serde_json::to_string(&header).unwrap();
        let roundtrip: HttpHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.name, "Authorization");
        assert_eq!(roundtrip.value, "Bearer token");
    }

    #[test]
    fn test_tcp_connect_defaults() {
        let json = r#"{"host":"db.example.com","port":5432}"#;
        let req: EgressTcpConnectRequest = serde_json::from_str(json).unwrap();
        assert!(!req.tls); // default false
        assert!(req.sni_override.is_none());
        assert!(req.credential_id.is_none());
    }
}
