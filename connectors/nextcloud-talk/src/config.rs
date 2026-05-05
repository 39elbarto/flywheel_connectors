//! Nextcloud Talk connector configuration.

#![allow(clippy::missing_errors_doc)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::prelude::{FcpError, FcpResult};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_ACCOUNT_ID: &str = "default";
const DEFAULT_WEBHOOK_PUBLIC_PATH: &str = "/nextcloud-talk-webhook";

/// Nextcloud Talk connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextcloudTalkConfig {
    /// Base server URL, including any deployment subpath.
    pub server_url: String,

    /// Authentication mode for the OCS and Talk APIs.
    pub auth: NextcloudTalkAuth,

    /// Default request timeout for outbound requests.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    /// Long-poll timeout passed to the chat API.
    #[serde(default = "default_long_poll_timeout_secs")]
    pub long_poll_timeout_secs: u64,

    /// Shared retry policy for outbound request helpers.
    #[serde(default)]
    pub retry: HttpRetryConfig,

    /// Optional forced response language for API requests.
    #[serde(default)]
    pub force_language: Option<String>,

    /// Stable account identifier for multi-account setup surfaces.
    #[serde(default)]
    pub account_id: Option<String>,

    /// Optional display name for operator-facing setup and status output.
    #[serde(default)]
    pub account_name: Option<String>,

    /// Optional webhook bot setup. This is separate from OCS API authentication.
    #[serde(default)]
    pub webhook: NextcloudTalkWebhookConfig,

    /// Sender and room policy for webhook/manual-poll event admission.
    #[serde(default)]
    pub inbound_policy: NextcloudTalkInboundPolicy,

    /// Network policy for the configured Nextcloud server and webhook backend URLs.
    #[serde(default)]
    pub network: NextcloudTalkNetworkPolicy,
}

/// Authentication strategy for the Nextcloud Talk connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NextcloudTalkAuth {
    /// Basic authentication using the account password.
    Basic { username: String, password: String },

    /// Basic authentication using a recommended app password.
    AppPassword {
        username: String,
        app_password: String,
    },

    /// Bearer-token authentication for OIDC style deployments.
    BearerToken { access_token: String },

    /// Host-managed credential injection.
    CredentialId { credential_id: String },
}

/// Webhook bot configuration for inbound Nextcloud Talk events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextcloudTalkWebhookConfig {
    /// Whether a host-side webhook receiver is expected to be provisioned.
    #[serde(default)]
    pub enabled: bool,

    /// Public path Nextcloud calls for bot webhooks.
    #[serde(default = "default_webhook_public_path")]
    pub public_path: String,

    /// Optional externally reachable webhook URL when served behind a reverse proxy.
    #[serde(default)]
    pub public_url: Option<String>,

    /// Shared bot secret used to authenticate webhook requests.
    #[serde(default)]
    pub bot_secret: Option<NextcloudTalkSecretRef>,

    /// Allowed Nextcloud backend/base URLs accepted from webhook headers.
    #[serde(default)]
    pub backend_allowlist: Vec<String>,
}

impl Default for NextcloudTalkWebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            public_path: default_webhook_public_path(),
            public_url: None,
            bot_secret: None,
            backend_allowlist: Vec::new(),
        }
    }
}

/// Redaction-safe reference to the webhook bot secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum NextcloudTalkSecretRef {
    /// Inline secret material. Accepted for compatibility with simple setup flows.
    Inline { secret: String },

    /// Host-managed credential injection.
    CredentialId { credential_id: String },
}

/// Sender and room policy for inbound Nextcloud Talk events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextcloudTalkInboundPolicy {
    /// Direct-message policy. Supported values mirror channel setup surfaces.
    #[serde(default = "default_dm_policy")]
    pub dm_policy: String,

    /// Group-message policy. Defaults to allowlist to avoid open room ingestion.
    #[serde(default = "default_group_policy")]
    pub group_policy: String,

    /// Allowed direct-message senders.
    #[serde(default)]
    pub allow_from: Vec<String>,

    /// Allowed group-message senders.
    #[serde(default)]
    pub group_allow_from: Vec<String>,

    /// Allowed room tokens or wildcard patterns.
    #[serde(default)]
    pub rooms: Vec<String>,
}

impl Default for NextcloudTalkInboundPolicy {
    fn default() -> Self {
        Self {
            dm_policy: default_dm_policy(),
            group_policy: default_group_policy(),
            allow_from: Vec::new(),
            group_allow_from: Vec::new(),
            rooms: Vec::new(),
        }
    }
}

/// Runtime network policy for self-hosted Nextcloud Talk deployments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NextcloudTalkNetworkPolicy {
    /// Dangerous opt-in for trusted private/internal Nextcloud hosts.
    #[serde(default, alias = "dangerously_allow_private_network")]
    pub allow_private_networks: bool,

    /// Dangerous opt-in for trusted tailnet-hosted Nextcloud deployments.
    #[serde(default)]
    pub allow_tailnet_networks: bool,

    /// Optional exact/wildcard host allowlist. Empty means any public host.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

/// Classification of a configured URL under connector network policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextcloudTalkUrlPolicyReport {
    pub url: String,
    pub host: String,
    pub classification: &'static str,
    pub allowed: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkHostClass {
    Public,
    Localhost,
    Private,
    Tailnet,
    InternalName,
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

const fn default_long_poll_timeout_secs() -> u64 {
    30
}

fn default_webhook_public_path() -> String {
    DEFAULT_WEBHOOK_PUBLIC_PATH.to_string()
}

fn default_dm_policy() -> String {
    "pairing".to_string()
}

fn default_group_policy() -> String {
    "allowlist".to_string()
}

impl NextcloudTalkConfig {
    /// Parse and validate connector configuration from JSON.
    pub fn from_value(value: Value) -> FcpResult<Self> {
        let config: Self =
            serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid Nextcloud Talk config: {error}"),
            })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration invariants.
    pub fn validate(&self) -> FcpResult<()> {
        let parsed =
            Url::parse(self.server_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid server_url: {error}"),
            })?;

        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "server_url must use http or https".into(),
            });
        }

        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "server_url must not contain a query string or fragment".into(),
            });
        }

        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }

        if !(1..=60).contains(&self.long_poll_timeout_secs) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "long_poll_timeout_secs must be between 1 and 60".into(),
            });
        }

        if let Some(force_language) = &self.force_language {
            validate_non_empty("force_language", force_language)?;
        }
        if let Some(account_id) = &self.account_id {
            validate_non_empty("account_id", account_id)?;
        }
        if let Some(account_name) = &self.account_name {
            validate_non_empty("account_name", account_name)?;
        }

        self.auth.validate()?;
        self.webhook.validate(self)?;
        self.inbound_policy.validate()?;
        self.validate_url_policy("server_url", &parsed)?;
        Ok(())
    }

    /// Return the normalized server URL without a trailing slash.
    #[must_use]
    pub fn normalized_server_url(&self) -> String {
        self.server_url.trim().trim_end_matches('/').to_string()
    }

    /// Return the configured account id or the default single-account id.
    #[must_use]
    pub fn account_id(&self) -> &str {
        self.account_id.as_deref().unwrap_or(DEFAULT_ACCOUNT_ID)
    }

    /// Return the configured account display label without exposing secrets.
    #[must_use]
    pub fn account_label(&self) -> String {
        self.account_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(
                || self.account_id().to_string(),
                |name| format!("{} ({})", self.account_id(), name),
            )
    }

    /// Report the configured server URL policy decision.
    pub fn server_url_policy_report(&self) -> FcpResult<NextcloudTalkUrlPolicyReport> {
        let parsed =
            Url::parse(self.server_url.trim()).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid server_url: {error}"),
            })?;
        self.url_policy_report(&parsed)
    }

    fn url_policy_report(&self, url: &Url) -> FcpResult<NextcloudTalkUrlPolicyReport> {
        let host = url.host_str().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: "URL must include a host".into(),
        })?;
        let normalized_host = host.trim_end_matches('.').to_ascii_lowercase();
        let classification = classify_host(&normalized_host);
        let host_allowed = self.host_allowlist_matches(&normalized_host);
        let (allowed, reason) = match classification {
            NetworkHostClass::Tailnet if !self.network.allow_tailnet_networks => (
                false,
                "tailnet host requires network.allow_tailnet_networks=true",
            ),
            NetworkHostClass::Localhost
            | NetworkHostClass::Private
            | NetworkHostClass::InternalName
                if !self.network.allow_private_networks =>
            {
                (
                    false,
                    "private/internal host requires network.allow_private_networks=true",
                )
            }
            _ if !host_allowed => (false, "host is not listed in network.allowed_hosts"),
            _ => (true, "allowed by configured network policy"),
        };

        Ok(NextcloudTalkUrlPolicyReport {
            url: normalize_url(url),
            host: normalized_host,
            classification: classification.as_str(),
            allowed,
            reason,
        })
    }

    fn validate_url_policy(&self, field: &str, url: &Url) -> FcpResult<()> {
        let report = self.url_policy_report(url)?;
        if report.allowed {
            return Ok(());
        }
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} rejected by network policy: {}", report.reason),
        })
    }

    fn host_allowlist_matches(&self, host: &str) -> bool {
        self.network.allowed_hosts.is_empty()
            || self
                .network
                .allowed_hosts
                .iter()
                .any(|pattern| host_matches(pattern, host))
    }
}

impl NextcloudTalkAuth {
    /// Return a stable label for diagnostics.
    #[must_use]
    pub const fn mode_label(&self) -> &'static str {
        match self {
            Self::Basic { .. } => "basic",
            Self::AppPassword { .. } => "app_password",
            Self::BearerToken { .. } => "bearer_token",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Validate the selected authentication mode.
    pub fn validate(&self) -> FcpResult<()> {
        match self {
            Self::Basic { username, password } => {
                validate_non_empty("auth.username", username)?;
                validate_non_empty("auth.password", password)?;
            }
            Self::AppPassword {
                username,
                app_password,
            } => {
                validate_non_empty("auth.username", username)?;
                validate_non_empty("auth.app_password", app_password)?;
            }
            Self::BearerToken { access_token } => {
                validate_non_empty("auth.access_token", access_token)?;
            }
            Self::CredentialId { credential_id } => {
                validate_non_empty("auth.credential_id", credential_id)?;
            }
        }
        Ok(())
    }
}

impl NextcloudTalkWebhookConfig {
    fn validate(&self, config: &NextcloudTalkConfig) -> FcpResult<()> {
        validate_path("webhook.public_path", &self.public_path)?;
        if let Some(url) = &self.public_url {
            let parsed = parse_http_url("webhook.public_url", url)?;
            config.validate_url_policy("webhook.public_url", &parsed)?;
        }
        if let Some(secret) = &self.bot_secret {
            secret.validate()?;
        }
        for backend in &self.backend_allowlist {
            let parsed = parse_http_url("webhook.backend_allowlist", backend)?;
            config.validate_url_policy("webhook.backend_allowlist", &parsed)?;
        }
        Ok(())
    }

    /// Return whether webhook mode has enough local configuration to start.
    #[must_use]
    pub const fn readiness_label(&self) -> &'static str {
        if !self.enabled {
            "manual_poll"
        } else if self.bot_secret.is_some() {
            "webhook_ready"
        } else {
            "webhook_missing_secret"
        }
    }

    /// Return a redaction-safe label for the webhook bot secret source.
    #[must_use]
    pub fn secret_source_label(&self) -> &'static str {
        self.bot_secret
            .as_ref()
            .map_or("none", NextcloudTalkSecretRef::source_label)
    }
}

impl NextcloudTalkSecretRef {
    fn validate(&self) -> FcpResult<()> {
        match self {
            Self::Inline { secret } => validate_non_empty("webhook.bot_secret.secret", secret),
            Self::CredentialId { credential_id } => {
                validate_non_empty("webhook.bot_secret.credential_id", credential_id)
            }
        }
    }

    /// Return a redaction-safe secret source label.
    #[must_use]
    pub const fn source_label(&self) -> &'static str {
        match self {
            Self::Inline { .. } => "inline",
            Self::CredentialId { .. } => "credential_id",
        }
    }

    /// Return the secret material or credential id for hashing only.
    #[must_use]
    pub fn fingerprint_material(&self) -> &str {
        match self {
            Self::Inline { secret } => secret,
            Self::CredentialId { credential_id } => credential_id,
        }
    }
}

impl NextcloudTalkInboundPolicy {
    fn validate(&self) -> FcpResult<()> {
        validate_policy(
            "inbound_policy.dm_policy",
            &self.dm_policy,
            &["pairing", "allowlist", "open"],
        )?;
        validate_policy(
            "inbound_policy.group_policy",
            &self.group_policy,
            &["allowlist", "open", "disabled"],
        )?;
        validate_non_empty_entries("inbound_policy.allow_from", &self.allow_from)?;
        validate_non_empty_entries("inbound_policy.group_allow_from", &self.group_allow_from)?;
        validate_non_empty_entries("inbound_policy.rooms", &self.rooms)?;
        if self.dm_policy == "open" && self.allow_from.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "inbound_policy.allow_from must include an explicit wildcard when dm_policy is open".into(),
            });
        }
        if self.group_policy == "open" && self.group_allow_from.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "inbound_policy.group_allow_from must include an explicit wildcard when group_policy is open".into(),
            });
        }
        Ok(())
    }
}

impl NetworkHostClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Localhost => "localhost",
            Self::Private => "private",
            Self::Tailnet => "tailnet",
            Self::InternalName => "internal_name",
        }
    }
}

fn parse_http_url(field: &str, value: &str) -> FcpResult<Url> {
    let parsed = Url::parse(value.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {field}: {error}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must use http or https"),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not contain a query string or fragment"),
        });
    }
    Ok(parsed)
}

fn validate_non_empty(field: &str, value: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn validate_non_empty_entries(field: &str, values: &[String]) -> FcpResult<()> {
    for value in values {
        validate_non_empty(field, value)?;
    }
    Ok(())
}

fn validate_policy(field: &str, value: &str, allowed: &[&str]) -> FcpResult<()> {
    validate_non_empty(field, value)?;
    if allowed.contains(&value) {
        return Ok(());
    }
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field} must be one of: {}", allowed.join(", ")),
    })
}

fn validate_path(field: &str, value: &str) -> FcpResult<()> {
    validate_non_empty(field, value)?;
    if !value.starts_with('/') || value.contains('?') || value.contains('#') {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an absolute path without query or fragment"),
        });
    }
    Ok(())
}

fn normalize_url(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_string()
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let normalized = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    if let Some(suffix) = normalized.strip_prefix("*.") {
        return host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
    }
    normalized == host
}

fn classify_host(host: &str) -> NetworkHostClass {
    if host == "localhost" || host.ends_with(".localhost") {
        return NetworkHostClass::Localhost;
    }
    if host.ends_with(".ts.net") || host == "ts.net" {
        return NetworkHostClass::Tailnet;
    }
    if has_domain_suffix(host, "local")
        || has_domain_suffix(host, "internal")
        || has_domain_suffix(host, "home.arpa")
    {
        return NetworkHostClass::InternalName;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    if !host.contains('.') {
        return NetworkHostClass::InternalName;
    }
    NetworkHostClass::Public
}

fn classify_ip(ip: IpAddr) -> NetworkHostClass {
    match ip {
        IpAddr::V4(ip) if ip.is_loopback() => NetworkHostClass::Localhost,
        IpAddr::V6(ip) if ip.is_loopback() => NetworkHostClass::Localhost,
        IpAddr::V4(ip) if is_tailnet_ipv4(ip) => NetworkHostClass::Tailnet,
        IpAddr::V6(ip) if is_tailnet_ipv6(ip) => NetworkHostClass::Tailnet,
        IpAddr::V4(ip) if is_private_ipv4(ip) => NetworkHostClass::Private,
        IpAddr::V6(ip) if is_private_ipv6(ip) => NetworkHostClass::Private,
        _ => NetworkHostClass::Public,
    }
}

fn is_tailnet_ipv4(ip: Ipv4Addr) -> bool {
    matches!(ip.octets(), [100, second, _, _] if (64..=127).contains(&second))
}

const fn is_tailnet_ipv6(ip: Ipv6Addr) -> bool {
    matches!(ip.segments(), [0xfd7a, 0x115c, 0xa1e0, _, _, _, _, _])
}

const fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
}

const fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let [first, _, _, _, _, _, _, _] = ip.segments();
    ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

fn has_domain_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_app_password_config() {
        let config = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "secret"
            }
        }))
        .expect("config should parse");

        assert_eq!(config.normalized_server_url(), "https://cloud.example.com");
        assert_eq!(config.long_poll_timeout_secs, 30);
        assert!(matches!(config.auth, NextcloudTalkAuth::AppPassword { .. }));
    }

    #[test]
    fn reject_invalid_long_poll_timeout() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            },
            "long_poll_timeout_secs": 0
        }))
        .expect_err("timeout must be validated");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn reject_server_url_with_query_string() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com?foo=bar",
            "auth": {
                "mode": "bearer_token",
                "access_token": "oidc"
            }
        }))
        .expect_err("server_url must reject query strings");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn reject_blank_force_language() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            },
            "force_language": "   "
        }))
        .expect_err("blank force_language must be rejected");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn normalize_server_url_trims_whitespace_and_trailing_slash() {
        let config = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "  https://cloud.example.com/subdir/  ",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            }
        }))
        .expect("config should parse");

        assert_eq!(
            config.normalized_server_url(),
            "https://cloud.example.com/subdir"
        );
    }

    #[test]
    fn reject_private_server_url_without_opt_in() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "http://10.0.0.5",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            }
        }))
        .expect_err("private networks require explicit opt-in");

        assert!(
            error
                .to_string()
                .contains("network.allow_private_networks=true")
        );
    }

    #[test]
    fn accept_private_server_url_with_explicit_opt_in() {
        let config = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "http://10.0.0.5",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            },
            "network": {
                "allow_private_networks": true
            }
        }))
        .expect("private URL should parse with opt-in");

        let report = config.server_url_policy_report().expect("policy report");
        assert!(report.allowed);
        assert_eq!(report.classification, "private");
    }

    #[test]
    fn reject_tailnet_server_url_without_tailnet_opt_in() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://nextcloud.tailnet.ts.net",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            }
        }))
        .expect_err("tailnet URLs require explicit opt-in");

        assert!(
            error
                .to_string()
                .contains("network.allow_tailnet_networks=true")
        );
    }

    #[test]
    fn reject_unlisted_server_host_when_allowlist_is_set() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://other.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            },
            "network": {
                "allowed_hosts": ["cloud.example.com"]
            }
        }))
        .expect_err("host allowlist should fail closed");

        assert!(error.to_string().contains("network.allowed_hosts"));
    }

    #[test]
    fn parse_webhook_bot_secret_credential_id() {
        let config = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            },
            "account_id": "work",
            "account_name": "Work Talk",
            "webhook": {
                "enabled": true,
                "bot_secret": {
                    "source": "credential_id",
                    "credential_id": "bot_cred"
                }
            },
            "inbound_policy": {
                "dm_policy": "allowlist",
                "allow_from": ["alice"],
                "rooms": ["engineering"]
            }
        }))
        .expect("webhook credential id should parse");

        assert_eq!(config.account_id(), "work");
        assert_eq!(config.webhook.readiness_label(), "webhook_ready");
        assert_eq!(config.webhook.secret_source_label(), "credential_id");
    }

    #[test]
    fn reject_webhook_public_url_private_without_opt_in() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "ocs_cred"
            },
            "webhook": {
                "enabled": true,
                "public_url": "http://127.0.0.1:8788/nextcloud-talk-webhook",
                "bot_secret": {
                    "source": "credential_id",
                    "credential_id": "bot_cred"
                }
            }
        }))
        .expect_err("webhook URL should obey network policy");

        assert!(
            error
                .to_string()
                .contains("network.allow_private_networks=true")
        );
    }

    #[test]
    fn reject_open_dm_policy_without_explicit_allowlist_wildcard() {
        let error = NextcloudTalkConfig::from_value(serde_json::json!({
            "server_url": "https://cloud.example.com",
            "auth": {
                "mode": "credential_id",
                "credential_id": "cred_123"
            },
            "inbound_policy": {
                "dm_policy": "open"
            }
        }))
        .expect_err("open DM policy should require explicit allow_from");

        assert!(error.to_string().contains("inbound_policy.allow_from"));
    }
}
