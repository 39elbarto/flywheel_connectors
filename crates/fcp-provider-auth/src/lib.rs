//! Shared provider authentication primitives for FCP connectors.
//!
//! This crate is the common layer above raw credential leases and below
//! connector-specific clients. It keeps credential material redaction-safe while
//! giving connectors a uniform way to apply API keys, setup tokens, cached JWTs,
//! and later OAuth profile state to outbound requests.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use fcp_async_core::http::{HttpClient, HttpClientBuilder, Method};
use fcp_async_core::time;
use fcp_oauth::{
    OAuth2Client, OAuth2Config, OAuthTokens as FcpOAuthTokens, Pkce, PkceMethod, TokenResponse,
};
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

const DEFAULT_AUTHORIZATION_HEADER: &str = "Authorization";
const DEFAULT_BEARER_PREFIX: &str = "Bearer ";
const DEFAULT_SETUP_TOKEN_PREFIX: &str = "Setup ";
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";
const DEFAULT_OAUTH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_DEVICE_CODE_INTERVAL: Duration = Duration::from_secs(5);
const REDACTED: &str = "[REDACTED]";

/// Result type for provider-auth operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// Secret string material that redacts in all formatted output and zeroizes on
/// drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap credential material.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the raw material to code that is about to place it on an outbound
    /// authenticated request.
    #[must_use]
    pub fn expose_material(&self) -> &str {
        &self.0
    }

    /// Return whether this material has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return a bounded operator-safe preview for audit messages.
    #[must_use]
    pub fn redacted_preview(&self) -> String {
        if self.0.is_empty() {
            return REDACTED.to_owned();
        }

        let mut preview: String = self.0.chars().take(8).collect();
        preview.push_str("...");
        preview
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Redaction-safe outbound authentication envelope.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuthRequest {
    headers: BTreeMap<String, SecretString>,
}

impl AuthRequest {
    /// Create an empty auth request envelope.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a credential header value.
    ///
    /// # Errors
    ///
    /// Returns an error when the header name is empty or contains invalid
    /// characters, or when the header value contains newline characters.
    pub fn insert_material_header(
        &mut self,
        name: impl Into<String>,
        value: SecretString,
    ) -> AuthResult<()> {
        let name = name.into();
        validate_header_name(&name)?;
        validate_header_value(value.expose_material(), "header_value")?;
        self.headers.insert(name, value);
        Ok(())
    }

    /// Return a credential header value by case-sensitive name.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&SecretString> {
        self.headers.get(name)
    }

    /// Return the number of credential auth headers in this envelope.
    #[must_use]
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Iterate over auth headers.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &SecretString)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }
}

impl fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_headers: BTreeMap<&str, &str> = self
            .headers
            .keys()
            .map(|name| (name.as_str(), REDACTED))
            .collect();

        f.debug_struct("AuthRequest")
            .field("headers", &redacted_headers)
            .finish()
    }
}

/// Redaction-safe provider authentication errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// Configuration was invalid before any outbound request was made.
    #[error("invalid auth configuration for {field}: {reason}")]
    InvalidConfig {
        /// Configuration field name.
        field: &'static str,
        /// Redaction-safe reason.
        reason: String,
    },
    /// Authentication material is missing for a method that requires it.
    #[error("{method} auth material is missing")]
    MissingMaterial {
        /// Auth method identifier.
        method: &'static str,
    },
    /// Authentication material has expired.
    #[error("{method} auth material expired at {expires_at}")]
    Expired {
        /// Auth method identifier.
        method: &'static str,
        /// Expiration timestamp.
        expires_at: DateTime<Utc>,
    },
    /// A profile was not found in the store.
    #[error("auth profile not found for provider {provider}: {profile_id}")]
    ProfileNotFound {
        /// Provider name.
        provider: String,
        /// Opaque profile identifier.
        profile_id: String,
    },
    /// No profiles exist for a provider.
    #[error("no auth profiles configured for provider {provider}")]
    NoProfiles {
        /// Provider name.
        provider: String,
    },
    /// A method exists but this first slice has not wired the requested
    /// operation yet.
    #[error("{method} auth does not support {operation} yet")]
    UnsupportedMethod {
        /// Auth method identifier.
        method: &'static str,
        /// Operation name.
        operation: &'static str,
    },
    /// Internal shared state was poisoned.
    #[error("auth state unavailable: {reason}")]
    StateUnavailable {
        /// Redaction-safe reason.
        reason: String,
    },
    /// OAuth flow state is pending and should be polled again later.
    #[error("oauth device-code authorization is still pending; poll again after {retry_after:?}")]
    AuthorizationPending {
        /// Provider-directed retry interval.
        retry_after: Duration,
    },
    /// OAuth flow failed with a redaction-safe reason.
    #[error("oauth {operation} failed: {reason}")]
    OAuthFlow {
        /// OAuth operation being performed.
        operation: &'static str,
        /// Redaction-safe reason.
        reason: String,
    },
}

impl AuthError {
    fn invalid_config(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidConfig {
            field,
            reason: reason.into(),
        }
    }
}

/// Redaction-safe OAuth token material returned by provider-auth flows.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthTokenSet {
    access_token: SecretString,
    token_type: String,
    expires_at: Option<DateTime<Utc>>,
    refresh_token: Option<SecretString>,
    scopes: Vec<String>,
}

impl OAuthTokenSet {
    /// Build a provider-auth token set from parsed OAuth token material.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error if the token material is incomplete.
    pub fn new(
        access_token: impl Into<SecretString>,
        token_type: impl Into<String>,
        expires_at: Option<DateTime<Utc>>,
        refresh_token: Option<SecretString>,
        scopes: Vec<String>,
    ) -> AuthResult<Self> {
        let access_token = access_token.into();
        let token_type = token_type.into();
        if access_token.is_empty() {
            return Err(AuthError::MissingMaterial {
                method: "oauth_token",
            });
        }
        validate_non_empty("token_type", &token_type)?;
        Ok(Self {
            access_token,
            token_type,
            expires_at,
            refresh_token,
            scopes,
        })
    }

    /// Access-token material.
    #[must_use]
    pub const fn access_token(&self) -> &SecretString {
        &self.access_token
    }

    /// OAuth token type, usually `Bearer`.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Access-token expiration, when the provider supplied one.
    #[must_use]
    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Refresh-token material, when present.
    #[must_use]
    pub const fn refresh_token(&self) -> Option<&SecretString> {
        self.refresh_token.as_ref()
    }

    /// Granted OAuth scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Build an authorization header from the stored token.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error if the token is missing required material.
    pub fn authorization_header(&self) -> AuthResult<SecretString> {
        if self.access_token.is_empty() {
            return Err(AuthError::MissingMaterial {
                method: "oauth_token",
            });
        }
        validate_header_value(&self.token_type, "token_type")?;
        Ok(SecretString::new(format!(
            "{} {}",
            self.token_type,
            self.access_token.expose_material()
        )))
    }

    fn from_fcp_oauth(tokens: &FcpOAuthTokens) -> AuthResult<Self> {
        let expires_at = tokens
            .time_until_expiry()
            .map(|remaining| Utc::now() + chrono_duration(remaining));
        Self::new(
            SecretString::new(tokens.access_token()),
            tokens.token_type().to_owned(),
            expires_at,
            tokens.refresh_token().map(SecretString::new),
            tokens.scopes().to_vec(),
        )
    }
}

impl fmt::Debug for OAuthTokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokenSet")
            .field("access_token", &REDACTED)
            .field("token_type", &self.token_type)
            .field("expires_at", &self.expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| REDACTED),
            )
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Uniform authentication method interface for connector request builders.
#[async_trait]
pub trait AuthMethod: Send + Sync {
    /// Stable method identifier.
    fn id(&self) -> &'static str;

    /// Validate local configuration and currently held auth material.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe [`AuthError`] if configuration is incomplete,
    /// malformed, expired, or unsupported for this slice.
    async fn validate(&self, cx: &fcp_async_core::Cx) -> AuthResult<()>;

    /// Apply this method's request authentication.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe [`AuthError`] if the method cannot currently
    /// build request authentication.
    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()>;

    /// Time until this method next requires refresh, if it is TTL-bounded.
    fn requires_refresh_in(&self) -> Option<Duration>;

    /// Refresh auth material.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe [`AuthError`] if refresh is unsupported or
    /// fails.
    async fn refresh(&self, cx: &fcp_async_core::Cx) -> AuthResult<()>;
}

/// Static API-key authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyAuth {
    /// Secret API key.
    pub key: SecretString,
    /// Header name, defaulting to `Authorization`.
    pub header_name: String,
    /// Header value prefix, defaulting to `Bearer `.
    pub value_prefix: String,
}

impl ApiKeyAuth {
    /// Create default Bearer-token API-key auth.
    #[must_use]
    pub fn new(key: impl Into<SecretString>) -> Self {
        Self {
            key: key.into(),
            header_name: DEFAULT_AUTHORIZATION_HEADER.to_owned(),
            value_prefix: DEFAULT_BEARER_PREFIX.to_owned(),
        }
    }

    /// Override the outbound header name.
    #[must_use]
    pub fn with_header_name(mut self, header_name: impl Into<String>) -> Self {
        self.header_name = header_name.into();
        self
    }

    /// Override the outbound header value prefix.
    #[must_use]
    pub fn with_value_prefix(mut self, value_prefix: impl Into<String>) -> Self {
        self.value_prefix = value_prefix.into();
        self
    }
}

#[async_trait]
impl AuthMethod for ApiKeyAuth {
    fn id(&self) -> &'static str {
        "api_key"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        if self.key.is_empty() {
            return Err(AuthError::MissingMaterial { method: self.id() });
        }
        validate_header_name(&self.header_name)?;
        validate_header_value(&self.value_prefix, "value_prefix")
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        let prefix = &self.value_prefix;
        let credential_material = self.key.expose_material();
        request.insert_material_header(
            self.header_name.clone(),
            SecretString::new(format!("{prefix}{credential_material}")),
        )
    }

    fn requires_refresh_in(&self) -> Option<Duration> {
        None
    }

    async fn refresh(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "refresh",
        })
    }
}

/// Short-lived first-run setup token authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupTokenAuth {
    /// Secret setup token.
    pub token: SecretString,
    /// Token expiration.
    pub expires_at: DateTime<Utc>,
    /// Header name, defaulting to `Authorization`.
    pub header_name: String,
    /// Header value prefix, defaulting to `Setup `.
    pub value_prefix: String,
}

impl SetupTokenAuth {
    /// Create setup-token auth with the default header shape.
    #[must_use]
    pub fn new(token: impl Into<SecretString>, expires_at: DateTime<Utc>) -> Self {
        Self {
            token: token.into(),
            expires_at,
            header_name: DEFAULT_AUTHORIZATION_HEADER.to_owned(),
            value_prefix: DEFAULT_SETUP_TOKEN_PREFIX.to_owned(),
        }
    }
}

#[async_trait]
impl AuthMethod for SetupTokenAuth {
    fn id(&self) -> &'static str {
        "setup_token"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        if self.token.is_empty() {
            return Err(AuthError::MissingMaterial { method: self.id() });
        }
        validate_header_name(&self.header_name)?;
        validate_header_value(&self.value_prefix, "value_prefix")?;
        ensure_not_expired(self.id(), self.expires_at)
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        let prefix = &self.value_prefix;
        let setup_material = self.token.expose_material();
        request.insert_material_header(
            self.header_name.clone(),
            SecretString::new(format!("{prefix}{setup_material}")),
        )
    }

    fn requires_refresh_in(&self) -> Option<Duration> {
        duration_until(self.expires_at)
    }

    async fn refresh(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "refresh",
        })
    }
}

/// OAuth device-code method state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthDeviceCodeAuth {
    /// OAuth client identifier.
    pub client_id: String,
    /// Device-code endpoint URL.
    pub device_code_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Space-delimited OAuth scopes.
    pub scope: String,
    /// Current access token, if one has already been acquired.
    pub access_token: Option<SecretString>,
    /// Refresh token, if the provider issued one.
    pub refresh_token: Option<SecretString>,
    /// Access-token expiration.
    pub expires_at: Option<DateTime<Utc>>,
}

/// OAuth device-code flow configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthDeviceCodeConfig {
    /// OAuth client identifier.
    pub client_id: String,
    /// Device-code endpoint URL.
    pub device_code_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Space-delimited OAuth scopes.
    pub scope: String,
    /// HTTP request timeout for device-code endpoints.
    pub timeout: Duration,
    /// Default polling interval when the provider omits one.
    pub poll_interval: Duration,
}

impl OAuthDeviceCodeConfig {
    /// Build a device-code config from profile state.
    #[must_use]
    pub fn from_auth(method: &OAuthDeviceCodeAuth) -> Self {
        Self {
            client_id: method.client_id.clone(),
            device_code_url: method.device_code_url.clone(),
            token_url: method.token_url.clone(),
            scope: method.scope.clone(),
            timeout: DEFAULT_OAUTH_TIMEOUT,
            poll_interval: DEFAULT_DEVICE_CODE_INTERVAL,
        }
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty("client_id", &self.client_id)?;
        validate_auth_endpoint_url("device_code_url", &self.device_code_url)?;
        validate_auth_endpoint_url("token_url", &self.token_url)?;
        if self.timeout.is_zero() {
            return Err(AuthError::invalid_config(
                "timeout",
                "OAuth device-code timeout must be greater than zero",
            ));
        }
        if self.poll_interval.is_zero() {
            return Err(AuthError::invalid_config(
                "poll_interval",
                "OAuth device-code poll interval must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Provider-issued device-code challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCodeChallenge {
    /// Device code sent only to the token endpoint.
    pub device_code: SecretString,
    /// User-facing code the operator enters at the verification URI.
    pub user_code: String,
    /// Verification URL the operator should open.
    pub verification_uri: String,
    /// Optional complete verification URL.
    pub verification_uri_complete: Option<String>,
    /// Challenge expiration.
    pub expires_at: DateTime<Utc>,
    /// Provider-directed polling interval.
    pub interval: Duration,
}

/// OAuth device-code flow state machine.
#[derive(Clone)]
pub struct OAuthDeviceCodeFlow {
    config: OAuthDeviceCodeConfig,
    challenge: DeviceCodeChallenge,
    http_client: Arc<HttpClient>,
}

impl fmt::Debug for OAuthDeviceCodeFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthDeviceCodeFlow")
            .field("config", &self.config)
            .field("challenge", &self.challenge)
            .field("http_client", &"HttpClient(..)")
            .finish()
    }
}

impl OAuthDeviceCodeFlow {
    /// Start a device-code flow and return the state machine with its challenge.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error when configuration is invalid, transport
    /// fails, or the provider response is malformed.
    pub async fn start(cx: &fcp_async_core::Cx, config: OAuthDeviceCodeConfig) -> AuthResult<Self> {
        config.validate()?;
        let http_client = Arc::new(
            HttpClientBuilder::new()
                .user_agent("fcp-provider-auth/0.1.0")
                .build(),
        );
        let response = send_oauth_form(
            cx,
            &http_client,
            &config.device_code_url,
            &[
                ("client_id", config.client_id.as_str()),
                ("scope", &config.scope),
            ],
            config.timeout,
            "device_code_start",
        )
        .await?;

        if !response.is_success() {
            return Err(oauth_flow_status_error(
                "device_code_start",
                response.status,
            ));
        }
        let started_at = Utc::now();
        let response: DeviceCodeStartResponse = response
            .json()
            .map_err(|error| invalid_oauth_response("device_code_start", &error))?;
        let challenge = response.into_challenge(started_at, config.poll_interval)?;

        Ok(Self {
            config,
            challenge,
            http_client,
        })
    }

    /// Current device-code challenge.
    #[must_use]
    pub const fn challenge(&self) -> &DeviceCodeChallenge {
        &self.challenge
    }

    /// Poll the token endpoint once.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::AuthorizationPending`] when the provider says the
    /// operator has not completed authorization yet. Callers should wait for
    /// the included retry interval and poll again.
    pub async fn poll(&mut self, cx: &fcp_async_core::Cx) -> AuthResult<OAuthTokenSet> {
        ensure_not_expired("oauth_device_code", self.challenge.expires_at)?;
        let device_code = self.challenge.device_code.expose_material();
        let grant_type = fcp_oauth::GrantType::DeviceCode.to_string();
        let response = send_oauth_form(
            cx,
            &self.http_client,
            &self.config.token_url,
            &[
                ("grant_type", grant_type.as_str()),
                ("device_code", device_code),
                ("client_id", self.config.client_id.as_str()),
            ],
            self.config.timeout,
            "device_code_poll",
        )
        .await?;
        let status = response.status;
        let response: DeviceCodePollResponse = response
            .json()
            .map_err(|error| invalid_oauth_response("device_code_poll", &error))?;
        if let Some(error) = response.error.as_deref() {
            return self.handle_device_poll_error(error);
        }
        if !(200..300).contains(&status) {
            return Err(oauth_flow_status_error("device_code_poll", status));
        }
        response.into_token_set()
    }

    fn handle_device_poll_error(&mut self, error: &str) -> AuthResult<OAuthTokenSet> {
        match error {
            "authorization_pending" => Err(AuthError::AuthorizationPending {
                retry_after: self.challenge.interval,
            }),
            "slow_down" => {
                let next = self.challenge.interval.as_secs().saturating_add(5).max(1);
                self.challenge.interval = Duration::from_secs(next);
                Err(AuthError::AuthorizationPending {
                    retry_after: self.challenge.interval,
                })
            }
            code => Err(AuthError::OAuthFlow {
                operation: "device_code_poll",
                reason: format!("provider returned terminal error `{code}`"),
            }),
        }
    }
}

#[async_trait]
impl AuthMethod for OAuthDeviceCodeAuth {
    fn id(&self) -> &'static str {
        "oauth_device_code"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_non_empty("client_id", &self.client_id)?;
        validate_auth_endpoint_url("device_code_url", &self.device_code_url)?;
        validate_auth_endpoint_url("token_url", &self.token_url)?;
        if let Some(expires_at) = self.expires_at {
            ensure_not_expired(self.id(), expires_at)?;
        }
        Ok(())
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        insert_bearer_material(self.id(), self.access_token.as_ref(), request)
    }

    fn requires_refresh_in(&self) -> Option<Duration> {
        self.expires_at.and_then(duration_until)
    }

    async fn refresh(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "refresh",
        })
    }
}

/// OAuth authorization-code method state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthAuthCodeAuth {
    /// OAuth client identifier.
    pub client_id: String,
    /// OAuth client secret, when the provider requires one.
    pub client_secret: Option<SecretString>,
    /// Authorization endpoint URL.
    pub authorize_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Space-delimited OAuth scopes.
    pub scope: String,
    /// Whether PKCE is required for this profile.
    pub use_pkce: bool,
    /// Current access token, if one has already been acquired.
    pub access_token: Option<SecretString>,
    /// Refresh token, if the provider issued one.
    pub refresh_token: Option<SecretString>,
    /// Access-token expiration.
    pub expires_at: Option<DateTime<Utc>>,
}

/// OAuth authorization-code flow configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthAuthCodeConfig {
    /// OAuth client identifier.
    pub client_id: String,
    /// OAuth client secret, if required by the provider.
    pub client_secret: Option<SecretString>,
    /// Authorization endpoint URL.
    pub authorize_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Space-delimited OAuth scopes.
    pub scope: String,
    /// Whether PKCE is required.
    pub use_pkce: bool,
    /// HTTP request timeout for token exchange.
    pub timeout: Duration,
}

impl OAuthAuthCodeConfig {
    /// Build an authorization-code config from profile state.
    #[must_use]
    pub fn from_auth(method: &OAuthAuthCodeAuth) -> Self {
        Self {
            client_id: method.client_id.clone(),
            client_secret: method.client_secret.clone(),
            authorize_url: method.authorize_url.clone(),
            token_url: method.token_url.clone(),
            redirect_uri: method.redirect_uri.clone(),
            scope: method.scope.clone(),
            use_pkce: method.use_pkce,
            timeout: DEFAULT_OAUTH_TIMEOUT,
        }
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty("client_id", &self.client_id)?;
        validate_auth_endpoint_url("authorize_url", &self.authorize_url)?;
        validate_auth_endpoint_url("token_url", &self.token_url)?;
        validate_auth_endpoint_url("redirect_uri", &self.redirect_uri)?;
        if self.timeout.is_zero() {
            return Err(AuthError::invalid_config(
                "timeout",
                "OAuth authorization-code timeout must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// PKCE verifier owned by provider-auth so `fcp-oauth` types do not leak into
/// connector-facing APIs.
#[derive(Clone, PartialEq, Eq)]
pub struct PkceVerifier {
    inner: Pkce,
}

impl PkceVerifier {
    /// Redaction-safe code challenge.
    #[must_use]
    pub fn code_challenge(&self) -> &str {
        self.inner.challenge()
    }

    /// PKCE challenge method.
    #[must_use]
    pub const fn method(&self) -> PkceMethod {
        self.inner.method()
    }
}

impl fmt::Debug for PkceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PkceVerifier")
            .field("verifier", &REDACTED)
            .field("challenge", &REDACTED)
            .field("method", &self.inner.method())
            .finish()
    }
}

/// Authorization-code challenge returned to the operator/UI layer.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationCodeChallenge {
    /// Redaction-safe URL containing state and PKCE challenge query params.
    pub authorize_url: url::Url,
    /// CSRF state; send it to callback validation but keep it out of logs.
    pub state: SecretString,
    /// PKCE verifier for the token exchange, when PKCE is enabled.
    pub pkce: Option<PkceVerifier>,
}

impl fmt::Debug for AuthorizationCodeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut redacted_url = self.authorize_url.clone();
        redacted_url.set_query(None);
        redacted_url.set_fragment(None);
        f.debug_struct("AuthorizationCodeChallenge")
            .field("authorize_url", &redacted_url.as_str())
            .field("state", &REDACTED)
            .field("pkce", &self.pkce)
            .finish()
    }
}

/// OAuth authorization-code flow helpers.
#[derive(Clone, Debug, Default)]
pub struct OAuthAuthCodeFlow;

impl OAuthAuthCodeFlow {
    /// Build an authorization URL plus one-time CSRF/PKCE state.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error when configuration is invalid.
    pub fn build_authorize_url(
        config: &OAuthAuthCodeConfig,
    ) -> AuthResult<AuthorizationCodeChallenge> {
        config.validate()?;
        let client = oauth2_client_from_auth_code_config(config)?;
        let scopes = split_scopes(&config.scope);
        let session = if config.use_pkce {
            client.authorization_session_with_pkce(&scopes)
        } else {
            client.authorization_session(&scopes)
        }
        .map_err(|error| oauth_error("authorization_url", &error))?;
        let authorize_url =
            url::Url::parse(session.authorization_url()).map_err(|error| AuthError::OAuthFlow {
                operation: "authorization_url",
                reason: error.to_string(),
            })?;
        Ok(AuthorizationCodeChallenge {
            authorize_url,
            state: SecretString::new(session.state()),
            pkce: session.pkce().cloned().map(|inner| PkceVerifier { inner }),
        })
    }

    /// Exchange an authorization code for tokens.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error when configuration is invalid, PKCE is
    /// missing for a PKCE profile, or token exchange fails.
    pub async fn exchange_code(
        cx: &fcp_async_core::Cx,
        config: &OAuthAuthCodeConfig,
        code: &str,
        pkce: Option<&PkceVerifier>,
    ) -> AuthResult<OAuthTokenSet> {
        cx.checkpoint().map_err(|error| AuthError::OAuthFlow {
            operation: "authorization_code_exchange",
            reason: error.to_string(),
        })?;
        config.validate()?;
        let client = oauth2_client_from_auth_code_config(config)?;
        let tokens = if config.use_pkce {
            let verifier = pkce.ok_or_else(|| {
                AuthError::invalid_config("pkce", "PKCE verifier is required for this profile")
            })?;
            client.exchange_code_with_pkce(code, &verifier.inner).await
        } else {
            client.exchange_code(code).await
        }
        .map_err(|error| oauth_error("authorization_code_exchange", &error))?;
        OAuthTokenSet::from_fcp_oauth(&tokens)
    }
}

#[async_trait]
impl AuthMethod for OAuthAuthCodeAuth {
    fn id(&self) -> &'static str {
        "oauth_auth_code"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_non_empty("client_id", &self.client_id)?;
        validate_auth_endpoint_url("authorize_url", &self.authorize_url)?;
        validate_auth_endpoint_url("token_url", &self.token_url)?;
        validate_auth_endpoint_url("redirect_uri", &self.redirect_uri)?;
        if let Some(expires_at) = self.expires_at {
            ensure_not_expired(self.id(), expires_at)?;
        }
        Ok(())
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        insert_bearer_material(self.id(), self.access_token.as_ref(), request)
    }

    fn requires_refresh_in(&self) -> Option<Duration> {
        self.expires_at.and_then(duration_until)
    }

    async fn refresh(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "refresh",
        })
    }
}

/// Cached JWT-token authentication.
#[derive(Clone)]
pub struct JwtAuth {
    generator: Arc<dyn Fn() -> AuthResult<SecretString> + Send + Sync>,
    cached_token: Arc<Mutex<Option<CachedJwtToken>>>,
    /// Token time-to-live.
    pub ttl: Duration,
    /// Header name, defaulting to `Authorization`.
    pub header_name: String,
    /// Header value prefix, defaulting to `Bearer `.
    pub value_prefix: String,
}

impl fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cache_state = match self.cached_token.lock() {
            Ok(cache) if cache.is_some() => "present",
            Ok(_) => "empty",
            Err(_) => "unavailable",
        };

        f.debug_struct("JwtAuth")
            .field("generator", &"JwtGenerator(..)")
            .field("cached_token", &cache_state)
            .field("ttl", &self.ttl)
            .field("header_name", &self.header_name)
            .field("value_prefix", &self.value_prefix)
            .finish()
    }
}

impl JwtAuth {
    /// Create JWT auth from a redaction-safe token generator.
    #[must_use]
    pub fn new(
        generator: impl Fn() -> AuthResult<SecretString> + Send + Sync + 'static,
        ttl: Duration,
    ) -> Self {
        Self {
            generator: Arc::new(generator),
            cached_token: Arc::new(Mutex::new(None)),
            ttl,
            header_name: DEFAULT_AUTHORIZATION_HEADER.to_owned(),
            value_prefix: DEFAULT_BEARER_PREFIX.to_owned(),
        }
    }

    fn cache(&self) -> AuthResult<MutexGuard<'_, Option<CachedJwtToken>>> {
        self.cached_token
            .lock()
            .map_err(|_| AuthError::StateUnavailable {
                reason: "jwt token cache poisoned".to_owned(),
            })
    }

    fn generate_and_cache(&self) -> AuthResult<SecretString> {
        let generated_material = (self.generator)()?;
        if generated_material.is_empty() {
            return Err(AuthError::MissingMaterial { method: self.id() });
        }

        let expires_at = Utc::now() + chrono_duration(self.ttl);
        *self.cache()? = Some(CachedJwtToken {
            material: generated_material.clone(),
            expires_at,
        });
        Ok(generated_material)
    }
}

#[derive(Clone, Debug)]
struct CachedJwtToken {
    material: SecretString,
    expires_at: DateTime<Utc>,
}

#[async_trait]
impl AuthMethod for JwtAuth {
    fn id(&self) -> &'static str {
        "jwt"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        if self.ttl.is_zero() {
            return Err(AuthError::invalid_config(
                "ttl",
                "JWT token TTL must be greater than zero",
            ));
        }
        validate_header_name(&self.header_name)?;
        validate_header_value(&self.value_prefix, "value_prefix")
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;

        let cached = {
            let cache = self.cache()?;
            cache
                .as_ref()
                .filter(|cached| Utc::now() < cached.expires_at)
                .map(|cached| cached.material.clone())
        };
        let jwt_material = match cached {
            Some(cached_material) => cached_material,
            None => self.generate_and_cache()?,
        };
        let prefix = &self.value_prefix;
        let jwt_material = jwt_material.expose_material();

        request.insert_material_header(
            self.header_name.clone(),
            SecretString::new(format!("{prefix}{jwt_material}")),
        )
    }

    fn requires_refresh_in(&self) -> Option<Duration> {
        self.cache().ok().and_then(|cache| {
            cache
                .as_ref()
                .and_then(|cached| duration_until(cached.expires_at))
        })
    }

    async fn refresh(&self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.validate(cx).await?;
        self.generate_and_cache().map(|_| ())
    }
}

/// AWS Signature Version 4 credential material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigV4Auth {
    /// AWS access key identifier.
    pub access_key: SecretString,
    /// AWS secret access key.
    pub secret_key: SecretString,
    /// Optional AWS session token.
    pub session_token: Option<SecretString>,
    /// AWS region.
    pub region: String,
    /// AWS service name.
    pub service: String,
}

#[async_trait]
impl AuthMethod for SigV4Auth {
    fn id(&self) -> &'static str {
        "sigv4"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        if self.access_key.is_empty() || self.secret_key.is_empty() {
            return Err(AuthError::MissingMaterial { method: self.id() });
        }
        validate_non_empty("region", &self.region)?;
        validate_non_empty("service", &self.service)
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        _request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "canonical request signing",
        })
    }

    fn requires_refresh_in(&self) -> Option<Duration> {
        None
    }

    async fn refresh(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "refresh",
        })
    }
}

/// Concrete multi-method auth enum used in provider profiles.
#[derive(Clone, Debug)]
pub enum AuthMethodKind {
    /// API-key Bearer-token auth.
    ApiKey(ApiKeyAuth),
    /// OAuth device-code profile state.
    OAuthDeviceCode(OAuthDeviceCodeAuth),
    /// OAuth authorization-code profile state.
    OAuthAuthCode(OAuthAuthCodeAuth),
    /// Short-lived setup token.
    SetupToken(SetupTokenAuth),
    /// Cached JWT-token auth.
    Jwt(JwtAuth),
    /// AWS Signature Version 4 auth material.
    SigV4(SigV4Auth),
}

#[async_trait]
impl AuthMethod for AuthMethodKind {
    fn id(&self) -> &'static str {
        match self {
            Self::ApiKey(method) => method.id(),
            Self::OAuthDeviceCode(method) => method.id(),
            Self::OAuthAuthCode(method) => method.id(),
            Self::SetupToken(method) => method.id(),
            Self::Jwt(method) => method.id(),
            Self::SigV4(method) => method.id(),
        }
    }

    async fn validate(&self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        match self {
            Self::ApiKey(method) => method.validate(cx).await,
            Self::OAuthDeviceCode(method) => method.validate(cx).await,
            Self::OAuthAuthCode(method) => method.validate(cx).await,
            Self::SetupToken(method) => method.validate(cx).await,
            Self::Jwt(method) => method.validate(cx).await,
            Self::SigV4(method) => method.validate(cx).await,
        }
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        match self {
            Self::ApiKey(method) => method.build_request_auth(cx, request).await,
            Self::OAuthDeviceCode(method) => method.build_request_auth(cx, request).await,
            Self::OAuthAuthCode(method) => method.build_request_auth(cx, request).await,
            Self::SetupToken(method) => method.build_request_auth(cx, request).await,
            Self::Jwt(method) => method.build_request_auth(cx, request).await,
            Self::SigV4(method) => method.build_request_auth(cx, request).await,
        }
    }

    fn requires_refresh_in(&self) -> Option<Duration> {
        match self {
            Self::ApiKey(method) => method.requires_refresh_in(),
            Self::OAuthDeviceCode(method) => method.requires_refresh_in(),
            Self::OAuthAuthCode(method) => method.requires_refresh_in(),
            Self::SetupToken(method) => method.requires_refresh_in(),
            Self::Jwt(method) => method.requires_refresh_in(),
            Self::SigV4(method) => method.requires_refresh_in(),
        }
    }

    async fn refresh(&self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        match self {
            Self::ApiKey(method) => method.refresh(cx).await,
            Self::OAuthDeviceCode(method) => method.refresh(cx).await,
            Self::OAuthAuthCode(method) => method.refresh(cx).await,
            Self::SetupToken(method) => method.refresh(cx).await,
            Self::Jwt(method) => method.refresh(cx).await,
            Self::SigV4(method) => method.refresh(cx).await,
        }
    }
}

/// Stored provider authentication profile.
#[derive(Clone, Debug)]
pub struct AuthProfile {
    /// Opaque profile identifier.
    pub id: String,
    /// Provider identifier, for example `anthropic` or `openai`.
    pub provider: String,
    /// Concrete authentication method.
    pub method: AuthMethodKind,
    /// Human-readable profile label.
    pub label: String,
    /// Lower values are preferred when resolving the active profile.
    pub priority: i32,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl AuthProfile {
    /// Create a provider auth profile.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        provider: impl Into<String>,
        method: AuthMethodKind,
        label: impl Into<String>,
        priority: i32,
    ) -> Self {
        Self {
            id: id.into(),
            provider: provider.into(),
            method,
            label: label.into(),
            priority,
            created_at: Utc::now(),
            last_used_at: None,
        }
    }
}

/// Async store for provider auth profiles.
#[async_trait]
pub trait AuthProfileStore: Send + Sync {
    /// List profiles for a provider in resolution order.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe [`AuthError`] if the backing store is
    /// unavailable.
    async fn list_profiles(&self, provider: &str) -> AuthResult<Vec<AuthProfile>>;

    /// Get one profile by provider and profile identifier.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProfileNotFound`] when no profile exists.
    async fn get_profile(&self, provider: &str, profile_id: &str) -> AuthResult<AuthProfile>;

    /// Save or replace one profile.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe [`AuthError`] when the profile shape is invalid
    /// or the backing store is unavailable.
    async fn save_profile(&self, profile: AuthProfile) -> AuthResult<()>;

    /// Delete one profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProfileNotFound`] when no profile exists.
    async fn delete_profile(&self, provider: &str, profile_id: &str) -> AuthResult<()>;

    /// Pick the active profile for a provider.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::NoProfiles`] when the provider has no profiles.
    async fn pick_active(&self, provider: &str) -> AuthResult<AuthProfile>;
}

/// In-memory auth profile store for tests and ephemeral connector harnesses.
#[derive(Debug, Default)]
pub struct InMemoryAuthProfileStore {
    profiles: Mutex<BTreeMap<(String, String), AuthProfile>>,
}

impl InMemoryAuthProfileStore {
    /// Create an empty in-memory profile store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn profiles(&self) -> AuthResult<MutexGuard<'_, BTreeMap<(String, String), AuthProfile>>> {
        self.profiles
            .lock()
            .map_err(|_| AuthError::StateUnavailable {
                reason: "profile store lock poisoned".to_owned(),
            })
    }
}

#[async_trait]
impl AuthProfileStore for InMemoryAuthProfileStore {
    async fn list_profiles(&self, provider: &str) -> AuthResult<Vec<AuthProfile>> {
        validate_non_empty("provider", provider)?;

        let mut profiles: Vec<_> = self
            .profiles()?
            .values()
            .filter(|profile| profile.provider == provider)
            .cloned()
            .collect();
        profiles.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(profiles)
    }

    async fn get_profile(&self, provider: &str, profile_id: &str) -> AuthResult<AuthProfile> {
        validate_non_empty("provider", provider)?;
        validate_non_empty("profile_id", profile_id)?;

        self.profiles()?
            .get(&(provider.to_owned(), profile_id.to_owned()))
            .cloned()
            .ok_or_else(|| AuthError::ProfileNotFound {
                provider: provider.to_owned(),
                profile_id: profile_id.to_owned(),
            })
    }

    async fn save_profile(&self, profile: AuthProfile) -> AuthResult<()> {
        validate_profile_shape(&profile)?;
        self.profiles()?
            .insert((profile.provider.clone(), profile.id.clone()), profile);
        Ok(())
    }

    async fn delete_profile(&self, provider: &str, profile_id: &str) -> AuthResult<()> {
        validate_non_empty("provider", provider)?;
        validate_non_empty("profile_id", profile_id)?;

        let removed = self
            .profiles()?
            .remove(&(provider.to_owned(), profile_id.to_owned()));
        match removed {
            Some(_) => Ok(()),
            None => Err(AuthError::ProfileNotFound {
                provider: provider.to_owned(),
                profile_id: profile_id.to_owned(),
            }),
        }
    }

    async fn pick_active(&self, provider: &str) -> AuthResult<AuthProfile> {
        self.list_profiles(provider)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| AuthError::NoProfiles {
                provider: provider.to_owned(),
            })
    }
}

fn validate_profile_shape(profile: &AuthProfile) -> AuthResult<()> {
    validate_non_empty("id", &profile.id)?;
    validate_non_empty("provider", &profile.provider)?;
    validate_non_empty("label", &profile.label)
}

fn validate_non_empty(field: &'static str, value: &str) -> AuthResult<()> {
    if value.trim().is_empty() {
        return Err(AuthError::invalid_config(field, "value cannot be empty"));
    }
    Ok(())
}

fn validate_header_name(header_name: &str) -> AuthResult<()> {
    validate_non_empty("header_name", header_name)?;
    if !header_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(AuthError::invalid_config(
            "header_name",
            "header name must contain only ASCII letters, digits, and '-'",
        ));
    }
    Ok(())
}

fn validate_header_value(value: &str, field: &'static str) -> AuthResult<()> {
    if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(AuthError::invalid_config(
            field,
            "header values cannot contain newlines",
        ));
    }
    Ok(())
}

fn validate_auth_endpoint_url(field: &'static str, raw_url: &str) -> AuthResult<()> {
    validate_non_empty(field, raw_url)?;
    let url = url::Url::parse(raw_url)
        .map_err(|error| AuthError::invalid_config(field, error.to_string()))?;

    match url.scheme() {
        "https" => Ok(()),
        "http" if url.host_str().is_some_and(is_loopback_host) => Ok(()),
        _ => Err(AuthError::invalid_config(
            field,
            "URL must use https, except http loopback URLs for local tests",
        )),
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn ensure_not_expired(method: &'static str, expires_at: DateTime<Utc>) -> AuthResult<()> {
    if Utc::now() >= expires_at {
        return Err(AuthError::Expired { method, expires_at });
    }
    Ok(())
}

fn duration_until(expires_at: DateTime<Utc>) -> Option<Duration> {
    expires_at.signed_duration_since(Utc::now()).to_std().ok()
}

fn chrono_duration(duration: Duration) -> TimeDelta {
    TimeDelta::from_std(duration).unwrap_or(TimeDelta::MAX)
}

fn split_scopes(scope: &str) -> Vec<&str> {
    scope.split_whitespace().collect()
}

fn oauth_error(operation: &'static str, error: &fcp_oauth::OAuthError) -> AuthError {
    AuthError::OAuthFlow {
        operation,
        reason: error.to_string(),
    }
}

fn oauth_flow_status_error(operation: &'static str, status: u16) -> AuthError {
    AuthError::OAuthFlow {
        operation,
        reason: format!("provider endpoint returned unsuccessful status {status}"),
    }
}

fn invalid_oauth_response(operation: &'static str, error: &serde_json::Error) -> AuthError {
    AuthError::OAuthFlow {
        operation,
        reason: format!("invalid provider JSON response: {error}"),
    }
}

fn oauth2_client_from_auth_code_config(config: &OAuthAuthCodeConfig) -> AuthResult<OAuth2Client> {
    let mut oauth_config = config
        .client_secret
        .as_ref()
        .map_or_else(
            || {
                OAuth2Config::public_client(
                    config.client_id.clone(),
                    config.authorize_url.clone(),
                    config.token_url.clone(),
                )
            },
            |secret| {
                OAuth2Config::new(
                    config.client_id.clone(),
                    secret.expose_material().to_owned(),
                    config.authorize_url.clone(),
                    config.token_url.clone(),
                )
            },
        )
        .with_redirect_uri(config.redirect_uri.clone())
        .with_scopes(
            split_scopes(&config.scope)
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
        .with_pkce(config.use_pkce)
        .with_pkce_method(PkceMethod::S256)
        .with_timeout(config.timeout);

    if config.client_secret.is_some() {
        oauth_config = oauth_config.with_auth_style(fcp_oauth::AuthStyle::Post);
    }

    OAuth2Client::new(oauth_config).map_err(|error| oauth_error("oauth2_client", &error))
}

async fn send_oauth_form(
    cx: &fcp_async_core::Cx,
    http_client: &HttpClient,
    url: &str,
    pairs: &[(&str, &str)],
    timeout: Duration,
    operation: &'static str,
) -> AuthResult<fcp_async_core::http::HttpResponse> {
    let body = encode_form_pairs(pairs);
    let headers = vec![
        ("Content-Type".to_owned(), FORM_CONTENT_TYPE.to_owned()),
        ("Accept".to_owned(), JSON_CONTENT_TYPE.to_owned()),
    ];
    match time::timeout(
        timeout,
        http_client.request(cx, Method::Post, url, headers, body),
    )
    .await
    {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) => Err(AuthError::OAuthFlow {
            operation,
            reason: error.to_string(),
        }),
        Err(error) => Err(AuthError::OAuthFlow {
            operation,
            reason: format!("request failed: {error}"),
        }),
    }
}

fn encode_form_pairs(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        if !value.is_empty() {
            serializer.append_pair(key, value);
        }
    }
    serializer.finish().into_bytes()
}

#[derive(Debug, Deserialize)]
struct DeviceCodeStartResponse {
    device_code: String,
    user_code: String,
    #[serde(alias = "verification_url")]
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

impl DeviceCodeStartResponse {
    fn into_challenge(
        self,
        started_at: DateTime<Utc>,
        default_interval: Duration,
    ) -> AuthResult<DeviceCodeChallenge> {
        validate_non_empty("device_code", &self.device_code)?;
        validate_non_empty("user_code", &self.user_code)?;
        validate_auth_endpoint_url("verification_uri", &self.verification_uri)?;
        if self.expires_in == 0 {
            return Err(AuthError::invalid_config(
                "expires_in",
                "device-code challenge must have a positive expiration",
            ));
        }
        let interval = self
            .interval
            .filter(|interval| *interval > 0)
            .map_or(default_interval, Duration::from_secs);
        Ok(DeviceCodeChallenge {
            device_code: SecretString::new(self.device_code),
            user_code: self.user_code,
            verification_uri: self.verification_uri,
            verification_uri_complete: self.verification_uri_complete,
            expires_at: started_at + chrono_duration(Duration::from_secs(self.expires_in)),
            interval,
        })
    }
}

#[derive(Debug, Deserialize)]
struct DeviceCodePollResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

impl DeviceCodePollResponse {
    fn into_token_set(self) -> AuthResult<OAuthTokenSet> {
        let response = TokenResponse {
            access_token: self.access_token.ok_or_else(|| AuthError::OAuthFlow {
                operation: "device_code_poll",
                reason: "provider response omitted access_token".to_owned(),
            })?,
            token_type: self.token_type.ok_or_else(|| AuthError::OAuthFlow {
                operation: "device_code_poll",
                reason: "provider response omitted token_type".to_owned(),
            })?,
            expires_in: self.expires_in,
            refresh_token: self.refresh_token,
            scope: self.scope,
            id_token: None,
        };
        let tokens = FcpOAuthTokens::from_response(response)
            .map_err(|error| oauth_error("device_code_poll", &error))?;
        OAuthTokenSet::from_fcp_oauth(&tokens)
    }
}

fn insert_bearer_material(
    method: &'static str,
    material: Option<&SecretString>,
    request: &mut AuthRequest,
) -> AuthResult<()> {
    let material = material.ok_or(AuthError::MissingMaterial { method })?;
    if material.is_empty() {
        return Err(AuthError::MissingMaterial { method });
    }
    request.insert_material_header(
        DEFAULT_AUTHORIZATION_HEADER,
        SecretString::new(format!(
            "{DEFAULT_BEARER_PREFIX}{}",
            material.expose_material()
        )),
    )
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;

    use super::*;

    #[derive(Clone, Debug)]
    struct ParsedHttpRequest {
        path: String,
        body: String,
    }

    fn cx() -> fcp_async_core::Cx {
        fcp_async_core::Cx::for_testing()
    }

    fn block_on<T>(future: impl Future<Output = AuthResult<T>>) -> AuthResult<T> {
        fcp_async_core::runtime::block_on_sync(future).unwrap()
    }

    fn future_time() -> DateTime<Utc> {
        Utc::now() + TimeDelta::seconds(60)
    }

    fn past_time() -> DateTime<Utc> {
        Utc::now() - TimeDelta::seconds(60)
    }

    fn read_http_request(stream: &mut TcpStream) -> ParsedHttpRequest {
        let mut raw = Vec::new();
        let mut buf = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut buf).expect("read HTTP request");
            assert!(read > 0, "client closed before request headers");
            raw.extend_from_slice(&buf[..read]);
            if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };

        let headers_text = String::from_utf8_lossy(&raw[..header_end]);
        let mut lines = headers_text.lines();
        let request_line = lines.next().expect("request line");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .expect("request path")
            .to_owned();
        let content_length = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);

        let mut body = raw[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut buf).expect("read HTTP body");
            assert!(read > 0, "client closed before request body");
            body.extend_from_slice(&buf[..read]);
        }
        body.truncate(content_length);

        ParsedHttpRequest {
            path,
            body: String::from_utf8(body).expect("form body utf8"),
        }
    }

    fn write_json(stream: &mut TcpStream, status: u16, body: &str) {
        let reason = if status == 200 { "OK" } else { "Bad Request" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write HTTP response");
        stream.flush().expect("flush HTTP response");
    }

    fn spawn_json_sequence_server(
        responses: Vec<(u16, String)>,
    ) -> (
        SocketAddr,
        Arc<Mutex<Vec<ParsedHttpRequest>>>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test HTTP server");
        let address = listener.local_addr().expect("test HTTP server address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().expect("accept test HTTP request");
                let request = read_http_request(&mut stream);
                requests_for_thread
                    .lock()
                    .expect("requests lock")
                    .push(request);
                write_json(&mut stream, status, &body);
            }
        });
        (address, requests, handle)
    }

    #[test]
    fn secret_string_and_auth_request_debug_redact_raw_values() {
        let mut request = AuthRequest::new();
        request
            .insert_material_header("Authorization", SecretString::new("Bearer alpha-material"))
            .unwrap();

        let material_debug = format!("{:?}", SecretString::new("alpha-material"));
        let request_debug = format!("{request:?}");

        assert_eq!(material_debug, REDACTED);
        assert!(!request_debug.contains("alpha-material"));
        assert!(!request_debug.contains("Bearer alpha-material"));
        assert!(request_debug.contains(REDACTED));
    }

    #[test]
    fn api_key_auth_sets_default_authorization_header() {
        let cx = cx();
        let auth = ApiKeyAuth::new("provider-material");
        let mut request = AuthRequest::new();

        block_on(auth.build_request_auth(&cx, &mut request)).unwrap();

        assert_eq!(request.header_count(), 1);
        assert_eq!(
            request
                .header_value(DEFAULT_AUTHORIZATION_HEADER)
                .unwrap()
                .expose_material(),
            "Bearer provider-material"
        );
    }

    #[test]
    fn api_key_auth_rejects_empty_key_and_invalid_header() {
        let cx = cx();
        let empty = ApiKeyAuth::new("");
        let invalid_header = ApiKeyAuth::new("material").with_header_name("Bad Header");

        assert!(matches!(
            block_on(empty.validate(&cx)),
            Err(AuthError::MissingMaterial { method: "api_key" })
        ));
        assert!(matches!(
            block_on(invalid_header.validate(&cx)),
            Err(AuthError::InvalidConfig {
                field: "header_name",
                ..
            })
        ));
    }

    #[test]
    fn setup_token_respects_expiration() {
        let cx = cx();
        let live = SetupTokenAuth::new("setup-material", future_time());
        let expired = SetupTokenAuth::new("setup-material", past_time());
        let mut request = AuthRequest::new();

        block_on(live.build_request_auth(&cx, &mut request)).unwrap();
        assert_eq!(
            request
                .header_value(DEFAULT_AUTHORIZATION_HEADER)
                .unwrap()
                .expose_material(),
            "Setup setup-material"
        );
        assert!(matches!(
            block_on(expired.validate(&cx)),
            Err(AuthError::Expired {
                method: "setup_token",
                ..
            })
        ));
    }

    #[test]
    fn oauth_profiles_can_apply_existing_access_tokens() {
        let cx = cx();
        let device = OAuthDeviceCodeAuth {
            client_id: "client".to_owned(),
            device_code_url: "https://auth.example.com/device".to_owned(),
            token_url: "https://auth.example.com/token".to_owned(),
            scope: "read write".to_owned(),
            access_token: Some(SecretString::new("oauth-material")),
            refresh_token: Some(SecretString::new("refresh-material")),
            expires_at: Some(future_time()),
        };
        let mut request = AuthRequest::new();

        block_on(device.build_request_auth(&cx, &mut request)).unwrap();

        assert_eq!(
            request
                .header_value(DEFAULT_AUTHORIZATION_HEADER)
                .unwrap()
                .expose_material(),
            "Bearer oauth-material"
        );
    }

    #[test]
    fn auth_code_profile_rejects_insecure_non_loopback_urls() {
        let cx = cx();
        let method = OAuthAuthCodeAuth {
            client_id: "client".to_owned(),
            client_secret: None,
            authorize_url: "http://auth.example.com/authorize".to_owned(),
            token_url: "https://auth.example.com/token".to_owned(),
            redirect_uri: "http://localhost:8090/callback".to_owned(),
            scope: "read".to_owned(),
            use_pkce: true,
            access_token: Some(SecretString::new("access")),
            refresh_token: None,
            expires_at: Some(future_time()),
        };

        assert!(matches!(
            block_on(method.validate(&cx)),
            Err(AuthError::InvalidConfig {
                field: "authorize_url",
                ..
            })
        ));
    }

    #[test]
    fn auth_code_flow_builds_pkce_url_and_exchanges_tokens() {
        let cx = cx();
        let (address, requests, server) = spawn_json_sequence_server(vec![(
            200,
            r#"{"access_token":"access-token","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-token","scope":"read write"}"#
                .to_owned(),
        )]);
        let config = OAuthAuthCodeConfig {
            client_id: "client".to_owned(),
            client_secret: None,
            authorize_url: format!("http://{address}/authorize"),
            token_url: format!("http://{address}/token"),
            redirect_uri: "http://127.0.0.1/callback".to_owned(),
            scope: "read write".to_owned(),
            use_pkce: true,
            timeout: Duration::from_secs(5),
        };

        let challenge = OAuthAuthCodeFlow::build_authorize_url(&config).unwrap();
        assert_eq!(challenge.authorize_url.path(), "/authorize");
        assert!(
            challenge
                .authorize_url
                .query()
                .expect("authorization query")
                .contains("code_challenge=")
        );
        let debug = format!("{challenge:?}");
        assert!(!debug.contains(challenge.state.expose_material()));
        assert!(debug.contains(REDACTED));

        let tokens = block_on(OAuthAuthCodeFlow::exchange_code(
            &cx,
            &config,
            "auth-code",
            challenge.pkce.as_ref(),
        ))
        .unwrap();

        assert_eq!(tokens.access_token().expose_material(), "access-token");
        assert_eq!(
            tokens.refresh_token().unwrap().expose_material(),
            "refresh-token"
        );
        assert_eq!(tokens.scopes(), &["read".to_owned(), "write".to_owned()]);
        server.join().expect("token server");
        let requests = requests.lock().expect("requests lock").clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/token");
        assert!(requests[0].body.contains("grant_type=authorization_code"));
        assert!(requests[0].body.contains("code=auth-code"));
        assert!(requests[0].body.contains("code_verifier="));
    }

    #[test]
    fn device_code_flow_handles_pending_and_success() {
        let cx = cx();
        let (address, requests, server) = spawn_json_sequence_server(vec![
            (
                200,
                r#"{"device_code":"device-secret","user_code":"ABCD-EFGH","verification_uri":"http://127.0.0.1/verify","expires_in":600,"interval":2}"#
                    .to_owned(),
            ),
            (400, r#"{"error":"authorization_pending"}"#.to_owned()),
            (
                200,
                r#"{"access_token":"device-access","token_type":"Bearer","expires_in":3600,"refresh_token":"device-refresh","scope":"bot send"}"#
                    .to_owned(),
            ),
        ]);
        let config = OAuthDeviceCodeConfig {
            client_id: "client".to_owned(),
            device_code_url: format!("http://{address}/device"),
            token_url: format!("http://{address}/token"),
            scope: "bot send".to_owned(),
            timeout: Duration::from_secs(5),
            poll_interval: Duration::from_secs(5),
        };

        let mut flow = block_on(OAuthDeviceCodeFlow::start(&cx, config)).unwrap();
        assert_eq!(flow.challenge().user_code, "ABCD-EFGH");
        assert_eq!(flow.challenge().interval, Duration::from_secs(2));
        assert!(matches!(
            block_on(flow.poll(&cx)),
            Err(AuthError::AuthorizationPending {
                retry_after
            }) if retry_after == Duration::from_secs(2)
        ));
        let tokens = block_on(flow.poll(&cx)).unwrap();

        assert_eq!(tokens.access_token().expose_material(), "device-access");
        assert_eq!(
            tokens.refresh_token().unwrap().expose_material(),
            "device-refresh"
        );
        server.join().expect("device-code server");
        let requests = requests.lock().expect("requests lock").clone();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/device", "/token", "/token"]
        );
        assert!(requests[0].body.contains("client_id=client"));
        assert!(requests[1].body.contains("device_code=device-secret"));
        assert!(requests[2].body.contains("device_code=device-secret"));
    }

    #[test]
    fn jwt_auth_generates_once_and_reuses_cache_until_refresh() {
        let cx = cx();
        let calls = Arc::new(Mutex::new(0_u32));
        let calls_for_generator = Arc::clone(&calls);
        let auth = JwtAuth::new(
            move || {
                let next_call = {
                    let mut calls = calls_for_generator.lock().unwrap();
                    *calls += 1;
                    *calls
                };
                Ok(SecretString::new(format!("jwt-material-{next_call}")))
            },
            Duration::from_secs(60),
        );
        let mut first = AuthRequest::new();
        let mut second = AuthRequest::new();
        let mut refreshed = AuthRequest::new();

        block_on(auth.build_request_auth(&cx, &mut first)).unwrap();
        block_on(auth.build_request_auth(&cx, &mut second)).unwrap();
        block_on(auth.refresh(&cx)).unwrap();
        block_on(auth.build_request_auth(&cx, &mut refreshed)).unwrap();

        assert_eq!(
            first
                .header_value(DEFAULT_AUTHORIZATION_HEADER)
                .unwrap()
                .expose_material(),
            "Bearer jwt-material-1"
        );
        assert_eq!(
            second
                .header_value(DEFAULT_AUTHORIZATION_HEADER)
                .unwrap()
                .expose_material(),
            "Bearer jwt-material-1"
        );
        assert_eq!(
            refreshed
                .header_value(DEFAULT_AUTHORIZATION_HEADER)
                .unwrap()
                .expose_material(),
            "Bearer jwt-material-2"
        );
        assert_eq!(*calls.lock().unwrap(), 2);
    }

    #[test]
    fn sigv4_validates_material_without_faking_a_signature() {
        let cx = cx();
        let sigv4 = SigV4Auth {
            access_key: SecretString::new("akid"),
            secret_key: SecretString::new("aws-private-material"),
            session_token: Some(SecretString::new("session-material")),
            region: "us-east-1".to_owned(),
            service: "bedrock".to_owned(),
        };
        let mut request = AuthRequest::new();

        assert!(matches!(
            block_on(sigv4.build_request_auth(&cx, &mut request)),
            Err(AuthError::UnsupportedMethod {
                method: "sigv4",
                operation: "canonical request signing",
            })
        ));
        assert_eq!(request.header_count(), 0);
        let debug = format!("{sigv4:?}");
        assert!(!debug.contains("aws-private-material"));
        assert!(!debug.contains("session-material"));
    }

    #[test]
    fn profile_store_sorts_by_priority_then_profile_id() {
        let store = InMemoryAuthProfileStore::new();
        let low = AuthProfile::new(
            "work",
            "anthropic",
            AuthMethodKind::ApiKey(ApiKeyAuth::new("work-key")),
            "work",
            10,
        );
        let preferred = AuthProfile::new(
            "personal",
            "anthropic",
            AuthMethodKind::SetupToken(SetupTokenAuth::new("setup", future_time())),
            "personal",
            1,
        );

        block_on(store.save_profile(low)).unwrap();
        block_on(store.save_profile(preferred)).unwrap();

        let listed = block_on(store.list_profiles("anthropic")).unwrap();
        let active = block_on(store.pick_active("anthropic")).unwrap();

        assert_eq!(
            listed
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>(),
            vec!["personal", "work"]
        );
        assert_eq!(active.id, "personal");
    }

    #[test]
    fn profile_store_get_delete_and_empty_pick_are_typed() {
        let store = InMemoryAuthProfileStore::new();
        let profile = AuthProfile::new(
            "profile",
            "openai",
            AuthMethodKind::ApiKey(ApiKeyAuth::new("openai-material")),
            "default",
            0,
        );

        block_on(store.save_profile(profile)).unwrap();
        assert_eq!(
            block_on(store.get_profile("openai", "profile")).unwrap().id,
            "profile"
        );
        block_on(store.delete_profile("openai", "profile")).unwrap();

        assert!(matches!(
            block_on(store.get_profile("openai", "profile")),
            Err(AuthError::ProfileNotFound {
                provider,
                profile_id
            }) if provider == "openai" && profile_id == "profile"
        ));
        assert!(matches!(
            block_on(store.pick_active("openai")),
            Err(AuthError::NoProfiles { provider }) if provider == "openai"
        ));
    }

    #[test]
    fn auth_method_kind_delegates_all_variants() {
        let cx = cx();
        let methods = vec![
            AuthMethodKind::ApiKey(ApiKeyAuth::new("api-key")),
            AuthMethodKind::OAuthDeviceCode(OAuthDeviceCodeAuth {
                client_id: "client".to_owned(),
                device_code_url: "https://auth.example.com/device".to_owned(),
                token_url: "https://auth.example.com/token".to_owned(),
                scope: "read".to_owned(),
                access_token: Some(SecretString::new("device-material")),
                refresh_token: None,
                expires_at: Some(future_time()),
            }),
            AuthMethodKind::OAuthAuthCode(OAuthAuthCodeAuth {
                client_id: "client".to_owned(),
                client_secret: None,
                authorize_url: "https://auth.example.com/authorize".to_owned(),
                token_url: "https://auth.example.com/token".to_owned(),
                redirect_uri: "http://127.0.0.1:8080/callback".to_owned(),
                scope: "read".to_owned(),
                use_pkce: true,
                access_token: Some(SecretString::new("auth-code-material")),
                refresh_token: None,
                expires_at: Some(future_time()),
            }),
            AuthMethodKind::SetupToken(SetupTokenAuth::new("setup", future_time())),
            AuthMethodKind::Jwt(JwtAuth::new(
                || Ok(SecretString::new("jwt-material")),
                Duration::from_secs(60),
            )),
            AuthMethodKind::SigV4(SigV4Auth {
                access_key: SecretString::new("akid"),
                secret_key: SecretString::new("sigv4-material"),
                session_token: None,
                region: "us-west-2".to_owned(),
                service: "execute-api".to_owned(),
            }),
        ];

        for method in methods {
            block_on(method.validate(&cx)).unwrap();
            assert!(!method.id().is_empty());
        }
    }
}
