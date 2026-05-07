//! Provider authentication profiles and method selection for FCP connectors.
//!
//! This crate owns the provider/profile layer above raw credential leasing and
//! OAuth primitives. Host admin routes, CLI helpers, provider-specific imports,
//! and credential-pool integration are intentionally kept outside this crate's
//! core primitives.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// AWS `SigV4` algorithm label.
pub const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// `SigV4` payload sentinel for services that permit unsigned payloads.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// SHA-256 hash of an empty payload.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Result type for provider-auth operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// Provider-auth errors. All variants are safe to render in logs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    /// Caller supplied an invalid static configuration value.
    #[error("invalid auth configuration for {field}: {reason}")]
    InvalidConfig {
        /// Field name.
        field: &'static str,
        /// Redaction-safe validation reason.
        reason: String,
    },

    /// A request header name or value contained invalid bytes.
    #[error("invalid auth header {field}: {reason}")]
    InvalidHeader {
        /// Header field being validated.
        field: &'static str,
        /// Redaction-safe validation reason.
        reason: String,
    },

    /// The auth method cannot build request auth without token material.
    #[error("auth method {method} has no usable token material")]
    MissingToken {
        /// Auth method id.
        method: &'static str,
    },

    /// The auth method needs request-signing fields that were not supplied.
    #[error("auth method {method} needs request signing context")]
    MissingSigningContext {
        /// Auth method id.
        method: &'static str,
    },

    /// The auth method's token material has expired.
    #[error("auth method {method} token expired at {expires_at}")]
    Expired {
        /// Auth method id.
        method: &'static str,
        /// Expiration timestamp.
        expires_at: DateTime<Utc>,
    },

    /// The requested provider profile does not exist.
    #[error("auth profile {profile_id} for provider {provider} not found")]
    ProfileNotFound {
        /// Canonical provider id.
        provider: String,
        /// Profile id.
        profile_id: String,
    },

    /// No profiles exist for the requested provider.
    #[error("provider {provider} has no auth profiles")]
    ProviderNotFound {
        /// Canonical provider id.
        provider: String,
    },

    /// Method surface is declared but intentionally deferred to a later slice.
    #[error("auth method {method} does not support {operation} in this slice")]
    UnsupportedMethod {
        /// Auth method id.
        method: &'static str,
        /// Operation name.
        operation: &'static str,
    },

    /// Provider returned a terminal OAuth error.
    #[error("auth method {method} rejected by provider with {code}: {reason}")]
    ProviderRejected {
        /// Auth method id.
        method: &'static str,
        /// Provider error code.
        code: String,
        /// Redaction-safe provider reason.
        reason: String,
    },

    /// Provider response was missing a field required by the OAuth state machine.
    #[error("auth method {method} got invalid provider response: {reason}")]
    InvalidProviderResponse {
        /// Auth method id.
        method: &'static str,
        /// Redaction-safe response validation reason.
        reason: String,
    },
}

fn invalid_config(field: &'static str, reason: impl Into<String>) -> AuthError {
    AuthError::InvalidConfig {
        field,
        reason: reason.into(),
    }
}

fn validate_non_empty(value: &str, field: &'static str) -> AuthResult<()> {
    if value.trim().is_empty() {
        return Err(invalid_config(field, "must not be empty"));
    }
    Ok(())
}

fn canonical_provider(provider: &str) -> AuthResult<String> {
    validate_non_empty(provider, "provider")?;
    Ok(provider.trim().to_ascii_lowercase())
}

fn validate_header_name(name: &str) -> AuthResult<()> {
    validate_non_empty(name, "header_name")?;
    if name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(AuthError::InvalidHeader {
            field: "header_name",
            reason: "only ASCII alphanumeric characters and '-' are allowed".to_string(),
        })
    }
}

fn validate_header_value(value: &str) -> AuthResult<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(AuthError::InvalidHeader {
            field: "header_value",
            reason: "CR/LF bytes are not allowed".to_string(),
        });
    }
    validate_non_empty(value, "header_value")
}

fn validate_no_crlf(value: &str, field: &'static str) -> AuthResult<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(AuthError::InvalidConfig {
            field,
            reason: "CR/LF bytes are not allowed".to_string(),
        });
    }
    Ok(())
}

fn validate_payload_hash(value: &str) -> AuthResult<()> {
    if value == UNSIGNED_PAYLOAD {
        return Ok(());
    }
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(invalid_config(
            "payload_hash",
            "must be a SHA-256 hex digest or UNSIGNED-PAYLOAD",
        ))
    }
}

fn validate_oauth_endpoint(value: &str, field: &'static str) -> AuthResult<()> {
    validate_non_empty(value, field)?;
    validate_no_crlf(value, field)
}

fn parse_oauth_url(value: &str, field: &'static str) -> AuthResult<Url> {
    validate_oauth_endpoint(value, field)?;
    let parsed = Url::parse(value).map_err(|error| invalid_config(field, error.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        _ => Err(invalid_config(field, "must use http or https scheme")),
    }
}

fn validate_oauth_error(code: &str, reason: &str) -> AuthResult<()> {
    validate_non_empty(code, "oauth_error_code")?;
    validate_no_crlf(code, "oauth_error_code")?;
    validate_non_empty(reason, "oauth_error_reason")?;
    validate_no_crlf(reason, "oauth_error_reason")
}

fn validate_oauth_state(state: &str) -> AuthResult<()> {
    validate_non_empty(state, "state")?;
    validate_no_crlf(state, "state")
}

fn validate_pkce_verifier(verifier: &str) -> AuthResult<()> {
    if !(43..=128).contains(&verifier.len()) {
        return Err(invalid_config("pkce_verifier", "must be 43-128 characters"));
    }
    if verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        Ok(())
    } else {
        Err(invalid_config(
            "pkce_verifier",
            "must contain only RFC 7636 unreserved characters",
        ))
    }
}

fn pkce_s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn generate_url_safe_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn build_authorization_request(
    config: &OAuthAuthCodeConfig,
    state: RedactedSecret,
    pkce: Option<OAuthPkce>,
) -> AuthResult<OAuthAuthCodeRequest> {
    let mut url = parse_oauth_url(&config.authorize_url, "authorize_url")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &config.client_id);
        query.append_pair("redirect_uri", &config.redirect_uri);
        if !config.scope.trim().is_empty() {
            query.append_pair("scope", &config.scope);
        }
        query.append_pair("state", state.expose_secret());
        if let Some(pkce) = pkce.as_ref() {
            query.append_pair("code_challenge", &pkce.challenge);
            query.append_pair("code_challenge_method", &pkce.method.to_string());
        }
    }
    Ok(OAuthAuthCodeRequest {
        authorization_url: url.to_string(),
        state,
        pkce,
    })
}

fn std_duration_until(expires_at: DateTime<Utc>) -> StdDuration {
    let remaining = expires_at.signed_duration_since(Utc::now());
    remaining.to_std().unwrap_or(StdDuration::ZERO)
}

fn chrono_duration(duration: StdDuration) -> AuthResult<TimeDelta> {
    TimeDelta::from_std(duration)
        .map_err(|_| invalid_config("ttl", "duration is outside chrono range"))
}

/// Secret string wrapper that redacts every formatting path and zeroizes on drop.
#[derive(Eq)]
pub struct RedactedSecret(Zeroizing<String>);

impl RedactedSecret {
    /// Construct a non-empty secret wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the secret is empty.
    pub fn new(material: impl Into<String>) -> AuthResult<Self> {
        let material = material.into();
        validate_non_empty(&material, "credential_material")?;
        Ok(Self(Zeroizing::new(material)))
    }

    /// Borrow the raw secret for the narrow boundary that applies auth.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Return a redaction-safe stable hint for diagnostics.
    #[must_use]
    pub fn redacted_token_first8(&self) -> String {
        let prefix: String = self.expose_secret().chars().take(8).collect();
        if prefix.is_empty() {
            "[REDACTED]".to_string()
        } else {
            format!("{prefix}...")
        }
    }
}

impl Clone for RedactedSecret {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.expose_secret().to_string()))
    }
}

impl PartialEq for RedactedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedactedSecret([REDACTED])")
    }
}

impl fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Signable request context for AWS `SigV4` auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4SigningContext {
    /// HTTP method such as `GET` or `POST`.
    pub method: String,
    /// Absolute path component. Empty paths are canonicalized to `/`.
    pub uri_path: String,
    /// Query parameters before `SigV4` URI encoding.
    pub query_params: BTreeMap<String, String>,
    /// SHA-256 payload hash or [`UNSIGNED_PAYLOAD`].
    pub payload_hash: String,
    /// Optional fixed timestamp for deterministic tests.
    pub signing_time: Option<DateTime<Utc>>,
}

impl SigV4SigningContext {
    /// Construct a `SigV4` signing context without query parameters.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] for invalid method, path, or payload hash.
    pub fn new(
        method: impl Into<String>,
        uri_path: impl Into<String>,
        payload_hash: impl Into<String>,
    ) -> AuthResult<Self> {
        let method = method.into().trim().to_ascii_uppercase();
        let mut uri_path = uri_path.into();
        let payload_hash = payload_hash.into();
        validate_non_empty(&method, "method")?;
        validate_no_crlf(&method, "method")?;
        validate_no_crlf(&uri_path, "uri_path")?;
        validate_payload_hash(&payload_hash)?;
        if uri_path.is_empty() {
            uri_path.push('/');
        }
        let payload_hash = if payload_hash == UNSIGNED_PAYLOAD {
            payload_hash
        } else {
            payload_hash.to_ascii_lowercase()
        };
        Ok(Self {
            method,
            uri_path,
            query_params: BTreeMap::new(),
            payload_hash,
            signing_time: None,
        })
    }

    /// Add a query parameter to this signing context.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] if the key is empty or either field contains CR/LF.
    pub fn with_query_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> AuthResult<Self> {
        let key = key.into();
        let value = value.into();
        validate_non_empty(&key, "query_param")?;
        validate_no_crlf(&key, "query_param")?;
        validate_no_crlf(&value, "query_value")?;
        self.query_params.insert(key, value);
        Ok(self)
    }

    /// Use a deterministic signing timestamp.
    #[must_use]
    pub const fn with_signing_time(mut self, signing_time: DateTime<Utc>) -> Self {
        self.signing_time = Some(signing_time);
        self
    }
}

/// Minimal request-auth target used by connector clients and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRequest {
    headers: BTreeMap<String, String>,
    sigv4_context: Option<SigV4SigningContext>,
}

impl AuthRequest {
    /// Construct an empty request-auth target.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            headers: BTreeMap::new(),
            sigv4_context: None,
        }
    }

    /// Set a validated header.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidHeader`] when the header name or value is
    /// empty or contains bytes unsafe for outbound HTTP headers.
    pub fn set_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> AuthResult<()> {
        let name = name.into();
        let value = value.into();
        validate_header_name(&name)?;
        validate_header_value(&value)?;
        self.headers.insert(name, value);
        Ok(())
    }

    /// Read a header value by exact name.
    #[must_use]
    pub fn value_for(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Borrow all request auth headers.
    #[must_use]
    pub const fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }

    /// Attach `SigV4` signing context for methods that need full request details.
    pub fn set_sigv4_context(&mut self, context: SigV4SigningContext) {
        self.sigv4_context = Some(context);
    }

    /// Borrow `SigV4` signing context, if present.
    #[must_use]
    pub const fn sigv4_context(&self) -> Option<&SigV4SigningContext> {
        self.sigv4_context.as_ref()
    }
}

/// Shared behavior for provider auth methods.
#[async_trait]
pub trait AuthMethod: Send + Sync {
    /// Stable method id, for example `api_key` or `oauth_device`.
    fn id(&self) -> &'static str;

    /// Validate method configuration and current token state.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the method cannot be used safely.
    async fn validate(&self, cx: &fcp_async_core::Cx) -> AuthResult<()>;

    /// Apply auth material to a request.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the method is missing token material,
    /// expired, unsupported in this slice, or would produce an unsafe header.
    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()>;

    /// Return time until refresh is needed, if this method is TTL-bounded.
    fn requires_refresh_in(&self) -> Option<StdDuration>;

    /// Refresh token material.
    ///
    /// # Errors
    ///
    /// The default implementation returns [`AuthError::UnsupportedMethod`].
    async fn refresh(&mut self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "refresh",
        })
    }
}

/// Static API-key authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKeyAuth {
    /// Secret API key.
    pub key: RedactedSecret,
    /// Header that receives the credential.
    pub header_name: String,
    /// Optional value prefix such as `Bearer`.
    pub value_prefix: Option<String>,
}

impl ApiKeyAuth {
    /// Construct bearer-token API-key auth using the `Authorization` header.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the key is empty.
    pub fn bearer(key: impl Into<String>) -> AuthResult<Self> {
        Self::new(key, "Authorization", Some("Bearer"))
    }

    /// Construct API-key auth with a custom header and optional value prefix.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the key, header name, or prefix is invalid.
    pub fn new(
        key: impl Into<String>,
        header_name: impl Into<String>,
        value_prefix: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        let header_name = header_name.into();
        validate_header_name(&header_name)?;
        let value_prefix = value_prefix.map(Into::into);
        if let Some(prefix) = value_prefix.as_deref() {
            validate_non_empty(prefix, "value_prefix")?;
            validate_header_value(prefix)?;
        }
        Ok(Self {
            key: RedactedSecret::new(key)?,
            header_name,
            value_prefix,
        })
    }

    fn header_value(&self) -> String {
        self.value_prefix.as_deref().map_or_else(
            || self.key.expose_secret().to_string(),
            |prefix| format!("{prefix} {}", self.key.expose_secret()),
        )
    }
}

impl fmt::Debug for ApiKeyAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyAuth")
            .field("key", &self.key)
            .field("header_name", &self.header_name)
            .field("value_prefix", &self.value_prefix)
            .finish()
    }
}

#[async_trait]
impl AuthMethod for ApiKeyAuth {
    fn id(&self) -> &'static str {
        "api_key"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_header_name(&self.header_name)?;
        validate_header_value(&self.header_value())
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        request.set_header(self.header_name.clone(), self.header_value())
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        None
    }
}

/// OAuth device-code auth state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeAuth {
    /// OAuth client id.
    pub client_id: String,
    /// Device-code endpoint URL.
    pub device_code_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Requested scope string.
    pub scope: String,
    /// Current access token, if the flow has completed.
    pub access_token: Option<RedactedSecret>,
    /// Current refresh token, if the provider issued one.
    pub refresh_token: Option<RedactedSecret>,
    /// Access-token expiration time.
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthDeviceCodeAuth {
    /// Construct OAuth device-code auth state without token material.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required OAuth fields are empty
    /// or contain bytes unsafe for logs/HTTP form fields.
    pub fn new(
        client_id: impl Into<String>,
        device_code_url: impl Into<String>,
        token_url: impl Into<String>,
        scope: impl Into<String>,
    ) -> AuthResult<Self> {
        let config = OAuthDeviceCodeConfig::new(client_id, device_code_url, token_url, scope)?;
        Ok(Self::from_config(config))
    }

    /// Construct auth state from a validated flow config.
    #[must_use]
    pub fn from_config(config: OAuthDeviceCodeConfig) -> Self {
        Self {
            client_id: config.client_id,
            device_code_url: config.device_code_url,
            token_url: config.token_url,
            scope: config.scope,
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }

    /// Replace cached token material after a completed device-code flow.
    pub fn apply_tokens(&mut self, tokens: OAuthTokens) {
        let OAuthTokens {
            access_token,
            refresh_token,
            expires_at,
            ..
        } = tokens;
        let access_slot = &mut self.access_token;
        *access_slot = Some(access_token);
        let refresh_slot = &mut self.refresh_token;
        *refresh_slot = refresh_token;
        self.expires_at = expires_at;
    }

    fn validate_config(&self) -> AuthResult<()> {
        validate_non_empty(&self.client_id, "client_id")?;
        validate_no_crlf(&self.client_id, "client_id")?;
        validate_oauth_endpoint(&self.device_code_url, "device_code_url")?;
        validate_oauth_endpoint(&self.token_url, "token_url")?;
        validate_no_crlf(&self.scope, "scope")
    }
}

#[async_trait]
impl AuthMethod for OAuthDeviceCodeAuth {
    fn id(&self) -> &'static str {
        "oauth_device"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.validate_config()
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        apply_bearer_token(
            self.id(),
            self.access_token.as_ref(),
            self.expires_at,
            request,
        )
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        self.expires_at.map(std_duration_until)
    }
}

/// OAuth device-code flow configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeConfig {
    /// OAuth client id.
    pub client_id: String,
    /// Device-code endpoint URL.
    pub device_code_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Requested scope string. Empty scope is allowed for providers that infer defaults.
    pub scope: String,
    /// Initial provider polling interval.
    pub default_poll_interval: StdDuration,
}

impl OAuthDeviceCodeConfig {
    /// Construct device-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn new(
        client_id: impl Into<String>,
        device_code_url: impl Into<String>,
        token_url: impl Into<String>,
        scope: impl Into<String>,
    ) -> AuthResult<Self> {
        let client_id = client_id.into();
        let device_code_url = device_code_url.into();
        let token_url = token_url.into();
        let scope = scope.into();
        validate_non_empty(&client_id, "client_id")?;
        validate_no_crlf(&client_id, "client_id")?;
        validate_oauth_endpoint(&device_code_url, "device_code_url")?;
        validate_oauth_endpoint(&token_url, "token_url")?;
        validate_no_crlf(&scope, "scope")?;
        Ok(Self {
            client_id,
            device_code_url,
            token_url,
            scope,
            default_poll_interval: StdDuration::from_secs(5),
        })
    }

    /// Override the provider polling interval used before a challenge is issued.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the interval is zero.
    pub fn with_default_poll_interval(mut self, interval: StdDuration) -> AuthResult<Self> {
        if interval.is_zero() {
            return Err(invalid_config(
                "default_poll_interval",
                "must be greater than zero",
            ));
        }
        self.default_poll_interval = interval;
        Ok(self)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty(&self.client_id, "client_id")?;
        validate_no_crlf(&self.client_id, "client_id")?;
        validate_oauth_endpoint(&self.device_code_url, "device_code_url")?;
        validate_oauth_endpoint(&self.token_url, "token_url")?;
        validate_no_crlf(&self.scope, "scope")?;
        if self.default_poll_interval.is_zero() {
            return Err(invalid_config(
                "default_poll_interval",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Device-code challenge returned by an OAuth provider.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeChallenge {
    /// Provider device code. Treated as secret because it authorizes polling.
    pub device_code: RedactedSecret,
    /// User-facing short code to enter in a browser.
    pub user_code: String,
    /// Browser verification URL.
    pub verification_uri: String,
    /// Optional complete verification URL with the user code embedded.
    pub verification_uri_complete: Option<String>,
    /// Challenge expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Provider-requested polling interval.
    pub interval: StdDuration,
}

impl OAuthDeviceCodeChallenge {
    /// Construct a device-code challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn new(
        device_code: impl Into<String>,
        user_code: impl Into<String>,
        verification_uri: impl Into<String>,
        verification_uri_complete: Option<impl Into<String>>,
        expires_at: DateTime<Utc>,
        interval: StdDuration,
    ) -> AuthResult<Self> {
        let challenge = Self {
            device_code: RedactedSecret::new(device_code)?,
            user_code: user_code.into(),
            verification_uri: verification_uri.into(),
            verification_uri_complete: verification_uri_complete.map(Into::into),
            expires_at,
            interval,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_no_crlf(self.device_code.expose_secret(), "device_code")?;
        validate_non_empty(&self.user_code, "user_code")?;
        validate_no_crlf(&self.user_code, "user_code")?;
        validate_oauth_endpoint(&self.verification_uri, "verification_uri")?;
        if let Some(uri) = self.verification_uri_complete.as_deref() {
            validate_oauth_endpoint(uri, "verification_uri_complete")?;
        }
        if self.interval.is_zero() {
            return Err(invalid_config("interval", "must be greater than zero"));
        }
        Ok(())
    }
}

impl fmt::Debug for OAuthDeviceCodeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthDeviceCodeChallenge")
            .field("device_code", &self.device_code)
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_at", &self.expires_at)
            .field("interval", &self.interval)
            .finish()
    }
}

/// OAuth token set returned by a completed flow.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthTokens {
    /// Access token used for bearer request auth.
    pub access_token: RedactedSecret,
    /// Token type. This slice supports bearer tokens.
    pub token_type: String,
    /// Optional refresh token.
    pub refresh_token: Option<RedactedSecret>,
    /// Optional expiration timestamp.
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional granted scope.
    pub scope: Option<String>,
}

impl OAuthTokens {
    /// Construct a bearer token set.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when token fields are empty or unsafe.
    pub fn bearer(
        access_token: impl Into<String>,
        expires_in: Option<StdDuration>,
        refresh_token: Option<impl Into<String>>,
        scope: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        let scope = scope.map(Into::into);
        if let Some(scope) = scope.as_deref() {
            validate_no_crlf(scope, "scope")?;
        }
        Ok(Self {
            access_token: RedactedSecret::new(access_token)?,
            token_type: "Bearer".to_string(),
            refresh_token: refresh_token.map(RedactedSecret::new).transpose()?,
            expires_at: expires_in
                .map(chrono_duration)
                .transpose()?
                .map(|duration| Utc::now() + duration),
            scope,
        })
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty(&self.token_type, "token_type")?;
        validate_no_crlf(&self.token_type, "token_type")?;
        if !self.token_type.eq_ignore_ascii_case("bearer") {
            return Err(invalid_config(
                "token_type",
                "only bearer tokens are supported in this slice",
            ));
        }
        if let Some(scope) = self.scope.as_deref() {
            validate_no_crlf(scope, "scope")?;
        }
        Ok(())
    }
}

impl fmt::Debug for OAuthTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTokens")
            .field("access_token", &self.access_token)
            .field("token_type", &self.token_type)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Provider status returned when polling a device-code token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthDeviceCodeProviderResponse {
    /// User has not completed browser authorization yet.
    AuthorizationPending,
    /// Provider asked the client to increase the polling interval.
    SlowDown,
    /// User completed authorization and the provider returned tokens.
    Authorized(OAuthTokens),
    /// User denied authorization.
    AccessDenied {
        /// Redaction-safe denial reason.
        reason: String,
    },
    /// Device code expired before authorization completed.
    ExpiredToken {
        /// Redaction-safe expiry reason.
        reason: String,
    },
}

/// Public polling result returned by [`OAuthDeviceCodeFlow::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthDeviceCodePoll {
    /// Authorization is still pending. Caller should wait `retry_after`.
    Pending {
        /// Current retry interval.
        retry_after: StdDuration,
    },
    /// Authorization succeeded.
    Authorized(OAuthTokens),
}

/// Transport boundary for OAuth device-code providers.
#[async_trait]
pub trait OAuthDeviceCodeTransport: Send + Sync {
    /// Start a provider device-code flow.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures or invalid provider responses.
    async fn start(&self, config: &OAuthDeviceCodeConfig) -> AuthResult<OAuthDeviceCodeChallenge>;

    /// Poll a provider token endpoint.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures or invalid provider responses.
    async fn poll(
        &self,
        config: &OAuthDeviceCodeConfig,
        challenge: &OAuthDeviceCodeChallenge,
    ) -> AuthResult<OAuthDeviceCodeProviderResponse>;
}

/// OAuth device-code state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDeviceCodeFlow {
    config: OAuthDeviceCodeConfig,
    challenge: OAuthDeviceCodeChallenge,
    poll_interval: StdDuration,
}

impl OAuthDeviceCodeFlow {
    /// Start a device-code flow through the supplied transport.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config is invalid or the provider
    /// returns an invalid challenge.
    pub async fn start<T>(
        cx: &fcp_async_core::Cx,
        config: OAuthDeviceCodeConfig,
        transport: &T,
    ) -> AuthResult<Self>
    where
        T: OAuthDeviceCodeTransport + ?Sized,
    {
        let _ = cx;
        config.validate()?;
        let challenge = transport.start(&config).await?;
        challenge
            .validate()
            .map_err(|error| AuthError::InvalidProviderResponse {
                method: "oauth_device",
                reason: error.to_string(),
            })?;
        if Utc::now() >= challenge.expires_at {
            return Err(AuthError::Expired {
                method: "oauth_device",
                expires_at: challenge.expires_at,
            });
        }
        Ok(Self {
            poll_interval: challenge.interval,
            config,
            challenge,
        })
    }

    /// Borrow the user-facing challenge.
    #[must_use]
    pub const fn challenge(&self) -> &OAuthDeviceCodeChallenge {
        &self.challenge
    }

    /// Return the current polling interval.
    #[must_use]
    pub const fn poll_interval(&self) -> StdDuration {
        self.poll_interval
    }

    /// Poll for authorization completion.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for terminal provider failures, expired
    /// challenges, or malformed token responses.
    pub async fn poll<T>(
        &mut self,
        cx: &fcp_async_core::Cx,
        transport: &T,
    ) -> AuthResult<OAuthDeviceCodePoll>
    where
        T: OAuthDeviceCodeTransport + ?Sized,
    {
        let _ = cx;
        if Utc::now() >= self.challenge.expires_at {
            return Err(AuthError::Expired {
                method: "oauth_device",
                expires_at: self.challenge.expires_at,
            });
        }
        match transport.poll(&self.config, &self.challenge).await? {
            OAuthDeviceCodeProviderResponse::AuthorizationPending => {
                Ok(OAuthDeviceCodePoll::Pending {
                    retry_after: self.poll_interval,
                })
            }
            OAuthDeviceCodeProviderResponse::SlowDown => {
                self.poll_interval = self
                    .poll_interval
                    .checked_add(StdDuration::from_secs(5))
                    .unwrap_or(StdDuration::MAX);
                Ok(OAuthDeviceCodePoll::Pending {
                    retry_after: self.poll_interval,
                })
            }
            OAuthDeviceCodeProviderResponse::Authorized(tokens) => {
                tokens.validate()?;
                Ok(OAuthDeviceCodePoll::Authorized(tokens))
            }
            OAuthDeviceCodeProviderResponse::AccessDenied { reason } => {
                validate_oauth_error("access_denied", &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_device",
                    code: "access_denied".to_string(),
                    reason,
                })
            }
            OAuthDeviceCodeProviderResponse::ExpiredToken { reason } => {
                validate_oauth_error("expired_token", &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_device",
                    code: "expired_token".to_string(),
                    reason,
                })
            }
        }
    }
}

/// OAuth authorization-code auth state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeAuth {
    /// OAuth client id.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<RedactedSecret>,
    /// Authorization endpoint URL.
    pub authorize_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Registered redirect URI.
    pub redirect_uri: String,
    /// Requested scope string.
    pub scope: String,
    /// Whether PKCE must be used.
    pub use_pkce: bool,
    /// Current access token, if the flow has completed.
    pub access_token: Option<RedactedSecret>,
    /// Current refresh token, if the provider issued one.
    pub refresh_token: Option<RedactedSecret>,
    /// Access-token expiration time.
    pub expires_at: Option<DateTime<Utc>>,
}

impl OAuthAuthCodeAuth {
    /// Construct public-client OAuth authorization-code auth state.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when OAuth fields are empty or unsafe.
    pub fn public_client(
        client_id: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        let config = OAuthAuthCodeConfig::public_client(
            client_id,
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )?;
        Ok(Self::from_config(config))
    }

    /// Construct confidential-client OAuth authorization-code auth state.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when OAuth fields are empty or unsafe.
    pub fn confidential_client(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        let config = OAuthAuthCodeConfig::confidential_client(
            client_id,
            client_secret,
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )?;
        Ok(Self::from_config(config))
    }

    /// Construct auth state from a validated flow config.
    #[must_use]
    pub fn from_config(config: OAuthAuthCodeConfig) -> Self {
        Self {
            client_id: config.client_id,
            client_secret: config.client_secret,
            authorize_url: config.authorize_url,
            token_url: config.token_url,
            redirect_uri: config.redirect_uri,
            scope: config.scope,
            use_pkce: config.use_pkce,
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }

    /// Replace cached token material after a completed auth-code exchange.
    pub fn apply_tokens(&mut self, tokens: OAuthTokens) {
        let OAuthTokens {
            access_token,
            refresh_token,
            expires_at,
            ..
        } = tokens;
        let access_slot = &mut self.access_token;
        *access_slot = Some(access_token);
        let refresh_slot = &mut self.refresh_token;
        *refresh_slot = refresh_token;
        self.expires_at = expires_at;
    }

    fn validate_config(&self) -> AuthResult<()> {
        let config = OAuthAuthCodeConfig {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            authorize_url: self.authorize_url.clone(),
            token_url: self.token_url.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            use_pkce: self.use_pkce,
        };
        config.validate()
    }
}

#[async_trait]
impl AuthMethod for OAuthAuthCodeAuth {
    fn id(&self) -> &'static str {
        "oauth_auth_code"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.validate_config()
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        apply_bearer_token(
            self.id(),
            self.access_token.as_ref(),
            self.expires_at,
            request,
        )
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        self.expires_at.map(std_duration_until)
    }
}

/// OAuth authorization-code flow configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeConfig {
    /// OAuth client id.
    pub client_id: String,
    /// Optional client secret for confidential clients.
    pub client_secret: Option<RedactedSecret>,
    /// Authorization endpoint URL.
    pub authorize_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Registered redirect URI.
    pub redirect_uri: String,
    /// Requested scope string. Empty scope is allowed for provider defaults.
    pub scope: String,
    /// Whether to include S256 PKCE in the authorization request and exchange.
    pub use_pkce: bool,
}

impl OAuthAuthCodeConfig {
    /// Construct public-client authorization-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn public_client(
        client_id: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        Self::new(
            client_id,
            Option::<String>::None,
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )
    }

    /// Construct confidential-client authorization-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn confidential_client(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        Self::new(
            client_id,
            Some(client_secret.into()),
            authorize_url,
            token_url,
            redirect_uri,
            scope,
            use_pkce,
        )
    }

    /// Construct authorization-code flow configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when required fields are empty or unsafe.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        use_pkce: bool,
    ) -> AuthResult<Self> {
        let config = Self {
            client_id: client_id.into(),
            client_secret: client_secret.map(RedactedSecret::new).transpose()?,
            authorize_url: authorize_url.into(),
            token_url: token_url.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            use_pkce,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> AuthResult<()> {
        validate_non_empty(&self.client_id, "client_id")?;
        validate_no_crlf(&self.client_id, "client_id")?;
        if let Some(secret) = &self.client_secret {
            validate_no_crlf(secret.expose_secret(), "client_secret")?;
        }
        parse_oauth_url(&self.authorize_url, "authorize_url")?;
        parse_oauth_url(&self.token_url, "token_url")?;
        parse_oauth_url(&self.redirect_uri, "redirect_uri")?;
        validate_no_crlf(&self.scope, "scope")
    }
}

impl fmt::Debug for OAuthAuthCodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthAuthCodeConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("authorize_url", &self.authorize_url)
            .field("token_url", &self.token_url)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("use_pkce", &self.use_pkce)
            .finish()
    }
}

/// PKCE code-challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthPkceChallengeMethod {
    /// SHA-256 based `S256` challenge.
    S256,
}

impl fmt::Display for OAuthPkceChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S256 => f.write_str("S256"),
        }
    }
}

/// Redaction-safe PKCE verifier/challenge pair.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthPkce {
    /// Secret code verifier used at token exchange.
    pub verifier: RedactedSecret,
    /// Public code challenge sent in the authorization URL.
    pub challenge: String,
    /// Challenge method.
    pub method: OAuthPkceChallengeMethod,
}

impl OAuthPkce {
    /// Generate a random S256 PKCE verifier and challenge.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] if generated material fails validation.
    pub fn generate() -> AuthResult<Self> {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self::from_verifier(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Build S256 PKCE material from an existing verifier.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the verifier violates RFC 7636
    /// length or character constraints.
    pub fn from_verifier(verifier: impl Into<String>) -> AuthResult<Self> {
        let verifier = verifier.into();
        validate_pkce_verifier(&verifier)?;
        let challenge = pkce_s256_challenge(&verifier);
        Ok(Self {
            verifier: RedactedSecret::new(verifier)?,
            challenge,
            method: OAuthPkceChallengeMethod::S256,
        })
    }
}

impl fmt::Debug for OAuthPkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthPkce")
            .field("verifier", &self.verifier)
            .field("challenge", &self.challenge)
            .field("method", &self.method)
            .finish()
    }
}

/// Authorization URL plus callback validation state.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeRequest {
    authorization_url: String,
    state: RedactedSecret,
    pkce: Option<OAuthPkce>,
}

impl OAuthAuthCodeRequest {
    /// Borrow the user-facing authorization URL.
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    /// Borrow the expected callback state.
    #[must_use]
    pub const fn state(&self) -> &RedactedSecret {
        &self.state
    }

    /// Borrow PKCE material, when enabled.
    #[must_use]
    pub const fn pkce(&self) -> Option<&OAuthPkce> {
        self.pkce.as_ref()
    }
}

impl fmt::Debug for OAuthAuthCodeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthAuthCodeRequest")
            .field("authorization_url", &"[REDACTED]")
            .field("state", &self.state)
            .field("pkce", &self.pkce.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// OAuth authorization-code callback payload.
#[derive(Clone, PartialEq, Eq)]
pub enum OAuthAuthCodeCallback {
    /// Provider returned an authorization code.
    Authorized {
        /// Secret authorization code.
        code: RedactedSecret,
        /// Callback state.
        state: String,
    },
    /// Provider returned an OAuth error.
    Rejected {
        /// Provider error code.
        error: String,
        /// Optional redaction-safe error description.
        description: Option<String>,
        /// Optional callback state.
        state: Option<String>,
    },
}

impl OAuthAuthCodeCallback {
    /// Construct an authorized callback.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the code or state is empty or unsafe.
    pub fn authorized(code: impl Into<String>, state: impl Into<String>) -> AuthResult<Self> {
        let state = state.into();
        validate_oauth_state(&state)?;
        Ok(Self::Authorized {
            code: RedactedSecret::new(code)?,
            state,
        })
    }

    /// Construct a rejected callback.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when provider fields are empty or unsafe.
    pub fn rejected(
        error: impl Into<String>,
        description: Option<impl Into<String>>,
        state: Option<impl Into<String>>,
    ) -> AuthResult<Self> {
        let error = error.into();
        validate_non_empty(&error, "oauth_error_code")?;
        validate_no_crlf(&error, "oauth_error_code")?;
        let description = description.map(Into::into);
        if let Some(description) = description.as_deref() {
            validate_no_crlf(description, "oauth_error_reason")?;
        }
        let state = state.map(Into::into);
        if let Some(state) = state.as_deref() {
            validate_oauth_state(state)?;
        }
        Ok(Self::Rejected {
            error,
            description,
            state,
        })
    }
}

impl fmt::Debug for OAuthAuthCodeCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorized { code, state: _ } => f
                .debug_struct("OAuthAuthCodeCallback::Authorized")
                .field("code", code)
                .field("state", &"[REDACTED]")
                .finish(),
            Self::Rejected {
                error,
                description,
                state,
            } => f
                .debug_struct("OAuthAuthCodeCallback::Rejected")
                .field("error", error)
                .field("description", description)
                .field("state", &state.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

/// Validated authorization code ready for token exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeGrant {
    /// Secret authorization code.
    pub code: RedactedSecret,
    /// Callback state that matched the request state.
    pub state: RedactedSecret,
}

impl fmt::Debug for OAuthAuthCodeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthAuthCodeGrant")
            .field("code", &self.code)
            .field("state", &self.state)
            .finish()
    }
}

/// Provider response returned by an authorization-code token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthAuthCodeProviderResponse {
    /// Token exchange succeeded.
    Authorized(OAuthTokens),
    /// Token exchange failed with a terminal provider error.
    Rejected {
        /// Provider error code.
        code: String,
        /// Redaction-safe provider reason.
        reason: String,
    },
}

/// Transport boundary for OAuth authorization-code providers.
#[async_trait]
pub trait OAuthAuthCodeTransport: Send + Sync {
    /// Exchange an authorization code for tokens.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures or invalid provider responses.
    async fn exchange(
        &self,
        config: &OAuthAuthCodeConfig,
        grant: &OAuthAuthCodeGrant,
        pkce: Option<&OAuthPkce>,
    ) -> AuthResult<OAuthAuthCodeProviderResponse>;
}

/// OAuth authorization-code state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthAuthCodeFlow {
    config: OAuthAuthCodeConfig,
    request: OAuthAuthCodeRequest,
}

impl OAuthAuthCodeFlow {
    /// Start an authorization-code flow with generated state and optional PKCE.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config or generated PKCE material is invalid.
    pub fn start(config: OAuthAuthCodeConfig) -> AuthResult<Self> {
        Self::start_with_state(config, generate_url_safe_secret())
    }

    /// Start an authorization-code flow with caller-supplied state.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config, state, or generated PKCE material is invalid.
    pub fn start_with_state(
        config: OAuthAuthCodeConfig,
        state: impl Into<String>,
    ) -> AuthResult<Self> {
        let pkce = if config.use_pkce {
            Some(OAuthPkce::generate()?)
        } else {
            None
        };
        Self::start_with_state_and_pkce(config, state, pkce)
    }

    /// Start an authorization-code flow with caller-supplied state and PKCE material.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when static config, state, or PKCE state is invalid.
    pub fn start_with_state_and_pkce(
        config: OAuthAuthCodeConfig,
        state: impl Into<String>,
        pkce: Option<OAuthPkce>,
    ) -> AuthResult<Self> {
        config.validate()?;
        if config.use_pkce && pkce.is_none() {
            return Err(invalid_config("pkce", "PKCE material is required"));
        }
        if !config.use_pkce && pkce.is_some() {
            return Err(invalid_config(
                "pkce",
                "PKCE material supplied while PKCE is disabled",
            ));
        }
        let state = state.into();
        validate_oauth_state(&state)?;
        let request = build_authorization_request(&config, RedactedSecret::new(state)?, pkce)?;
        Ok(Self { config, request })
    }

    /// Borrow the authorization request.
    #[must_use]
    pub const fn request(&self) -> &OAuthAuthCodeRequest {
        &self.request
    }

    /// Validate a provider callback and extract the authorization grant.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for provider rejection, state mismatch, or unsafe callback fields.
    pub fn complete_callback(
        &self,
        callback: OAuthAuthCodeCallback,
    ) -> AuthResult<OAuthAuthCodeGrant> {
        match callback {
            OAuthAuthCodeCallback::Authorized { code, state } => {
                self.ensure_state_matches(Some(&state))?;
                validate_no_crlf(code.expose_secret(), "authorization_code")?;
                Ok(OAuthAuthCodeGrant {
                    code,
                    state: RedactedSecret::new(state)?,
                })
            }
            OAuthAuthCodeCallback::Rejected {
                error,
                description,
                state,
            } => {
                self.ensure_state_matches(state.as_deref())?;
                let reason = description.unwrap_or_else(|| error.clone());
                validate_oauth_error(&error, &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_auth_code",
                    code: error,
                    reason,
                })
            }
        }
    }

    /// Exchange an authorization grant for tokens.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] for transport failures, provider rejections, or malformed tokens.
    pub async fn exchange<T>(
        &self,
        cx: &fcp_async_core::Cx,
        transport: &T,
        grant: &OAuthAuthCodeGrant,
    ) -> AuthResult<OAuthTokens>
    where
        T: OAuthAuthCodeTransport + ?Sized,
    {
        let _ = cx;
        match transport
            .exchange(&self.config, grant, self.request.pkce())
            .await?
        {
            OAuthAuthCodeProviderResponse::Authorized(tokens) => {
                tokens.validate()?;
                Ok(tokens)
            }
            OAuthAuthCodeProviderResponse::Rejected { code, reason } => {
                validate_oauth_error(&code, &reason)?;
                Err(AuthError::ProviderRejected {
                    method: "oauth_auth_code",
                    code,
                    reason,
                })
            }
        }
    }

    fn ensure_state_matches(&self, state: Option<&str>) -> AuthResult<()> {
        let Some(state) = state else {
            return Err(AuthError::InvalidProviderResponse {
                method: "oauth_auth_code",
                reason: "callback state missing".to_string(),
            });
        };
        validate_oauth_state(state)?;
        if state != self.request.state.expose_secret() {
            return Err(AuthError::InvalidProviderResponse {
                method: "oauth_auth_code",
                reason: "callback state mismatch".to_string(),
            });
        }
        Ok(())
    }
}

/// Short-lived setup-token auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupTokenAuth {
    /// Setup token.
    pub token: RedactedSecret,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Header that receives the token.
    pub header_name: String,
}

impl SetupTokenAuth {
    /// Construct setup-token auth using bearer `Authorization`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the token or header is invalid.
    pub fn bearer(token: impl Into<String>, expires_at: DateTime<Utc>) -> AuthResult<Self> {
        Self::new(token, expires_at, "Authorization")
    }

    /// Construct setup-token auth with a custom header.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when the token or header is invalid.
    pub fn new(
        token: impl Into<String>,
        expires_at: DateTime<Utc>,
        header_name: impl Into<String>,
    ) -> AuthResult<Self> {
        let header_name = header_name.into();
        validate_header_name(&header_name)?;
        Ok(Self {
            token: RedactedSecret::new(token)?,
            expires_at,
            header_name,
        })
    }

    fn ensure_live(&self) -> AuthResult<()> {
        if Utc::now() >= self.expires_at {
            return Err(AuthError::Expired {
                method: "setup_token",
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

#[async_trait]
impl AuthMethod for SetupTokenAuth {
    fn id(&self) -> &'static str {
        "setup_token"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.ensure_live()
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        request.set_header(
            self.header_name.clone(),
            format!("Bearer {}", self.token.expose_secret()),
        )
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        Some(std_duration_until(self.expires_at))
    }
}

/// Cached JWT token plus expiration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtCachedToken {
    /// Generated JWT.
    pub token: RedactedSecret,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
}

/// JWT generator auth.
#[derive(Clone)]
pub struct JwtAuth {
    /// Stable method id suffix for diagnostics.
    pub id: String,
    /// Token TTL.
    pub ttl: StdDuration,
    generator: Arc<dyn Fn() -> AuthResult<String> + Send + Sync>,
    cached_token: Arc<RwLock<Option<JwtCachedToken>>>,
}

impl JwtAuth {
    /// Construct a JWT auth method from a token generator.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when `id` is empty or `ttl` is zero.
    pub fn new(
        id: impl Into<String>,
        ttl: StdDuration,
        generator: impl Fn() -> AuthResult<String> + Send + Sync + 'static,
    ) -> AuthResult<Self> {
        let id = id.into();
        validate_non_empty(&id, "jwt_id")?;
        if ttl.is_zero() {
            return Err(invalid_config("ttl", "must be greater than zero"));
        }
        Ok(Self {
            id,
            ttl,
            generator: Arc::new(generator),
            cached_token: Arc::new(RwLock::new(None)),
        })
    }

    /// Return the cached token snapshot, if present.
    #[must_use]
    pub fn cached_token(&self) -> Option<JwtCachedToken> {
        self.cached_token.read().clone()
    }

    fn regenerate_jwt(&self) -> AuthResult<JwtCachedToken> {
        let jwt = RedactedSecret::new((self.generator)()?)?;
        let expires_at = Utc::now() + chrono_duration(self.ttl)?;
        let cached = JwtCachedToken {
            token: jwt,
            expires_at,
        };
        *self.cached_token.write() = Some(cached.clone());
        Ok(cached)
    }

    fn jwt_material(&self) -> AuthResult<RedactedSecret> {
        if let Some(cached) = self.cached_token.read().as_ref() {
            if Utc::now() < cached.expires_at {
                return Ok(cached.token.clone());
            }
        }

        Ok(self.regenerate_jwt()?.token)
    }
}

impl fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtAuth")
            .field("id", &self.id)
            .field("ttl", &self.ttl)
            .field("cached_token", &self.cached_token())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthMethod for JwtAuth {
    fn id(&self) -> &'static str {
        "jwt"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_non_empty(&self.id, "jwt_id")?;
        if self.ttl.is_zero() {
            return Err(invalid_config("ttl", "must be greater than zero"));
        }
        Ok(())
    }

    async fn build_request_auth(
        &self,
        cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        self.validate(cx).await?;
        let jwt = self.jwt_material()?;
        request.set_header("Authorization", format!("Bearer {}", jwt.expose_secret()))
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        self.cached_token()
            .map(|cached| std_duration_until(cached.expires_at))
    }

    async fn refresh(&mut self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        self.validate(cx).await?;
        self.regenerate_jwt()?;
        Ok(())
    }
}

/// Result of applying AWS `SigV4` signing to request headers.
#[derive(Clone, PartialEq, Eq)]
pub struct SigV4SignedAuth {
    /// Authorization header value.
    pub authorization: String,
    /// Timestamp used for `x-amz-date`.
    pub x_amz_date: String,
    /// Payload hash used for `x-amz-content-sha256`.
    pub x_amz_content_sha256: String,
    /// Optional temporary-security session token header.
    pub x_amz_security_token: Option<String>,
    /// Semicolon-separated canonical signed header names.
    pub signed_headers: String,
}

impl fmt::Debug for SigV4SignedAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigV4SignedAuth")
            .field("authorization", &self.authorization)
            .field("x_amz_date", &self.x_amz_date)
            .field("x_amz_content_sha256", &self.x_amz_content_sha256)
            .field(
                "x_amz_security_token",
                &self.x_amz_security_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("signed_headers", &self.signed_headers)
            .finish()
    }
}

/// AWS `SigV4` auth configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Auth {
    /// Access key id.
    pub access_key: RedactedSecret,
    /// Secret access key.
    pub secret_key: RedactedSecret,
    /// Optional session token.
    pub session_token: Option<RedactedSecret>,
    /// AWS region.
    pub region: String,
    /// AWS service id.
    pub service: String,
}

impl SigV4Auth {
    /// Construct `SigV4` auth configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when any required field is empty.
    pub fn new(
        access_key: impl Into<String>,
        signing_key: impl Into<String>,
        session_token: Option<impl Into<String>>,
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> AuthResult<Self> {
        let region = region.into();
        let service = service.into();
        validate_non_empty(&region, "region")?;
        validate_non_empty(&service, "service")?;
        Ok(Self {
            access_key: RedactedSecret::new(access_key)?,
            secret_key: RedactedSecret::new(signing_key)?,
            session_token: session_token.map(RedactedSecret::new).transpose()?,
            region: region.to_ascii_lowercase(),
            service: service.to_ascii_lowercase(),
        })
    }

    /// Sign a request context and return the headers `SigV4` must apply.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when required request context or headers are invalid.
    pub fn sign(
        &self,
        context: &SigV4SigningContext,
        request_headers: &BTreeMap<String, String>,
    ) -> AuthResult<SigV4SignedAuth> {
        validate_non_empty(&self.region, "region")?;
        validate_non_empty(&self.service, "service")?;
        let signing_time = context.signing_time.unwrap_or_else(Utc::now);
        let date_stamp = signing_time.format("%Y%m%d").to_string();
        let amz_date = signing_time.format("%Y%m%dT%H%M%SZ").to_string();
        let credential_scope =
            format!("{date_stamp}/{}/{}/aws4_request", self.region, self.service);

        let mut headers = request_headers.clone();
        headers.insert("x-amz-date".to_string(), amz_date.clone());
        headers.insert(
            "x-amz-content-sha256".to_string(),
            context.payload_hash.clone(),
        );
        if let Some(session_token) = &self.session_token {
            headers.insert(
                "x-amz-security-token".to_string(),
                session_token.expose_secret().to_string(),
            );
        }

        let (canonical_headers, signed_headers) = canonical_headers(&headers)?;
        let canonical_request = canonical_request(context, &canonical_headers, &signed_headers);
        let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign =
            format!("{SIGV4_ALGORITHM}\n{amz_date}\n{credential_scope}\n{canonical_hash}");
        let signing_key = self.derive_signing_key(&date_stamp);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "{SIGV4_ALGORITHM} Credential={}/{credential_scope},SignedHeaders={signed_headers},Signature={signature}",
            self.access_key.expose_secret(),
        );

        Ok(SigV4SignedAuth {
            authorization,
            x_amz_date: amz_date,
            x_amz_content_sha256: context.payload_hash.clone(),
            x_amz_security_token: self
                .session_token
                .as_ref()
                .map(|token| token.expose_secret().to_string()),
            signed_headers,
        })
    }

    fn derive_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let key_for_date = hmac_sha256(
            format!("AWS4{}", self.secret_key.expose_secret()).as_bytes(),
            date_stamp.as_bytes(),
        );
        let key_for_region = hmac_sha256(&key_for_date, self.region.as_bytes());
        let key_for_service = hmac_sha256(&key_for_region, self.service.as_bytes());
        hmac_sha256(&key_for_service, b"aws4_request")
    }
}

#[async_trait]
impl AuthMethod for SigV4Auth {
    fn id(&self) -> &'static str {
        "sigv4"
    }

    async fn validate(&self, _cx: &fcp_async_core::Cx) -> AuthResult<()> {
        validate_non_empty(&self.region, "region")?;
        validate_non_empty(&self.service, "service")
    }

    async fn build_request_auth(
        &self,
        _cx: &fcp_async_core::Cx,
        request: &mut AuthRequest,
    ) -> AuthResult<()> {
        let context = request
            .sigv4_context()
            .ok_or_else(|| AuthError::MissingSigningContext { method: self.id() })?;
        let signed = self.sign(context, request.headers())?;
        request.set_header("x-amz-date", signed.x_amz_date)?;
        request.set_header("x-amz-content-sha256", signed.x_amz_content_sha256)?;
        if let Some(session_token) = signed.x_amz_security_token {
            request.set_header("x-amz-security-token", session_token)?;
        }
        request.set_header("Authorization", signed.authorization)
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        None
    }
}

/// Hash request payload bytes as lowercase SHA-256 hex.
#[must_use]
pub fn sha256_payload_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn canonical_request(
    context: &SigV4SigningContext,
    canonical_headers: &str,
    signed_headers: &str,
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{signed_headers}\n{}",
        context.method,
        canonical_uri(&context.uri_path),
        canonical_query(&context.query_params),
        canonical_headers,
        context.payload_hash,
    )
}

fn canonical_headers(headers: &BTreeMap<String, String>) -> AuthResult<(String, String)> {
    let mut normalized = BTreeMap::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if name == "authorization" {
            continue;
        }
        validate_header_name(&name)?;
        validate_header_value(value)?;
        normalized.insert(name, normalize_header_value(value));
    }
    if !normalized.contains_key("host") {
        return Err(invalid_config("host_header", "SigV4 signing requires host"));
    }

    let mut canonical = String::new();
    for (name, value) in &normalized {
        let _ = writeln!(&mut canonical, "{name}:{value}");
    }
    let signed = normalized.keys().cloned().collect::<Vec<_>>().join(";");
    Ok((canonical, signed))
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn canonical_query(params: &BTreeMap<String, String>) -> String {
    let mut encoded = params
        .iter()
        .map(|(key, value)| (uri_encode(key), uri_encode(value)))
        .collect::<Vec<_>>();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_uri(path: &str) -> String {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    path.split('/')
        .map(uri_encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn uri_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                let _ = write!(&mut encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

fn apply_bearer_token(
    method: &'static str,
    access_token: Option<&RedactedSecret>,
    expires_at: Option<DateTime<Utc>>,
    request: &mut AuthRequest,
) -> AuthResult<()> {
    if let Some(expires_at) = expires_at {
        if Utc::now() >= expires_at {
            return Err(AuthError::Expired { method, expires_at });
        }
    }
    let bearer_material = access_token.ok_or(AuthError::MissingToken { method })?;
    request.set_header(
        "Authorization",
        format!("Bearer {}", bearer_material.expose_secret()),
    )
}

/// Supported auth method variants.
#[derive(Debug, Clone)]
pub enum AuthMethodKind {
    /// Static API-key auth.
    ApiKey(ApiKeyAuth),
    /// OAuth device-code auth.
    OAuthDeviceCode(OAuthDeviceCodeAuth),
    /// OAuth authorization-code auth.
    OAuthAuthCode(OAuthAuthCodeAuth),
    /// Short-lived setup-token auth.
    SetupToken(SetupTokenAuth),
    /// JWT generator auth.
    Jwt(JwtAuth),
    /// AWS `SigV4` auth config.
    SigV4(SigV4Auth),
}

#[async_trait]
impl AuthMethod for AuthMethodKind {
    fn id(&self) -> &'static str {
        match self {
            Self::ApiKey(method) => method.id(),
            Self::OAuthDeviceCode(_) => "oauth_device",
            Self::OAuthAuthCode(_) => "oauth_auth_code",
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
        self.validate(cx).await?;
        match self {
            Self::ApiKey(method) => method.build_request_auth(cx, request).await,
            Self::OAuthDeviceCode(method) => method.build_request_auth(cx, request).await,
            Self::OAuthAuthCode(method) => method.build_request_auth(cx, request).await,
            Self::SetupToken(method) => method.build_request_auth(cx, request).await,
            Self::Jwt(method) => method.build_request_auth(cx, request).await,
            Self::SigV4(method) => method.build_request_auth(cx, request).await,
        }
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        match self {
            Self::ApiKey(method) => method.requires_refresh_in(),
            Self::OAuthDeviceCode(method) => method.requires_refresh_in(),
            Self::OAuthAuthCode(method) => method.requires_refresh_in(),
            Self::SetupToken(method) => method.requires_refresh_in(),
            Self::Jwt(method) => method.requires_refresh_in(),
            Self::SigV4(method) => method.requires_refresh_in(),
        }
    }

    async fn refresh(&mut self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
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

/// One provider auth profile.
#[derive(Debug, Clone)]
pub struct AuthProfile {
    /// Opaque profile id.
    pub id: String,
    /// Canonical provider id.
    pub provider: String,
    /// Concrete auth method.
    pub method: AuthMethodKind,
    /// Redaction-safe operator label.
    pub label: String,
    /// Lower values are preferred.
    pub priority: i32,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl AuthProfile {
    /// Construct an auth profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfig`] when id, provider, or label is empty.
    pub fn new(
        id: impl Into<String>,
        provider: impl Into<String>,
        method: AuthMethodKind,
        label: impl Into<String>,
        priority: i32,
    ) -> AuthResult<Self> {
        let id = id.into();
        let provider = canonical_provider(&provider.into())?;
        let label = label.into();
        validate_non_empty(&id, "profile_id")?;
        validate_non_empty(&label, "label")?;
        Ok(Self {
            id,
            provider,
            method,
            label,
            priority,
            created_at: Utc::now(),
            last_used_at: None,
        })
    }
}

/// Storage boundary for provider auth profiles.
#[async_trait]
pub trait AuthProfileStore: Send + Sync {
    /// List provider profiles in active-selection order.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when the provider id is invalid.
    async fn list_profiles(&self, provider: &str) -> AuthResult<Vec<AuthProfile>>;

    /// Get one provider profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProfileNotFound`] when no matching profile exists.
    async fn get_profile(&self, provider: &str, profile_id: &str) -> AuthResult<AuthProfile>;

    /// Save or replace a provider profile.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthError`] when profile identity fields are invalid.
    async fn save_profile(&self, profile: AuthProfile) -> AuthResult<()>;

    /// Delete one provider profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProfileNotFound`] when no matching profile exists.
    async fn delete_profile(&self, provider: &str, profile_id: &str) -> AuthResult<()>;

    /// Pick the active provider profile.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::ProviderNotFound`] when the provider has no profiles.
    async fn pick_active(&self, provider: &str) -> AuthResult<AuthProfile>;
}

/// Concurrency-safe in-memory auth profile store.
#[derive(Debug, Default)]
pub struct InMemoryAuthProfileStore {
    profiles: RwLock<BTreeMap<(String, String), AuthProfile>>,
}

impl InMemoryAuthProfileStore {
    /// Construct an empty in-memory profile store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            profiles: RwLock::new(BTreeMap::new()),
        }
    }
}

fn profile_sort_key(profile: &AuthProfile) -> (i32, &str, DateTime<Utc>) {
    (profile.priority, profile.id.as_str(), profile.created_at)
}

#[async_trait]
impl AuthProfileStore for InMemoryAuthProfileStore {
    async fn list_profiles(&self, provider: &str) -> AuthResult<Vec<AuthProfile>> {
        let provider = canonical_provider(provider)?;
        let mut profiles = self
            .profiles
            .read()
            .values()
            .filter(|profile| profile.provider == provider)
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| profile_sort_key(left).cmp(&profile_sort_key(right)));
        Ok(profiles)
    }

    async fn get_profile(&self, provider: &str, profile_id: &str) -> AuthResult<AuthProfile> {
        let provider = canonical_provider(provider)?;
        validate_non_empty(profile_id, "profile_id")?;
        self.profiles
            .read()
            .get(&(provider.clone(), profile_id.to_string()))
            .cloned()
            .ok_or_else(|| AuthError::ProfileNotFound {
                provider,
                profile_id: profile_id.to_string(),
            })
    }

    async fn save_profile(&self, mut profile: AuthProfile) -> AuthResult<()> {
        validate_non_empty(&profile.id, "profile_id")?;
        validate_non_empty(&profile.label, "label")?;
        profile.provider = canonical_provider(&profile.provider)?;
        self.profiles
            .write()
            .insert((profile.provider.clone(), profile.id.clone()), profile);
        Ok(())
    }

    async fn delete_profile(&self, provider: &str, profile_id: &str) -> AuthResult<()> {
        let provider = canonical_provider(provider)?;
        validate_non_empty(profile_id, "profile_id")?;
        let removed = self
            .profiles
            .write()
            .remove(&(provider.clone(), profile_id.to_string()));
        if removed.is_some() {
            Ok(())
        } else {
            Err(AuthError::ProfileNotFound {
                provider,
                profile_id: profile_id.to_string(),
            })
        }
    }

    async fn pick_active(&self, provider: &str) -> AuthResult<AuthProfile> {
        let provider = canonical_provider(provider)?;
        self.list_profiles(&provider)
            .await?
            .into_iter()
            .next()
            .ok_or(AuthError::ProviderNotFound { provider })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;

    fn cx() -> fcp_async_core::Cx {
        fcp_async_core::Cx::for_testing()
    }

    fn sigv4_time() -> DateTime<Utc> {
        "2013-05-24T00:00:00Z".parse().unwrap()
    }

    fn aws_example_access_key() -> String {
        ["AKIAIOSFODNN7", "EXAMPLE"].concat()
    }

    fn sigv4_auth(session_token: Option<&str>) -> SigV4Auth {
        SigV4Auth::new(
            aws_example_access_key(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token.map(str::to_string),
            "us-east-1",
            "s3",
        )
        .unwrap()
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        fcp_async_core::runtime::block_on_sync(future).unwrap()
    }

    fn api_profile(id: &str, provider: &str, priority: i32) -> AuthProfile {
        AuthProfile::new(
            id,
            provider,
            AuthMethodKind::ApiKey(ApiKeyAuth::bearer(format!("fixture-{id}")).unwrap()),
            id,
            priority,
        )
        .unwrap()
    }

    fn oauth_config() -> OAuthDeviceCodeConfig {
        OAuthDeviceCodeConfig::new(
            "fixture-client",
            "https://auth.example.test/device",
            "https://auth.example.test/token",
            "chat messages",
        )
        .unwrap()
    }

    fn oauth_challenge() -> OAuthDeviceCodeChallenge {
        OAuthDeviceCodeChallenge::new(
            "fixture-device-code",
            "ABCD-EFGH",
            "https://auth.example.test/verify",
            Some("https://auth.example.test/verify?user_code=ABCD-EFGH"),
            Utc::now() + TimeDelta::minutes(5),
            StdDuration::from_secs(5),
        )
        .unwrap()
    }

    fn oauth_tokens() -> OAuthTokens {
        OAuthTokens::bearer(
            "fixture-access-token",
            Some(StdDuration::from_secs(3_600)),
            Some("fixture-refresh-token"),
            Some("chat messages"),
        )
        .unwrap()
    }

    fn auth_code_config() -> OAuthAuthCodeConfig {
        OAuthAuthCodeConfig::public_client(
            "fixture-client",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
            "https://agent.example.test/oauth/callback",
            "chat messages",
            true,
        )
        .unwrap()
    }

    fn auth_code_pkce() -> OAuthPkce {
        OAuthPkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap()
    }

    #[derive(Debug)]
    struct ScriptedDeviceTransport {
        challenge: OAuthDeviceCodeChallenge,
        responses: Mutex<VecDeque<OAuthDeviceCodeProviderResponse>>,
    }

    impl ScriptedDeviceTransport {
        fn new(responses: impl IntoIterator<Item = OAuthDeviceCodeProviderResponse>) -> Self {
            Self {
                challenge: oauth_challenge(),
                responses: Mutex::new(responses.into_iter().collect()),
            }
        }

        fn with_challenge(mut self, challenge: OAuthDeviceCodeChallenge) -> Self {
            self.challenge = challenge;
            self
        }
    }

    #[async_trait]
    impl OAuthDeviceCodeTransport for ScriptedDeviceTransport {
        async fn start(
            &self,
            _config: &OAuthDeviceCodeConfig,
        ) -> AuthResult<OAuthDeviceCodeChallenge> {
            Ok(self.challenge.clone())
        }

        async fn poll(
            &self,
            _config: &OAuthDeviceCodeConfig,
            _challenge: &OAuthDeviceCodeChallenge,
        ) -> AuthResult<OAuthDeviceCodeProviderResponse> {
            self.responses
                .lock()
                .pop_front()
                .ok_or_else(|| AuthError::InvalidProviderResponse {
                    method: "oauth_device",
                    reason: "scripted transport had no response".to_string(),
                })
        }
    }

    #[derive(Debug)]
    struct ScriptedAuthCodeTransport {
        responses: Mutex<VecDeque<OAuthAuthCodeProviderResponse>>,
        seen_pkce_challenges: Mutex<Vec<Option<String>>>,
    }

    impl ScriptedAuthCodeTransport {
        fn new(responses: impl IntoIterator<Item = OAuthAuthCodeProviderResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                seen_pkce_challenges: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl OAuthAuthCodeTransport for ScriptedAuthCodeTransport {
        async fn exchange(
            &self,
            config: &OAuthAuthCodeConfig,
            grant: &OAuthAuthCodeGrant,
            pkce: Option<&OAuthPkce>,
        ) -> AuthResult<OAuthAuthCodeProviderResponse> {
            assert_eq!(config.client_id, "fixture-client");
            assert_eq!(grant.code.expose_secret(), "fixture-auth-code");
            self.seen_pkce_challenges
                .lock()
                .push(pkce.map(|pkce| pkce.challenge.clone()));
            self.responses
                .lock()
                .pop_front()
                .ok_or_else(|| AuthError::InvalidProviderResponse {
                    method: "oauth_auth_code",
                    reason: "scripted transport had no response".to_string(),
                })
        }
    }

    #[test]
    fn api_key_auth_sets_bearer_header_and_redacts_debug() {
        let auth = ApiKeyAuth::bearer("fixture-api-key-value").unwrap();
        let mut request = AuthRequest::new();

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-api-key-value")
        );
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture-api-key-value"));
    }

    #[test]
    fn auth_request_rejects_header_injection() {
        let mut request = AuthRequest::new();

        let error = request
            .set_header("Authorization", "Bearer good\nX-Injected: bad")
            .unwrap_err();

        assert!(matches!(
            error,
            AuthError::InvalidHeader {
                field: "header_value",
                ..
            }
        ));
    }

    #[test]
    fn setup_token_refuses_expired_token() {
        let auth =
            SetupTokenAuth::bearer("setup-token", Utc::now() - TimeDelta::seconds(1)).unwrap();
        let mut request = AuthRequest::new();

        let error = run(auth.build_request_auth(&cx(), &mut request)).unwrap_err();

        assert!(matches!(
            error,
            AuthError::Expired {
                method: "setup_token",
                ..
            }
        ));
        assert!(request.headers().is_empty());
    }

    #[test]
    fn method_kind_delegates_api_key_auth() {
        let auth = AuthMethodKind::ApiKey(ApiKeyAuth::bearer("fixture-kind").unwrap());
        let mut request = AuthRequest::new();

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();

        assert_eq!(auth.id(), "api_key");
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-kind")
        );
    }

    #[test]
    fn oauth_device_flow_handles_pending_slow_down_and_success() {
        let expected_tokens = oauth_tokens();
        let transport = ScriptedDeviceTransport::new([
            OAuthDeviceCodeProviderResponse::AuthorizationPending,
            OAuthDeviceCodeProviderResponse::SlowDown,
            OAuthDeviceCodeProviderResponse::Authorized(expected_tokens.clone()),
        ]);
        let mut flow = run(OAuthDeviceCodeFlow::start(
            &cx(),
            oauth_config(),
            &transport,
        ))
        .unwrap();

        assert_eq!(flow.challenge().user_code, "ABCD-EFGH");
        assert_eq!(flow.poll_interval(), StdDuration::from_secs(5));
        assert_eq!(
            run(flow.poll(&cx(), &transport)).unwrap(),
            OAuthDeviceCodePoll::Pending {
                retry_after: StdDuration::from_secs(5)
            }
        );
        assert_eq!(
            run(flow.poll(&cx(), &transport)).unwrap(),
            OAuthDeviceCodePoll::Pending {
                retry_after: StdDuration::from_secs(10)
            }
        );

        assert_eq!(
            run(flow.poll(&cx(), &transport)).unwrap(),
            OAuthDeviceCodePoll::Authorized(expected_tokens.clone())
        );
        assert_eq!(
            expected_tokens.access_token.expose_secret(),
            "fixture-access-token"
        );
        assert_eq!(
            expected_tokens
                .refresh_token
                .as_ref()
                .map(RedactedSecret::expose_secret),
            Some("fixture-refresh-token")
        );
    }

    #[test]
    fn oauth_device_flow_maps_denied_and_expired_responses() {
        let denied =
            ScriptedDeviceTransport::new([OAuthDeviceCodeProviderResponse::AccessDenied {
                reason: "operator denied browser authorization".to_string(),
            }]);
        let mut denied_flow =
            run(OAuthDeviceCodeFlow::start(&cx(), oauth_config(), &denied)).unwrap();

        let denied_error = run(denied_flow.poll(&cx(), &denied)).unwrap_err();
        assert_eq!(
            denied_error,
            AuthError::ProviderRejected {
                method: "oauth_device",
                code: "access_denied".to_string(),
                reason: "operator denied browser authorization".to_string(),
            }
        );

        let expired =
            ScriptedDeviceTransport::new([OAuthDeviceCodeProviderResponse::ExpiredToken {
                reason: "device code expired".to_string(),
            }]);
        let mut expired_flow =
            run(OAuthDeviceCodeFlow::start(&cx(), oauth_config(), &expired)).unwrap();

        let expired_error = run(expired_flow.poll(&cx(), &expired)).unwrap_err();
        assert_eq!(
            expired_error,
            AuthError::ProviderRejected {
                method: "oauth_device",
                code: "expired_token".to_string(),
                reason: "device code expired".to_string(),
            }
        );
    }

    #[test]
    fn oauth_device_flow_rejects_malformed_provider_challenge() {
        let mut challenge = oauth_challenge();
        challenge.interval = StdDuration::ZERO;
        let transport = ScriptedDeviceTransport::new([]).with_challenge(challenge);

        let error = run(OAuthDeviceCodeFlow::start(
            &cx(),
            oauth_config(),
            &transport,
        ))
        .unwrap_err();

        assert_eq!(
            error,
            AuthError::InvalidProviderResponse {
                method: "oauth_device",
                reason: "invalid auth configuration for interval: must be greater than zero"
                    .to_string(),
            }
        );
    }

    #[test]
    fn oauth_device_auth_builds_bearer_header_and_redacts_debug() {
        let mut auth = OAuthDeviceCodeAuth::new(
            "fixture-client",
            "https://auth.example.test/device",
            "https://auth.example.test/token",
            "chat messages",
        )
        .unwrap();
        auth.apply_tokens(oauth_tokens());
        let mut request = AuthRequest::new();

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-access-token")
        );
        assert!(auth.requires_refresh_in().is_some());
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture-access-token"));
        assert!(!debug.contains("fixture-refresh-token"));
    }

    #[test]
    fn oauth_device_debug_redacts_polling_device_code() {
        let challenge = oauth_challenge();
        let tokens = oauth_tokens();

        let challenge_debug = format!("{challenge:?}");
        let tokens_debug = format!("{tokens:?}");

        assert!(challenge_debug.contains("ABCD-EFGH"));
        assert!(!challenge_debug.contains("fixture-device-code"));
        assert!(!tokens_debug.contains("fixture-access-token"));
        assert!(!tokens_debug.contains("fixture-refresh-token"));
    }

    #[test]
    fn auth_code_flow_builds_authorize_url_with_pkce_vector() {
        let pkce = auth_code_pkce();
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(pkce),
        )
        .unwrap();
        let url = Url::parse(flow.request().authorization_url()).unwrap();
        let params = url
            .query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            url.as_str().split('?').next(),
            Some("https://auth.example.test/authorize")
        );
        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("fixture-client")
        );
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("https://agent.example.test/oauth/callback")
        );
        assert_eq!(
            params.get("scope").map(String::as_str),
            Some("chat messages")
        );
        assert_eq!(params.get("state").map(String::as_str), Some("fixed-state"));
        assert_eq!(
            params.get("code_challenge").map(String::as_str),
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );

        let debug = format!("{:?}", flow.request());
        assert!(!debug.contains("fixed-state"));
        assert!(!debug.contains("dBjftJeZ4"));
    }

    #[test]
    fn auth_code_flow_validates_callback_state_and_provider_error() {
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(auth_code_pkce()),
        )
        .unwrap();

        let mismatch = flow
            .complete_callback(
                OAuthAuthCodeCallback::authorized("fixture-auth-code", "wrong-state").unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            mismatch,
            AuthError::InvalidProviderResponse {
                method: "oauth_auth_code",
                reason: "callback state mismatch".to_string(),
            }
        );

        let denied = flow
            .complete_callback(
                OAuthAuthCodeCallback::rejected(
                    "access_denied",
                    Some("operator denied browser authorization"),
                    Some("fixed-state"),
                )
                .unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            denied,
            AuthError::ProviderRejected {
                method: "oauth_auth_code",
                code: "access_denied".to_string(),
                reason: "operator denied browser authorization".to_string(),
            }
        );
    }

    #[test]
    fn auth_code_flow_exchanges_grant_for_tokens() {
        let expected_tokens = oauth_tokens();
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(auth_code_pkce()),
        )
        .unwrap();
        let grant = flow
            .complete_callback(
                OAuthAuthCodeCallback::authorized("fixture-auth-code", "fixed-state").unwrap(),
            )
            .unwrap();
        let transport =
            ScriptedAuthCodeTransport::new([OAuthAuthCodeProviderResponse::Authorized(
                expected_tokens.clone(),
            )]);

        let tokens = run(flow.exchange(&cx(), &transport, &grant)).unwrap();

        assert_eq!(tokens, expected_tokens);
        assert_eq!(
            transport.seen_pkce_challenges.lock().as_slice(),
            &[Some(
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()
            )]
        );
    }

    #[test]
    fn auth_code_flow_maps_exchange_rejection_and_malformed_token() {
        let flow = OAuthAuthCodeFlow::start_with_state_and_pkce(
            auth_code_config(),
            "fixed-state",
            Some(auth_code_pkce()),
        )
        .unwrap();
        let grant = flow
            .complete_callback(
                OAuthAuthCodeCallback::authorized("fixture-auth-code", "fixed-state").unwrap(),
            )
            .unwrap();
        let rejected = ScriptedAuthCodeTransport::new([OAuthAuthCodeProviderResponse::Rejected {
            code: "invalid_grant".to_string(),
            reason: "authorization code expired".to_string(),
        }]);

        let error = run(flow.exchange(&cx(), &rejected, &grant)).unwrap_err();
        assert_eq!(
            error,
            AuthError::ProviderRejected {
                method: "oauth_auth_code",
                code: "invalid_grant".to_string(),
                reason: "authorization code expired".to_string(),
            }
        );

        let bad_tokens = OAuthTokens {
            access_token: RedactedSecret::new("fixture-access-token").unwrap(),
            token_type: "mac".to_string(),
            refresh_token: None,
            expires_at: None,
            scope: None,
        };
        let malformed =
            ScriptedAuthCodeTransport::new([OAuthAuthCodeProviderResponse::Authorized(bad_tokens)]);

        let error = run(flow.exchange(&cx(), &malformed, &grant)).unwrap_err();
        assert_eq!(
            error,
            AuthError::InvalidConfig {
                field: "token_type",
                reason: "only bearer tokens are supported in this slice".to_string(),
            }
        );
    }

    #[test]
    fn auth_code_auth_builds_bearer_header_and_redacts_debug() {
        let mut auth = OAuthAuthCodeAuth::confidential_client(
            "fixture-client",
            "fixture-client-secret",
            "https://auth.example.test/authorize",
            "https://auth.example.test/token",
            "https://agent.example.test/oauth/callback",
            "chat messages",
            true,
        )
        .unwrap();
        auth.apply_tokens(oauth_tokens());
        let mut request = AuthRequest::new();

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-access-token")
        );
        assert!(auth.requires_refresh_in().is_some());
        let debug = format!("{auth:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture-client-secret"));
        assert!(!debug.contains("fixture-access-token"));
        assert!(!debug.contains("fixture-refresh-token"));
    }

    #[test]
    fn jwt_auth_caches_generated_token() {
        let auth = JwtAuth::new("glm", StdDuration::from_secs(60), || {
            Ok("fixture-jwt-value".to_string())
        })
        .unwrap();
        let mut request = AuthRequest::new();

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();

        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-jwt-value")
        );
        assert!(auth.cached_token().is_some());
        assert!(!format!("{auth:?}").contains("fixture-jwt-value"));
    }

    #[test]
    fn jwt_refresh_regenerates_cached_token() {
        let counter = Arc::new(AtomicUsize::new(0));
        let generator_counter = Arc::clone(&counter);
        let mut auth = JwtAuth::new("glm", StdDuration::from_secs(60), move || {
            Ok(format!(
                "fixture-jwt-{}",
                generator_counter.fetch_add(1, Ordering::SeqCst)
            ))
        })
        .unwrap();
        let mut request = AuthRequest::new();

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();
        assert_eq!(
            request.value_for("Authorization"),
            Some("Bearer fixture-jwt-0")
        );

        run(auth.refresh(&cx())).unwrap();
        let cached = auth.cached_token().unwrap();
        assert_eq!(cached.token.expose_secret(), "fixture-jwt-1");
        assert!(auth.requires_refresh_in().is_some());

        let mut refreshed_request = AuthRequest::new();
        run(auth.build_request_auth(&cx(), &mut refreshed_request)).unwrap();
        assert_eq!(
            refreshed_request.value_for("Authorization"),
            Some("Bearer fixture-jwt-1")
        );
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn sigv4_signs_aws_get_bucket_lifecycle_vector() {
        let auth = sigv4_auth(None);
        let context = SigV4SigningContext::new("GET", "/", EMPTY_PAYLOAD_SHA256)
            .unwrap()
            .with_query_param("lifecycle", "")
            .unwrap()
            .with_signing_time(sigv4_time());
        let mut request = AuthRequest::new();
        request
            .set_header("Host", "examplebucket.s3.amazonaws.com")
            .unwrap();
        request.set_sigv4_context(context);

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();

        assert_eq!(request.value_for("x-amz-date"), Some("20130524T000000Z"));
        assert_eq!(
            request.value_for("x-amz-content-sha256"),
            Some(EMPTY_PAYLOAD_SHA256)
        );
        let expected_authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
            aws_example_access_key()
        );
        assert_eq!(
            request.value_for("Authorization"),
            Some(expected_authorization.as_str())
        );
    }

    #[test]
    fn sigv4_includes_session_token_and_redacts_debug() {
        let auth = sigv4_auth(Some("fixture-session-token"));
        let context = SigV4SigningContext::new("POST", "/model/invoke", sha256_payload_hex(b"{}"))
            .unwrap()
            .with_signing_time(sigv4_time());
        let mut request = AuthRequest::new();
        request.set_header("Host", "bedrock.amazonaws.com").unwrap();
        request.set_sigv4_context(context);

        run(auth.build_request_auth(&cx(), &mut request)).unwrap();

        assert_eq!(
            request.value_for("x-amz-security-token"),
            Some("fixture-session-token")
        );
        assert!(
            request
                .value_for("Authorization")
                .unwrap()
                .contains("x-amz-security-token")
        );
        assert!(!format!("{auth:?}").contains("fixture-session-token"));
        let signed = auth
            .sign(request.sigv4_context().unwrap(), request.headers())
            .unwrap();
        assert!(!format!("{signed:?}").contains("fixture-session-token"));
    }

    #[test]
    fn sigv4_requires_signing_context() {
        let auth = sigv4_auth(None);
        let mut request = AuthRequest::new();
        request
            .set_header("Host", "examplebucket.s3.amazonaws.com")
            .unwrap();

        let error = run(auth.build_request_auth(&cx(), &mut request)).unwrap_err();

        assert_eq!(error, AuthError::MissingSigningContext { method: "sigv4" });
    }

    #[test]
    fn profile_store_orders_by_priority_then_id() {
        let store = InMemoryAuthProfileStore::new();
        let later = api_profile("later", "Anthropic", 20);
        let tie_b = api_profile("tie-b", "anthropic", 10);
        let tie_a = api_profile("tie-a", "anthropic", 10);

        run(store.save_profile(later)).unwrap();
        run(store.save_profile(tie_b)).unwrap();
        run(store.save_profile(tie_a)).unwrap();

        let profiles = run(store.list_profiles("ANTHROPIC")).unwrap();
        let ids = profiles
            .iter()
            .map(|profile| profile.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["tie-a", "tie-b", "later"]);

        let active = run(store.pick_active("anthropic")).unwrap();
        assert_eq!(active.id, "tie-a");
    }

    #[test]
    fn profile_store_reports_missing_provider_and_profile() {
        let store = InMemoryAuthProfileStore::new();

        let missing_provider = run(store.pick_active("openai")).unwrap_err();
        assert_eq!(
            missing_provider,
            AuthError::ProviderNotFound {
                provider: "openai".to_string()
            }
        );

        let missing_profile = run(store.get_profile("openai", "work")).unwrap_err();
        assert_eq!(
            missing_profile,
            AuthError::ProfileNotFound {
                provider: "openai".to_string(),
                profile_id: "work".to_string()
            }
        );
    }

    #[test]
    fn profile_store_delete_removes_profile() {
        let store = InMemoryAuthProfileStore::new();

        run(store.save_profile(api_profile("work", "openai", 0))).unwrap();
        run(store.delete_profile("openai", "work")).unwrap();

        let error = run(store.get_profile("openai", "work")).unwrap_err();
        assert!(matches!(error, AuthError::ProfileNotFound { .. }));
    }
}
