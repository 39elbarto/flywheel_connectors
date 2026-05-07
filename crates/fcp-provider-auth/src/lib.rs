//! Provider authentication profiles and method selection for FCP connectors.
//!
//! This crate owns the provider/profile layer above raw credential leasing and
//! OAuth primitives. The first slice intentionally keeps host admin routes and
//! full OAuth polling/exchange flows out of scope while defining the stable
//! redaction-safe types those later surfaces will use.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use thiserror::Error;
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
            Self::OAuthDeviceCode(method) => {
                validate_non_empty(&method.client_id, "client_id")?;
                validate_non_empty(&method.device_code_url, "device_code_url")?;
                validate_non_empty(&method.token_url, "token_url")
            }
            Self::OAuthAuthCode(method) => {
                validate_non_empty(&method.client_id, "client_id")?;
                validate_non_empty(&method.authorize_url, "authorize_url")?;
                validate_non_empty(&method.token_url, "token_url")?;
                validate_non_empty(&method.redirect_uri, "redirect_uri")
            }
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
            Self::OAuthDeviceCode(method) => apply_bearer_token(
                self.id(),
                method.access_token.as_ref(),
                method.expires_at,
                request,
            ),
            Self::OAuthAuthCode(method) => apply_bearer_token(
                self.id(),
                method.access_token.as_ref(),
                method.expires_at,
                request,
            ),
            Self::SetupToken(method) => method.build_request_auth(cx, request).await,
            Self::Jwt(method) => method.build_request_auth(cx, request).await,
            Self::SigV4(method) => method.build_request_auth(cx, request).await,
        }
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        match self {
            Self::ApiKey(method) => method.requires_refresh_in(),
            Self::OAuthDeviceCode(method) => method.expires_at.map(std_duration_until),
            Self::OAuthAuthCode(method) => method.expires_at.map(std_duration_until),
            Self::SetupToken(method) => method.requires_refresh_in(),
            Self::Jwt(method) => method.requires_refresh_in(),
            Self::SigV4(method) => method.requires_refresh_in(),
        }
    }

    async fn refresh(&mut self, cx: &fcp_async_core::Cx) -> AuthResult<()> {
        match self {
            Self::ApiKey(method) => method.refresh(cx).await,
            Self::OAuthDeviceCode(_) | Self::OAuthAuthCode(_) => {
                Err(AuthError::UnsupportedMethod {
                    method: self.id(),
                    operation: "refresh",
                })
            }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
