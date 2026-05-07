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
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use parking_lot::RwLock;
use thiserror::Error;
use zeroize::Zeroizing;

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

/// Minimal request-auth target used by connector clients and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRequest {
    headers: BTreeMap<String, String>,
}

impl AuthRequest {
    /// Construct an empty request-auth target.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            headers: BTreeMap::new(),
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

    fn jwt_material(&self) -> AuthResult<RedactedSecret> {
        if let Some(cached) = self.cached_token.read().as_ref() {
            if Utc::now() < cached.expires_at {
                return Ok(cached.token.clone());
            }
        }

        let jwt = RedactedSecret::new((self.generator)()?)?;
        let expires_at = Utc::now() + chrono_duration(self.ttl)?;
        *self.cached_token.write() = Some(JwtCachedToken {
            token: jwt.clone(),
            expires_at,
        });
        Ok(jwt)
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
            region,
            service,
        })
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
        _request: &mut AuthRequest,
    ) -> AuthResult<()> {
        Err(AuthError::UnsupportedMethod {
            method: self.id(),
            operation: "sigv4_request_signing",
        })
    }

    fn requires_refresh_in(&self) -> Option<StdDuration> {
        None
    }
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

    fn cx() -> fcp_async_core::Cx {
        fcp_async_core::Cx::for_testing()
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
