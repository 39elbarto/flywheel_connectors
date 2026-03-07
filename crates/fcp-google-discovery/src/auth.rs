//! Shared Google authentication precedence/materialization rules for FCP connectors.
//!
//! This module codifies a strict source-selection chain and FCP-specific
//! secret-residency constraints, while preserving upstream-compatible auth breadth.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use fcp_core::CredentialId;
use fcp_oauth::{AuthStyle, OAuth2Client, OAuth2Config};
use reqwest::Url;

/// Google OAuth token endpoint default.
pub const DEFAULT_GOOGLE_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Canonical Google quota-project header.
pub const GOOGLE_QUOTA_PROJECT_HEADER: &str = "x-goog-user-project";
/// Canonical bearer-auth header name.
pub const GOOGLE_AUTHORIZATION_HEADER: &str = "authorization";
/// Canonical FCP credential reference header name.
pub const FCP_CREDENTIAL_ID_HEADER: &str = "x-fcp-credential-id";

/// Configuration context for source-admission checks.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleAuthContext {
    /// Connector runtime configuration (strictest secret-residency policy).
    ConnectorRuntime,
    /// Provisioning/setup workflows (host/operator control plane).
    ProvisioningSetup,
}

impl std::fmt::Display for GoogleAuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectorRuntime => write!(f, "connector_runtime"),
            Self::ProvisioningSetup => write!(f, "provisioning_setup"),
        }
    }
}

/// Upstream/provider source kinds observed in Google auth chains.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum GoogleAuthSourceKind {
    /// Explicit access token value.
    AccessToken,
    /// Secretless credential reference.
    CredentialId,
    /// Refresh-token exchange materialization path.
    OAuthRefresh,
    /// Explicit local credentials file path.
    CredentialsFile,
    /// Local encrypted credential store/profile.
    EncryptedLocalCredentials,
    /// Provider-default credential lookup.
    DefaultCredentials,
    /// Application Default Credentials (ADC) chain.
    ApplicationDefaultCredentials,
}

impl std::fmt::Display for GoogleAuthSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccessToken => write!(f, "access_token"),
            Self::CredentialId => write!(f, "credential_id"),
            Self::OAuthRefresh => write!(f, "oauth_refresh"),
            Self::CredentialsFile => write!(f, "credentials_file"),
            Self::EncryptedLocalCredentials => write!(f, "encrypted_local_credentials"),
            Self::DefaultCredentials => write!(f, "default_credentials"),
            Self::ApplicationDefaultCredentials => write!(f, "application_default_credentials"),
        }
    }
}

/// Whether a source is allowed in a given context.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleAuthSourceDisposition {
    /// Source is allowed.
    Allowed,
    /// Source is only allowed in provisioning/setup workflows.
    ProvisioningOnly,
    /// Source is rejected under FCP policy.
    Rejected,
}

/// Policy row describing source usage rules.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GoogleAuthSourcePolicy {
    /// Source kind.
    pub source: GoogleAuthSourceKind,
    /// Runtime disposition.
    pub runtime: GoogleAuthSourceDisposition,
    /// Provisioning disposition.
    pub provisioning: GoogleAuthSourceDisposition,
    /// Human rationale.
    pub rationale: &'static str,
}

const GOOGLE_AUTH_SOURCE_POLICIES: [GoogleAuthSourcePolicy; 7] = [
    GoogleAuthSourcePolicy {
        source: GoogleAuthSourceKind::AccessToken,
        runtime: GoogleAuthSourceDisposition::Allowed,
        provisioning: GoogleAuthSourceDisposition::Allowed,
        rationale: "ephemeral token values are allowed when kept in-memory only",
    },
    GoogleAuthSourcePolicy {
        source: GoogleAuthSourceKind::CredentialId,
        runtime: GoogleAuthSourceDisposition::Allowed,
        provisioning: GoogleAuthSourceDisposition::Allowed,
        rationale: "preferred FCP path: host-managed secretless materialization via egress proxy",
    },
    GoogleAuthSourcePolicy {
        source: GoogleAuthSourceKind::OAuthRefresh,
        runtime: GoogleAuthSourceDisposition::Allowed,
        provisioning: GoogleAuthSourceDisposition::Allowed,
        rationale: "allowed if refresh materialization composes with fcp-oauth and secrets stay in-memory",
    },
    GoogleAuthSourcePolicy {
        source: GoogleAuthSourceKind::CredentialsFile,
        runtime: GoogleAuthSourceDisposition::ProvisioningOnly,
        provisioning: GoogleAuthSourceDisposition::Allowed,
        rationale: "file-based creds are setup-time only; connector runtime must not depend on local credential files",
    },
    GoogleAuthSourcePolicy {
        source: GoogleAuthSourceKind::EncryptedLocalCredentials,
        runtime: GoogleAuthSourceDisposition::Rejected,
        provisioning: GoogleAuthSourceDisposition::Rejected,
        rationale: "connector-owned encrypted local credential stores conflict with FCP secret residency model",
    },
    GoogleAuthSourcePolicy {
        source: GoogleAuthSourceKind::DefaultCredentials,
        runtime: GoogleAuthSourceDisposition::ProvisioningOnly,
        provisioning: GoogleAuthSourceDisposition::Allowed,
        rationale: "default credential discovery belongs in host provisioning paths, not connector runtime",
    },
    GoogleAuthSourcePolicy {
        source: GoogleAuthSourceKind::ApplicationDefaultCredentials,
        runtime: GoogleAuthSourceDisposition::ProvisioningOnly,
        provisioning: GoogleAuthSourceDisposition::Allowed,
        rationale: "ADC evaluation is host/policy controlled and should materialize runtime-safe credential references",
    },
];

/// Return the canonical Google auth source matrix.
#[must_use]
pub const fn google_auth_source_policies() -> &'static [GoogleAuthSourcePolicy] {
    &GOOGLE_AUTH_SOURCE_POLICIES
}

/// Auth-chain errors.
#[derive(Debug, thiserror::Error)]
pub enum GoogleAuthError {
    /// Configuration validation failure.
    #[error("invalid google auth configuration: {message}")]
    InvalidConfig {
        /// Validation failure details.
        message: String,
    },

    /// Multiple auth sources selected simultaneously.
    #[error("expected exactly one auth source but found {count}")]
    ExactlyOneSourceRequired {
        /// Number of selected sources.
        count: usize,
    },

    /// Source selected in an incompatible context.
    #[error("auth source `{auth_source}` is not allowed for `{context}`: {reason}")]
    SourceNotAllowed {
        /// Rejected source kind.
        auth_source: GoogleAuthSourceKind,
        /// Evaluation context.
        context: GoogleAuthContext,
        /// Policy rationale.
        reason: &'static str,
    },

    /// Refresh-token exchange failed.
    #[error("oauth refresh exchange failed: {message}")]
    OAuthRefreshExchange {
        /// Upstream exchange failure summary.
        message: String,
    },

    /// Refreshed token does not satisfy required scopes.
    #[error(
        "refreshed token missing required scopes: [{missing}] (granted: [{granted}])",
        missing = .missing.join(", "),
        granted = .granted.join(", ")
    )]
    MissingRequiredScopes {
        /// Missing required scopes.
        missing: Vec<String>,
        /// Granted scope set from token response.
        granted: Vec<String>,
    },
}

/// Refresh-token exchange input.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleRefreshExchangeRequest {
    /// OAuth client id.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: String,
    /// Refresh token value.
    pub refresh_token: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Requested scope set.
    pub requested_scopes: Vec<String>,
}

/// Refresh-token exchange output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleRefreshExchangeResult {
    /// Materialized access token.
    pub access_token: String,
    /// Granted scopes from token response.
    pub granted_scopes: Vec<String>,
}

/// Pluggable refresh-token exchange contract.
pub trait GoogleRefreshTokenExchanger: Send + Sync {
    /// Exchange a refresh token for an access token.
    fn exchange<'a>(
        &'a self,
        request: &'a GoogleRefreshExchangeRequest,
    ) -> Pin<
        Box<dyn Future<Output = Result<GoogleRefreshExchangeResult, GoogleAuthError>> + Send + 'a>,
    >;
}

/// `fcp-oauth`-backed refresh-token exchanger.
#[derive(Debug, Default)]
pub struct FcpOAuthRefreshTokenExchanger;

impl GoogleRefreshTokenExchanger for FcpOAuthRefreshTokenExchanger {
    fn exchange<'a>(
        &'a self,
        request: &'a GoogleRefreshExchangeRequest,
    ) -> Pin<
        Box<dyn Future<Output = Result<GoogleRefreshExchangeResult, GoogleAuthError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut config = OAuth2Config::new(
                request.client_id.clone(),
                request.client_secret.clone(),
                "https://accounts.google.com/o/oauth2/v2/auth",
                request.token_url.clone(),
            )
            .with_auth_style(AuthStyle::Post);

            if !request.requested_scopes.is_empty() {
                config = config.with_token_param("scope", request.requested_scopes.join(" "));
            }

            let client = OAuth2Client::new(config).map_err(|error| {
                GoogleAuthError::OAuthRefreshExchange {
                    message: error.to_string(),
                }
            })?;
            let tokens = client
                .refresh_tokens(&request.refresh_token)
                .await
                .map_err(|error| GoogleAuthError::OAuthRefreshExchange {
                    message: error.to_string(),
                })?;

            Ok(GoogleRefreshExchangeResult {
                access_token: tokens.access_token().to_string(),
                granted_scopes: tokens.scopes().to_vec(),
            })
        })
    }
}

/// Refresh-token source details.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleOAuthRefreshSource {
    /// OAuth client id.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: String,
    /// Refresh token value.
    pub refresh_token: String,
    /// Token endpoint URL.
    pub token_url: String,
}

/// Selected auth source from provider chain.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GoogleAuthSource {
    /// Explicit access token.
    AccessToken {
        /// Bearer token value.
        access_token: String,
    },
    /// Secretless credential reference.
    CredentialId {
        /// Credential handle.
        credential_id: CredentialId,
    },
    /// Refresh-token exchange source.
    OAuthRefresh(GoogleOAuthRefreshSource),
    /// Explicit local credentials file.
    CredentialsFile {
        /// File path.
        path: String,
    },
    /// Local encrypted credential store.
    EncryptedLocalCredentials {
        /// Store/profile identifier.
        profile: String,
    },
    /// Provider default credentials chain.
    DefaultCredentials,
    /// Application Default Credentials chain.
    ApplicationDefaultCredentials,
}

impl GoogleAuthSource {
    /// Source kind for policy lookup.
    #[must_use]
    pub const fn kind(&self) -> GoogleAuthSourceKind {
        match self {
            Self::AccessToken { .. } => GoogleAuthSourceKind::AccessToken,
            Self::CredentialId { .. } => GoogleAuthSourceKind::CredentialId,
            Self::OAuthRefresh(_) => GoogleAuthSourceKind::OAuthRefresh,
            Self::CredentialsFile { .. } => GoogleAuthSourceKind::CredentialsFile,
            Self::EncryptedLocalCredentials { .. } => {
                GoogleAuthSourceKind::EncryptedLocalCredentials
            }
            Self::DefaultCredentials => GoogleAuthSourceKind::DefaultCredentials,
            Self::ApplicationDefaultCredentials => {
                GoogleAuthSourceKind::ApplicationDefaultCredentials
            }
        }
    }
}

/// Parsed Google auth selection with shared metadata.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleAuthSelection {
    /// Selected source.
    pub source: GoogleAuthSource,
    /// Required scopes (used for refresh exchange validation).
    pub required_scopes: Vec<String>,
    /// Optional quota project for billing/attribution propagation.
    pub quota_project_id: Option<String>,
}

impl GoogleAuthSelection {
    /// Parse connector-runtime auth configuration and enforce source policy.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleAuthError`] if parsing, precedence, or policy validation fails.
    pub fn from_connector_config(params: &serde_json::Value) -> Result<Self, GoogleAuthError> {
        Self::from_config(params, GoogleAuthContext::ConnectorRuntime)
    }

    /// Parse auth configuration for a specific context.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleAuthError`] if parsing, precedence, or policy validation fails.
    pub fn from_config(
        params: &serde_json::Value,
        context: GoogleAuthContext,
    ) -> Result<Self, GoogleAuthError> {
        let mut selected_sources = Vec::new();

        if let Some(access_token) = parse_access_token(params)? {
            selected_sources.push(GoogleAuthSource::AccessToken { access_token });
        }
        if let Some(credential_id) = parse_credential_id(params)? {
            selected_sources.push(GoogleAuthSource::CredentialId { credential_id });
        }
        if let Some(refresh_source) = parse_oauth_refresh_source(params)? {
            selected_sources.push(GoogleAuthSource::OAuthRefresh(refresh_source));
        }
        if let Some(path) = parse_credentials_file_source(params)? {
            selected_sources.push(GoogleAuthSource::CredentialsFile { path });
        }
        if let Some(profile) = parse_encrypted_local_credentials_source(params)? {
            selected_sources.push(GoogleAuthSource::EncryptedLocalCredentials { profile });
        }
        if parse_default_credentials_source(params)? {
            selected_sources.push(GoogleAuthSource::DefaultCredentials);
        }
        if parse_adc_source(params)? {
            selected_sources.push(GoogleAuthSource::ApplicationDefaultCredentials);
        }

        if selected_sources.len() != 1 {
            return Err(GoogleAuthError::ExactlyOneSourceRequired {
                count: selected_sources.len(),
            });
        }

        let Some(source) = selected_sources.pop() else {
            return Err(GoogleAuthError::ExactlyOneSourceRequired { count: 0 });
        };
        ensure_source_allowed(source.kind(), context)?;

        Ok(Self {
            source,
            required_scopes: parse_required_scopes(params)?,
            quota_project_id: parse_quota_project_id(params)?,
        })
    }

    /// Source kind helper.
    #[must_use]
    pub const fn source_kind(&self) -> GoogleAuthSourceKind {
        self.source.kind()
    }

    /// Quota project header for this selection.
    #[must_use]
    pub fn quota_project_header(&self) -> Option<(&'static str, &str)> {
        self.quota_project_id
            .as_deref()
            .map(|value| (GOOGLE_QUOTA_PROJECT_HEADER, value))
    }

    /// Materialize runtime auth using the default `fcp-oauth` exchanger.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleAuthError`] if source cannot be materialized or scope checks fail.
    pub async fn materialize(&self) -> Result<GoogleMaterializedAuth, GoogleAuthError> {
        let exchanger = FcpOAuthRefreshTokenExchanger;
        self.materialize_with(&exchanger).await
    }

    /// Materialize runtime auth using a caller-supplied refresh exchanger.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleAuthError`] if source cannot be materialized or scope checks fail.
    pub async fn materialize_with(
        &self,
        exchanger: &dyn GoogleRefreshTokenExchanger,
    ) -> Result<GoogleMaterializedAuth, GoogleAuthError> {
        match &self.source {
            GoogleAuthSource::AccessToken { access_token } => {
                Ok(GoogleMaterializedAuth::BearerToken {
                    access_token: access_token.clone(),
                    source: GoogleAuthSourceKind::AccessToken,
                    granted_scopes: Vec::new(),
                    quota_project_id: self.quota_project_id.clone(),
                })
            }
            GoogleAuthSource::CredentialId { credential_id } => {
                Ok(GoogleMaterializedAuth::CredentialReference {
                    credential_id: *credential_id,
                    quota_project_id: self.quota_project_id.clone(),
                })
            }
            GoogleAuthSource::OAuthRefresh(refresh_source) => {
                let request = GoogleRefreshExchangeRequest {
                    client_id: refresh_source.client_id.clone(),
                    client_secret: refresh_source.client_secret.clone(),
                    refresh_token: refresh_source.refresh_token.clone(),
                    token_url: refresh_source.token_url.clone(),
                    requested_scopes: self.required_scopes.clone(),
                };
                let result = exchanger.exchange(&request).await?;
                let granted_scopes = normalize_scope_list(result.granted_scopes);
                let missing = missing_scopes(&self.required_scopes, &granted_scopes);
                if !missing.is_empty() {
                    return Err(GoogleAuthError::MissingRequiredScopes {
                        missing,
                        granted: granted_scopes,
                    });
                }

                Ok(GoogleMaterializedAuth::BearerToken {
                    access_token: result.access_token,
                    source: GoogleAuthSourceKind::OAuthRefresh,
                    granted_scopes,
                    quota_project_id: self.quota_project_id.clone(),
                })
            }
            other => Err(GoogleAuthError::SourceNotAllowed {
                auth_source: other.kind(),
                context: GoogleAuthContext::ConnectorRuntime,
                reason: source_policy(other.kind()).rationale,
            }),
        }
    }
}

/// Runtime auth output.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GoogleMaterializedAuth {
    /// Bearer-token auth.
    BearerToken {
        /// Access token value.
        access_token: String,
        /// Source used to produce this token.
        source: GoogleAuthSourceKind,
        /// Granted scope set (refresh path only; empty for direct token mode).
        granted_scopes: Vec<String>,
        /// Optional quota project id.
        quota_project_id: Option<String>,
    },
    /// Secretless credential-reference auth.
    CredentialReference {
        /// Credential id for egress injection.
        credential_id: CredentialId,
        /// Optional quota project id.
        quota_project_id: Option<String>,
    },
}

impl GoogleMaterializedAuth {
    /// Access token when this is bearer mode.
    #[must_use]
    pub fn access_token(&self) -> Option<&str> {
        match self {
            Self::BearerToken { access_token, .. } => Some(access_token.as_str()),
            Self::CredentialReference { .. } => None,
        }
    }

    /// Credential id when this is secretless reference mode.
    #[must_use]
    pub const fn credential_id(&self) -> Option<CredentialId> {
        match self {
            Self::BearerToken { .. } => None,
            Self::CredentialReference { credential_id, .. } => Some(*credential_id),
        }
    }

    /// Granted scopes when this is bearer mode.
    #[must_use]
    pub fn granted_scopes(&self) -> &[String] {
        match self {
            Self::BearerToken { granted_scopes, .. } => granted_scopes.as_slice(),
            Self::CredentialReference { .. } => &[],
        }
    }

    /// Quota project id if present.
    #[must_use]
    pub fn quota_project_id(&self) -> Option<&str> {
        match self {
            Self::BearerToken {
                quota_project_id, ..
            }
            | Self::CredentialReference {
                quota_project_id, ..
            } => quota_project_id.as_deref(),
        }
    }

    /// Quota project header pair if present.
    #[must_use]
    pub fn quota_project_header(&self) -> Option<(&'static str, &str)> {
        self.quota_project_id()
            .map(|value| (GOOGLE_QUOTA_PROJECT_HEADER, value))
    }

    /// Apply auth + quota headers to a mutable `(name, value)` header list.
    pub fn apply_headers(&self, headers: &mut Vec<(String, String)>) {
        match self {
            Self::BearerToken { access_token, .. } => {
                upsert_header(
                    headers,
                    GOOGLE_AUTHORIZATION_HEADER,
                    format!("Bearer {access_token}"),
                );
            }
            Self::CredentialReference { credential_id, .. } => {
                upsert_header(headers, FCP_CREDENTIAL_ID_HEADER, credential_id.to_string());
            }
        }
        apply_quota_project_header(headers, self.quota_project_id());
    }
}

/// Apply quota project header, replacing any existing value case-insensitively.
pub fn apply_quota_project_header(
    headers: &mut Vec<(String, String)>,
    quota_project_id: Option<&str>,
) {
    let Some(quota_project_id) = quota_project_id else {
        return;
    };
    upsert_header(
        headers,
        GOOGLE_QUOTA_PROJECT_HEADER,
        quota_project_id.to_string(),
    );
}

fn source_policy(source: GoogleAuthSourceKind) -> &'static GoogleAuthSourcePolicy {
    google_auth_source_policies()
        .iter()
        .find(|policy| policy.source == source)
        .expect("source policy matrix must cover all source kinds")
}

fn source_disposition(
    source: GoogleAuthSourceKind,
    context: GoogleAuthContext,
) -> GoogleAuthSourceDisposition {
    let policy = source_policy(source);
    match context {
        GoogleAuthContext::ConnectorRuntime => policy.runtime,
        GoogleAuthContext::ProvisioningSetup => policy.provisioning,
    }
}

fn ensure_source_allowed(
    source: GoogleAuthSourceKind,
    context: GoogleAuthContext,
) -> Result<(), GoogleAuthError> {
    let disposition = source_disposition(source, context);
    if matches!(disposition, GoogleAuthSourceDisposition::Allowed) {
        return Ok(());
    }

    Err(GoogleAuthError::SourceNotAllowed {
        auth_source: source,
        context,
        reason: source_policy(source).rationale,
    })
}

fn parse_access_token(params: &serde_json::Value) -> Result<Option<String>, GoogleAuthError> {
    let token = parse_optional_string_field(params, "token")?;
    let access_token = parse_optional_string_field(params, "access_token")?;

    match (token, access_token) {
        (Some(token), Some(access_token)) if token != access_token => {
            Err(GoogleAuthError::InvalidConfig {
                message: "`token` and `access_token` must match when both are provided".to_string(),
            })
        }
        (Some(token), Some(_) | None) => Ok(Some(token)),
        (None, Some(access_token)) => Ok(Some(access_token)),
        (None, None) => Ok(None),
    }
}

fn parse_credential_id(
    params: &serde_json::Value,
) -> Result<Option<CredentialId>, GoogleAuthError> {
    let Some(raw) = parse_optional_string_field(params, "credential_id")? else {
        return Ok(None);
    };
    let credential_id = CredentialId::parse(&raw).map_err(|_| GoogleAuthError::InvalidConfig {
        message: "`credential_id` must be a valid UUID".to_string(),
    })?;
    Ok(Some(credential_id))
}

fn parse_oauth_refresh_source(
    params: &serde_json::Value,
) -> Result<Option<GoogleOAuthRefreshSource>, GoogleAuthError> {
    let Some(value) = params.get("oauth_refresh") else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or_else(|| GoogleAuthError::InvalidConfig {
            message: "`oauth_refresh` must be an object".to_string(),
        })?;

    let required_string = |key: &str| -> Result<String, GoogleAuthError> {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| GoogleAuthError::InvalidConfig {
                message: format!("`oauth_refresh.{key}` is required"),
            })
    };

    let token_url = object
        .get("token_url")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_GOOGLE_OAUTH_TOKEN_URL);
    validate_token_url(token_url)?;

    Ok(Some(GoogleOAuthRefreshSource {
        client_id: required_string("client_id")?,
        client_secret: required_string("client_secret")?,
        refresh_token: required_string("refresh_token")?,
        token_url: token_url.to_string(),
    }))
}

fn parse_credentials_file_source(
    params: &serde_json::Value,
) -> Result<Option<String>, GoogleAuthError> {
    parse_optional_string_field(params, "credentials_file")
}

fn parse_encrypted_local_credentials_source(
    params: &serde_json::Value,
) -> Result<Option<String>, GoogleAuthError> {
    let Some(value) = params.get("encrypted_local_credentials") else {
        return Ok(None);
    };

    match value {
        serde_json::Value::Bool(enabled) => {
            if *enabled {
                Ok(Some("encrypted_local_credentials".to_string()))
            } else {
                Ok(None)
            }
        }
        serde_json::Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(GoogleAuthError::InvalidConfig {
                    message: "`encrypted_local_credentials` must not be empty".to_string(),
                });
            }
            Ok(Some(trimmed.to_string()))
        }
        serde_json::Value::Object(object) => {
            let profile = object
                .get("profile")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("encrypted_local_credentials");
            Ok(Some(profile.to_string()))
        }
        _ => Err(GoogleAuthError::InvalidConfig {
            message: "`encrypted_local_credentials` must be bool, string, or object".to_string(),
        }),
    }
}

fn parse_default_credentials_source(params: &serde_json::Value) -> Result<bool, GoogleAuthError> {
    Ok(parse_optional_bool_field(params, "default_credentials")?.unwrap_or(false))
}

fn parse_adc_source(params: &serde_json::Value) -> Result<bool, GoogleAuthError> {
    let adc = parse_optional_bool_field(params, "adc")?.unwrap_or(false);
    let application_default =
        parse_optional_bool_field(params, "application_default_credentials")?.unwrap_or(false);
    Ok(adc || application_default)
}

fn parse_required_scopes(params: &serde_json::Value) -> Result<Vec<String>, GoogleAuthError> {
    let Some(value) = params.get("required_scopes") else {
        return Ok(Vec::new());
    };

    let values = value
        .as_array()
        .ok_or_else(|| GoogleAuthError::InvalidConfig {
            message: "`required_scopes` must be an array of non-empty strings".to_string(),
        })?;

    let mut scopes = Vec::with_capacity(values.len());
    for value in values {
        let raw = value
            .as_str()
            .ok_or_else(|| GoogleAuthError::InvalidConfig {
                message: "`required_scopes` must contain only strings".to_string(),
            })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(GoogleAuthError::InvalidConfig {
                message: "`required_scopes` entries must not be empty".to_string(),
            });
        }
        scopes.push(trimmed.to_string());
    }

    Ok(normalize_scope_list(scopes))
}

fn parse_quota_project_id(params: &serde_json::Value) -> Result<Option<String>, GoogleAuthError> {
    let Some(value) = params.get("quota_project_id") else {
        return Ok(None);
    };

    let raw = value
        .as_str()
        .ok_or_else(|| GoogleAuthError::InvalidConfig {
            message: "`quota_project_id` must be a string".to_string(),
        })?
        .trim();

    if raw.is_empty() {
        return Err(GoogleAuthError::InvalidConfig {
            message: "`quota_project_id` must not be empty".to_string(),
        });
    }

    Ok(Some(raw.to_string()))
}

fn parse_optional_string_field(
    params: &serde_json::Value,
    field: &str,
) -> Result<Option<String>, GoogleAuthError> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };

    let raw = value
        .as_str()
        .ok_or_else(|| GoogleAuthError::InvalidConfig {
            message: format!("`{field}` must be a string"),
        })?
        .trim();
    if raw.is_empty() {
        return Err(GoogleAuthError::InvalidConfig {
            message: format!("`{field}` must not be empty"),
        });
    }

    Ok(Some(raw.to_string()))
}

fn parse_optional_bool_field(
    params: &serde_json::Value,
    field: &str,
) -> Result<Option<bool>, GoogleAuthError> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };
    let parsed = value
        .as_bool()
        .ok_or_else(|| GoogleAuthError::InvalidConfig {
            message: format!("`{field}` must be a boolean"),
        })?;
    Ok(Some(parsed))
}

fn validate_token_url(token_url: &str) -> Result<(), GoogleAuthError> {
    let parsed = Url::parse(token_url).map_err(|error| GoogleAuthError::InvalidConfig {
        message: format!("`oauth_refresh.token_url` is invalid: {error}"),
    })?;
    if parsed.scheme() == "https" {
        return Ok(());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| GoogleAuthError::InvalidConfig {
            message: "`oauth_refresh.token_url` must include a host".to_string(),
        })?;
    if is_local_test_host(host) {
        return Ok(());
    }

    Err(GoogleAuthError::InvalidConfig {
        message: "`oauth_refresh.token_url` must use https unless targeting localhost for tests"
            .to_string(),
    })
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn normalize_scope_list(scopes: Vec<String>) -> Vec<String> {
    let mut normalized: Vec<String> = scopes
        .into_iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

fn missing_scopes(required_scopes: &[String], granted_scopes: &[String]) -> Vec<String> {
    if required_scopes.is_empty() {
        return Vec::new();
    }

    let required: BTreeSet<&str> = required_scopes.iter().map(String::as_str).collect();
    let granted: BTreeSet<&str> = granted_scopes.iter().map(String::as_str).collect();

    required
        .difference(&granted)
        .map(|scope| (*scope).to_string())
        .collect()
}

fn upsert_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    headers.retain(|(existing_name, _)| !existing_name.eq_ignore_ascii_case(name));
    headers.push((name.to_string(), value));
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use fcp_async_core::runtime::block_on_sync;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Default)]
    struct FailIfCalledExchanger;

    impl GoogleRefreshTokenExchanger for FailIfCalledExchanger {
        fn exchange<'a>(
            &'a self,
            _request: &'a GoogleRefreshExchangeRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GoogleRefreshExchangeResult, GoogleAuthError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                Err(GoogleAuthError::OAuthRefreshExchange {
                    message: "refresh exchanger should not be called".to_string(),
                })
            })
        }
    }

    #[derive(Debug)]
    struct RecordingExchanger {
        response: GoogleRefreshExchangeResult,
        request: Mutex<Option<GoogleRefreshExchangeRequest>>,
    }

    impl RecordingExchanger {
        fn new(response: GoogleRefreshExchangeResult) -> Self {
            Self {
                response,
                request: Mutex::new(None),
            }
        }

        fn recorded_request(&self) -> Option<GoogleRefreshExchangeRequest> {
            self.request.lock().expect("recorded request lock").clone()
        }
    }

    impl GoogleRefreshTokenExchanger for RecordingExchanger {
        fn exchange<'a>(
            &'a self,
            request: &'a GoogleRefreshExchangeRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GoogleRefreshExchangeResult, GoogleAuthError>>
                    + Send
                    + 'a,
            >,
        > {
            let captured_request = request.clone();
            let response = self.response.clone();
            Box::pin(async move {
                *self.request.lock().expect("record request lock") = Some(captured_request);
                Ok(response)
            })
        }
    }

    fn header_value<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn access_token_source_materializes_bearer_and_quota_header() {
        let selection = GoogleAuthSelection::from_connector_config(&json!({
            "token": "  ya29.access-token  ",
            "quota_project_id": "billing-project"
        }))
        .expect("parse access token config");
        assert_eq!(selection.source_kind(), GoogleAuthSourceKind::AccessToken);

        let materialized = block_on_sync(selection.materialize_with(&FailIfCalledExchanger))
            .expect("runtime for materialization")
            .expect("materialize access token");

        assert_eq!(materialized.access_token(), Some("ya29.access-token"));
        assert_eq!(materialized.quota_project_id(), Some("billing-project"));

        let mut headers = vec![("Authorization".to_string(), "Bearer stale".to_string())];
        materialized.apply_headers(&mut headers);
        assert_eq!(
            header_value(&headers, GOOGLE_AUTHORIZATION_HEADER),
            Some("Bearer ya29.access-token")
        );
        assert_eq!(
            header_value(&headers, GOOGLE_QUOTA_PROJECT_HEADER),
            Some("billing-project")
        );
    }

    #[test]
    fn credential_id_source_materializes_secretless_reference() {
        let credential_id = CredentialId::new();
        let selection = GoogleAuthSelection::from_connector_config(&json!({
            "credential_id": credential_id.to_string(),
            "quota_project_id": "project-123"
        }))
        .expect("parse credential_id config");
        assert_eq!(selection.source_kind(), GoogleAuthSourceKind::CredentialId);

        let materialized = block_on_sync(selection.materialize_with(&FailIfCalledExchanger))
            .expect("runtime for materialization")
            .expect("materialize credential_id");

        assert_eq!(materialized.credential_id(), Some(credential_id));
        assert_eq!(materialized.quota_project_id(), Some("project-123"));

        let mut headers = Vec::new();
        materialized.apply_headers(&mut headers);
        assert_eq!(
            header_value(&headers, FCP_CREDENTIAL_ID_HEADER),
            Some(credential_id.to_string().as_str())
        );
        assert_eq!(
            header_value(&headers, GOOGLE_QUOTA_PROJECT_HEADER),
            Some("project-123")
        );
    }

    #[test]
    fn refresh_source_exchanges_token_and_validates_required_scopes() {
        let selection = GoogleAuthSelection::from_connector_config(&json!({
            "oauth_refresh": {
                "client_id": "client-id",
                "client_secret": "client-secret",
                "refresh_token": "refresh-token"
            },
            "required_scopes": ["scope.b", "scope.a", "scope.a"],
            "quota_project_id": "billing-project"
        }))
        .expect("parse refresh config");
        assert_eq!(selection.source_kind(), GoogleAuthSourceKind::OAuthRefresh);

        let exchanger = RecordingExchanger::new(GoogleRefreshExchangeResult {
            access_token: "ya29.refreshed".to_string(),
            granted_scopes: vec![
                "scope.a".to_string(),
                "scope.b".to_string(),
                "scope.b".to_string(),
            ],
        });

        let materialized = block_on_sync(selection.materialize_with(&exchanger))
            .expect("runtime for materialization")
            .expect("materialize refreshed token");

        assert_eq!(materialized.access_token(), Some("ya29.refreshed"));
        assert_eq!(
            materialized.granted_scopes(),
            &vec!["scope.a".to_string(), "scope.b".to_string()]
        );
        assert_eq!(
            materialized.quota_project_header(),
            Some((GOOGLE_QUOTA_PROJECT_HEADER, "billing-project"))
        );

        let request = exchanger
            .recorded_request()
            .expect("captured refresh request");
        assert_eq!(request.client_id, "client-id");
        assert_eq!(request.client_secret, "client-secret");
        assert_eq!(request.refresh_token, "refresh-token");
        assert_eq!(request.token_url, DEFAULT_GOOGLE_OAUTH_TOKEN_URL);
        assert_eq!(
            request.requested_scopes,
            vec!["scope.a".to_string(), "scope.b".to_string()]
        );
    }

    #[test]
    fn refresh_source_rejects_missing_required_scope() {
        let selection = GoogleAuthSelection::from_connector_config(&json!({
            "oauth_refresh": {
                "client_id": "client-id",
                "client_secret": "client-secret",
                "refresh_token": "refresh-token"
            },
            "required_scopes": ["scope.a", "scope.b"]
        }))
        .expect("parse refresh config");

        let exchanger = RecordingExchanger::new(GoogleRefreshExchangeResult {
            access_token: "ya29.refreshed".to_string(),
            granted_scopes: vec!["scope.a".to_string()],
        });

        let err = block_on_sync(selection.materialize_with(&exchanger))
            .expect("runtime for materialization")
            .expect_err("missing scope must fail");
        assert!(
            matches!(
                &err,
                GoogleAuthError::MissingRequiredScopes { missing, granted }
                if missing == &vec!["scope.b".to_string()]
                    && granted == &vec!["scope.a".to_string()]
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn runtime_rejects_credentials_file_source_but_provisioning_allows_it() {
        let params = json!({
            "credentials_file": "/tmp/google-creds.json"
        });

        let runtime_err =
            GoogleAuthSelection::from_connector_config(&params).expect_err("runtime should reject");
        assert!(
            matches!(
                runtime_err,
                GoogleAuthError::SourceNotAllowed {
                    auth_source: GoogleAuthSourceKind::CredentialsFile,
                    context: GoogleAuthContext::ConnectorRuntime,
                    ..
                }
            ),
            "unexpected error: {runtime_err}"
        );

        let provisioning =
            GoogleAuthSelection::from_config(&params, GoogleAuthContext::ProvisioningSetup)
                .expect("provisioning should allow credentials file");
        assert_eq!(
            provisioning.source_kind(),
            GoogleAuthSourceKind::CredentialsFile
        );
    }

    #[test]
    fn exactly_one_source_is_enforced() {
        let params = json!({
            "token": "ya29.token",
            "credential_id": CredentialId::new().to_string()
        });

        let err =
            GoogleAuthSelection::from_connector_config(&params).expect_err("multiple source error");
        assert!(
            matches!(err, GoogleAuthError::ExactlyOneSourceRequired { count: 2 }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn quota_project_header_is_upserted_case_insensitively() {
        let mut headers = vec![
            ("X-Goog-User-Project".to_string(), "old-project".to_string()),
            ("x-extra".to_string(), "1".to_string()),
        ];

        apply_quota_project_header(&mut headers, Some("new-project"));

        assert_eq!(
            header_value(&headers, GOOGLE_QUOTA_PROJECT_HEADER),
            Some("new-project")
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(GOOGLE_QUOTA_PROJECT_HEADER))
                .count(),
            1
        );
    }

    #[test]
    fn source_policy_matrix_covers_all_known_source_kinds() {
        let covered: BTreeSet<GoogleAuthSourceKind> = google_auth_source_policies()
            .iter()
            .map(|policy| policy.source)
            .collect();

        let expected = BTreeSet::from([
            GoogleAuthSourceKind::AccessToken,
            GoogleAuthSourceKind::CredentialId,
            GoogleAuthSourceKind::OAuthRefresh,
            GoogleAuthSourceKind::CredentialsFile,
            GoogleAuthSourceKind::EncryptedLocalCredentials,
            GoogleAuthSourceKind::DefaultCredentials,
            GoogleAuthSourceKind::ApplicationDefaultCredentials,
        ]);

        assert_eq!(covered, expected);
    }

    // ── GoogleAuthContext tests ──────────────────────────────────────────

    #[test]
    fn auth_context_display_connector_runtime() {
        let ctx = GoogleAuthContext::ConnectorRuntime;
        assert_eq!(ctx.to_string(), "connector_runtime");
    }

    #[test]
    fn auth_context_display_provisioning_setup() {
        let ctx = GoogleAuthContext::ProvisioningSetup;
        assert_eq!(ctx.to_string(), "provisioning_setup");
    }

    #[test]
    fn auth_context_clone_and_eq() {
        let a = GoogleAuthContext::ConnectorRuntime;
        let b = a;
        assert_eq!(a, b);

        let c = GoogleAuthContext::ProvisioningSetup;
        let d = c;
        assert_eq!(c, d);

        assert_ne!(a, c);
    }

    // ── GoogleAuthSourceKind tests ──────────────────────────────────────

    #[test]
    fn source_kind_ordering() {
        let kinds = [
            GoogleAuthSourceKind::AccessToken,
            GoogleAuthSourceKind::CredentialId,
            GoogleAuthSourceKind::OAuthRefresh,
            GoogleAuthSourceKind::CredentialsFile,
            GoogleAuthSourceKind::EncryptedLocalCredentials,
            GoogleAuthSourceKind::DefaultCredentials,
            GoogleAuthSourceKind::ApplicationDefaultCredentials,
        ];
        // Derived Ord uses variant declaration order, so each successive kind
        // should be strictly greater than the previous one.
        for window in kinds.windows(2) {
            assert!(
                window[0] < window[1],
                "{:?} should be less than {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn source_kind_clone_and_eq() {
        let a = GoogleAuthSourceKind::OAuthRefresh;
        let b = a;
        assert_eq!(a, b);

        let c = GoogleAuthSourceKind::CredentialId;
        assert_ne!(a, c);
    }

    // ── GoogleAuthSourceDisposition tests ───────────────────────────────

    #[test]
    fn disposition_all_variants_debug() {
        let allowed = format!("{:?}", GoogleAuthSourceDisposition::Allowed);
        assert!(allowed.contains("Allowed"), "got: {allowed}");

        let prov = format!("{:?}", GoogleAuthSourceDisposition::ProvisioningOnly);
        assert!(prov.contains("ProvisioningOnly"), "got: {prov}");

        let rejected = format!("{:?}", GoogleAuthSourceDisposition::Rejected);
        assert!(rejected.contains("Rejected"), "got: {rejected}");
    }

    // ── GoogleAuthSourcePolicy tests ────────────────────────────────────

    #[test]
    fn source_policy_matrix_has_correct_count() {
        let policies = google_auth_source_policies();
        assert_eq!(
            policies.len(),
            7,
            "expected exactly 7 policy rows (one per source kind)"
        );
    }

    #[test]
    fn source_policies_all_contexts_covered() {
        // Every source kind should have a disposition for both runtime and provisioning.
        for policy in google_auth_source_policies() {
            // Ensure the runtime and provisioning dispositions are not some
            // impossible default — they must each be one of the three valid values.
            let valid = [
                GoogleAuthSourceDisposition::Allowed,
                GoogleAuthSourceDisposition::ProvisioningOnly,
                GoogleAuthSourceDisposition::Rejected,
            ];
            assert!(
                valid.contains(&policy.runtime),
                "runtime disposition for {:?} must be valid",
                policy.source
            );
            assert!(
                valid.contains(&policy.provisioning),
                "provisioning disposition for {:?} must be valid",
                policy.source
            );
            assert!(
                !policy.rationale.is_empty(),
                "rationale for {:?} must not be empty",
                policy.source
            );
        }
    }

    // ── GoogleAuthError Display tests ───────────────────────────────────

    #[test]
    fn auth_error_display_no_source_selected() {
        let err = GoogleAuthError::ExactlyOneSourceRequired { count: 0 };
        let msg = err.to_string();
        assert!(
            msg.contains("expected exactly one auth source but found 0"),
            "got: {msg}"
        );
    }

    #[test]
    fn auth_error_display_multiple_sources() {
        let err = GoogleAuthError::ExactlyOneSourceRequired { count: 3 };
        let msg = err.to_string();
        assert!(
            msg.contains("expected exactly one auth source but found 3"),
            "got: {msg}"
        );
    }

    #[test]
    fn auth_error_display_source_rejected() {
        let err = GoogleAuthError::SourceNotAllowed {
            auth_source: GoogleAuthSourceKind::EncryptedLocalCredentials,
            context: GoogleAuthContext::ConnectorRuntime,
            reason: "test reason",
        };
        let msg = err.to_string();
        assert!(msg.contains("encrypted_local_credentials"), "got: {msg}");
        assert!(msg.contains("connector_runtime"), "got: {msg}");
        assert!(msg.contains("test reason"), "got: {msg}");
    }

    #[test]
    fn auth_error_display_scope_mismatch() {
        let err = GoogleAuthError::MissingRequiredScopes {
            missing: vec!["scope.a".to_string(), "scope.c".to_string()],
            granted: vec!["scope.b".to_string()],
        };
        let msg = err.to_string();
        assert!(msg.contains("scope.a"), "got: {msg}");
        assert!(msg.contains("scope.c"), "got: {msg}");
        assert!(msg.contains("scope.b"), "got: {msg}");
    }

    #[test]
    fn auth_error_display_materialization_failed() {
        let err = GoogleAuthError::OAuthRefreshExchange {
            message: "network timeout".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("oauth refresh exchange failed"), "got: {msg}");
        assert!(msg.contains("network timeout"), "got: {msg}");
    }

    // ── GoogleRefreshExchangeRequest tests ──────────────────────────────

    #[test]
    fn refresh_exchange_request_fields() {
        let request = GoogleRefreshExchangeRequest {
            client_id: "cid".to_string(),
            client_secret: "csec".to_string(),
            refresh_token: "rt".to_string(),
            token_url: "https://example.com/token".to_string(),
            requested_scopes: vec!["s1".to_string(), "s2".to_string()],
        };
        assert_eq!(request.client_id, "cid");
        assert_eq!(request.client_secret, "csec");
        assert_eq!(request.refresh_token, "rt");
        assert_eq!(request.token_url, "https://example.com/token");
        assert_eq!(request.requested_scopes.len(), 2);

        // Clone + PartialEq
        let cloned = request.clone();
        assert_eq!(request, cloned);
    }

    #[test]
    fn refresh_exchange_result_with_scopes() {
        let result = GoogleRefreshExchangeResult {
            access_token: "ya29.tok".to_string(),
            granted_scopes: vec![
                "https://www.googleapis.com/auth/gmail.readonly".to_string(),
                "https://www.googleapis.com/auth/calendar".to_string(),
            ],
        };
        assert_eq!(result.access_token, "ya29.tok");
        assert_eq!(result.granted_scopes.len(), 2);
        assert!(
            result
                .granted_scopes
                .contains(&"https://www.googleapis.com/auth/gmail.readonly".to_string())
        );

        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    // ── GoogleAuthSource tests ──────────────────────────────────────────

    #[test]
    fn auth_source_access_token_construction() {
        let source = GoogleAuthSource::AccessToken {
            access_token: "ya29.test".to_string(),
        };
        assert_eq!(source.kind(), GoogleAuthSourceKind::AccessToken);
        // Clone + PartialEq
        let cloned = source.clone();
        assert_eq!(source, cloned);
    }

    #[test]
    fn auth_source_credential_id_construction() {
        let cid = CredentialId::new();
        let source = GoogleAuthSource::CredentialId { credential_id: cid };
        assert_eq!(source.kind(), GoogleAuthSourceKind::CredentialId);
        let cloned = source.clone();
        assert_eq!(source, cloned);
    }

    #[test]
    fn auth_source_oauth_refresh_construction() {
        let source = GoogleAuthSource::OAuthRefresh(GoogleOAuthRefreshSource {
            client_id: "cid".to_string(),
            client_secret: "csec".to_string(),
            refresh_token: "rt".to_string(),
            token_url: DEFAULT_GOOGLE_OAUTH_TOKEN_URL.to_string(),
        });
        assert_eq!(source.kind(), GoogleAuthSourceKind::OAuthRefresh);
        let cloned = source.clone();
        assert_eq!(source, cloned);
    }

    // ── GoogleAuthSelection from_config tests ───────────────────────────

    #[test]
    fn auth_selection_from_config_empty_params_fails() {
        let params = json!({});
        let err = GoogleAuthSelection::from_connector_config(&params)
            .expect_err("empty params should fail");
        assert!(
            matches!(err, GoogleAuthError::ExactlyOneSourceRequired { count: 0 }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn auth_selection_from_config_access_token() {
        let params = json!({ "access_token": "ya29.direct" });
        let sel = GoogleAuthSelection::from_connector_config(&params).expect("access_token config");
        assert_eq!(sel.source_kind(), GoogleAuthSourceKind::AccessToken);
        assert!(sel.required_scopes.is_empty());
        assert!(sel.quota_project_id.is_none());
    }

    #[test]
    fn auth_selection_from_config_credential_id() {
        let cid = CredentialId::new();
        let params = json!({ "credential_id": cid.to_string() });
        let sel =
            GoogleAuthSelection::from_connector_config(&params).expect("credential_id config");
        assert_eq!(sel.source_kind(), GoogleAuthSourceKind::CredentialId);
    }

    #[test]
    fn auth_selection_from_config_multiple_sources_rejected() {
        let cid = CredentialId::new();
        let params = json!({
            "access_token": "ya29.tok",
            "credential_id": cid.to_string(),
            "credentials_file": "/tmp/creds.json"
        });
        let err = GoogleAuthSelection::from_connector_config(&params)
            .expect_err("multiple sources should fail");
        match err {
            GoogleAuthError::ExactlyOneSourceRequired { count } => {
                assert!(count >= 2, "expected count >= 2, got {count}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn auth_selection_rejects_credentials_file_at_runtime() {
        let params = json!({ "credentials_file": "/tmp/creds.json" });
        let err = GoogleAuthSelection::from_connector_config(&params)
            .expect_err("credentials_file at runtime should fail");
        assert!(
            matches!(
                &err,
                GoogleAuthError::SourceNotAllowed {
                    auth_source: GoogleAuthSourceKind::CredentialsFile,
                    context: GoogleAuthContext::ConnectorRuntime,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    // ── GoogleMaterializedAuth tests ────────────────────────────────────

    #[test]
    fn materialized_auth_access_token_getter() {
        let mat = GoogleMaterializedAuth::BearerToken {
            access_token: "ya29.hello".to_string(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        };
        assert_eq!(mat.access_token(), Some("ya29.hello"));
        assert!(mat.credential_id().is_none());
    }

    #[test]
    fn materialized_auth_credential_id_getter() {
        let cid = CredentialId::new();
        let mat = GoogleMaterializedAuth::CredentialReference {
            credential_id: cid,
            quota_project_id: None,
        };
        assert_eq!(mat.credential_id(), Some(cid));
        assert!(mat.access_token().is_none());
    }

    #[test]
    fn materialized_auth_granted_scopes() {
        let mat = GoogleMaterializedAuth::BearerToken {
            access_token: "ya29.tok".to_string(),
            source: GoogleAuthSourceKind::OAuthRefresh,
            granted_scopes: vec!["scope.a".to_string(), "scope.b".to_string()],
            quota_project_id: None,
        };
        assert_eq!(
            mat.granted_scopes(),
            &["scope.a".to_string(), "scope.b".to_string()]
        );

        // CredentialReference returns empty scopes
        let cid = CredentialId::new();
        let cred_ref = GoogleMaterializedAuth::CredentialReference {
            credential_id: cid,
            quota_project_id: None,
        };
        assert!(cred_ref.granted_scopes().is_empty());
    }

    #[test]
    fn materialized_auth_apply_headers_bearer() {
        let mat = GoogleMaterializedAuth::BearerToken {
            access_token: "ya29.test-apply".to_string(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        };
        let mut headers = Vec::new();
        mat.apply_headers(&mut headers);
        assert_eq!(
            header_value(&headers, GOOGLE_AUTHORIZATION_HEADER),
            Some("Bearer ya29.test-apply")
        );
        // No quota project header when None
        assert!(header_value(&headers, GOOGLE_QUOTA_PROJECT_HEADER).is_none());
    }

    #[test]
    fn materialized_auth_apply_headers_credential_id() {
        let cid = CredentialId::new();
        let mat = GoogleMaterializedAuth::CredentialReference {
            credential_id: cid,
            quota_project_id: None,
        };
        let mut headers = Vec::new();
        mat.apply_headers(&mut headers);
        assert_eq!(
            header_value(&headers, FCP_CREDENTIAL_ID_HEADER),
            Some(cid.to_string().as_str())
        );
        assert!(header_value(&headers, GOOGLE_AUTHORIZATION_HEADER).is_none());
    }

    #[test]
    fn materialized_auth_apply_headers_with_quota_project() {
        let mat = GoogleMaterializedAuth::BearerToken {
            access_token: "ya29.quota".to_string(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: Some("my-billing-project".to_string()),
        };
        let mut headers = Vec::new();
        mat.apply_headers(&mut headers);
        assert_eq!(
            header_value(&headers, GOOGLE_QUOTA_PROJECT_HEADER),
            Some("my-billing-project")
        );
        assert_eq!(
            header_value(&headers, GOOGLE_AUTHORIZATION_HEADER),
            Some("Bearer ya29.quota")
        );
    }

    #[test]
    fn materialized_auth_apply_headers_quota_project_case_insensitive() {
        let mat = GoogleMaterializedAuth::BearerToken {
            access_token: "ya29.case".to_string(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: Some("new-project".to_string()),
        };
        // Pre-populate with a differently-cased quota header
        let mut headers = vec![
            ("X-Goog-User-Project".to_string(), "old-project".to_string()),
            ("x-custom".to_string(), "keep-me".to_string()),
        ];
        mat.apply_headers(&mut headers);

        // The old header should have been replaced (case-insensitive upsert)
        let quota_count = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(GOOGLE_QUOTA_PROJECT_HEADER))
            .count();
        assert_eq!(
            quota_count, 1,
            "should have exactly one quota header after upsert"
        );
        assert_eq!(
            header_value(&headers, GOOGLE_QUOTA_PROJECT_HEADER),
            Some("new-project")
        );
        // Custom header should be preserved
        assert_eq!(header_value(&headers, "x-custom"), Some("keep-me"));
    }
}
