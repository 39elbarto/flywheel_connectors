//! OAuth 2.0 implementation.
//!
//! Supports authorization code flow (with PKCE) and client credentials flow.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use asupersync::http::h1::{HttpClient, HttpClientBuilder, Method, Response as HttpResponse};
use base64::{Engine, engine::general_purpose::STANDARD};
use fcp_async_core::time;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    GrantType, OAuthError, OAuthResult, OAuthTokens, Pkce, PkceMethod, ResponseMode, TokenResponse,
};

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";

/// OAuth authentication style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthStyle {
    /// HTTP Basic Authentication (Authorization header).
    Basic,
    /// Request body parameters (`client_id/client_secret`).
    #[default]
    Post,
}

impl std::fmt::Display for AuthStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Post => write!(f, "post"),
        }
    }
}

/// OAuth 2.0 configuration.
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// Client ID.
    pub client_id: String,
    /// Client secret (optional for public clients).
    pub client_secret: Option<String>,
    /// Authorization endpoint URL.
    pub authorization_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Redirect URI for authorization code flow.
    pub redirect_uri: Option<String>,
    /// Default scopes to request.
    pub default_scopes: Vec<String>,
    /// Whether to use PKCE.
    pub use_pkce: bool,
    /// PKCE method.
    pub pkce_method: PkceMethod,
    /// Response mode for authorization.
    pub response_mode: ResponseMode,
    /// Authentication style for token requests.
    pub auth_style: AuthStyle,
    /// Additional authorization parameters.
    pub extra_auth_params: HashMap<String, String>,
    /// Additional token parameters.
    pub extra_token_params: HashMap<String, String>,
    /// HTTP client timeout.
    pub timeout: Duration,
}

impl OAuth2Config {
    /// Create a new OAuth 2.0 configuration.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            redirect_uri: None,
            default_scopes: Vec::new(),
            use_pkce: true,
            pkce_method: PkceMethod::S256,
            response_mode: ResponseMode::Query,
            auth_style: AuthStyle::Post,
            extra_auth_params: HashMap::new(),
            extra_token_params: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Create configuration for a public client (no secret).
    #[must_use]
    pub fn public_client(
        client_id: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            redirect_uri: None,
            default_scopes: Vec::new(),
            use_pkce: true, // PKCE is required for public clients
            pkce_method: PkceMethod::S256,
            response_mode: ResponseMode::Query,
            auth_style: AuthStyle::Post,
            extra_auth_params: HashMap::new(),
            extra_token_params: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Set the redirect URI.
    #[must_use]
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Set default scopes.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.default_scopes = scopes;
        self
    }

    /// Enable or disable PKCE.
    #[must_use]
    pub const fn with_pkce(mut self, enabled: bool) -> Self {
        self.use_pkce = enabled;
        self
    }

    /// Set PKCE method.
    #[must_use]
    pub const fn with_pkce_method(mut self, method: PkceMethod) -> Self {
        self.pkce_method = method;
        self
    }

    /// Set response mode.
    #[must_use]
    pub const fn with_response_mode(mut self, mode: ResponseMode) -> Self {
        self.response_mode = mode;
        self
    }

    /// Set authentication style.
    #[must_use]
    pub const fn with_auth_style(mut self, style: AuthStyle) -> Self {
        self.auth_style = style;
        self
    }

    /// Add extra authorization parameter.
    #[must_use]
    pub fn with_auth_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_auth_params.insert(key.into(), value.into());
        self
    }

    /// Add extra token parameter.
    #[must_use]
    pub fn with_token_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_token_params.insert(key.into(), value.into());
        self
    }

    /// Set timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// OAuth 2.0 client.
#[derive(Clone)]
pub struct OAuth2Client {
    config: OAuth2Config,
    http_client: Arc<HttpClient>,
}

impl std::fmt::Debug for OAuth2Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2Client")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl OAuth2Client {
    /// Create a new OAuth 2.0 client.
    ///
    /// # Errors
    /// Returns an error when the configured authorization URL, token URL,
    /// or redirect URI is invalid.
    pub fn new(config: OAuth2Config) -> OAuthResult<Self> {
        Url::parse(&config.authorization_url)?;
        Url::parse(&config.token_url)?;
        if let Some(redirect_uri) = config.redirect_uri.as_deref() {
            Url::parse(redirect_uri)?;
        }

        Ok(Self {
            config,
            http_client: Arc::new(
                HttpClientBuilder::new()
                    .user_agent("fcp-oauth/0.1.0")
                    .build(),
            ),
        })
    }

    /// Create with a custom HTTP client.
    #[must_use]
    pub fn with_http_client(config: OAuth2Config, http_client: HttpClient) -> Self {
        Self {
            config,
            http_client: Arc::new(http_client),
        }
    }

    /// Generate authorization URL without PKCE.
    ///
    /// Returns (`authorization_url`, `state`).
    ///
    /// # Errors
    /// Returns an error when the configured authorization endpoint is invalid.
    pub fn authorization_url(&self, scopes: &[&str]) -> OAuthResult<(String, String)> {
        let state = generate_state();
        let url = self.build_auth_url(scopes, &state, None)?;
        Ok((url, state))
    }

    /// Generate authorization URL with PKCE.
    ///
    /// Returns (`authorization_url`, `state`, `pkce`).
    ///
    /// # Errors
    /// Returns an error when the configured authorization endpoint is invalid.
    pub fn authorization_url_with_pkce(
        &self,
        scopes: &[&str],
    ) -> OAuthResult<(String, String, Pkce)> {
        let state = generate_state();
        let pkce = Pkce::with_method(self.config.pkce_method);
        let url = self.build_auth_url(scopes, &state, Some(&pkce))?;
        Ok((url, state, pkce))
    }

    /// Build the authorization URL.
    fn build_auth_url(
        &self,
        scopes: &[&str],
        state: &str,
        pkce: Option<&Pkce>,
    ) -> OAuthResult<String> {
        let mut url = Url::parse(&self.config.authorization_url)?;

        {
            let mut params = url.query_pairs_mut();

            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.config.client_id);
            params.append_pair("state", state);

            if let Some(redirect_uri) = &self.config.redirect_uri {
                params.append_pair("redirect_uri", redirect_uri);
            }

            // Combine default scopes with requested scopes
            let all_scopes: Vec<&str> = self
                .config
                .default_scopes
                .iter()
                .map(String::as_str)
                .chain(scopes.iter().copied())
                .collect();

            if !all_scopes.is_empty() {
                params.append_pair("scope", &all_scopes.join(" "));
            }

            // PKCE parameters
            if let Some(pkce) = pkce {
                params.append_pair("code_challenge", pkce.challenge());
                params.append_pair("code_challenge_method", &pkce.method().to_string());
            }

            // Response mode (if not default)
            if self.config.response_mode != ResponseMode::Query {
                params.append_pair("response_mode", &self.config.response_mode.to_string());
            }

            // Extra parameters
            for (key, value) in &self.config.extra_auth_params {
                params.append_pair(key, value);
            }
        }

        Ok(url.to_string())
    }

    /// Exchange authorization code for tokens.
    ///
    /// # Errors
    /// Returns an error when token exchange fails or the response is invalid.
    pub async fn exchange_code(&self, code: &str) -> OAuthResult<OAuthTokens> {
        self.exchange_code_internal(code, None).await
    }

    /// Exchange authorization code for tokens with PKCE verification.
    ///
    /// # Errors
    /// Returns an error when token exchange fails or the response is invalid.
    pub async fn exchange_code_with_pkce(
        &self,
        code: &str,
        pkce: &Pkce,
    ) -> OAuthResult<OAuthTokens> {
        self.exchange_code_internal(code, Some(pkce)).await
    }

    /// Internal code exchange implementation.
    async fn exchange_code_internal(
        &self,
        code: &str,
        pkce: Option<&Pkce>,
    ) -> OAuthResult<OAuthTokens> {
        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::AuthorizationCode.to_string());
        params.insert("code", code.to_string());

        if let Some(redirect_uri) = &self.config.redirect_uri {
            params.insert("redirect_uri", redirect_uri.clone());
        }

        if let Some(pkce) = pkce {
            params.insert("code_verifier", pkce.verifier().to_string());
        }

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        self.token_request(params).await
    }

    /// Get tokens using client credentials flow.
    ///
    /// # Errors
    /// Returns an error when client credentials are misconfigured, token exchange fails,
    /// or the token response is invalid.
    pub async fn client_credentials(&self, scopes: &[&str]) -> OAuthResult<OAuthTokens> {
        // Only require secret if not public client (though client creds usually implies confidential)
        // If public client tries client creds, it might fail at provider, but we shouldn't block it here if secret is None
        // But RFC says client credentials grant is for confidential clients.
        if self.config.client_secret.is_none() {
            return Err(OAuthError::InvalidConfig(
                "Client secret required for client credentials flow".into(),
            ));
        }

        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::ClientCredentials.to_string());

        let all_scopes: Vec<&str> = self
            .config
            .default_scopes
            .iter()
            .map(String::as_str)
            .chain(scopes.iter().copied())
            .collect();

        if !all_scopes.is_empty() {
            params.insert("scope", all_scopes.join(" "));
        }

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        self.token_request(params).await
    }

    /// Refresh tokens using a refresh token.
    ///
    /// # Errors
    /// Returns an error when token refresh fails or the token response is invalid.
    pub async fn refresh_tokens(&self, refresh_token: &str) -> OAuthResult<OAuthTokens> {
        let mut params = HashMap::new();
        params.insert("grant_type", GrantType::RefreshToken.to_string());
        params.insert("refresh_token", refresh_token.to_string());

        // Extra parameters
        for (key, value) in &self.config.extra_token_params {
            params.insert(key, value.clone());
        }

        self.token_request(params).await
    }

    /// Make a token request.
    async fn token_request(&self, mut params: HashMap<&str, String>) -> OAuthResult<OAuthTokens> {
        let mut headers = vec![
            ("Content-Type".to_string(), FORM_CONTENT_TYPE.to_string()),
            ("Accept".to_string(), JSON_CONTENT_TYPE.to_string()),
        ];

        match self.config.auth_style {
            AuthStyle::Basic => {
                let credentials = format!(
                    "{}:{}",
                    self.config.client_id,
                    self.config.client_secret.as_deref().unwrap_or("")
                );
                headers.push((
                    "Authorization".to_string(),
                    format!("Basic {}", STANDARD.encode(credentials)),
                ));
            }
            AuthStyle::Post => {
                params.insert("client_id", self.config.client_id.clone());
                if let Some(secret) = &self.config.client_secret {
                    params.insert("client_secret", secret.clone());
                }
            }
        }

        let body = serde_urlencoded::to_string(&params)
            .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))?;
        let response = self
            .send_request(
                Method::Post,
                &self.config.token_url,
                headers,
                body.into_bytes(),
            )
            .await?;

        if !response.is_success() {
            let error: TokenErrorResponse =
                response.json().unwrap_or_else(|_| TokenErrorResponse {
                    error: "unknown_error".to_string(),
                    error_description: None,
                    error_uri: None,
                });

            return Err(OAuthError::TokenExchangeFailed(format!(
                "{}: {}",
                error.error,
                error.error_description.unwrap_or_default()
            )));
        }

        let token_response: TokenResponse = response.json()?;
        Ok(OAuthTokens::from_response(token_response))
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &OAuth2Config {
        &self.config
    }

    async fn send_request(
        &self,
        method: Method,
        url: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> OAuthResult<HttpResponse> {
        match time::timeout(
            self.config.timeout,
            self.http_client.request(method, url, headers, body),
        )
        .await
        {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(OAuthError::from_http_client_error(&error)),
            Err(error) => Err(OAuthError::from_async_error(error, self.config.timeout)),
        }
    }
}

/// OAuth 2.0 error response.
#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    error_description: Option<String>,
    #[allow(dead_code)] // Part of OAuth spec, kept for debugging/future use
    error_uri: Option<String>,
}

/// Authorization callback parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCallback {
    /// Authorization code.
    pub code: Option<String>,
    /// State parameter.
    pub state: Option<String>,
    /// Error code.
    pub error: Option<String>,
    /// Error description.
    pub error_description: Option<String>,
    /// Error URI.
    pub error_uri: Option<String>,
}

impl AuthorizationCallback {
    /// Parse callback from query string.
    ///
    /// # Errors
    /// Returns an error when the query string cannot be deserialized into callback fields.
    pub fn from_query(query: &str) -> OAuthResult<Self> {
        serde_urlencoded::from_str(query)
            .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))
    }

    /// Parse callback from URL.
    ///
    /// # Errors
    /// Returns an error when the URL is invalid or callback parameters cannot be parsed.
    pub fn from_url(url: &str) -> OAuthResult<Self> {
        let parsed = Url::parse(url)?;
        let query = parsed.query().unwrap_or("");
        Self::from_query(query)
    }

    /// Validate the callback and extract the code.
    ///
    /// # Errors
    /// Returns an error for provider error callbacks, state mismatches, or missing `code`.
    pub fn validate(&self, expected_state: &str) -> OAuthResult<String> {
        // Check for errors first
        if let Some(error) = &self.error {
            return Err(OAuthError::AuthorizationError {
                error: error.clone(),
                description: self.error_description.clone().unwrap_or_default(),
                error_uri: self.error_uri.clone(),
            });
        }

        // Validate state
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing state parameter".into()))?;

        if state != expected_state {
            return Err(OAuthError::StateMismatch {
                expected: expected_state.to_string(),
                actual: state.clone(),
            });
        }

        // Extract code
        self.code
            .clone()
            .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing authorization code".into()))
    }
}

/// Generate a cryptographically random state parameter.
fn generate_state() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn run_with_tokio_reactor<F, T>(future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio test runtime")
            .block_on(future)
    }

    fn test_config() -> OAuth2Config {
        OAuth2Config::new(
            "test_client_id",
            "test_client_secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://localhost:3000/callback")
    }

    #[test]
    fn test_authorization_url() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();

        let (url, state) = client.authorization_url(&["read", "write"]).unwrap();

        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=test_client_id"));
        assert!(url.contains(&format!("state={state}")));
        assert!(url.contains("scope=read+write"));
        assert!(url.contains("redirect_uri="));
    }

    #[test]
    fn test_authorization_url_with_pkce() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();

        let (url, _state, pkce) = client.authorization_url_with_pkce(&["read"]).unwrap();

        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(!pkce.verifier().is_empty());
    }

    #[test]
    fn test_callback_validation() {
        let callback = AuthorizationCallback {
            code: Some("auth_code_123".to_string()),
            state: Some("expected_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let code = callback.validate("expected_state").unwrap();
        assert_eq!(code, "auth_code_123");
    }

    #[test]
    fn test_callback_state_mismatch() {
        let callback = AuthorizationCallback {
            code: Some("auth_code_123".to_string()),
            state: Some("wrong_state".to_string()),
            error: None,
            error_description: None,
            error_uri: None,
        };

        let result = callback.validate("expected_state");
        assert!(matches!(result, Err(OAuthError::StateMismatch { .. })));
    }

    #[test]
    fn test_callback_error() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".to_string()),
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
            error_uri: None,
        };

        let result = callback.validate("state");
        assert!(matches!(result, Err(OAuthError::AuthorizationError { .. })));
    }

    #[test]
    fn test_public_client_config() {
        let config = OAuth2Config::public_client(
            "public_client",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );

        assert!(config.client_secret.is_none());
        assert!(config.use_pkce); // PKCE should be enabled by default for public clients
    }

    // ── New tests ──

    #[test]
    fn test_auth_style_display() {
        assert_eq!(AuthStyle::Basic.to_string(), "basic");
        assert_eq!(AuthStyle::Post.to_string(), "post");
    }

    #[test]
    fn test_auth_style_default_is_post() {
        assert_eq!(AuthStyle::default(), AuthStyle::Post);
    }

    #[test]
    fn test_oauth2_config_builder_chain() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("https://localhost/callback")
        .with_scopes(vec!["read".into(), "write".into()])
        .with_pkce(false)
        .with_pkce_method(PkceMethod::Plain)
        .with_response_mode(ResponseMode::FormPost)
        .with_auth_style(AuthStyle::Basic)
        .with_auth_param("prompt", "consent")
        .with_token_param("audience", "api")
        .with_timeout(Duration::from_secs(60));

        assert_eq!(
            config.redirect_uri,
            Some("https://localhost/callback".into())
        );
        assert_eq!(config.default_scopes, vec!["read", "write"]);
        assert!(!config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::Plain);
        assert_eq!(config.response_mode, ResponseMode::FormPost);
        assert_eq!(config.auth_style, AuthStyle::Basic);
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            Some(&"consent".to_string())
        );
        assert_eq!(
            config.extra_token_params.get("audience"),
            Some(&"api".to_string())
        );
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_callback_from_query() {
        let callback = AuthorizationCallback::from_query("code=abc&state=xyz").unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
        assert_eq!(callback.state, Some("xyz".to_string()));
    }

    #[test]
    fn test_callback_from_url() {
        let callback =
            AuthorizationCallback::from_url("https://localhost/callback?code=abc&state=xyz")
                .unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
        assert_eq!(callback.state, Some("xyz".to_string()));
    }

    #[test]
    fn test_callback_missing_state() {
        let callback = AuthorizationCallback {
            code: Some("abc".into()),
            state: None,
            error: None,
            error_description: None,
            error_uri: None,
        };
        let result = callback.validate("expected");
        assert!(matches!(result, Err(OAuthError::InvalidTokenResponse(_))));
    }

    #[test]
    fn test_callback_missing_code() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let result = callback.validate("state");
        assert!(matches!(result, Err(OAuthError::InvalidTokenResponse(_))));
    }

    #[test]
    fn test_authorization_url_with_default_scopes() {
        let config = test_config().with_scopes(vec!["profile".into()]);
        let client = OAuth2Client::new(config).unwrap();

        let (url, _) = client.authorization_url(&["email"]).unwrap();
        // Should contain both default and requested scopes
        assert!(url.contains("scope=profile+email"));
    }

    #[test]
    fn test_authorization_url_with_form_post_response_mode() {
        let config = test_config().with_response_mode(ResponseMode::FormPost);
        let client = OAuth2Client::new(config).unwrap();

        let (url, _) = client.authorization_url(&["read"]).unwrap();
        assert!(url.contains("response_mode=form_post"));
    }

    #[test]
    fn test_oauth2_client_config_accessor() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        assert_eq!(client.config().client_id, "test_client_id");
    }

    #[test]
    fn test_exchange_code_with_mock_server() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=authorization_code"))
                .and(body_string_contains("code=auth-code-123"))
                .and(body_string_contains(
                    "redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Fcallback",
                ))
                .and(body_string_contains("client_id=test_client_id"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "access-123",
                    "token_type": "Bearer",
                    "refresh_token": "refresh-123",
                    "expires_in": 3600,
                    "scope": "read write"
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client.exchange_code("auth-code-123").await.unwrap();
            assert_eq!(tokens.access_token(), "access-123");
            assert_eq!(tokens.refresh_token(), Some("refresh-123"));
            assert_eq!(tokens.scopes(), &["read", "write"]);
        });
    }

    #[test]
    fn test_exchange_code_with_pkce_sends_verifier() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            let pkce = Pkce::with_method(PkceMethod::S256);
            let expected_verifier = pkce.verifier().to_string();

            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=authorization_code"))
                .and(body_string_contains("code=auth-code-pkce"))
                .and(body_string_contains(format!(
                    "code_verifier={expected_verifier}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "pkce-access",
                    "token_type": "Bearer",
                    "refresh_token": "pkce-refresh",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::public_client(
                "public-client",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client
                .exchange_code_with_pkce("auth-code-pkce", &pkce)
                .await
                .unwrap();
            assert_eq!(tokens.access_token(), "pkce-access");
            assert_eq!(tokens.refresh_token(), Some("pkce-refresh"));
        });
    }

    #[test]
    fn test_refresh_tokens_with_mock_server() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains("refresh_token=refresh-token-xyz"))
                .and(body_string_contains("client_id=test_client_id"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "fresh-access-token",
                    "token_type": "Bearer",
                    "refresh_token": "new-refresh-token",
                    "expires_in": 7200
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();

            let tokens = client.refresh_tokens("refresh-token-xyz").await.unwrap();
            assert_eq!(tokens.access_token(), "fresh-access-token");
            assert_eq!(tokens.refresh_token(), Some("new-refresh-token"));
        });
    }

    #[test]
    fn test_exchange_code_maps_error_response() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "authorization code expired"
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "test_client_id",
                "test_client_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_redirect_uri("https://localhost:3000/callback");
            let client = OAuth2Client::new(config).unwrap();

            let error = client.exchange_code("expired-code").await.unwrap_err();
            let OAuthError::TokenExchangeFailed(message) = error else {
                panic!("expected token exchange error")
            };
            assert!(message.contains("invalid_grant"));
            assert!(message.contains("authorization code expired"));
        });
    }

    // ── New batch: OAuth2Config construction and builder ──

    #[test]
    fn test_config_new_defaults() {
        let config = OAuth2Config::new("id", "secret", "https://a.com/auth", "https://a.com/tok");
        assert_eq!(config.client_id, "id");
        assert_eq!(config.client_secret, Some("secret".to_string()));
        assert_eq!(config.authorization_url, "https://a.com/auth");
        assert_eq!(config.token_url, "https://a.com/tok");
        assert!(config.redirect_uri.is_none());
        assert!(config.default_scopes.is_empty());
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert_eq!(config.response_mode, ResponseMode::Query);
        assert_eq!(config.auth_style, AuthStyle::Post);
        assert!(config.extra_auth_params.is_empty());
        assert!(config.extra_token_params.is_empty());
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_public_client_defaults() {
        let config = OAuth2Config::public_client("pub", "https://a.com/auth", "https://a.com/tok");
        assert_eq!(config.client_id, "pub");
        assert!(config.client_secret.is_none());
        assert!(config.use_pkce);
        assert_eq!(config.pkce_method, PkceMethod::S256);
        assert_eq!(config.auth_style, AuthStyle::Post);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_clone() {
        let config = test_config()
            .with_scopes(vec!["read".into()])
            .with_auth_param("prompt", "login");
        let cloned = config.clone();
        assert_eq!(config.client_id, cloned.client_id);
        assert_eq!(config.client_secret, cloned.client_secret);
        assert_eq!(config.default_scopes, cloned.default_scopes);
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            cloned.extra_auth_params.get("prompt")
        );
    }

    #[test]
    fn test_config_debug() {
        let config = test_config();
        let debug = format!("{config:?}");
        assert!(debug.contains("OAuth2Config"));
        assert!(debug.contains("test_client_id"));
    }

    #[test]
    fn test_config_with_multiple_auth_params() {
        let config = test_config()
            .with_auth_param("prompt", "consent")
            .with_auth_param("login_hint", "user@example.com")
            .with_auth_param("access_type", "offline");
        assert_eq!(config.extra_auth_params.len(), 3);
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            Some(&"consent".to_string())
        );
        assert_eq!(
            config.extra_auth_params.get("login_hint"),
            Some(&"user@example.com".to_string())
        );
        assert_eq!(
            config.extra_auth_params.get("access_type"),
            Some(&"offline".to_string())
        );
    }

    #[test]
    fn test_config_with_multiple_token_params() {
        let config = test_config()
            .with_token_param("audience", "https://api.example.com")
            .with_token_param("resource", "urn:example:resource");
        assert_eq!(config.extra_token_params.len(), 2);
    }

    // ── New batch: OAuth2Client creation and validation ──

    #[test]
    fn test_client_rejects_invalid_authorization_url() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "not-a-url",
            "https://auth.example.com/token",
        );
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_rejects_invalid_token_url() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "not-a-url",
        );
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_rejects_invalid_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .with_redirect_uri("://bad");
        let result = OAuth2Client::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_accepts_no_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        // No redirect_uri set — should succeed
        assert!(OAuth2Client::new(config).is_ok());
    }

    #[test]
    fn test_client_debug() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("OAuth2Client"));
        assert!(debug.contains("test_client_id"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_client_clone() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let cloned = client.clone();
        assert_eq!(cloned.config().client_id, "test_client_id");
    }

    // ── New batch: Authorization URL generation edge cases ──

    #[test]
    fn test_authorization_url_empty_scopes() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        // With no scopes, scope param should not appear
        assert!(!url.contains("scope="));
    }

    #[test]
    fn test_authorization_url_single_scope() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&["openid"]).unwrap();
        assert!(url.contains("scope=openid"));
    }

    #[test]
    fn test_authorization_url_many_scopes() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client
            .authorization_url(&["openid", "email", "profile", "offline_access"])
            .unwrap();
        assert!(url.contains("scope=openid+email+profile+offline_access"));
    }

    #[test]
    fn test_authorization_url_contains_redirect_uri() {
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        // redirect_uri should be URL-encoded
        assert!(url.contains("redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Fcallback"));
    }

    #[test]
    fn test_authorization_url_without_redirect_uri() {
        let config = OAuth2Config::new(
            "id",
            "secret",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(!url.contains("redirect_uri="));
    }

    #[test]
    fn test_authorization_url_state_is_unique() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (_, state1) = client.authorization_url(&[]).unwrap();
        let (_, state2) = client.authorization_url(&[]).unwrap();
        let (_, state3) = client.authorization_url(&[]).unwrap();
        assert_ne!(state1, state2);
        assert_ne!(state2, state3);
    }

    #[test]
    fn test_authorization_url_state_not_empty() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (_, state) = client.authorization_url(&[]).unwrap();
        assert!(!state.is_empty());
    }

    #[test]
    fn test_authorization_url_with_extra_auth_params() {
        let config = test_config()
            .with_auth_param("prompt", "consent")
            .with_auth_param("access_type", "offline");
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("access_type=offline"));
    }

    #[test]
    fn test_authorization_url_query_response_mode_not_in_url() {
        // Default response_mode is Query; it should NOT be appended
        let config = test_config();
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(!url.contains("response_mode="));
    }

    #[test]
    fn test_authorization_url_fragment_response_mode() {
        let config = test_config().with_response_mode(ResponseMode::Fragment);
        let client = OAuth2Client::new(config).unwrap();
        let (url, _) = client.authorization_url(&[]).unwrap();
        assert!(url.contains("response_mode=fragment"));
    }

    #[test]
    fn test_authorization_url_with_pkce_plain_method() {
        let config = test_config().with_pkce_method(PkceMethod::Plain);
        let client = OAuth2Client::new(config).unwrap();
        let (url, _, pkce) = client.authorization_url_with_pkce(&[]).unwrap();
        assert!(url.contains("code_challenge_method=plain"));
        // For plain method, challenge equals verifier
        assert_eq!(pkce.verifier(), pkce.challenge());
    }

    #[test]
    fn test_authorization_url_with_pkce_returns_unique_pkce() {
        let client = OAuth2Client::new(test_config()).unwrap();
        let (_, _, pkce1) = client.authorization_url_with_pkce(&[]).unwrap();
        let (_, _, pkce2) = client.authorization_url_with_pkce(&[]).unwrap();
        assert_ne!(pkce1.verifier(), pkce2.verifier());
    }

    // ── New batch: AuthorizationCallback edge cases ──

    #[test]
    fn test_callback_from_query_empty() {
        let callback = AuthorizationCallback::from_query("").unwrap();
        assert!(callback.code.is_none());
        assert!(callback.state.is_none());
        assert!(callback.error.is_none());
    }

    #[test]
    fn test_callback_from_url_no_query() {
        let callback = AuthorizationCallback::from_url("https://localhost/callback").unwrap();
        assert!(callback.code.is_none());
        assert!(callback.state.is_none());
    }

    #[test]
    fn test_callback_from_url_invalid_url() {
        let result = AuthorizationCallback::from_url("://bad");
        assert!(result.is_err());
    }

    #[test]
    fn test_callback_error_with_description_and_uri() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".into()),
            error: Some("server_error".into()),
            error_description: Some("Internal server error".into()),
            error_uri: Some("https://provider.com/errors/500".into()),
        };
        let result = callback.validate("state");
        match result {
            Err(OAuthError::AuthorizationError {
                error,
                description,
                error_uri,
            }) => {
                assert_eq!(error, "server_error");
                assert_eq!(description, "Internal server error");
                assert_eq!(
                    error_uri,
                    Some("https://provider.com/errors/500".to_string())
                );
            }
            other => panic!("expected AuthorizationError, got {other:?}"),
        }
    }

    #[test]
    fn test_callback_error_takes_precedence_over_code() {
        // If both error and code are present, error should be returned first
        let callback = AuthorizationCallback {
            code: Some("code".into()),
            state: Some("state".into()),
            error: Some("access_denied".into()),
            error_description: None,
            error_uri: None,
        };
        let result = callback.validate("state");
        assert!(matches!(result, Err(OAuthError::AuthorizationError { .. })));
    }

    #[test]
    fn test_callback_serde_roundtrip() {
        let callback = AuthorizationCallback {
            code: Some("code123".into()),
            state: Some("state456".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let json = serde_json::to_string(&callback).unwrap();
        let roundtrip: AuthorizationCallback = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.code, Some("code123".to_string()));
        assert_eq!(roundtrip.state, Some("state456".to_string()));
    }

    #[test]
    fn test_callback_clone() {
        let callback = AuthorizationCallback {
            code: Some("c".into()),
            state: Some("s".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let cloned = callback.clone();
        assert_eq!(callback.code, cloned.code);
        assert_eq!(callback.state, cloned.state);
    }

    #[test]
    fn test_callback_debug() {
        let callback = AuthorizationCallback {
            code: Some("c".into()),
            state: Some("s".into()),
            error: None,
            error_description: None,
            error_uri: None,
        };
        let debug = format!("{callback:?}");
        assert!(debug.contains("AuthorizationCallback"));
    }

    // ── New batch: AuthStyle ──

    #[test]
    fn test_auth_style_eq() {
        assert_eq!(AuthStyle::Basic, AuthStyle::Basic);
        assert_eq!(AuthStyle::Post, AuthStyle::Post);
        assert_ne!(AuthStyle::Basic, AuthStyle::Post);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_auth_style_clone_copy() {
        let style = AuthStyle::Basic;
        let copied = style;
        let cloned = style.clone();
        assert_eq!(style, copied);
        assert_eq!(style, cloned);
    }

    #[test]
    fn test_auth_style_debug() {
        let debug = format!("{:?}", AuthStyle::Basic);
        assert!(debug.contains("Basic"));
        let debug = format!("{:?}", AuthStyle::Post);
        assert!(debug.contains("Post"));
    }

    // ── New batch: Mock server flows ──

    #[test]
    fn test_client_credentials_requires_secret() {
        run_with_tokio_reactor(async {
            let config = OAuth2Config::public_client(
                "public",
                "https://auth.example.com/authorize",
                "https://auth.example.com/token",
            );
            let client = OAuth2Client::new(config).unwrap();
            let result = client.client_credentials(&["read"]).await;
            assert!(matches!(result, Err(OAuthError::InvalidConfig(_))));
        });
    }

    #[test]
    fn test_client_credentials_with_mock_server() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=client_credentials"))
                .and(body_string_contains("client_id=cc_client"))
                .and(body_string_contains("scope=api.read+api.write"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "cc-access-tok",
                    "token_type": "Bearer",
                    "expires_in": 1800
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "cc_client",
                "cc_secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client
                .client_credentials(&["api.read", "api.write"])
                .await
                .unwrap();
            assert_eq!(tokens.access_token(), "cc-access-tok");
            assert!(tokens.refresh_token().is_none());
        });
    }

    #[test]
    fn test_client_credentials_with_default_scopes() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=client_credentials"))
                .and(body_string_contains("scope=default.scope+extra.scope"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_scopes(vec!["default.scope".into()]);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.client_credentials(&["extra.scope"]).await.unwrap();
            assert_eq!(tokens.access_token(), "tok");
        });
    }

    #[test]
    fn test_exchange_code_error_non_json_body() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();
            let result = client.exchange_code("code").await;
            // Should get a TokenExchangeFailed with fallback error parsing
            assert!(matches!(result, Err(OAuthError::TokenExchangeFailed(_))));
        });
    }

    #[test]
    fn test_exchange_code_with_extra_token_params() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains(
                    "audience=https%3A%2F%2Fapi.example.com",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok-extra",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_token_param("audience", "https://api.example.com");
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert_eq!(tokens.access_token(), "tok-extra");
        });
    }

    #[test]
    fn test_refresh_with_extra_token_params() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(body_string_contains("grant_type=refresh_token"))
                .and(body_string_contains(
                    "audience=https%3A%2F%2Fapi.example.com",
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "refreshed-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_token_param("audience", "https://api.example.com");
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.refresh_tokens("old-refresh").await.unwrap();
            assert_eq!(tokens.access_token(), "refreshed-tok");
        });
    }

    #[test]
    fn test_token_response_without_refresh_token() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "no-refresh-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert!(tokens.refresh_token().is_none());
        });
    }

    #[test]
    fn test_token_response_with_scopes_parsed() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "tok",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "openid email profile"
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            );
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert_eq!(tokens.scopes(), &["openid", "email", "profile"]);
        });
    }

    #[test]
    fn test_basic_auth_style_sends_authorization_header() {
        run_with_tokio_reactor(async {
            let server = MockServer::start().await;
            // With Basic auth, client_id/secret should be in Authorization header, not body
            Mock::given(method("POST"))
                .and(path("/token"))
                .and(wiremock::matchers::header_exists("Authorization"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "basic-tok",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })))
                .mount(&server)
                .await;

            let config = OAuth2Config::new(
                "id",
                "secret",
                format!("{}/authorize", server.uri()),
                format!("{}/token", server.uri()),
            )
            .with_auth_style(AuthStyle::Basic);
            let client = OAuth2Client::new(config).unwrap();
            let tokens = client.exchange_code("code").await.unwrap();
            assert_eq!(tokens.access_token(), "basic-tok");
        });
    }

    // ── Expanded tests: OAuth2Config edge cases ──

    #[test]
    fn test_config_auth_param_overwrite() {
        let config = test_config()
            .with_auth_param("prompt", "login")
            .with_auth_param("prompt", "consent");
        assert_eq!(
            config.extra_auth_params.get("prompt"),
            Some(&"consent".to_string())
        );
    }

    #[test]
    fn test_config_token_param_overwrite() {
        let config = test_config()
            .with_token_param("audience", "v1")
            .with_token_param("audience", "v2");
        assert_eq!(
            config.extra_token_params.get("audience"),
            Some(&"v2".to_string())
        );
    }

    #[test]
    fn test_config_empty_scopes_vec() {
        let config = test_config().with_scopes(Vec::new());
        assert!(config.default_scopes.is_empty());
    }

    #[test]
    fn test_config_timeout_zero() {
        let config = test_config().with_timeout(Duration::from_secs(0));
        assert_eq!(config.timeout, Duration::from_secs(0));
    }

    #[test]
    fn test_config_timeout_large() {
        let config = test_config().with_timeout(Duration::from_secs(300));
        assert_eq!(config.timeout, Duration::from_secs(300));
    }

    // ── Expanded tests: AuthorizationCallback parsing ──

    #[test]
    fn test_callback_from_query_with_error() {
        let callback = AuthorizationCallback::from_query(
            "error=access_denied&error_description=User+denied&state=s",
        )
        .unwrap();
        assert_eq!(callback.error, Some("access_denied".to_string()));
        assert_eq!(
            callback.error_description,
            Some("User denied".to_string())
        );
        assert!(callback.code.is_none());
    }

    #[test]
    fn test_callback_from_query_url_encoded_values() {
        let callback =
            AuthorizationCallback::from_query("code=abc%20def&state=my%26state").unwrap();
        assert_eq!(callback.code, Some("abc def".to_string()));
        assert_eq!(callback.state, Some("my&state".to_string()));
    }

    #[test]
    fn test_callback_from_url_with_fragment_ignored() {
        // Fragments are not part of query string
        let callback = AuthorizationCallback::from_url(
            "https://localhost/callback?code=abc&state=xyz#extra",
        )
        .unwrap();
        assert_eq!(callback.code, Some("abc".to_string()));
    }

    #[test]
    fn test_callback_validate_error_without_description() {
        let callback = AuthorizationCallback {
            code: None,
            state: Some("state".into()),
            error: Some("invalid_scope".into()),
            error_description: None,
            error_uri: None,
        };
        let err = callback.validate("state").unwrap_err();
        if let OAuthError::AuthorizationError { description, .. } = err {
            assert!(description.is_empty());
        } else {
            panic!("wrong variant");
        }
    }

    // ── Expanded tests: generate_state ──

    #[test]
    fn test_generate_state_length() {
        let state = generate_state();
        // 32 bytes -> base64url no padding = 43 chars
        assert_eq!(state.len(), 43);
    }

    #[test]
    fn test_generate_state_valid_chars() {
        let state = generate_state();
        assert!(
            state
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn test_generate_state_uniqueness() {
        let s1 = generate_state();
        let s2 = generate_state();
        let s3 = generate_state();
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
    }

    // ── Expanded tests: OAuth2Client with custom HTTP client ──

    #[test]
    fn test_client_with_custom_http_client() {
        let config = test_config();
        let http_client = HttpClientBuilder::new().build();
        let client = OAuth2Client::with_http_client(config, http_client);
        assert_eq!(client.config().client_id, "test_client_id");
    }

    #[test]
    fn test_client_with_custom_http_client_config_accessor() {
        let config = test_config()
            .with_scopes(vec!["admin".into()])
            .with_auth_style(AuthStyle::Basic);
        let http_client = HttpClientBuilder::new().build();
        let client = OAuth2Client::with_http_client(config, http_client);
        assert_eq!(client.config().default_scopes, vec!["admin"]);
        assert_eq!(client.config().auth_style, AuthStyle::Basic);
    }
}
