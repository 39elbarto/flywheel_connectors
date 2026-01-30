//! OAuth 2.0 implementation.
//!
//! Supports authorization code flow (with PKCE) and client credentials flow.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    GrantType, OAuthError, OAuthResult, OAuthTokens, Pkce, PkceMethod, ResponseMode, TokenResponse,
};

/// OAuth authentication style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthStyle {
    /// HTTP Basic Authentication (Authorization header).
    Basic,
    /// Request body parameters (client_id/client_secret).
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
#[derive(Debug, Clone)]
pub struct OAuth2Client {
    config: OAuth2Config,
    http_client: Client,
}

impl OAuth2Client {
    /// Create a new OAuth 2.0 client.
    ///
    /// # Errors
    /// Returns `OAuthError::HttpError` if the HTTP client fails to build.
    pub fn new(config: OAuth2Config) -> OAuthResult<Self> {
        let http_client = Client::builder().timeout(config.timeout).build()?;

        Ok(Self {
            config,
            http_client,
        })
    }

    /// Create with a custom HTTP client.
    #[must_use]
    pub const fn with_http_client(config: OAuth2Config, http_client: Client) -> Self {
        Self {
            config,
            http_client,
        }
    }

    /// Generate authorization URL without PKCE.
    ///
    /// Returns (authorization_url, state).
    pub fn authorization_url(&self, scopes: &[&str]) -> OAuthResult<(String, String)> {
        let state = generate_state();
        let url = self.build_auth_url(scopes, &state, None)?;
        Ok((url, state))
    }

    /// Generate authorization URL with PKCE.
    ///
    /// Returns (authorization_url, state, pkce).
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
    pub async fn exchange_code(&self, code: &str) -> OAuthResult<OAuthTokens> {
        self.exchange_code_internal(code, None).await
    }

    /// Exchange authorization code for tokens with PKCE verification.
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
        let mut request = self.http_client.post(&self.config.token_url);

        match self.config.auth_style {
            AuthStyle::Basic => {
                if let Some(secret) = &self.config.client_secret {
                    request = request.basic_auth(&self.config.client_id, Some(secret));
                } else {
                    request = request.basic_auth(&self.config.client_id, Some(""));
                }
            }
            AuthStyle::Post => {
                params.insert("client_id", self.config.client_id.clone());
                if let Some(secret) = &self.config.client_secret {
                    params.insert("client_secret", secret.clone());
                }
            }
        }

        let response = request.form(&params).send().await?;

        if !response.status().is_success() {
            let error: TokenErrorResponse =
                response
                    .json()
                    .await
                    .unwrap_or_else(|_| TokenErrorResponse {
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

        let token_response: TokenResponse = response.json().await?;
        Ok(OAuthTokens::from_response(token_response))
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &OAuth2Config {
        &self.config
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
    pub fn from_query(query: &str) -> OAuthResult<Self> {
        serde_urlencoded::from_str(query)
            .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))
    }

    /// Parse callback from URL.
    pub fn from_url(url: &str) -> OAuthResult<Self> {
        let parsed = Url::parse(url)?;
        let query = parsed.query().unwrap_or("");
        Self::from_query(query)
    }

    /// Validate the callback and extract the code.
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
}
