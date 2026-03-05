//! OAuth 1.0a implementation.
//!
//! Supports the three-legged OAuth 1.0a flow used by Twitter and other providers.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha1::Sha1;
use url::Url;

use crate::{OAuthError, OAuthResult};

/// OAuth 1.0a configuration.
#[derive(Debug, Clone)]
pub struct OAuth1Config {
    /// Consumer key (API key).
    pub consumer_key: String,
    /// Consumer secret (API secret).
    pub consumer_secret: String,
    /// Request token URL.
    pub request_token_url: String,
    /// Authorization URL.
    pub authorization_url: String,
    /// Access token URL.
    pub access_token_url: String,
    /// Callback URL.
    pub callback_url: Option<String>,
}

impl OAuth1Config {
    /// Create a new OAuth 1.0a configuration.
    #[must_use]
    pub fn new(
        consumer_key: impl Into<String>,
        consumer_secret: impl Into<String>,
        request_token_url: impl Into<String>,
        authorization_url: impl Into<String>,
        access_token_url: impl Into<String>,
    ) -> Self {
        Self {
            consumer_key: consumer_key.into(),
            consumer_secret: consumer_secret.into(),
            request_token_url: request_token_url.into(),
            authorization_url: authorization_url.into(),
            access_token_url: access_token_url.into(),
            callback_url: None,
        }
    }

    /// Set callback URL.
    #[must_use]
    pub fn with_callback(mut self, url: impl Into<String>) -> Self {
        self.callback_url = Some(url.into());
        self
    }
}

/// OAuth 1.0a tokens.
#[derive(Debug, Clone)]
pub struct OAuth1Tokens {
    /// OAuth token.
    pub token: String,
    /// OAuth token secret.
    pub token_secret: String,
    /// User ID (if provided).
    pub user_id: Option<String>,
    /// Screen name (if provided).
    pub screen_name: Option<String>,
}

/// Request token from the initial OAuth 1.0a step.
#[derive(Debug, Clone)]
pub struct RequestToken {
    /// OAuth token.
    pub token: String,
    /// OAuth token secret.
    pub token_secret: String,
    /// Whether the callback was confirmed.
    pub callback_confirmed: bool,
}

/// OAuth 1.0a client.
#[derive(Debug, Clone)]
pub struct OAuth1Client {
    config: OAuth1Config,
    http_client: Client,
}

impl OAuth1Client {
    /// Create a new OAuth 1.0a client.
    #[must_use]
    pub fn new(config: OAuth1Config) -> Self {
        Self {
            config,
            http_client: Client::new(),
        }
    }

    /// Create with a custom HTTP client.
    #[must_use]
    pub const fn with_http_client(config: OAuth1Config, http_client: Client) -> Self {
        Self {
            config,
            http_client,
        }
    }

    /// Step 1: Get a request token.
    ///
    /// # Errors
    /// Returns an error when signing fails, the HTTP request fails, or the provider
    /// returns an unsuccessful response / malformed token payload.
    pub async fn get_request_token(&self) -> OAuthResult<RequestToken> {
        let mut params = BTreeMap::new();
        params.insert(
            "oauth_callback",
            self.config.callback_url.as_deref().unwrap_or("oob"),
        );

        let auth_header =
            self.build_auth_header("POST", &self.config.request_token_url, &params, None, None)?;

        let response = self
            .http_client
            .post(&self.config.request_token_url)
            .header("Authorization", auth_header)
            .send()
            .await?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(OAuthError::TokenExchangeFailed(format!(
                "Request token failed: {text}"
            )));
        }

        let body = response.text().await?;
        parse_request_token(&body)
    }

    /// Step 2: Build the authorization URL for user authorization.
    #[must_use]
    pub fn authorization_url(&self, request_token: &RequestToken) -> String {
        format!(
            "{}?oauth_token={}",
            self.config.authorization_url, request_token.token
        )
    }

    /// Step 3: Exchange the request token for an access token.
    ///
    /// # Errors
    /// Returns an error when signing fails, the HTTP request fails, or the provider
    /// returns an unsuccessful response / malformed token payload.
    pub async fn get_access_token(
        &self,
        request_token: &RequestToken,
        oauth_verifier: &str,
    ) -> OAuthResult<OAuth1Tokens> {
        let mut params = BTreeMap::new();
        params.insert("oauth_verifier", oauth_verifier);

        let auth_header = self.build_auth_header(
            "POST",
            &self.config.access_token_url,
            &params,
            Some(&request_token.token),
            Some(&request_token.token_secret),
        )?;

        let response = self
            .http_client
            .post(&self.config.access_token_url)
            .header("Authorization", auth_header)
            .form(&[("oauth_verifier", oauth_verifier)])
            .send()
            .await?;

        if !response.status().is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(OAuthError::TokenExchangeFailed(format!(
                "Access token failed: {text}"
            )));
        }

        let body = response.text().await?;
        parse_access_token(&body)
    }

    /// Sign a request with OAuth 1.0a.
    ///
    /// # Errors
    /// Returns an error when URL parsing or signature construction fails.
    pub fn sign_request(
        &self,
        method: &str,
        url: &str,
        tokens: &OAuth1Tokens,
        extra_params: &BTreeMap<&str, &str>,
    ) -> OAuthResult<String> {
        self.build_auth_header(
            method,
            url,
            extra_params,
            Some(&tokens.token),
            Some(&tokens.token_secret),
        )
    }

    /// Build OAuth 1.0a Authorization header.
    fn build_auth_header(
        &self,
        method: &str,
        url: &str,
        extra_params: &BTreeMap<&str, &str>,
        token: Option<&str>,
        token_secret: Option<&str>,
    ) -> OAuthResult<String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or_else(|_| "0".to_string(), |d| d.as_secs().to_string());

        let nonce = generate_nonce();

        // Collect all OAuth parameters
        let mut oauth_params: BTreeMap<String, String> = BTreeMap::new();
        oauth_params.insert(
            "oauth_consumer_key".to_string(),
            self.config.consumer_key.clone(),
        );
        oauth_params.insert("oauth_nonce".to_string(), nonce);
        oauth_params.insert(
            "oauth_signature_method".to_string(),
            "HMAC-SHA1".to_string(),
        );
        oauth_params.insert("oauth_timestamp".to_string(), timestamp);
        oauth_params.insert("oauth_version".to_string(), "1.0".to_string());

        if let Some(t) = token {
            oauth_params.insert("oauth_token".to_string(), t.to_string());
        }

        // Add extra parameters for signature calculation
        for (k, v) in extra_params {
            oauth_params.insert((*k).to_string(), (*v).to_string());
        }

        // Calculate signature
        let signature =
            self.calculate_signature(method, url, &oauth_params, token_secret.unwrap_or(""))?;

        oauth_params.insert("oauth_signature".to_string(), signature);

        // Remove non-oauth parameters before building header
        oauth_params.retain(|k, _| k.starts_with("oauth_"));

        // Build header string
        let header_parts: Vec<String> = oauth_params
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", percent_encode(k), percent_encode(v)))
            .collect();

        Ok(format!("OAuth {}", header_parts.join(", ")))
    }

    /// Calculate HMAC-SHA1 signature.
    fn calculate_signature(
        &self,
        method: &str,
        url: &str,
        params: &BTreeMap<String, String>,
        token_secret: &str,
    ) -> OAuthResult<String> {
        // Parse URL to separate base URL from query params
        let parsed_url = Url::parse(url)?;
        let base_url = format!(
            "{}://{}{}",
            parsed_url.scheme(),
            parsed_url.host_str().unwrap_or(""),
            parsed_url.path()
        );

        // Collect all parameters (OAuth + query string)
        let mut all_params: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in parsed_url.query_pairs() {
            all_params.push((k.into_owned(), v.into_owned()));
        }

        // Sort parameters by key, then by value
        all_params.sort_unstable();

        // Build parameter string (sorted)
        let param_string: String = all_params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Build signature base string
        let signature_base = format!(
            "{}&{}&{}",
            method.to_uppercase(),
            percent_encode(&base_url),
            percent_encode(&param_string)
        );

        // Build signing key
        let signing_key = format!(
            "{}&{}",
            percent_encode(&self.config.consumer_secret),
            percent_encode(token_secret)
        );

        // Calculate HMAC-SHA1
        let mut mac = Hmac::<Sha1>::new_from_slice(signing_key.as_bytes())
            .map_err(|e| OAuthError::SignatureError(e.to_string()))?;
        mac.update(signature_base.as_bytes());
        let result = mac.finalize();

        Ok(STANDARD.encode(result.into_bytes()))
    }

    /// Get configuration.
    #[must_use]
    pub const fn config(&self) -> &OAuth1Config {
        &self.config
    }
}

/// Parse request token response.
fn parse_request_token(body: &str) -> OAuthResult<RequestToken> {
    let params: std::collections::HashMap<String, String> = serde_urlencoded::from_str(body)
        .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))?;

    let token = params
        .get("oauth_token")
        .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing oauth_token".into()))?
        .clone();

    let token_secret = params
        .get("oauth_token_secret")
        .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing oauth_token_secret".into()))?
        .clone();

    let callback_confirmed = params
        .get("oauth_callback_confirmed")
        .is_some_and(|v| v == "true");

    Ok(RequestToken {
        token,
        token_secret,
        callback_confirmed,
    })
}

/// Parse access token response.
fn parse_access_token(body: &str) -> OAuthResult<OAuth1Tokens> {
    let params: std::collections::HashMap<String, String> = serde_urlencoded::from_str(body)
        .map_err(|e| OAuthError::InvalidTokenResponse(e.to_string()))?;

    let token = params
        .get("oauth_token")
        .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing oauth_token".into()))?
        .clone();

    let token_secret = params
        .get("oauth_token_secret")
        .ok_or_else(|| OAuthError::InvalidTokenResponse("Missing oauth_token_secret".into()))?
        .clone();

    Ok(OAuth1Tokens {
        token,
        token_secret,
        user_id: params.get("user_id").cloned(),
        screen_name: params.get("screen_name").cloned(),
    })
}

/// Generate a random nonce.
fn generate_nonce() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Percent-encode a string per RFC 3986.
fn percent_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut result = String::new();
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            result.push(byte as char);
        } else {
            let _ = write!(result, "%{byte:02X}");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OAuth1Config {
        OAuth1Config::new(
            "consumer_key",
            "consumer_secret",
            "https://api.twitter.com/oauth/request_token",
            "https://api.twitter.com/oauth/authorize",
            "https://api.twitter.com/oauth/access_token",
        )
        .with_callback("https://localhost:3000/callback")
    }

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("foo=bar&baz"), "foo%3Dbar%26baz");
        assert_eq!(percent_encode("test-_.~"), "test-_.~");
    }

    #[test]
    fn test_parse_request_token() {
        let body = "oauth_token=abc123&oauth_token_secret=secret456&oauth_callback_confirmed=true";
        let token = parse_request_token(body).unwrap();

        assert_eq!(token.token, "abc123");
        assert_eq!(token.token_secret, "secret456");
        assert!(token.callback_confirmed);
    }

    #[test]
    fn test_parse_access_token() {
        let body =
            "oauth_token=access123&oauth_token_secret=secret789&user_id=12345&screen_name=testuser";
        let tokens = parse_access_token(body).unwrap();

        assert_eq!(tokens.token, "access123");
        assert_eq!(tokens.token_secret, "secret789");
        assert_eq!(tokens.user_id, Some("12345".to_string()));
        assert_eq!(tokens.screen_name, Some("testuser".to_string()));
    }

    #[test]
    fn test_authorization_url() {
        let config = test_config();
        let client = OAuth1Client::new(config);

        let request_token = RequestToken {
            token: "request_token_123".to_string(),
            token_secret: "request_secret".to_string(),
            callback_confirmed: true,
        };

        let url = client.authorization_url(&request_token);
        assert!(url.contains("oauth_token=request_token_123"));
    }

    #[test]
    fn test_signature_calculation() {
        // Test vector based on Twitter's OAuth signature examples
        let config = OAuth1Config::new(
            "xvz1evFS4wEEPTGEFPHBog",
            "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
            "https://api.twitter.com/oauth/request_token",
            "https://api.twitter.com/oauth/authorize",
            "https://api.twitter.com/oauth/access_token",
        );

        let client = OAuth1Client::new(config);

        // Note: This is a simplified test - real signature verification
        // would require fixed timestamp and nonce
        let params: BTreeMap<String, String> = BTreeMap::new();
        let result = client.calculate_signature(
            "POST",
            "https://api.twitter.com/1/statuses/update.json",
            &params,
            "token_secret",
        );

        assert!(result.is_ok());
    }

    // ── New tests ──

    #[test]
    fn test_oauth1_config_fields() {
        let config = test_config();
        assert_eq!(config.consumer_key, "consumer_key");
        assert_eq!(config.consumer_secret, "consumer_secret");
        assert!(config.request_token_url.contains("request_token"));
        assert!(config.authorization_url.contains("authorize"));
        assert!(config.access_token_url.contains("access_token"));
        assert_eq!(
            config.callback_url,
            Some("https://localhost:3000/callback".to_string())
        );
    }

    #[test]
    fn test_oauth1_config_no_callback() {
        let config = OAuth1Config::new(
            "key",
            "secret",
            "https://example.com/request",
            "https://example.com/authorize",
            "https://example.com/access",
        );
        assert!(config.callback_url.is_none());
    }

    #[test]
    fn test_oauth1_client_config_accessor() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        assert_eq!(client.config().consumer_key, "consumer_key");
    }

    #[test]
    fn test_parse_request_token_missing_token() {
        let body = "oauth_token_secret=secret456";
        let result = parse_request_token(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_token_missing_secret() {
        let body = "oauth_token=abc123";
        let result = parse_request_token(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_access_token_missing_fields() {
        let body = "oauth_token=abc123";
        let result = parse_access_token(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_access_token_without_optional_fields() {
        let body = "oauth_token=access123&oauth_token_secret=secret789";
        let tokens = parse_access_token(body).unwrap();
        assert_eq!(tokens.token, "access123");
        assert_eq!(tokens.token_secret, "secret789");
        assert!(tokens.user_id.is_none());
        assert!(tokens.screen_name.is_none());
    }

    #[test]
    fn test_parse_request_token_callback_not_confirmed() {
        let body = "oauth_token=abc&oauth_token_secret=def&oauth_callback_confirmed=false";
        let token = parse_request_token(body).unwrap();
        assert!(!token.callback_confirmed);
    }

    #[test]
    fn test_percent_encode_special_chars() {
        assert_eq!(percent_encode("a+b"), "a%2Bb");
        assert_eq!(percent_encode("/path"), "%2Fpath");
        assert_eq!(percent_encode("100%"), "100%25");
    }

    // ── Batch: percent_encode edge cases ──

    #[test]
    fn test_percent_encode_empty() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn test_percent_encode_unreserved_chars_passthrough() {
        // RFC 3986 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        let unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        assert_eq!(percent_encode(unreserved), unreserved);
    }

    #[test]
    fn test_percent_encode_all_reserved_chars() {
        // All RFC 3986 reserved characters must be encoded
        assert_eq!(percent_encode(":"), "%3A");
        assert_eq!(percent_encode("@"), "%40");
        assert_eq!(percent_encode("!"), "%21");
        assert_eq!(percent_encode("$"), "%24");
        assert_eq!(percent_encode("'"), "%27");
        assert_eq!(percent_encode("("), "%28");
        assert_eq!(percent_encode(")"), "%29");
        assert_eq!(percent_encode("*"), "%2A");
        assert_eq!(percent_encode(","), "%2C");
        assert_eq!(percent_encode(";"), "%3B");
        assert_eq!(percent_encode("["), "%5B");
        assert_eq!(percent_encode("]"), "%5D");
        assert_eq!(percent_encode("#"), "%23");
    }

    #[test]
    fn test_percent_encode_space_variants() {
        assert_eq!(percent_encode(" "), "%20");
        assert_eq!(percent_encode("\t"), "%09");
        assert_eq!(percent_encode("\n"), "%0A");
    }

    #[test]
    fn test_percent_encode_multibyte_utf8() {
        // Each byte of multi-byte UTF-8 must be individually percent-encoded
        let encoded = percent_encode("é");
        assert_eq!(encoded, "%C3%A9"); // é = 0xC3 0xA9
    }

    #[test]
    fn test_percent_encode_mixed() {
        assert_eq!(
            percent_encode("Hello World! foo=bar&baz"),
            "Hello%20World%21%20foo%3Dbar%26baz"
        );
    }

    // ── Batch: signature calculation ──

    #[test]
    fn test_signature_with_extra_params() {
        let config = test_config();
        let client = OAuth1Client::new(config);

        let mut params: BTreeMap<String, String> = BTreeMap::new();
        params.insert("status".to_string(), "Hello World".to_string());
        params.insert("include_entities".to_string(), "true".to_string());

        let result = client.calculate_signature(
            "POST",
            "https://api.twitter.com/1/statuses/update.json",
            &params,
            "token_secret_value",
        );

        assert!(result.is_ok());
        // Signature should be non-empty base64
        let sig = result.unwrap();
        assert!(!sig.is_empty());
        // Base64 output should end with = or contain only base64 chars
        assert!(sig
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
    }

    #[test]
    fn test_signature_with_query_params_in_url() {
        let config = test_config();
        let client = OAuth1Client::new(config);

        let params: BTreeMap<String, String> = BTreeMap::new();
        // URL with query parameters — these should be included in signature
        let result = client.calculate_signature(
            "GET",
            "https://api.twitter.com/1/statuses/show.json?id=12345&trim_user=true",
            &params,
            "",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_different_methods_produce_different_sigs() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<String, String> = BTreeMap::new();

        let sig_get = client
            .calculate_signature("GET", "https://api.example.com/resource", &params, "secret")
            .unwrap();
        let sig_post = client
            .calculate_signature("POST", "https://api.example.com/resource", &params, "secret")
            .unwrap();

        assert_ne!(sig_get, sig_post);
    }

    #[test]
    fn test_signature_method_case_insensitive() {
        // Per OAuth spec, method is uppercased in base string
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<String, String> = BTreeMap::new();

        let sig_upper = client
            .calculate_signature("GET", "https://api.example.com/r", &params, "s")
            .unwrap();
        let sig_lower = client
            .calculate_signature("get", "https://api.example.com/r", &params, "s")
            .unwrap();

        // Both should produce same signature since method is uppercased
        assert_eq!(sig_upper, sig_lower);
    }

    #[test]
    fn test_signature_empty_token_secret() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<String, String> = BTreeMap::new();

        let result =
            client.calculate_signature("GET", "https://api.example.com/r", &params, "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_invalid_url() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<String, String> = BTreeMap::new();

        let result = client.calculate_signature("GET", "not-a-url", &params, "secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_url_with_port() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<String, String> = BTreeMap::new();

        let result = client.calculate_signature(
            "GET",
            "https://api.example.com:8443/resource",
            &params,
            "",
        );
        assert!(result.is_ok());
    }

    // ── Batch: auth header format ──

    #[test]
    fn test_auth_header_starts_with_oauth() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<&str, &str> = BTreeMap::new();

        let header = client
            .build_auth_header("GET", "https://api.example.com/r", &params, None, None)
            .unwrap();
        assert!(header.starts_with("OAuth "));
    }

    #[test]
    fn test_auth_header_contains_required_oauth_params() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<&str, &str> = BTreeMap::new();

        let header = client
            .build_auth_header("GET", "https://api.example.com/r", &params, None, None)
            .unwrap();

        assert!(header.contains("oauth_consumer_key="));
        assert!(header.contains("oauth_nonce="));
        assert!(header.contains("oauth_signature_method="));
        assert!(header.contains("oauth_timestamp="));
        assert!(header.contains("oauth_version="));
        assert!(header.contains("oauth_signature="));
    }

    #[test]
    fn test_auth_header_with_token() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<&str, &str> = BTreeMap::new();

        let header = client
            .build_auth_header(
                "GET",
                "https://api.example.com/r",
                &params,
                Some("my_token"),
                Some("my_secret"),
            )
            .unwrap();

        assert!(header.contains("oauth_token="));
    }

    #[test]
    fn test_auth_header_without_token() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<&str, &str> = BTreeMap::new();

        let header = client
            .build_auth_header("GET", "https://api.example.com/r", &params, None, None)
            .unwrap();

        // Should NOT contain oauth_token when no token is provided
        assert!(!header.contains("oauth_token="));
    }

    #[test]
    fn test_auth_header_excludes_non_oauth_params() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let mut params: BTreeMap<&str, &str> = BTreeMap::new();
        params.insert("status", "Hello");

        let header = client
            .build_auth_header("GET", "https://api.example.com/r", &params, None, None)
            .unwrap();

        // Non-oauth params should be used for signature but NOT appear in header
        assert!(!header.contains("status="));
    }

    #[test]
    fn test_auth_header_values_are_quoted() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let params: BTreeMap<&str, &str> = BTreeMap::new();

        let header = client
            .build_auth_header("GET", "https://api.example.com/r", &params, None, None)
            .unwrap();

        // Each param should be key="value"
        for part in header.strip_prefix("OAuth ").unwrap().split(", ") {
            let parts: Vec<&str> = part.splitn(2, '=').collect();
            assert_eq!(parts.len(), 2, "expected key=value: {part}");
            assert!(parts[1].starts_with('"'), "value not quoted: {part}");
            assert!(parts[1].ends_with('"'), "value not quoted: {part}");
        }
    }

    // ── Batch: nonce generation ──

    #[test]
    fn test_generate_nonce_uniqueness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce();
        // 32 bytes → base64url (no padding) = 43 chars
        assert_eq!(nonce.len(), 43);
    }

    #[test]
    fn test_generate_nonce_base64url_chars() {
        let nonce = generate_nonce();
        assert!(nonce
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    // ── Batch: parse edge cases ──

    #[test]
    fn test_parse_request_token_empty_body() {
        let result = parse_request_token("");
        // Empty body should fail (missing required fields)
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_token_no_callback_confirmed_field() {
        let body = "oauth_token=abc&oauth_token_secret=def";
        let token = parse_request_token(body).unwrap();
        assert!(!token.callback_confirmed);
    }

    #[test]
    fn test_parse_request_token_callback_confirmed_missing_value() {
        // Presence of field with non-"true" value
        let body = "oauth_token=abc&oauth_token_secret=def&oauth_callback_confirmed=yes";
        let token = parse_request_token(body).unwrap();
        assert!(!token.callback_confirmed);
    }

    #[test]
    fn test_parse_access_token_empty_body() {
        let result = parse_access_token("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_access_token_url_encoded_values() {
        let body = "oauth_token=tok%20en&oauth_token_secret=se%26cret";
        let tokens = parse_access_token(body).unwrap();
        assert_eq!(tokens.token, "tok en");
        assert_eq!(tokens.token_secret, "se&cret");
    }

    #[test]
    fn test_parse_access_token_extra_fields_ignored() {
        let body = "oauth_token=t&oauth_token_secret=s&extra_field=extra_value";
        let tokens = parse_access_token(body).unwrap();
        assert_eq!(tokens.token, "t");
        assert_eq!(tokens.token_secret, "s");
    }

    #[test]
    fn test_parse_request_token_malformed_encoding() {
        // Invalid percent encoding — serde_urlencoded may or may not handle this
        let body = "oauth_token=%ZZ&oauth_token_secret=valid";
        let result = parse_request_token(body);
        // Should either succeed (lenient) or fail (strict) — not panic
        let _ = result;
    }

    // ── Batch: OAuth1Client construction ──

    #[test]
    fn test_oauth1_client_with_custom_http_client() {
        let config = test_config();
        let http_client = Client::new();
        let client = OAuth1Client::with_http_client(config, http_client);
        assert_eq!(client.config().consumer_key, "consumer_key");
    }

    #[test]
    fn test_oauth1_config_clone() {
        let config = test_config();
        let cloned = config.clone();
        assert_eq!(config.consumer_key, cloned.consumer_key);
        assert_eq!(config.consumer_secret, cloned.consumer_secret);
        assert_eq!(config.callback_url, cloned.callback_url);
    }

    #[test]
    fn test_oauth1_tokens_clone() {
        let tokens = OAuth1Tokens {
            token: "tok".to_string(),
            token_secret: "sec".to_string(),
            user_id: Some("uid".to_string()),
            screen_name: Some("sn".to_string()),
        };
        let cloned = tokens.clone();
        assert_eq!(tokens.token, cloned.token);
        assert_eq!(tokens.token_secret, cloned.token_secret);
        assert_eq!(tokens.user_id, cloned.user_id);
        assert_eq!(tokens.screen_name, cloned.screen_name);
    }

    #[test]
    fn test_request_token_clone() {
        let rt = RequestToken {
            token: "t".to_string(),
            token_secret: "s".to_string(),
            callback_confirmed: true,
        };
        let cloned = rt.clone();
        assert_eq!(rt.token, cloned.token);
        assert!(cloned.callback_confirmed);
    }

    #[test]
    fn test_oauth1_config_debug() {
        let config = test_config();
        let debug = format!("{config:?}");
        assert!(debug.contains("consumer_key"));
        assert!(debug.contains("OAuth1Config"));
    }

    #[test]
    fn test_oauth1_tokens_debug() {
        let tokens = OAuth1Tokens {
            token: "t".to_string(),
            token_secret: "s".to_string(),
            user_id: None,
            screen_name: None,
        };
        let debug = format!("{tokens:?}");
        assert!(debug.contains("OAuth1Tokens"));
    }

    // ── Batch: sign_request ──

    #[test]
    fn test_sign_request_produces_valid_header() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let tokens = OAuth1Tokens {
            token: "access_token".to_string(),
            token_secret: "access_secret".to_string(),
            user_id: None,
            screen_name: None,
        };
        let extra = BTreeMap::new();

        let header = client
            .sign_request("GET", "https://api.example.com/resource", &tokens, &extra)
            .unwrap();

        assert!(header.starts_with("OAuth "));
        assert!(header.contains("oauth_token="));
    }

    #[test]
    fn test_sign_request_with_extra_params() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let tokens = OAuth1Tokens {
            token: "t".to_string(),
            token_secret: "s".to_string(),
            user_id: None,
            screen_name: None,
        };
        let mut extra = BTreeMap::new();
        extra.insert("count", "25");
        extra.insert("since_id", "12345");

        let header = client
            .sign_request("GET", "https://api.example.com/timeline", &tokens, &extra)
            .unwrap();

        // Extra params should not appear in header (they're for signature only)
        assert!(!header.contains("count="));
        assert!(!header.contains("since_id="));
    }

    // ── Batch: authorization_url construction ──

    #[test]
    fn test_authorization_url_format() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let rt = RequestToken {
            token: "my_request_token".to_string(),
            token_secret: "secret".to_string(),
            callback_confirmed: true,
        };

        let url = client.authorization_url(&rt);
        assert_eq!(
            url,
            "https://api.twitter.com/oauth/authorize?oauth_token=my_request_token"
        );
    }

    #[test]
    fn test_authorization_url_special_chars_in_token() {
        let config = test_config();
        let client = OAuth1Client::new(config);
        let rt = RequestToken {
            token: "token with spaces".to_string(),
            token_secret: "s".to_string(),
            callback_confirmed: true,
        };

        let url = client.authorization_url(&rt);
        // Token is included as-is (caller should URL-encode if needed)
        assert!(url.contains("oauth_token=token with spaces"));
    }
}
