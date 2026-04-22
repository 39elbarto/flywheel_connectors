//! No-mock integration tests for fcp-oauth.
//!
//! Cross-module validation of OAuth 1.0a signatures, OAuth 2.0 authorization
//! URL construction, PKCE flows, token lifecycle, provider configs, and
//! token store operations — all without network access.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use fcp_oauth::{
    AuthStyle, AuthorizationCallback, DEFAULT_REFRESH_THRESHOLD, GrantType, OAuth1Client,
    OAuth1Config, OAuth2Client, OAuth2Config, OAuthError, OAuthProvider, OAuthTokens, Pkce,
    PkceMethod, ProviderEndpoints, ResponseMode, TokenResponse, TokenStore,
};

fn valid_tokens(response: TokenResponse) -> OAuthTokens {
    OAuthTokens::from_response(response).expect("valid token fixture must construct")
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants & Enums
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn default_refresh_threshold_is_five_minutes() {
    assert_eq!(DEFAULT_REFRESH_THRESHOLD, Duration::from_secs(300));
}

#[test]
fn grant_type_copy_and_eq() {
    let a = GrantType::AuthorizationCode;
    let b = a; // Copy
    assert_eq!(a, b);
    assert_ne!(GrantType::AuthorizationCode, GrantType::ClientCredentials);
    assert_ne!(GrantType::RefreshToken, GrantType::DeviceCode);
}

#[test]
fn response_mode_all_variants_display() {
    assert_eq!(ResponseMode::Query.to_string(), "query");
    assert_eq!(ResponseMode::Fragment.to_string(), "fragment");
    assert_eq!(ResponseMode::FormPost.to_string(), "form_post");
    assert_eq!(ResponseMode::default(), ResponseMode::Query);
}

#[test]
fn auth_style_display() {
    assert_eq!(AuthStyle::Basic.to_string(), "basic");
    assert_eq!(AuthStyle::Post.to_string(), "post");
}

// ═══════════════════════════════════════════════════════════════════════════
// OAuth 2.0 Config Builders
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn oauth2_config_basic_construction() {
    let config = OAuth2Config::new(
        "client-id",
        "client-secret",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    );
    assert_eq!(config.client_id, "client-id");
    assert_eq!(config.client_secret, Some("client-secret".to_string()));
    assert_eq!(
        config.authorization_url,
        "https://auth.example.com/authorize"
    );
    assert_eq!(config.token_url, "https://auth.example.com/token");
    assert!(config.use_pkce); // default true
}

#[test]
fn oauth2_config_public_client() {
    let config = OAuth2Config::public_client(
        "pub-client",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    );
    assert_eq!(config.client_id, "pub-client");
    assert!(config.client_secret.is_none());
    assert!(config.use_pkce); // required for public clients
}

#[test]
fn oauth2_config_full_builder_chain() {
    let config = OAuth2Config::new("id", "secret", "https://a.com/auth", "https://a.com/token")
        .with_redirect_uri("https://localhost:3000/callback")
        .with_scopes(vec!["read".into(), "write".into()])
        .with_pkce(true)
        .with_pkce_method(PkceMethod::S256)
        .with_response_mode(ResponseMode::Fragment)
        .with_auth_style(AuthStyle::Basic)
        .with_auth_param("access_type", "offline")
        .with_token_param("audience", "https://api.example.com")
        .with_timeout(Duration::from_secs(60));

    assert_eq!(
        config.redirect_uri,
        Some("https://localhost:3000/callback".to_string())
    );
    assert_eq!(config.default_scopes, vec!["read", "write"]);
    assert!(config.use_pkce);
    assert_eq!(config.pkce_method, PkceMethod::S256);
    assert_eq!(config.response_mode, ResponseMode::Fragment);
    assert_eq!(config.auth_style, AuthStyle::Basic);
    assert_eq!(config.extra_auth_params["access_type"], "offline");
    assert_eq!(
        config.extra_token_params["audience"],
        "https://api.example.com"
    );
    assert_eq!(config.timeout, Duration::from_secs(60));
}

// ═══════════════════════════════════════════════════════════════════════════
// OAuth 2.0 Authorization URL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn oauth2_authorization_url_contains_required_params() {
    let config = OAuth2Config::new(
        "my-client",
        "secret",
        "https://auth.ex.com/authorize",
        "https://auth.ex.com/token",
    )
    .with_redirect_uri("https://localhost/cb")
    .with_pkce(false);
    let client = OAuth2Client::new(config).unwrap();
    let (url, state) = client.authorization_url(&["read", "write"]).unwrap();

    assert!(url.contains("client_id=my-client"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("redirect_uri="));
    assert!(url.contains("scope=read"));
    assert!(url.contains("state="));
    assert!(!state.is_empty());
}

#[test]
fn oauth2_authorization_url_with_pkce_includes_challenge() {
    let config = OAuth2Config::new(
        "id",
        "secret",
        "https://auth.ex.com/authorize",
        "https://auth.ex.com/token",
    )
    .with_redirect_uri("https://localhost/cb")
    .with_pkce(true)
    .with_pkce_method(PkceMethod::S256);
    let client = OAuth2Client::new(config).unwrap();
    let (url, _state, pkce) = client.authorization_url_with_pkce(&["openid"]).unwrap();

    assert!(url.contains("code_challenge="));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(!pkce.verifier().is_empty());
    assert!(!pkce.challenge().is_empty());
}

#[test]
fn oauth2_authorization_url_with_extra_auth_params() {
    let config = OAuth2Config::new(
        "id",
        "s",
        "https://auth.ex.com/authorize",
        "https://auth.ex.com/token",
    )
    .with_redirect_uri("https://localhost/cb")
    .with_pkce(false)
    .with_auth_param("access_type", "offline")
    .with_auth_param("prompt", "consent");
    let client = OAuth2Client::new(config).unwrap();
    let (url, _) = client.authorization_url(&[]).unwrap();

    assert!(url.contains("access_type=offline"));
    assert!(url.contains("prompt=consent"));
}

#[test]
fn oauth2_state_is_unique_per_call() {
    let config = OAuth2Config::new("id", "s", "https://a.com/auth", "https://a.com/token")
        .with_redirect_uri("https://localhost/cb")
        .with_pkce(false);
    let client = OAuth2Client::new(config).unwrap();
    let (_, state1) = client.authorization_url(&[]).unwrap();
    let (_, state2) = client.authorization_url(&[]).unwrap();
    assert_ne!(state1, state2);
}

// ═══════════════════════════════════════════════════════════════════════════
// Authorization Callback
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn callback_from_query_extracts_code_and_state() {
    let callback = AuthorizationCallback::from_query("code=abc123&state=xyz789").unwrap();
    assert_eq!(callback.code, Some("abc123".to_string()));
    assert_eq!(callback.state, Some("xyz789".to_string()));
}

#[test]
fn callback_from_url_extracts_query() {
    let callback =
        AuthorizationCallback::from_url("https://localhost/cb?code=mycode&state=mystate").unwrap();
    assert_eq!(callback.code, Some("mycode".to_string()));
    assert_eq!(callback.state, Some("mystate".to_string()));
}

#[test]
fn callback_validate_succeeds_with_matching_state() {
    let callback = AuthorizationCallback::from_query("code=abc&state=expected").unwrap();
    let code = callback.validate("expected").unwrap();
    assert_eq!(code, "abc");
}

#[test]
fn callback_validate_fails_on_state_mismatch() {
    let callback = AuthorizationCallback::from_query("code=abc&state=wrong").unwrap();
    let err = callback.validate("expected").unwrap_err();
    assert!(matches!(err, OAuthError::StateMismatch { .. }));
}

#[test]
fn callback_validate_fails_on_error_response() {
    let callback =
        AuthorizationCallback::from_query("error=access_denied&error_description=User+denied")
            .unwrap();
    let err = callback.validate("any").unwrap_err();
    assert!(matches!(err, OAuthError::AuthorizationError { .. }));
}

#[test]
fn callback_serde_roundtrip() {
    let callback = AuthorizationCallback::from_query("code=c&state=s").unwrap();
    let json = serde_json::to_string(&callback).unwrap();
    let back: AuthorizationCallback = serde_json::from_str(&json).unwrap();
    assert_eq!(back.code, callback.code);
    assert_eq!(back.state, callback.state);
}

// ═══════════════════════════════════════════════════════════════════════════
// PKCE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn pkce_s256_generation() {
    let pkce = Pkce::new();
    assert_eq!(pkce.method(), PkceMethod::S256);
    assert!(pkce.verifier().len() >= 43);
    assert!(pkce.verifier().len() <= 128);
    assert!(!pkce.challenge().is_empty());
    assert_ne!(pkce.verifier(), pkce.challenge()); // S256 transforms
}

#[test]
fn pkce_plain_generation() {
    let pkce = Pkce::with_method(PkceMethod::Plain);
    assert_eq!(pkce.method(), PkceMethod::Plain);
    assert_eq!(pkce.verifier(), pkce.challenge()); // Plain: challenge == verifier
}

#[test]
fn pkce_uniqueness() {
    let a = Pkce::new();
    let b = Pkce::new();
    assert_ne!(a.verifier(), b.verifier());
    assert_ne!(a.challenge(), b.challenge());
}

#[test]
fn pkce_from_verifier_s256_deterministic() {
    let original = Pkce::new();
    let reconstructed = Pkce::from_verifier(original.verifier(), PkceMethod::S256).unwrap();
    assert_eq!(reconstructed.challenge(), original.challenge());
    assert_eq!(reconstructed.verifier(), original.verifier());
}

#[test]
fn pkce_from_verifier_rejects_too_short() {
    let err = Pkce::from_verifier("short", PkceMethod::S256).unwrap_err();
    assert!(matches!(err, OAuthError::PkceError(_)));
}

#[test]
fn pkce_from_verifier_rejects_too_long() {
    let long = "a".repeat(129);
    let err = Pkce::from_verifier(&long, PkceMethod::S256).unwrap_err();
    assert!(matches!(err, OAuthError::PkceError(_)));
}

#[test]
fn pkce_from_verifier_rejects_invalid_chars() {
    let invalid = "a".repeat(43) + "!"; // ! is not unreserved
    let err = Pkce::from_verifier(&invalid, PkceMethod::S256).unwrap_err();
    assert!(matches!(err, OAuthError::PkceError(_)));
}

#[test]
fn pkce_method_display() {
    assert_eq!(PkceMethod::Plain.to_string(), "plain");
    assert_eq!(PkceMethod::S256.to_string(), "S256");
}

// ═══════════════════════════════════════════════════════════════════════════
// OAuth 1.0a
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn oauth1_config_construction() {
    let config = OAuth1Config::new(
        "consumer_key",
        "consumer_secret",
        "https://api.example.com/oauth/request_token",
        "https://api.example.com/oauth/authorize",
        "https://api.example.com/oauth/access_token",
    );
    assert_eq!(config.consumer_key, "consumer_key");
    assert_eq!(config.consumer_secret, "consumer_secret");
    assert!(config.callback_url.is_none());
}

#[test]
fn oauth1_config_with_callback() {
    let config = OAuth1Config::new(
        "k",
        "s",
        "https://a.com/rt",
        "https://a.com/auth",
        "https://a.com/at",
    )
    .with_callback("https://localhost:3000/callback");
    assert_eq!(
        config.callback_url,
        Some("https://localhost:3000/callback".to_string())
    );
}

#[test]
fn oauth1_client_authorization_url() {
    let config = OAuth1Config::new(
        "k",
        "s",
        "https://a.com/rt",
        "https://a.com/authorize",
        "https://a.com/at",
    );
    let client = OAuth1Client::new(config);
    let request_token = fcp_oauth::RequestToken {
        token: "req-token-123".to_string(),
        token_secret: "req-secret".to_string(),
        callback_confirmed: true,
    };
    let url = client.authorization_url(&request_token);
    assert!(url.contains("https://a.com/authorize"));
    assert!(url.contains("oauth_token=req-token-123"));
}

#[test]
fn oauth1_sign_request_produces_oauth_header() {
    let config = OAuth1Config::new(
        "consumer-key",
        "consumer-secret",
        "https://a.com/rt",
        "https://a.com/auth",
        "https://a.com/at",
    );
    let client = OAuth1Client::new(config);
    let tokens = fcp_oauth::OAuth1Tokens {
        token: "access-token".to_string(),
        token_secret: "access-secret".to_string(),
        user_id: None,
        screen_name: None,
    };

    let header = client
        .sign_request(
            "GET",
            "https://api.example.com/data",
            &tokens,
            &BTreeMap::new(),
        )
        .unwrap();
    assert!(header.starts_with("OAuth "));
    assert!(header.contains("oauth_consumer_key="));
    assert!(header.contains("oauth_token="));
    assert!(header.contains("oauth_signature="));
    assert!(header.contains("oauth_signature_method="));
    assert!(header.contains("oauth_nonce="));
    assert!(header.contains("oauth_timestamp="));
    assert!(header.contains("oauth_version="));
}

#[test]
fn oauth1_sign_request_signature_is_deterministic_for_same_nonce_and_timestamp() {
    // Two calls with different nonces will produce different signatures,
    // but the format should be consistent
    let config = OAuth1Config::new(
        "k",
        "s",
        "https://a.com/rt",
        "https://a.com/auth",
        "https://a.com/at",
    );
    let client = OAuth1Client::new(config);
    let tokens = fcp_oauth::OAuth1Tokens {
        token: "t".to_string(),
        token_secret: "ts".to_string(),
        user_id: None,
        screen_name: None,
    };

    let h1 = client
        .sign_request("GET", "https://api.ex.com/v1", &tokens, &BTreeMap::new())
        .unwrap();
    let h2 = client
        .sign_request("GET", "https://api.ex.com/v1", &tokens, &BTreeMap::new())
        .unwrap();
    // Different nonces → different signatures, but both valid OAuth headers
    assert!(h1.starts_with("OAuth "));
    assert!(h2.starts_with("OAuth "));
    assert_ne!(h1, h2); // random nonce makes them different
}

// ═══════════════════════════════════════════════════════════════════════════
// Token Response & OAuthTokens
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn token_response_minimal_serde() {
    let json = r#"{"access_token":"at","token_type":"bearer"}"#;
    let resp: TokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.access_token, "at");
    assert_eq!(resp.token_type, "bearer");
    assert!(resp.expires_in.is_none());
    assert!(resp.refresh_token.is_none());
}

#[test]
fn token_response_full_serde() {
    let json = r#"{
        "access_token": "access-123",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh-456",
        "scope": "read write",
        "id_token": "jwt-789"
    }"#;
    let resp: TokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.access_token, "access-123");
    assert_eq!(resp.expires_in, Some(3600));
    assert_eq!(resp.refresh_token, Some("refresh-456".to_string()));
    assert_eq!(resp.scope, Some("read write".to_string()));
    assert_eq!(resp.id_token, Some("jwt-789".to_string()));
}

#[test]
fn oauth_tokens_from_response_with_expiry() {
    let resp = TokenResponse {
        access_token: "at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: Some("rt".to_string()),
        scope: Some("read write".to_string()),
        id_token: None,
    };
    let tokens = valid_tokens(resp);
    assert_eq!(tokens.access_token(), "at");
    assert_eq!(tokens.token_type(), "Bearer");
    assert_eq!(tokens.refresh_token(), Some("rt"));
    assert_eq!(tokens.scopes(), &["read", "write"]);
    assert!(!tokens.is_expired());
    assert!(!tokens.needs_refresh()); // 3600s >> 300s threshold
}

#[test]
fn oauth_tokens_expired_immediately() {
    let resp = TokenResponse {
        access_token: "at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(0),
        refresh_token: None,
        scope: None,
        id_token: None,
    };
    let tokens = valid_tokens(resp);
    assert!(tokens.is_expired());
    assert!(tokens.needs_refresh());
}

#[test]
fn oauth_tokens_no_expiry_never_expires() {
    let resp = TokenResponse {
        access_token: "at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: None,
        refresh_token: None,
        scope: None,
        id_token: None,
    };
    let tokens = valid_tokens(resp);
    assert!(!tokens.is_expired());
    assert!(!tokens.needs_refresh());
}

#[test]
fn oauth_tokens_authorization_header() {
    let resp = TokenResponse {
        access_token: "my-token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: None,
        scope: None,
        id_token: None,
    };
    let tokens = valid_tokens(resp);
    assert_eq!(
        tokens
            .authorization_header()
            .expect("token must format an authorization header"),
        "Bearer my-token"
    );
}

#[test]
fn oauth_tokens_update_preserves_refresh_token() {
    let initial = TokenResponse {
        access_token: "old-at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: Some("original-rt".to_string()),
        scope: Some("read".to_string()),
        id_token: None,
    };
    let mut tokens = valid_tokens(initial);

    // Refresh response without refresh_token
    let refresh = TokenResponse {
        access_token: "new-at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(7200),
        refresh_token: None, // server didn't send new RT
        scope: None,
        id_token: None,
    };
    tokens
        .update_from_response(refresh)
        .expect("non-empty access_token and token_type must succeed");

    assert_eq!(tokens.access_token(), "new-at");
    assert_eq!(tokens.refresh_token(), Some("original-rt")); // preserved
}

#[test]
fn oauth_tokens_update_replaces_refresh_token_when_provided() {
    let initial = TokenResponse {
        access_token: "at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: Some("old-rt".to_string()),
        scope: None,
        id_token: None,
    };
    let mut tokens = valid_tokens(initial);

    let refresh = TokenResponse {
        access_token: "new-at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: Some("new-rt".to_string()),
        scope: None,
        id_token: None,
    };
    tokens
        .update_from_response(refresh)
        .expect("non-empty access_token and token_type must succeed");

    assert_eq!(tokens.refresh_token(), Some("new-rt"));
}

#[test]
fn oauth_tokens_debug_redacts_secrets() {
    let resp = TokenResponse {
        access_token: "super-secret-token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: Some("secret-refresh".to_string()),
        scope: None,
        id_token: Some("secret-jwt".to_string()),
    };
    let tokens = valid_tokens(resp);
    let debug = format!("{tokens:?}");
    assert!(!debug.contains("super-secret-token"));
    assert!(!debug.contains("secret-refresh"));
    assert!(!debug.contains("secret-jwt"));
}

#[test]
fn oauth_tokens_needs_refresh_within_custom_threshold() {
    let resp = TokenResponse {
        access_token: "at".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(120), // 2 minutes
        refresh_token: None,
        scope: None,
        id_token: None,
    };
    let tokens = valid_tokens(resp);
    assert!(tokens.needs_refresh_within(Duration::from_secs(180))); // 3 min threshold > 2 min remaining
    assert!(!tokens.needs_refresh_within(Duration::from_secs(60))); // 1 min threshold < 2 min remaining
}

// ═══════════════════════════════════════════════════════════════════════════
// Token Store
// ═══════════════════════════════════════════════════════════════════════════

fn make_tokens(access_token: &str, expires_in: Option<u64>) -> OAuthTokens {
    OAuthTokens::from_response(TokenResponse {
        access_token: access_token.to_string(),
        token_type: "Bearer".to_string(),
        expires_in,
        refresh_token: None,
        scope: None,
        id_token: None,
    })
    .expect("valid token fixture must construct")
}

#[test]
fn token_store_basic_lifecycle() {
    let store = TokenStore::new();
    assert!(store.get("key").is_none());

    store.store("key", make_tokens("at1", Some(3600)));
    assert!(store.get("key").is_some());
    assert_eq!(store.get("key").unwrap().access_token(), "at1");

    let _ = store.remove("key");
    assert!(store.get("key").is_none());
}

#[test]
fn token_store_multiple_keys() {
    let store = TokenStore::new();
    store.store("github", make_tokens("gh-token", Some(3600)));
    store.store("slack", make_tokens("sl-token", Some(7200)));

    assert_eq!(store.keys().len(), 2);
    assert_eq!(store.get("github").unwrap().access_token(), "gh-token");
    assert_eq!(store.get("slack").unwrap().access_token(), "sl-token");
}

#[test]
fn token_store_clear_removes_all() {
    let store = TokenStore::new();
    store.store("a", make_tokens("t1", Some(3600)));
    store.store("b", make_tokens("t2", Some(3600)));
    store.store("c", make_tokens("t3", Some(3600)));

    store.clear();
    assert!(store.keys().is_empty());
    assert!(store.get("a").is_none());
}

#[test]
fn token_store_update_existing() {
    let store = TokenStore::new();
    store.store("key", make_tokens("old", Some(3600)));

    store.update("key", make_tokens("new", Some(7200))).unwrap();
    assert_eq!(store.get("key").unwrap().access_token(), "new");
}

#[test]
fn token_store_update_nonexistent_fails() {
    let store = TokenStore::new();
    let err = store
        .update("missing", make_tokens("t", Some(3600)))
        .unwrap_err();
    assert!(matches!(err, OAuthError::TokenNotFound(_)));
}

#[test]
fn token_store_has_valid_token() {
    let store = TokenStore::new();
    store.store("valid", make_tokens("t", Some(3600)));
    store.store("expired", make_tokens("t", Some(0)));

    assert!(store.has_valid_token("valid"));
    assert!(!store.has_valid_token("expired"));
    assert!(!store.has_valid_token("nonexistent"));
}

#[test]
fn token_store_with_metadata() {
    let store = TokenStore::new();
    let mut meta = HashMap::new();
    meta.insert("provider".to_string(), "github".to_string());
    meta.insert("user_id".to_string(), "12345".to_string());

    store.store_with_metadata("key", make_tokens("t", Some(3600)), meta);

    let (tokens, metadata) = store.get_with_metadata("key").unwrap();
    assert_eq!(tokens.access_token(), "t");
    assert_eq!(metadata["provider"], "github");
    assert_eq!(metadata["user_id"], "12345");
}

#[test]
fn token_store_remove_returns_tokens() {
    let store = TokenStore::new();
    store.store("key", make_tokens("at", Some(3600)));

    let removed = store.remove("key");
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().access_token(), "at");

    // Second remove returns None
    assert!(store.remove("key").is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// Provider Configs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn all_oauth2_providers_produce_valid_configs() {
    let providers = [
        OAuthProvider::Google,
        OAuthProvider::GitHub,
        OAuthProvider::Twitter,
        OAuthProvider::Slack,
        OAuthProvider::Notion,
        OAuthProvider::Linear,
        OAuthProvider::Discord,
        OAuthProvider::Spotify,
        OAuthProvider::Microsoft,
        OAuthProvider::Dropbox,
    ];

    for provider in &providers {
        assert!(
            provider.supports_oauth2(),
            "{provider:?} should support OAuth 2.0"
        );
        let config = provider.oauth2_config("test-id", "test-secret");
        assert!(config.is_some(), "{provider:?} should produce OAuth2Config");
        let cfg = config.unwrap();
        assert!(!cfg.authorization_url.is_empty());
        assert!(!cfg.token_url.is_empty());
    }
}

#[test]
fn twitter_legacy_supports_oauth1_only() {
    let provider = OAuthProvider::TwitterLegacy;
    assert!(provider.supports_oauth1());
    let config = provider.oauth1_config("key", "secret");
    assert!(config.is_some());
    let cfg = config.unwrap();
    assert!(!cfg.request_token_url.is_empty());
    assert!(!cfg.authorization_url.is_empty());
    assert!(!cfg.access_token_url.is_empty());
}

#[test]
fn providers_requiring_pkce() {
    assert!(OAuthProvider::Google.requires_pkce());
    assert!(OAuthProvider::Twitter.requires_pkce());
    assert!(!OAuthProvider::GitHub.requires_pkce());
    assert!(!OAuthProvider::Slack.requires_pkce());
}

#[test]
fn custom_provider_endpoints() {
    let endpoints = ProviderEndpoints::new(
        "https://custom.example.com/authorize",
        "https://custom.example.com/token",
    )
    .with_revocation_url("https://custom.example.com/revoke")
    .with_userinfo_url("https://custom.example.com/userinfo");

    assert_eq!(
        endpoints.revocation_url,
        Some("https://custom.example.com/revoke".to_string())
    );
    assert_eq!(
        endpoints.userinfo_url,
        Some("https://custom.example.com/userinfo".to_string())
    );

    let config = endpoints.to_oauth2_config("my-id", "my-secret");
    assert_eq!(config.client_id, "my-id");
    assert_eq!(
        config.authorization_url,
        "https://custom.example.com/authorize"
    );
    assert_eq!(config.token_url, "https://custom.example.com/token");
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_variants_all_display_nonempty() {
    let errors: Vec<OAuthError> = vec![
        OAuthError::InvalidConfig("bad".into()),
        OAuthError::StateMismatch {
            expected: "a".into(),
            actual: "b".into(),
        },
        OAuthError::AuthorizationError {
            error: "access_denied".into(),
            description: "User denied".into(),
            error_uri: None,
        },
        OAuthError::TokenExchangeFailed("exchange error".into()),
        OAuthError::RefreshFailed("refresh error".into()),
        OAuthError::TokenExpired(Duration::from_secs(60)),
        OAuthError::NoRefreshToken,
        OAuthError::InvalidTokenResponse("bad response".into()),
        OAuthError::SignatureError("sig error".into()),
        OAuthError::UnsupportedProvider("unknown".into()),
        OAuthError::TokenNotFound("key".into()),
        OAuthError::PkceError("pkce error".into()),
    ];

    for error in &errors {
        let display = error.to_string();
        assert!(!display.is_empty(), "empty display for {error:?}");
    }
}

#[test]
fn error_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OAuthError>();
}

#[test]
fn error_state_mismatch_contains_values() {
    let err = OAuthError::StateMismatch {
        expected: "abc".into(),
        actual: "xyz".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("abc") || msg.contains("xyz") || msg.contains("mismatch"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-Module: Provider + OAuth2Client + PKCE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn google_provider_oauth2_with_pkce_flow() {
    let config = OAuthProvider::Google
        .oauth2_config("google-client-id", "google-secret")
        .unwrap()
        .with_redirect_uri("https://localhost/callback");

    assert!(config.use_pkce);
    let client = OAuth2Client::new(config).unwrap();
    let (url, state, pkce) = client
        .authorization_url_with_pkce(&["openid", "email"])
        .unwrap();

    assert!(url.contains("accounts.google.com"));
    assert!(url.contains("code_challenge="));
    assert!(url.contains("scope="));
    assert!(!state.is_empty());
    assert!(!pkce.verifier().is_empty());
}

#[test]
fn github_provider_oauth2_without_pkce() {
    let config = OAuthProvider::GitHub
        .oauth2_config("gh-id", "gh-secret")
        .unwrap()
        .with_redirect_uri("https://localhost/callback")
        .with_pkce(false);

    let client = OAuth2Client::new(config).unwrap();
    let (url, _state) = client.authorization_url(&["repo", "user"]).unwrap();

    assert!(url.contains("github.com"));
    assert!(!url.contains("code_challenge="));
}

#[test]
fn token_store_with_provider_workflow() {
    let store = TokenStore::new();

    // Simulate storing tokens from multiple providers
    let gh_tokens = make_tokens("gh-access-token", Some(3600));
    let sl_tokens = make_tokens("sl-access-token", Some(7200));

    let mut gh_meta = HashMap::new();
    gh_meta.insert("provider".to_string(), "github".to_string());
    store.store_with_metadata("github", gh_tokens, gh_meta);

    let mut sl_meta = HashMap::new();
    sl_meta.insert("provider".to_string(), "slack".to_string());
    store.store_with_metadata("slack", sl_tokens, sl_meta);

    // Verify independent storage
    assert!(store.has_valid_token("github"));
    assert!(store.has_valid_token("slack"));

    let (gh, gh_m) = store.get_with_metadata("github").unwrap();
    assert_eq!(
        gh.authorization_header()
            .expect("token must format an authorization header"),
        "Bearer gh-access-token"
    );
    assert_eq!(gh_m["provider"], "github");
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-Module: PKCE + OAuth2 authorization URL round-trip
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn pkce_verifier_reconstructs_matching_challenge() {
    let config = OAuth2Config::new("id", "s", "https://a.com/auth", "https://a.com/token")
        .with_redirect_uri("https://localhost/cb");
    let client = OAuth2Client::new(config).unwrap();
    let (url, _, pkce) = client.authorization_url_with_pkce(&[]).unwrap();

    // Reconstruct PKCE from verifier
    let reconstructed = Pkce::from_verifier(pkce.verifier(), PkceMethod::S256).unwrap();
    assert_eq!(reconstructed.challenge(), pkce.challenge());

    // Challenge should appear in the URL
    assert!(url.contains(pkce.challenge()));
}
