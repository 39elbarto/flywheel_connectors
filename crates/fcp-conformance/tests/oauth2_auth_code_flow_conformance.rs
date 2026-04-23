//! br-axxrd — Conformance mirror for RFC 6749 §4.1 OAuth 2.0 Authorization
//! Code Grant (with PKCE extension RFC 7636 where specified).
//!
//! Each test is tagged with its RFC clause (`rfc6749_<section>_...`).
//! Oracles are drawn directly from the normative MUST clauses:
//!   §4.1.1 — authorization request required params
//!   §4.1.2 — authorization response semantics (code+state on success,
//!            error+state on failure)
//!   §4.1.4 — access-token response shape
//!   §10.12 — state binds authorization request to session (CSRF defense)
//!
//! Cross-reference: the fuzz targets `fuzz_oauth_callback_url` /
//! `fuzz_oauth_token_response` find crashes; this suite finds spec
//! divergences against a known-good deterministic vector set.

use fcp_oauth::{
    AuthorizationCallback, OAuth2Client, OAuth2Config, OAuthError, OAuthTokens, TokenResponse,
};
use url::Url;

// ── RFC 6749 §4.1.1: authorization request ───────────────────────────

/// Build a baseline OAuth2 client against an in-memory endpoint so URL
/// construction is deterministic. Any test that needs a network path
/// should use the `_with_mock_server` suite next to fcp-oauth's own
/// unit tests — the conformance suite stays pure-logic.
fn test_client(use_pkce: bool) -> OAuth2Client {
    let mut config = OAuth2Config::new(
        "conformance-client",
        "conformance-secret",
        "https://idp.example.test/authorize",
        "https://idp.example.test/token",
    )
    .with_redirect_uri("https://localhost:3000/callback");
    config.use_pkce = use_pkce;
    OAuth2Client::new(config).expect("valid conformance config must build")
}

#[test]
fn rfc6749_4_1_1_authorization_url_contains_required_params() {
    // §4.1.1 required: response_type=code, client_id, redirect_uri, state.
    // §4.1.1 RECOMMENDED: state (we always emit).
    let client = test_client(false);
    let (url_str, state) = client
        .authorization_url(&["read", "write"])
        .expect("authorization URL must build");
    let url = Url::parse(&url_str).expect("authorization URL must be a valid URL");
    assert_eq!(url.host_str(), Some("idp.example.test"));
    assert_eq!(url.path(), "/authorize");

    let pairs: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    assert_eq!(
        pairs.get("response_type"),
        Some(&"code".to_string()),
        "RFC 6749 §4.1.1 response_type MUST be `code`"
    );
    assert_eq!(
        pairs.get("client_id"),
        Some(&"conformance-client".to_string()),
        "RFC 6749 §4.1.1 client_id required"
    );
    assert_eq!(
        pairs.get("redirect_uri"),
        Some(&"https://localhost:3000/callback".to_string()),
        "RFC 6749 §4.1.1 redirect_uri required"
    );
    assert_eq!(
        pairs.get("state").map(String::as_str),
        Some(state.as_str()),
        "RFC 6749 §4.1.1 state MUST echo the client-emitted value"
    );
    assert!(
        !state.is_empty(),
        "RFC 6749 §10.12 state MUST be non-empty to defend against CSRF"
    );
}

#[test]
fn rfc7636_4_3_authorization_url_with_pkce_includes_challenge_and_method() {
    // RFC 7636 §4.3: the authorization request MUST carry
    //   code_challenge = <challenge>, code_challenge_method = <method>
    // in addition to the RFC 6749 §4.1.1 parameters.
    let client = test_client(true);
    let (url_str, state, pkce) = client
        .authorization_url_with_pkce(&["openid"])
        .expect("PKCE authorization URL must build");
    let url = Url::parse(&url_str).expect("authorization URL must parse");

    let pairs: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(pairs.get("response_type"), Some(&"code".to_string()));
    assert_eq!(pairs.get("state").map(String::as_str), Some(state.as_str()));
    assert_eq!(
        pairs.get("code_challenge").map(String::as_str),
        Some(pkce.challenge()),
        "RFC 7636 §4.3 code_challenge MUST match the session's challenge"
    );
    assert_eq!(
        pairs.get("code_challenge_method"),
        Some(&pkce.method().to_string()),
        "RFC 7636 §4.3 code_challenge_method MUST be present"
    );
}

// ── RFC 6749 §4.1.2: authorization response ──────────────────────────

#[test]
fn rfc6749_4_1_2_success_callback_echoes_state_and_code() {
    let callback = AuthorizationCallback::from_url(
        "https://localhost:3000/callback?code=auth_code_xyz&state=state_abc",
    )
    .expect("well-formed callback URL must parse");
    assert_eq!(callback.code.as_deref(), Some("auth_code_xyz"));
    assert_eq!(callback.state.as_deref(), Some("state_abc"));

    let code = callback
        .validate("state_abc")
        .expect("matching state + present code → validate returns the code");
    assert_eq!(code, "auth_code_xyz");
}

#[test]
fn rfc6749_4_1_2_error_callback_surfaces_provider_error_and_description() {
    // §4.1.2.1: on error, the AS redirects with ?error=<code>,
    // ?error_description=<text>, ?error_uri=<link>, and state.
    let callback = AuthorizationCallback::from_url(
        "https://localhost:3000/callback?error=access_denied&error_description=user_declined&state=abc",
    )
    .expect("well-formed error callback URL must parse");

    let err = callback
        .validate("abc")
        .expect_err("§4.1.2.1 error callback MUST surface as an error");
    match err {
        OAuthError::AuthorizationError {
            error, description, ..
        } => {
            assert_eq!(error, "access_denied");
            assert_eq!(description, "user_declined");
        }
        other => panic!("expected AuthorizationError, got {other:?}"),
    }
}

#[test]
fn rfc6749_10_12_state_mismatch_is_rejected() {
    // §10.12: state binds the authorization request to the session.
    // A callback state that does not match the client-emitted state is
    // a CSRF attempt and MUST be rejected.
    let callback = AuthorizationCallback::from_url(
        "https://localhost:3000/callback?code=legit_code&state=attacker_state",
    )
    .unwrap();
    let err = callback
        .validate("client_state")
        .expect_err("§10.12 state mismatch MUST be rejected");
    assert!(matches!(err, OAuthError::StateMismatch { .. }));
}

#[test]
fn rfc6749_10_12_empty_expected_state_is_rejected() {
    // Defense-in-depth: validate() MUST refuse an empty expected_state so
    // a caller that accidentally passes "" cannot race every callback to
    // "matching" state=""; that would defeat §10.12 entirely.
    let callback = AuthorizationCallback::from_url(
        "https://localhost:3000/callback?code=legit_code&state=whatever",
    )
    .unwrap();
    let err = callback
        .validate("")
        .expect_err("empty expected_state MUST be rejected to preserve §10.12 semantics");
    assert!(matches!(err, OAuthError::InvalidState(_)));
}

// ── RFC 6749 §4.1.4: access token response ───────────────────────────

fn minimal_token_response() -> TokenResponse {
    TokenResponse {
        access_token: "at_minimal".into(),
        token_type: "Bearer".into(),
        expires_in: None,
        refresh_token: None,
        scope: None,
        id_token: None,
    }
}

#[test]
fn rfc6749_4_1_4_token_response_requires_access_token_and_token_type() {
    // §4.1.4: the response MUST include access_token + token_type.
    // (expires_in, refresh_token, scope are optional per §4.1.4.)
    let tokens = OAuthTokens::from_response(minimal_token_response())
        .expect("access_token + token_type alone satisfies §4.1.4");
    assert_eq!(tokens.access_token(), "at_minimal");
    assert_eq!(tokens.token_type(), "Bearer");
    // Optional fields default to absent.
    assert!(tokens.refresh_token().is_none());
    assert!(tokens.scopes().is_empty());
    assert!(tokens.id_token().is_none());
}

#[test]
fn rfc6749_4_1_4_empty_access_token_is_rejected() {
    // Implementations that treat "access_token": "" as a valid response
    // ship a broken Authorization header to every subsequent request.
    // This is a stricter variant than the RFC literally requires but
    // matches the broader correctness invariant §4.1.4 implies.
    let mut resp = minimal_token_response();
    resp.access_token = String::new();
    let err = OAuthTokens::from_response(resp)
        .expect_err("empty access_token MUST NOT produce a usable OAuthTokens");
    assert!(matches!(err, OAuthError::EmptyTokenField("access_token")));
}

#[test]
fn rfc6749_4_1_4_empty_token_type_is_rejected() {
    let mut resp = minimal_token_response();
    resp.token_type = String::new();
    let err = OAuthTokens::from_response(resp)
        .expect_err("empty token_type MUST NOT produce a usable OAuthTokens");
    assert!(matches!(err, OAuthError::EmptyTokenField("token_type")));
}

#[test]
fn rfc6749_4_1_4_full_token_response_preserves_all_fields() {
    let response = TokenResponse {
        access_token: "at_full".into(),
        token_type: "Bearer".into(),
        expires_in: Some(3600),
        refresh_token: Some("rt_full".into()),
        scope: Some("read write admin".into()),
        id_token: Some("id_abc".into()),
    };
    let tokens = OAuthTokens::from_response(response).unwrap();
    assert_eq!(tokens.access_token(), "at_full");
    assert_eq!(tokens.token_type(), "Bearer");
    assert_eq!(tokens.refresh_token(), Some("rt_full"));
    assert_eq!(tokens.scopes(), &["read", "write", "admin"]);
    assert_eq!(tokens.id_token(), Some("id_abc"));
}

#[test]
fn rfc6749_scope_is_space_separated_list() {
    // §3.3 scope = 1*( SP / scope-token ).  The parser MUST split the
    // token-response scope string on whitespace, preserving order.
    let response = TokenResponse {
        access_token: "at".into(),
        token_type: "Bearer".into(),
        expires_in: None,
        refresh_token: None,
        scope: Some("openid  email\tprofile".into()),
        id_token: None,
    };
    let tokens = OAuthTokens::from_response(response).unwrap();
    assert_eq!(tokens.scopes(), &["openid", "email", "profile"]);
}
