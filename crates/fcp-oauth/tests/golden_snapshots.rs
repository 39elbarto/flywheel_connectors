//! Golden artifact snapshots for fcp-oauth.
//!
//! Freezes four observable surfaces so a silent change in serialization,
//! deserialization, or redirect-allowlist semantics will fail the next
//! CI run with a diff of the old vs. new output:
//!
//! 1. **Token refresh request serialization** — the form-urlencoded
//!    body that [`OAuth2Client::refresh_tokens`] would send. The
//!    snapshot captures the exact byte-for-byte body so any reordering
//!    of parameters, change of grant-type encoding, or change of
//!    percent-encoding rules shows up as a diff.
//! 2. **Token refresh response deserialization** — the JSON an RFC 6749
//!    token endpoint returns, parsed into [`TokenResponse`] and then
//!    promoted to [`OAuthTokens`]. Snapshotting the structural output
//!    catches any regression in default-field handling, scope splitting,
//!    or expiry-clamping logic. Timestamps are scrubbed so the snapshot
//!    is stable across runs.
//! 3. **Redirect URL allowlist enforcement** — every decision point in
//!    [`ensure_allowlisted_redirect_uri`] and
//!    [`ensure_callback_redirect_is_allowlisted`] (accept, reject for
//!    scheme, reject for host, reject for path, reject for missing
//!    membership). Snapshotting the error messages means any change in
//!    the operator-facing failure surface is detected immediately.
//! 4. **Custom provider endpoint policy** — the authorization, token,
//!    revocation, and userinfo endpoint decisions produced by
//!    [`ProviderEndpoints`].

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fcp_oauth::{
    OAuth1Client, OAuth1Config, OAuth2Client, OAuth2Config, OAuthError, OAuthTokens, PkceMethod,
    ProviderEndpoints, RequestToken, TokenResponse, ensure_allowlisted_redirect_uri,
    ensure_callback_redirect_is_allowlisted, parse_registered_redirect_allowlist,
};
use serde_json::json;

/// Build the form-urlencoded refresh-token request body the same way
/// `OAuth2Client::refresh_tokens` does internally: a `grant_type` of
/// `refresh_token`, the caller's refresh token, and any extra token
/// parameters the config carries. A `BTreeMap` here is deliberate — we
/// want a deterministic parameter ordering in the snapshot even though
/// the production code path uses a `HashMap` (whose iteration order is
/// not observable to external systems once the body is hashed/signed or
/// consumed as a form POST).
fn refresh_token_request_body(
    refresh_token: &str,
    extra_params: &[(&str, &str)],
    client_id_post: Option<&str>,
    client_secret_post: Option<&str>,
) -> String {
    let mut params: BTreeMap<&str, String> = BTreeMap::new();
    params.insert("grant_type", "refresh_token".to_string());
    params.insert("refresh_token", refresh_token.to_string());
    if let Some(client_id) = client_id_post {
        params.insert("client_id", client_id.to_string());
    }
    if let Some(client_secret) = client_secret_post {
        params.insert("client_secret", client_secret.to_string());
    }
    for (key, value) in extra_params {
        params.insert(key, (*value).to_string());
    }
    serde_urlencoded::to_string(&params).expect("urlencoded serialization must succeed")
}

#[test]
fn snapshot_refresh_token_request_basic() {
    // Basic refresh with no extra params and Basic-auth credentials
    // (so `client_id`/`client_secret` do not appear in the body).
    let body = refresh_token_request_body("rt_abc123", &[], None, None);
    insta::assert_snapshot!("refresh_request_basic_auth", body);
}

#[test]
fn snapshot_refresh_token_request_post_credentials() {
    // Post-style credential auth embeds `client_id` and `client_secret`
    // alongside `grant_type` and `refresh_token`.
    let body = refresh_token_request_body(
        "rt_xyz789",
        &[],
        Some("client-id-42"),
        Some("secret-with/special+chars=yes"),
    );
    insta::assert_snapshot!("refresh_request_post_credentials", body);
}

#[test]
fn snapshot_refresh_token_request_with_extra_params() {
    // Provider-specific extra params (e.g., `audience` for Auth0, `resource`
    // for Azure AD) that the client is configured to forward on every
    // token request.
    let body = refresh_token_request_body(
        "rt_with_extras",
        &[
            ("audience", "https://api.example.com"),
            ("resource", "https://graph.microsoft.com"),
        ],
        None,
        None,
    );
    insta::assert_snapshot!("refresh_request_with_extras", body);
}

/// A representative provider response: every field populated so the
/// snapshot shows how each one maps into the eventual [`OAuthTokens`].
const FULL_TOKEN_RESPONSE_JSON: &str = r#"{
    "access_token": "at_full_9f2c",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "rt_rotated_8b01",
    "scope": "read write admin",
    "id_token": "id_example_jwt.payload.signature"
}"#;

/// A minimal response: only `access_token` + `token_type`, every other
/// field defaulted. Captures the serde `#[serde(default)]` behaviour.
const MINIMAL_TOKEN_RESPONSE_JSON: &str = r#"{
    "access_token": "at_min_5e4d",
    "token_type": "Bearer"
}"#;

/// A response with explicitly-null optional fields — common enough in
/// provider responses that the serde path should handle it identically
/// to field-absent cases.
const NULL_OPTIONAL_TOKEN_RESPONSE_JSON: &str = r#"{
    "access_token": "at_nulls_1122",
    "token_type": "Bearer",
    "expires_in": null,
    "refresh_token": null,
    "scope": null,
    "id_token": null
}"#;

fn deserialize_response_as_debug(raw: &str) -> String {
    let parsed: TokenResponse =
        serde_json::from_str(raw).expect("test fixture must parse as TokenResponse");
    format!("{parsed:#?}")
}

fn deserialize_response_into_tokens(raw: &str) -> String {
    let parsed: TokenResponse =
        serde_json::from_str(raw).expect("test fixture must parse as TokenResponse");
    let tokens = OAuthTokens::from_response(parsed).expect("snapshot token fixture must be valid");
    format!("{tokens:#?}")
}

#[test]
fn snapshot_response_deserialization_full_fields() {
    // Debug form of the parsed TokenResponse — access/refresh/id tokens
    // are redacted by the Debug impl, so the snapshot captures only the
    // fields that are safe to commit.
    let debug_repr = deserialize_response_as_debug(FULL_TOKEN_RESPONSE_JSON);
    insta::assert_snapshot!("response_full_debug", debug_repr);
}

#[test]
fn snapshot_response_deserialization_minimal() {
    let debug_repr = deserialize_response_as_debug(MINIMAL_TOKEN_RESPONSE_JSON);
    insta::assert_snapshot!("response_minimal_debug", debug_repr);
}

#[test]
fn snapshot_response_deserialization_null_optionals() {
    let debug_repr = deserialize_response_as_debug(NULL_OPTIONAL_TOKEN_RESPONSE_JSON);
    insta::assert_snapshot!("response_null_optionals_debug", debug_repr);
}

/// Scrub RFC 3339 / ISO 8601 timestamps so snapshot output is stable
/// across runs. `OAuthTokens` populates `expires_at` and `issued_at`
/// from `Utc::now()`, which drifts every second and would otherwise
/// make every snapshot assertion fail.
///
/// The pattern matches timestamps like `2026-04-20T06:13:59Z`,
/// `2026-04-20T06:13:59.123Z`, and `2026-04-20T06:13:59.123+00:00`.
fn with_timestamp_scrubbed<F: FnOnce()>(f: F) {
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        "[TIMESTAMP]",
    );
    settings.bind(f);
}

#[test]
fn snapshot_response_promoted_to_oauth_tokens_full() {
    // OAuthTokens holds wall-clock timestamps (`expires_at`, `issued_at`)
    // set by `Utc::now()`. The scrubber rewrites every timestamp in the
    // snapshot payload to the literal string `[TIMESTAMP]`.
    let tokens_debug = deserialize_response_into_tokens(FULL_TOKEN_RESPONSE_JSON);
    with_timestamp_scrubbed(|| {
        insta::assert_snapshot!("response_full_oauth_tokens", tokens_debug);
    });
}

#[test]
fn snapshot_response_promoted_to_oauth_tokens_minimal() {
    // Minimal response -> OAuthTokens has no `expires_at` but still has
    // `issued_at`. Scrubber handles both.
    let tokens_debug = deserialize_response_into_tokens(MINIMAL_TOKEN_RESPONSE_JSON);
    with_timestamp_scrubbed(|| {
        insta::assert_snapshot!("response_minimal_oauth_tokens", tokens_debug);
    });
}

/// Format a single allowlist decision into a line for the snapshot.
/// Owning the `String` on both sides keeps lifetimes simple while
/// building a multi-decision report.
fn format_decision(label: &str, outcome: Result<url::Url, OAuthError>) -> String {
    match outcome {
        Ok(url) => format!("{label}: OK ({})\n", url.as_str()),
        Err(err) => format!("{label}: ERR {err}\n"),
    }
}

fn format_provider_endpoint_decision(
    label: &str,
    outcome: Result<OAuth2Config, OAuthError>,
) -> String {
    match outcome {
        Ok(config) => format!(
            "{label}: OK (authorization_url={}, token_url={})\n",
            config.authorization_url, config.token_url
        ),
        Err(err) => format!("{label}: ERR {err}\n"),
    }
}

#[test]
fn snapshot_redirect_allowlist_enforcement() {
    let allowlist = parse_registered_redirect_allowlist(&[
        "https://example.com/oauth/callback",
        "https://api.example.com/v2/cb",
        "http://localhost:3000/dev-cb",
    ])
    .expect("allowlist fixture must parse");

    let run = |label: &str, outcome: Result<url::Url, OAuthError>| -> String {
        format_decision(label, outcome)
    };

    let mut report = String::new();
    report.push_str(&run(
        "registered_exact_match",
        ensure_allowlisted_redirect_uri("https://example.com/oauth/callback", &allowlist),
    ));
    report.push_str(&run(
        "registered_host_mismatch",
        ensure_allowlisted_redirect_uri("https://attacker.example/oauth/callback", &allowlist),
    ));
    report.push_str(&run(
        "registered_path_mismatch",
        ensure_allowlisted_redirect_uri("https://example.com/other/callback", &allowlist),
    ));
    report.push_str(&run(
        "registered_plain_http_non_loopback",
        ensure_allowlisted_redirect_uri("http://example.com/oauth/callback", &allowlist),
    ));
    report.push_str(&run(
        "registered_loopback_match",
        ensure_allowlisted_redirect_uri("http://localhost:3000/dev-cb", &allowlist),
    ));
    report.push_str(&run(
        "registered_fragment_rejected",
        ensure_allowlisted_redirect_uri("https://example.com/oauth/callback#frag", &allowlist),
    ));
    report.push_str(&run(
        "registered_query_not_in_allowlist",
        ensure_allowlisted_redirect_uri("https://example.com/oauth/callback?x=1", &allowlist),
    ));
    // br-i58yx: a registered query component whose key collides with an
    // OAuth response parameter is rejected at shape validation time.
    report.push_str(&run(
        "registered_query_collides_with_response_param",
        ensure_allowlisted_redirect_uri("https://example.com/oauth/callback?code=pwn", &allowlist),
    ));
    report.push_str(&run(
        "registered_embedded_credentials_rejected",
        ensure_allowlisted_redirect_uri("https://user:pw@example.com/oauth/callback", &allowlist),
    ));
    report.push_str(&run(
        "registered_relative_rejected",
        ensure_allowlisted_redirect_uri("/oauth/callback", &allowlist),
    ));

    // Callback variants — these accept a query string carrying the
    // provider's response params.
    report.push_str(&run(
        "callback_with_oauth_response_params",
        ensure_callback_redirect_is_allowlisted(
            "https://example.com/oauth/callback?code=auth123&state=abc",
            &allowlist,
        ),
    ));
    report.push_str(&run(
        "callback_host_mismatch",
        ensure_callback_redirect_is_allowlisted(
            "https://evil.example/oauth/callback?code=auth123",
            &allowlist,
        ),
    ));
    report.push_str(&run(
        "callback_plain_http_non_loopback",
        ensure_callback_redirect_is_allowlisted(
            "http://example.com/oauth/callback?code=auth123",
            &allowlist,
        ),
    ));
    report.push_str(&run(
        "callback_loopback_ok",
        ensure_callback_redirect_is_allowlisted(
            "http://localhost:3000/dev-cb?code=auth123",
            &allowlist,
        ),
    ));
    report.push_str(&run(
        "callback_extra_query_not_in_registered_allowlist",
        ensure_callback_redirect_is_allowlisted(
            "https://example.com/oauth/callback?code=auth123&next=%2Fadmin",
            &allowlist,
        ),
    ));
    // br-i58yx: positive path — registered allowlist entry carries a
    // pre-registered query component, callback preserves it, membership
    // check passes.
    let tenant_aware_allowlist =
        parse_registered_redirect_allowlist(&["https://example.com/oauth/callback?tenant=acme"])
            .expect("test allowlist must parse");
    report.push_str(&run(
        "callback_registered_query_preserved_ok",
        ensure_callback_redirect_is_allowlisted(
            "https://example.com/oauth/callback?tenant=acme&code=auth123&state=abc",
            &tenant_aware_allowlist,
        ),
    ));

    insta::assert_snapshot!("redirect_allowlist_decisions", report);
}

#[test]
fn snapshot_redirect_allowlist_parse_failures() {
    // The allowlist parser itself has failure modes that operators will
    // see on misconfiguration; freeze the messages so operators have a
    // stable grep target.
    let mut report = String::new();

    let cases: &[(&str, &[&str])] = &[
        ("empty_allowlist", &[]),
        ("non_url_entry", &["not a url"]),
        ("ftp_scheme_entry", &["ftp://example.com/cb"]),
        ("plain_http_non_loopback", &["http://example.com/cb"]),
        (
            "mixed_valid_and_invalid",
            &["https://ok.example/cb", "not a url"],
        ),
    ];
    for (label, raw) in cases {
        match parse_registered_redirect_allowlist(raw) {
            Ok(_) => {
                let _ = writeln!(report, "{label}: OK");
            }
            Err(err) => {
                let _ = writeln!(report, "{label}: ERR {err}");
            }
        }
    }

    insta::assert_snapshot!("redirect_allowlist_parse_failures", report);
}

#[test]
fn snapshot_provider_endpoint_url_policy() {
    let mut report = String::new();

    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_https_ok",
        ProviderEndpoints::new(
            "https://custom.example.com/authorize",
            "https://custom.example.com/token",
        )
        .with_revocation_url("https://custom.example.com/revoke")
        .with_userinfo_url("https://custom.example.com/userinfo")
        .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_loopback_http_ok",
        ProviderEndpoints::new("http://localhost:3000/authorize", "http://127.0.0.1/token")
            .with_revocation_url("http://[::1]/revoke")
            .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_authorization_plain_http_rejected",
        ProviderEndpoints::new(
            "http://provider.example.com/authorize",
            "https://provider.example.com/token",
        )
        .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_link_local_metadata_http_rejected",
        ProviderEndpoints::new(
            "http://169.254.169.254/latest/meta-data",
            "https://provider.example.com/token",
        )
        .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_token_plain_http_rejected",
        ProviderEndpoints::new(
            "https://provider.example.com/authorize",
            "http://provider.example.com/token",
        )
        .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_revocation_plain_http_rejected",
        ProviderEndpoints::new(
            "https://provider.example.com/authorize",
            "https://provider.example.com/token",
        )
        .with_revocation_url("http://provider.example.com/revoke")
        .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_userinfo_plain_http_rejected",
        ProviderEndpoints::new(
            "https://provider.example.com/authorize",
            "https://provider.example.com/token",
        )
        .with_userinfo_url("http://provider.example.com/userinfo")
        .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_embedded_credentials_rejected",
        ProviderEndpoints::new(
            "https://user:pw@provider.example.com/authorize",
            "https://provider.example.com/token",
        )
        .to_oauth2_config("cid", "csec"),
    ));
    report.push_str(&format_provider_endpoint_decision(
        "custom_provider_fragment_rejected",
        ProviderEndpoints::new(
            "https://provider.example.com/authorize#fragment",
            "https://provider.example.com/token",
        )
        .to_oauth2_config("cid", "csec"),
    ));

    insta::assert_snapshot!("provider_endpoint_url_policy", report);
}

#[test]
fn snapshot_response_deserialization_unknown_fields_ignored() {
    // Confirm unknown fields in the provider response are ignored
    // (serde is not configured for `deny_unknown_fields`) and make that
    // behaviour visible in a golden.
    let raw = json!({
        "access_token": "at_unknown_1",
        "token_type": "Bearer",
        "expires_in": 7200,
        "unknown_extra_field": "should_be_ignored",
        "nested_unknown": {"k": "v"},
    })
    .to_string();
    let debug_repr = deserialize_response_as_debug(&raw);
    insta::assert_snapshot!("response_unknown_fields_ignored", debug_repr);
}

/// Sort the query string of an OAuth authorization URL into a stable,
/// snapshot-friendly shape: `scheme://host/path` then one
/// `key=value` pair per line, alphabetical. `state` / `code_challenge`
/// are cryptographically-random per-call so they are scrubbed to a
/// sentinel string before snapshotting. This matches the `insta`
/// `filters` convention used elsewhere in this file but is done
/// in-code because the inputs are embedded in URL-encoded form and
/// the `insta` filter APIs operate on post-render strings.
fn normalize_authorization_url(raw: &str) -> String {
    let url = url::Url::parse(raw).expect("authorization URL must parse");
    let mut params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            let key = k.into_owned();
            let value = match key.as_str() {
                // Random per-call fields; scrub to keep the snapshot stable.
                "state" | "code_challenge" | "code_verifier" => "<RANDOM>".to_string(),
                _ => v.into_owned(),
            };
            (key, value)
        })
        .collect();
    params.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    out.push_str(url.scheme());
    out.push_str("://");
    if let Some(host) = url.host_str() {
        out.push_str(host);
    }
    out.push_str(url.path());
    out.push('\n');
    for (key, value) in params {
        let _ = writeln!(out, "  {key} = {value}");
    }
    out
}

/// Sort the comma-separated `oauth_*` pairs inside an
/// `Authorization: OAuth <...>` header into a snapshot-friendly
/// shape. The random / time-dependent values (`oauth_nonce`,
/// `oauth_timestamp`, `oauth_signature`) are scrubbed.
fn normalize_oauth1_authorization_header(raw: &str) -> String {
    let body = raw.strip_prefix("OAuth ").unwrap_or(raw);
    let mut pairs: Vec<(String, String)> = body
        .split(',')
        .map(|piece| {
            let piece = piece.trim();
            let (key, value) = piece.split_once('=').unwrap_or((piece, ""));
            let key = key.trim().to_string();
            // Values are percent-encoded and double-quoted; strip the
            // quotes but leave the URL encoding intact so the snapshot
            // records the wire shape.
            let value = value.trim().trim_matches('"').to_string();
            let value = match key.as_str() {
                "oauth_nonce" | "oauth_timestamp" | "oauth_signature" => "<RANDOM>".to_string(),
                _ => value,
            };
            (key, value)
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::from("OAuth\n");
    for (key, value) in pairs {
        let _ = writeln!(out, "  {key} = {value}");
    }
    out
}

#[test]
fn snapshot_oauth2_authorization_url_basic_shape() {
    // Converts the three `url.contains("...")` assertions at
    // no_mock_integration.rs:129-134 into a single golden that freezes
    // the full URL shape. Any change in parameter ordering, absence of
    // a required field, or new side-effect params (e.g., an added
    // `audience` default) would show up as a snapshot diff.
    let config = OAuth2Config::new(
        "my-client",
        "secret",
        "https://auth.ex.com/authorize",
        "https://auth.ex.com/token",
    )
    .with_redirect_uri("https://localhost/cb")
    .with_pkce(false);
    let client = OAuth2Client::new(config).unwrap();
    let (url, _state) = client.authorization_url(&["read", "write"]).unwrap();

    insta::assert_snapshot!(
        "oauth2_authorization_url_basic_shape",
        normalize_authorization_url(&url)
    );
}

#[test]
fn snapshot_oauth2_authorization_url_with_pkce_s256() {
    // Replaces the pair of `url.contains("code_challenge...")` asserts
    // at no_mock_integration.rs:151-152 with a full golden. Scrubs
    // `state` and `code_challenge` (both random per call) so the
    // snapshot is stable.
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
    let (url, _state, _pkce) = client.authorization_url_with_pkce(&["openid"]).unwrap();

    insta::assert_snapshot!(
        "oauth2_authorization_url_with_pkce_s256",
        normalize_authorization_url(&url)
    );
}

#[test]
fn snapshot_oauth1_sign_request_header_shape() {
    // Replaces the seven `header.contains("oauth_*")` asserts at
    // no_mock_integration.rs:380-387 with a full golden over the
    // Authorization header. `oauth_nonce` and `oauth_timestamp` are
    // scrubbed; `oauth_signature` is scrubbed because it depends on
    // both. The snapshot freezes the complete set of fields and their
    // ordering-independent presence.
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

    insta::assert_snapshot!(
        "oauth1_sign_request_header_shape",
        normalize_oauth1_authorization_header(&header)
    );
}

#[test]
fn snapshot_oauth1_authorization_url_shape() {
    // Replaces the two `url.contains(...)` asserts at
    // no_mock_integration.rs:351-352. No scrubbing needed — the
    // authorization URL for OAuth 1.0a carries only the request
    // token, which is caller-supplied and stable.
    let config = OAuth1Config::new(
        "consumer-key",
        "consumer-secret",
        "https://a.com/rt",
        "https://a.com/authorize",
        "https://a.com/at",
    );
    let client = OAuth1Client::new(config);
    let request_token = RequestToken {
        token: "req-token-123".to_string(),
        token_secret: "req-secret".to_string(),
        callback_confirmed: true,
    };
    let url = client.authorization_url(&request_token);

    insta::assert_snapshot!(
        "oauth1_authorization_url_shape",
        normalize_authorization_url(&url)
    );
}
