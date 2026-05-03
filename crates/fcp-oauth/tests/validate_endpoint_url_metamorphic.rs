//! Metamorphic tests for `validate_oauth_endpoint_url` (br-f34558bc9).
//!
//! The dedup landed in commit f34558bc9 collapsed two near-identical URL
//! validation paths into a single canonical entry-point. Pre-fix the
//! inline copy in `oauth2.rs::validate_oauth2_config` could drift from
//! `redirect_allowlist::validate_oauth_endpoint_url` and admit different
//! URLs depending on which API a caller used. The dedup makes the two
//! paths share one function — but a future refactor could reintroduce
//! drift.
//!
//! Two metamorphic relations pin the contract:
//!
//! - **MR.dedup (call-site verdict equivalence)** — for any URL string
//!   `s`, `validate_oauth_endpoint_url(s, ...)` agrees with
//!   `OAuth2Client::new(OAuth2Config::new(_, _, s, _))` on accept-vs-reject.
//!   Ok(direct) ⇔ Ok(via OAuth2Client). Catches any reintroduced inline
//!   drift OR a refactor that removes the call from
//!   `validate_oauth2_config`.
//!
//! - **MR.field-symmetry (authorization_url ≡ token_url)** — both
//!   endpoint fields go through the same validator with only the field
//!   label differing. Validating the same URL as `authorization_url`
//!   vs `token_url` MUST produce the same accept-vs-reject verdict
//!   (the field name only affects the error message text).

use fcp_oauth::{OAuth2Client, OAuth2Config, validate_oauth_endpoint_url};
use proptest::prelude::*;

/// Generate a URL-shaped string from a small grammar that hits each
/// branch of the validator: scheme, credentials, host, fragment, query.
/// Bias toward "almost-valid" shapes so the verdicts split between Ok
/// and Err — testing inputs that ALL pass or ALL fail wouldn't catch
/// drift between the two paths.
fn arb_endpoint_url() -> impl Strategy<Value = String> {
    prop_oneof![
        // Always-valid HTTPS endpoints
        Just("https://provider.example.com/oauth/authorize".to_string()),
        Just("https://provider.example.com/oauth/token".to_string()),
        Just("https://api.example.com/v2/oauth?audience=widgets".to_string()),
        // Loopback http (allowed by policy)
        Just("http://127.0.0.1:8080/oauth/authorize".to_string()),
        Just("http://localhost:9999/oauth/token".to_string()),
        // Plain http on non-loopback (rejected: must be https-or-loopback)
        Just("http://provider.example.com/oauth/authorize".to_string()),
        // Embedded creds (rejected)
        Just("https://user:pass@provider.example.com/oauth/authorize".to_string()),
        Just("https://user@provider.example.com/oauth/authorize".to_string()),
        // Fragment (rejected)
        Just("https://provider.example.com/oauth/authorize#frag".to_string()),
        // Missing host (rejected — cannot_be_a_base or no host)
        Just("file:///etc/passwd".to_string()),
        Just("data:text/plain,hi".to_string()),
        // Unparseable (rejected)
        Just("not a url at all".to_string()),
        Just(String::new()),
        Just("https://".to_string()),
        // Random-prefix HTTPS to widen the input space cheaply
        "[a-z]{3,8}".prop_map(|host| format!("https://{host}.example.com/auth")),
    ]
}

proptest! {
    /// MR.dedup: the two paths MUST agree on accept-vs-reject.
    ///
    /// Pre-dedup the inline `validate_oauth_endpoint_url` body in
    /// `oauth2.rs` could have drifted from the canonical body in
    /// `redirect_allowlist.rs`. This MR pins that whatever the
    /// canonical predicate accepts, `OAuth2Client::new` accepts via
    /// its `validate_oauth2_config` dispatch — and conversely.
    #[test]
    fn mr_dedup_canonical_validator_agrees_with_oauth2_client_construction(
        url in arb_endpoint_url(),
    ) {
        let direct = validate_oauth_endpoint_url(&url, "authorization_url");

        // Pair the candidate `url` with a known-good token_url so the
        // OAuth2Client::new outcome is determined by the auth_url
        // field alone. The token_url choice is canonical-valid (loopback
        // http, also accepted by the validator) so it never spuriously
        // fails the indirect path.
        let token_url = "https://provider.example.com/oauth/token";
        let config = OAuth2Config::new("client-id", "client-secret", url.clone(), token_url);
        let indirect = OAuth2Client::new(config);

        prop_assert_eq!(
            direct.is_ok(),
            indirect.is_ok(),
            "br-f34558bc9 MR.dedup violated: validate_oauth_endpoint_url and \
             OAuth2Client::new disagree on URL `{}` — direct={:?}, indirect={:?}. \
             A drift between the canonical validator and the call-site means an \
             attacker can sneak a bad URL through the path that uses the looser \
             check.",
            url,
            direct.as_ref().map(|_| "Ok"),
            indirect.as_ref().map(|_| "Ok"),
        );
    }

    /// MR.field-symmetry: the auth_url and token_url fields share one
    /// validator with only the field label differing. Pin that the same
    /// URL gets the same verdict in either field slot.
    ///
    /// Pre-dedup nothing structurally tied the two field-call sites
    /// together; a refactor could have edited one and not the other.
    /// Post-dedup both calls go through the same function — this MR
    /// catches any future code that reintroduces a per-field validator
    /// branch.
    #[test]
    fn mr_field_symmetry_authorization_and_token_urls_agree(
        url in arb_endpoint_url(),
    ) {
        let known_good = "https://provider.example.com/oauth/auth";

        // Probe URL placed in authorization_url; token_url is canonical.
        let auth_first = OAuth2Client::new(OAuth2Config::new(
            "cid",
            "csec",
            url.clone(),
            known_good,
        ))
        .is_ok();

        // Same probe URL placed in token_url; authorization_url is canonical.
        let token_first = OAuth2Client::new(OAuth2Config::new(
            "cid",
            "csec",
            known_good,
            url.clone(),
        ))
        .is_ok();

        prop_assert_eq!(
            auth_first,
            token_first,
            "br-f34558bc9 MR.field-symmetry violated: URL `{}` accepted in one \
             endpoint slot and rejected in the other (auth_first={}, token_first={}). \
             Both slots must apply the SAME validator predicate; per-slot drift \
             would let an attacker pin a malicious URL into whichever slot has \
             the looser check.",
            url,
            auth_first,
            token_first,
        );
    }
}

/// Targeted regression: a hand-built short list of canonical-shape URLs
/// that MUST all agree under both MRs. Acts as a smoke floor so a
/// proptest config that shrinks too aggressively still catches the
/// most common drift.
#[test]
fn mr_dedup_smoke_floor_on_canonical_inputs() {
    let token_url = "https://provider.example.com/oauth/token";
    let cases = [
        ("https://provider.example.com/oauth/authorize", true),
        ("http://127.0.0.1:9999/oauth/authorize", true),
        ("http://provider.example.com/oauth/authorize", false),
        ("https://user:pw@provider.example.com/auth", false),
        ("https://provider.example.com/auth#anchor", false),
        ("not a url", false),
    ];

    for (url, expected_ok) in cases {
        let direct = validate_oauth_endpoint_url(url, "authorization_url").is_ok();
        let indirect = OAuth2Client::new(OAuth2Config::new("cid", "csec", url, token_url)).is_ok();

        assert_eq!(
            direct, expected_ok,
            "smoke floor: validate_oauth_endpoint_url(`{url}`) expected Ok={expected_ok}, got {direct}"
        );
        assert_eq!(
            indirect, expected_ok,
            "smoke floor: OAuth2Client::new with auth_url=`{url}` expected Ok={expected_ok}, got {indirect}"
        );
    }
}
