//! OAuth redirect URI allowlist enforcement.
//!
//! Connectors that mint OAuth authorization URLs and consume provider
//! callbacks need to defend against being used as a confused deputy: a
//! caller-supplied `redirect_uri` (or a callback URL whose redirect was
//! attacker-influenced) must be confined to a list the operator
//! pre-registered. The shape of that defense is identical across every
//! OAuth-bearing connector — github landed it first
//! (`connectors/github/src/connector.rs:1361..1456`), and the tracking
//! bead `flywheel_connectors-pizld` calls for promoting it so other
//! connectors don't reinvent it (or, worse, skip it).
//!
//! This module owns:
//!
//! - [`validate_redirect_uri_shape`] — the structural rules every
//!   redirect URI must satisfy regardless of allowlist membership: must
//!   have a network host, no embedded user/password, no fragment,
//!   optionally no query, and a secure scheme (`https` or `http`
//!   pointing at a loopback address).
//! - [`is_secure_or_loopback_redirect`] — the scheme/host predicate
//!   underlying the secure-scheme check, exposed so callers building
//!   their own validators reuse the same definition.
//! - [`normalize_registered_redirect_uri`] — parse-and-validate for
//!   URIs the operator pre-registers (no query allowed).
//! - [`normalize_callback_redirect_uri`] — parse-and-validate for the
//!   provider callback URL (query is allowed but stripped from the
//!   normalized form so equality against the allowlist matches).
//! - [`ensure_allowlisted_redirect_uri`] — full enforcement: parse,
//!   validate shape, confirm membership in the allowlist.
//! - [`ensure_callback_redirect_is_allowlisted`] — the callback
//!   variant of the above.
//! - [`parse_registered_redirect_allowlist`] — convenience for
//!   normalizing an entire allowlist at admin-config load time so
//!   bad entries fail loudly rather than at the first request.
//!
//! All functions surface failures through [`OAuthError::InvalidConfig`]
//! with operator-actionable messages that name the offending field.

use crate::error::{OAuthError, OAuthResult};
use url::Url;

/// Whether a parsed URL is permitted as an OAuth redirect target by scheme.
///
/// `https` is always acceptable; `http` is acceptable only when the host
/// resolves to a loopback address (`localhost`, `127.0.0.1`, or `::1`) so
/// local development workflows remain usable without opening a redirect to
/// arbitrary plaintext destinations.
///
/// Uses [`Url::host`] (typed) rather than [`Url::host_str`] so the
/// IPv6 loopback check works regardless of how the host was rendered:
/// `http://[::1]/` round-trips through `host_str()` as `"[::1]"` (with
/// brackets) but `host()` yields `Host::Ipv6(::1)` directly, which we
/// can compare without worrying about the bracket convention.
#[must_use]
pub fn is_secure_or_loopback_redirect(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        },
        _ => false,
    }
}

/// Validate the structural shape of a redirect URI.
///
/// `field` is the operator-facing name of the field being validated
/// (e.g. `"redirect_uri"`, `"callback_url"`, or
/// `"allowed_redirect_uris"`). It appears verbatim in error messages so
/// bad input can be located in the request payload.
///
/// `allow_query` controls whether a non-empty query string is permitted
/// — set `true` for callback URLs (the provider appends `code=` and
/// `state=` query params), `false` for the operator-registered allowlist
/// entries and the `redirect_uri` parameter on the authorize request.
///
/// # Errors
///
/// Returns [`OAuthError::InvalidConfig`] with an operator-actionable
/// message if the URL violates any of:
///
/// - missing network host (relative URLs, opaque schemes)
/// - embedded `user`/`password` credentials
/// - non-empty fragment
/// - non-empty query when `allow_query == false`
/// - scheme that is neither `https` nor loopback `http`
pub fn validate_redirect_uri_shape(url: &Url, field: &str, allow_query: bool) -> OAuthResult<()> {
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(OAuthError::InvalidConfig(format!(
            "{field} must include a network host"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OAuthError::InvalidConfig(format!(
            "{field} must not include embedded credentials"
        )));
    }
    if url.fragment().is_some() {
        return Err(OAuthError::InvalidConfig(format!(
            "{field} must not include a fragment"
        )));
    }
    if !allow_query && url.query().is_some() {
        return Err(OAuthError::InvalidConfig(format!(
            "{field} must not include query parameters"
        )));
    }
    if !is_secure_or_loopback_redirect(url) {
        return Err(OAuthError::InvalidConfig(format!(
            "{field} must use https or loopback http"
        )));
    }
    Ok(())
}

/// Parse and validate a redirect URI that an operator pre-registered.
///
/// Applies to entries in the allowlist plus the `redirect_uri` echoed
/// back on the authorization request. Query parameters and fragments
/// are rejected because the registered URI has to match the provider's
/// stored value byte-for-byte modulo encoding.
///
/// # Errors
///
/// Returns [`OAuthError::InvalidConfig`] if the URI is unparseable or
/// fails [`validate_redirect_uri_shape`].
pub fn normalize_registered_redirect_uri(raw: &str, field: &str) -> OAuthResult<Url> {
    let url = Url::parse(raw).map_err(|e| {
        OAuthError::InvalidConfig(format!("{field} must be a valid absolute URL: {e}"))
    })?;
    validate_redirect_uri_shape(&url, field, false)?;
    Ok(url)
}

/// Parse and validate a provider callback URL.
///
/// Returns the normalized form with the OAuth response parameters
/// (`code`, `state`, `error`) stripped. The stripped form is what
/// should be compared against the allowlist — if comparison were done
/// against the raw callback URL with the query intact, every match
/// would fail.
///
/// # Errors
///
/// Returns [`OAuthError::InvalidConfig`] if the URI is unparseable or
/// fails [`validate_redirect_uri_shape`] (with `allow_query = true`,
/// since the provider's callback always carries query parameters).
pub fn normalize_callback_redirect_uri(callback_url: &str) -> OAuthResult<Url> {
    let mut url = Url::parse(callback_url).map_err(|e| {
        OAuthError::InvalidConfig(format!("callback_url must be a valid absolute URL: {e}"))
    })?;
    validate_redirect_uri_shape(&url, "callback_url", true)?;
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// Confirm a caller-supplied `redirect_uri` is byte-equal (modulo
/// canonicalisation by [`Url`]) to one of the operator-registered
/// allowlist entries.
///
/// # Errors
///
/// Returns [`OAuthError::InvalidConfig`] with a message naming
/// `redirect_uri` if validation fails or no allowlist entry matches.
pub fn ensure_allowlisted_redirect_uri(raw: &str, allowlist: &[Url]) -> OAuthResult<Url> {
    let redirect_uri = normalize_registered_redirect_uri(raw, "redirect_uri")?;
    if allowlist.contains(&redirect_uri) {
        return Ok(redirect_uri);
    }
    Err(OAuthError::InvalidConfig(
        "redirect_uri is not present in allowed_redirect_uris".to_string(),
    ))
}

/// The callback variant of [`ensure_allowlisted_redirect_uri`].
///
/// Parses the provider's full callback URL, strips the OAuth response
/// query parameters, and compares the resulting registered-shape URI
/// against the allowlist.
///
/// # Errors
///
/// Returns [`OAuthError::InvalidConfig`] if the callback is malformed
/// or its inferred redirect URI is not in the allowlist.
pub fn ensure_callback_redirect_is_allowlisted(
    callback_url: &str,
    allowlist: &[Url],
) -> OAuthResult<Url> {
    let callback_redirect_uri = normalize_callback_redirect_uri(callback_url)?;
    if allowlist.contains(&callback_redirect_uri) {
        return Ok(callback_redirect_uri);
    }
    Err(OAuthError::InvalidConfig(
        "callback_url resolved to a redirect URI outside allowed_redirect_uris".to_string(),
    ))
}

/// Normalize an entire registered-redirect-URI allowlist.
///
/// Call this once when configuration is read so the per-request
/// enforcement path stays branch-free on the allowlist itself — every
/// entry has already been parsed and shape-checked by the time a
/// request arrives.
///
/// # Errors
///
/// Returns [`OAuthError::InvalidConfig`] if `raw` is empty or any entry
/// fails [`normalize_registered_redirect_uri`].
pub fn parse_registered_redirect_allowlist(raw: &[&str]) -> OAuthResult<Vec<Url>> {
    if raw.is_empty() {
        return Err(OAuthError::InvalidConfig(
            "allowed_redirect_uris must not be empty".to_string(),
        ));
    }
    raw.iter()
        .map(|entry| normalize_registered_redirect_uri(entry, "allowed_redirect_uris"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist(raw: &[&str]) -> Vec<Url> {
        parse_registered_redirect_allowlist(raw).expect("test allowlist must parse")
    }

    // ── is_secure_or_loopback_redirect ─────────────────────────────────────

    #[test]
    fn is_secure_accepts_https_anywhere() {
        let url = Url::parse("https://example.com/callback").unwrap();
        assert!(is_secure_or_loopback_redirect(&url));
    }

    #[test]
    fn is_secure_accepts_http_loopback_hostname() {
        let url = Url::parse("http://localhost:8080/callback").unwrap();
        assert!(is_secure_or_loopback_redirect(&url));
    }

    #[test]
    fn is_secure_accepts_http_loopback_ipv4() {
        let url = Url::parse("http://127.0.0.1:8080/callback").unwrap();
        assert!(is_secure_or_loopback_redirect(&url));
    }

    #[test]
    fn is_secure_accepts_http_loopback_ipv6() {
        let url = Url::parse("http://[::1]:8080/callback").unwrap();
        assert!(is_secure_or_loopback_redirect(&url));
    }

    #[test]
    fn is_secure_rejects_http_to_public_host() {
        let url = Url::parse("http://example.com/callback").unwrap();
        assert!(!is_secure_or_loopback_redirect(&url));
    }

    #[test]
    fn is_secure_rejects_unknown_scheme() {
        let url = Url::parse("ftp://example.com/callback").unwrap();
        assert!(!is_secure_or_loopback_redirect(&url));
    }

    // ── validate_redirect_uri_shape ────────────────────────────────────────

    #[test]
    fn shape_accepts_clean_https_uri() {
        let url = Url::parse("https://example.com/callback").unwrap();
        validate_redirect_uri_shape(&url, "redirect_uri", false).unwrap();
    }

    #[test]
    fn shape_rejects_embedded_credentials() {
        let url = Url::parse("https://user:pw@example.com/callback").unwrap();
        let err = validate_redirect_uri_shape(&url, "redirect_uri", false).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("credentials")));
    }

    #[test]
    fn shape_rejects_fragment() {
        let url = Url::parse("https://example.com/callback#frag").unwrap();
        let err = validate_redirect_uri_shape(&url, "redirect_uri", false).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("fragment")));
    }

    #[test]
    fn shape_rejects_query_when_disallowed() {
        let url = Url::parse("https://example.com/callback?code=x").unwrap();
        let err = validate_redirect_uri_shape(&url, "redirect_uri", false).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("query")));
    }

    #[test]
    fn shape_allows_query_when_allowed() {
        let url = Url::parse("https://example.com/callback?code=x&state=y").unwrap();
        validate_redirect_uri_shape(&url, "callback_url", true).unwrap();
    }

    #[test]
    fn shape_rejects_plaintext_http_to_public_host() {
        let url = Url::parse("http://example.com/callback").unwrap();
        let err = validate_redirect_uri_shape(&url, "redirect_uri", false).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("https or loopback")));
    }

    #[test]
    fn shape_rejects_data_uri() {
        let url = Url::parse("data:text/plain,hi").unwrap();
        let err = validate_redirect_uri_shape(&url, "redirect_uri", false).unwrap_err();
        // `data:` is `cannot_be_a_base()` — host check fires first.
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("network host")));
    }

    // ── normalize_registered_redirect_uri ──────────────────────────────────

    #[test]
    fn normalize_registered_strips_nothing_but_validates() {
        let url =
            normalize_registered_redirect_uri("https://example.com/cb", "allowed_redirect_uris")
                .unwrap();
        assert_eq!(url.as_str(), "https://example.com/cb");
    }

    #[test]
    fn normalize_registered_rejects_query() {
        let err = normalize_registered_redirect_uri(
            "https://example.com/cb?x=1",
            "allowed_redirect_uris",
        )
        .unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("query")));
    }

    #[test]
    fn normalize_registered_field_name_appears_in_error() {
        let err = normalize_registered_redirect_uri("not a url", "redirect_uri").unwrap_err();
        let display = err.to_string();
        assert!(display.contains("redirect_uri"));
    }

    // ── normalize_callback_redirect_uri ────────────────────────────────────

    #[test]
    fn normalize_callback_strips_query_for_allowlist_comparison() {
        let url =
            normalize_callback_redirect_uri("https://example.com/cb?code=abc&state=def").unwrap();
        // The OAuth callback carries query params, but the normalized
        // form used for allowlist comparison must not.
        assert_eq!(url.as_str(), "https://example.com/cb");
    }

    #[test]
    fn normalize_callback_rejects_fragment_per_validate_shape() {
        // Fragments are rejected by `validate_redirect_uri_shape`
        // unconditionally — even on the callback path. OAuth response
        // parameters travel in the query string for the authorization
        // code grant; fragments are reserved for the implicit-grant
        // flow, which this connector surface does not support.
        let err =
            normalize_callback_redirect_uri("https://example.com/cb?code=abc#frag").unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("fragment")));
    }

    #[test]
    fn normalize_callback_rejects_credentials() {
        let err = normalize_callback_redirect_uri("https://u:p@example.com/cb?code=x").unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("credentials")));
    }

    // ── ensure_allowlisted_redirect_uri ────────────────────────────────────

    #[test]
    fn allowlist_accepts_exact_match() {
        let allowed = allowlist(&["https://example.com/cb"]);
        let url = ensure_allowlisted_redirect_uri("https://example.com/cb", &allowed).unwrap();
        assert_eq!(url.as_str(), "https://example.com/cb");
    }

    #[test]
    fn allowlist_rejects_unregistered_host() {
        let allowed = allowlist(&["https://example.com/cb"]);
        let err =
            ensure_allowlisted_redirect_uri("https://evil.example.com/cb", &allowed).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("not present")));
    }

    #[test]
    fn allowlist_rejects_unregistered_path() {
        let allowed = allowlist(&["https://example.com/cb"]);
        let err =
            ensure_allowlisted_redirect_uri("https://example.com/admin/cb", &allowed).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("not present")));
    }

    #[test]
    fn allowlist_rejects_unregistered_scheme() {
        // The shape check fires before the membership check — http to a
        // non-loopback host is the deeper failure.
        let allowed = allowlist(&["https://example.com/cb"]);
        let err = ensure_allowlisted_redirect_uri("http://example.com/cb", &allowed).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("https or loopback")));
    }

    // ── ensure_callback_redirect_is_allowlisted ────────────────────────────

    #[test]
    fn callback_strip_then_allowlist_accepts_match() {
        let allowed = allowlist(&["https://example.com/cb"]);
        let url = ensure_callback_redirect_is_allowlisted(
            "https://example.com/cb?code=abc&state=def",
            &allowed,
        )
        .unwrap();
        // Returned URL is the normalised (query-stripped) form so the
        // caller can use it as a stable key.
        assert_eq!(url.as_str(), "https://example.com/cb");
    }

    #[test]
    fn callback_rejects_evil_origin_even_with_matching_path() {
        let allowed = allowlist(&["https://example.com/cb"]);
        let err = ensure_callback_redirect_is_allowlisted(
            "https://evil.example.com/cb?code=abc",
            &allowed,
        )
        .unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("outside")));
    }

    // ── parse_registered_redirect_allowlist ────────────────────────────────

    #[test]
    fn parse_allowlist_rejects_empty_input() {
        let err = parse_registered_redirect_allowlist(&[]).unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("empty")));
    }

    #[test]
    fn parse_allowlist_propagates_per_entry_error() {
        let err = parse_registered_redirect_allowlist(&[
            "https://example.com/cb",
            "http://evil.example.com/cb",
        ])
        .unwrap_err();
        // The second entry is what fails: plaintext http to a non-loopback
        // host.
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("https or loopback")));
    }

    #[test]
    fn parse_allowlist_accepts_mixed_loopback_and_https() {
        let allowed = parse_registered_redirect_allowlist(&[
            "https://example.com/cb",
            "http://localhost:3000/cb",
            "http://127.0.0.1:8080/cb",
            "http://[::1]:9000/cb",
        ])
        .unwrap();
        assert_eq!(allowed.len(), 4);
    }

    // ── confused-deputy regression scenarios ───────────────────────────────

    #[test]
    fn confused_deputy_attacker_supplied_redirect_with_match_path_rejected() {
        // The classic confused-deputy: attacker tries to swap the host
        // while keeping a path that "looks legit" relative to the
        // allowlist entry.
        let allowed = allowlist(&["https://app.legit.example/oauth/callback"]);
        let err =
            ensure_allowlisted_redirect_uri("https://app.evil.example/oauth/callback", &allowed)
                .unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("not present")));
    }

    #[test]
    fn embedded_credentials_blocked_even_inside_allowlisted_host() {
        // `https://attacker:password@example.com/cb` — host matches but
        // the embedded creds are rejected at the shape check before the
        // allowlist comparison runs.
        let allowed = allowlist(&["https://example.com/cb"]);
        let err =
            ensure_allowlisted_redirect_uri("https://attacker:password@example.com/cb", &allowed)
                .unwrap_err();
        assert!(matches!(err, OAuthError::InvalidConfig(ref m) if m.contains("credentials")));
    }
}
