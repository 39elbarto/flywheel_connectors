//! Operator-safe redaction helpers for connector retry/log code.
//!
//! Bead: `flywheel_connectors-ptb6n` (H.3 production-hardening
//! audit closure). Connector retry paths historically logged full
//! request URLs at debug level — those URLs frequently carry
//! user/account/resource IDs in the path or query string. This
//! module provides [`redact_url`], the canonical operator-safe
//! rendering: `scheme://host[:port] + path-prefix`, with opaque-id
//! path components replaced with `<id>`, no query string, no
//! fragment.
//!
//! # Contract
//!
//! For an input like `https://api.github.com/repos/octocat/private/issues/42?token=abc#frag`
//! the helper returns `https://api.github.com/repos/octocat/private/issues/<id>`
//! — preserving the route shape (operators can see WHICH endpoint
//! was hit) while stripping the user-identifying fragment, the
//! query (which may carry tokens or filters), and any opaque
//! numeric / UUID-shaped trailing path component.
//!
//! # Heuristics
//!
//! A path component is treated as an opaque id when ANY of:
//!   * Length ≥ 16 (typical for UUIDs, opaque IDs, base64 tokens)
//!   * Composed entirely of digits (numeric IDs of any length)
//!   * Composed entirely of hex characters AND length ≥ 8
//!     (covers BLAKE3 / SHA fragments commonly used as IDs)
//!
//! These heuristics are deliberately conservative: a slug like
//! `octocat` (alphanumeric, length < 16) is preserved because it
//! aids operators inspecting logs; a UUID like
//! `f47ac10b-58cc-4372-a567-0e02b2c3d479` is redacted because it is
//! correlation-bearing PII.
//!
//! # Failure mode
//!
//! On any URL parse failure the helper returns the literal string
//! `"<unparseable-url>"` — never echoing the input back. This is
//! defensive: a malformed input must not bypass the redaction.
//!
//! # Examples
//!
//! ```
//! use fcp_prelude::log_redaction::redact_url;
//!
//! assert_eq!(
//!     redact_url("https://api.github.com/repos/octocat/private/issues/42?token=abc"),
//!     "https://api.github.com/repos/octocat/private/issues/<id>"
//! );
//! assert_eq!(
//!     redact_url("https://api.example.com/v1/users/f47ac10b-58cc-4372-a567-0e02b2c3d479"),
//!     "https://api.example.com/v1/users/<id>"
//! );
//! assert_eq!(
//!     redact_url("https://api.example.com/v1/health"),
//!     "https://api.example.com/v1/health"
//! );
//! ```

/// Render a URL in operator-safe form for log emission.
///
/// See module-level docs for the full contract. Briefly:
///
///   * `scheme://host[:port]` is preserved verbatim
///   * Path components that look like opaque IDs are replaced with
///     `<id>`
///   * Query string and fragment are dropped entirely
///   * Parse failure returns `"<unparseable-url>"` — never echoes
///     the input back
#[must_use]
pub fn redact_url(input: &str) -> String {
    let trimmed = input.trim();
    // Find the scheme separator. Without `://` we can't safely tell
    // host from path, so fall through to the unparseable bucket.
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return UNPARSEABLE.to_string();
    };
    if scheme.is_empty() || rest.is_empty() {
        return UNPARSEABLE.to_string();
    }
    // Validate scheme is alphanumeric+`+-.` per RFC 3986.
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return UNPARSEABLE.to_string();
    }

    // Strip query and fragment.
    let no_query = rest.split_once('?').map_or(rest, |(p, _)| p);
    let no_fragment = no_query.split_once('#').map_or(no_query, |(p, _)| p);

    // Split off the host (and optional port + userinfo) from the path.
    // userinfo (`user:pass@host`) is dropped entirely — credentials in
    // URLs are sensitive even when the rest of the URL is benign.
    let (authority, path) = no_fragment
        .split_once('/')
        .map_or((no_fragment, ""), |(a, p)| (a, p));
    if authority.is_empty() {
        return UNPARSEABLE.to_string();
    }
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_userinfo, host)| host);

    // Walk the path, redacting opaque-id components.
    let mut out = String::with_capacity(input.len());
    out.push_str(scheme);
    out.push_str("://");
    out.push_str(host_port);
    if !path.is_empty() {
        for segment in path.split('/') {
            out.push('/');
            if segment.is_empty() {
                continue;
            }
            if looks_like_opaque_id(segment) {
                out.push_str("<id>");
            } else {
                out.push_str(segment);
            }
        }
    }
    out
}

/// Sentinel returned on URL parse failure. Stable across releases —
/// log-search dashboards may key off it.
pub const UNPARSEABLE: &str = "<unparseable-url>";

/// Heuristic for "this path component is an opaque ID worth
/// redacting". See module-level docs for the full criteria.
fn looks_like_opaque_id(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    // All-digits → numeric id.
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // All-hex AND length ≥ 8 → hash/uuid-shaped id.
    let all_hex = segment.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if all_hex && segment.len() >= 8 {
        return true;
    }
    // Long opaque tokens.
    if segment.len() >= 16 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_full_url_with_query_and_fragment() {
        assert_eq!(
            redact_url("https://api.github.com/repos/octocat/private/issues/42?token=abc#frag"),
            "https://api.github.com/repos/octocat/private/issues/<id>"
        );
    }

    #[test]
    fn preserves_route_with_short_alphabetic_components() {
        // `octocat`, `private`, `issues` are operator-useful breadcrumbs
        // and should NOT be redacted.
        assert_eq!(
            redact_url("https://api.github.com/repos/octocat/private/issues"),
            "https://api.github.com/repos/octocat/private/issues"
        );
    }

    #[test]
    fn redacts_uuid_path_component() {
        assert_eq!(
            redact_url("https://api.example.com/v1/users/f47ac10b-58cc-4372-a567-0e02b2c3d479"),
            "https://api.example.com/v1/users/<id>"
        );
    }

    #[test]
    fn redacts_numeric_id_of_any_length() {
        assert_eq!(
            redact_url("https://api.example.com/users/1"),
            "https://api.example.com/users/<id>"
        );
        assert_eq!(
            redact_url("https://api.example.com/users/123456789"),
            "https://api.example.com/users/<id>"
        );
    }

    #[test]
    fn redacts_blake3_or_sha_fragment() {
        assert_eq!(
            redact_url("https://obj.example.com/blob/deadbeef"),
            "https://obj.example.com/blob/<id>"
        );
        assert_eq!(
            redact_url("https://obj.example.com/blob/c5e8a4b1f9d3a7e8c2b5d9f1a4e7c0d3"),
            "https://obj.example.com/blob/<id>"
        );
    }

    #[test]
    fn redacts_long_opaque_token_segment() {
        // 16+ chars triggers the catch-all opaque-token rule even
        // when the segment is alphanumeric-mixed.
        assert_eq!(
            redact_url("https://api.example.com/v1/jobs/aZbYcXdWeVfUgThS"),
            "https://api.example.com/v1/jobs/<id>"
        );
    }

    #[test]
    fn drops_query_string_entirely() {
        let out = redact_url("https://api.example.com/search?q=secret&key=abc&token=xyz");
        assert!(!out.contains("secret"));
        assert!(!out.contains("key="));
        assert!(!out.contains("token"));
        assert_eq!(out, "https://api.example.com/search");
    }

    #[test]
    fn drops_fragment_entirely() {
        let out = redact_url("https://api.example.com/page#section-with-pii");
        assert!(!out.contains("section"));
        assert!(!out.contains("pii"));
        assert_eq!(out, "https://api.example.com/page");
    }

    #[test]
    fn drops_userinfo_credentials() {
        // user:pass@host pattern — credentials in the URL must be
        // dropped, host preserved.
        assert_eq!(
            redact_url("https://alice:s3cret@api.example.com/v1/users/me"),
            "https://api.example.com/v1/users/me"
        );
    }

    #[test]
    fn preserves_port() {
        assert_eq!(
            redact_url("https://api.example.com:8443/health"),
            "https://api.example.com:8443/health"
        );
    }

    #[test]
    fn preserves_scheme_for_non_https() {
        assert_eq!(
            redact_url("http://api.example.com/v1"),
            "http://api.example.com/v1"
        );
        assert_eq!(
            redact_url("ws://stream.example.com/chan"),
            "ws://stream.example.com/chan"
        );
    }

    #[test]
    fn returns_sentinel_on_unparseable_input() {
        // Empty.
        assert_eq!(redact_url(""), UNPARSEABLE);
        // No scheme.
        assert_eq!(redact_url("api.example.com/foo"), UNPARSEABLE);
        // Empty scheme.
        assert_eq!(redact_url("://api.example.com/foo"), UNPARSEABLE);
        // Empty rest.
        assert_eq!(redact_url("https://"), UNPARSEABLE);
        // Invalid scheme characters.
        assert_eq!(redact_url("not_a_scheme://x/y"), UNPARSEABLE);
    }

    #[test]
    fn never_echoes_unparseable_input_back() {
        // Defense-in-depth: any input that fails to parse must NOT
        // appear verbatim in the output, even partially. Pin this on
        // a few adversarial-shaped strings.
        let adversarial = [
            "https://?q=secret",
            "https://#frag-only",
            "javascript:alert('xss')",
            "data:text/plain;base64,c2VjcmV0",
        ];
        for input in adversarial {
            let out = redact_url(input);
            // Either we got the sentinel OR the output is structurally
            // valid (scheme://host without secret leakage). Pin the
            // safety property: secret substrings never survive.
            assert!(
                !out.contains("secret") && !out.contains("xss") && !out.contains("alert"),
                "redact_url leaked sensitive bytes for {input:?}: {out}"
            );
        }
    }

    #[test]
    fn redacts_each_path_component_independently() {
        // A path with mixed safe + opaque components only redacts the
        // opaque ones, preserving the route shape for operators.
        assert_eq!(
            redact_url("https://api.example.com/v1/orgs/123/projects/abc/runs/456"),
            "https://api.example.com/v1/orgs/<id>/projects/abc/runs/<id>"
        );
    }

    #[test]
    fn handles_trailing_slash() {
        assert_eq!(
            redact_url("https://api.example.com/v1/users/"),
            "https://api.example.com/v1/users/"
        );
    }

    #[test]
    fn handles_root_path() {
        // The root "/" canonicalizes to the bare host since the path
        // is empty after the scheme separator. Both inputs render to
        // the same operator-safe form — operators reading the log can
        // see WHICH host was hit without ambiguity.
        let with_slash = redact_url("https://api.example.com/");
        let without_slash = redact_url("https://api.example.com");
        assert_eq!(with_slash, "https://api.example.com");
        assert_eq!(without_slash, "https://api.example.com");
        assert_eq!(with_slash, without_slash);
    }

    #[test]
    fn looks_like_opaque_id_predicate_matrix() {
        // Numeric of any length:
        assert!(looks_like_opaque_id("1"));
        assert!(looks_like_opaque_id("42"));
        assert!(looks_like_opaque_id("123456789"));
        // UUID:
        assert!(looks_like_opaque_id("f47ac10b-58cc-4372-a567-0e02b2c3d479"));
        // Hex of length >= 8:
        assert!(looks_like_opaque_id("deadbeef"));
        assert!(looks_like_opaque_id("c5e8a4b1f9d3a7e8c2b5d9f1a4e7c0d3"));
        // Long opaque alphanumeric (>= 16 chars):
        assert!(looks_like_opaque_id("aZbYcXdWeVfUgThS"));
        // NOT opaque:
        assert!(!looks_like_opaque_id("octocat"));
        assert!(!looks_like_opaque_id("issues"));
        assert!(!looks_like_opaque_id("v1"));
        assert!(!looks_like_opaque_id("hello"));
        // Empty:
        assert!(!looks_like_opaque_id(""));
        // Short hex (< 8):
        assert!(!looks_like_opaque_id("abc"));
    }

    #[test]
    fn redaction_is_idempotent() {
        // redact_url(redact_url(x)) == redact_url(x) — applying the
        // helper twice must not further degrade an already-redacted
        // string. Pins that the sentinel `<id>` itself is not
        // mistaken for an opaque component on a second pass.
        let inputs = [
            "https://api.github.com/repos/octocat/issues/42?token=abc",
            "https://api.example.com/v1/users/f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "https://obj.example.com/blob/deadbeef",
        ];
        for input in inputs {
            let once = redact_url(input);
            let twice = redact_url(&once);
            assert_eq!(once, twice, "redaction not idempotent for {input}");
        }
    }
}
