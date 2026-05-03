//! Golden vector for `validate_oauth_endpoint_url`.
//!
//! Freezes the canonical accept/reject verdict for a fixed matrix of
//! adversarial and well-formed URL shapes. Pre-fix the verdict was
//! enforced by hand-built unit tests scattered across two files
//! (`oauth2.rs` had its own copy; `redirect_allowlist.rs` had the
//! canonical). The dedup landed in commit f34558bc9 collapsed both
//! into one entry-point. This golden file pins that single
//! entry-point's verdict on every adversarial branch in one diffable
//! artifact:
//!
//! - Any future change to the predicate (adding a scheme, loosening
//!   the credential check, accepting fragments, etc.) MUST also bump
//!   this golden — and the diff is the evidence trail an operator
//!   needs to approve the policy change.
//! - A subtle regression (e.g. accidentally accepting plain http on
//!   a non-loopback host) shows as a single-line diff in the golden,
//!   not as a per-case test failure scattered across the file.
//!
//! Update flow:
//!   UPDATE_GOLDENS=1 cargo test -p fcp-oauth --test golden_validate_oauth_endpoint_url
//!   git diff crates/fcp-oauth/tests/snapshots/
//!   # human review every diff line — accept only intentional changes
//!   git add crates/fcp-oauth/tests/snapshots/
//!
//! The vector covers the eight rejection branches (parse error,
//! cannot_be_a_base, missing host, embedded user, embedded password,
//! fragment, plain http on non-loopback, query-allowed) plus
//! seven accept shapes (https, https+query, https+path, https+port,
//! loopback http, loopback http+port, loopback http on localhost).

use fcp_oauth::validate_oauth_endpoint_url;

/// Canonical 16-case input matrix. Keep in stable lexicographic
/// order so a re-sort doesn't churn the golden.
fn canonical_inputs() -> Vec<&'static str> {
    let mut inputs = vec![
        // Accept shapes (7)
        "http://127.0.0.1:8080/oauth/token",
        "http://localhost:9999/oauth/auth",
        "https://api.example.com/v2/oauth?audience=widgets",
        "https://provider.example.com/oauth/authorize",
        "https://provider.example.com:8443/oauth/token",
        "https://provider.example.com/path/with/slashes",
        "https://very-long-subdomain.example.com/oauth",
        // Reject shapes (9)
        "",                                                     // empty
        "data:text/plain,hi",                                   // cannot_be_a_base
        "file:///etc/passwd",                                   // no network host
        "http://provider.example.com/oauth/authorize",          // plain http on non-loopback
        "https://",                                             // unparseable / no host
        "https://provider.example.com/oauth/authorize#frag",    // fragment
        "https://user:pw@provider.example.com/oauth/authorize", // embedded user+password
        "https://user@provider.example.com/oauth/authorize",    // embedded user only
        "not a url at all",                                     // unparseable
    ];
    inputs.sort();
    inputs
}

/// One row of the golden vector. Records the input, the accept
/// verdict, and (for rejections) a stable error-class label derived
/// from the error message. We don't pin the FULL error text because
/// it includes the field-name parameter passed at the call site;
/// the class label is derived by string-matching on the policy
/// keyword inside the message and is stable across field-name
/// changes.
fn classify(input: &str) -> String {
    let result = validate_oauth_endpoint_url(input, "url");
    match result {
        Ok(normalized) => format!("ACCEPT  normalized=`{normalized}`"),
        Err(err) => {
            let msg = err.to_string();
            // Derive a stable error class from the policy keyword in
            // the message. The classes intentionally mirror the
            // branches in `validate_redirect_uri_shape` so an
            // operator reading this golden can map each rejection to
            // the policy line that fires it.
            let class = if msg.contains("must be a valid absolute URL") {
                "REJECT  class=parse_error"
            } else if msg.contains("must include a network host") {
                "REJECT  class=missing_host"
            } else if msg.contains("must not include embedded credentials") {
                "REJECT  class=embedded_credentials"
            } else if msg.contains("must not include a fragment") {
                "REJECT  class=fragment"
            } else if msg.contains("must use https or loopback http") {
                "REJECT  class=insecure_scheme"
            } else {
                "REJECT  class=other"
            };
            class.to_string()
        }
    }
}

/// Render the full golden vector as a deterministic table. The
/// padding is fixed-width so the diff after a single-line verdict
/// flip is one-line and easy to review.
fn render_golden() -> String {
    let mut rows = vec![
        "# validate_oauth_endpoint_url canonical golden vector".to_string(),
        "# br-f34558bc9: dedup canonical predicate; this golden is the".to_string(),
        "#   reviewable accept/reject matrix for every documented branch.".to_string(),
        "# Format: <pad-input>  | <verdict and class>".to_string(),
        "#   ACCEPT rows include the normalized URL the validator returns.".to_string(),
        "#   REJECT rows tag a stable error class (parse_error,".to_string(),
        "#   missing_host, embedded_credentials, fragment, insecure_scheme).".to_string(),
        String::new(),
    ];
    let inputs = canonical_inputs();
    let pad = inputs.iter().map(|s| s.len()).max().unwrap_or(0);
    for input in inputs {
        let display_input = if input.is_empty() {
            "<empty>".to_string()
        } else {
            input.to_string()
        };
        let verdict = classify(input);
        rows.push(format!(
            "{display_input:<pad$}  | {verdict}",
            pad = pad.max(8)
        ));
    }
    rows.join("\n") + "\n"
}

#[test]
fn golden_validate_oauth_endpoint_url_canonical_matrix() {
    let actual = render_golden();
    insta::assert_snapshot!("validate_oauth_endpoint_url_canonical_matrix", actual);
}
