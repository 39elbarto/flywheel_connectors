//! Capability-token resource-constraint enforcement conformance.
//!
//! Capability tokens are bearer-style — anyone holding a token can
//! invoke an operation within its validity window. The replay-defense
//! that prevents a leaked token from being used against unintended
//! resources is `CapabilityConstraints::{resource_allow, resource_deny}`,
//! enforced by `CapabilityVerifier::verify_unbound` against the
//! `resource_uris` the caller passes in.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Wildcard allow = unrestricted.** `resource_allow = ["*"]`
//!    accepts any URI, and accepts even the empty resource_uris slice.
//! 2. **Non-wildcard allow requires resource_uris.** If the token
//!    declares a specific allow pattern but the caller forgets to
//!    pass any URIs, the verifier MUST reject with
//!    `ResourceNotAllowed` (defense-in-depth: prevents silent
//!    scope-bypass when ~76 connector call sites still pass `&[]`).
//! 3. **Allow-list match is per-URI.** Each URI must match at least
//!    one allow pattern; one non-matching URI rejects the entire
//!    invocation.
//! 4. **Glob matching uses `*` and `?`.** A pattern like
//!    `notion://page/*` matches `notion://page/123` but not
//!    `notion://other/123`.
//! 5. **Deny overrides allow.** A URI that matches both an allow and
//!    a deny pattern MUST be rejected.
//! 6. **Empty constraints = unconstrained.** A token with empty
//!    `resource_allow` and empty `resource_deny` accepts any URI
//!    (and any empty slice).
//! 7. **`ResourceNotAllowed` names the failing URI.** The error
//!    payload tells the caller WHICH URI was rejected so the failure
//!    surfaces to triage.

use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityId, CapabilityToken, CapabilityVerifier, FcpError,
    OperationId, ZoneId,
};
use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;

fn constraints_cbor(constraints: &CapabilityConstraints) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(constraints, &mut buf).expect("encode constraints");
    buf
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    constraints: &CapabilityConstraints,
) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id("cap.test")
        .zone_id(ZoneId::work().as_str())
        .principal("user:test")
        .operations(&["op.test"])
        .issuer("node:primary")
        .validity(now - Duration::minutes(1), now + Duration::hours(1))
        .constraints_cbor(&constraints_cbor(constraints))
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

fn build_verifier(signing_key: &Ed25519SigningKey) -> CapabilityVerifier {
    CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    )
}

fn cap() -> CapabilityId {
    CapabilityId::new("cap.test").expect("capability id")
}

fn op() -> OperationId {
    OperationId::new("op.test").expect("operation id")
}

#[test]
fn wildcard_allow_accepts_arbitrary_uri() {
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    verifier
        .verify_unbound(token, &cap(), &op(), &["notion://page/anything".to_string()])
        .expect("wildcard allow must accept any resource URI");
}

#[test]
fn wildcard_allow_accepts_empty_resource_uris_slice() {
    // The defense-in-depth check explicitly exempts pure wildcard
    // allow lists so the existing `verifier.verify(.., &[])` call
    // sites continue to work.
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    verifier
        .verify_unbound(token, &cap(), &op(), &[])
        .expect("wildcard allow with empty resource_uris must succeed");
}

#[test]
fn empty_constraints_set_denies_all_per_c3_4_default_deny() {
    // NORMATIVE C3.4: an empty CapabilityConstraints (both
    // resource_allow and resource_deny empty) means DENY ALL — not
    // "unconstrained". The verifier surfaces CapabilityDenied with
    // a fixed reason string so triage tooling can detect the
    // default-deny path.
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints::default();
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    let err = verifier
        .verify_unbound(token, &cap(), &op(), &["arbitrary://uri".to_string()])
        .expect_err("empty constraint set MUST deny all (C3.4)");
    match err {
        FcpError::CapabilityDenied {
            capability,
            reason,
        } => {
            assert_eq!(
                capability, "constraints",
                "CapabilityDenied must point at the constraints field"
            );
            assert!(
                reason.contains("C3.4"),
                "default-deny reason must reference the C3.4 normative rule; got {reason:?}"
            );
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

#[test]
fn non_wildcard_allow_with_empty_resource_uris_is_rejected() {
    // Defense-in-depth: a token that declares a specific allow
    // pattern but is verified against `&[]` MUST reject. Otherwise
    // the for-loop iterates zero times and the allow-list silently
    // passes — turning a scoped token into an unscoped one.
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["notion://page/123".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    let err = verifier
        .verify_unbound(token, &cap(), &op(), &[])
        .expect_err("non-wildcard allow with empty resource_uris must be rejected");
    match err {
        FcpError::ResourceNotAllowed { resource } => {
            assert!(
                resource.contains("non-wildcard"),
                "ResourceNotAllowed must surface the defense-in-depth message; got {resource:?}"
            );
        }
        other => panic!("expected FcpError::ResourceNotAllowed, got {other:?}"),
    }
}

#[test]
fn non_wildcard_allow_accepts_matching_uri() {
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["notion://page/123".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    verifier
        .verify_unbound(
            token,
            &cap(),
            &op(),
            &["notion://page/123".to_string()],
        )
        .expect("specific allow pattern must accept the exact matching URI");
}

#[test]
fn non_wildcard_allow_rejects_non_matching_uri_and_names_it() {
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["notion://page/123".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    let err = verifier
        .verify_unbound(
            token,
            &cap(),
            &op(),
            &["notion://page/999".to_string()],
        )
        .expect_err("non-matching URI must be rejected");
    match err {
        FcpError::ResourceNotAllowed { resource } => {
            assert_eq!(
                resource, "notion://page/999",
                "ResourceNotAllowed must name the failing URI exactly so triage tooling can route the failure"
            );
        }
        other => panic!("expected FcpError::ResourceNotAllowed, got {other:?}"),
    }
}

#[test]
fn glob_star_pattern_matches_path_segment() {
    // Allow pattern `notion://page/*` accepts any concrete page id.
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["notion://page/*".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    verifier
        .verify_unbound(
            token.clone(),
            &cap(),
            &op(),
            &["notion://page/abc-123".to_string()],
        )
        .expect("glob pattern must match any suffix");

    let err = verifier
        .verify_unbound(
            token,
            &cap(),
            &op(),
            &["notion://other/abc-123".to_string()],
        )
        .expect_err("glob anchored at path-prefix must not match a different prefix");
    assert!(matches!(err, FcpError::ResourceNotAllowed { .. }));
}

#[test]
fn one_failing_uri_in_a_batch_rejects_the_whole_invocation() {
    // Per-URI semantics: every URI in resource_uris must independently
    // satisfy the allow list. A single non-matching URI rejects the
    // entire invocation — there is no "best-effort allow some" mode.
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["notion://page/*".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    let err = verifier
        .verify_unbound(
            token,
            &cap(),
            &op(),
            &[
                "notion://page/ok-1".to_string(),
                "notion://other/bad".to_string(),
                "notion://page/ok-2".to_string(),
            ],
        )
        .expect_err("any single non-matching URI must reject the whole batch");
    match err {
        FcpError::ResourceNotAllowed { resource } => {
            assert_eq!(
                resource, "notion://other/bad",
                "ResourceNotAllowed must name the specific URI that failed"
            );
        }
        other => panic!("expected FcpError::ResourceNotAllowed, got {other:?}"),
    }
}

#[test]
fn deny_pattern_overrides_allow_pattern() {
    // A URI that matches BOTH an allow pattern and a deny pattern
    // MUST be rejected. Otherwise an attacker could exploit a wider
    // allow rule to slip past a narrower deny.
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["notion://page/*".to_string()],
        resource_deny: vec!["notion://page/secret-*".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    // Allowed URI passes.
    verifier
        .verify_unbound(
            token.clone(),
            &cap(),
            &op(),
            &["notion://page/regular-1".to_string()],
        )
        .expect("allow pattern must accept a non-denied URI");

    // Denied URI rejected even though it ALSO matches the allow rule.
    let err = verifier
        .verify_unbound(
            token,
            &cap(),
            &op(),
            &["notion://page/secret-1".to_string()],
        )
        .expect_err("deny pattern must override allow pattern");
    match err {
        FcpError::ResourceNotAllowed { resource } => {
            assert_eq!(resource, "notion://page/secret-1");
        }
        other => panic!("expected FcpError::ResourceNotAllowed, got {other:?}"),
    }
}

#[test]
fn deny_only_with_no_allow_passes_unmatched_uris() {
    // Just a deny list with empty allow: only denied URIs are
    // rejected; everything else passes.
    let signing_key = Ed25519SigningKey::generate();
    let constraints = CapabilityConstraints {
        resource_allow: vec![],
        resource_deny: vec!["notion://page/secret-*".to_string()],
        ..Default::default()
    };
    let token = build_token(&signing_key, &constraints);
    let verifier = build_verifier(&signing_key);

    verifier
        .verify_unbound(
            token.clone(),
            &cap(),
            &op(),
            &["notion://page/regular".to_string()],
        )
        .expect("deny-only with empty allow must pass non-matching URIs");

    let err = verifier
        .verify_unbound(
            token,
            &cap(),
            &op(),
            &["notion://page/secret-x".to_string()],
        )
        .expect_err("deny pattern still rejects matching URI");
    assert!(matches!(err, FcpError::ResourceNotAllowed { .. }));
}
