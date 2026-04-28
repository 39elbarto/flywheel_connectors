#![no_main]

//! Fuzz target for `CredentialObject::is_host_allowed`,
//! `is_ip_literal`, `has_ip_literal_in_host_allow`, and
//! `validate_host_policy` (credential.rs:205-300).
//!
//! These predicates gate egress proxy host injection of credentials:
//! `is_host_allowed` decides whether a credential's secret may be
//! attached to an outbound request to a given host. Wrong answers
//! either let the credential leak to an attacker-chosen destination
//! (false-positive) or break legitimate outbound traffic
//! (false-negative). NOT covered by any existing fuzz target.
//!
//! A regression that:
//!   - made wildcard `*.example.com` match `example.com` itself
//!     would let a credential bound to subdomains escape to the base
//!     domain (which often has a different security posture).
//!   - dropped case-folding would let an attacker bypass an exact-
//!     match `host_allow` by capitalizing the request host.
//!   - dropped IP-port stripping in `is_ip_literal` would let
//!     `10.0.0.1:8080` slip past a `reject_ip_literals` policy gate.
//!
//! Properties asserted:
//!
//!   1. **Empty allow-list**: any host is allowed when `host_allow`
//!      is empty.
//!   2. **Exact match (case-insensitive)**: `host_allow` containing
//!      `H` allows `H`, `h`, `H.upper()`, `h.lower()`.
//!   3. **Wildcard subdomain**: `*.example.com` allows
//!      `foo.example.com`, `foo.bar.example.com` but NOT
//!      `example.com` itself.
//!   4. **Mismatch**: a host not in the allow-list is rejected.
//!   5. **`is_ip_literal`**: accepts IPv4 (with/without port), IPv6
//!      with brackets (with/without port), bare IPv6; rejects
//!      hostnames.
//!   6. **`has_ip_literal_in_host_allow` agreement**: returns true
//!      iff at least one entry (after stripping the wildcard
//!      prefix) is an IP literal.
//!   7. **`validate_host_policy` rejects IP literals when
//!      `reject_ip_literals=true`** and accepts otherwise.
//!
//!   Once-gated anchors verify each branch on hand-picked inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::SchemaId;
use fcp_core::{
    CredentialApplication, CredentialId, CredentialObject, CredentialValidationError, ObjectHeader,
    Provenance, SecretId, ZoneId,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static CRED_HOST_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    host_allow: Vec<String>,
    candidate_hosts: Vec<String>,
}

const MAX_PATTERNS: usize = 8;
const MAX_HOSTS: usize = 8;
const MAX_STR: usize = 128;

fn make_credential(host_allow: Vec<String>) -> CredentialObject {
    CredentialObject {
        header: ObjectHeader {
            schema: SchemaId::new("fcp.core", "CredentialObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        credential_id: CredentialId::new(),
        label: None,
        secret_id: SecretId::new(),
        application: CredentialApplication::HttpAuthorizationBearer,
        host_allow,
        expires_at: None,
        description: None,
        tags: vec![],
    }
}

fuzz_target!(|data: &[u8]| {
    CRED_HOST_ANCHOR.call_once(assert_cred_host_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.host_allow.len() > MAX_PATTERNS
        || input.candidate_hosts.len() > MAX_HOSTS
        || input.host_allow.iter().any(|s| s.len() > MAX_STR)
        || input.candidate_hosts.iter().any(|s| s.len() > MAX_STR)
    {
        return;
    }

    let cred = make_credential(input.host_allow.clone());

    // ── PROPERTY 1: empty allow-list → any host allowed ─────────────────
    if input.host_allow.is_empty() {
        let empty_cred = make_credential(vec![]);
        for host in &input.candidate_hosts {
            assert!(
                empty_cred.is_host_allowed(host),
                "empty host_allow rejected host {host:?}"
            );
        }
    }

    // ── PROPERTY 2: case-insensitive exact match ────────────────────────
    for pattern in &input.host_allow {
        // Skip wildcards in this property — they have their own.
        if pattern.starts_with("*.") {
            continue;
        }
        let upper = pattern.to_uppercase();
        let lower = pattern.to_lowercase();
        // The pattern itself must match.
        assert!(
            cred.is_host_allowed(pattern),
            "exact pattern {pattern:?} not allowed by its own credential"
        );
        // Case variants must also match.
        assert!(
            cred.is_host_allowed(&upper),
            "uppercase variant of pattern {pattern:?} (={upper:?}) not allowed"
        );
        assert!(
            cred.is_host_allowed(&lower),
            "lowercase variant of pattern {pattern:?} (={lower:?}) not allowed"
        );
    }

    // ── PROPERTY 6: has_ip_literal_in_host_allow agreement ──────────────
    let any_ip = input.host_allow.iter().any(|h| {
        let host = h.strip_prefix("*.").unwrap_or(h);
        CredentialObject::is_ip_literal(host)
    });
    assert_eq!(
        cred.has_ip_literal_in_host_allow(),
        any_ip,
        "has_ip_literal_in_host_allow disagrees with manual scan"
    );

    // ── PROPERTY 7: validate_host_policy with reject_ip_literals=true ───
    let policy = cred.validate_host_policy(true);
    if any_ip {
        match policy {
            Err(CredentialValidationError::HostNotAllowed { .. }) => {}
            other => panic!(
                "validate_host_policy(reject_ip_literals=true) on host_allow with IP returned {other:?}; \
                 expected HostNotAllowed"
            ),
        }
    } else {
        assert!(
            policy.is_ok(),
            "validate_host_policy rejected non-IP host_allow under reject_ip_literals=true"
        );
    }
    assert!(
        cred.validate_host_policy(false).is_ok(),
        "validate_host_policy(reject_ip_literals=false) rejected — must always pass"
    );
});

/// Once-gated anchors: hand-picked branches.
fn assert_cred_host_anchored() {
    // (a) Empty host_allow → all hosts allowed.
    let empty = make_credential(vec![]);
    assert!(empty.is_host_allowed("anything.com"));
    assert!(empty.is_host_allowed("10.0.0.1"));

    // (b) Exact match (case-insensitive).
    let exact = make_credential(vec!["api.example.com".to_string()]);
    assert!(
        exact.is_host_allowed("api.example.com"),
        "ANCHOR: exact lowercase pattern accepts itself"
    );
    assert!(
        exact.is_host_allowed("API.EXAMPLE.COM"),
        "ANCHOR REGRESSION: case folding lost — uppercase host rejected by lowercase pattern"
    );
    assert!(
        !exact.is_host_allowed("evil.example.com"),
        "ANCHOR REGRESSION: exact pattern matched non-equal host"
    );

    // (c) Wildcard subdomain.
    let wild = make_credential(vec!["*.example.com".to_string()]);
    assert!(
        wild.is_host_allowed("foo.example.com"),
        "ANCHOR: *.example.com accepts foo.example.com"
    );
    assert!(
        wild.is_host_allowed("foo.bar.example.com"),
        "ANCHOR: *.example.com accepts multi-level subdomains"
    );
    assert!(
        !wild.is_host_allowed("example.com"),
        "ANCHOR REGRESSION: *.example.com matched the base domain (must NOT)"
    );
    assert!(
        !wild.is_host_allowed("evil.com"),
        "ANCHOR: *.example.com rejected unrelated domain"
    );
    // Case-insensitive wildcard.
    assert!(
        wild.is_host_allowed("Foo.EXAMPLE.com"),
        "ANCHOR: case folding under wildcard"
    );

    // (d) is_ip_literal — IPv4.
    assert!(
        CredentialObject::is_ip_literal("127.0.0.1"),
        "ANCHOR: 127.0.0.1 is IP"
    );
    assert!(
        CredentialObject::is_ip_literal("127.0.0.1:8080"),
        "ANCHOR REGRESSION: IPv4 with port not detected"
    );

    // (e) is_ip_literal — IPv6.
    assert!(
        CredentialObject::is_ip_literal("[::1]"),
        "ANCHOR: bracketed IPv6 detected"
    );
    assert!(
        CredentialObject::is_ip_literal("[::1]:8080"),
        "ANCHOR: bracketed IPv6 with port detected"
    );
    assert!(
        CredentialObject::is_ip_literal("::1"),
        "ANCHOR: bare IPv6 detected"
    );

    // (f) is_ip_literal — hostnames rejected.
    assert!(
        !CredentialObject::is_ip_literal("api.example.com"),
        "ANCHOR: hostname must not be classified as IP"
    );
    assert!(
        !CredentialObject::is_ip_literal("api.example.com:443"),
        "ANCHOR: hostname:port must not be classified as IP"
    );

    // (g) has_ip_literal_in_host_allow + validate_host_policy.
    let with_ip = make_credential(vec!["10.0.0.1".to_string(), "api.example.com".to_string()]);
    assert!(with_ip.has_ip_literal_in_host_allow());
    match with_ip.validate_host_policy(true) {
        Err(CredentialValidationError::HostNotAllowed { .. }) => {}
        other => panic!(
            "ANCHOR REGRESSION: validate_host_policy(reject=true) on IP allow-list returned {other:?}"
        ),
    }
    assert!(with_ip.validate_host_policy(false).is_ok());

    let no_ip = make_credential(vec!["api.example.com".to_string()]);
    assert!(!no_ip.has_ip_literal_in_host_allow());
    assert!(no_ip.validate_host_policy(true).is_ok());

    // (h) Wildcard with IP suffix → still an IP after strip.
    let wild_ip = make_credential(vec!["*.10.0.0.1".to_string()]);
    assert!(
        wild_ip.has_ip_literal_in_host_allow(),
        "ANCHOR: wildcard IP detected via strip_prefix(*.)"
    );
}
