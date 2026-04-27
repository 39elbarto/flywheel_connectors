#![no_main]

//! Fuzz target for `retention_for_schema` / `requires_storage`
//! namespace-prefix bypass-resistance (control_plane.rs:101-140).
//!
//! The control-plane retention dispatcher classifies objects as
//! Required (must store for audit) or Ephemeral (may drop). The
//! dispatch is namespace-prefix matching with explicit anti-bypass
//! logic at `namespace_matches_prefix` (control_plane.rs:101-109):
//! a hyphen or other non-dot separator MUST NOT match — otherwise
//! `fcp.heartbeat-evil` would match `fcp.heartbeat` and evade the
//! default-Required audit retention.
//!
//! Existing fcp-protocol fuzz coverage does NOT touch this surface.
//!
//! Properties asserted:
//!
//!   1. **Default is Required**: any namespace not matching a known
//!      prefix returns Required (audit-safe default).
//!   2. **Required exact match**: each REQUIRED_PREFIXES entry maps
//!      to Required when used as the namespace verbatim.
//!   3. **Ephemeral exact match**: each EPHEMERAL_PREFIXES entry maps
//!      to Ephemeral when used verbatim.
//!   4. **Dot-subnamespace inheritance**: `prefix.subns` inherits the
//!      prefix's classification.
//!   5. **Anti-bypass**: `prefix-suffix` (or any non-dot separator)
//!      MUST NOT match the prefix's classification — falls through to
//!      the default Required.
//!   6. **requires_storage ⇔ retention == Required**.
//!
//!   Once-gated regression anchors:
//!     (a) `fcp.heartbeat-evil` → Required (the documented bypass).
//!     (b) `fcp.heartbeat` → Ephemeral.
//!     (c) `fcp.heartbeat.x` → Ephemeral (legitimate dot-suffix).
//!     (d) `fcp.invoke.unknown` → Required.
//!     (e) `unknown.foo` → Required (default).

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::SchemaId;
use fcp_protocol::{ControlPlaneRetention, requires_storage, retention_for_schema};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static RETENTION_ANCHOR: Once = Once::new();

const REQUIRED_PREFIXES: &[&str] = &[
    "fcp.invoke",
    "fcp.receipt",
    "fcp.approval",
    "fcp.secret",
    "fcp.revoke",
    "fcp.audit",
    "fcp.grant",
    "fcp.membership",
];

const EPHEMERAL_PREFIXES: &[&str] = &[
    "fcp.health",
    "fcp.handshake",
    "fcp.status",
    "fcp.introspect",
    "fcp.configure",
    "fcp.simulate",
    "fcp.ping",
    "fcp.heartbeat",
];

#[derive(Arbitrary, Debug)]
struct Input {
    /// Pick a base prefix from REQUIRED ∪ EPHEMERAL or use a custom string.
    base_disc: u8,
    /// Suffix to append (often a separator + chars).
    suffix: String,
}

fn pick_prefix(disc: u8) -> Option<(&'static str, ControlPlaneRetention)> {
    let req_len = REQUIRED_PREFIXES.len();
    let eph_len = EPHEMERAL_PREFIXES.len();
    let total = req_len + eph_len;
    if total == 0 {
        return None;
    }
    let idx = (disc as usize) % (total + 1);
    if idx < req_len {
        Some((REQUIRED_PREFIXES[idx], ControlPlaneRetention::Required))
    } else if idx < total {
        Some((
            EPHEMERAL_PREFIXES[idx - req_len],
            ControlPlaneRetention::Ephemeral,
        ))
    } else {
        None // Unknown — falls to default
    }
}

fn make_schema(namespace: &str) -> Option<SchemaId> {
    SchemaId::try_new(namespace, "T", Version::new(1, 0, 0)).ok()
}

fn assert_requires_storage_agrees(schema: &SchemaId) {
    let retention = retention_for_schema(schema);
    let stores = requires_storage(schema);
    let expected_stores = retention == ControlPlaneRetention::Required;
    assert_eq!(
        stores, expected_stores,
        "requires_storage ({stores}) disagrees with retention_for_schema ({retention:?}) \
         for namespace={:?}",
        schema.namespace
    );
}

fuzz_target!(|data: &[u8]| {
    RETENTION_ANCHOR.call_once(assert_retention_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Reject inputs that would contain reserved separators (try_new
    // rejects ':' and '@'; we want only the prefix-matching surface here).
    if input.suffix.contains(':') || input.suffix.contains('@') {
        return;
    }

    let base = pick_prefix(input.base_disc);

    // ── PROPERTY 1: default is Required for unknown ───────────────────
    if let Some((prefix, expected)) = base {
        // ── PROPERTY 2+3: exact-match classification ──────────────────
        if let Some(schema) = make_schema(prefix) {
            let got = retention_for_schema(&schema);
            assert_eq!(
                got, expected,
                "exact-match {prefix:?} returned {got:?}; expected {expected:?}"
            );
            assert_requires_storage_agrees(&schema);
        }

        if input.suffix.is_empty() {
            return;
        }

        // ── PROPERTY 4+5: dot-suffix inheritance vs anti-bypass ───────
        let with_suffix = format!("{prefix}{}", input.suffix);
        if let Some(schema) = make_schema(&with_suffix) {
            let got = retention_for_schema(&schema);
            assert_requires_storage_agrees(&schema);

            if input.suffix.starts_with('.') {
                // Inherits classification.
                assert_eq!(
                    got, expected,
                    "dot-suffix {with_suffix:?} did not inherit {expected:?} \
                     classification; got {got:?}"
                );
            } else if expected == ControlPlaneRetention::Ephemeral {
                // CRITICAL anti-bypass: a non-dot separator after an
                // Ephemeral prefix MUST NOT classify as Ephemeral.
                assert_ne!(
                    got,
                    ControlPlaneRetention::Ephemeral,
                    "anti-bypass FAILED: namespace {with_suffix:?} matched \
                     ephemeral prefix {prefix:?} via non-dot separator; \
                     attacker could evade audit retention by appending '-evil'"
                );
            }
            // For Required prefixes, both '.' and non-dot suffixes
            // ultimately classify as Required (either by inheritance
            // or by default). We don't assert Required-on-non-dot
            // explicitly because the namespace might happen to also
            // match an Ephemeral prefix — which is a separate
            // ambiguity not in scope here.
        }
    } else {
        // Custom unknown namespace — default Required (Property 1).
        if let Some(schema) = make_schema(&format!("custom.{}", input.suffix.replace('.', "_"))) {
            let got = retention_for_schema(&schema);
            assert_eq!(
                got,
                ControlPlaneRetention::Required,
                "unknown namespace {:?} did not default to Required; got {got:?}",
                schema.namespace
            );
            assert_requires_storage_agrees(&schema);
        }
    }
});

/// Once-gated regression anchors verifying the documented anti-bypass
/// invariant and the canonical classification table.
fn assert_retention_anchored() {
    let mk = |ns: &str| SchemaId::try_new(ns, "T", Version::new(1, 0, 0)).expect("anchor schema");

    // (a) Documented bypass attack: 'fcp.heartbeat-evil' MUST be Required.
    let evil = mk("fcp.heartbeat-evil");
    assert_eq!(
        retention_for_schema(&evil),
        ControlPlaneRetention::Required,
        "ANCHOR REGRESSION: 'fcp.heartbeat-evil' classified as Ephemeral — \
         namespace_matches_prefix at control_plane.rs:101-109 used plain \
         starts_with; attacker could evade audit retention with hyphen suffix"
    );
    assert!(requires_storage(&evil));

    // (b) Plain 'fcp.heartbeat' is Ephemeral.
    let heartbeat = mk("fcp.heartbeat");
    assert_eq!(
        retention_for_schema(&heartbeat),
        ControlPlaneRetention::Ephemeral,
        "ANCHOR: 'fcp.heartbeat' must classify as Ephemeral"
    );

    // (c) 'fcp.heartbeat.x' (legitimate dot-suffix) is Ephemeral.
    let heartbeat_sub = mk("fcp.heartbeat.x");
    assert_eq!(
        retention_for_schema(&heartbeat_sub),
        ControlPlaneRetention::Ephemeral,
        "ANCHOR REGRESSION: legitimate sub-namespace 'fcp.heartbeat.x' did \
         not inherit Ephemeral classification — dot-separator inheritance \
         broken at control_plane.rs:105-107"
    );

    // (d) 'fcp.invoke.unknown' inherits Required.
    let invoke_sub = mk("fcp.invoke.unknown");
    assert_eq!(
        retention_for_schema(&invoke_sub),
        ControlPlaneRetention::Required,
        "ANCHOR: 'fcp.invoke.unknown' must inherit Required from 'fcp.invoke'"
    );

    // (e) Unknown namespace → default Required.
    let unknown = mk("totally.unknown");
    assert_eq!(
        retention_for_schema(&unknown),
        ControlPlaneRetention::Required,
        "ANCHOR REGRESSION: unknown namespace 'totally.unknown' did not \
         default to Required — fail-safe audit-retention default broken"
    );
    assert!(requires_storage(&unknown));
}
