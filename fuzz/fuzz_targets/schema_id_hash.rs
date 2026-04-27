#![no_main]

//! Collision-resistance fuzz target for `fcp_cbor::SchemaId::hash`.
//!
//! Property: the BLAKE3-based schema hash is **injective** in
//! `(namespace, name, version)`.  Distinct tuples MUST hash to distinct
//! 32-byte digests; equal tuples MUST hash to identical digests.
//!
//! This is the post-mzi9x normative invariant: prior to length-prefixing,
//! the historical encoding `namespace || ':' || name || '@' || version`
//! collided when `:` or `@` appeared inside a component
//! (e.g. `("a:b","c")` and `("a","b:c")` both produced `"a:b:c@1.0.0"`).
//! The current implementation feeds each component length-prefixed
//! (u64-LE byte length || bytes), which forecloses that ambiguity.
//!
//! Bypasses `SchemaId::new` / `try_new` validation by setting the public
//! fields directly — the threat model is an attacker who constructs a
//! `SchemaId` literal in code or via serde and embeds reserved separators
//! to try and shift the cryptographic identity of a schema.
//!
//! Also exercises:
//!   * `try_new` validation: if accepted, hash must equal direct-field
//!     construction of the same tuple.
//!   * Determinism: re-hashing the same tuple yields the same bytes.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::{SchemaHash, SchemaId};
use libfuzzer_sys::fuzz_target;
use semver::Version;

const MAX_COMPONENT_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct PairInput {
    ns_a: Vec<u8>,
    name_a: Vec<u8>,
    major_a: u32,
    minor_a: u32,
    patch_a: u32,

    ns_b: Vec<u8>,
    name_b: Vec<u8>,
    major_b: u32,
    minor_b: u32,
    patch_b: u32,
}

/// Build a `String` from arbitrary bytes by lossy UTF-8 conversion (the
/// SchemaId fields are `String`, not `Vec<u8>`). The hash itself feeds
/// `String::as_bytes()` so the fuzzer can still reach mutations across
/// the boundary; we only sacrifice the rare invalid-UTF-8 corner.
fn to_component(bytes: &[u8]) -> String {
    let truncated = if bytes.len() > MAX_COMPONENT_LEN {
        &bytes[..MAX_COMPONENT_LEN]
    } else {
        bytes
    };
    String::from_utf8_lossy(truncated).into_owned()
}

/// Construct a `SchemaId` directly via the public fields, bypassing the
/// `new` / `try_new` reserved-separator check. Required to reach the
/// threat model described in the module doc.
fn build_direct(namespace: String, name: String, major: u32, minor: u32, patch: u32) -> SchemaId {
    SchemaId {
        namespace,
        name,
        version: Version::new(u64::from(major), u64::from(minor), u64::from(patch)),
    }
}

fn tuples_equal(a: &SchemaId, b: &SchemaId) -> bool {
    a.namespace == b.namespace && a.name == b.name && a.version == b.version
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = PairInput::arbitrary(&mut u) else {
        return;
    };

    let ns_a = to_component(&input.ns_a);
    let name_a = to_component(&input.name_a);
    let ns_b = to_component(&input.ns_b);
    let name_b = to_component(&input.name_b);

    let a = build_direct(
        ns_a.clone(),
        name_a.clone(),
        input.major_a,
        input.minor_a,
        input.patch_a,
    );
    let b = build_direct(
        ns_b.clone(),
        name_b.clone(),
        input.major_b,
        input.minor_b,
        input.patch_b,
    );

    let ha: SchemaHash = a.hash();
    let hb: SchemaHash = b.hash();

    // PROPERTY 1 (determinism): hashing the same SchemaId twice must
    // produce identical digests. Catches non-determinism from
    // hasher-state leakage or serializer drift.
    assert_eq!(ha, a.hash(), "SchemaId::hash is not deterministic on a");
    assert_eq!(hb, b.hash(), "SchemaId::hash is not deterministic on b");

    // PROPERTY 2 (injectivity): equal-tuple ⟺ equal-hash.
    //
    // Forward: structural equality of `(namespace, name, version)`
    // implies hash equality. This is just determinism via Eq, but the
    // assertion is cheap and catches encoder paths that ever read
    // out-of-band state.
    if tuples_equal(&a, &b) {
        assert_eq!(
            ha, hb,
            "equal SchemaId tuples produced distinct hashes (a={:?}, b={:?})",
            a, b
        );
    } else {
        // Reverse: structural inequality MUST imply hash inequality.
        // BLAKE3 collisions on 32 bytes have ≈2^-128 odds, so any
        // collision the fuzzer surfaces here is either a real injectivity
        // bug in the length-prefixing scheme or — vanishingly — a
        // genuine BLAKE3 collision (which would be far bigger news than
        // an FCP regression). Either is worth investigating.
        assert_ne!(
            ha, hb,
            "distinct SchemaId tuples produced identical hashes — possible LP-encoding regression\n  a = (ns={:?}, name={:?}, ver={})\n  b = (ns={:?}, name={:?}, ver={})",
            a.namespace, a.name, a.version, b.namespace, b.name, b.version,
        );
    }

    // PROPERTY 3 + 4 (validation parity): `try_new` accepts iff neither
    // component contains a reserved separator (`:` or `@`); when it
    // accepts, the validated `SchemaId` MUST hash identically to the
    // direct-field construction (validation must not transform fields).
    let has_reserved = ns_a.contains([':', '@']) || name_a.contains([':', '@']);
    match SchemaId::try_new(ns_a, name_a, a.version) {
        Ok(validated) => {
            assert!(
                !has_reserved,
                "try_new accepted a tuple containing a reserved separator"
            );
            assert_eq!(
                validated.hash(),
                ha,
                "try_new-validated SchemaId hashes differently than direct construction"
            );
        }
        Err(_) => {
            assert!(
                has_reserved,
                "try_new rejected a tuple with no reserved separators"
            );
        }
    }
});
