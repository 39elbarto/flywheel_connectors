#![no_main]

//! Fuzz target for `SchemaId::try_new` `ReservedSeparator` error-field
//! correctness (lib.rs:74-98).
//!
//! `SchemaId::try_new` rejects `':' ` or `'@'` in namespace/name with
//! `SchemaIdError::ReservedSeparator { field, separator }`. Existing
//! `schema_id_hash` tests injectivity + try_new accept/reject parity,
//! but does NOT verify the error variant's `field` and `separator`
//! values. A regression that mis-labeled the field (e.g., reported
//! "name" when namespace was the offender) or returned a different
//! separator char would break operator diagnostics.
//!
//! Properties asserted:
//!
//!   1. **':' in namespace** → ReservedSeparator { field: "namespace",
//!      separator: ':' }
//!   2. **'@' in namespace** → ReservedSeparator { field: "namespace",
//!      separator: '@' }
//!   3. **':' in name** → ReservedSeparator { field: "name",
//!      separator: ':' }
//!   4. **'@' in name** → ReservedSeparator { field: "name",
//!      separator: '@' }
//!   5. **Namespace-first ordering**: when both fields contain
//!      reserved chars, namespace error is reported (reject_reserved
//!      is called on namespace before name at lib.rs:81-82).
//!   6. **Clean inputs accept** with the documented (namespace, name,
//!      version) verbatim.
//!
//!   Once-gated anchors verify each (field, separator) pair + ordering.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::{SchemaId, SchemaIdError};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static SCHEMA_ID_ERROR_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    namespace: String,
    name: String,
}

const MAX_LEN: usize = 256;

fn version() -> Version {
    Version::new(1, 0, 0)
}

fuzz_target!(|data: &[u8]| {
    SCHEMA_ID_ERROR_ANCHOR.call_once(assert_schema_id_error_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.namespace.len() > MAX_LEN || input.name.len() > MAX_LEN {
        return;
    }

    let ns_has_reserved = input.namespace.contains(':') || input.namespace.contains('@');
    let name_has_reserved = input.name.contains(':') || input.name.contains('@');

    let result = SchemaId::try_new(input.namespace.clone(), input.name.clone(), version());

    if ns_has_reserved {
        // ── PROPERTY 5: namespace-first ordering ─────────────────────
        match result {
            Err(SchemaIdError::ReservedSeparator { field, separator }) => {
                assert_eq!(
                    field, "namespace",
                    "namespace contains reserved but error reports field={field:?}"
                );
                assert!(
                    separator == ':' || separator == '@',
                    "separator {separator:?} not in {{':', '@'}}"
                );
                assert!(
                    input.namespace.contains(separator),
                    "reported separator {separator:?} not actually in namespace {:?}",
                    input.namespace
                );
            }
            Ok(_) => panic!(
                "try_new accepted namespace {:?} containing reserved separator",
                input.namespace
            ),
        }
    } else if name_has_reserved {
        match result {
            Err(SchemaIdError::ReservedSeparator { field, separator }) => {
                assert_eq!(
                    field, "name",
                    "name contains reserved but error reports field={field:?}"
                );
                assert!(
                    separator == ':' || separator == '@',
                    "separator {separator:?} not in {{':', '@'}}"
                );
                assert!(
                    input.name.contains(separator),
                    "reported separator {separator:?} not actually in name {:?}",
                    input.name
                );
            }
            Ok(_) => panic!(
                "try_new accepted name {:?} containing reserved separator",
                input.name
            ),
        }
    } else {
        // ── PROPERTY 6: clean inputs accept ──────────────────────────
        let id = result.expect("clean input MUST be accepted");
        assert_eq!(id.namespace, input.namespace);
        assert_eq!(id.name, input.name);
    }
});

/// Once-gated anchors verifying each (field, separator) pair + the
/// namespace-first ordering.
fn assert_schema_id_error_anchored() {
    let v = version();

    // (a) ':' in namespace.
    match SchemaId::try_new("a:b", "n", v.clone()) {
        Err(SchemaIdError::ReservedSeparator { field, separator }) => {
            assert_eq!(field, "namespace", "ANCHOR: ':' in namespace field wrong");
            assert_eq!(separator, ':', "ANCHOR: ':' in namespace separator wrong");
        }
        other => panic!("ANCHOR: ':' in namespace returned {other:?}"),
    }

    // (b) '@' in namespace.
    match SchemaId::try_new("a@b", "n", v.clone()) {
        Err(SchemaIdError::ReservedSeparator { field, separator }) => {
            assert_eq!(field, "namespace");
            assert_eq!(separator, '@');
        }
        other => panic!("ANCHOR: '@' in namespace returned {other:?}"),
    }

    // (c) ':' in name.
    match SchemaId::try_new("ns", "a:b", v.clone()) {
        Err(SchemaIdError::ReservedSeparator { field, separator }) => {
            assert_eq!(field, "name", "ANCHOR: ':' in name field wrong");
            assert_eq!(separator, ':');
        }
        other => panic!("ANCHOR: ':' in name returned {other:?}"),
    }

    // (d) '@' in name.
    match SchemaId::try_new("ns", "a@b", v.clone()) {
        Err(SchemaIdError::ReservedSeparator { field, separator }) => {
            assert_eq!(field, "name");
            assert_eq!(separator, '@');
        }
        other => panic!("ANCHOR: '@' in name returned {other:?}"),
    }

    // (e) Namespace-first ordering: BOTH fields contain reserved → namespace error.
    match SchemaId::try_new("a:b", "c@d", v.clone()) {
        Err(SchemaIdError::ReservedSeparator { field, separator }) => {
            assert_eq!(
                field, "namespace",
                "ANCHOR REGRESSION: when both fields contain reserved chars, \
                 namespace error MUST be reported first (lib.rs:81-82 ordering)"
            );
            assert_eq!(separator, ':');
        }
        other => panic!("ANCHOR: both-fields-reserved returned {other:?}"),
    }

    // (f) Clean acceptance.
    let clean = SchemaId::try_new("fcp.core", "Capability", v).expect("ANCHOR: clean accept");
    assert_eq!(clean.namespace, "fcp.core");
    assert_eq!(clean.name, "Capability");
}
