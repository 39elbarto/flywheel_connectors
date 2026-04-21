#![no_main]

use fcp_cbor::to_canonical_cbor;
use fcp_manifest::ConnectorManifest;
use libfuzzer_sys::fuzz_target;

// Cap input size: larger manifests exhaust the fuzzer's budget without
// exercising new code paths (TOML parsing is O(n)).
const MAX_INPUT_BYTES: usize = 64 * 1024;

// Cap serialized-output size. A sane round-trip should not grow the manifest
// by more than ~8x. A runaway serializer producing arbitrarily large output
// is a correctness bug we want to catch.
const MAX_ROUNDTRIP_OUTPUT_BYTES: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    // parse_str_unchecked is the narrow TOML-parsing boundary. `parse_str`
    // additionally calls `validate`, which rejects many syntactically-parseable
    // shapes — we want to exercise the full space of TOML-parseable manifests,
    // so we use the unchecked variant for the primary round-trip oracle.
    let Ok(manifest) = ConnectorManifest::parse_str_unchecked(raw) else {
        // Bounded error is the acceptable outcome for malformed input. The
        // `Err` value must be typed `ManifestError` (enforced by the signature).
        return;
    };

    // Serialize back to TOML. A successfully parsed manifest must always
    // re-serialize; if it doesn't, there is a bug in the serde derive or
    // a field with non-representable TOML contents (e.g. a top-level array
    // value). Panic to surface the bug.
    let toml_str = match toml::to_string(&manifest) {
        Ok(s) => s,
        Err(e) => {
            panic!(
                "manifest parsed but failed to re-serialize to TOML: {e}\noriginal input:\n{raw}"
            );
        }
    };

    assert!(
        toml_str.len() <= MAX_ROUNDTRIP_OUTPUT_BYTES,
        "TOML round-trip output grew to {} bytes from {}-byte input",
        toml_str.len(),
        raw.len()
    );

    // Re-parse the serialized form. Must succeed — a serializer that emits
    // TOML which its own parser rejects is a round-trip violation.
    let reparsed = match ConnectorManifest::parse_str_unchecked(&toml_str) {
        Ok(m) => m,
        Err(e) => {
            panic!(
                "round-trip broken: parse → to_toml → parse failed on second parse: {e}\n\
                 serialized TOML:\n{toml_str}"
            );
        }
    };

    // Canonical semantic equality: the two manifests may serialize to
    // different TOML (field ordering, quoting, formatting) but their
    // canonical CBOR encoding is deterministic and compares structural
    // semantics. If both manifests canonicalize, they must agree.
    if let (Ok(a), Ok(b)) = (to_canonical_cbor(&manifest), to_canonical_cbor(&reparsed)) {
        assert_eq!(
            a, b,
            "round-trip broken: canonical CBOR of original != canonical CBOR of reparsed\n\
             original TOML:\n{raw}\nreserialized TOML:\n{toml_str}"
        );
    }

    // Third pass: reparsed → TOML → manifest. This catches non-idempotent
    // serializers where the second round-trip stabilizes.
    if let Ok(toml_str2) = toml::to_string(&reparsed)
        && let Ok(reparsed2) = ConnectorManifest::parse_str_unchecked(&toml_str2)
        && let (Ok(a), Ok(b)) = (to_canonical_cbor(&reparsed), to_canonical_cbor(&reparsed2))
    {
        assert_eq!(
            a, b,
            "round-trip not idempotent: parse → serialize → parse → serialize → parse produced \
             different canonical CBOR"
        );
    }
});
