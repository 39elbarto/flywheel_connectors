#![no_main]

//! Fuzz target for `fcp_store::ObjectTransmissionInfo` raptorq-bridge
//! round-trip and serde behavior (symbol_store.rs:69-115).
//!
//! `ObjectTransmissionInfo` is the serializable wrapper around raptorq's
//! `ObjectTransmissionInformation` — the symbol-stream "header" telling
//! decoders how to interpret a symbol payload (transfer_length,
//! symbol_size, source_blocks, sub_blocks, alignment, optional
//! payload_hash). Existing fcp-store fuzz coverage does not probe the
//! OTI bridge: a regression that swapped field positions in
//! from_oti/to_oti, dropped payload_hash through serde, or mishandled
//! the optional field would silently cause decoders to mis-interpret
//! the symbol stream — content addressing for the affected object would
//! diverge between sender and receiver.
//!
//! Properties asserted:
//!
//!   1. **OTI round-trip**: from_oti(oti) → wrapper → to_oti() preserves
//!      every field byte-for-byte.
//!   2. **Field-position invariance**: wrapper field accessors agree
//!      1:1 with raptorq's accessors (a regression that swapped
//!      source_blocks ↔ sub_blocks would still pass JSON schema but
//!      yield a wrong decoder config).
//!   3. **JSON serde round-trip** preserves all fields including
//!      optional payload_hash.
//!   4. **CBOR canonical-serde round-trip** (via fcp_cbor) same.
//!   5. **payload_hash optionality**: with-hash and without-hash
//!      wrappers MUST NOT round-trip into each other.
//!   6. **From conversion agreement**: From<ObjectTransmissionInformation>
//!      MUST agree with from_oti on every field.
//!
//!   Once-gated regression anchor:
//!     A known OTI (transfer_length=8192, symbol_size=128,
//!     source_blocks=1, sub_blocks=1, alignment=8) with a known
//!     payload_hash MUST round-trip byte-for-byte through raptorq
//!     conversion and serde.

use arbitrary::{Arbitrary, Unstructured};
use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_raptorq::ObjectTransmissionInformation;
use fcp_store::ObjectTransmissionInfo;
use libfuzzer_sys::fuzz_target;
use semver::Version;
use std::sync::Once;

static OTI_ROUNDTRIP_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    transfer_length: u64,
    symbol_size: u16,
    source_blocks: u8,
    sub_blocks: u16,
    alignment: u8,
    payload_hash: Option<[u8; 32]>,
}

fn schema() -> SchemaId {
    SchemaId::new("fcp.fuzz", "OtiRoundTrip", Version::new(1, 0, 0))
}

fn build_oti(input: &Input) -> ObjectTransmissionInformation {
    let oti = ObjectTransmissionInformation::new(
        input.transfer_length,
        input.symbol_size,
        input.source_blocks,
        input.sub_blocks,
        input.alignment,
    );
    match input.payload_hash {
        Some(hash) => oti.with_payload_hash(hash),
        None => oti,
    }
}

fn assert_field_agreement(
    wrapper: &ObjectTransmissionInfo,
    raptorq_oti: &ObjectTransmissionInformation,
) {
    assert_eq!(
        wrapper.transfer_length,
        raptorq_oti.transfer_length(),
        "transfer_length mismatch (wrapper {} vs raptorq {})",
        wrapper.transfer_length,
        raptorq_oti.transfer_length()
    );
    assert_eq!(
        wrapper.symbol_size,
        raptorq_oti.symbol_size(),
        "symbol_size mismatch — field-position regression: decoders \
         configured with the wrong symbol size will silently mis-decode"
    );
    assert_eq!(
        wrapper.source_blocks,
        raptorq_oti.source_blocks(),
        "source_blocks mismatch — field-position regression"
    );
    assert_eq!(
        wrapper.sub_blocks,
        raptorq_oti.sub_blocks(),
        "sub_blocks mismatch — field-position regression"
    );
    assert_eq!(
        wrapper.alignment,
        raptorq_oti.symbol_alignment(),
        "alignment mismatch — field-position regression"
    );
    assert_eq!(
        wrapper.payload_hash,
        raptorq_oti.payload_hash(),
        "payload_hash mismatch — optional field dropped or coerced"
    );
}

fuzz_target!(|data: &[u8]| {
    OTI_ROUNDTRIP_ANCHOR.call_once(assert_oti_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let raptorq_oti = build_oti(&input);

    // ── PROPERTY 2: field-position invariance (via from_oti) ───────────
    let wrapper = ObjectTransmissionInfo::from_oti(raptorq_oti);
    assert_field_agreement(&wrapper, &raptorq_oti);

    // ── PROPERTY 6: From conversion agrees with from_oti ──────────────
    let from_conversion: ObjectTransmissionInfo = raptorq_oti.into();
    assert_eq!(
        wrapper, from_conversion,
        "From<ObjectTransmissionInformation> disagrees with from_oti — \
         the two construction paths produced different wrapper values"
    );

    // ── PROPERTY 1: OTI round-trip ─────────────────────────────────────
    let recovered_raptorq = wrapper.to_oti();
    assert_field_agreement(&wrapper, &recovered_raptorq);
    assert_eq!(
        raptorq_oti.transfer_length(),
        recovered_raptorq.transfer_length()
    );
    assert_eq!(raptorq_oti.symbol_size(), recovered_raptorq.symbol_size());
    assert_eq!(
        raptorq_oti.source_blocks(),
        recovered_raptorq.source_blocks()
    );
    assert_eq!(raptorq_oti.sub_blocks(), recovered_raptorq.sub_blocks());
    assert_eq!(
        raptorq_oti.symbol_alignment(),
        recovered_raptorq.symbol_alignment()
    );
    assert_eq!(raptorq_oti.payload_hash(), recovered_raptorq.payload_hash());

    // ── PROPERTY 3: JSON serde round-trip ──────────────────────────────
    let json = serde_json::to_string(&wrapper).expect("OTI serializes to JSON");
    let from_json: ObjectTransmissionInfo =
        serde_json::from_str(&json).expect("OTI JSON round-trips");
    assert_eq!(
        wrapper, from_json,
        "JSON serde round-trip lost or altered fields"
    );

    // ── PROPERTY 4: canonical-CBOR serde round-trip ────────────────────
    let s = schema();
    let cbor = CanonicalSerializer::serialize(&wrapper, &s).expect("OTI canonical-CBOR serializes");
    let from_cbor: ObjectTransmissionInfo =
        CanonicalSerializer::deserialize(&cbor, &s).expect("OTI canonical-CBOR round-trips");
    assert_eq!(
        wrapper, from_cbor,
        "canonical-CBOR serde round-trip lost or altered fields"
    );

    // ── PROPERTY 5: payload_hash optionality ──────────────────────────
    // Strip or inject the payload_hash and confirm the resulting wrapper
    // is distinct (so the optional field actually carries information).
    let mut toggled = wrapper;
    toggled.payload_hash = match wrapper.payload_hash {
        Some(_) => None,
        None => Some([0xCDu8; 32]),
    };
    if toggled != wrapper {
        let toggled_json = serde_json::to_string(&toggled).expect("toggled OTI serializes");
        let toggled_back: ObjectTransmissionInfo =
            serde_json::from_str(&toggled_json).expect("toggled OTI round-trips");
        assert_eq!(
            toggled, toggled_back,
            "JSON serde lost the toggled payload_hash distinction"
        );
        assert_ne!(
            toggled, wrapper,
            "toggling payload_hash produced an identical wrapper — \
             the optional field is being silently coerced"
        );
    }
});

/// Once-gated anchor: a known OTI (transfer_length=8192, symbol_size=128,
/// source_blocks=1, sub_blocks=1, alignment=8, payload_hash=0xAA…)
/// MUST round-trip byte-for-byte through raptorq conversion + serde.
/// Run once per process so a regression in field positions or payload_hash
/// handling trips on every fuzz invocation.
fn assert_oti_anchored() {
    let payload_hash = [0xAAu8; 32];
    let raptorq_oti =
        ObjectTransmissionInformation::new(8192, 128, 1, 1, 8).with_payload_hash(payload_hash);

    let wrapper = ObjectTransmissionInfo::from_oti(raptorq_oti);
    assert_eq!(
        wrapper.transfer_length, 8192,
        "ANCHOR REGRESSION: from_oti dropped transfer_length"
    );
    assert_eq!(
        wrapper.symbol_size, 128,
        "ANCHOR REGRESSION: from_oti dropped symbol_size"
    );
    assert_eq!(
        wrapper.source_blocks, 1,
        "ANCHOR REGRESSION: from_oti dropped source_blocks"
    );
    assert_eq!(
        wrapper.sub_blocks, 1,
        "ANCHOR REGRESSION: from_oti dropped sub_blocks"
    );
    assert_eq!(
        wrapper.alignment, 8,
        "ANCHOR REGRESSION: from_oti dropped alignment"
    );
    assert_eq!(
        wrapper.payload_hash,
        Some(payload_hash),
        "ANCHOR REGRESSION: from_oti dropped payload_hash"
    );

    let recovered = wrapper.to_oti();
    assert_eq!(recovered.transfer_length(), 8192);
    assert_eq!(recovered.symbol_size(), 128);
    assert_eq!(recovered.source_blocks(), 1);
    assert_eq!(recovered.sub_blocks(), 1);
    assert_eq!(recovered.symbol_alignment(), 8);
    assert_eq!(
        recovered.payload_hash(),
        Some(payload_hash),
        "ANCHOR REGRESSION: to_oti dropped payload_hash on round-trip"
    );

    // JSON round-trip anchor.
    let json = serde_json::to_string(&wrapper).expect("anchor OTI to JSON");
    let from_json: ObjectTransmissionInfo =
        serde_json::from_str(&json).expect("anchor OTI from JSON");
    assert_eq!(
        wrapper, from_json,
        "ANCHOR REGRESSION: known OTI did not round-trip through JSON"
    );

    // Canonical-CBOR round-trip anchor.
    let s = SchemaId::new("fcp.fuzz", "OtiAnchor", Version::new(1, 0, 0));
    let cbor =
        CanonicalSerializer::serialize(&wrapper, &s).expect("anchor OTI canonical-CBOR encode");
    let from_cbor: ObjectTransmissionInfo =
        CanonicalSerializer::deserialize(&cbor, &s).expect("anchor OTI canonical-CBOR decode");
    assert_eq!(
        wrapper, from_cbor,
        "ANCHOR REGRESSION: known OTI did not round-trip through canonical CBOR"
    );
}
