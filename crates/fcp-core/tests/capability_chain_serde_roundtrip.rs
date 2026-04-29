use ciborium::value::Value as CborValue;
use fcp_core::{CapabilityChain, ObjectId};

// There is no separate CapabilityChainStep type in fcp-core; each ObjectId in
// the transparent Vec is a positional chain step.

fn expect_cbor_array(value: CborValue) -> Vec<CborValue> {
    match value {
        CborValue::Array(items) => items,
        other => Err::<Vec<CborValue>, _>(format!(
            "CapabilityChain MUST encode as a CBOR array, got {other:?}"
        ))
        .expect("CapabilityChain CBOR array"),
    }
}

fn expect_cbor_bytes(value: &CborValue) -> &[u8] {
    match value {
        CborValue::Bytes(bytes) => bytes.as_slice(),
        other => Err::<&[u8], _>(format!(
            "CapabilityChain item MUST encode as bytes, got {other:?}"
        ))
        .expect("CapabilityChain CBOR item bytes"),
    }
}

fn object_id(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn representative_chain() -> CapabilityChain {
    CapabilityChain::new(vec![object_id(0x11), object_id(0x22), object_id(0x33)])
}

#[test]
fn capability_chain_step_order_is_positional_not_lexicographic() {
    let original_steps = vec![object_id(0x33), object_id(0x11), object_id(0x22)];
    let chain = CapabilityChain::new(original_steps.clone());

    assert_eq!(chain.as_slice(), original_steps.as_slice());

    let mut sorted_steps = original_steps.clone();
    sorted_steps.sort();
    assert_eq!(
        sorted_steps,
        vec![object_id(0x11), object_id(0x22), object_id(0x33)],
        "fixture must prove ObjectId has a different lexicographic order"
    );
    assert_ne!(
        chain,
        CapabilityChain::new(sorted_steps),
        "CapabilityChain order is positional and MUST NOT be normalized by ObjectId ordering"
    );

    let json = serde_json::to_string(&chain).expect("CapabilityChain encodes as JSON");
    assert_eq!(
        json,
        format!(
            r#"["{}","{}","{}"]"#,
            "33".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
        ),
    );
}

#[test]
fn capability_chain_equality_and_wire_bytes_are_order_sensitive() {
    let forward = representative_chain();
    let reversed = CapabilityChain::new(vec![object_id(0x33), object_id(0x22), object_id(0x11)]);

    assert_ne!(forward, reversed);

    let forward_json = serde_json::to_string(&forward).expect("forward JSON");
    let reversed_json = serde_json::to_string(&reversed).expect("reversed JSON");
    assert_ne!(
        forward_json, reversed_json,
        "JSON bytes must change when capability chain step order changes"
    );

    let mut forward_cbor = Vec::new();
    ciborium::ser::into_writer(&forward, &mut forward_cbor).expect("forward CBOR");
    let mut reversed_cbor = Vec::new();
    ciborium::ser::into_writer(&reversed, &mut reversed_cbor).expect("reversed CBOR");
    assert_ne!(
        forward_cbor, reversed_cbor,
        "CBOR bytes must change when capability chain step order changes"
    );

    let forward_back: CapabilityChain =
        serde_json::from_str(&forward_json).expect("forward JSON roundtrip");
    let reversed_back: CapabilityChain =
        serde_json::from_str(&reversed_json).expect("reversed JSON roundtrip");
    assert_eq!(forward_back, forward);
    assert_eq!(reversed_back, reversed);
}

#[test]
fn duplicate_capability_chain_steps_remain_distinct_positions() {
    let steps = vec![
        object_id(0x11),
        object_id(0x22),
        object_id(0x22),
        object_id(0x33),
    ];
    let chain = CapabilityChain::new(steps.clone());

    assert_eq!(chain.len(), 4);
    assert_eq!(chain.as_slice(), steps.as_slice());
    assert_eq!(chain.clone().into_inner(), steps);

    let json = serde_json::to_string(&chain).expect("CapabilityChain encodes as JSON");
    assert_eq!(
        json,
        format!(
            r#"["{}","{}","{}","{}"]"#,
            "11".repeat(32),
            "22".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        ),
        "serialization must preserve duplicate positional steps"
    );
}

#[test]
fn capability_chain_json_roundtrip_preserves_order_and_hex_shape() {
    let chain = representative_chain();

    let json = serde_json::to_string(&chain).expect("CapabilityChain encodes as JSON");
    assert_eq!(
        json,
        format!(
            r#"["{}","{}","{}"]"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        ),
    );

    let decoded: CapabilityChain =
        serde_json::from_str(&json).expect("CapabilityChain decodes from JSON");
    assert_eq!(decoded, chain);
    assert_eq!(
        decoded.as_slice(),
        &[object_id(0x11), object_id(0x22), object_id(0x33)]
    );
}

#[test]
fn capability_chain_cbor_roundtrip_preserves_order_and_binary_shape() {
    let chain = representative_chain();

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&chain, &mut bytes).expect("CapabilityChain encodes as CBOR");
    let decoded: CapabilityChain =
        ciborium::de::from_reader(bytes.as_slice()).expect("CapabilityChain decodes from CBOR");
    assert_eq!(decoded, chain);

    let cbor: CborValue =
        ciborium::de::from_reader(bytes.as_slice()).expect("CapabilityChain decodes as CBOR value");
    let items = expect_cbor_array(cbor);
    assert_eq!(items.len(), 3);
    for (item, expected_byte) in items.iter().zip([0x11, 0x22, 0x33]) {
        assert_eq!(expect_cbor_bytes(item), &[expected_byte; 32]);
    }
}

#[test]
fn empty_capability_chain_json_and_cbor_roundtrip_as_empty_array() {
    let chain = CapabilityChain::default();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);

    let json = serde_json::to_string(&chain).expect("empty CapabilityChain encodes as JSON");
    assert_eq!(json, "[]");
    let decoded_json: CapabilityChain =
        serde_json::from_str(&json).expect("empty CapabilityChain decodes from JSON");
    assert_eq!(decoded_json, chain);

    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&chain, &mut cbor_bytes)
        .expect("empty CapabilityChain encodes as CBOR");
    let decoded_cbor: CapabilityChain = ciborium::de::from_reader(cbor_bytes.as_slice())
        .expect("empty CapabilityChain decodes from CBOR");
    assert_eq!(decoded_cbor, chain);

    let cbor: CborValue = ciborium::de::from_reader(cbor_bytes.as_slice())
        .expect("empty CapabilityChain decodes as CBOR value");
    assert_eq!(cbor, CborValue::Array(Vec::new()));
}
