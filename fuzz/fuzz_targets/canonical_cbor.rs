#![no_main]

use ciborium::value::Value;
use fcp_cbor::{CanonicalSerializer, SchemaId, to_canonical_cbor};
use libfuzzer_sys::fuzz_target;
use semver::Version;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fn schema() -> SchemaId {
    SchemaId::new("fcp.cbor", "FuzzValue", Version::new(1, 0, 0))
}

fn prefixed(schema: &SchemaId, canonical: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(fcp_cbor::SCHEMA_HASH_LEN + canonical.len());
    data.extend_from_slice(schema.hash().as_bytes());
    data.extend_from_slice(canonical);
    data
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let schema = schema();

    let _ = CanonicalSerializer::deserialize::<Value>(data, &schema);
    let _ = CanonicalSerializer::deserialize_unchecked::<Value>(data, &schema);

    if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(data)
        && let Ok(serialized) = CanonicalSerializer::serialize(&json_value, &schema)
        && let Ok(decoded) =
            CanonicalSerializer::deserialize::<serde_json::Value>(&serialized, &schema)
    {
        let reserialized = CanonicalSerializer::serialize(&decoded, &schema).unwrap_or_default();
        assert_eq!(serialized, reserialized);
    }

    if let Ok(value) = ciborium::from_reader::<Value, _>(data)
        && let Ok(canonical) = to_canonical_cbor(&value)
    {
        let prefixed = prefixed(&schema, &canonical);
        let decoded = CanonicalSerializer::deserialize::<Value>(&prefixed, &schema);
        let unchecked = CanonicalSerializer::deserialize_unchecked::<Value>(&prefixed, &schema);

        if let Ok(decoded) = decoded {
            let recanonical = to_canonical_cbor(&decoded).unwrap_or_default();
            assert_eq!(canonical, recanonical);
        }
        if let Ok(decoded) = unchecked {
            let recanonical = to_canonical_cbor(&decoded).unwrap_or_default();
            assert_eq!(canonical, recanonical);
        }
    }
});
