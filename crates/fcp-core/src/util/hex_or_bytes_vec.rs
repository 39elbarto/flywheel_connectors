//! Serde module for serializing `Vec<u8>` as Hex (human-readable) or Bytes (binary).

use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a byte vec.
///
/// # Errors
/// Returns any serializer error when serialization fails.
pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        hex::serde::serialize(bytes, serializer)
    } else {
        serializer.serialize_bytes(bytes)
    }
}

/// Deserialize a byte vec.
///
/// # Errors
/// Returns an error if hex decoding fails or the underlying deserializer reports an error.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    } else {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.to_vec())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(byte) = seq.next_element()? {
                    vec.push(byte);
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    /// Test wrapper using the vec variant.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct BlobField {
        #[serde(with = "super")]
        data: Vec<u8>,
    }

    // ── JSON (human-readable / hex) roundtrips ──────────────────────────

    #[test]
    fn json_roundtrip_nonempty() {
        let blob = BlobField {
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(json.contains("deadbeef"));
        let back: BlobField = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn json_roundtrip_empty() {
        let blob = BlobField { data: vec![] };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(
            json.contains(r#""""#),
            "empty vec should produce empty hex string"
        );
        let back: BlobField = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn json_roundtrip_single_byte() {
        let blob = BlobField { data: vec![0x42] };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(json.contains("42"));
        let back: BlobField = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn json_roundtrip_all_zeros() {
        let blob = BlobField {
            data: vec![0x00; 16],
        };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(json.contains(&"0".repeat(32)));
        let back: BlobField = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn json_roundtrip_all_ff() {
        let blob = BlobField {
            data: vec![0xff; 8],
        };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(json.contains("ffffffffffffffff"));
        let back: BlobField = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn json_roundtrip_large_blob() {
        let blob = BlobField {
            data: (0..=255).collect(),
        };
        let json = serde_json::to_string(&blob).unwrap();
        let back: BlobField = serde_json::from_str(&json).unwrap();
        assert_eq!(back, blob);
    }

    // ── JSON error cases ────────────────────────────────────────────────

    #[test]
    fn json_rejects_invalid_hex() {
        let bad = r#"{"data":"zzzz"}"#;
        let result = serde_json::from_str::<BlobField>(bad);
        assert!(result.is_err());
    }

    #[test]
    fn json_rejects_odd_length_hex() {
        let bad = r#"{"data":"abc"}"#;
        let result = serde_json::from_str::<BlobField>(bad);
        assert!(result.is_err());
    }

    // ── CBOR (binary) roundtrips ────────────────────────────────────────

    #[test]
    fn cbor_roundtrip_nonempty() {
        let blob = BlobField {
            data: vec![0xca, 0xfe, 0xba, 0xbe],
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&blob, &mut cbor).unwrap();
        let back: BlobField = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn cbor_roundtrip_empty() {
        let blob = BlobField { data: vec![] };
        let mut cbor = Vec::new();
        ciborium::into_writer(&blob, &mut cbor).unwrap();
        let back: BlobField = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn cbor_roundtrip_large() {
        let blob = BlobField {
            data: vec![0xAB; 1024],
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&blob, &mut cbor).unwrap();
        let back: BlobField = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(back, blob);
    }

    // ── Cross-format consistency ────────────────────────────────────────

    #[test]
    fn json_and_cbor_decode_to_same_value() {
        let original = BlobField {
            data: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        };

        let json = serde_json::to_string(&original).unwrap();
        let from_json: BlobField = serde_json::from_str(&json).unwrap();

        let mut cbor = Vec::new();
        ciborium::into_writer(&original, &mut cbor).unwrap();
        let from_cbor: BlobField = ciborium::from_reader(&cbor[..]).unwrap();

        assert_eq!(from_json, from_cbor);
        assert_eq!(from_json, original);
    }

    // ── Hex format details ──────────────────────────────────────────────

    #[test]
    fn json_uses_lowercase_hex() {
        let blob = BlobField {
            data: vec![0xAB, 0xCD],
        };
        let json = serde_json::to_string(&blob).unwrap();
        assert!(json.contains("abcd"));
        assert!(!json.contains("ABCD"));
    }

    #[test]
    fn json_accepts_uppercase_hex() {
        let input = r#"{"data":"ABCD"}"#;
        let result = serde_json::from_str::<BlobField>(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data, vec![0xAB, 0xCD]);
    }

    // ── Determinism ─────────────────────────────────────────────────────

    #[test]
    fn json_serialization_deterministic() {
        let blob = BlobField {
            data: vec![1, 2, 3, 4, 5],
        };
        let json1 = serde_json::to_string(&blob).unwrap();
        let json2 = serde_json::to_string(&blob).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn cbor_serialization_deterministic() {
        let blob = BlobField {
            data: vec![1, 2, 3, 4, 5],
        };
        let mut cbor1 = Vec::new();
        ciborium::into_writer(&blob, &mut cbor1).unwrap();
        let mut cbor2 = Vec::new();
        ciborium::into_writer(&blob, &mut cbor2).unwrap();
        assert_eq!(cbor1, cbor2);
    }
}
