//! Serde module for serializing byte arrays as Hex (human-readable) or Bytes (binary).

use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a byte slice.
///
/// # Errors
/// Returns any serializer error when serialization fails.
pub fn serialize<S, T>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    if serializer.is_human_readable() {
        hex::serde::serialize(bytes, serializer)
    } else {
        serializer.serialize_bytes(bytes.as_ref())
    }
}

/// Deserialize a byte array.
///
/// # Errors
/// Returns an error if hex decoding fails, the length is incorrect, or the
/// underlying deserializer reports an error.
pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        struct HexExpected<const N: usize>;
        impl<const N: usize> serde::de::Expected for HexExpected<N> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a hex string decoding to {N} bytes")
            }
        }

        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(s).map_err(serde::de::Error::custom)?;
        if vec.len() != N {
            return Err(serde::de::Error::invalid_length(
                vec.len(),
                &HexExpected::<N>,
            ));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&vec);
        Ok(arr)
    } else {
        // For binary formats, we can use serde_bytes logic or just visit_bytes
        struct BytesVisitor<const N: usize>;

        impl<'de, const N: usize> serde::de::Visitor<'de> for BytesVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a byte array of length {N}")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != N {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; N];
                arr.copy_from_slice(v);
                Ok(arr)
            }

            // Support seq access if the format doesn't support bytes (like json-binary hybrids)
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; N];
                for (i, v) in arr.iter_mut().enumerate() {
                    *v = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }

                // Enforce exactly N elements, otherwise it's a silent truncation
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(N + 1, &self));
                }

                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    /// Test wrapper for fixed-size 32-byte arrays (e.g., Ed25519 public keys).
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Key32 {
        #[serde(with = "super")]
        data: [u8; 32],
    }

    /// Test wrapper for fixed-size 64-byte arrays (e.g., Ed25519 signatures).
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sig64 {
        #[serde(with = "super")]
        data: [u8; 64],
    }

    /// Test wrapper for a 1-byte array.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Byte1 {
        #[serde(with = "super")]
        data: [u8; 1],
    }

    // ── JSON (human-readable / hex) roundtrips ──────────────────────────

    #[test]
    fn json_roundtrip_32_bytes() {
        let key = Key32 { data: [0xab; 32] };
        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("abababab"), "expected hex encoding");
        let back: Key32 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn json_roundtrip_64_bytes() {
        let sig = Sig64 { data: [0xcd; 64] };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("cdcdcdcd"), "expected hex encoding");
        let back: Sig64 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sig);
    }

    #[test]
    fn json_roundtrip_1_byte() {
        let b = Byte1 { data: [0xff] };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("ff"), "expected hex encoding");
        let back: Byte1 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn json_all_zeros() {
        let key = Key32 { data: [0x00; 32] };
        let json = serde_json::to_string(&key).unwrap();
        let expected_hex = "0".repeat(64);
        assert!(json.contains(&expected_hex));
        let back: Key32 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn json_sequential_bytes() {
        let mut data = [0u8; 32];
        #[allow(clippy::cast_possible_truncation)]
        for (i, v) in data.iter_mut().enumerate() {
            *v = i as u8; // i is at most 31, fits in u8
        }
        let key = Key32 { data };
        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("000102030405"));
        let back: Key32 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, key);
    }

    // ── JSON error cases ────────────────────────────────────────────────

    #[test]
    fn json_rejects_invalid_hex() {
        let bad = r#"{"data":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}"#;
        let result = serde_json::from_str::<Key32>(bad);
        assert!(result.is_err());
    }

    #[test]
    fn json_rejects_wrong_length_too_short() {
        // 30 bytes = 60 hex chars instead of 64
        let short_hex = "ab".repeat(30);
        let bad = format!(r#"{{"data":"{short_hex}"}}"#);
        let result = serde_json::from_str::<Key32>(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn json_rejects_wrong_length_too_long() {
        // 34 bytes = 68 hex chars instead of 64
        let long_hex = "ab".repeat(34);
        let bad = format!(r#"{{"data":"{long_hex}"}}"#);
        let result = serde_json::from_str::<Key32>(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn json_rejects_odd_length_hex() {
        let bad = r#"{"data":"abc"}"#;
        let result = serde_json::from_str::<Byte1>(bad);
        assert!(result.is_err());
    }

    #[test]
    fn json_rejects_empty_string() {
        let bad = r#"{"data":""}"#;
        let result = serde_json::from_str::<Key32>(bad);
        assert!(result.is_err());
    }

    // ── CBOR (binary) roundtrips ────────────────────────────────────────

    #[test]
    fn cbor_roundtrip_32_bytes() {
        let key = Key32 { data: [0xfe; 32] };
        let mut cbor = Vec::new();
        ciborium::into_writer(&key, &mut cbor).unwrap();
        let back: Key32 = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn cbor_roundtrip_64_bytes() {
        let sig = Sig64 { data: [0x42; 64] };
        let mut cbor = Vec::new();
        ciborium::into_writer(&sig, &mut cbor).unwrap();
        let back: Sig64 = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(back, sig);
    }

    #[test]
    fn cbor_roundtrip_1_byte() {
        let b = Byte1 { data: [0x99] };
        let mut cbor = Vec::new();
        ciborium::into_writer(&b, &mut cbor).unwrap();
        let back: Byte1 = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn cbor_all_zeros() {
        let key = Key32 { data: [0x00; 32] };
        let mut cbor = Vec::new();
        ciborium::into_writer(&key, &mut cbor).unwrap();
        let back: Key32 = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(back, key);
    }

    // ── Cross-format consistency ────────────────────────────────────────

    #[test]
    fn json_and_cbor_decode_to_same_value() {
        let original = Key32 { data: [0x13; 32] };

        let json = serde_json::to_string(&original).unwrap();
        let from_json: Key32 = serde_json::from_str(&json).unwrap();

        let mut cbor = Vec::new();
        ciborium::into_writer(&original, &mut cbor).unwrap();
        let from_cbor: Key32 = ciborium::from_reader(&cbor[..]).unwrap();

        assert_eq!(from_json, from_cbor);
        assert_eq!(from_json, original);
    }

    // ── Hex format details ──────────────────────────────────────────────

    #[test]
    fn json_uses_lowercase_hex() {
        let key = Key32 { data: [0xAB; 32] };
        let json = serde_json::to_string(&key).unwrap();
        // hex crate outputs lowercase
        assert!(json.contains("abab"));
        assert!(!json.contains("ABAB"));
    }

    #[test]
    fn json_accepts_uppercase_hex() {
        let upper_hex = "AB".repeat(32);
        let input = format!(r#"{{"data":"{upper_hex}"}}"#);
        let result = serde_json::from_str::<Key32>(&input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data, [0xAB; 32]);
    }

    #[test]
    fn json_accepts_mixed_case_hex() {
        let mixed = "aAbBcCdD".repeat(8);
        let input = format!(r#"{{"data":"{mixed}"}}"#);
        let result = serde_json::from_str::<Key32>(&input);
        assert!(result.is_ok());
    }

    // ── Determinism ─────────────────────────────────────────────────────

    #[test]
    fn json_serialization_deterministic() {
        let key = Key32 { data: [0x77; 32] };
        let json1 = serde_json::to_string(&key).unwrap();
        let json2 = serde_json::to_string(&key).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn cbor_serialization_deterministic() {
        let key = Key32 { data: [0x77; 32] };
        let mut cbor1 = Vec::new();
        ciborium::into_writer(&key, &mut cbor1).unwrap();
        let mut cbor2 = Vec::new();
        ciborium::into_writer(&key, &mut cbor2).unwrap();
        assert_eq!(cbor1, cbor2);
    }
}
