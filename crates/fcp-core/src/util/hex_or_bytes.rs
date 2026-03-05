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
