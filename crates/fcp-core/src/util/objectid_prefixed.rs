//! Serde helpers for manifest-facing `objectid:<hex>` object references.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ObjectId;

/// Serialize an [`ObjectId`] as `objectid:<hex>` for human-readable formats.
///
/// # Errors
/// Returns any serializer error produced by `serde`.
pub fn serialize<S>(object_id: &ObjectId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&object_id.to_prefixed_string())
    } else {
        crate::util::hex_or_bytes::serialize(object_id.as_bytes(), serializer)
    }
}

/// Deserialize an [`ObjectId`] from `objectid:<hex>` for human-readable formats.
///
/// # Errors
/// Returns a serde error if the input is malformed.
pub fn deserialize<'de, D>(deserializer: D) -> Result<ObjectId, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let value = String::deserialize(deserializer)?;
        ObjectId::parse_prefixed(&value).map_err(serde::de::Error::custom)
    } else {
        crate::util::hex_or_bytes::deserialize::<D, 32>(deserializer).map(ObjectId::from_bytes)
    }
}

/// Serde helpers for `Option<ObjectId>`.
pub mod option {
    use super::{Deserialize, Deserializer, ObjectId, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct WrappedObjectId(#[serde(with = "super")] ObjectId);

    /// Serialize an optional [`ObjectId`] using the parent module's encoding.
    ///
    /// # Errors
    /// Returns any serializer error produced by `serde`.
    pub fn serialize<S>(value: &Option<ObjectId>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.map(WrappedObjectId).serialize(serializer)
    }

    /// Deserialize an optional [`ObjectId`] using the parent module's encoding.
    ///
    /// # Errors
    /// Returns any deserializer error produced by `serde`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<ObjectId>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<WrappedObjectId>::deserialize(deserializer)
            .map(|value| value.map(|wrapped| wrapped.0))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::ObjectId;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Wrapper {
        #[serde(with = "super")]
        object_id: ObjectId,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct OptionalWrapper {
        #[serde(default, with = "super::option")]
        object_id: Option<ObjectId>,
    }

    #[test]
    fn json_roundtrip_uses_prefixed_form() {
        let wrapper = Wrapper {
            object_id: ObjectId::from_bytes([0xab; 32]),
        };
        let json = serde_json::to_string(&wrapper).unwrap();
        assert!(json.contains("objectid:"));
        let roundtrip: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, wrapper);
    }

    #[test]
    fn json_accepts_raw_hex_for_backward_reading() {
        let json = format!(r#"{{"object_id":"{}"}}"#, "cd".repeat(32));
        let parsed: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.object_id, ObjectId::from_bytes([0xcd; 32]));
    }

    #[test]
    fn option_roundtrip_none() {
        let wrapper = OptionalWrapper { object_id: None };
        let json = serde_json::to_string(&wrapper).unwrap();
        let roundtrip: OptionalWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, wrapper);
    }
}
