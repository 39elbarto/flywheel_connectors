//! Object Transmission Information (OTI) for `RaptorQ`.
//!
//! Replaces the external `raptorq::ObjectTransmissionInformation` with an
//! API-compatible struct owned by this crate.

use serde::{Deserialize, Serialize};

/// Describes how an object was encoded with `RaptorQ`.
///
/// Contains the parameters needed by a decoder to reconstruct the original
/// object from received encoding symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectTransmissionInformation {
    /// Total length of the original object in bytes.
    transfer_length: u64,
    /// Size of each encoding symbol in bytes.
    symbol_size: u16,
    /// Number of source blocks (always 1 for FCP).
    source_blocks: u8,
    /// Number of sub-blocks per source block.
    sub_blocks: u16,
    /// Symbol alignment in bytes.
    alignment: u8,
}

impl ObjectTransmissionInformation {
    /// Create a new OTI.
    #[must_use]
    pub const fn new(
        transfer_length: u64,
        symbol_size: u16,
        source_blocks: u8,
        sub_blocks: u16,
        alignment: u8,
    ) -> Self {
        Self {
            transfer_length,
            symbol_size,
            source_blocks,
            sub_blocks,
            alignment,
        }
    }

    /// Total length of the original object in bytes.
    #[must_use]
    pub const fn transfer_length(&self) -> u64 {
        self.transfer_length
    }

    /// Size of each encoding symbol in bytes.
    #[must_use]
    pub const fn symbol_size(&self) -> u16 {
        self.symbol_size
    }

    /// Number of source blocks.
    #[must_use]
    pub const fn source_blocks(&self) -> u8 {
        self.source_blocks
    }

    /// Number of sub-blocks per source block.
    #[must_use]
    pub const fn sub_blocks(&self) -> u16 {
        self.sub_blocks
    }

    /// Symbol alignment in bytes.
    #[must_use]
    pub const fn symbol_alignment(&self) -> u8 {
        self.alignment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oti_roundtrip() {
        let oti = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
        assert_eq!(oti.transfer_length(), 1024);
        assert_eq!(oti.symbol_size(), 64);
        assert_eq!(oti.source_blocks(), 1);
        assert_eq!(oti.sub_blocks(), 1);
        assert_eq!(oti.symbol_alignment(), 8);
    }

    #[test]
    fn oti_clone_eq() {
        let oti1 = ObjectTransmissionInformation::new(512, 32, 1, 1, 4);
        let oti2 = oti1;
        assert_eq!(oti1, oti2);
    }

    #[test]
    fn oti_serde_roundtrip() {
        let oti = ObjectTransmissionInformation::new(4096, 128, 1, 2, 8);
        let json = serde_json::to_string(&oti).unwrap();
        let decoded: ObjectTransmissionInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(oti, decoded);
    }

    #[test]
    fn oti_zero_values() {
        let oti = ObjectTransmissionInformation::new(0, 0, 0, 0, 0);
        assert_eq!(oti.transfer_length(), 0);
        assert_eq!(oti.symbol_size(), 0);
        assert_eq!(oti.source_blocks(), 0);
        assert_eq!(oti.sub_blocks(), 0);
        assert_eq!(oti.symbol_alignment(), 0);
    }

    #[test]
    fn oti_max_values() {
        let oti =
            ObjectTransmissionInformation::new(u64::MAX, u16::MAX, u8::MAX, u16::MAX, u8::MAX);
        assert_eq!(oti.transfer_length(), u64::MAX);
        assert_eq!(oti.symbol_size(), u16::MAX);
        assert_eq!(oti.source_blocks(), u8::MAX);
        assert_eq!(oti.sub_blocks(), u16::MAX);
        assert_eq!(oti.symbol_alignment(), u8::MAX);
    }

    #[test]
    fn oti_copy_semantics() {
        let oti1 = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
        let oti2 = oti1; // Copy
        let oti3 = oti1; // Can still use oti1 because Copy
        assert_eq!(oti2, oti3);
        assert_eq!(oti1, oti2);
    }

    #[test]
    fn oti_inequality() {
        let oti1 = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
        let oti2 = ObjectTransmissionInformation::new(2048, 64, 1, 1, 8);
        assert_ne!(oti1, oti2);
    }

    #[test]
    fn oti_inequality_symbol_size() {
        let oti1 = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
        let oti2 = ObjectTransmissionInformation::new(1024, 128, 1, 1, 8);
        assert_ne!(oti1, oti2);
    }

    #[test]
    fn oti_debug_format() {
        let oti = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
        let debug = format!("{oti:?}");
        assert!(debug.contains("ObjectTransmissionInformation"));
        assert!(debug.contains("1024"));
        assert!(debug.contains("64"));
    }

    #[test]
    fn oti_serde_json_structure() {
        let oti = ObjectTransmissionInformation::new(4096, 128, 1, 2, 8);
        let value: serde_json::Value = serde_json::to_value(oti).unwrap();
        assert_eq!(value["transfer_length"], 4096);
        assert_eq!(value["symbol_size"], 128);
        assert_eq!(value["source_blocks"], 1);
        assert_eq!(value["sub_blocks"], 2);
        assert_eq!(value["alignment"], 8);
    }

    #[test]
    fn oti_serde_from_json_string() {
        let json = r#"{"transfer_length":512,"symbol_size":32,"source_blocks":1,"sub_blocks":1,"alignment":4}"#;
        let oti: ObjectTransmissionInformation = serde_json::from_str(json).unwrap();
        assert_eq!(oti.transfer_length(), 512);
        assert_eq!(oti.symbol_size(), 32);
        assert_eq!(oti.source_blocks(), 1);
        assert_eq!(oti.sub_blocks(), 1);
        assert_eq!(oti.symbol_alignment(), 4);
    }

    #[test]
    fn oti_serde_invalid_json_fails() {
        let json = r#"{"transfer_length":"not_a_number"}"#;
        let result = serde_json::from_str::<ObjectTransmissionInformation>(json);
        assert!(result.is_err());
    }

    #[test]
    fn oti_serde_missing_field_fails() {
        let json = r#"{"transfer_length":512,"symbol_size":32}"#;
        let result = serde_json::from_str::<ObjectTransmissionInformation>(json);
        assert!(result.is_err());
    }

    #[test]
    fn oti_typical_fcp_values() {
        // FCP typically uses 1 source block, alignment 8
        let oti = ObjectTransmissionInformation::new(1_048_576, 1280, 1, 1, 8);
        assert_eq!(oti.transfer_length(), 1_048_576); // 1 MiB
        assert_eq!(oti.symbol_size(), 1280);
        assert_eq!(oti.source_blocks(), 1);
        assert_eq!(oti.symbol_alignment(), 8);
    }

    #[test]
    fn oti_each_field_differs() {
        let base = ObjectTransmissionInformation::new(100, 10, 1, 1, 1);
        // Differ only in source_blocks
        let other_src_blocks = ObjectTransmissionInformation::new(100, 10, 2, 1, 1);
        assert_ne!(base, other_src_blocks);
        // Differ only in sub_blocks
        let other_sub_blocks = ObjectTransmissionInformation::new(100, 10, 1, 2, 1);
        assert_ne!(base, other_sub_blocks);
        // Differ only in alignment
        let other_align = ObjectTransmissionInformation::new(100, 10, 1, 1, 2);
        assert_ne!(base, other_align);
    }

    // ── Additional OTI tests ───────────────────────────────────────────────

    #[test]
    fn oti_serde_roundtrip_max_values() {
        let oti =
            ObjectTransmissionInformation::new(u64::MAX, u16::MAX, u8::MAX, u16::MAX, u8::MAX);
        let json = serde_json::to_string(&oti).unwrap();
        let decoded: ObjectTransmissionInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(oti, decoded);
    }

    #[test]
    fn oti_serde_roundtrip_zero_values() {
        let oti = ObjectTransmissionInformation::new(0, 0, 0, 0, 0);
        let json = serde_json::to_string(&oti).unwrap();
        let decoded: ObjectTransmissionInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(oti, decoded);
    }

    #[test]
    fn oti_serde_extra_fields_ignored() {
        // JSON with an extra field should still deserialize (serde default behavior)
        let json = r#"{"transfer_length":1024,"symbol_size":64,"source_blocks":1,"sub_blocks":1,"alignment":8,"extra_field":"ignored"}"#;
        let oti: ObjectTransmissionInformation = serde_json::from_str(json).unwrap();
        assert_eq!(oti.transfer_length(), 1024);
        assert_eq!(oti.symbol_size(), 64);
    }

    #[test]
    fn oti_small_symbol_size() {
        let oti = ObjectTransmissionInformation::new(10, 1, 1, 1, 1);
        assert_eq!(oti.transfer_length(), 10);
        assert_eq!(oti.symbol_size(), 1);
    }

    #[test]
    fn oti_large_transfer_length() {
        let oti = ObjectTransmissionInformation::new(1_000_000_000_000, 1024, 1, 1, 8);
        assert_eq!(oti.transfer_length(), 1_000_000_000_000);
    }

    #[test]
    fn oti_equality_reflexive() {
        let oti = ObjectTransmissionInformation::new(512, 64, 1, 1, 4);
        assert_eq!(oti, oti);
    }

    #[test]
    fn oti_equality_symmetric() {
        let oti1 = ObjectTransmissionInformation::new(512, 64, 1, 1, 4);
        let oti2 = ObjectTransmissionInformation::new(512, 64, 1, 1, 4);
        assert_eq!(oti1, oti2);
        assert_eq!(oti2, oti1);
    }

    #[test]
    fn oti_debug_contains_all_fields() {
        let oti = ObjectTransmissionInformation::new(999, 55, 3, 7, 2);
        let debug = format!("{oti:?}");
        assert!(debug.contains("999"));
        assert!(debug.contains("55"));
        assert!(debug.contains('3'));
        assert!(debug.contains('7'));
        assert!(debug.contains('2'));
    }

    // ── Additional OTI tests ──────────────────────────────────────────────

    #[test]
    fn oti_all_fields_one() {
        let oti = ObjectTransmissionInformation::new(1, 1, 1, 1, 1);
        assert_eq!(oti.transfer_length(), 1);
        assert_eq!(oti.symbol_size(), 1);
        assert_eq!(oti.source_blocks(), 1);
        assert_eq!(oti.sub_blocks(), 1);
        assert_eq!(oti.symbol_alignment(), 1);
    }

    #[test]
    fn oti_serde_roundtrip_all_ones() {
        let oti = ObjectTransmissionInformation::new(1, 1, 1, 1, 1);
        let json = serde_json::to_string(&oti).unwrap();
        let decoded: ObjectTransmissionInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(oti, decoded);
    }

    #[test]
    fn oti_serde_roundtrip_typical_fcp() {
        let oti = ObjectTransmissionInformation::new(1_048_576, 1024, 1, 1, 8);
        let json = serde_json::to_string(&oti).unwrap();
        let decoded: ObjectTransmissionInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(oti, decoded);
    }

    #[test]
    fn oti_inequality_all_field_pairs() {
        let base = ObjectTransmissionInformation::new(100, 64, 1, 1, 8);

        // Differ in transfer_length
        assert_ne!(base, ObjectTransmissionInformation::new(101, 64, 1, 1, 8));
        // Differ in symbol_size
        assert_ne!(base, ObjectTransmissionInformation::new(100, 65, 1, 1, 8));
        // Differ in source_blocks
        assert_ne!(base, ObjectTransmissionInformation::new(100, 64, 2, 1, 8));
        // Differ in sub_blocks
        assert_ne!(base, ObjectTransmissionInformation::new(100, 64, 1, 2, 8));
        // Differ in alignment
        assert_ne!(base, ObjectTransmissionInformation::new(100, 64, 1, 1, 4));
    }

    #[test]
    fn oti_copy_preserves_all_fields() {
        let original = ObjectTransmissionInformation::new(42, 16, 2, 3, 4);
        let copy = original;
        assert_eq!(original.transfer_length(), copy.transfer_length());
        assert_eq!(original.symbol_size(), copy.symbol_size());
        assert_eq!(original.source_blocks(), copy.source_blocks());
        assert_eq!(original.sub_blocks(), copy.sub_blocks());
        assert_eq!(original.symbol_alignment(), copy.symbol_alignment());
    }

    #[test]
    fn oti_serde_json_field_names() {
        let oti = ObjectTransmissionInformation::new(100, 64, 1, 1, 8);
        let json = serde_json::to_string(&oti).unwrap();
        assert!(json.contains("transfer_length"));
        assert!(json.contains("symbol_size"));
        assert!(json.contains("source_blocks"));
        assert!(json.contains("sub_blocks"));
        assert!(json.contains("alignment"));
    }

    #[test]
    fn oti_serde_invalid_type_for_symbol_size() {
        let json = r#"{"transfer_length":100,"symbol_size":"big","source_blocks":1,"sub_blocks":1,"alignment":8}"#;
        let result = serde_json::from_str::<ObjectTransmissionInformation>(json);
        assert!(result.is_err());
    }

    #[test]
    fn oti_serde_negative_value_fails() {
        let json = r#"{"transfer_length":-1,"symbol_size":64,"source_blocks":1,"sub_blocks":1,"alignment":8}"#;
        let result = serde_json::from_str::<ObjectTransmissionInformation>(json);
        assert!(result.is_err());
    }

    // ── Additional OTI edge-case tests ───────────────────────────────────

    #[test]
    fn oti_new_is_const() {
        // Verify const construction works at compile time
        const OTI: ObjectTransmissionInformation =
            ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
        assert_eq!(OTI.transfer_length(), 1024);
        assert_eq!(OTI.symbol_size(), 64);
    }

    #[test]
    fn oti_serde_bincode_style_roundtrip() {
        let oti = ObjectTransmissionInformation::new(4096, 128, 1, 2, 8);
        let json_bytes = serde_json::to_vec(&oti).unwrap();
        let decoded: ObjectTransmissionInformation = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(oti, decoded);
    }

    #[test]
    fn oti_multiple_source_blocks() {
        let oti = ObjectTransmissionInformation::new(1_000_000, 1024, 4, 2, 8);
        assert_eq!(oti.source_blocks(), 4);
        assert_eq!(oti.sub_blocks(), 2);
    }

    #[test]
    fn oti_alignment_values() {
        for align in [1, 2, 4, 8, 16] {
            let oti = ObjectTransmissionInformation::new(100, 64, 1, 1, align);
            assert_eq!(oti.symbol_alignment(), align);
        }
    }

    #[test]
    fn oti_serde_empty_json_object_fails() {
        let json = "{}";
        let result = serde_json::from_str::<ObjectTransmissionInformation>(json);
        assert!(result.is_err());
    }

    #[test]
    fn oti_serde_overflow_symbol_size_fails() {
        // u16 max is 65535, so 70000 should fail
        let json = r#"{"transfer_length":100,"symbol_size":70000,"source_blocks":1,"sub_blocks":1,"alignment":8}"#;
        let result = serde_json::from_str::<ObjectTransmissionInformation>(json);
        assert!(result.is_err());
    }

    #[test]
    fn oti_equality_transitive() {
        let a = ObjectTransmissionInformation::new(100, 64, 1, 1, 8);
        let b = ObjectTransmissionInformation::new(100, 64, 1, 1, 8);
        let c = ObjectTransmissionInformation::new(100, 64, 1, 1, 8);
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, c);
    }
}
