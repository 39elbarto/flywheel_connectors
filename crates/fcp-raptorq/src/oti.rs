//! Object Transmission Information (OTI) for RaptorQ.
//!
//! Replaces the external `raptorq::ObjectTransmissionInformation` with an
//! API-compatible struct owned by this crate.

use serde::{Deserialize, Serialize};

/// Describes how an object was encoded with RaptorQ.
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
}
