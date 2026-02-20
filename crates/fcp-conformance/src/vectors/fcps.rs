//! FCPS (data-plane) golden vectors.
//!
//! These vectors test the FCPS frame encoding/decoding for symbol distribution.
//!
//! # Wire Format (NORMATIVE)
//!
//! ```text
//! FCPS FRAME FORMAT (Symbol-Native)
//!
//!   Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")
//!   Bytes 4-5:    Version (u16 LE)
//!   Bytes 6-7:    Flags (u16 LE)
//!   Bytes 8-11:   Symbol Count (u32 LE)
//!   Bytes 12-15:  Total Payload Length (u32 LE)
//!   Bytes 16-47:  Object ID (32 bytes)
//!   Bytes 48-49:  Symbol Size (u16 LE, default 1024)
//!   Bytes 50-57:  Zone Key ID (8 bytes)
//!   Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3)
//!   Bytes 90-97:  Epoch ID (u64 LE)
//!   Bytes 98-105: Sender Instance ID (u64 LE)
//!   Bytes 106-113: Frame Seq (u64 LE)
//!   Bytes 114+:   Symbol payloads (concatenated)
//!
//!   Fixed header: 114 bytes
//!   Each symbol record: 4 (ESI) + 2 (K) + symbol_size (data) + 16 (auth_tag)
//! ```

use serde::{Deserialize, Serialize};

/// Golden vector for FCPS frame encoding/decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcpsGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Frame version (currently 1).
    pub version: u16,
    /// Frame flags (bit field).
    pub flags: u16,
    /// Object ID (32 bytes hex).
    pub object_id: String,
    /// Symbol size in bytes.
    pub symbol_size: u16,
    /// Zone key ID (8 bytes hex).
    pub zone_key_id: String,
    /// Zone ID hash (32 bytes hex).
    pub zone_id_hash: String,
    /// Epoch ID.
    pub epoch_id: u64,
    /// Sender instance ID.
    pub sender_instance_id: u64,
    /// Frame sequence number.
    pub frame_seq: u64,
    /// Symbol records in the frame.
    pub symbols: Vec<SymbolRecordVector>,
    /// Expected encoded header (114 bytes hex).
    pub expected_header: String,
    /// Expected total frame (hex).
    pub expected_frame: String,
}

/// Golden vector for a single symbol record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRecordVector {
    /// Encoding Symbol ID.
    pub esi: u32,
    /// Total source symbols K.
    pub k: u16,
    /// Symbol data (hex).
    pub data: String,
    /// Authentication tag (16 bytes hex).
    pub auth_tag: String,
    /// Expected encoded record (hex).
    pub expected_encoded: String,
}

impl FcpsGoldenVector {
    /// Load all FCPS golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            vector_1_minimal_frame(),
            vector_2_two_symbols(),
            vector_3_flags_variation(),
        ]
    }

    /// Verify this golden vector against the implementation.
    ///
    /// # Errors
    /// Returns an error description if verification fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_core::{ObjectId, ZoneIdHash, ZoneKeyId};
        use fcp_protocol::{FCPS_VERSION, FcpsFrame, FcpsFrameHeader, FrameFlags, SymbolRecord};

        // Parse expected values
        let object_id = ObjectId::from_bytes(
            hex::decode(&self.object_id)
                .map_err(|e| format!("invalid object_id hex: {e}"))?
                .try_into()
                .map_err(|_| "object_id must be 32 bytes")?,
        );
        let zone_key_id = ZoneKeyId::from_bytes(
            hex::decode(&self.zone_key_id)
                .map_err(|e| format!("invalid zone_key_id hex: {e}"))?
                .try_into()
                .map_err(|_| "zone_key_id must be 8 bytes")?,
        );
        let zone_id_hash = ZoneIdHash::from_bytes(
            hex::decode(&self.zone_id_hash)
                .map_err(|e| format!("invalid zone_id_hash hex: {e}"))?
                .try_into()
                .map_err(|_| "zone_id_hash must be 32 bytes")?,
        );

        // Build header
        let flags = FrameFlags::from_bits_truncate(self.flags);
        let symbol_record_size = 22 + self.symbol_size as usize; // ESI(4) + K(2) + data + tag(16)
        let total_payload_len = self.symbols.len() * symbol_record_size;

        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags,
            symbol_count: u32::try_from(self.symbols.len()).map_err(|_| "symbol count overflow")?,
            total_payload_len: u32::try_from(total_payload_len)
                .map_err(|_| "payload length overflow")?,
            object_id,
            symbol_size: self.symbol_size,
            zone_key_id,
            zone_id_hash,
            epoch_id: self.epoch_id,
            sender_instance_id: self.sender_instance_id,
            frame_seq: self.frame_seq,
        };

        // Verify header encoding
        let encoded_header = header.encode();
        let expected_header_bytes = hex::decode(&self.expected_header)
            .map_err(|e| format!("invalid expected_header hex: {e}"))?;
        if encoded_header.as_slice() != expected_header_bytes.as_slice() {
            return Err(format!(
                "header mismatch:\n  expected: {}\n  actual:   {}",
                self.expected_header,
                hex::encode(encoded_header)
            ));
        }

        // Build symbol records
        let mut symbols = Vec::new();
        for (i, sv) in self.symbols.iter().enumerate() {
            let data =
                hex::decode(&sv.data).map_err(|e| format!("invalid symbol[{i}] data hex: {e}"))?;
            if data.len() != self.symbol_size as usize {
                return Err(format!(
                    "symbol[{i}] data length {} != symbol_size {}",
                    data.len(),
                    self.symbol_size
                ));
            }
            let auth_tag: [u8; 16] = hex::decode(&sv.auth_tag)
                .map_err(|e| format!("invalid symbol[{i}] auth_tag hex: {e}"))?
                .try_into()
                .map_err(|_| format!("symbol[{i}] auth_tag must be 16 bytes"))?;

            let record = SymbolRecord {
                esi: sv.esi,
                k: sv.k,
                data,
                auth_tag,
            };

            // Verify symbol record encoding
            let encoded_record = record.encode();
            let expected_record_bytes = hex::decode(&sv.expected_encoded)
                .map_err(|e| format!("invalid symbol[{i}] expected_encoded hex: {e}"))?;
            if encoded_record != expected_record_bytes {
                return Err(format!(
                    "symbol[{i}] record mismatch:\n  expected: {}\n  actual:   {}",
                    sv.expected_encoded,
                    hex::encode(&encoded_record)
                ));
            }

            symbols.push(record);
        }

        // Build and verify complete frame
        let frame = FcpsFrame { header, symbols };
        let encoded_frame = frame.encode();
        let expected_frame_bytes = hex::decode(&self.expected_frame)
            .map_err(|e| format!("invalid expected_frame hex: {e}"))?;
        if encoded_frame != expected_frame_bytes {
            return Err(format!(
                "frame mismatch (len {} vs {}):\n  expected: {}\n  actual:   {}",
                expected_frame_bytes.len(),
                encoded_frame.len(),
                self.expected_frame,
                hex::encode(&encoded_frame)
            ));
        }

        // Verify round-trip decode
        let decoded = FcpsFrame::decode(&encoded_frame, encoded_frame.len() + 1)
            .map_err(|e| format!("decode failed: {e}"))?;
        if decoded != frame {
            return Err("round-trip decode mismatch".to_string());
        }

        Ok(())
    }
}

/// Vector 1: Minimal FCPS frame with one small symbol.
///
/// Tests basic header and single-symbol encoding with minimal data.
fn vector_1_minimal_frame() -> FcpsGoldenVector {
    // Build header bytes manually for expected value:
    // Magic: "FCPS" = 46 43 50 53
    // Version: 1 (LE) = 01 00
    // Flags: 0x0404 (ENCRYPTED | RAPTORQ) = 04 04
    // Symbol count: 1 (LE) = 01 00 00 00
    // Total payload len: 1 * (22 + 8) = 30 (LE) = 1e 00 00 00
    // Object ID: 32 bytes of 0x11
    // Symbol size: 8 (LE) = 08 00
    // Zone key ID: 8 bytes of 0x22
    // Zone ID hash: 32 bytes of 0x33
    // Epoch ID: 1000 (LE) = e8 03 00 00 00 00 00 00
    // Sender instance ID: 0xDEADBEEF (LE) = ef be ad de 00 00 00 00
    // Frame seq: 1 (LE) = 01 00 00 00 00 00 00 00

    let expected_header = concat!(
        "46435053",                                                         // Magic "FCPS"
        "0100",                                                             // Version 1
        "0404",     // Flags: ENCRYPTED | RAPTORQ
        "01000000", // Symbol count: 1
        "1e000000", // Total payload len: 30
        "1111111111111111111111111111111111111111111111111111111111111111", // Object ID
        "0800",     // Symbol size: 8
        "2222222222222222", // Zone key ID
        "3333333333333333333333333333333333333333333333333333333333333333", // Zone ID hash
        "e803000000000000", // Epoch ID: 1000
        "efbeadde00000000", // Sender instance ID: 0xDEADBEEF
        "0100000000000000"  // Frame seq: 1
    );

    // Symbol record:
    // ESI: 0 (LE) = 00 00 00 00
    // K: 10 (LE) = 0a 00
    // Data: 8 bytes of 0xAA
    // Auth tag: 16 bytes of 0xBB
    let expected_symbol = concat!(
        "00000000",                         // ESI: 0
        "0a00",                             // K: 10
        "aaaaaaaaaaaaaaaa",                 // Data: 8 bytes
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  // Auth tag: 16 bytes
    );

    let expected_frame = format!("{expected_header}{expected_symbol}");

    FcpsGoldenVector {
        description: "Minimal FCPS frame with one 8-byte symbol".to_string(),
        version: 1,
        flags: 0x0404, // ENCRYPTED | RAPTORQ
        object_id: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        symbol_size: 8,
        zone_key_id: "2222222222222222".to_string(),
        zone_id_hash: "3333333333333333333333333333333333333333333333333333333333333333"
            .to_string(),
        epoch_id: 1000,
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 1,
        symbols: vec![SymbolRecordVector {
            esi: 0,
            k: 10,
            data: "aaaaaaaaaaaaaaaa".to_string(),
            auth_tag: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            expected_encoded: expected_symbol.to_string(),
        }],
        expected_header: expected_header.to_string(),
        expected_frame,
    }
}

/// Vector 2: FCPS frame with two symbols.
///
/// Tests multi-symbol encoding with different ESI values.
fn vector_2_two_symbols() -> FcpsGoldenVector {
    // Header with 2 symbols, 16-byte symbol size
    // Total payload len: 2 * (22 + 16) = 76 = 0x4c
    let expected_header = concat!(
        "46435053",                                                         // Magic "FCPS"
        "0100",                                                             // Version 1
        "0404",     // Flags: ENCRYPTED | RAPTORQ
        "02000000", // Symbol count: 2
        "4c000000", // Total payload len: 76
        "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe", // Object ID
        "1000",     // Symbol size: 16
        "0102030405060708", // Zone key ID
        "abababababababababababababababababababababababababababababababab", // Zone ID hash
        "0a00000000000000", // Epoch ID: 10
        "0100000000000000", // Sender instance ID: 1
        "6400000000000000"  // Frame seq: 100
    );

    // Symbol 1: ESI=0, K=100
    let expected_symbol_1 = concat!(
        "00000000",                         // ESI: 0
        "6400",                             // K: 100
        "00112233445566778899aabbccddeeff", // Data: 16 bytes
        "ffeeddccbbaa99887766554433221100"  // Auth tag
    );

    // Symbol 2: ESI=1, K=100
    let expected_symbol_2 = concat!(
        "01000000",                         // ESI: 1
        "6400",                             // K: 100
        "11111111111111111111111111111111", // Data: 16 bytes
        "22222222222222222222222222222222"  // Auth tag
    );

    let expected_frame = format!("{expected_header}{expected_symbol_1}{expected_symbol_2}");

    FcpsGoldenVector {
        description: "FCPS frame with two 16-byte symbols".to_string(),
        version: 1,
        flags: 0x0404,
        object_id: "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".to_string(),
        symbol_size: 16,
        zone_key_id: "0102030405060708".to_string(),
        zone_id_hash: "abababababababababababababababababababababababababababababababab"
            .to_string(),
        epoch_id: 10,
        sender_instance_id: 1,
        frame_seq: 100,
        symbols: vec![
            SymbolRecordVector {
                esi: 0,
                k: 100,
                data: "00112233445566778899aabbccddeeff".to_string(),
                auth_tag: "ffeeddccbbaa99887766554433221100".to_string(),
                expected_encoded: expected_symbol_1.to_string(),
            },
            SymbolRecordVector {
                esi: 1,
                k: 100,
                data: "11111111111111111111111111111111".to_string(),
                auth_tag: "22222222222222222222222222222222".to_string(),
                expected_encoded: expected_symbol_2.to_string(),
            },
        ],
        expected_header: expected_header.to_string(),
        expected_frame,
    }
}

/// Vector 3: FCPS frame with various flags.
///
/// Tests different flag combinations (compressed, priority, streaming).
fn vector_3_flags_variation() -> FcpsGoldenVector {
    // Flags: ENCRYPTED | COMPRESSED | PRIORITY | STREAMING = 0x0404 | 0x0002 | 0x0200 | 0x0020
    // = 0x0626
    let flags: u16 = 0x0004 | 0x0002 | 0x0200 | 0x0020 | 0x0400; // = 0x0626

    // Header with 1 symbol, 4-byte symbol size
    // Total payload len: 1 * (22 + 4) = 26 = 0x1a
    let expected_header = concat!(
        "46435053",                                                         // Magic "FCPS"
        "0100",                                                             // Version 1
        "2606",                                                             // Flags: 0x0626
        "01000000",                                                         // Symbol count: 1
        "1a000000",                                                         // Total payload len: 26
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // Object ID (all 0xff)
        "0400",                                                             // Symbol size: 4
        "ffffffffffffffff", // Zone key ID (all 0xff)
        "0000000000000000000000000000000000000000000000000000000000000000", // Zone ID hash (all 0)
        "ffffffffffffffff", // Epoch ID: max u64
        "ffffffffffffffff", // Sender instance ID: max u64
        "0000000000000000"  // Frame seq: 0
    );

    let expected_symbol = concat!(
        "ffffffff",                         // ESI: max u32
        "ffff",                             // K: max u16
        "cafebabe",                         // Data: 4 bytes
        "00000000000000000000000000000000"  // Auth tag: all zeros
    );

    let expected_frame = format!("{expected_header}{expected_symbol}");

    FcpsGoldenVector {
        description: "FCPS frame with multiple flags and edge-case values".to_string(),
        version: 1,
        flags,
        object_id: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        symbol_size: 4,
        zone_key_id: "ffffffffffffffff".to_string(),
        zone_id_hash: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        epoch_id: u64::MAX,
        sender_instance_id: u64::MAX,
        frame_seq: 0,
        symbols: vec![SymbolRecordVector {
            esi: u32::MAX,
            k: u16::MAX,
            data: "cafebabe".to_string(),
            auth_tag: "00000000000000000000000000000000".to_string(),
            expected_encoded: expected_symbol.to_string(),
        }],
        expected_header: expected_header.to_string(),
        expected_frame,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vectors_parseable() {
        let vectors = FcpsGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 FCPS golden vectors");
    }

    #[test]
    fn all_vectors_verify() {
        let vectors = FcpsGoldenVector::load_all();
        for (i, v) in vectors.iter().enumerate() {
            v.verify()
                .unwrap_or_else(|e| panic!("vector {i} ({}) failed: {e}", v.description));
        }
    }

    #[test]
    fn vector_1_verification() {
        vector_1_minimal_frame()
            .verify()
            .expect("vector 1 should verify");
    }

    #[test]
    fn vector_2_verification() {
        vector_2_two_symbols()
            .verify()
            .expect("vector 2 should verify");
    }

    #[test]
    fn vector_3_verification() {
        vector_3_flags_variation()
            .verify()
            .expect("vector 3 should verify");
    }

    #[test]
    fn frame_decode_round_trip() {
        use fcp_protocol::FcpsFrame;

        for v in FcpsGoldenVector::load_all() {
            let frame_bytes = hex::decode(&v.expected_frame).expect("valid hex");
            let decoded = FcpsFrame::decode(&frame_bytes, frame_bytes.len() + 1)
                .expect("decode should succeed");
            let re_encoded = decoded.encode();
            assert_eq!(
                frame_bytes, re_encoded,
                "round-trip failed for: {}",
                v.description
            );
        }
    }

    #[test]
    fn header_field_positions() {
        // Verify specific byte positions match the spec
        let v = vector_1_minimal_frame();
        let header_bytes = hex::decode(&v.expected_header).expect("valid hex");

        // Magic at 0-3
        assert_eq!(&header_bytes[0..4], b"FCPS");

        // Version at 4-5
        assert_eq!(u16::from_le_bytes([header_bytes[4], header_bytes[5]]), 1);

        // Flags at 6-7
        assert_eq!(
            u16::from_le_bytes([header_bytes[6], header_bytes[7]]),
            0x0404
        );

        // Symbol count at 8-11
        assert_eq!(
            u32::from_le_bytes(header_bytes[8..12].try_into().unwrap()),
            1
        );

        // Total payload len at 12-15
        assert_eq!(
            u32::from_le_bytes(header_bytes[12..16].try_into().unwrap()),
            30 // 22 + 8
        );

        // Object ID at 16-47
        assert!(header_bytes[16..48].iter().all(|&b| b == 0x11));

        // Symbol size at 48-49
        assert_eq!(u16::from_le_bytes([header_bytes[48], header_bytes[49]]), 8);

        // Zone key ID at 50-57
        assert!(header_bytes[50..58].iter().all(|&b| b == 0x22));

        // Zone ID hash at 58-89
        assert!(header_bytes[58..90].iter().all(|&b| b == 0x33));

        // Epoch ID at 90-97
        assert_eq!(
            u64::from_le_bytes(header_bytes[90..98].try_into().unwrap()),
            1000
        );

        // Sender instance ID at 98-105
        assert_eq!(
            u64::from_le_bytes(header_bytes[98..106].try_into().unwrap()),
            0xDEAD_BEEF
        );

        // Frame seq at 106-113
        assert_eq!(
            u64::from_le_bytes(header_bytes[106..114].try_into().unwrap()),
            1
        );
    }
}
