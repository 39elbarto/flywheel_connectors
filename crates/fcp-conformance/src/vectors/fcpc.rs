//! FCPC (control-plane) golden vectors.
//!
//! These vectors test the FCPC frame encoding/decoding for control-plane messages.
//!
//! # Wire Format (NORMATIVE)
//!
//! ```text
//! FCPC FRAME FORMAT (Control-Plane)
//!
//!   Bytes 0-3:    Magic (0x46 0x43 0x50 0x43 = "FCPC")
//!   Bytes 4-5:    Version (u16 LE)
//!   Bytes 6-21:   Session ID (16 bytes)
//!   Bytes 22-29:  Sequence number (u64 LE)
//!   Bytes 30-31:  Flags (u16 LE)
//!   Bytes 32-35:  Ciphertext length (u32 LE, excludes tag)
//!   Bytes 36+:    Ciphertext (variable)
//!   Last 16:      AEAD authentication tag
//!
//!   Fixed header: 36 bytes
//!   AEAD tag: 16 bytes
//! ```
//!
//! # AEAD Construction
//!
//! - Algorithm: ChaCha20-Poly1305
//! - Key: `k_ctx` (32 bytes, derived from session handshake)
//! - Nonce: Built from `seq` (8 bytes) + direction byte (0=i2r, 1=r2i) + padding
//! - AAD: `session_id` (16 bytes) || `seq` (8 bytes LE) || `flags` (2 bytes LE)

use serde::{Deserialize, Serialize};

/// Golden vector for FCPC frame encoding/decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcpcGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Session ID bytes (16 bytes hex).
    pub session_id: String,
    /// Encryption key `k_ctx` (32 bytes hex).
    pub key: String,
    /// Sequence number.
    pub seq: u64,
    /// Frame flags (bit field).
    pub flags: u16,
    /// Direction: "i2r" (initiator to responder) or "r2i" (responder to initiator).
    pub direction: String,
    /// Plaintext payload (hex).
    pub plaintext: String,
    /// Expected encoded header (36 bytes hex).
    pub expected_header: String,
    /// Expected ciphertext (hex, excludes tag).
    pub expected_ciphertext: String,
    /// Expected authentication tag (16 bytes hex).
    pub expected_tag: String,
    /// Expected complete frame (hex).
    pub expected_frame: String,
}

impl FcpcGoldenVector {
    /// Load all FCPC golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            vector_1_minimal_frame(),
            vector_2_responder_direction(),
            vector_3_compressed_flag(),
        ]
    }

    /// Verify this golden vector against the implementation.
    ///
    /// # Errors
    /// Returns an error description if verification fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_protocol::{FcpcFrame, FcpcFrameFlags};
        use fcp_protocol::{MeshSessionId, SessionDirection};

        // Parse expected values
        let session_bytes: [u8; 16] = hex::decode(&self.session_id)
            .map_err(|e| format!("invalid session_id hex: {e}"))?
            .try_into()
            .map_err(|_| "session_id must be 16 bytes")?;
        let session_id = MeshSessionId(session_bytes);

        let key: [u8; 32] = hex::decode(&self.key)
            .map_err(|e| format!("invalid key hex: {e}"))?
            .try_into()
            .map_err(|_| "key must be 32 bytes")?;

        let direction = match self.direction.as_str() {
            "i2r" => SessionDirection::InitiatorToResponder,
            "r2i" => SessionDirection::ResponderToInitiator,
            other => return Err(format!("invalid direction: {other}")),
        };

        let plaintext =
            hex::decode(&self.plaintext).map_err(|e| format!("invalid plaintext hex: {e}"))?;

        let flags = FcpcFrameFlags::from_bits_truncate(self.flags);

        // Create frame using implementation
        let frame = FcpcFrame::seal(session_id, self.seq, direction, flags, &plaintext, &key)
            .map_err(|e| format!("seal failed: {e}"))?;

        // Verify header encoding
        let encoded_header = frame.header.encode();
        let expected_header_bytes = hex::decode(&self.expected_header)
            .map_err(|e| format!("invalid expected_header hex: {e}"))?;
        if encoded_header.as_slice() != expected_header_bytes.as_slice() {
            return Err(format!(
                "header mismatch:\n  expected: {}\n  actual:   {}",
                self.expected_header,
                hex::encode(encoded_header)
            ));
        }

        // Verify complete frame
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
        let decoded =
            FcpcFrame::decode(&encoded_frame).map_err(|e| format!("decode failed: {e}"))?;

        // Verify decryption
        let decrypted = decoded
            .open(direction, &key)
            .map_err(|e| format!("open failed: {e}"))?;
        if decrypted != plaintext {
            return Err(format!(
                "decryption mismatch:\n  expected: {}\n  actual:   {}",
                self.plaintext,
                hex::encode(&decrypted)
            ));
        }

        Ok(())
        vec![
            vector_1_minimal_frame(),
            vector_2_responder_direction(),
            vector_3_compressed_flag(),
        ]
    }

    /// Verify this golden vector against the implementation.
    ///
    /// # Errors
    /// Returns an error description if verification fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_protocol::{FcpcFrame, FcpcFrameFlags};
        use fcp_protocol::{MeshSessionId, SessionDirection};

        // Parse expected values
        let session_bytes: [u8; 16] = hex::decode(&self.session_id)
            .map_err(|e| format!("invalid session_id hex: {e}"))?
            .try_into()
            .map_err(|_| "session_id must be 16 bytes")?;
        let session_id = MeshSessionId(session_bytes);

        let key: [u8; 32] = hex::decode(&self.key)
            .map_err(|e| format!("invalid key hex: {e}"))?
            .try_into()
            .map_err(|_| "key must be 32 bytes")?;

        let direction = match self.direction.as_str() {
            "i2r" => SessionDirection::InitiatorToResponder,
            "r2i" => SessionDirection::ResponderToInitiator,
            other => return Err(format!("invalid direction: {other}")),
        };

        let plaintext =
            hex::decode(&self.plaintext).map_err(|e| format!("invalid plaintext hex: {e}"))?;

        let flags = FcpcFrameFlags::from_bits_truncate(self.flags);

        // Create frame using implementation
        let frame = FcpcFrame::seal(session_id, self.seq, direction, flags, &plaintext, &key)
            .map_err(|e| format!("seal failed: {e}"))?;

        // Verify header encoding
        let encoded_header = frame.header.encode();
        let expected_header_bytes = hex::decode(&self.expected_header)
            .map_err(|e| format!("invalid expected_header hex: {e}"))?;
        if encoded_header.as_slice() != expected_header_bytes.as_slice() {
            return Err(format!(
                "header mismatch:\n  expected: {}\n  actual:   {}",
                self.expected_header,
                hex::encode(encoded_header)
            ));
        }

        // Verify complete frame
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
        let decoded =
            FcpcFrame::decode(&encoded_frame).map_err(|e| format!("decode failed: {e}"))?;

        // Verify decryption
        let decrypted = decoded
            .open(direction, &key)
            .map_err(|e| format!("open failed: {e}"))?;
        if decrypted != plaintext {
            return Err(format!(
                "decryption mismatch:\n  expected: {}\n  actual:   {}",
                self.plaintext,
                hex::encode(&decrypted)
            ));
        }

        Ok(())
    }
}

/// Vector 1: Minimal FCPC frame with short payload.
///
/// Tests basic header and AEAD encryption with minimal data.
fn vector_1_minimal_frame() -> FcpcGoldenVector {
    // Header layout (36 bytes):
    // Bytes 0-3:   Magic "FCPC" = 46 43 50 43
    // Bytes 4-5:   Version 1 (LE) = 01 00
    // Bytes 6-21:  Session ID = 16 bytes of 0xAA
    // Bytes 22-29: Seq 1 (LE) = 01 00 00 00 00 00 00 00
    // Bytes 30-31: Flags 0x0001 (ENCRYPTED) = 01 00
    // Bytes 32-35: Length (ciphertext len, set after encryption)

    // Note: Expected values computed from implementation with deterministic inputs.
    // The ciphertext and tag depend on ChaCha20-Poly1305 with:
    // - Key: 32 bytes of 0x11
    // - Nonce: from seq=1, direction=i2r (0)
    // - AAD: session_id || seq || flags

    FcpcGoldenVector {
        description: "Minimal FCPC frame with 4-byte payload, initiator to responder".to_string(),
        session_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        key: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        seq: 1,
        flags: 0x0001, // ENCRYPTED
        direction: "i2r".to_string(),
        plaintext: "deadbeef".to_string(), // 4 bytes
        expected_header: "464350430100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0100000000000000010004000000".to_string(),
        expected_ciphertext: "0f893f59".to_string(),
        expected_tag: "a75b895a58a90ec5cae3ca5056ebb48a".to_string(),
        expected_frame: "464350430100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01000000000000000100040000000f893f59a75b895a58a90ec5cae3ca5056ebb48a".to_string(),
    }
}

/// Vector 2: FCPC frame in responder-to-initiator direction.
///
/// Tests that direction affects nonce construction.
fn vector_2_responder_direction() -> FcpcGoldenVector {
    FcpcGoldenVector {
        description: "FCPC frame with responder to initiator direction".to_string(),
        session_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        key: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        seq: 100,
        flags: 0x0001, // ENCRYPTED
        direction: "r2i".to_string(),
        plaintext: "48656c6c6f20576f726c6421".to_string(), // "Hello World!" in hex
        expected_header: "464350430100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb640000000000000001000c000000".to_string(),
        expected_ciphertext: "18a2b77901d32d3b640b088c".to_string(),
        expected_tag: "2767c21c5701f91d64698cdb272aa743".to_string(),
        expected_frame: "464350430100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb640000000000000001000c00000018a2b77901d32d3b640b088c2767c21c5701f91d64698cdb272aa743".to_string(),
    }
}

/// Vector 3: FCPC frame with COMPRESSED flag set.
///
/// Tests flag encoding (compression is reserved but flag should encode correctly).
fn vector_3_compressed_flag() -> FcpcGoldenVector {
    FcpcGoldenVector {
        description: "FCPC frame with ENCRYPTED | COMPRESSED flags".to_string(),
        session_id: "0102030405060708090a0b0c0d0e0f10".to_string(),
        key: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe".to_string(),
        seq: 42,
        flags: 0x0003, // ENCRYPTED | COMPRESSED
        direction: "i2r".to_string(),
        plaintext: "00".to_string(), // 1 byte
        expected_header: "4643504301000102030405060708090a0b0c0d0e0f102a00000000000000030001000000".to_string(),
        expected_ciphertext: "d8".to_string(),
        expected_tag: "c456396da873826e2f0dff06dfce284f".to_string(),
        expected_frame: "4643504301000102030405060708090a0b0c0d0e0f102a00000000000000030001000000d8c456396da873826e2f0dff06dfce284f".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_protocol::{FCPC_HEADER_LEN, FCPC_TAG_LEN, FcpcFrame, FcpcFrameFlags};
    use fcp_protocol::{MeshSessionId, SessionDirection};

    #[test]
    fn golden_vectors_parseable() {
        let vectors = FcpcGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 FCPC golden vectors");
    }

    #[test]
    fn generate_fcpc_golden_values() {
        println!("\n=== FCPC Golden Vector Values ===\n");

        for (i, v) in FcpcGoldenVector::load_all().iter().enumerate() {
            println!("Vector {}: {}", i + 1, v.description);

            let session_bytes: [u8; 16] = hex::decode(&v.session_id)
                .expect("valid hex")
                .try_into()
                .expect("16 bytes");
            let session_id = MeshSessionId(session_bytes);

            let key: [u8; 32] = hex::decode(&v.key)
                .expect("valid hex")
                .try_into()
                .expect("32 bytes");

            let direction = match v.direction.as_str() {
                "i2r" => SessionDirection::InitiatorToResponder,
                "r2i" => SessionDirection::ResponderToInitiator,
                _ => panic!("invalid direction"),
            };

            let plaintext = hex::decode(&v.plaintext).expect("valid hex");
            let flags = FcpcFrameFlags::from_bits_truncate(v.flags);

            let frame = FcpcFrame::seal(session_id, v.seq, direction, flags, &plaintext, &key)
                .expect("seal should succeed");

            let encoded = frame.encode();
            let header_hex = hex::encode(&encoded[..FCPC_HEADER_LEN]);
            let ciphertext_hex =
                hex::encode(&encoded[FCPC_HEADER_LEN..encoded.len() - FCPC_TAG_LEN]);
            let tag_hex = hex::encode(&encoded[encoded.len() - FCPC_TAG_LEN..]);

            println!("  expected_header: \"{header_hex}\"");
            println!("  expected_ciphertext: \"{ciphertext_hex}\"");
            println!("  expected_tag: \"{tag_hex}\"");
            println!("  expected_frame: \"{}\"", hex::encode(&encoded));
            println!();
        }
    }

    #[test]
    fn header_field_positions() {
        let session_id = MeshSessionId([0xAA; 16]);
        let key = [0x11; 32];
        let flags = FcpcFrameFlags::ENCRYPTED;

        let frame = FcpcFrame::seal(
            session_id,
            1,
            SessionDirection::InitiatorToResponder,
            flags,
            b"test",
            &key,
        )
        .expect("seal should succeed");

        let header_bytes = frame.header.encode();

        assert_eq!(&header_bytes[0..4], b"FCPC");
        assert_eq!(u16::from_le_bytes([header_bytes[4], header_bytes[5]]), 1);
        assert!(header_bytes[6..22].iter().all(|&b| b == 0xAA));
        assert_eq!(
            u64::from_le_bytes(header_bytes[22..30].try_into().unwrap()),
            1
        );
        assert_eq!(
            u16::from_le_bytes([header_bytes[30], header_bytes[31]]),
            0x0001
        );
        assert_eq!(
            u32::from_le_bytes(header_bytes[32..36].try_into().unwrap()),
            4
        );
    }

    #[test]
    fn frame_decode_round_trip() {
        let session_id = MeshSessionId([0xBB; 16]);
        let key = [0x22; 32];
        let plaintext = b"round trip test payload";
        let direction = SessionDirection::InitiatorToResponder;

        let frame = FcpcFrame::seal(
            session_id,
            999,
            direction,
            FcpcFrameFlags::ENCRYPTED,
            plaintext,
            &key,
        )
        .expect("seal should succeed");

        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode should succeed");
        let opened = decoded.open(direction, &key).expect("open should succeed");

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn direction_affects_ciphertext() {
        let session_id = MeshSessionId([0xCC; 16]);
        let key = [0x33; 32];
        let plaintext = b"same plaintext";

        let frame_i2r = FcpcFrame::seal(
            session_id,
            1,
            SessionDirection::InitiatorToResponder,
            FcpcFrameFlags::ENCRYPTED,
            plaintext,
            &key,
        )
        .expect("seal should succeed");

        let frame_r2i = FcpcFrame::seal(
            session_id,
            1,
            SessionDirection::ResponderToInitiator,
            FcpcFrameFlags::ENCRYPTED,
            plaintext,
            &key,
        )
        .expect("seal should succeed");

        assert_ne!(
            frame_i2r.ciphertext, frame_r2i.ciphertext,
            "different directions should produce different ciphertext"
        );
    }
}
