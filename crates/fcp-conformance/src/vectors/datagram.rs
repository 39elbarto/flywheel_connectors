//! FCPS datagram envelope golden vectors.
//!
//! These vectors test the FCPS datagram encoding/decoding and MAC verification.
//!
//! # Wire Format (NORMATIVE)
//!
//! ```text
//! FCPS DATAGRAM ENVELOPE
//!
//!   Bytes 0-15:   Session ID (16 bytes)
//!   Bytes 16-23:  Sequence number (u64 LE)
//!   Bytes 24-39:  MAC (16 bytes, truncated HMAC-SHA256 or BLAKE3-keyed)
//!   Bytes 40+:    Frame bytes (variable, may be empty)
//!
//!   Fixed header: 40 bytes (FCPS_DATAGRAM_HEADER_LEN)
//!   Default max datagram: 1200 bytes (DEFAULT_MAX_DATAGRAM_BYTES)
//! ```
//!
//! # MAC Computation (NORMATIVE)
//!
//! ```text
//! mac_input = session_id || direction_byte || seq_le || frame_bytes
//!
//! Suite1: HMAC-SHA256(mac_key, mac_input)[0..16]
//! Suite2: BLAKE3_keyed(mac_key, mac_input)[0..16]
//! ```

use serde::{Deserialize, Serialize};

/// Golden vector for FCPS datagram envelope encoding/decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Session ID (16 bytes hex).
    pub session_id: String,
    /// Sequence number.
    pub seq: u64,
    /// MAC (16 bytes hex).
    pub mac: String,
    /// Frame payload bytes (hex, may be empty).
    pub frame_bytes: String,
    /// Expected full encoded datagram (hex).
    pub expected_encoded: String,
}

/// Golden vector for FCPS datagram MAC computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramMacGoldenVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Crypto suite name ("Suite1" for HMAC-SHA256, "Suite2" for BLAKE3-keyed).
    pub suite: String,
    /// MAC key (32 bytes hex).
    pub mac_key: String,
    /// Session ID (16 bytes hex).
    pub session_id: String,
    /// Direction: `InitiatorToResponder` (0x00) or `ResponderToInitiator` (0x01).
    pub direction: String,
    /// Sequence number.
    pub seq: u64,
    /// Frame payload bytes (hex).
    pub frame_bytes: String,
    /// Expected MAC (16 bytes hex).
    pub expected_mac: String,
}

/// Golden vector for datagram decode error cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatagramErrorVector {
    /// Human-readable description of the test case.
    pub description: String,
    /// Raw input bytes (hex).
    pub input_bytes: String,
    /// Max datagram limit to apply.
    pub max_datagram_bytes: u16,
    /// Expected error kind: `TooShort` or `TooLarge`.
    pub expected_error: String,
}

impl DatagramGoldenVector {
    /// Load all datagram encoding golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_minimal_empty_frame(),
            Self::vector_2_with_payload(),
            Self::vector_3_max_seq(),
        ]
    }

    /// Vector 1: Minimal datagram with empty frame (header-only).
    #[must_use]
    pub fn vector_1_minimal_empty_frame() -> Self {
        // session_id = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        //               0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        let session_id = "deadbeefcafebabe0123456789abcdef";
        let seq: u64 = 0;
        let mac = "00000000000000000000000000000000";
        let frame_bytes = "";

        // Expected encoding: session_id(16) || seq_le(8) || mac(16) = 40 bytes
        let mut expected = String::new();
        expected.push_str(session_id);
        expected.push_str(&hex::encode(seq.to_le_bytes()));
        expected.push_str(mac);

        Self {
            description: "Minimal datagram with empty frame (header-only, 40 bytes)".into(),
            session_id: session_id.into(),
            seq,
            mac: mac.into(),
            frame_bytes: frame_bytes.into(),
            expected_encoded: expected,
        }
    }

    /// Vector 2: Datagram with a small frame payload.
    #[must_use]
    pub fn vector_2_with_payload() -> Self {
        let session_id = "0102030405060708090a0b0c0d0e0f10";
        let seq: u64 = 42;
        let mac = "abababababababababababababababab";
        let frame_bytes = "48656c6c6f2c20464350532100"; // "Hello, FCPS!\0"

        let mut expected = String::new();
        expected.push_str(session_id);
        expected.push_str(&hex::encode(seq.to_le_bytes()));
        expected.push_str(mac);
        expected.push_str(frame_bytes);

        Self {
            description: "Datagram with 'Hello, FCPS!' payload (seq=42)".into(),
            session_id: session_id.into(),
            seq,
            mac: mac.into(),
            frame_bytes: frame_bytes.into(),
            expected_encoded: expected,
        }
    }

    /// Vector 3: Datagram with max sequence number.
    #[must_use]
    pub fn vector_3_max_seq() -> Self {
        let session_id = "ffffffffffffffffffffffffffffffff";
        let seq: u64 = u64::MAX;
        let mac = "0123456789abcdef0123456789abcdef";
        let frame_bytes = "deadbeef";

        let mut expected = String::new();
        expected.push_str(session_id);
        expected.push_str(&hex::encode(seq.to_le_bytes()));
        expected.push_str(mac);
        expected.push_str(frame_bytes);

        Self {
            description: "Datagram with max seq (u64::MAX) and small payload".into(),
            session_id: session_id.into(),
            seq,
            mac: mac.into(),
            frame_bytes: frame_bytes.into(),
            expected_encoded: expected,
        }
    }
}

impl DatagramMacGoldenVector {
    /// Load all datagram MAC golden vectors.
    ///
    /// # Panics
    ///
    /// Panics if hard-coded hex values fail to decode (indicates a bug in the vectors).
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        use fcp_protocol::{
            MeshSessionId, SessionCryptoSuite, SessionDirection, compute_session_mac,
        };

        let mac_key_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let mac_key_bytes = hex::decode(mac_key_hex).unwrap();
        let mac_key: [u8; 32] = mac_key_bytes.try_into().unwrap();

        let session_id_hex = "deadbeefcafebabe0123456789abcdef";
        let session_id_bytes: [u8; 16] = hex::decode(session_id_hex).unwrap().try_into().unwrap();
        let session_id = MeshSessionId(session_id_bytes);

        let frame_payload = b"test-frame-payload";

        // Suite1 / Initiator-to-Responder
        let mac_s1_i2r = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &mac_key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame_payload,
        )
        .unwrap();

        // Suite1 / Responder-to-Initiator
        let mac_s1_r2i = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &mac_key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            1,
            frame_payload,
        )
        .unwrap();

        // Suite2 / Initiator-to-Responder
        let mac_s2_i2r = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &mac_key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame_payload,
        )
        .unwrap();

        // Suite2 / Responder-to-Initiator (seq=1000)
        let mac_s2_r2i_1000 = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &mac_key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            1000,
            frame_payload,
        )
        .unwrap();

        vec![
            Self {
                description: "Suite1 HMAC-SHA256 MAC, initiator-to-responder, seq=1".into(),
                suite: "Suite1".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "InitiatorToResponder".into(),
                seq: 1,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s1_i2r),
            },
            Self {
                description: "Suite1 HMAC-SHA256 MAC, responder-to-initiator, seq=1".into(),
                suite: "Suite1".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "ResponderToInitiator".into(),
                seq: 1,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s1_r2i),
            },
            Self {
                description: "Suite2 BLAKE3-keyed MAC, initiator-to-responder, seq=1".into(),
                suite: "Suite2".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "InitiatorToResponder".into(),
                seq: 1,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s2_i2r),
            },
            Self {
                description: "Suite2 BLAKE3-keyed MAC, responder-to-initiator, seq=1000".into(),
                suite: "Suite2".into(),
                mac_key: mac_key_hex.into(),
                session_id: session_id_hex.into(),
                direction: "ResponderToInitiator".into(),
                seq: 1000,
                frame_bytes: hex::encode(frame_payload),
                expected_mac: hex::encode(mac_s2_r2i_1000),
            },
        ]
    }
}

impl DatagramErrorVector {
    /// Load all datagram error case vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self {
                description: "Empty input (0 bytes) rejected as too short".into(),
                input_bytes: String::new(),
                max_datagram_bytes: 1200,
                expected_error: "TooShort".into(),
            },
            Self {
                description: "39 bytes (one byte short of header) rejected".into(),
                input_bytes: hex::encode([0u8; 39]),
                max_datagram_bytes: 1200,
                expected_error: "TooShort".into(),
            },
            Self {
                description: "1201 bytes exceeds default 1200 limit".into(),
                input_bytes: hex::encode([0u8; 1201]),
                max_datagram_bytes: 1200,
                expected_error: "TooLarge".into(),
            },
            Self {
                description: "101 bytes exceeds custom 100-byte limit".into(),
                input_bytes: hex::encode([0u8; 101]),
                max_datagram_bytes: 100,
                expected_error: "TooLarge".into(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DatagramGoldenVector structural tests ───────────────────────────

    #[test]
    fn load_all_encoding_vectors_returns_three() {
        let vectors = DatagramGoldenVector::load_all();
        assert_eq!(vectors.len(), 3);
    }

    #[test]
    fn vector_1_has_correct_description() {
        let v = DatagramGoldenVector::vector_1_minimal_empty_frame();
        assert!(v.description.contains("empty frame"));
    }

    #[test]
    fn vector_1_empty_frame_header_40_bytes() {
        let v = DatagramGoldenVector::vector_1_minimal_empty_frame();
        let encoded = hex::decode(&v.expected_encoded).unwrap();
        // 16 (session_id) + 8 (seq) + 16 (mac) + 0 (frame) = 40
        assert_eq!(encoded.len(), 40);
    }

    #[test]
    fn vector_1_session_id_is_16_bytes() {
        let v = DatagramGoldenVector::vector_1_minimal_empty_frame();
        let sid = hex::decode(&v.session_id).unwrap();
        assert_eq!(sid.len(), 16);
    }

    #[test]
    fn vector_1_mac_is_16_bytes() {
        let v = DatagramGoldenVector::vector_1_minimal_empty_frame();
        let mac = hex::decode(&v.mac).unwrap();
        assert_eq!(mac.len(), 16);
    }

    #[test]
    fn vector_1_seq_is_zero() {
        let v = DatagramGoldenVector::vector_1_minimal_empty_frame();
        assert_eq!(v.seq, 0);
    }

    #[test]
    fn vector_1_frame_bytes_empty() {
        let v = DatagramGoldenVector::vector_1_minimal_empty_frame();
        assert!(v.frame_bytes.is_empty());
    }

    #[test]
    fn vector_2_has_payload() {
        let v = DatagramGoldenVector::vector_2_with_payload();
        assert!(!v.frame_bytes.is_empty());
        let frame = hex::decode(&v.frame_bytes).unwrap();
        assert!(!frame.is_empty());
    }

    #[test]
    fn vector_2_seq_is_42() {
        let v = DatagramGoldenVector::vector_2_with_payload();
        assert_eq!(v.seq, 42);
    }

    #[test]
    fn vector_2_encoded_length_includes_payload() {
        let v = DatagramGoldenVector::vector_2_with_payload();
        let encoded = hex::decode(&v.expected_encoded).unwrap();
        let frame = hex::decode(&v.frame_bytes).unwrap();
        assert_eq!(encoded.len(), 40 + frame.len());
    }

    #[test]
    fn vector_3_max_seq() {
        let v = DatagramGoldenVector::vector_3_max_seq();
        assert_eq!(v.seq, u64::MAX);
    }

    #[test]
    fn vector_3_has_payload() {
        let v = DatagramGoldenVector::vector_3_max_seq();
        let frame = hex::decode(&v.frame_bytes).unwrap();
        assert!(!frame.is_empty());
    }

    #[test]
    fn all_encoding_vectors_have_valid_hex() {
        for v in DatagramGoldenVector::load_all() {
            assert!(
                hex::decode(&v.session_id).is_ok(),
                "session_id: {}",
                v.description
            );
            assert!(hex::decode(&v.mac).is_ok(), "mac: {}", v.description);
            assert!(
                hex::decode(&v.expected_encoded).is_ok(),
                "encoded: {}",
                v.description
            );
            if !v.frame_bytes.is_empty() {
                assert!(
                    hex::decode(&v.frame_bytes).is_ok(),
                    "frame: {}",
                    v.description
                );
            }
        }
    }

    #[test]
    fn all_encoding_vectors_session_id_16_bytes() {
        for v in DatagramGoldenVector::load_all() {
            let sid = hex::decode(&v.session_id).unwrap();
            assert_eq!(sid.len(), 16, "session_id length: {}", v.description);
        }
    }

    #[test]
    fn all_encoding_vectors_mac_16_bytes() {
        for v in DatagramGoldenVector::load_all() {
            let mac = hex::decode(&v.mac).unwrap();
            assert_eq!(mac.len(), 16, "mac length: {}", v.description);
        }
    }

    #[test]
    fn all_encoding_vectors_structure_self_consistent() {
        for v in DatagramGoldenVector::load_all() {
            let encoded = hex::decode(&v.expected_encoded).unwrap();
            let sid = hex::decode(&v.session_id).unwrap();
            let mac = hex::decode(&v.mac).unwrap();
            let frame = if v.frame_bytes.is_empty() {
                vec![]
            } else {
                hex::decode(&v.frame_bytes).unwrap()
            };

            // Verify: session_id || seq_le || mac || frame
            assert_eq!(
                &encoded[..16],
                &sid[..],
                "session_id mismatch: {}",
                v.description
            );
            let seq_bytes = v.seq.to_le_bytes();
            assert_eq!(
                &encoded[16..24],
                &seq_bytes[..],
                "seq mismatch: {}",
                v.description
            );
            assert_eq!(
                &encoded[24..40],
                &mac[..],
                "mac mismatch: {}",
                v.description
            );
            assert_eq!(
                &encoded[40..],
                &frame[..],
                "frame mismatch: {}",
                v.description
            );
        }
    }

    #[test]
    fn encoding_vectors_serde_roundtrip() {
        for v in DatagramGoldenVector::load_all() {
            let json = serde_json::to_string(&v).unwrap();
            let back: DatagramGoldenVector = serde_json::from_str(&json).unwrap();
            assert_eq!(back.session_id, v.session_id);
            assert_eq!(back.seq, v.seq);
            assert_eq!(back.mac, v.mac);
            assert_eq!(back.frame_bytes, v.frame_bytes);
            assert_eq!(back.expected_encoded, v.expected_encoded);
        }
    }

    // ── DatagramMacGoldenVector tests ───────────────────────────────────

    #[test]
    fn load_all_mac_vectors_returns_four() {
        let vectors = DatagramMacGoldenVector::load_all();
        assert_eq!(vectors.len(), 4);
    }

    #[test]
    fn mac_vectors_have_valid_hex() {
        for v in DatagramMacGoldenVector::load_all() {
            assert!(
                hex::decode(&v.mac_key).is_ok(),
                "mac_key: {}",
                v.description
            );
            assert!(
                hex::decode(&v.session_id).is_ok(),
                "session_id: {}",
                v.description
            );
            assert!(
                hex::decode(&v.frame_bytes).is_ok(),
                "frame_bytes: {}",
                v.description
            );
            assert!(
                hex::decode(&v.expected_mac).is_ok(),
                "expected_mac: {}",
                v.description
            );
        }
    }

    #[test]
    fn mac_vectors_key_is_32_bytes() {
        for v in DatagramMacGoldenVector::load_all() {
            let key = hex::decode(&v.mac_key).unwrap();
            assert_eq!(key.len(), 32, "mac_key length: {}", v.description);
        }
    }

    #[test]
    fn mac_vectors_session_id_is_16_bytes() {
        for v in DatagramMacGoldenVector::load_all() {
            let sid = hex::decode(&v.session_id).unwrap();
            assert_eq!(sid.len(), 16, "session_id length: {}", v.description);
        }
    }

    #[test]
    fn mac_vectors_expected_mac_is_16_bytes() {
        for v in DatagramMacGoldenVector::load_all() {
            let mac = hex::decode(&v.expected_mac).unwrap();
            assert_eq!(mac.len(), 16, "expected_mac length: {}", v.description);
        }
    }

    #[test]
    fn mac_vectors_suite_is_valid() {
        for v in DatagramMacGoldenVector::load_all() {
            assert!(
                v.suite == "Suite1" || v.suite == "Suite2",
                "invalid suite '{}': {}",
                v.suite,
                v.description
            );
        }
    }

    #[test]
    fn mac_vectors_direction_is_valid() {
        for v in DatagramMacGoldenVector::load_all() {
            assert!(
                v.direction == "InitiatorToResponder" || v.direction == "ResponderToInitiator",
                "invalid direction '{}': {}",
                v.direction,
                v.description
            );
        }
    }

    #[test]
    fn mac_vectors_cover_both_suites() {
        let vectors = DatagramMacGoldenVector::load_all();
        let suites: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.suite.as_str()).collect();
        assert!(suites.contains("Suite1"));
        assert!(suites.contains("Suite2"));
    }

    #[test]
    fn mac_vectors_cover_both_directions() {
        let vectors = DatagramMacGoldenVector::load_all();
        let dirs: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.direction.as_str()).collect();
        assert!(dirs.contains("InitiatorToResponder"));
        assert!(dirs.contains("ResponderToInitiator"));
    }

    #[test]
    fn mac_vectors_different_directions_produce_different_macs() {
        let vectors = DatagramMacGoldenVector::load_all();
        // Suite1 has both directions with seq=1
        let suite1: Vec<_> = vectors.iter().filter(|v| v.suite == "Suite1").collect();
        if suite1.len() >= 2 {
            assert_ne!(suite1[0].expected_mac, suite1[1].expected_mac);
        }
    }

    #[test]
    fn mac_vectors_serde_roundtrip() {
        for v in DatagramMacGoldenVector::load_all() {
            let json = serde_json::to_string(&v).unwrap();
            let back: DatagramMacGoldenVector = serde_json::from_str(&json).unwrap();
            assert_eq!(back.expected_mac, v.expected_mac);
            assert_eq!(back.suite, v.suite);
            assert_eq!(back.direction, v.direction);
            assert_eq!(back.seq, v.seq);
        }
    }

    // ── DatagramErrorVector tests ───────────────────────────────────────

    #[test]
    fn load_all_error_vectors_returns_four() {
        let vectors = DatagramErrorVector::load_all();
        assert_eq!(vectors.len(), 4);
    }

    #[test]
    fn error_vectors_have_valid_hex() {
        for v in DatagramErrorVector::load_all() {
            if !v.input_bytes.is_empty() {
                assert!(
                    hex::decode(&v.input_bytes).is_ok(),
                    "input_bytes: {}",
                    v.description
                );
            }
        }
    }

    #[test]
    fn error_vectors_expected_error_is_valid() {
        for v in DatagramErrorVector::load_all() {
            assert!(
                v.expected_error == "TooShort" || v.expected_error == "TooLarge",
                "invalid error kind '{}': {}",
                v.expected_error,
                v.description
            );
        }
    }

    #[test]
    fn error_vectors_cover_both_error_types() {
        let vectors = DatagramErrorVector::load_all();
        let errors: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.expected_error.as_str()).collect();
        assert!(errors.contains("TooShort"));
        assert!(errors.contains("TooLarge"));
    }

    #[test]
    fn error_vectors_too_short_has_less_than_40_bytes() {
        for v in DatagramErrorVector::load_all() {
            if v.expected_error == "TooShort" {
                let bytes = hex::decode(&v.input_bytes).unwrap_or_default();
                assert!(
                    bytes.len() < 40,
                    "TooShort should have <40 bytes: {}",
                    v.description
                );
            }
        }
    }

    #[test]
    fn error_vectors_too_large_exceeds_limit() {
        for v in DatagramErrorVector::load_all() {
            if v.expected_error == "TooLarge" {
                let bytes = hex::decode(&v.input_bytes).unwrap();
                assert!(
                    bytes.len() > v.max_datagram_bytes as usize,
                    "TooLarge should exceed limit: {}",
                    v.description
                );
            }
        }
    }

    #[test]
    fn error_vectors_serde_roundtrip() {
        for v in DatagramErrorVector::load_all() {
            let json = serde_json::to_string(&v).unwrap();
            let back: DatagramErrorVector = serde_json::from_str(&json).unwrap();
            assert_eq!(back.expected_error, v.expected_error);
            assert_eq!(back.max_datagram_bytes, v.max_datagram_bytes);
            assert_eq!(back.input_bytes, v.input_bytes);
        }
    }

    #[test]
    fn encoding_vectors_unique_descriptions() {
        let vectors = DatagramGoldenVector::load_all();
        let descs: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.description.as_str()).collect();
        assert_eq!(descs.len(), vectors.len(), "descriptions should be unique");
    }

    #[test]
    fn mac_vectors_unique_descriptions() {
        let vectors = DatagramMacGoldenVector::load_all();
        let descs: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.description.as_str()).collect();
        assert_eq!(descs.len(), vectors.len(), "descriptions should be unique");
    }

    #[test]
    fn error_vectors_unique_descriptions() {
        let vectors = DatagramErrorVector::load_all();
        let descs: std::collections::HashSet<&str> =
            vectors.iter().map(|v| v.description.as_str()).collect();
        assert_eq!(descs.len(), vectors.len(), "descriptions should be unique");
    }
}
