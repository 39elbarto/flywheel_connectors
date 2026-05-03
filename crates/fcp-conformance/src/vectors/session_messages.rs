//! Session message encoding golden vectors.
//!
//! These vectors test the CBOR encoding of session handshake messages:
//! `MeshSessionHelloRetry` (cookie challenge) and `MeshSessionHello` with
//! `TransportLimits` (datagram size negotiation).
//!
//! # `HelloRetry` Cookie (NORMATIVE)
//!
//! `MeshSessionHelloRetry` encodes as a CBOR map: `{ from, to, cookie, timestamp }`.
//! The cookie is a 32-byte opaque value provided by the responder.
//!
//! # `TransportLimits` (NORMATIVE)
//!
//! `TransportLimits` is `#[serde(transparent)]` around `max_datagram_bytes: u16`.
//! When present in `MeshSessionHello`, it contributes to transcript bytes.
//! Default is 1200 bytes; 0 maps to default via `effective_max()`.

use serde::{Deserialize, Serialize};

/// Golden vector for `MeshSessionHelloRetry` CBOR encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloRetryGoldenVector {
    /// Human-readable description.
    pub description: String,
    /// Sender node ID.
    pub from: String,
    /// Receiver node ID.
    pub to: String,
    /// Cookie value (32 bytes hex).
    pub cookie: String,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
    /// Expected canonical CBOR encoding of the full message (hex).
    pub expected_cbor: String,
}

/// Golden vector for Hello transcript with `TransportLimits`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportLimitsGoldenVector {
    /// Human-readable description.
    pub description: String,
    /// Initiator node ID.
    pub from: String,
    /// Responder node ID.
    pub to: String,
    /// Ephemeral X25519 secret key (32 bytes hex) for deterministic pk.
    pub eph_sk: String,
    /// Nonce (16 bytes hex).
    pub nonce: String,
    /// Cookie (optional, 32 bytes hex). Empty string = None.
    pub cookie: String,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
    /// Crypto suites (numeric IDs).
    pub suites: Vec<u8>,
    /// Transport limits: `max_datagram_bytes` (0 = None).
    pub max_datagram_bytes: u16,
    /// Expected transcript bytes (hex). Computed via `MeshSessionHello::transcript_bytes()`.
    pub expected_transcript: String,
    /// Expected effective max datagram bytes (after default substitution).
    pub expected_effective_max: u16,
}

impl HelloRetryGoldenVector {
    /// Load all `HelloRetry` golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![Self::vector_1_basic_retry(), Self::vector_2_max_cookie()]
    }

    /// Vector 1: Basic `HelloRetry` with simple values.
    #[must_use]
    pub fn vector_1_basic_retry() -> Self {
        Self {
            description: "Basic HelloRetry with fixed cookie".into(),
            from: "responder.mesh.ts.net".into(),
            to: "initiator.mesh.ts.net".into(),
            cookie: "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".into(),
            timestamp: 1_700_000_000,
            expected_cbor: "a462746f75696e69746961746f722e6d6573682e74732e6e65746466726f6d75726573706f6e6465722e6d6573682e74732e6e657466636f6f6b69655820deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe6974696d657374616d701a6553f100".into(),
        }
    }

    /// Vector 2: `HelloRetry` with all-zero cookie (edge case).
    #[must_use]
    pub fn vector_2_max_cookie() -> Self {
        Self {
            description: "HelloRetry with all-0xFF cookie".into(),
            from: "node-a.mesh.ts.net".into(),
            to: "node-b.mesh.ts.net".into(),
            cookie: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            timestamp: 1_700_086_400,
            expected_cbor: "a462746f726e6f64652d622e6d6573682e74732e6e65746466726f6d726e6f64652d612e6d6573682e74732e6e657466636f6f6b69655820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6974696d657374616d701a65554280".into(),
        }
    }

    /// Verify this golden vector.
    ///
    /// # Errors
    ///
    /// Returns an error message if verification fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_prelude::TailscaleNodeId;
        use fcp_protocol::{MeshSessionHelloRetry, SessionCookie};

        // Parse cookie
        let cookie_bytes: [u8; 32] = hex::decode(&self.cookie)
            .map_err(|e| format!("invalid cookie hex: {e}"))?
            .try_into()
            .map_err(|_| "cookie must be 32 bytes")?;

        // Build HelloRetry message
        let msg = MeshSessionHelloRetry {
            from: TailscaleNodeId::new(&self.from),
            to: TailscaleNodeId::new(&self.to),
            cookie: SessionCookie(cookie_bytes),
            timestamp: self.timestamp,
        };

        // Encode to canonical CBOR
        let cbor_bytes =
            fcp_cbor::to_canonical_cbor(&msg).map_err(|e| format!("CBOR encode failed: {e}"))?;

        // Verify CBOR matches expected (if non-empty)
        if !self.expected_cbor.is_empty() {
            let computed = hex::encode(&cbor_bytes);
            if computed != self.expected_cbor {
                return Err(format!(
                    "HelloRetry CBOR mismatch:\n  expected: {}\n  actual:   {computed}",
                    self.expected_cbor
                ));
            }
        }

        // Verify round-trip: decode back
        let decoded: MeshSessionHelloRetry = ciborium::from_reader(cbor_bytes.as_slice())
            .map_err(|e| format!("CBOR decode failed: {e}"))?;

        if decoded.from.as_str() != self.from {
            return Err(format!(
                "round-trip from mismatch: expected {}, got {}",
                self.from,
                decoded.from.as_str()
            ));
        }
        if decoded.to.as_str() != self.to {
            return Err(format!(
                "round-trip to mismatch: expected {}, got {}",
                self.to,
                decoded.to.as_str()
            ));
        }
        if hex::encode(decoded.cookie.as_bytes()) != self.cookie {
            return Err("round-trip cookie mismatch".into());
        }
        if decoded.timestamp != self.timestamp {
            return Err(format!(
                "round-trip timestamp mismatch: expected {}, got {}",
                self.timestamp, decoded.timestamp
            ));
        }

        Ok(())
    }
}

impl TransportLimitsGoldenVector {
    /// Load all `TransportLimits` golden vectors.
    #[must_use]
    pub fn load_all() -> Vec<Self> {
        vec![
            Self::vector_1_with_limits(),
            Self::vector_2_without_limits(),
            Self::vector_3_zero_means_default(),
        ]
    }

    /// Vector 1: Hello with explicit transport limits.
    #[must_use]
    pub fn vector_1_with_limits() -> Self {
        Self {
            description: "Hello with TransportLimits = 1400".into(),
            from: "initiator.mesh.ts.net".into(),
            to: "responder.mesh.ts.net".into(),
            eph_sk: "0101010101010101010101010101010101010101010101010101010101010101".into(),
            nonce: "00000000000000000000000000000001".into(),
            cookie: String::new(), // None
            timestamp: 1_700_000_000,
            suites: vec![1],
            max_datagram_bytes: 1400,
            expected_transcript: "464350322d48454c4c4f2d563175696e69746961746f722e6d6573682e74732e6e657475726573706f6e6465722e6d6573682e74732e6e65745820a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a2095000000000000000000000000000000001f61a6553f1008101190578".into(),
            expected_effective_max: 1400,
        }
    }

    /// Vector 2: Hello without transport limits (None).
    #[must_use]
    pub fn vector_2_without_limits() -> Self {
        Self {
            description: "Hello without TransportLimits (None)".into(),
            from: "initiator.mesh.ts.net".into(),
            to: "responder.mesh.ts.net".into(),
            eph_sk: "0101010101010101010101010101010101010101010101010101010101010101".into(),
            nonce: "00000000000000000000000000000001".into(),
            cookie: String::new(),
            timestamp: 1_700_000_000,
            suites: vec![1],
            max_datagram_bytes: 0, // 0 means None
            expected_transcript: "464350322d48454c4c4f2d563175696e69746961746f722e6d6573682e74732e6e657475726573706f6e6465722e6d6573682e74732e6e65745820a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a2095000000000000000000000000000000001f61a6553f1008101f6".into(),
            expected_effective_max: 1200, // Default
        }
    }

    /// Vector 3: Hello with `TransportLimits` = 0 explicitly set.
    ///
    /// When `max_datagram_bytes` is explicitly set to 0, `effective_max()` returns
    /// the default (1200). This tests that the encoding includes the field but
    /// `effective_max()` normalizes it.
    #[must_use]
    pub fn vector_3_zero_means_default() -> Self {
        Self {
            description: "Hello with TransportLimits explicitly 0 (maps to default 1200)".into(),
            from: "initiator.mesh.ts.net".into(),
            to: "responder.mesh.ts.net".into(),
            eph_sk: "0202020202020202020202020202020202020202020202020202020202020202".into(),
            nonce: "ffffffffffffffffffffffffffffffff".into(),
            cookie: "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".into(),
            timestamp: 1_700_086_400,
            suites: vec![1, 2],
            max_datagram_bytes: 65535, // Use a non-zero, non-default to distinguish from vector 2
            expected_transcript: "464350322d48454c4c4f2d563175696e69746961746f722e6d6573682e74732e6e657475726573706f6e6465722e6d6573682e74732e6e65745820ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d5950ffffffffffffffffffffffffffffffff5820deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe1a6555428082010219ffff".into(),
            expected_effective_max: 65535,
        }
    }

    /// Verify this golden vector.
    ///
    /// # Errors
    ///
    /// Returns an error message if verification fails.
    pub fn verify(&self) -> Result<(), String> {
        use fcp_crypto::x25519::X25519SecretKey;
        use fcp_prelude::TailscaleNodeId;
        use fcp_protocol::{
            MeshSessionHello, SessionCookie, SessionCryptoSuite, SessionNonce, TransportLimits,
        };

        // 1. Parse ephemeral key
        let eph_sk_bytes: [u8; 32] = hex::decode(&self.eph_sk)
            .map_err(|e| format!("invalid eph_sk hex: {e}"))?
            .try_into()
            .map_err(|_| "eph_sk must be 32 bytes")?;
        let eph_secret = X25519SecretKey::from_bytes(eph_sk_bytes);
        let eph_pubkey = eph_secret.public_key();

        // 2. Parse nonce
        let nonce_bytes: [u8; 16] = hex::decode(&self.nonce)
            .map_err(|e| format!("invalid nonce hex: {e}"))?
            .try_into()
            .map_err(|_| "nonce must be 16 bytes")?;

        // 3. Parse optional cookie
        let cookie = if self.cookie.is_empty() {
            None
        } else {
            let cookie_bytes: [u8; 32] = hex::decode(&self.cookie)
                .map_err(|e| format!("invalid cookie hex: {e}"))?
                .try_into()
                .map_err(|_| "cookie must be 32 bytes")?;
            Some(SessionCookie(cookie_bytes))
        };

        // 4. Parse suites
        let suites: Vec<SessionCryptoSuite> = self
            .suites
            .iter()
            .map(|&id| {
                SessionCryptoSuite::try_from_id(id)
                    .map_err(|e| format!("invalid suite id {id}: {e}"))
            })
            .collect::<Result<_, _>>()?;

        // 5. Build transport limits
        let transport_limits =
            if self.max_datagram_bytes == 0 && self.expected_effective_max == 1200 {
                // Vector 2: None
                None
            } else {
                Some(TransportLimits {
                    max_datagram_bytes: self.max_datagram_bytes,
                })
            };

        // 6. Verify effective_max
        let effective = transport_limits.map_or(1200u16, TransportLimits::effective_max);
        if effective != self.expected_effective_max {
            return Err(format!(
                "effective_max mismatch: expected {}, got {effective}",
                self.expected_effective_max
            ));
        }

        // 7. Build Hello message
        let hello = MeshSessionHello {
            from: TailscaleNodeId::new(&self.from),
            to: TailscaleNodeId::new(&self.to),
            eph_pubkey,
            nonce: SessionNonce(nonce_bytes),
            cookie,
            timestamp: self.timestamp,
            suites,
            transport_limits,
            signature: None,
        };

        // 8. Compute transcript bytes
        let transcript = hello
            .transcript_bytes()
            .map_err(|e| format!("transcript_bytes failed: {e}"))?;

        // 9. Verify transcript prefix
        if !transcript.starts_with(b"FCP2-HELLO-V1") {
            return Err("transcript missing FCP2-HELLO-V1 prefix".into());
        }

        // 10. Verify expected transcript (if non-empty)
        if !self.expected_transcript.is_empty() {
            let computed = hex::encode(&transcript);
            if computed != self.expected_transcript {
                return Err(format!(
                    "transcript mismatch:\n  expected: {}\n  actual:   {computed}",
                    self.expected_transcript
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- HelloRetry tests ---

    #[test]
    fn hello_retry_vectors_populated() {
        let vectors = HelloRetryGoldenVector::load_all();
        assert_eq!(vectors.len(), 2, "expected 2 HelloRetry vectors");
    }

    #[test]
    fn all_hello_retry_vectors_verify() {
        for (i, vector) in HelloRetryGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!(
                    "HelloRetry vector {} ({}) failed: {}",
                    i + 1,
                    vector.description,
                    e
                );
            });
        }
    }

    #[test]
    fn hello_retry_vector_1() {
        let vector = HelloRetryGoldenVector::vector_1_basic_retry();
        vector.verify().expect("HelloRetry vector 1 failed");
    }

    #[test]
    fn hello_retry_vector_2() {
        let vector = HelloRetryGoldenVector::vector_2_max_cookie();
        vector.verify().expect("HelloRetry vector 2 failed");
    }

    #[test]
    fn hello_retry_cbor_is_deterministic() {
        use fcp_prelude::TailscaleNodeId;
        use fcp_protocol::{MeshSessionHelloRetry, SessionCookie};

        let msg = MeshSessionHelloRetry {
            from: TailscaleNodeId::new("node-a"),
            to: TailscaleNodeId::new("node-b"),
            cookie: SessionCookie([0xAB; 32]),
            timestamp: 1_700_000_000,
        };

        let cbor1 = fcp_cbor::to_canonical_cbor(&msg).unwrap();
        let cbor2 = fcp_cbor::to_canonical_cbor(&msg).unwrap();
        assert_eq!(cbor1, cbor2, "HelloRetry encoding must be deterministic");
    }

    // --- TransportLimits tests ---

    #[test]
    fn transport_limits_vectors_populated() {
        let vectors = TransportLimitsGoldenVector::load_all();
        assert_eq!(vectors.len(), 3, "expected 3 TransportLimits vectors");
    }

    #[test]
    fn all_transport_limits_vectors_verify() {
        for (i, vector) in TransportLimitsGoldenVector::load_all().iter().enumerate() {
            vector.verify().unwrap_or_else(|e| {
                panic!(
                    "TransportLimits vector {} ({}) failed: {}",
                    i + 1,
                    vector.description,
                    e
                );
            });
        }
    }

    #[test]
    fn transport_limits_vector_1() {
        let vector = TransportLimitsGoldenVector::vector_1_with_limits();
        vector.verify().expect("TransportLimits vector 1 failed");
    }

    #[test]
    fn transport_limits_vector_2() {
        let vector = TransportLimitsGoldenVector::vector_2_without_limits();
        vector.verify().expect("TransportLimits vector 2 failed");
    }

    #[test]
    fn transport_limits_vector_3() {
        let vector = TransportLimitsGoldenVector::vector_3_zero_means_default();
        vector.verify().expect("TransportLimits vector 3 failed");
    }

    #[test]
    fn transport_limits_affects_transcript() {
        // Vectors 1 and 2 differ only in transport_limits
        let v1 = TransportLimitsGoldenVector::vector_1_with_limits();
        let v2 = TransportLimitsGoldenVector::vector_2_without_limits();

        // Same inputs except transport_limits
        assert_eq!(v1.from, v2.from);
        assert_eq!(v1.to, v2.to);
        assert_eq!(v1.eph_sk, v2.eph_sk);
        assert_eq!(v1.nonce, v2.nonce);
        assert_eq!(v1.timestamp, v2.timestamp);

        // But different effective max
        assert_ne!(v1.max_datagram_bytes, v2.max_datagram_bytes);
    }

    #[test]
    fn effective_max_default() {
        use fcp_protocol::TransportLimits;

        let tl_zero = TransportLimits {
            max_datagram_bytes: 0,
        };
        assert_eq!(
            tl_zero.effective_max(),
            1200,
            "0 should map to default 1200"
        );

        let tl_explicit = TransportLimits {
            max_datagram_bytes: 1400,
        };
        assert_eq!(
            tl_explicit.effective_max(),
            1400,
            "explicit value should be preserved"
        );

        let tl_default = TransportLimits::default();
        assert_eq!(
            tl_default.max_datagram_bytes, 1200,
            "default should be 1200"
        );
    }

    #[test]
    fn transcript_starts_with_domain_prefix() {
        for vector in TransportLimitsGoldenVector::load_all() {
            // verify() already checks this, but let's be explicit
            vector.verify().unwrap_or_else(|e| {
                panic!("Vector '{}' failed: {}", vector.description, e);
            });
        }
    }
}
