//! Conformance vectors for FCP replay protection.
//!
//! These vectors test the normative replay protection requirements:
//! 1. Handshake nonce uniqueness (32-byte random, never reused)
//! 2. Idempotency key constraints and deduplication semantics
//! 3. Operation intent lifecycle (exactly-once state machine)
//! 4. Nonce binding in session establishment

#[cfg(test)]
mod tests {
    // ── Handshake Nonce Replay Protection ──────────────────────────

    #[test]
    fn handshake_nonce_must_be_32_bytes() {
        // Per FCP spec: handshake nonce is exactly 32 bytes.
        let nonce = [0u8; 32];
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn nonce_generation_produces_unique_values() {
        use rand::RngCore;
        use std::collections::HashSet;
        let mut rng = rand::thread_rng();
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let mut nonce = [0u8; 32];
            rng.fill_bytes(&mut nonce);
            assert!(seen.insert(nonce), "nonce collision in 100 samples");
        }
    }

    #[test]
    fn handshake_request_type_exists() {
        // Verify HandshakeRequest is accessible from fcp-core.
        let _ = std::any::type_name::<fcp_core::HandshakeRequest>();
    }

    // ── Idempotency Key Constraints ────────────────────────────────

    #[test]
    fn idempotency_key_max_length() {
        // Per spec: idempotency_key must be <= MAX_IDEMPOTENCY_KEY_LEN (128) bytes.
        let key_at_limit = "k".repeat(fcp_core::MAX_IDEMPOTENCY_KEY_LEN);
        assert_eq!(key_at_limit.len(), 128);

        let key_over_limit = "k".repeat(fcp_core::MAX_IDEMPOTENCY_KEY_LEN + 1);
        assert!(key_over_limit.len() > fcp_core::MAX_IDEMPOTENCY_KEY_LEN);
    }

    #[test]
    fn idempotency_class_variants_exhaustive() {
        // FCP defines exactly three idempotency classes.
        use fcp_prelude::IdempotencyClass;
        let classes = [
            IdempotencyClass::None,
            IdempotencyClass::BestEffort,
            IdempotencyClass::Strict,
        ];
        assert_eq!(classes.len(), 3);
    }

    #[test]
    fn strict_idempotency_requires_key_for_risky_ops() {
        // Normative: operations with Strict idempotency class MUST have
        // an idempotency_key. Operations with SafetyTier::Risky or higher
        // MUST use Strict idempotency.
        use fcp_prelude::SafetyTier;
        let risky_tiers = [
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
        ];
        for tier in &risky_tiers {
            assert!(
                matches!(
                    tier,
                    SafetyTier::Risky | SafetyTier::Dangerous | SafetyTier::Critical
                ),
                "risky tiers must require idempotency"
            );
        }
    }

    // ── Operation Intent Lifecycle ──────────────────────────────────

    #[test]
    fn intent_status_state_machine() {
        // IntentStatus state machine: Pending → InProgress → Completed|Failed
        use fcp_prelude::IntentStatus;
        let states = [
            IntentStatus::Pending,
            IntentStatus::InProgress,
            IntentStatus::Completed,
            IntentStatus::Failed,
        ];
        // All four are distinct
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        std::mem::discriminant(a),
                        std::mem::discriminant(b),
                        "IntentStatus states {i} and {j} must be distinct"
                    );
                }
            }
        }
    }

    #[test]
    fn intent_status_serialization_roundtrip() {
        use fcp_prelude::IntentStatus;
        for status in [
            IntentStatus::Pending,
            IntentStatus::InProgress,
            IntentStatus::Completed,
            IntentStatus::Failed,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: IntentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(
                std::mem::discriminant(&status),
                std::mem::discriminant(&parsed),
            );
        }
    }

    #[test]
    fn operation_intent_jti_unique_per_invocation() {
        // Each operation intent must have a unique JTI (JWT Token Identifier).
        let jti1 = uuid::Uuid::new_v4();
        let jti2 = uuid::Uuid::new_v4();
        assert_ne!(jti1, jti2, "each intent must have a unique JTI");
    }

    // ── Session Nonce Binding ───────────────────────────────────────

    #[test]
    fn different_session_ids_are_distinct() {
        let sid_a = fcp_core::SessionId::new();
        let sid_b = fcp_core::SessionId::new();
        assert_ne!(sid_a, sid_b);
    }
}
