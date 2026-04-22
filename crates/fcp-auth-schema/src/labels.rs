//! CBOR integer labels for capability-token claims.
//!
//! These constants are the wire-format contract. Their values MUST NOT
//! change without a schema-version bump (see `AuthClaims::schema_version`
//! and `docs/architecture/adr/8n0rm-claim-schema-versioning.md`).
//!
//! Sign conventions (asserted by tests in this crate and in
//! `fcp-crypto`):
//! - CWT standard claims are **positive** integers (IANA-registered).
//! - FCP2 claims are **negative** integers (CWT private-use range).

/// CWT-standard claim keys (IANA-registered positive integers).
pub mod cwt_claims {
    /// Issuer claim key.
    pub const ISS: i64 = 1;
    /// Subject claim key.
    pub const SUB: i64 = 2;
    /// Audience claim key.
    pub const AUD: i64 = 3;
    /// Expiration time claim key.
    pub const EXP: i64 = 4;
    /// Not before claim key.
    pub const NBF: i64 = 5;
    /// Issued at claim key.
    pub const IAT: i64 = 6;
    /// CWT ID (token identifier) claim key.
    pub const CTI: i64 = 7;
}

/// FCP2-specific claim keys (negative integers, CWT private-use range).
pub mod fcp2_claims {
    /// Capability ID claim.
    pub const CAPABILITY_ID: i64 = -65537;
    /// Zone ID claim.
    pub const ZONE_ID: i64 = -65538;
    /// Allowed operations claim (array of operation IDs).
    ///
    /// **Deprecated / legacy.** Not emitted by `AuthClaims`. Retained
    /// only so `fcp-core::CapabilityVerifier`'s legacy fallback branch
    /// can be removed in 8n0rm.6.
    pub const OPERATIONS: i64 = -65539;
    /// Principal ID claim.
    pub const PRINCIPAL_ID: i64 = -65540;
    /// Delegation depth claim.
    pub const DELEGATION_DEPTH: i64 = -65541;
    /// Parent token ID claim (for delegated tokens).
    pub const PARENT_TOKEN: i64 = -65542;
    /// Issuing node ID claim.
    pub const ISS_NODE: i64 = -65543;
    /// Binary audience (`ObjectId`) claim.
    pub const AUD_BINARY: i64 = -65544;
    /// Grant Object IDs claim.
    pub const GRANT_OBJECT_IDS: i64 = -65545;
    /// Holder node ID claim.
    pub const HOLDER_NODE: i64 = -65546;
    /// Checkpoint ID claim.
    pub const CHK_ID: i64 = -65547;
    /// Checkpoint sequence claim.
    pub const CHK_SEQ: i64 = -65548;
    /// Capability constraints claim (CBOR map).
    pub const CONSTRAINTS: i64 = -65549;
    /// Granted capabilities (CBOR array of `CapabilityGrant`).
    pub const GRANTS: i64 = -65550;
    /// Instance ID claim.
    pub const INSTANCE_ID: i64 = -65551;
    /// Schema version claim.
    ///
    /// Present on every `AuthClaims`. Verifiers reject tokens whose
    /// version is outside their accepted range. Added in 8n0rm.5.
    pub const SCHEMA_VERSION: i64 = -65552;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwt_claims_are_positive() {
        assert!(cwt_claims::ISS > 0);
        assert!(cwt_claims::SUB > 0);
        assert!(cwt_claims::AUD > 0);
        assert!(cwt_claims::EXP > 0);
        assert!(cwt_claims::NBF > 0);
        assert!(cwt_claims::IAT > 0);
        assert!(cwt_claims::CTI > 0);
    }

    #[test]
    fn fcp2_claims_are_negative() {
        assert!(fcp2_claims::CAPABILITY_ID < 0);
        assert!(fcp2_claims::ZONE_ID < 0);
        assert!(fcp2_claims::OPERATIONS < 0);
        assert!(fcp2_claims::PRINCIPAL_ID < 0);
        assert!(fcp2_claims::DELEGATION_DEPTH < 0);
        assert!(fcp2_claims::PARENT_TOKEN < 0);
        assert!(fcp2_claims::ISS_NODE < 0);
        assert!(fcp2_claims::AUD_BINARY < 0);
        assert!(fcp2_claims::GRANT_OBJECT_IDS < 0);
        assert!(fcp2_claims::HOLDER_NODE < 0);
        assert!(fcp2_claims::CHK_ID < 0);
        assert!(fcp2_claims::CHK_SEQ < 0);
        assert!(fcp2_claims::CONSTRAINTS < 0);
        assert!(fcp2_claims::GRANTS < 0);
        assert!(fcp2_claims::INSTANCE_ID < 0);
        assert!(fcp2_claims::SCHEMA_VERSION < 0);
    }

    #[test]
    fn fcp2_labels_are_unique() {
        let labels = [
            fcp2_claims::CAPABILITY_ID,
            fcp2_claims::ZONE_ID,
            fcp2_claims::OPERATIONS,
            fcp2_claims::PRINCIPAL_ID,
            fcp2_claims::DELEGATION_DEPTH,
            fcp2_claims::PARENT_TOKEN,
            fcp2_claims::ISS_NODE,
            fcp2_claims::AUD_BINARY,
            fcp2_claims::GRANT_OBJECT_IDS,
            fcp2_claims::HOLDER_NODE,
            fcp2_claims::CHK_ID,
            fcp2_claims::CHK_SEQ,
            fcp2_claims::CONSTRAINTS,
            fcp2_claims::GRANTS,
            fcp2_claims::INSTANCE_ID,
            fcp2_claims::SCHEMA_VERSION,
        ];
        // Brute-force uniqueness check — small N, O(N^2) is fine.
        for (i, &a) in labels.iter().enumerate() {
            for &b in &labels[i + 1..] {
                assert_ne!(a, b, "duplicate FCP2 label: {a}");
            }
        }
    }
}
