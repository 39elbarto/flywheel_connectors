//! Error types for FCP2 stores.

use fcp_prelude::{ObjectId, ZoneId};
use thiserror::Error;

/// Errors for object store operations.
#[derive(Debug, Error)]
pub enum ObjectStoreError {
    #[error("object not found: {0}")]
    NotFound(ObjectId),

    #[error("object already exists: {0}")]
    AlreadyExists(ObjectId),

    #[error("storage quota exceeded: {used} / {max} bytes")]
    QuotaExceeded { used: u64, max: u64 },

    #[error("invalid object: {reason}")]
    InvalidObject { reason: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(String),

    /// Claimed `object_id` does not match the id derived from `(header, body)`
    /// under the zone's `ObjectIdKey`. Surfaced by an installed
    /// [`crate::ObjectIdVerifier`] at put / WAL replay / snapshot load.
    /// This is the concrete defense against the attacker-chosen-id
    /// injection vector called out in bead flywheel_connectors-4g0qr.
    #[error("content-id mismatch: claimed {claimed}, computed {computed}")]
    ContentIdMismatch {
        claimed: ObjectId,
        computed: ObjectId,
    },

    /// The installed verifier has no `ObjectIdKey` registered for the
    /// zone carried in `object.header.zone_id`. A replay or put whose
    /// zone is unknown to the verifier MUST fail closed rather than
    /// silently accept — otherwise an attacker can pick any
    /// zone-id for which no key is registered and bypass verification.
    #[error("verifier has no ObjectIdKey for zone `{zone}`")]
    VerifierKeyMissing { zone: ZoneId },

    /// Durable WAL or snapshot envelope failed keyed-MAC authentication.
    /// Surfaced when the keyed BLAKE3 MAC over `(version, seq, op)` —
    /// equivalent to HMAC-SHA256 in cryptographic strength but native to
    /// the workspace — does not match the recorded MAC (V2 envelopes),
    /// or when a V1 unkeyed envelope is loaded while
    /// `allow_legacy_unauth = false`. Defends against an on-disk tamperer
    /// who could otherwise recompute the unkeyed checksum to forge
    /// `Delete` / `SetRetention` records or rewrite a snapshot to omit
    /// objects, even when an `ObjectIdVerifier` is installed
    /// (bead flywheel_connectors-dgbtx).
    #[error("tampered audit envelope at {path}: {reason}")]
    TamperedAuditEnvelope { path: String, reason: String },
}

/// Errors for symbol store operations.
#[derive(Debug, Error)]
pub enum SymbolStoreError {
    #[error("symbol not found: object={object_id}, esi={esi}")]
    NotFound { object_id: ObjectId, esi: u32 },

    #[error("object not found: {0}")]
    ObjectNotFound(ObjectId),

    #[error("storage quota exceeded: {used} / {max} bytes")]
    QuotaExceeded { used: u64, max: u64 },

    #[error("invalid symbol: {reason}")]
    InvalidSymbol { reason: String },

    #[error("I/O error: {0}")]
    Io(String),

    /// Durable symbol-store WAL or snapshot envelope failed keyed-MAC
    /// authentication. See [`ObjectStoreError::TamperedAuditEnvelope`]
    /// for the full threat model — symbol-store WAL `DeleteObject` /
    /// `DeleteSymbol` records pose the same forgery risk as object-store
    /// `Delete` / `SetRetention`, so the same V2-envelope MAC defence
    /// applies (bead flywheel_connectors-dgbtx).
    #[error("tampered audit envelope at {path}: {reason}")]
    TamperedAuditEnvelope { path: String, reason: String },
}

/// Errors for quarantine operations.
#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("quarantine quota exceeded for zone: {used} / {max} bytes")]
    QuotaExceeded { used: u64, max: u64 },

    #[error("object not in quarantine: {0}")]
    NotFound(ObjectId),

    #[error("promotion denied: {reason}")]
    PromotionDenied { reason: String },

    #[error("schema validation failed: {reason}")]
    SchemaValidationFailed { reason: String },
}

/// Errors for repair operations.
#[derive(Debug, Error)]
pub enum RepairError {
    #[error("repair rate limit exceeded")]
    RateLimitExceeded,

    #[error("insufficient coverage data")]
    InsufficientCoverage,

    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),

    #[error("symbol store error: {0}")]
    SymbolStore(#[from] SymbolStoreError),

    #[error("decode error: {0}")]
    Decode(String),
}

/// Errors for lifecycle snapshot collection.
#[derive(Debug, Error)]
pub enum LifecycleSnapshotError {
    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),

    #[error("symbol store error: {0}")]
    SymbolStore(#[from] SymbolStoreError),
}

/// Errors for garbage collection.
#[derive(Debug, Error)]
pub enum GcError {
    #[error("GC in progress")]
    InProgress,

    #[error("invalid root: {0}")]
    InvalidRoot(ObjectId),

    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),

    #[error("symbol store error: {0}")]
    SymbolStore(#[from] SymbolStoreError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id() -> ObjectId {
        ObjectId::from_bytes([1; 32])
    }

    // --- ObjectStoreError Display ---

    #[test]
    fn object_store_not_found_display() {
        let err = ObjectStoreError::NotFound(test_id());
        assert!(err.to_string().contains("object not found"));
    }

    #[test]
    fn object_store_already_exists_display() {
        let err = ObjectStoreError::AlreadyExists(test_id());
        assert!(err.to_string().contains("object already exists"));
    }

    #[test]
    fn object_store_quota_exceeded_display() {
        let err = ObjectStoreError::QuotaExceeded {
            used: 500,
            max: 1000,
        };
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("1000"));
        assert!(msg.contains("quota exceeded"));
    }

    #[test]
    fn object_store_invalid_object_display() {
        let err = ObjectStoreError::InvalidObject {
            reason: "bad schema".into(),
        };
        assert!(err.to_string().contains("bad schema"));
    }

    #[test]
    fn object_store_serialization_display() {
        let err = ObjectStoreError::Serialization("cbor fail".into());
        assert!(err.to_string().contains("cbor fail"));
    }

    #[test]
    fn object_store_io_display() {
        let err = ObjectStoreError::Io("disk full".into());
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn object_store_debug() {
        let err = ObjectStoreError::NotFound(test_id());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
    }

    // --- SymbolStoreError Display ---

    #[test]
    fn symbol_store_not_found_display() {
        let err = SymbolStoreError::NotFound {
            object_id: test_id(),
            esi: 42,
        };
        let msg = err.to_string();
        assert!(msg.contains("symbol not found"));
        assert!(msg.contains("esi=42"));
    }

    #[test]
    fn symbol_store_object_not_found_display() {
        let err = SymbolStoreError::ObjectNotFound(test_id());
        assert!(err.to_string().contains("object not found"));
    }

    #[test]
    fn symbol_store_quota_exceeded_display() {
        let err = SymbolStoreError::QuotaExceeded {
            used: 100,
            max: 200,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("200"));
    }

    #[test]
    fn symbol_store_invalid_symbol_display() {
        let err = SymbolStoreError::InvalidSymbol {
            reason: "wrong size".into(),
        };
        assert!(err.to_string().contains("wrong size"));
    }

    #[test]
    fn symbol_store_io_display() {
        let err = SymbolStoreError::Io("read fail".into());
        assert!(err.to_string().contains("read fail"));
    }

    // --- QuarantineError Display ---

    #[test]
    fn quarantine_quota_exceeded_display() {
        let err = QuarantineError::QuotaExceeded {
            used: 1024,
            max: 2048,
        };
        let msg = err.to_string();
        assert!(msg.contains("1024"));
        assert!(msg.contains("2048"));
    }

    #[test]
    fn quarantine_not_found_display() {
        let err = QuarantineError::NotFound(test_id());
        assert!(err.to_string().contains("not in quarantine"));
    }

    #[test]
    fn quarantine_promotion_denied_display() {
        let err = QuarantineError::PromotionDenied {
            reason: "no checkpoint".into(),
        };
        assert!(err.to_string().contains("no checkpoint"));
    }

    #[test]
    fn quarantine_schema_validation_failed_display() {
        let err = QuarantineError::SchemaValidationFailed {
            reason: "missing field".into(),
        };
        assert!(err.to_string().contains("missing field"));
    }

    // --- RepairError Display ---

    #[test]
    fn repair_rate_limit_exceeded_display() {
        let err = RepairError::RateLimitExceeded;
        assert!(err.to_string().contains("rate limit"));
    }

    #[test]
    fn repair_insufficient_coverage_display() {
        let err = RepairError::InsufficientCoverage;
        assert!(err.to_string().contains("insufficient coverage"));
    }

    #[test]
    fn repair_decode_display() {
        let err = RepairError::Decode("bad raptorq".into());
        assert!(err.to_string().contains("bad raptorq"));
    }

    #[test]
    fn repair_from_object_store_error() {
        let inner = ObjectStoreError::NotFound(test_id());
        let err: RepairError = inner.into();
        assert!(err.to_string().contains("object"));
    }

    #[test]
    fn repair_from_symbol_store_error() {
        let inner = SymbolStoreError::ObjectNotFound(test_id());
        let err: RepairError = inner.into();
        assert!(err.to_string().contains("symbol"));
    }

    // --- GcError Display ---

    #[test]
    fn gc_in_progress_display() {
        let err = GcError::InProgress;
        assert!(err.to_string().contains("in progress"));
    }

    #[test]
    fn gc_invalid_root_display() {
        let err = GcError::InvalidRoot(test_id());
        assert!(err.to_string().contains("invalid root"));
    }

    #[test]
    fn gc_from_object_store_error() {
        let inner = ObjectStoreError::NotFound(test_id());
        let err: GcError = inner.into();
        assert!(err.to_string().contains("object"));
    }

    #[test]
    fn gc_from_symbol_store_error() {
        let inner = SymbolStoreError::ObjectNotFound(test_id());
        let err: GcError = inner.into();
        assert!(err.to_string().contains("symbol"));
    }

    // --- std::error::Error trait ---

    #[test]
    fn object_store_error_is_std_error() {
        let err = ObjectStoreError::NotFound(test_id());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn symbol_store_error_is_std_error() {
        let err = SymbolStoreError::ObjectNotFound(test_id());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn quarantine_error_is_std_error() {
        let err = QuarantineError::NotFound(test_id());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn repair_error_is_std_error() {
        let err = RepairError::RateLimitExceeded;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn gc_error_is_std_error() {
        let err = GcError::InProgress;
        let _: &dyn std::error::Error = &err;
    }

    // --- RepairError source chain ---

    #[test]
    fn repair_error_source_from_object_store() {
        use std::error::Error;
        let inner = ObjectStoreError::NotFound(test_id());
        let err: RepairError = inner.into();
        assert!(err.source().is_some());
    }

    #[test]
    fn repair_error_source_from_symbol_store() {
        use std::error::Error;
        let inner = SymbolStoreError::ObjectNotFound(test_id());
        let err: RepairError = inner.into();
        assert!(err.source().is_some());
    }

    #[test]
    fn repair_error_no_source_for_rate_limit() {
        use std::error::Error;
        let err = RepairError::RateLimitExceeded;
        assert!(err.source().is_none());
    }

    #[test]
    fn gc_error_source_from_object_store() {
        use std::error::Error;
        let inner = ObjectStoreError::NotFound(test_id());
        let err: GcError = inner.into();
        assert!(err.source().is_some());
    }

    // --- Additional debug format tests ---

    #[test]
    fn object_store_already_exists_debug() {
        let err = ObjectStoreError::AlreadyExists(test_id());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("AlreadyExists"));
    }

    #[test]
    fn object_store_quota_exceeded_debug() {
        let err = ObjectStoreError::QuotaExceeded {
            used: 100,
            max: 200,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("QuotaExceeded"));
        assert!(dbg.contains("100"));
    }

    #[test]
    fn object_store_invalid_object_debug() {
        let err = ObjectStoreError::InvalidObject {
            reason: "bad".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidObject"));
    }

    #[test]
    fn object_store_serialization_debug() {
        let err = ObjectStoreError::Serialization("json fail".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Serialization"));
    }

    #[test]
    fn object_store_io_debug() {
        let err = ObjectStoreError::Io("timeout".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Io"));
    }

    #[test]
    fn symbol_store_not_found_debug() {
        let err = SymbolStoreError::NotFound {
            object_id: test_id(),
            esi: 99,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("99"));
    }

    #[test]
    fn symbol_store_quota_exceeded_debug() {
        let err = SymbolStoreError::QuotaExceeded {
            used: 500,
            max: 1000,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("QuotaExceeded"));
    }

    #[test]
    fn quarantine_quota_exceeded_debug() {
        let err = QuarantineError::QuotaExceeded {
            used: 1024,
            max: 2048,
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("QuotaExceeded"));
    }

    #[test]
    fn quarantine_promotion_denied_debug() {
        let err = QuarantineError::PromotionDenied {
            reason: "nope".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PromotionDenied"));
    }

    #[test]
    fn quarantine_schema_validation_debug() {
        let err = QuarantineError::SchemaValidationFailed {
            reason: "missing".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("SchemaValidationFailed"));
    }

    #[test]
    fn repair_rate_limit_debug() {
        let err = RepairError::RateLimitExceeded;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RateLimitExceeded"));
    }

    #[test]
    fn repair_insufficient_coverage_debug() {
        let err = RepairError::InsufficientCoverage;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InsufficientCoverage"));
    }

    #[test]
    fn repair_decode_debug() {
        let err = RepairError::Decode("corrupt".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Decode"));
    }

    #[test]
    fn gc_in_progress_debug() {
        let err = GcError::InProgress;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InProgress"));
    }

    #[test]
    fn gc_invalid_root_debug() {
        let err = GcError::InvalidRoot(test_id());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidRoot"));
    }

    // --- Source chain exhaustive tests ---

    #[test]
    fn gc_error_no_source_for_in_progress() {
        use std::error::Error;
        let err = GcError::InProgress;
        assert!(err.source().is_none());
    }

    #[test]
    fn gc_error_source_from_symbol_store() {
        use std::error::Error;
        let inner = SymbolStoreError::ObjectNotFound(test_id());
        let err: GcError = inner.into();
        assert!(err.source().is_some());
    }

    #[test]
    fn repair_error_no_source_for_insufficient_coverage() {
        use std::error::Error;
        let err = RepairError::InsufficientCoverage;
        assert!(err.source().is_none());
    }

    #[test]
    fn repair_error_no_source_for_decode() {
        use std::error::Error;
        let err = RepairError::Decode("bad data".into());
        assert!(err.source().is_none());
    }

    // --- Display exact format tests ---

    #[test]
    fn object_store_quota_display_exact_format() {
        let err = ObjectStoreError::QuotaExceeded {
            used: 999,
            max: 2000,
        };
        assert_eq!(err.to_string(), "storage quota exceeded: 999 / 2000 bytes");
    }

    #[test]
    fn symbol_store_not_found_display_exact_format() {
        let err = SymbolStoreError::NotFound {
            object_id: test_id(),
            esi: 7,
        };
        let msg = err.to_string();
        assert!(msg.starts_with("symbol not found:"));
        assert!(msg.contains("esi=7"));
    }

    #[test]
    fn quarantine_schema_display_exact_format() {
        let err = QuarantineError::SchemaValidationFailed {
            reason: "field X missing".into(),
        };
        assert_eq!(err.to_string(), "schema validation failed: field X missing");
    }

    #[test]
    fn gc_error_invalid_root_display_exact() {
        let err = GcError::InvalidRoot(test_id());
        let msg = err.to_string();
        assert!(msg.starts_with("invalid root:"));
    }

    // --- Cross-conversion chained source tests ---

    #[test]
    fn repair_error_object_store_source_display() {
        use std::error::Error;
        let inner = ObjectStoreError::AlreadyExists(test_id());
        let err: RepairError = inner.into();
        let src = err.source().unwrap();
        assert!(src.to_string().contains("already exists"));
    }

    #[test]
    fn gc_error_object_store_source_display() {
        use std::error::Error;
        let inner = ObjectStoreError::Io("permission denied".into());
        let err: GcError = inner.into();
        let src = err.source().unwrap();
        assert!(src.to_string().contains("permission denied"));
    }

    #[test]
    fn gc_error_no_source_for_invalid_root() {
        use std::error::Error;
        let err = GcError::InvalidRoot(test_id());
        assert!(err.source().is_none());
    }

    #[test]
    fn repair_error_symbol_store_quota_source() {
        use std::error::Error;
        let inner = SymbolStoreError::QuotaExceeded { used: 50, max: 100 };
        let err: RepairError = inner.into();
        let src = err.source().unwrap();
        assert!(src.to_string().contains("50"));
    }

    #[test]
    fn object_store_error_not_found_different_ids() {
        let id_a = ObjectId::from_bytes([10; 32]);
        let id_b = ObjectId::from_bytes([20; 32]);
        let err_a = ObjectStoreError::NotFound(id_a);
        let err_b = ObjectStoreError::NotFound(id_b);
        assert_ne!(err_a.to_string(), err_b.to_string());
    }

    #[test]
    fn symbol_store_invalid_symbol_debug_contains_reason() {
        let err = SymbolStoreError::InvalidSymbol {
            reason: "truncated payload".into(),
        };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("truncated payload"));
    }
}
