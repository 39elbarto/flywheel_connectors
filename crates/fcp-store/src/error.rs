//! Error types for FCP2 stores.

use fcp_core::ObjectId;
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
}
