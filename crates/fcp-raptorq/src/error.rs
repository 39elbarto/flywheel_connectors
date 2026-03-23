//! `RaptorQ` error types.

use thiserror::Error;

/// Chunk reconstruction errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChunkError {
    /// Missing chunks for reconstruction.
    #[error("missing chunks: expected {expected}, got {got}")]
    MissingChunks {
        /// Number of expected chunks.
        expected: usize,
        /// Number of received chunks.
        got: usize,
    },

    /// Total length mismatch after reconstruction.
    #[error("length mismatch: expected {expected}, got {got}")]
    LengthMismatch {
        /// Expected total length.
        expected: u64,
        /// Actual reconstructed length.
        got: u64,
    },

    /// BLAKE3 hash verification failed.
    #[error("hash verification failed")]
    HashMismatch,

    /// Invalid chunk index.
    #[error("invalid chunk index {index}: manifest has {count} chunks")]
    InvalidChunkIndex {
        /// The invalid index.
        index: usize,
        /// Total chunk count.
        count: usize,
    },
}

/// `RaptorQ` encode errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    /// Payload exceeds maximum object size.
    #[error("payload too large: {size} bytes exceeds maximum {max} bytes")]
    PayloadTooLarge {
        /// Actual payload size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Empty payload cannot be encoded.
    #[error("cannot encode empty payload")]
    EmptyPayload,

    /// Encoder configuration is invalid.
    #[error("invalid encode configuration: {reason}")]
    InvalidConfiguration {
        /// Reason the configuration is invalid.
        reason: String,
    },

    /// The number of symbols needed for the payload exceeds the supported maximum (56,403).
    #[error("unsupported source block size K={requested}; supported range is 1..={max_supported}")]
    UnsupportedSourceBlockSize {
        /// The requested number of source symbols.
        requested: usize,
        /// The maximum supported number of source symbols (56,403).
        max_supported: usize,
    },
}

/// `RaptorQ` decode errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// Decode operation timed out.
    #[error("decode timed out")]
    Timeout,

    /// Decode operation was cancelled by execution context.
    #[error("decode cancelled")]
    Cancelled,

    /// Not enough symbols received for reconstruction.
    #[error("insufficient symbols: received {received}, need approximately {needed}")]
    InsufficientSymbols {
        /// Number of symbols received.
        received: u32,
        /// Approximate number needed.
        needed: u32,
    },

    /// Decode admission denied (too many concurrent decodes).
    #[error("decode admission denied: {reason}")]
    AdmissionDenied {
        /// Reason for denial.
        reason: String,
    },

    /// Symbol buffer limit exceeded.
    #[error("symbol buffer limit exceeded: {buffered} symbols, limit {limit}")]
    SymbolBufferExceeded {
        /// Number of symbols buffered.
        buffered: u32,
        /// Maximum allowed.
        limit: u32,
    },

    /// Memory limit exceeded.
    #[error("memory limit exceeded: {used} bytes, limit {limit} bytes")]
    MemoryLimitExceeded {
        /// Memory used.
        used: usize,
        /// Maximum allowed.
        limit: usize,
    },

    /// Invalid symbol data.
    #[error("invalid symbol: {reason}")]
    InvalidSymbol {
        /// Reason the symbol is invalid.
        reason: String,
    },

    /// Invalid transmission information (OTI).
    #[error("invalid transmission info: {reason}")]
    InvalidTransmissionInfo {
        /// Reason the OTI is invalid.
        reason: String,
    },

    /// Decode runtime orchestration failure.
    #[error("decode runtime failure: {reason}")]
    Runtime {
        /// Runtime failure reason.
        reason: String,
    },

    /// The number of symbols provided is not supported.
    #[error("unsupported source block size K={requested}; supported range is 1..={max_supported}")]
    UnsupportedSourceBlockSize {
        /// The requested number of source symbols.
        requested: usize,
        /// The maximum supported number of source symbols (56,403).
        max_supported: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_error_display() {
        let err = ChunkError::MissingChunks {
            expected: 10,
            got: 5,
        };
        assert_eq!(err.to_string(), "missing chunks: expected 10, got 5");

        let err = ChunkError::LengthMismatch {
            expected: 1000,
            got: 500,
        };
        assert_eq!(err.to_string(), "length mismatch: expected 1000, got 500");

        let err = ChunkError::HashMismatch;
        assert_eq!(err.to_string(), "hash verification failed");

        let err = ChunkError::InvalidChunkIndex { index: 5, count: 3 };
        assert_eq!(
            err.to_string(),
            "invalid chunk index 5: manifest has 3 chunks"
        );
    }

    #[test]
    fn encode_error_display() {
        let err = EncodeError::PayloadTooLarge {
            size: 100_000_000,
            max: 64_000_000,
        };
        assert!(err.to_string().contains("payload too large"));
        assert!(err.to_string().contains("100000000"));

        let err = EncodeError::EmptyPayload;
        assert_eq!(err.to_string(), "cannot encode empty payload");

        let err = EncodeError::InvalidConfiguration {
            reason: "symbol size must be greater than 0".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid encode configuration: symbol size must be greater than 0"
        );
    }

    #[test]
    fn decode_error_display() {
        let err = DecodeError::Timeout;
        assert_eq!(err.to_string(), "decode timed out");

        let err = DecodeError::Cancelled;
        assert_eq!(err.to_string(), "decode cancelled");

        let err = DecodeError::InsufficientSymbols {
            received: 50,
            needed: 100,
        };
        assert!(err.to_string().contains("insufficient symbols"));

        let err = DecodeError::AdmissionDenied {
            reason: "too many concurrent".into(),
        };
        assert!(err.to_string().contains("too many concurrent"));

        let err = DecodeError::SymbolBufferExceeded {
            buffered: 10001,
            limit: 10000,
        };
        assert!(err.to_string().contains("symbol buffer limit"));

        let err = DecodeError::MemoryLimitExceeded {
            used: 100_000_000,
            limit: 64_000_000,
        };
        assert!(err.to_string().contains("memory limit"));

        let err = DecodeError::InvalidSymbol {
            reason: "wrong size".into(),
        };
        assert!(err.to_string().contains("wrong size"));

        let err = DecodeError::Runtime {
            reason: "join failed".into(),
        };
        assert!(err.to_string().contains("runtime failure"));
    }

    #[test]
    fn errors_are_clone_and_eq() {
        let err1 = ChunkError::HashMismatch;
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err1 = EncodeError::EmptyPayload;
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err1 = DecodeError::Timeout;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    #[test]
    fn all_chunk_errors_implement_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&ChunkError::MissingChunks {
            expected: 1,
            got: 0,
        });
        assert_error(&ChunkError::LengthMismatch {
            expected: 1,
            got: 0,
        });
        assert_error(&ChunkError::HashMismatch);
        assert_error(&ChunkError::InvalidChunkIndex { index: 0, count: 0 });
    }

    #[test]
    fn all_encode_errors_implement_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&EncodeError::PayloadTooLarge { size: 1, max: 0 });
        assert_error(&EncodeError::EmptyPayload);
        assert_error(&EncodeError::InvalidConfiguration { reason: "x".into() });
    }

    #[test]
    fn all_decode_errors_implement_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&DecodeError::Timeout);
        assert_error(&DecodeError::Cancelled);
        assert_error(&DecodeError::InsufficientSymbols {
            received: 0,
            needed: 1,
        });
        assert_error(&DecodeError::AdmissionDenied { reason: "x".into() });
        assert_error(&DecodeError::SymbolBufferExceeded {
            buffered: 1,
            limit: 0,
        });
        assert_error(&DecodeError::MemoryLimitExceeded { used: 1, limit: 0 });
        assert_error(&DecodeError::InvalidSymbol { reason: "x".into() });
        assert_error(&DecodeError::InvalidTransmissionInfo { reason: "x".into() });
        assert_error(&DecodeError::Runtime { reason: "x".into() });
    }

    #[test]
    fn chunk_error_clone_eq_all_variants() {
        let variants: Vec<ChunkError> = vec![
            ChunkError::MissingChunks {
                expected: 5,
                got: 2,
            },
            ChunkError::LengthMismatch {
                expected: 100,
                got: 50,
            },
            ChunkError::HashMismatch,
            ChunkError::InvalidChunkIndex { index: 3, count: 2 },
        ];
        for v in &variants {
            assert_eq!(v, &v.clone());
        }
    }

    #[test]
    fn encode_error_clone_eq_all_variants() {
        let variants: Vec<EncodeError> = vec![
            EncodeError::PayloadTooLarge { size: 100, max: 50 },
            EncodeError::EmptyPayload,
            EncodeError::InvalidConfiguration {
                reason: "symbol size must be greater than 0".into(),
            },
        ];
        for v in &variants {
            assert_eq!(v, &v.clone());
        }
    }

    #[test]
    fn decode_error_clone_eq_all_variants() {
        let variants: Vec<DecodeError> = vec![
            DecodeError::Timeout,
            DecodeError::Cancelled,
            DecodeError::InsufficientSymbols {
                received: 10,
                needed: 20,
            },
            DecodeError::AdmissionDenied {
                reason: "test".into(),
            },
            DecodeError::SymbolBufferExceeded {
                buffered: 100,
                limit: 50,
            },
            DecodeError::MemoryLimitExceeded {
                used: 1000,
                limit: 500,
            },
            DecodeError::InvalidSymbol {
                reason: "bad".into(),
            },
            DecodeError::InvalidTransmissionInfo {
                reason: "oops".into(),
            },
            DecodeError::Runtime {
                reason: "fail".into(),
            },
        ];
        for v in &variants {
            assert_eq!(v, &v.clone());
        }
    }

    #[test]
    fn chunk_error_inequality() {
        let err1 = ChunkError::MissingChunks {
            expected: 10,
            got: 5,
        };
        let err2 = ChunkError::MissingChunks {
            expected: 10,
            got: 6,
        };
        assert_ne!(err1, err2);

        let err3 = ChunkError::HashMismatch;
        assert_ne!(err1, err3);
    }

    #[test]
    fn decode_error_inequality() {
        let err1 = DecodeError::Timeout;
        let err2 = DecodeError::Cancelled;
        assert_ne!(err1, err2);
    }

    #[test]
    fn invalid_transmission_info_display() {
        let err = DecodeError::InvalidTransmissionInfo {
            reason: "zero symbol size".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid transmission info: zero symbol size"
        );
    }

    #[test]
    fn debug_format_contains_variant_names() {
        assert!(format!("{:?}", ChunkError::HashMismatch).contains("HashMismatch"));
        assert!(format!("{:?}", EncodeError::EmptyPayload).contains("EmptyPayload"));
        assert!(format!("{:?}", DecodeError::Timeout).contains("Timeout"));
        assert!(format!("{:?}", DecodeError::Cancelled).contains("Cancelled"));
        assert!(format!("{:?}", DecodeError::Runtime { reason: "x".into() }).contains("Runtime"));
    }

    #[test]
    fn encode_error_inequality() {
        let err1 = EncodeError::EmptyPayload;
        let err2 = EncodeError::PayloadTooLarge { size: 1, max: 0 };
        assert_ne!(err1, err2);
    }

    #[test]
    fn chunk_error_boundary_values() {
        let err = ChunkError::MissingChunks {
            expected: 0,
            got: 0,
        };
        assert_eq!(err.to_string(), "missing chunks: expected 0, got 0");

        let err = ChunkError::LengthMismatch {
            expected: u64::MAX,
            got: 0,
        };
        assert!(err.to_string().contains(&u64::MAX.to_string()));

        let err = ChunkError::InvalidChunkIndex {
            index: usize::MAX,
            count: 0,
        };
        assert!(err.to_string().contains(&usize::MAX.to_string()));
    }

    #[test]
    fn encode_error_boundary_values() {
        let err = EncodeError::PayloadTooLarge { size: 0, max: 0 };
        assert_eq!(
            err.to_string(),
            "payload too large: 0 bytes exceeds maximum 0 bytes"
        );
    }

    #[test]
    fn decode_error_display_all_remaining() {
        let err = DecodeError::InsufficientSymbols {
            received: 0,
            needed: 0,
        };
        assert_eq!(
            err.to_string(),
            "insufficient symbols: received 0, need approximately 0"
        );

        let err = DecodeError::SymbolBufferExceeded {
            buffered: 0,
            limit: 0,
        };
        assert_eq!(
            err.to_string(),
            "symbol buffer limit exceeded: 0 symbols, limit 0"
        );

        let err = DecodeError::MemoryLimitExceeded { used: 0, limit: 0 };
        assert_eq!(
            err.to_string(),
            "memory limit exceeded: 0 bytes, limit 0 bytes"
        );
    }

    // ── ChunkError additional tests ────────────────────────────────────────

    #[test]
    fn chunk_error_missing_chunks_display_exact() {
        let err = ChunkError::MissingChunks {
            expected: 4,
            got: 1,
        };
        assert_eq!(err.to_string(), "missing chunks: expected 4, got 1");
    }

    #[test]
    fn chunk_error_length_mismatch_display_exact() {
        let err = ChunkError::LengthMismatch {
            expected: 65536,
            got: 32768,
        };
        assert_eq!(
            err.to_string(),
            "length mismatch: expected 65536, got 32768"
        );
    }

    #[test]
    fn chunk_error_invalid_chunk_index_display_exact() {
        let err = ChunkError::InvalidChunkIndex {
            index: 10,
            count: 5,
        };
        assert_eq!(
            err.to_string(),
            "invalid chunk index 10: manifest has 5 chunks"
        );
    }

    #[test]
    fn chunk_error_ne_cross_variant() {
        assert_ne!(
            ChunkError::HashMismatch,
            ChunkError::MissingChunks {
                expected: 0,
                got: 0
            }
        );
        assert_ne!(
            ChunkError::HashMismatch,
            ChunkError::LengthMismatch {
                expected: 0,
                got: 0
            }
        );
        assert_ne!(
            ChunkError::HashMismatch,
            ChunkError::InvalidChunkIndex { index: 0, count: 0 }
        );
    }

    // ── EncodeError additional tests ───────────────────────────────────────

    #[test]
    fn encode_error_payload_too_large_display_exact() {
        let err = EncodeError::PayloadTooLarge {
            size: 128_000_000,
            max: 67_108_864,
        };
        assert_eq!(
            err.to_string(),
            "payload too large: 128000000 bytes exceeds maximum 67108864 bytes"
        );
    }

    #[test]
    fn encode_error_empty_payload_display_exact() {
        let err = EncodeError::EmptyPayload;
        assert_eq!(err.to_string(), "cannot encode empty payload");
    }

    #[test]
    fn encode_error_invalid_configuration_display_exact() {
        let err = EncodeError::InvalidConfiguration {
            reason: "chunk size must be greater than 0".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid encode configuration: chunk size must be greater than 0"
        );
    }

    // ── DecodeError additional tests ───────────────────────────────────────

    #[test]
    fn decode_error_timeout_display_exact() {
        let err = DecodeError::Timeout;
        assert_eq!(err.to_string(), "decode timed out");
    }

    #[test]
    fn decode_error_cancelled_display_exact() {
        let err = DecodeError::Cancelled;
        assert_eq!(err.to_string(), "decode cancelled");
    }

    #[test]
    fn decode_error_admission_denied_display_exact() {
        let err = DecodeError::AdmissionDenied {
            reason: "max concurrent (16) exceeded".into(),
        };
        assert_eq!(
            err.to_string(),
            "decode admission denied: max concurrent (16) exceeded"
        );
    }

    #[test]
    fn decode_error_invalid_symbol_display_exact() {
        let err = DecodeError::InvalidSymbol {
            reason: "symbol size mismatch: expected 64 bytes, got 128 bytes".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid symbol: symbol size mismatch: expected 64 bytes, got 128 bytes"
        );
    }

    #[test]
    fn decode_error_runtime_display_exact() {
        let err = DecodeError::Runtime {
            reason: "async task join failed".into(),
        };
        assert_eq!(
            err.to_string(),
            "decode runtime failure: async task join failed"
        );
    }

    #[test]
    fn decode_error_insufficient_symbols_display_exact() {
        let err = DecodeError::InsufficientSymbols {
            received: 50,
            needed: 101,
        };
        assert_eq!(
            err.to_string(),
            "insufficient symbols: received 50, need approximately 101"
        );
    }

    #[test]
    fn decode_error_symbol_buffer_exceeded_display_exact() {
        let err = DecodeError::SymbolBufferExceeded {
            buffered: 10001,
            limit: 10000,
        };
        assert_eq!(
            err.to_string(),
            "symbol buffer limit exceeded: 10001 symbols, limit 10000"
        );
    }

    #[test]
    fn decode_error_memory_limit_exceeded_display_exact() {
        let err = DecodeError::MemoryLimitExceeded {
            used: 100_000_000,
            limit: 67_108_864,
        };
        assert_eq!(
            err.to_string(),
            "memory limit exceeded: 100000000 bytes, limit 67108864 bytes"
        );
    }

    #[test]
    fn decode_error_invalid_transmission_info_display_exact() {
        let err = DecodeError::InvalidTransmissionInfo {
            reason: "symbol size must be > 0".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid transmission info: symbol size must be > 0"
        );
    }

    // ── Debug format tests ─────────────────────────────────────────────────

    #[test]
    fn chunk_error_debug_all_variants() {
        let variants: Vec<ChunkError> = vec![
            ChunkError::MissingChunks {
                expected: 1,
                got: 0,
            },
            ChunkError::LengthMismatch {
                expected: 1,
                got: 0,
            },
            ChunkError::HashMismatch,
            ChunkError::InvalidChunkIndex { index: 0, count: 0 },
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn encode_error_debug_all_variants() {
        let variants: Vec<EncodeError> = vec![
            EncodeError::PayloadTooLarge { size: 1, max: 0 },
            EncodeError::EmptyPayload,
            EncodeError::InvalidConfiguration { reason: "x".into() },
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    #[test]
    fn decode_error_debug_all_variants() {
        let variants: Vec<DecodeError> = vec![
            DecodeError::Timeout,
            DecodeError::Cancelled,
            DecodeError::InsufficientSymbols {
                received: 0,
                needed: 1,
            },
            DecodeError::AdmissionDenied { reason: "x".into() },
            DecodeError::SymbolBufferExceeded {
                buffered: 1,
                limit: 0,
            },
            DecodeError::MemoryLimitExceeded { used: 1, limit: 0 },
            DecodeError::InvalidSymbol { reason: "x".into() },
            DecodeError::InvalidTransmissionInfo { reason: "x".into() },
            DecodeError::Runtime { reason: "x".into() },
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    // ── Error trait source() tests ─────────────────────────────────────────

    #[test]
    fn chunk_error_source_is_none() {
        use std::error::Error;
        let err = ChunkError::HashMismatch;
        assert!(err.source().is_none());
    }

    #[test]
    fn encode_error_source_is_none() {
        use std::error::Error;
        let err = EncodeError::EmptyPayload;
        assert!(err.source().is_none());
    }

    #[test]
    fn decode_error_source_is_none() {
        use std::error::Error;
        let err = DecodeError::Timeout;
        assert!(err.source().is_none());
    }

    // ── Additional error coverage ─────────────────────────────────────────

    #[test]
    fn chunk_error_missing_chunks_with_large_values() {
        let err = ChunkError::MissingChunks {
            expected: usize::MAX,
            got: usize::MAX - 1,
        };
        let msg = err.to_string();
        assert!(msg.contains(&usize::MAX.to_string()));
        assert!(msg.contains(&(usize::MAX - 1).to_string()));
    }

    #[test]
    fn chunk_error_invalid_chunk_index_zero_count() {
        let err = ChunkError::InvalidChunkIndex { index: 0, count: 0 };
        assert_eq!(
            err.to_string(),
            "invalid chunk index 0: manifest has 0 chunks"
        );
    }

    #[test]
    fn encode_error_payload_too_large_boundary() {
        let err = EncodeError::PayloadTooLarge {
            size: usize::MAX,
            max: usize::MAX - 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("payload too large"));
        assert!(msg.contains(&usize::MAX.to_string()));
    }

    #[test]
    fn decode_error_admission_denied_empty_reason() {
        let err = DecodeError::AdmissionDenied {
            reason: String::new(),
        };
        assert_eq!(err.to_string(), "decode admission denied: ");
    }

    #[test]
    fn decode_error_invalid_symbol_empty_reason() {
        let err = DecodeError::InvalidSymbol {
            reason: String::new(),
        };
        assert_eq!(err.to_string(), "invalid symbol: ");
    }

    #[test]
    fn decode_error_invalid_transmission_info_empty_reason() {
        let err = DecodeError::InvalidTransmissionInfo {
            reason: String::new(),
        };
        assert_eq!(err.to_string(), "invalid transmission info: ");
    }

    #[test]
    fn decode_error_runtime_empty_reason() {
        let err = DecodeError::Runtime {
            reason: String::new(),
        };
        assert_eq!(err.to_string(), "decode runtime failure: ");
    }

    #[test]
    fn chunk_error_ne_same_variant_different_fields() {
        let a = ChunkError::LengthMismatch {
            expected: 100,
            got: 50,
        };
        let b = ChunkError::LengthMismatch {
            expected: 100,
            got: 51,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn chunk_error_ne_invalid_chunk_index_different_fields() {
        let a = ChunkError::InvalidChunkIndex { index: 1, count: 5 };
        let b = ChunkError::InvalidChunkIndex { index: 2, count: 5 };
        assert_ne!(a, b);

        let c = ChunkError::InvalidChunkIndex { index: 1, count: 6 };
        assert_ne!(a, c);
    }

    #[test]
    fn encode_error_payload_too_large_different_fields() {
        let a = EncodeError::PayloadTooLarge { size: 100, max: 50 };
        let b = EncodeError::PayloadTooLarge { size: 200, max: 50 };
        assert_ne!(a, b);
    }

    #[test]
    fn decode_error_insufficient_symbols_different_fields() {
        let a = DecodeError::InsufficientSymbols {
            received: 10,
            needed: 20,
        };
        let b = DecodeError::InsufficientSymbols {
            received: 11,
            needed: 20,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn decode_error_symbol_buffer_exceeded_different_fields() {
        let a = DecodeError::SymbolBufferExceeded {
            buffered: 100,
            limit: 50,
        };
        let b = DecodeError::SymbolBufferExceeded {
            buffered: 101,
            limit: 50,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn decode_error_memory_limit_different_fields() {
        let a = DecodeError::MemoryLimitExceeded {
            used: 1000,
            limit: 500,
        };
        let b = DecodeError::MemoryLimitExceeded {
            used: 1001,
            limit: 500,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn all_errors_source_is_none() {
        use std::error::Error;

        let chunk_variants: Vec<ChunkError> = vec![
            ChunkError::MissingChunks {
                expected: 1,
                got: 0,
            },
            ChunkError::LengthMismatch {
                expected: 1,
                got: 0,
            },
            ChunkError::HashMismatch,
            ChunkError::InvalidChunkIndex { index: 0, count: 0 },
        ];
        for v in &chunk_variants {
            assert!(v.source().is_none(), "ChunkError should have no source");
        }

        let encode_variants: Vec<EncodeError> = vec![
            EncodeError::PayloadTooLarge { size: 1, max: 0 },
            EncodeError::EmptyPayload,
            EncodeError::InvalidConfiguration { reason: "x".into() },
        ];
        for v in &encode_variants {
            assert!(v.source().is_none(), "EncodeError should have no source");
        }

        let decode_variants: Vec<DecodeError> = vec![
            DecodeError::Timeout,
            DecodeError::Cancelled,
            DecodeError::InsufficientSymbols {
                received: 0,
                needed: 1,
            },
            DecodeError::AdmissionDenied { reason: "x".into() },
            DecodeError::SymbolBufferExceeded {
                buffered: 1,
                limit: 0,
            },
            DecodeError::MemoryLimitExceeded { used: 1, limit: 0 },
            DecodeError::InvalidSymbol { reason: "x".into() },
            DecodeError::InvalidTransmissionInfo { reason: "x".into() },
            DecodeError::Runtime { reason: "x".into() },
        ];
        for v in &decode_variants {
            assert!(v.source().is_none(), "DecodeError should have no source");
        }
    }

    #[test]
    fn chunk_error_debug_field_values() {
        let err = ChunkError::MissingChunks {
            expected: 42,
            got: 7,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("42"));
        assert!(debug.contains('7'));
    }

    #[test]
    fn encode_error_debug_field_values() {
        let err = EncodeError::PayloadTooLarge {
            size: 999,
            max: 111,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("999"));
        assert!(debug.contains("111"));
    }

    #[test]
    fn encode_error_invalid_configuration_debug_field_values() {
        let err = EncodeError::InvalidConfiguration {
            reason: "symbol size must be greater than 0".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("symbol size must be greater than 0"));
    }

    #[test]
    fn decode_error_debug_field_values() {
        let err = DecodeError::InsufficientSymbols {
            received: 55,
            needed: 77,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("55"));
        assert!(debug.contains("77"));
    }

    // ── Error interoperability and formatting tests ──────────────────────

    #[test]
    fn chunk_error_display_is_not_empty() {
        let variants: Vec<ChunkError> = vec![
            ChunkError::MissingChunks {
                expected: 1,
                got: 0,
            },
            ChunkError::LengthMismatch {
                expected: 1,
                got: 0,
            },
            ChunkError::HashMismatch,
            ChunkError::InvalidChunkIndex { index: 0, count: 0 },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn encode_error_display_is_not_empty() {
        let variants: Vec<EncodeError> = vec![
            EncodeError::PayloadTooLarge { size: 1, max: 0 },
            EncodeError::EmptyPayload,
            EncodeError::InvalidConfiguration { reason: "x".into() },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn decode_error_display_is_not_empty() {
        let variants: Vec<DecodeError> = vec![
            DecodeError::Timeout,
            DecodeError::Cancelled,
            DecodeError::InsufficientSymbols {
                received: 0,
                needed: 1,
            },
            DecodeError::AdmissionDenied {
                reason: "test".into(),
            },
            DecodeError::SymbolBufferExceeded {
                buffered: 1,
                limit: 0,
            },
            DecodeError::MemoryLimitExceeded { used: 1, limit: 0 },
            DecodeError::InvalidSymbol {
                reason: "test".into(),
            },
            DecodeError::InvalidTransmissionInfo {
                reason: "test".into(),
            },
            DecodeError::Runtime {
                reason: "test".into(),
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn chunk_error_clone_preserves_fields() {
        let err = ChunkError::MissingChunks {
            expected: 42,
            got: 7,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
        if let ChunkError::MissingChunks { expected, got } = cloned {
            assert_eq!(expected, 42);
            assert_eq!(got, 7);
        }
    }

    #[test]
    fn encode_error_clone_preserves_fields() {
        let err = EncodeError::PayloadTooLarge {
            size: 999,
            max: 500,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
        if let EncodeError::PayloadTooLarge { size, max } = cloned {
            assert_eq!(size, 999);
            assert_eq!(max, 500);
        }
    }

    #[test]
    fn encode_error_invalid_configuration_clone_preserves_fields() {
        let err = EncodeError::InvalidConfiguration {
            reason: "chunk size must be greater than 0".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
        if let EncodeError::InvalidConfiguration { reason } = cloned {
            assert_eq!(reason, "chunk size must be greater than 0");
        }
    }

    #[test]
    fn decode_error_clone_preserves_string_fields() {
        let err = DecodeError::AdmissionDenied {
            reason: "max concurrent (16) exceeded".into(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
        if let DecodeError::AdmissionDenied { reason } = cloned {
            assert_eq!(reason, "max concurrent (16) exceeded");
        }
    }

    #[test]
    fn decode_error_invalid_symbol_with_special_chars() {
        let err = DecodeError::InvalidSymbol {
            reason: "symbol contains \0 null bytes".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("null bytes"));
    }

    #[test]
    fn decode_error_runtime_with_long_message() {
        let long_reason = "x".repeat(10_000);
        let err = DecodeError::Runtime {
            reason: long_reason.clone(),
        };
        let msg = err.to_string();
        assert!(msg.contains(&long_reason));
    }

    #[test]
    fn chunk_error_hash_mismatch_eq() {
        let a = ChunkError::HashMismatch;
        let b = ChunkError::HashMismatch;
        assert_eq!(a, b);
    }

    #[test]
    fn decode_error_timeout_eq() {
        let a = DecodeError::Timeout;
        let b = DecodeError::Timeout;
        assert_eq!(a, b);
    }

    #[test]
    fn decode_error_cancelled_eq() {
        let a = DecodeError::Cancelled;
        let b = DecodeError::Cancelled;
        assert_eq!(a, b);
    }

    // ── Additional error tests (batch 2) ──────────────────────────────────

    #[test]
    fn chunk_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ChunkError>();
    }

    #[test]
    fn encode_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EncodeError>();
    }

    #[test]
    fn decode_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DecodeError>();
    }

    #[test]
    fn chunk_error_missing_chunks_symmetric_equality() {
        let a = ChunkError::MissingChunks {
            expected: 5,
            got: 3,
        };
        let b = ChunkError::MissingChunks {
            expected: 5,
            got: 3,
        };
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn decode_error_admission_denied_different_reasons() {
        let a = DecodeError::AdmissionDenied {
            reason: "reason A".into(),
        };
        let b = DecodeError::AdmissionDenied {
            reason: "reason B".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn decode_error_invalid_symbol_different_reasons() {
        let a = DecodeError::InvalidSymbol {
            reason: "size mismatch".into(),
        };
        let b = DecodeError::InvalidSymbol {
            reason: "corrupt data".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn decode_error_invalid_transmission_info_different_reasons() {
        let a = DecodeError::InvalidTransmissionInfo {
            reason: "zero symbol size".into(),
        };
        let b = DecodeError::InvalidTransmissionInfo {
            reason: "zero transfer length".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn decode_error_runtime_different_reasons() {
        let a = DecodeError::Runtime {
            reason: "join error".into(),
        };
        let b = DecodeError::Runtime {
            reason: "panic".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn chunk_error_length_mismatch_symmetric() {
        let a = ChunkError::LengthMismatch {
            expected: 1000,
            got: 500,
        };
        let b = ChunkError::LengthMismatch {
            expected: 1000,
            got: 500,
        };
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn encode_error_payload_too_large_symmetric() {
        let a = EncodeError::PayloadTooLarge {
            size: 1000,
            max: 500,
        };
        let b = EncodeError::PayloadTooLarge {
            size: 1000,
            max: 500,
        };
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn encode_error_invalid_configuration_different_reasons() {
        let a = EncodeError::InvalidConfiguration {
            reason: "symbol size must be greater than 0".into(),
        };
        let b = EncodeError::InvalidConfiguration {
            reason: "chunk size must be greater than 0".into(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn decode_error_insufficient_symbols_symmetric() {
        let a = DecodeError::InsufficientSymbols {
            received: 50,
            needed: 100,
        };
        let b = DecodeError::InsufficientSymbols {
            received: 50,
            needed: 100,
        };
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn decode_error_symbol_buffer_exceeded_symmetric() {
        let a = DecodeError::SymbolBufferExceeded {
            buffered: 100,
            limit: 50,
        };
        let b = DecodeError::SymbolBufferExceeded {
            buffered: 100,
            limit: 50,
        };
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn decode_error_memory_limit_exceeded_symmetric() {
        let a = DecodeError::MemoryLimitExceeded {
            used: 1000,
            limit: 500,
        };
        let b = DecodeError::MemoryLimitExceeded {
            used: 1000,
            limit: 500,
        };
        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn chunk_error_display_and_debug_differ() {
        let err = ChunkError::HashMismatch;
        let display = err.to_string();
        let debug = format!("{err:?}");
        // Display is human-friendly, Debug includes variant name
        assert_ne!(display, debug);
    }

    #[test]
    fn encode_error_display_and_debug_differ() {
        let err = EncodeError::EmptyPayload;
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert_ne!(display, debug);
    }

    #[test]
    fn decode_error_display_and_debug_differ() {
        let err = DecodeError::Timeout;
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert_ne!(display, debug);
    }
}
