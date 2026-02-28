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
}
