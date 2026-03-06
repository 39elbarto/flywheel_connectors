//! Chunked object manifest and raw chunk types (NORMATIVE).
//!
//! Large objects above `max_chunk_threshold` MUST be represented as a manifest
//! referencing ordered `RawChunk` objects.

// Allow truncation casts - object sizes are bounded and these are capacity hints
#![allow(clippy::cast_possible_truncation)]

use fcp_core::ObjectId;
use serde::{Deserialize, Serialize};

use crate::error::ChunkError;

/// Chunked object manifest (NORMATIVE for objects above `max_chunk_threshold`).
///
/// Enables:
/// - Partial retrieval (fetch chunks on demand)
/// - Targeted repair (repair one chunk, not whole object)
/// - Bounded memory reconstruction
/// - Chunk-level deduplication
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkedObjectManifest {
    /// Total byte length of the original payload.
    pub total_len: u64,
    /// Chunk size in bytes (except possibly last chunk).
    pub chunk_size: u32,
    /// Ordered chunk object IDs (each chunk is a normal `StoredObject`).
    pub chunks: Vec<ObjectId>,
    /// BLAKE3 hash of the full payload for end-to-end verification.
    pub payload_hash: [u8; 32],
}

impl ChunkedObjectManifest {
    /// Create a manifest from a large payload.
    ///
    /// Returns the manifest and the raw chunks that should be stored separately.
    #[must_use]
    pub fn from_payload(payload: &[u8], chunk_size: u32) -> (Self, Vec<RawChunk>) {
        let payload_hash = *blake3::hash(payload).as_bytes();
        let mut chunks = Vec::new();
        let mut chunk_ids = Vec::new();

        for chunk_data in payload.chunks(chunk_size as usize) {
            let chunk = RawChunk::new(chunk_data.to_vec());
            chunk_ids.push(chunk.content_id());
            chunks.push(chunk);
        }

        let manifest = Self {
            total_len: payload.len() as u64,
            chunk_size,
            chunks: chunk_ids,
            payload_hash,
        };

        (manifest, chunks)
    }

    /// Reconstruct the payload from chunks (validates hash).
    ///
    /// # Errors
    ///
    /// Returns `ChunkError` if:
    /// - Wrong number of chunks provided
    /// - Total length doesn't match
    /// - BLAKE3 hash verification fails
    pub fn reconstruct(&self, chunks: &[RawChunk]) -> Result<Vec<u8>, ChunkError> {
        if chunks.len() != self.chunks.len() {
            return Err(ChunkError::MissingChunks {
                expected: self.chunks.len(),
                got: chunks.len(),
            });
        }

        let actual_len: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        if actual_len != self.total_len {
            return Err(ChunkError::LengthMismatch {
                expected: self.total_len,
                got: actual_len,
            });
        }

        // Pre-allocate based on verified actual chunks length, not just the manifest claim.
        // Since we verified actual_len == self.total_len, this is safe from manifest lies,
        // but we still cap it to avoid OOM from huge valid payloads if system is constrained.
        // For now, usize limit is the main constraint.
        let capacity = usize::try_from(actual_len).map_err(|_| ChunkError::LengthMismatch {
            expected: self.total_len,
            got: actual_len,
        })?;

        let mut payload = Vec::with_capacity(capacity);
        for chunk in chunks {
            payload.extend_from_slice(&chunk.bytes);
        }

        // Verify hash
        let actual_hash = blake3::hash(&payload);
        if actual_hash.as_bytes() != &self.payload_hash {
            return Err(ChunkError::HashMismatch);
        }

        Ok(payload)
    }

    /// Reconstruct the payload from chunks without hash verification.
    ///
    /// Use this only when you've already verified individual chunk hashes.
    ///
    /// # Errors
    ///
    /// Returns `ChunkError` if wrong number of chunks or length mismatch.
    pub fn reconstruct_unchecked(&self, chunks: &[RawChunk]) -> Result<Vec<u8>, ChunkError> {
        if chunks.len() != self.chunks.len() {
            return Err(ChunkError::MissingChunks {
                expected: self.chunks.len(),
                got: chunks.len(),
            });
        }

        let actual_len: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        if actual_len != self.total_len {
            return Err(ChunkError::LengthMismatch {
                expected: self.total_len,
                got: actual_len,
            });
        }

        // Safe allocation based on actual chunks provided
        let capacity = usize::try_from(actual_len).map_err(|_| ChunkError::LengthMismatch {
            expected: self.total_len,
            got: actual_len,
        })?;

        let mut payload = Vec::with_capacity(capacity);
        for chunk in chunks {
            payload.extend_from_slice(&chunk.bytes);
        }

        Ok(payload)
    }

    /// Number of chunks in the manifest.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Get the expected size of a specific chunk.
    ///
    /// # Errors
    ///
    /// Returns `ChunkError::InvalidChunkIndex` if index is out of bounds.
    pub fn chunk_size_at(&self, index: usize) -> Result<usize, ChunkError> {
        if index >= self.chunks.len() {
            return Err(ChunkError::InvalidChunkIndex {
                index,
                count: self.chunks.len(),
            });
        }

        // Last chunk may be smaller
        if index == self.chunks.len() - 1 {
            let remaining = self.total_len as usize % self.chunk_size as usize;
            if remaining == 0 {
                Ok(self.chunk_size as usize)
            } else {
                Ok(remaining)
            }
        } else {
            Ok(self.chunk_size as usize)
        }
    }

    /// Verify the payload hash matches.
    #[must_use]
    pub fn verify_hash(&self, payload: &[u8]) -> bool {
        let actual_hash = blake3::hash(payload);
        actual_hash.as_bytes() == &self.payload_hash
    }
}

/// A chunk is a raw bytes container (NORMATIVE).
///
/// Chunks are stored as normal objects and referenced by their content-addressed ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawChunk {
    /// The raw bytes of this chunk.
    pub bytes: Vec<u8>,
}

impl RawChunk {
    /// Create a new raw chunk.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Derive a content-addressed ID for this chunk.
    ///
    /// Uses unscoped `ObjectId` since chunks are referenced by content hash.
    #[must_use]
    pub fn content_id(&self) -> ObjectId {
        ObjectId::from_unscoped_bytes(&self.bytes)
    }

    /// Get the length of this chunk in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if this chunk is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_chunk_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let chunk = RawChunk::new(data.clone());
        assert_eq!(chunk.bytes, data);
        assert_eq!(chunk.len(), 5);
        assert!(!chunk.is_empty());
    }

    #[test]
    fn raw_chunk_empty() {
        let chunk = RawChunk::new(vec![]);
        assert!(chunk.is_empty());
        assert_eq!(chunk.len(), 0);
    }

    #[test]
    fn raw_chunk_content_id_deterministic() {
        let data = vec![1, 2, 3, 4, 5];
        let chunk1 = RawChunk::new(data.clone());
        let chunk2 = RawChunk::new(data);
        assert_eq!(chunk1.content_id(), chunk2.content_id());
    }

    #[test]
    fn raw_chunk_content_id_differs_by_content() {
        let chunk1 = RawChunk::new(vec![1, 2, 3]);
        let chunk2 = RawChunk::new(vec![4, 5, 6]);
        assert_ne!(chunk1.content_id(), chunk2.content_id());
    }

    #[test]
    fn manifest_from_payload_single_chunk() {
        let payload = vec![0u8; 1000]; // 1000 bytes
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        assert_eq!(manifest.total_len, 1000);
        assert_eq!(manifest.chunk_size, 64 * 1024);
        assert_eq!(manifest.chunk_count(), 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].bytes, payload);
    }

    #[test]
    fn manifest_from_payload_multiple_chunks() {
        let payload = vec![42u8; 200_000]; // 200KB
        let chunk_size = 64 * 1024; // 64KB chunks
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

        assert_eq!(manifest.total_len, 200_000);
        // 200KB / 64KB = 3.125 -> 4 chunks
        assert_eq!(manifest.chunk_count(), 4);
        assert_eq!(chunks.len(), 4);

        // First 3 chunks are full size
        assert_eq!(chunks[0].len(), 64 * 1024);
        assert_eq!(chunks[1].len(), 64 * 1024);
        assert_eq!(chunks[2].len(), 64 * 1024);
        // Last chunk is the remainder
        assert_eq!(chunks[3].len(), 200_000 - 3 * 64 * 1024);
    }

    #[test]
    fn manifest_reconstruct_success() {
        let payload: Vec<u8> = (0..200_000_u32).map(|i| (i % 256) as u8).collect();
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert_eq!(reconstructed, payload);
    }

    #[test]
    fn manifest_reconstruct_missing_chunks() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        // Remove one chunk
        chunks.pop();

        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::MissingChunks { .. })));
    }

    #[test]
    fn manifest_reconstruct_hash_mismatch() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        // Corrupt one chunk
        chunks[0].bytes[0] = 255;

        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::HashMismatch)));
    }

    #[test]
    fn manifest_reconstruct_unchecked() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        // Corrupt one chunk - unchecked won't catch this
        chunks[0].bytes[0] = 255;

        // unchecked should succeed even with corruption
        let result = manifest.reconstruct_unchecked(&chunks);
        assert!(result.is_ok());
        // But hash verification should fail
        assert!(!manifest.verify_hash(&result.unwrap()));
    }

    #[test]
    fn manifest_chunk_size_at() {
        let payload = vec![42u8; 200_000];
        let chunk_size = 64 * 1024;
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

        // First chunks are full size
        assert_eq!(manifest.chunk_size_at(0).unwrap(), 64 * 1024);
        assert_eq!(manifest.chunk_size_at(1).unwrap(), 64 * 1024);
        assert_eq!(manifest.chunk_size_at(2).unwrap(), 64 * 1024);
        // Last chunk is remainder
        assert_eq!(manifest.chunk_size_at(3).unwrap(), 200_000 - 3 * 64 * 1024);

        // Invalid index
        let result = manifest.chunk_size_at(10);
        assert!(matches!(result, Err(ChunkError::InvalidChunkIndex { .. })));
    }

    #[test]
    fn manifest_verify_hash() {
        let payload = vec![1u8; 1000];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        assert!(manifest.verify_hash(&payload));
        assert!(!manifest.verify_hash(&[0u8; 1000]));
    }

    #[test]
    fn manifest_serialization_roundtrip() {
        let payload = vec![42u8; 100_000];
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        let json = serde_json::to_string(&manifest).unwrap();
        let deserialized: ChunkedObjectManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.total_len, manifest.total_len);
        assert_eq!(deserialized.chunk_size, manifest.chunk_size);
        assert_eq!(deserialized.chunks.len(), manifest.chunks.len());
        assert_eq!(deserialized.payload_hash, manifest.payload_hash);
    }

    #[test]
    fn empty_payload_creates_empty_manifest() {
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        assert_eq!(manifest.total_len, 0);
        assert_eq!(manifest.chunk_count(), 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn exactly_chunk_size_payload() {
        let payload = vec![1u8; 64 * 1024];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);

        assert_eq!(manifest.chunk_count(), 1);
        assert_eq!(chunks[0].len(), 64 * 1024);
        assert_eq!(manifest.chunk_size_at(0).unwrap(), 64 * 1024);
    }

    // ── RawChunk additional tests ──────────────────────────────────────────

    #[test]
    fn raw_chunk_content_id_differs_from_empty() {
        let filled = RawChunk::new(vec![1, 2, 3]);
        let empty = RawChunk::new(vec![]);
        assert_ne!(filled.content_id(), empty.content_id());
    }

    #[test]
    fn raw_chunk_large_payload() {
        let data = vec![0xABu8; 1_000_000];
        let chunk = RawChunk::new(data.clone());
        assert_eq!(chunk.len(), 1_000_000);
        assert!(!chunk.is_empty());
        assert_eq!(chunk.bytes, data);
    }

    #[test]
    fn raw_chunk_single_byte() {
        let chunk = RawChunk::new(vec![0xFF]);
        assert_eq!(chunk.len(), 1);
        assert!(!chunk.is_empty());
    }

    #[test]
    fn raw_chunk_clone() {
        let chunk = RawChunk::new(vec![10, 20, 30]);
        let cloned = chunk.clone();
        assert_eq!(cloned.bytes, chunk.bytes);
        assert_eq!(cloned.content_id(), chunk.content_id());
    }

    #[test]
    fn raw_chunk_debug_format() {
        let chunk = RawChunk::new(vec![1, 2]);
        let debug = format!("{chunk:?}");
        assert!(debug.contains("RawChunk"));
    }

    #[test]
    fn raw_chunk_serde_roundtrip() {
        let chunk = RawChunk::new(vec![5, 10, 15, 20]);
        let json = serde_json::to_string(&chunk).unwrap();
        let deserialized: RawChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.bytes, chunk.bytes);
    }

    // ── Manifest edge cases ────────────────────────────────────────────────

    #[test]
    fn manifest_from_payload_chunk_size_one() {
        let payload = vec![1u8, 2, 3, 4, 5];
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&payload, 1);

        assert_eq!(manifest.total_len, 5);
        assert_eq!(manifest.chunk_size, 1);
        assert_eq!(manifest.chunk_count(), 5);
        assert_eq!(chunks.len(), 5);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.len(), 1);
            assert_eq!(chunk.bytes[0], (i + 1) as u8);
        }
    }

    #[test]
    fn manifest_reconstruct_empty_manifest() {
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        let reconstructed = manifest.reconstruct(&chunks).unwrap();
        assert!(reconstructed.is_empty());
    }

    #[test]
    fn manifest_reconstruct_unchecked_empty() {
        let (manifest, chunks) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        let reconstructed = manifest.reconstruct_unchecked(&chunks).unwrap();
        assert!(reconstructed.is_empty());
    }

    #[test]
    fn manifest_reconstruct_unchecked_missing_chunks() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);
        chunks.pop();
        let result = manifest.reconstruct_unchecked(&chunks);
        assert!(matches!(result, Err(ChunkError::MissingChunks { .. })));
    }

    #[test]
    fn manifest_reconstruct_unchecked_length_mismatch() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);
        // Replace last chunk with a shorter one to cause length mismatch
        let last_idx = chunks.len() - 1;
        chunks[last_idx] = RawChunk::new(vec![0u8; 1]);
        let result = manifest.reconstruct_unchecked(&chunks);
        assert!(matches!(result, Err(ChunkError::LengthMismatch { .. })));
    }

    #[test]
    fn manifest_chunk_size_at_evenly_divisible() {
        // Payload that is evenly divisible by chunk size
        let payload = vec![42u8; 256 * 1024]; // 256KB / 64KB = 4 even chunks
        let chunk_size = 64 * 1024;
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, chunk_size);

        assert_eq!(manifest.chunk_count(), 4);
        for i in 0..4 {
            assert_eq!(manifest.chunk_size_at(i).unwrap(), 64 * 1024);
        }
    }

    #[test]
    fn manifest_verify_hash_empty_payload() {
        let (manifest, _) = ChunkedObjectManifest::from_payload(&[], 64 * 1024);
        assert!(manifest.verify_hash(&[]));
        assert!(!manifest.verify_hash(&[1u8]));
    }

    #[test]
    fn manifest_payload_hash_deterministic() {
        let payload = vec![42u8; 10_000];
        let (m1, _) = ChunkedObjectManifest::from_payload(&payload, 1024);
        let (m2, _) = ChunkedObjectManifest::from_payload(&payload, 1024);
        assert_eq!(m1.payload_hash, m2.payload_hash);
    }

    #[test]
    fn manifest_payload_hash_changes_with_content() {
        let payload_a = vec![1u8; 1000];
        let payload_b = vec![2u8; 1000];
        let (m1, _) = ChunkedObjectManifest::from_payload(&payload_a, 1024);
        let (m2, _) = ChunkedObjectManifest::from_payload(&payload_b, 1024);
        assert_ne!(m1.payload_hash, m2.payload_hash);
    }

    #[test]
    fn manifest_chunk_ids_are_unique() {
        // Each chunk with different content should have a unique ID
        let payload: Vec<u8> = (0..1000_u32).map(|i| (i % 256) as u8).collect();
        let (manifest, _) = ChunkedObjectManifest::from_payload(&payload, 100);

        let mut seen = std::collections::HashSet::new();
        for id in &manifest.chunks {
            assert!(seen.insert(id), "duplicate chunk ID found");
        }
    }

    #[test]
    fn manifest_reconstruct_extra_chunks_rejected() {
        let payload = vec![1u8; 100];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 50);
        // Add an extra chunk
        chunks.push(RawChunk::new(vec![0u8; 50]));
        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::MissingChunks { expected: 2, got: 3 })));
    }

    #[test]
    fn manifest_reconstruct_length_mismatch_error() {
        let payload = vec![1u8; 200_000];
        let (manifest, mut chunks) = ChunkedObjectManifest::from_payload(&payload, 64 * 1024);
        // Replace a chunk with one of different length
        chunks[0] = RawChunk::new(vec![0u8; 1]);
        let result = manifest.reconstruct(&chunks);
        assert!(matches!(result, Err(ChunkError::LengthMismatch { .. })));
    }
}
