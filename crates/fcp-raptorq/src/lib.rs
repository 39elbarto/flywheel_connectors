//! FCP2 `RaptorQ` encoding/decoding and chunking policy.
//!
//! This module implements the `RaptorQ` fountain code encoding/decoding and chunked object
//! manifest functionality from `FCP_Specification_V2.md`.
//!
//! # Overview
//!
//! FCP2 uses `RaptorQ` as the universal encoding scheme because:
//! - Any K' symbols reconstruct the original (K' ≈ K × 1.002)
//! - No symbol is special - all are equally useful for reconstruction
//! - No coordination needed - receivers don't need to coordinate which symbols they receive
//! - Lost symbols don't require retransmission - any new symbol helps
//! - Multipath aggregation - symbols from any source contribute equally
//! - `DoS` resistant - no single symbol is critical
//! - Resumable without bookmarks - just accumulate more symbols
//!
//! # Chunking
//!
//! Large objects above `max_chunk_threshold` are represented as a manifest referencing
//! ordered `RawChunk` objects, enabling:
//! - Partial retrieval (first chunks first for streaming)
//! - Targeted repair (repair the missing chunk, not the whole multi-MB object)
//! - Dedupe across versions (chunk-level content addressing)
//! - Bounded memory (reconstruct one chunk at a time)
//! - Smoother streaming (progressive display)

#![forbid(unsafe_code)]

mod chunk;
mod config;
mod decode;
mod encode;
mod envelope;
mod error;
mod golden;

pub use chunk::{ChunkedObjectManifest, RawChunk};
pub use config::{RaptorQConfig, RaptorQPathProfile, RaptorQPreset};
pub use decode::{DecodeAdmissionController, DecodePermit, RaptorQDecoder};
pub use encode::{EncodingDecision, RaptorQEncoder};
pub use envelope::SymbolEnvelope;
pub use error::{ChunkError, DecodeError, EncodeError};
