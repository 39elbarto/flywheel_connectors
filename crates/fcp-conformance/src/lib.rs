//! FCP2 conformance tooling: golden vectors, interop helpers, and harness glue.
//!
//! This crate provides:
//! - **Golden vectors**: Canonical byte sequences for protocol structures
//! - **Interop helpers**: Test utilities for cross-implementation verification
//! - **Harness glue**: Integration points for E2E test frameworks
//!
//! # Golden Vectors
//!
//! Golden vectors provide byte-exact test cases for:
//! - FCPS frame encoding/decoding (data-plane)
//! - FCPC frame encoding/decoding (control-plane)
//! - Session handshake transcripts
//! - Capability token `COSE_Sign1` encoding
//! - Holder proof signable bytes
//! - Signing-bytes canonicalization and quorum signature sorting
//! - `ObjectId` keyed derivation
//! - Canonical CBOR payloads (schema hash prefix + CBOR bytes)
//!
//! These vectors are normative: if the implementation doesn't produce
//! these exact bytes, it's non-compliant.

#![forbid(unsafe_code)]

pub mod compliance;
pub mod harness;
pub mod interop;
pub mod reqcheck;
pub mod schemas;
pub mod vecgen;
pub mod vectors;

// Re-export vector types for convenience
pub use compliance::{
    CheckStatus, ComplianceFinding, ComplianceReport, DynamicCompliance, DynamicSuite,
    StaticCompliance, run_dynamic_checks,
};
pub use vectors::capability::CapabilityTokenGoldenVector;
pub use vectors::core::{CanonicalPayloadGoldenVector, ObjectIdGoldenVector};
pub use vectors::datagram::{DatagramErrorVector, DatagramGoldenVector, DatagramMacGoldenVector};
pub use vectors::fcpc::FcpcGoldenVector;
pub use vectors::fcps::FcpsGoldenVector;
pub use vectors::holder_proof::HolderProofGoldenVector;
pub use vectors::session::SessionGoldenVector;
pub use vectors::signing::{QuorumSortGoldenVector, SigningBytesGoldenVector};

// Re-export harness types for convenience
pub use harness::{
    LogCollector, LogEntry, MockClock, SharedMockClock, SimulatedNetwork, TestHarness, TestMeshNode,
};

// Re-export interop types for convenience
pub use interop::{
    CapabilityInteropTests, CrossZoneInteropTests, FcpcInteropTests, FcpsInteropTests,
    InteropTestSummary, SessionInteropTests, TestFailure, run_all as run_all_interop_tests,
};
