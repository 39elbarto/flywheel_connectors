//! # fcp-auth-schema
//!
//! Typed capability-token claim schema shared between `fcp-crypto`
//! (builder side) and `fcp-core` (verifier side). Owns the single
//! source of truth for the auth-critical claim layout.
//!
//! ## Background
//!
//! Before this crate existed, `fcp-crypto::cose::CapabilityTokenBuilder`
//! and `fcp-core::CapabilityVerifier` each knew about FCP claim labels
//! by integer constant, and drift between them was caught only by
//! runtime tests (or worse, by a verification failure in production).
//!
//! This crate owns:
//!
//! 1. The CBOR integer label constants (`cwt_claims`, `fcp2_claims`)
//! 2. The typed `AuthClaims` struct
//! 3. Canonical-CBOR serialization (deterministic, sorted by label
//!    integer) and its inverse.
//!
//! `fcp-crypto` consumes `AuthClaims` to build COSE_Sign1 token bytes.
//! `fcp-core` parses signed-bytes payload into `AuthClaims` to run
//! capability verification against typed fields.
//!
//! ## Dependency direction
//!
//! ```text
//! fcp-auth-schema ──┬── fcp-crypto
//!                   │
//!                   └── fcp-core (also depends on fcp-crypto)
//! ```
//!
//! No cycles. `fcp-auth-schema` has no dependency on `fcp-crypto` or
//! `fcp-core`; it is the bottom of the auth stack.
//!
//! See also:
//! - `docs/architecture/adr/8n0rm-claim-schema-inventory.md`
//! - `docs/architecture/adr/8n0rm-typed-claims.md`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod claims;
pub mod labels;

pub use claims::{AuthClaims, SchemaError};
