//! # `fcp-prelude` — canonical FCP type-import surface
//!
//! Bead: `flywheel_connectors-y1daf.1` (B.6) "Delete fcp-core as
//! public re-export crate; replace with fcp-prelude + deny-import
//! lints."
//!
//! ## Purpose
//!
//! `fcp-core` has accumulated as an unstable "junk drawer" of
//! re-exports during the FCP3 semantic carve-out. The long-term
//! design splits ownership across:
//!
//! | Owner crate     | Domain                                                          |
//! |-----------------|-----------------------------------------------------------------|
//! | `fcp-kernel`    | execution lifecycle (connectors, leases, operations, runtime)   |
//! | `fcp-policy`    | zone, capability, principal, trust, posture, provenance         |
//! | `fcp-evidence`  | audit chains, revocation, content-addressed objects, supply chain |
//! | `fcp-protocol`  | wire framing, sessions, transport (already separate)            |
//! | `fcp-cbor`      | canonical CBOR + schema hashes (already separate)               |
//! | `fcp-crypto`    | signatures, KEM, hashes, KDF (already separate)                 |
//!
//! `fcp-prelude` is the **single import surface** that consumers
//! should target. As types physically migrate from `fcp-core` into
//! their owner crates (currently they are still re-exported from
//! `fcp-core`'s private modules), the corresponding section in this
//! file switches its `pub use` source — consumers see no change.
//!
//! ## Migration plan (per bead y1daf.1 sequence)
//!
//! 1. **Audit fcp-core re-exports.** ✅ Done — see groupings below.
//!    Today fcp-core exposes ~30 internal modules + 4 external-crate
//!    re-exports. The full inventory is preserved in this file's
//!    section comments next to each `pub use`.
//! 2. **Add `#[deprecated]` to fcp-core re-exports.** ⏳ Deferred.
//!    Adding `#[deprecated]` to a wildcard re-export is not directly
//!    supported by rustc; it requires per-symbol re-exports in
//!    fcp-core, which is a separate refactor. Today, the soft-
//!    deprecation lives in `fcp-core/src/lib.rs` doc comments
//!    ("New code should import from the owner crate, not from
//!    fcp-core") and in this crate's documentation.
//! 3. **Update workspace consumers to import from `fcp-prelude`.**
//!    ⏳ Bulk migration work — `rg "use fcp_core::" crates/ connectors/`
//!    reports >1000 import sites across >1000 files. Tracked as
//!    follow-on `y1daf.1.x` per-crate-group beads. This PR ships
//!    the foundation; the migration is purely mechanical once the
//!    target crate (this one) exists.
//! 4. **Convert deprecation to lint-error.** ⏳ Gated on step 3.
//!    The workspace `clippy.toml` carries the `disallowed-types`
//!    config commented as TODO so the eventual flip is one-line.
//! 5. **Move fcp-core to archive.** ⏳ Gated on step 3. Per AGENTS.md
//!    no-deletion rule, fcp-core would be MOVED to
//!    `crates/fcp-core-junk-drawer-archive/`, never deleted.
//! 6. **Create `fcp-prelude`.** ✅ This crate.
//!
//! ## Import contract for new code
//!
//! ```ignore
//! // ❌ Discouraged (will eventually be lint-denied):
//! use fcp_core::{CapabilityToken, ZoneId};
//!
//! // ✅ Preferred:
//! use fcp_prelude::{CapabilityToken, ZoneId};
//! ```
//!
//! ## Re-export structure
//!
//! Today this crate re-exports the entire `fcp-core` public surface
//! via a single `pub use fcp_core::*` because `fcp-core`'s internal
//! modules are private (`mod`, not `pub mod`). The semantic-group
//! commentary lives below — when a group migrates to its owner
//! crate, the wildcard for that group is replaced with explicit
//! `pub use fcp_kernel::{...}` / `pub use fcp_policy::{...}` /
//! `pub use fcp_evidence::{...}` per the ownership map above.
//!
//! Smoke tests in `mod tests` exercise one representative type per
//! ownership group so a future migration that breaks the
//! consumer-visible contract is caught immediately.

#![forbid(unsafe_code)]

// ═══════════════════════════════════════════════════════════════════════
// Top-level re-export surface
// ═══════════════════════════════════════════════════════════════════════
//
// Every public symbol fcp-core currently exposes is reachable through
// fcp_prelude. The semantic groupings below DOCUMENT the eventual
// owner crate per category — when a group migrates, the wildcard
// here will be replaced with an explicit per-symbol `pub use` from
// that owner crate, leaving every consumer's `use fcp_prelude::X`
// untouched.
//
// Acceptable shared-primitive residue (will stay in fcp-core long-term):
//   - error::*                        // FcpError, FcpResult
//   - tool_schema (public module)     // tool/schema primitives
//   - util (public module)            // generic helpers
//
// Assigned to fcp-kernel (execution lifecycle):
//   - connector::*, connector_artifacts::*, connector_descriptors::*,
//     connector_state::*              // connector identity + state
//   - crdt::*                         // replicated state primitives
//   - credential::*                   // credential IDs + validation
//   - event::*                        // connector / system events
//   - health::*                       // connector + system health rollups
//   - lease::*                        // lease tokens + purposes
//   - lifecycle::*                    // lifecycle state machine
//   - operation::*                    // operation IDs / status / metadata
//   - pem (public module)             // PEM encoding helpers
//   - protocol::*                     // shared wire-protocol primitives
//   - provisioning::*                 // bootstrap / provisioning types
//   - quorum::*                       // quorum signatures + node identity
//   - ratelimit::*                    // rate-limit scope + classification
//   - release::*                      // release artifact descriptors
//   - secret::*                       // secret access tokens + redaction
//
// Assigned to fcp-policy (zone, capability, trust):
//   - capability::*                   // CapabilityToken, ZoneId, PrincipalId
//   - enforcement::*                  // EnforcementCheckOrder + outcomes
//   - enrollment::*                   // device enrollment workflow
//   - pcs (public module)             // Post-Compromise Security
//   - policy::*                       // ZonePolicy, ApprovalPolicy, decision
//   - posture::*                      // PostureAttestation + requirements
//   - provenance::*                   // provenance + taint + label adjustments
//   - zone_keys::*                    // ZoneKey, manifests, key rings
//
// Assigned to fcp-evidence (audit, revocation, objects):
//   - audit::*                        // AuditEvent + chain primitives
//   - checkpoint::*                   // ZoneCheckpoint snapshots
//   - object::*                       // ObjectId, ObjectHeader, refs
//   - revocation::*                   // RevocationRegistry + push messages
//   - supply_chain::*                 // SBOM, attestation, supply-chain types
//
// External re-exports the legacy fcp-core barrel exposed:
//   - async_trait::async_trait
//   - chrono::{DateTime, Utc}
//   - uuid::Uuid

pub use fcp_core::*;

// External crate re-exports (mirror fcp-core's compatibility surface).
pub use async_trait::async_trait;
pub use chrono::{DateTime, Utc};
pub use fcp_crypto::{CredentialIdHash, SecretFetchError, SecretFetchHook, ZeroizingSecret};
pub use uuid::Uuid;

// ── Production-hardening helpers (ptb6n) ───────────────────────────
//
// `log_redaction` is a tactical addition for the H.3 audit closure:
// connector retry-logging code historically logged full request URLs
// at debug level, which can carry user/account/resource IDs in the
// path or query. The [`log_redaction::redact_url`] helper produces an
// operator-safe rendering (scheme://host + path-prefix only — no
// query, no fragment, opaque-id path components replaced with
// `<id>`). Future production-hardening cycles may move this into a
// dedicated `fcp-redaction` crate; today it lives in fcp-prelude
// because every workspace consumer (connectors + platform) already
// imports the prelude after y1daf.1+orw5s.
pub mod log_redaction;

#[cfg(test)]
mod tests {
    //! Smoke tests proving the re-export surface compiles and
    //! resolves the canonical types correctly. If a future PR
    //! switches the wildcard `pub use fcp_core::*` (or any per-
    //! group replacement) and the type signature drifts, these
    //! tests fail and force the migrating PR to update the
    //! consumer-visible contract in lockstep.
    //!
    //! These tests are NOT comprehensive — they exercise one
    //! representative type per ownership group. Comprehensive
    //! coverage of every re-exported symbol lives in the owner
    //! crates' own test suites.

    use super::*;

    #[test]
    fn lifecycle_group_resolves_canonical_types() {
        let _: ConnectorId = ConnectorId::from_static("github:request_response:1.0.0");
        let _: OperationId = OperationId::new("github.issues.create").expect("valid op id");
    }

    #[test]
    fn policy_group_resolves_canonical_types() {
        let _: ZoneId = ZoneId::work();
        let _: PrincipalId = PrincipalId::new("alice").expect("valid principal id");
        let _: SafetyTier = SafetyTier::Safe;
        let _: TrustLevel = TrustLevel::Owner;
    }

    #[test]
    fn evidence_group_resolves_canonical_types() {
        let _: ObjectId = ObjectId::from_bytes([0u8; 32]);
        let _: SbomFormat = SbomFormat::Cyclonedx;
    }

    #[test]
    fn shared_primitive_residue_resolves_error_type() {
        // FcpError is the canonical workspace-wide error type.
        let err = FcpError::ResourceNotAllowed {
            resource: "test".to_string(),
        };
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn external_re_exports_resolve_async_chrono_uuid() {
        // Compile-time witnesses. If a future Rust toolchain bumps
        // an external crate's API and breaks one of these, the
        // failure surfaces here as a single localized test rather
        // than at every consumer site.
        let _: DateTime<Utc> = chrono::Utc::now();
        let _: Uuid = Uuid::nil();
    }

    #[test]
    fn crypto_re_exports_resolve_zeroizing_secret() {
        let secret = ZeroizingSecret::from("prelude-secret");
        assert_eq!(secret.as_bytes(), b"prelude-secret");
        assert_eq!(secret.to_string(), "ZeroizingSecret(<redacted, len=14>)");
    }

    #[test]
    fn crypto_re_exports_resolve_secret_fetch_contract() {
        fn assert_secret_fetch_hook<T: SecretFetchHook + ?Sized>() {}

        let error = SecretFetchError::not_found("prelude-secret-id");
        let rendered = error.to_string();

        assert_secret_fetch_hook::<dyn SecretFetchHook>();
        assert!(!rendered.contains("prelude-secret-id"));
        assert_eq!(
            CredentialIdHash::from_credential_id("prelude-secret-id")
                .as_str()
                .len(),
            64
        );
    }

    #[test]
    fn quorum_group_resolves_node_identity_types() {
        let _: NodeId = NodeId::new("test-node");
        let _: NodeSignature =
            NodeSignature::new(NodeId::new("test-node"), [0u8; 64], 1_700_000_000);
    }

    #[test]
    fn rate_limit_scope_is_reachable() {
        let _: OperationRateLimitScope = OperationRateLimitScope::PerConnector;
    }

    #[test]
    fn audit_event_is_reachable_via_prelude() {
        // AuditEvent is the workspace-wide audit primitive.
        let _ = std::mem::size_of::<AuditEvent>();
    }
}
