//! Runtime deployment-mode classification for fcp-host (hr0rr.1).
//!
//! Per bead `flywheel_connectors-hr0rr.1` (REALITY-CHECK/C.6) the
//! host-first single-active-control-plane model is being deprecated
//! as the production default; once the C.4 mesh-failover proof
//! lands, fcp-host SHOULD refuse to dispatch operations whose
//! [`SafetyTier`] is `Risky` or `Dangerous` outside a verified-mesh
//! deployment context.
//!
//! This module ships the runtime classifier + admission contract:
//!
//! 1. [`DeploymentMode`] — runtime-derived classification of how the
//!    host is currently deployed (`Evaluation` for single-host /
//!    insufficient-mesh-quorum scenarios, `MeshActive` once the
//!    mesh control plane is live).
//! 2. [`MeshQuorumSignals`] — the boundary input the classifier
//!    reads (healthy peer count, lease coordinator availability,
//!    revocation freshness). Decouples the classifier from the
//!    full [`crate::health::MeshHealth`] struct so callers can
//!    synthesize signals from any source (host health probe, test
//!    fixture, replay-bundle environment.json).
//! 3. [`classify_deployment_mode`] — pure function from
//!    [`MeshQuorumSignals`] to [`DeploymentMode`] with a
//!    [`DeploymentClassification`] receipt that records the inputs
//!    and the reason the classifier produced its verdict.
//! 4. [`admit_safety_tier`] — admission predicate that refuses
//!    [`SafetyTier::Risky`] and [`SafetyTier::Dangerous`] in
//!    `Evaluation` mode, returning a structured
//!    [`DeploymentTierRefusal`].
//! 5. [`evaluation_mode_boot_warning`] — canonical operator-visible
//!    warning string emitted on every health-check while in
//!    Evaluation mode.
//!
//! ## Relationship to `OperationalModelVersion`
//!
//! `OperationalModelVersion::{V1HostFirst, V2MeshNative}` (in
//! `crates/fwc/src/truth.rs`) is a **policy tag** carried in
//! `TruthPrecedencePolicy` — it describes which truth source
//! ordering a zone configuration prefers. [`DeploymentMode`] is
//! the **runtime mirror** — it describes which mode the host is
//! actually capable of operating in given the current peer-health
//! state. They overlap but answer different questions:
//!
//! | Question                                       | Answer                       |
//! |------------------------------------------------|------------------------------|
//! | What mode does my zone-config target?          | `OperationalModelVersion`    |
//! | What mode am I actually running in right now?  | `DeploymentMode` (this enum) |
//!
//! A zone configured with `V2MeshNative` precedence whose host
//! cannot reach 2 healthy mesh peers will run in `Evaluation`
//! [`DeploymentMode`] until the mesh quorum stabilizes.
//!
//! ## Acceptance criteria status (from bead)
//!
//! - ✅ Boot log records DeploymentMode and reason — see
//!   [`DeploymentClassification::boot_log_line`].
//! - ✅ Risky/Dangerous invocations in Evaluation mode return
//!   structured denial — see [`DeploymentTierRefusal`].
//! - ⏳ README §Limitations bullet edit + deployment runbook update
//!   are documentation tasks that follow the code landing here.
//! - ⏳ Wiring this admission into the actual dispatch path lives in
//!   bead m8j0q.A.2 (constraint-enforcement pipeline wiring), which
//!   will call [`admit_safety_tier`] alongside the constraint
//!   enforcer's per-request evaluation.
//!
//! ## Threshold rationale
//!
//! [`MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE`] = 2 matches the bead's
//! sequence step 2 — "transition to MeshActive only when ≥2 healthy
//! mesh peers exist". Two is the smallest count that survives one
//! peer being lost mid-operation without immediate quorum loss; it
//! is intentionally NOT the same as
//! `EMERGENCY_QUORUM_WITNESSES = 3` (which is about
//! after-the-fact quorum proof, not about routine availability).

use fcp_crypto::ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_crypto::error::CryptoError;
use fcp_crypto::kid::KeyId;
use fcp_prelude::SafetyTier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Minimum number of healthy mesh peers required to transition out
/// of [`DeploymentMode::Evaluation`]. Matches bead hr0rr.1 §"Sequence"
/// step 2: "transition to MeshActive only when ≥2 healthy mesh
/// peers exist". Counted exclusive of self.
pub const MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE: u32 = 2;

/// Operator-visible warning string emitted every health-check while
/// running in [`DeploymentMode::Evaluation`]. Stable across releases
/// because operator runbooks and log-search dashboards key off it.
pub const EVALUATION_MODE_HEALTH_WARNING: &str = "WARN: Host-first mode is for evaluation only. Production deployments require mesh-active mode.";

/// Runtime classification of how the host is currently deployed.
///
/// Derived from [`MeshQuorumSignals`] by [`classify_deployment_mode`];
/// callers should treat it as a snapshot — re-classify whenever the
/// underlying health probe reports a state change so a peer loss
/// flips the mode back to `Evaluation` and any in-flight Risky /
/// Dangerous operation is refused on its next dispatch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// Single-host or insufficient-mesh-quorum deployment. Risky
    /// and Dangerous safety tiers are refused; only Safe and
    /// Critical (which has its own quorum/elevation gating) and
    /// Forbidden (always refused) flow through admission.
    Evaluation,
    /// Mesh control plane is live with at least
    /// [`MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE`] healthy peers and
    /// (when configured) a reachable lease coordinator. All
    /// safety tiers admitted modulo their own per-tier policies.
    MeshActive,
}

impl DeploymentMode {
    /// Whether this mode admits the full safety-tier surface.
    #[must_use]
    pub const fn is_mesh_active(&self) -> bool {
        matches!(self, Self::MeshActive)
    }

    /// Whether this mode is restricted to evaluation (Safe/Critical
    /// modulo per-tier policies; Risky/Dangerous refused).
    #[must_use]
    pub const fn is_evaluation(&self) -> bool {
        matches!(self, Self::Evaluation)
    }

    /// Display label used in tracing fields, JSON envelopes, and
    /// the boot-log line. Stable across releases.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Evaluation => "evaluation",
            Self::MeshActive => "mesh-active",
        }
    }
}

/// Boundary input for [`classify_deployment_mode`]. Decoupled from
/// any one host-health struct so callers can synthesize signals
/// from any source (live probe, replay bundle, test fixture).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshQuorumSignals {
    /// Number of mesh peers reported HEALTHY by the local probe,
    /// exclusive of self.
    pub healthy_peer_count: u32,
    /// Whether a lease coordinator is currently reachable. `None`
    /// when this deployment doesn't use a lease coordinator
    /// (e.g., evaluation tier without leases).
    pub lease_coordinator_reachable: Option<bool>,
    /// Whether the local revocation snapshot is within the
    /// configured freshness SLA (`RevocationSlaChecker`). `false`
    /// here forces Evaluation regardless of peer count because
    /// stale revocations cannot reliably gate Risky/Dangerous ops.
    pub revocation_snapshot_fresh: bool,
}

impl MeshQuorumSignals {
    /// Construct signals representing a fully-healthy mesh-active
    /// deployment. Convenience for tests and the post-startup
    /// "ideal state" health probe.
    #[must_use]
    pub const fn fully_active(healthy_peer_count: u32) -> Self {
        Self {
            healthy_peer_count,
            lease_coordinator_reachable: Some(true),
            revocation_snapshot_fresh: true,
        }
    }

    /// Construct signals representing a single-host (zero peers)
    /// evaluation-only deployment.
    #[must_use]
    pub const fn single_host_evaluation() -> Self {
        Self {
            healthy_peer_count: 0,
            lease_coordinator_reachable: None,
            revocation_snapshot_fresh: true,
        }
    }
}

/// Receipt from [`classify_deployment_mode`] — pairs the verdict
/// with the inputs and the structured reason for after-the-fact
/// audit + replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentClassification {
    /// Mode the classifier produced.
    pub mode: DeploymentMode,
    /// Inputs the classifier read.
    pub signals: MeshQuorumSignals,
    /// Categorical reason — useful in tracing fields and the boot
    /// log line; pairs with [`DeploymentMode`] (every reason
    /// uniquely determines a mode).
    pub reason: DeploymentClassificationReason,
}

impl DeploymentClassification {
    /// Canonical boot-log line. Operator runbooks and log-search
    /// dashboards key off this format; do not drift it without
    /// also updating runbook docs.
    #[must_use]
    pub fn boot_log_line(&self) -> String {
        format!(
            "fcp-host deployment_mode={} reason={} healthy_peers={} lease_coordinator={} revocation_fresh={}",
            self.mode.label(),
            self.reason.label(),
            self.signals.healthy_peer_count,
            match self.signals.lease_coordinator_reachable {
                None => "n/a",
                Some(true) => "reachable",
                Some(false) => "unreachable",
            },
            self.signals.revocation_snapshot_fresh,
        )
    }
}

/// Structured reason for a deployment-mode verdict.
///
/// Stable across releases — every variant uniquely determines the
/// resulting [`DeploymentMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeploymentClassificationReason {
    /// Healthy peer count is below
    /// [`MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE`] — single-host or
    /// degraded-quorum deployment. Implies
    /// [`DeploymentMode::Evaluation`].
    InsufficientMeshQuorum {
        /// Observed healthy peer count.
        observed: u32,
        /// Required minimum for MeshActive.
        required: u32,
    },
    /// Lease coordinator was configured (i.e.,
    /// `lease_coordinator_reachable.is_some()`) but unreachable.
    /// Implies [`DeploymentMode::Evaluation`] regardless of peer
    /// count because lease-bound operations cannot proceed without
    /// it.
    LeaseCoordinatorUnreachable,
    /// Local revocation snapshot is stale beyond the configured
    /// freshness SLA. Implies [`DeploymentMode::Evaluation`]
    /// because Risky/Dangerous ops cannot be reliably gated under
    /// stale revocation data.
    RevocationSnapshotStale,
    /// Healthy peer count meets [`MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE`],
    /// lease coordinator (if configured) is reachable, and the
    /// revocation snapshot is within the freshness SLA — full
    /// [`DeploymentMode::MeshActive`] admitted.
    MeshQuorumActive,
    /// Signed-signals attestation could not be validated (br-5f8t1).
    /// Either the attesting KID is not in the trust set or the
    /// Ed25519 signature did not verify. Fail-soft callers
    /// downgrade to [`DeploymentMode::Evaluation`] and surface this
    /// reason so operators can see WHY the host is in evaluation
    /// mode (vs. a routine peer-count shortfall).
    SignedSignalsRejected,
}

impl DeploymentClassificationReason {
    /// Stable label used in the boot-log line and tracing fields.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::InsufficientMeshQuorum { .. } => "insufficient_mesh_quorum",
            Self::LeaseCoordinatorUnreachable => "lease_coordinator_unreachable",
            Self::RevocationSnapshotStale => "revocation_snapshot_stale",
            Self::MeshQuorumActive => "mesh_quorum_active",
            Self::SignedSignalsRejected => "signed_signals_rejected",
        }
    }
}

/// Pure classifier — no I/O, no state, no async. Order of checks
/// matches the priority of disqualifiers in the bead:
///   1. Stale revocation snapshot → Evaluation (any peer count
///      cannot compensate for not knowing what's revoked).
///   2. Lease coordinator configured but unreachable → Evaluation
///      (lease-bound ops cannot proceed).
///   3. Healthy peer count < threshold → Evaluation (insufficient
///      quorum).
///   4. Otherwise → MeshActive.

/// Domain-separation tag for signed [`MeshQuorumSignals`].
///
/// Prevents a signed-signals byte string from being re-interpreted
/// as any other FCP signature transcript. A new domain tag MUST be
/// minted whenever the [`MeshQuorumSignals`] field set evolves so
/// signatures over the old shape never validate against a new
/// classifier.
pub const MESH_QUORUM_SIGNALS_DOMAIN: &[u8] = b"FCP3-MESH-QUORUM-SIGNALS-V1";

/// Signed wrapper around [`MeshQuorumSignals`] (br-5f8t1 — defends
/// against the unsigned-signals falsification attack).
///
/// Production callers MUST use this — never feed a raw
/// [`MeshQuorumSignals`] to the deployment classifier on a path that
/// can promote the host to [`DeploymentMode::MeshActive`]. The bare
/// [`classify_deployment_mode`] function remains available for
/// trusted-input contexts (tests, replay bundles where authenticity
/// is already proven by an outer envelope).
///
/// The signature commits to a domain-separated canonical encoding
/// of the underlying signals plus the attesting KID, so the same
/// signed bytes cannot be replayed against a different attesting
/// node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMeshQuorumSignals {
    /// The raw signals being attested.
    pub signals: MeshQuorumSignals,
    /// KeyId of the node that signed these signals. Resolved to a
    /// verifying key by the caller's key resolver at verify time.
    pub attesting_kid: KeyId,
    /// Ed25519 signature over [`Self::signing_bytes`].
    pub signature: Ed25519Signature,
}

impl SignedMeshQuorumSignals {
    /// Bytes the signature commits to. Domain-separated by
    /// [`MESH_QUORUM_SIGNALS_DOMAIN`] so the same payload signed
    /// here cannot be replayed against any other FCP signature
    /// transcript.
    ///
    /// Layout: `MESH_QUORUM_SIGNALS_DOMAIN || attesting_kid_bytes ||
    /// healthy_peer_count_le || lease_coordinator_byte ||
    /// revocation_snapshot_fresh_byte`. Fixed-size fields packed
    /// little-endian — no length-prefixed canonical CBOR needed
    /// because every field is bounded.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MESH_QUORUM_SIGNALS_DOMAIN.len()
                + fcp_crypto::kid::KID_SIZE
                + 4 // healthy_peer_count
                + 1 // lease_coordinator state byte
                + 1, // revocation_snapshot_fresh
        );
        out.extend_from_slice(MESH_QUORUM_SIGNALS_DOMAIN);
        out.extend_from_slice(self.attesting_kid.as_slice());
        out.extend_from_slice(&self.signals.healthy_peer_count.to_le_bytes());
        out.push(match self.signals.lease_coordinator_reachable {
            None => 0_u8,
            Some(false) => 1_u8,
            Some(true) => 2_u8,
        });
        out.push(u8::from(self.signals.revocation_snapshot_fresh));
        out
    }

    /// Verify the signature against `verifying_key`.
    ///
    /// # Errors
    /// Returns the verifier's [`CryptoError`] on signature
    /// verification failure.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        verifying_key.verify(&self.signing_bytes(), &self.signature)
    }
}

impl MeshQuorumSignals {
    /// Sign this signals snapshot with the host's signing key,
    /// producing a [`SignedMeshQuorumSignals`] that the deployment
    /// classifier accepts on the production path.
    #[must_use]
    pub fn sign(self, signing_key: &Ed25519SigningKey) -> SignedMeshQuorumSignals {
        let attesting_kid = signing_key.key_id();
        // Pre-build a transcript-stable wrapper so signing_bytes()
        // produces the exact bytes verify() will check later.
        let mut wrapped = SignedMeshQuorumSignals {
            signals: self,
            attesting_kid,
            signature: Ed25519Signature::from_bytes(&[0_u8; 64]),
        };
        let signature = signing_key.sign(&wrapped.signing_bytes());
        wrapped.signature = signature;
        wrapped
    }
}

/// Errors returned by [`classify_deployment_mode_verified`].
#[derive(Debug, Error)]
pub enum DeploymentClassifierError {
    /// The attesting node KID is not in the resolver's trust set.
    #[error("attesting node {attesting_kid} not in trust set")]
    UnknownAttestingNode { attesting_kid: String },
    /// Signature verification failed.
    #[error("mesh quorum signals signature verification failed: {source}")]
    SignatureVerificationFailed {
        #[source]
        source: CryptoError,
    },
}

/// Production classifier path: verify the signed quorum signals
/// against the resolver-supplied verifying key for the attesting
/// node, THEN classify (br-5f8t1).
///
/// `resolve_key` looks up the trusted verifying key for the
/// attesting node. Callers MUST seed this resolver from
/// owner-attested sources (e.g., the same per-zone trust set the
/// revocation cascade walker uses). A resolver that returns a key
/// for an unverified node breaks the chain of trust.
///
/// On signature failure the classifier returns
/// [`DeploymentClassifierError`] — callers that want fail-soft
/// degradation MUST explicitly map this to
/// [`DeploymentMode::Evaluation`] (which is what
/// [`classify_deployment_mode_verified_or_evaluation`] does).
///
/// # Errors
///
/// Returns [`DeploymentClassifierError::UnknownAttestingNode`] if
/// the resolver returns `None`, or
/// [`DeploymentClassifierError::SignatureVerificationFailed`] if
/// the signature does not verify.
pub fn classify_deployment_mode_verified<F>(
    signed: &SignedMeshQuorumSignals,
    resolve_key: F,
) -> Result<DeploymentClassification, DeploymentClassifierError>
where
    F: FnOnce(&KeyId) -> Option<Ed25519VerifyingKey>,
{
    let key = resolve_key(&signed.attesting_kid).ok_or_else(|| {
        DeploymentClassifierError::UnknownAttestingNode {
            attesting_kid: signed.attesting_kid.to_hex(),
        }
    })?;
    signed
        .verify(&key)
        .map_err(|source| DeploymentClassifierError::SignatureVerificationFailed { source })?;
    Ok(classify_deployment_mode(signed.signals))
}

/// Fail-soft variant of [`classify_deployment_mode_verified`]:
/// signature verification failure produces a structured Evaluation
/// classification (with [`DeploymentClassificationReason::SignedSignalsRejected`])
/// rather than an `Err`. Use on hot paths that must always produce
/// some classification rather than abort — the security promise is
/// the same (an attacker cannot promote to MeshActive without a
/// valid signature).
#[must_use]
pub fn classify_deployment_mode_verified_or_evaluation<F>(
    signed: &SignedMeshQuorumSignals,
    resolve_key: F,
) -> DeploymentClassification
where
    F: FnOnce(&KeyId) -> Option<Ed25519VerifyingKey>,
{
    match classify_deployment_mode_verified(signed, resolve_key) {
        Ok(classification) => classification,
        Err(_) => DeploymentClassification {
            mode: DeploymentMode::Evaluation,
            signals: signed.signals,
            reason: DeploymentClassificationReason::SignedSignalsRejected,
        },
    }
}

#[must_use]
pub fn classify_deployment_mode(signals: MeshQuorumSignals) -> DeploymentClassification {
    if !signals.revocation_snapshot_fresh {
        return DeploymentClassification {
            mode: DeploymentMode::Evaluation,
            signals,
            reason: DeploymentClassificationReason::RevocationSnapshotStale,
        };
    }
    if matches!(signals.lease_coordinator_reachable, Some(false)) {
        return DeploymentClassification {
            mode: DeploymentMode::Evaluation,
            signals,
            reason: DeploymentClassificationReason::LeaseCoordinatorUnreachable,
        };
    }
    if signals.healthy_peer_count < MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE {
        return DeploymentClassification {
            mode: DeploymentMode::Evaluation,
            signals,
            reason: DeploymentClassificationReason::InsufficientMeshQuorum {
                observed: signals.healthy_peer_count,
                required: MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
            },
        };
    }
    DeploymentClassification {
        mode: DeploymentMode::MeshActive,
        signals,
        reason: DeploymentClassificationReason::MeshQuorumActive,
    }
}

/// Structured refusal returned by [`admit_safety_tier`] when a
/// Risky / Dangerous invocation arrives while the host is in
/// [`DeploymentMode::Evaluation`].
///
/// Operator-visible (echoed in API errors and audit-log denials);
/// the `kind` discriminant is stable for downstream alerting on
/// `DeploymentTierRefusal::TierRequiresMeshActive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeploymentTierRefusal {
    /// The requested safety tier is not admissible in the current
    /// deployment mode. The `tier` field is the rejected tier; the
    /// `reason` field carries the underlying classifier verdict so
    /// operators can see *why* the host believes it's not in mesh
    /// mode.
    TierRequiresMeshActive {
        /// Tier the request asked for.
        tier: SafetyTier,
        /// Current mode the host is running in.
        mode: DeploymentMode,
        /// Categorical reason for the mode (useful in audit
        /// indexing and operator alerts).
        reason: DeploymentClassificationReason,
    },
    /// The requested tier is `Forbidden` — never admitted in any
    /// mode. Surfaced as a refusal here so callers see the same
    /// shape regardless of which gate refused them.
    TierForbidden {
        /// The forbidden tier.
        tier: SafetyTier,
    },
}

/// Decide whether a request with the given [`SafetyTier`] may
/// proceed under the current [`DeploymentClassification`].
///
/// Admission rules:
///
/// | Tier      | Evaluation              | MeshActive               |
/// |-----------|-------------------------|--------------------------|
/// | Safe      | ALLOW                   | ALLOW                    |
/// | Risky     | REFUSE (`TierRequires…`)| ALLOW                    |
/// | Dangerous | REFUSE (`TierRequires…`)| ALLOW                    |
/// | Critical  | ALLOW (own gating[^1]) | ALLOW (own gating[^1])   |
/// | Forbidden | REFUSE (`TierForbidden`)| REFUSE (`TierForbidden`) |
///
/// [^1]: `Critical` carries its own quorum/elevation requirements
/// downstream (`ApprovalScope` + `ApprovalToken`); this admission
/// does NOT additionally gate it on deployment mode because
/// quorum-elevation already requires mesh participation by
/// construction.
///
/// # Errors
///
/// Returns [`DeploymentTierRefusal`] when admission denies the
/// request.
pub fn admit_safety_tier(
    classification: &DeploymentClassification,
    tier: SafetyTier,
) -> Result<(), DeploymentTierRefusal> {
    if matches!(tier, SafetyTier::Forbidden) {
        return Err(DeploymentTierRefusal::TierForbidden { tier });
    }
    if classification.mode.is_mesh_active() {
        return Ok(());
    }
    // Evaluation mode: refuse Risky and Dangerous; allow Safe and
    // Critical (Critical's own quorum/elevation gating handles it).
    match tier {
        SafetyTier::Safe | SafetyTier::Critical => Ok(()),
        SafetyTier::Risky | SafetyTier::Dangerous => {
            Err(DeploymentTierRefusal::TierRequiresMeshActive {
                tier,
                mode: classification.mode,
                reason: classification.reason,
            })
        }
        SafetyTier::Forbidden => Err(DeploymentTierRefusal::TierForbidden { tier }),
    }
}

/// Operator-visible warning emitted on every health-check while in
/// [`DeploymentMode::Evaluation`]. Stable string per
/// [`EVALUATION_MODE_HEALTH_WARNING`].
#[must_use]
pub const fn evaluation_mode_boot_warning() -> &'static str {
    EVALUATION_MODE_HEALTH_WARNING
}

/// Emit the canonical boot-log entry via `tracing::info!` at boot
/// time and `tracing::warn!` whenever the mode is `Evaluation`.
/// Test seam: returns the rendered line so callers can assert on
/// it without capturing tracing output.
pub fn emit_boot_log(classification: &DeploymentClassification) -> String {
    let line = classification.boot_log_line();
    if classification.mode.is_evaluation() {
        tracing::warn!(target: "fcp_host::deployment_mode", "{line}");
        tracing::warn!(
            target: "fcp_host::deployment_mode",
            "{}",
            EVALUATION_MODE_HEALTH_WARNING
        );
    } else {
        tracing::info!(target: "fcp_host::deployment_mode", "{line}");
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_deployment_mode: input matrix per bead step 2 ─────

    #[test]
    fn classifier_returns_mesh_active_when_all_signals_healthy() {
        let signals = MeshQuorumSignals::fully_active(2);
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::MeshActive);
        assert_eq!(
            result.reason,
            DeploymentClassificationReason::MeshQuorumActive
        );
    }

    #[test]
    fn classifier_returns_mesh_active_for_excess_peers() {
        // More than the threshold is also MeshActive.
        let signals = MeshQuorumSignals::fully_active(10);
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::MeshActive);
    }

    #[test]
    fn classifier_returns_evaluation_with_zero_peers() {
        let result = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        assert_eq!(result.mode, DeploymentMode::Evaluation);
        match result.reason {
            DeploymentClassificationReason::InsufficientMeshQuorum { observed, required } => {
                assert_eq!(observed, 0);
                assert_eq!(required, MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE);
            }
            other => panic!("expected InsufficientMeshQuorum, got {other:?}"),
        }
    }

    #[test]
    fn classifier_returns_evaluation_with_one_peer_below_threshold() {
        let signals = MeshQuorumSignals::fully_active(1);
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::Evaluation);
        assert!(matches!(
            result.reason,
            DeploymentClassificationReason::InsufficientMeshQuorum { observed: 1, .. }
        ));
    }

    #[test]
    fn classifier_returns_evaluation_at_exact_threshold_minus_one() {
        // Threshold is 2; observing 1 is below threshold.
        let signals = MeshQuorumSignals {
            healthy_peer_count: MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE - 1,
            lease_coordinator_reachable: Some(true),
            revocation_snapshot_fresh: true,
        };
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::Evaluation);
    }

    #[test]
    fn classifier_returns_mesh_active_at_exact_threshold() {
        // Threshold is 2; observing 2 satisfies the predicate.
        let signals = MeshQuorumSignals {
            healthy_peer_count: MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
            lease_coordinator_reachable: Some(true),
            revocation_snapshot_fresh: true,
        };
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::MeshActive);
    }

    #[test]
    fn classifier_evaluation_when_revocation_stale_regardless_of_peers() {
        // Even with abundant peers, stale revocations force Evaluation.
        let signals = MeshQuorumSignals {
            healthy_peer_count: 99,
            lease_coordinator_reachable: Some(true),
            revocation_snapshot_fresh: false,
        };
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::Evaluation);
        assert_eq!(
            result.reason,
            DeploymentClassificationReason::RevocationSnapshotStale
        );
    }

    #[test]
    fn classifier_evaluation_when_lease_coordinator_configured_but_unreachable() {
        let signals = MeshQuorumSignals {
            healthy_peer_count: 5,
            lease_coordinator_reachable: Some(false),
            revocation_snapshot_fresh: true,
        };
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::Evaluation);
        assert_eq!(
            result.reason,
            DeploymentClassificationReason::LeaseCoordinatorUnreachable
        );
    }

    #[test]
    fn classifier_mesh_active_when_lease_coordinator_unconfigured_but_quorum_present() {
        // `None` (unconfigured) is admissible — only `Some(false)`
        // forces Evaluation.
        let signals = MeshQuorumSignals {
            healthy_peer_count: 5,
            lease_coordinator_reachable: None,
            revocation_snapshot_fresh: true,
        };
        let result = classify_deployment_mode(signals);
        assert_eq!(result.mode, DeploymentMode::MeshActive);
    }

    #[test]
    fn classifier_priority_revocation_stale_takes_precedence_over_quorum() {
        // If both revocation is stale AND peer count is below
        // threshold, revocation-stale wins (it's the first check).
        let signals = MeshQuorumSignals {
            healthy_peer_count: 0,
            lease_coordinator_reachable: Some(false),
            revocation_snapshot_fresh: false,
        };
        let result = classify_deployment_mode(signals);
        assert_eq!(
            result.reason,
            DeploymentClassificationReason::RevocationSnapshotStale,
            "revocation-stale must take priority over peer-count + lease checks"
        );
    }

    // ── admit_safety_tier: per (mode × tier) admission matrix ──────

    #[test]
    fn admit_safety_tier_allows_safe_in_evaluation() {
        let class = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        admit_safety_tier(&class, SafetyTier::Safe).expect("Safe must always admit");
    }

    #[test]
    fn admit_safety_tier_allows_safe_in_mesh_active() {
        let class = classify_deployment_mode(MeshQuorumSignals::fully_active(3));
        admit_safety_tier(&class, SafetyTier::Safe).expect("Safe must always admit");
    }

    #[test]
    fn admit_safety_tier_refuses_risky_in_evaluation() {
        let class = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        let err = admit_safety_tier(&class, SafetyTier::Risky)
            .expect_err("Risky must be refused in Evaluation");
        match err {
            DeploymentTierRefusal::TierRequiresMeshActive { tier, mode, reason } => {
                assert_eq!(tier, SafetyTier::Risky);
                assert_eq!(mode, DeploymentMode::Evaluation);
                assert!(matches!(
                    reason,
                    DeploymentClassificationReason::InsufficientMeshQuorum { .. }
                ));
            }
            other => panic!("expected TierRequiresMeshActive, got {other:?}"),
        }
    }

    #[test]
    fn admit_safety_tier_refuses_dangerous_in_evaluation() {
        let class = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        let err = admit_safety_tier(&class, SafetyTier::Dangerous)
            .expect_err("Dangerous must be refused in Evaluation");
        assert!(matches!(
            err,
            DeploymentTierRefusal::TierRequiresMeshActive {
                tier: SafetyTier::Dangerous,
                ..
            }
        ));
    }

    #[test]
    fn admit_safety_tier_allows_risky_in_mesh_active() {
        let class = classify_deployment_mode(MeshQuorumSignals::fully_active(3));
        admit_safety_tier(&class, SafetyTier::Risky).expect("Risky admits in MeshActive");
    }

    #[test]
    fn admit_safety_tier_allows_dangerous_in_mesh_active() {
        let class = classify_deployment_mode(MeshQuorumSignals::fully_active(3));
        admit_safety_tier(&class, SafetyTier::Dangerous).expect("Dangerous admits in MeshActive");
    }

    #[test]
    fn admit_safety_tier_allows_critical_in_evaluation() {
        // Critical has its own quorum/elevation gating; deployment
        // mode does NOT additionally gate it because the
        // quorum-elevation path already requires mesh by
        // construction.
        let class = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        admit_safety_tier(&class, SafetyTier::Critical)
            .expect("Critical admits regardless of deployment mode");
    }

    #[test]
    fn admit_safety_tier_refuses_forbidden_in_both_modes() {
        let eval = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        let active = classify_deployment_mode(MeshQuorumSignals::fully_active(3));
        for class in [eval, active] {
            let err = admit_safety_tier(&class, SafetyTier::Forbidden)
                .expect_err("Forbidden never admits");
            assert!(matches!(
                err,
                DeploymentTierRefusal::TierForbidden {
                    tier: SafetyTier::Forbidden
                }
            ));
        }
    }

    #[test]
    fn admit_safety_tier_refusal_carries_underlying_reason_for_audit() {
        // Operator-alerting depends on the refusal carrying the
        // reason discriminant (so a stale-revocation cause vs
        // insufficient-peers cause are distinguishable).
        let stale_signals = MeshQuorumSignals {
            healthy_peer_count: 99,
            lease_coordinator_reachable: Some(true),
            revocation_snapshot_fresh: false,
        };
        let class = classify_deployment_mode(stale_signals);
        let err = admit_safety_tier(&class, SafetyTier::Risky)
            .expect_err("Risky refused due to stale revocation");
        match err {
            DeploymentTierRefusal::TierRequiresMeshActive { reason, .. } => {
                assert_eq!(
                    reason,
                    DeploymentClassificationReason::RevocationSnapshotStale
                );
            }
            other => panic!("expected TierRequiresMeshActive, got {other:?}"),
        }
    }

    // ── boot log + warning ──────────────────────────────────────────

    #[test]
    fn boot_log_line_contains_mode_and_reason_labels() {
        let class = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        let line = class.boot_log_line();
        assert!(line.contains("deployment_mode=evaluation"));
        assert!(line.contains("reason=insufficient_mesh_quorum"));
        assert!(line.contains("healthy_peers=0"));
    }

    #[test]
    fn boot_log_line_records_lease_coordinator_state() {
        let unreachable = MeshQuorumSignals {
            healthy_peer_count: 5,
            lease_coordinator_reachable: Some(false),
            revocation_snapshot_fresh: true,
        };
        let line = classify_deployment_mode(unreachable).boot_log_line();
        assert!(line.contains("lease_coordinator=unreachable"));

        let reachable = MeshQuorumSignals::fully_active(2);
        let line = classify_deployment_mode(reachable).boot_log_line();
        assert!(line.contains("lease_coordinator=reachable"));

        let unconfigured = MeshQuorumSignals {
            healthy_peer_count: 2,
            lease_coordinator_reachable: None,
            revocation_snapshot_fresh: true,
        };
        let line = classify_deployment_mode(unconfigured).boot_log_line();
        assert!(line.contains("lease_coordinator=n/a"));
    }

    #[test]
    fn evaluation_mode_warning_string_is_stable() {
        // Operator runbooks key off this string; pin it byte-for-byte.
        assert_eq!(
            evaluation_mode_boot_warning(),
            "WARN: Host-first mode is for evaluation only. Production deployments require mesh-active mode."
        );
    }

    #[test]
    fn emit_boot_log_returns_rendered_line_for_test_assertions() {
        let class = classify_deployment_mode(MeshQuorumSignals::fully_active(2));
        let line = emit_boot_log(&class);
        assert_eq!(line, class.boot_log_line());
    }

    // ── DeploymentMode predicates ───────────────────────────────────

    #[test]
    fn deployment_mode_predicates_are_mutually_exclusive() {
        assert!(DeploymentMode::Evaluation.is_evaluation());
        assert!(!DeploymentMode::Evaluation.is_mesh_active());
        assert!(DeploymentMode::MeshActive.is_mesh_active());
        assert!(!DeploymentMode::MeshActive.is_evaluation());
    }

    #[test]
    fn deployment_mode_labels_are_stable() {
        assert_eq!(DeploymentMode::Evaluation.label(), "evaluation");
        assert_eq!(DeploymentMode::MeshActive.label(), "mesh-active");
    }

    // ── serde round-trip + exhaustive sentinels ────────────────────

    #[test]
    fn deployment_classification_round_trips_through_json() {
        let class = classify_deployment_mode(MeshQuorumSignals::fully_active(3));
        let json = serde_json::to_string(&class).expect("encode");
        let back: DeploymentClassification = serde_json::from_str(&json).expect("decode");
        assert_eq!(back, class);
    }

    #[test]
    fn deployment_tier_refusal_round_trips_through_json_per_variant() {
        let cases = [
            DeploymentTierRefusal::TierRequiresMeshActive {
                tier: SafetyTier::Risky,
                mode: DeploymentMode::Evaluation,
                reason: DeploymentClassificationReason::InsufficientMeshQuorum {
                    observed: 0,
                    required: 2,
                },
            },
            DeploymentTierRefusal::TierForbidden {
                tier: SafetyTier::Forbidden,
            },
        ];
        for original in cases {
            let json = serde_json::to_string(&original).expect("encode");
            let back: DeploymentTierRefusal = serde_json::from_str(&json).expect("decode");
            assert_eq!(back, original);
        }
    }

    #[test]
    fn deployment_classification_reason_exhaustive_match_sentinel() {
        let probes = [
            DeploymentClassificationReason::InsufficientMeshQuorum {
                observed: 0,
                required: 2,
            },
            DeploymentClassificationReason::LeaseCoordinatorUnreachable,
            DeploymentClassificationReason::RevocationSnapshotStale,
            DeploymentClassificationReason::MeshQuorumActive,
        ];
        for r in probes {
            match r {
                DeploymentClassificationReason::InsufficientMeshQuorum { .. }
                | DeploymentClassificationReason::LeaseCoordinatorUnreachable
                | DeploymentClassificationReason::RevocationSnapshotStale
                | DeploymentClassificationReason::MeshQuorumActive
                | DeploymentClassificationReason::SignedSignalsRejected => (),
            }
        }
    }

    #[test]
    fn deployment_tier_refusal_exhaustive_match_sentinel() {
        let probes = [
            DeploymentTierRefusal::TierRequiresMeshActive {
                tier: SafetyTier::Risky,
                mode: DeploymentMode::Evaluation,
                reason: DeploymentClassificationReason::InsufficientMeshQuorum {
                    observed: 0,
                    required: 2,
                },
            },
            DeploymentTierRefusal::TierForbidden {
                tier: SafetyTier::Forbidden,
            },
        ];
        for r in probes {
            match r {
                DeploymentTierRefusal::TierRequiresMeshActive { .. }
                | DeploymentTierRefusal::TierForbidden { .. } => (),
            }
        }
    }

    // ── Mode transitions across health-probe cycles ────────────────

    #[test]
    fn mode_transitions_back_to_evaluation_when_peer_lost_below_threshold() {
        // Bead acceptance: "kill peers; verify mode transitions
        // back to Evaluation".
        let healthy = classify_deployment_mode(MeshQuorumSignals::fully_active(2));
        assert_eq!(healthy.mode, DeploymentMode::MeshActive);

        // Peer lost; count drops below threshold.
        let degraded = classify_deployment_mode(MeshQuorumSignals::fully_active(1));
        assert_eq!(degraded.mode, DeploymentMode::Evaluation);
    }

    #[test]
    fn mode_transitions_to_mesh_active_when_peer_count_recovers() {
        let degraded = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        assert_eq!(degraded.mode, DeploymentMode::Evaluation);

        let recovered = classify_deployment_mode(MeshQuorumSignals::fully_active(2));
        assert_eq!(recovered.mode, DeploymentMode::MeshActive);
    }

    #[test]
    fn mode_transition_carries_reason_change_for_audit() {
        // Pin: when the mode flips back to Evaluation due to peer
        // loss, the reason must clearly distinguish "lost peers"
        // (InsufficientMeshQuorum) from "stale revocation" so an
        // audit replay can reconstruct what happened.
        let healthy = classify_deployment_mode(MeshQuorumSignals::fully_active(2));
        let lost_peers = classify_deployment_mode(MeshQuorumSignals::fully_active(1));
        assert_ne!(healthy.reason, lost_peers.reason);
        assert!(matches!(
            lost_peers.reason,
            DeploymentClassificationReason::InsufficientMeshQuorum { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────
    // br-5f8t1 — SignedMeshQuorumSignals (defends against unsigned-
    // signals falsification → forced MeshActive).
    //
    // Pin the production-path classifier discipline: only signed
    // signals attested by a trusted KID can promote the host to
    // MeshActive. Unsigned, mis-signed, or unknown-attester signals
    // either error (verified path) or fail-soft to Evaluation
    // (verified_or_evaluation path). Defaults stay fail-closed.
    // ─────────────────────────────────────────────────────────────────

    fn signing_key_a() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[0xA1_u8; 32]).expect("valid signing key A")
    }

    fn signing_key_b() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[0xB2_u8; 32]).expect("valid signing key B")
    }

    fn fully_active_signed_by_a() -> SignedMeshQuorumSignals {
        MeshQuorumSignals::fully_active(3).sign(&signing_key_a())
    }

    fn evaluation_signed_by_a() -> SignedMeshQuorumSignals {
        MeshQuorumSignals::single_host_evaluation().sign(&signing_key_a())
    }

    #[test]
    fn signed_signals_round_trip_under_attesting_key_verifies() {
        let signed = fully_active_signed_by_a();
        signed
            .verify(&signing_key_a().verifying_key())
            .expect("signature MUST verify under the attesting key");
    }

    #[test]
    fn signed_signals_under_wrong_key_fails_verification() {
        let signed = fully_active_signed_by_a();
        signed
            .verify(&signing_key_b().verifying_key())
            .expect_err("signature MUST NOT verify under a different key");
    }

    #[test]
    fn signed_signals_classifier_promotes_to_mesh_active_when_signature_valid_and_quorum_healthy()
    {
        let signed = fully_active_signed_by_a();
        let classification = classify_deployment_mode_verified(&signed, |kid| {
            (kid == &signing_key_a().key_id()).then(|| signing_key_a().verifying_key())
        })
        .expect("verified classifier accepts valid signature + healthy quorum");
        assert_eq!(classification.mode, DeploymentMode::MeshActive);
        assert_eq!(
            classification.reason,
            DeploymentClassificationReason::MeshQuorumActive
        );
    }

    #[test]
    fn signed_signals_classifier_rejects_unknown_attesting_kid() {
        let signed = fully_active_signed_by_a();
        let err = classify_deployment_mode_verified(&signed, |_| None)
            .expect_err("verified classifier MUST reject unknown attesting KID");
        assert!(matches!(
            err,
            DeploymentClassifierError::UnknownAttestingNode { .. }
        ));
    }

    #[test]
    fn signed_signals_classifier_rejects_signature_under_wrong_key() {
        let signed = fully_active_signed_by_a();
        let err = classify_deployment_mode_verified(&signed, |_| {
            Some(signing_key_b().verifying_key())
        })
        .expect_err("verified classifier MUST reject signature under wrong key");
        assert!(matches!(
            err,
            DeploymentClassifierError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn signed_signals_classifier_rejects_tampered_signals() {
        // Sign healthy(3) signals, then mutate the signals field
        // post-signing. Verification MUST fail because signing_bytes
        // recomputes from the (now-tampered) signals + the
        // attached signature was over the ORIGINAL signals.
        let mut tampered = fully_active_signed_by_a();
        tampered.signals.healthy_peer_count = 999;
        let err = classify_deployment_mode_verified(&tampered, |_| {
            Some(signing_key_a().verifying_key())
        })
        .expect_err("verified classifier MUST reject post-signing tampering");
        assert!(matches!(
            err,
            DeploymentClassifierError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn signed_signals_attesting_kid_in_signing_bytes_prevents_kid_swap() {
        // Sign signals with key A (kid_A), then mutate
        // attesting_kid → kid_B but keep the signature bytes. The
        // signing transcript includes attesting_kid, so swapping
        // it post-signing must invalidate the signature.
        let mut swapped = fully_active_signed_by_a();
        swapped.attesting_kid = signing_key_b().key_id();
        // Resolver returns key_a (the actual signer's key); swap
        // changed attesting_kid in the transcript so signature
        // verification fails because the bytes-being-verified differ
        // from what was signed.
        let err = classify_deployment_mode_verified(&swapped, |_| {
            Some(signing_key_a().verifying_key())
        })
        .expect_err("kid swap MUST invalidate the signature");
        assert!(matches!(
            err,
            DeploymentClassifierError::SignatureVerificationFailed { .. }
        ));
    }

    #[test]
    fn signed_signals_classifier_evaluation_signals_yield_evaluation_even_when_signed() {
        // Even with a valid signature, signals that classify to
        // Evaluation (single-host, no peers) MUST stay in Evaluation.
        // Signature is about authenticity, not about authorizing a
        // mode upgrade beyond what the signals support.
        let signed = evaluation_signed_by_a();
        let classification = classify_deployment_mode_verified(&signed, |_| {
            Some(signing_key_a().verifying_key())
        })
        .expect("signature valid");
        assert_eq!(classification.mode, DeploymentMode::Evaluation);
        // Reason is the underlying signals reason, NOT
        // SignedSignalsRejected (which is reserved for verification
        // failure).
        assert_ne!(
            classification.reason,
            DeploymentClassificationReason::SignedSignalsRejected
        );
    }

    #[test]
    fn signed_signals_fail_soft_path_evaluates_on_signature_failure() {
        // The fail-soft variant MUST NEVER produce MeshActive when
        // verification fails — instead returns Evaluation with
        // SignedSignalsRejected reason so audit consumers can see
        // the bypass attempt.
        let signed = fully_active_signed_by_a();
        let classification = classify_deployment_mode_verified_or_evaluation(&signed, |_| {
            Some(signing_key_b().verifying_key()) // wrong key
        });
        assert_eq!(classification.mode, DeploymentMode::Evaluation);
        assert_eq!(
            classification.reason,
            DeploymentClassificationReason::SignedSignalsRejected
        );
    }

    #[test]
    fn signed_signals_fail_soft_path_unknown_attester_evaluates() {
        // Same fail-soft contract for the unknown-attester case.
        let signed = fully_active_signed_by_a();
        let classification = classify_deployment_mode_verified_or_evaluation(&signed, |_| None);
        assert_eq!(classification.mode, DeploymentMode::Evaluation);
        assert_eq!(
            classification.reason,
            DeploymentClassificationReason::SignedSignalsRejected
        );
    }

    #[test]
    fn signed_signals_signing_bytes_have_domain_separator() {
        // The signed transcript MUST be prefixed by the
        // MESH_QUORUM_SIGNALS_DOMAIN tag so a signature over signed
        // signals cannot be replayed against any other FCP signature
        // transcript.
        let signed = fully_active_signed_by_a();
        let bytes = signed.signing_bytes();
        assert!(
            bytes.starts_with(MESH_QUORUM_SIGNALS_DOMAIN),
            "signing_bytes MUST begin with MESH_QUORUM_SIGNALS_DOMAIN"
        );
    }

    #[test]
    fn signed_signals_admit_safety_tier_refuses_risky_when_signature_invalid() {
        // End-to-end: an attacker presenting forged signals MUST NOT
        // be able to admit a Risky operation through the
        // (signed-classifier + admit_safety_tier) chain.
        let attacker_signed = fully_active_signed_by_a();
        // Resolver returns the WRONG key (signature won't verify).
        let classification = classify_deployment_mode_verified_or_evaluation(
            &attacker_signed,
            |_| Some(signing_key_b().verifying_key()),
        );
        let refusal = admit_safety_tier(&classification, SafetyTier::Risky)
            .expect_err("Risky MUST be refused under unverified signals");
        assert!(matches!(
            refusal,
            DeploymentTierRefusal::TierRequiresMeshActive { .. }
        ));
    }
}
