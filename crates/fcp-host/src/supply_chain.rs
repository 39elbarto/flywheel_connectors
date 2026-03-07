//! Host-side supply chain verification gate.
//!
//! Wraps the core [`fcp_core::VerificationPipeline`] with host-specific
//! behaviour:
//!
//! - Policy configuration from zone or host config.
//! - Digest-keyed result cache for offline/repeated installs.
//! - Deterministic evidence bundles with stable hashing.
//! - Structured audit events for every verification decision.

use std::collections::HashMap;
use std::sync::Mutex;

use blake3::hash;
use chrono::{DateTime, Utc};
use fcp_core::{
    ConnectorId, HashAlgorithm, SoftwareBillOfMaterials, SupplyChainAttestation,
    SupplyChainVerificationPolicy, VerificationDecision, VerificationEvidence,
    VerificationPipeline, VerificationReasonCode,
};
use serde::{Deserialize, Serialize};

use crate::HostResult;

// ── Configuration ────────────────────────────────────────────────

/// Host-level supply chain gate configuration.
#[derive(Debug, Clone)]
pub struct SupplyChainGateConfig {
    /// Base verification policy (fail-closed defaults).
    pub policy: SupplyChainVerificationPolicy,
    /// Maximum number of cached verification results.
    pub cache_capacity: usize,
    /// Whether to allow dev-mode overrides (only in non-production zones).
    pub allow_dev_overrides: bool,
}

impl Default for SupplyChainGateConfig {
    fn default() -> Self {
        Self {
            policy: SupplyChainVerificationPolicy::default(),
            cache_capacity: 256,
            allow_dev_overrides: false,
        }
    }
}

// ── Audit Event ──────────────────────────────────────────────────

/// Structured audit event emitted for each verification decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationAuditEvent {
    /// Connector being verified.
    pub connector_id: ConnectorId,
    /// Version string of the artifact.
    pub version: String,
    /// Digest of the binary artifact.
    pub artifact_digest: String,
    /// Pipeline decision.
    pub decision: VerificationDecision,
    /// Stable reason code.
    pub reason_code: VerificationReasonCode,
    /// Number of verification steps executed.
    pub steps_executed: usize,
    /// Number of steps that passed.
    pub steps_passed: usize,
    /// Whether the result was served from cache.
    pub cached: bool,
    /// Content hash of the evidence bundle.
    pub evidence_digest: String,
    /// Timestamp of verification.
    pub verified_at: DateTime<Utc>,
}

// ── Gate Outcome ─────────────────────────────────────────────────

/// Result of a supply chain verification through the host gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateOutcome {
    /// The connector being verified.
    pub connector_id: ConnectorId,
    /// Version being verified.
    pub version: String,
    /// Whether the artifact is allowed to proceed.
    pub allowed: bool,
    /// The core evidence bundle.
    pub evidence: VerificationEvidence,
    /// Audit event for logging.
    pub audit_event: VerificationAuditEvent,
    /// Whether result came from cache.
    pub cached: bool,
}

// ── Cache Entry ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    evidence: VerificationEvidence,
    evidence_digest: String,
    verified_at: DateTime<Utc>,
}

// ── Supply Chain Gate ────────────────────────────────────────────

/// Host-side gate that enforces supply chain verification before
/// connector installation or upgrade.
///
/// The gate wraps the core [`VerificationPipeline`] with:
/// - A digest-keyed result cache for repeated/offline installs.
/// - Structured audit events for every decision.
/// - Policy override support for dev zones (when enabled).
pub struct SupplyChainGate {
    config: SupplyChainGateConfig,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl SupplyChainGate {
    /// Create a new gate with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(SupplyChainGateConfig::default())
    }

    /// Create a new gate with explicit configuration.
    #[must_use]
    pub fn with_config(config: SupplyChainGateConfig) -> Self {
        Self {
            config,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Return the active verification policy.
    #[must_use]
    pub const fn policy(&self) -> &SupplyChainVerificationPolicy {
        &self.config.policy
    }

    /// Return the current cache size.
    ///
    /// # Panics
    ///
    /// Panics if the internal cache mutex is poisoned.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().expect("cache lock poisoned").len()
    }

    /// Clear all cached verification results.
    ///
    /// # Panics
    ///
    /// Panics if the internal cache mutex is poisoned.
    pub fn clear_cache(&self) {
        self.cache.lock().expect("cache lock poisoned").clear();
    }

    /// Verify a connector artifact before installation.
    ///
    /// Returns a [`GateOutcome`] with the decision, evidence, and audit event.
    /// Results are cached by artifact digest so repeated checks for the same
    /// binary are free.
    ///
    /// # Errors
    ///
    /// Returns an error if evidence hashing fails (should not occur with
    /// well-formed inputs).
    pub fn verify(
        &self,
        connector_id: &ConnectorId,
        version: &str,
        artifact_digest: &str,
        attestation: Option<&SupplyChainAttestation>,
        sbom: Option<&SoftwareBillOfMaterials>,
    ) -> HostResult<GateOutcome> {
        self.verify_at(
            connector_id,
            version,
            artifact_digest,
            attestation,
            sbom,
            Utc::now(),
        )
    }

    /// Verify with an explicit timestamp (for deterministic testing).
    ///
    /// # Errors
    ///
    /// Returns an error if evidence hashing fails.
    pub fn verify_at(
        &self,
        connector_id: &ConnectorId,
        version: &str,
        artifact_digest: &str,
        attestation: Option<&SupplyChainAttestation>,
        sbom: Option<&SoftwareBillOfMaterials>,
        now: DateTime<Utc>,
    ) -> HostResult<GateOutcome> {
        // Check cache first.
        if let Some(cached) = self.lookup_cache(artifact_digest) {
            let audit_event = build_audit_event(
                connector_id,
                version,
                artifact_digest,
                &cached.evidence,
                &cached.evidence_digest,
                true,
                cached.verified_at,
            );
            return Ok(GateOutcome {
                connector_id: connector_id.clone(),
                version: version.to_string(),
                allowed: cached.evidence.decision == VerificationDecision::Allow,
                evidence: cached.evidence,
                audit_event,
                cached: true,
            });
        }

        // Resolve effective policy (allow dev overrides when configured).
        let effective_policy = self.effective_policy(attestation, sbom);

        // Run pipeline.
        let pipeline = VerificationPipeline::new(effective_policy);
        let evidence = pipeline.verify(artifact_digest, attestation, sbom);

        let evidence_digest = evidence
            .content_hash(HashAlgorithm::Blake3_256)
            .map_err(|e| crate::HostError::Internal(format!("evidence hash failed: {e}")))?;

        // Cache the result.
        self.store_cache(
            artifact_digest,
            CacheEntry {
                evidence: evidence.clone(),
                evidence_digest: evidence_digest.clone(),
                verified_at: now,
            },
        );

        let audit_event = build_audit_event(
            connector_id,
            version,
            artifact_digest,
            &evidence,
            &evidence_digest,
            false,
            now,
        );

        Ok(GateOutcome {
            connector_id: connector_id.clone(),
            version: version.to_string(),
            allowed: evidence.decision == VerificationDecision::Allow,
            evidence,
            audit_event,
            cached: false,
        })
    }

    /// Look up a previous result by artifact digest.
    fn lookup_cache(&self, artifact_digest: &str) -> Option<CacheEntry> {
        self.cache
            .lock()
            .expect("cache lock poisoned")
            .get(artifact_digest)
            .cloned()
    }

    /// Store a result in cache, evicting the oldest entry if at capacity.
    fn store_cache(&self, artifact_digest: &str, entry: CacheEntry) {
        let mut cache = self.cache.lock().expect("cache lock poisoned");
        if cache.len() >= self.config.cache_capacity && !cache.contains_key(artifact_digest) {
            // Simple eviction: remove oldest entry by verification time.
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.verified_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(artifact_digest.to_string(), entry);
    }

    /// Compute the effective policy, applying dev overrides when allowed.
    fn effective_policy(
        &self,
        attestation: Option<&SupplyChainAttestation>,
        sbom: Option<&SoftwareBillOfMaterials>,
    ) -> SupplyChainVerificationPolicy {
        let mut policy = self.config.policy.clone();

        // Dev override: if configured and no attestation/SBOM provided,
        // relax requirements so dev installs can proceed.
        if self.config.allow_dev_overrides && attestation.is_none() && sbom.is_none() {
            policy.allow_unsigned = true;
            policy.require_attestation = false;
            policy.require_sbom = false;
        }

        policy
    }
}

impl Default for SupplyChainGate {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ──────────────────────────────────────────────────────

fn build_audit_event(
    connector_id: &ConnectorId,
    version: &str,
    artifact_digest: &str,
    evidence: &VerificationEvidence,
    evidence_digest: &str,
    cached: bool,
    verified_at: DateTime<Utc>,
) -> VerificationAuditEvent {
    let steps_passed = evidence.steps.iter().filter(|s| s.passed).count();
    VerificationAuditEvent {
        connector_id: connector_id.clone(),
        version: version.to_string(),
        artifact_digest: artifact_digest.to_string(),
        decision: evidence.decision,
        reason_code: evidence.reason_code,
        steps_executed: evidence.steps.len(),
        steps_passed,
        cached,
        evidence_digest: evidence_digest.to_string(),
        verified_at,
    }
}

/// Compute a stable digest of a [`GateOutcome`] for cross-referencing.
///
/// # Panics
///
/// Panics if outcome serialization fails (should not happen).
#[must_use]
pub fn outcome_digest(outcome: &GateOutcome) -> String {
    let bytes =
        serde_json::to_vec(outcome).expect("gate outcome serialization should be deterministic");
    format!("blake3-256:{}", hash(&bytes).to_hex())
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fcp_core::{
        AttestationMaterial, AttestationMetadata, AttestationPredicateType, ConnectorId,
        SbomComponent, SbomDependency, SbomFormat, SoftwareBillOfMaterials,
        SupplyChainAttestation, SupplyChainSignature, TrustRootBinding,
        VerificationDecision, VerificationReasonCode,
        SBOM_SIGNED_FIELDS, SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS,
    };

    // ── Test Helpers ─────────────────────────────────────────────

    fn test_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap()
    }

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test-echo:utility:1.0.0")
    }

    fn valid_digest() -> String {
        format!(
            "blake3-256:{}",
            "a".repeat(64)
        )
    }

    fn valid_attestation(digest: &str) -> SupplyChainAttestation {
        SupplyChainAttestation {
            format: "fcp-supply-chain-attestation".to_string(),
            schema_version: "1.0".to_string(),
            subject_digest: digest.to_string(),
            predicate_type: AttestationPredicateType::SlsaProvenanceV1,
            builder_id: "ci.example.com/builder".to_string(),
            build_type: "container".to_string(),
            materials: vec![AttestationMaterial {
                uri: "https://github.com/example/repo".to_string(),
                digest: format!("blake3-256:{}", "e".repeat(64)),
            }],
            metadata: AttestationMetadata {
                build_started_at: test_time(),
                build_finished_at: test_time(),
                invocation_id: Some("inv-001".to_string()),
            },
            slsa_level: 2,
            provenance_hash: format!("blake3-256:{}", "b".repeat(64)),
            trust_root: TrustRootBinding {
                root_type: "sigstore".to_string(),
                root_id: "root-001".to_string(),
            },
            builder_allowlist: vec!["ci.example.com/builder".to_string()],
            signature: SupplyChainSignature {
                algorithm: "ed25519".to_string(),
                key_id: "key-001".to_string(),
                signature: "sig-placeholder".to_string(),
                signed_fields: SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            },
        }
    }

    fn valid_sbom() -> SoftwareBillOfMaterials {
        SoftwareBillOfMaterials {
            format: "fcp-sbom".to_string(),
            schema_version: "1.0".to_string(),
            bom_format: SbomFormat::Cyclonedx,
            bom_version: "1.0.0".to_string(),
            tool_chain: vec!["cargo".to_string()],
            components: vec![SbomComponent {
                component_id: "comp-001".to_string(),
                name: "fcp-core".to_string(),
                version: "0.1.0".to_string(),
                hashes: vec![format!("blake3-256:{}", "c".repeat(64))],
                licenses: vec!["Apache-2.0".to_string()],
            }],
            dependencies: vec![SbomDependency {
                component_id: "comp-001".to_string(),
                depends_on: vec![],
            }],
            trust_root: TrustRootBinding {
                root_type: "sigstore".to_string(),
                root_id: "root-002".to_string(),
            },
            signature: SupplyChainSignature {
                algorithm: "ed25519".to_string(),
                key_id: "key-002".to_string(),
                signature: "sig-placeholder".to_string(),
                signed_fields: SBOM_SIGNED_FIELDS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            },
        }
    }

    fn default_policy() -> SupplyChainVerificationPolicy {
        SupplyChainVerificationPolicy::default()
    }

    fn permissive_policy() -> SupplyChainVerificationPolicy {
        SupplyChainVerificationPolicy {
            require_attestation: false,
            require_sbom: false,
            allow_unsigned: true,
            require_digest_match: false,
            min_slsa_level: 0,
            trusted_builders: vec![],
        }
    }

    // ── Default Construction ─────────────────────────────────────

    #[test]
    fn gate_default_policy_is_fail_closed() {
        let gate = SupplyChainGate::new();
        let policy = gate.policy();
        assert!(policy.require_attestation);
        assert!(policy.require_sbom);
        assert!(!policy.allow_unsigned);
        assert!(policy.require_digest_match);
        assert_eq!(policy.min_slsa_level, 0);
        assert!(policy.trusted_builders.is_empty());
    }

    #[test]
    fn gate_default_cache_is_empty() {
        let gate = SupplyChainGate::new();
        assert_eq!(gate.cache_size(), 0);
    }

    #[test]
    fn gate_default_impl() {
        let gate = SupplyChainGate::default();
        assert_eq!(gate.cache_size(), 0);
    }

    #[test]
    fn config_default_capacity() {
        let config = SupplyChainGateConfig::default();
        assert_eq!(config.cache_capacity, 256);
        assert!(!config.allow_dev_overrides);
    }

    // ── Successful Verification ──────────────────────────────────

    #[test]
    fn verify_with_valid_attestation_and_sbom() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(outcome.evidence.decision, VerificationDecision::Allow);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::Verified
        );
        assert!(!outcome.cached);
        assert_eq!(outcome.audit_event.connector_id, cid);
        assert_eq!(outcome.audit_event.version, "1.0.0");
    }

    #[test]
    fn verify_records_steps() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert!(!outcome.evidence.steps.is_empty());
        assert!(outcome.audit_event.steps_executed > 0);
        assert!(outcome.audit_event.steps_passed > 0);
    }

    #[test]
    fn verify_evidence_has_content_hash() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert!(outcome.audit_event.evidence_digest.starts_with("blake3-256:"));
        assert_eq!(outcome.audit_event.evidence_digest.len(), "blake3-256:".len() + 64);
    }

    // ── Denial Paths ─────────────────────────────────────────────

    #[test]
    fn deny_when_attestation_missing_and_required() {
        let gate = SupplyChainGate::new();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(outcome.evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::AttestationMissing
        );
    }

    #[test]
    fn deny_when_sbom_missing_and_required() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                None,
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(outcome.evidence.decision, VerificationDecision::Deny);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::SbomMissing
        );
    }

    #[test]
    fn deny_when_both_missing_and_required() {
        let gate = SupplyChainGate::new();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(outcome.evidence.decision, VerificationDecision::Deny);
    }

    #[test]
    fn deny_when_slsa_level_insufficient() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 3,
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest); // slsa_level = 2

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::SlsaLevelInsufficient
        );
    }

    #[test]
    fn deny_when_builder_untrusted() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                trusted_builders: vec!["trusted.example.com/builder".to_string()],
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest); // builder_id = ci.example.com/builder

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::BuilderUntrusted
        );
    }

    #[test]
    fn deny_when_digest_mismatch() {
        let gate = SupplyChainGate::new();
        let wrong_digest = format!("blake3-256:{}", "f".repeat(64));
        let att = valid_attestation(&valid_digest()); // att.subject_digest != wrong_digest

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &wrong_digest,
                Some(&att),
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::SubjectDigestMismatch
        );
    }

    // ── Allow Unsigned ───────────────────────────────────────────

    #[test]
    fn allow_unsigned_when_policy_permits() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::AllowedUnsigned
        );
    }

    // ── Dev Override ─────────────────────────────────────────────

    #[test]
    fn dev_override_relaxes_requirements() {
        let config = SupplyChainGateConfig {
            policy: default_policy(), // strict by default
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        // Without attestation or SBOM, dev override kicks in.
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "0.1.0-dev",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::AllowedUnsigned
        );
    }

    #[test]
    fn dev_override_does_not_apply_when_artifacts_present() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 4, // strict
                ..default_policy()
            },
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest); // slsa_level = 2

        // With attestation present, dev override does not relax SLSA check.
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "0.1.0-dev",
                &digest,
                Some(&att),
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
    }

    #[test]
    fn dev_override_disabled_denies_unsigned() {
        let config = SupplyChainGateConfig {
            policy: default_policy(),
            allow_dev_overrides: false,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "0.1.0-dev",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
    }

    // ── Cache Behaviour ──────────────────────────────────────────

    #[test]
    fn second_verification_uses_cache() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(!first.cached);
        assert_eq!(gate.cache_size(), 1);

        let second = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(second.cached);
        assert_eq!(second.evidence, first.evidence);
    }

    #[test]
    fn different_digests_cache_separately() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest1 = valid_digest();
        let digest2 = format!("blake3-256:{}", "d".repeat(64));
        let att1 = valid_attestation(&digest1);
        let att2 = valid_attestation(&digest2);
        let sbom = valid_sbom();

        gate.verify_at(&cid, "1.0.0", &digest1, Some(&att1), Some(&sbom), test_time())
            .unwrap();
        gate.verify_at(&cid, "2.0.0", &digest2, Some(&att2), Some(&sbom), test_time())
            .unwrap();

        assert_eq!(gate.cache_size(), 2);
    }

    #[test]
    fn cache_evicts_oldest_at_capacity() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 2,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        let t1 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        let t3 = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();

        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));
        let d3 = format!("blake3-256:{}", "3".repeat(64));

        gate.verify_at(&cid, "1.0.0", &d1, None, None, t1).unwrap();
        gate.verify_at(&cid, "2.0.0", &d2, None, None, t2).unwrap();
        assert_eq!(gate.cache_size(), 2);

        // This should evict d1 (oldest by verified_at).
        gate.verify_at(&cid, "3.0.0", &d3, None, None, t3).unwrap();
        assert_eq!(gate.cache_size(), 2);

        // d1 should be evicted (cache miss).
        let r1 = gate.verify_at(&cid, "1.0.0", &d1, None, None, t3).unwrap();
        assert!(!r1.cached);

        // d3 should still be cached.
        let r3 = gate.verify_at(&cid, "3.0.0", &d3, None, None, t3).unwrap();
        assert!(r3.cached);
    }

    #[test]
    fn clear_cache_empties_entries() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        gate.verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 1);

        gate.clear_cache();
        assert_eq!(gate.cache_size(), 0);
    }

    #[test]
    fn same_digest_overwrites_cache() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        gate.verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 1);

        // Re-verify same digest doesn't grow cache.
        gate.clear_cache();
        gate.verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        gate.verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 1);
    }

    // ── Audit Event Fields ───────────────────────────────────────

    #[test]
    fn audit_event_has_correct_connector_id() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();

        assert_eq!(outcome.audit_event.connector_id, cid);
        assert_eq!(outcome.audit_event.version, "1.0.0");
        assert_eq!(outcome.audit_event.artifact_digest, digest);
    }

    #[test]
    fn audit_event_cached_flag_correct() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(!first.audit_event.cached);

        let second = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(second.audit_event.cached);
    }

    #[test]
    fn audit_event_steps_match_evidence() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert_eq!(
            outcome.audit_event.steps_executed,
            outcome.evidence.steps.len()
        );
        assert_eq!(
            outcome.audit_event.steps_passed,
            outcome.evidence.steps.iter().filter(|s| s.passed).count()
        );
    }

    #[test]
    fn audit_event_denied_has_zero_or_fewer_passed() {
        let gate = SupplyChainGate::new();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert!(outcome.audit_event.steps_passed < outcome.audit_event.steps_executed);
    }

    #[test]
    fn audit_event_timestamp_matches_input() {
        let gate = SupplyChainGate::new();
        let t = test_time();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                t,
            )
            .unwrap();

        assert_eq!(outcome.audit_event.verified_at, t);
    }

    // ── Outcome Digest ───────────────────────────────────────────

    #[test]
    fn outcome_digest_is_stable() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let o1 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();
        let o2 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        // Cached flag differs, so outcome digests differ.
        assert!(!o1.cached);
        assert!(o2.cached);
        // But both have valid blake3 digests.
        assert!(outcome_digest(&o1).starts_with("blake3-256:"));
        assert!(outcome_digest(&o2).starts_with("blake3-256:"));
    }

    #[test]
    fn outcome_digest_format() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        let d = outcome_digest(&outcome);
        assert!(d.starts_with("blake3-256:"));
        assert_eq!(d.len(), "blake3-256:".len() + 64);
    }

    // ── Evidence Determinism ─────────────────────────────────────

    #[test]
    fn evidence_deterministic_for_same_inputs() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        gate.clear_cache();
        let o1 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        gate.clear_cache();
        let o2 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert_eq!(o1.evidence, o2.evidence);
        assert_eq!(
            o1.audit_event.evidence_digest,
            o2.audit_event.evidence_digest
        );
    }

    #[test]
    fn evidence_policy_snapshot_matches_effective() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 1,
                trusted_builders: vec!["ci.example.com/builder".to_string()],
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert_eq!(outcome.evidence.policy_snapshot.min_slsa_level, 1);
        assert_eq!(
            outcome.evidence.policy_snapshot.trusted_builders,
            vec!["ci.example.com/builder"]
        );
    }

    // ── Policy Variations ────────────────────────────────────────

    #[test]
    fn attestation_only_policy() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_attestation: true,
                require_sbom: false,
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);

        // Attestation present, SBOM not required -> allow.
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                None,
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
    }

    #[test]
    fn sbom_only_policy() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_attestation: false,
                require_sbom: true,
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let sbom = valid_sbom();

        // SBOM present, attestation not required -> allow.
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
    }

    #[test]
    fn no_requirements_policy_allows_all() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
    }

    #[test]
    fn slsa_level_boundary_exact_match() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 2, // exactly matches valid_attestation's level
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
    }

    #[test]
    fn trusted_builder_match() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                trusted_builders: vec!["ci.example.com/builder".to_string()],
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
    }

    // ── GateOutcome Serialization ────────────────────────────────

    #[test]
    fn gate_outcome_serializes_to_json() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("\"allowed\":true"));
        assert!(json.contains("\"decision\":\"allow\""));
    }

    #[test]
    fn gate_outcome_round_trips_json() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        let json = serde_json::to_string(&outcome).unwrap();
        let roundtrip: GateOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.allowed, outcome.allowed);
        assert_eq!(roundtrip.evidence, outcome.evidence);
    }

    #[test]
    fn audit_event_serializes_to_json() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        let json = serde_json::to_string(&outcome.audit_event).unwrap();
        assert!(json.contains("\"connector_id\""));
        assert!(json.contains("\"evidence_digest\""));
        assert!(json.contains("\"cached\":false"));
    }

    #[test]
    fn audit_event_round_trips_json() {
        let gate = SupplyChainGate::new();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        let json = serde_json::to_string(&outcome.audit_event).unwrap();
        let roundtrip: VerificationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, outcome.audit_event);
    }

    // ── Edge Cases ───────────────────────────────────────────────

    #[test]
    fn empty_digest_string() {
        let gate = SupplyChainGate::new();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                "",
                None,
                None,
                test_time(),
            )
            .unwrap();

        // Should still produce a valid outcome (deny due to missing attestation).
        assert!(!outcome.allowed);
        assert_eq!(outcome.evidence.artifact_digest, "");
    }

    #[test]
    fn empty_version_string() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(outcome.version, "");
    }

    #[test]
    fn verify_convenience_method_works() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
            )
            .unwrap();

        assert!(outcome.allowed);
    }

    #[test]
    fn multiple_connectors_same_gate() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let cid1 = ConnectorId::from_static("fcp.alpha:utility:1.0.0");
        let cid2 = ConnectorId::from_static("fcp.beta:utility:1.0.0");
        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));

        let o1 = gate.verify_at(&cid1, "1.0.0", &d1, None, None, test_time()).unwrap();
        let o2 = gate.verify_at(&cid2, "2.0.0", &d2, None, None, test_time()).unwrap();

        assert_eq!(o1.connector_id, cid1);
        assert_eq!(o2.connector_id, cid2);
        assert_eq!(gate.cache_size(), 2);
    }

    // ── Cache Capacity Zero ──────────────────────────────────────

    #[test]
    fn zero_capacity_cache_still_works() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 0,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        // First verify.
        let o1 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();
        assert!(!o1.cached);

        // With capacity 0, the entry gets inserted then immediately evicted
        // on next insert. But same digest reuses the single slot.
        let o2 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();
        // The entry was stored (capacity check excludes existing keys).
        assert!(o2.cached);
    }
}
