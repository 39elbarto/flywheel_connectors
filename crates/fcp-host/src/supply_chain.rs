//! Host-side supply chain verification gate.
//!
//! Wraps the evidence-owned [`VerificationPipeline`] with host-specific
//! behaviour:
//!
//! - Policy configuration from zone or host config.
//! - Verification-input-keyed result cache for offline/repeated installs.
//! - Deterministic evidence bundles with stable hashing.
//! - Structured audit events for every verification decision.

use std::collections::HashMap;
use std::sync::Mutex;

use blake3::hash;
use chrono::{DateTime, Utc};
use fcp_evidence::{
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
/// The gate wraps the evidence-owned [`VerificationPipeline`] with:
/// - A verification-input-keyed result cache for repeated/offline installs.
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
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Clear all cached verification results.
    pub fn clear_cache(&self) {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Verify a connector artifact before installation.
    ///
    /// Returns a [`GateOutcome`] with the decision, evidence, and audit event.
    /// Results are cached by artifact digest plus the verification inputs so
    /// repeated checks for the same artifact under the same evidence and policy
    /// are free.
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
        // Resolve effective policy (allow dev overrides when configured).
        let effective_policy = self.effective_policy(attestation, sbom);
        let cache_key =
            verification_cache_key(artifact_digest, &effective_policy, attestation, sbom).map_err(
                |e| crate::HostError::Internal(format!("cache key construction failed: {e}")),
            )?;

        // Check cache first.
        if let Some(cached) = self.lookup_cache(&cache_key) {
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

        // Run pipeline.
        let pipeline = VerificationPipeline::new(effective_policy);
        let evidence = pipeline.verify(artifact_digest, attestation, sbom);

        let evidence_digest = evidence
            .content_hash(HashAlgorithm::Blake3_256)
            .map_err(|e| crate::HostError::Internal(format!("evidence hash failed: {e}")))?;

        // Cache the result.
        self.store_cache(
            &cache_key,
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

    /// Look up a previous result by verification cache key.
    fn lookup_cache(&self, cache_key: &str) -> Option<CacheEntry> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(cache_key)
            .cloned()
    }

    /// Store a result in cache, evicting the oldest entry if at capacity.
    fn store_cache(&self, cache_key: &str, entry: CacheEntry) {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() >= self.config.cache_capacity && !cache.contains_key(cache_key) {
            // Simple eviction: remove oldest entry by verification time.
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.verified_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(cache_key.to_string(), entry);
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

#[derive(Serialize)]
struct VerificationCacheKey<'a> {
    artifact_digest: &'a str,
    policy: &'a SupplyChainVerificationPolicy,
    attestation: Option<&'a SupplyChainAttestation>,
    sbom: Option<&'a SoftwareBillOfMaterials>,
}

fn verification_cache_key(
    artifact_digest: &str,
    policy: &SupplyChainVerificationPolicy,
    attestation: Option<&SupplyChainAttestation>,
    sbom: Option<&SoftwareBillOfMaterials>,
) -> Result<String, serde_json::Error> {
    let payload = VerificationCacheKey {
        artifact_digest,
        policy,
        attestation,
        sbom,
    };
    let bytes = serde_json::to_vec(&payload)?;
    Ok(format!("blake3-256:{}", hash(&bytes).to_hex()))
}

/// Compute a stable digest of a [`GateOutcome`] for cross-referencing.
#[must_use]
pub fn outcome_digest(outcome: &GateOutcome) -> String {
    let bytes = serde_json::to_vec(outcome).unwrap_or_default();
    format!("blake3-256:{}", hash(&bytes).to_hex())
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fcp_prelude::{
        AttestationMaterial, AttestationMetadata, AttestationPredicateType, SBOM_SIGNED_FIELDS,
        SUPPLY_CHAIN_ATTESTATION_SIGNED_FIELDS, SbomComponent, SbomDependency,
    };
    use fcp_evidence::{
        ConnectorId, SbomFormat, SoftwareBillOfMaterials, SupplyChainAttestation,
        SupplyChainSignature, TrustRootBinding, VerificationDecision, VerificationReasonCode,
    };

    // ── Test Helpers ─────────────────────────────────────────────

    fn test_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap()
    }

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test-echo:utility:1.0.0")
    }

    fn valid_digest() -> String {
        format!("blake3-256:{}", "a".repeat(64))
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
                // 64-byte Ed25519 signature shape, 128 hex chars. The
                // upstream validator (fcp-evidence/-core) requires the
                // `signature` field to parse as hex or base64; any free-
                // form placeholder (e.g. "sig-placeholder") trips
                // `attestation_validation`/`sbom_validation` with
                // `signature must be valid hex or base64`.
                signature: "f".repeat(128),
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
                // 64-byte Ed25519 signature shape, 128 hex chars. The
                // upstream validator (fcp-evidence/-core) requires the
                // `signature` field to parse as hex or base64; any free-
                // form placeholder (e.g. "sig-placeholder") trips
                // `attestation_validation`/`sbom_validation` with
                // `signature must be valid hex or base64`.
                signature: "f".repeat(128),
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

    fn assert_permissive_invalid_digest_denied(digest: &str) -> GateOutcome {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                digest,
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::ArtifactDigestInvalid
        );
        assert_eq!(
            outcome.audit_event.reason_code,
            VerificationReasonCode::ArtifactDigestInvalid
        );
        assert!(
            outcome
                .evidence
                .steps
                .iter()
                .any(|step| step.step == "artifact_digest_validation" && !step.passed)
        );

        outcome
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

        assert!(
            outcome
                .audit_event
                .evidence_digest
                .starts_with("blake3-256:")
        );
        assert_eq!(
            outcome.audit_event.evidence_digest.len(),
            "blake3-256:".len() + 64
        );
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

        gate.verify_at(
            &cid,
            "1.0.0",
            &digest1,
            Some(&att1),
            Some(&sbom),
            test_time(),
        )
        .unwrap();
        gate.verify_at(
            &cid,
            "2.0.0",
            &digest2,
            Some(&att2),
            Some(&sbom),
            test_time(),
        )
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
    fn reverifying_same_input_does_not_grow_cache() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        gate.verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 1);

        // Re-verify the same verification inputs; the second call should hit cache.
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
                min_slsa_level: 1, // exactly matches valid_attestation's level
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
        let outcome = assert_permissive_invalid_digest_denied("");

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
            .verify(&test_connector_id(), "1.0.0", &valid_digest(), None, None)
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
        let cid2 = ConnectorId::from_static("fcp.beta:utility:2.0.0");
        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));

        let o1 = gate
            .verify_at(&cid1, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        let o2 = gate
            .verify_at(&cid2, "2.0.0", &d2, None, None, test_time())
            .unwrap();

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

    // ── Serde Roundtrip: VerificationAuditEvent ─────────────────

    #[test]
    fn audit_event_serde_roundtrip_denied() {
        let gate = SupplyChainGate::new();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "2.0.0",
                &valid_digest(),
                None,
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        let json = serde_json::to_string(&outcome.audit_event).unwrap();
        let rt: VerificationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, outcome.audit_event);
        assert_eq!(rt.decision, VerificationDecision::Deny);
    }

    #[test]
    fn audit_event_serde_roundtrip_allowed() {
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
        let rt: VerificationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, outcome.audit_event);
        assert_eq!(rt.decision, VerificationDecision::Allow);
    }

    // ── Serde Roundtrip: GateOutcome ────────────────────────────

    #[test]
    fn gate_outcome_serde_roundtrip_denied() {
        let gate = SupplyChainGate::new();
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "3.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        let json = serde_json::to_string(&outcome).unwrap();
        let rt: GateOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.allowed, outcome.allowed);
        assert!(!rt.allowed);
        assert_eq!(rt.evidence, outcome.evidence);
        assert_eq!(rt.audit_event, outcome.audit_event);
    }

    #[test]
    fn gate_outcome_json_contains_expected_keys() {
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

        let val = serde_json::to_value(&outcome).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("connector_id"));
        assert!(obj.contains_key("version"));
        assert!(obj.contains_key("allowed"));
        assert!(obj.contains_key("evidence"));
        assert!(obj.contains_key("audit_event"));
        assert!(obj.contains_key("cached"));
    }

    // ── Clone Behaviour ─────────────────────────────────────────

    #[test]
    fn gate_config_clone_preserves_fields() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 3,
                trusted_builders: vec!["builder-a".to_string()],
                ..default_policy()
            },
            cache_capacity: 128,
            allow_dev_overrides: true,
        };
        let cloned = config.clone();
        assert_eq!(config.cache_capacity, cloned.cache_capacity);
        assert_eq!(config.allow_dev_overrides, cloned.allow_dev_overrides);
        assert_eq!(config.policy.min_slsa_level, cloned.policy.min_slsa_level);
        assert_eq!(
            config.policy.trusted_builders,
            cloned.policy.trusted_builders
        );
    }

    #[test]
    fn gate_outcome_clone_preserves_fields() {
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

        let cloned = outcome.clone();
        assert_eq!(outcome.allowed, cloned.allowed);
        assert_eq!(outcome.connector_id, cloned.connector_id);
        assert_eq!(outcome.version, cloned.version);
        assert_eq!(outcome.evidence, cloned.evidence);
        assert_eq!(outcome.audit_event, cloned.audit_event);
        assert_eq!(outcome.cached, cloned.cached);
    }

    #[test]
    fn audit_event_clone_preserves_all_fields() {
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

        let cloned = outcome.audit_event.clone();
        assert_eq!(outcome.audit_event.connector_id, cloned.connector_id);
        assert_eq!(outcome.audit_event.version, cloned.version);
        assert_eq!(outcome.audit_event.artifact_digest, cloned.artifact_digest);
        assert_eq!(outcome.audit_event.decision, cloned.decision);
        assert_eq!(outcome.audit_event.reason_code, cloned.reason_code);
        assert_eq!(outcome.audit_event.steps_executed, cloned.steps_executed);
        assert_eq!(outcome.audit_event.steps_passed, cloned.steps_passed);
        assert_eq!(outcome.audit_event.cached, cloned.cached);
        assert_eq!(outcome.audit_event.evidence_digest, cloned.evidence_digest);
        assert_eq!(outcome.audit_event.verified_at, cloned.verified_at);
    }

    // ── Debug Trait ──────────────────────────────────────────────

    #[test]
    fn gate_config_debug_output() {
        let config = SupplyChainGateConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("SupplyChainGateConfig"));
        assert!(dbg.contains("cache_capacity"));
        assert!(dbg.contains("256"));
    }

    // ── PartialEq for VerificationAuditEvent ────────────────────

    #[test]
    fn audit_events_equal_for_same_inputs() {
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

        assert_eq!(o1.audit_event, o2.audit_event);
    }

    #[test]
    fn audit_events_differ_for_different_versions() {
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
                "2.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert_ne!(o1.audit_event, o2.audit_event);
    }

    // ── Cache Eviction Ordering ─────────────────────────────────

    #[test]
    fn cache_evicts_correct_oldest_entry() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 3,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        let t1 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        let t3 = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();
        let t4 = Utc.with_ymd_and_hms(2026, 1, 4, 0, 0, 0).unwrap();

        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));
        let d3 = format!("blake3-256:{}", "3".repeat(64));
        let d4 = format!("blake3-256:{}", "4".repeat(64));

        gate.verify_at(&cid, "1.0.0", &d1, None, None, t1).unwrap();
        gate.verify_at(&cid, "2.0.0", &d2, None, None, t2).unwrap();
        gate.verify_at(&cid, "3.0.0", &d3, None, None, t3).unwrap();
        assert_eq!(gate.cache_size(), 3);

        // Insert d4 should evict d1 (oldest).
        gate.verify_at(&cid, "4.0.0", &d4, None, None, t4).unwrap();
        assert_eq!(gate.cache_size(), 3);

        // d2 still cached (was second oldest, but not evicted yet).
        let r2 = gate.verify_at(&cid, "2.0.0", &d2, None, None, t4).unwrap();
        assert!(r2.cached);

        // d3 still cached.
        let r3 = gate.verify_at(&cid, "3.0.0", &d3, None, None, t4).unwrap();
        assert!(r3.cached);

        // d4 still cached.
        let r4 = gate.verify_at(&cid, "4.0.0", &d4, None, None, t4).unwrap();
        assert!(r4.cached);
    }

    #[test]
    fn cache_capacity_one_replaces_single_entry() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 1,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));

        gate.verify_at(&cid, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 1);

        gate.verify_at(&cid, "2.0.0", &d2, None, None, test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 1);

        // d1 should be evicted.
        let r1 = gate
            .verify_at(&cid, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        assert!(!r1.cached);
    }

    #[test]
    fn clear_cache_then_verify_gives_non_cached() {
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

        let outcome = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(!outcome.cached);
        assert!(!outcome.audit_event.cached);
    }

    // ── Outcome Digest Variations ───────────────────────────────

    #[test]
    fn outcome_digest_differs_for_different_decisions() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        gate.clear_cache();
        let allowed = gate
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
        let denied = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert_ne!(outcome_digest(&allowed), outcome_digest(&denied));
    }

    #[test]
    fn outcome_digest_stable_for_identical_outcomes() {
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

        assert_eq!(outcome_digest(&o1), outcome_digest(&o2));
    }

    #[test]
    fn outcome_digest_hex_chars_only() {
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

        let d = outcome_digest(&outcome);
        let hex_part = &d["blake3-256:".len()..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── Policy Snapshot in Evidence ─────────────────────────────

    #[test]
    fn evidence_policy_snapshot_reflects_permissive() {
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

        assert!(!outcome.evidence.policy_snapshot.require_attestation);
        assert!(!outcome.evidence.policy_snapshot.require_sbom);
        assert!(outcome.evidence.policy_snapshot.allow_unsigned);
        assert!(!outcome.evidence.policy_snapshot.require_digest_match);
        assert_eq!(outcome.evidence.policy_snapshot.min_slsa_level, 0);
    }

    #[test]
    fn evidence_policy_snapshot_reflects_strict() {
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

        assert!(outcome.evidence.policy_snapshot.require_attestation);
        assert!(outcome.evidence.policy_snapshot.require_sbom);
        assert!(!outcome.evidence.policy_snapshot.allow_unsigned);
        assert!(outcome.evidence.policy_snapshot.require_digest_match);
    }

    #[test]
    fn dev_override_policy_snapshot_shows_relaxed() {
        let config = SupplyChainGateConfig {
            policy: default_policy(),
            allow_dev_overrides: true,
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

        // Dev override should have relaxed these in the effective policy.
        assert!(outcome.evidence.policy_snapshot.allow_unsigned);
        assert!(!outcome.evidence.policy_snapshot.require_attestation);
        assert!(!outcome.evidence.policy_snapshot.require_sbom);
    }

    // ── Dev Override Edge Cases ──────────────────────────────────

    #[test]
    fn dev_override_only_when_both_artifacts_missing() {
        let config = SupplyChainGateConfig {
            policy: default_policy(),
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        // With only SBOM, dev override should NOT activate.
        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "0.1.0-dev",
                &valid_digest(),
                None,
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        // Still applies strict policy since sbom is present (attestation present check).
        // Dev override requires BOTH attestation and sbom to be None.
        assert!(outcome.evidence.policy_snapshot.require_attestation);
    }

    #[test]
    fn dev_override_does_not_activate_with_only_attestation() {
        let config = SupplyChainGateConfig {
            policy: default_policy(),
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "0.1.0-dev",
                &digest,
                Some(&att),
                None,
                test_time(),
            )
            .unwrap();

        // Attestation present, so dev override doesn't relax policy.
        assert!(outcome.evidence.policy_snapshot.require_sbom);
    }

    // ── Verification Step Details ───────────────────────────────

    #[test]
    fn allowed_outcome_all_steps_pass() {
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

        assert!(outcome.allowed);
        assert!(outcome.evidence.steps.iter().all(|s| s.passed));
    }

    #[test]
    fn denied_outcome_has_at_least_one_failing_step() {
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
        assert!(outcome.evidence.steps.iter().any(|s| !s.passed));
    }

    #[test]
    fn permissive_no_artifacts_produces_minimal_steps() {
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

        // Permissive policy with no attestation/sbom should have few or no steps.
        assert!(outcome.allowed);
        assert_eq!(
            outcome.audit_event.steps_executed,
            outcome.evidence.steps.len()
        );
    }

    // ── Boundary / Edge Cases ───────────────────────────────────

    #[test]
    fn very_long_version_string() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();
        let long_version = "v".repeat(1000);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                &long_version,
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(outcome.version, long_version);
        assert_eq!(outcome.audit_event.version, long_version);
    }

    #[test]
    fn very_long_digest_string() {
        let long_digest = "x".repeat(10000);

        let outcome = assert_permissive_invalid_digest_denied(&long_digest);

        assert_eq!(outcome.audit_event.artifact_digest, long_digest);
    }

    #[test]
    fn unicode_version_string() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "v1.0.0-\u{1F600}",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert_eq!(outcome.version, "v1.0.0-\u{1F600}");
    }

    #[test]
    fn large_cache_capacity() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: usize::MAX,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        for i in 0u64..10 {
            let d = format!("blake3-256:{i:064}");
            gate.verify_at(&cid, "1.0.0", &d, None, None, test_time())
                .unwrap();
        }
        assert_eq!(gate.cache_size(), 10);
    }

    #[test]
    fn zero_slsa_level_policy_accepts_any() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 0,
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
    fn max_slsa_level_policy_denies_low_level() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 4,
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
    fn slsa_level_one_below_required_denies() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 3, // att is 2, exactly one below
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);

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
    }

    #[test]
    fn slsa_level_one_above_required_allows() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 1, // att is 2, one above
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);

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

        assert!(outcome.allowed);
    }

    // ── Multiple Trusted Builders ───────────────────────────────

    #[test]
    fn multiple_trusted_builders_first_matches() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                trusted_builders: vec![
                    "ci.example.com/builder".to_string(),
                    "other.example.com/builder".to_string(),
                ],
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);

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

        assert!(outcome.allowed);
    }

    #[test]
    fn multiple_trusted_builders_none_match() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                trusted_builders: vec![
                    "unknown-builder-a".to_string(),
                    "unknown-builder-b".to_string(),
                ],
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);

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
    fn empty_trusted_builders_accepts_all() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                trusted_builders: vec![],
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();
        let att = valid_attestation(&digest);

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

        assert!(outcome.allowed);
    }

    // ── Digest Matching ─────────────────────────────────────────

    #[test]
    fn digest_match_disabled_allows_mismatch() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_digest_match: false,
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let artifact_digest = format!("blake3-256:{}", "f".repeat(64));
        let att = valid_attestation(&valid_digest()); // Different from artifact_digest

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &artifact_digest,
                Some(&att),
                Some(&valid_sbom()),
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
    }

    #[test]
    fn digest_match_enabled_denies_mismatch() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_digest_match: true,
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let artifact_digest = format!("blake3-256:{}", "f".repeat(64));
        let att = valid_attestation(&valid_digest());

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &artifact_digest,
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

    // ── Cached Outcome Preserves Decision ───────────────────────

    #[test]
    fn cached_denied_outcome_stays_denied() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();

        // First: deny (no attestation).
        let first = gate
            .verify_at(&cid, "1.0.0", &valid_digest(), None, None, test_time())
            .unwrap();
        assert!(!first.allowed);
        assert!(!first.cached);

        // Second: cache hit, still denied.
        let second = gate
            .verify_at(&cid, "1.0.0", &valid_digest(), None, None, test_time())
            .unwrap();
        assert!(!second.allowed);
        assert!(second.cached);
        assert_eq!(second.evidence.decision, VerificationDecision::Deny);
    }

    #[test]
    fn cached_allowed_outcome_stays_allowed() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(first.allowed);
        assert!(!first.cached);

        let second = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(second.allowed);
        assert!(second.cached);
    }

    // ── Connector ID Propagation ────────────────────────────────

    #[test]
    fn different_connector_ids_produce_distinct_outcomes() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let cid_a = ConnectorId::from_static("fcp.alpha:utility:1.0.0");
        let cid_b = ConnectorId::from_static("fcp.beta:utility:2.0.0");
        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));

        let o1 = gate
            .verify_at(&cid_a, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        let o2 = gate
            .verify_at(&cid_b, "2.0.0", &d2, None, None, test_time())
            .unwrap();

        assert_eq!(o1.connector_id, cid_a);
        assert_eq!(o2.connector_id, cid_b);
        assert_ne!(o1.connector_id, o2.connector_id);
    }

    #[test]
    fn same_connector_different_digests_are_separate_cache_entries() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));

        gate.verify_at(&cid, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        gate.verify_at(&cid, "1.0.0", &d2, None, None, test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 2);
    }

    // ── Timestamp Handling ──────────────────────────────────────

    #[test]
    fn different_timestamps_produce_same_evidence_digest() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let t1 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0).unwrap();

        gate.clear_cache();
        let o1 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                t1,
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
                t2,
            )
            .unwrap();

        // Evidence digest depends only on evidence content, not timestamp.
        assert_eq!(
            o1.audit_event.evidence_digest,
            o2.audit_event.evidence_digest
        );
    }

    #[test]
    fn audit_event_timestamps_differ_for_different_verify_times() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let t1 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0).unwrap();

        gate.clear_cache();
        let o1 = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                t1,
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
                t2,
            )
            .unwrap();

        assert_eq!(o1.audit_event.verified_at, t1);
        assert_eq!(o2.audit_event.verified_at, t2);
    }

    // ── Evidence Artifact Digest ────────────────────────────────

    #[test]
    fn evidence_artifact_digest_matches_input() {
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

        assert_eq!(outcome.evidence.artifact_digest, digest);
    }

    #[test]
    fn evidence_artifact_digest_matches_for_denied() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(outcome.evidence.artifact_digest, digest);
    }

    // ── SupplyChainGateConfig Variations ────────────────────────

    #[test]
    fn config_with_custom_capacity() {
        let config = SupplyChainGateConfig {
            cache_capacity: 42,
            ..SupplyChainGateConfig::default()
        };
        assert_eq!(config.cache_capacity, 42);
        assert!(!config.allow_dev_overrides);
    }

    // ── Concurrent-like Usage (single-threaded simulation) ──────

    #[test]
    fn rapid_sequential_verifications_stay_consistent() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 5,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        for i in 0u64..20 {
            let d = format!("blake3-256:{i:064}");
            let outcome = gate
                .verify_at(&cid, "1.0.0", &d, None, None, test_time())
                .unwrap();
            assert!(outcome.allowed);
        }

        // Cache should be at capacity.
        assert_eq!(gate.cache_size(), 5);
    }

    // ── Verify Convenience Method ───────────────────────────────

    // ── Outcome Fields Consistency ──────────────────────────────

    #[test]
    fn outcome_version_matches_input() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "42.99.0-rc.1",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert_eq!(outcome.version, "42.99.0-rc.1");
        assert_eq!(outcome.audit_event.version, "42.99.0-rc.1");
    }

    #[test]
    fn outcome_allowed_matches_decision() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        // Allowed case.
        let allowed = gate
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
            allowed.allowed,
            allowed.evidence.decision == VerificationDecision::Allow
        );

        // Denied case.
        gate.clear_cache();
        let denied = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();
        assert_eq!(
            denied.allowed,
            denied.evidence.decision == VerificationDecision::Allow
        );
    }

    #[test]
    fn outcome_decision_and_reason_code_consistent() {
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

        // Allow decision should have Verified reason code.
        assert_eq!(outcome.evidence.decision, VerificationDecision::Allow);
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::Verified
        );
        assert_eq!(outcome.audit_event.decision, outcome.evidence.decision);
        assert_eq!(
            outcome.audit_event.reason_code,
            outcome.evidence.reason_code
        );
    }

    // ── Gate policy() Accessor ──────────────────────────────────

    #[test]
    fn policy_accessor_returns_configured_policy() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 3,
                trusted_builders: vec!["builder-x".to_string()],
                ..default_policy()
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let p = gate.policy();
        assert_eq!(p.min_slsa_level, 3);
        assert!(p.require_attestation);
        // default_policy() sets require_sbom to true (fail-closed default)
        assert!(p.require_sbom);
        assert!(!p.allow_unsigned);
        assert!(p.require_digest_match);
        assert_eq!(p.trusted_builders, vec!["builder-x"]);
    }

    #[test]
    fn policy_accessor_default_matches_default_policy() {
        let gate = SupplyChainGate::new();
        let p = gate.policy();
        let d = default_policy();
        assert_eq!(p.require_attestation, d.require_attestation);
        assert_eq!(p.require_sbom, d.require_sbom);
        assert_eq!(p.min_slsa_level, d.min_slsa_level);
        assert_eq!(p.allow_unsigned, d.allow_unsigned);
        assert_eq!(p.require_digest_match, d.require_digest_match);
        assert_eq!(p.trusted_builders, d.trusted_builders);
    }

    // ── Serde: SupplyChainVerificationPolicy ────────────────────

    #[test]
    fn policy_serde_roundtrip() {
        let policy = SupplyChainVerificationPolicy {
            require_attestation: true,
            require_sbom: false,
            min_slsa_level: 2,
            trusted_builders: vec!["builder-1".to_string(), "builder-2".to_string()],
            allow_unsigned: true,
            require_digest_match: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let rt: SupplyChainVerificationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, policy);
    }

    // ── Evidence Content Hash ───────────────────────────────────

    #[test]
    fn evidence_content_hash_is_blake3_format() {
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

        let hash = outcome
            .evidence
            .content_hash(HashAlgorithm::Blake3_256)
            .unwrap();
        assert!(hash.starts_with("blake3-256:"));
        let hex_part = &hash["blake3-256:".len()..];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn evidence_content_hash_sha256_format() {
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

        let hash = outcome
            .evidence
            .content_hash(HashAlgorithm::Sha256)
            .unwrap();
        assert!(hash.starts_with("sha256:"));
        let hex_part = &hash["sha256:".len()..];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── VerificationDecision Serde ──────────────────────────────

    #[test]
    fn verification_decision_allow_serde() {
        let json = serde_json::to_string(&VerificationDecision::Allow).unwrap();
        assert_eq!(json, r#""allow""#);
        let rt: VerificationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationDecision::Allow);
    }

    #[test]
    fn verification_decision_deny_serde() {
        let json = serde_json::to_string(&VerificationDecision::Deny).unwrap();
        assert_eq!(json, r#""deny""#);
        let rt: VerificationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationDecision::Deny);
    }

    // ── VerificationReasonCode Serde ────────────────────────────

    #[test]
    fn reason_code_verified_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::Verified).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::Verified);
    }

    #[test]
    fn reason_code_attestation_missing_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::AttestationMissing).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::AttestationMissing);
    }

    #[test]
    fn reason_code_slsa_level_insufficient_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::SlsaLevelInsufficient).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::SlsaLevelInsufficient);
    }

    #[test]
    fn reason_code_builder_untrusted_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::BuilderUntrusted).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::BuilderUntrusted);
    }

    #[test]
    fn reason_code_subject_digest_mismatch_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::SubjectDigestMismatch).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::SubjectDigestMismatch);
    }

    #[test]
    fn reason_code_sbom_missing_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::SbomMissing).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::SbomMissing);
    }

    #[test]
    fn reason_code_allowed_unsigned_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::AllowedUnsigned).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::AllowedUnsigned);
    }

    #[test]
    fn reason_code_attestation_invalid_serde() {
        let json = serde_json::to_string(&VerificationReasonCode::AttestationInvalid).unwrap();
        let rt: VerificationReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, VerificationReasonCode::AttestationInvalid);
    }

    // ── Verification Step Serde ─────────────────────────────────

    #[test]
    fn verification_step_serde_roundtrip() {
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

        for step in &outcome.evidence.steps {
            let json = serde_json::to_string(step).unwrap();
            let rt: fcp_evidence::VerificationStep = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, *step);
        }
    }

    // ── Eviction Does Not Evict Current Digest ──────────────────

    #[test]
    fn reinserting_same_verification_input_does_not_trigger_eviction() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 2,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));

        gate.verify_at(&cid, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        gate.verify_at(&cid, "2.0.0", &d2, None, None, test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 2);

        // Re-verify d1 — should be a cache hit, no eviction.
        gate.verify_at(&cid, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        assert_eq!(gate.cache_size(), 2);
    }

    // ── Extended Cache Eviction Scenarios ───────────────────────

    #[test]
    fn eviction_with_identical_timestamps_picks_some_entry() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 2,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();
        let t = test_time();

        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));
        let d3 = format!("blake3-256:{}", "3".repeat(64));

        gate.verify_at(&cid, "1.0.0", &d1, None, None, t).unwrap();
        gate.verify_at(&cid, "2.0.0", &d2, None, None, t).unwrap();
        assert_eq!(gate.cache_size(), 2);

        // Insert d3 — evicts one of d1 or d2 (same timestamp, deterministic but unspecified which).
        gate.verify_at(&cid, "3.0.0", &d3, None, None, t).unwrap();
        assert_eq!(gate.cache_size(), 2);

        // d3 should be cached.
        let r3 = gate.verify_at(&cid, "3.0.0", &d3, None, None, t).unwrap();
        assert!(r3.cached);
    }

    #[test]
    fn cache_grows_up_to_capacity_then_stays() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 4,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        for i in 0u64..10 {
            let d = format!("blake3-256:{i:064}");
            let t = Utc
                .with_ymd_and_hms(2026, 1, 1, 0, 0, u32::try_from(i).unwrap_or(0))
                .unwrap();
            gate.verify_at(&cid, "1.0.0", &d, None, None, t).unwrap();
        }
        assert_eq!(gate.cache_size(), 4);
    }

    #[test]
    fn eviction_preserves_newest_entries() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 3,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        // Insert 5 entries with increasing timestamps.
        for i in 0u64..5 {
            let d = format!("blake3-256:{i:064}");
            let t = Utc
                .with_ymd_and_hms(2026, 1, 1, 0, u32::try_from(i).unwrap_or(0), 0)
                .unwrap();
            gate.verify_at(&cid, "1.0.0", &d, None, None, t).unwrap();
        }
        assert_eq!(gate.cache_size(), 3);

        // The newest 3 (d2, d3, d4) should be cached; d0 and d1 evicted.
        let d4 = format!("blake3-256:{:064}", 4);
        let r4 = gate
            .verify_at(&cid, "1.0.0", &d4, None, None, test_time())
            .unwrap();
        assert!(r4.cached);
    }

    #[test]
    fn clear_cache_then_refill_works() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 3,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        for i in 0u64..3 {
            let d = format!("blake3-256:{i:064}");
            gate.verify_at(&cid, "1.0.0", &d, None, None, test_time())
                .unwrap();
        }
        assert_eq!(gate.cache_size(), 3);

        gate.clear_cache();
        assert_eq!(gate.cache_size(), 0);

        // Refill.
        for i in 10u64..13 {
            let d = format!("blake3-256:{i:064}");
            gate.verify_at(&cid, "1.0.0", &d, None, None, test_time())
                .unwrap();
        }
        assert_eq!(gate.cache_size(), 3);
    }

    #[test]
    fn multiple_clear_cycles_are_safe() {
        let gate = SupplyChainGate::new();
        for _ in 0..5 {
            gate.clear_cache();
            assert_eq!(gate.cache_size(), 0);
        }
    }

    // ── Cached Result Policy Snapshot Preservation ──────────────

    #[test]
    fn cached_result_preserves_policy_snapshot() {
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

        let first = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();
        assert!(!first.cached);

        let second = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();
        assert!(second.cached);
        assert_eq!(
            first.evidence.policy_snapshot,
            second.evidence.policy_snapshot
        );
        assert_eq!(second.evidence.policy_snapshot.min_slsa_level, 1);
    }

    #[test]
    fn cached_result_preserves_evidence_digest() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        let second = gate
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
            first.audit_event.evidence_digest,
            second.audit_event.evidence_digest
        );
    }

    // ── Audit Event Step Counts Under Various Policies ──────────

    #[test]
    fn audit_event_step_counts_for_allowed_unsigned() {
        // Use a permissive policy that allows unsigned connectors
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                None,
                None,
                test_time(),
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(
            outcome.audit_event.steps_passed,
            outcome.audit_event.steps_executed
        );
    }

    #[test]
    fn audit_event_decision_matches_evidence_decision() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let allowed = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();
        assert_eq!(allowed.audit_event.decision, allowed.evidence.decision);

        gate.clear_cache();
        let denied = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                None,
                None,
                test_time(),
            )
            .unwrap();
        assert_eq!(denied.audit_event.decision, denied.evidence.decision);
    }

    #[test]
    fn audit_event_reason_code_matches_evidence() {
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

        assert_eq!(
            outcome.audit_event.reason_code,
            outcome.evidence.reason_code
        );
        assert_eq!(
            outcome.audit_event.reason_code,
            VerificationReasonCode::AttestationMissing
        );
    }

    // ── Cached Audit Event Timestamp ────────────────────────────

    #[test]
    fn cached_audit_event_preserves_original_timestamp() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let t1 = Utc.with_ymd_and_hms(2026, 3, 1, 10, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 6, 1, 10, 0, 0).unwrap();

        let first = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), t1)
            .unwrap();
        assert_eq!(first.audit_event.verified_at, t1);

        // Cache hit uses original cache entry timestamp.
        let second = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), t2)
            .unwrap();
        assert!(second.cached);
        // The cached entry preserves its original verified_at.
        assert_eq!(second.audit_event.verified_at, t1);
    }

    // ── Outcome Digest Edge Cases ──────────────────────────────

    #[test]
    fn outcome_digest_differs_for_different_connectors() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let cid_a = ConnectorId::from_static("fcp.alpha:utility:1.0.0");
        let cid_b = ConnectorId::from_static("fcp.beta:utility:1.0.0");
        let d1 = format!("blake3-256:{}", "a".repeat(64));
        let d2 = format!("blake3-256:{}", "b".repeat(64));

        gate.clear_cache();
        let o1 = gate
            .verify_at(&cid_a, "1.0.0", &d1, None, None, test_time())
            .unwrap();
        gate.clear_cache();
        let o2 = gate
            .verify_at(&cid_b, "1.0.0", &d2, None, None, test_time())
            .unwrap();

        assert_ne!(outcome_digest(&o1), outcome_digest(&o2));
    }

    #[test]
    fn outcome_digest_differs_for_different_versions() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = test_connector_id();

        gate.clear_cache();
        let o1 = gate
            .verify_at(&cid, "1.0.0", &valid_digest(), None, None, test_time())
            .unwrap();
        gate.clear_cache();
        let o2 = gate
            .verify_at(&cid, "2.0.0", &valid_digest(), None, None, test_time())
            .unwrap();

        assert_ne!(outcome_digest(&o1), outcome_digest(&o2));
    }

    #[test]
    fn outcome_digest_for_empty_version_is_valid() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "",
                &valid_digest(),
                None,
                None,
                test_time(),
            )
            .unwrap();

        let d = outcome_digest(&outcome);
        assert!(d.starts_with("blake3-256:"));
        assert_eq!(d.len(), "blake3-256:".len() + 64);
    }

    #[test]
    fn outcome_digest_for_empty_digest_string_is_valid() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let outcome = gate
            .verify_at(&test_connector_id(), "1.0.0", "", None, None, test_time())
            .unwrap();

        let d = outcome_digest(&outcome);
        assert!(d.starts_with("blake3-256:"));
        assert_eq!(d.len(), "blake3-256:".len() + 64);
    }

    // ── Dev Override Detailed Interactions ──────────────────────

    #[test]
    fn dev_override_with_strict_slsa_no_artifacts_still_allows() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                min_slsa_level: 4,
                ..default_policy()
            },
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        // Dev override relaxes all requirements when both artifacts missing.
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
    fn dev_override_effective_policy_does_not_mutate_stored_policy() {
        let config = SupplyChainGateConfig {
            policy: default_policy(),
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        // Trigger dev override.
        gate.verify_at(
            &test_connector_id(),
            "dev",
            &valid_digest(),
            None,
            None,
            test_time(),
        )
        .unwrap();

        // Stored policy should remain strict.
        let p = gate.policy();
        assert!(p.require_attestation);
        assert!(p.require_sbom);
        assert!(!p.allow_unsigned);
    }

    #[test]
    fn dev_override_then_strict_verify_still_denies() {
        let config = SupplyChainGateConfig {
            policy: default_policy(),
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        // Dev override allows this.
        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let dev = gate
            .verify_at(&test_connector_id(), "dev", &d1, None, None, test_time())
            .unwrap();
        assert!(dev.allowed);

        // Strict verify (with attestation present) on different digest — should deny if SBOM missing.
        let d2 = format!("blake3-256:{}", "2".repeat(64));
        let att = valid_attestation(&d2);
        let strict = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &d2,
                Some(&att),
                None,
                test_time(),
            )
            .unwrap();
        assert!(!strict.allowed);
        assert_eq!(
            strict.evidence.reason_code,
            VerificationReasonCode::SbomMissing
        );
    }

    // ── GateOutcome Field Consistency ───────────────────────────

    #[test]
    fn outcome_connector_id_matches_input() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let cid = ConnectorId::from_static("fcp.custom-conn:utility:3.2.1");

        let outcome = gate
            .verify_at(&cid, "3.2.1", &valid_digest(), None, None, test_time())
            .unwrap();

        assert_eq!(outcome.connector_id, cid);
        assert_eq!(outcome.audit_event.connector_id, cid);
    }

    #[test]
    fn outcome_cached_flag_matches_audit_event() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert_eq!(first.cached, first.audit_event.cached);
        assert!(!first.cached);

        let second = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert_eq!(second.cached, second.audit_event.cached);
        assert!(second.cached);
    }

    // ── Serialization Additional Scenarios ──────────────────────

    #[test]
    fn gate_outcome_denied_json_contains_deny() {
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

        let json = serde_json::to_string(&outcome).unwrap();
        assert!(json.contains("\"allowed\":false"));
        assert!(json.contains("\"decision\":\"deny\""));
    }

    #[test]
    fn gate_outcome_cached_flag_serializes() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        let json1 = serde_json::to_string(&first).unwrap();
        assert!(json1.contains("\"cached\":false"));

        let second = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        let json2 = serde_json::to_string(&second).unwrap();
        assert!(json2.contains("\"cached\":true"));
    }

    #[test]
    fn gate_outcome_json_value_structure() {
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

        let val = serde_json::to_value(&outcome).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("connector_id"));
        assert!(obj.contains_key("version"));
        assert!(obj.contains_key("allowed"));
        assert!(obj.contains_key("evidence"));
        assert!(obj.contains_key("audit_event"));
        assert!(obj.contains_key("cached"));
    }

    // ── Verify with Different Connector IDs But Same Digest ────

    #[test]
    fn same_digest_different_connectors_share_cache() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let digest = valid_digest();

        let cid_a = ConnectorId::from_static("fcp.alpha:utility:1.0.0");
        let cid_b = ConnectorId::from_static("fcp.beta:utility:1.0.0");

        let first = gate
            .verify_at(&cid_a, "1.0.0", &digest, None, None, test_time())
            .unwrap();
        assert!(!first.cached);

        // Same verification inputs, different connector: cache reuse is still valid.
        let second = gate
            .verify_at(&cid_b, "1.0.0", &digest, None, None, test_time())
            .unwrap();
        assert!(second.cached);
        assert_eq!(gate.cache_size(), 1);

        // But the outcome has the correct connector_id from the second call.
        assert_eq!(second.connector_id, cid_b);
        assert_eq!(second.audit_event.connector_id, cid_b);
    }

    // ── Convenience verify() Method ────────────────────────────

    #[test]
    fn verify_convenience_populates_all_fields() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let outcome = gate
            .verify(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(outcome.connector_id, test_connector_id());
        assert_eq!(outcome.version, "1.0.0");
        assert!(!outcome.cached);
        assert!(
            outcome
                .audit_event
                .evidence_digest
                .starts_with("blake3-256:")
        );
    }

    #[test]
    fn verify_convenience_denied_case() {
        let gate = SupplyChainGate::new();

        let outcome = gate
            .verify(&test_connector_id(), "1.0.0", &valid_digest(), None, None)
            .unwrap();

        assert!(!outcome.allowed);
        assert_eq!(outcome.evidence.decision, VerificationDecision::Deny);
    }

    // ── Policy Edge Cases ──────────────────────────────────────

    #[test]
    fn attestation_required_sbom_not_required_no_sbom_allows() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_attestation: true,
                require_sbom: false,
                allow_unsigned: false,
                require_digest_match: true,
                min_slsa_level: 0,
                trusted_builders: vec![],
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
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

        assert!(outcome.allowed);
    }

    #[test]
    fn sbom_required_attestation_not_required_no_attestation_allows() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_attestation: false,
                require_sbom: true,
                allow_unsigned: false,
                require_digest_match: false,
                min_slsa_level: 0,
                trusted_builders: vec![],
            },
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

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

        assert!(outcome.allowed);
    }

    #[test]
    fn neither_required_allows_with_no_artifacts() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_attestation: false,
                require_sbom: false,
                allow_unsigned: true,
                require_digest_match: false,
                min_slsa_level: 0,
                trusted_builders: vec![],
            },
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

    #[test]
    fn both_required_both_present_matching_digest_allows() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_attestation: true,
                require_sbom: true,
                allow_unsigned: false,
                require_digest_match: true,
                min_slsa_level: 0,
                trusted_builders: vec![],
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
        assert_eq!(
            outcome.evidence.reason_code,
            VerificationReasonCode::Verified
        );
    }

    // ── Gate Debug Trait ────────────────────────────────────────

    #[test]
    fn gate_new_has_default_config() {
        let gate = SupplyChainGate::new();
        assert_eq!(gate.cache_size(), 0);
        assert!(gate.policy().require_attestation);
    }

    #[test]
    fn gate_outcome_debug_output() {
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

        let dbg = format!("{outcome:?}");
        assert!(dbg.contains("GateOutcome"));
        assert!(dbg.contains("allowed"));
    }

    #[test]
    fn audit_event_debug_output() {
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

        let dbg = format!("{:?}", outcome.audit_event);
        assert!(dbg.contains("VerificationAuditEvent"));
        assert!(dbg.contains("connector_id"));
    }

    // ── Evidence Steps in Cached Results ────────────────────────

    #[test]
    fn cached_result_has_same_steps() {
        let gate = SupplyChainGate::new();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        let second = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &digest,
                Some(&att),
                Some(&sbom),
                test_time(),
            )
            .unwrap();

        assert_eq!(first.evidence.steps, second.evidence.steps);
        assert_eq!(
            first.audit_event.steps_executed,
            second.audit_event.steps_executed
        );
        assert_eq!(
            first.audit_event.steps_passed,
            second.audit_event.steps_passed
        );
    }

    // ── Clone of Cached Outcome ────────────────────────────────

    #[test]
    fn clone_of_cached_outcome_preserves_cached_flag() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        gate.verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();

        let cached = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(cached.cached);

        let cloned = cached.clone();
        assert!(cloned.cached);
        assert_eq!(cloned.evidence, cached.evidence);
        assert_eq!(cloned.audit_event, cached.audit_event);
    }

    // ── Multiple Connectors Eviction ───────────────────────────

    #[test]
    fn eviction_across_multiple_connector_ids() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            cache_capacity: 2,
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);

        let cid_a = ConnectorId::from_static("fcp.alpha:utility:1.0.0");
        let cid_b = ConnectorId::from_static("fcp.beta:utility:1.0.0");
        let cid_c = ConnectorId::from_static("fcp.gamma:utility:1.0.0");

        let d1 = format!("blake3-256:{}", "1".repeat(64));
        let d2 = format!("blake3-256:{}", "2".repeat(64));
        let d3 = format!("blake3-256:{}", "3".repeat(64));

        let t1 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
        let t3 = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();

        gate.verify_at(&cid_a, "1.0.0", &d1, None, None, t1)
            .unwrap();
        gate.verify_at(&cid_b, "1.0.0", &d2, None, None, t2)
            .unwrap();
        assert_eq!(gate.cache_size(), 2);

        // Evict d1 (oldest).
        gate.verify_at(&cid_c, "1.0.0", &d3, None, None, t3)
            .unwrap();
        assert_eq!(gate.cache_size(), 2);

        // d2 still cached (was second oldest, but not evicted yet).
        let r2 = gate
            .verify_at(&cid_b, "1.0.0", &d2, None, None, t3)
            .unwrap();
        assert!(r2.cached);

        // d3 still cached.
        let r3 = gate
            .verify_at(&cid_c, "1.0.0", &d3, None, None, t3)
            .unwrap();
        assert!(r3.cached);
    }

    // ── Outcome Digest Consistency After Clone ─────────────────

    #[test]
    fn outcome_digest_same_for_clone() {
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

        let cloned = outcome.clone();
        assert_eq!(outcome_digest(&outcome), outcome_digest(&cloned));
    }

    // ── Artifact Digest Edge Cases ─────────────────────────────

    #[test]
    fn whitespace_only_digest() {
        let outcome = assert_permissive_invalid_digest_denied("   ");

        assert_eq!(outcome.audit_event.artifact_digest, "   ");
    }

    #[test]
    fn special_characters_in_digest() {
        let digest = "sha256:abc!@#$%^&*()";
        let outcome = assert_permissive_invalid_digest_denied(digest);

        assert_eq!(outcome.audit_event.artifact_digest, digest);
    }

    #[test]
    fn unicode_digest_string() {
        let digest = "blake3-256:\u{1F600}\u{1F601}\u{1F602}";
        let outcome = assert_permissive_invalid_digest_denied(digest);

        assert_eq!(outcome.evidence.artifact_digest, digest);
    }

    // ── Cache Key Boundary: Same Digest New Artifacts ──────────

    #[test]
    fn same_digest_with_new_artifacts_recomputes_and_allows() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();

        // First verify without artifacts (denied).
        let first = gate
            .verify_at(&cid, "1.0.0", &digest, None, None, test_time())
            .unwrap();
        assert!(!first.allowed);

        // Second verify with valid artifacts should recompute under a different cache key.
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();
        let second = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(!second.cached);
        assert!(second.allowed);
        assert_eq!(gate.cache_size(), 2);
    }

    #[test]
    fn same_digest_without_artifacts_after_verified_artifacts_recomputes_and_denies() {
        let gate = SupplyChainGate::new();
        let cid = test_connector_id();
        let digest = valid_digest();
        let att = valid_attestation(&digest);
        let sbom = valid_sbom();

        let first = gate
            .verify_at(&cid, "1.0.0", &digest, Some(&att), Some(&sbom), test_time())
            .unwrap();
        assert!(first.allowed);

        let second = gate
            .verify_at(&cid, "1.0.0", &digest, None, None, test_time())
            .unwrap();
        assert!(!second.cached);
        assert!(!second.allowed);
        assert_eq!(gate.cache_size(), 2);
    }

    // ── Verify At Epoch Time ───────────────────────────────────

    #[test]
    fn verify_at_unix_epoch() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let epoch = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                epoch,
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(outcome.audit_event.verified_at, epoch);
    }

    #[test]
    fn verify_at_far_future() {
        let config = SupplyChainGateConfig {
            policy: permissive_policy(),
            ..SupplyChainGateConfig::default()
        };
        let gate = SupplyChainGate::with_config(config);
        let far_future = Utc.with_ymd_and_hms(2099, 12, 31, 23, 59, 59).unwrap();

        let outcome = gate
            .verify_at(
                &test_connector_id(),
                "1.0.0",
                &valid_digest(),
                None,
                None,
                far_future,
            )
            .unwrap();

        assert!(outcome.allowed);
        assert_eq!(outcome.audit_event.verified_at, far_future);
    }

    // ── SupplyChainGateConfig Custom Variations ────────────────

    #[test]
    fn config_all_fields_customized() {
        let config = SupplyChainGateConfig {
            policy: SupplyChainVerificationPolicy {
                require_attestation: false,
                require_sbom: false,
                allow_unsigned: true,
                require_digest_match: false,
                min_slsa_level: 1,
                trusted_builders: vec!["b1".to_string(), "b2".to_string()],
            },
            cache_capacity: 500,
            allow_dev_overrides: true,
        };
        assert_eq!(config.cache_capacity, 500);
        assert!(config.allow_dev_overrides);
        assert_eq!(config.policy.min_slsa_level, 1);
        assert_eq!(config.policy.trusted_builders.len(), 2);
    }

    #[test]
    fn config_debug_with_dev_overrides() {
        let config = SupplyChainGateConfig {
            allow_dev_overrides: true,
            ..SupplyChainGateConfig::default()
        };
        let dbg = format!("{config:?}");
        assert!(dbg.contains("allow_dev_overrides"));
        assert!(dbg.contains("true"));
    }
}
