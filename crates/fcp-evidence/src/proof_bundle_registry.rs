//! Canonical registry schema for proof bundles and proof-manifest rows.
//!
//! The registry is intentionally stricter than the older proof graph corpus: it
//! records the owner, rerun command, artifact digests, freshness policy, and
//! live/replay/static proof class before a row can be treated as green proof.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable schema identifier for proof-bundle registry documents.
pub const PROOF_BUNDLE_REGISTRY_SCHEMA: &str = "fcp.proof-bundle-registry.v1";

/// Machine-readable proof registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleRegistry {
    /// Schema identifier; must be [`PROOF_BUNDLE_REGISTRY_SCHEMA`].
    pub schema: String,
    /// Stable registry id, for example `fcp3-final-proof`.
    pub registry_id: String,
    /// Registry generation timestamp as Unix milliseconds.
    pub generated_at_unix_ms: u64,
    /// Source documents, scripts, and catalog surfaces represented by entries.
    #[serde(default)]
    pub sources: Vec<ProofBundleSource>,
    /// Individual proof rows.
    #[serde(default)]
    pub proofs: Vec<ProofBundleEntry>,
}

impl ProofBundleRegistry {
    /// Validate the registry against the fail-closed freshness and provenance contract.
    ///
    /// # Errors
    ///
    /// Returns [`ProofBundleRegistryError`] when required ownership,
    /// rerun, digest, source, freshness, or live-claim fields are missing or
    /// inconsistent.
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), ProofBundleRegistryError> {
        if self.schema != PROOF_BUNDLE_REGISTRY_SCHEMA {
            return Err(ProofBundleRegistryError::InvalidSchema {
                expected: PROOF_BUNDLE_REGISTRY_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if is_blank(&self.registry_id) {
            return Err(ProofBundleRegistryError::MissingRegistryId);
        }

        let mut source_ids = BTreeSet::new();
        for source in &self.sources {
            source.validate()?;
            if !source_ids.insert(source.source_id.as_str()) {
                return Err(ProofBundleRegistryError::DuplicateSource {
                    source_id: source.source_id.clone(),
                });
            }
        }

        for proof in &self.proofs {
            proof.validate(now_unix_ms, &source_ids)?;
        }

        Ok(())
    }
}

/// Source surface represented by one or more proof entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleSource {
    /// Stable source id used by proof entries.
    pub source_id: String,
    /// Repository-relative source path.
    pub path: String,
    /// Human-readable source purpose.
    pub purpose: String,
    /// Source class.
    pub source_kind: ProofBundleSourceKind,
    /// Default proof class for rows from this source.
    pub default_proof_class: ProofClass,
    /// Bead that owns the source surface, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owning_bead: Option<String>,
}

impl ProofBundleSource {
    fn validate(&self) -> Result<(), ProofBundleRegistryError> {
        if is_blank(&self.source_id) {
            return Err(ProofBundleRegistryError::MissingSourceId);
        }
        if is_blank(&self.path) {
            return Err(ProofBundleRegistryError::MissingSourcePath {
                source_id: self.source_id.clone(),
            });
        }
        Ok(())
    }
}

/// Kind of source material represented by the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleSourceKind {
    /// Top-level final proof manifest.
    FinalProofManifest,
    /// Section-level proof index.
    SectionProofIndex,
    /// Core platform evidence index.
    CorePlatformEvidenceIndex,
    /// E2E script that writes `BUNDLE_MANIFEST.json`.
    E2eBundleManifestProducer,
    /// Existing `fwc` or `fcp-evidence` proof graph/catalog surface.
    FwcProofGraphSurface,
    /// Other documented proof source.
    Other,
}

/// Class of evidence behind a proof row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofClass {
    /// A real live-service run.
    Live,
    /// A host-backed run against the local FCP host.
    HostBacked,
    /// A replay or dry-run bundle.
    Replay,
    /// Offline artifact or deterministic static corpus.
    OfflineStatic,
    /// Static documentation or review index.
    StaticDoc,
    /// A structured skip record with a reason and evidence path.
    StructuredSkip,
}

impl ProofClass {
    /// Return whether this proof class may set `verifier.live_claim=true`.
    #[must_use]
    pub const fn permits_live_claim(self) -> bool {
        matches!(self, Self::Live | Self::HostBacked)
    }
}

/// One proof registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleEntry {
    /// Stable proof id.
    pub proof_id: String,
    /// Owning Beads id.
    pub owning_bead: String,
    /// Redaction-safe claim text.
    pub claim_text: String,
    /// Source document row or script location.
    pub source_document: ProofSourceDocumentRow,
    /// Evidence class.
    pub proof_class: ProofClass,
    /// Command that regenerates or rechecks the proof.
    pub rerun: ProofRegistryCommand,
    /// Artifacts expected from the proof rerun.
    #[serde(default)]
    pub expected_artifacts: Vec<ExpectedProofArtifact>,
    /// Git revision under test.
    pub git_revision_under_test: String,
    /// Proof generation timestamp as Unix milliseconds.
    pub generated_at_unix_ms: u64,
    /// Freshness policy used by gates.
    pub freshness_policy: FreshnessPolicy,
    /// Last verifier observation.
    pub verifier: VerifierObservation,
    /// Structured skip data, required when `proof_class` is `structured_skip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_skip: Option<StructuredSkipReason>,
    /// Redaction policy for the proof entry.
    pub redaction: ProofRedaction,
}

impl ProofBundleEntry {
    fn validate(
        &self,
        now_unix_ms: u64,
        known_sources: &BTreeSet<&str>,
    ) -> Result<(), ProofBundleRegistryError> {
        if is_blank(&self.proof_id) {
            return Err(ProofBundleRegistryError::MissingProofId);
        }
        if is_blank(&self.owning_bead) {
            return Err(ProofBundleRegistryError::MissingOwner {
                proof_id: self.proof_id.clone(),
            });
        }
        if is_blank(&self.claim_text) {
            return Err(ProofBundleRegistryError::MissingClaimText {
                proof_id: self.proof_id.clone(),
            });
        }
        if !known_sources.contains(self.source_document.source_id.as_str()) {
            return Err(ProofBundleRegistryError::UnknownSource {
                proof_id: self.proof_id.clone(),
                source_id: self.source_document.source_id.clone(),
            });
        }
        if self.rerun.argv.is_empty() {
            return Err(ProofBundleRegistryError::MissingRerunCommand {
                proof_id: self.proof_id.clone(),
            });
        }
        if self.expected_artifacts.is_empty() {
            return Err(ProofBundleRegistryError::MissingExpectedArtifact {
                proof_id: self.proof_id.clone(),
            });
        }

        if let Some(artifact) = self
            .expected_artifacts
            .iter()
            .find(|artifact| artifact.required && !artifact.has_digest())
        {
            return Err(ProofBundleRegistryError::MissingDigest {
                proof_id: self.proof_id.clone(),
                artifact_path: artifact.path.clone(),
            });
        }

        self.verifier.validate(&self.proof_id, self.proof_class)?;
        self.validate_structured_skip()?;

        let classification = self
            .freshness_policy
            .classify(self.generated_at_unix_ms, now_unix_ms);
        if classification == FreshnessClassification::StaleFailClosed {
            return Err(ProofBundleRegistryError::StaleFreshness {
                proof_id: self.proof_id.clone(),
                classification,
            });
        }

        Ok(())
    }

    fn validate_structured_skip(&self) -> Result<(), ProofBundleRegistryError> {
        if self.proof_class == ProofClass::StructuredSkip {
            let Some(skip) = &self.structured_skip else {
                return Err(ProofBundleRegistryError::MissingStructuredSkip {
                    proof_id: self.proof_id.clone(),
                });
            };
            if is_blank(&skip.reason_code) {
                return Err(ProofBundleRegistryError::MissingStructuredSkipReason {
                    proof_id: self.proof_id.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Source document row or script location for a proof entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSourceDocumentRow {
    /// Source id from [`ProofBundleSource`].
    pub source_id: String,
    /// Section heading or script phase.
    pub section: String,
    /// Table row label or artifact name.
    pub row_label: String,
    /// Optional one-based line hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_hint: Option<u32>,
}

/// Rerun command used by either proof regeneration or verifier observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRegistryCommand {
    /// Command argv; the executable is `argv[0]`.
    pub argv: Vec<String>,
    /// Repository-relative working directory.
    pub working_dir: String,
    /// Whether this command must be routed through `rch`.
    pub requires_rch: bool,
    /// Environment keys required by the command. Values are never stored.
    #[serde(default)]
    pub required_env_keys: BTreeSet<String>,
    /// Accepted process exit codes.
    pub expected_exit_codes: BTreeSet<i32>,
}

/// Artifact expected from proof generation or verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedProofArtifact {
    /// Repository-relative or bundle-relative path.
    pub path: String,
    /// Artifact kind such as `manifest`, `summary`, or `forensic_steps`.
    pub kind: String,
    /// Required artifacts must carry a digest.
    pub required: bool,
    /// Digest for required artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<ArtifactDigest>,
    /// Script, manifest, or crate surface that produces the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced_by: Option<String>,
}

impl ExpectedProofArtifact {
    fn has_digest(&self) -> bool {
        self.digest
            .as_ref()
            .is_some_and(|digest| !is_blank(&digest.value))
    }
}

/// Artifact digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDigest {
    /// Digest algorithm.
    pub algorithm: ArtifactDigestAlgorithm,
    /// Hex-encoded digest value.
    pub value: String,
}

/// Supported artifact digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDigestAlgorithm {
    /// BLAKE3 digest.
    Blake3,
    /// SHA-256 digest.
    Sha256,
    /// SHA-512 digest.
    Sha512,
}

/// Freshness policy for a proof entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessPolicy {
    /// Maximum accepted artifact age in milliseconds.
    pub max_age_ms: u64,
    /// Whether this proof is required before a gate can be green.
    pub required_for_green: bool,
    /// Action when the proof is stale.
    pub stale_action: StaleProofAction,
}

impl FreshnessPolicy {
    /// Classify a proof timestamp against this freshness policy.
    #[must_use]
    pub const fn classify(
        &self,
        generated_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> FreshnessClassification {
        let age_ms = now_unix_ms.saturating_sub(generated_at_unix_ms);
        if age_ms <= self.max_age_ms {
            FreshnessClassification::Fresh
        } else {
            match (self.required_for_green, self.stale_action) {
                (true, StaleProofAction::FailClosed) => FreshnessClassification::StaleFailClosed,
                (_, StaleProofAction::SkipOnly) => FreshnessClassification::StaleSkipOnly,
                _ => FreshnessClassification::StaleWarnOnly,
            }
        }
    }
}

/// Stale-proof action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleProofAction {
    /// Required gate must fail closed.
    FailClosed,
    /// Gate may warn but not mark proof green.
    WarnOnly,
    /// Proof row is skipped and cannot mark a claim green.
    SkipOnly,
}

/// Freshness classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessClassification {
    /// Proof is within its freshness window.
    Fresh,
    /// Required proof is stale and must fail closed.
    StaleFailClosed,
    /// Proof is stale but advisory only.
    StaleWarnOnly,
    /// Proof is stale and skipped.
    StaleSkipOnly,
}

/// Last verifier observation for a proof entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierObservation {
    /// Verifier command that produced this observation.
    pub command: ProofRegistryCommand,
    /// Verifier result.
    pub result: VerificationResult,
    /// Observation timestamp as Unix milliseconds.
    pub observed_at_unix_ms: u64,
    /// Redaction-safe verifier log path.
    pub log_path: String,
    /// Whether the verifier claims this proof is live.
    pub live_claim: bool,
}

impl VerifierObservation {
    fn validate(
        &self,
        proof_id: &str,
        proof_class: ProofClass,
    ) -> Result<(), ProofBundleRegistryError> {
        if self.command.argv.is_empty() {
            return Err(ProofBundleRegistryError::MissingVerifierCommand {
                proof_id: proof_id.to_owned(),
            });
        }
        if self.live_claim && !proof_class.permits_live_claim() {
            return Err(ProofBundleRegistryError::LiveClaimForNonLiveProof {
                proof_id: proof_id.to_owned(),
                proof_class,
            });
        }
        Ok(())
    }
}

/// Verifier result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    /// Verifier passed.
    Passed,
    /// Verifier failed.
    Failed,
    /// Verifier was blocked by infrastructure or missing prerequisites.
    Blocked,
    /// Verifier recorded a structured skip.
    Skipped,
}

/// Structured skip metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredSkipReason {
    /// Whether the skip is allowed by the proof policy.
    pub allowed: bool,
    /// Stable reason code.
    pub reason_code: String,
    /// Redaction-safe path to skip evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_path: Option<String>,
}

/// Redaction metadata for a proof entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRedaction {
    /// Redaction classification.
    pub classification: RedactionClassification,
    /// Redaction notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Redaction classification for registry content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClassification {
    /// Safe to publish inside repo artifacts.
    Public,
    /// Internal redaction-safe metadata.
    Internal,
    /// Redacted or synthetic metadata.
    Redacted,
    /// Secret-bearing raw transcript; not allowed in this registry.
    SecretBearing,
}

/// Validation failures for proof-bundle registries.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProofBundleRegistryError {
    /// The registry schema id does not match the canonical id.
    #[error("invalid proof bundle registry schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema id.
        expected: &'static str,
        /// Actual schema id.
        actual: String,
    },
    /// The registry id is missing.
    #[error("proof bundle registry id is required")]
    MissingRegistryId,
    /// A source id is missing.
    #[error("proof bundle source id is required")]
    MissingSourceId,
    /// A source path is missing.
    #[error("proof bundle source {source_id} path is required")]
    MissingSourcePath {
        /// Source id.
        source_id: String,
    },
    /// A source id appears more than once.
    #[error("duplicate proof bundle source {source_id}")]
    DuplicateSource {
        /// Source id.
        source_id: String,
    },
    /// A proof id is missing.
    #[error("proof id is required")]
    MissingProofId,
    /// A proof owner is missing.
    #[error("proof {proof_id} is missing an owning bead")]
    MissingOwner {
        /// Proof id.
        proof_id: String,
    },
    /// Claim text is missing.
    #[error("proof {proof_id} is missing claim text")]
    MissingClaimText {
        /// Proof id.
        proof_id: String,
    },
    /// Source id is not present in the source inventory.
    #[error("proof {proof_id} references unknown source {source_id}")]
    UnknownSource {
        /// Proof id.
        proof_id: String,
        /// Source id.
        source_id: String,
    },
    /// Rerun argv is missing.
    #[error("proof {proof_id} is missing a rerun command")]
    MissingRerunCommand {
        /// Proof id.
        proof_id: String,
    },
    /// No expected artifacts are listed.
    #[error("proof {proof_id} is missing expected artifacts")]
    MissingExpectedArtifact {
        /// Proof id.
        proof_id: String,
    },
    /// A required artifact has no digest.
    #[error("proof {proof_id} required artifact {artifact_path} is missing a digest")]
    MissingDigest {
        /// Proof id.
        proof_id: String,
        /// Artifact path.
        artifact_path: String,
    },
    /// Verifier command argv is missing.
    #[error("proof {proof_id} is missing a verifier command")]
    MissingVerifierCommand {
        /// Proof id.
        proof_id: String,
    },
    /// A non-live proof class tried to claim live proof.
    #[error("proof {proof_id} has non-live class {proof_class:?} but claims live proof")]
    LiveClaimForNonLiveProof {
        /// Proof id.
        proof_id: String,
        /// Proof class.
        proof_class: ProofClass,
    },
    /// Structured skip metadata is missing.
    #[error("proof {proof_id} is a structured skip but has no structured skip metadata")]
    MissingStructuredSkip {
        /// Proof id.
        proof_id: String,
    },
    /// Structured skip reason is missing.
    #[error("proof {proof_id} is a structured skip but has no reason code")]
    MissingStructuredSkipReason {
        /// Proof id.
        proof_id: String,
    },
    /// Required proof freshness failed closed.
    #[error("proof {proof_id} is stale with classification {classification:?}")]
    StaleFreshness {
        /// Proof id.
        proof_id: String,
        /// Freshness classification.
        classification: FreshnessClassification,
    },
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_700_000_000_000;

    fn command(argv: &[&str]) -> ProofRegistryCommand {
        ProofRegistryCommand {
            argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
            working_dir: ".".to_owned(),
            requires_rch: false,
            required_env_keys: BTreeSet::new(),
            expected_exit_codes: BTreeSet::from([0]),
        }
    }

    fn digest() -> ArtifactDigest {
        ArtifactDigest {
            algorithm: ArtifactDigestAlgorithm::Blake3,
            value: "0123456789abcdef".repeat(4),
        }
    }

    fn source() -> ProofBundleSource {
        ProofBundleSource {
            source_id: "final-manifest".to_owned(),
            path: "docs/FCP3_Final_Proof_Manifest.md".to_owned(),
            purpose: "Final proof manifest".to_owned(),
            source_kind: ProofBundleSourceKind::FinalProofManifest,
            default_proof_class: ProofClass::StaticDoc,
            owning_bead: Some("flywheel_connectors-8bqme.3".to_owned()),
        }
    }

    fn proof() -> ProofBundleEntry {
        ProofBundleEntry {
            proof_id: "final-operational-proof".to_owned(),
            owning_bead: "flywheel_connectors-8bqme.3".to_owned(),
            claim_text: "Operational proof index is wired into final review".to_owned(),
            source_document: ProofSourceDocumentRow {
                source_id: "final-manifest".to_owned(),
                section: "Proof Sections".to_owned(),
                row_label: "Operational".to_owned(),
                line_hint: Some(28),
            },
            proof_class: ProofClass::StaticDoc,
            rerun: command(&[
                "rg",
                "-n",
                "Operational",
                "docs/FCP3_Final_Proof_Manifest.md",
            ]),
            expected_artifacts: vec![ExpectedProofArtifact {
                path: "docs/FCP3_Final_Proof_Manifest.md".to_owned(),
                kind: "proof_manifest".to_owned(),
                required: true,
                digest: Some(digest()),
                produced_by: Some("docs/FCP3_Final_Proof_Manifest.md".to_owned()),
            }],
            git_revision_under_test: "HEAD".to_owned(),
            generated_at_unix_ms: NOW_MS,
            freshness_policy: FreshnessPolicy {
                max_age_ms: 60_000,
                required_for_green: true,
                stale_action: StaleProofAction::FailClosed,
            },
            verifier: VerifierObservation {
                command: command(&[
                    "rg",
                    "-n",
                    "Operational",
                    "docs/FCP3_Final_Proof_Manifest.md",
                ]),
                result: VerificationResult::Passed,
                observed_at_unix_ms: NOW_MS,
                log_path: "target/proof/final-operational-proof.log".to_owned(),
                live_claim: false,
            },
            structured_skip: None,
            redaction: ProofRedaction {
                classification: RedactionClassification::Public,
                notes: None,
            },
        }
    }

    fn registry_with(proof: ProofBundleEntry) -> ProofBundleRegistry {
        ProofBundleRegistry {
            schema: PROOF_BUNDLE_REGISTRY_SCHEMA.to_owned(),
            registry_id: "test-registry".to_owned(),
            generated_at_unix_ms: NOW_MS,
            sources: vec![source()],
            proofs: vec![proof],
        }
    }

    #[test]
    fn valid_static_doc_registry_passes_without_live_claim() {
        registry_with(proof())
            .validate(NOW_MS)
            .expect("valid registry should pass");
    }

    #[test]
    fn missing_owner_fails_validation() {
        let mut proof = proof();
        proof.owning_bead.clear();

        let error = registry_with(proof)
            .validate(NOW_MS)
            .expect_err("missing owner should fail");

        assert!(matches!(
            error,
            ProofBundleRegistryError::MissingOwner { .. }
        ));
    }

    #[test]
    fn missing_rerun_command_fails_validation() {
        let mut proof = proof();
        proof.rerun.argv.clear();

        let error = registry_with(proof)
            .validate(NOW_MS)
            .expect_err("missing rerun should fail");

        assert!(matches!(
            error,
            ProofBundleRegistryError::MissingRerunCommand { .. }
        ));
    }

    #[test]
    fn missing_digest_on_required_artifact_fails_validation() {
        let mut proof = proof();
        if let Some(artifact) = proof.expected_artifacts.first_mut() {
            artifact.digest = None;
        }

        let error = registry_with(proof)
            .validate(NOW_MS)
            .expect_err("missing digest should fail");

        assert!(matches!(
            error,
            ProofBundleRegistryError::MissingDigest { .. }
        ));
    }

    #[test]
    fn structured_skip_requires_reason_code() {
        let mut proof = proof();
        proof.proof_class = ProofClass::StructuredSkip;
        proof.verifier.result = VerificationResult::Skipped;
        proof.structured_skip = Some(StructuredSkipReason {
            allowed: true,
            reason_code: String::new(),
            evidence_path: Some("target/proof/skip.json".to_owned()),
        });

        let error = registry_with(proof)
            .validate(NOW_MS)
            .expect_err("structured skip without reason should fail");

        assert!(matches!(
            error,
            ProofBundleRegistryError::MissingStructuredSkipReason { .. }
        ));
    }

    #[test]
    fn stale_fail_closed_policy_is_classified_and_rejected() {
        let proof = proof();

        assert_eq!(
            proof.freshness_policy.classify(NOW_MS - 120_000, NOW_MS),
            FreshnessClassification::StaleFailClosed
        );

        let error = registry_with(ProofBundleEntry {
            generated_at_unix_ms: NOW_MS - 120_000,
            ..proof
        })
        .validate(NOW_MS)
        .expect_err("stale fail-closed proof should fail");

        assert!(matches!(
            error,
            ProofBundleRegistryError::StaleFreshness { .. }
        ));
    }

    #[test]
    fn replay_and_static_entries_cannot_claim_live_proof() {
        let mut proof = proof();
        proof.proof_class = ProofClass::Replay;
        proof.verifier.live_claim = true;

        let error = registry_with(proof)
            .validate(NOW_MS)
            .expect_err("replay proof cannot claim live proof");

        assert!(matches!(
            error,
            ProofBundleRegistryError::LiveClaimForNonLiveProof { .. }
        ));
    }
}
