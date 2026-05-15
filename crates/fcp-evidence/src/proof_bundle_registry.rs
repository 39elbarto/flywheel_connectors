//! Canonical registry schema for proof bundles and proof-manifest rows.
//!
//! The registry is intentionally stricter than the older proof graph corpus: it
//! records the owner, rerun command, artifact digests, freshness policy, and
//! live/replay/static proof class before a row can be treated as green proof.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};

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

/// Deterministic proof-bundle validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofBundleValidator {
    now_unix_ms: u64,
}

impl ProofBundleValidator {
    /// Create a validator pinned to a caller-supplied clock.
    #[must_use]
    pub const fn new(now_unix_ms: u64) -> Self {
        Self { now_unix_ms }
    }

    /// Validate a registry and observed artifact catalog without running commands.
    #[must_use]
    pub fn validate(
        &self,
        registry: &ProofBundleRegistry,
        observed_artifacts: &BTreeMap<String, ObservedProofArtifact>,
    ) -> ProofBundleValidationReport {
        let source_ids = registry
            .sources
            .iter()
            .map(|source| source.source_id.as_str())
            .collect::<BTreeSet<_>>();
        let proofs = registry
            .proofs
            .iter()
            .map(|proof| (*self).validate_proof(proof, &source_ids, observed_artifacts))
            .collect::<Vec<_>>();
        let status = aggregate_status(&proofs);

        ProofBundleValidationReport {
            schema: PROOF_BUNDLE_REGISTRY_SCHEMA.to_owned(),
            registry_id: registry.registry_id.clone(),
            generated_at_unix_ms: self.now_unix_ms,
            status,
            proofs,
        }
    }

    fn validate_proof(
        self,
        proof: &ProofBundleEntry,
        known_sources: &BTreeSet<&str>,
        observed_artifacts: &BTreeMap<String, ObservedProofArtifact>,
    ) -> ProofBundleValidationRow {
        let artifact_paths = proof
            .expected_artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect::<Vec<_>>();
        let freshness = ProofFreshnessStatus::from_policy(
            &proof.freshness_policy,
            proof.generated_at_unix_ms,
            self.now_unix_ms,
        );

        let (status, reason_code, detail) =
            Self::validate_proof_status(proof, known_sources, observed_artifacts, &freshness);

        ProofBundleValidationRow {
            proof_id: proof.proof_id.clone(),
            owning_bead: proof.owning_bead.clone(),
            status,
            reason_code,
            detail,
            proof_class: proof.proof_class,
            source_document: proof.source_document.clone(),
            artifact_paths,
            rerun_argv: proof.rerun.argv.clone(),
            freshness,
        }
    }

    fn validate_proof_status(
        proof: &ProofBundleEntry,
        known_sources: &BTreeSet<&str>,
        observed_artifacts: &BTreeMap<String, ObservedProofArtifact>,
        freshness: &ProofFreshnessStatus,
    ) -> (
        ProofValidationStatus,
        ProofValidationReasonCode,
        Option<String>,
    ) {
        if is_blank(&proof.owning_bead) {
            return red(ProofValidationReasonCode::MissingOwner, None);
        }
        if !known_sources.contains(proof.source_document.source_id.as_str()) {
            return red(
                ProofValidationReasonCode::MissingSource,
                Some(proof.source_document.source_id.clone()),
            );
        }
        if proof.rerun.argv.is_empty() {
            return red(ProofValidationReasonCode::RerunMissing, None);
        }
        if proof.verifier.command.argv.is_empty() {
            return red(ProofValidationReasonCode::VerifierCommandMissing, None);
        }
        if proof.verifier.live_claim && !proof.proof_class.permits_live_claim() {
            return red(ProofValidationReasonCode::NonLiveProofClaimedLive, None);
        }
        if proof.proof_class == ProofClass::StructuredSkip
            || proof.verifier.result == VerificationResult::Skipped
        {
            return yellow(ProofValidationReasonCode::StructuredSkipNonGreen, None);
        }
        if freshness.classification == FreshnessClassification::StaleFailClosed {
            return red(ProofValidationReasonCode::StaleFailClosed, None);
        }
        if freshness.classification == FreshnessClassification::StaleWarnOnly {
            return yellow(ProofValidationReasonCode::StaleWarnOnly, None);
        }
        if freshness.classification == FreshnessClassification::StaleSkipOnly {
            return yellow(ProofValidationReasonCode::StaleSkipOnly, None);
        }

        if let Some((reason, detail)) = validate_artifacts(proof, observed_artifacts) {
            return red(reason, detail);
        }

        match proof.verifier.result {
            VerificationResult::Passed => {
                if proof.proof_class.permits_live_claim() {
                    green()
                } else {
                    yellow(ProofValidationReasonCode::OfflineEvidenceNonLive, None)
                }
            }
            VerificationResult::Failed => red(ProofValidationReasonCode::VerifierFailed, None),
            VerificationResult::Blocked => (
                ProofValidationStatus::InfraBlocked,
                ProofValidationReasonCode::VerifierInfraBlocked,
                None,
            ),
            VerificationResult::Skipped => {
                yellow(ProofValidationReasonCode::StructuredSkipNonGreen, None)
            }
        }
    }
}

/// Observed artifact metadata supplied to the validator by a caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedProofArtifact {
    /// Path matching `ExpectedProofArtifact.path`.
    pub path: String,
    /// Whether the artifact was present.
    pub exists: bool,
    /// Observed digest, if computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<ArtifactDigest>,
}

/// JSON-serializable validator report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleValidationReport {
    /// Report schema.
    pub schema: String,
    /// Registry id under validation.
    pub registry_id: String,
    /// Report generation timestamp as Unix milliseconds.
    pub generated_at_unix_ms: u64,
    /// Aggregate status.
    pub status: ProofValidationStatus,
    /// Per-proof rows.
    pub proofs: Vec<ProofBundleValidationRow>,
}

/// Per-proof validator row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleValidationRow {
    /// Proof id.
    pub proof_id: String,
    /// Owning Beads id.
    pub owning_bead: String,
    /// Deterministic proof status.
    pub status: ProofValidationStatus,
    /// Primary reason code.
    pub reason_code: ProofValidationReasonCode,
    /// Optional detail such as a missing path or source id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Evidence class.
    pub proof_class: ProofClass,
    /// Source row.
    pub source_document: ProofSourceDocumentRow,
    /// Artifact paths considered by the validator.
    pub artifact_paths: Vec<String>,
    /// Rerun argv from the registry.
    pub rerun_argv: Vec<String>,
    /// Freshness age/window details.
    pub freshness: ProofFreshnessStatus,
}

/// Proof validator status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofValidationStatus {
    /// Proof is valid for a live or host-backed green gate.
    Green,
    /// Proof is valid metadata but not green live proof.
    Yellow,
    /// Proof failed closed.
    Red,
    /// Proof could not run because infrastructure was unavailable.
    InfraBlocked,
}

/// Proof validator reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofValidationReasonCode {
    /// Passed as green proof.
    Pass,
    /// Owning bead is absent.
    MissingOwner,
    /// Source row does not match the source inventory.
    MissingSource,
    /// Rerun command is absent.
    RerunMissing,
    /// Verifier command is absent.
    VerifierCommandMissing,
    /// Required artifact path is absent.
    MissingArtifact,
    /// Required artifact digest is absent.
    MissingDigest,
    /// Observed digest differs from the expected digest.
    DigestMismatch,
    /// Required proof is stale and fail-closed.
    StaleFailClosed,
    /// Stale proof is advisory only.
    StaleWarnOnly,
    /// Stale proof is skipped.
    StaleSkipOnly,
    /// Structured skip is non-green.
    StructuredSkipNonGreen,
    /// Replay/static/offline evidence is valid but non-live.
    OfflineEvidenceNonLive,
    /// Verifier failed.
    VerifierFailed,
    /// Verifier was blocked by infrastructure.
    VerifierInfraBlocked,
    /// Replay/static/offline proof tried to claim live status.
    NonLiveProofClaimedLive,
}

/// Freshness details emitted for every proof row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFreshnessStatus {
    /// Current artifact age in milliseconds.
    pub age_ms: u64,
    /// Configured max age in milliseconds.
    pub max_age_ms: u64,
    /// Freshness classification.
    pub classification: FreshnessClassification,
}

impl ProofFreshnessStatus {
    const fn from_policy(
        policy: &FreshnessPolicy,
        generated_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            age_ms: now_unix_ms.saturating_sub(generated_at_unix_ms),
            max_age_ms: policy.max_age_ms,
            classification: policy.classify(generated_at_unix_ms, now_unix_ms),
        }
    }
}

fn validate_artifacts(
    proof: &ProofBundleEntry,
    observed_artifacts: &BTreeMap<String, ObservedProofArtifact>,
) -> Option<(ProofValidationReasonCode, Option<String>)> {
    for expected in &proof.expected_artifacts {
        if !expected.required {
            continue;
        }
        let Some(expected_digest) = &expected.digest else {
            return Some((
                ProofValidationReasonCode::MissingDigest,
                Some(expected.path.clone()),
            ));
        };
        let Some(observed) = observed_artifacts.get(&expected.path) else {
            return Some((
                ProofValidationReasonCode::MissingArtifact,
                Some(expected.path.clone()),
            ));
        };
        if !observed.exists {
            return Some((
                ProofValidationReasonCode::MissingArtifact,
                Some(expected.path.clone()),
            ));
        }
        let Some(observed_digest) = &observed.digest else {
            return Some((
                ProofValidationReasonCode::MissingDigest,
                Some(expected.path.clone()),
            ));
        };
        if observed_digest != expected_digest {
            return Some((
                ProofValidationReasonCode::DigestMismatch,
                Some(expected.path.clone()),
            ));
        }
    }
    None
}

fn aggregate_status(proofs: &[ProofBundleValidationRow]) -> ProofValidationStatus {
    if proofs
        .iter()
        .any(|proof| proof.status == ProofValidationStatus::Red)
    {
        ProofValidationStatus::Red
    } else if proofs
        .iter()
        .any(|proof| proof.status == ProofValidationStatus::InfraBlocked)
    {
        ProofValidationStatus::InfraBlocked
    } else if proofs
        .iter()
        .any(|proof| proof.status == ProofValidationStatus::Yellow)
    {
        ProofValidationStatus::Yellow
    } else {
        ProofValidationStatus::Green
    }
}

const fn green() -> (
    ProofValidationStatus,
    ProofValidationReasonCode,
    Option<String>,
) {
    (
        ProofValidationStatus::Green,
        ProofValidationReasonCode::Pass,
        None,
    )
}

const fn yellow(
    reason_code: ProofValidationReasonCode,
    detail: Option<String>,
) -> (
    ProofValidationStatus,
    ProofValidationReasonCode,
    Option<String>,
) {
    (ProofValidationStatus::Yellow, reason_code, detail)
}

const fn red(
    reason_code: ProofValidationReasonCode,
    detail: Option<String>,
) -> (
    ProofValidationStatus,
    ProofValidationReasonCode,
    Option<String>,
) {
    (ProofValidationStatus::Red, reason_code, detail)
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

    fn observed_artifacts(proof: &ProofBundleEntry) -> BTreeMap<String, ObservedProofArtifact> {
        proof
            .expected_artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact.path.clone(),
                    ObservedProofArtifact {
                        path: artifact.path.clone(),
                        exists: true,
                        digest: artifact.digest.clone(),
                    },
                )
            })
            .collect()
    }

    fn validation_row(
        proof: ProofBundleEntry,
        artifacts: &BTreeMap<String, ObservedProofArtifact>,
    ) -> ProofBundleValidationRow {
        let report = ProofBundleValidator::new(NOW_MS).validate(&registry_with(proof), artifacts);
        assert_eq!(report.proofs.len(), 1);
        report.proofs[0].clone()
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

    #[test]
    fn validator_emits_green_for_fresh_live_pass() {
        let mut proof = proof();
        proof.proof_class = ProofClass::Live;
        proof.verifier.live_claim = true;
        let artifacts = observed_artifacts(&proof);

        let report = ProofBundleValidator::new(NOW_MS).validate(&registry_with(proof), &artifacts);

        assert_eq!(report.status, ProofValidationStatus::Green);
        assert_eq!(report.proofs.len(), 1);
        assert_eq!(report.proofs[0].status, ProofValidationStatus::Green);
        assert_eq!(
            report.proofs[0].reason_code,
            ProofValidationReasonCode::Pass
        );

        let json = serde_json::to_value(&report).expect("validation report should serialize");
        assert_eq!(
            json["proofs"][0]["owning_bead"],
            "flywheel_connectors-8bqme.3"
        );
        assert_eq!(
            json["proofs"][0]["freshness"]["max_age_ms"],
            serde_json::json!(60_000)
        );
        assert_eq!(
            json["proofs"][0]["artifact_paths"][0],
            "docs/FCP3_Final_Proof_Manifest.md"
        );
    }

    #[test]
    fn validator_fails_stale_required_proof() {
        let proof = ProofBundleEntry {
            generated_at_unix_ms: NOW_MS - 120_000,
            ..proof()
        };
        let artifacts = observed_artifacts(&proof);

        let row = validation_row(proof, &artifacts);

        assert_eq!(row.status, ProofValidationStatus::Red);
        assert_eq!(row.reason_code, ProofValidationReasonCode::StaleFailClosed);
        assert_eq!(
            row.freshness.classification,
            FreshnessClassification::StaleFailClosed
        );
    }

    #[test]
    fn validator_fails_missing_required_artifact() {
        let proof = proof();
        let artifacts = BTreeMap::new();

        let row = validation_row(proof, &artifacts);

        assert_eq!(row.status, ProofValidationStatus::Red);
        assert_eq!(row.reason_code, ProofValidationReasonCode::MissingArtifact);
        assert_eq!(
            row.detail.as_deref(),
            Some("docs/FCP3_Final_Proof_Manifest.md")
        );
    }

    #[test]
    fn validator_fails_digest_mismatch() {
        let proof = proof();
        let mut artifacts = observed_artifacts(&proof);
        if let Some(artifact) = artifacts.get_mut("docs/FCP3_Final_Proof_Manifest.md") {
            artifact.digest = Some(ArtifactDigest {
                algorithm: ArtifactDigestAlgorithm::Blake3,
                value: "fedcba9876543210".repeat(4),
            });
        }

        let row = validation_row(proof, &artifacts);

        assert_eq!(row.status, ProofValidationStatus::Red);
        assert_eq!(row.reason_code, ProofValidationReasonCode::DigestMismatch);
    }

    #[test]
    fn validator_fails_missing_rerun_command() {
        let mut proof = proof();
        proof.rerun.argv.clear();
        let artifacts = observed_artifacts(&proof);

        let row = validation_row(proof, &artifacts);

        assert_eq!(row.status, ProofValidationStatus::Red);
        assert_eq!(row.reason_code, ProofValidationReasonCode::RerunMissing);
    }

    #[test]
    fn validator_marks_structured_skip_non_green() {
        let mut proof = proof();
        proof.proof_class = ProofClass::StructuredSkip;
        proof.verifier.result = VerificationResult::Skipped;
        proof.structured_skip = Some(StructuredSkipReason {
            allowed: true,
            reason_code: "missing_live_fixture".to_owned(),
            evidence_path: Some("target/proof/skip.json".to_owned()),
        });
        let artifacts = observed_artifacts(&proof);

        let row = validation_row(proof, &artifacts);

        assert_eq!(row.status, ProofValidationStatus::Yellow);
        assert_eq!(
            row.reason_code,
            ProofValidationReasonCode::StructuredSkipNonGreen
        );
    }

    #[test]
    fn validator_distinguishes_infra_blocked_verifier() {
        let mut proof = proof();
        proof.proof_class = ProofClass::HostBacked;
        proof.verifier.live_claim = true;
        proof.verifier.result = VerificationResult::Blocked;
        let artifacts = observed_artifacts(&proof);

        let report = ProofBundleValidator::new(NOW_MS).validate(&registry_with(proof), &artifacts);

        assert_eq!(report.status, ProofValidationStatus::InfraBlocked);
        assert_eq!(report.proofs[0].status, ProofValidationStatus::InfraBlocked);
        assert_eq!(
            report.proofs[0].reason_code,
            ProofValidationReasonCode::VerifierInfraBlocked
        );
    }

    #[test]
    fn validator_marks_static_doc_as_non_live_yellow() {
        let proof = proof();
        let artifacts = observed_artifacts(&proof);

        let row = validation_row(proof, &artifacts);

        assert_eq!(row.status, ProofValidationStatus::Yellow);
        assert_eq!(
            row.reason_code,
            ProofValidationReasonCode::OfflineEvidenceNonLive
        );
    }
}
