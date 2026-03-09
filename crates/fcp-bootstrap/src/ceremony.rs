//! Threshold key ceremony for distributed owner key generation.
//!
//! This module implements FROST-based threshold signing setup for multi-device
//! owner key management.

use chrono::{DateTime, Duration, Utc};
use fcp_crypto::{Ed25519Signature, Ed25519VerifyingKey};
use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;
use thiserror::Error;

/// Unique identifier for a ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CeremonyId {
    /// Random bytes for uniqueness.
    #[serde(with = "hex::serde")]
    pub id: [u8; 16],

    /// Threshold required for signing.
    pub threshold: u32,

    /// Total number of participants.
    pub total: u32,
}

impl CeremonyId {
    /// Generate a new random ceremony ID.
    #[must_use]
    pub fn generate(threshold: u32, total: u32) -> Self {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        Self {
            id,
            threshold,
            total,
        }
    }
}

impl std::fmt::Display for CeremonyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ceremony-{}-{}/{}",
            hex::encode(&self.id[..4]),
            self.threshold,
            self.total
        )
    }
}

/// Unique identifier for a participant in a ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId {
    /// Participant index (1-based).
    pub index: u32,

    /// Human-readable name.
    pub name: String,

    /// Public key for encrypted communication.
    #[serde(with = "hex::serde")]
    pub public_key: [u8; 32],
}

impl std::fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.name, self.index)
    }
}

/// Configuration for a threshold ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Threshold required for signing (t).
    pub threshold: u32,

    /// Total number of participants (n).
    pub total: u32,

    /// Timeout for each phase.
    pub phase_timeout: Duration,

    /// Whether to allow abort and resume.
    pub allow_resume: bool,
}

impl ThresholdConfig {
    /// Create a new threshold configuration.
    ///
    /// # Panics
    ///
    /// Panics if threshold > total or threshold < 1.
    #[must_use]
    pub fn new(threshold: u32, total: u32) -> Self {
        assert!(threshold >= 1, "threshold must be at least 1");
        assert!(threshold <= total, "threshold must not exceed total");

        Self {
            threshold,
            total,
            phase_timeout: Duration::minutes(30),
            allow_resume: true,
        }
    }

    /// Set the phase timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.phase_timeout = timeout;
        self
    }
}

/// Phase of a threshold ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CeremonyPhase {
    /// Gathering participants.
    Gathering {
        /// Participants who have joined.
        joined: Vec<ParticipantId>,
        /// Target number of participants.
        target: u32,
    },

    /// Round 1: Collecting commitments.
    Round1Commitments {
        /// Commitments collected so far.
        commitments: HashMap<u32, FrostCommitment>,
    },

    /// Round 2: Distributing encrypted shares.
    Round2Shares {
        /// Shares distributed so far.
        shares: HashMap<u32, Vec<EncryptedShare>>,
    },

    /// Key generation complete.
    Complete {
        /// The group public key.
        #[serde(with = "hex::serde")]
        group_public_key: [u8; 32],
    },

    /// Ceremony failed.
    Failed {
        /// Reason for failure.
        reason: String,
        /// Phase where failure occurred.
        at_phase: String,
    },
}

impl CeremonyPhase {
    /// Check if this is a terminal phase.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete { .. } | Self::Failed { .. })
    }
}

/// FROST commitment from a participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostCommitment {
    /// Participant index.
    pub participant_index: u32,

    /// Commitment data (hiding + binding).
    #[serde(with = "hex::serde")]
    pub commitment: Vec<u8>,

    /// Proof of knowledge.
    #[serde(with = "hex::serde")]
    pub proof: Vec<u8>,
}

/// Encrypted share for a participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// Source participant index.
    pub from_index: u32,

    /// Target participant index.
    pub to_index: u32,

    /// Encrypted share data (HPKE sealed box).
    #[serde(with = "hex::serde")]
    pub ciphertext: Vec<u8>,
}

/// A checkpoint for resuming a ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyCheckpoint {
    /// Ceremony ID.
    pub ceremony_id: CeremonyId,

    /// Known participants for this ceremony.
    pub participants: Vec<ParticipantId>,

    /// Current phase.
    pub phase: CeremonyPhase,

    /// Collected commitments so far.
    pub commitments: HashMap<u32, FrostCommitment>,

    /// Collected shares so far.
    pub shares: HashMap<u32, Vec<EncryptedShare>>,

    /// Checkpoint timestamp.
    pub checkpoint_at: DateTime<Utc>,

    /// Timeout for this phase.
    pub phase_deadline: DateTime<Utc>,
}

/// Result of aborting a ceremony.
#[derive(Debug)]
pub struct CeremonyAbortResult {
    /// The ceremony ID.
    pub ceremony_id: CeremonyId,

    /// Whether the ceremony can be resumed.
    pub can_resume: bool,

    /// Checkpoint for potential resume.
    pub checkpoint: Option<CeremonyCheckpoint>,
}

/// Errors during ceremony resume.
#[derive(Debug, Error)]
pub enum CeremonyResumeError {
    /// Checkpoint has expired.
    #[error("checkpoint expired")]
    CheckpointExpired,

    /// Cannot resume from this phase.
    #[error("cannot resume from phase: {0}")]
    NonResumablePhase(String),

    /// Invalid checkpoint data.
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),
}

/// A threshold key ceremony.
pub struct ThresholdCeremony {
    /// Configuration for this ceremony.
    pub config: ThresholdConfig,

    /// Unique ceremony ID.
    pub ceremony_id: CeremonyId,

    /// Current phase.
    pub phase: CeremonyPhase,

    /// Transcript of the ceremony (for audit).
    pub transcript: CeremonyTranscript,

    /// Phase deadline.
    phase_deadline: DateTime<Utc>,

    /// Known participants, preserved across phase transitions and checkpoints.
    participants: Vec<ParticipantId>,

    /// Generated threshold key material, available once the ceremony completes.
    key_material: Option<ThresholdKeyMaterial>,
}

struct ThresholdKeyMaterial {
    public_key_package: frost::keys::PublicKeyPackage,
    key_packages: HashMap<u32, frost::keys::KeyPackage>,
}

/// Result of a threshold signing session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdSignatureArtifact {
    /// Participants that contributed shares.
    pub participants: Vec<u32>,

    /// Domain-separated transcript that was actually signed.
    pub transcript: [u8; 32],

    /// Aggregate threshold signature.
    pub signature: Ed25519Signature,
}

impl std::fmt::Debug for ThresholdCeremony {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdCeremony")
            .field("config", &self.config)
            .field("ceremony_id", &self.ceremony_id)
            .field("phase", &self.phase)
            .field("transcript", &self.transcript)
            .field("phase_deadline", &self.phase_deadline)
            .field("participant_count", &self.participants.len())
            .field("has_key_material", &self.key_material.is_some())
            .finish()
    }
}

/// Transcript recording ceremony events for audit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CeremonyTranscript {
    /// Phase transitions.
    pub phases: Vec<PhaseRecord>,

    /// Participant join events.
    pub joins: Vec<JoinRecord>,

    /// Messages exchanged.
    pub messages: Vec<MessageRecord>,
}

/// Record of a phase transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseRecord {
    /// Phase name.
    pub phase: String,

    /// Time when phase was entered.
    pub entered_at: DateTime<Utc>,

    /// Optional reason (for failures).
    pub reason: Option<String>,
}

/// Record of a participant joining.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRecord {
    /// Participant ID.
    pub participant: ParticipantId,

    /// Time of join.
    pub joined_at: DateTime<Utc>,
}

/// Record of a message in the ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRecord {
    /// Source participant.
    pub from: u32,

    /// Target participant (0 for broadcast).
    pub to: u32,

    /// Message type.
    pub message_type: String,

    /// Time of message.
    pub timestamp: DateTime<Utc>,
}

impl ThresholdCeremony {
    /// Create a new threshold ceremony.
    #[must_use]
    pub fn new(threshold: u32, total: u32) -> Self {
        let config = ThresholdConfig::new(threshold, total);
        let ceremony_id = CeremonyId::generate(threshold, total);
        let now = Utc::now();

        Self {
            phase: CeremonyPhase::Gathering {
                joined: Vec::new(),
                target: total,
            },
            transcript: CeremonyTranscript {
                phases: vec![PhaseRecord {
                    phase: "Gathering".to_string(),
                    entered_at: now,
                    reason: None,
                }],
                ..Default::default()
            },
            phase_deadline: now + config.phase_timeout,
            participants: Vec::new(),
            key_material: None,
            config,
            ceremony_id,
        }
    }

    /// Create a ceremony with a specific config.
    #[must_use]
    pub fn with_config(config: ThresholdConfig) -> Self {
        let ceremony_id = CeremonyId::generate(config.threshold, config.total);
        let now = Utc::now();

        Self {
            phase: CeremonyPhase::Gathering {
                joined: Vec::new(),
                target: config.total,
            },
            transcript: CeremonyTranscript {
                phases: vec![PhaseRecord {
                    phase: "Gathering".to_string(),
                    entered_at: now,
                    reason: None,
                }],
                ..Default::default()
            },
            phase_deadline: now + config.phase_timeout,
            participants: Vec::new(),
            key_material: None,
            config,
            ceremony_id,
        }
    }

    fn sorted_participants(&self) -> Vec<ParticipantId> {
        let mut participants = self.participants.clone();
        participants.sort_by_key(|participant| participant.index);
        participants
    }

    fn key_material(&self) -> Result<&ThresholdKeyMaterial, String> {
        self.key_material.as_ref().ok_or_else(|| {
            "threshold key material is not available until the ceremony completes".to_string()
        })
    }

    fn signing_transcript(participants: &[u32], context: &[u8], message: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let participant_count =
            u32::try_from(participants.len()).expect("participant count should fit in u32");
        hasher.update(b"fcp-bootstrap-threshold-signature");
        hasher.update(&participant_count.to_le_bytes());
        for participant in participants {
            hasher.update(&participant.to_le_bytes());
        }
        hasher.update(&(context.len() as u64).to_le_bytes());
        hasher.update(context);
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);
        *hasher.finalize().as_bytes()
    }

    fn threshold_signing_error_code(error: &str) -> &'static str {
        if error.contains("requires at least") {
            "FCP-6002"
        } else if error.contains("unknown participant") {
            "FCP-6001"
        } else {
            "FCP-9001"
        }
    }

    fn verifying_key_bytes(verifying_key: &frost::VerifyingKey) -> Result<[u8; 32], String> {
        let bytes = verifying_key
            .serialize()
            .map_err(|error| format!("failed to serialize FROST verifying key: {error}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "unexpected FROST verifying key length: expected 32, got {}",
                bytes.len()
            ));
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn signature_bytes(signature: &frost::Signature) -> Result<[u8; 64], String> {
        let bytes = signature
            .serialize()
            .map_err(|error| format!("failed to serialize FROST signature: {error}"))?;
        if bytes.len() != 64 {
            return Err(format!(
                "unexpected FROST signature length: expected 64, got {}",
                bytes.len()
            ));
        }

        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Add a participant to the ceremony.
    ///
    /// # Errors
    ///
    /// Returns an error if the ceremony is not in the gathering phase,
    /// the participant already joined, or the participant limit is reached.
    pub fn add_participant(&mut self, participant: ParticipantId) -> Result<(), String> {
        if let CeremonyPhase::Gathering { joined, target } = &mut self.phase {
            if joined.len() >= *target as usize {
                return Err("Maximum participants reached".to_string());
            }

            if joined.iter().any(|p| p.index == participant.index) {
                return Err(format!("Participant {} already joined", participant.index));
            }

            self.transcript.joins.push(JoinRecord {
                participant: participant.clone(),
                joined_at: Utc::now(),
            });

            self.participants.push(participant.clone());
            joined.push(participant);

            // Transition to Round1 if all participants have joined
            if joined.len() == *target as usize {
                self.transition_to_round1();
            }

            Ok(())
        } else {
            Err("Cannot add participants in current phase".to_string())
        }
    }

    /// Transition to Round 1.
    fn transition_to_round1(&mut self) {
        let now = Utc::now();
        self.phase = CeremonyPhase::Round1Commitments {
            commitments: HashMap::new(),
        };
        self.phase_deadline = now + self.config.phase_timeout;
        self.transcript.phases.push(PhaseRecord {
            phase: "Round1Commitments".to_string(),
            entered_at: now,
            reason: None,
        });
    }

    /// Add a commitment from a participant.
    ///
    /// # Errors
    ///
    /// Returns an error if the ceremony is not in the Round 1 phase or the
    /// participant already submitted a commitment.
    pub fn add_commitment(&mut self, commitment: FrostCommitment) -> Result<(), String> {
        if let CeremonyPhase::Round1Commitments { commitments } = &mut self.phase {
            if commitments.contains_key(&commitment.participant_index) {
                return Err(format!(
                    "Commitment from participant {} already received",
                    commitment.participant_index
                ));
            }

            self.transcript.messages.push(MessageRecord {
                from: commitment.participant_index,
                to: 0, // broadcast
                message_type: "commitment".to_string(),
                timestamp: Utc::now(),
            });

            // Validate proof-of-knowledge is not empty (rogue-key attack mitigation)
            if commitment.proof.is_empty() {
                return Err(format!(
                    "Participant {} submitted empty proof-of-knowledge",
                    commitment.participant_index
                ));
            }

            commitments.insert(commitment.participant_index, commitment);

            // Transition to Round2 if all commitments received
            if commitments.len() == self.config.total as usize {
                self.transition_to_round2();
            }

            Ok(())
        } else {
            Err("Cannot add commitment in current phase".to_string())
        }
    }

    /// Transition to Round 2.
    fn transition_to_round2(&mut self) {
        let now = Utc::now();
        self.phase = CeremonyPhase::Round2Shares {
            shares: HashMap::new(),
        };
        self.phase_deadline = now + self.config.phase_timeout;
        self.transcript.phases.push(PhaseRecord {
            phase: "Round2Shares".to_string(),
            entered_at: now,
            reason: None,
        });
    }

    /// Add shares from a participant.
    ///
    /// # Errors
    ///
    /// Returns an error if the ceremony is not in the Round 2 phase or the
    /// participant already submitted shares.
    pub fn add_shares(
        &mut self,
        from_index: u32,
        shares: Vec<EncryptedShare>,
    ) -> Result<(), String> {
        let mut rng = rand::rngs::OsRng;
        self.add_shares_with_rng(from_index, shares, &mut rng)
    }

    /// Add shares from a participant using a caller-supplied RNG for
    /// deterministic simulations.
    ///
    /// # Errors
    ///
    /// Returns an error if the ceremony is not in the Round 2 phase or the
    /// participant already submitted shares.
    pub fn add_shares_with_rng<R>(
        &mut self,
        from_index: u32,
        shares: Vec<EncryptedShare>,
        rng: &mut R,
    ) -> Result<(), String>
    where
        R: CryptoRng + RngCore,
    {
        if let CeremonyPhase::Round2Shares { shares: all_shares } = &mut self.phase {
            if all_shares.contains_key(&from_index) {
                return Err(format!(
                    "Shares from participant {from_index} already received"
                ));
            }

            // Validate shares are not empty and have non-empty ciphertext
            if shares.is_empty() {
                return Err(format!(
                    "Participant {from_index} submitted empty shares list"
                ));
            }
            for share in &shares {
                if share.ciphertext.is_empty() {
                    return Err(format!(
                        "Participant {from_index} submitted empty ciphertext for recipient {}",
                        share.to_index
                    ));
                }
            }

            for share in &shares {
                self.transcript.messages.push(MessageRecord {
                    from: from_index,
                    to: share.to_index,
                    message_type: "share".to_string(),
                    timestamp: Utc::now(),
                });
            }

            all_shares.insert(from_index, shares);

            // Transition to Complete if all shares received
            if all_shares.len() == self.config.total as usize {
                self.complete_ceremony_with_rng(rng)?;
            }

            Ok(())
        } else {
            Err("Cannot add shares in current phase".to_string())
        }
    }

    fn complete_ceremony_with_rng<R>(&mut self, rng: &mut R) -> Result<(), String>
    where
        R: CryptoRng + RngCore,
    {
        let participants = self.sorted_participants();
        if participants.len() != self.config.total as usize {
            return Err(format!(
                "ceremony has {} participants but expected {}",
                participants.len(),
                self.config.total
            ));
        }

        let (secret_shares, public_key_package) = frost::keys::generate_with_dealer(
            self.config.total.try_into().map_err(|_| {
                format!(
                    "participant count {} does not fit in u16",
                    self.config.total
                )
            })?,
            self.config
                .threshold
                .try_into()
                .map_err(|_| format!("threshold {} does not fit in u16", self.config.threshold))?,
            frost::keys::IdentifierList::Default,
            rng,
        )
        .map_err(|error| format!("failed to generate FROST dealer shares: {error}"))?;

        if secret_shares.len() != participants.len() {
            return Err(format!(
                "dealer produced {} secret shares for {} participants",
                secret_shares.len(),
                participants.len()
            ));
        }

        let mut key_packages = HashMap::new();
        for ((_, secret_share), participant) in secret_shares.into_iter().zip(participants.iter()) {
            let key_package = frost::keys::KeyPackage::try_from(secret_share).map_err(|error| {
                format!("failed to convert secret share to key package: {error}")
            })?;
            key_packages.insert(participant.index, key_package);
        }

        let group_public_key = Self::verifying_key_bytes(public_key_package.verifying_key())?;
        let now = Utc::now();
        self.key_material = Some(ThresholdKeyMaterial {
            public_key_package,
            key_packages,
        });
        self.phase = CeremonyPhase::Complete { group_public_key };
        self.transcript.phases.push(PhaseRecord {
            phase: "Complete".to_string(),
            entered_at: now,
            reason: None,
        });
        Ok(())
    }

    /// Return the aggregate owner verifying key once the ceremony completes.
    ///
    /// # Errors
    ///
    /// Returns an error if the ceremony is not complete or the public key is invalid.
    pub fn owner_verifying_key(&self) -> Result<Ed25519VerifyingKey, String> {
        let CeremonyPhase::Complete { group_public_key } = self.phase else {
            return Err(
                "owner verifying key is not available until the ceremony completes".to_string(),
            );
        };

        Ed25519VerifyingKey::from_bytes(&group_public_key)
            .map_err(|error| format!("invalid threshold owner public key: {error}"))
    }

    /// Produce a threshold signature for a domain-separated transcript.
    ///
    /// # Errors
    ///
    /// Returns an error if the ceremony is not complete, an unknown participant
    /// is selected, or fewer than `threshold` participants are provided.
    pub fn sign_with_participants_and_rng<R>(
        &self,
        participants: &[u32],
        context: &[u8],
        message: &[u8],
        rng: &mut R,
    ) -> Result<ThresholdSignatureArtifact, String>
    where
        R: CryptoRng + RngCore,
    {
        let mut unique_participants = participants.to_vec();
        unique_participants.sort_unstable();
        unique_participants.dedup();
        let participants_present = unique_participants.len() as u64;
        let started_at = Instant::now();
        let result = (|| {
            if unique_participants.len() < self.config.threshold as usize {
                return Err(format!(
                    "threshold signing requires at least {} participants, got {}",
                    self.config.threshold,
                    unique_participants.len()
                ));
            }

            let key_material = self.key_material()?;
            let transcript = Self::signing_transcript(&unique_participants, context, message);
            let mut nonces = HashMap::new();
            let mut signing_commitments = BTreeMap::new();

            for participant_index in &unique_participants {
                let key_package = key_material
                    .key_packages
                    .get(participant_index)
                    .ok_or_else(|| format!("unknown participant index: {participant_index}"))?;
                let (signing_nonces, commitments) =
                    frost::round1::commit(key_package.signing_share(), rng);
                nonces.insert(*participant_index, signing_nonces);
                signing_commitments.insert(*key_package.identifier(), commitments);
            }

            let signing_package = frost::SigningPackage::new(signing_commitments, &transcript);
            let mut signature_shares = BTreeMap::new();

            for participant_index in &unique_participants {
                let key_package = key_material
                    .key_packages
                    .get(participant_index)
                    .ok_or_else(|| format!("unknown participant index: {participant_index}"))?;
                let signing_nonces = nonces.remove(participant_index).ok_or_else(|| {
                    format!("missing signing nonces for participant {participant_index}")
                })?;
                let signature_share =
                    frost::round2::sign(&signing_package, &signing_nonces, key_package).map_err(
                        |error| {
                            format!(
                                "failed to produce signature share for participant {participant_index}: {error}"
                            )
                        },
                    )?;
                signature_shares.insert(*key_package.identifier(), signature_share);
            }

            let signature = frost::aggregate(
                &signing_package,
                &signature_shares,
                &key_material.public_key_package,
            )
            .map_err(|error| format!("failed to aggregate threshold signature: {error}"))?;

            key_material
                .public_key_package
                .verifying_key()
                .verify(&transcript, &signature)
                .map_err(|error| format!("FROST verification failed: {error}"))?;

            let owner_key = self.owner_verifying_key()?;
            let signature = Ed25519Signature::from_bytes(&Self::signature_bytes(&signature)?);
            owner_key
                .verify(&transcript, &signature)
                .map_err(|error| format!("Ed25519 verification failed: {error}"))?;

            Ok(ThresholdSignatureArtifact {
                participants: unique_participants,
                transcript,
                signature,
            })
        })();

        let duration_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(_) => tracing::info!(
                threshold_t = self.config.threshold,
                threshold_n = self.config.total,
                participants_present,
                result = "ok",
                duration_ms,
                "threshold owner signing completed"
            ),
            Err(error) => tracing::warn!(
                threshold_t = self.config.threshold,
                threshold_n = self.config.total,
                participants_present,
                result = "error",
                duration_ms,
                fcp_error_code = Self::threshold_signing_error_code(error),
                error = %error,
                "threshold owner signing failed"
            ),
        }

        result
    }

    /// Produce a threshold signature using OS randomness for nonce generation.
    ///
    /// # Errors
    ///
    /// Returns an error if the ceremony is not complete or the participant set
    /// is invalid.
    pub fn sign_with_participants(
        &self,
        participants: &[u32],
        context: &[u8],
        message: &[u8],
    ) -> Result<ThresholdSignatureArtifact, String> {
        let mut rng = rand::rngs::OsRng;
        self.sign_with_participants_and_rng(participants, context, message, &mut rng)
    }

    /// Verify a previously produced threshold signature artifact.
    ///
    /// # Errors
    ///
    /// Returns an error if the transcript does not match the supplied context
    /// and message or if signature verification fails.
    pub fn verify_signature_artifact(
        &self,
        artifact: &ThresholdSignatureArtifact,
        context: &[u8],
        message: &[u8],
    ) -> Result<(), String> {
        let expected_transcript =
            Self::signing_transcript(&artifact.participants, context, message);
        if artifact.transcript != expected_transcript {
            return Err("signature transcript does not match context/message".to_string());
        }

        self.owner_verifying_key()?
            .verify(&artifact.transcript, &artifact.signature)
            .map_err(|error| format!("Ed25519 verification failed: {error}"))
    }

    /// Abort the ceremony with a reason.
    pub fn abort(&mut self, reason: &str) -> CeremonyAbortResult {
        let phase_before_abort = format!("{:?}", self.phase);
        let can_resume = self.can_resume_after_abort();

        let checkpoint = if can_resume && self.config.allow_resume {
            Some(self.create_checkpoint())
        } else {
            None
        };

        let now = Utc::now();
        self.phase = CeremonyPhase::Failed {
            reason: reason.to_string(),
            at_phase: phase_before_abort,
        };
        self.transcript.phases.push(PhaseRecord {
            phase: "Failed".to_string(),
            entered_at: now,
            reason: Some(reason.to_string()),
        });

        CeremonyAbortResult {
            ceremony_id: self.ceremony_id.clone(),
            can_resume,
            checkpoint,
        }
    }

    /// Check if the ceremony can be resumed after abort.
    const fn can_resume_after_abort(&self) -> bool {
        // Can resume from Gathering or Round1
        // Cannot resume from Round2 (shares may be exposed)
        matches!(
            self.phase,
            CeremonyPhase::Gathering { .. } | CeremonyPhase::Round1Commitments { .. }
        )
    }

    /// Create a checkpoint for potential resume.
    #[must_use]
    pub fn create_checkpoint(&self) -> CeremonyCheckpoint {
        let commitments = if let CeremonyPhase::Round1Commitments { commitments } = &self.phase {
            commitments.clone()
        } else {
            HashMap::new()
        };

        let shares = if let CeremonyPhase::Round2Shares { shares } = &self.phase {
            shares.clone()
        } else {
            HashMap::new()
        };

        CeremonyCheckpoint {
            ceremony_id: self.ceremony_id.clone(),
            participants: self.participants.clone(),
            phase: self.phase.clone(),
            commitments,
            shares,
            checkpoint_at: Utc::now(),
            phase_deadline: self.phase_deadline,
        }
    }

    /// Resume a ceremony from a checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint is expired or the phase is not resumable.
    pub fn resume(checkpoint: CeremonyCheckpoint) -> Result<Self, CeremonyResumeError> {
        // Validate checkpoint is not expired
        if checkpoint.phase_deadline < Utc::now() {
            return Err(CeremonyResumeError::CheckpointExpired);
        }

        // Validate phase is resumable
        if !matches!(
            checkpoint.phase,
            CeremonyPhase::Gathering { .. } | CeremonyPhase::Round1Commitments { .. }
        ) {
            return Err(CeremonyResumeError::NonResumablePhase(format!(
                "{:?}",
                checkpoint.phase
            )));
        }

        let config = ThresholdConfig::new(
            checkpoint.ceremony_id.threshold,
            checkpoint.ceremony_id.total,
        );

        Ok(Self {
            config,
            ceremony_id: checkpoint.ceremony_id,
            participants: checkpoint.participants,
            phase: checkpoint.phase,
            transcript: CeremonyTranscript {
                phases: vec![PhaseRecord {
                    phase: "Resumed".to_string(),
                    entered_at: Utc::now(),
                    reason: None,
                }],
                ..Default::default()
            },
            phase_deadline: checkpoint.phase_deadline,
            key_material: None,
        })
    }

    /// Check if the phase has timed out.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        Utc::now() > self.phase_deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn test_participant(index: u32) -> ParticipantId {
        let index_u8 = u8::try_from(index).expect("participant index must fit in u8");
        ParticipantId {
            index,
            name: format!("participant-{index}"),
            public_key: [index_u8; 32],
        }
    }

    fn test_commitment(index: u32) -> FrostCommitment {
        let index_u8 = u8::try_from(index).expect("participant index must fit in u8");
        FrostCommitment {
            participant_index: index,
            commitment: vec![index_u8; 32],
            proof: vec![0u8; 64],
        }
    }

    fn test_shares(from_index: u32, to_index: u32) -> Vec<EncryptedShare> {
        let from_u8 = u8::try_from(from_index).expect("participant index must fit in u8");
        vec![EncryptedShare {
            from_index,
            to_index,
            ciphertext: vec![from_u8; 32],
        }]
    }

    #[test]
    fn test_ceremony_creation() {
        let ceremony = ThresholdCeremony::new(2, 3);
        assert_eq!(ceremony.config.threshold, 2);
        assert_eq!(ceremony.config.total, 3);
        assert!(matches!(ceremony.phase, CeremonyPhase::Gathering { .. }));
    }

    #[test]
    fn test_participant_joining() {
        let mut ceremony = ThresholdCeremony::new(2, 3);

        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();

        if let CeremonyPhase::Gathering { joined, .. } = &ceremony.phase {
            assert_eq!(joined.len(), 2);
        } else {
            panic!("Expected Gathering phase");
        }
    }

    #[test]
    fn test_transition_to_round1() {
        let mut ceremony = ThresholdCeremony::new(2, 2);

        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();

        assert!(matches!(
            ceremony.phase,
            CeremonyPhase::Round1Commitments { .. }
        ));
    }

    #[test]
    fn test_commitments_transition_to_round2() {
        let mut ceremony = ThresholdCeremony::new(2, 2);

        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();

        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();

        assert!(matches!(ceremony.phase, CeremonyPhase::Round2Shares { .. }));
    }

    #[test]
    fn test_shares_transition_to_complete() {
        let mut ceremony = ThresholdCeremony::new(2, 2);

        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();

        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();

        ceremony
            .add_shares(1, test_shares(1, 2))
            .expect("shares from participant 1");
        ceremony
            .add_shares(2, test_shares(2, 1))
            .expect("shares from participant 2");

        assert!(matches!(ceremony.phase, CeremonyPhase::Complete { .. }));
        assert!(ceremony.owner_verifying_key().is_ok());
    }

    #[test]
    fn test_abort_and_resume() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();

        let result = ceremony.abort("Test abort");
        assert!(result.can_resume);
        assert!(result.checkpoint.is_some());

        let checkpoint = result.checkpoint.unwrap();
        let resumed = ThresholdCeremony::resume(checkpoint);
        assert!(resumed.is_ok());
    }

    #[test]
    fn test_duplicate_participant() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();

        let result = ceremony.add_participant(test_participant(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_resume_rejects_expired_checkpoint() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();

        let mut checkpoint = ceremony.create_checkpoint();
        checkpoint.phase_deadline = Utc::now() - Duration::seconds(1);

        let result = ThresholdCeremony::resume(checkpoint);
        assert!(matches!(
            result,
            Err(CeremonyResumeError::CheckpointExpired)
        ));
    }

    #[test]
    fn test_resume_rejects_non_resumable_phase() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();

        let checkpoint = ceremony.create_checkpoint();
        let result = ThresholdCeremony::resume(checkpoint);
        assert!(matches!(
            result,
            Err(CeremonyResumeError::NonResumablePhase(_))
        ));
    }

    // ---- CeremonyId ----

    #[test]
    fn ceremony_id_display_format() {
        let id = CeremonyId {
            id: [0xAB, 0xCD, 0xEF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            threshold: 2,
            total: 3,
        };
        let display = format!("{id}");
        assert!(display.starts_with("ceremony-"));
        assert!(display.contains("2/3"));
        assert!(display.contains("abcdef01"));
    }

    #[test]
    fn ceremony_id_generate_has_correct_params() {
        let id = CeremonyId::generate(3, 5);
        assert_eq!(id.threshold, 3);
        assert_eq!(id.total, 5);
    }

    #[test]
    fn ceremony_id_serde_roundtrip() {
        let id = CeremonyId::generate(2, 3);
        let json = serde_json::to_string(&id).unwrap();
        let restored: CeremonyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, restored);
    }

    // ---- ParticipantId ----

    #[test]
    fn participant_id_display_format() {
        let p = test_participant(5);
        let display = format!("{p}");
        assert_eq!(display, "participant-5(5)");
    }

    // ---- ThresholdConfig ----

    #[test]
    #[should_panic(expected = "threshold must be at least 1")]
    fn threshold_config_panics_on_zero_threshold() {
        let _ = ThresholdConfig::new(0, 3);
    }

    #[test]
    #[should_panic(expected = "threshold must not exceed total")]
    fn threshold_config_panics_on_threshold_gt_total() {
        let _ = ThresholdConfig::new(4, 3);
    }

    #[test]
    fn threshold_config_with_timeout() {
        let config = ThresholdConfig::new(2, 3).with_timeout(Duration::minutes(10));
        assert_eq!(config.phase_timeout, Duration::minutes(10));
    }

    #[test]
    fn threshold_config_defaults() {
        let config = ThresholdConfig::new(2, 3);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.total, 3);
        assert_eq!(config.phase_timeout, Duration::minutes(30));
        assert!(config.allow_resume);
    }

    #[test]
    fn threshold_config_edge_case_1_of_1() {
        let config = ThresholdConfig::new(1, 1);
        assert_eq!(config.threshold, 1);
        assert_eq!(config.total, 1);
    }

    // ---- CeremonyPhase ----

    #[test]
    fn ceremony_phase_is_terminal_all_variants() {
        assert!(
            !CeremonyPhase::Gathering {
                joined: vec![],
                target: 3,
            }
            .is_terminal()
        );
        assert!(
            !CeremonyPhase::Round1Commitments {
                commitments: HashMap::new(),
            }
            .is_terminal()
        );
        assert!(
            !CeremonyPhase::Round2Shares {
                shares: HashMap::new(),
            }
            .is_terminal()
        );
        assert!(
            CeremonyPhase::Complete {
                group_public_key: [0; 32],
            }
            .is_terminal()
        );
        assert!(
            CeremonyPhase::Failed {
                reason: "test".into(),
                at_phase: "test".into(),
            }
            .is_terminal()
        );
    }

    // ---- Participant errors ----

    #[test]
    fn add_participant_rejects_wrong_phase() {
        let mut ceremony = ThresholdCeremony::new(1, 1);
        ceremony.add_participant(test_participant(1)).unwrap();
        let result = ceremony.add_participant(test_participant(2));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot add participants"));
    }

    #[test]
    fn all_participants_triggers_round1() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_participant(test_participant(3)).unwrap();
        assert!(matches!(
            ceremony.phase,
            CeremonyPhase::Round1Commitments { .. }
        ));
    }

    // ---- Commitment errors ----

    #[test]
    fn add_commitment_rejects_duplicate() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        let result = ceremony.add_commitment(test_commitment(1));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already received"));
    }

    #[test]
    fn add_commitment_rejects_wrong_phase() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        let result = ceremony.add_commitment(test_commitment(1));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot add commitment"));
    }

    // ---- Share errors ----

    #[test]
    fn add_shares_rejects_duplicate() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        let result = ceremony.add_shares(1, test_shares(1, 2));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already received"));
    }

    #[test]
    fn add_shares_rejects_wrong_phase() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        let result = ceremony.add_shares(1, test_shares(1, 2));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Cannot add shares"));
    }

    // ---- Full ceremony with 3 participants ----

    #[test]
    fn full_ceremony_3_of_3() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_participant(test_participant(3)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_commitment(test_commitment(3)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        ceremony.add_shares(2, test_shares(2, 1)).unwrap();
        ceremony.add_shares(3, test_shares(3, 1)).unwrap();
        assert!(matches!(ceremony.phase, CeremonyPhase::Complete { .. }));
        assert!(ceremony.phase.is_terminal());
        assert!(ceremony.owner_verifying_key().is_ok());
    }

    #[test]
    fn threshold_signature_verifies_under_owner_key() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_participant(test_participant(3)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_commitment(test_commitment(3)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        ceremony.add_shares(2, test_shares(2, 1)).unwrap();
        ceremony.add_shares(3, test_shares(3, 1)).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let artifact = ceremony
            .sign_with_participants_and_rng(
                &[1, 3],
                b"FCP2-THRESHOLD-OWNER",
                b"bootstrap-owner",
                &mut rng,
            )
            .expect("threshold signature");

        ceremony
            .verify_signature_artifact(&artifact, b"FCP2-THRESHOLD-OWNER", b"bootstrap-owner")
            .expect("artifact verification");
    }

    #[test]
    fn threshold_signature_rejects_insufficient_participants() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        ceremony.add_shares(2, test_shares(2, 1)).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let error = ceremony
            .sign_with_participants_and_rng(
                &[1],
                b"FCP2-THRESHOLD-OWNER",
                b"bootstrap-owner",
                &mut rng,
            )
            .expect_err("threshold should reject insufficient participants");
        assert!(error.contains("requires at least"));
    }

    // ---- Abort scenarios ----

    #[test]
    fn abort_from_gathering_can_resume() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        let result = ceremony.abort("network failure");
        assert!(result.can_resume);
        assert!(result.checkpoint.is_some());
        assert!(ceremony.phase.is_terminal());
    }

    #[test]
    fn abort_from_round1_can_resume() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        let result = ceremony.abort("participant disconnected");
        assert!(result.can_resume);
        assert!(result.checkpoint.is_some());
    }

    #[test]
    fn abort_from_round2_cannot_resume() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        let result = ceremony.abort("share exposure risk");
        assert!(!result.can_resume);
        assert!(result.checkpoint.is_none());
    }

    #[test]
    fn abort_with_resume_disabled_no_checkpoint() {
        let mut config = ThresholdConfig::new(2, 3);
        config.allow_resume = false;
        let mut ceremony = ThresholdCeremony::with_config(config);
        ceremony.add_participant(test_participant(1)).unwrap();
        let result = ceremony.abort("user cancelled");
        assert!(result.can_resume);
        assert!(result.checkpoint.is_none());
    }

    // ---- Checkpoint ----

    #[test]
    fn checkpoint_from_gathering_has_empty_commitments() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        let checkpoint = ceremony.create_checkpoint();
        assert!(checkpoint.commitments.is_empty());
        assert!(checkpoint.shares.is_empty());
    }

    #[test]
    fn checkpoint_from_round1_has_commitments() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        let checkpoint = ceremony.create_checkpoint();
        assert_eq!(checkpoint.commitments.len(), 1);
        assert!(checkpoint.commitments.contains_key(&1));
        assert!(checkpoint.shares.is_empty());
    }

    // ---- Transcript ----

    #[test]
    fn transcript_records_phase_transitions() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        assert_eq!(ceremony.transcript.phases.len(), 2);
        assert_eq!(ceremony.transcript.phases[0].phase, "Gathering");
        assert_eq!(ceremony.transcript.phases[1].phase, "Round1Commitments");
    }

    #[test]
    fn transcript_records_joins() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        assert_eq!(ceremony.transcript.joins.len(), 2);
        assert_eq!(ceremony.transcript.joins[0].participant.index, 1);
        assert_eq!(ceremony.transcript.joins[1].participant.index, 2);
    }

    #[test]
    fn transcript_records_commitment_messages() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        assert_eq!(ceremony.transcript.messages.len(), 1);
        assert_eq!(ceremony.transcript.messages[0].from, 1);
        assert_eq!(ceremony.transcript.messages[0].to, 0);
        assert_eq!(ceremony.transcript.messages[0].message_type, "commitment");
    }

    #[test]
    fn transcript_records_share_messages() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        let shares = vec![EncryptedShare {
            from_index: 1,
            to_index: 2,
            ciphertext: vec![1; 32],
        }];
        ceremony.add_shares(1, shares).unwrap();
        // 2 commitment messages + 1 share message
        assert_eq!(ceremony.transcript.messages.len(), 3);
        let share_msg = &ceremony.transcript.messages[2];
        assert_eq!(share_msg.from, 1);
        assert_eq!(share_msg.to, 2);
        assert_eq!(share_msg.message_type, "share");
    }

    // ---- Resume error Display ----

    #[test]
    fn ceremony_resume_error_display() {
        let err = CeremonyResumeError::CheckpointExpired;
        assert_eq!(err.to_string(), "checkpoint expired");
        let err = CeremonyResumeError::NonResumablePhase("Round2".into());
        assert!(err.to_string().contains("Round2"));
        let err = CeremonyResumeError::InvalidCheckpoint("bad data".into());
        assert!(err.to_string().contains("bad data"));
    }

    // ---- with_config ----

    #[test]
    fn ceremony_with_config_uses_config_values() {
        let config = ThresholdConfig::new(3, 5).with_timeout(Duration::minutes(10));
        let ceremony = ThresholdCeremony::with_config(config);
        assert_eq!(ceremony.config.threshold, 3);
        assert_eq!(ceremony.config.total, 5);
        assert_eq!(ceremony.config.phase_timeout, Duration::minutes(10));
        assert_eq!(ceremony.ceremony_id.threshold, 3);
        assert_eq!(ceremony.ceremony_id.total, 5);
    }

    // ---- Abort result fields ----

    #[test]
    fn abort_result_contains_ceremony_id() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        let expected_id = ceremony.ceremony_id.clone();
        let result = ceremony.abort("test");
        assert_eq!(result.ceremony_id, expected_id);
    }

    #[test]
    fn abort_records_failure_in_transcript() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.abort("timeout");
        let last_phase = ceremony.transcript.phases.last().unwrap();
        assert_eq!(last_phase.phase, "Failed");
        assert_eq!(last_phase.reason.as_deref(), Some("timeout"));
    }

    // ── Security regression: rogue-key attack mitigations (f07de35) ──

    #[test]
    fn add_commitment_rejects_empty_proof() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();

        // Create a commitment with empty proof-of-knowledge
        let bad_commitment = FrostCommitment {
            participant_index: 1,
            commitment: vec![1u8; 32],
            proof: vec![], // Empty proof — rogue-key attack vector
        };

        let result = ceremony.add_commitment(bad_commitment);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("empty proof"),
            "Error should mention empty proof-of-knowledge"
        );
    }

    #[test]
    fn add_shares_rejects_empty_shares_list() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();

        // Now in Round2Shares phase — submit empty shares list
        let result = ceremony.add_shares(1, vec![]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("empty shares"),
            "Error should mention empty shares list"
        );
    }

    #[test]
    fn add_shares_rejects_empty_ciphertext() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();

        // Submit shares with an empty ciphertext
        let bad_shares = vec![EncryptedShare {
            from_index: 1,
            to_index: 2,
            ciphertext: vec![], // Empty ciphertext — invalid
        }];

        let result = ceremony.add_shares(1, bad_shares);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("empty ciphertext"),
            "Error should mention empty ciphertext"
        );
    }

    // ---- CeremonyId serde with known values ----

    #[test]
    fn ceremony_id_clone_preserves_fields() {
        let id = CeremonyId::generate(2, 5);
        let cloned = id.clone();
        assert_eq!(id.id, cloned.id);
        assert_eq!(id.threshold, cloned.threshold);
        assert_eq!(id.total, cloned.total);
    }

    #[test]
    fn ceremony_id_display_contains_threshold_total() {
        let id = CeremonyId::generate(4, 7);
        let display = format!("{id}");
        assert!(display.contains("4/7"));
    }

    // ---- ParticipantId serde roundtrip ----

    #[test]
    fn participant_id_serde_roundtrip() {
        let p = test_participant(3);
        let json = serde_json::to_string(&p).unwrap();
        let restored: ParticipantId = serde_json::from_str(&json).unwrap();
        assert_eq!(p, restored);
    }

    #[test]
    fn participant_id_clone_preserves_fields() {
        let p = test_participant(7);
        let cloned = p.clone();
        assert_eq!(p.index, cloned.index);
        assert_eq!(p.name, cloned.name);
        assert_eq!(p.public_key, cloned.public_key);
    }

    // ---- FrostCommitment serde roundtrip ----

    #[test]
    fn frost_commitment_serde_roundtrip() {
        let c = test_commitment(2);
        let json = serde_json::to_string(&c).unwrap();
        let restored: FrostCommitment = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.participant_index, 2);
        assert_eq!(restored.commitment.len(), 32);
    }

    #[test]
    fn frost_commitment_clone() {
        let c = test_commitment(4);
        let cloned = c.clone();
        assert_eq!(c.participant_index, cloned.participant_index);
        assert_eq!(c.commitment, cloned.commitment);
        assert_eq!(c.proof, cloned.proof);
    }

    // ---- EncryptedShare serde roundtrip ----

    #[test]
    fn encrypted_share_serde_roundtrip() {
        let share = EncryptedShare {
            from_index: 1,
            to_index: 2,
            ciphertext: vec![0xAB; 64],
        };
        let json = serde_json::to_string(&share).unwrap();
        let restored: EncryptedShare = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.from_index, 1);
        assert_eq!(restored.to_index, 2);
        assert_eq!(restored.ciphertext.len(), 64);
    }

    // ---- ThresholdConfig serde roundtrip ----

    #[test]
    fn threshold_config_serde_roundtrip() {
        let config = ThresholdConfig::new(3, 5);
        let json = serde_json::to_string(&config).unwrap();
        let restored: ThresholdConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.threshold, 3);
        assert_eq!(restored.total, 5);
        assert!(restored.allow_resume);
    }

    #[test]
    fn threshold_config_clone() {
        let config = ThresholdConfig::new(2, 4);
        let cloned = config.clone();
        assert_eq!(config.threshold, cloned.threshold);
        assert_eq!(config.total, cloned.total);
        assert_eq!(config.allow_resume, cloned.allow_resume);
    }

    // ---- ThresholdCeremony debug ----

    #[test]
    fn threshold_ceremony_debug_format() {
        let ceremony = ThresholdCeremony::new(2, 3);
        let debug = format!("{ceremony:?}");
        assert!(debug.contains("ThresholdCeremony"));
        assert!(debug.contains("participant_count"));
        assert!(debug.contains("has_key_material"));
    }

    // ---- CeremonyTranscript default ----

    #[test]
    fn ceremony_transcript_default_is_empty() {
        let transcript = CeremonyTranscript::default();
        assert!(transcript.phases.is_empty());
        assert!(transcript.joins.is_empty());
        assert!(transcript.messages.is_empty());
    }

    // ---- Max participants reached ----

    #[test]
    fn add_participant_rejects_over_limit() {
        let mut ceremony = ThresholdCeremony::new(1, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        // Now in Round1, adding more should fail
        let result = ceremony.add_participant(test_participant(3));
        assert!(result.is_err());
    }

    // ---- owner_verifying_key before completion ----

    #[test]
    fn owner_verifying_key_fails_before_completion() {
        let ceremony = ThresholdCeremony::new(2, 3);
        let result = ceremony.owner_verifying_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not available"));
    }

    // ---- is_timed_out ----

    #[test]
    fn ceremony_is_not_timed_out_when_fresh() {
        let ceremony = ThresholdCeremony::new(2, 3);
        assert!(!ceremony.is_timed_out());
    }

    // ---- Checkpoint serde roundtrip ----

    #[test]
    fn checkpoint_serde_roundtrip() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        let checkpoint = ceremony.create_checkpoint();
        let json = serde_json::to_string(&checkpoint).unwrap();
        let restored: CeremonyCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.ceremony_id, checkpoint.ceremony_id);
        assert_eq!(restored.participants.len(), checkpoint.participants.len());
    }

    // ---- CeremonyId uniqueness ----

    #[test]
    fn ceremony_id_generate_produces_unique_ids() {
        let id1 = CeremonyId::generate(2, 3);
        let id2 = CeremonyId::generate(2, 3);
        assert_ne!(id1.id, id2.id, "two generated IDs should differ");
    }

    #[test]
    fn ceremony_id_hash_works_in_hashset() {
        use std::collections::HashSet;
        let id1 = CeremonyId::generate(2, 3);
        let id2 = id1.clone();
        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        assert_eq!(set.len(), 1);
    }

    // ---- ParticipantId hash ----

    #[test]
    fn participant_id_hash_works_in_hashset() {
        use std::collections::HashSet;
        let p1 = test_participant(1);
        let p2 = test_participant(1);
        let p3 = test_participant(2);
        let mut set = HashSet::new();
        set.insert(p1);
        set.insert(p2);
        set.insert(p3);
        assert_eq!(set.len(), 2);
    }

    // ---- CeremonyPhase clone ----

    #[test]
    fn ceremony_phase_clone_gathering() {
        let phase = CeremonyPhase::Gathering {
            joined: vec![test_participant(1)],
            target: 3,
        };
        let cloned = phase.clone();
        match (&phase, &cloned) {
            (
                CeremonyPhase::Gathering {
                    joined: j1,
                    target: t1,
                },
                CeremonyPhase::Gathering {
                    joined: j2,
                    target: t2,
                },
            ) => {
                assert_eq!(j1.len(), j2.len());
                assert_eq!(t1, t2);
            }
            _ => panic!("expected Gathering"),
        }
    }

    #[test]
    fn ceremony_phase_clone_complete() {
        let phase = CeremonyPhase::Complete {
            group_public_key: [0xAB; 32],
        };
        #[allow(clippy::redundant_clone)]
        let cloned = phase.clone();
        match cloned {
            CeremonyPhase::Complete { group_public_key } => {
                assert_eq!(group_public_key, [0xAB; 32]);
            }
            _ => panic!("expected Complete"),
        }
    }

    // ---- ThresholdConfig boundary ----

    #[test]
    fn threshold_config_equal_threshold_and_total() {
        let config = ThresholdConfig::new(5, 5);
        assert_eq!(config.threshold, 5);
        assert_eq!(config.total, 5);
    }

    #[test]
    fn threshold_config_with_timeout_chaining() {
        let config = ThresholdConfig::new(2, 3)
            .with_timeout(Duration::minutes(5));
        assert_eq!(config.phase_timeout, Duration::minutes(5));
        assert_eq!(config.threshold, 2);
    }

    // ---- Transcript serde ----

    #[test]
    fn ceremony_transcript_serde_roundtrip() {
        let transcript = CeremonyTranscript {
            phases: vec![PhaseRecord {
                phase: "Gathering".to_string(),
                entered_at: Utc::now(),
                reason: None,
            }],
            joins: vec![JoinRecord {
                participant: test_participant(1),
                joined_at: Utc::now(),
            }],
            messages: vec![MessageRecord {
                from: 1,
                to: 0,
                message_type: "commitment".to_string(),
                timestamp: Utc::now(),
            }],
        };
        let json = serde_json::to_string(&transcript).unwrap();
        let restored: CeremonyTranscript = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.phases.len(), 1);
        assert_eq!(restored.joins.len(), 1);
        assert_eq!(restored.messages.len(), 1);
    }

    // ---- PhaseRecord serde ----

    #[test]
    fn phase_record_with_reason_serde() {
        let record = PhaseRecord {
            phase: "Failed".to_string(),
            entered_at: Utc::now(),
            reason: Some("timeout".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: PhaseRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.phase, "Failed");
        assert_eq!(restored.reason, Some("timeout".to_string()));
    }

    #[test]
    fn phase_record_without_reason_serde() {
        let record = PhaseRecord {
            phase: "Gathering".to_string(),
            entered_at: Utc::now(),
            reason: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: PhaseRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.reason, None);
    }

    // ---- CeremonyResumeError is std::error::Error ----

    #[test]
    fn ceremony_resume_error_is_error_trait() {
        let err = CeremonyResumeError::CheckpointExpired;
        let _: &dyn std::error::Error = &err;
    }

    // ---- Resume from Gathering ----

    #[test]
    fn resume_from_gathering_preserves_participants() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();

        let result = ceremony.abort("pause");
        let checkpoint = result.checkpoint.unwrap();
        assert_eq!(checkpoint.participants.len(), 2);

        let resumed = ThresholdCeremony::resume(checkpoint).unwrap();
        assert_eq!(resumed.participants.len(), 2);
    }

    // ---- Full ceremony then abort ----

    #[test]
    fn complete_ceremony_then_abort_cannot_resume() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        ceremony.add_shares(2, test_shares(2, 1)).unwrap();

        // Now in Complete phase
        let result = ceremony.abort("user changed mind");
        // Complete is not resumable (not Gathering or Round1)
        assert!(!result.can_resume);
    }

    // ---- Checkpoint fields ----

    #[test]
    fn checkpoint_has_correct_ceremony_id() {
        let ceremony = ThresholdCeremony::new(3, 5);
        let expected_id = ceremony.ceremony_id.clone();
        let checkpoint = ceremony.create_checkpoint();
        assert_eq!(checkpoint.ceremony_id, expected_id);
    }

    #[test]
    fn checkpoint_deadline_is_in_future() {
        let ceremony = ThresholdCeremony::new(2, 3);
        let checkpoint = ceremony.create_checkpoint();
        assert!(checkpoint.phase_deadline > Utc::now());
    }

    // ---- EncryptedShare clone ----

    #[test]
    fn encrypted_share_clone() {
        let share = EncryptedShare {
            from_index: 1,
            to_index: 2,
            ciphertext: vec![0xAB; 48],
        };
        let cloned = share.clone();
        assert_eq!(share.from_index, cloned.from_index);
        assert_eq!(share.to_index, cloned.to_index);
        assert_eq!(share.ciphertext, cloned.ciphertext);
    }

    // ---- ThresholdSignatureArtifact eq ----

    #[test]
    fn threshold_signature_artifact_eq() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_participant(test_participant(3)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_commitment(test_commitment(3)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        ceremony.add_shares(2, test_shares(2, 1)).unwrap();
        ceremony.add_shares(3, test_shares(3, 1)).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let artifact = ceremony
            .sign_with_participants_and_rng(
                &[1, 2],
                b"ctx",
                b"msg",
                &mut rng,
            )
            .unwrap();

        let cloned = artifact.clone();
        assert_eq!(artifact, cloned);
    }

    // ---- verify_signature_artifact wrong context ----

    #[test]
    fn verify_signature_artifact_wrong_context_fails() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_participant(test_participant(3)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_commitment(test_commitment(3)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        ceremony.add_shares(2, test_shares(2, 1)).unwrap();
        ceremony.add_shares(3, test_shares(3, 1)).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(55);
        let artifact = ceremony
            .sign_with_participants_and_rng(
                &[1, 3],
                b"correct-context",
                b"message",
                &mut rng,
            )
            .unwrap();

        // Verify with wrong context should fail
        let err = ceremony
            .verify_signature_artifact(&artifact, b"wrong-context", b"message")
            .unwrap_err();
        assert!(err.contains("transcript does not match"));
    }

    // ---- verify_signature_artifact wrong message ----

    #[test]
    fn verify_signature_artifact_wrong_message_fails() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        ceremony.add_participant(test_participant(3)).unwrap();
        ceremony.add_commitment(test_commitment(1)).unwrap();
        ceremony.add_commitment(test_commitment(2)).unwrap();
        ceremony.add_commitment(test_commitment(3)).unwrap();
        ceremony.add_shares(1, test_shares(1, 2)).unwrap();
        ceremony.add_shares(2, test_shares(2, 1)).unwrap();
        ceremony.add_shares(3, test_shares(3, 1)).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(77);
        let artifact = ceremony
            .sign_with_participants_and_rng(
                &[2, 3],
                b"context",
                b"correct-message",
                &mut rng,
            )
            .unwrap();

        let err = ceremony
            .verify_signature_artifact(&artifact, b"context", b"wrong-message")
            .unwrap_err();
        assert!(err.contains("transcript does not match"));
    }

    // ---- sign before completion ----

    #[test]
    fn sign_before_completion_fails() {
        let mut ceremony = ThresholdCeremony::new(2, 2);
        ceremony.add_participant(test_participant(1)).unwrap();
        ceremony.add_participant(test_participant(2)).unwrap();
        // Only in Round1, not Complete
        let result = ceremony.sign_with_participants(&[1, 2], b"ctx", b"msg");
        assert!(result.is_err());
    }

    // ---- CeremonyAbortResult debug ----

    #[test]
    fn ceremony_abort_result_debug() {
        let mut ceremony = ThresholdCeremony::new(2, 3);
        let result = ceremony.abort("test");
        let debug = format!("{result:?}");
        assert!(debug.contains("CeremonyAbortResult"));
        assert!(debug.contains("can_resume"));
    }
}
