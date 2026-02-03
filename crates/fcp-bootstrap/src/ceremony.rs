//! Threshold key ceremony for distributed owner key generation.
//!
//! This module implements FROST-based threshold signing setup for multi-device
//! owner key management.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
#[derive(Debug)]
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
            config,
            ceremony_id,
        }
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
        if let CeremonyPhase::Round2Shares { shares: all_shares } = &mut self.phase {
            if all_shares.contains_key(&from_index) {
                return Err(format!(
                    "Shares from participant {from_index} already received"
                ));
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
                self.complete_ceremony();
            }

            Ok(())
        } else {
            Err("Cannot add shares in current phase".to_string())
        }
    }

    /// Complete the ceremony (placeholder - actual FROST aggregation would go here).
    fn complete_ceremony(&mut self) {
        let now = Utc::now();
        // In a real implementation, this would aggregate the shares to derive
        // the group public key using FROST protocol.
        let group_public_key = [0u8; 32]; // Placeholder

        self.phase = CeremonyPhase::Complete { group_public_key };
        self.transcript.phases.push(PhaseRecord {
            phase: "Complete".to_string(),
            entered_at: now,
            reason: None,
        });
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
}
