//! Bootstrap phase state machine.
//!
//! This module defines the phases of the bootstrap process and the
//! transitions between them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The current phase of the bootstrap process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BootstrapPhase {
    /// System is uninitialized.
    Uninitialized,

    /// Validating system time against NTP.
    TimeValidation,

    /// Generating or importing the owner key.
    KeyGeneration,

    /// Setting up the threshold ceremony (multi-device only).
    CeremonySetup {
        /// Number of participants.
        participant_count: u32,
        /// Threshold required for signing.
        threshold: u32,
    },

    /// Round 1 of the threshold ceremony (commitment exchange).
    CeremonyRound1 {
        /// Commitments collected so far.
        commitments_collected: u32,
        /// Total commitments needed.
        commitments_needed: u32,
    },

    /// Round 2 of the threshold ceremony (share distribution).
    CeremonyRound2 {
        /// Shares distributed so far.
        shares_distributed: u32,
        /// Total shares needed.
        shares_needed: u32,
    },

    /// Creating the genesis state.
    GenesisCreate,

    /// Enrolling the first device.
    Enrollment,

    /// Bootstrap completed successfully.
    Completed {
        /// Fingerprint of the created genesis.
        fingerprint: String,
        /// Time when bootstrap completed.
        completed_at: DateTime<Utc>,
    },

    /// Bootstrap failed.
    Failed {
        /// Error message.
        reason: String,
        /// Phase where failure occurred.
        at_phase: String,
    },
}

impl BootstrapPhase {
    /// Check if this is a terminal phase.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::Failed { .. })
    }

    /// Check if this phase can be resumed after a crash.
    #[must_use]
    pub const fn is_resumable(&self) -> bool {
        matches!(
            self,
            Self::TimeValidation
                | Self::KeyGeneration
                | Self::CeremonySetup { .. }
                | Self::CeremonyRound1 { .. }
        )
    }

    /// Get a human-readable description of this phase.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Uninitialized => "System is not initialized",
            Self::TimeValidation => "Validating system time",
            Self::KeyGeneration => "Generating owner key",
            Self::CeremonySetup { .. } => "Setting up key ceremony",
            Self::CeremonyRound1 { .. } => "Ceremony round 1: collecting commitments",
            Self::CeremonyRound2 { .. } => "Ceremony round 2: distributing shares",
            Self::GenesisCreate => "Creating genesis state",
            Self::Enrollment => "Enrolling first device",
            Self::Completed { .. } => "Bootstrap completed",
            Self::Failed { .. } => "Bootstrap failed",
        }
    }
}

impl std::fmt::Display for BootstrapPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uninitialized => write!(f, "Uninitialized"),
            Self::TimeValidation => write!(f, "TimeValidation"),
            Self::KeyGeneration => write!(f, "KeyGeneration"),
            Self::CeremonySetup {
                participant_count,
                threshold,
            } => {
                write!(f, "CeremonySetup({threshold}/{participant_count})")
            }
            Self::CeremonyRound1 {
                commitments_collected,
                commitments_needed,
            } => write!(
                f,
                "CeremonyRound1({commitments_collected}/{commitments_needed})"
            ),
            Self::CeremonyRound2 {
                shares_distributed,
                shares_needed,
            } => write!(f, "CeremonyRound2({shares_distributed}/{shares_needed})"),
            Self::GenesisCreate => write!(f, "GenesisCreate"),
            Self::Enrollment => write!(f, "Enrollment"),
            Self::Completed { fingerprint, .. } => write!(f, "Completed({fingerprint})"),
            Self::Failed { reason, .. } => write!(f, "Failed({reason})"),
        }
    }
}

/// Result of attempting to initialize.
#[derive(Debug, Clone)]
pub enum InitResult {
    /// Fresh initialization completed.
    Created(crate::genesis::GenesisState),

    /// Genesis already exists at this location.
    AlreadyExists {
        /// Fingerprint of the existing genesis.
        fingerprint: String,
        /// Time of the existing genesis.
        genesis_time: DateTime<Utc>,
        /// Suggestion for what to do.
        suggestion: InitSuggestion,
    },

    /// Partial state detected (crashed during previous init).
    PartialState {
        /// Phase where the crash occurred.
        phase: BootstrapPhase,
        /// Suggestion for what to do.
        suggestion: PartialStateSuggestion,
    },
}

/// Suggestion for handling an existing genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSuggestion {
    /// Use the existing genesis (no action needed).
    UseExisting,
    /// Run with --force to overwrite (DANGEROUS).
    ForceOverwrite,
    /// Run in a different directory.
    UseDifferentPath,
}

impl std::fmt::Display for InitSuggestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UseExisting => write!(f, "Use the existing genesis"),
            Self::ForceOverwrite => {
                write!(
                    f,
                    "Run with --force --i-understand-this-is-destructive to overwrite"
                )
            }
            Self::UseDifferentPath => write!(f, "Run in a different directory"),
        }
    }
}

/// Suggestion for handling partial state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialStateSuggestion {
    /// Resume from where we left off.
    Resume,
    /// Clean up and start fresh.
    CleanAndRetry,
}

impl std::fmt::Display for PartialStateSuggestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resume => write!(f, "Resume the previous bootstrap attempt"),
            Self::CleanAndRetry => write!(f, "Clean up partial state and start fresh"),
        }
    }
}

/// Detects partial state from a crashed initialization.
#[must_use]
pub fn detect_partial_state(data_dir: &Path) -> Option<BootstrapPhase> {
    // Check for lock file
    let lock_file = data_dir.join("init.lock");
    if lock_file.exists() {
        // Try to read the phase from the lock file
        if let Ok(contents) = std::fs::read_to_string(&lock_file) {
            if let Ok(phase) = serde_json::from_str::<BootstrapPhase>(&contents) {
                return Some(phase);
            }
        }
        // Lock file exists but can't be parsed - assume early phase
        return Some(BootstrapPhase::TimeValidation);
    }

    // Check for partial genesis directory
    let genesis_partial = data_dir.join("genesis.partial");
    if genesis_partial.exists() {
        return Some(BootstrapPhase::GenesisCreate);
    }

    // Check for uncommitted key material
    let keys_partial = data_dir.join("keys.partial");
    if keys_partial.exists() {
        return Some(BootstrapPhase::KeyGeneration);
    }

    None
}

/// Write the current phase to the lock file.
///
/// # Errors
///
/// Returns an I/O error if the phase cannot be serialized or written.
pub fn write_phase_lock(data_dir: &Path, phase: &BootstrapPhase) -> std::io::Result<()> {
    let lock_file = data_dir.join("init.lock");
    let contents = serde_json::to_string(phase)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(lock_file, contents)
}

/// Remove the phase lock file (call on successful completion).
///
/// # Errors
///
/// Returns an I/O error if the lock file cannot be removed.
pub fn remove_phase_lock(data_dir: &Path) -> std::io::Result<()> {
    let lock_file = data_dir.join("init.lock");
    if lock_file.exists() {
        std::fs::remove_file(lock_file)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_phase_display() {
        let phase = BootstrapPhase::CeremonyRound1 {
            commitments_collected: 2,
            commitments_needed: 3,
        };
        assert_eq!(format!("{phase}"), "CeremonyRound1(2/3)");
    }

    #[test]
    fn test_phase_is_terminal() {
        assert!(!BootstrapPhase::Uninitialized.is_terminal());
        assert!(
            BootstrapPhase::Completed {
                fingerprint: "test".to_string(),
                completed_at: Utc::now(),
            }
            .is_terminal()
        );
        assert!(
            BootstrapPhase::Failed {
                reason: "test".to_string(),
                at_phase: "test".to_string(),
            }
            .is_terminal()
        );
    }

    #[test]
    fn test_phase_lock_roundtrip() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::CeremonySetup {
            participant_count: 3,
            threshold: 2,
        };

        write_phase_lock(dir.path(), &phase).unwrap();

        let detected = detect_partial_state(dir.path());
        assert!(detected.is_some());

        remove_phase_lock(dir.path()).unwrap();
        let detected_after = detect_partial_state(dir.path());
        assert!(detected_after.is_none());
    }

    // ---- is_terminal for all variants ----

    #[test]
    fn test_non_terminal_phases() {
        let non_terminal = [
            BootstrapPhase::Uninitialized,
            BootstrapPhase::TimeValidation,
            BootstrapPhase::KeyGeneration,
            BootstrapPhase::CeremonySetup {
                participant_count: 3,
                threshold: 2,
            },
            BootstrapPhase::CeremonyRound1 {
                commitments_collected: 1,
                commitments_needed: 3,
            },
            BootstrapPhase::CeremonyRound2 {
                shares_distributed: 0,
                shares_needed: 3,
            },
            BootstrapPhase::GenesisCreate,
            BootstrapPhase::Enrollment,
        ];
        for phase in &non_terminal {
            assert!(!phase.is_terminal(), "{phase} should not be terminal");
        }
    }

    // ---- is_resumable ----

    #[test]
    fn test_is_resumable() {
        assert!(!BootstrapPhase::Uninitialized.is_resumable());
        assert!(BootstrapPhase::TimeValidation.is_resumable());
        assert!(BootstrapPhase::KeyGeneration.is_resumable());
        assert!(
            BootstrapPhase::CeremonySetup {
                participant_count: 3,
                threshold: 2,
            }
            .is_resumable()
        );
        assert!(
            BootstrapPhase::CeremonyRound1 {
                commitments_collected: 1,
                commitments_needed: 3,
            }
            .is_resumable()
        );
        // Round2 is NOT resumable
        assert!(
            !BootstrapPhase::CeremonyRound2 {
                shares_distributed: 1,
                shares_needed: 3,
            }
            .is_resumable()
        );
        assert!(!BootstrapPhase::GenesisCreate.is_resumable());
        assert!(!BootstrapPhase::Enrollment.is_resumable());
    }

    // ---- description for all variants ----

    #[test]
    fn test_all_phases_have_descriptions() {
        let phases: Vec<BootstrapPhase> = vec![
            BootstrapPhase::Uninitialized,
            BootstrapPhase::TimeValidation,
            BootstrapPhase::KeyGeneration,
            BootstrapPhase::CeremonySetup {
                participant_count: 3,
                threshold: 2,
            },
            BootstrapPhase::CeremonyRound1 {
                commitments_collected: 0,
                commitments_needed: 3,
            },
            BootstrapPhase::CeremonyRound2 {
                shares_distributed: 0,
                shares_needed: 3,
            },
            BootstrapPhase::GenesisCreate,
            BootstrapPhase::Enrollment,
            BootstrapPhase::Completed {
                fingerprint: "fp".into(),
                completed_at: Utc::now(),
            },
            BootstrapPhase::Failed {
                reason: "test".into(),
                at_phase: "test".into(),
            },
        ];
        for phase in &phases {
            let desc = phase.description();
            assert!(!desc.is_empty(), "{phase} has empty description");
        }
    }

    // ---- Display for all variants ----

    #[test]
    fn test_display_all_variants() {
        assert_eq!(
            format!("{}", BootstrapPhase::Uninitialized),
            "Uninitialized"
        );
        assert_eq!(
            format!("{}", BootstrapPhase::TimeValidation),
            "TimeValidation"
        );
        assert_eq!(
            format!("{}", BootstrapPhase::KeyGeneration),
            "KeyGeneration"
        );
        assert_eq!(
            format!(
                "{}",
                BootstrapPhase::CeremonySetup {
                    participant_count: 5,
                    threshold: 3,
                }
            ),
            "CeremonySetup(3/5)"
        );
        assert_eq!(
            format!(
                "{}",
                BootstrapPhase::CeremonyRound2 {
                    shares_distributed: 1,
                    shares_needed: 5,
                }
            ),
            "CeremonyRound2(1/5)"
        );
        assert_eq!(
            format!("{}", BootstrapPhase::GenesisCreate),
            "GenesisCreate"
        );
        assert_eq!(format!("{}", BootstrapPhase::Enrollment), "Enrollment");
        assert!(
            format!(
                "{}",
                BootstrapPhase::Completed {
                    fingerprint: "fp123".into(),
                    completed_at: Utc::now(),
                }
            )
            .contains("fp123")
        );
        assert!(
            format!(
                "{}",
                BootstrapPhase::Failed {
                    reason: "disk full".into(),
                    at_phase: "genesis".into(),
                }
            )
            .contains("disk full")
        );
    }

    // ---- Serde roundtrip ----

    #[test]
    fn test_phase_serde_roundtrip_all() {
        let phases = vec![
            BootstrapPhase::Uninitialized,
            BootstrapPhase::TimeValidation,
            BootstrapPhase::KeyGeneration,
            BootstrapPhase::CeremonySetup {
                participant_count: 3,
                threshold: 2,
            },
            BootstrapPhase::CeremonyRound1 {
                commitments_collected: 1,
                commitments_needed: 3,
            },
            BootstrapPhase::CeremonyRound2 {
                shares_distributed: 2,
                shares_needed: 3,
            },
            BootstrapPhase::GenesisCreate,
            BootstrapPhase::Enrollment,
        ];
        for phase in phases {
            let json = serde_json::to_string(&phase).unwrap();
            let back: BootstrapPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(phase, back, "serde roundtrip failed for {phase}");
        }
    }

    // ---- detect_partial_state ----

    #[test]
    fn test_detect_partial_state_genesis_partial() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("genesis.partial")).unwrap();
        let detected = detect_partial_state(dir.path());
        assert_eq!(detected, Some(BootstrapPhase::GenesisCreate));
    }

    #[test]
    fn test_detect_partial_state_keys_partial() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("keys.partial")).unwrap();
        let detected = detect_partial_state(dir.path());
        assert_eq!(detected, Some(BootstrapPhase::KeyGeneration));
    }

    #[test]
    fn test_detect_partial_state_corrupt_lock() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("init.lock"), "not valid json").unwrap();
        let detected = detect_partial_state(dir.path());
        // Corrupt lock → fallback to TimeValidation
        assert_eq!(detected, Some(BootstrapPhase::TimeValidation));
    }

    #[test]
    fn test_detect_no_partial_state() {
        let dir = tempdir().unwrap();
        assert!(detect_partial_state(dir.path()).is_none());
    }

    // ---- remove_phase_lock idempotent ----

    #[test]
    fn test_remove_phase_lock_when_no_lock() {
        let dir = tempdir().unwrap();
        // Should not error when lock doesn't exist
        assert!(remove_phase_lock(dir.path()).is_ok());
    }

    // ---- InitSuggestion Display ----

    #[test]
    fn test_init_suggestion_display() {
        assert!(
            InitSuggestion::UseExisting
                .to_string()
                .contains("Use the existing")
        );
        assert!(
            InitSuggestion::ForceOverwrite
                .to_string()
                .contains("--force")
        );
        assert!(
            InitSuggestion::UseDifferentPath
                .to_string()
                .contains("different directory")
        );
    }

    // ---- PartialStateSuggestion Display ----

    #[test]
    fn test_partial_state_suggestion_display() {
        assert!(
            PartialStateSuggestion::Resume
                .to_string()
                .contains("Resume")
        );
        assert!(
            PartialStateSuggestion::CleanAndRetry
                .to_string()
                .contains("Clean up")
        );
    }

    // ---- InitSuggestion/PartialStateSuggestion eq ----

    #[test]
    fn test_suggestion_eq() {
        assert_eq!(InitSuggestion::UseExisting, InitSuggestion::UseExisting);
        assert_ne!(InitSuggestion::UseExisting, InitSuggestion::ForceOverwrite);
        assert_eq!(
            PartialStateSuggestion::Resume,
            PartialStateSuggestion::Resume
        );
        assert_ne!(
            PartialStateSuggestion::Resume,
            PartialStateSuggestion::CleanAndRetry
        );
    }

    // ---- BootstrapPhase Clone ----

    #[test]
    fn phase_clone_uninitialized() {
        let phase = BootstrapPhase::Uninitialized;
        let cloned = phase.clone();
        assert_eq!(phase, cloned);
    }

    #[test]
    fn phase_clone_ceremony_setup() {
        let phase = BootstrapPhase::CeremonySetup {
            participant_count: 5,
            threshold: 3,
        };
        let cloned = phase.clone();
        assert_eq!(phase, cloned);
    }

    #[test]
    fn phase_clone_completed() {
        let phase = BootstrapPhase::Completed {
            fingerprint: "SHA256:test".to_string(),
            completed_at: Utc::now(),
        };
        let cloned = phase.clone();
        assert_eq!(phase, cloned);
    }

    #[test]
    fn phase_clone_failed() {
        let phase = BootstrapPhase::Failed {
            reason: "disk full".to_string(),
            at_phase: "GenesisCreate".to_string(),
        };
        let cloned = phase.clone();
        assert_eq!(phase, cloned);
    }

    // ---- BootstrapPhase Debug ----

    #[test]
    fn phase_debug_contains_variant_names() {
        let phase = BootstrapPhase::CeremonyRound2 {
            shares_distributed: 2,
            shares_needed: 5,
        };
        let debug = format!("{phase:?}");
        assert!(debug.contains("CeremonyRound2"));
        assert!(debug.contains('2'));
        assert!(debug.contains('5'));
    }

    // ---- Serde roundtrip for Completed and Failed ----

    #[test]
    fn phase_serde_roundtrip_completed() {
        let phase = BootstrapPhase::Completed {
            fingerprint: "SHA256:fp123".to_string(),
            completed_at: Utc::now(),
        };
        let json = serde_json::to_string(&phase).unwrap();
        let back: BootstrapPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, back);
    }

    #[test]
    fn phase_serde_roundtrip_failed() {
        let phase = BootstrapPhase::Failed {
            reason: "timeout".to_string(),
            at_phase: "Round1".to_string(),
        };
        let json = serde_json::to_string(&phase).unwrap();
        let back: BootstrapPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, back);
    }

    // ---- Phase lock with various phases ----

    #[test]
    fn phase_lock_roundtrip_uninitialized() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::Uninitialized;
        write_phase_lock(dir.path(), &phase).unwrap();
        let detected = detect_partial_state(dir.path());
        assert!(detected.is_some());
        assert_eq!(detected.unwrap(), BootstrapPhase::Uninitialized);
    }

    #[test]
    fn phase_lock_roundtrip_ceremony_round1() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::CeremonyRound1 {
            commitments_collected: 2,
            commitments_needed: 5,
        };
        write_phase_lock(dir.path(), &phase).unwrap();
        let detected = detect_partial_state(dir.path()).unwrap();
        assert_eq!(detected, phase);
    }

    // ---- InitSuggestion copy ----

    #[test]
    fn init_suggestion_copy() {
        let s = InitSuggestion::UseExisting;
        let copied = s;
        assert_eq!(s, copied);
    }

    #[test]
    fn partial_state_suggestion_copy() {
        let s = PartialStateSuggestion::Resume;
        let copied = s;
        assert_eq!(s, copied);
    }

    // ---- Display lengths non-empty ----

    #[test]
    fn init_suggestion_display_not_empty() {
        let variants = [
            InitSuggestion::UseExisting,
            InitSuggestion::ForceOverwrite,
            InitSuggestion::UseDifferentPath,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn partial_state_suggestion_display_not_empty() {
        let variants = [
            PartialStateSuggestion::Resume,
            PartialStateSuggestion::CleanAndRetry,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // ---- Phase lock with various phases ----

    #[test]
    fn phase_lock_roundtrip_ceremony_round2() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::CeremonyRound2 {
            shares_distributed: 3,
            shares_needed: 5,
        };
        write_phase_lock(dir.path(), &phase).unwrap();
        let detected = detect_partial_state(dir.path()).unwrap();
        assert_eq!(detected, phase);
    }

    #[test]
    fn phase_lock_roundtrip_genesis_create() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::GenesisCreate;
        write_phase_lock(dir.path(), &phase).unwrap();
        let detected = detect_partial_state(dir.path()).unwrap();
        assert_eq!(detected, phase);
    }

    #[test]
    fn phase_lock_roundtrip_enrollment() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::Enrollment;
        write_phase_lock(dir.path(), &phase).unwrap();
        let detected = detect_partial_state(dir.path()).unwrap();
        assert_eq!(detected, phase);
    }

    #[test]
    fn phase_lock_roundtrip_completed() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::Completed {
            fingerprint: "SHA256:abc123".to_string(),
            completed_at: Utc::now(),
        };
        write_phase_lock(dir.path(), &phase).unwrap();
        let detected = detect_partial_state(dir.path()).unwrap();
        // Completed phase should still be detectable from lock file
        match detected {
            BootstrapPhase::Completed { fingerprint, .. } => {
                assert_eq!(fingerprint, "SHA256:abc123");
            }
            other => panic!("expected Completed, got {other}"),
        }
    }

    // ---- Lock file priority over partial markers ----

    #[test]
    fn lock_file_takes_priority_over_genesis_partial() {
        let dir = tempdir().unwrap();
        // Create both a lock file and a genesis.partial marker
        std::fs::create_dir(dir.path().join("genesis.partial")).unwrap();
        let phase = BootstrapPhase::KeyGeneration;
        write_phase_lock(dir.path(), &phase).unwrap();
        // Lock file should take priority
        let detected = detect_partial_state(dir.path()).unwrap();
        assert_eq!(detected, BootstrapPhase::KeyGeneration);
    }

    #[test]
    fn genesis_partial_takes_priority_over_keys_partial() {
        let dir = tempdir().unwrap();
        // Create both partial markers (no lock file)
        std::fs::create_dir(dir.path().join("genesis.partial")).unwrap();
        std::fs::create_dir(dir.path().join("keys.partial")).unwrap();
        // genesis.partial is checked before keys.partial
        let detected = detect_partial_state(dir.path()).unwrap();
        assert_eq!(detected, BootstrapPhase::GenesisCreate);
    }

    // ---- Phase serde with edge values ----

    #[test]
    fn phase_serde_ceremony_round1_zero_collected() {
        let phase = BootstrapPhase::CeremonyRound1 {
            commitments_collected: 0,
            commitments_needed: 0,
        };
        let json = serde_json::to_string(&phase).unwrap();
        let back: BootstrapPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, back);
    }

    #[test]
    fn phase_serde_ceremony_setup_max_values() {
        let phase = BootstrapPhase::CeremonySetup {
            participant_count: u32::MAX,
            threshold: u32::MAX,
        };
        let json = serde_json::to_string(&phase).unwrap();
        let back: BootstrapPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, back);
    }

    // ---- Description content verification ----

    #[test]
    fn description_uninitialized_contains_not_initialized() {
        assert!(
            BootstrapPhase::Uninitialized
                .description()
                .contains("not initialized")
        );
    }

    #[test]
    fn description_time_validation_contains_time() {
        assert!(
            BootstrapPhase::TimeValidation
                .description()
                .contains("time")
        );
    }

    #[test]
    fn description_key_generation_contains_key() {
        assert!(
            BootstrapPhase::KeyGeneration
                .description()
                .contains("key")
        );
    }

    #[test]
    fn description_completed_contains_completed() {
        let phase = BootstrapPhase::Completed {
            fingerprint: "fp".into(),
            completed_at: Utc::now(),
        };
        assert!(phase.description().contains("completed"));
    }

    #[test]
    fn description_failed_contains_failed() {
        let phase = BootstrapPhase::Failed {
            reason: "err".into(),
            at_phase: "p".into(),
        };
        assert!(phase.description().contains("failed"));
    }

    // ---- InitSuggestion Debug ----

    #[test]
    fn init_suggestion_debug() {
        let debug = format!("{:?}", InitSuggestion::ForceOverwrite);
        assert!(debug.contains("ForceOverwrite"));
    }

    #[test]
    fn partial_state_suggestion_debug() {
        let debug = format!("{:?}", PartialStateSuggestion::CleanAndRetry);
        assert!(debug.contains("CleanAndRetry"));
    }

    // ---- write_phase_lock overwrites existing lock ----

    #[test]
    fn write_phase_lock_overwrites_existing() {
        let dir = tempdir().unwrap();
        let phase1 = BootstrapPhase::TimeValidation;
        write_phase_lock(dir.path(), &phase1).unwrap();

        let phase2 = BootstrapPhase::KeyGeneration;
        write_phase_lock(dir.path(), &phase2).unwrap();

        let detected = detect_partial_state(dir.path()).unwrap();
        assert_eq!(detected, BootstrapPhase::KeyGeneration);
    }

    // ---- Display for Failed with empty reason ----

    #[test]
    fn display_failed_empty_reason() {
        let phase = BootstrapPhase::Failed {
            reason: String::new(),
            at_phase: "TimeValidation".into(),
        };
        let display = format!("{phase}");
        assert!(display.starts_with("Failed("));
    }

    // ---- Display for Completed contains fingerprint ----

    #[test]
    fn display_completed_shows_fingerprint() {
        let phase = BootstrapPhase::Completed {
            fingerprint: "SHA256:uniquevalue".into(),
            completed_at: Utc::now(),
        };
        let display = format!("{phase}");
        assert!(display.contains("SHA256:uniquevalue"));
    }
}
