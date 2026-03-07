//! Cross-module integration tests for `fcp-bootstrap`.
//!
//! Tests exercise real bootstrap pipelines spanning multiple modules
//! (recovery phrase → keypair → genesis, ceremony lifecycle, cold recovery,
//! phase state machine, workflow configuration) without mocks.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use fcp_bootstrap::genesis::{GENESIS_SCHEMA_VERSION, REQUIRED_ZONES};
use fcp_bootstrap::{
    // Workflow
    BootstrapConfig,
    // Error
    BootstrapError,
    BootstrapMode,
    // Phase
    BootstrapPhase,
    // Ceremony
    CeremonyCheckpoint,
    CeremonyId,
    CeremonyPhase,
    // Cold recovery
    ColdRecovery,
    ColdRecoveryError,
    ColdRecoveryWarning,
    // Hardware token
    DetectedToken,
    // Genesis
    GenesisState,
    GenesisValidationError,
    InitSuggestion,
    PartialStateSuggestion,
    ParticipantId,
    // Recovery
    RecoveryPhrase,
    RecoveryPhraseError,
    ThresholdCeremony,
    ThresholdConfig,
    // Time
    TimeValidation,
    TimeValidationResult,
    TokenDetector,
};
use fcp_crypto::{Ed25519Signature, Ed25519SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// ============================================================================
// 1. Recovery phrase → keypair → genesis pipeline
// ============================================================================

#[test]
fn recovery_phrase_to_genesis_pipeline() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let keypair = phrase.derive_owner_keypair();
    let vk = keypair.public();

    let genesis = GenesisState::create(&vk);
    genesis.validate().unwrap();

    assert_eq!(genesis.schema_version, GENESIS_SCHEMA_VERSION);
    assert_eq!(genesis.initial_zones.len(), REQUIRED_ZONES.len());
}

#[test]
fn recovery_phrase_deterministic_keypair() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let words = phrase.to_phrase();

    let kp1 = phrase.derive_owner_keypair();
    let restored = RecoveryPhrase::from_mnemonic(&words).unwrap();
    let kp2 = restored.derive_owner_keypair();

    assert_eq!(kp1.public().to_bytes(), kp2.public().to_bytes());
}

#[test]
fn recovery_phrase_deterministic_genesis_fingerprint() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let kp = phrase.derive_owner_keypair();

    let g1 = GenesisState::create_deterministic(&kp.public());
    let g2 = GenesisState::create_deterministic(&kp.public());

    assert_eq!(g1.fingerprint(), g2.fingerprint());
}

#[test]
fn genesis_fingerprint_differs_per_key() {
    let k1 = Ed25519SigningKey::generate();
    let k2 = Ed25519SigningKey::generate();

    let g1 = GenesisState::create_deterministic(&k1.verifying_key());
    let g2 = GenesisState::create_deterministic(&k2.verifying_key());

    assert_ne!(g1.fingerprint(), g2.fingerprint());
}

// ============================================================================
// 2. Genesis validation
// ============================================================================

#[test]
fn genesis_contains_all_required_zones() {
    let key = Ed25519SigningKey::generate();
    let genesis = GenesisState::create(&key.verifying_key());

    for zone in REQUIRED_ZONES {
        assert!(
            genesis.initial_zones.iter().any(|z| z.zone_id == *zone),
            "missing zone: {zone}"
        );
    }
}

#[test]
fn genesis_cbor_roundtrip() {
    let key = Ed25519SigningKey::generate();
    let genesis = GenesisState::create(&key.verifying_key());

    let cbor = genesis.to_cbor().unwrap();
    let restored = GenesisState::from_cbor(&cbor).unwrap();

    assert_eq!(genesis.schema_version, restored.schema_version);
    assert_eq!(genesis.owner_public_key, restored.owner_public_key);
    assert_eq!(genesis.initial_zones.len(), restored.initial_zones.len());
}

#[test]
fn genesis_owner_verifying_key_roundtrip() {
    let key = Ed25519SigningKey::generate();
    let vk = key.verifying_key();
    let genesis = GenesisState::create(&vk);

    let recovered = genesis.owner_verifying_key().unwrap();
    assert_eq!(vk.to_bytes(), recovered.to_bytes());
}

// ============================================================================
// 3. Cold recovery pipeline
// ============================================================================

#[test]
fn cold_recovery_from_phrase() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();

    assert!(!recovery.was_verified()); // no fingerprint provided
    assert!(!recovery.warnings.is_empty());
    assert!(
        recovery
            .warnings
            .contains(&ColdRecoveryWarning::FingerprintNotVerified)
    );

    recovery.genesis.validate().unwrap();
}

#[test]
fn cold_recovery_with_fingerprint_verification() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let kp = phrase.derive_owner_keypair();
    let genesis = GenesisState::create_deterministic(&kp.public());
    let fp = genesis.fingerprint();

    let recovery = ColdRecovery::from_phrase(&phrase, Some(&fp)).unwrap();
    assert!(recovery.was_verified());
    assert!(
        !recovery
            .warnings
            .contains(&ColdRecoveryWarning::FingerprintNotVerified)
    );
}

#[test]
fn cold_recovery_wrong_fingerprint_fails() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let err = ColdRecovery::from_phrase(&phrase, Some("wrong-fingerprint")).unwrap_err();
    assert!(matches!(err, ColdRecoveryError::FingerprintMismatch { .. }));
}

// ============================================================================
// 4. Recovery phrase validation
// ============================================================================

#[test]
fn recovery_phrase_invalid_mnemonic() {
    let err = RecoveryPhrase::from_mnemonic("not a valid mnemonic phrase").unwrap_err();
    assert!(matches!(err, RecoveryPhraseError::WrongWordCount(5)));
}

#[test]
fn recovery_phrase_words_roundtrip() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let words = phrase.words();
    assert_eq!(words.len(), 24);

    let restored = RecoveryPhrase::from_words(&words).unwrap();
    assert_eq!(phrase, restored);
}

#[test]
fn recovery_phrase_entropy_nonzero() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let entropy = phrase.entropy();
    assert!(!entropy.is_empty());
    assert!(entropy.iter().any(|b| *b != 0));
}

// ============================================================================
// 5. Ceremony lifecycle
// ============================================================================

#[test]
fn ceremony_creation_and_participant_join() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    assert!(!ceremony.phase.is_terminal());

    let p1 = ParticipantId {
        index: 1,
        name: "Alice".into(),
        public_key: [0x11; 32],
    };
    let p2 = ParticipantId {
        index: 2,
        name: "Bob".into(),
        public_key: [0x22; 32],
    };
    let p3 = ParticipantId {
        index: 3,
        name: "Carol".into(),
        public_key: [0x33; 32],
    };

    ceremony.add_participant(p1).unwrap();
    ceremony.add_participant(p2).unwrap();
    ceremony.add_participant(p3).unwrap();

    // Should transition to Round1Commitments after all participants join
    assert!(matches!(
        ceremony.phase,
        CeremonyPhase::Round1Commitments { .. }
    ));
}

#[test]
fn ceremony_abort_and_checkpoint() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    ceremony
        .add_participant(ParticipantId {
            index: 1,
            name: "Alice".into(),
            public_key: [0x11; 32],
        })
        .unwrap();

    let result = ceremony.abort("test abort");
    assert_eq!(result.ceremony_id, ceremony.ceremony_id);
}

#[test]
fn ceremony_checkpoint_and_resume() {
    let config = ThresholdConfig::new(2, 3).with_timeout(chrono::Duration::seconds(3600));
    let mut ceremony = ThresholdCeremony::with_config(config);

    let p1 = ParticipantId {
        index: 1,
        name: "Alice".into(),
        public_key: [0x11; 32],
    };
    ceremony.add_participant(p1).unwrap();

    let checkpoint = ceremony.create_checkpoint();
    let resumed = ThresholdCeremony::resume(checkpoint).unwrap();
    assert!(matches!(resumed.phase, CeremonyPhase::Gathering { .. }));
}

#[test]
fn ceremony_duplicate_participant_rejected() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    let p1 = ParticipantId {
        index: 1,
        name: "Alice".into(),
        public_key: [0x11; 32],
    };

    ceremony.add_participant(p1.clone()).unwrap();
    assert!(ceremony.add_participant(p1).is_err());
}

#[test]
fn ceremony_id_display_format() {
    let id = CeremonyId::generate(2, 3);
    let display = format!("{id}");
    assert!(!display.is_empty());
}

#[test]
fn ceremony_transcript_records_events() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    ceremony
        .add_participant(ParticipantId {
            index: 1,
            name: "Test".into(),
            public_key: [0xAA; 32],
        })
        .unwrap();

    assert!(!ceremony.transcript.joins.is_empty());
    assert!(!ceremony.transcript.phases.is_empty());
}

#[test]
fn ceremony_threshold_signature_supports_partial_availability() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    let mut split_rng = ChaCha20Rng::seed_from_u64(7331);
    for index in 1..=3 {
        ceremony
            .add_participant(ParticipantId {
                index,
                name: format!("device-{index}"),
                public_key: [u8::try_from(index).unwrap(); 32],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_commitment(fcp_bootstrap::FrostCommitment {
                participant_index: index,
                commitment: vec![u8::try_from(index).unwrap(); 32],
                proof: vec![0xAA; 64],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_shares_with_rng(
                index,
                vec![fcp_bootstrap::EncryptedShare {
                    from_index: index,
                    to_index: index,
                    ciphertext: vec![u8::try_from(index).unwrap(); 32],
                }],
                &mut split_rng,
            )
            .unwrap();
    }

    let mut rng = ChaCha20Rng::seed_from_u64(1337);
    let artifact = ceremony
        .sign_with_participants_and_rng(
            &[1, 2],
            b"FCP2-THRESHOLD-OWNER",
            b"integration-threshold-owner",
            &mut rng,
        )
        .unwrap();

    ceremony
        .verify_signature_artifact(
            &artifact,
            b"FCP2-THRESHOLD-OWNER",
            b"integration-threshold-owner",
        )
        .unwrap();
}

#[test]
fn ceremony_threshold_signature_rejects_tampered_participants() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    let mut split_rng = ChaCha20Rng::seed_from_u64(9001);
    for index in 1..=3 {
        ceremony
            .add_participant(ParticipantId {
                index,
                name: format!("device-{index}"),
                public_key: [u8::try_from(index).unwrap(); 32],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_commitment(fcp_bootstrap::FrostCommitment {
                participant_index: index,
                commitment: vec![u8::try_from(index).unwrap(); 32],
                proof: vec![0xAC; 64],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_shares_with_rng(
                index,
                vec![fcp_bootstrap::EncryptedShare {
                    from_index: index,
                    to_index: index,
                    ciphertext: vec![u8::try_from(index).unwrap(); 32],
                }],
                &mut split_rng,
            )
            .unwrap();
    }

    let mut signing_rng = ChaCha20Rng::seed_from_u64(9002);
    let mut artifact = ceremony
        .sign_with_participants_and_rng(
            &[1, 2],
            b"FCP2-THRESHOLD-OWNER",
            b"tampered-participants",
            &mut signing_rng,
        )
        .unwrap();
    artifact.participants = vec![1, 3];

    let error = ceremony
        .verify_signature_artifact(&artifact, b"FCP2-THRESHOLD-OWNER", b"tampered-participants")
        .unwrap_err();
    assert!(error.contains("signature transcript does not match"));
}

#[test]
fn ceremony_threshold_signature_rejects_replayed_context() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    let mut split_rng = ChaCha20Rng::seed_from_u64(9051);
    for index in 1..=3 {
        ceremony
            .add_participant(ParticipantId {
                index,
                name: format!("device-{index}"),
                public_key: [u8::try_from(index).unwrap(); 32],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_commitment(fcp_bootstrap::FrostCommitment {
                participant_index: index,
                commitment: vec![u8::try_from(index).unwrap(); 32],
                proof: vec![0xAE; 64],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_shares_with_rng(
                index,
                vec![fcp_bootstrap::EncryptedShare {
                    from_index: index,
                    to_index: index,
                    ciphertext: vec![u8::try_from(index).unwrap(); 32],
                }],
                &mut split_rng,
            )
            .unwrap();
    }

    let mut signing_rng = ChaCha20Rng::seed_from_u64(9052);
    let artifact = ceremony
        .sign_with_participants_and_rng(
            &[1, 3],
            b"FCP2-THRESHOLD-OWNER",
            b"original-context",
            &mut signing_rng,
        )
        .unwrap();

    let error = ceremony
        .verify_signature_artifact(&artifact, b"FCP2-THRESHOLD-OWNER", b"replayed-context")
        .unwrap_err();
    assert!(error.contains("signature transcript does not match"));
}

#[test]
fn ceremony_threshold_signature_rejects_tampered_signature() {
    let mut ceremony = ThresholdCeremony::new(2, 3);
    let mut split_rng = ChaCha20Rng::seed_from_u64(9101);
    for index in 1..=3 {
        ceremony
            .add_participant(ParticipantId {
                index,
                name: format!("device-{index}"),
                public_key: [u8::try_from(index).unwrap(); 32],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_commitment(fcp_bootstrap::FrostCommitment {
                participant_index: index,
                commitment: vec![u8::try_from(index).unwrap(); 32],
                proof: vec![0xAD; 64],
            })
            .unwrap();
    }
    for index in 1..=3 {
        ceremony
            .add_shares_with_rng(
                index,
                vec![fcp_bootstrap::EncryptedShare {
                    from_index: index,
                    to_index: index,
                    ciphertext: vec![u8::try_from(index).unwrap(); 32],
                }],
                &mut split_rng,
            )
            .unwrap();
    }

    let mut signing_rng = ChaCha20Rng::seed_from_u64(9102);
    let mut artifact = ceremony
        .sign_with_participants_and_rng(
            &[2, 3],
            b"FCP2-THRESHOLD-OWNER",
            b"tampered-signature",
            &mut signing_rng,
        )
        .unwrap();
    let mut signature_bytes = artifact.signature.to_bytes();
    signature_bytes[0] ^= 0x01;
    artifact.signature = Ed25519Signature::from_bytes(&signature_bytes);

    let error = ceremony
        .verify_signature_artifact(&artifact, b"FCP2-THRESHOLD-OWNER", b"tampered-signature")
        .unwrap_err();
    assert!(error.contains("Ed25519 verification failed"));
}

// ============================================================================
// 6. Phase state machine
// ============================================================================

#[test]
fn phase_terminal_states() {
    let completed = BootstrapPhase::Completed {
        fingerprint: "abc".into(),
        completed_at: Utc::now(),
    };
    assert!(completed.is_terminal());
    assert!(!completed.is_resumable());

    let failed = BootstrapPhase::Failed {
        reason: "test".into(),
        at_phase: "KeyGeneration".into(),
    };
    assert!(failed.is_terminal());
    assert!(!failed.is_resumable());
}

#[test]
fn phase_resumable_states() {
    let gathering = BootstrapPhase::CeremonySetup {
        participant_count: 1,
        threshold: 2,
    };
    assert!(gathering.is_resumable());
    assert!(!gathering.is_terminal());

    let round1 = BootstrapPhase::CeremonyRound1 {
        commitments_collected: 1,
        commitments_needed: 3,
    };
    assert!(round1.is_resumable());
}

#[test]
fn phase_descriptions_non_empty() {
    let phases = [
        BootstrapPhase::Uninitialized,
        BootstrapPhase::TimeValidation,
        BootstrapPhase::KeyGeneration,
        BootstrapPhase::GenesisCreate,
        BootstrapPhase::Enrollment,
    ];

    for phase in &phases {
        assert!(
            !phase.description().is_empty(),
            "{phase:?} has empty description"
        );
    }
}

#[test]
fn phase_display_format() {
    let phase = BootstrapPhase::Uninitialized;
    assert!(!format!("{phase}").is_empty());

    let s1 = InitSuggestion::UseExisting;
    assert!(!format!("{s1}").is_empty());

    let s2 = PartialStateSuggestion::Resume;
    assert!(!format!("{s2}").is_empty());
}

#[test]
fn phase_serde_roundtrip() {
    let phase = BootstrapPhase::CeremonyRound2 {
        shares_distributed: 2,
        shares_needed: 3,
    };
    let json = serde_json::to_string(&phase).unwrap();
    let restored: BootstrapPhase = serde_json::from_str(&json).unwrap();
    assert_eq!(phase, restored);
}

// ============================================================================
// 7. Phase lock file management
// ============================================================================

#[test]
fn phase_lock_write_and_detect() {
    let dir = tempfile::tempdir().unwrap();
    let phase = BootstrapPhase::KeyGeneration;

    fcp_bootstrap::phase::write_phase_lock(dir.path(), &phase).unwrap();
    let detected = fcp_bootstrap::phase::detect_partial_state(dir.path());
    assert!(detected.is_some());

    fcp_bootstrap::phase::remove_phase_lock(dir.path()).unwrap();
    let after_remove = fcp_bootstrap::phase::detect_partial_state(dir.path());
    assert!(after_remove.is_none());
}

// ============================================================================
// 8. Time validation
// ============================================================================

#[test]
fn time_validation_offline_should_proceed() {
    let tv = TimeValidation::offline();
    assert_eq!(tv.result, TimeValidationResult::CannotValidate);
    assert!(tv.result.should_proceed());
    assert!(!tv.result.is_error());
}

#[test]
fn time_validation_result_display() {
    let results = [
        TimeValidationResult::Valid,
        TimeValidationResult::CannotValidate,
        TimeValidationResult::DriftWarning {
            drift: Duration::from_secs(5),
        },
        TimeValidationResult::DriftError {
            drift: Duration::from_secs(60),
        },
    ];

    for r in &results {
        assert!(!format!("{r}").is_empty());
    }
}

#[test]
fn time_validation_error_blocks_proceed() {
    let err = TimeValidationResult::DriftError {
        drift: Duration::from_secs(60),
    };
    assert!(!err.should_proceed());
    assert!(err.is_error());
}

#[test]
fn time_validation_warning_allows_proceed() {
    let warn = TimeValidationResult::DriftWarning {
        drift: Duration::from_secs(3),
    };
    assert!(warn.should_proceed());
    assert!(!warn.is_error());
}

// ============================================================================
// 9. Hardware token detection
// ============================================================================

#[test]
fn token_detector_default_empty() {
    let detector = TokenDetector::default();
    let tokens = detector.detect_all();
    // May or may not find tokens depending on system — just verify no crash
    let _ = tokens;
}

#[test]
fn detected_token_mechanism_checks() {
    let token = DetectedToken {
        provider: PathBuf::from("/usr/lib/pkcs11.so"),
        slot: 0,
        label: "Test Token".into(),
        manufacturer: "TestCorp".into(),
        serial: "12345".into(),
        mechanisms: vec!["CKM_EDDSA".into(), "CKM_EC_EDWARDS_KEY_PAIR_GEN".into()],
    };

    assert!(token.supports_ed25519());
    assert!(!token.supports_x25519());
    assert!(!format!("{token}").is_empty());
}

#[test]
fn detected_token_serde_roundtrip() {
    let token = DetectedToken {
        provider: PathBuf::from("/test"),
        slot: 1,
        label: "Token".into(),
        manufacturer: "Mfg".into(),
        serial: "SN001".into(),
        mechanisms: vec!["CKM_EDDSA".into()],
    };

    let json = serde_json::to_string(&token).unwrap();
    let restored: DetectedToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

// ============================================================================
// 10. Workflow configuration
// ============================================================================

#[test]
fn bootstrap_config_builder() {
    let config = BootstrapConfig::builder()
        .data_dir("/tmp/fcp-test-bootstrap")
        .mode(BootstrapMode::SingleDevice)
        .skip_time_validation(true)
        .force_overwrite(false)
        .build()
        .unwrap();

    assert_eq!(config.data_dir, PathBuf::from("/tmp/fcp-test-bootstrap"));
    assert!(config.skip_time_validation);
    assert!(!config.force_overwrite);
}

#[test]
fn bootstrap_mode_display() {
    let modes = [
        BootstrapMode::SingleDevice,
        BootstrapMode::MultiDevice {
            device_count: 3,
            threshold: 2,
        },
    ];

    for mode in &modes {
        assert!(!format!("{mode}").is_empty());
    }
}

// ============================================================================
// 11. Error types
// ============================================================================

#[test]
fn bootstrap_error_display_variants() {
    let errors: Vec<BootstrapError> = vec![
        BootstrapError::TimeSkew {
            drift: Duration::from_secs(10),
            suggestion: "synchronize clock",
        },
        BootstrapError::AlreadyExists {
            fingerprint: "abc123".into(),
        },
        BootstrapError::PartialState {
            phase: "KeyGeneration".into(),
        },
        BootstrapError::InvalidRecoveryPhrase("bad words".into()),
        BootstrapError::NoHardwareTokens,
        BootstrapError::Crypto("test crypto error".into()),
    ];

    for err in &errors {
        assert!(!format!("{err}").is_empty());
    }
}

#[test]
fn genesis_validation_error_display() {
    let errors = [
        GenesisValidationError::InvalidOwnerKey,
        GenesisValidationError::MissingRequiredZone("z:owner".into()),
        GenesisValidationError::InvalidZoneId("bad".into()),
        GenesisValidationError::FutureTimestamp,
        GenesisValidationError::UnsupportedSchemaVersion(99),
    ];

    for err in &errors {
        assert!(!format!("{err}").is_empty());
    }
}

#[test]
fn cold_recovery_warning_display() {
    let warnings = [
        ColdRecoveryWarning::NoAuditHistory,
        ColdRecoveryWarning::RevocationStateUnknown,
        ColdRecoveryWarning::SingleNodeStart,
        ColdRecoveryWarning::DataLoss,
        ColdRecoveryWarning::FingerprintNotVerified,
    ];

    for w in &warnings {
        assert!(!format!("{w}").is_empty());
    }
}

// ============================================================================
// 12. Cross-module: ceremony → checkpoint serde
// ============================================================================

#[test]
fn ceremony_checkpoint_json_roundtrip() {
    let checkpoint = CeremonyCheckpoint {
        ceremony_id: CeremonyId::generate(2, 3),
        participants: vec![],
        phase: CeremonyPhase::Gathering {
            joined: vec![],
            target: 3,
        },
        commitments: HashMap::new(),
        shares: HashMap::new(),
        checkpoint_at: Utc::now(),
        phase_deadline: Utc::now() + chrono::Duration::hours(1),
    };

    let json = serde_json::to_string(&checkpoint).unwrap();
    let restored: CeremonyCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.ceremony_id, checkpoint.ceremony_id);
}

// ============================================================================
// 13. Cross-module: full single-device bootstrap
// ============================================================================

#[test]
fn single_device_bootstrap_workflow() {
    let dir = tempfile::tempdir().unwrap();

    let config = BootstrapConfig::builder()
        .data_dir(dir.path())
        .mode(BootstrapMode::SingleDevice)
        .skip_time_validation(true)
        .build()
        .unwrap();

    let workflow = fcp_bootstrap::BootstrapWorkflow::new(config).unwrap();
    let genesis = workflow.run().unwrap();

    genesis.validate().unwrap();
    assert_eq!(genesis.schema_version, GENESIS_SCHEMA_VERSION);
    assert!(!genesis.fingerprint().is_empty());
}

// ============================================================================
// 14. Cross-module: recovery phrase → cold recovery → genesis validation
// ============================================================================

#[test]
fn full_cold_recovery_pipeline() {
    // Original bootstrap
    let phrase = RecoveryPhrase::generate().unwrap();
    let kp = phrase.derive_owner_keypair();
    let original_genesis = GenesisState::create_deterministic(&kp.public());
    let fingerprint = original_genesis.fingerprint();

    // Disaster recovery with the same phrase
    let recovery = ColdRecovery::from_phrase(&phrase, Some(&fingerprint)).unwrap();

    assert!(recovery.was_verified());
    recovery.genesis.validate().unwrap();
    assert_eq!(recovery.fingerprint(), fingerprint);

    // Owner key matches
    let recovered_vk = recovery.genesis.owner_verifying_key().unwrap();
    assert_eq!(recovered_vk.to_bytes(), kp.public().to_bytes());
}

// ============================================================================
// 15. Threshold config validation
// ============================================================================

#[test]
fn threshold_config_valid() {
    let config = ThresholdConfig::new(2, 3);
    assert_eq!(config.threshold, 2);
    assert_eq!(config.total, 3);
}

#[test]
#[should_panic(expected = "threshold must not exceed total")]
fn threshold_config_threshold_exceeds_total() {
    let _ = ThresholdConfig::new(5, 3);
}

#[test]
#[should_panic(expected = "threshold must be at least 1")]
fn threshold_config_zero_threshold() {
    let _ = ThresholdConfig::new(0, 3);
}

// ============================================================================
// 16. Ceremony phase terminal checks
// ============================================================================

#[test]
fn ceremony_phase_terminal_and_nonterminal() {
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
        CeremonyPhase::Complete {
            group_public_key: [0; 32],
        }
        .is_terminal()
    );

    assert!(
        CeremonyPhase::Failed {
            reason: "err".into(),
            at_phase: "round1".into(),
        }
        .is_terminal()
    );
}

// ============================================================================
// 17. Participant ID display
// ============================================================================

#[test]
fn participant_id_display_and_serde() {
    let p = ParticipantId {
        index: 1,
        name: "Alice".into(),
        public_key: [0xAA; 32],
    };

    assert!(!format!("{p}").is_empty());

    let json = serde_json::to_string(&p).unwrap();
    let restored: ParticipantId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// ============================================================================
// 18. OwnerKeypair security properties
// ============================================================================

#[test]
fn owner_keypair_sign_verify() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let kp = phrase.derive_owner_keypair();
    let vk = kp.public();

    let sig = kp.sign(b"test message");
    vk.verify(b"test message", &sig).unwrap();
}

#[test]
fn owner_keypair_debug_redacted() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let kp = phrase.derive_owner_keypair();
    let debug = format!("{kp:?}");
    // Should not contain raw key bytes
    assert!(!debug.contains("0x"));
}

#[test]
fn recovery_phrase_debug_redacted() {
    let phrase = RecoveryPhrase::generate().unwrap();
    let debug = format!("{phrase:?}");
    // Should not leak the actual mnemonic words
    let words = phrase.words();
    for word in &words {
        assert!(!debug.contains(word), "Debug output leaked word: {word}");
    }
}
