//! Bootstrap workflow orchestration.
//!
//! This module provides the main workflow for bootstrapping an FCP2 mesh,
//! coordinating all the phases from time validation through genesis creation.

use crate::ceremony::{ThresholdCeremony, ThresholdConfig};
use crate::error::{BootstrapError, BootstrapResult};
use crate::genesis::GenesisState;
use crate::hardware_token::{DetectedToken, TokenDetector};
use crate::phase::{BootstrapPhase, detect_partial_state, remove_phase_lock, write_phase_lock};
use crate::recovery_phrase::RecoveryPhrase;
use crate::time_validation::{TimeValidation, TimeValidationResult};

use std::path::{Path, PathBuf};

/// Mode of bootstrap operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapMode {
    /// Single device bootstrap (no threshold signing).
    SingleDevice,

    /// Multi-device bootstrap with threshold signing.
    MultiDevice {
        /// Number of devices.
        device_count: u32,
        /// Threshold required for signing.
        threshold: u32,
    },

    /// Use a hardware token for key storage.
    HardwareToken {
        /// The detected token to use.
        token: DetectedToken,
    },

    /// Import from an existing recovery phrase.
    Import {
        /// The recovery phrase to import.
        phrase: RecoveryPhrase,
    },
}

impl std::fmt::Display for BootstrapMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingleDevice => write!(f, "Single Device"),
            Self::MultiDevice {
                device_count,
                threshold,
            } => {
                write!(f, "Multi-Device ({threshold}/{device_count})")
            }
            Self::HardwareToken { token } => write!(f, "Hardware Token ({token})"),
            Self::Import { .. } => write!(f, "Import from Recovery Phrase"),
        }
    }
}

/// Configuration for the bootstrap workflow.
#[derive(Debug)]
pub struct BootstrapConfig {
    /// Directory for FCP data storage.
    pub data_dir: PathBuf,

    /// Bootstrap mode.
    pub mode: BootstrapMode,

    /// Skip time validation (not recommended).
    pub skip_time_validation: bool,

    /// Allow proceeding with time drift warning.
    pub allow_time_drift_warning: bool,

    /// Force overwrite existing genesis (dangerous).
    pub force_overwrite: bool,
}

impl BootstrapConfig {
    /// Create a new configuration builder.
    #[must_use]
    pub fn builder() -> BootstrapConfigBuilder {
        BootstrapConfigBuilder::default()
    }
}

/// Builder for `BootstrapConfig`.
#[derive(Debug, Default)]
pub struct BootstrapConfigBuilder {
    data_dir: Option<PathBuf>,
    mode: Option<BootstrapMode>,
    skip_time_validation: bool,
    allow_time_drift_warning: bool,
    force_overwrite: bool,
}

impl BootstrapConfigBuilder {
    /// Set the data directory.
    #[must_use]
    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    /// Set the bootstrap mode.
    #[must_use]
    pub fn mode(mut self, mode: BootstrapMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Skip time validation.
    #[must_use]
    pub const fn skip_time_validation(mut self, skip: bool) -> Self {
        self.skip_time_validation = skip;
        self
    }

    /// Allow proceeding with time drift warning.
    #[must_use]
    pub const fn allow_time_drift_warning(mut self, allow: bool) -> Self {
        self.allow_time_drift_warning = allow;
        self
    }

    /// Force overwrite existing genesis.
    #[must_use]
    pub const fn force_overwrite(mut self, force: bool) -> Self {
        self.force_overwrite = force;
        self
    }

    /// Build the configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if required fields are missing.
    pub fn build(self) -> BootstrapResult<BootstrapConfig> {
        let data_dir = self
            .data_dir
            .ok_or_else(|| BootstrapError::Config("data_dir is required".to_string()))?;

        let mode = self
            .mode
            .ok_or_else(|| BootstrapError::Config("mode is required".to_string()))?;

        Ok(BootstrapConfig {
            data_dir,
            mode,
            skip_time_validation: self.skip_time_validation,
            allow_time_drift_warning: self.allow_time_drift_warning,
            force_overwrite: self.force_overwrite,
        })
    }
}

/// The main bootstrap workflow.
pub struct BootstrapWorkflow {
    config: BootstrapConfig,
    phase: BootstrapPhase,
    time_validation: Option<TimeValidation>,
    ceremony: Option<ThresholdCeremony>,
}

impl BootstrapWorkflow {
    /// Create a new bootstrap workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization state is invalid or filesystem setup fails.
    pub fn new(config: BootstrapConfig) -> BootstrapResult<Self> {
        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)?;

        // Check for existing genesis or partial state
        let init_result = check_initialization_state(&config.data_dir, config.force_overwrite)?;

        match init_result {
            InitCheckResult::Fresh => {
                // Can proceed with fresh bootstrap
                Ok(Self {
                    config,
                    phase: BootstrapPhase::Uninitialized,
                    time_validation: None,
                    ceremony: None,
                })
            }
            InitCheckResult::AlreadyExists { fingerprint } => {
                Err(BootstrapError::AlreadyExists { fingerprint })
            }
            InitCheckResult::PartialState { phase } => Err(BootstrapError::PartialState {
                phase: format!("{phase}"),
            }),
        }
    }

    /// Run the bootstrap workflow to completion.
    ///
    /// # Errors
    ///
    /// Returns an error if any bootstrap phase fails.
    pub fn run(mut self) -> BootstrapResult<GenesisState> {
        // Phase 1: Time validation
        if !self.config.skip_time_validation {
            self.run_time_validation()?;
        }

        // Phase 2: Key generation based on mode
        // Clone mode to avoid borrow conflicts
        let mode = self.config.mode.clone();
        let genesis = match mode {
            BootstrapMode::SingleDevice => self.run_single_device_bootstrap()?,
            BootstrapMode::MultiDevice {
                device_count,
                threshold,
            } => self.run_multi_device_bootstrap(threshold, device_count)?,
            BootstrapMode::HardwareToken { token } => self.run_hardware_token_bootstrap(&token)?,
            BootstrapMode::Import { phrase } => self.run_import_bootstrap(&phrase)?,
        };

        // Validate genesis
        genesis
            .validate()
            .map_err(|e| BootstrapError::Internal(e.to_string()))?;

        // Clean up phase lock
        remove_phase_lock(&self.config.data_dir)?;

        // Update phase to completed
        self.phase = BootstrapPhase::Completed {
            fingerprint: genesis.fingerprint(),
            completed_at: chrono::Utc::now(),
        };

        // Save genesis to disk
        self.save_genesis(&genesis)?;

        tracing::info!(
            fingerprint = genesis.fingerprint(),
            "Bootstrap completed successfully"
        );

        Ok(genesis)
    }

    /// Run time validation phase.
    fn run_time_validation(&mut self) -> BootstrapResult<()> {
        self.phase = BootstrapPhase::TimeValidation;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        tracing::info!("Validating system time...");

        let validation = TimeValidation::check();
        tracing::info!(result = %validation.result, "Time validation complete");

        match &validation.result {
            TimeValidationResult::DriftError { drift } => {
                return Err(BootstrapError::TimeSkew {
                    drift: *drift,
                    suggestion: "Synchronize system clock before bootstrap",
                });
            }
            TimeValidationResult::DriftWarning { drift } => {
                if !self.config.allow_time_drift_warning {
                    tracing::warn!(
                        drift_secs = drift.as_secs(),
                        "Clock drift detected. Use --allow-drift to proceed."
                    );
                    return Err(BootstrapError::TimeSkew {
                        drift: *drift,
                        suggestion: "Use --allow-drift or synchronize system clock",
                    });
                }
                tracing::warn!(
                    drift_secs = drift.as_secs(),
                    "Clock drift detected, proceeding anyway"
                );
            }
            TimeValidationResult::CannotValidate => {
                tracing::warn!("Could not validate time (no network). Proceeding anyway.");
            }
            TimeValidationResult::Valid => {
                tracing::info!("System time validated");
            }
        }

        self.time_validation = Some(validation);
        Ok(())
    }

    /// Run single-device bootstrap (generate new key locally).
    fn run_single_device_bootstrap(&mut self) -> BootstrapResult<GenesisState> {
        self.phase = BootstrapPhase::KeyGeneration;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        tracing::info!("Generating owner key...");

        // Generate recovery phrase
        let phrase =
            RecoveryPhrase::generate().map_err(|e| BootstrapError::Crypto(e.to_string()))?;

        // Display recovery phrase (in real implementation, this would be a secure display)
        tracing::info!("Recovery phrase generated. Store it securely!");
        // phrase.words() would be displayed to user

        // Derive keypair and create genesis
        let keypair = phrase.derive_owner_keypair();
        let genesis = GenesisState::create(&keypair.public());

        // Save recovery phrase (encrypted with device key in real implementation)
        Self::save_recovery_phrase(&phrase);

        self.phase = BootstrapPhase::GenesisCreate;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        Ok(genesis)
    }

    /// Run multi-device bootstrap with threshold ceremony.
    fn run_multi_device_bootstrap(
        &mut self,
        threshold: u32,
        total: u32,
    ) -> BootstrapResult<GenesisState> {
        self.phase = BootstrapPhase::CeremonySetup {
            participant_count: total,
            threshold,
        };
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        tracing::info!(threshold, total, "Starting threshold key ceremony");

        // Initialize ceremony
        let config = ThresholdConfig::new(threshold, total);
        let ceremony = ThresholdCeremony::with_config(config);
        self.ceremony = Some(ceremony);

        // In a real implementation, this would coordinate with other devices
        // For now, we return an error indicating this is not yet implemented
        Err(BootstrapError::Ceremony(
            "Multi-device ceremony not yet fully implemented".to_string(),
        ))
    }

    /// Run hardware token bootstrap.
    fn run_hardware_token_bootstrap(
        &mut self,
        token: &DetectedToken,
    ) -> BootstrapResult<GenesisState> {
        self.phase = BootstrapPhase::KeyGeneration;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        tracing::info!(?token, "Using hardware token for key generation");

        // In a real implementation, this would:
        // 1. Connect to the token
        // 2. Generate keypair on token
        // 3. Get public key
        // 4. Create genesis

        Err(BootstrapError::HardwareToken(
            "Hardware token support not yet fully implemented".to_string(),
        ))
    }

    /// Run import bootstrap from existing recovery phrase.
    fn run_import_bootstrap(&mut self, phrase: &RecoveryPhrase) -> BootstrapResult<GenesisState> {
        self.phase = BootstrapPhase::KeyGeneration;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        tracing::info!("Importing from recovery phrase...");

        // Derive keypair from phrase
        let keypair = phrase.derive_owner_keypair();

        // Create deterministic genesis (so fingerprint matches)
        let genesis = GenesisState::create_deterministic(&keypair.public());

        // Save the recovery phrase
        Self::save_recovery_phrase(phrase);

        self.phase = BootstrapPhase::GenesisCreate;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        Ok(genesis)
    }

    /// Save the genesis state to disk.
    fn save_genesis(&self, genesis: &GenesisState) -> BootstrapResult<()> {
        let genesis_path = self.config.data_dir.join("genesis.cbor");
        let cbor = genesis.to_cbor()?;
        std::fs::write(genesis_path, cbor)?;
        Ok(())
    }

    /// Save the recovery phrase (in a real implementation, this would be encrypted).
    fn save_recovery_phrase(_phrase: &RecoveryPhrase) {
        // In a real implementation, we would:
        // 1. Encrypt the phrase with a device-specific key
        // 2. Store it in a secure location
        // 3. Optionally split it with Shamir's secret sharing

        // For now, we just log that we would save it
        tracing::debug!("Recovery phrase would be saved (encrypted) to secure storage");
    }

    /// Get the current phase.
    #[must_use]
    pub const fn phase(&self) -> &BootstrapPhase {
        &self.phase
    }
}

/// Result of checking initialization state.
enum InitCheckResult {
    /// Fresh initialization can proceed.
    Fresh,

    /// Genesis already exists.
    AlreadyExists { fingerprint: String },

    /// Partial state from crashed init.
    PartialState { phase: BootstrapPhase },
}

/// Check the current initialization state.
fn check_initialization_state(
    data_dir: &Path,
    force_overwrite: bool,
) -> BootstrapResult<InitCheckResult> {
    // Check for existing genesis
    let genesis_path = data_dir.join("genesis.cbor");
    if genesis_path.exists() {
        if force_overwrite {
            tracing::warn!("Force overwrite enabled, removing existing genesis");
            std::fs::remove_file(&genesis_path)?;
        } else {
            // Load existing genesis to get fingerprint
            let cbor = std::fs::read(&genesis_path)?;
            let genesis = GenesisState::from_cbor(&cbor)?;
            return Ok(InitCheckResult::AlreadyExists {
                fingerprint: genesis.fingerprint(),
            });
        }
    }

    // Check for partial state
    if let Some(phase) = detect_partial_state(data_dir) {
        return Ok(InitCheckResult::PartialState { phase });
    }

    Ok(InitCheckResult::Fresh)
}

/// Detect available hardware tokens.
#[must_use]
pub fn detect_hardware_tokens() -> Vec<DetectedToken> {
    let detector = TokenDetector::new();
    detector.detect_fcp_compatible()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_builder() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();

        assert_eq!(config.data_dir, dir.path());
        assert!(matches!(config.mode, BootstrapMode::SingleDevice));
    }

    #[test]
    fn test_config_builder_missing_data_dir() {
        let result = BootstrapConfig::builder()
            .mode(BootstrapMode::SingleDevice)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_workflow_creation() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();

        let workflow = BootstrapWorkflow::new(config).unwrap();
        assert!(matches!(workflow.phase(), BootstrapPhase::Uninitialized));
    }

    #[test]
    fn test_workflow_detects_existing_genesis() {
        let dir = tempdir().unwrap();

        // Create a genesis first
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        std::fs::write(dir.path().join("genesis.cbor"), cbor).unwrap();

        // Try to create workflow
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();

        let result = BootstrapWorkflow::new(config);
        assert!(matches!(result, Err(BootstrapError::AlreadyExists { .. })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_single_device_bootstrap() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .skip_time_validation(true)
            .build()
            .unwrap();

        let workflow = BootstrapWorkflow::new(config).unwrap();
        let genesis = workflow.run().unwrap();

        assert!(genesis.validate().is_ok());
        assert!(dir.path().join("genesis.cbor").exists());
    }

    // ---- BootstrapMode Display ----

    #[test]
    fn test_mode_display_single_device() {
        assert_eq!(BootstrapMode::SingleDevice.to_string(), "Single Device");
    }

    #[test]
    fn test_mode_display_multi_device() {
        let mode = BootstrapMode::MultiDevice {
            device_count: 5,
            threshold: 3,
        };
        assert_eq!(mode.to_string(), "Multi-Device (3/5)");
    }

    #[test]
    fn test_mode_display_import() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let mode = BootstrapMode::Import { phrase };
        assert_eq!(mode.to_string(), "Import from Recovery Phrase");
    }

    // ---- Config builder edge cases ----

    #[test]
    fn test_config_builder_missing_mode() {
        let dir = tempdir().unwrap();
        let result = BootstrapConfig::builder().data_dir(dir.path()).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_builder_all_flags() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .skip_time_validation(true)
            .allow_time_drift_warning(true)
            .force_overwrite(true)
            .build()
            .unwrap();

        assert!(config.skip_time_validation);
        assert!(config.allow_time_drift_warning);
        assert!(config.force_overwrite);
    }

    #[test]
    fn test_config_builder_defaults() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();

        assert!(!config.skip_time_validation);
        assert!(!config.allow_time_drift_warning);
        assert!(!config.force_overwrite);
    }

    // ---- Multi-device not yet implemented ----

    #[test]
    fn test_multi_device_not_implemented() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::MultiDevice {
                device_count: 3,
                threshold: 2,
            })
            .skip_time_validation(true)
            .build()
            .unwrap();

        let workflow = BootstrapWorkflow::new(config).unwrap();
        let result = workflow.run();
        assert!(matches!(result, Err(BootstrapError::Ceremony(_))));
    }

    // ---- Import mode bootstrap ----

    #[test]
    fn test_import_mode_bootstrap() {
        let dir = tempdir().unwrap();
        let phrase = RecoveryPhrase::generate().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::Import { phrase })
            .skip_time_validation(true)
            .build()
            .unwrap();

        let workflow = BootstrapWorkflow::new(config).unwrap();
        let genesis = workflow.run().unwrap();
        assert!(genesis.validate().is_ok());
        assert!(dir.path().join("genesis.cbor").exists());
    }

    // ---- Force overwrite existing genesis ----

    #[test]
    fn test_force_overwrite() {
        let dir = tempdir().unwrap();

        // Create an initial genesis
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        std::fs::write(dir.path().join("genesis.cbor"), cbor).unwrap();

        // Force overwrite should succeed
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .skip_time_validation(true)
            .force_overwrite(true)
            .build()
            .unwrap();

        let workflow = BootstrapWorkflow::new(config).unwrap();
        let genesis = workflow.run().unwrap();
        assert!(genesis.validate().is_ok());
    }

    // ---- Partial state detection ----

    #[test]
    fn test_workflow_detects_partial_state() {
        let dir = tempdir().unwrap();

        // Create a lock file to simulate partial state
        let phase = BootstrapPhase::KeyGeneration;
        crate::phase::write_phase_lock(dir.path(), &phase).unwrap();

        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();

        let result = BootstrapWorkflow::new(config);
        assert!(matches!(result, Err(BootstrapError::PartialState { .. })));
    }

    // ---- BootstrapMode eq ----

    #[test]
    fn test_mode_eq() {
        assert_eq!(BootstrapMode::SingleDevice, BootstrapMode::SingleDevice);
        assert_ne!(
            BootstrapMode::SingleDevice,
            BootstrapMode::MultiDevice {
                device_count: 3,
                threshold: 2,
            }
        );
    }

    // ---- detect_hardware_tokens ----

    #[test]
    fn test_detect_hardware_tokens_does_not_panic() {
        // Just verify it doesn't crash — no real tokens expected in CI
        let tokens = detect_hardware_tokens();
        // tokens will be empty in CI environment
        let _ = tokens;
    }
}
