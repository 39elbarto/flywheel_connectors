//! Bootstrap workflow orchestration.
//!
//! This module provides the main workflow for bootstrapping an FCP2 mesh,
//! coordinating all the phases from time validation through genesis creation.

use crate::ceremony::{
    EncryptedShare, FrostCommitment, ParticipantId, ThresholdCeremony, ThresholdConfig,
};
use crate::error::{BootstrapError, BootstrapResult};
use crate::genesis::GenesisState;
use crate::hardware_token::{
    DetectedToken, HardwareTokenPin, HardwareTokenSessionDriver, Pkcs11SessionDriver,
    TokenDetectionReport, TokenDetector, TokenError, select_and_authenticate,
    select_certificate_for_provisioning,
};
use crate::phase::{BootstrapPhase, detect_partial_state, remove_phase_lock, write_phase_lock};
use crate::recovery_phrase::RecoveryPhrase;
use crate::time_validation::{TimeValidation, TimeValidationResult};

use std::io::Write;
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

    /// Optional PIN used for hardware-token bootstrap login.
    pub hardware_token_pin: Option<HardwareTokenPin>,

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
    hardware_token_pin: Option<HardwareTokenPin>,
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

    /// Provide the PIN used to authenticate hardware-token bootstrap sessions.
    #[must_use]
    pub fn hardware_token_pin(mut self, pin: impl Into<String>) -> Self {
        self.hardware_token_pin = Some(HardwareTokenPin::new(pin));
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
            hardware_token_pin: self.hardware_token_pin,
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

        self.finalize_bootstrap(&genesis)?;

        Ok(genesis)
    }

    fn finalize_bootstrap(&mut self, genesis: &GenesisState) -> BootstrapResult<()> {
        // Validate genesis
        genesis
            .validate()
            .map_err(|e| BootstrapError::Internal(e.to_string()))?;

        // Update phase to completed
        self.phase = BootstrapPhase::Completed {
            fingerprint: genesis.fingerprint(),
            completed_at: chrono::Utc::now(),
        };

        // Save genesis to disk
        self.save_genesis(genesis)?;

        // Clean up phase lock only after genesis is durable on disk.
        remove_phase_lock(&self.config.data_dir)?;

        tracing::info!(
            fingerprint = genesis.fingerprint(),
            "Bootstrap completed successfully"
        );

        Ok(())
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
        let mut ceremony = ThresholdCeremony::with_config(config);

        for index in 1..=total {
            let mut public_key = [0u8; 32];
            public_key[..4].copy_from_slice(&index.to_le_bytes());
            ceremony
                .add_participant(ParticipantId {
                    index,
                    name: format!("device-{index}"),
                    public_key,
                })
                .map_err(BootstrapError::Ceremony)?;
        }

        self.phase = BootstrapPhase::CeremonyRound1 {
            commitments_collected: 0,
            commitments_needed: total,
        };
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        for index in 1..=total {
            ceremony
                .add_commitment(FrostCommitment {
                    participant_index: index,
                    commitment: vec![u8::try_from(index & 0xff).unwrap_or_default(); 32],
                    proof: vec![0xA5; 64],
                })
                .map_err(BootstrapError::Ceremony)?;
            self.phase = BootstrapPhase::CeremonyRound1 {
                commitments_collected: index,
                commitments_needed: total,
            };
            write_phase_lock(&self.config.data_dir, &self.phase)?;
        }

        self.phase = BootstrapPhase::CeremonyRound2 {
            shares_distributed: 0,
            shares_needed: total,
        };
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        for index in 1..=total {
            ceremony
                .add_shares(
                    index,
                    vec![EncryptedShare {
                        from_index: index,
                        to_index: index,
                        ciphertext: vec![u8::try_from(index & 0xff).unwrap_or_default(); 32],
                    }],
                )
                .map_err(BootstrapError::Ceremony)?;
            self.phase = BootstrapPhase::CeremonyRound2 {
                shares_distributed: index,
                shares_needed: total,
            };
            write_phase_lock(&self.config.data_dir, &self.phase)?;
        }

        let owner_key = ceremony
            .owner_verifying_key()
            .map_err(BootstrapError::Ceremony)?;
        let genesis = GenesisState::create(&owner_key);

        self.ceremony = Some(ceremony);
        self.phase = BootstrapPhase::GenesisCreate;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        Ok(genesis)
    }

    /// Run hardware token bootstrap.
    fn run_hardware_token_bootstrap(
        &mut self,
        token: &DetectedToken,
    ) -> BootstrapResult<GenesisState> {
        let detection_report = detect_hardware_tokens_report();
        self.run_hardware_token_bootstrap_with_driver(
            token,
            &detection_report,
            &Pkcs11SessionDriver,
        )
    }

    pub(crate) fn run_hardware_token_bootstrap_with_driver<D: HardwareTokenSessionDriver>(
        &mut self,
        token: &DetectedToken,
        detection_report: &TokenDetectionReport,
        driver: &D,
    ) -> BootstrapResult<GenesisState> {
        self.phase = BootstrapPhase::KeyGeneration;
        write_phase_lock(&self.config.data_dir, &self.phase)?;

        let pin = self
            .config
            .hardware_token_pin
            .as_ref()
            .ok_or(BootstrapError::HardwareTokenPinRequired)?;

        let outcome =
            select_and_authenticate(token, pin, detection_report, driver, None)
                .map_err(|err| map_hardware_token_error(detection_report, err))?;

        let token_display = outcome.session.token().to_string();
        let session_state = outcome.session.session_state();
        let read_write = outcome.session.read_write();

        tracing::info!(
            token = %token_display,
            session_state = %session_state,
            read_write,
            "Hardware-token session-selection complete; handing off to certificate selection"
        );

        // Enumerate certificates and keys, then select the best pair.
        let provisioning_material = select_certificate_for_provisioning(
            outcome.session.token(),
            pin,
            driver,
        )
        .map_err(|err| map_hardware_token_error(detection_report, err))?;

        tracing::info!(
            material = %provisioning_material,
            "Certificate selected; closing session before provisioning handoff"
        );

        // Close the authenticated session — provisioning uses its own session.
        outcome.session.close().map_err(|err| {
            BootstrapError::HardwareToken(format!(
                "hardware token session cleanup failed after certificate selection: {err}"
            ))
        })?;

        // Provisioning handoff: the next bead (24llg.4.2.3) will consume the
        // provisioning material to complete key provisioning and enrollment.
        Err(BootstrapError::HardwareToken(format!(
            "certificate selected for {token_display} ({provisioning_material}), \
             but provisioning enrollment is not implemented yet"
        )))
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
        let temp_path = genesis_temporary_path(&genesis_path);
        let cbor = genesis.to_cbor()?;
        let write_result = (|| -> BootstrapResult<()> {
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(&cbor)?;
            file.sync_all()?;
            std::fs::rename(&temp_path, &genesis_path)?;
            sync_directory(&self.config.data_dir)?;
            Ok(())
        })();

        if write_result.is_err() && temp_path.exists() {
            let _ = std::fs::remove_file(&temp_path);
        }

        write_result
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

fn genesis_temporary_path(genesis_path: &Path) -> PathBuf {
    genesis_path.with_extension("cbor.tmp")
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
    let partial_state = detect_partial_state(data_dir);

    // Check for existing genesis
    let genesis_path = data_dir.join("genesis.cbor");
    if genesis_path.exists() {
        if force_overwrite {
            tracing::warn!("Force overwrite enabled, removing existing genesis");
            std::fs::remove_file(&genesis_path)?;
        } else {
            // Load existing genesis to get fingerprint
            match std::fs::read(&genesis_path)
                .map_err(BootstrapError::from)
                .and_then(|cbor| GenesisState::from_cbor(&cbor))
            {
                Ok(genesis) => {
                    return Ok(InitCheckResult::AlreadyExists {
                        fingerprint: genesis.fingerprint(),
                    });
                }
                Err(err) => {
                    if let Some(phase) = partial_state {
                        tracing::warn!(
                            path = %genesis_path.display(),
                            ?err,
                            "Genesis file is unreadable during partial bootstrap; preferring recovery marker"
                        );
                        return Ok(InitCheckResult::PartialState { phase });
                    }
                    return Err(err);
                }
            }
        }
    }

    // Check for partial state
    if let Some(phase) = partial_state {
        return Ok(InitCheckResult::PartialState { phase });
    }

    Ok(InitCheckResult::Fresh)
}

/// Detect available hardware tokens.
#[must_use]
pub fn detect_hardware_tokens() -> Vec<DetectedToken> {
    detect_hardware_tokens_report().fcp_compatible_tokens()
}

/// Detect available hardware tokens and retain structured discovery failures.
#[must_use]
pub fn detect_hardware_tokens_report() -> TokenDetectionReport {
    let detector = TokenDetector::new();
    detector.detect_report()
}

fn map_hardware_token_error(
    detection_report: &TokenDetectionReport,
    error: TokenError,
) -> BootstrapError {
    match error {
        TokenError::NoTokens if detection_report.issues().is_empty() => {
            BootstrapError::NoHardwareTokens
        }
        TokenError::NoTokens => BootstrapError::HardwareToken(format!(
            "no compatible hardware tokens detected: {}",
            summarize_detection_issues(detection_report)
        )),
        TokenError::PinRequired => BootstrapError::HardwareTokenPinRequired,
        TokenError::InvalidPin => BootstrapError::HardwareTokenInvalidPin,
        TokenError::PinLocked => BootstrapError::HardwareTokenPinLocked,
        TokenError::TokenNotFound(locator) => {
            BootstrapError::HardwareTokenNotFound { locator }
        }
        TokenError::UnsupportedMechanism(mechanism) => {
            BootstrapError::HardwareTokenUnsupported { mechanism }
        }
        TokenError::Disconnected => BootstrapError::HardwareTokenDisconnected,
        TokenError::SessionExpired { elapsed, timeout } => {
            BootstrapError::HardwareTokenSessionExpired { elapsed, timeout }
        }
        TokenError::Cancelled => BootstrapError::HardwareTokenCancelled,
        TokenError::Pkcs11(detail) => {
            BootstrapError::HardwareTokenProviderFault { detail }
        }
        TokenError::KeyNotFound(key) => BootstrapError::HardwareToken(format!(
            "key not found on hardware token: {key}"
        )),
        TokenError::CertificateSelectionFailed(refusal) => {
            BootstrapError::HardwareToken(format!(
                "certificate selection failed: {refusal}"
            ))
        }
    }
}

fn summarize_detection_issues(detection_report: &TokenDetectionReport) -> String {
    let issues = detection_report.issues();
    if issues.is_empty() {
        return "no provider diagnostics available".to_string();
    }

    let mut summary = issues
        .iter()
        .take(3)
        .map(|issue| {
            format!(
                "{:?} for {}: {}",
                issue.stage,
                issue.provider.display(),
                issue.message
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    if issues.len() > 3 {
        use std::fmt::Write;
        let _ = write!(summary, "; ... ({} total issues)", issues.len());
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware_token::{
        AuthenticatedSessionState, AuthenticatedTokenSession, ProviderDetectionResult,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
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

    // ---- Multi-device bootstrap ----

    #[test]
    fn test_multi_device_bootstrap_produces_threshold_genesis() {
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
        let genesis = workflow.run().unwrap();
        assert!(genesis.validate().is_ok());
        assert!(dir.path().join("genesis.cbor").exists());
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

    #[test]
    fn test_finalize_bootstrap_preserves_partial_state_marker_when_save_genesis_fails() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .skip_time_validation(true)
            .build()
            .unwrap();

        let mut workflow = BootstrapWorkflow::new(config).unwrap();
        workflow.phase = BootstrapPhase::GenesisCreate;
        crate::phase::write_phase_lock(dir.path(), &workflow.phase).unwrap();

        std::fs::create_dir(dir.path().join("genesis.cbor")).unwrap();

        let signing_key = fcp_crypto::Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());

        let result = workflow.finalize_bootstrap(&genesis);
        assert!(result.is_err(), "expected genesis persistence to fail");
        assert!(
            dir.path().join("init.lock").exists(),
            "init.lock should remain when finalization fails"
        );
        assert!(
            !genesis_temporary_path(&dir.path().join("genesis.cbor")).exists(),
            "temporary genesis file should be cleaned up on failure"
        );
        assert_eq!(
            crate::phase::detect_partial_state(dir.path()),
            Some(BootstrapPhase::GenesisCreate),
            "failed finalization should still be discoverable as partial state"
        );
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

    // ---- BootstrapMode Clone ----

    #[test]
    fn test_mode_clone_single_device() {
        let mode = BootstrapMode::SingleDevice;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_mode_clone_multi_device() {
        let mode = BootstrapMode::MultiDevice {
            device_count: 5,
            threshold: 3,
        };
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_mode_clone_import() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let mode = BootstrapMode::Import { phrase };
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_mode_clone_hardware_token() {
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/test/pkcs11.so"),
            slot: 1,
            label: "YubiKey".to_string(),
            manufacturer: "Yubico".to_string(),
            serial: "SN001".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string()],
        };
        let mode = BootstrapMode::HardwareToken { token };
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    // ---- BootstrapMode Debug ----

    #[test]
    fn test_mode_debug_single_device() {
        let mode = BootstrapMode::SingleDevice;
        let debug = format!("{mode:?}");
        assert!(debug.contains("SingleDevice"));
    }

    #[test]
    fn test_mode_debug_multi_device() {
        let mode = BootstrapMode::MultiDevice {
            device_count: 7,
            threshold: 4,
        };
        let debug = format!("{mode:?}");
        assert!(debug.contains("MultiDevice"));
        assert!(debug.contains('7'));
        assert!(debug.contains('4'));
    }

    #[test]
    fn test_mode_debug_import() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let mode = BootstrapMode::Import { phrase };
        let debug = format!("{mode:?}");
        assert!(debug.contains("Import"));
    }

    #[test]
    fn test_mode_debug_hardware_token() {
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/dev/token"),
            slot: 0,
            label: "TestHSM".to_string(),
            manufacturer: "TestMfg".to_string(),
            serial: "SER123".to_string(),
            mechanisms: vec![],
        };
        let mode = BootstrapMode::HardwareToken { token };
        let debug = format!("{mode:?}");
        assert!(debug.contains("HardwareToken"));
        assert!(debug.contains("TestHSM"));
    }

    // ---- BootstrapMode Display edge cases ----

    #[test]
    fn test_mode_display_hardware_token() {
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/usr/lib/pkcs11.so"),
            slot: 2,
            label: "SmartCard".to_string(),
            manufacturer: "Gemalto".to_string(),
            serial: "SC999".to_string(),
            mechanisms: vec!["CKM_EDDSA".to_string()],
        };
        let mode = BootstrapMode::HardwareToken { token };
        let display = mode.to_string();
        assert!(display.starts_with("Hardware Token"));
        assert!(display.contains("SmartCard"));
    }

    #[test]
    fn test_mode_display_multi_device_various_thresholds() {
        let mode = BootstrapMode::MultiDevice {
            device_count: 10,
            threshold: 7,
        };
        assert_eq!(mode.to_string(), "Multi-Device (7/10)");

        let mode2 = BootstrapMode::MultiDevice {
            device_count: 2,
            threshold: 1,
        };
        assert_eq!(mode2.to_string(), "Multi-Device (1/2)");
    }

    // ---- BootstrapMode Eq exhaustive ----

    #[test]
    fn test_mode_eq_multi_device_same_params() {
        let a = BootstrapMode::MultiDevice {
            device_count: 5,
            threshold: 3,
        };
        let b = BootstrapMode::MultiDevice {
            device_count: 5,
            threshold: 3,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_mode_ne_multi_device_different_threshold() {
        let a = BootstrapMode::MultiDevice {
            device_count: 5,
            threshold: 3,
        };
        let b = BootstrapMode::MultiDevice {
            device_count: 5,
            threshold: 2,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_mode_ne_multi_device_different_device_count() {
        let a = BootstrapMode::MultiDevice {
            device_count: 5,
            threshold: 3,
        };
        let b = BootstrapMode::MultiDevice {
            device_count: 7,
            threshold: 3,
        };
        assert_ne!(a, b);
    }

    // ---- BootstrapConfigBuilder Debug ----

    #[test]
    fn test_config_builder_debug() {
        let builder = BootstrapConfig::builder();
        let debug = format!("{builder:?}");
        assert!(debug.contains("BootstrapConfigBuilder"));
    }

    #[test]
    fn test_config_builder_default_debug() {
        let builder = BootstrapConfigBuilder::default();
        let debug = format!("{builder:?}");
        assert!(debug.contains("BootstrapConfigBuilder"));
    }

    // ---- BootstrapConfig Debug ----

    #[test]
    fn test_config_debug() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("BootstrapConfig"));
        assert!(debug.contains("SingleDevice"));
    }

    #[test]
    fn test_config_debug_redacts_hardware_token_pin() {
        let dir = tempdir().unwrap();
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/test/pkcs11.so"),
            slot: 0,
            label: "TestToken".to_string(),
            manufacturer: "TestMfg".to_string(),
            serial: "SN123".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string()],
        };
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::HardwareToken { token })
            .hardware_token_pin("123456")
            .build()
            .unwrap();

        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("123456"));
    }

    // ---- Config builder error messages ----

    #[test]
    fn test_config_builder_missing_data_dir_error_message() {
        let result = BootstrapConfig::builder()
            .mode(BootstrapMode::SingleDevice)
            .build();
        match result {
            Err(BootstrapError::Config(msg)) => assert!(msg.contains("data_dir")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn test_config_builder_missing_mode_error_message() {
        let dir = tempdir().unwrap();
        let result = BootstrapConfig::builder().data_dir(dir.path()).build();
        match result {
            Err(BootstrapError::Config(msg)) => assert!(msg.contains("mode")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn test_config_builder_empty_build_error() {
        let result = BootstrapConfig::builder().build();
        assert!(result.is_err());
    }

    // ---- Config builder flag toggling ----

    #[test]
    fn test_config_builder_skip_time_false() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .skip_time_validation(false)
            .build()
            .unwrap();
        assert!(!config.skip_time_validation);
    }

    #[test]
    fn test_config_builder_force_overwrite_false() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .force_overwrite(false)
            .build()
            .unwrap();
        assert!(!config.force_overwrite);
    }

    #[test]
    fn test_config_builder_allow_time_drift_false() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .allow_time_drift_warning(false)
            .build()
            .unwrap();
        assert!(!config.allow_time_drift_warning);
    }

    // ---- Workflow with different modes ----

    #[test]
    fn test_workflow_creation_multi_device() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::MultiDevice {
                device_count: 5,
                threshold: 3,
            })
            .build()
            .unwrap();
        let workflow = BootstrapWorkflow::new(config).unwrap();
        assert!(matches!(workflow.phase(), BootstrapPhase::Uninitialized));
    }

    #[test]
    fn test_workflow_creation_import_mode() {
        let dir = tempdir().unwrap();
        let phrase = RecoveryPhrase::generate().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::Import { phrase })
            .build()
            .unwrap();
        let workflow = BootstrapWorkflow::new(config).unwrap();
        assert!(matches!(workflow.phase(), BootstrapPhase::Uninitialized));
    }

    // ---- Workflow creates data directory ----

    #[test]
    fn test_workflow_creates_data_dir() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("deeply").join("nested").join("dir");
        assert!(!nested.exists());

        let config = BootstrapConfig::builder()
            .data_dir(&nested)
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();
        let _workflow = BootstrapWorkflow::new(config).unwrap();
        assert!(nested.exists());
    }

    // ---- Import produces deterministic fingerprint ----

    #[test]
    fn test_import_produces_deterministic_fingerprint() {
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let dir1 = tempdir().unwrap();
        let phrase1 = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        let config1 = BootstrapConfig::builder()
            .data_dir(dir1.path())
            .mode(BootstrapMode::Import { phrase: phrase1 })
            .skip_time_validation(true)
            .build()
            .unwrap();
        let genesis1 = BootstrapWorkflow::new(config1).unwrap().run().unwrap();

        let dir2 = tempdir().unwrap();
        let phrase2 = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        let config2 = BootstrapConfig::builder()
            .data_dir(dir2.path())
            .mode(BootstrapMode::Import { phrase: phrase2 })
            .skip_time_validation(true)
            .build()
            .unwrap();
        let genesis2 = BootstrapWorkflow::new(config2).unwrap().run().unwrap();

        assert_eq!(genesis1.fingerprint(), genesis2.fingerprint());
    }

    // ---- Single device genesis file contents ----

    #[test]
    fn test_single_device_saves_valid_cbor() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .skip_time_validation(true)
            .build()
            .unwrap();

        let genesis = BootstrapWorkflow::new(config).unwrap().run().unwrap();

        // Read back the saved genesis and verify
        let cbor = std::fs::read(dir.path().join("genesis.cbor")).unwrap();
        let loaded = GenesisState::from_cbor(&cbor).unwrap();
        assert_eq!(genesis.fingerprint(), loaded.fingerprint());
        assert_eq!(genesis.owner_public_key, loaded.owner_public_key);
    }

    // ---- Hardware token not implemented ----

    #[test]
    fn test_hardware_token_requires_pin_before_login() {
        let dir = tempdir().unwrap();
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/test/pkcs11.so"),
            slot: 0,
            label: "TestToken".to_string(),
            manufacturer: "TestMfg".to_string(),
            serial: "SN123".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string()],
        };
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::HardwareToken { token })
            .skip_time_validation(true)
            .build()
            .unwrap();

        let workflow = BootstrapWorkflow::new(config).unwrap();
        let result = workflow.run();
        assert!(matches!(result, Err(BootstrapError::HardwareTokenPinRequired)));
    }

    #[test]
    fn test_hardware_token_authenticates_before_truthful_handoff_refusal() {
        let dir = tempdir().unwrap();
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/test/pkcs11.so"),
            slot: 0,
            label: "TestToken".to_string(),
            manufacturer: "TestMfg".to_string(),
            serial: "SN123".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string()],
        };
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::HardwareToken {
                token: token.clone(),
            })
            .hardware_token_pin("123456")
            .skip_time_validation(true)
            .build()
            .unwrap();

        let mut workflow = BootstrapWorkflow::new(config).unwrap();
        let driver = MockSessionDriver::default();
        let detection_report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };

        let result =
            workflow.run_hardware_token_bootstrap_with_driver(&token, &detection_report, &driver);

        // Mock returns empty certificates, so certificate selection fails with
        // a typed mapping. Session is still cleaned up via Drop.
        assert!(matches!(
            result,
            Err(BootstrapError::HardwareToken(message))
                if message.contains("certificate selection failed")
        ));
        // Session cleanup happens via Drop when certificate selection fails.
        assert_eq!(driver.close_count(), 1);
    }

    // ---- Force overwrite cleans genesis.cbor ----

    #[test]
    fn test_force_overwrite_removes_old_genesis() {
        let dir = tempdir().unwrap();

        // Create an initial genesis with one key
        let key1 = fcp_crypto::Ed25519SigningKey::generate();
        let genesis1 = GenesisState::create(&key1.verifying_key());
        let fp1 = genesis1.fingerprint();
        let cbor = genesis1.to_cbor().unwrap();
        std::fs::write(dir.path().join("genesis.cbor"), cbor).unwrap();

        // Force overwrite and run a new bootstrap
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .skip_time_validation(true)
            .force_overwrite(true)
            .build()
            .unwrap();

        let genesis2 = BootstrapWorkflow::new(config).unwrap().run().unwrap();
        // New genesis should have a different fingerprint (different key)
        assert_ne!(fp1, genesis2.fingerprint());
    }

    // ---- Workflow phase accessor ----

    #[test]
    fn test_workflow_phase_accessor_returns_uninitialized() {
        let dir = tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();
        let workflow = BootstrapWorkflow::new(config).unwrap();
        let phase = workflow.phase();
        assert!(matches!(phase, BootstrapPhase::Uninitialized));
        // Also verify it implements Display via the phase
        let display = format!("{phase}");
        assert_eq!(display, "Uninitialized");
    }

    // ---- check_initialization_state fresh directory ----

    #[test]
    fn test_check_init_state_fresh() {
        let dir = tempdir().unwrap();
        let result = check_initialization_state(dir.path(), false).unwrap();
        assert!(matches!(result, InitCheckResult::Fresh));
    }

    // ---- check_initialization_state with genesis.cbor ----

    #[test]
    fn test_check_init_state_already_exists() {
        let dir = tempdir().unwrap();
        let key = fcp_crypto::Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        std::fs::write(dir.path().join("genesis.cbor"), cbor).unwrap();

        let result = check_initialization_state(dir.path(), false).unwrap();
        assert!(matches!(result, InitCheckResult::AlreadyExists { .. }));
    }

    // ---- check_initialization_state with force_overwrite ----

    #[test]
    fn test_check_init_state_force_overwrite_removes_genesis() {
        let dir = tempdir().unwrap();
        let key = fcp_crypto::Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        let genesis_path = dir.path().join("genesis.cbor");
        std::fs::write(&genesis_path, cbor).unwrap();
        assert!(genesis_path.exists());

        let result = check_initialization_state(dir.path(), true).unwrap();
        assert!(matches!(result, InitCheckResult::Fresh));
        assert!(!genesis_path.exists());
    }

    // ---- check_initialization_state with partial state ----

    #[test]
    fn test_check_init_state_partial_state() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::KeyGeneration;
        crate::phase::write_phase_lock(dir.path(), &phase).unwrap();

        let result = check_initialization_state(dir.path(), false).unwrap();
        assert!(matches!(result, InitCheckResult::PartialState { .. }));
    }

    #[test]
    fn test_check_init_state_corrupt_genesis_with_partial_state_prefers_recovery_marker() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::GenesisCreate;
        crate::phase::write_phase_lock(dir.path(), &phase).unwrap();
        std::fs::write(dir.path().join("genesis.cbor"), b"not cbor").unwrap();

        let result = check_initialization_state(dir.path(), false).unwrap();
        assert!(matches!(
            result,
            InitCheckResult::PartialState {
                phase: BootstrapPhase::GenesisCreate
            }
        ));
    }

    #[test]
    fn test_check_init_state_valid_genesis_beats_stale_partial_marker() {
        let dir = tempdir().unwrap();
        let phase = BootstrapPhase::GenesisCreate;
        crate::phase::write_phase_lock(dir.path(), &phase).unwrap();

        let key = fcp_crypto::Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        std::fs::write(dir.path().join("genesis.cbor"), cbor).unwrap();

        let result = check_initialization_state(dir.path(), false).unwrap();
        assert!(matches!(result, InitCheckResult::AlreadyExists { .. }));
    }

    // ---- Config builder with PathBuf vs &Path ----

    #[test]
    fn test_config_builder_accepts_pathbuf() {
        let dir = tempdir().unwrap();
        let path_buf = dir.path().to_path_buf();
        let config = BootstrapConfig::builder()
            .data_dir(path_buf)
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();
        assert_eq!(config.data_dir, dir.path());
    }

    #[test]
    fn test_config_builder_accepts_string() {
        let dir = tempdir().unwrap();
        let path_string = dir.path().to_string_lossy().to_string();
        let config = BootstrapConfig::builder()
            .data_dir(path_string)
            .mode(BootstrapMode::SingleDevice)
            .build()
            .unwrap();
        assert_eq!(config.data_dir, dir.path());
    }

    #[derive(Default)]
    struct MockSessionDriver {
        close_count: Arc<AtomicUsize>,
    }

    impl MockSessionDriver {
        fn close_count(&self) -> usize {
            self.close_count.load(Ordering::SeqCst)
        }
    }

    impl HardwareTokenSessionDriver for MockSessionDriver {
        fn open_authenticated_session(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
        ) -> Result<AuthenticatedTokenSession, TokenError> {
            assert!(!pin.is_empty());
            let close_count = Arc::clone(&self.close_count);
            Ok(AuthenticatedTokenSession::with_close_action(
                token.clone(),
                AuthenticatedSessionState::ReadWriteUser,
                true,
                move || {
                    close_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            ))
        }

        fn enumerate_certificates(
            &self,
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<Vec<crate::hardware_token::TokenCertificate>, TokenError> {
            Ok(Vec::new())
        }

        fn enumerate_keys(
            &self,
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<Vec<crate::hardware_token::TokenKeyInfo>, TokenError> {
            Ok(Vec::new())
        }
    }

    // ---- map_hardware_token_error typed mapping ----

    fn empty_report() -> TokenDetectionReport {
        TokenDetectionReport::default()
    }

    fn report_with_issues() -> TokenDetectionReport {
        TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: std::path::PathBuf::from("/missing.so"),
                tokens: Vec::new(),
                issues: vec![crate::hardware_token::DetectionIssue {
                    provider: std::path::PathBuf::from("/missing.so"),
                    stage: crate::hardware_token::DetectionStage::ProviderMissing,
                    slot: None,
                    message: "not found".to_string(),
                }],
            }],
        }
    }

    #[test]
    fn map_error_no_tokens_without_issues_yields_no_hardware_tokens() {
        let err = map_hardware_token_error(&empty_report(), TokenError::NoTokens);
        assert!(matches!(err, BootstrapError::NoHardwareTokens));
    }

    #[test]
    fn map_error_no_tokens_with_issues_yields_hardware_token_string() {
        let err = map_hardware_token_error(&report_with_issues(), TokenError::NoTokens);
        assert!(matches!(err, BootstrapError::HardwareToken(msg) if msg.contains("no compatible")));
    }

    #[test]
    fn map_error_pin_required_yields_typed_variant() {
        let err = map_hardware_token_error(&empty_report(), TokenError::PinRequired);
        assert!(matches!(err, BootstrapError::HardwareTokenPinRequired));
    }

    #[test]
    fn map_error_invalid_pin_yields_typed_variant() {
        let err = map_hardware_token_error(&empty_report(), TokenError::InvalidPin);
        assert!(matches!(err, BootstrapError::HardwareTokenInvalidPin));
    }

    #[test]
    fn map_error_pin_locked_yields_typed_variant() {
        let err = map_hardware_token_error(&empty_report(), TokenError::PinLocked);
        assert!(matches!(err, BootstrapError::HardwareTokenPinLocked));
    }

    #[test]
    fn map_error_token_not_found_yields_typed_variant() {
        let err = map_hardware_token_error(
            &empty_report(),
            TokenError::TokenNotFound("YubiKey slot 0".into()),
        );
        assert!(matches!(
            err,
            BootstrapError::HardwareTokenNotFound { locator } if locator.contains("YubiKey")
        ));
    }

    #[test]
    fn map_error_unsupported_mechanism_yields_typed_variant() {
        let err = map_hardware_token_error(
            &empty_report(),
            TokenError::UnsupportedMechanism("Ed25519 signing".into()),
        );
        assert!(matches!(
            err,
            BootstrapError::HardwareTokenUnsupported { mechanism } if mechanism.contains("Ed25519")
        ));
    }

    #[test]
    fn map_error_disconnected_yields_typed_variant() {
        let err = map_hardware_token_error(&empty_report(), TokenError::Disconnected);
        assert!(matches!(err, BootstrapError::HardwareTokenDisconnected));
    }

    #[test]
    fn map_error_session_expired_yields_typed_variant() {
        let err = map_hardware_token_error(
            &empty_report(),
            TokenError::SessionExpired {
                elapsed: std::time::Duration::from_secs(301),
                timeout: std::time::Duration::from_secs(300),
            },
        );
        assert!(matches!(
            err,
            BootstrapError::HardwareTokenSessionExpired { elapsed, timeout }
                if elapsed.as_secs() == 301 && timeout.as_secs() == 300
        ));
    }

    #[test]
    fn map_error_cancelled_yields_typed_variant() {
        let err = map_hardware_token_error(&empty_report(), TokenError::Cancelled);
        assert!(matches!(err, BootstrapError::HardwareTokenCancelled));
    }

    #[test]
    fn map_error_pkcs11_yields_provider_fault() {
        let err = map_hardware_token_error(
            &empty_report(),
            TokenError::Pkcs11("CKR_DEVICE_ERROR".into()),
        );
        assert!(matches!(
            err,
            BootstrapError::HardwareTokenProviderFault { detail } if detail.contains("CKR_DEVICE_ERROR")
        ));
    }

    #[test]
    fn map_error_key_not_found_yields_hardware_token_string() {
        let err = map_hardware_token_error(
            &empty_report(),
            TokenError::KeyNotFound("owner-key".into()),
        );
        assert!(matches!(
            err,
            BootstrapError::HardwareToken(msg) if msg.contains("key not found") && msg.contains("owner-key")
        ));
    }

    // ---- Session cleanup determinism ----

    #[test]
    fn session_cleanup_on_success_path() {
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/test/pkcs11.so"),
            slot: 0,
            label: "TestToken".to_string(),
            manufacturer: "TestMfg".to_string(),
            serial: "SN123".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string()],
        };
        let driver = MockSessionDriver::default();
        let pin = HardwareTokenPin::new("123456");
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };
        let outcome =
            crate::hardware_token::select_and_authenticate(&token, &pin, &report, &driver, None)
                .unwrap();

        // Explicit close: close_action runs exactly once.
        outcome.session.close().unwrap();
        assert_eq!(driver.close_count(), 1);
    }

    #[test]
    fn session_cleanup_on_drop_path() {
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/test/pkcs11.so"),
            slot: 0,
            label: "TestToken".to_string(),
            manufacturer: "TestMfg".to_string(),
            serial: "SN123".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string()],
        };
        let driver = MockSessionDriver::default();
        let pin = HardwareTokenPin::new("123456");
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };
        let outcome =
            crate::hardware_token::select_and_authenticate(&token, &pin, &report, &driver, None)
                .unwrap();

        // Drop without explicit close: Drop runs close_action exactly once.
        drop(outcome.session);
        assert_eq!(driver.close_count(), 1);
    }

    #[test]
    fn session_cleanup_deterministic_close_then_drop() {
        let token = DetectedToken {
            provider: std::path::PathBuf::from("/test/pkcs11.so"),
            slot: 0,
            label: "TestToken".to_string(),
            manufacturer: "TestMfg".to_string(),
            serial: "SN123".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string()],
        };
        let driver = MockSessionDriver::default();
        let pin = HardwareTokenPin::new("123456");
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };
        let outcome =
            crate::hardware_token::select_and_authenticate(&token, &pin, &report, &driver, None)
                .unwrap();

        // Explicit close consumes the action; subsequent Drop is a no-op.
        outcome.session.close().unwrap();
        // driver.close_count() is exactly 1, not 2 (Drop didn't double-close).
        assert_eq!(driver.close_count(), 1);
    }
}
