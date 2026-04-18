//! Hardware token detection and integration.
//!
//! This module provides cross-platform support for detecting and using
//! hardware security modules (HSMs) and smart cards via PKCS#11.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Information about a detected hardware token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedToken {
    /// PKCS#11 provider library path.
    pub provider: PathBuf,

    /// Slot number.
    pub slot: u32,

    /// Token label.
    pub label: String,

    /// Manufacturer name.
    pub manufacturer: String,

    /// Token serial number.
    pub serial: String,

    /// Supported mechanisms.
    pub mechanisms: Vec<String>,
}

impl DetectedToken {
    /// Check if this token supports Ed25519.
    #[must_use]
    pub fn supports_ed25519(&self) -> bool {
        self.mechanisms
            .iter()
            .any(|m| m.contains("ED25519") || m.contains("EDDSA"))
    }

    /// Check if this token supports ECDH for X25519.
    #[must_use]
    pub fn supports_x25519(&self) -> bool {
        self.mechanisms
            .iter()
            .any(|m| m.contains("X25519") || m.contains("ECDH"))
    }
}

impl std::fmt::Display for DetectedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) [slot {}]",
            self.label, self.manufacturer, self.slot
        )
    }
}

/// Discovery stages for provider and slot probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionStage {
    /// The configured provider path does not exist on disk.
    ProviderMissing,
    /// The provider library could not be loaded.
    LoadProvider,
    /// The provider library could not be initialized.
    InitializeProvider,
    /// Slot enumeration failed.
    EnumerateSlots,
    /// The slot identifier could not be represented in `DetectedToken`.
    NormalizeSlotId,
    /// Token metadata could not be read for a slot.
    ReadTokenInfo,
    /// Mechanism enumeration failed for a slot.
    ReadMechanisms,
    /// The provider library could not be finalized cleanly.
    FinalizeProvider,
}

/// A specific discovery failure surfaced during PKCS#11 probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionIssue {
    /// Provider library path that produced the issue.
    pub provider: PathBuf,
    /// Detection stage that failed.
    pub stage: DetectionStage,
    /// Optional raw slot identifier associated with the issue.
    pub slot: Option<u64>,
    /// Human-readable failure details.
    pub message: String,
}

impl DetectionIssue {
    fn new(
        provider: &Path,
        stage: DetectionStage,
        slot: Option<u64>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.to_path_buf(),
            stage,
            slot,
            message: message.into(),
        }
    }
}

/// The result of probing a single PKCS#11 provider library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDetectionResult {
    /// Provider library path that was probed.
    pub provider: PathBuf,
    /// Token candidates discovered from this provider.
    pub tokens: Vec<DetectedToken>,
    /// Structured issues encountered while probing this provider.
    pub issues: Vec<DetectionIssue>,
}

impl ProviderDetectionResult {
    fn new(provider: &Path) -> Self {
        Self {
            provider: provider.to_path_buf(),
            tokens: Vec::new(),
            issues: Vec::new(),
        }
    }

    fn push_issue(&mut self, stage: DetectionStage, slot: Option<u64>, message: impl Into<String>) {
        self.issues
            .push(DetectionIssue::new(&self.provider, stage, slot, message));
    }
}

/// Aggregate report for a hardware-token discovery pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenDetectionReport {
    /// Per-provider probe results in probe order.
    pub providers: Vec<ProviderDetectionResult>,
}

impl TokenDetectionReport {
    /// Return every discovered token candidate across all providers.
    #[must_use]
    pub fn all_tokens(&self) -> Vec<DetectedToken> {
        self.providers
            .iter()
            .flat_map(|provider| provider.tokens.iter().cloned())
            .collect()
    }

    /// Return only FCP-compatible tokens across all providers.
    #[must_use]
    pub fn fcp_compatible_tokens(&self) -> Vec<DetectedToken> {
        self.providers
            .iter()
            .flat_map(|provider| provider.tokens.iter().cloned())
            .filter(DetectedToken::supports_ed25519)
            .collect()
    }

    /// Return every structured issue reported during discovery.
    #[must_use]
    pub fn issues(&self) -> Vec<DetectionIssue> {
        self.providers
            .iter()
            .flat_map(|provider| provider.issues.iter().cloned())
            .collect()
    }

    /// Whether discovery found at least one token candidate.
    #[must_use]
    pub fn has_detected_tokens(&self) -> bool {
        self.providers
            .iter()
            .any(|provider| !provider.tokens.is_empty())
    }
}

/// Redacted PIN material for hardware-token login.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HardwareTokenPin(String);

impl HardwareTokenPin {
    /// Create a new hardware-token PIN wrapper.
    #[must_use]
    pub fn new(pin: impl Into<String>) -> Self {
        Self(pin.into())
    }

    /// Whether the provided PIN is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn to_auth_pin(&self) -> AuthPin {
        AuthPin::new(self.0.clone().into())
    }
}

impl fmt::Debug for HardwareTokenPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Normalized state for an authenticated PKCS#11 session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatedSessionState {
    /// Read-only session, no authenticated user.
    ReadOnlyPublic,
    /// Read-only session authenticated as a normal user.
    ReadOnlyUser,
    /// Read-write session, no authenticated user.
    ReadWritePublic,
    /// Read-write session authenticated as a normal user.
    ReadWriteUser,
    /// Read-write session authenticated as the security officer.
    ReadWriteSecurityOfficer,
}

impl From<SessionState> for AuthenticatedSessionState {
    fn from(value: SessionState) -> Self {
        match value {
            SessionState::RoPublic => Self::ReadOnlyPublic,
            SessionState::RoUser => Self::ReadOnlyUser,
            SessionState::RwPublic => Self::ReadWritePublic,
            SessionState::RwUser => Self::ReadWriteUser,
            SessionState::RwSecurityOfficer => Self::ReadWriteSecurityOfficer,
        }
    }
}

impl fmt::Display for AuthenticatedSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ReadOnlyPublic => "ro-public",
            Self::ReadOnlyUser => "ro-user",
            Self::ReadWritePublic => "rw-public",
            Self::ReadWriteUser => "rw-user",
            Self::ReadWriteSecurityOfficer => "rw-so",
        };
        f.write_str(label)
    }
}

/// Default session timeout: 5 minutes.
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// A live authenticated hardware-token session with redaction-safe metadata.
pub struct AuthenticatedTokenSession {
    token: DetectedToken,
    session_state: AuthenticatedSessionState,
    read_write: bool,
    created_at: Instant,
    timeout: Duration,
    close_action: Option<Box<dyn FnOnce() -> Result<(), TokenError>>>,
}

impl fmt::Debug for AuthenticatedTokenSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedTokenSession")
            .field("token", &self.token)
            .field("session_state", &self.session_state)
            .field("read_write", &self.read_write)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedTokenSession {
    /// Create an authenticated session wrapper with an injected close action.
    pub(crate) fn with_close_action(
        token: DetectedToken,
        session_state: AuthenticatedSessionState,
        read_write: bool,
        close_action: impl FnOnce() -> Result<(), TokenError> + 'static,
    ) -> Self {
        Self {
            token,
            session_state,
            read_write,
            created_at: Instant::now(),
            timeout: DEFAULT_SESSION_TIMEOUT,
            close_action: Some(Box::new(close_action)),
        }
    }

    /// The canonical detected token that was authenticated.
    #[must_use]
    pub const fn token(&self) -> &DetectedToken {
        &self.token
    }

    /// The authenticated session state reported by the token.
    #[must_use]
    pub const fn session_state(&self) -> AuthenticatedSessionState {
        self.session_state
    }

    /// Whether the session has read-write access.
    #[must_use]
    pub const fn read_write(&self) -> bool {
        self.read_write
    }

    /// Whether this session has exceeded its timeout.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.timeout
    }

    /// The elapsed time since this session was authenticated.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// The configured session timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Set a custom session timeout.
    pub const fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Check that the session is still valid (not expired) before use.
    ///
    /// # Errors
    ///
    /// Returns `TokenError::Disconnected` if the session has expired.
    pub fn check_alive(&self) -> Result<(), TokenError> {
        if self.is_expired() {
            return Err(TokenError::SessionExpired {
                elapsed: self.created_at.elapsed(),
                timeout: self.timeout,
            });
        }
        Ok(())
    }

    /// Close the authenticated session immediately.
    ///
    /// # Errors
    ///
    /// Returns a token error if logout or session cleanup fails.
    pub fn close(mut self) -> Result<(), TokenError> {
        if let Some(close_action) = self.close_action.take() {
            return close_action();
        }
        Ok(())
    }
}

impl Drop for AuthenticatedTokenSession {
    fn drop(&mut self) {
        if let Some(close_action) = self.close_action.take() {
            if let Err(err) = close_action() {
                tracing::warn!(
                    provider = %self.token.provider.display(),
                    slot = self.token.slot,
                    label = %self.token.label,
                    ?err,
                    "Failed to close authenticated hardware-token session"
                );
            }
        }
    }
}

/// Driver abstraction for opening authenticated hardware-token sessions.
pub(crate) trait HardwareTokenSessionDriver: Send + Sync {
    /// Open and authenticate a session for the selected token.
    ///
    /// # Errors
    ///
    /// Returns a token error if the provider, slot, or login sequence fails.
    fn open_authenticated_session(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<AuthenticatedTokenSession, TokenError>;
}

/// Real PKCS#11-backed session driver.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Pkcs11SessionDriver;

impl HardwareTokenSessionDriver for Pkcs11SessionDriver {
    fn open_authenticated_session(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<AuthenticatedTokenSession, TokenError> {
        let provider_guard = provider_probe_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let pkcs11 = Pkcs11::new(&token.provider).map_err(map_pkcs11_error)?;
        let owns_initialization =
            match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
                Ok(()) => true,
                Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => false,
                Err(err) => return Err(map_pkcs11_error(err)),
            };

        let slot = Slot::try_from(u64::from(token.slot))
            .map_err(|err| TokenError::Pkcs11(err.to_string()))?;
        let session = match pkcs11.open_rw_session(slot) {
            Ok(session) => session,
            Err(err) => {
                let _ = finalize_pkcs11_context(pkcs11, owns_initialization);
                return Err(map_pkcs11_error(err));
            }
        };

        let auth_pin = pin.to_auth_pin();
        match session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(err) => {
                cleanup_failed_session(session, pkcs11, owns_initialization);
                return Err(map_pkcs11_error(err));
            }
        }

        let session_info = match session.get_session_info() {
            Ok(session_info) => session_info,
            Err(err) => {
                cleanup_failed_session(session, pkcs11, owns_initialization);
                return Err(map_pkcs11_error(err));
            }
        };

        let session_state = AuthenticatedSessionState::from(session_info.session_state());
        let read_write = session_info.read_write();

        Ok(AuthenticatedTokenSession::with_close_action(
            token.clone(),
            session_state,
            read_write,
            move || {
                let close_result = close_pkcs11_session(session, session_state);
                let finalize_result = finalize_pkcs11_context(pkcs11, owns_initialization);
                drop(provider_guard);
                close_result.and(finalize_result)
            },
        ))
    }
}

/// Rank detected tokens into a deterministic bootstrap order.
#[must_use]
pub fn rank_detected_tokens(tokens: &[DetectedToken]) -> Vec<DetectedToken> {
    let mut ranked = tokens.to_vec();
    ranked.sort_by_key(token_rank_key);
    ranked
}

type TokenRankKey = (
    Reverse<bool>,
    Reverse<bool>,
    PathBuf,
    u32,
    String,
    String,
    String,
);

fn token_rank_key(token: &DetectedToken) -> TokenRankKey {
    (
        Reverse(token.supports_ed25519()),
        Reverse(token.supports_x25519()),
        token.provider.clone(),
        token.slot,
        token.serial.clone(),
        token.label.clone(),
        token.manufacturer.clone(),
    )
}

fn token_identity_matches(requested: &DetectedToken, candidate: &DetectedToken) -> bool {
    requested.provider == candidate.provider
        && requested.slot == candidate.slot
        && token_field_matches(&requested.label, &candidate.label)
        && token_field_matches(&requested.manufacturer, &candidate.manufacturer)
        && token_field_matches(&requested.serial, &candidate.serial)
}

fn token_field_matches(requested: &str, candidate: &str) -> bool {
    requested == candidate || requested == "unknown" || candidate == "unknown"
}

/// Canonicalize a requested bootstrap token against the latest discovery pass.
///
/// # Errors
///
/// Returns a typed refusal if the token is absent or lacks the required
/// Ed25519 signing capability.
pub(crate) fn select_bootstrap_token(
    requested: &DetectedToken,
    candidates: &[DetectedToken],
) -> Result<DetectedToken, TokenError> {
    if candidates.is_empty() {
        return Err(TokenError::NoTokens);
    }

    let ranked = rank_detected_tokens(candidates);
    let Some(candidate) = ranked
        .into_iter()
        .find(|candidate| token_identity_matches(requested, candidate))
    else {
        return Err(TokenError::TokenNotFound(token_locator(requested)));
    };

    if !candidate.supports_ed25519() {
        return Err(TokenError::UnsupportedMechanism(
            "Ed25519 signing".to_string(),
        ));
    }

    Ok(candidate)
}

/// Establish a truthful authenticated bootstrap session for a selected token.
///
/// # Errors
///
/// Returns a typed refusal if the PIN is missing, the token is unavailable, or
/// PKCS#11 login fails.
pub(crate) fn authenticate_bootstrap_session_with_driver<D: HardwareTokenSessionDriver>(
    requested: &DetectedToken,
    candidates: &[DetectedToken],
    pin: &HardwareTokenPin,
    driver: &D,
) -> Result<AuthenticatedTokenSession, TokenError> {
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let selected = select_bootstrap_token(requested, candidates)?;
    driver.open_authenticated_session(&selected, pin)
}

/// The outcome of a hardware-token session-selection flow.
///
/// Captures both the authenticated session and the discovery context
/// so downstream consumers (certificate selection, provisioning) can
/// make decisions with full context.
#[derive(Debug)]
pub struct SessionSelectionOutcome {
    /// The authenticated session, ready for downstream operations.
    pub session: AuthenticatedTokenSession,
    /// The full discovery report that produced the candidate list.
    pub detection_report: TokenDetectionReport,
    /// The token that was selected after ranking.
    pub selected_token: DetectedToken,
}

/// Run the full session-selection state machine: detect → rank → select → authenticate.
///
/// This is the canonical entry point for hardware-token bootstrap.  It returns a
/// live authenticated session or a typed refusal.  The caller is responsible for
/// closing the session when done (via `session.close()` or `Drop`).
///
/// # Errors
///
/// Returns a typed `TokenError` if detection finds no tokens, the requested
/// token is missing or incompatible, the PIN is missing/invalid, or the
/// PKCS#11 login fails.
pub(crate) fn select_and_authenticate<D: HardwareTokenSessionDriver>(
    requested: &DetectedToken,
    pin: &HardwareTokenPin,
    detection_report: &TokenDetectionReport,
    driver: &D,
    session_timeout: Option<Duration>,
) -> Result<SessionSelectionOutcome, TokenError> {
    // Fail fast on missing PIN before any PKCS#11 work.
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let candidates = detection_report.all_tokens();

    tracing::info!(
        requested_provider = %requested.provider.display(),
        requested_slot = requested.slot,
        candidate_count = candidates.len(),
        detection_issues = detection_report.issues().len(),
        "Session-selection: ranking token candidates"
    );

    let selected = select_bootstrap_token(requested, &candidates)?;

    tracing::info!(
        provider = %selected.provider.display(),
        slot = selected.slot,
        label = %selected.label,
        ed25519 = selected.supports_ed25519(),
        x25519 = selected.supports_x25519(),
        "Session-selection: opening authenticated session"
    );

    let mut session =
        authenticate_bootstrap_session_with_driver(requested, &candidates, pin, driver)?;

    if let Some(timeout) = session_timeout {
        session.set_timeout(timeout);
    }

    tracing::info!(
        provider = %session.token().provider.display(),
        slot = session.token().slot,
        label = %session.token().label,
        session_state = %session.session_state(),
        read_write = session.read_write(),
        timeout_secs = session.timeout().as_secs(),
        "Session-selection: authenticated session established"
    );

    Ok(SessionSelectionOutcome {
        session,
        detection_report: detection_report.clone(),
        selected_token: selected,
    })
}

fn token_locator(token: &DetectedToken) -> String {
    format!(
        "{} [{}] via {} slot {}",
        token.label,
        token.serial,
        token.provider.display(),
        token.slot
    )
}

fn cleanup_failed_session(session: Session, pkcs11: Pkcs11, owns_initialization: bool) {
    let _ = session.close();
    let _ = finalize_pkcs11_context(pkcs11, owns_initialization);
}

fn close_pkcs11_session(
    session: Session,
    session_state: AuthenticatedSessionState,
) -> Result<(), TokenError> {
    let logout_result = match session_state {
        AuthenticatedSessionState::ReadOnlyUser
        | AuthenticatedSessionState::ReadWriteUser
        | AuthenticatedSessionState::ReadWriteSecurityOfficer => match session.logout() {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserNotLoggedIn, _)) => Ok(()),
            Err(err) => Err(map_pkcs11_error(err)),
        },
        AuthenticatedSessionState::ReadOnlyPublic | AuthenticatedSessionState::ReadWritePublic => {
            Ok(())
        }
    };

    let close_result = session.close().map_err(map_pkcs11_error);
    logout_result.and(close_result)
}

fn finalize_pkcs11_context(pkcs11: Pkcs11, owns_initialization: bool) -> Result<(), TokenError> {
    if owns_initialization {
        pkcs11.finalize().map_err(map_pkcs11_error)
    } else {
        Ok(())
    }
}

fn map_pkcs11_error(error: Pkcs11Error) -> TokenError {
    match error {
        Pkcs11Error::Pkcs11(
            RvError::PinIncorrect
            | RvError::PinInvalid
            | RvError::PinExpired
            | RvError::UserPinNotInitialized,
            _,
        ) => TokenError::InvalidPin,
        Pkcs11Error::Pkcs11(RvError::PinLocked, _) => TokenError::PinLocked,
        Pkcs11Error::Pkcs11(
            RvError::Cancel | RvError::FunctionCanceled | RvError::FunctionRejected,
            _,
        ) => TokenError::Cancelled,
        Pkcs11Error::Pkcs11(
            RvError::DeviceRemoved
            | RvError::TokenNotPresent
            | RvError::SessionClosed
            | RvError::SessionHandleInvalid
            | RvError::SlotIdInvalid,
            _,
        ) => TokenError::Disconnected,
        other => TokenError::Pkcs11(other.to_string()),
    }
}

/// Provider for hardware token operations.
pub trait HardwareTokenProvider: Send + Sync {
    /// List available tokens.
    fn list_tokens(&self) -> Vec<DetectedToken>;

    /// Generate an Ed25519 keypair on the token.
    ///
    /// # Errors
    ///
    /// Returns a token error if key generation fails or the token is unavailable.
    fn generate_keypair(
        &self,
        token: &DetectedToken,
        pin: &str,
        label: &str,
    ) -> Result<[u8; 32], TokenError>;

    /// Sign data with a key on the token.
    ///
    /// # Errors
    ///
    /// Returns a token error if signing fails or the token is unavailable.
    fn sign(
        &self,
        token: &DetectedToken,
        pin: &str,
        key_label: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, TokenError>;
}

/// Errors during token operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// No tokens found.
    #[error("no hardware tokens detected")]
    NoTokens,

    /// A PIN is required before a login attempt can be made.
    #[error("hardware token PIN is required")]
    PinRequired,

    /// Token not found.
    #[error("token not found: {0}")]
    TokenNotFound(String),

    /// Invalid PIN.
    #[error("invalid PIN")]
    InvalidPin,

    /// The PIN is locked after repeated failures.
    #[error("hardware token PIN is locked")]
    PinLocked,

    /// The user canceled or rejected the login flow.
    #[error("hardware token login was cancelled")]
    Cancelled,

    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Mechanism not supported.
    #[error("mechanism not supported: {0}")]
    UnsupportedMechanism(String),

    /// PKCS#11 error.
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    /// Token disconnected during operation.
    #[error("token disconnected")]
    Disconnected,

    /// Session expired due to timeout.
    #[error("hardware token session expired after {elapsed:?} (timeout: {timeout:?})")]
    SessionExpired {
        /// How long the session has been alive.
        elapsed: Duration,
        /// The configured timeout.
        timeout: Duration,
    },
}

/// Cross-platform token detector.
pub struct TokenDetector {
    /// Provider paths to search.
    provider_paths: Vec<PathBuf>,
}

impl TokenDetector {
    /// Create a new token detector with default provider paths.
    #[must_use]
    pub fn new() -> Self {
        Self::from_provider_paths(default_provider_paths())
    }

    /// Create a detector with an explicit provider search list.
    #[must_use]
    pub const fn from_provider_paths(provider_paths: Vec<PathBuf>) -> Self {
        Self { provider_paths }
    }

    /// Add a custom provider path.
    pub fn add_provider(&mut self, path: PathBuf) {
        self.provider_paths.push(path);
    }

    /// Probe all configured providers and return a structured discovery report.
    #[must_use]
    pub fn detect_report(&self) -> TokenDetectionReport {
        TokenDetectionReport {
            providers: self
                .provider_paths
                .iter()
                .map(|provider| detect_tokens_for_provider(provider.as_path()))
                .collect(),
        }
    }

    /// Detect all available tokens.
    #[must_use]
    pub fn detect_all(&self) -> Vec<DetectedToken> {
        self.detect_report().all_tokens()
    }

    /// Detect tokens that support the required mechanisms for FCP.
    #[must_use]
    pub fn detect_fcp_compatible(&self) -> Vec<DetectedToken> {
        self.detect_report().fcp_compatible_tokens()
    }
}

impl Default for TokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Get default PKCS#11 provider paths for the current platform.
fn default_provider_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib64/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib/x86_64-linux-gnu/libykcs11.so"),
            PathBuf::from("/usr/lib/libykcs11.so"),
        ]
    }

    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/usr/local/lib/opensc-pkcs11.so"),
            PathBuf::from("/opt/homebrew/lib/opensc-pkcs11.so"),
            PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"),
            PathBuf::from("/usr/local/lib/libykcs11.dylib"),
            PathBuf::from("/opt/homebrew/lib/libykcs11.dylib"),
        ]
    }

    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from(r"C:\Windows\System32\opensc-pkcs11.dll"),
            PathBuf::from(r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"),
            PathBuf::from(r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"),
        ]
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        vec![]
    }
}

/// Detect tokens for a specific PKCS#11 provider and surface discovery failures.
fn detect_tokens_for_provider(provider: &Path) -> ProviderDetectionResult {
    let _probe_guard = provider_probe_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut result = ProviderDetectionResult::new(provider);

    if !provider.exists() {
        result.push_issue(
            DetectionStage::ProviderMissing,
            None,
            format!("provider library not found at {}", provider.display()),
        );
        return result;
    }

    tracing::debug!(provider = %provider.display(), "Probing PKCS#11 provider");

    let pkcs11 = match Pkcs11::new(provider) {
        Ok(pkcs11) => pkcs11,
        Err(err) => {
            result.push_issue(DetectionStage::LoadProvider, None, err.to_string());
            return result;
        }
    };

    if let Err(err) = pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        result.push_issue(DetectionStage::InitializeProvider, None, err.to_string());
        return result;
    }

    match pkcs11.get_slots_with_token() {
        Ok(slots) => {
            for slot in slots {
                probe_slot(&pkcs11, slot, &mut result);
            }
        }
        Err(err) => result.push_issue(DetectionStage::EnumerateSlots, None, err.to_string()),
    }

    if let Err(err) = pkcs11.finalize() {
        result.push_issue(DetectionStage::FinalizeProvider, None, err.to_string());
    }

    result
}

fn probe_slot(pkcs11: &Pkcs11, slot: Slot, result: &mut ProviderDetectionResult) {
    let raw_slot = slot.id();
    let slot_id = match u32::try_from(raw_slot) {
        Ok(slot_id) => slot_id,
        Err(err) => {
            result.push_issue(
                DetectionStage::NormalizeSlotId,
                Some(raw_slot),
                err.to_string(),
            );
            return;
        }
    };

    let token_info = match pkcs11.get_token_info(slot) {
        Ok(token_info) => token_info,
        Err(err) => {
            result.push_issue(
                DetectionStage::ReadTokenInfo,
                Some(raw_slot),
                err.to_string(),
            );
            return;
        }
    };

    let mechanisms = match pkcs11.get_mechanism_list(slot) {
        Ok(mechanisms) => {
            let mut names: Vec<String> = mechanisms
                .into_iter()
                .map(|item| item.to_string())
                .collect();
            names.sort();
            names.dedup();
            names
        }
        Err(err) => {
            result.push_issue(
                DetectionStage::ReadMechanisms,
                Some(raw_slot),
                err.to_string(),
            );
            Vec::new()
        }
    };

    let label = normalize_token_field(token_info.label());
    let manufacturer = normalize_token_field(token_info.manufacturer_id());
    let serial = normalize_token_field(token_info.serial_number());

    tracing::debug!(
        provider = %result.provider.display(),
        slot = raw_slot,
        label = %label,
        manufacturer = %manufacturer,
        mechanism_count = mechanisms.len(),
        "Discovered PKCS#11 token candidate"
    );

    result.tokens.push(DetectedToken {
        provider: result.provider.clone(),
        slot: slot_id,
        label,
        manufacturer,
        serial,
        mechanisms,
    });
}

fn normalize_token_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn provider_probe_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Mock token provider for testing.
#[cfg(test)]
pub mod mock {
    use super::*;

    /// A mock hardware token provider for testing.
    pub struct MockTokenProvider {
        tokens: Vec<DetectedToken>,
    }

    impl MockTokenProvider {
        /// Create a new mock provider with no tokens.
        #[must_use]
        pub fn new() -> Self {
            Self { tokens: Vec::new() }
        }

        /// Add a mock token.
        pub fn add_token(&mut self, token: DetectedToken) {
            self.tokens.push(token);
        }
    }

    impl Default for MockTokenProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HardwareTokenProvider for MockTokenProvider {
        fn list_tokens(&self) -> Vec<DetectedToken> {
            self.tokens.clone()
        }

        fn generate_keypair(
            &self,
            _token: &DetectedToken,
            _pin: &str,
            _label: &str,
        ) -> Result<[u8; 32], TokenError> {
            use rand::RngCore;
            // Generate a random public key for testing
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            Ok(key)
        }

        fn sign(
            &self,
            _token: &DetectedToken,
            _pin: &str,
            _key_label: &str,
            _data: &[u8],
        ) -> Result<Vec<u8>, TokenError> {
            use rand::RngCore;
            // Generate a random signature for testing
            let mut sig = vec![0u8; 64];
            rand::thread_rng().fill_bytes(&mut sig);
            Ok(sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempfile::tempdir;

    fn test_token() -> DetectedToken {
        DetectedToken {
            provider: PathBuf::from("/test/provider.so"),
            slot: 0,
            label: "Test Token".to_string(),
            manufacturer: "Test Manufacturer".to_string(),
            serial: "123456".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string(), "CKM_ECDH".to_string()],
        }
    }

    #[test]
    fn test_token_supports_ed25519() {
        let token = test_token();
        assert!(token.supports_ed25519());
    }

    #[test]
    fn test_token_display() {
        let token = test_token();
        let display = format!("{token}");
        assert!(display.contains("Test Token"));
        assert!(display.contains("Test Manufacturer"));
    }

    #[test]
    fn test_detector_creation() {
        let detector = TokenDetector::new();
        assert!(!detector.provider_paths.is_empty());
    }

    #[test]
    fn test_mock_provider() {
        use mock::MockTokenProvider;

        let mut provider = MockTokenProvider::new();
        provider.add_token(test_token());

        let tokens = provider.list_tokens();
        assert_eq!(tokens.len(), 1);

        let pubkey = provider
            .generate_keypair(&tokens[0], "1234", "test-key")
            .unwrap();
        assert_eq!(pubkey.len(), 32);
    }

    #[test]
    fn hardware_token_pin_debug_is_redacted() {
        let pin = HardwareTokenPin::new("123456");
        assert_eq!(format!("{pin:?}"), "<redacted>");
    }

    #[test]
    fn rank_detected_tokens_prefers_fcp_capabilities_and_stable_order() {
        let mut weaker = test_token();
        weaker.slot = 9;
        weaker.mechanisms = vec!["CKM_RSA_PKCS".to_string()];

        let mut ed25519_only = test_token();
        ed25519_only.slot = 2;
        ed25519_only.serial = "A".to_string();
        ed25519_only.mechanisms = vec!["CKM_ED25519".to_string()];

        let mut ed25519_and_x25519 = test_token();
        ed25519_and_x25519.slot = 1;
        ed25519_and_x25519.serial = "B".to_string();
        ed25519_and_x25519.mechanisms = vec!["CKM_ECDH".to_string(), "CKM_ED25519".to_string()];

        let ranked =
            rank_detected_tokens(&[weaker, ed25519_only.clone(), ed25519_and_x25519.clone()]);

        assert_eq!(ranked[0], ed25519_and_x25519);
        assert_eq!(ranked[1], ed25519_only);
        assert!(!ranked[2].supports_ed25519());
    }

    #[test]
    fn select_bootstrap_token_matches_requested_identity() {
        let requested = test_token();
        let mut distractor = requested.clone();
        distractor.slot = 7;
        distractor.serial = "different".to_string();

        let selected =
            select_bootstrap_token(&requested, &[distractor, requested.clone()]).unwrap();
        assert_eq!(selected, requested);
    }

    #[test]
    fn authenticate_bootstrap_session_refuses_missing_pin() {
        let requested = test_token();
        let pin = HardwareTokenPin::new("");
        let result = authenticate_bootstrap_session_with_driver(
            &requested,
            std::slice::from_ref(&requested),
            &pin,
            &MockSessionDriver::default(),
        );

        assert!(matches!(result, Err(TokenError::PinRequired)));
    }

    #[test]
    fn authenticate_bootstrap_session_refuses_unsupported_mechanism() {
        let mut requested = test_token();
        requested.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        let pin = HardwareTokenPin::new("123456");

        let result = authenticate_bootstrap_session_with_driver(
            &requested,
            std::slice::from_ref(&requested),
            &pin,
            &MockSessionDriver::default(),
        );

        assert!(matches!(
            result,
            Err(TokenError::UnsupportedMechanism(mechanism)) if mechanism.contains("Ed25519")
        ));
    }

    #[test]
    fn authenticate_bootstrap_session_returns_authenticated_session_and_closes_it() {
        let requested = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();

        let session = authenticate_bootstrap_session_with_driver(
            &requested,
            std::slice::from_ref(&requested),
            &pin,
            &driver,
        )
        .unwrap();

        assert_eq!(session.token(), &requested);
        assert_eq!(
            session.session_state(),
            AuthenticatedSessionState::ReadWriteUser
        );
        assert!(session.read_write());
        assert_eq!(driver.close_count(), 0);

        session.close().unwrap();
        assert_eq!(driver.close_count(), 1);
    }

    // ---- DetectedToken mechanism checks ----

    #[test]
    fn token_without_ed25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        assert!(!token.supports_ed25519());
    }

    #[test]
    fn token_supports_ed25519_via_eddsa() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_EDDSA".to_string()];
        assert!(token.supports_ed25519());
    }

    #[test]
    fn token_supports_x25519_via_ecdh() {
        let token = test_token();
        assert!(token.supports_x25519());
    }

    #[test]
    fn token_without_x25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        assert!(!token.supports_x25519());
    }

    #[test]
    fn token_supports_x25519_via_x25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_X25519".to_string()];
        assert!(token.supports_x25519());
    }

    #[test]
    fn token_empty_mechanisms() {
        let mut token = test_token();
        token.mechanisms = vec![];
        assert!(!token.supports_ed25519());
        assert!(!token.supports_x25519());
    }

    // ---- DetectedToken Display ----

    #[test]
    fn token_display_format() {
        let token = test_token();
        let display = format!("{token}");
        assert_eq!(display, "Test Token (Test Manufacturer) [slot 0]");
    }

    // ---- DetectedToken serde roundtrip ----

    #[test]
    fn token_serde_roundtrip() {
        let token = test_token();
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, restored);
    }

    // ---- TokenDetector ----

    #[test]
    fn detector_default_same_as_new() {
        let d1 = TokenDetector::new();
        let d2 = TokenDetector::default();
        assert_eq!(d1.provider_paths.len(), d2.provider_paths.len());
    }

    #[test]
    fn detector_from_provider_paths() {
        let providers = vec![PathBuf::from("/one.so"), PathBuf::from("/two.so")];
        let detector = TokenDetector::from_provider_paths(providers.clone());
        assert_eq!(detector.provider_paths, providers);
    }

    #[test]
    fn detector_add_provider() {
        let mut detector = TokenDetector::new();
        let original_count = detector.provider_paths.len();
        detector.add_provider(PathBuf::from("/custom/pkcs11.so"));
        assert_eq!(detector.provider_paths.len(), original_count + 1);
    }

    #[test]
    fn detector_detect_all_returns_empty_in_ci() {
        let detector = TokenDetector::new();
        let tokens = detector.detect_all();
        // No real PKCS#11 providers in CI
        assert!(tokens.is_empty());
    }

    #[test]
    fn detector_detect_fcp_compatible_returns_empty_in_ci() {
        let detector = TokenDetector::new();
        let tokens = detector.detect_fcp_compatible();
        assert!(tokens.is_empty());
    }

    #[test]
    fn detector_report_records_missing_provider() {
        let provider = PathBuf::from("/definitely/missing/pkcs11-provider.so");
        let detector = TokenDetector::from_provider_paths(vec![provider.clone()]);
        let report = detector.detect_report();

        assert!(!report.has_detected_tokens());
        assert!(report.all_tokens().is_empty());
        assert_eq!(report.providers.len(), 1);
        assert_eq!(report.providers[0].provider, provider);
        assert_eq!(report.providers[0].issues.len(), 1);
        assert_eq!(
            report.providers[0].issues[0].stage,
            DetectionStage::ProviderMissing
        );
    }

    #[test]
    fn detector_report_records_load_failure_for_non_library_file() {
        let dir = tempdir().unwrap();
        let provider = dir.path().join("not-a-library.txt");
        std::fs::write(&provider, "plain text").unwrap();

        let detector = TokenDetector::from_provider_paths(vec![provider.clone()]);
        let report = detector.detect_report();
        let issues = &report.providers[0].issues;

        assert!(report.all_tokens().is_empty());
        assert!(
            issues
                .iter()
                .any(|issue| issue.stage == DetectionStage::LoadProvider)
        );
        assert_eq!(issues[0].provider, provider);
    }

    #[test]
    fn token_detection_report_filters_fcp_compatible_tokens() {
        let mut incompatible = test_token();
        incompatible.mechanisms = vec!["CKM_RSA_PKCS".to_string()];

        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: PathBuf::from("/provider.so"),
                tokens: vec![test_token(), incompatible],
                issues: Vec::new(),
            }],
        };

        let compatible = report.fcp_compatible_tokens();
        assert_eq!(compatible.len(), 1);
        assert!(compatible[0].supports_ed25519());
    }

    #[test]
    fn token_detection_report_collects_issues() {
        let issue = DetectionIssue::new(
            Path::new("/provider.so"),
            DetectionStage::LoadProvider,
            None,
            "load failed",
        );
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: PathBuf::from("/provider.so"),
                tokens: Vec::new(),
                issues: vec![issue.clone()],
            }],
        };

        assert_eq!(report.issues(), vec![issue]);
    }

    // ---- MockTokenProvider ----

    #[test]
    fn mock_provider_default() {
        use mock::MockTokenProvider;
        let provider = MockTokenProvider::default();
        assert!(provider.list_tokens().is_empty());
    }

    #[test]
    fn mock_provider_sign_returns_64_bytes() {
        use mock::MockTokenProvider;
        let mut provider = MockTokenProvider::new();
        let token = test_token();
        provider.add_token(token.clone());
        let sig = provider.sign(&token, "1234", "test-key", b"data").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn mock_provider_multiple_tokens() {
        use mock::MockTokenProvider;
        let mut provider = MockTokenProvider::new();
        let mut t1 = test_token();
        t1.slot = 0;
        t1.label = "Token A".into();
        let mut t2 = test_token();
        t2.slot = 1;
        t2.label = "Token B".into();
        provider.add_token(t1);
        provider.add_token(t2);
        assert_eq!(provider.list_tokens().len(), 2);
    }

    // ---- TokenError Display ----

    #[test]
    fn token_error_display() {
        assert_eq!(
            TokenError::NoTokens.to_string(),
            "no hardware tokens detected"
        );
        assert!(
            TokenError::TokenNotFound("yubikey".into())
                .to_string()
                .contains("yubikey")
        );
        assert_eq!(TokenError::InvalidPin.to_string(), "invalid PIN");
        assert!(
            TokenError::KeyNotFound("owner".into())
                .to_string()
                .contains("owner")
        );
        assert!(
            TokenError::UnsupportedMechanism("RSA".into())
                .to_string()
                .contains("RSA")
        );
        assert!(
            TokenError::Pkcs11("init failed".into())
                .to_string()
                .contains("init failed")
        );
        assert_eq!(TokenError::Disconnected.to_string(), "token disconnected");
    }

    // ---- DetectedToken clone ----

    #[test]
    fn detected_token_clone() {
        let token = test_token();
        let cloned = token.clone();
        assert_eq!(token.provider, cloned.provider);
        assert_eq!(token.slot, cloned.slot);
        assert_eq!(token.label, cloned.label);
        assert_eq!(token.manufacturer, cloned.manufacturer);
        assert_eq!(token.serial, cloned.serial);
        assert_eq!(token.mechanisms, cloned.mechanisms);
    }

    // ---- DetectedToken debug ----

    #[test]
    fn detected_token_debug() {
        let token = test_token();
        let debug = format!("{token:?}");
        assert!(debug.contains("DetectedToken"));
        assert!(debug.contains("Test Token"));
        assert!(debug.contains("123456"));
    }

    // ---- DetectedToken with many mechanisms ----

    #[test]
    fn token_with_many_mechanisms() {
        let mut token = test_token();
        token.mechanisms = vec![
            "CKM_RSA_PKCS".to_string(),
            "CKM_ED25519".to_string(),
            "CKM_ECDH".to_string(),
            "CKM_AES_CBC".to_string(),
            "CKM_X25519".to_string(),
        ];
        assert!(token.supports_ed25519());
        assert!(token.supports_x25519());
    }

    // ---- Token Display with different slots ----

    #[test]
    fn token_display_different_slots() {
        let mut token = test_token();
        token.slot = 42;
        let display = format!("{token}");
        assert!(display.contains("[slot 42]"));
    }

    // ---- Token serde with empty mechanisms ----

    #[test]
    fn token_serde_roundtrip_empty_mechanisms() {
        let mut token = test_token();
        token.mechanisms = vec![];
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, restored);
        assert!(restored.mechanisms.is_empty());
    }

    // ---- TokenError Debug ----

    #[test]
    fn token_error_debug() {
        let err = TokenError::InvalidPin;
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidPin"));
    }

    #[test]
    fn token_error_disconnected_debug() {
        let err = TokenError::Disconnected;
        let debug = format!("{err:?}");
        assert!(debug.contains("Disconnected"));
    }

    // ---- TokenError is std::error::Error ----

    #[test]
    fn token_error_is_error_trait() {
        let err = TokenError::NoTokens;
        let _: &dyn std::error::Error = &err;
    }

    // ---- Token with unicode label ----

    #[test]
    fn token_unicode_label() {
        let mut token = test_token();
        token.label = "S\u{00e9}curit\u{00e9} Token".to_string();
        let display = format!("{token}");
        assert!(display.contains("S\u{00e9}curit\u{00e9}"));
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token.label, restored.label);
    }

    // ---- DetectedToken supports_ed25519 with partial match ----

    #[test]
    fn token_supports_ed25519_case_sensitive() {
        let mut token = test_token();
        token.mechanisms = vec!["ckm_ed25519".to_string()];
        // Mechanism check uses contains, which is case-sensitive
        assert!(!token.supports_ed25519());
    }

    #[test]
    fn token_supports_x25519_case_sensitive() {
        let mut token = test_token();
        token.mechanisms = vec!["ckm_x25519".to_string()];
        assert!(!token.supports_x25519());
    }

    // ---- DetectedToken with mixed mechanisms ----

    #[test]
    fn token_ed25519_but_not_x25519() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_ED25519".to_string()];
        assert!(token.supports_ed25519());
        assert!(!token.supports_x25519());
    }

    #[test]
    fn token_x25519_but_not_ed25519() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_X25519".to_string()];
        assert!(!token.supports_ed25519());
        assert!(token.supports_x25519());
    }

    // ---- DetectedToken serde with special chars ----

    #[test]
    fn token_serde_with_special_chars_in_serial() {
        let mut token = test_token();
        token.serial = "SN/2026-#001".to_string();
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token.serial, restored.serial);
    }

    // ---- DetectedToken PartialEq ----

    #[test]
    fn detected_token_eq_identical() {
        let t1 = test_token();
        let t2 = test_token();
        assert_eq!(t1, t2);
    }

    #[test]
    fn detected_token_ne_different_slot() {
        let t1 = test_token();
        let mut t2 = test_token();
        t2.slot = 99;
        assert_ne!(t1, t2);
    }

    #[test]
    fn detected_token_ne_different_serial() {
        let t1 = test_token();
        let mut t2 = test_token();
        t2.serial = "DIFFERENT".to_string();
        assert_ne!(t1, t2);
    }

    // ---- TokenError Debug for all variants ----

    #[test]
    fn token_error_debug_no_tokens() {
        let err = TokenError::NoTokens;
        let debug = format!("{err:?}");
        assert!(debug.contains("NoTokens"));
    }

    #[test]
    fn token_error_debug_pin_required() {
        let err = TokenError::PinRequired;
        let debug = format!("{err:?}");
        assert!(debug.contains("PinRequired"));
    }

    #[test]
    fn token_error_debug_token_not_found() {
        let err = TokenError::TokenNotFound("slot-3".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("TokenNotFound"));
        assert!(debug.contains("slot-3"));
    }

    #[test]
    fn token_error_debug_unsupported_mechanism() {
        let err = TokenError::UnsupportedMechanism("CKM_RSA".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("UnsupportedMechanism"));
    }

    #[test]
    fn token_error_debug_pkcs11() {
        let err = TokenError::Pkcs11("CKR_DEVICE_ERROR".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Pkcs11"));
    }

    #[test]
    fn detection_issue_serde_roundtrip() {
        let issue = DetectionIssue::new(
            Path::new("/provider.so"),
            DetectionStage::ReadMechanisms,
            Some(7),
            "mechanism enumeration failed",
        );
        let json = serde_json::to_string(&issue).unwrap();
        let restored: DetectionIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(issue, restored);
    }

    // ---- MockTokenProvider generate_keypair returns different keys ----

    #[test]
    fn mock_provider_generate_keypair_returns_32_bytes() {
        use mock::MockTokenProvider;
        let provider = MockTokenProvider::new();
        let token = test_token();
        let key = provider.generate_keypair(&token, "0000", "key1").unwrap();
        assert_eq!(key.len(), 32);
    }

    // ---- Multi-provider discovery report ----

    #[test]
    fn token_detection_report_multi_provider_aggregates_tokens_and_issues() {
        let mut good_token = test_token();
        good_token.provider = PathBuf::from("/good/provider.so");

        let issue = DetectionIssue::new(
            Path::new("/bad/provider.so"),
            DetectionStage::ProviderMissing,
            None,
            "provider not found",
        );

        let report = TokenDetectionReport {
            providers: vec![
                ProviderDetectionResult {
                    provider: PathBuf::from("/good/provider.so"),
                    tokens: vec![good_token.clone()],
                    issues: Vec::new(),
                },
                ProviderDetectionResult {
                    provider: PathBuf::from("/bad/provider.so"),
                    tokens: Vec::new(),
                    issues: vec![issue],
                },
            ],
        };

        assert_eq!(report.all_tokens().len(), 1);
        assert_eq!(report.all_tokens()[0], good_token);
        assert!(report.has_detected_tokens());
        assert_eq!(report.issues().len(), 1);
        assert_eq!(report.fcp_compatible_tokens().len(), 1);
    }

    // ---- Token identity matching edge cases ----

    #[test]
    fn token_identity_matches_unknown_field_wildcards() {
        let mut requested = test_token();
        requested.label = "unknown".to_string();

        let candidate = test_token();

        // "unknown" in requested should match any candidate label
        assert!(token_identity_matches(&requested, &candidate));
    }

    #[test]
    fn token_identity_matches_unknown_candidate_wildcards() {
        let requested = test_token();

        let mut candidate = test_token();
        candidate.manufacturer = "unknown".to_string();

        // "unknown" in candidate should also wildcard
        assert!(token_identity_matches(&requested, &candidate));
    }

    #[test]
    fn token_identity_does_not_match_different_slot() {
        let requested = test_token();
        let mut candidate = test_token();
        candidate.slot = 99;

        assert!(!token_identity_matches(&requested, &candidate));
    }

    #[test]
    fn token_identity_does_not_match_different_provider() {
        let requested = test_token();
        let mut candidate = test_token();
        candidate.provider = PathBuf::from("/other/provider.so");

        assert!(!token_identity_matches(&requested, &candidate));
    }

    // ---- AuthenticatedSessionState coverage ----

    #[test]
    fn authenticated_session_state_display_all_variants() {
        assert_eq!(AuthenticatedSessionState::ReadOnlyPublic.to_string(), "ro-public");
        assert_eq!(AuthenticatedSessionState::ReadOnlyUser.to_string(), "ro-user");
        assert_eq!(AuthenticatedSessionState::ReadWritePublic.to_string(), "rw-public");
        assert_eq!(AuthenticatedSessionState::ReadWriteUser.to_string(), "rw-user");
        assert_eq!(
            AuthenticatedSessionState::ReadWriteSecurityOfficer.to_string(),
            "rw-so"
        );
    }

    #[test]
    fn authenticated_session_state_serde_roundtrip_all_variants() {
        let variants = [
            AuthenticatedSessionState::ReadOnlyPublic,
            AuthenticatedSessionState::ReadOnlyUser,
            AuthenticatedSessionState::ReadWritePublic,
            AuthenticatedSessionState::ReadWriteUser,
            AuthenticatedSessionState::ReadWriteSecurityOfficer,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let restored: AuthenticatedSessionState = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, restored);
        }
    }

    // ---- TokenDetectionReport serde roundtrip ----

    #[test]
    fn token_detection_report_serde_roundtrip() {
        let issue = DetectionIssue::new(
            Path::new("/missing.so"),
            DetectionStage::ProviderMissing,
            None,
            "not found",
        );
        let report = TokenDetectionReport {
            providers: vec![
                ProviderDetectionResult {
                    provider: PathBuf::from("/good.so"),
                    tokens: vec![test_token()],
                    issues: Vec::new(),
                },
                ProviderDetectionResult {
                    provider: PathBuf::from("/missing.so"),
                    tokens: Vec::new(),
                    issues: vec![issue],
                },
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let restored: TokenDetectionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.providers.len(), 2);
        assert_eq!(restored.all_tokens().len(), 1);
        assert_eq!(restored.issues().len(), 1);
    }

    // ---- Select bootstrap token edge cases ----

    #[test]
    fn select_bootstrap_token_empty_candidates_returns_no_tokens() {
        let result = select_bootstrap_token(&test_token(), &[]);
        assert!(matches!(result, Err(TokenError::NoTokens)));
    }

    #[test]
    fn select_bootstrap_token_not_found_returns_descriptive_error() {
        let requested = test_token();
        let mut other = test_token();
        other.slot = 99;
        other.serial = "different".to_string();
        other.provider = PathBuf::from("/other.so");

        let result = select_bootstrap_token(&requested, &[other]);
        assert!(matches!(result, Err(TokenError::TokenNotFound(_))));
    }

    // ---- HardwareTokenPin ----

    #[test]
    fn hardware_token_pin_is_empty_for_empty_string() {
        let pin = HardwareTokenPin::new("");
        assert!(pin.is_empty());
    }

    #[test]
    fn hardware_token_pin_is_not_empty_for_real_pin() {
        let pin = HardwareTokenPin::new("123456");
        assert!(!pin.is_empty());
    }

    // ---- DetectionStage serde roundtrip ----

    #[test]
    fn detection_stage_serde_roundtrip_all_variants() {
        let stages = [
            DetectionStage::ProviderMissing,
            DetectionStage::LoadProvider,
            DetectionStage::InitializeProvider,
            DetectionStage::EnumerateSlots,
            DetectionStage::NormalizeSlotId,
            DetectionStage::ReadTokenInfo,
            DetectionStage::ReadMechanisms,
            DetectionStage::FinalizeProvider,
        ];
        for stage in &stages {
            let json = serde_json::to_string(stage).unwrap();
            let restored: DetectionStage = serde_json::from_str(&json).unwrap();
            assert_eq!(*stage, restored);
        }
    }

    // ---- Session drop does not panic without close action ----

    #[test]
    fn authenticated_session_drop_without_close_action_does_not_panic() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        drop(session); // Should not panic
    }

    // ---- Session timeout ----

    #[test]
    fn session_not_expired_immediately() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        assert!(!session.is_expired());
        session.check_alive().unwrap();
    }

    #[test]
    fn session_expired_after_zero_timeout() {
        let mut session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        session.set_timeout(Duration::ZERO);
        // Even Duration::ZERO may not trigger immediately on fast CPUs,
        // but with a tiny sleep it definitely will.
        std::thread::sleep(Duration::from_millis(1));
        assert!(session.is_expired());
        assert!(matches!(
            session.check_alive(),
            Err(TokenError::SessionExpired { .. })
        ));
    }

    #[test]
    fn session_default_timeout_is_5_minutes() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        assert_eq!(session.timeout(), Duration::from_secs(300));
    }

    #[test]
    fn session_custom_timeout() {
        let mut session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        session.set_timeout(Duration::from_secs(60));
        assert_eq!(session.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn session_elapsed_is_nonnegative() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        assert!(session.elapsed() < Duration::from_secs(5));
    }

    // ---- SessionExpired error display ----

    #[test]
    fn session_expired_error_display() {
        let err = TokenError::SessionExpired {
            elapsed: Duration::from_secs(301),
            timeout: Duration::from_secs(300),
        };
        let display = err.to_string();
        assert!(display.contains("expired"));
        assert!(display.contains("301"));
    }

    #[test]
    fn session_expired_error_debug() {
        let err = TokenError::SessionExpired {
            elapsed: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("SessionExpired"));
    }

    // ---- select_and_authenticate state machine ----

    #[test]
    fn select_and_authenticate_returns_outcome_with_session() {
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };

        let outcome = select_and_authenticate(&token, &pin, &report, &driver, None).unwrap();
        assert_eq!(outcome.selected_token, token);
        assert_eq!(
            outcome.session.session_state(),
            AuthenticatedSessionState::ReadWriteUser
        );
        assert!(outcome.session.read_write());
        assert!(!outcome.session.is_expired());
        outcome.session.close().unwrap();
        assert_eq!(driver.close_count(), 1);
    }

    #[test]
    fn select_and_authenticate_applies_custom_timeout() {
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };

        let outcome = select_and_authenticate(
            &token,
            &pin,
            &report,
            &driver,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        assert_eq!(outcome.session.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn select_and_authenticate_refuses_empty_pin() {
        let token = test_token();
        let pin = HardwareTokenPin::new("");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport::default();

        let result = select_and_authenticate(&token, &pin, &report, &driver, None);
        assert!(matches!(result, Err(TokenError::PinRequired)));
    }

    #[test]
    fn select_and_authenticate_refuses_missing_token() {
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport::default();

        let result = select_and_authenticate(&token, &pin, &report, &driver, None);
        assert!(matches!(result, Err(TokenError::NoTokens)));
    }

    #[test]
    fn select_and_authenticate_refuses_incompatible_token() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };

        let result = select_and_authenticate(&token, &pin, &report, &driver, None);
        assert!(matches!(result, Err(TokenError::UnsupportedMechanism(_))));
    }

    #[test]
    fn select_and_authenticate_picks_best_from_multiple_candidates() {
        let mut weaker = test_token();
        weaker.slot = 1;
        weaker.serial = "weak".to_string();
        weaker.mechanisms = vec!["CKM_RSA_PKCS".to_string()];

        let strong = test_token(); // has Ed25519 + ECDH

        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: strong.provider.clone(),
                tokens: vec![weaker, strong.clone()],
                issues: Vec::new(),
            }],
        };

        let outcome =
            select_and_authenticate(&strong, &pin, &report, &driver, None).unwrap();
        assert_eq!(outcome.selected_token, strong);
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
            _pin: &HardwareTokenPin,
        ) -> Result<AuthenticatedTokenSession, TokenError> {
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
    }
}
