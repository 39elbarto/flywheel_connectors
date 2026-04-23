//! Hardware token detection and integration.
//!
//! This module provides cross-platform support for detecting and using
//! hardware security modules (HSMs) and smart cards via PKCS#11.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use x509_parser::parse_x509_certificate;
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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HardwareTokenPin {
    value: String,
    // Compare on a fixed-width digest so length mismatches do not short-circuit.
    digest: [u8; 32],
}

impl PartialEq for HardwareTokenPin {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.digest.ct_eq(&other.digest).into()
    }
}

impl Eq for HardwareTokenPin {}

impl HardwareTokenPin {
    /// Create a new hardware-token PIN wrapper.
    #[must_use]
    pub fn new(pin: impl Into<String>) -> Self {
        let value = pin.into();
        let digest = *blake3::hash(value.as_bytes()).as_bytes();
        Self { value, digest }
    }

    /// Whether the provided PIN is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn to_auth_pin(&self) -> AuthPin {
        AuthPin::new(self.value.clone().into())
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

/// Driver abstraction for opening authenticated hardware-token sessions
/// and enumerating certificate/key objects.
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

    /// Enumerate all certificate objects visible in the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns a token error if the PKCS#11 find-objects call fails.
    fn enumerate_certificates(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenCertificate>, TokenError>;

    /// Enumerate all private key objects visible in the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns a token error if the PKCS#11 find-objects call fails.
    fn enumerate_keys(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenKeyInfo>, TokenError>;
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
        if pin.is_empty() {
            return Err(TokenError::PinRequired);
        }

        let (pkcs11, owns_initialization) = acquire_provider_context(&token.provider)?;

        let slot = Slot::try_from(u64::from(token.slot))
            .map_err(|err| TokenError::Pkcs11(err.to_string()))?;
        let session = match pkcs11.open_rw_session(slot) {
            Ok(session) => session,
            Err(err) => {
                let _ = finalize_pkcs11_context(&token.provider, pkcs11, owns_initialization);
                return Err(map_pkcs11_error(err));
            }
        };

        let auth_pin = pin.to_auth_pin();
        match session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(err) => {
                cleanup_failed_session(&token.provider, session, pkcs11, owns_initialization);
                return Err(map_pkcs11_error(err));
            }
        }

        let session_info = match session.get_session_info() {
            Ok(session_info) => session_info,
            Err(err) => {
                cleanup_failed_session(&token.provider, session, pkcs11, owns_initialization);
                return Err(map_pkcs11_error(err));
            }
        };

        let session_state = AuthenticatedSessionState::from(session_info.session_state());
        let read_write = session_info.read_write();
        let provider = token.provider.clone();

        Ok(AuthenticatedTokenSession::with_close_action(
            token.clone(),
            session_state,
            read_write,
            move || {
                let close_result = close_pkcs11_session(session, session_state);
                let finalize_result =
                    finalize_pkcs11_context(&provider, pkcs11, owns_initialization);
                close_result.and(finalize_result)
            },
        ))
    }

    fn enumerate_certificates(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenCertificate>, TokenError> {
        if pin.is_empty() {
            return Err(TokenError::PinRequired);
        }

        let enumeration = open_enumeration_session(token, pin)?;
        let template = [Attribute::Class(ObjectClass::CERTIFICATE)];
        let handles = enumeration
            .session()
            .find_objects(&template)
            .map_err(map_pkcs11_error)?;

        let mut certs = Vec::new();
        for handle in handles {
            match read_certificate_object(enumeration.session(), handle) {
                Ok(cert) => certs.push(cert),
                Err(err) => {
                    tracing::warn!(
                        handle = ?handle,
                        error = %err,
                        "Skipping unreadable certificate object"
                    );
                }
            }
        }

        let _ = enumeration.close();
        Ok(certs)
    }

    fn enumerate_keys(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenKeyInfo>, TokenError> {
        if pin.is_empty() {
            return Err(TokenError::PinRequired);
        }

        let enumeration = open_enumeration_session(token, pin)?;
        let template = [Attribute::Class(ObjectClass::PRIVATE_KEY)];
        let handles = enumeration
            .session()
            .find_objects(&template)
            .map_err(map_pkcs11_error)?;

        let mut keys = Vec::new();
        for handle in handles {
            match read_key_object(enumeration.session(), handle) {
                Ok(key) => keys.push(key),
                Err(err) => {
                    tracing::warn!(
                        handle = ?handle,
                        error = %err,
                        "Skipping unreadable key object"
                    );
                }
            }
        }

        let _ = enumeration.close();
        Ok(keys)
    }
}

/// RAII wrapper for a PIN-authenticated enumeration session (br-tcp0f).
///
/// Pre-tcp0f the enumeration path opened a read-write user session via
/// PKCS#11 `C_Login`, returned the bare `Session`, and the callers invoked
/// only `session.close()` afterwards — never `C_Logout` and never
/// `C_Finalize`. The token was therefore left in an authenticated state
/// and the provider context initialized after the temporary PIN-authenticated
/// browse step, extending the lifetime of authenticated hardware-token
/// access without re-prompting for the PIN.
///
/// This wrapper owns the PKCS#11 context + session
/// and routes teardown through [`close_pkcs11_session`] (logout + close)
/// and [`finalize_pkcs11_context`]. An [`EnumerationSession::close`]
/// consuming method is the preferred exit path; [`Drop`] runs the same
/// cleanup on panic or early return as a defense-in-depth backstop.
struct EnumerationSession {
    provider: PathBuf,
    pkcs11: Option<Pkcs11>,
    session: Option<Session>,
    owns_initialization: bool,
}

impl EnumerationSession {
    fn session(&self) -> &Session {
        self.session
            .as_ref()
            .expect("enumeration session is still open")
    }

    fn close(mut self) -> Result<(), TokenError> {
        self.run_cleanup()
    }

    fn run_cleanup(&mut self) -> Result<(), TokenError> {
        let session = self.session.take();
        let pkcs11 = self.pkcs11.take();
        match (session, pkcs11) {
            (Some(session), Some(pkcs11)) => {
                // Login was performed as UserType::User on a read-write
                // session (see `open_enumeration_session`), so the state
                // at close time is always ReadWriteUser.
                let close_result =
                    close_pkcs11_session(session, AuthenticatedSessionState::ReadWriteUser);
                let finalize_result = finalize_pkcs11_context(
                    &self.provider,
                    pkcs11,
                    self.owns_initialization,
                );
                close_result.and(finalize_result)
            }
            _ => Ok(()),
        }
    }
}

impl Drop for EnumerationSession {
    fn drop(&mut self) {
        if self.session.is_none() && self.pkcs11.is_none() {
            return;
        }
        if let Err(err) = self.run_cleanup() {
            tracing::warn!(
                component = "fcp_bootstrap.hardware_token",
                error = %err,
                "EnumerationSession dropped without close(); best-effort cleanup failed"
            );
        } else {
            tracing::warn!(
                component = "fcp_bootstrap.hardware_token",
                "EnumerationSession dropped without close(); fell back to best-effort cleanup"
            );
        }
    }
}

/// Open a temporary authenticated session for object enumeration.
///
/// The returned [`EnumerationSession`] carries the PKCS#11 context
/// and read-write user session so that teardown
/// (logout + close + finalize) always runs, whether via
/// [`EnumerationSession::close`] or [`Drop`]. See br-tcp0f.
fn open_enumeration_session(
    token: &DetectedToken,
    pin: &HardwareTokenPin,
) -> Result<EnumerationSession, TokenError> {
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let (pkcs11, owns_initialization) = acquire_provider_context(&token.provider)?;

    let slot = match Slot::try_from(u64::from(token.slot)) {
        Ok(slot) => slot,
        Err(err) => {
            let _ = finalize_pkcs11_context(&token.provider, pkcs11, owns_initialization);
            return Err(TokenError::Pkcs11(err.to_string()));
        }
    };

    let session = match pkcs11.open_rw_session(slot) {
        Ok(session) => session,
        Err(err) => {
            let _ = finalize_pkcs11_context(&token.provider, pkcs11, owns_initialization);
            return Err(map_pkcs11_error(err));
        }
    };

    let auth_pin = pin.to_auth_pin();
    match session.login(UserType::User, Some(&auth_pin)) {
        Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(err) => {
            cleanup_failed_session(&token.provider, session, pkcs11, owns_initialization);
            return Err(map_pkcs11_error(err));
        }
    }

    Ok(EnumerationSession {
        provider: token.provider.clone(),
        pkcs11: Some(pkcs11),
        session: Some(session),
        owns_initialization,
    })
}

/// Read a certificate object's attributes from its handle.
fn read_certificate_object(
    session: &Session,
    handle: ObjectHandle,
) -> Result<TokenCertificate, TokenError> {
    let attrs = session
        .get_attributes(
            handle,
            &[
                AttributeType::Label,
                AttributeType::Id,
                AttributeType::Value,
                AttributeType::Subject,
                AttributeType::Issuer,
            ],
        )
        .map_err(map_pkcs11_error)?;

    let mut label = String::new();
    let mut id = Vec::new();
    let mut der_bytes = Vec::new();
    let mut subject = String::new();
    let mut issuer = String::new();

    for attr in attrs {
        match attr {
            Attribute::Label(v) => label = String::from_utf8_lossy(&v).into_owned(),
            Attribute::Id(v) => id = v,
            Attribute::Value(v) => der_bytes = v,
            Attribute::Subject(v) => {
                subject = String::from_utf8_lossy(&v).into_owned();
            }
            Attribute::Issuer(v) => {
                issuer = String::from_utf8_lossy(&v).into_owned();
            }
            _ => {}
        }
    }

    // Heuristic: if subject == issuer the certificate is likely self-signed / CA.
    // CKA_CERTIFICATE_CATEGORY is not available in our cryptoki version.
    let is_ca = !subject.is_empty() && subject == issuer;

    Ok(TokenCertificate {
        label,
        id,
        der_bytes,
        subject,
        issuer,
        is_ca,
    })
}

/// Read a private key object's attributes from its handle.
fn read_key_object(session: &Session, handle: ObjectHandle) -> Result<TokenKeyInfo, TokenError> {
    let attrs = session
        .get_attributes(
            handle,
            &[
                AttributeType::Label,
                AttributeType::Id,
                AttributeType::KeyType,
                AttributeType::Sign,
                AttributeType::Derive,
            ],
        )
        .map_err(map_pkcs11_error)?;

    let mut label = String::new();
    let mut id = Vec::new();
    let mut key_type = TokenKeyType::Other(0);
    let mut can_sign = false;
    let mut can_derive = false;

    for attr in attrs {
        match attr {
            Attribute::Label(v) => label = String::from_utf8_lossy(&v).into_owned(),
            Attribute::Id(v) => id = v,
            Attribute::KeyType(kt) => {
                key_type = map_cryptoki_key_type(kt);
            }
            Attribute::Sign(v) => can_sign = v,
            Attribute::Derive(v) => can_derive = v,
            _ => {}
        }
    }

    Ok(TokenKeyInfo {
        label,
        id,
        key_type,
        can_sign,
        can_derive,
    })
}

/// Map a cryptoki `KeyType` to our `TokenKeyType`.
fn map_cryptoki_key_type(kt: KeyType) -> TokenKeyType {
    if kt == KeyType::EC_EDWARDS {
        TokenKeyType::Ed25519
    } else if kt == KeyType::EC_MONTGOMERY {
        TokenKeyType::X25519
    } else if kt == KeyType::EC {
        // EC could be P-256 or P-384; without OID inspection we classify as P-256.
        TokenKeyType::EcdsaP256
    } else if kt == KeyType::RSA {
        TokenKeyType::Rsa
    } else {
        TokenKeyType::Other(0)
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

// ── Certificate and key enumeration types ─────────────────────────────

/// The cryptographic key type of a PKCS#11 object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKeyType {
    /// `Ed25519` signing key (`EdDSA`).
    Ed25519,
    /// X25519 key agreement.
    X25519,
    /// ECDSA with P-256 curve.
    EcdsaP256,
    /// ECDSA with P-384 curve.
    EcdsaP384,
    /// RSA key.
    Rsa,
    /// Unknown or unsupported key type.
    Other(u32),
}

impl fmt::Display for TokenKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::X25519 => write!(f, "X25519"),
            Self::EcdsaP256 => write!(f, "ECDSA-P256"),
            Self::EcdsaP384 => write!(f, "ECDSA-P384"),
            Self::Rsa => write!(f, "RSA"),
            Self::Other(id) => write!(f, "Other({id})"),
        }
    }
}

/// A certificate object discovered on a hardware token.
///
/// Abstracts away PKCS#11 object handles so downstream consumers
/// do not need provider-specific trivia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCertificate {
    /// Human-readable label assigned to the certificate object.
    pub label: String,
    /// Opaque PKCS#11 object identifier (`CKA_ID`).
    pub id: Vec<u8>,
    /// DER-encoded X.509 certificate bytes (`CKA_VALUE`).
    pub der_bytes: Vec<u8>,
    /// Certificate subject (common name or full DN string).
    pub subject: String,
    /// Certificate issuer (common name or full DN string).
    pub issuer: String,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
}

impl fmt::Display for TokenCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_hex = hex::encode(&self.id);
        if self.is_ca {
            write!(f, "{} (CA, id={})", self.label, id_hex)
        } else {
            write!(f, "{} (id={})", self.label, id_hex)
        }
    }
}

/// A private key discovered on a hardware token.
///
/// The actual key material never leaves the token — this struct
/// carries only metadata needed for selection and matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenKeyInfo {
    /// Human-readable label.
    pub label: String,
    /// Opaque PKCS#11 object identifier (`CKA_ID`), used to match
    /// certificates with their corresponding private keys.
    pub id: Vec<u8>,
    /// The key type.
    pub key_type: TokenKeyType,
    /// Whether the key supports signing operations.
    pub can_sign: bool,
    /// Whether the key supports key derivation / agreement.
    pub can_derive: bool,
}

impl fmt::Display for TokenKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_hex = hex::encode(&self.id);
        write!(f, "{} ({}, id={})", self.label, self.key_type, id_hex)
    }
}

/// A matched certificate–private-key pair on a hardware token.
///
/// The pairing is done by matching the PKCS#11 `CKA_ID` attribute
/// between the certificate and private key objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateKeyPair {
    /// The certificate.
    pub certificate: TokenCertificate,
    /// The matching private key metadata.
    pub key: TokenKeyInfo,
}

impl fmt::Display for CertificateKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cert={} key={}", self.certificate.label, self.key)
    }
}

/// Validated cryptographic material ready for provisioning handoff.
///
/// This is the typed boundary between hardware-token bootstrap and
/// the provisioning layer.  It carries enough information to proceed
/// with enrollment without exposing PKCS#11 session internals.
#[derive(Debug, Clone)]
pub struct ProvisioningMaterial {
    /// The selected certificate–key pair.
    pub pair: CertificateKeyPair,
    /// The token that holds the key material.
    pub token: DetectedToken,
    /// All candidate pairs that were considered (for audit logs).
    pub candidates_considered: usize,
    /// Human-readable reason for selecting this pair.
    pub selection_reason: String,
}

impl fmt::Display for ProvisioningMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProvisioningMaterial({}, selected from {} candidates: {})",
            self.pair, self.candidates_considered, self.selection_reason
        )
    }
}

/// Reason why certificate selection could not produce provisioning material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSelectionRefusal {
    /// No certificates found on the token.
    NoCertificates,
    /// No private keys found on the token.
    NoKeys,
    /// Certificates exist but none have a matching private key.
    NoMatchingKeyPair,
    /// Matching pairs exist but none have an FCP-compatible key type.
    NoCompatibleKeyType {
        /// The key types that were found.
        found: Vec<TokenKeyType>,
    },
    /// Multiple ambiguous matches with no deterministic winner.
    AmbiguousSelection {
        /// The number of equally-ranked candidates.
        count: usize,
    },
}

impl fmt::Display for CertificateSelectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificates => write!(f, "no certificates found on token"),
            Self::NoKeys => write!(f, "no private keys found on token"),
            Self::NoMatchingKeyPair => {
                write!(f, "no certificate has a matching private key on this token")
            }
            Self::NoCompatibleKeyType { found } => {
                let types: Vec<_> = found.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "no FCP-compatible key type found (have: {})",
                    types.join(", ")
                )
            }
            Self::AmbiguousSelection { count } => {
                write!(
                    f,
                    "{count} equally-ranked certificate candidates; cannot select deterministically"
                )
            }
        }
    }
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

// ── Certificate selection and provisioning handoff ────────────────────

/// Match certificates with their private keys by `CKA_ID`.
#[must_use]
pub fn match_certificate_key_pairs(
    certs: &[TokenCertificate],
    keys: &[TokenKeyInfo],
) -> Vec<CertificateKeyPair> {
    let mut pairs = Vec::new();
    for cert in certs {
        if cert.is_ca || cert.id.is_empty() {
            continue;
        }
        for key in keys {
            if key.id == cert.id {
                pairs.push(CertificateKeyPair {
                    certificate: cert.clone(),
                    key: key.clone(),
                });
                break; // one key per cert
            }
        }
    }
    pairs
}

/// FCP-compatible key type preference: Ed25519 > X25519 > ECDSA-P256 > ECDSA-P384.
/// RSA and unknown types are not compatible.
const fn fcp_key_type_rank(kt: TokenKeyType) -> Option<u8> {
    match kt {
        TokenKeyType::Ed25519 => Some(0),
        TokenKeyType::X25519 => Some(1),
        TokenKeyType::EcdsaP256 => Some(2),
        TokenKeyType::EcdsaP384 => Some(3),
        TokenKeyType::Rsa | TokenKeyType::Other(_) => None,
    }
}

/// Select the best certificate–key pair for FCP provisioning.
///
/// Selection rules:
/// 1. Only pairs with FCP-compatible key types are considered.
/// 2. Ed25519 is preferred, then X25519, then ECDSA curves.
/// 3. Among equal key types, signing-capable keys are preferred.
/// 4. Final tiebreak: lexicographic on (label, id) for determinism.
///
/// # Errors
///
/// Returns a typed `TokenError::CertificateSelectionFailed` with the
/// specific refusal reason if no suitable pair exists.
pub(crate) fn select_certificate_for_provisioning<D: HardwareTokenSessionDriver>(
    token: &DetectedToken,
    pin: &HardwareTokenPin,
    driver: &D,
) -> Result<ProvisioningMaterial, TokenError> {
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let certs = driver.enumerate_certificates(token, pin)?;
    if certs.is_empty() {
        return Err(TokenError::CertificateSelectionFailed(
            CertificateSelectionRefusal::NoCertificates,
        ));
    }

    let keys = driver.enumerate_keys(token, pin)?;
    if keys.is_empty() {
        return Err(TokenError::CertificateSelectionFailed(
            CertificateSelectionRefusal::NoKeys,
        ));
    }

    tracing::info!(
        certs = certs.len(),
        keys = keys.len(),
        "Enumerating certificate-key pairs for provisioning"
    );

    let pairs = match_certificate_key_pairs(&certs, &keys);
    if pairs.is_empty() {
        return Err(TokenError::CertificateSelectionFailed(
            CertificateSelectionRefusal::NoMatchingKeyPair,
        ));
    }

    // Filter to FCP-compatible key types.
    let mut compatible: Vec<_> = pairs
        .iter()
        .filter(|p| fcp_key_type_rank(p.key.key_type).is_some())
        .collect();

    if compatible.is_empty() {
        let found: Vec<_> = pairs.iter().map(|p| p.key.key_type).collect();
        return Err(TokenError::CertificateSelectionFailed(
            CertificateSelectionRefusal::NoCompatibleKeyType { found },
        ));
    }

    // Sort by preference: key type rank, then signing capability, then deterministic tiebreak.
    compatible.sort_by(|a, b| {
        let rank_a = fcp_key_type_rank(a.key.key_type).unwrap_or(u8::MAX);
        let rank_b = fcp_key_type_rank(b.key.key_type).unwrap_or(u8::MAX);
        rank_a
            .cmp(&rank_b)
            .then_with(|| b.key.can_sign.cmp(&a.key.can_sign))
            .then_with(|| a.certificate.label.cmp(&b.certificate.label))
            .then_with(|| a.key.id.cmp(&b.key.id))
    });

    let best = compatible[0];
    let candidates_considered = compatible.len();

    let selection_reason = format!(
        "key type {} ranked best among {} compatible pair(s)",
        best.key.key_type, candidates_considered
    );

    tracing::info!(
        selected_cert = %best.certificate,
        selected_key = %best.key,
        candidates = candidates_considered,
        reason = %selection_reason,
        "Certificate selected for provisioning"
    );

    Ok(ProvisioningMaterial {
        pair: best.clone(),
        token: token.clone(),
        candidates_considered,
        selection_reason,
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

fn cleanup_failed_session(
    provider: &Path,
    session: Session,
    pkcs11: Pkcs11,
    owns_initialization: bool,
) {
    let _ = session.close();
    let _ = finalize_pkcs11_context(provider, pkcs11, owns_initialization);
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

fn acquire_provider_context(provider: &Path) -> Result<(Pkcs11, bool), TokenError> {
    let mut sessions = provider_session_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let pkcs11 = Pkcs11::new(provider).map_err(map_pkcs11_error)?;
    let owns_initialization = match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => true,
        Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => false,
        Err(err) => return Err(map_pkcs11_error(err)),
    };

    *sessions.entry(provider.to_path_buf()).or_insert(0) += 1;
    Ok((pkcs11, owns_initialization))
}

fn finalize_pkcs11_context(
    provider: &Path,
    pkcs11: Pkcs11,
    owns_initialization: bool,
) -> Result<(), TokenError> {
    let mut sessions = provider_session_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let provider_key = provider.to_path_buf();

    let should_finalize = {
        let active_sessions = sessions.entry(provider_key.clone()).or_insert(0);
        if *active_sessions > 0 {
            *active_sessions -= 1;
        }
        owns_initialization && *active_sessions == 0
    };

    let finalize_result = if should_finalize {
        pkcs11.finalize().map_err(map_pkcs11_error)
    } else {
        Ok(())
    };

    if sessions.get(&provider_key).copied().unwrap_or_default() == 0 {
        sessions.remove(&provider_key);
    }

    finalize_result
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

    /// Certificate selection failed — no suitable identity on this token.
    #[error("certificate selection failed: {0}")]
    CertificateSelectionFailed(CertificateSelectionRefusal),

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

fn provider_session_registry() -> &'static Mutex<HashMap<PathBuf, usize>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
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
    fn hardware_token_pin_equality_uses_fixed_width_digest() {
        let short = HardwareTokenPin::new("1");
        let long = HardwareTokenPin::new("123456");
        let long_again = HardwareTokenPin::new("123456");

        assert_eq!(short.digest.len(), 32);
        assert_eq!(long.digest.len(), 32);
        assert_eq!(long, long_again);
        assert_ne!(short, long);
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
        assert_eq!(
            AuthenticatedSessionState::ReadOnlyPublic.to_string(),
            "ro-public"
        );
        assert_eq!(
            AuthenticatedSessionState::ReadOnlyUser.to_string(),
            "ro-user"
        );
        assert_eq!(
            AuthenticatedSessionState::ReadWritePublic.to_string(),
            "rw-public"
        );
        assert_eq!(
            AuthenticatedSessionState::ReadWriteUser.to_string(),
            "rw-user"
        );
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

        let outcome = select_and_authenticate(&strong, &pin, &report, &driver, None).unwrap();
        assert_eq!(outcome.selected_token, strong);
    }

    #[derive(Default)]
    struct MockSessionDriver {
        close_count: Arc<AtomicUsize>,
        certs: Arc<Mutex<Vec<TokenCertificate>>>,
        keys: Arc<Mutex<Vec<TokenKeyInfo>>>,
    }

    impl MockSessionDriver {
        fn close_count(&self) -> usize {
            self.close_count.load(Ordering::SeqCst)
        }

        fn with_certs_and_keys(certs: Vec<TokenCertificate>, keys: Vec<TokenKeyInfo>) -> Self {
            Self {
                close_count: Arc::new(AtomicUsize::new(0)),
                certs: Arc::new(Mutex::new(certs)),
                keys: Arc::new(Mutex::new(keys)),
            }
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

        fn enumerate_certificates(
            &self,
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenCertificate>, TokenError> {
            Ok(self.certs.lock().unwrap().clone())
        }

        fn enumerate_keys(
            &self,
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenKeyInfo>, TokenError> {
            Ok(self.keys.lock().unwrap().clone())
        }
    }

    // ── Test helpers for certificate selection ───────────────────────────

    fn test_cert(label: &str, id: &[u8]) -> TokenCertificate {
        TokenCertificate {
            label: label.to_string(),
            id: id.to_vec(),
            der_bytes: vec![0x30, 0x82], // minimal DER stub
            subject: format!("CN={label}"),
            issuer: "CN=TestCA".to_string(),
            is_ca: false,
        }
    }

    fn test_key(label: &str, id: &[u8], key_type: TokenKeyType) -> TokenKeyInfo {
        TokenKeyInfo {
            label: label.to_string(),
            id: id.to_vec(),
            key_type,
            can_sign: true,
            can_derive: false,
        }
    }

    // ── Certificate/key type tests ──────────────────────────────────────

    #[test]
    fn token_key_type_display_all_variants() {
        assert_eq!(TokenKeyType::Ed25519.to_string(), "Ed25519");
        assert_eq!(TokenKeyType::X25519.to_string(), "X25519");
        assert_eq!(TokenKeyType::EcdsaP256.to_string(), "ECDSA-P256");
        assert_eq!(TokenKeyType::EcdsaP384.to_string(), "ECDSA-P384");
        assert_eq!(TokenKeyType::Rsa.to_string(), "RSA");
        assert_eq!(TokenKeyType::Other(42).to_string(), "Other(42)");
    }

    #[test]
    fn token_key_type_serde_roundtrip() {
        let variants = [
            TokenKeyType::Ed25519,
            TokenKeyType::X25519,
            TokenKeyType::EcdsaP256,
            TokenKeyType::EcdsaP384,
            TokenKeyType::Rsa,
            TokenKeyType::Other(99),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let restored: TokenKeyType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn token_certificate_display() {
        let cert = test_cert("my-cert", &[0x01, 0x02]);
        assert!(cert.to_string().contains("my-cert"));
        assert!(cert.to_string().contains("0102"));
    }

    #[test]
    fn token_certificate_ca_display() {
        let mut cert = test_cert("root-ca", &[0xaa]);
        cert.is_ca = true;
        assert!(cert.to_string().contains("CA"));
    }

    #[test]
    fn token_key_info_display() {
        let key = test_key("my-key", &[0x01], TokenKeyType::Ed25519);
        let display = key.to_string();
        assert!(display.contains("my-key"));
        assert!(display.contains("Ed25519"));
    }

    #[test]
    fn certificate_key_pair_display() {
        let pair = CertificateKeyPair {
            certificate: test_cert("cert-1", &[0x01]),
            key: test_key("key-1", &[0x01], TokenKeyType::Ed25519),
        };
        let display = pair.to_string();
        assert!(display.contains("cert-1"));
        assert!(display.contains("key-1"));
    }

    #[test]
    fn provisioning_material_display() {
        let mat = ProvisioningMaterial {
            pair: CertificateKeyPair {
                certificate: test_cert("c", &[1]),
                key: test_key("k", &[1], TokenKeyType::Ed25519),
            },
            token: test_token(),
            candidates_considered: 3,
            selection_reason: "best key type".to_string(),
        };
        let display = mat.to_string();
        assert!(display.contains("3 candidates"));
    }

    // ── match_certificate_key_pairs ─────────────────────────────────────

    #[test]
    fn match_pairs_by_id() {
        let certs = vec![
            test_cert("c1", &[0x01]),
            test_cert("c2", &[0x02]),
            test_cert("c3", &[0x03]),
        ];
        let keys = vec![
            test_key("k2", &[0x02], TokenKeyType::Ed25519),
            test_key("k3", &[0x03], TokenKeyType::X25519),
        ];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].certificate.label, "c2");
        assert_eq!(pairs[1].certificate.label, "c3");
    }

    #[test]
    fn match_pairs_skips_ca_certs() {
        let mut ca = test_cert("ca", &[0x01]);
        ca.is_ca = true;
        let certs = vec![ca, test_cert("end", &[0x02])];
        let keys = vec![
            test_key("k1", &[0x01], TokenKeyType::Ed25519),
            test_key("k2", &[0x02], TokenKeyType::Ed25519),
        ];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].certificate.label, "end");
    }

    #[test]
    fn match_pairs_skips_empty_id_certs() {
        let certs = vec![test_cert("no-id", &[])];
        let keys = vec![test_key("k", &[], TokenKeyType::Ed25519)];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert!(pairs.is_empty());
    }

    #[test]
    fn match_pairs_no_overlap_returns_empty() {
        let certs = vec![test_cert("c", &[0x01])];
        let keys = vec![test_key("k", &[0x02], TokenKeyType::Ed25519)];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert!(pairs.is_empty());
    }

    // ── select_certificate_for_provisioning ─────────────────────────────

    #[test]
    fn select_cert_no_certs_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(vec![], vec![]);
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoCertificates)
        ));
    }

    #[test]
    fn select_cert_empty_pin_returns_pin_required() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("c1", &[1])],
            vec![test_key("k1", &[1], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(err, TokenError::PinRequired));
    }

    #[test]
    fn select_cert_no_keys_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(vec![test_cert("c1", &[1])], vec![]);
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoKeys)
        ));
    }

    #[test]
    fn select_cert_no_matching_pair_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("c1", &[1])],
            vec![test_key("k1", &[2], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoMatchingKeyPair)
        ));
    }

    #[test]
    fn select_cert_incompatible_key_type_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("c1", &[1])],
            vec![test_key("k1", &[1], TokenKeyType::Rsa)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        match err {
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoCompatibleKeyType { found },
            ) => {
                assert_eq!(found, vec![TokenKeyType::Rsa]);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn select_cert_prefers_ed25519_over_ecdsa() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("ecdsa-cert", &[1]), test_cert("ed-cert", &[2])],
            vec![
                test_key("ecdsa-key", &[1], TokenKeyType::EcdsaP256),
                test_key("ed-key", &[2], TokenKeyType::Ed25519),
            ],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.key.key_type, TokenKeyType::Ed25519);
        assert_eq!(material.pair.certificate.label, "ed-cert");
        assert_eq!(material.candidates_considered, 2);
    }

    #[test]
    fn select_cert_prefers_x25519_over_ecdsa() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("ec-cert", &[1]), test_cert("x-cert", &[2])],
            vec![
                test_key("ec-key", &[1], TokenKeyType::EcdsaP384),
                test_key("x-key", &[2], TokenKeyType::X25519),
            ],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.key.key_type, TokenKeyType::X25519);
    }

    #[test]
    fn select_cert_single_ed25519_pair_succeeds() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("my-cert", &[0xAB])],
            vec![test_key("my-key", &[0xAB], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.certificate.label, "my-cert");
        assert_eq!(material.pair.key.label, "my-key");
        assert_eq!(material.pair.key.key_type, TokenKeyType::Ed25519);
        assert_eq!(material.candidates_considered, 1);
        assert_eq!(material.token, token);
    }

    #[test]
    fn select_cert_signing_key_preferred_over_derive_only() {
        let mut derive_key = test_key("derive-key", &[1], TokenKeyType::Ed25519);
        derive_key.can_sign = false;
        derive_key.can_derive = true;

        let sign_key = test_key("sign-key", &[2], TokenKeyType::Ed25519);

        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("d-cert", &[1]), test_cert("s-cert", &[2])],
            vec![derive_key, sign_key],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.certificate.label, "s-cert");
        assert!(material.pair.key.can_sign);
    }

    #[test]
    fn select_cert_deterministic_tiebreak_by_label() {
        // Two Ed25519 signing keys — tiebreak by certificate label.
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("beta-cert", &[2]), test_cert("alpha-cert", &[1])],
            vec![
                test_key("k2", &[2], TokenKeyType::Ed25519),
                test_key("k1", &[1], TokenKeyType::Ed25519),
            ],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.certificate.label, "alpha-cert");
    }

    // ── CertificateSelectionRefusal display ─────────────────────────────

    #[test]
    fn certificate_selection_refusal_display_all_variants() {
        assert!(
            CertificateSelectionRefusal::NoCertificates
                .to_string()
                .contains("no certificates")
        );
        assert!(
            CertificateSelectionRefusal::NoKeys
                .to_string()
                .contains("no private keys")
        );
        assert!(
            CertificateSelectionRefusal::NoMatchingKeyPair
                .to_string()
                .contains("matching private key")
        );
        let no_compat = CertificateSelectionRefusal::NoCompatibleKeyType {
            found: vec![TokenKeyType::Rsa],
        };
        assert!(no_compat.to_string().contains("RSA"));
        let ambig = CertificateSelectionRefusal::AmbiguousSelection { count: 3 };
        assert!(ambig.to_string().contains('3'));
    }

    // ── TokenError::CertificateSelectionFailed display ──────────────────

    #[test]
    fn certificate_selection_failed_error_display() {
        let err =
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoCertificates);
        let display = err.to_string();
        assert!(display.contains("certificate selection failed"));
        assert!(display.contains("no certificates"));
    }
}
