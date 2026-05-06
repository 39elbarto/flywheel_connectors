//! Shared voice-call provider primitives for FCP connectors.
//!
//! The crate keeps provider-specific webhook canonicalization, replay
//! detection, session state, auth-token handling, and redaction-safe evidence
//! logging in one place so Twilio, Telnyx, and Plivo connectors can share the
//! same security behavior.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use url::Url;

const TWILIO_HMAC_SHA1_BYTES: usize = 20;
const TELNYX_SIGNATURE_BYTES: usize = 64;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SPKI_DER_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const TOKEN_BYTES: usize = 16;
const MAX_LOG_FIELD_CHARS: usize = 96;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Voice-call provider supported by the shared primitives.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceProvider {
    /// Twilio Programmable Voice.
    Twilio,
    /// Telnyx Call Control / Programmable Voice.
    Telnyx,
    /// Plivo Voice API.
    Plivo,
}

impl VoiceProvider {
    /// Stable provider label used in replay keys and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Twilio => "twilio",
            Self::Telnyx => "telnyx",
            Self::Plivo => "plivo",
        }
    }
}

impl fmt::Display for VoiceProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// HTTP method relevant to provider signature canonicalization.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VoiceWebhookMethod {
    /// GET webhook request.
    Get,
    /// POST webhook request.
    Post,
}

impl VoiceWebhookMethod {
    /// Parse a case-insensitive HTTP method.
    pub fn parse(input: &str) -> VoiceCallResult<Self> {
        match input.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            other => Err(VoiceCallError::InvalidRequest(format!(
                "voice webhook method must be GET or POST, got `{other}`"
            ))),
        }
    }
}

/// Provider-neutral request verification trait.
pub trait WebhookSignatureVerifier<Request> {
    /// Provider handled by this verifier.
    fn provider(&self) -> VoiceProvider;

    /// Verify the request and update replay state after a successful signature check.
    fn verify_request(
        &self,
        request: Request,
        replay_cache: &mut WebhookReplayCache,
    ) -> VoiceCallResult<SignatureVerification>;
}

/// Shared result type for the crate.
pub type VoiceCallResult<T> = Result<T, VoiceCallError>;

/// Error type for shared voice-call primitives.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
pub enum VoiceCallError {
    /// Request shape is invalid before cryptographic validation can run.
    #[error("invalid voice-call request: {0}")]
    InvalidRequest(String),
    /// A required provider header is absent.
    #[error("missing voice-call provider header: {0}")]
    MissingHeader(String),
    /// Signature or public key material is malformed.
    #[error("malformed voice-call signature material: {0}")]
    MalformedSignatureMaterial(String),
    /// Signature verification failed.
    #[error("invalid voice-call webhook signature: {0}")]
    InvalidSignature(String),
    /// Timestamp is outside the accepted replay window.
    #[error(
        "voice-call webhook timestamp outside tolerance: provider={provider}, skew_seconds={skew_seconds}, tolerance_seconds={tolerance_seconds}"
    )]
    TimestampOutsideTolerance {
        /// Provider whose timestamp was rejected.
        provider: VoiceProvider,
        /// Absolute observed skew in seconds.
        skew_seconds: i64,
        /// Configured tolerance in seconds.
        tolerance_seconds: i64,
    },
    /// A verified request was already seen.
    #[error("voice-call webhook replay detected: {0}")]
    Replay(String),
    /// Internal invariant failed.
    #[error("internal voice-call error: {0}")]
    Internal(String),
}

impl VoiceCallError {
    /// Convert into the workspace FCP error taxonomy.
    pub fn to_fcp_error(&self) -> fcp_core::FcpError {
        match self {
            Self::InvalidRequest(message)
            | Self::MalformedSignatureMaterial(message)
            | Self::MissingHeader(message) => fcp_core::FcpError::InvalidRequest {
                code: 1003,
                message: message.clone(),
            },
            Self::InvalidSignature(_) | Self::TimestampOutsideTolerance { .. } => {
                fcp_core::FcpError::InvalidSignature
            }
            Self::Replay(key) => fcp_core::FcpError::Conflict {
                message: format!("duplicate voice-call webhook request: {key}"),
            },
            Self::Internal(message) => fcp_core::FcpError::Internal {
                message: message.clone(),
            },
        }
    }
}

/// Opaque auth token used for callback/session binding.
#[derive(Clone, Eq, PartialEq)]
pub struct CallAuthToken {
    encoded: String,
}

impl CallAuthToken {
    /// Generate a 128-bit random token and encode it URL-safe without padding.
    pub fn generate() -> Self {
        let mut bytes = [0_u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self::from_entropy(bytes)
    }

    /// Deterministically construct a token from entropy bytes.
    pub fn from_entropy(bytes: [u8; TOKEN_BYTES]) -> Self {
        Self {
            encoded: URL_SAFE_NO_PAD.encode(bytes),
        }
    }

    /// Construct from a provider callback parameter previously issued by FCP.
    pub fn from_callback_parameter(encoded: impl Into<String>) -> VoiceCallResult<Self> {
        let encoded = encoded.into();
        let trimmed = encoded.trim();
        if trimmed.is_empty() || trimmed != encoded {
            return Err(VoiceCallError::InvalidRequest(
                "call auth token must be a non-empty base64url value without surrounding whitespace"
                    .into(),
            ));
        }
        let decoded = URL_SAFE_NO_PAD.decode(trimmed).map_err(|error| {
            VoiceCallError::InvalidRequest(format!("call auth token must be base64url: {error}"))
        })?;
        if decoded.len() != TOKEN_BYTES {
            return Err(VoiceCallError::InvalidRequest(format!(
                "call auth token must decode to {TOKEN_BYTES} bytes"
            )));
        }
        Ok(Self { encoded })
    }

    /// Validate a supplied token with constant-time comparison.
    pub fn verify(&self, candidate: &str) -> bool {
        self.encoded
            .as_bytes()
            .ct_eq(candidate.as_bytes())
            .unwrap_u8()
            == 1
    }

    /// Return the token material for provider callback embedding.
    pub fn expose_secret(&self) -> &str {
        &self.encoded
    }

    /// Redacted preview for logs and diagnostics.
    pub fn preview(&self) -> String {
        preview_secret(&self.encoded)
    }
}

impl fmt::Debug for CallAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallAuthToken")
            .field("encoded", &self.preview())
            .finish()
    }
}

/// Session persistence policy. The default is non-persistent memory only.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPersistenceMode {
    /// Sessions are kept in memory only and disappear on restart.
    Disabled,
    /// A connector supplied an external persistence backend.
    ExternalOptIn,
}

/// Session correlation scope.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionScope {
    /// One session per provider call identifier.
    PerCall,
    /// One session per provider and phone-number pair.
    PerPhoneNumber,
}

/// Provider-neutral call session stored by connector runtimes.
#[derive(Debug, Clone)]
pub struct CallSession {
    /// Provider that owns the call.
    pub provider: VoiceProvider,
    /// FCP zone binding for this call.
    pub zone_id: String,
    /// Provider call identifier.
    pub call_id: String,
    /// Optional provider call-session identifier.
    pub call_session_id: Option<String>,
    /// Redaction-safe caller hash.
    pub caller_hash: String,
    /// Redaction-safe callee hash.
    pub callee_hash: String,
    /// Opaque callback/session binding token.
    pub auth_token: CallAuthToken,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Expiry time.
    pub expires_at: DateTime<Utc>,
}

impl CallSession {
    /// Build a new provider-neutral session.
    pub fn new(
        provider: VoiceProvider,
        zone_id: impl Into<String>,
        call_id: impl Into<String>,
        from_number: &str,
        to_number: &str,
        created_at: DateTime<Utc>,
        ttl: Duration,
    ) -> Self {
        Self {
            provider,
            zone_id: zone_id.into(),
            call_id: call_id.into(),
            call_session_id: None,
            caller_hash: stable_redacted_hash(from_number),
            callee_hash: stable_redacted_hash(to_number),
            auth_token: CallAuthToken::generate(),
            created_at,
            expires_at: created_at + ttl,
        }
    }

    /// Whether the session is expired at `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// In-memory session store used by connectors and tests.
#[derive(Debug)]
pub struct MemorySessionStore {
    sessions: BTreeMap<String, CallSession>,
    persistence_mode: SessionPersistenceMode,
}

impl MemorySessionStore {
    /// Create an in-memory non-persistent store.
    pub const fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            persistence_mode: SessionPersistenceMode::Disabled,
        }
    }

    /// Create a store that records an opt-in external persistence boundary.
    pub const fn with_external_persistence_boundary() -> Self {
        Self {
            sessions: BTreeMap::new(),
            persistence_mode: SessionPersistenceMode::ExternalOptIn,
        }
    }

    /// Configured persistence mode.
    pub const fn persistence_mode(&self) -> SessionPersistenceMode {
        self.persistence_mode
    }

    /// Insert or replace a session.
    pub fn upsert(&mut self, scope: SessionScope, session: CallSession) -> String {
        let key = session_key(scope, &session);
        self.sessions.insert(key.clone(), session);
        key
    }

    /// Fetch a live session by key.
    pub fn get_live(&mut self, key: &str, now: DateTime<Utc>) -> Option<&CallSession> {
        self.expire(now);
        self.sessions.get(key)
    }

    /// Remove expired sessions and return the number removed.
    pub fn expire(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, session| !session.is_expired(now));
        before.saturating_sub(self.sessions.len())
    }

    /// Number of sessions currently retained.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the store currently holds no sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider-neutral session-store contract.
pub trait SessionStore {
    /// Insert or replace a session.
    fn upsert(&mut self, scope: SessionScope, session: CallSession) -> String;

    /// Fetch a live session by key.
    fn get_live(&mut self, key: &str, now: DateTime<Utc>) -> Option<&CallSession>;

    /// Remove expired sessions.
    fn expire(&mut self, now: DateTime<Utc>) -> usize;

    /// Configured persistence boundary.
    fn persistence_mode(&self) -> SessionPersistenceMode;
}

impl SessionStore for MemorySessionStore {
    fn upsert(&mut self, scope: SessionScope, session: CallSession) -> String {
        Self::upsert(self, scope, session)
    }

    fn get_live(&mut self, key: &str, now: DateTime<Utc>) -> Option<&CallSession> {
        Self::get_live(self, key, now)
    }

    fn expire(&mut self, now: DateTime<Utc>) -> usize {
        Self::expire(self, now)
    }

    fn persistence_mode(&self) -> SessionPersistenceMode {
        self.persistence_mode()
    }
}

fn session_key(scope: SessionScope, session: &CallSession) -> String {
    match scope {
        SessionScope::PerCall => format!(
            "{}:zone:{}:call:{}",
            session.provider, session.zone_id, session.call_id
        ),
        SessionScope::PerPhoneNumber => format!(
            "{}:zone:{}:phone:{}:{}",
            session.provider, session.zone_id, session.caller_hash, session.callee_hash
        ),
    }
}

/// Result of replay-cache insertion.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReplayDecision {
    /// First observation of this verified request.
    Accepted { key: String },
    /// Duplicate observation inside the replay window.
    Replayed { key: String },
}

impl ReplayDecision {
    /// Whether this decision is a replay.
    pub const fn is_replay(&self) -> bool {
        matches!(self, Self::Replayed { .. })
    }

    /// Replay key for evidence and idempotency.
    pub fn key(&self) -> &str {
        match self {
            Self::Accepted { key } | Self::Replayed { key } => key,
        }
    }
}

/// Bounded in-memory replay cache keyed by provider-specific request digest.
#[derive(Debug, Clone)]
pub struct WebhookReplayCache {
    window: Duration,
    entries: BTreeMap<String, DateTime<Utc>>,
    insertions_since_prune: u64,
}

impl WebhookReplayCache {
    /// Create a replay cache with the given retention window.
    pub const fn new(window: Duration) -> Self {
        Self {
            window,
            entries: BTreeMap::new(),
            insertions_since_prune: 0,
        }
    }

    /// Insert `key` at `now` or report that it was already present.
    pub fn check_and_insert(
        &mut self,
        key: impl Into<String>,
        now: DateTime<Utc>,
    ) -> ReplayDecision {
        self.insertions_since_prune = self.insertions_since_prune.saturating_add(1);
        if self.insertions_since_prune >= 64 {
            self.prune(now);
        }

        let key = key.into();
        if self.entries.contains_key(&key) {
            ReplayDecision::Replayed { key }
        } else {
            self.entries.insert(key.clone(), now);
            ReplayDecision::Accepted { key }
        }
    }

    /// Remove expired replay keys.
    pub fn prune(&mut self, now: DateTime<Utc>) -> usize {
        self.insertions_since_prune = 0;
        let before = self.entries.len();
        let window = self.window;
        self.entries
            .retain(|_, inserted_at| now.signed_duration_since(*inserted_at) <= window);
        before.saturating_sub(self.entries.len())
    }

    /// Number of replay keys retained.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for WebhookReplayCache {
    fn default() -> Self {
        Self::new(Duration::minutes(10))
    }
}

/// Provider verification result.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureVerification {
    /// Provider that was verified.
    pub provider: VoiceProvider,
    /// True when the signature matched and timestamp checks passed.
    pub valid: bool,
    /// Stable reason code for logs and operator UI.
    pub reason_code: String,
    /// Human-readable reason with no secrets.
    pub reason: String,
    /// True when the verified request key was already seen.
    pub is_replay: bool,
    /// Stable replay/idempotency key for the verified request.
    pub verified_request_key: Option<String>,
}

impl SignatureVerification {
    fn accepted(provider: VoiceProvider, replay: &ReplayDecision) -> Self {
        let is_replay = replay.is_replay();
        Self {
            provider,
            valid: true,
            reason_code: if is_replay {
                "replay".into()
            } else {
                "signature_validated".into()
            },
            reason: if is_replay {
                "Signature is valid, but this signed webhook was already seen within the replay window"
                    .into()
            } else {
                "Signature is valid".into()
            },
            is_replay,
            verified_request_key: Some(replay.key().to_string()),
        }
    }

    fn denied(provider: VoiceProvider, reason_code: &str, reason: impl Into<String>) -> Self {
        Self {
            provider,
            valid: false,
            reason_code: reason_code.into(),
            reason: reason.into(),
            is_replay: false,
            verified_request_key: None,
        }
    }
}

/// Case-insensitive provider header map.
#[derive(Debug, Clone, Default)]
pub struct ProviderHeaders {
    values: BTreeMap<String, String>,
}

impl ProviderHeaders {
    /// Create from key/value pairs.
    pub fn new(headers: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>) -> Self {
        let mut values = BTreeMap::new();
        for (name, value) in headers {
            values.insert(name.into().to_ascii_lowercase(), value.into());
        }
        Self { values }
    }

    /// Get a header value case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn required(&self, provider: VoiceProvider, name: &str) -> VoiceCallResult<&str> {
        self.get(name).ok_or_else(|| {
            VoiceCallError::MissingHeader(format!("{provider} webhook missing `{name}`"))
        })
    }
}

/// Tunnel/source mode for inbound voice webhooks.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// Public HTTPS URL is supplied directly.
    PublicHttps,
    /// Local HTTP URL is allowed for deterministic tests.
    LocalTestHttp,
    /// Trusted reverse proxy headers may reconstruct the public URL.
    TrustedProxyForwarded,
}

/// Inbound URL policy for signature verification.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InboundPolicy {
    /// Allowed public callback hosts.
    pub allowed_hosts: Option<Vec<String>>,
    /// Reverse proxy hosts whose forwarded headers may be trusted.
    pub trusted_proxy_hosts: Vec<String>,
    /// Tunnel/source mode.
    pub tunnel_mode: TunnelMode,
}

impl InboundPolicy {
    /// Strict public HTTPS policy.
    pub const fn public_https() -> Self {
        Self {
            allowed_hosts: None,
            trusted_proxy_hosts: Vec::new(),
            tunnel_mode: TunnelMode::PublicHttps,
        }
    }

    /// Allow a fixed host list.
    #[must_use]
    pub fn with_allowed_hosts(mut self, hosts: impl IntoIterator<Item = String>) -> Self {
        self.allowed_hosts = Some(hosts.into_iter().collect());
        self
    }

    /// Trust reverse proxy forwarded headers from fixed peer hosts.
    #[must_use]
    pub fn with_trusted_proxy_hosts(mut self, hosts: impl IntoIterator<Item = String>) -> Self {
        self.trusted_proxy_hosts = hosts.into_iter().collect();
        self.tunnel_mode = TunnelMode::TrustedProxyForwarded;
        self
    }

    /// Normalize the effective public webhook URL under this policy.
    pub fn normalize_url(
        &self,
        raw_url: &str,
        headers: &ProviderHeaders,
        peer_host: Option<&str>,
    ) -> VoiceCallResult<String> {
        let effective_url = if self.trusts_peer(peer_host) {
            forwarded_public_url(raw_url, headers)?
        } else {
            raw_url.to_string()
        };
        normalize_public_webhook_url(&effective_url, self.allowed_hosts.as_deref())
    }

    fn trusts_peer(&self, peer_host: Option<&str>) -> bool {
        if self.tunnel_mode != TunnelMode::TrustedProxyForwarded {
            return false;
        }
        let Some(peer_host) = peer_host else {
            return false;
        };
        let trusted = self
            .trusted_proxy_hosts
            .iter()
            .map(|host| host.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        trusted.contains(&peer_host.to_ascii_lowercase())
    }
}

fn forwarded_public_url(raw_url: &str, headers: &ProviderHeaders) -> VoiceCallResult<String> {
    let proto = headers.required(VoiceProvider::Twilio, "x-forwarded-proto")?;
    let host = headers.required(VoiceProvider::Twilio, "x-forwarded-host")?;
    let parsed = Url::parse(raw_url).map_err(|error| {
        VoiceCallError::InvalidRequest(format!("invalid proxied webhook url: {error}"))
    })?;
    let mut public_url = format!("{proto}://{host}{}", parsed.path());
    if let Some(query) = parsed.query() {
        public_url.push('?');
        public_url.push_str(query);
    }
    Ok(public_url)
}

/// Validate and normalize a public webhook URL.
pub fn normalize_public_webhook_url(
    raw_url: &str,
    allowed_hosts: Option<&[String]>,
) -> VoiceCallResult<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(VoiceCallError::InvalidRequest(
            "webhook url must not be empty".into(),
        ));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|error| VoiceCallError::InvalidRequest(format!("invalid webhook url: {error}")))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(VoiceCallError::InvalidRequest(
            "webhook url must use http or https".into(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| VoiceCallError::InvalidRequest("webhook url must include a host".into()))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(VoiceCallError::InvalidRequest(
            "webhook url must not include userinfo".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(VoiceCallError::InvalidRequest(
            "webhook url must not include a fragment".into(),
        ));
    }

    let local_host = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if parsed.scheme() == "http" && !local_host {
        return Err(VoiceCallError::InvalidRequest(
            "webhook url must use https unless targeting localhost/127.0.0.1/::1 for tests".into(),
        ));
    }

    if let Some(allowed_hosts) = allowed_hosts {
        if allowed_hosts.is_empty() {
            return Err(VoiceCallError::InvalidRequest(
                "allowed_hosts must not be empty when provided".into(),
            ));
        }
        let normalized = host.to_ascii_lowercase();
        let allowed = allowed_hosts
            .iter()
            .map(|candidate| candidate.trim().to_ascii_lowercase())
            .any(|candidate| candidate == normalized);
        if !allowed {
            return Err(VoiceCallError::InvalidRequest(format!(
                "webhook url host `{host}` is not in allowed_hosts"
            )));
        }
    }

    Ok(trimmed.to_string())
}

/// Build the exact Twilio HMAC-SHA1 string-to-sign.
pub fn build_twilio_data_to_sign(url: &str, params: &[(String, String)]) -> String {
    let mut sorted = params.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut data = String::from(url);
    for (key, value) in sorted {
        data.push_str(&key);
        data.push_str(&value);
    }
    data
}

/// Compute a Twilio `X-Twilio-Signature` value.
pub fn compute_twilio_signature(
    auth_token: &str,
    url: &str,
    params: &[(String, String)],
) -> VoiceCallResult<String> {
    let data_to_sign = build_twilio_data_to_sign(url, params);
    let mut mac = HmacSha1::new_from_slice(auth_token.as_bytes())
        .map_err(|error| VoiceCallError::Internal(format!("failed to initialize HMAC: {error}")))?;
    mac.update(data_to_sign.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

/// Twilio webhook signature verifier.
#[derive(Debug, Clone)]
pub struct TwilioSignatureVerifier {
    auth_token: String,
    allowed_hosts: Option<Vec<String>>,
}

/// Twilio verification request.
#[derive(Debug, Clone, Copy)]
pub struct TwilioVerificationRequest<'a> {
    /// Public callback URL.
    pub url: &'a str,
    /// Form parameters used in Twilio canonicalization.
    pub params: &'a [(String, String)],
    /// `X-Twilio-Signature` header.
    pub signature: &'a str,
    /// Verification time for replay cache insertion.
    pub now: DateTime<Utc>,
}

impl TwilioSignatureVerifier {
    /// Create a Twilio verifier.
    pub fn new(auth_token: impl Into<String>) -> Self {
        Self {
            auth_token: auth_token.into(),
            allowed_hosts: None,
        }
    }

    /// Restrict accepted verification URLs to the supplied hosts.
    #[must_use]
    pub fn with_allowed_hosts(mut self, allowed_hosts: impl IntoIterator<Item = String>) -> Self {
        self.allowed_hosts = Some(allowed_hosts.into_iter().collect());
        self
    }

    /// Verify a Twilio webhook and update the replay cache only after signature success.
    pub fn verify(
        &self,
        url: &str,
        params: &[(String, String)],
        signature: &str,
        replay_cache: &mut WebhookReplayCache,
        now: DateTime<Utc>,
    ) -> VoiceCallResult<SignatureVerification> {
        let verification_url = normalize_public_webhook_url(url, self.allowed_hosts.as_deref())?;
        if signature.is_empty() {
            return Ok(SignatureVerification::denied(
                VoiceProvider::Twilio,
                "empty_signature",
                "Signature is empty",
            ));
        }
        let Ok(provided) = STANDARD.decode(signature) else {
            return Ok(SignatureVerification::denied(
                VoiceProvider::Twilio,
                "malformed_signature",
                "Signature is not valid base64",
            ));
        };
        if provided.len() != TWILIO_HMAC_SHA1_BYTES {
            return Ok(SignatureVerification::denied(
                VoiceProvider::Twilio,
                "malformed_signature",
                "Signature must decode to a 20-byte HMAC-SHA1 digest",
            ));
        }

        let expected = compute_twilio_signature(&self.auth_token, &verification_url, params)?;
        let expected = STANDARD.decode(expected).map_err(|error| {
            VoiceCallError::Internal(format!(
                "failed to decode computed Twilio signature: {error}"
            ))
        })?;
        if provided.as_slice().ct_eq(expected.as_slice()).unwrap_u8() != 1 {
            return Ok(SignatureVerification::denied(
                VoiceProvider::Twilio,
                "invalid_signature",
                "Invalid Twilio HMAC-SHA1 signature",
            ));
        }

        let replay_key = twilio_replay_key(&verification_url, params, signature);
        let replay = replay_cache.check_and_insert(replay_key, now);
        Ok(SignatureVerification::accepted(
            VoiceProvider::Twilio,
            &replay,
        ))
    }
}

impl<'a> WebhookSignatureVerifier<TwilioVerificationRequest<'a>> for TwilioSignatureVerifier {
    fn provider(&self) -> VoiceProvider {
        VoiceProvider::Twilio
    }

    fn verify_request(
        &self,
        request: TwilioVerificationRequest<'a>,
        replay_cache: &mut WebhookReplayCache,
    ) -> VoiceCallResult<SignatureVerification> {
        self.verify(
            request.url,
            request.params,
            request.signature,
            replay_cache,
            request.now,
        )
    }
}

/// Preserve the existing Twilio replay-key shape used by the connector.
pub fn twilio_replay_key(url: &str, params: &[(String, String)], signature: &str) -> String {
    let mut sorted = params.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let canonical_params = sorted
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let mut hasher = Sha1::new();
    hasher.update(url.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical_params.as_bytes());
    hasher.update(b"\n");
    hasher.update(signature.as_bytes());
    format!(
        "twilio:req:{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize().as_slice())
    )
}

/// Telnyx webhook verifier.
#[derive(Debug, Clone)]
pub struct TelnyxSignatureVerifier {
    public_key: ed25519_dalek::VerifyingKey,
    timestamp_tolerance: Duration,
}

/// Telnyx verification request.
#[derive(Debug, Clone, Copy)]
pub struct TelnyxVerificationRequest<'a> {
    /// Telnyx signature headers.
    pub headers: &'a ProviderHeaders,
    /// Raw JSON payload bytes.
    pub raw_json_payload: &'a [u8],
    /// Verification time for replay cache insertion.
    pub now: DateTime<Utc>,
}

impl TelnyxSignatureVerifier {
    /// Create a verifier from a raw, hex, base64, PEM, or SPKI DER public key.
    pub fn new(public_key: &str, timestamp_tolerance: Duration) -> VoiceCallResult<Self> {
        Ok(Self {
            public_key: parse_ed25519_public_key(public_key)?,
            timestamp_tolerance,
        })
    }

    /// Verify a Telnyx webhook and update replay state only after signature success.
    pub fn verify(
        &self,
        headers: &ProviderHeaders,
        raw_json_payload: &[u8],
        replay_cache: &mut WebhookReplayCache,
        now: DateTime<Utc>,
    ) -> VoiceCallResult<SignatureVerification> {
        let timestamp = headers.required(VoiceProvider::Telnyx, "telnyx-timestamp")?;
        let signature = headers.required(VoiceProvider::Telnyx, "telnyx-signature-ed25519")?;
        let signed_at = parse_unix_timestamp(timestamp, VoiceProvider::Telnyx)?;
        enforce_timestamp_tolerance(
            VoiceProvider::Telnyx,
            signed_at,
            now,
            self.timestamp_tolerance,
        )?;

        let signature = decode_fixed_base64(signature, TELNYX_SIGNATURE_BYTES, "Telnyx signature")?;
        let signature = ed25519_dalek::Signature::from_slice(&signature).map_err(|error| {
            VoiceCallError::MalformedSignatureMaterial(format!(
                "invalid Telnyx Ed25519 signature bytes: {error}"
            ))
        })?;
        let signed_payload = telnyx_signed_payload(timestamp, raw_json_payload);
        if self
            .public_key
            .verify_strict(&signed_payload, &signature)
            .is_err()
        {
            return Ok(SignatureVerification::denied(
                VoiceProvider::Telnyx,
                "invalid_signature",
                "Invalid Telnyx Ed25519 signature",
            ));
        }

        let replay_key = digest_replay_key(
            VoiceProvider::Telnyx,
            &[
                timestamp.as_bytes(),
                signature.to_bytes().as_slice(),
                raw_json_payload,
            ],
        );
        let replay = replay_cache.check_and_insert(replay_key, now);
        Ok(SignatureVerification::accepted(
            VoiceProvider::Telnyx,
            &replay,
        ))
    }
}

impl<'a> WebhookSignatureVerifier<TelnyxVerificationRequest<'a>> for TelnyxSignatureVerifier {
    fn provider(&self) -> VoiceProvider {
        VoiceProvider::Telnyx
    }

    fn verify_request(
        &self,
        request: TelnyxVerificationRequest<'a>,
        replay_cache: &mut WebhookReplayCache,
    ) -> VoiceCallResult<SignatureVerification> {
        self.verify(
            request.headers,
            request.raw_json_payload,
            replay_cache,
            request.now,
        )
    }
}

fn telnyx_signed_payload(timestamp: &str, raw_json_payload: &[u8]) -> Vec<u8> {
    let mut signed_payload = Vec::with_capacity(timestamp.len() + 1 + raw_json_payload.len());
    signed_payload.extend_from_slice(timestamp.as_bytes());
    signed_payload.push(b'|');
    signed_payload.extend_from_slice(raw_json_payload);
    signed_payload
}

/// Plivo webhook signature version.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlivoSignatureVersion {
    /// Plivo V2 HMAC-SHA256 over base URL plus nonce.
    V2,
    /// Plivo V3 HMAC-SHA256 over canonical request plus nonce.
    V3,
}

/// Plivo webhook verifier.
#[derive(Debug, Clone)]
pub struct PlivoSignatureVerifier {
    auth_token: String,
}

/// Plivo webhook verification input.
#[derive(Debug, Clone, Copy)]
pub struct PlivoVerificationRequest<'a> {
    /// Signature version to validate.
    pub version: PlivoSignatureVersion,
    /// HTTP method Plivo used for the callback.
    pub method: VoiceWebhookMethod,
    /// Public callback URL.
    pub url: &'a str,
    /// Query or form parameters received with the callback.
    pub params: &'a BTreeMap<String, PlivoParamValue>,
    /// Provider headers containing signature and nonce.
    pub headers: &'a ProviderHeaders,
    /// Verification time for replay cache insertion.
    pub now: DateTime<Utc>,
}

impl PlivoSignatureVerifier {
    /// Create a Plivo verifier.
    pub fn new(auth_token: impl Into<String>) -> Self {
        Self {
            auth_token: auth_token.into(),
        }
    }

    /// Verify a Plivo V2 or V3 signature and update replay state after success.
    pub fn verify(
        &self,
        request: PlivoVerificationRequest<'_>,
        replay_cache: &mut WebhookReplayCache,
    ) -> VoiceCallResult<SignatureVerification> {
        let (signature_header, nonce_header) = match request.version {
            PlivoSignatureVersion::V2 => ("x-plivo-signature-v2", "x-plivo-signature-v2-nonce"),
            PlivoSignatureVersion::V3 => ("x-plivo-signature-v3", "x-plivo-signature-v3-nonce"),
        };
        let signature = request
            .headers
            .required(VoiceProvider::Plivo, signature_header)?;
        let nonce = request
            .headers
            .required(VoiceProvider::Plivo, nonce_header)?;
        let computed = self.compute(
            request.version,
            request.method,
            request.url,
            request.params,
            nonce,
        )?;
        let accepted = signature
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate.as_bytes().ct_eq(computed.as_bytes()).unwrap_u8() == 1);
        if !accepted {
            return Ok(SignatureVerification::denied(
                VoiceProvider::Plivo,
                "invalid_signature",
                format!("Invalid Plivo {:?} HMAC-SHA256 signature", request.version),
            ));
        }

        let replay_key = digest_replay_key(
            VoiceProvider::Plivo,
            &[
                format!("{:?}", request.version).as_bytes(),
                method_label(request.method).as_bytes(),
                request.url.as_bytes(),
                nonce.as_bytes(),
                signature.as_bytes(),
            ],
        );
        let replay = replay_cache.check_and_insert(replay_key, request.now);
        Ok(SignatureVerification::accepted(
            VoiceProvider::Plivo,
            &replay,
        ))
    }

    /// Compute a Plivo V2 or V3 signature.
    pub fn compute(
        &self,
        version: PlivoSignatureVersion,
        method: VoiceWebhookMethod,
        url: &str,
        params: &BTreeMap<String, PlivoParamValue>,
        nonce: &str,
    ) -> VoiceCallResult<String> {
        let base = match version {
            PlivoSignatureVersion::V2 => plivo_v2_base_url(url)?,
            PlivoSignatureVersion::V3 => build_plivo_v3_base_string(method, url, params)?,
        };
        let payload = match version {
            PlivoSignatureVersion::V2 => format!("{base}{nonce}"),
            PlivoSignatureVersion::V3 => format!("{base}.{nonce}"),
        };
        let mut mac = HmacSha256::new_from_slice(self.auth_token.as_bytes()).map_err(|error| {
            VoiceCallError::Internal(format!("failed to initialize Plivo HMAC: {error}"))
        })?;
        mac.update(payload.as_bytes());
        Ok(STANDARD.encode(mac.finalize().into_bytes()))
    }
}

impl<'a> WebhookSignatureVerifier<PlivoVerificationRequest<'a>> for PlivoSignatureVerifier {
    fn provider(&self) -> VoiceProvider {
        VoiceProvider::Plivo
    }

    fn verify_request(
        &self,
        request: PlivoVerificationRequest<'a>,
        replay_cache: &mut WebhookReplayCache,
    ) -> VoiceCallResult<SignatureVerification> {
        self.verify(request, replay_cache)
    }
}

const fn method_label(method: VoiceWebhookMethod) -> &'static str {
    match method {
        VoiceWebhookMethod::Get => "GET",
        VoiceWebhookMethod::Post => "POST",
    }
}

/// Plivo form/query parameter value used for V3 canonicalization.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PlivoParamValue {
    /// Scalar value.
    Scalar(String),
    /// Repeated values; sorted by value during canonicalization.
    List(Vec<String>),
    /// Nested map; recursively sorted and concatenated.
    Map(BTreeMap<String, Self>),
}

impl From<&str> for PlivoParamValue {
    fn from(value: &str) -> Self {
        Self::Scalar(value.into())
    }
}

impl From<String> for PlivoParamValue {
    fn from(value: String) -> Self {
        Self::Scalar(value)
    }
}

fn plivo_v2_base_url(raw_url: &str) -> VoiceCallResult<String> {
    let parsed = Url::parse(raw_url)
        .map_err(|error| VoiceCallError::InvalidRequest(format!("invalid Plivo URL: {error}")))?;
    let mut base = parsed;
    base.set_query(None);
    base.set_fragment(None);
    Ok(base.to_string())
}

/// Build the Plivo V3 base string before `.{nonce}` is appended.
pub fn build_plivo_v3_base_string(
    method: VoiceWebhookMethod,
    raw_url: &str,
    params: &BTreeMap<String, PlivoParamValue>,
) -> VoiceCallResult<String> {
    let parsed = Url::parse(raw_url)
        .map_err(|error| VoiceCallError::InvalidRequest(format!("invalid Plivo URL: {error}")))?;
    match method {
        VoiceWebhookMethod::Get => construct_plivo_get_url(&parsed, params, true),
        VoiceWebhookMethod::Post => {
            let base = construct_plivo_get_url(&parsed, &BTreeMap::new(), params.is_empty())?;
            Ok(format!("{base}{}", sorted_plivo_params_string(params)))
        }
    }
}

fn construct_plivo_get_url(
    parsed: &Url,
    params: &BTreeMap<String, PlivoParamValue>,
    empty_post_params: bool,
) -> VoiceCallResult<String> {
    let mut base = parsed.clone();
    let query = parsed.query().unwrap_or_default().to_string();
    base.set_query(None);
    base.set_fragment(None);
    let mut merged = params.clone();
    for (key, value) in query_params(&query)? {
        merged.entry(key).or_insert(value);
    }
    let query_string = sorted_plivo_query_string(&merged);
    let mut result = base.to_string();
    if !query_string.is_empty() || !empty_post_params {
        result.push('?');
        result.push_str(&query_string);
    }
    if !query_string.is_empty() && !empty_post_params {
        result.push('.');
    }
    Ok(result)
}

fn query_params(query: &str) -> VoiceCallResult<Vec<(String, PlivoParamValue)>> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(VoiceCallError::InvalidRequest(format!(
                "Plivo query parameter `{pair}` is missing `=`"
            )));
        };
        grouped
            .entry(key.to_string())
            .or_default()
            .push(value.to_string());
    }
    Ok(grouped
        .into_iter()
        .map(|(key, values)| {
            if let [value] = values.as_slice() {
                (key, PlivoParamValue::Scalar(value.clone()))
            } else {
                (key, PlivoParamValue::List(values))
            }
        })
        .collect())
}

fn sorted_plivo_query_string(params: &BTreeMap<String, PlivoParamValue>) -> String {
    let parts = params.iter().map(|(key, value)| match value {
        PlivoParamValue::Scalar(value) => format!("{key}={value}"),
        PlivoParamValue::List(values) => {
            let mut values = values.clone();
            values.sort();
            values
                .into_iter()
                .map(|value| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("&")
        }
        PlivoParamValue::Map(map) => format!("{key}={}", sorted_plivo_params_string(map)),
    });
    parts.collect::<Vec<_>>().join("&")
}

fn sorted_plivo_params_string(params: &BTreeMap<String, PlivoParamValue>) -> String {
    params
        .iter()
        .map(|(key, value)| match value {
            PlivoParamValue::Scalar(value) => format!("{key}{value}"),
            PlivoParamValue::List(values) => {
                let mut values = values.clone();
                values.sort();
                let mut output = String::new();
                for value in values {
                    output.push_str(key);
                    output.push_str(&value);
                }
                output
            }
            PlivoParamValue::Map(map) => format!("{key}{}", sorted_plivo_params_string(map)),
        })
        .collect::<String>()
}

fn parse_ed25519_public_key(input: &str) -> VoiceCallResult<ed25519_dalek::VerifyingKey> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(VoiceCallError::MalformedSignatureMaterial(
            "Ed25519 public key must not be empty".into(),
        ));
    }
    let bytes = if trimmed.starts_with("-----BEGIN") {
        let der = decode_pem_body(trimmed)?;
        if der.len() == ED25519_PUBLIC_KEY_BYTES {
            der
        } else if der.len() == ED25519_PUBLIC_KEY_BYTES + ED25519_SPKI_DER_PREFIX.len()
            && der.starts_with(ED25519_SPKI_DER_PREFIX)
        {
            der.get(ED25519_SPKI_DER_PREFIX.len()..)
                .ok_or_else(|| {
                    VoiceCallError::MalformedSignatureMaterial(
                        "SPKI public key is missing Ed25519 key bytes".into(),
                    )
                })?
                .to_vec()
        } else {
            return Err(VoiceCallError::MalformedSignatureMaterial(
                "PEM public key is not raw Ed25519 or Ed25519 SubjectPublicKeyInfo".into(),
            ));
        }
    } else if trimmed.len() == ED25519_PUBLIC_KEY_BYTES * 2
        && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        hex::decode(trimmed).map_err(|error| {
            VoiceCallError::MalformedSignatureMaterial(format!(
                "invalid hex Ed25519 public key: {error}"
            ))
        })?
    } else {
        STANDARD.decode(trimmed).map_err(|error| {
            VoiceCallError::MalformedSignatureMaterial(format!(
                "public key must be hex, base64, raw PEM, or SPKI PEM: {error}"
            ))
        })?
    };

    let key_bytes: [u8; ED25519_PUBLIC_KEY_BYTES] = bytes.try_into().map_err(|_| {
        VoiceCallError::MalformedSignatureMaterial(
            "Ed25519 public key must decode to 32 bytes".into(),
        )
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|error| {
        VoiceCallError::MalformedSignatureMaterial(format!("invalid Ed25519 public key: {error}"))
    })
}

fn decode_pem_body(input: &str) -> VoiceCallResult<Vec<u8>> {
    let body = input
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect::<String>();
    STANDARD.decode(body).map_err(|error| {
        VoiceCallError::MalformedSignatureMaterial(format!("invalid PEM base64 body: {error}"))
    })
}

fn decode_fixed_base64(input: &str, expected_len: usize, label: &str) -> VoiceCallResult<Vec<u8>> {
    let decoded = STANDARD.decode(input).map_err(|error| {
        VoiceCallError::MalformedSignatureMaterial(format!("{label} is not valid base64: {error}"))
    })?;
    if decoded.len() == expected_len {
        Ok(decoded)
    } else {
        Err(VoiceCallError::MalformedSignatureMaterial(format!(
            "{label} must decode to {expected_len} bytes"
        )))
    }
}

fn parse_unix_timestamp(input: &str, provider: VoiceProvider) -> VoiceCallResult<DateTime<Utc>> {
    let timestamp = input.parse::<i64>().map_err(|error| {
        VoiceCallError::InvalidRequest(format!(
            "{provider} timestamp must be Unix seconds: {error}"
        ))
    })?;
    DateTime::from_timestamp(timestamp, 0).ok_or_else(|| {
        VoiceCallError::InvalidRequest(format!("{provider} timestamp is outside chrono range"))
    })
}

fn enforce_timestamp_tolerance(
    provider: VoiceProvider,
    signed_at: DateTime<Utc>,
    now: DateTime<Utc>,
    tolerance: Duration,
) -> VoiceCallResult<()> {
    let skew = now.signed_duration_since(signed_at).num_seconds().abs();
    let tolerance_seconds = tolerance.num_seconds();
    if skew <= tolerance_seconds {
        Ok(())
    } else {
        Err(VoiceCallError::TimestampOutsideTolerance {
            provider,
            skew_seconds: skew,
            tolerance_seconds,
        })
    }
}

fn digest_replay_key(provider: VoiceProvider, chunks: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
        hasher.update(b"\n");
    }
    format!(
        "{}:req:{}",
        provider,
        URL_SAFE_NO_PAD.encode(hasher.finalize().as_bytes())
    )
}

/// Redaction-safe evidence log event.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VoiceEvidenceEvent {
    /// Stable scenario/event name.
    pub event: String,
    /// Provider involved.
    pub provider: VoiceProvider,
    /// Stable outcome code.
    pub outcome: String,
    /// Redaction-safe request-key preview.
    pub request_key_preview: Option<String>,
    /// Extra redaction-safe fields.
    pub fields: BTreeMap<String, String>,
}

impl VoiceEvidenceEvent {
    /// Create an event from a verification result.
    pub fn from_verification(
        event: impl Into<String>,
        verification: &SignatureVerification,
    ) -> Self {
        let request_key_preview = verification
            .verified_request_key
            .as_deref()
            .map(preview_secret);
        Self {
            event: event.into(),
            provider: verification.provider,
            outcome: verification.reason_code.clone(),
            request_key_preview,
            fields: BTreeMap::from([
                ("valid".into(), verification.valid.to_string()),
                ("is_replay".into(), verification.is_replay.to_string()),
            ]),
        }
    }

    /// Add a redaction-safe field.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl AsRef<str>) -> Self {
        self.fields
            .insert(key.into(), redact_log_value(value.as_ref()));
        self
    }

    /// Serialize as one JSONL line.
    pub fn to_jsonl_line(&self) -> VoiceCallResult<String> {
        serde_json::to_string(self).map_err(|error| {
            VoiceCallError::Internal(format!("failed to serialize evidence event: {error}"))
        })
    }
}

/// Stable non-reversible hash for phone numbers, call IDs, and request material.
pub fn stable_redacted_hash(value: &str) -> String {
    let digest = blake3::hash(value.trim().as_bytes());
    format!("hash:{}", URL_SAFE_NO_PAD.encode(&digest.as_bytes()[..16]))
}

/// Mask an E.164-ish phone number for operator logs.
pub fn mask_phone_number(value: &str) -> String {
    let trimmed = value.trim();
    let chars = trimmed.chars().collect::<Vec<_>>();
    if chars.len() <= 6 {
        return "*".repeat(chars.len().max(1));
    }
    let prefix = chars.iter().take(3).collect::<String>();
    let suffix = chars.iter().skip(chars.len() - 4).collect::<String>();
    format!("{prefix}***{suffix}")
}

fn preview_secret(value: &str) -> String {
    let prefix = value.chars().take(8).collect::<String>();
    format!("{prefix}...redacted")
}

fn redact_log_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('+') && trimmed.chars().all(|c| c == '+' || c.is_ascii_digit()) {
        return mask_phone_number(trimmed);
    }
    if trimmed.len() > MAX_LOG_FIELD_CHARS {
        format!("{}...truncated", &trimmed[..MAX_LOG_FIELD_CHARS])
    } else {
        trimmed.into()
    }
}

/// Deterministic mock-provider fixture metadata for tests and harnesses.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MockVoiceProviderFixture {
    /// Fixture identifier.
    pub id: String,
    /// Provider exercised by this fixture.
    pub provider: VoiceProvider,
    /// Redaction-safe request hash.
    pub request_hash: String,
    /// Redaction-safe session hash.
    pub session_hash: String,
}

impl MockVoiceProviderFixture {
    /// Create a redaction-safe fixture descriptor.
    pub fn new(
        id: impl Into<String>,
        provider: VoiceProvider,
        request_material: &str,
        session_material: &str,
    ) -> Self {
        Self {
            id: id.into(),
            provider,
            request_hash: stable_redacted_hash(request_material),
            session_hash: stable_redacted_hash(session_material),
        }
    }
}

/// Provider-neutral call shutdown reason.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallShutdownReason {
    /// Provider reported a terminal callback.
    ProviderCompleted,
    /// Agent cancelled the call.
    AgentCancelled,
    /// Session expired.
    Timeout,
    /// Connector shutdown requested cleanup.
    ConnectorShutdown,
}

/// Redaction-safe cleanup/shutdown result.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallCleanupResult {
    /// Provider being cleaned up.
    pub provider: VoiceProvider,
    /// Redaction-safe call identifier hash.
    pub call_id_hash: String,
    /// Shutdown reason.
    pub reason: CallShutdownReason,
    /// Whether cleanup completed.
    pub cleanup_ok: bool,
    /// Optional FCP error code.
    pub fcp_error_code: Option<String>,
}

impl CallCleanupResult {
    /// Successful cleanup result.
    pub fn completed(provider: VoiceProvider, call_id: &str, reason: CallShutdownReason) -> Self {
        Self {
            provider,
            call_id_hash: stable_redacted_hash(call_id),
            reason,
            cleanup_ok: true,
            fcp_error_code: None,
        }
    }

    /// Failed cleanup result.
    pub fn failed(
        provider: VoiceProvider,
        call_id: &str,
        reason: CallShutdownReason,
        error: &VoiceCallError,
    ) -> Self {
        Self {
            provider,
            call_id_hash: stable_redacted_hash(call_id),
            reason,
            cleanup_ok: false,
            fcp_error_code: Some(error.to_fcp_error().error_code()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    const TEST_HMAC_KEY: &str = "fixture_hmac_key_for_signature_tests";

    fn params(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn call_auth_token_redacts_debug_and_verifies_constant_shape() {
        let binding = CallAuthToken::generate();
        assert_eq!(binding.expose_secret().len(), 22);
        assert!(!binding.expose_secret().contains('='));
        assert!(binding.verify(binding.expose_secret()));
        assert!(!binding.verify("wrong"));
        let debug = format!("{binding:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(binding.expose_secret()));
        assert_eq!(
            CallAuthToken::from_callback_parameter(binding.expose_secret())
                .expect("generated callback token should parse")
                .preview(),
            binding.preview()
        );
        assert!(CallAuthToken::from_callback_parameter("stream-token").is_err());
    }

    #[test]
    fn memory_session_store_expires_without_leaking_numbers() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let session = CallSession::new(
            VoiceProvider::Twilio,
            "z:work",
            "CA123",
            "+15551230000",
            "+15559870000",
            now,
            Duration::minutes(5),
        );
        let mut store = MemorySessionStore::default();
        let key = store.upsert(SessionScope::PerCall, session);
        assert_eq!(store.len(), 1);
        let fetched = store.get_live(&key, now + Duration::minutes(1)).unwrap();
        assert_eq!(fetched.call_id, "CA123");
        assert!(!format!("{fetched:?}").contains("+15551230000"));
        assert_eq!(store.expire(now + Duration::minutes(6)), 1);
        assert!(store.is_empty());
    }

    #[test]
    fn memory_session_store_scopes_phone_and_call_separately_and_restart_is_empty() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let session = CallSession::new(
            VoiceProvider::Telnyx,
            "z:work",
            "call-a",
            "+15551230000",
            "+15559870000",
            now,
            Duration::minutes(5),
        );
        let mut store = MemorySessionStore::with_external_persistence_boundary();
        let call_key = store.upsert(SessionScope::PerCall, session.clone());
        let phone_key = store.upsert(SessionScope::PerPhoneNumber, session);
        assert_ne!(call_key, phone_key);
        assert_eq!(
            store.persistence_mode(),
            SessionPersistenceMode::ExternalOptIn
        );
        assert_eq!(store.len(), 2);

        let restarted = MemorySessionStore::default();
        assert_eq!(
            restarted.persistence_mode(),
            SessionPersistenceMode::Disabled
        );
        assert!(restarted.is_empty());
    }

    #[test]
    fn replay_cache_marks_duplicates_and_prunes_after_window() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut cache = WebhookReplayCache::new(Duration::seconds(5));
        assert!(!cache.check_and_insert("provider:req:1", now).is_replay());
        assert!(cache.check_and_insert("provider:req:1", now).is_replay());
        assert_eq!(cache.prune(now + Duration::seconds(6)), 1);
        assert!(
            !cache
                .check_and_insert("provider:req:1", now + Duration::seconds(7))
                .is_replay()
        );
    }

    #[test]
    fn replay_keys_are_provider_prefixed_and_isolated() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut cache = WebhookReplayCache::default();
        let telnyx = digest_replay_key(VoiceProvider::Telnyx, &[b"same"]);
        let plivo = digest_replay_key(VoiceProvider::Plivo, &[b"same"]);
        assert_ne!(telnyx, plivo);
        assert!(!cache.check_and_insert(telnyx, now).is_replay());
        assert!(!cache.check_and_insert(plivo, now).is_replay());
    }

    #[test]
    fn twilio_signature_matches_sorted_hmac_and_replay_key_shape() {
        let url = "https://example.com/twilio";
        let form = params(&[
            ("From", "+15551234567"),
            ("Body", "Hello"),
            ("CallSid", "CAxxx"),
        ]);
        let signature = compute_twilio_signature(TEST_HMAC_KEY, url, &form).unwrap();
        assert_eq!(
            signature, "y0D+g6t3hy/D5qOTcyseXDVJttw=",
            "fixed vector protects Twilio HMAC canonicalization"
        );
        let replay_key = twilio_replay_key(url, &form, &signature);
        assert!(replay_key.starts_with("twilio:req:"));
    }

    #[test]
    fn twilio_verifier_accepts_valid_signature_then_marks_replay() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let url = "https://example.com/twilio";
        let form = params(&[("From", "+15551234567"), ("Body", "Hello")]);
        let signature = compute_twilio_signature(TEST_HMAC_KEY, url, &form).unwrap();
        let verifier = TwilioSignatureVerifier::new(TEST_HMAC_KEY);
        let mut cache = WebhookReplayCache::default();
        let first = verifier
            .verify(url, &form, &signature, &mut cache, now)
            .unwrap();
        let second = verifier
            .verify(url, &form, &signature, &mut cache, now)
            .unwrap();
        assert!(first.valid);
        assert!(!first.is_replay);
        assert!(second.valid);
        assert!(second.is_replay);
        assert_eq!(first.verified_request_key, second.verified_request_key);
    }

    #[test]
    fn twilio_verifier_rejects_disallowed_host_and_wrong_signature() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let form = params(&[("Body", "Hello")]);
        let signature =
            compute_twilio_signature(TEST_HMAC_KEY, "https://example.com/twilio", &form).unwrap();
        let verifier = TwilioSignatureVerifier::new(TEST_HMAC_KEY)
            .with_allowed_hosts(["hooks.example.com".into()]);
        let mut cache = WebhookReplayCache::default();
        assert!(
            verifier
                .verify(
                    "https://example.com/twilio",
                    &form,
                    &signature,
                    &mut cache,
                    now
                )
                .is_err()
        );
        let verifier = TwilioSignatureVerifier::new(TEST_HMAC_KEY);
        let denied = verifier
            .verify(
                "https://example.com/twilio",
                &form,
                "bad-base64",
                &mut cache,
                now,
            )
            .unwrap();
        assert!(!denied.valid);
        assert_eq!(denied.reason_code, "malformed_signature");
    }

    #[test]
    fn inbound_policy_trusts_forwarded_url_only_from_configured_proxy() {
        let policy = InboundPolicy::public_https()
            .with_allowed_hosts(["voice.example.com".to_string()])
            .with_trusted_proxy_hosts(["10.0.0.2".to_string()]);
        let headers = ProviderHeaders::new([
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "voice.example.com"),
        ]);
        let normalized = policy
            .normalize_url(
                "http://127.0.0.1/twilio/status?CallSid=CA123",
                &headers,
                Some("10.0.0.2"),
            )
            .unwrap();
        assert_eq!(
            normalized,
            "https://voice.example.com/twilio/status?CallSid=CA123"
        );
        assert!(
            policy
                .normalize_url("http://127.0.0.1/twilio/status", &headers, Some("10.0.0.3"),)
                .is_err()
        );
    }

    #[test]
    fn telnyx_verifier_accepts_base64_signature_and_rejects_replay() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let signing_key = SigningKey::from_bytes(&[3_u8; 32]);
        let public_key = STANDARD.encode(signing_key.verifying_key().to_bytes());
        let verifier = TelnyxSignatureVerifier::new(&public_key, Duration::minutes(5)).unwrap();
        let timestamp = now.timestamp().to_string();
        let payload =
            br#"{"data":{"event_type":"call.initiated","payload":{"from":"+15551234567"}}}"#;
        let signed_payload = telnyx_signed_payload(&timestamp, payload);
        let signature = STANDARD.encode(signing_key.sign(&signed_payload).to_bytes());
        let headers = ProviderHeaders::new([
            ("Telnyx-Timestamp", timestamp.as_str()),
            ("Telnyx-Signature-Ed25519", signature.as_str()),
        ]);
        let mut cache = WebhookReplayCache::default();
        let first = verifier.verify(&headers, payload, &mut cache, now).unwrap();
        let second = verifier.verify(&headers, payload, &mut cache, now).unwrap();
        assert!(first.valid);
        assert!(!first.is_replay);
        assert!(second.is_replay);
    }

    #[test]
    fn telnyx_verifier_accepts_spki_pem_and_rejects_stale_timestamp() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let signing_key = SigningKey::from_bytes(&[4_u8; 32]);
        let mut spki = ED25519_SPKI_DER_PREFIX.to_vec();
        spki.extend_from_slice(&signing_key.verifying_key().to_bytes());
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            STANDARD.encode(spki)
        );
        let verifier = TelnyxSignatureVerifier::new(&pem, Duration::minutes(5)).unwrap();
        let timestamp = (now - Duration::minutes(6)).timestamp().to_string();
        let payload = br#"{"data":{"event_type":"call.answered"}}"#;
        let signed_payload = telnyx_signed_payload(&timestamp, payload);
        let signature = STANDARD.encode(signing_key.sign(&signed_payload).to_bytes());
        let headers = ProviderHeaders::new([
            ("telnyx-timestamp", timestamp.as_str()),
            ("telnyx-signature-ed25519", signature.as_str()),
        ]);
        let mut cache = WebhookReplayCache::default();
        let err = verifier
            .verify(&headers, payload, &mut cache, now)
            .expect_err("stale timestamp must fail closed");
        assert!(matches!(
            err,
            VoiceCallError::TimestampOutsideTolerance { .. }
        ));
    }

    #[test]
    fn telnyx_verifier_accepts_raw_hex_public_key_through_trait() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let signing_key = SigningKey::from_bytes(&[5_u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let verifier = TelnyxSignatureVerifier::new(&public_key, Duration::minutes(5)).unwrap();
        let timestamp = now.timestamp().to_string();
        let payload = br#"{"data":{"event_type":"call.bridged"}}"#;
        let signed_payload = telnyx_signed_payload(&timestamp, payload);
        let signature = STANDARD.encode(signing_key.sign(&signed_payload).to_bytes());
        let headers = ProviderHeaders::new([
            ("telnyx-timestamp", timestamp.as_str()),
            ("telnyx-signature-ed25519", signature.as_str()),
        ]);
        let mut cache = WebhookReplayCache::default();
        let telnyx_result = verifier
            .verify_request(
                TelnyxVerificationRequest {
                    headers: &headers,
                    raw_json_payload: payload,
                    now,
                },
                &mut cache,
            )
            .unwrap();
        assert_eq!(verifier.provider(), VoiceProvider::Telnyx);
        assert!(telnyx_result.valid);
    }

    #[test]
    fn plivo_v2_matches_sdk_shape_and_accepts_comma_separated_signature() {
        let verifier = PlivoSignatureVerifier::new("plivo_test_auth_token");
        let url = "https://example.com/answer/?ignored=query";
        let nonce = "05429567804466091622";
        let signature = verifier
            .compute(
                PlivoSignatureVersion::V2,
                VoiceWebhookMethod::Get,
                url,
                &BTreeMap::new(),
                nonce,
            )
            .unwrap();
        assert_eq!(signature, "VsV6OMNPwof2Xzndy/tbRHiVryVEKo5Y80vilsNiGJU=");
        let headers = ProviderHeaders::new([
            ("X-Plivo-Signature-V2", format!("wrong,{signature}")),
            ("X-Plivo-Signature-V2-Nonce", nonce.into()),
        ]);
        let mut cache = WebhookReplayCache::default();
        let empty_params = BTreeMap::new();
        let plivo_result = verifier
            .verify(
                PlivoVerificationRequest {
                    version: PlivoSignatureVersion::V2,
                    method: VoiceWebhookMethod::Get,
                    url,
                    params: &empty_params,
                    headers: &headers,
                    now: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                },
                &mut cache,
            )
            .unwrap();
        assert!(plivo_result.valid);
    }

    #[test]
    fn plivo_v3_canonicalizes_query_post_and_nested_params() {
        let verifier = PlivoSignatureVerifier::new("plivo_test_auth_token");
        let mut params = BTreeMap::new();
        params.insert("To".into(), "+15555555555".into());
        params.insert("From".into(), "+15551111111".into());
        params.insert("Digits".into(), "1234".into());
        params.insert(
            "CallUUID".into(),
            "4vbcpem8-0u46-x1ha-9af1-438vc92bf374".into(),
        );
        let base = build_plivo_v3_base_string(
            VoiceWebhookMethod::Post,
            "https://example.com/abcd?foo=bar",
            &params,
        )
        .unwrap();
        assert_eq!(
            base,
            "https://example.com/abcd?foo=bar.CallUUID4vbcpem8-0u46-x1ha-9af1-438vc92bf374Digits1234From+15551111111To+15555555555"
        );
        let signature = verifier
            .compute(
                PlivoSignatureVersion::V3,
                VoiceWebhookMethod::Post,
                "https://example.com/abcd?foo=bar",
                &params,
                "kjsdhfsd87sd7yisud2",
            )
            .unwrap();
        assert_eq!(signature, "Rd0E/xpBKM9WgLTg4CX7mKwJlvGex3GvJivzq1ESO6c=");

        let headers = ProviderHeaders::new([
            ("X-Plivo-Signature-V3", format!("bad,{signature}")),
            (
                "X-Plivo-Signature-V3-Nonce",
                "kjsdhfsd87sd7yisud2".to_string(),
            ),
        ]);
        let mut cache = WebhookReplayCache::default();
        let plivo_v3_result = verifier
            .verify_request(
                PlivoVerificationRequest {
                    version: PlivoSignatureVersion::V3,
                    method: VoiceWebhookMethod::Post,
                    url: "https://example.com/abcd?foo=bar",
                    params: &params,
                    headers: &headers,
                    now: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                },
                &mut cache,
            )
            .unwrap();
        assert!(plivo_v3_result.valid);
    }

    #[test]
    fn mock_fixture_and_cleanup_results_are_redaction_safe() {
        let fixture = MockVoiceProviderFixture::new(
            "telnyx-call-bridged",
            VoiceProvider::Telnyx,
            "request with +15551234567",
            "session CA123",
        );
        assert!(fixture.request_hash.starts_with("hash:"));
        assert!(!format!("{fixture:?}").contains("+15551234567"));

        let cleanup = CallCleanupResult::completed(
            VoiceProvider::Telnyx,
            "CA123",
            CallShutdownReason::ProviderCompleted,
        );
        assert!(cleanup.cleanup_ok);
        assert!(cleanup.call_id_hash.starts_with("hash:"));
        assert!(!format!("{cleanup:?}").contains("CA123"));

        let failed = CallCleanupResult::failed(
            VoiceProvider::Plivo,
            "CA999",
            CallShutdownReason::ConnectorShutdown,
            &VoiceCallError::InvalidSignature("bad fixture".into()),
        );
        assert_eq!(failed.fcp_error_code.as_deref(), Some("FCP-2003"));
    }

    #[test]
    fn evidence_event_redacts_numbers_and_request_keys() {
        let verification = SignatureVerification {
            provider: VoiceProvider::Twilio,
            valid: true,
            reason_code: "signature_validated".into(),
            reason: "Signature is valid".into(),
            is_replay: false,
            verified_request_key: Some("twilio:req:abcdefghijklmnopqrstuvwxyz".into()),
        };
        let event = VoiceEvidenceEvent::from_verification("twilio_signature", &verification)
            .with_field("from", "+15551234567")
            .with_field("long", "x".repeat(MAX_LOG_FIELD_CHARS + 10));
        let line = event.to_jsonl_line().unwrap();
        assert!(line.contains("+15***4567"));
        assert!(!line.contains("+15551234567"));
        assert!(line.contains("twilio:r...redacted"));
        assert!(line.contains("truncated"));
    }
}
