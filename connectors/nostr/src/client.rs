//! Nostr relay client: crypto, WebSocket relay communication, and `ConnectorRuntime` integration.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cbc::{Decryptor, Encryptor};
use fcp_prelude::{FcpError, FcpResult};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_streaming::{StreamError, WsClient, WsConnection, WsMessage};
use rand::{RngCore, rngs::OsRng};
use secp256k1::{
    Keypair, Message, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey, ecdh,
    schnorr::Signature,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::types::{
    DEFAULT_INBOUND_DM_FUTURE_SKEW_SECS, DEFAULT_INBOUND_DM_GLOBAL_RATE_LIMIT,
    DEFAULT_INBOUND_DM_MAX_CONTENT_BYTES, DEFAULT_INBOUND_DM_PER_SENDER_RATE_LIMIT,
    DEFAULT_INBOUND_DM_RATE_WINDOW_SECS, DEFAULT_INBOUND_DM_SEEN_EVENT_CAPACITY,
    DEFAULT_INBOUND_DM_STALE_AFTER_SECS, DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
    DEFAULT_RELAY_CIRCUIT_RESET_MS, EVENT_INBOUND_DM, InboundDmPolicyMode, MAX_DM_PLAINTEXT_BYTES,
    NIP01_KIND_PROFILE, NIP04_KIND_ENCRYPTED_DM, NostrConfig, NostrInboundDmConfig, OP_HEALTH,
    OP_PROFILE_IMPORT, OP_PROFILE_PUBLISH, OP_PUBLISH_NOTE, OP_QUERY_EVENTS, OP_RELAYS_HEALTH,
    OP_SEND_DM, RelayUrlPolicy, build_filter, canonicalize_relay_url, canonicalize_relay_urls,
    dm_tags, merge_profiles, normalize_public_key_input, normalize_secret_key_input, note_kind,
    note_tags, parse_dm_send_input, parse_profile_import_input, parse_profile_publish_input,
    profile_from_imported_content, profile_to_content_value, required_string,
    sanitize_profile_for_display,
};

const READ_ONLY_RECONNECT_ATTEMPTS: usize = 2;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

// ─── Relay binding ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RelayBinding {
    url: Url,
}

impl RelayBinding {
    /// Parse and validate a Nostr relay URL under production policy.
    ///
    /// # Errors
    ///
    /// Returns an error if `raw` is empty, malformed, or does not use
    /// `ws://` or `wss://`.
    pub fn parse(raw: &str) -> FcpResult<Self> {
        Self::parse_with_policy(raw, RelayUrlPolicy::production())
    }

    /// Parse and validate a Nostr relay URL under an explicit policy.
    ///
    /// # Errors
    ///
    /// Returns an error if `raw` is empty, malformed, or rejected by policy.
    pub fn parse_with_policy(raw: &str, policy: RelayUrlPolicy) -> FcpResult<Self> {
        let url = canonicalize_relay_url(raw, policy)?;
        Ok(Self { url })
    }

    #[must_use]
    pub const fn from_url(url: Url) -> Self {
        Self { url }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

// ─── Relay resilience state ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayCircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
pub struct RelayCircuitBreaker {
    state: RelayCircuitState,
    failure_count: u32,
    failure_threshold: u32,
    reset_after_ms: u64,
    last_failure_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayResiliencePolicy {
    pub failure_threshold: u32,
    pub reset_after_ms: u64,
}

impl RelayResiliencePolicy {
    #[must_use]
    pub const fn new(failure_threshold: u32, reset_after_ms: u64) -> Self {
        Self {
            failure_threshold,
            reset_after_ms,
        }
    }
}

impl Default for RelayResiliencePolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
            DEFAULT_RELAY_CIRCUIT_RESET_MS,
        )
    }
}

impl RelayCircuitBreaker {
    #[must_use]
    pub const fn new(failure_threshold: u32, reset_after_ms: u64) -> Self {
        Self {
            state: RelayCircuitState::Closed,
            failure_count: 0,
            failure_threshold,
            reset_after_ms,
            last_failure_ms: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> RelayCircuitState {
        self.state
    }

    #[must_use]
    pub const fn failure_count(&self) -> u32 {
        self.failure_count
    }

    pub const fn can_attempt(&mut self, now_ms: u64) -> bool {
        match self.state {
            RelayCircuitState::Closed | RelayCircuitState::HalfOpen => true,
            RelayCircuitState::Open => {
                let Some(last_failure_ms) = self.last_failure_ms else {
                    self.state = RelayCircuitState::HalfOpen;
                    return true;
                };
                if now_ms.saturating_sub(last_failure_ms) >= self.reset_after_ms {
                    self.state = RelayCircuitState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub const fn record_success(&mut self) {
        self.state = RelayCircuitState::Closed;
        self.failure_count = 0;
        self.last_failure_ms = None;
    }

    pub const fn record_failure(&mut self, now_ms: u64) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_failure_ms = Some(now_ms);
        self.state = match self.state {
            RelayCircuitState::HalfOpen => RelayCircuitState::Open,
            RelayCircuitState::Closed | RelayCircuitState::Open => {
                if self.failure_count >= self.failure_threshold {
                    RelayCircuitState::Open
                } else {
                    RelayCircuitState::Closed
                }
            }
        };
    }
}

impl Default for RelayCircuitBreaker {
    fn default() -> Self {
        let policy = RelayResiliencePolicy::default();
        Self::new(policy.failure_threshold, policy.reset_after_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayResilienceSnapshot {
    pub relay_url: String,
    pub circuit_state: RelayCircuitState,
    pub success_count: u64,
    pub failure_count: u64,
    pub skipped_count: u64,
    pub average_latency_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct RelayResilienceState {
    circuit_breaker: RelayCircuitBreaker,
    success_count: u64,
    failure_count: u64,
    skipped_count: u64,
    latency_total_ms: u128,
    latency_count: u64,
    last_error: Option<String>,
}

impl RelayResilienceState {
    const fn new(policy: RelayResiliencePolicy) -> Self {
        Self {
            circuit_breaker: RelayCircuitBreaker::new(
                policy.failure_threshold,
                policy.reset_after_ms,
            ),
            success_count: 0,
            failure_count: 0,
            skipped_count: 0,
            latency_total_ms: 0,
            latency_count: 0,
            last_error: None,
        }
    }

    const fn can_attempt(&mut self, now_ms: u64) -> bool {
        let allowed = self.circuit_breaker.can_attempt(now_ms);
        if !allowed {
            self.skipped_count = self.skipped_count.saturating_add(1);
        }
        allowed
    }

    fn record_success(&mut self, latency_ms: u128) {
        self.circuit_breaker.record_success();
        self.success_count = self.success_count.saturating_add(1);
        self.latency_total_ms = self.latency_total_ms.saturating_add(latency_ms);
        self.latency_count = self.latency_count.saturating_add(1);
        self.last_error = None;
    }

    fn record_failure(&mut self, now_ms: u64, error: String) {
        self.circuit_breaker.record_failure(now_ms);
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_error = Some(error);
    }

    fn snapshot(&self, relay_url: &str) -> RelayResilienceSnapshot {
        let average_latency_ms = if self.latency_count == 0 {
            None
        } else {
            let average = self.latency_total_ms / u128::from(self.latency_count);
            Some(u64::try_from(average).unwrap_or(u64::MAX))
        };
        RelayResilienceSnapshot {
            relay_url: relay_url.to_string(),
            circuit_state: self.circuit_breaker.state(),
            success_count: self.success_count,
            failure_count: self.failure_count,
            skipped_count: self.skipped_count,
            average_latency_ms,
            last_error: self.last_error.clone(),
        }
    }
}

impl std::fmt::Debug for RelayBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayBinding")
            .field("url", &self.url.as_str())
            .finish()
    }
}

// ─── Key material ────────────────────────────────────────────────────────

pub struct NostrKeyMaterial {
    secret_key: SecretKey,
    public_key_hex: String,
}

impl NostrKeyMaterial {
    /// Construct key material from a raw-hex or NIP-19 `nsec` secp256k1 secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is malformed or invalid.
    pub fn from_secret_key_input(raw: &str) -> FcpResult<Self> {
        let secret_key = parse_secret_key(raw)?;
        let public_key_hex = derive_public_key_hex(&secret_key);
        Ok(Self {
            secret_key,
            public_key_hex,
        })
    }

    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }
}

impl std::fmt::Debug for NostrKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrKeyMaterial")
            .field("secret_key", &"[REDACTED]")
            .field("public_key_hex", &self.public_key_hex)
            .finish()
    }
}

// ─── Crypto functions ────────────────────────────────────────────────────

/// Parse a raw-hex or NIP-19 `nsec` secp256k1 secret key.
///
/// # Errors
///
/// Returns an error if `raw` is not valid raw hex or `nsec`, or does not decode
/// to a valid secp256k1 secret scalar.
pub fn parse_secret_key(raw: &str) -> FcpResult<SecretKey> {
    let normalized = normalize_secret_key_input(raw)?;
    let bytes =
        hex::decode(normalized.canonical_secret_hex()).map_err(|error| FcpError::Internal {
            message: format!("normalized Nostr secret key hex failed to decode: {error}"),
        })?;
    SecretKey::from_slice(&bytes).map_err(|error| FcpError::Internal {
        message: format!("normalized Nostr secret key unexpectedly failed validation: {error}"),
    })
}

#[must_use]
pub fn derive_public_key_hex(secret_key: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    pubkey.to_string()
}

/// Build and sign a Nostr event object for relay submission.
///
/// # Errors
///
/// Returns an error if the event cannot be encoded, hashed, or signed.
pub fn build_signed_event(
    secret_key: &SecretKey,
    public_key_hex: &str,
    kind: u64,
    tags: &Value,
    content: &str,
) -> FcpResult<Value> {
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| FcpError::Internal {
            message: format!("system clock error: {error}"),
        })?
        .as_secs();
    build_signed_event_at(secret_key, public_key_hex, kind, tags, content, created_at)
}

/// Build and sign a Nostr event object using a caller-selected timestamp.
///
/// # Errors
///
/// Returns an error if the event cannot be encoded, hashed, or signed.
pub fn build_signed_event_at(
    secret_key: &SecretKey,
    public_key_hex: &str,
    kind: u64,
    tags: &Value,
    content: &str,
    created_at: u64,
) -> FcpResult<Value> {
    let canonical = json!([0, public_key_hex, created_at, kind, tags, content]);
    let canonical_bytes = serde_json::to_vec(&canonical).map_err(|error| FcpError::Internal {
        message: format!("failed to encode Nostr canonical event: {error}"),
    })?;
    let id = hex::encode(Sha256::digest(canonical_bytes));
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let msg =
        Message::from_digest_slice(&hex::decode(&id).map_err(|error| FcpError::Internal {
            message: format!("failed to decode event id hex: {error}"),
        })?)
        .map_err(|error| FcpError::Internal {
            message: format!("failed to build secp256k1 message: {error}"),
        })?;
    let sig: Signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    Ok(json!({
        "id": id,
        "pubkey": public_key_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig.to_string(),
    }))
}

/// Build and sign a NIP-01 kind=0 profile event.
///
/// # Errors
///
/// Returns an error if profile validation, content encoding, or signing fails.
pub fn build_profile_event(
    secret_key: &SecretKey,
    public_key_hex: &str,
    profile: &crate::types::NostrProfile,
    last_published_at: Option<u64>,
) -> FcpResult<Value> {
    profile.validate()?;
    let now = current_unix_seconds();
    let created_at = last_published_at.map_or(now, |last| now.max(last.saturating_add(1)));
    let content = serde_json::to_string(&profile_to_content_value(profile)).map_err(|error| {
        FcpError::Internal {
            message: format!("failed to encode Nostr profile content: {error}"),
        }
    })?;
    build_signed_event_at(
        secret_key,
        public_key_hex,
        NIP01_KIND_PROFILE,
        &json!([]),
        &content,
        created_at,
    )
}

#[must_use]
pub fn verify_nostr_event_signature(event: &Value) -> bool {
    let Some(event_id) = event.get("id").and_then(Value::as_str) else {
        return false;
    };
    let Some(pubkey_hex) = event.get("pubkey").and_then(Value::as_str) else {
        return false;
    };
    let Some(created_at) = event.get("created_at").and_then(Value::as_u64) else {
        return false;
    };
    let Some(kind) = event.get("kind").and_then(Value::as_u64) else {
        return false;
    };
    let Some(content) = event.get("content").and_then(Value::as_str) else {
        return false;
    };
    let Some(tags) = event.get("tags") else {
        return false;
    };
    let Some(sig) = event.get("sig").and_then(Value::as_str) else {
        return false;
    };
    let canonical = json!([0, pubkey_hex, created_at, kind, tags, content]);
    let Ok(canonical_bytes) = serde_json::to_vec(&canonical) else {
        return false;
    };
    let expected_id = hex::encode(Sha256::digest(canonical_bytes));
    if expected_id != event_id {
        return false;
    }
    let Ok(message_bytes) = hex::decode(event_id) else {
        return false;
    };
    let Ok(message) = Message::from_digest_slice(&message_bytes) else {
        return false;
    };
    let Ok(pubkey_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey_bytes) else {
        return false;
    };
    let Ok(signature) = Signature::from_str(sig) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &pubkey)
        .is_ok()
}

#[must_use]
pub fn profile_event_matches(event: &Value, expected_pubkey_hex: &str) -> bool {
    event.get("kind").and_then(Value::as_u64) == Some(NIP01_KIND_PROFILE)
        && event.get("pubkey").and_then(Value::as_str) == Some(expected_pubkey_hex)
        && event
            .get("content")
            .and_then(Value::as_str)
            .and_then(|content| serde_json::from_str::<Value>(content).ok())
            .is_some_and(|content| content.is_object())
        && verify_nostr_event_signature(event)
}

fn select_profile_import_candidate(
    candidates: Vec<(String, Value)>,
    expected_pubkey_hex: &str,
) -> (Option<(String, Value, u64)>, Vec<Value>) {
    let mut best: Option<(String, Value, u64)> = None;
    let mut invalid_candidates = Vec::new();
    for (relay, event) in candidates {
        if !profile_event_matches(&event, expected_pubkey_hex) {
            invalid_candidates.push(json!({
                "relay": relay,
                "event_id": event.get("id").cloned().unwrap_or(Value::Null),
                "result": "invalid_signature_or_shape",
            }));
            continue;
        }
        let created_at = event
            .get("created_at")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if best
            .as_ref()
            .is_none_or(|(_, _, best_created)| created_at > *best_created)
        {
            best = Some((relay, event, created_at));
        }
    }
    (best, invalid_candidates)
}

/// Build, encrypt, and sign a NIP-04 encrypted DM event.
///
/// # Errors
///
/// Returns an error if the recipient cannot be normalized, plaintext is
/// invalid, NIP-04 encryption fails, or event signing fails.
pub fn build_nip04_dm_event(
    secret_key: &SecretKey,
    sender_public_key_hex: &str,
    recipient_pubkey: &str,
    plaintext: &str,
    reply_to_event_id: Option<&str>,
) -> FcpResult<Value> {
    let mut iv = [0_u8; 16];
    OsRng.fill_bytes(&mut iv);
    build_nip04_dm_event_with_iv(
        secret_key,
        sender_public_key_hex,
        recipient_pubkey,
        plaintext,
        reply_to_event_id,
        iv,
    )
}

fn build_nip04_dm_event_with_iv(
    secret_key: &SecretKey,
    sender_public_key_hex: &str,
    recipient_pubkey: &str,
    plaintext: &str,
    reply_to_event_id: Option<&str>,
    iv: [u8; 16],
) -> FcpResult<Value> {
    let normalized_recipient = normalize_public_key_input(recipient_pubkey)?;
    let encrypted_content = nip04_encrypt_plaintext_with_iv(
        secret_key,
        normalized_recipient.canonical_public_key_hex(),
        plaintext,
        iv,
    )?;
    let tags = dm_tags(
        normalized_recipient.canonical_public_key_hex(),
        reply_to_event_id,
    )?;
    build_signed_event(
        secret_key,
        sender_public_key_hex,
        NIP04_KIND_ENCRYPTED_DM,
        &tags,
        &encrypted_content,
    )
}

fn nip04_encrypt_plaintext_with_iv(
    secret_key: &SecretKey,
    recipient_pubkey: &str,
    plaintext: &str,
    iv: [u8; 16],
) -> FcpResult<String> {
    if plaintext.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "Nostr DM plaintext must be a non-empty string".into(),
        });
    }
    let message_len = plaintext.len();
    if message_len > MAX_DM_PLAINTEXT_BYTES {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "Nostr DM plaintext exceeds {MAX_DM_PLAINTEXT_BYTES} byte limit; got {message_len} bytes"
            ),
        });
    }
    let recipient_public_key = recipient_public_key_for_nip04(recipient_pubkey)?;
    let shared_point = ecdh::shared_secret_point(&recipient_public_key, secret_key);
    let mut shared_x = [0_u8; 32];
    shared_x.copy_from_slice(&shared_point[..32]);

    let plaintext_bytes = plaintext.as_bytes();
    let padded_len = ((message_len / 16) + 1) * 16;
    let mut buffer = vec![0_u8; padded_len];
    buffer[..message_len].copy_from_slice(plaintext_bytes);
    let ciphertext = Aes256CbcEnc::new_from_slices(&shared_x, &iv)
        .map_err(|error| FcpError::Internal {
            message: format!("failed to initialize NIP-04 AES-256-CBC encryptor: {error}"),
        })?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, message_len)
        .map_err(|_| FcpError::Internal {
            message: "failed to apply NIP-04 PKCS#7 padding".into(),
        })?;

    Ok(format!(
        "{}?iv={}",
        BASE64.encode(ciphertext),
        BASE64.encode(iv)
    ))
}

fn recipient_public_key_for_nip04(recipient_pubkey: &str) -> FcpResult<PublicKey> {
    public_key_for_nip04(recipient_pubkey, "recipient")
}

fn public_key_for_nip04(public_key: &str, role: &str) -> FcpResult<PublicKey> {
    let normalized = normalize_public_key_input(public_key)?;
    let public_key_bytes = hex::decode(normalized.canonical_public_key_hex()).map_err(|error| {
        FcpError::InvalidRequest {
            code: 1005,
            message: format!("Nostr DM {role} public key must be valid hex: {error}"),
        }
    })?;
    let x_only =
        XOnlyPublicKey::from_slice(&public_key_bytes).map_err(|_| FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "Nostr DM {role} public key must be a valid secp256k1 x-only public key"
            ),
        })?;
    Ok(PublicKey::from_x_only_public_key(x_only, Parity::Even))
}

fn nip04_decrypt_content(
    secret_key: &SecretKey,
    sender_pubkey: &str,
    content: &str,
) -> Result<String, InboundDmRejectionReason> {
    let (ciphertext_b64, iv_b64) = content
        .split_once("?iv=")
        .ok_or(InboundDmRejectionReason::MalformedCiphertext)?;
    if ciphertext_b64.is_empty() || iv_b64.is_empty() {
        return Err(InboundDmRejectionReason::MalformedCiphertext);
    }
    let sender_public_key = public_key_for_nip04(sender_pubkey, "sender")
        .map_err(|_| InboundDmRejectionReason::MalformedEvent)?;
    let shared_point = ecdh::shared_secret_point(&sender_public_key, secret_key);
    let mut shared_x = [0_u8; 32];
    shared_x.copy_from_slice(&shared_point[..32]);
    let iv = BASE64
        .decode(iv_b64)
        .map_err(|_| InboundDmRejectionReason::MalformedCiphertext)?;
    if iv.len() != 16 {
        return Err(InboundDmRejectionReason::MalformedCiphertext);
    }
    let mut ciphertext = BASE64
        .decode(ciphertext_b64)
        .map_err(|_| InboundDmRejectionReason::MalformedCiphertext)?;
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(InboundDmRejectionReason::MalformedCiphertext);
    }
    let plaintext = Aes256CbcDec::new_from_slices(&shared_x, &iv)
        .map_err(|_| InboundDmRejectionReason::DecryptFailed)?
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
        .map_err(|_| InboundDmRejectionReason::DecryptFailed)?;
    String::from_utf8(plaintext.to_vec()).map_err(|_| InboundDmRejectionReason::DecryptFailed)
}

// ─── Inbound NIP-04 DM validation core ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundDmPolicy {
    mode: InboundDmPolicyMode,
    allowed_senders: BTreeSet<String>,
    stale_after_secs: i64,
    future_skew_secs: i64,
    max_content_bytes: usize,
}

impl InboundDmPolicy {
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            mode: InboundDmPolicyMode::Disabled,
            allowed_senders: BTreeSet::new(),
            stale_after_secs: DEFAULT_INBOUND_DM_STALE_AFTER_SECS,
            future_skew_secs: DEFAULT_INBOUND_DM_FUTURE_SKEW_SECS,
            max_content_bytes: DEFAULT_INBOUND_DM_MAX_CONTENT_BYTES,
        }
    }

    #[must_use]
    pub const fn open() -> Self {
        Self {
            mode: InboundDmPolicyMode::Open,
            allowed_senders: BTreeSet::new(),
            stale_after_secs: DEFAULT_INBOUND_DM_STALE_AFTER_SECS,
            future_skew_secs: DEFAULT_INBOUND_DM_FUTURE_SKEW_SECS,
            max_content_bytes: DEFAULT_INBOUND_DM_MAX_CONTENT_BYTES,
        }
    }

    /// Build an allowlist policy from raw hex, `npub`, or `nostr:npub` sender keys.
    ///
    /// # Errors
    ///
    /// Returns an error if any sender key cannot be normalized.
    pub fn allowlist<I, S>(senders: I) -> FcpResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self {
            mode: InboundDmPolicyMode::Allowlist,
            allowed_senders: normalize_sender_set(senders)?,
            ..Self::open()
        })
    }

    /// Build an FCP pairing-equivalent policy from an explicit paired sender set.
    ///
    /// `OpenClaw`'s pairing is gateway-stateful. This core represents the same
    /// decision point as an explicit sender set so the host/subscription layer
    /// can own how pairings are established.
    ///
    /// # Errors
    ///
    /// Returns an error if any sender key cannot be normalized.
    pub fn pairing_equivalent<I, S>(paired_senders: I) -> FcpResult<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self {
            mode: InboundDmPolicyMode::PairingEquivalent,
            allowed_senders: normalize_sender_set(paired_senders)?,
            ..Self::open()
        })
    }

    /// Build inbound policy from operator configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured policy or sender keys are invalid.
    pub fn from_config(config: &NostrInboundDmConfig) -> FcpResult<Self> {
        config.validate()?;
        let policy = match config.policy_mode {
            InboundDmPolicyMode::Disabled => Self::disabled(),
            InboundDmPolicyMode::Open => Self::open(),
            InboundDmPolicyMode::Allowlist => Self::allowlist(&config.allowed_senders)?,
            InboundDmPolicyMode::PairingEquivalent => {
                Self::pairing_equivalent(&config.allowed_senders)?
            }
        };
        Ok(policy
            .with_time_bounds(config.stale_after_secs, config.future_skew_secs)
            .with_max_content_bytes(config.max_content_bytes))
    }

    #[must_use]
    pub const fn mode(&self) -> InboundDmPolicyMode {
        self.mode
    }

    #[must_use]
    pub const fn max_content_bytes(&self) -> usize {
        self.max_content_bytes
    }

    #[must_use]
    pub const fn stale_after_secs(&self) -> i64 {
        self.stale_after_secs
    }

    #[must_use]
    pub const fn future_skew_secs(&self) -> i64 {
        self.future_skew_secs
    }

    #[must_use]
    pub const fn with_time_bounds(mut self, stale_after_secs: i64, future_skew_secs: i64) -> Self {
        self.stale_after_secs = stale_after_secs;
        self.future_skew_secs = future_skew_secs;
        self
    }

    #[must_use]
    pub const fn with_max_content_bytes(mut self, max_content_bytes: usize) -> Self {
        self.max_content_bytes = max_content_bytes;
        self
    }

    fn allows_sender(&self, sender_pubkey: &str) -> Result<(), InboundDmRejectionReason> {
        match self.mode {
            InboundDmPolicyMode::Disabled => Err(InboundDmRejectionReason::PolicyDisabled),
            InboundDmPolicyMode::Open => Ok(()),
            InboundDmPolicyMode::Allowlist | InboundDmPolicyMode::PairingEquivalent => self
                .allowed_senders
                .contains(sender_pubkey)
                .then_some(())
                .ok_or(InboundDmRejectionReason::PolicySenderBlocked),
        }
    }
}

impl Default for InboundDmPolicy {
    fn default() -> Self {
        Self::open()
    }
}

fn normalize_sender_set<I, S>(senders: I) -> FcpResult<BTreeSet<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    senders
        .into_iter()
        .map(|sender| {
            normalize_public_key_input(sender.as_ref())
                .map(|normalized| normalized.canonical_public_key_hex().to_string())
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundDmRateLimits {
    pub window_secs: i64,
    pub global_max_events: u32,
    pub per_sender_max_events: u32,
}

impl InboundDmRateLimits {
    #[must_use]
    pub const fn new(window_secs: i64, global_max_events: u32, per_sender_max_events: u32) -> Self {
        Self {
            window_secs,
            global_max_events,
            per_sender_max_events,
        }
    }
}

impl Default for InboundDmRateLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_INBOUND_DM_RATE_WINDOW_SECS,
            DEFAULT_INBOUND_DM_GLOBAL_RATE_LIMIT,
            DEFAULT_INBOUND_DM_PER_SENDER_RATE_LIMIT,
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InboundDmRateState {
    window_started_at: Option<i64>,
    global_count: u32,
    per_sender_counts: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Copy)]
struct InboundDmRateRecord {
    global_bucket_before: u32,
    global_bucket_after: u32,
    sender_bucket_before: u32,
    sender_bucket_after: u32,
    rate_limit_scope: Option<&'static str>,
    retry_after_ms: Option<u64>,
    window_started_at: Option<i64>,
}

impl InboundDmRateState {
    fn record(
        &mut self,
        sender_pubkey: &str,
        now_secs: i64,
        limits: InboundDmRateLimits,
    ) -> (Option<InboundDmRejectionReason>, InboundDmRateRecord) {
        self.reset_if_needed(now_secs, limits.window_secs);
        let global_before = self.global_count;
        let sender_before = self
            .per_sender_counts
            .get(sender_pubkey)
            .copied()
            .unwrap_or_default();
        if self.global_count >= limits.global_max_events {
            return (
                Some(InboundDmRejectionReason::GlobalRateLimited),
                InboundDmRateRecord {
                    global_bucket_before: global_before,
                    global_bucket_after: self.global_count,
                    sender_bucket_before: sender_before,
                    sender_bucket_after: sender_before,
                    rate_limit_scope: Some("global"),
                    retry_after_ms: self.retry_after_ms(now_secs, limits.window_secs),
                    window_started_at: self.window_started_at,
                },
            );
        }
        if sender_before >= limits.per_sender_max_events {
            return (
                Some(InboundDmRejectionReason::SenderRateLimited),
                InboundDmRateRecord {
                    global_bucket_before: global_before,
                    global_bucket_after: self.global_count,
                    sender_bucket_before: sender_before,
                    sender_bucket_after: sender_before,
                    rate_limit_scope: Some("sender"),
                    retry_after_ms: self.retry_after_ms(now_secs, limits.window_secs),
                    window_started_at: self.window_started_at,
                },
            );
        }
        self.global_count = self.global_count.saturating_add(1);
        let sender_after = sender_before.saturating_add(1);
        self.per_sender_counts
            .insert(sender_pubkey.to_string(), sender_after);
        (
            None,
            InboundDmRateRecord {
                global_bucket_before: global_before,
                global_bucket_after: self.global_count,
                sender_bucket_before: sender_before,
                sender_bucket_after: sender_after,
                rate_limit_scope: None,
                retry_after_ms: None,
                window_started_at: self.window_started_at,
            },
        )
    }

    fn reset_if_needed(&mut self, now_secs: i64, window_secs: i64) {
        let Some(window_started_at) = self.window_started_at else {
            self.window_started_at = Some(now_secs);
            return;
        };
        if now_secs < window_started_at
            || now_secs.saturating_sub(window_started_at) >= window_secs.max(1)
        {
            self.window_started_at = Some(now_secs);
            self.global_count = 0;
            self.per_sender_counts.clear();
        }
    }

    fn retry_after_ms(&self, now_secs: i64, window_secs: i64) -> Option<u64> {
        let window_started_at = self.window_started_at?;
        let retry_after_secs = window_started_at
            .saturating_add(window_secs.max(1))
            .saturating_sub(now_secs)
            .max(0);
        Some(u64::try_from(retry_after_secs).unwrap_or(u64::MAX) * 1000)
    }
}

#[derive(Debug)]
pub struct InboundDmGuardState {
    seen_events: DedupTracker,
    rate_limits: InboundDmRateLimits,
    rate_state: InboundDmRateState,
    cursor: Option<i64>,
    reconnect_generation: u64,
    restart_generation: u64,
    last_transition: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundDmGuardSnapshot {
    pub version: u32,
    pub cursor: Option<i64>,
    pub recent_event_ids: Vec<String>,
    pub seen_event_capacity: usize,
    pub overflow_count: usize,
    pub rate_limits: InboundDmRateLimits,
    pub rate_window_started_at: Option<i64>,
    pub global_count: u32,
    pub per_sender_counts: BTreeMap<String, u32>,
    pub reconnect_generation: u64,
    pub restart_generation: u64,
}

impl InboundDmGuardState {
    pub const SNAPSHOT_VERSION: u32 = 1;

    /// Create bounded inbound replay/rate-limit state.
    ///
    /// # Panics
    ///
    /// Panics if `seen_event_capacity` is zero.
    #[must_use]
    pub fn new(seen_event_capacity: usize, rate_limits: InboundDmRateLimits) -> Self {
        Self {
            seen_events: DedupTracker::new(seen_event_capacity),
            rate_limits,
            rate_state: InboundDmRateState::default(),
            cursor: None,
            reconnect_generation: 0,
            restart_generation: 0,
            last_transition: None,
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: InboundDmGuardSnapshot) -> Self {
        let capacity = snapshot.seen_event_capacity.max(1);
        let rate_limits = if snapshot.rate_limits.window_secs > 0
            && snapshot.rate_limits.global_max_events > 0
            && snapshot.rate_limits.per_sender_max_events > 0
        {
            snapshot.rate_limits
        } else {
            InboundDmRateLimits::default()
        };
        Self::from_snapshot_with_config(snapshot, capacity, rate_limits)
    }

    #[must_use]
    pub fn from_snapshot_with_config(
        snapshot: InboundDmGuardSnapshot,
        seen_event_capacity: usize,
        rate_limits: InboundDmRateLimits,
    ) -> Self {
        let mut seen_events = DedupTracker::from_recent_ids(
            seen_event_capacity,
            snapshot.recent_event_ids,
            snapshot.overflow_count,
        );
        seen_events.retain_valid_event_ids();
        Self {
            seen_events,
            rate_limits,
            rate_state: InboundDmRateState {
                window_started_at: snapshot.rate_window_started_at,
                global_count: snapshot.global_count,
                per_sender_counts: snapshot.per_sender_counts,
            },
            cursor: snapshot.cursor,
            reconnect_generation: snapshot.reconnect_generation,
            restart_generation: snapshot.restart_generation.saturating_add(1),
            last_transition: None,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> InboundDmGuardSnapshot {
        InboundDmGuardSnapshot {
            version: Self::SNAPSHOT_VERSION,
            cursor: self.cursor,
            recent_event_ids: self.seen_events.recent_event_ids(),
            seen_event_capacity: self.seen_events.max_capacity(),
            overflow_count: self.seen_events.overflow_count(),
            rate_limits: self.rate_limits,
            rate_window_started_at: self.rate_state.window_started_at,
            global_count: self.rate_state.global_count,
            per_sender_counts: self.rate_state.per_sender_counts.clone(),
            reconnect_generation: self.reconnect_generation,
            restart_generation: self.restart_generation,
        }
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<i64> {
        self.cursor
    }

    #[must_use]
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    #[must_use]
    pub const fn restart_generation(&self) -> u64 {
        self.restart_generation
    }

    pub const fn mark_reconnect(&mut self) {
        self.reconnect_generation = self.reconnect_generation.saturating_add(1);
    }

    #[must_use]
    pub fn last_transition(&self) -> Value {
        self.last_transition.clone().unwrap_or_else(|| {
            json!({
                "cursor_before": self.cursor,
                "cursor_after": self.cursor,
                "seen_state": self.seen_state_json(false, false, None),
                "seen_inserted": false,
                "seen_evicted": null,
                "duplicate_source": null,
                "reconnect_generation": self.reconnect_generation,
                "restart_generation": self.restart_generation,
                "global_bucket_before": self.rate_state.global_count,
                "global_bucket_after": self.rate_state.global_count,
                "sender_bucket_before": 0,
                "sender_bucket_after": 0,
                "rate_limit_scope": null,
                "retry_after_ms": null,
            })
        })
    }

    fn record(
        &mut self,
        event_id: &str,
        sender_pubkey: &str,
        event_created_at: i64,
        now_secs: i64,
    ) -> Result<(), InboundDmRejectionReason> {
        let cursor_before = self.cursor;
        if cursor_before.is_some_and(|cursor| event_created_at < cursor) {
            self.record_transition(
                cursor_before,
                cursor_before,
                false,
                None,
                Some("cursor"),
                InboundDmRateRecord {
                    global_bucket_before: self.rate_state.global_count,
                    global_bucket_after: self.rate_state.global_count,
                    sender_bucket_before: self
                        .rate_state
                        .per_sender_counts
                        .get(sender_pubkey)
                        .copied()
                        .unwrap_or_default(),
                    sender_bucket_after: self
                        .rate_state
                        .per_sender_counts
                        .get(sender_pubkey)
                        .copied()
                        .unwrap_or_default(),
                    rate_limit_scope: None,
                    retry_after_ms: None,
                    window_started_at: self.rate_state.window_started_at,
                },
            );
            return Err(InboundDmRejectionReason::DuplicateEvent);
        }

        if self.seen_events.contains(event_id) {
            self.record_transition(
                cursor_before,
                cursor_before,
                false,
                None,
                Some("recent_event_id"),
                InboundDmRateRecord {
                    global_bucket_before: self.rate_state.global_count,
                    global_bucket_after: self.rate_state.global_count,
                    sender_bucket_before: self
                        .rate_state
                        .per_sender_counts
                        .get(sender_pubkey)
                        .copied()
                        .unwrap_or_default(),
                    sender_bucket_after: self
                        .rate_state
                        .per_sender_counts
                        .get(sender_pubkey)
                        .copied()
                        .unwrap_or_default(),
                    rate_limit_scope: None,
                    retry_after_ms: None,
                    window_started_at: self.rate_state.window_started_at,
                },
            );
            return Err(InboundDmRejectionReason::DuplicateEvent);
        }

        let (rate_rejection, rate_record) =
            self.rate_state
                .record(sender_pubkey, now_secs, self.rate_limits);
        if let Some(reason) = rate_rejection {
            self.record_transition(cursor_before, cursor_before, false, None, None, rate_record);
            return Err(reason);
        }

        let dedup = self.seen_events.insert_with_outcome(event_id);
        let evicted = match dedup {
            DedupInsertOutcome::Inserted { evicted } => evicted,
            DedupInsertOutcome::Duplicate => {
                self.record_transition(
                    cursor_before,
                    cursor_before,
                    false,
                    None,
                    Some("recent_event_id"),
                    rate_record,
                );
                return Err(InboundDmRejectionReason::DuplicateEvent);
            }
        };
        self.record_transition(
            cursor_before,
            cursor_before,
            true,
            evicted.as_deref(),
            None,
            rate_record,
        );
        Ok(())
    }

    fn mark_accepted(&mut self, event_created_at: i64) {
        let cursor_before = self.cursor;
        self.cursor = Some(
            self.cursor
                .map_or(event_created_at, |cursor| cursor.max(event_created_at)),
        );
        if let Some(Value::Object(ref mut transition)) = self.last_transition {
            transition.insert("cursor_before".into(), json!(cursor_before));
            transition.insert("cursor_after".into(), json!(self.cursor));
            transition.insert(
                "cursor".into(),
                json!({
                    "before": cursor_before,
                    "after": self.cursor,
                }),
            );
        }
    }

    fn record_transition(
        &mut self,
        cursor_before: Option<i64>,
        cursor_after: Option<i64>,
        seen_inserted: bool,
        seen_evicted: Option<&str>,
        duplicate_source: Option<&'static str>,
        rate_record: InboundDmRateRecord,
    ) {
        self.last_transition = Some(json!({
            "cursor_before": cursor_before,
            "cursor_after": cursor_after,
            "cursor": {
                "before": cursor_before,
                "after": cursor_after,
            },
            "seen_state": self.seen_state_json(seen_inserted, duplicate_source.is_some(), seen_evicted),
            "seen_inserted": seen_inserted,
            "seen_evicted": seen_evicted,
            "duplicate_source": duplicate_source,
            "reconnect_generation": self.reconnect_generation,
            "restart_generation": self.restart_generation,
            "global_bucket_before": rate_record.global_bucket_before,
            "global_bucket_after": rate_record.global_bucket_after,
            "sender_bucket_before": rate_record.sender_bucket_before,
            "sender_bucket_after": rate_record.sender_bucket_after,
            "rate_window_started_at": rate_record.window_started_at,
            "rate_limit_scope": rate_record.rate_limit_scope,
            "retry_after_ms": rate_record.retry_after_ms,
        }));
    }

    fn seen_state_json(&self, inserted: bool, duplicate: bool, evicted: Option<&str>) -> Value {
        json!({
            "len": self.seen_events.len(),
            "capacity": self.seen_events.max_capacity(),
            "overflow_count": self.seen_events.overflow_count(),
            "inserted": inserted,
            "duplicate": duplicate,
            "evicted": evicted,
        })
    }
}

impl Default for InboundDmGuardState {
    fn default() -> Self {
        Self::new(
            DEFAULT_INBOUND_DM_SEEN_EVENT_CAPACITY,
            InboundDmRateLimits::default(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundDmRejectionReason {
    MalformedEvent,
    InvalidEventId,
    InvalidSignature,
    WrongKind,
    MissingRecipientTag,
    WrongTarget,
    SelfMessage,
    StaleEvent,
    FutureSkew,
    OversizedCiphertext,
    MalformedCiphertext,
    DecryptFailed,
    PolicyDisabled,
    PolicySenderBlocked,
    DuplicateEvent,
    GlobalRateLimited,
    SenderRateLimited,
}

impl InboundDmRejectionReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedEvent => "malformed_event",
            Self::InvalidEventId => "invalid_event_id",
            Self::InvalidSignature => "invalid_signature",
            Self::WrongKind => "wrong_kind",
            Self::MissingRecipientTag => "missing_recipient_tag",
            Self::WrongTarget => "wrong_target",
            Self::SelfMessage => "self_message",
            Self::StaleEvent => "stale_event",
            Self::FutureSkew => "future_skew",
            Self::OversizedCiphertext => "oversized_ciphertext",
            Self::MalformedCiphertext => "malformed_ciphertext",
            Self::DecryptFailed => "decrypt_failed",
            Self::PolicyDisabled => "policy_disabled",
            Self::PolicySenderBlocked => "policy_sender_blocked",
            Self::DuplicateEvent => "duplicate_event",
            Self::GlobalRateLimited => "global_rate_limited",
            Self::SenderRateLimited => "sender_rate_limited",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct InboundDmAccepted {
    pub event_id: String,
    pub sender_pubkey_hex: String,
    pub recipient_pubkey_hex: String,
    pub event_kind: u64,
    pub created_at: i64,
    pub plaintext: String,
}

impl std::fmt::Debug for InboundDmAccepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundDmAccepted")
            .field("event_id", &self.event_id)
            .field("sender_pubkey_hex", &self.sender_pubkey_hex)
            .field("recipient_pubkey_hex", &self.recipient_pubkey_hex)
            .field("event_kind", &self.event_kind)
            .field("created_at", &self.created_at)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InboundDmRejected {
    pub event_id: Option<String>,
    pub claimed_sender_pubkey_hex: Option<String>,
    pub reason: InboundDmRejectionReason,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum InboundDmDecision {
    Accepted(InboundDmAccepted),
    Rejected(InboundDmRejected),
}

impl InboundDmDecision {
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    #[must_use]
    pub const fn rejection_reason(&self) -> Option<InboundDmRejectionReason> {
        match self {
            Self::Accepted(_) => None,
            Self::Rejected(rejected) => Some(rejected.reason),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InboundDmSubscriptionOutcome {
    pub stream_id: String,
    pub relay: String,
    pub topic: String,
    pub filter: Value,
    pub diagnostics: Vec<Value>,
    pub accepted: Vec<InboundDmAccepted>,
}

impl InboundDmSubscriptionOutcome {
    #[must_use]
    pub fn new(stream_id: &str, relay: &RelayBinding, filter: Value) -> Self {
        Self {
            stream_id: stream_id.to_string(),
            relay: relay.as_str().to_string(),
            topic: EVENT_INBOUND_DM.to_string(),
            filter,
            diagnostics: Vec::new(),
            accepted: Vec::new(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn record(&mut self, stage: &'static str, detail: Value) {
        self.diagnostics.push(subscription_diagnostic(
            &self.stream_id,
            &self.relay,
            stage,
            &self.filter,
            &detail,
        ));
    }
}

struct InboundDmRawEvent {
    event_id: String,
    sender_pubkey_hex: String,
    created_at: i64,
    kind: u64,
    tags: Value,
    content: String,
    sig: String,
}

/// Validate, policy-check, rate-limit, replay-check, and decrypt one inbound NIP-04 DM event.
///
/// This is intentionally subscription-free. The stream layer can feed relay
/// events through the same core without duplicating signature, policy, or
/// decrypt logic.
#[must_use]
pub fn evaluate_inbound_dm_event(
    event: &Value,
    secret_key: &SecretKey,
    recipient_public_key_hex: &str,
    policy: &InboundDmPolicy,
    guard_state: &mut InboundDmGuardState,
    now_secs: i64,
) -> InboundDmDecision {
    let recipient = match normalize_public_key_input(recipient_public_key_hex) {
        Ok(recipient) => recipient.canonical_public_key_hex().to_string(),
        Err(_) => {
            return rejected(None, None, InboundDmRejectionReason::MalformedEvent);
        }
    };
    let raw = match parse_inbound_dm_raw_event(event) {
        Ok(raw) => raw,
        Err(rejected) => return InboundDmDecision::Rejected(rejected),
    };
    if raw.kind != NIP04_KIND_ENCRYPTED_DM {
        return rejected(
            Some(raw.event_id),
            Some(raw.sender_pubkey_hex),
            InboundDmRejectionReason::WrongKind,
        );
    }
    match recipient_tag_state(&raw.tags, &recipient) {
        RecipientTagState::Missing => {
            return rejected(
                Some(raw.event_id),
                Some(raw.sender_pubkey_hex),
                InboundDmRejectionReason::MissingRecipientTag,
            );
        }
        RecipientTagState::WrongTarget => {
            return rejected(
                Some(raw.event_id),
                Some(raw.sender_pubkey_hex),
                InboundDmRejectionReason::WrongTarget,
            );
        }
        RecipientTagState::Matches => {}
    }
    if raw.sender_pubkey_hex == recipient {
        return rejected(
            Some(raw.event_id),
            Some(raw.sender_pubkey_hex),
            InboundDmRejectionReason::SelfMessage,
        );
    }
    if now_secs.saturating_sub(raw.created_at) > policy.stale_after_secs() {
        return rejected(
            Some(raw.event_id),
            Some(raw.sender_pubkey_hex),
            InboundDmRejectionReason::StaleEvent,
        );
    }
    if raw.created_at.saturating_sub(now_secs) > policy.future_skew_secs() {
        return rejected(
            Some(raw.event_id),
            Some(raw.sender_pubkey_hex),
            InboundDmRejectionReason::FutureSkew,
        );
    }
    if raw.content.len() > policy.max_content_bytes() {
        return rejected(
            Some(raw.event_id),
            Some(raw.sender_pubkey_hex),
            InboundDmRejectionReason::OversizedCiphertext,
        );
    }
    if !verify_inbound_dm_signature(&raw) {
        return rejected(
            Some(raw.event_id),
            Some(raw.sender_pubkey_hex),
            InboundDmRejectionReason::InvalidSignature,
        );
    }
    if let Err(reason) = policy.allows_sender(&raw.sender_pubkey_hex) {
        return rejected(Some(raw.event_id), Some(raw.sender_pubkey_hex), reason);
    }
    if let Err(reason) = guard_state.record(
        &raw.event_id,
        &raw.sender_pubkey_hex,
        raw.created_at,
        now_secs,
    ) {
        return rejected(Some(raw.event_id), Some(raw.sender_pubkey_hex), reason);
    }
    match nip04_decrypt_content(secret_key, &raw.sender_pubkey_hex, &raw.content) {
        Ok(plaintext) => {
            guard_state.mark_accepted(raw.created_at);
            InboundDmDecision::Accepted(InboundDmAccepted {
                event_id: raw.event_id,
                sender_pubkey_hex: raw.sender_pubkey_hex,
                recipient_pubkey_hex: recipient,
                event_kind: NIP04_KIND_ENCRYPTED_DM,
                created_at: raw.created_at,
                plaintext,
            })
        }
        Err(reason) => rejected(Some(raw.event_id), Some(raw.sender_pubkey_hex), reason),
    }
}

const fn rejected(
    event_id: Option<String>,
    claimed_sender_pubkey_hex: Option<String>,
    reason: InboundDmRejectionReason,
) -> InboundDmDecision {
    InboundDmDecision::Rejected(InboundDmRejected {
        event_id,
        claimed_sender_pubkey_hex,
        retryable: matches!(
            reason,
            InboundDmRejectionReason::GlobalRateLimited
                | InboundDmRejectionReason::SenderRateLimited
                | InboundDmRejectionReason::FutureSkew
        ),
        reason,
    })
}

fn parse_inbound_dm_raw_event(event: &Value) -> Result<InboundDmRawEvent, InboundDmRejected> {
    let event_id = field_string(event, "id").map_err(|reason| rejection(None, None, reason))?;
    if !is_fixed_hex(event_id, 64) {
        return Err(rejection(
            Some(event_id.to_ascii_lowercase()),
            None,
            InboundDmRejectionReason::InvalidEventId,
        ));
    }
    let sender = field_string(event, "pubkey")
        .map_err(|reason| rejection(Some(event_id.to_ascii_lowercase()), None, reason))?;
    let sender_pubkey_hex = normalize_public_key_input(sender)
        .map_err(|_| {
            rejection(
                Some(event_id.to_ascii_lowercase()),
                None,
                InboundDmRejectionReason::MalformedEvent,
            )
        })?
        .canonical_public_key_hex()
        .to_string();
    let created_at = event_i64(event, "created_at").map_err(|reason| {
        rejection(
            Some(event_id.to_ascii_lowercase()),
            Some(sender_pubkey_hex.clone()),
            reason,
        )
    })?;
    let kind = event_u64(event, "kind").map_err(|reason| {
        rejection(
            Some(event_id.to_ascii_lowercase()),
            Some(sender_pubkey_hex.clone()),
            reason,
        )
    })?;
    let tags = event
        .get("tags")
        .filter(|value| value.is_array())
        .cloned()
        .ok_or_else(|| {
            rejection(
                Some(event_id.to_ascii_lowercase()),
                Some(sender_pubkey_hex.clone()),
                InboundDmRejectionReason::MalformedEvent,
            )
        })?;
    let content = field_string(event, "content").map_err(|reason| {
        rejection(
            Some(event_id.to_ascii_lowercase()),
            Some(sender_pubkey_hex.clone()),
            reason,
        )
    })?;
    let sig = field_string(event, "sig").map_err(|reason| {
        rejection(
            Some(event_id.to_ascii_lowercase()),
            Some(sender_pubkey_hex.clone()),
            reason,
        )
    })?;
    if !is_fixed_hex(sig, 128) {
        return Err(rejection(
            Some(event_id.to_ascii_lowercase()),
            Some(sender_pubkey_hex),
            InboundDmRejectionReason::InvalidSignature,
        ));
    }
    Ok(InboundDmRawEvent {
        event_id: event_id.to_ascii_lowercase(),
        sender_pubkey_hex,
        created_at,
        kind,
        tags,
        content: content.to_string(),
        sig: sig.to_ascii_lowercase(),
    })
}

const fn rejection(
    event_id: Option<String>,
    claimed_sender_pubkey_hex: Option<String>,
    reason: InboundDmRejectionReason,
) -> InboundDmRejected {
    InboundDmRejected {
        event_id,
        claimed_sender_pubkey_hex,
        retryable: matches!(
            reason,
            InboundDmRejectionReason::GlobalRateLimited
                | InboundDmRejectionReason::SenderRateLimited
                | InboundDmRejectionReason::FutureSkew
        ),
        reason,
    }
}

fn field_string<'a>(event: &'a Value, field: &str) -> Result<&'a str, InboundDmRejectionReason> {
    event
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(InboundDmRejectionReason::MalformedEvent)
}

fn event_i64(event: &Value, field: &str) -> Result<i64, InboundDmRejectionReason> {
    if let Some(value) = event.get(field).and_then(Value::as_i64) {
        return Ok(value);
    }
    event
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(InboundDmRejectionReason::MalformedEvent)
}

fn event_u64(event: &Value, field: &str) -> Result<u64, InboundDmRejectionReason> {
    event
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(InboundDmRejectionReason::MalformedEvent)
}

fn is_fixed_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecipientTagState {
    Missing,
    WrongTarget,
    Matches,
}

fn recipient_tag_state(tags: &Value, recipient_pubkey_hex: &str) -> RecipientTagState {
    let Some(items) = tags.as_array() else {
        return RecipientTagState::Missing;
    };
    let mut saw_p_tag = false;
    for tag in items {
        let Some(tag_items) = tag.as_array() else {
            continue;
        };
        if !matches!(tag_items.first().and_then(Value::as_str), Some("p")) {
            continue;
        }
        saw_p_tag = true;
        if tag_items
            .get(1)
            .and_then(Value::as_str)
            .and_then(|raw| normalize_public_key_input(raw).ok())
            .is_some_and(|normalized| normalized.canonical_public_key_hex() == recipient_pubkey_hex)
        {
            return RecipientTagState::Matches;
        }
    }
    if saw_p_tag {
        RecipientTagState::WrongTarget
    } else {
        RecipientTagState::Missing
    }
}

fn verify_inbound_dm_signature(raw: &InboundDmRawEvent) -> bool {
    let canonical = json!([
        0,
        raw.sender_pubkey_hex,
        raw.created_at,
        raw.kind,
        raw.tags,
        raw.content
    ]);
    let Ok(canonical_bytes) = serde_json::to_vec(&canonical) else {
        return false;
    };
    let expected_id = hex::encode(Sha256::digest(canonical_bytes));
    if expected_id != raw.event_id {
        return false;
    }
    let Ok(message_bytes) = hex::decode(&raw.event_id) else {
        return false;
    };
    let Ok(message) = Message::from_digest_slice(&message_bytes) else {
        return false;
    };
    let Ok(pubkey_bytes) = hex::decode(&raw.sender_pubkey_hex) else {
        return false;
    };
    let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey_bytes) else {
        return false;
    };
    let Ok(signature) = Signature::from_str(&raw.sig) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &pubkey)
        .is_ok()
}

// ─── Relay frame parsing ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    Event {
        sub_id: String,
        event: Value,
    },
    Eose {
        sub_id: String,
    },
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    Notice {
        message: String,
    },
    Raw(Value),
}

impl RelayFrame {
    #[allow(clippy::option_if_let_else)]
    pub fn from_value(value: Value) -> Self {
        let Some(items) = value.as_array() else {
            return Self::Raw(value);
        };
        match items.first().and_then(Value::as_str) {
            Some("EVENT") => match (items.get(1).and_then(Value::as_str), items.get(2).cloned()) {
                (Some(sub_id), Some(event)) => Self::Event {
                    sub_id: sub_id.to_string(),
                    event,
                },
                _ => Self::Raw(value),
            },
            Some("EOSE") => match items.get(1).and_then(Value::as_str) {
                Some(sub_id) => Self::Eose {
                    sub_id: sub_id.to_string(),
                },
                None => Self::Raw(value),
            },
            Some("OK") => match (
                items.get(1).and_then(Value::as_str),
                items.get(2).and_then(Value::as_bool),
                items.get(3).and_then(Value::as_str),
            ) {
                (Some(event_id), Some(accepted), Some(message)) => Self::Ok {
                    event_id: event_id.to_string(),
                    accepted,
                    message: message.to_string(),
                },
                _ => Self::Raw(value),
            },
            Some("NOTICE") => match items.get(1).and_then(Value::as_str) {
                Some(message) => Self::Notice {
                    message: message.to_string(),
                },
                None => Self::Raw(value),
            },
            _ => Self::Raw(value),
        }
    }

    #[must_use]
    pub fn into_json(self) -> Value {
        match self {
            Self::Event { sub_id, event } => json!(["EVENT", sub_id, event]),
            Self::Eose { sub_id } => json!(["EOSE", sub_id]),
            Self::Ok {
                event_id,
                accepted,
                message,
            } => json!(["OK", event_id, accepted, message]),
            Self::Notice { message } => json!(["NOTICE", message]),
            Self::Raw(value) => value,
        }
    }
}

// ─── Relay query state (dedup) ───────────────────────────────────────────

#[derive(Debug, Default)]
pub struct RelayQueryState {
    seen_event_ids: BTreeSet<String>,
    events: Vec<Value>,
}

impl RelayQueryState {
    pub fn push_event(&mut self, event: Value) {
        let Some(id) = event.get("id").and_then(Value::as_str) else {
            tracing::warn!("skipping event without id field");
            return;
        };
        if self.seen_event_ids.insert(id.to_string()) {
            self.events.push(event);
        }
    }

    #[must_use]
    pub fn into_events(self) -> Vec<Value> {
        self.events
    }
}

// ─── Relay health scoring ────────────────────────────────────────────────

/// Per-relay health score with latency and NIP support information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHealthScore {
    pub relay_url: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub supports_nip04: bool,
    pub supports_nip44: bool,
    pub last_checked: String,
}

impl RelayHealthScore {
    /// Create a score for an unreachable relay.
    #[must_use]
    pub fn unreachable(relay_url: &str, last_checked: String) -> Self {
        Self {
            relay_url: relay_url.to_string(),
            reachable: false,
            latency_ms: None,
            supports_nip04: false,
            supports_nip44: false,
            last_checked,
        }
    }
}

pub fn sort_relay_health_scores(scores: &mut [RelayHealthScore]) {
    scores.sort_by(|left, right| {
        right
            .reachable
            .cmp(&left.reachable)
            .then_with(|| {
                left.latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&right.latency_ms.unwrap_or(u64::MAX))
            })
            .then_with(|| right.supports_nip04.cmp(&left.supports_nip04))
            .then_with(|| right.supports_nip44.cmp(&left.supports_nip44))
            .then_with(|| left.relay_url.cmp(&right.relay_url))
    });
}

// ─── Dedup tracker (cross-relay) ────────────────────────────────────────

/// Tracks recent event IDs across relay queries with bounded capacity.
///
/// When at capacity, new insertions evict the oldest ID and increment
/// `overflow_count`. That keeps restart/reconnect replay protection bounded
/// without turning old IDs into permanent memory growth.
pub struct DedupTracker {
    seen: HashSet<String>,
    order: VecDeque<String>,
    max_capacity: usize,
    overflow_count: usize,
}

enum DedupInsertOutcome {
    Inserted { evicted: Option<String> },
    Duplicate,
}

impl DedupTracker {
    /// Create a new tracker with the given maximum capacity.
    ///
    /// # Panics
    ///
    /// Panics if `max_capacity` is zero.
    #[must_use]
    pub fn new(max_capacity: usize) -> Self {
        assert!(max_capacity > 0, "DedupTracker max_capacity must be > 0");
        Self {
            seen: HashSet::with_capacity(max_capacity.min(1024)),
            order: VecDeque::with_capacity(max_capacity.min(1024)),
            max_capacity,
            overflow_count: 0,
        }
    }

    fn from_recent_ids(max_capacity: usize, event_ids: Vec<String>, overflow_count: usize) -> Self {
        let mut tracker = Self::new(max_capacity);
        tracker.overflow_count = overflow_count;
        for event_id in event_ids
            .into_iter()
            .rev()
            .filter(|event_id| is_fixed_hex(event_id, 64))
            .take(max_capacity)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            if tracker.seen.insert(event_id.clone()) {
                tracker.order.push_back(event_id);
            }
        }
        tracker
    }

    /// Insert an event ID. Returns `true` if the ID was newly inserted
    /// (not a duplicate), `false` if already seen.
    pub fn insert(&mut self, event_id: &str) -> bool {
        matches!(
            self.insert_with_outcome(event_id),
            DedupInsertOutcome::Inserted { .. }
        )
    }

    fn insert_with_outcome(&mut self, event_id: &str) -> DedupInsertOutcome {
        if self.seen.contains(event_id) {
            return DedupInsertOutcome::Duplicate;
        }
        let mut evicted = None;
        if self.seen.len() >= self.max_capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
                evicted = Some(oldest);
            }
            self.overflow_count = self.overflow_count.saturating_add(1);
        }
        let event_id = event_id.to_string();
        self.seen.insert(event_id.clone());
        self.order.push_back(event_id);
        DedupInsertOutcome::Inserted { evicted }
    }

    /// Returns the number of unique event IDs tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` if no event IDs have been tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Returns the number of insertions dropped due to capacity overflow.
    #[must_use]
    pub const fn overflow_count(&self) -> usize {
        self.overflow_count
    }

    #[must_use]
    pub const fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    #[must_use]
    pub fn recent_event_ids(&self) -> Vec<String> {
        self.order.iter().cloned().collect()
    }

    fn retain_valid_event_ids(&mut self) {
        self.order.retain(|event_id| is_fixed_hex(event_id, 64));
        self.seen = self.order.iter().cloned().collect();
    }

    /// Returns `true` if the tracker has seen this event ID.
    #[must_use]
    pub fn contains(&self, event_id: &str) -> bool {
        self.seen.contains(event_id)
    }
}

impl std::fmt::Debug for DedupTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupTracker")
            .field("tracked", &self.seen.len())
            .field("max_capacity", &self.max_capacity)
            .field("overflow_count", &self.overflow_count)
            .field("oldest_first", &self.order)
            .finish()
    }
}

// ─── Nostr relay client (per-relay) ──────────────────────────────────────

pub struct NostrRelayClient<'a> {
    pub relay: &'a RelayBinding,
    timeout: Duration,
}

impl<'a> NostrRelayClient<'a> {
    #[must_use]
    pub const fn new(relay: &'a RelayBinding, timeout: Duration) -> Self {
        Self { relay, timeout }
    }

    async fn connect_once(&self, context: &'static str) -> FcpResult<WsConnection> {
        WsClient::new(self.relay.as_str())
            .connect()
            .await
            .map_err(map_stream_error(context, self.relay.as_str()))
    }

    async fn recv(
        &self,
        ws: &mut WsConnection,
        context: &'static str,
    ) -> FcpResult<Option<WsMessage>> {
        Box::pin(fcp_async_core::time::timeout(self.timeout, ws.recv()))
            .await
            .map_err(|_| relay_timeout(self.relay.as_str(), context))?
            .map_err(map_stream_error(context, self.relay.as_str()))
    }

    /// Publish a signed event to a relay and return the relay response.
    ///
    /// # Errors
    ///
    /// Returns an error if the relay connection fails, the relay closes early,
    /// or the relay rejects the event.
    pub async fn publish(&self, event: &Value) -> FcpResult<Value> {
        let mut ws = self.connect_once("nostr publish connect").await?;
        ws.send_json(&json!(["EVENT", event]))
            .await
            .map_err(map_stream_error("nostr publish send", self.relay.as_str()))?;
        let response = Box::pin(self.recv(&mut ws, "nostr publish recv")).await?;
        let _ = ws.close().await;
        let response = response.ok_or_else(|| {
            relay_external_error(
                self.relay.as_str(),
                "closed before acknowledging event".into(),
                true,
            )
        })?;
        let frame = parse_ws_message(&response, self.relay)?;
        match frame {
            RelayFrame::Ok {
                accepted: false,
                message,
                ..
            } => Err(relay_external_error(
                self.relay.as_str(),
                format!("rejected published event: {message}"),
                false,
            )),
            RelayFrame::Notice { message } => Err(relay_external_error(
                self.relay.as_str(),
                format!("notice during publish: {message}"),
                false,
            )),
            other => Ok(json!({
                "relay": self.relay.as_str(),
                "response": other.into_json(),
            })),
        }
    }

    /// Execute a Nostr `REQ` query against a relay.
    ///
    /// # Errors
    ///
    /// Returns an error if the relay connection fails, the relay closes before
    /// `EOSE`, or a retryable query exhausts all attempts.
    pub async fn query(&self, sub_id: &str, filter: &Value) -> FcpResult<Vec<Value>> {
        let mut query_state = RelayQueryState::default();
        let mut last_error = None;
        for attempt in 0..READ_ONLY_RECONNECT_ATTEMPTS {
            match Box::pin(self.query_once(sub_id, filter, &mut query_state)).await {
                Ok(()) => return Ok(query_state.into_events()),
                Err(error)
                    if attempt + 1 < READ_ONLY_RECONNECT_ATTEMPTS
                        && is_retryable_relay_error(&error) =>
                {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            relay_external_error(self.relay.as_str(), "query retries exhausted".into(), true)
        }))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn subscribe_inbound_dms_once(
        &self,
        stream_id: &str,
        recipient_public_key_hex: &str,
        since: Option<i64>,
        secret_key: &SecretKey,
        policy: &InboundDmPolicy,
        guard_state: &Mutex<InboundDmGuardState>,
        persist_state: impl Fn(&InboundDmGuardState) -> String,
    ) -> InboundDmSubscriptionOutcome {
        let filter = inbound_dm_subscription_filter(recipient_public_key_hex, since);
        let mut outcome = InboundDmSubscriptionOutcome::new(stream_id, self.relay, filter.clone());
        let start = Instant::now();
        let mut ws = match self
            .connect_once("nostr inbound dm subscribe connect")
            .await
        {
            Ok(ws) => {
                outcome.record(
                    "connect",
                    json!({
                        "subscribe_result": "connected",
                        "elapsed_ms": elapsed_ms(start),
                    }),
                );
                ws
            }
            Err(error) => {
                outcome.record(
                    "connect",
                    json!({
                        "subscribe_result": "connect_failed",
                        "shutdown_result": "not_started",
                        "error": error.to_string(),
                        "elapsed_ms": elapsed_ms(start),
                    }),
                );
                return outcome;
            }
        };

        let start = Instant::now();
        if let Err(error) = ws.send_json(&json!(["REQ", stream_id, filter])).await {
            outcome.record(
                "subscribe_ack",
                json!({
                    "subscribe_result": "send_failed",
                    "error": error.to_string(),
                    "elapsed_ms": elapsed_ms(start),
                }),
            );
            let _ = ws.close().await;
            outcome.record(
                "shutdown",
                json!({
                    "shutdown_result": "closed_after_send_failure",
                    "elapsed_ms": elapsed_ms(start),
                }),
            );
            return outcome;
        }
        outcome.record(
            "subscribe_ack",
            json!({
                "subscribe_result": "req_sent",
                "elapsed_ms": elapsed_ms(start),
            }),
        );

        loop {
            let start = Instant::now();
            let message = match Box::pin(self.recv(&mut ws, "nostr inbound dm recv")).await {
                Ok(Some(message)) => message,
                Ok(None) => {
                    outcome.record(
                        "disconnect",
                        json!({
                            "shutdown_result": "relay_closed",
                            "elapsed_ms": elapsed_ms(start),
                        }),
                    );
                    break;
                }
                Err(error) => {
                    outcome.record(
                        "disconnect",
                        json!({
                            "shutdown_result": "recv_error",
                            "error": error.to_string(),
                            "elapsed_ms": elapsed_ms(start),
                        }),
                    );
                    break;
                }
            };

            let frame = match parse_ws_message(&message, self.relay) {
                Ok(frame) => frame,
                Err(error) => {
                    outcome.record(
                        "event_receive",
                        json!({
                            "core_decision": "rejected",
                            "rejection_reason": "malformed_relay_frame",
                            "decrypt_result": "not_attempted",
                            "error": error.to_string(),
                            "elapsed_ms": elapsed_ms(start),
                        }),
                    );
                    continue;
                }
            };

            match frame {
                RelayFrame::Event { sub_id, event } if sub_id == stream_id => {
                    let (decision, state_transition, persistence_result) = {
                        let mut guard = guard_state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let decision = evaluate_inbound_dm_event(
                            &event,
                            secret_key,
                            recipient_public_key_hex,
                            policy,
                            &mut guard,
                            i64::try_from(current_unix_seconds()).unwrap_or(i64::MAX),
                        );
                        let state_transition = guard.last_transition();
                        let persistence_result = persist_state(&guard);
                        drop(guard);
                        (decision, state_transition, persistence_result)
                    };
                    match decision {
                        InboundDmDecision::Accepted(accepted) => {
                            outcome.record(
                                "event_receive",
                                json!({
                                    "event_id": accepted.event_id,
                                    "sender": accepted.sender_pubkey_hex,
                                    "event_kind": accepted.event_kind,
                                    "core_decision": "accepted",
                                    "policy_decision": "allowed",
                                    "decrypt_result": "success",
                                    "state": state_transition.clone(),
                                    "cursor_before": state_transition["cursor_before"].clone(),
                                    "cursor_after": state_transition["cursor_after"].clone(),
                                    "seen_state": state_transition["seen_state"].clone(),
                                    "seen_inserted": state_transition["seen_inserted"].clone(),
                                    "seen_evicted": state_transition["seen_evicted"].clone(),
                                    "duplicate_source": state_transition["duplicate_source"].clone(),
                                    "reconnect_generation": state_transition["reconnect_generation"].clone(),
                                    "restart_generation": state_transition["restart_generation"].clone(),
                                    "global_bucket_before": state_transition["global_bucket_before"].clone(),
                                    "global_bucket_after": state_transition["global_bucket_after"].clone(),
                                    "sender_bucket_before": state_transition["sender_bucket_before"].clone(),
                                    "sender_bucket_after": state_transition["sender_bucket_after"].clone(),
                                    "rate_limit_scope": state_transition["rate_limit_scope"].clone(),
                                    "retry_after_ms": state_transition["retry_after_ms"].clone(),
                                    "persistence_result": persistence_result,
                                    "elapsed_ms": elapsed_ms(start),
                                }),
                            );
                            outcome.accepted.push(accepted);
                        }
                        InboundDmDecision::Rejected(rejected) => {
                            outcome.record(
                                "event_receive",
                                json!({
                                    "event_id": rejected.event_id,
                                    "sender": rejected.claimed_sender_pubkey_hex,
                                    "event_kind": NIP04_KIND_ENCRYPTED_DM,
                                    "core_decision": "rejected",
                                    "policy_decision": if matches!(
                                        rejected.reason,
                                        InboundDmRejectionReason::PolicyDisabled
                                            | InboundDmRejectionReason::PolicySenderBlocked
                                    ) {
                                        "blocked"
                                    } else {
                                        "not_applicable"
                                    },
                                    "rejection_reason": rejected.reason.as_str(),
                                    "state": state_transition.clone(),
                                    "cursor_before": state_transition["cursor_before"].clone(),
                                    "cursor_after": state_transition["cursor_after"].clone(),
                                    "seen_state": state_transition["seen_state"].clone(),
                                    "seen_inserted": state_transition["seen_inserted"].clone(),
                                    "seen_evicted": state_transition["seen_evicted"].clone(),
                                    "duplicate_source": state_transition["duplicate_source"].clone(),
                                    "reconnect_generation": state_transition["reconnect_generation"].clone(),
                                    "restart_generation": state_transition["restart_generation"].clone(),
                                    "global_bucket_before": state_transition["global_bucket_before"].clone(),
                                    "global_bucket_after": state_transition["global_bucket_after"].clone(),
                                    "sender_bucket_before": state_transition["sender_bucket_before"].clone(),
                                    "sender_bucket_after": state_transition["sender_bucket_after"].clone(),
                                    "rate_limit_scope": state_transition["rate_limit_scope"].clone(),
                                    "retry_after_ms": state_transition["retry_after_ms"].clone(),
                                    "persistence_result": persistence_result,
                                    "decrypt_result": if matches!(
                                        rejected.reason,
                                        InboundDmRejectionReason::DecryptFailed
                                    ) {
                                        "failed"
                                    } else {
                                        "not_attempted"
                                    },
                                    "retryable": rejected.retryable,
                                    "elapsed_ms": elapsed_ms(start),
                                }),
                            );
                        }
                    }
                }
                RelayFrame::Event { sub_id, .. } => {
                    outcome.record(
                        "event_receive",
                        json!({
                            "core_decision": "rejected",
                            "rejection_reason": "wrong_subscription_id",
                            "decrypt_result": "not_attempted",
                            "relay_sub_id": sub_id,
                            "elapsed_ms": elapsed_ms(start),
                        }),
                    );
                }
                RelayFrame::Eose { sub_id } if sub_id == stream_id => {
                    let close_result = ws
                        .send_json(&json!(["CLOSE", stream_id]))
                        .await
                        .map_or_else(
                            |error| format!("close_send_failed: {error}"),
                            |()| "close_sent".to_string(),
                        );
                    outcome.record(
                        "unsubscribe",
                        json!({
                            "unsubscribe_result": close_result,
                            "shutdown_result": "eose",
                            "elapsed_ms": elapsed_ms(start),
                        }),
                    );
                    break;
                }
                RelayFrame::Notice { message } => {
                    outcome.record(
                        "event_receive",
                        json!({
                            "core_decision": "rejected",
                            "rejection_reason": "relay_notice",
                            "decrypt_result": "not_attempted",
                            "notice": message,
                            "elapsed_ms": elapsed_ms(start),
                        }),
                    );
                }
                RelayFrame::Ok { .. } | RelayFrame::Raw(_) | RelayFrame::Eose { .. } => {
                    outcome.record(
                        "event_receive",
                        json!({
                            "core_decision": "rejected",
                            "rejection_reason": "unexpected_relay_frame",
                            "decrypt_result": "not_attempted",
                            "elapsed_ms": elapsed_ms(start),
                        }),
                    );
                }
            }
        }

        let start = Instant::now();
        let shutdown_result = ws.close().await.map_or_else(
            |error| format!("close_failed: {error}"),
            |()| "closed".into(),
        );
        outcome.record(
            "shutdown",
            json!({
                "shutdown_result": shutdown_result,
                "elapsed_ms": elapsed_ms(start),
            }),
        );
        outcome
    }

    async fn query_once(
        &self,
        sub_id: &str,
        filter: &Value,
        query_state: &mut RelayQueryState,
    ) -> FcpResult<()> {
        let mut ws = self.connect_once("nostr query connect").await?;
        ws.send_json(&json!(["REQ", sub_id, filter]))
            .await
            .map_err(map_stream_error("nostr query send", self.relay.as_str()))?;

        loop {
            let Some(message) = Box::pin(self.recv(&mut ws, "nostr query recv")).await? else {
                let _ = ws.close().await;
                return Err(relay_external_error(
                    self.relay.as_str(),
                    "closed before EOSE".into(),
                    true,
                ));
            };
            let frame = parse_ws_message(&message, self.relay)?;
            match frame {
                RelayFrame::Eose {
                    sub_id: frame_sub_id,
                } if frame_sub_id == sub_id => break,
                RelayFrame::Event {
                    sub_id: frame_sub_id,
                    event,
                } if frame_sub_id == sub_id => {
                    query_state.push_event(event);
                }
                RelayFrame::Notice { message } => {
                    let _ = ws.close().await;
                    return Err(relay_external_error(
                        self.relay.as_str(),
                        format!("notice during query: {message}"),
                        false,
                    ));
                }
                _ => {}
            }
        }

        let _ = ws.send_json(&json!(["CLOSE", sub_id])).await;
        let _ = ws.close().await;
        Ok(())
    }

    /// Score a relay's health: latency, reachability, and NIP-04/NIP-44 support.
    ///
    /// This connects to the relay, measures connection latency, then issues
    /// a bounded REQ for kind=4 (NIP-04 encrypted DM) events to probe whether
    /// the relay indexes that event kind. NIP-44 support is inferred from
    /// kind=1059 (gift-wrapped) events.
    ///
    /// # Errors
    ///
    /// Does not return errors; unreachable relays get a score with
    /// `reachable: false`.
    pub async fn score_relay_health(&self) -> RelayHealthScore {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_checked = now.to_string();

        // Measure connection latency
        let connect_start = Instant::now();
        let Ok(mut ws) = self.connect_once("nostr health score connect").await else {
            return RelayHealthScore::unreachable(self.relay.as_str(), last_checked);
        };
        let latency_ms = connect_start.elapsed().as_millis();
        let latency_ms = u64::try_from(latency_ms).unwrap_or(u64::MAX);

        // Probe NIP-04 support: REQ for kind=4, limit=1
        let sub_nip04 = format!("fcp-nip04-{}", Uuid::new_v4().simple());
        let nip04_filter = json!({"kinds": [4], "limit": 1});
        let supports_nip04 =
            Box::pin(self.probe_kind_support(&mut ws, &sub_nip04, &nip04_filter)).await;

        // Probe NIP-44 support: REQ for kind=1059 (gift-wrapped), limit=1
        let sub_nip44 = format!("fcp-nip44-{}", Uuid::new_v4().simple());
        let nip44_filter = json!({"kinds": [1059], "limit": 1});
        let supports_nip44 =
            Box::pin(self.probe_kind_support(&mut ws, &sub_nip44, &nip44_filter)).await;

        let _ = ws.close().await;

        RelayHealthScore {
            relay_url: self.relay.as_str().to_string(),
            reachable: true,
            latency_ms: Some(latency_ms),
            supports_nip04,
            supports_nip44,
            last_checked,
        }
    }

    /// Probe whether a relay responds to a REQ without a NOTICE rejection.
    ///
    /// Returns `true` if the relay sends EOSE (with or without events),
    /// `false` if it sends NOTICE or the connection drops.
    async fn probe_kind_support(
        &self,
        ws: &mut WsConnection,
        sub_id: &str,
        filter: &Value,
    ) -> bool {
        if ws.send_json(&json!(["REQ", sub_id, filter])).await.is_err() {
            return false;
        }

        // Read frames until EOSE or NOTICE (with timeout)
        loop {
            let Ok(Some(message)) = Box::pin(self.recv(ws, "nostr probe recv")).await else {
                return false;
            };
            let Ok(frame) = parse_ws_message(&message, self.relay) else {
                return false;
            };
            match frame {
                RelayFrame::Eose { sub_id: ref sid } if sid == sub_id => {
                    let _ = ws.send_json(&json!(["CLOSE", sub_id])).await;
                    return true;
                }
                RelayFrame::Event {
                    sub_id: ref sid, ..
                } if sid == sub_id => {
                    // Relay is returning events of this kind - it supports them
                    // Continue reading until EOSE
                }
                RelayFrame::Notice { .. } => {
                    let _ = ws.send_json(&json!(["CLOSE", sub_id])).await;
                    return false;
                }
                _ => {}
            }
        }
    }

    /// Verify that a relay accepts WebSocket connections.
    ///
    /// # Errors
    ///
    /// Returns an error if the relay cannot be reached after the configured
    /// retry budget is exhausted.
    pub async fn health(&self) -> FcpResult<Value> {
        let mut last_error = None;
        for attempt in 0..READ_ONLY_RECONNECT_ATTEMPTS {
            match self.connect_once("nostr health connect").await {
                Ok(mut ws) => {
                    let _ = ws.close().await;
                    return Ok(json!({
                        "relay": self.relay.as_str(),
                        "reachable": true,
                    }));
                }
                Err(error)
                    if attempt + 1 < READ_ONLY_RECONNECT_ATTEMPTS
                        && is_retryable_relay_error(&error) =>
                {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            relay_external_error(self.relay.as_str(), "health retries exhausted".into(), true)
        }))
    }
}

// ─── NostrClient (aggregate over all relays) ─────────────────────────────

pub struct NostrClient {
    pub relays: Vec<RelayBinding>,
    pub key_material: NostrKeyMaterial,
    pub request_timeout: Duration,
    pub default_query_limit: u64,
    runtime: ConnectorRuntime,
    relay_resilience: Mutex<BTreeMap<String, RelayResilienceState>>,
    relay_resilience_policy: RelayResiliencePolicy,
    inbound_dm_policy: InboundDmPolicy,
    inbound_dm_seen_event_capacity: usize,
    inbound_dm_rate_limits: InboundDmRateLimits,
}

impl std::fmt::Debug for NostrClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrClient")
            .field("relays", &self.relays)
            .field("key_material", &self.key_material)
            .field("request_timeout", &self.request_timeout)
            .field("default_query_limit", &self.default_query_limit)
            .field("relay_resilience", &self.relay_resilience_snapshots())
            .field("relay_resilience_policy", &self.relay_resilience_policy)
            .field("inbound_dm_policy", &self.inbound_dm_policy)
            .field(
                "inbound_dm_seen_event_capacity",
                &self.inbound_dm_seen_event_capacity,
            )
            .field("inbound_dm_rate_limits", &self.inbound_dm_rate_limits)
            .field("runtime", &"ConnectorRuntime")
            .finish_non_exhaustive()
    }
}

impl NostrClient {
    /// Build a `NostrClient` from validated config.
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid (bad relay URLs, bad secret key, etc.).
    pub fn new(config: &NostrConfig) -> FcpResult<Self> {
        config.validate()?;
        let relays = canonicalize_relay_urls(&config.relay_urls, config.relay_policy())?
            .into_iter()
            .map(RelayBinding::from_url)
            .collect::<Vec<_>>();
        let key_material = NostrKeyMaterial::from_secret_key_input(&config.secret_key_hex)?;
        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        let relay_resilience_policy = RelayResiliencePolicy::new(
            config.relay_circuit_failure_threshold,
            config.relay_circuit_reset_ms,
        );
        let inbound_dm_policy = InboundDmPolicy::from_config(&config.inbound_dm)?;
        let inbound_dm_rate_limits = InboundDmRateLimits::new(
            config.inbound_dm.rate_window_secs,
            config.inbound_dm.global_rate_limit,
            config.inbound_dm.per_sender_rate_limit,
        );
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
        );
        Ok(Self {
            relays,
            key_material,
            request_timeout,
            default_query_limit: config.default_query_limit,
            runtime,
            relay_resilience: Mutex::new(BTreeMap::new()),
            relay_resilience_policy,
            inbound_dm_policy,
            inbound_dm_seen_event_capacity: config.inbound_dm.seen_event_capacity,
            inbound_dm_rate_limits,
        })
    }

    #[must_use]
    pub const fn runtime(&self) -> &ConnectorRuntime {
        &self.runtime
    }

    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    #[must_use]
    pub const fn inbound_dm_policy(&self) -> &InboundDmPolicy {
        &self.inbound_dm_policy
    }

    #[must_use]
    pub const fn inbound_dm_seen_event_capacity(&self) -> usize {
        self.inbound_dm_seen_event_capacity
    }

    #[must_use]
    pub const fn inbound_dm_rate_limits(&self) -> InboundDmRateLimits {
        self.inbound_dm_rate_limits
    }

    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        self.key_material.secret_key()
    }

    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        self.key_material.public_key_hex()
    }

    #[must_use]
    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    #[must_use]
    pub fn relay_urls(&self) -> Vec<String> {
        self.relays
            .iter()
            .map(|relay| relay.as_str().to_string())
            .collect()
    }

    pub fn relay_clients(&self) -> impl Iterator<Item = NostrRelayClient<'_>> {
        self.relays
            .iter()
            .map(|relay| NostrRelayClient::new(relay, self.request_timeout))
    }

    #[must_use]
    pub fn relay_resilience_snapshots(&self) -> Vec<RelayResilienceSnapshot> {
        let states = self.relay_resilience_states();
        self.relays
            .iter()
            .map(|relay| {
                states.get(relay.as_str()).map_or_else(
                    || {
                        RelayResilienceState::new(self.relay_resilience_policy)
                            .snapshot(relay.as_str())
                    },
                    |state| state.snapshot(relay.as_str()),
                )
            })
            .collect()
    }

    #[must_use]
    pub fn relay_resilience_metrics(&self, operation: &str) -> Vec<Value> {
        self.relay_resilience_snapshots()
            .into_iter()
            .map(|snapshot| {
                json!({
                    "labels": {
                        "connector": "nostr",
                        "operation": operation,
                        "relay": snapshot.relay_url,
                        "circuit_state": snapshot.circuit_state,
                    },
                    "success_count": snapshot.success_count,
                    "failure_count": snapshot.failure_count,
                    "skipped_count": snapshot.skipped_count,
                    "average_latency_ms": snapshot.average_latency_ms,
                })
            })
            .collect()
    }

    fn relay_resilience_states(&self) -> MutexGuard<'_, BTreeMap<String, RelayResilienceState>> {
        self.relay_resilience
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn relay_can_attempt(&self, relay: &RelayBinding) -> bool {
        let now_ms = current_unix_ms();
        let mut states = self.relay_resilience_states();
        let state = states
            .entry(relay.as_str().to_string())
            .or_insert_with(|| RelayResilienceState::new(self.relay_resilience_policy));
        let allowed = state.can_attempt(now_ms);
        drop(states);
        allowed
    }

    fn record_relay_success(&self, relay: &RelayBinding, latency_ms: u128) {
        let mut states = self.relay_resilience_states();
        let state = states
            .entry(relay.as_str().to_string())
            .or_insert_with(|| RelayResilienceState::new(self.relay_resilience_policy));
        state.record_success(latency_ms);
        drop(states);
    }

    fn record_relay_failure(&self, relay: &RelayBinding, error: String) {
        let now_ms = current_unix_ms();
        let mut states = self.relay_resilience_states();
        let state = states
            .entry(relay.as_str().to_string())
            .or_insert_with(|| RelayResilienceState::new(self.relay_resilience_policy));
        state.record_failure(now_ms, error);
        drop(states);
    }

    /// Publish a signed note to all configured relays.
    ///
    /// # Errors
    ///
    /// Returns an error if the input payload is invalid or the note cannot be
    /// signed before relay fan-out begins.
    pub async fn publish_note(&self, input: &Value) -> FcpResult<Value> {
        let content = required_string(input, "content")?;
        let kind = note_kind(input)?;
        let tags = note_tags(input)?;
        let event = build_signed_event(
            self.secret_key(),
            self.public_key_hex(),
            kind,
            &tags,
            content,
        )?;

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for relay in self.relay_clients() {
            if !self.relay_can_attempt(relay.relay) {
                rejected.push(json!({
                    "relay": relay.relay.as_str(),
                    "error": "relay circuit breaker open",
                    "retryable": true,
                    "circuit_state": RelayCircuitState::Open,
                }));
                continue;
            }
            let start = Instant::now();
            match Box::pin(relay.publish(&event)).await {
                Ok(result) => {
                    self.record_relay_success(relay.relay, start.elapsed().as_millis());
                    accepted.push(result);
                }
                Err(error) => {
                    let error_text = error.to_string();
                    self.record_relay_failure(relay.relay, error_text.clone());
                    rejected.push(json!({
                        "relay": relay.relay.as_str(),
                        "error": error_text,
                    }));
                }
            }
        }

        Ok(json!({
            "event": event,
            "accepted_relays": accepted,
            "rejected_relays": rejected,
            "relay_resilience": self.relay_resilience_snapshots(),
            "relay_metrics": self.relay_resilience_metrics(OP_PUBLISH_NOTE),
        }))
    }

    /// Encrypt a NIP-04 direct message and publish the signed kind-4 event.
    ///
    /// The returned payload exposes event id, sender/recipient public metadata,
    /// and per-relay delivery results. It intentionally omits plaintext and
    /// encrypted content from the client output.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is invalid or if local encryption/signing
    /// fails before relay fan-out begins.
    pub async fn send_dm(&self, input: &Value) -> FcpResult<Value> {
        let request = parse_dm_send_input(input, self.public_key_hex())?;
        let event = build_nip04_dm_event(
            self.secret_key(),
            self.public_key_hex(),
            request.recipient_pubkey(),
            request.plaintext(),
            request.reply_to_event_id(),
        )?;

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for relay in self.relay_clients() {
            if !self.relay_can_attempt(relay.relay) {
                rejected.push(json!({
                    "relay": relay.relay.as_str(),
                    "error": "relay circuit breaker open",
                    "retryable": true,
                    "circuit_state": RelayCircuitState::Open,
                }));
                continue;
            }
            let start = Instant::now();
            match Box::pin(relay.publish(&event)).await {
                Ok(result) => {
                    self.record_relay_success(relay.relay, start.elapsed().as_millis());
                    accepted.push(result);
                }
                Err(error) => {
                    let retryable = is_retryable_relay_error(&error);
                    let error_text = error.to_string();
                    self.record_relay_failure(relay.relay, error_text.clone());
                    rejected.push(json!({
                        "relay": relay.relay.as_str(),
                        "error": error_text,
                        "retryable": retryable,
                    }));
                }
            }
        }

        Ok(json!({
            "event_id": event["id"].clone(),
            "event_kind": NIP04_KIND_ENCRYPTED_DM,
            "sender_pubkey_hex": self.public_key_hex(),
            "recipient_pubkey_hex": request.recipient_pubkey(),
            "recipient_format": request.recipient_format().as_str(),
            "tags": event["tags"].clone(),
            "created_at": event["created_at"].clone(),
            "accepted_relays": accepted,
            "rejected_relays": rejected,
            "relay_resilience": self.relay_resilience_snapshots(),
            "relay_metrics": self.relay_resilience_metrics(OP_SEND_DM),
        }))
    }

    /// Publish a NIP-01 profile metadata event to all configured relays.
    ///
    /// # Errors
    ///
    /// Returns an error if profile validation or signing fails before relay
    /// fan-out begins.
    pub async fn publish_profile(
        &self,
        input: &Value,
        persisted_last_published_at: Option<u64>,
    ) -> FcpResult<Value> {
        let request = parse_profile_publish_input(input)?;
        let last_published_at = match (persisted_last_published_at, request.last_published_at()) {
            (Some(persisted), Some(host)) => Some(persisted.max(host)),
            (Some(persisted), None) => Some(persisted),
            (None, Some(host)) => Some(host),
            (None, None) => None,
        };
        let event = build_profile_event(
            self.secret_key(),
            self.public_key_hex(),
            request.profile(),
            last_published_at,
        )?;

        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for relay in self.relay_clients() {
            if !self.relay_can_attempt(relay.relay) {
                rejected.push(json!({
                    "relay": relay.relay.as_str(),
                    "error": "relay circuit breaker open",
                    "retryable": true,
                    "circuit_state": RelayCircuitState::Open,
                }));
                continue;
            }
            let start = Instant::now();
            match Box::pin(relay.publish(&event)).await {
                Ok(result) => {
                    self.record_relay_success(relay.relay, start.elapsed().as_millis());
                    accepted.push(result);
                }
                Err(error) => {
                    let retryable = is_retryable_relay_error(&error);
                    let error_text = error.to_string();
                    self.record_relay_failure(relay.relay, error_text.clone());
                    rejected.push(json!({
                        "relay": relay.relay.as_str(),
                        "error": error_text,
                        "retryable": retryable,
                    }));
                }
            }
        }

        Ok(json!({
            "event": event,
            "event_kind": NIP01_KIND_PROFILE,
            "profile": profile_to_content_value(request.profile()),
            "display_profile": sanitize_profile_for_display(request.profile()),
            "accepted_relays": accepted,
            "rejected_relays": rejected,
            "persist_recommended": !accepted.is_empty(),
            "relay_resilience": self.relay_resilience_snapshots(),
            "relay_metrics": self.relay_resilience_metrics(OP_PROFILE_PUBLISH),
        }))
    }

    /// Import the newest verified NIP-01 profile event for a public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the input key/profile is invalid or relay queries
    /// cannot be built.
    pub async fn import_profile(&self, input: &Value) -> FcpResult<Value> {
        let request = parse_profile_import_input(input, self.public_key_hex())?;
        let filter = json!({
            "kinds": [NIP01_KIND_PROFILE],
            "authors": [request.pubkey_hex()],
            "limit": 1,
        });
        let sub_id = format!("fcp-profile-{}", Uuid::new_v4().simple());
        let mut relay_results = Vec::with_capacity(self.relay_count());
        let mut candidates = Vec::new();
        for relay in self.relay_clients() {
            if !self.relay_can_attempt(relay.relay) {
                relay_results.push(json!({
                    "relay": relay.relay.as_str(),
                    "result": "skipped",
                    "error": "relay circuit breaker open",
                    "retryable": true,
                    "circuit_state": RelayCircuitState::Open,
                }));
                continue;
            }
            let start = Instant::now();
            match Box::pin(relay.query(&sub_id, &filter)).await {
                Ok(events) => {
                    self.record_relay_success(relay.relay, start.elapsed().as_millis());
                    for event in &events {
                        candidates.push((relay.relay.as_str().to_string(), event.clone()));
                    }
                    relay_results.push(json!({
                        "relay": relay.relay.as_str(),
                        "result": "ok",
                        "event_count": events.len(),
                    }));
                }
                Err(error) => {
                    let error_text = error.to_string();
                    self.record_relay_failure(relay.relay, error_text.clone());
                    relay_results.push(json!({
                        "relay": relay.relay.as_str(),
                        "result": "error",
                        "error": error_text,
                        "retryable": is_retryable_relay_error(&error),
                    }));
                }
            }
        }

        let (best, invalid_candidates) =
            select_profile_import_candidate(candidates, request.pubkey_hex());

        let Some((source_relay, event, created_at)) = best else {
            return Ok(json!({
                "ok": false,
                "pubkey_hex": request.pubkey_hex(),
                "error": "no verified NIP-01 profile event found",
                "relays_queried": self.relay_urls(),
                "relay_results": relay_results,
                "invalid_candidates": invalid_candidates,
                "relay_resilience": self.relay_resilience_snapshots(),
                "relay_metrics": self.relay_resilience_metrics(OP_PROFILE_IMPORT),
            }));
        };

        let content_text = event
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: "profile event content must be a string".into(),
            })?;
        let content: Value =
            serde_json::from_str(content_text).map_err(|error| FcpError::InvalidRequest {
                code: 1005,
                message: format!("profile event content must be valid JSON: {error}"),
            })?;
        let (profile, dropped_profile_fields) = profile_from_imported_content(&content)?;
        let merged_profile = merge_profiles(request.local_profile(), Some(&profile));

        Ok(json!({
            "ok": true,
            "pubkey_hex": request.pubkey_hex(),
            "profile": profile,
            "display_profile": sanitize_profile_for_display(&profile),
            "merged_profile": merged_profile,
            "event": {
                "id": event["id"].clone(),
                "pubkey": event["pubkey"].clone(),
                "created_at": created_at,
                "kind": NIP01_KIND_PROFILE,
            },
            "source_relay": source_relay,
            "relays_queried": self.relay_urls(),
            "relay_results": relay_results,
            "dropped_profile_fields": dropped_profile_fields,
            "invalid_candidates": invalid_candidates,
            "relay_resilience": self.relay_resilience_snapshots(),
            "relay_metrics": self.relay_resilience_metrics(OP_PROFILE_IMPORT),
        }))
    }

    /// Query events from all configured relays.
    ///
    /// # Errors
    ///
    /// Returns an error if the query filter input is invalid.
    pub async fn query_events(&self, input: &Value) -> FcpResult<Value> {
        let filter = build_filter(input, self.default_query_limit)?;
        let sub_id = format!("fcp-{}", Uuid::new_v4().simple());
        let mut per_relay = Vec::new();
        for relay in self.relay_clients() {
            if !self.relay_can_attempt(relay.relay) {
                per_relay.push(json!({
                    "relay": relay.relay.as_str(),
                    "error": "relay circuit breaker open",
                    "retryable": true,
                    "circuit_state": RelayCircuitState::Open,
                }));
                continue;
            }
            let start = Instant::now();
            match Box::pin(relay.query(&sub_id, &filter)).await {
                Ok(events) => {
                    self.record_relay_success(relay.relay, start.elapsed().as_millis());
                    per_relay.push(json!({
                        "relay": relay.relay.as_str(),
                        "events": events,
                    }));
                }
                Err(error) => {
                    let error_text = error.to_string();
                    self.record_relay_failure(relay.relay, error_text.clone());
                    per_relay.push(json!({
                        "relay": relay.relay.as_str(),
                        "error": error_text,
                    }));
                }
            }
        }
        Ok(json!({
            "subscription_id": sub_id,
            "filter": filter,
            "results": per_relay,
            "relay_resilience": self.relay_resilience_snapshots(),
            "relay_metrics": self.relay_resilience_metrics(OP_QUERY_EVENTS),
        }))
    }

    /// Score relay health across all configured relays.
    ///
    /// Returns a JSON object with per-relay health scores including latency
    /// and NIP support information.
    pub async fn relay_health_scores(&self) -> Value {
        let mut scores = Vec::with_capacity(self.relay_count());
        for relay in self.relay_clients() {
            if !self.relay_can_attempt(relay.relay) {
                scores.push(RelayHealthScore::unreachable(
                    relay.relay.as_str(),
                    current_unix_seconds().to_string(),
                ));
                continue;
            }
            let start = Instant::now();
            let score = Box::pin(relay.score_relay_health()).await;
            if score.reachable {
                self.record_relay_success(relay.relay, start.elapsed().as_millis());
            } else {
                self.record_relay_failure(relay.relay, "relay health score unreachable".into());
            }
            scores.push(score);
        }
        sort_relay_health_scores(&mut scores);
        json!({
            "public_key_hex": self.public_key_hex(),
            "relay_scores": scores,
            "scored_count": scores.len(),
            "relay_resilience": self.relay_resilience_snapshots(),
            "relay_metrics": self.relay_resilience_metrics(OP_RELAYS_HEALTH),
        })
    }

    /// Gather per-relay connectivity details.
    ///
    /// # Errors
    ///
    /// Returns an error only if local result construction fails before relay
    /// probing begins.
    pub async fn health_details(&self) -> FcpResult<Value> {
        let mut results = Vec::with_capacity(self.relay_count());
        for relay in self.relay_clients() {
            if !self.relay_can_attempt(relay.relay) {
                results.push(json!({
                    "relay": relay.relay.as_str(),
                    "reachable": false,
                    "error": "relay circuit breaker open",
                    "retryable": true,
                    "circuit_state": RelayCircuitState::Open,
                }));
                continue;
            }
            let start = Instant::now();
            match relay.health().await {
                Ok(result) => {
                    self.record_relay_success(relay.relay, start.elapsed().as_millis());
                    results.push(result);
                }
                Err(error) => {
                    let error_text = error.to_string();
                    self.record_relay_failure(relay.relay, error_text.clone());
                    results.push(json!({
                        "relay": relay.relay.as_str(),
                        "reachable": false,
                        "error": error_text,
                    }));
                }
            }
        }
        Ok(json!({
            "public_key_hex": self.public_key_hex(),
            "relay_health": results,
            "relay_resilience": self.relay_resilience_snapshots(),
            "relay_metrics": self.relay_resilience_metrics(OP_HEALTH),
        }))
    }
}

#[must_use]
pub fn inbound_dm_subscription_filter(recipient_public_key_hex: &str, since: Option<i64>) -> Value {
    let mut filter = json!({
        "kinds": [NIP04_KIND_ENCRYPTED_DM],
        "#p": [recipient_public_key_hex],
    });
    if let Some(since) = since {
        filter["since"] = json!(since);
    }
    filter
}

#[must_use]
pub fn inbound_dm_subscription_event_payload(
    accepted: &InboundDmAccepted,
    relay: &str,
    stream_id: &str,
) -> Value {
    json!({
        "stream_id": stream_id,
        "relay": relay,
        "event_id": accepted.event_id,
        "sender": accepted.sender_pubkey_hex,
        "recipient": accepted.recipient_pubkey_hex,
        "event_kind": accepted.event_kind,
        "created_at": accepted.created_at,
        "plaintext": accepted.plaintext,
    })
}

fn subscription_diagnostic(
    stream_id: &str,
    relay: &str,
    stage: &'static str,
    filter: &Value,
    detail: &Value,
) -> Value {
    let filter_kinds = filter.get("kinds").cloned().unwrap_or_else(|| json!([]));
    let filter_p_tag = filter.get("#p").cloned().unwrap_or_else(|| json!([]));
    let mut diagnostic = json!({
        "stream_id": stream_id,
        "relay": relay,
        "stage": stage,
        "event_kind": detail.get("event_kind").cloned().unwrap_or(Value::Null),
        "event_id": detail.get("event_id").cloned().unwrap_or(Value::Null),
        "filter_kinds": filter_kinds,
        "filter_p_tag": filter_p_tag,
        "subscribe_result": detail.get("subscribe_result").cloned().unwrap_or(Value::Null),
        "unsubscribe_result": detail.get("unsubscribe_result").cloned().unwrap_or(Value::Null),
        "cancellation_reason": detail.get("cancellation_reason").cloned().unwrap_or(Value::Null),
        "core_decision": detail.get("core_decision").cloned().unwrap_or(Value::Null),
        "rejection_reason": detail.get("rejection_reason").cloned().unwrap_or(Value::Null),
        "decrypt_result": detail.get("decrypt_result").cloned().unwrap_or(Value::Null),
        "shutdown_result": detail.get("shutdown_result").cloned().unwrap_or(Value::Null),
        "elapsed_ms": detail.get("elapsed_ms").cloned().unwrap_or(Value::Null),
    });
    if let (Some(object), Some(extra)) = (diagnostic.as_object_mut(), detail.as_object()) {
        for (key, value) in extra {
            object.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    diagnostic
}

// ─── Helper functions ────────────────────────────────────────────────────

fn parse_ws_message(message: &WsMessage, relay: &RelayBinding) -> FcpResult<RelayFrame> {
    match message {
        WsMessage::Text(text) => serde_json::from_str::<Value>(text)
            .map(RelayFrame::from_value)
            .map_err(|error| {
                relay_external_error(
                    relay.as_str(),
                    format!("failed to parse relay frame: {error}"),
                    false,
                )
            }),
        other => Err(relay_external_error(
            relay.as_str(),
            format!("unexpected relay frame type: {other:?}"),
            false,
        )),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn relay_external_error(relay: &str, message: String, retryable: bool) -> FcpError {
    FcpError::External {
        service: "nostr".into(),
        message: format!("relay `{relay}`: {message}"),
        status_code: None,
        retryable,
        retry_after: None,
    }
}

fn relay_timeout(relay: &str, context: &'static str) -> FcpError {
    relay_external_error(relay, format!("{context} timed out"), true)
}

fn map_stream_error(context: &'static str, relay: &str) -> impl Fn(StreamError) -> FcpError {
    let relay = relay.to_string();
    move |error| relay_external_error(&relay, format!("{context} failed: {error}"), true)
}

#[must_use]
pub const fn is_retryable_relay_error(error: &FcpError) -> bool {
    matches!(
        error,
        FcpError::External {
            retryable: true,
            ..
        } | FcpError::UpstreamTimeout { .. }
    )
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn current_unix_ms() -> u64 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(ms).unwrap_or(u64::MAX)
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const RECIPIENT_SCALAR_HEX: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn parse_secret_key_valid_hex() {
        let sk = parse_secret_key(TEST_SECRET_KEY_HEX);
        assert!(sk.is_ok());
    }

    #[test]
    fn parse_secret_key_valid_nsec() {
        let nsec = crate::types::encode_secret_key_nsec(TEST_SECRET_KEY_HEX).unwrap();
        let hex_scalar = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let nsec_scalar = parse_secret_key(&nsec).unwrap();
        assert_eq!(
            derive_public_key_hex(&hex_scalar),
            derive_public_key_hex(&nsec_scalar)
        );
    }

    #[test]
    fn parse_secret_key_invalid_hex() {
        assert!(parse_secret_key("not_hex").is_err());
    }

    #[test]
    fn parse_secret_key_rejects_invalid_bech32_type_without_leaking_input() {
        let public_key = derive_public_key_hex(&parse_secret_key(TEST_SECRET_KEY_HEX).unwrap());
        let npub = crate::types::encode_public_key_npub(&public_key).unwrap();
        let err = parse_secret_key(&npub).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("prefix must be `nsec`"));
        assert!(!message.contains(&npub));
        assert!(!message.contains(TEST_SECRET_KEY_HEX));
    }

    #[test]
    fn parse_secret_key_all_zeros_rejected() {
        let all_zeros = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(parse_secret_key(all_zeros).is_err());
    }

    #[test]
    fn derive_public_key_hex_returns_64_char_hex() {
        let sk = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let pk = derive_public_key_hex(&sk);
        assert_eq!(pk.len(), 64);
        assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn build_signed_event_produces_hex_id_and_signature() {
        let sk = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let pk = derive_public_key_hex(&sk);
        let event = build_signed_event(&sk, &pk, 1, &json!([]), "hello nostr").unwrap();
        assert_eq!(event["id"].as_str().unwrap().len(), 64);
        assert_eq!(event["sig"].as_str().unwrap().len(), 128);
        assert_eq!(event["pubkey"].as_str().unwrap(), pk);
        assert_eq!(event["kind"], 1);
        assert_eq!(event["content"], "hello nostr");
    }

    #[test]
    fn build_signed_event_includes_tags() {
        let sk = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let pk = derive_public_key_hex(&sk);
        let tags = json!([["p", "someone"]]);
        let event = build_signed_event(&sk, &pk, 1, &tags, "test").unwrap();
        assert_eq!(event["tags"], tags);
    }

    #[test]
    fn build_profile_event_signs_kind_zero_and_enforces_monotonic_timestamp() {
        let sk = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let pk = derive_public_key_hex(&sk);
        let future_timestamp = current_unix_seconds() + 60;
        let profile = crate::types::NostrProfile {
            name: Some("profiletest".into()),
            display_name: Some("Profile Test".into()),
            website: Some("https://example.com".into()),
            ..crate::types::NostrProfile::default()
        };
        let event = build_profile_event(&sk, &pk, &profile, Some(future_timestamp)).unwrap();
        assert_eq!(event["kind"], NIP01_KIND_PROFILE);
        assert_eq!(event["pubkey"], pk);
        assert_eq!(event["created_at"], future_timestamp + 1);
        assert!(verify_nostr_event_signature(&event));
        let content: Value = serde_json::from_str(event["content"].as_str().unwrap()).unwrap();
        assert_eq!(content["display_name"], "Profile Test");
        assert_eq!(content["website"], "https://example.com");
    }

    #[test]
    fn profile_event_signature_verification_rejects_tampering() {
        let sk = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let pk = derive_public_key_hex(&sk);
        let profile = crate::types::NostrProfile {
            name: Some("profiletest".into()),
            ..crate::types::NostrProfile::default()
        };
        let mut event = build_profile_event(&sk, &pk, &profile, None).unwrap();
        assert!(profile_event_matches(&event, &pk));
        event["content"] = json!("{\"name\":\"tampered\"}");
        assert!(!verify_nostr_event_signature(&event));
        assert!(!profile_event_matches(&event, &pk));
    }

    #[test]
    fn equivalent_hex_and_nsec_signing_inputs_have_same_event_shape() {
        let nsec = crate::types::encode_secret_key_nsec(TEST_SECRET_KEY_HEX).unwrap();
        let hex_material = NostrKeyMaterial::from_secret_key_input(TEST_SECRET_KEY_HEX).unwrap();
        let nsec_material = NostrKeyMaterial::from_secret_key_input(&nsec).unwrap();
        assert_eq!(
            hex_material.public_key_hex(),
            nsec_material.public_key_hex()
        );

        let tags = json!([["t", "fcp"]]);
        let hex_event = build_signed_event(
            hex_material.secret_key(),
            hex_material.public_key_hex(),
            1,
            &tags,
            "same shape",
        )
        .unwrap();
        let nsec_event = build_signed_event(
            nsec_material.secret_key(),
            nsec_material.public_key_hex(),
            1,
            &tags,
            "same shape",
        )
        .unwrap();
        assert_eq!(hex_event["pubkey"], nsec_event["pubkey"]);
        assert_eq!(hex_event["kind"], nsec_event["kind"]);
        assert_eq!(hex_event["tags"], nsec_event["tags"]);
        assert_eq!(hex_event["content"], nsec_event["content"]);
        assert_eq!(hex_event["id"].as_str().unwrap().len(), 64);
        assert_eq!(nsec_event["id"].as_str().unwrap().len(), 64);
        assert_eq!(hex_event["sig"].as_str().unwrap().len(), 128);
        assert_eq!(nsec_event["sig"].as_str().unwrap().len(), 128);
    }

    fn decrypt_nip04_content(
        recipient_scalar: &SecretKey,
        sender_public_key_hex: &str,
        content: &str,
    ) -> String {
        let (ciphertext_b64, iv_b64) = content
            .split_once("?iv=")
            .expect("NIP-04 content should include iv query parameter");
        let sender_public_key =
            recipient_public_key_for_nip04(sender_public_key_hex).expect("valid sender pubkey");
        let shared_point = ecdh::shared_secret_point(&sender_public_key, recipient_scalar);
        let mut shared_x = [0_u8; 32];
        shared_x.copy_from_slice(&shared_point[..32]);
        let iv = BASE64.decode(iv_b64).expect("base64 iv");
        let mut ciphertext = BASE64.decode(ciphertext_b64).expect("base64 ciphertext");
        let plaintext = Aes256CbcDec::new_from_slices(&shared_x, &iv)
            .expect("valid key and iv")
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
            .expect("NIP-04 decrypt should succeed");
        String::from_utf8(plaintext.to_vec()).expect("plaintext should be UTF-8")
    }

    #[test]
    fn build_nip04_dm_event_encrypts_and_signs_kind4() {
        let sender_scalar = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let sender_pubkey = derive_public_key_hex(&sender_scalar);
        let recipient_scalar = parse_secret_key(RECIPIENT_SCALAR_HEX).unwrap();
        let recipient_pubkey = derive_public_key_hex(&recipient_scalar);
        let iv = [7_u8; 16];
        let event = build_nip04_dm_event_with_iv(
            &sender_scalar,
            &sender_pubkey,
            &recipient_pubkey,
            "private hello",
            None,
            iv,
        )
        .unwrap();

        assert_eq!(event["kind"], NIP04_KIND_ENCRYPTED_DM);
        assert_eq!(event["pubkey"], sender_pubkey);
        assert_eq!(event["tags"], json!([["p", recipient_pubkey]]));
        assert_ne!(event["content"], "private hello");
        assert!(event["content"].as_str().unwrap().contains("?iv="));
        assert_eq!(
            decrypt_nip04_content(
                &recipient_scalar,
                &sender_pubkey,
                event["content"].as_str().unwrap()
            ),
            "private hello"
        );

        let canonical = json!([
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"]
        ]);
        let canonical_bytes = serde_json::to_vec(&canonical).unwrap();
        assert_eq!(event["id"], hex::encode(Sha256::digest(canonical_bytes)));
    }

    #[test]
    fn build_nip04_dm_event_normalizes_recipient_and_includes_reply_tag() {
        let sender_scalar = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let sender_pubkey = derive_public_key_hex(&sender_scalar);
        let recipient_scalar = parse_secret_key(RECIPIENT_SCALAR_HEX).unwrap();
        let recipient_pubkey = derive_public_key_hex(&recipient_scalar);
        let recipient_npub = crate::types::encode_public_key_npub(&recipient_pubkey).unwrap();
        let reply = "cd".repeat(32);
        let event = build_nip04_dm_event_with_iv(
            &sender_scalar,
            &sender_pubkey,
            &format!("nostr:{recipient_npub}"),
            "reply",
            Some(&reply),
            [8_u8; 16],
        )
        .unwrap();
        assert_eq!(
            event["tags"],
            json!([["p", recipient_pubkey], ["e", reply]])
        );
    }

    #[test]
    fn build_nip04_dm_event_id_changes_when_iv_changes() {
        let sender_scalar = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let sender_pubkey = derive_public_key_hex(&sender_scalar);
        let recipient_scalar = parse_secret_key(RECIPIENT_SCALAR_HEX).unwrap();
        let recipient_pubkey = derive_public_key_hex(&recipient_scalar);
        let first = build_nip04_dm_event_with_iv(
            &sender_scalar,
            &sender_pubkey,
            &recipient_pubkey,
            "same plaintext",
            None,
            [1_u8; 16],
        )
        .unwrap();
        let second = build_nip04_dm_event_with_iv(
            &sender_scalar,
            &sender_pubkey,
            &recipient_pubkey,
            "same plaintext",
            None,
            [2_u8; 16],
        )
        .unwrap();
        assert_ne!(first["content"], second["content"]);
        assert_ne!(first["id"], second["id"]);
        assert_eq!(first["tags"], second["tags"]);
    }

    fn inbound_dm_fixture(
        plaintext: &str,
        iv: [u8; 16],
    ) -> (SecretKey, String, String, Value, i64) {
        let sender_scalar = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let sender_pubkey = derive_public_key_hex(&sender_scalar);
        let recipient_scalar = parse_secret_key(RECIPIENT_SCALAR_HEX).unwrap();
        let recipient_pubkey = derive_public_key_hex(&recipient_scalar);
        let event = build_nip04_dm_event_with_iv(
            &sender_scalar,
            &sender_pubkey,
            &recipient_pubkey,
            plaintext,
            None,
            iv,
        )
        .unwrap();
        let created_at = event["created_at"].as_i64().unwrap();
        (
            recipient_scalar,
            recipient_pubkey,
            sender_pubkey,
            event,
            created_at,
        )
    }

    fn decision_reason(decision: &InboundDmDecision) -> InboundDmRejectionReason {
        decision.rejection_reason().expect("expected rejection")
    }

    fn evaluate_fixture(
        event: &Value,
        recipient_scalar: &SecretKey,
        recipient_pubkey: &str,
        policy: &InboundDmPolicy,
        state: &mut InboundDmGuardState,
        now_secs: i64,
    ) -> InboundDmDecision {
        evaluate_inbound_dm_event(
            event,
            recipient_scalar,
            recipient_pubkey,
            policy,
            state,
            now_secs,
        )
    }

    #[test]
    fn inbound_dm_core_accepts_valid_event_and_decrypts_plaintext() {
        let (recipient_scalar, recipient_pubkey, sender_pubkey, event, now_secs) =
            inbound_dm_fixture("synthetic inbound hello", [9_u8; 16]);
        let mut state = InboundDmGuardState::default();
        let decision = evaluate_fixture(
            &event,
            &recipient_scalar,
            &recipient_pubkey,
            &InboundDmPolicy::open(),
            &mut state,
            now_secs,
        );

        assert!(
            decision.is_accepted(),
            "expected accepted decision: {decision:?}"
        );
        let InboundDmDecision::Accepted(accepted) = decision else {
            return;
        };
        assert_eq!(accepted.event_id, event["id"]);
        assert_eq!(accepted.sender_pubkey_hex, sender_pubkey);
        assert_eq!(accepted.recipient_pubkey_hex, recipient_pubkey);
        assert_eq!(accepted.event_kind, NIP04_KIND_ENCRYPTED_DM);
        assert_eq!(accepted.plaintext, "synthetic inbound hello");
    }

    #[test]
    fn inbound_dm_core_rejects_invalid_signature_before_decrypting() {
        let (recipient_scalar, recipient_pubkey, _sender_pubkey, mut event, now_secs) =
            inbound_dm_fixture("synthetic inbound hello", [10_u8; 16]);
        event["content"] = json!("tampered ciphertext?iv=still-tampered");
        let mut state = InboundDmGuardState::default();
        let decision = evaluate_fixture(
            &event,
            &recipient_scalar,
            &recipient_pubkey,
            &InboundDmPolicy::open(),
            &mut state,
            now_secs,
        );

        assert_eq!(
            decision_reason(&decision),
            InboundDmRejectionReason::InvalidSignature
        );
    }

    #[test]
    fn inbound_dm_core_rejects_wrong_kind_missing_or_wrong_target_and_self_loop() {
        let (recipient_scalar, recipient_pubkey, _sender_pubkey, mut event, now_secs) =
            inbound_dm_fixture("synthetic inbound hello", [11_u8; 16]);
        let mut wrong_kind = event.clone();
        wrong_kind["kind"] = json!(1);
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &wrong_kind,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::WrongKind
        );

        let mut missing_p = event.clone();
        missing_p["tags"] = json!([]);
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &missing_p,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::MissingRecipientTag
        );

        let other_pubkey =
            derive_public_key_hex(&parse_secret_key("33".repeat(32).as_str()).unwrap());
        event["tags"] = json!([["p", other_pubkey]]);
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &event,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::WrongTarget
        );

        let self_event = build_nip04_dm_event_with_iv(
            &recipient_scalar,
            &recipient_pubkey,
            &recipient_pubkey,
            "self loop",
            None,
            [12_u8; 16],
        )
        .unwrap();
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &self_event,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                self_event["created_at"].as_i64().unwrap()
            )),
            InboundDmRejectionReason::SelfMessage
        );
    }

    #[test]
    fn inbound_dm_core_rejects_stale_future_skew_and_oversized_ciphertext() {
        let (recipient_scalar, recipient_pubkey, _sender_pubkey, mut event, now_secs) =
            inbound_dm_fixture("synthetic inbound hello", [13_u8; 16]);
        let policy = InboundDmPolicy::open().with_time_bounds(10, 5);

        let mut expired_event = event.clone();
        expired_event["created_at"] = json!(now_secs - 11);
        let mut guard = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &expired_event,
                &recipient_scalar,
                &recipient_pubkey,
                &policy,
                &mut guard,
                now_secs
            )),
            InboundDmRejectionReason::StaleEvent
        );

        let mut future = event.clone();
        future["created_at"] = json!(now_secs + 6);
        let mut guard = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &future,
                &recipient_scalar,
                &recipient_pubkey,
                &policy,
                &mut guard,
                now_secs
            )),
            InboundDmRejectionReason::FutureSkew
        );

        event["content"] = json!("x".repeat(policy.max_content_bytes() + 1));
        let mut guard = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &event,
                &recipient_scalar,
                &recipient_pubkey,
                &policy,
                &mut guard,
                now_secs
            )),
            InboundDmRejectionReason::OversizedCiphertext
        );
    }

    #[test]
    fn inbound_dm_core_rejects_malformed_ciphertext_and_decrypt_failure() {
        let recipient_scalar = parse_secret_key(RECIPIENT_SCALAR_HEX).unwrap();
        let recipient_pubkey = derive_public_key_hex(&recipient_scalar);
        let sender_scalar = parse_secret_key(TEST_SECRET_KEY_HEX).unwrap();
        let sender_pubkey = derive_public_key_hex(&sender_scalar);
        let tags = json!([["p", recipient_pubkey]]);
        let malformed = build_signed_event(
            &sender_scalar,
            &sender_pubkey,
            NIP04_KIND_ENCRYPTED_DM,
            &tags,
            "not-a-nip04-envelope",
        )
        .unwrap();
        let now_secs = malformed["created_at"].as_i64().unwrap();
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &malformed,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::MalformedCiphertext
        );

        let bad_ciphertext = format!(
            "{}?iv={}",
            BASE64.encode([0_u8; 16]),
            BASE64.encode([0_u8; 16])
        );
        let decrypt_failure = build_signed_event(
            &sender_scalar,
            &sender_pubkey,
            NIP04_KIND_ENCRYPTED_DM,
            &tags,
            &bad_ciphertext,
        )
        .unwrap();
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &decrypt_failure,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                decrypt_failure["created_at"].as_i64().unwrap()
            )),
            InboundDmRejectionReason::DecryptFailed
        );
    }

    #[test]
    fn inbound_dm_core_enforces_disabled_open_allowlist_and_pairing_policy() {
        let (recipient_scalar, recipient_pubkey, sender_pubkey, event, now_secs) =
            inbound_dm_fixture("synthetic policy hello", [14_u8; 16]);
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &event,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::disabled(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::PolicyDisabled
        );

        let mut state = InboundDmGuardState::default();
        assert!(
            evaluate_fixture(
                &event,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )
            .is_accepted()
        );

        let blocked = InboundDmPolicy::allowlist(["44".repeat(32)]).unwrap();
        let mut state = InboundDmGuardState::default();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &event,
                &recipient_scalar,
                &recipient_pubkey,
                &blocked,
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::PolicySenderBlocked
        );

        let sender_npub = crate::types::encode_public_key_npub(&sender_pubkey).unwrap();
        let allowlist = InboundDmPolicy::allowlist([sender_npub.as_str()]).unwrap();
        let mut state = InboundDmGuardState::default();
        assert!(
            evaluate_fixture(
                &event,
                &recipient_scalar,
                &recipient_pubkey,
                &allowlist,
                &mut state,
                now_secs
            )
            .is_accepted()
        );

        let paired = InboundDmPolicy::pairing_equivalent([format!("nostr:{sender_npub}")]).unwrap();
        let mut state = InboundDmGuardState::default();
        assert!(
            evaluate_fixture(
                &event,
                &recipient_scalar,
                &recipient_pubkey,
                &paired,
                &mut state,
                now_secs
            )
            .is_accepted()
        );
        assert_eq!(paired.mode(), InboundDmPolicyMode::PairingEquivalent);
    }

    #[test]
    fn inbound_dm_core_replay_and_rate_limits_duplicates_global_and_sender() {
        let (recipient_scalar, recipient_pubkey, _sender_pubkey, first, now_secs) =
            inbound_dm_fixture("first", [15_u8; 16]);
        let mut state = InboundDmGuardState::default();
        assert!(
            evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )
            .is_accepted()
        );
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::DuplicateEvent
        );
        assert_eq!(
            state.last_transition()["duplicate_source"],
            "recent_event_id"
        );

        let (_, _, _, second, _) = inbound_dm_fixture("second", [16_u8; 16]);
        let mut state = InboundDmGuardState::new(10, InboundDmRateLimits::new(60, 1, 10));
        assert!(
            evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )
            .is_accepted()
        );
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &second,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::GlobalRateLimited
        );
        let global_transition = state.last_transition();
        assert_eq!(global_transition["rate_limit_scope"], "global");
        assert_eq!(global_transition["global_bucket_before"], 1);
        assert_eq!(global_transition["global_bucket_after"], 1);
        assert!(global_transition["retry_after_ms"].as_u64().unwrap() > 0);

        let mut state = InboundDmGuardState::new(10, InboundDmRateLimits::new(60, 10, 1));
        assert!(
            evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )
            .is_accepted()
        );
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &second,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::SenderRateLimited
        );
        let sender_transition = state.last_transition();
        assert_eq!(sender_transition["rate_limit_scope"], "sender");
        assert_eq!(sender_transition["sender_bucket_before"], 1);
        assert_eq!(sender_transition["sender_bucket_after"], 1);
    }

    #[test]
    fn inbound_dm_state_advances_cursor_and_survives_reconnect_and_restart() {
        let (recipient_scalar, recipient_pubkey, _sender_pubkey, first, now_secs) =
            inbound_dm_fixture("cursor one", [18_u8; 16]);
        let mut state = InboundDmGuardState::default();
        assert!(
            evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )
            .is_accepted()
        );
        assert_eq!(state.cursor(), first["created_at"].as_i64());
        assert_eq!(state.last_transition()["cursor_before"], Value::Null);
        assert_eq!(state.last_transition()["cursor_after"], json!(now_secs));

        state.mark_reconnect();
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )),
            InboundDmRejectionReason::DuplicateEvent
        );
        assert_eq!(
            state.last_transition()["duplicate_source"],
            "recent_event_id"
        );
        assert_eq!(state.last_transition()["reconnect_generation"], 1);

        let snapshot = state.snapshot();
        let mut restored = InboundDmGuardState::from_snapshot(snapshot);
        assert_eq!(restored.restart_generation(), 1);
        assert_eq!(
            decision_reason(&evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut restored,
                now_secs
            )),
            InboundDmRejectionReason::DuplicateEvent
        );
        assert_eq!(
            restored.last_transition()["duplicate_source"],
            "recent_event_id"
        );
    }

    #[test]
    fn inbound_dm_state_bounds_recent_ids_and_allows_independent_senders() {
        let (recipient_scalar, recipient_pubkey, sender_pubkey, first, now_secs) =
            inbound_dm_fixture("sender one", [19_u8; 16]);
        let second_sender_scalar =
            parse_secret_key("3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        let second_sender_pubkey = derive_public_key_hex(&second_sender_scalar);
        let second_sender_event = build_nip04_dm_event_with_iv(
            &second_sender_scalar,
            &second_sender_pubkey,
            &recipient_pubkey,
            "sender two",
            None,
            [20_u8; 16],
        )
        .unwrap();

        let mut state = InboundDmGuardState::new(2, InboundDmRateLimits::new(60, 10, 1));
        assert!(
            evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )
            .is_accepted()
        );
        assert!(
            evaluate_fixture(
                &second_sender_event,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut state,
                now_secs
            )
            .is_accepted(),
            "per-sender buckets must be independent"
        );
        assert_eq!(state.snapshot().per_sender_counts[&sender_pubkey], 1);
        assert_eq!(state.snapshot().per_sender_counts[&second_sender_pubkey], 1);

        let (_, _, _, third, _) = inbound_dm_fixture("sender one third", [21_u8; 16]);
        let mut bounded = InboundDmGuardState::new(1, InboundDmRateLimits::new(60, 10, 10));
        assert!(
            evaluate_fixture(
                &first,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut bounded,
                now_secs
            )
            .is_accepted()
        );
        assert!(
            evaluate_fixture(
                &third,
                &recipient_scalar,
                &recipient_pubkey,
                &InboundDmPolicy::open(),
                &mut bounded,
                now_secs
            )
            .is_accepted()
        );
        let snapshot = bounded.snapshot();
        assert_eq!(snapshot.recent_event_ids.len(), 1);
        assert_eq!(snapshot.overflow_count, 1);
        assert_eq!(
            bounded.last_transition()["seen_evicted"],
            first["id"].as_str().unwrap()
        );
        assert!(
            serde_json::to_string(&snapshot)
                .unwrap()
                .contains(third["id"].as_str().unwrap())
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("sender one third"),
            "state snapshots must not persist plaintext"
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains(TEST_SECRET_KEY_HEX),
            "state snapshots must not persist private keys"
        );
    }

    #[test]
    fn inbound_dm_core_debug_redacts_plaintext_and_secret_material() {
        let (recipient_scalar, recipient_pubkey, _sender_pubkey, event, now_secs) =
            inbound_dm_fixture("top secret synthetic text", [17_u8; 16]);
        let mut state = InboundDmGuardState::default();
        let decision = evaluate_fixture(
            &event,
            &recipient_scalar,
            &recipient_pubkey,
            &InboundDmPolicy::open(),
            &mut state,
            now_secs,
        );
        let debug = format!("{decision:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("top secret synthetic text"));
        assert!(!debug.contains(TEST_SECRET_KEY_HEX));
        assert!(!debug.contains(RECIPIENT_SCALAR_HEX));
    }

    #[test]
    fn inbound_dm_core_preserves_public_query_and_note_boundaries() {
        assert!(note_kind(&json!({"kind": NIP04_KIND_ENCRYPTED_DM})).is_err());
        let filter = build_filter(&json!({"kinds": [NIP04_KIND_ENCRYPTED_DM], "limit": 1}), 25)
            .expect("bounded public query should still accept explicit kind filters");
        assert_eq!(filter["kinds"], json!([NIP04_KIND_ENCRYPTED_DM]));
        assert_eq!(filter["limit"], 1);
    }

    #[test]
    fn relay_frame_parses_event() {
        let frame = RelayFrame::from_value(json!(["EVENT", "sub-1", {"id": "a", "content": "hi"}]));
        assert!(matches!(frame, RelayFrame::Event { .. }));
    }

    #[test]
    fn relay_frame_parses_eose() {
        let frame = RelayFrame::from_value(json!(["EOSE", "sub-1"]));
        assert!(matches!(frame, RelayFrame::Eose { sub_id } if sub_id == "sub-1"));
    }

    #[test]
    fn relay_frame_parses_ok() {
        let frame = RelayFrame::from_value(json!(["OK", "event-1", true, ""]));
        assert!(matches!(frame, RelayFrame::Ok { accepted: true, .. }));
    }

    #[test]
    fn relay_frame_parses_notice() {
        let frame = RelayFrame::from_value(json!(["NOTICE", "rate-limited"]));
        assert!(matches!(frame, RelayFrame::Notice { message } if message == "rate-limited"));
    }

    #[test]
    fn relay_frame_raw_fallback() {
        let frame = RelayFrame::from_value(json!({"unexpected": true}));
        assert!(matches!(frame, RelayFrame::Raw(_)));
    }

    #[test]
    fn relay_frame_roundtrip_event() {
        let original = json!(["EVENT", "s1", {"id": "abc"}]);
        let frame = RelayFrame::from_value(original.clone());
        assert_eq!(frame.into_json(), original);
    }

    #[test]
    fn relay_frame_roundtrip_notice() {
        let original = json!(["NOTICE", "hello"]);
        let frame = RelayFrame::from_value(original.clone());
        assert_eq!(frame.into_json(), original);
    }

    #[test]
    fn relay_query_state_dedup_by_id() {
        let mut state = RelayQueryState::default();
        state.push_event(json!({"id": "abc", "content": "first"}));
        state.push_event(json!({"id": "abc", "content": "duplicate"}));
        state.push_event(json!({"id": "def", "content": "second"}));
        let events = state.into_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["content"], "first");
        assert_eq!(events[1]["content"], "second");
    }

    #[test]
    fn relay_query_state_no_id_skipped() {
        let mut state = RelayQueryState::default();
        state.push_event(json!({"content": "no id 1"}));
        state.push_event(json!({"content": "no id 2"}));
        assert_eq!(state.into_events().len(), 0);
    }

    #[test]
    fn relay_binding_debug_shows_url() {
        let binding = RelayBinding::parse("wss://relay.example.com").unwrap();
        let debug = format!("{binding:?}");
        assert!(debug.contains("wss://relay.example.com"));
    }

    #[test]
    fn relay_binding_rejects_localhost_without_policy() {
        assert!(RelayBinding::parse("ws://localhost:7777").is_err());
        assert!(
            RelayBinding::parse_with_policy("ws://localhost:7777", RelayUrlPolicy::local_harness())
                .is_ok()
        );
    }

    #[test]
    fn nostr_key_material_debug_redacts_secret() {
        let km = NostrKeyMaterial::from_secret_key_input(TEST_SECRET_KEY_HEX).unwrap();
        let debug = format!("{km:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_SECRET_KEY_HEX));
        assert!(debug.contains(&km.public_key_hex));
    }

    #[test]
    fn nostr_client_debug_redacts_secrets() {
        let config = NostrConfig {
            relay_urls: vec!["wss://relay.example.com".into()],
            secret_key_hex: TEST_SECRET_KEY_HEX.into(),
            request_timeout_ms: 15_000,
            default_query_limit: 25,
            allow_local_relays: false,
            relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
            relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
            inbound_dm: NostrInboundDmConfig::default(),
        };
        let client = NostrClient::new(&config).unwrap();
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_SECRET_KEY_HEX));
    }

    #[test]
    fn nostr_client_rejects_invalid_config() {
        let config = NostrConfig {
            relay_urls: vec![],
            secret_key_hex: TEST_SECRET_KEY_HEX.into(),
            request_timeout_ms: 15_000,
            default_query_limit: 25,
            allow_local_relays: false,
            relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
            relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
            inbound_dm: NostrInboundDmConfig::default(),
        };
        assert!(NostrClient::new(&config).is_err());
    }

    #[test]
    fn nostr_client_relay_urls() {
        let config = NostrConfig {
            relay_urls: vec![
                "wss://relay1.example.com".into(),
                "wss://relay2.example.com".into(),
            ],
            secret_key_hex: TEST_SECRET_KEY_HEX.into(),
            request_timeout_ms: 15_000,
            default_query_limit: 25,
            allow_local_relays: false,
            relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
            relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
            inbound_dm: NostrInboundDmConfig::default(),
        };
        let client = NostrClient::new(&config).unwrap();
        let urls = client.relay_urls();
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("relay1"));
        assert!(urls[1].contains("relay2"));
    }

    #[test]
    fn nostr_client_canonicalizes_and_deduplicates_relays() {
        let config = NostrConfig {
            relay_urls: vec![
                " wss://Relay1.EXAMPLE.com ".into(),
                "wss://relay1.example.com/".into(),
                "wss://relay2.example.com/chat".into(),
            ],
            secret_key_hex: TEST_SECRET_KEY_HEX.into(),
            request_timeout_ms: 15_000,
            default_query_limit: 25,
            allow_local_relays: false,
            relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
            relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
            inbound_dm: NostrInboundDmConfig::default(),
        };
        let client = NostrClient::new(&config).unwrap();
        assert_eq!(
            client.relay_urls(),
            vec![
                "wss://relay1.example.com/".to_string(),
                "wss://relay2.example.com/chat".to_string()
            ]
        );
    }

    #[test]
    fn nostr_client_exposes_initial_resilience_snapshots() {
        let config = NostrConfig {
            relay_urls: vec!["wss://relay.example.com".into()],
            secret_key_hex: TEST_SECRET_KEY_HEX.into(),
            request_timeout_ms: 15_000,
            default_query_limit: 25,
            allow_local_relays: false,
            relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
            relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
            inbound_dm: NostrInboundDmConfig::default(),
        };
        let client = NostrClient::new(&config).unwrap();
        let snapshots = client.relay_resilience_snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].relay_url, "wss://relay.example.com/");
        assert_eq!(snapshots[0].circuit_state, RelayCircuitState::Closed);
        assert_eq!(snapshots[0].success_count, 0);
        assert_eq!(snapshots[0].failure_count, 0);
    }

    #[test]
    fn nostr_client_resilience_metrics_include_stable_labels() {
        let config = NostrConfig {
            relay_urls: vec!["wss://relay.example.com".into()],
            secret_key_hex: TEST_SECRET_KEY_HEX.into(),
            request_timeout_ms: 15_000,
            default_query_limit: 25,
            allow_local_relays: false,
            relay_circuit_failure_threshold: DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD,
            relay_circuit_reset_ms: DEFAULT_RELAY_CIRCUIT_RESET_MS,
            inbound_dm: NostrInboundDmConfig::default(),
        };
        let client = NostrClient::new(&config).unwrap();
        let metrics = client.relay_resilience_metrics(OP_PUBLISH_NOTE);
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0]["labels"]["connector"], "nostr");
        assert_eq!(metrics[0]["labels"]["operation"], OP_PUBLISH_NOTE);
        assert_eq!(metrics[0]["labels"]["relay"], "wss://relay.example.com/");
        assert_eq!(metrics[0]["labels"]["circuit_state"], "closed");
    }

    #[test]
    fn is_retryable_true_for_external_retryable() {
        let err = FcpError::External {
            service: "nostr".into(),
            message: "test".into(),
            status_code: None,
            retryable: true,
            retry_after: None,
        };
        assert!(is_retryable_relay_error(&err));
    }

    #[test]
    fn is_retryable_false_for_non_retryable() {
        let err = FcpError::External {
            service: "nostr".into(),
            message: "test".into(),
            status_code: None,
            retryable: false,
            retry_after: None,
        };
        assert!(!is_retryable_relay_error(&err));
    }

    #[test]
    fn relay_circuit_breaker_opens_after_threshold() {
        let mut breaker = RelayCircuitBreaker::new(2, 1_000);
        assert!(breaker.can_attempt(0));
        breaker.record_failure(10);
        assert_eq!(breaker.state(), RelayCircuitState::Closed);
        breaker.record_failure(20);
        assert_eq!(breaker.state(), RelayCircuitState::Open);
        assert!(!breaker.can_attempt(500));
    }

    #[test]
    fn relay_circuit_breaker_half_opens_after_reset() {
        let mut breaker = RelayCircuitBreaker::new(1, 1_000);
        breaker.record_failure(10);
        assert_eq!(breaker.state(), RelayCircuitState::Open);
        assert!(breaker.can_attempt(1_010));
        assert_eq!(breaker.state(), RelayCircuitState::HalfOpen);
    }

    #[test]
    fn relay_circuit_breaker_closes_on_success() {
        let mut breaker = RelayCircuitBreaker::new(1, 1_000);
        breaker.record_failure(10);
        assert!(breaker.can_attempt(1_010));
        breaker.record_success();
        assert_eq!(breaker.state(), RelayCircuitState::Closed);
        assert_eq!(breaker.failure_count(), 0);
    }

    #[test]
    fn relay_resilience_state_records_latency_and_errors() {
        let mut state = RelayResilienceState::default();
        assert!(state.can_attempt(0));
        state.record_success(25);
        state.record_failure(100, "timeout".into());
        let snapshot = state.snapshot("wss://relay.example.com/");
        assert_eq!(snapshot.success_count, 1);
        assert_eq!(snapshot.failure_count, 1);
        assert_eq!(snapshot.average_latency_ms, Some(25));
        assert_eq!(snapshot.last_error.as_deref(), Some("timeout"));
    }

    // ── RelayHealthScore tests ──────────────────────────────────────────

    #[test]
    fn relay_health_scores_sort_reachable_low_latency_first() {
        let mut scores = vec![
            RelayHealthScore {
                relay_url: "wss://slow.example.com/".into(),
                reachable: true,
                latency_ms: Some(40),
                supports_nip04: true,
                supports_nip44: false,
                last_checked: "1".into(),
            },
            RelayHealthScore {
                relay_url: "wss://down.example.com/".into(),
                reachable: false,
                latency_ms: None,
                supports_nip04: false,
                supports_nip44: false,
                last_checked: "1".into(),
            },
            RelayHealthScore {
                relay_url: "wss://fast.example.com/".into(),
                reachable: true,
                latency_ms: Some(5),
                supports_nip04: false,
                supports_nip44: false,
                last_checked: "1".into(),
            },
        ];
        sort_relay_health_scores(&mut scores);
        let urls = scores
            .iter()
            .map(|score| score.relay_url.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            urls,
            vec![
                "wss://fast.example.com/",
                "wss://slow.example.com/",
                "wss://down.example.com/"
            ]
        );
    }

    #[test]
    fn relay_health_score_unreachable_has_correct_defaults() {
        let score = RelayHealthScore::unreachable("wss://down.example.com", "1700000000".into());
        assert!(!score.reachable);
        assert!(score.latency_ms.is_none());
        assert!(!score.supports_nip04);
        assert!(!score.supports_nip44);
        assert_eq!(score.relay_url, "wss://down.example.com");
        assert_eq!(score.last_checked, "1700000000");
    }

    #[test]
    fn relay_health_score_serializes_to_json() {
        let score = RelayHealthScore {
            relay_url: "wss://relay.example.com".into(),
            reachable: true,
            latency_ms: Some(42),
            supports_nip04: true,
            supports_nip44: false,
            last_checked: "1700000001".into(),
        };
        let json = serde_json::to_value(&score).unwrap();
        assert_eq!(json["relay_url"], "wss://relay.example.com");
        assert_eq!(json["reachable"], true);
        assert_eq!(json["latency_ms"], 42);
        assert_eq!(json["supports_nip04"], true);
        assert_eq!(json["supports_nip44"], false);
        assert_eq!(json["last_checked"], "1700000001");
    }

    #[test]
    fn relay_health_score_deserializes_from_json() {
        let json = json!({
            "relay_url": "wss://relay.example.com",
            "reachable": true,
            "latency_ms": 55,
            "supports_nip04": false,
            "supports_nip44": true,
            "last_checked": "1700000002"
        });
        let score: RelayHealthScore = serde_json::from_value(json).unwrap();
        assert!(score.reachable);
        assert_eq!(score.latency_ms, Some(55));
        assert!(!score.supports_nip04);
        assert!(score.supports_nip44);
    }

    #[test]
    fn relay_health_score_unreachable_serialization_roundtrip() {
        let score = RelayHealthScore::unreachable("wss://lost.example.com", "1700000003".into());
        let json = serde_json::to_value(&score).unwrap();
        let deserialized: RelayHealthScore = serde_json::from_value(json).unwrap();
        assert!(!deserialized.reachable);
        assert!(deserialized.latency_ms.is_none());
        assert_eq!(deserialized.relay_url, "wss://lost.example.com");
    }

    // ── DedupTracker tests ──────────────────────────────────────────────

    #[test]
    fn dedup_tracker_inserts_new_ids() {
        let mut tracker = DedupTracker::new(100);
        assert!(tracker.insert("abc"));
        assert!(tracker.insert("def"));
        assert_eq!(tracker.len(), 2);
        assert!(!tracker.is_empty());
    }

    #[test]
    fn dedup_tracker_rejects_duplicate_ids() {
        let mut tracker = DedupTracker::new(100);
        assert!(tracker.insert("abc"));
        assert!(!tracker.insert("abc"));
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn dedup_tracker_respects_capacity_limit() {
        let mut tracker = DedupTracker::new(3);
        assert!(tracker.insert("a"));
        assert!(tracker.insert("b"));
        assert!(tracker.insert("c"));
        // At capacity now - new inserts evict the oldest IDs.
        assert!(tracker.insert("d"));
        assert!(tracker.insert("e"));
        assert_eq!(tracker.len(), 3);
        assert_eq!(tracker.overflow_count(), 2);
        assert!(!tracker.contains("a"));
        assert!(!tracker.contains("b"));
        assert!(tracker.contains("c"));
        assert!(tracker.contains("d"));
        assert!(tracker.contains("e"));
    }

    #[test]
    fn dedup_tracker_contains_works() {
        let mut tracker = DedupTracker::new(100);
        tracker.insert("abc");
        assert!(tracker.contains("abc"));
        assert!(!tracker.contains("xyz"));
    }

    #[test]
    fn dedup_tracker_empty_initially() {
        let tracker = DedupTracker::new(10);
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.overflow_count(), 0);
    }

    #[test]
    #[should_panic(expected = "max_capacity must be > 0")]
    fn dedup_tracker_panics_on_zero_capacity() {
        let _ = DedupTracker::new(0);
    }

    #[test]
    fn dedup_tracker_debug_output() {
        let mut tracker = DedupTracker::new(5);
        tracker.insert("a");
        tracker.insert("b");
        let debug = format!("{tracker:?}");
        assert!(debug.contains("tracked"));
        assert!(debug.contains("max_capacity"));
        assert!(debug.contains("overflow_count"));
    }

    #[test]
    fn dedup_tracker_overflow_count_saturates() {
        let mut tracker = DedupTracker::new(1);
        tracker.insert("only");
        // Flood with overflow insertions - should not panic
        for i in 0..1000 {
            tracker.insert(&format!("overflow_{i}"));
        }
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.overflow_count(), 1000);
    }

    #[test]
    fn dedup_tracker_duplicate_at_capacity_does_not_overflow() {
        let mut tracker = DedupTracker::new(2);
        tracker.insert("a");
        tracker.insert("b");
        // Re-inserting existing should return false but NOT increment overflow
        assert!(!tracker.insert("a"));
        assert_eq!(tracker.overflow_count(), 0);
    }
}
