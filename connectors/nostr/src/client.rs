//! Nostr relay client: crypto, WebSocket relay communication, and `ConnectorRuntime` integration.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fcp_core::{FcpError, FcpResult};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_streaming::{StreamError, WsClient, WsConnection, WsMessage};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::types::{
    NostrConfig, build_filter, note_kind, note_tags, required_string, validate_relay_url,
};

const READ_ONLY_RECONNECT_ATTEMPTS: usize = 2;

// ─── Relay binding ───────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RelayBinding {
    url: Url,
}

impl RelayBinding {
    /// Parse and validate a Nostr relay URL.
    ///
    /// # Errors
    ///
    /// Returns an error if `raw` is empty, malformed, or does not use
    /// `ws://` or `wss://`.
    pub fn parse(raw: &str) -> FcpResult<Self> {
        let url = validate_relay_url(raw)?;
        Ok(Self { url })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
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
    /// Construct key material from a hex-encoded secp256k1 secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is malformed or invalid.
    pub fn from_secret_key_hex(raw: &str) -> FcpResult<Self> {
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

/// Parse a hex-encoded secp256k1 secret key.
///
/// # Errors
///
/// Returns an error if `raw` is not valid hex or does not decode to a valid
/// secp256k1 secret key.
pub fn parse_secret_key(raw: &str) -> FcpResult<SecretKey> {
    let bytes = hex::decode(raw.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("secret_key_hex must be valid hex: {error}"),
    })?;
    SecretKey::from_slice(&bytes).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("secret_key_hex is not a valid secp256k1 secret key: {error}"),
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
        fcp_async_core::time::timeout(self.timeout, ws.recv())
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
        let response = self.recv(&mut ws, "nostr publish recv").await?;
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
            match self.query_once(sub_id, filter, &mut query_state).await {
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
            let Some(message) = self.recv(&mut ws, "nostr query recv").await? else {
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
}

impl std::fmt::Debug for NostrClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrClient")
            .field("relays", &self.relays)
            .field("key_material", &self.key_material)
            .field("request_timeout", &self.request_timeout)
            .field("default_query_limit", &self.default_query_limit)
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
        let relays = config
            .relay_urls
            .iter()
            .map(|relay| RelayBinding::parse(relay))
            .collect::<FcpResult<Vec<_>>>()?;
        let key_material = NostrKeyMaterial::from_secret_key_hex(&config.secret_key_hex)?;
        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
        );
        Ok(Self {
            relays,
            key_material,
            request_timeout,
            default_query_limit: config.default_query_limit,
            runtime,
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
            match relay.publish(&event).await {
                Ok(result) => accepted.push(result),
                Err(error) => rejected.push(json!({
                    "relay": relay.relay.as_str(),
                    "error": error.to_string(),
                })),
            }
        }

        Ok(json!({
            "event": event,
            "accepted_relays": accepted,
            "rejected_relays": rejected,
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
            match relay.query(&sub_id, &filter).await {
                Ok(events) => per_relay.push(json!({
                    "relay": relay.relay.as_str(),
                    "events": events,
                })),
                Err(error) => per_relay.push(json!({
                    "relay": relay.relay.as_str(),
                    "error": error.to_string(),
                })),
            }
        }
        Ok(json!({
            "subscription_id": sub_id,
            "filter": filter,
            "results": per_relay,
        }))
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
            match relay.health().await {
                Ok(result) => results.push(result),
                Err(error) => results.push(json!({
                    "relay": relay.relay.as_str(),
                    "reachable": false,
                    "error": error.to_string(),
                })),
            }
        }
        Ok(json!({
            "public_key_hex": self.public_key_hex(),
            "relay_health": results,
        }))
    }
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

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn parse_secret_key_valid_hex() {
        let sk = parse_secret_key(TEST_SECRET_KEY_HEX);
        assert!(sk.is_ok());
    }

    #[test]
    fn parse_secret_key_invalid_hex() {
        assert!(parse_secret_key("not_hex").is_err());
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
    fn nostr_key_material_debug_redacts_secret() {
        let km = NostrKeyMaterial::from_secret_key_hex(TEST_SECRET_KEY_HEX).unwrap();
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
        };
        let client = NostrClient::new(&config).unwrap();
        let urls = client.relay_urls();
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("relay1"));
        assert!(urls[1].contains("relay2"));
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
}
