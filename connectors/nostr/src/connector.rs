//! `Nostr` relay connector.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, AuthCaps, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityVerifier, ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::prelude::*;
use fcp_streaming::{StreamError, WsClient, WsMessage};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_QUERY_LIMIT: u64 = 25;
const NOTE_KIND_TEXT: u64 = 1;

const OP_PUBLISH_NOTE: &str = "nostr.notes.publish";
const OP_QUERY_EVENTS: &str = "nostr.events.query";
const OP_LIST_RELAYS: &str = "nostr.relays.list";
const OP_HEALTH: &str = "nostr.health";

const CAP_NOTES_WRITE: &str = "nostr.notes.write";
const CAP_EVENTS_READ: &str = "nostr.events.read";
const CAP_RELAYS_READ: &str = "nostr.relays.read";
const CAP_HEALTH_READ: &str = "nostr.health.read";

#[derive(Clone, Deserialize)]
struct NostrConfig {
    relay_urls: Vec<String>,
    secret_key_hex: String,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default = "default_query_limit")]
    default_query_limit: u64,
}

impl std::fmt::Debug for NostrConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrConfig")
            .field("relay_urls", &self.relay_urls)
            .field("secret_key_hex", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("default_query_limit", &self.default_query_limit)
            .finish()
    }
}

struct NostrState {
    relay_urls: Vec<String>,
    secret_key_hex: String,
    request_timeout: Duration,
    default_query_limit: u64,
    public_key_hex: String,
}

impl std::fmt::Debug for NostrState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrState")
            .field("relay_urls", &self.relay_urls)
            .field("secret_key_hex", &"[REDACTED]")
            .field("request_timeout", &self.request_timeout)
            .field("default_query_limit", &self.default_query_limit)
            .field("public_key_hex", &self.public_key_hex)
            .finish()
    }
}

#[derive(Debug)]
pub struct NostrConnector {
    base: BaseConnector,
    state: Option<NostrState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

const fn default_query_limit() -> u64 {
    DEFAULT_QUERY_LIMIT
}

impl NostrConfig {
    fn validate(&self) -> FcpResult<()> {
        if self.relay_urls.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "relay_urls must not be empty".into(),
            });
        }
        if self.secret_key_hex.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "secret_key_hex must not be empty".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        if self.default_query_limit == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "default_query_limit must be greater than zero".into(),
            });
        }
        for relay in &self.relay_urls {
            let url = Url::parse(relay).map_err(|error| FcpError::InvalidRequest {
                code: 1001,
                message: format!("invalid relay URL `{relay}`: {error}"),
            })?;
            if !matches!(url.scheme(), "ws" | "wss") {
                return Err(FcpError::InvalidRequest {
                    code: 1001,
                    message: format!("relay URL `{relay}` must use ws:// or wss://"),
                });
            }
        }
        parse_secret_key(&self.secret_key_hex)?;
        Ok(())
    }
}

impl NostrState {
    fn new(config: NostrConfig) -> FcpResult<Self> {
        config.validate()?;
        let public_key_hex = derive_public_key_hex(&config.secret_key_hex)?;
        Ok(Self {
            relay_urls: config.relay_urls,
            secret_key_hex: config.secret_key_hex,
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            default_query_limit: config.default_query_limit,
            public_key_hex,
        })
    }

    fn secret_key(&self) -> FcpResult<SecretKey> {
        parse_secret_key(&self.secret_key_hex)
    }
}

impl NostrConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.nostr")),
            state: None,
            verifier: None,
            started_at: Instant::now(),
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    #[allow(clippy::too_many_lines)]
    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_PUBLISH_NOTE,
                "Publish a signed public Nostr note",
                "Sign one public kind-1 Nostr note with the configured secp256k1 secret key and publish it to every configured relay. This first slice does not construct encrypted DMs, profile metadata events, or long-lived relay sessions.",
                CAP_NOTES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": { "type": "string" },
                        "kind": { "type": "integer", "enum": [1] },
                        "tags": { "type": "array", "items": { "type": "array", "items": { "type": "string" } } }
                    }
                }),
                "Use when you need to publish one public note through the connector's bound keypair to every configured relay.",
                &[
                    "This first slice does not construct or decrypt encrypted DMs (NIP-04/NIP-17).",
                    "`kind` is fixed to `1` for this first-slice note operation.",
                    "`secret_key_hex` is raw hex, not bech32 `nsec` input.",
                    "Publishing fans out to every configured relay; there is no per-request relay override.",
                ],
                &[CAP_HEALTH_READ, CAP_RELAYS_READ, CAP_EVENTS_READ],
            ),
            operation(
                OP_QUERY_EVENTS,
                "Query bounded public Nostr events from configured relays",
                "Run one bounded REQ/EOSE query across configured relays and collect matching public events. The connector does not maintain long-lived subscriptions, replay cursors, or cross-relay dedupe.",
                CAP_EVENTS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({
                    "type": "object",
                    "properties": {
                        "authors": { "type": "array", "items": { "type": "string" } },
                        "kinds": { "type": "array", "items": { "type": "integer" } },
                        "ids": { "type": "array", "items": { "type": "string" } },
                        "since": { "type": "integer" },
                        "until": { "type": "integer" },
                        "limit": { "type": "integer" }
                    }
                }),
                "Use for bounded public-event queries when you already know the relay set and do not need a long-lived subscription.",
                &[
                    "This is a bounded public-event query surface, not DM sync.",
                    "If `limit` is omitted the connector uses `default_query_limit`.",
                    "Results are returned per relay and may contain duplicates across relays.",
                ],
                &[CAP_RELAYS_READ, CAP_HEALTH_READ],
            ),
            operation(
                OP_LIST_RELAYS,
                "List configured relays",
                "Return the configured relay allowlist and the x-only public key derived from the bound secp256k1 secret key. This is local inspection only; it does not discover or mutate relays.",
                CAP_RELAYS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use to inspect which relays and public key this connector instance is bound to.",
                &[
                    "This does not discover relays from NIP metadata or mutate relay policy.",
                    "The relay list is static configuration for this first slice.",
                ],
                &[CAP_HEALTH_READ, CAP_EVENTS_READ],
            ),
            operation(
                OP_HEALTH,
                "Verify relay connectivity and local signing identity",
                "Open and close each configured relay and report reachability alongside the derived public key. This verifies relay reachability and local key derivation, not encrypted DM support or publish success policy.",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before publishing to confirm the configured relay set is reachable and the bound signing identity is coherent.",
                &[
                    "Health checks websocket reachability only; it does not prove encrypted DM support.",
                    "Health does not score, rank, or deduplicate relays.",
                ],
                &[CAP_RELAYS_READ, CAP_NOTES_WRITE],
            ),
        ]
    }

    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let state = self.state.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        let capability = required_capability(req.operation.as_str())?;
        verifier.verify(&req.capability_token, &capability, &req.operation, &[])?;

        let output = match req.operation.as_str() {
            OP_PUBLISH_NOTE => publish_note(state, &req.input).await?,
            OP_QUERY_EVENTS => query_events(state, &req.input).await?,
            OP_LIST_RELAYS => json!({
                "relays": state.relay_urls,
                "public_key_hex": state.public_key_hex,
            }),
            OP_HEALTH => health_details(state).await?,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("unknown operation: {}", req.operation),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for NostrConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FcpConnector for NostrConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: Value) -> FcpResult<()> {
        let config: NostrConfig =
            serde_json::from_value(config).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("invalid Nostr configuration: {error}"),
            })?;
        self.state = Some(NostrState::new(config)?);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: granted_capabilities(req.capabilities_requested),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: Some(nostr_auth_caps()),
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot {
            status: if self.state.is_some() {
                HealthState::Ready
            } else {
                HealthState::Starting
            },
            uptime_ms: u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            load: None,
            details: self.state.as_ref().map(|state| {
                json!({
                    "relay_count": state.relay_urls.len(),
                    "public_key_hex": state.public_key_hex,
                })
            }),
            rate_limit: None,
        }
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(state) = self.state.as_ref() else {
            return Ok(SelfCheckReport::failed(
                "not_configured",
                "configure must be called before Nostr self_check",
            ));
        };
        match health_details(state).await {
            Ok(_) => Ok(SelfCheckReport::ok()),
            Err(error) => Ok(SelfCheckReport::from_error(&error)),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        self.state = None;
        self.verifier = None;
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: Self::operations(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: Some(nostr_auth_caps()),
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match required_capability(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        let Some(state) = self.state.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        };
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) = verifier.verify(&req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        if let Err(error) = validate_simulation_input(req.operation.as_str(), &req.input, state) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

async fn publish_note(state: &NostrState, input: &Value) -> FcpResult<Value> {
    let content = required_string(input, "content")?;
    let kind = note_kind(input)?;
    let tags = note_tags(input)?;
    let event = build_signed_event(
        &state.secret_key()?,
        &state.public_key_hex,
        kind,
        &tags,
        content,
    )?;

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for relay in &state.relay_urls {
        match publish_to_relay(relay, state.request_timeout, &event).await {
            Ok(result) => accepted.push(result),
            Err(error) => rejected.push(json!({
                "relay": relay,
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

async fn query_events(state: &NostrState, input: &Value) -> FcpResult<Value> {
    let filter = build_filter(input, state.default_query_limit)?;
    let sub_id = format!("fcp-{}", Uuid::new_v4().simple());
    let mut per_relay = Vec::new();
    for relay in &state.relay_urls {
        match query_relay(relay, state.request_timeout, &sub_id, &filter).await {
            Ok(events) => per_relay.push(json!({
                "relay": relay,
                "events": events,
            })),
            Err(error) => per_relay.push(json!({
                "relay": relay,
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

async fn health_details(state: &NostrState) -> FcpResult<Value> {
    let mut results = Vec::with_capacity(state.relay_urls.len());
    for relay in &state.relay_urls {
        match connect_relay(relay).await {
            Ok(mut ws) => {
                let _ = ws.close().await;
                results.push(json!({
                    "relay": relay,
                    "reachable": true,
                }));
            }
            Err(error) => results.push(json!({
                "relay": relay,
                "reachable": false,
                "error": error.to_string(),
            })),
        }
    }
    Ok(json!({
        "public_key_hex": state.public_key_hex,
        "relay_health": results,
    }))
}

async fn publish_to_relay(relay: &str, timeout: Duration, event: &Value) -> FcpResult<Value> {
    let mut ws = connect_relay(relay).await?;
    let payload = json!(["EVENT", event]);
    ws.send_json(&payload)
        .await
        .map_err(map_stream_error("nostr publish send"))?;
    let response = fcp_async_core::time::timeout(timeout, ws.recv())
        .await
        .map_err(|_| FcpError::UpstreamTimeout {
            service: "nostr".into(),
        })?
        .map_err(map_stream_error("nostr publish recv"))?;
    let _ = ws.close().await;
    let response = response.ok_or_else(|| FcpError::External {
        service: "nostr".into(),
        message: format!("relay `{relay}` closed before acknowledging event"),
        status_code: None,
        retryable: true,
        retry_after: None,
    })?;
    let parsed = parse_ws_message(&response)?;
    Ok(json!({
        "relay": relay,
        "response": parsed,
    }))
}

async fn query_relay(
    relay: &str,
    timeout: Duration,
    sub_id: &str,
    filter: &Value,
) -> FcpResult<Vec<Value>> {
    let mut ws = connect_relay(relay).await?;
    ws.send_json(&json!(["REQ", sub_id, filter]))
        .await
        .map_err(map_stream_error("nostr query send"))?;

    let mut events = Vec::new();
    loop {
        let message = fcp_async_core::time::timeout(timeout, ws.recv())
            .await
            .map_err(|_| FcpError::UpstreamTimeout {
                service: "nostr".into(),
            })?
            .map_err(map_stream_error("nostr query recv"))?;
        let Some(message) = message else {
            break;
        };
        let parsed = parse_ws_message(&message)?;
        if is_eose(&parsed, sub_id) {
            break;
        }
        if let Some(event) = extract_event(&parsed, sub_id) {
            events.push(event);
        }
    }

    let _ = ws.send_json(&json!(["CLOSE", sub_id])).await;
    let _ = ws.close().await;
    Ok(events)
}

async fn connect_relay(relay: &str) -> FcpResult<fcp_streaming::WsConnection> {
    WsClient::new(relay)
        .connect()
        .await
        .map_err(map_stream_error("nostr relay connect"))
}

fn map_stream_error(context: &'static str) -> impl Fn(StreamError) -> FcpError {
    move |error| FcpError::External {
        service: "nostr".into(),
        message: format!("{context} failed: {error}"),
        status_code: None,
        retryable: true,
        retry_after: None,
    }
}

fn parse_secret_key(raw: &str) -> FcpResult<SecretKey> {
    let bytes = hex::decode(raw.trim()).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("secret_key_hex must be valid hex: {error}"),
    })?;
    SecretKey::from_slice(&bytes).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("secret_key_hex is not a valid secp256k1 secret key: {error}"),
    })
}

fn derive_public_key_hex(secret_key_hex: &str) -> FcpResult<String> {
    let secp = Secp256k1::new();
    let secret_key = parse_secret_key(secret_key_hex)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    Ok(pubkey.to_string())
}

fn build_signed_event(
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

fn build_filter(input: &Value, default_limit: u64) -> FcpResult<Value> {
    let mut filter = serde_json::Map::new();
    if let Some(authors) = string_array_field(input, "authors")? {
        filter.insert("authors".into(), Value::Array(authors));
    }
    if let Some(ids) = string_array_field(input, "ids")? {
        filter.insert("ids".into(), Value::Array(ids));
    }
    if let Some(kinds) = u64_array_field(input, "kinds")? {
        filter.insert("kinds".into(), Value::Array(kinds));
    }
    if let Some(since) = i64_field(input, "since")? {
        filter.insert("since".into(), json!(since));
    }
    if let Some(until) = i64_field(input, "until")? {
        filter.insert("until".into(), json!(until));
    }
    let limit = u64_field(input, "limit")?.unwrap_or(default_limit);
    if limit == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "limit must be greater than zero".into(),
        });
    }
    filter.insert("limit".into(), json!(limit));
    Ok(Value::Object(filter))
}

fn parse_ws_message(message: &WsMessage) -> FcpResult<Value> {
    match message {
        WsMessage::Text(text) => {
            serde_json::from_str::<Value>(text).map_err(|error| FcpError::External {
                service: "nostr".into(),
                message: format!("failed to parse relay frame: {error}"),
                status_code: None,
                retryable: false,
                retry_after: None,
            })
        }
        other => Err(FcpError::External {
            service: "nostr".into(),
            message: format!("unexpected relay frame type: {other:?}"),
            status_code: None,
            retryable: false,
            retry_after: None,
        }),
    }
}

fn is_eose(parsed: &Value, sub_id: &str) -> bool {
    parsed
        .as_array()
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        == Some("EOSE")
        && parsed
            .as_array()
            .and_then(|items| items.get(1))
            .and_then(Value::as_str)
            == Some(sub_id)
}

fn extract_event(parsed: &Value, sub_id: &str) -> Option<Value> {
    let items = parsed.as_array()?;
    if items.first().and_then(Value::as_str) != Some("EVENT") {
        return None;
    }
    if items.get(1).and_then(Value::as_str) != Some(sub_id) {
        return None;
    }
    items.get(2).cloned()
}

fn required_capability(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_PUBLISH_NOTE => CAP_NOTES_WRITE,
        OP_QUERY_EVENTS => CAP_EVENTS_READ,
        OP_LIST_RELAYS => CAP_RELAYS_READ,
        OP_HEALTH => CAP_HEALTH_READ,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn validate_simulation_input(operation: &str, input: &Value, state: &NostrState) -> FcpResult<()> {
    match operation {
        OP_PUBLISH_NOTE => {
            let _ = required_string(input, "content")?;
            let _ = note_kind(input)?;
            let _ = note_tags(input)?;
            Ok(())
        }
        OP_QUERY_EVENTS => {
            let _ = build_filter(input, state.default_query_limit)?;
            Ok(())
        }
        OP_LIST_RELAYS | OP_HEALTH => Ok(()),
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("unknown operation: {operation}"),
        }),
    }
}

fn granted_capabilities(requested: Vec<CapabilityId>) -> Vec<CapabilityGrant> {
    requested
        .into_iter()
        .filter(|capability| {
            matches!(
                capability.as_str(),
                CAP_NOTES_WRITE | CAP_EVENTS_READ | CAP_RELAYS_READ | CAP_HEALTH_READ
            )
        })
        .map(|capability| CapabilityGrant {
            capability,
            operation: None,
        })
        .collect()
}

fn nostr_auth_caps() -> AuthCaps {
    AuthCaps {
        methods: vec!["secp256k1_secret_key_hex".to_string()],
        oauth: None,
    }
}

fn note_kind(input: &Value) -> FcpResult<u64> {
    let kind = u64_field(input, "kind")?.unwrap_or(NOTE_KIND_TEXT);
    if kind != NOTE_KIND_TEXT {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "nostr.notes.publish only supports kind=1 public notes in this first slice"
                .into(),
        });
    }
    Ok(kind)
}

fn note_tags(input: &Value) -> FcpResult<Value> {
    let Some(tags) = input.get("tags") else {
        return Ok(Value::Array(Vec::new()));
    };
    let Value::Array(tag_rows) = tags else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "tags must be an array of string arrays".into(),
        });
    };
    for tag in tag_rows {
        let Value::Array(parts) = tag else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "each tag must be an array of strings".into(),
            });
        };
        if parts.iter().any(|part| !part.is_string()) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "each tag entry must be a string".into(),
            });
        }
    }
    Ok(Value::Array(tag_rows.clone()))
}

fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    let Some(raw) = value.get(field) else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        });
    };
    let Some(text) = raw.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-empty string"),
        });
    };
    if text.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-empty string"),
        });
    }
    Ok(text)
}

fn string_array_field(input: &Value, field: &str) -> FcpResult<Option<Vec<Value>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an array of strings"),
        });
    };
    if items.iter().any(|item| !item.is_string()) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must contain only strings"),
        });
    }
    Ok(Some(items.clone()))
}

fn u64_array_field(input: &Value, field: &str) -> FcpResult<Option<Vec<Value>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an array of integers"),
        });
    };
    if items.iter().any(|item| item.as_u64().is_none()) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must contain only integers"),
        });
    }
    Ok(Some(items.clone()))
}

fn i64_field(input: &Value, field: &str) -> FcpResult<Option<i64>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an integer"),
        })
}

fn u64_field(input: &Value, field: &str) -> FcpResult<Option<u64>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an unsigned integer"),
        })
}

#[allow(clippy::too_many_arguments)]
fn operation(
    id: &'static str,
    summary: &str,
    description: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
    common_mistakes: &[&str],
    related: &[&'static str],
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: Some(description.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: common_mistakes
                .iter()
                .map(|item| (*item).to_string())
                .collect(),
            examples: Vec::new(),
            related: related
                .iter()
                .map(|capability| CapabilityId::from_static(capability))
                .collect(),
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{CapabilityToken, ConnectorId, ZoneId};

    #[test]
    fn config_requires_at_least_one_relay() {
        let error = serde_json::from_value::<NostrConfig>(json!({
            "relay_urls": [],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
        }))
        .expect("config should deserialize")
        .validate()
        .expect_err("relay_urls must be required");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn build_signed_event_produces_hex_id_and_signature() {
        let secret_key =
            parse_secret_key("1111111111111111111111111111111111111111111111111111111111111111")
                .expect("secret key should parse");
        let public_key = derive_public_key_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("public key should derive");
        let event = build_signed_event(&secret_key, &public_key, 1, &json!([]), "hello nostr")
            .expect("event should build");
        assert_eq!(event["id"].as_str().unwrap().len(), 64);
        assert_eq!(event["sig"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn filter_uses_default_limit() {
        let filter = build_filter(&json!({ "kinds": [1] }), 25).expect("filter should build");
        assert_eq!(filter["limit"], 25);
        assert_eq!(filter["kinds"], json!([1]));
    }

    #[test]
    fn note_kind_rejects_non_note_kinds() {
        let error = note_kind(&json!({ "kind": 4 })).expect_err("kind 4 must be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn note_kind_rejects_non_integer_values() {
        let error =
            note_kind(&json!({ "kind": "1" })).expect_err("string kind values must be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn note_tags_require_string_arrays() {
        let error = note_tags(&json!({ "tags": [["p", 3]] }))
            .expect_err("non-string tag entries must be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn required_string_rejects_non_string_values() {
        let error = required_string(&json!({ "content": 7 }), "content")
            .expect_err("numeric content must be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
        assert_eq!(
            error.to_string(),
            "Invalid request: content must be a non-empty string"
        );
    }

    #[test]
    fn filter_rejects_invalid_limit_type() {
        let error = build_filter(&json!({ "limit": "10" }), 25)
            .expect_err("string limit values must be rejected");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn filter_rejects_non_string_authors() {
        let error = build_filter(&json!({ "authors": ["ok", 3] }), 25)
            .expect_err("authors must contain only strings");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn introspection_reports_raw_key_auth_boundary() {
        let intro = NostrConnector::new().introspect();
        let auth = intro.auth_caps.expect("auth caps should be present");
        assert_eq!(auth.methods, vec!["secp256k1_secret_key_hex"]);
        let publish = intro
            .operations
            .iter()
            .find(|op| op.id.as_str() == OP_PUBLISH_NOTE)
            .expect("publish operation should exist");
        assert!(
            publish
                .description
                .as_deref()
                .unwrap_or_default()
                .contains("does not construct encrypted DMs")
        );
        let related: Vec<_> = publish
            .ai_hints
            .related
            .iter()
            .map(CapabilityId::as_str)
            .collect();
        assert_eq!(
            related,
            vec![CAP_HEALTH_READ, CAP_RELAYS_READ, CAP_EVENTS_READ]
        );
    }

    #[test]
    fn simulate_denies_when_not_configured() {
        let connector = NostrConnector::new();
        let response = fcp_async_core::runtime::block_on_sync(async {
            connector
                .simulate(SimulateRequest::new(
                    ConnectorId::from_static("fcp.nostr"),
                    OperationId::from_static(OP_PUBLISH_NOTE),
                    ZoneId::community(),
                    json!({ "content": "hello" }),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .expect("runtime should complete");
        let response = response.expect("simulate should succeed");
        assert!(!response.would_succeed);
        assert_eq!(response.denial_code.as_deref(), Some("FCP-5002"));
        assert_eq!(
            response.failure_reason.as_deref(),
            Some("Connector is not configured")
        );
    }
}
