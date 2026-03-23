//! Nostr relay connector.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fcp_core::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, HealthState, IdempotencyClass, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier, SelfCheckReport,
    SessionId, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest,
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

const OP_PUBLISH_NOTE: &str = "nostr.notes.publish";
const OP_QUERY_EVENTS: &str = "nostr.events.query";
const OP_LIST_RELAYS: &str = "nostr.relays.list";
const OP_HEALTH: &str = "nostr.health";

const CAP_NOTES_WRITE: &str = "nostr.notes.write";
const CAP_EVENTS_READ: &str = "nostr.events.read";
const CAP_RELAYS_READ: &str = "nostr.relays.read";
const CAP_HEALTH_READ: &str = "nostr.health.read";

#[derive(Debug, Clone, Deserialize)]
struct NostrConfig {
    relay_urls: Vec<String>,
    secret_key_hex: String,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default = "default_query_limit")]
    default_query_limit: u64,
}

#[derive(Debug)]
struct NostrState {
    relay_urls: Vec<String>,
    secret_key_hex: String,
    request_timeout: Duration,
    default_query_limit: u64,
    public_key_hex: String,
}

#[derive(Debug)]
pub struct NostrConnector {
    base: BaseConnector,
    state: Option<NostrState>,
    verifier: Option<CapabilityVerifier>,
    started_at: Instant,
}

fn default_timeout_ms() -> u64 {
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

    fn operations() -> Vec<OperationInfo> {
        vec![
            operation(
                OP_PUBLISH_NOTE,
                "Publish a signed Nostr note",
                CAP_NOTES_WRITE,
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                json!({
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": { "type": "string" },
                        "kind": { "type": "integer" },
                        "tags": { "type": "array", "items": { "type": "array", "items": { "type": "string" } } }
                    }
                }),
                "Use to publish a signed public note to all configured relays.",
            ),
            operation(
                OP_QUERY_EVENTS,
                "Query Nostr events from configured relays",
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
                "Use for bounded public-event queries; this connector does not maintain a long-lived subscription.",
            ),
            operation(
                OP_LIST_RELAYS,
                "List configured relays",
                CAP_RELAYS_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use to inspect which relays this connector instance targets.",
            ),
            operation(
                OP_HEALTH,
                "Verify relay connectivity and signing identity",
                CAP_HEALTH_READ,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                json!({ "type": "object" }),
                "Use before publishing to make sure configured relays are reachable.",
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
            capabilities_granted: req
                .capabilities_requested
                .into_iter()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
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
            auth_caps: None,
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
    let kind = input.get("kind").and_then(Value::as_u64).unwrap_or(1);
    let tags = input
        .get("tags")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
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
        .map_err(|_| FcpError::Timeout { operation: "nostr publish wait".into(), timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX) })?
        .map_err(map_stream_error("nostr publish recv"))?;
    let _ = ws.close().await;
    let response = response.ok_or(FcpError::Upstream {
        service: "nostr".into(),
        message: format!("relay `{relay}` closed before acknowledging event"),
        retryable: true,
    })?;
    let parsed = parse_ws_message(&response)?;
    Ok(json!({
        "relay": relay,
        "response": parsed,
    }))
}

async fn query_relay(relay: &str, timeout: Duration, sub_id: &str, filter: &Value) -> FcpResult<Vec<Value>> {
    let mut ws = connect_relay(relay).await?;
    ws.send_json(&json!(["REQ", sub_id, filter]))
        .await
        .map_err(map_stream_error("nostr query send"))?;

    let mut events = Vec::new();
    loop {
        let message = fcp_async_core::time::timeout(timeout, ws.recv())
            .await
            .map_err(|_| FcpError::Timeout { operation: "nostr query wait".into(), timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX) })?
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
    move |error| FcpError::Upstream {
        service: "nostr".into(),
        message: format!("{context} failed: {error}"),
        retryable: true,
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
    let msg = Message::from_digest_slice(&hex::decode(&id).map_err(|error| FcpError::Internal {
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
    if let Some(authors) = input.get("authors") {
        filter.insert("authors".into(), authors.clone());
    }
    if let Some(ids) = input.get("ids") {
        filter.insert("ids".into(), ids.clone());
    }
    if let Some(kinds) = input.get("kinds") {
        filter.insert("kinds".into(), kinds.clone());
    }
    if let Some(since) = input.get("since").and_then(Value::as_i64) {
        filter.insert("since".into(), json!(since));
    }
    if let Some(until) = input.get("until").and_then(Value::as_i64) {
        filter.insert("until".into(), json!(until));
    }
    let limit = input
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(default_limit);
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
        WsMessage::Text(text) => serde_json::from_str::<Value>(text).map_err(|error| FcpError::Upstream {
            service: "nostr".into(),
            message: format!("failed to parse relay frame: {error}"),
            retryable: false,
        }),
        other => Err(FcpError::Upstream {
            service: "nostr".into(),
            message: format!("unexpected relay frame type: {other:?}"),
            retryable: false,
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
    Ok(CapabilityId::from(capability.to_string()))
}

fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        })
}

fn operation(
    id: &str,
    summary: &str,
    capability: &str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    input_schema: Value,
    when_to_use: &str,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from(id.to_string()),
        summary: summary.into(),
        description: Some(summary.into()),
        input_schema,
        output_schema: json!({ "type": "object" }),
        capability: CapabilityId::from(capability.to_string()),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: when_to_use.into(),
            common_mistakes: vec![
                "This first slice signs only hex-encoded secret keys and does not implement encrypted DMs."
                    .into(),
            ],
            examples: Vec::new(),
            related: vec![CapabilityId::from(OP_HEALTH.to_string())],
        },
        rate_limit: None,
        requires_approval: Some(ApprovalMode::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let secret_key = parse_secret_key(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("secret key should parse");
        let public_key =
            derive_public_key_hex("1111111111111111111111111111111111111111111111111111111111111111")
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
}
