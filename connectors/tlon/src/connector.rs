use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use fcp_prelude::{
    BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse, OperationId,
    SessionId,
};
use reqwest::{Client, Response, StatusCode, header};
use serde_json::{Value, json};
use tracing::{debug, info};
use url::Url;

use crate::{TlonError, TlonResult};

const CONNECTOR_ID: &str = "fcp.tlon";
const CONNECTOR_VERSION: &str = "0.1.0";
const BOUNDARY: &str = "Authenticated Urbit Eyre channel runtime for DM send, channel send, and local target resolution with SSRF-safe base URL validation.";
const NOT_HANDSHAKEN_REASON_CODE: &str = "not_handshaken";
const NOT_HANDSHAKEN_MESSAGE: &str = "Connector configured, but handshake has not completed yet.";
const NOT_CONFIGURED_REASON_CODE: &str = "not_configured";
const READY_REASON_CODE: &str = "ready";
const DM_SEND_OPERATION: &str = "tlon.dm.send";
const CHANNEL_SEND_OPERATION: &str = "tlon.channel.send";
const TARGET_RESOLVE_OPERATION: &str = "tlon.target.resolve";
const DM_CAPABILITY: &str = "tlon.dm";
const CHANNEL_CAPABILITY: &str = "tlon.channel";
const DEFAULT_CHANNEL_ID: &str = "fcp-tlon";
const DEFAULT_DM_APP: &str = "tlon";
const DEFAULT_DM_MARK: &str = "tlon-dm-action";
const DEFAULT_CHANNEL_APP: &str = "tlon";
const DEFAULT_CHANNEL_MARK: &str = "tlon-channel-action";
const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_TARGET_BYTES: usize = 512;

fn dm_send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["ship", "message"],
        "additionalProperties": false,
        "properties": {
            "ship": {
                "type": "string",
                "description": "Target ship name (e.g. ~zod)"
            },
            "message": {
                "type": "string",
                "description": "Message text to send"
            }
        }
    })
}

fn channel_send_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["channel", "message"],
        "additionalProperties": false,
        "properties": {
            "channel": {
                "type": "string",
                "description": "Target channel path or identifier"
            },
            "message": {
                "type": "string",
                "description": "Message text to send"
            }
        }
    })
}

fn target_resolve_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["target"],
        "additionalProperties": false,
        "properties": {
            "target": {
                "type": "string",
                "description": "Human-friendly DM or channel target to resolve"
            }
        }
    })
}

fn ok_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["ok"],
        "additionalProperties": false,
        "properties": {
            "ok": {
                "type": "boolean"
            }
        }
    })
}

fn target_resolve_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["resolved"],
        "additionalProperties": false,
        "properties": {
            "resolved": {
                "type": "boolean"
            }
        }
    })
}

#[derive(Clone)]
enum TlonAuth {
    SessionCookie(String),
    CredentialId(String),
}

impl TlonAuth {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let session_cookie = params
            .get("session_cookie")
            .or_else(|| params.get("cookie"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let credential_id = params
            .get("credential_id")
            .or_else(|| params.get("auth_ref"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        match (session_cookie, credential_id) {
            (Some(cookie), None) => Ok(Self::SessionCookie(cookie)),
            (None, Some(id)) => Ok(Self::CredentialId(id)),
            (Some(_), Some(_)) => Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide exactly one of session_cookie/cookie or credential_id/auth_ref"
                    .into(),
            }),
            (None, None) => Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing session_cookie/cookie or credential_id/auth_ref".into(),
            }),
        }
    }

    fn auth_mode(&self) -> &'static str {
        match self {
            Self::SessionCookie(_) => "session_cookie",
            Self::CredentialId(_) => "credential_id",
        }
    }

    fn requires_credential_injection(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for TlonAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionCookie(_) => formatter
                .debug_tuple("SessionCookie")
                .field(&"<redacted>")
                .finish(),
            Self::CredentialId(id) => formatter.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

#[derive(Debug, Clone)]
struct NormalizedShip {
    display: String,
    eyre: String,
}

#[derive(Debug, Clone)]
struct NormalizedChannel {
    display: String,
    target_ship: Option<NormalizedShip>,
}

#[derive(Debug, Clone)]
struct TlonConfig {
    base_url: String,
    auth: TlonAuth,
    own_ship: NormalizedShip,
    channel_id: String,
    dm_app: String,
    dm_mark: String,
    channel_app: String,
    channel_mark: String,
    timeout_ms: u64,
}

impl TlonConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let allow_private_network = params
            .get("allow_private_network")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let base_url = params
            .get("base_url")
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing base_url".into(),
            })
            .and_then(|url| validate_base_url(url, allow_private_network))?;
        let auth = TlonAuth::from_params(params)?;
        let own_ship = params
            .get("ship")
            .and_then(Value::as_str)
            .map_or_else(|| normalize_ship("~zod"), normalize_ship)?;
        let channel_id = optional_trimmed(params, "channel_id")
            .map_or_else(|| Ok(DEFAULT_CHANNEL_ID.to_owned()), validate_channel_id)?;
        let dm_app =
            optional_trimmed(params, "dm_app").map_or_else(|| Ok(DEFAULT_DM_APP.to_owned()), validate_term)?;
        let dm_mark = optional_trimmed(params, "dm_mark")
            .map_or_else(|| Ok(DEFAULT_DM_MARK.to_owned()), validate_term)?;
        let channel_app = optional_trimmed(params, "channel_app")
            .map_or_else(|| Ok(DEFAULT_CHANNEL_APP.to_owned()), validate_term)?;
        let channel_mark = optional_trimmed(params, "channel_mark")
            .map_or_else(|| Ok(DEFAULT_CHANNEL_MARK.to_owned()), validate_term)?;
        let timeout_ms = params
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .clamp(1_000, 60_000);

        Ok(Self {
            base_url,
            auth,
            own_ship,
            channel_id,
            dm_app,
            dm_mark,
            channel_app,
            channel_mark,
            timeout_ms,
        })
    }
}

#[derive(Debug)]
struct TlonClient {
    client: Client,
    base_url: String,
    auth: TlonAuth,
    channel_id: String,
}

impl TlonClient {
    fn new(config: &TlonConfig) -> TlonResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .user_agent("fcp-tlon/0.1.0 (FCP connector)")
            .build()?;
        Ok(Self {
            client,
            base_url: config.base_url.clone(),
            auth: config.auth.clone(),
            channel_id: config.channel_id.clone(),
        })
    }

    async fn send_action(&self, action: Value) -> TlonResult<Value> {
        let url = format!("{}/~/channel/{}", self.base_url, self.channel_id);
        debug!(
            endpoint_kind = "urbit_eyre_channel",
            action_kind = action.get("action").and_then(Value::as_str).unwrap_or("unknown"),
            "sending Tlon Eyre action"
        );
        let request = match &self.auth {
            TlonAuth::SessionCookie(cookie) => self
                .client
                .put(&url)
                .header(header::COOKIE, cookie.as_str()),
            TlonAuth::CredentialId(credential_id) => self
                .client
                .put(&url)
                .header("X-FCP-Credential-Id", credential_id.as_str()),
        }
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!([action]));

        let response = request.send().await?;
        Self::handle_response(response).await
    }

    async fn handle_response(response: Response) -> TlonResult<Value> {
        let status = response.status();
        if status == StatusCode::NO_CONTENT || status.is_success() {
            return Ok(json!({
                "ok": true,
                "provider_status": "accepted",
                "provider_status_class": "eyre_channel_accepted"
            }));
        }

        let retry_after_ms = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| seconds.saturating_mul(1000));
        let body = response.text().await.unwrap_or_default();
        let message = redact_provider_message(&body);

        match status.as_u16() {
            401 | 403 => Err(TlonError::Api {
                status_code: status.as_u16(),
                message: "provider authorization failed".into(),
            }),
            404 => Err(TlonError::ShipNotFound("provider endpoint".into())),
            429 => Err(TlonError::RateLimited {
                retry_after_ms: retry_after_ms.unwrap_or(60_000),
            }),
            code => Err(TlonError::Api {
                status_code: code,
                message,
            }),
        }
    }
}

pub struct TlonConnector {
    base: Arc<BaseConnector>,
    config: Option<TlonConfig>,
    client: Option<Arc<TlonClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

#[allow(clippy::missing_errors_doc, clippy::unused_async)]
impl TlonConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = TlonConfig::from_params(&params)?;
        let client = Arc::new(TlonClient::new(&config).map_err(|error| error.to_fcp_error())?);
        info!(
            auth_mode = config.auth.auth_mode(),
            endpoint_kind = "urbit_eyre",
            "configured Tlon connector"
        );
        self.client = Some(client);
        self.config = Some(config);
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "configured": true,
            "auth_mode": self.config.as_ref().map(|config| config.auth.auth_mode()),
            "endpoint_kind": "urbit_eyre"
        }))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        if self.config.is_none() {
            return Err(FcpError::NotConfigured);
        }

        if params.get("host_public_key").is_some() {
            return self.handle_bound_handshake(params);
        }

        self.verifier = None;
        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "connector_version": CONNECTOR_VERSION,
            "protocol_version": "2.0",
            "capabilities": [DM_CAPABILITY, CHANNEL_CAPABILITY],
            "capability_enforcement": "host_boundary_or_full_handshake",
            "session_id": session_id,
            "surface_status": "implemented",
            "surface_status_rationale": BOUNDARY
        }))
    }

    fn handle_bound_handshake(&mut self, params: Value) -> FcpResult<Value> {
        let request: HandshakeRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {error}"),
            })?;
        self.verifier = Some(CapabilityVerifier::new(
            request.host_public_key,
            request.zone,
            self.base.instance_id.clone(),
        ));
        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted = request
            .capabilities_requested
            .into_iter()
            .filter(|capability| is_supported_capability(capability.as_str()))
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        serde_json::to_value(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "blake3-256:fcp.tlon.manifest.v1".into(),
            nonce: request.nonce,
            event_caps: Some(EventCaps::default()),
            auth_caps: None,
            op_catalog_hash: Some("blake3-256:fcp.tlon.ops.v1".into()),
        })
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize handshake response: {error}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        Ok(json!({
            "status": if configured && handshaken { "healthy" } else if configured { "degraded" } else { "unconfigured" },
            "configured": configured,
            "handshaken": handshaken,
            "live_requests_supported": configured && handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();
        let client_ready = self.client.is_some();
        let credential_injection_required = self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.requires_credential_injection());
        Ok(json!({
            "status": if configured && handshaken && client_ready { "healthy" } else if configured { "degraded" } else { "unhealthy" },
            "checks": [
                { "name": "configuration", "passed": configured, "critical": true },
                { "name": "handshake", "passed": handshaken, "critical": false },
                { "name": "client", "passed": client_ready, "critical": true },
                { "name": "credential_injection", "passed": !credential_injection_required, "critical": false, "message": if credential_injection_required { "credential_id mode requires host egress credential injection" } else { "session cookie auth configured" } },
                { "name": "invoke_surface", "passed": configured && handshaken && client_ready, "critical": false, "message": BOUNDARY }
            ]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        let (status, reason_code, message) = if self.config.is_none() {
            ("degraded", json!(NOT_CONFIGURED_REASON_CODE), json!(BOUNDARY))
        } else if self.session_id.is_none() {
            (
                "degraded",
                json!(NOT_HANDSHAKEN_REASON_CODE),
                json!(NOT_HANDSHAKEN_MESSAGE),
            )
        } else if self
            .config
            .as_ref()
            .is_some_and(|config| config.auth.requires_credential_injection())
        {
            (
                "degraded",
                json!("credential_injection_required"),
                json!("credential_id mode requires host egress credential injection"),
            )
        } else {
            ("ok", json!(READY_REASON_CODE), json!(BOUNDARY))
        };
        Ok(json!({
            "status": status,
            "reason_code": reason_code,
            "message": message
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        Ok(json!({
            "connector_id": CONNECTOR_ID,
            "version": CONNECTOR_VERSION,
            "operations": [
                {
                    "id": DM_SEND_OPERATION,
                    "summary": "Send a Tlon DM",
                    "capability": DM_CAPABILITY,
                    "risk_level": "medium",
                    "safety_tier": "safe",
                    "idempotency": "best_effort",
                    "implemented": true,
                    "input_schema": dm_send_input_schema(),
                    "output_schema": ok_output_schema(),
                    "ai_hints": {
                        "when_to_use": "When you need to send a direct message to a ship on the Tlon/Urbit network.",
                        "common_mistakes": ["Omitting the ~ prefix on ship names."],
                        "examples": [],
                        "related": []
                    }
                },
                {
                    "id": CHANNEL_SEND_OPERATION,
                    "summary": "Send a Tlon channel message",
                    "capability": CHANNEL_CAPABILITY,
                    "risk_level": "medium",
                    "safety_tier": "safe",
                    "idempotency": "best_effort",
                    "implemented": true,
                    "input_schema": channel_send_input_schema(),
                    "output_schema": ok_output_schema(),
                    "ai_hints": {
                        "when_to_use": "When you need to send a message into a Tlon/Urbit channel.",
                        "common_mistakes": ["Using a DM target where a channel path is required."],
                        "examples": [],
                        "related": []
                    }
                },
                {
                    "id": TARGET_RESOLVE_OPERATION,
                    "summary": "Resolve a Tlon DM or channel target",
                    "capability": CHANNEL_CAPABILITY,
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "implemented": true,
                    "input_schema": target_resolve_input_schema(),
                    "output_schema": target_resolve_output_schema(),
                    "ai_hints": {
                        "when_to_use": "When you need to normalize or validate a Tlon target before sending.",
                        "common_mistakes": [],
                        "examples": [],
                        "related": []
                    }
                }
            ],
            "surface_status": "implemented",
            "surface_status_rationale": BOUNDARY,
            "events": [],
            "resource_types": []
        }))
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        self.base.check_ready()?;
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let capability = required_capability(operation)?;
        self.verify_capability(&params, operation, capability)?;

        self.request_count.fetch_add(1, Ordering::Relaxed);
        let result = match operation {
            DM_SEND_OPERATION => self.invoke_dm_send(&input).await,
            CHANNEL_SEND_OPERATION => self.invoke_channel_send(&input).await,
            TARGET_RESOLVE_OPERATION => self.invoke_target_resolve(&input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        };

        if result.is_err() {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let operation = params
            .get("operation_id")
            .or_else(|| params.get("operation"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let known = matches!(
            operation,
            DM_SEND_OPERATION | CHANNEL_SEND_OPERATION | TARGET_RESOLVE_OPERATION
        );
        let ready = self.config.is_some() && self.session_id.is_some();

        Ok(json!({
            "allowed": known && ready,
            "simulate_capability": if known { required_capability(operation).unwrap_or("unknown") } else { "unsupported" },
            "reason": if !known { "Unknown operation." } else if ready { "Operation supported" } else { "Connector must be configured and handshaken first" }
        }))
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.config = None;
        self.client = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    fn client(&self) -> FcpResult<&TlonClient> {
        self.client
            .as_deref()
            .ok_or_else(|| FcpError::Internal {
                message: "Tlon client not initialized".into(),
            })
    }

    fn config(&self) -> FcpResult<&TlonConfig> {
        self.config
            .as_ref()
            .ok_or_else(|| FcpError::NotConfigured)
    }

    fn verify_capability(
        &self,
        params: &Value,
        operation: &str,
        capability: &str,
    ) -> FcpResult<()> {
        let Some(verifier) = &self.verifier else {
            return Ok(());
        };
        let token_value = params
            .get("capability_token")
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;
        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid capability_token format: {error}"),
                }
            })?;
        let operation_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let capability_id: CapabilityId =
            capability.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid capability ID format".into(),
            })?;
        verifier.verify_bound(token, &capability_id, &operation_id, &[])?;
        Ok(())
    }

    async fn invoke_dm_send(&self, input: &Value) -> FcpResult<Value> {
        let config = self.config()?;
        let ship = require_ship(input, "ship")?;
        let message = require_message(input)?;
        let action = build_poke_action(
            self.next_action_id(),
            &ship.eyre,
            &config.dm_app,
            &config.dm_mark,
            json!({
                "kind": "dm.send",
                "ship": ship.display,
                "message": message
            }),
        );
        self.client()
            .and_then(|client| futures_result(client.send_action(action)))
            .await
    }

    async fn invoke_channel_send(&self, input: &Value) -> FcpResult<Value> {
        let config = self.config()?;
        let channel = require_channel(input, "channel")?;
        let message = require_message(input)?;
        let ship = channel
            .target_ship
            .as_ref()
            .unwrap_or(&config.own_ship)
            .eyre
            .clone();
        let action = build_poke_action(
            self.next_action_id(),
            &ship,
            &config.channel_app,
            &config.channel_mark,
            json!({
                "kind": "channel.send",
                "channel": channel.display,
                "message": message
            }),
        );
        self.client()
            .and_then(|client| futures_result(client.send_action(action)))
            .await
    }

    fn invoke_target_resolve(&self, input: &Value) -> FcpResult<Value> {
        let target = require_str(input, "target")?;
        if target.starts_with('~') {
            let _ = normalize_ship(target)?;
        } else {
            let _ = normalize_channel(target)?;
        }
        Ok(json!({ "resolved": true }))
    }

    fn next_action_id(&self) -> u64 {
        self.request_count
            .load(Ordering::Relaxed)
            .saturating_add(1)
    }
}

async fn futures_result(future: impl std::future::Future<Output = TlonResult<Value>>) -> FcpResult<Value> {
    future.await.map_err(|error| error.to_fcp_error())
}

fn supported_capabilities() -> [&'static str; 2] {
    [DM_CAPABILITY, CHANNEL_CAPABILITY]
}

fn is_supported_capability(capability: &str) -> bool {
    supported_capabilities().contains(&capability)
}

fn required_capability(operation: &str) -> FcpResult<&'static str> {
    match operation {
        DM_SEND_OPERATION => Ok(DM_CAPABILITY),
        CHANNEL_SEND_OPERATION | TARGET_RESOLVE_OPERATION => Ok(CHANNEL_CAPABILITY),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn build_poke_action(id: u64, ship: &str, app: &str, mark: &str, payload: Value) -> Value {
    json!({
        "id": id,
        "action": "poke",
        "ship": ship,
        "app": app,
        "mark": mark,
        "json": payload
    })
}

fn optional_trimmed<'a>(params: &'a Value, field: &str) -> Option<&'a str> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn require_str<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn require_ship(input: &Value, field: &str) -> FcpResult<NormalizedShip> {
    normalize_ship(require_str(input, field)?)
}

fn require_channel(input: &Value, field: &str) -> FcpResult<NormalizedChannel> {
    normalize_channel(require_str(input, field)?)
}

fn require_message(input: &Value) -> FcpResult<&str> {
    let message = require_str(input, "message")?;
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("message exceeds {MAX_MESSAGE_BYTES} bytes"),
        });
    }
    if message.chars().any(|ch| ch == '\0') {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "message must not contain NUL bytes".into(),
        });
    }
    Ok(message)
}

fn normalize_ship(raw: &str) -> FcpResult<NormalizedShip> {
    let trimmed = raw.trim();
    let without_prefix = trimmed.strip_prefix('~').unwrap_or(trimmed);
    if without_prefix.is_empty()
        || without_prefix.len() > 128
        || !without_prefix
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        || without_prefix.starts_with('-')
        || without_prefix.ends_with('-')
        || without_prefix.contains("--")
    {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "ship must be an Urbit @p-style name such as ~zod or ~sampel-palnet".into(),
        });
    }
    Ok(NormalizedShip {
        display: format!("~{without_prefix}"),
        eyre: without_prefix.to_owned(),
    })
}

fn normalize_channel(raw: &str) -> FcpResult<NormalizedChannel> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('/')
        || trimmed.len() > MAX_TARGET_BYTES
        || trimmed.contains('\0')
        || trimmed.contains("..")
        || trimmed.contains("//")
    {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "channel must be an absolute Urbit/Tlon channel path without traversal"
                .into(),
        });
    }
    let target_ship = extract_ship_from_channel(trimmed)?;
    Ok(NormalizedChannel {
        display: trimmed.to_owned(),
        target_ship,
    })
}

fn extract_ship_from_channel(channel: &str) -> FcpResult<Option<NormalizedShip>> {
    let mut parts = channel.split('/').filter(|part| !part.is_empty());
    match (parts.next(), parts.next()) {
        (Some("ship"), Some(ship)) => normalize_ship(ship).map(Some),
        _ => Ok(None),
    }
}

fn validate_term(raw: &str) -> FcpResult<String> {
    let term = raw.trim();
    if term.is_empty()
        || term.len() > 64
        || !term
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        || term.starts_with('-')
        || term.ends_with('-')
    {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "Urbit app/mark terms must be lowercase ASCII term strings".into(),
        });
    }
    Ok(term.to_owned())
}

fn validate_channel_id(raw: &str) -> FcpResult<String> {
    let channel_id = raw.trim();
    if channel_id.is_empty()
        || channel_id.len() > 96
        || !channel_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "channel_id must be a bounded ASCII identifier".into(),
        });
    }
    Ok(channel_id.to_owned())
}

fn validate_base_url(raw: &str, allow_private_network: bool) -> FcpResult<String> {
    let parsed = Url::parse(raw).map_err(|error| FcpError::InvalidRequest {
        code: 1005,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "base_url scheme must be http or https".into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "base_url must not contain userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "base_url must not contain query or fragment components".into(),
        });
    }
    let host = parsed.host_str().ok_or_else(|| FcpError::InvalidRequest {
        code: 1005,
        message: "base_url must include a host".into(),
    })?;
    let private = is_private_or_loopback_host(host);
    if private && !allow_private_network {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "base_url targets a private or loopback host; set allow_private_network=true for a dedicated test ship or approved LAN endpoint".into(),
        });
    }
    if parsed.scheme() == "http" && !private {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "base_url must use https unless it targets an explicitly allowed private or loopback host".into(),
        });
    }
    let mut sanitized = parsed;
    sanitized.set_path(sanitized.path().trim_end_matches('/'));
    Ok(sanitized.as_str().trim_end_matches('/').to_owned())
}

fn is_private_or_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip == Ipv6Addr::UNSPECIFIED
        }
    })
}

fn redact_provider_message(raw: &str) -> String {
    let compact = raw
        .chars()
        .map(|ch| if ch.is_control() && !ch.is_whitespace() { ' ' } else { ch })
        .collect::<String>();
    let lower = compact.to_ascii_lowercase();
    if ["cookie", "session", "token", "secret", "password", "message", "body"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return "<redacted provider error>".into();
    }
    let mut redacted = compact.trim().to_owned();
    redacted.truncate(512);
    if redacted.is_empty() {
        "provider returned an error without a body".into()
    } else {
        redacted
    }
}

impl Default for TlonConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn planned_only_connector_reports_degraded_readiness() {
        let mut connector = TlonConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");

        let pre_handshake = connector
            .handle_self_check()
            .await
            .expect("self_check before handshake should succeed");
        assert_eq!(pre_handshake["status"], "degraded");
        assert_eq!(pre_handshake["reason_code"], NOT_HANDSHAKEN_REASON_CODE);

        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let health = connector
            .handle_health()
            .await
            .expect("health should succeed");
        assert_eq!(health["status"], "degraded");
        assert_eq!(health["live_requests_supported"], false);

        let doctor = connector
            .handle_doctor()
            .await
            .expect("doctor should succeed");
        assert_eq!(doctor["status"], "degraded");
        assert_eq!(doctor["checks"][2]["passed"], false);

        let introspect = connector
            .handle_introspect()
            .await
            .expect("introspect should succeed");
        assert_eq!(introspect["surface_status"], "incubating");
        assert!(
            introspect["operations"]
                .as_array()
                .expect("operations should be an array")
                .iter()
                .all(|operation| {
                    operation.get("implemented").and_then(Value::as_bool) == Some(false)
                })
        );

        let self_check = connector
            .handle_self_check()
            .await
            .expect("self_check should succeed");
        assert_eq!(self_check["status"], "unsupported");
        assert_eq!(self_check["reason_code"], UNIMPLEMENTED_REASON_CODE);
    }

    #[fcp_async_core::runtime::test]
    async fn planned_operation_invoke_and_simulate_refuse_execution() {
        let mut connector = TlonConnector::new();
        connector
            .handle_configure(json!({}))
            .await
            .expect("configure should succeed");
        connector
            .handle_handshake(json!({}))
            .await
            .expect("handshake should succeed");

        let error = connector
            .handle_invoke(json!({"operation_id": "tlon.dm.send"}))
            .await
            .expect_err("invoke should refuse planned operation");
        assert!(error.to_string().contains("not implemented"));

        let simulate = connector
            .handle_simulate(json!({"operation_id": "tlon.dm.send"}))
            .await
            .expect("simulate should succeed");
        assert_eq!(simulate["allowed"], false);
        assert_eq!(simulate["simulate_capability"], "unsupported");
    }
}
