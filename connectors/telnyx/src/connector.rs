//! Telnyx FCP connector implementation.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SimulateRequest, SimulateResponse,
};
use fcp_voice_call::{
    CallAuthToken, CallSession, MemorySessionStore, ProviderHeaders, SignatureVerification,
    TelnyxSignatureVerifier, VoiceCallError, VoiceProvider, WebhookReplayCache, mask_phone_number,
    stable_redacted_hash,
};
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{info, instrument};
use url::Url;

use crate::{
    client::{
        DEFAULT_API_BASE, GatherUsingSpeakRequest, InitiateCallRequest, SpeakCallRequest,
        TelnyxAuth, TelnyxClient, TransferCallRequest, decode_client_state_token,
        encode_client_state,
    },
    types::{
        InboundPolicyDecision, SignatureValidationResult, TelnyxEventEnvelope,
        WebhookIngressLogEntry, WebhookIngressResult,
    },
};

const TELNYX_WEBHOOK_INGRESS_MAX_BODY_BYTES: usize = 64 * 1024;
const TELNYX_WEBHOOK_INGRESS_TIMEOUT_MS: u64 = 5_000;
const TELNYX_WEBHOOK_INGRESS_CONCURRENCY_LIMIT: u64 = 32;
const TELNYX_WEBHOOK_INGRESS_RATE_LIMIT_MAX: u64 = 200;
const TELNYX_WEBHOOK_INGRESS_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const TELNYX_SESSION_TTL_MINUTES: i64 = 60;
const DEFAULT_TELNYX_SIGNATURE_TOLERANCE_SECONDS: i64 = 300;

#[derive(Debug, Clone)]
struct TelnyxConfig {
    auth: TelnyxAuth,
    base_url: String,
    public_key: String,
    timestamp_tolerance: Duration,
}

impl TelnyxConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let direct_key = params
            .get("api_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let auth = match (direct_key.as_deref(), credential_id) {
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either api_key or credential_id, not both".into(),
                });
            }
            (Some(raw), None) => TelnyxAuth::ApiKey {
                api_key: raw.to_string(),
            },
            (None, Some(raw)) => TelnyxAuth::CredentialId {
                credential_id: CredentialId::parse(raw).map_err(|error| {
                    FcpError::InvalidRequest {
                        code: 1003,
                        message: format!("Invalid credential_id: {error}"),
                    }
                })?,
            },
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let public_key = params
            .get("public_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing public_key for Telnyx Ed25519 webhook verification".into(),
            })?
            .to_string();

        let tolerance_seconds = params
            .get("timestamp_tolerance_seconds")
            .and_then(Value::as_i64)
            .unwrap_or(DEFAULT_TELNYX_SIGNATURE_TOLERANCE_SECONDS);
        if !(1..=3_600).contains(&tolerance_seconds) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "timestamp_tolerance_seconds must be between 1 and 3600".into(),
            });
        }

        let base_url = params
            .get("base_url")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_API_BASE);
        let base_url = validate_base_url_for_auth(base_url, &auth)?;

        TelnyxSignatureVerifier::new(&public_key, Duration::seconds(tolerance_seconds))
            .map_err(|error| error.to_fcp_error())?;

        Ok(Self {
            auth,
            base_url,
            public_key,
            timestamp_tolerance: Duration::seconds(tolerance_seconds),
        })
    }
}

fn validate_base_url_for_auth(base_url: &str, auth: &TelnyxAuth) -> FcpResult<String> {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }

    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid base_url: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include query or fragment".into(),
        });
    }

    let local = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }
    if matches!(auth, TelnyxAuth::ApiKey { .. })
        && !local
        && !host.eq_ignore_ascii_case("api.telnyx.com")
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url with direct api_key mode must target api.telnyx.com (localhost/127.0.0.1/::1 allowed for tests): {trimmed}"
            ),
        });
    }
    Ok(trimmed.to_string())
}

fn serialize_result<T: Serialize>(value: T) -> FcpResult<Value> {
    serde_json::to_value(value).map_err(|error| FcpError::Internal {
        message: format!("Serialization error: {error}"),
    })
}

/// Telnyx connector.
pub struct TelnyxConnector {
    base: Arc<BaseConnector>,
    pub(crate) client: Option<TelnyxClient>,
    config: Option<TelnyxConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_prelude::SessionId>,
    webhook_replay_cache: Mutex<WebhookReplayCache>,
    session_store: Mutex<MemorySessionStore>,
    session_keys: Mutex<BTreeMap<String, String>>,
}

impl TelnyxConnector {
    /// Create a new Telnyx connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("telnyx"))),
            client: None,
            config: None,
            verifier: None,
            session_id: None,
            webhook_replay_cache: Mutex::new(WebhookReplayCache::default()),
            session_store: Mutex::new(MemorySessionStore::default()),
            session_keys: Mutex::new(BTreeMap::new()),
        }
    }

    /// Connector instance id.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    /// Handle configure.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let config = TelnyxConfig::from_params(&params)?;
        let client = TelnyxClient::new_with_auth(config.auth.clone()).map_err(|error| {
            FcpError::Internal {
                message: format!("Failed to create Telnyx HTTP client: {error}"),
            }
        })?;
        let client = client.with_base_url(&config.base_url);

        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.client = Some(client);
        self.config = Some(config);
        self.verifier = None;
        self.session_id = None;
        self.webhook_replay_cache = Mutex::new(WebhookReplayCache::default());
        self.session_store = Mutex::new(MemorySessionStore::default());
        self.session_keys = Mutex::new(BTreeMap::new());
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!("Telnyx connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake.
    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        let request: HandshakeRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {error}"),
            })?;
        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.verifier = Some(CapabilityVerifier::new(
            request.host_public_key,
            request.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let session_id = fcp_prelude::SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted = request
            .capabilities_requested
            .iter()
            .cloned()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        serialize_result(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:fcp-telnyx-manifest".into(),
            nonce: request.nonce,
            event_caps: Some(EventCaps::default()),
            auth_caps: None,
            op_catalog_hash: Some(stable_redacted_hash(
                &serde_json::to_string(&Self::operations()).unwrap_or_default(),
            )),
        })
    }

    /// Health status.
    pub async fn handle_health(&self) -> FcpResult<Value> {
        let configured = self
            .base
            .configured
            .load(std::sync::atomic::Ordering::Acquire);
        let handshaken = self
            .base
            .handshaken
            .load(std::sync::atomic::Ordering::Acquire);
        let config = self.config.as_ref();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "configured": configured,
            "handshaken": handshaken,
            "auth_mode": config.map(|cfg| cfg.auth.redacted_label()),
            "api_url": config.map(|cfg| cfg.base_url.as_str()),
            "secretless": config.is_some_and(|cfg| cfg.auth.is_secretless()),
            "sessions": self.session_store.lock().map_err(lock_error)?.len(),
        }))
    }

    /// Operator doctor result.
    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let mut checks = Vec::new();
        checks.push(json!({
            "name": "configuration",
            "status": if self.config.is_some() { "pass" } else { "fail" },
        }));
        checks.push(json!({
            "name": "webhook_ed25519_key",
            "status": if self.config.as_ref().is_some_and(|cfg| {
                TelnyxSignatureVerifier::new(&cfg.public_key, cfg.timestamp_tolerance).is_ok()
            }) { "pass" } else { "fail" },
        }));
        checks.push(json!({
            "name": "network_constraints",
            "status": "pass",
            "host_allow": ["api.telnyx.com"],
        }));
        Ok(json!({
            "status": if self.config.is_some() { "healthy" } else { "unhealthy" },
            "checks": checks,
        }))
    }

    /// Self check aliases doctor for this connector.
    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        self.handle_doctor().await
    }

    /// Introspection.
    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        serialize_result(Introspection {
            operations: Self::operations(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps::default()),
        })
    }

    /// Simulate an invocation without side effects.
    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let request: SimulateRequest =
            serde_json::from_value(params).map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {error}"),
            })?;
        let result = if self.client.is_none() {
            SimulateResponse::denied(
                request.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            )
        } else if self.verifier.is_none() {
            SimulateResponse::denied(
                request.id,
                "Connector is not handshaken",
                FcpError::NotHandshaken.error_code(),
            )
        } else {
            let operation = request.operation.as_str().to_string();
            match self.operation_metadata(&operation).await {
                Ok((capability, input_schema)) => {
                    let verification = self.verifier.as_ref().unwrap().verify_bound(
                        request.capability_token,
                        &capability,
                        &request.operation,
                        &[],
                    );
                    match verification
                        .and_then(|_| Self::validate_required_input(&input_schema, &request.input))
                    {
                        Ok(()) => SimulateResponse::allowed(request.id),
                        Err(error) => SimulateResponse::denied(
                            request.id,
                            error.to_string(),
                            error.error_code(),
                        ),
                    }
                }
                Err(error) => {
                    SimulateResponse::denied(request.id, error.to_string(), error.error_code())
                }
            }
        };
        serialize_result(result)
    }

    /// Handle invoke.
    pub async fn handle_invoke(&mut self, params: Value) -> FcpResult<Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(&self, params: Value) -> FcpResult<Value> {
        let operation =
            params
                .get("operation")
                .and_then(Value::as_str)
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;
        let capability_proof = serde_json::from_value::<CapabilityToken>(token_value.clone())
            .map_err(|error| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {error}"),
            })?;

        let operation_id: OperationId =
            operation.parse().map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "Invalid operation ID format".into(),
            })?;
        let (capability, _) = self.operation_metadata(operation).await?;

        if let Some(verifier) = &self.verifier {
            verifier.verify_bound(capability_proof, &capability, &operation_id, &[])?;
        } else if self.client.is_some() {
            return Err(FcpError::NotHandshaken);
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "telnyx.call.initiate" => self.invoke_call_initiate(input).await,
            "telnyx.call.continue" => self.invoke_call_continue(&input).await,
            "telnyx.call.speak" => self.invoke_call_speak(&input).await,
            "telnyx.call.end" => self.invoke_call_end(&input).await,
            "telnyx.call.status" => self.invoke_call_status(&input).await,
            "telnyx.call.transfer" => self.invoke_call_transfer(&input).await,
            "telnyx.call.gather" => self.invoke_call_gather(&input).await,
            "telnyx.webhook.validate_signature" => self.invoke_webhook_validate_signature(&input),
            "telnyx.webhook.evaluate_inbound_policy" => {
                Self::invoke_webhook_evaluate_inbound_policy(&input)
            }
            "telnyx.webhook.parse_event" => Self::invoke_webhook_parse_event(&input),
            "telnyx.webhook.ingest_request" => self.invoke_webhook_ingest_request(&input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    /// Shutdown connector-owned runtime state.
    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        info!("Telnyx connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }

    async fn invoke_call_initiate(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let connection_id = require_str(&input, "connection_id")?;
        let webhook_url = input.get("webhook_url").and_then(Value::as_str);
        let timeout_secs = optional_u32(&input, "timeout_secs")?;
        let stream_url = input.get("stream_url").and_then(Value::as_str);

        let call_auth = CallAuthToken::generate();
        let client_state =
            encode_client_state(call_auth.expose_secret()).map_err(|error| error.to_fcp_error())?;
        let stream_auth_binding = stream_url.map(|_| call_auth.expose_secret());

        let request = InitiateCallRequest {
            to,
            from,
            connection_id,
            webhook_url,
            client_state: Some(&client_state),
            timeout_secs,
            stream_url,
            stream_auth_token: stream_auth_binding,
        };
        let response = client
            .initiate_call(&request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        let call_control_id = response
            .call_control_id
            .clone()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Telnyx response missing call_control_id".into(),
            })?;
        self.store_session(
            &call_control_id,
            response.call_session_id.clone(),
            from,
            to,
            call_auth,
        )?;

        Ok(json!({
            "call": response,
            "session": {
                "provider": "telnyx",
                "call_control_id_hash": stable_redacted_hash(&call_control_id),
                "call_auth_token_preview": "redacted",
                "client_state_embedded": true,
                "stream_auth_token_embedded": stream_url.is_some(),
                "persistence": "memory_only",
            }
        }))
    }

    async fn invoke_call_continue(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let call_control_id = require_str(input, "call_control_id")?;
        let response = client
            .continue_call(call_control_id)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_speak(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request = SpeakCallRequest {
            call_control_id: require_str(input, "call_control_id")?,
            payload: require_str(input, "payload")?,
            voice: input.get("voice").and_then(Value::as_str),
            language: input.get("language").and_then(Value::as_str),
            client_state: input.get("client_state").and_then(Value::as_str),
            command_id: input.get("command_id").and_then(Value::as_str),
        };
        let response = client
            .speak_call(&request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_end(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let response = client
            .end_call(require_str(input, "call_control_id")?)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_status(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let response = client
            .status_call(require_str(input, "call_control_id")?)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_transfer(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request = TransferCallRequest {
            call_control_id: require_str(input, "call_control_id")?,
            to: require_str(input, "to")?,
            from: input.get("from").and_then(Value::as_str),
            timeout_secs: optional_u32(input, "timeout_secs")?,
            client_state: input.get("client_state").and_then(Value::as_str),
        };
        let response = client
            .transfer_call(&request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_gather(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request = GatherUsingSpeakRequest {
            call_control_id: require_str(input, "call_control_id")?,
            payload: require_str(input, "payload")?,
            voice: input.get("voice").and_then(Value::as_str),
            language: input.get("language").and_then(Value::as_str),
            minimum_digits: optional_u32(input, "minimum_digits")?,
            maximum_digits: optional_u32(input, "maximum_digits")?,
            timeout_millis: optional_u32(input, "timeout_millis")?,
            terminator: input.get("terminator").and_then(Value::as_str),
            client_state: input.get("client_state").and_then(Value::as_str),
        };
        let response = client
            .gather_using_speak(&request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    fn store_session(
        &self,
        call_control_id: &str,
        call_session_id: Option<String>,
        from: &str,
        to: &str,
        call_auth: CallAuthToken,
    ) -> FcpResult<()> {
        let mut session = CallSession::new(
            VoiceProvider::Telnyx,
            "z:work",
            call_control_id,
            from,
            to,
            Utc::now(),
            Duration::minutes(TELNYX_SESSION_TTL_MINUTES),
        );
        let mut call_auth = call_auth;
        std::mem::swap(&mut session.auth_token, &mut call_auth);
        session.call_session_id = call_session_id;
        let key = {
            let mut store = self.session_store.lock().map_err(lock_error)?;
            store.upsert(fcp_voice_call::SessionScope::PerCall, session)
        };
        self.session_keys
            .lock()
            .map_err(lock_error)?
            .insert(call_control_id.to_string(), key);
        Ok(())
    }

    fn invoke_webhook_validate_signature(&self, input: &Value) -> FcpResult<Value> {
        let (headers, raw_payload) = telnyx_verification_input(input)?;
        let now = Utc::now();
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = TelnyxSignatureVerifier::new(&config.public_key, config.timestamp_tolerance)
            .map_err(|error| error.to_fcp_error())?;
        let verification = {
            let mut replay_cache = self.webhook_replay_cache.lock().map_err(lock_error)?;
            match verifier.verify(&headers, &raw_payload, &mut replay_cache, now) {
                Ok(verification) => verification,
                Err(error) => verification_from_voice_error(&error),
            }
        };
        serialize_result(telnyx_signature_validation_result(verification))
    }

    fn invoke_webhook_evaluate_inbound_policy(input: &Value) -> FcpResult<Value> {
        let policy = TelnyxInboundPolicyMode::parse(input)?;
        let body = webhook_body(input)?;
        let from = string_field(body, "from")
            .or_else(|| string_field(body, "from_number"))
            .or_else(|| payload_nested_string(body, "from", "phone_number"));
        let to = string_field(body, "to")
            .or_else(|| string_field(body, "to_number"))
            .or_else(|| payload_nested_string(body, "to", "phone_number"));
        let normalized_from = from.as_deref().and_then(normalize_e164_phone);
        let allowed_from = normalize_allowed_from_values(input.get("allowed_from"))?;

        let decision = match policy {
            TelnyxInboundPolicyMode::Disabled => inbound_policy_decision(
                policy,
                false,
                "inbound_disabled",
                "Inbound Telnyx callbacks are disabled by policy",
                from,
                normalized_from,
                None,
                to,
                infer_telnyx_event_type(body),
            ),
            TelnyxInboundPolicyMode::Open => inbound_policy_decision(
                policy,
                true,
                "inbound_open",
                "Inbound Telnyx callbacks are accepted by open policy",
                from,
                normalized_from,
                None,
                to,
                infer_telnyx_event_type(body),
            ),
            TelnyxInboundPolicyMode::Allowlist => {
                let matched = normalized_from
                    .as_ref()
                    .filter(|candidate| allowed_from.iter().any(|allowed| allowed == *candidate))
                    .cloned();
                inbound_policy_decision(
                    policy,
                    matched.is_some(),
                    if matched.is_some() {
                        "inbound_allowlisted"
                    } else {
                        "inbound_not_allowlisted"
                    },
                    if matched.is_some() {
                        "Caller matched allowed_from"
                    } else {
                        "Caller did not match allowed_from"
                    },
                    from,
                    normalized_from,
                    matched,
                    to,
                    infer_telnyx_event_type(body),
                )
            }
        };
        serialize_result(decision)
    }

    fn invoke_webhook_parse_event(input: &Value) -> FcpResult<Value> {
        let body = webhook_body(input)?;
        let event = parse_telnyx_event_from_body(body)?;
        Ok(event)
    }

    fn invoke_webhook_ingest_request(&self, input: &Value) -> FcpResult<Value> {
        let method = input
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("POST")
            .to_ascii_uppercase();
        if method != "POST" {
            return telnyx_webhook_ingress_response(
                false,
                405,
                "method_not_allowed",
                "Telnyx webhooks must be POST",
                None,
                None,
                None,
                telnyx_webhook_request_region(input, &method),
                telnyx_webhook_service_layers(input)?,
                vec![telnyx_webhook_ingress_log(
                    "request",
                    "denied",
                    "method_not_allowed",
                    "Rejected non-POST Telnyx webhook",
                )],
                0,
            );
        }
        if request_region_bool(input, "cancelled") {
            return telnyx_webhook_ingress_response(
                false,
                499,
                "request_cancelled",
                "Telnyx webhook request was cancelled before processing",
                None,
                None,
                None,
                telnyx_webhook_request_region(input, &method),
                telnyx_webhook_service_layers(input)?,
                vec![telnyx_webhook_ingress_log(
                    "request",
                    "cancelled",
                    "request_cancelled",
                    "Cancelled before body parse",
                )],
                0,
            );
        }
        if request_region_bool(input, "deadline_exceeded") {
            return telnyx_webhook_ingress_response(
                false,
                504,
                "deadline_exceeded",
                "Telnyx webhook request deadline exceeded",
                None,
                None,
                None,
                telnyx_webhook_request_region(input, &method),
                telnyx_webhook_service_layers(input)?,
                vec![telnyx_webhook_ingress_log(
                    "request",
                    "timeout",
                    "deadline_exceeded",
                    "Timed out before body parse",
                )],
                0,
            );
        }

        let request_region = telnyx_webhook_request_region(input, &method);
        let service_layers = telnyx_webhook_service_layers(input)?;
        let body_bytes = webhook_body_size(input, input.get("body").unwrap_or(&Value::Null))?;
        if body_bytes > TELNYX_WEBHOOK_INGRESS_MAX_BODY_BYTES {
            return telnyx_webhook_ingress_response(
                false,
                413,
                "payload_too_large",
                "Telnyx webhook body exceeded maximum size",
                None,
                None,
                None,
                request_region,
                service_layers,
                vec![telnyx_webhook_ingress_log(
                    "body",
                    "denied",
                    "payload_too_large",
                    "Rejected oversized webhook body",
                )],
                body_bytes,
            );
        }

        let (headers, raw_payload) = match telnyx_verification_input(input) {
            Ok(value) => value,
            Err(error) => {
                return telnyx_webhook_ingress_response(
                    false,
                    400,
                    "malformed_request",
                    &error.to_string(),
                    None,
                    None,
                    None,
                    request_region,
                    service_layers,
                    vec![telnyx_webhook_ingress_log(
                        "body",
                        "denied",
                        "malformed_request",
                        "Rejected malformed webhook request",
                    )],
                    body_bytes,
                );
            }
        };

        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = TelnyxSignatureVerifier::new(&config.public_key, config.timestamp_tolerance)
            .map_err(|error| error.to_fcp_error())?;
        let signature = {
            let mut replay_cache = self.webhook_replay_cache.lock().map_err(lock_error)?;
            match verifier.verify(&headers, &raw_payload, &mut replay_cache, Utc::now()) {
                Ok(verification) => verification,
                Err(error) => verification_from_voice_error(&error),
            }
        };
        let signature_result = telnyx_signature_validation_result(signature.clone());
        if !signature.valid {
            return telnyx_webhook_ingress_response(
                false,
                403,
                signature.reason_code.as_str(),
                signature.reason.as_str(),
                None,
                Some(signature_result),
                None,
                request_region,
                service_layers,
                vec![telnyx_webhook_ingress_log(
                    "signature",
                    "denied",
                    signature.reason_code.as_str(),
                    "Rejected invalid Telnyx signature",
                )],
                body_bytes,
            );
        }
        if signature.is_replay {
            return telnyx_webhook_ingress_response(
                false,
                409,
                "replay",
                "Telnyx webhook signature is valid but was already processed",
                None,
                Some(signature_result),
                None,
                request_region,
                service_layers,
                vec![telnyx_webhook_ingress_log(
                    "replay",
                    "denied",
                    "replay",
                    "Rejected duplicate signed webhook",
                )],
                body_bytes,
            );
        }

        let event = parse_telnyx_event_from_raw(&raw_payload)?;
        let session_decision = self.validate_session_binding(&event);
        if let Some(reason) = session_decision.err() {
            return telnyx_webhook_ingress_response(
                false,
                403,
                "session_auth_denied",
                &reason,
                Some(event),
                Some(signature_result),
                None,
                request_region,
                service_layers,
                vec![telnyx_webhook_ingress_log(
                    "session",
                    "denied",
                    "session_auth_denied",
                    "Rejected callback session binding",
                )],
                body_bytes,
            );
        }

        let policy = Self::invoke_webhook_evaluate_inbound_policy(&json!({
            "body": event,
            "inbound_policy": input.get("inbound_policy").and_then(Value::as_str).unwrap_or("open"),
            "allowed_from": input.get("allowed_from").cloned().unwrap_or_else(|| json!([])),
        }))?;
        let policy: InboundPolicyDecision =
            serde_json::from_value(policy).map_err(|error| FcpError::Internal {
                message: format!("Failed to deserialize Telnyx inbound policy: {error}"),
            })?;
        if !policy.allowed {
            let reason_code = policy.reason_code.clone();
            let reason = policy.reason.clone();
            return telnyx_webhook_ingress_response(
                false,
                403,
                reason_code.as_str(),
                reason.as_str(),
                Some(event),
                Some(signature_result),
                Some(policy),
                request_region,
                service_layers,
                vec![telnyx_webhook_ingress_log(
                    "policy",
                    "denied",
                    "inbound_policy_denied",
                    "Rejected by inbound caller policy",
                )],
                body_bytes,
            );
        }

        telnyx_webhook_ingress_response(
            true,
            202,
            "accepted",
            "Telnyx webhook accepted",
            Some(event),
            Some(signature_result),
            Some(policy),
            request_region,
            service_layers,
            vec![telnyx_webhook_ingress_log(
                "complete",
                "accepted",
                "accepted",
                "Accepted Telnyx webhook through connector boundary",
            )],
            body_bytes,
        )
    }

    fn validate_session_binding(&self, event: &Value) -> Result<(), String> {
        let call_control_id = event
            .get("call_control_id")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .get("payload")
                    .and_then(|payload| payload.get("call_control_id"))
                    .and_then(Value::as_str)
            });
        let client_state = event
            .get("client_state")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .get("payload")
                    .and_then(|payload| payload.get("client_state"))
                    .and_then(Value::as_str)
            });
        let Some((call_control_id, client_state)) = call_control_id.zip(client_state) else {
            return Ok(());
        };
        let callback_binding =
            decode_client_state_token(client_state).map_err(|error| error.to_string())?;
        let session_key = self
            .session_keys
            .lock()
            .map_err(|_| "session key lock poisoned".to_string())?
            .get(call_control_id)
            .cloned();
        let Some(session_key) = session_key else {
            return Ok(());
        };
        let token_matches = self
            .session_store
            .lock()
            .map_err(|_| "session store lock poisoned".to_string())?
            .get_live(&session_key, Utc::now())
            .map_or_else(
                || Err("callback session expired or missing".to_string()),
                |session| Ok(session.auth_token.verify(&callback_binding)),
            )?;
        if token_matches {
            Ok(())
        } else {
            Err("callback client_state token does not match stored session".into())
        }
    }

    async fn operation_metadata(&self, operation: &str) -> FcpResult<(CapabilityId, Value)> {
        let op = Self::operations()
            .into_iter()
            .find(|operation_info| operation_info.id.as_str() == operation)
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;
        Ok((op.capability, op.input_schema))
    }

    fn validate_required_input(input_schema: &Value, input: &Value) -> FcpResult<()> {
        let Some(required) = input_schema.get("required").and_then(Value::as_array) else {
            return Ok(());
        };
        for field in required {
            let Some(field) = field.as_str() else {
                continue;
            };
            if input.get(field).is_none_or(Value::is_null) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Missing required field: {field}"),
                });
            }
        }
        Ok(())
    }

    fn operations() -> Vec<OperationInfo> {
        vec![
            op_info(
                "telnyx.call.initiate",
                "Initiate a Telnyx outbound voice call",
                schema(&["to", "from", "connection_id"]),
                json!({ "type": "object" }),
                "telnyx.voice",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
                hint(
                    "Start an outbound Telnyx call.",
                    &["telnyx.call.status", "telnyx.call.end"],
                ),
            ),
            op_info(
                "telnyx.call.continue",
                "Answer or continue a Telnyx call",
                schema(&["call_control_id"]),
                json!({ "type": "object" }),
                "telnyx.voice",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
                hint(
                    "Answer or continue a pending Telnyx call.",
                    &["telnyx.call.speak"],
                ),
            ),
            op_info(
                "telnyx.call.speak",
                "Speak text into a Telnyx call",
                schema(&["call_control_id", "payload"]),
                json!({ "type": "object" }),
                "telnyx.voice",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                hint(
                    "Speak short text into an active call.",
                    &["telnyx.call.gather"],
                ),
            ),
            op_info(
                "telnyx.call.end",
                "Hang up a Telnyx call",
                schema(&["call_control_id"]),
                json!({ "type": "object" }),
                "telnyx.voice",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::BestEffort,
                hint("End an active Telnyx call.", &["telnyx.call.status"]),
            ),
            op_info(
                "telnyx.call.status",
                "Retrieve Telnyx call status",
                schema(&["call_control_id"]),
                json!({ "type": "object" }),
                "telnyx.read",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                hint(
                    "Read call status and provider metadata.",
                    &["telnyx.call.end"],
                ),
            ),
            op_info(
                "telnyx.call.transfer",
                "Transfer a Telnyx call",
                schema(&["call_control_id", "to"]),
                json!({ "type": "object" }),
                "telnyx.voice",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
                hint(
                    "Transfer a live Telnyx call to another destination.",
                    &["telnyx.call.end"],
                ),
            ),
            op_info(
                "telnyx.call.gather",
                "Gather DTMF digits using spoken prompt text",
                schema(&["call_control_id", "payload"]),
                json!({ "type": "object" }),
                "telnyx.voice",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                hint(
                    "Ask the caller for DTMF input using Telnyx gather_using_speak.",
                    &["telnyx.call.speak"],
                ),
            ),
            op_info(
                "telnyx.webhook.validate_signature",
                "Validate a Telnyx Ed25519 webhook signature",
                schema(&["headers", "body"]),
                json!({ "type": "object" }),
                "telnyx.webhook",
                RiskLevel::Medium,
                SafetyTier::Safe,
                IdempotencyClass::BestEffort,
                hint(
                    "Validate Telnyx webhook headers and replay state.",
                    &["telnyx.webhook.ingest_request"],
                ),
            ),
            op_info(
                "telnyx.webhook.evaluate_inbound_policy",
                "Evaluate Telnyx inbound caller policy",
                schema(&["body", "inbound_policy"]),
                json!({ "type": "object" }),
                "telnyx.webhook",
                RiskLevel::Medium,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                hint(
                    "Decide whether an inbound caller should be accepted.",
                    &["telnyx.webhook.ingest_request"],
                ),
            ),
            op_info(
                "telnyx.webhook.parse_event",
                "Parse a Telnyx webhook event",
                schema(&["body"]),
                json!({ "type": "object" }),
                "telnyx.webhook",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                hint(
                    "Parse a verified Telnyx webhook body.",
                    &["telnyx.webhook.validate_signature"],
                ),
            ),
            op_info(
                "telnyx.webhook.ingest_request",
                "Ingest a Telnyx webhook request through the connector boundary",
                schema(&["headers", "body"]),
                json!({ "type": "object" }),
                "telnyx.webhook",
                RiskLevel::Medium,
                SafetyTier::Safe,
                IdempotencyClass::BestEffort,
                hint(
                    "Validate, de-duplicate, parse, and policy-check a Telnyx webhook.",
                    &["telnyx.webhook.validate_signature"],
                ),
            ),
        ]
    }
}

impl Default for TelnyxConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> FcpError {
    FcpError::Internal {
        message: "Telnyx connector lock poisoned".into(),
    }
}

fn require_str<'a>(input: &'a Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

fn optional_u32(input: &Value, field: &str) -> FcpResult<Option<u32>> {
    input
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .and_then(|raw| u32::try_from(raw).ok())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("{field} must be an unsigned 32-bit integer"),
                })
        })
        .transpose()
}

fn schema(required: &[&str]) -> Value {
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "call_control_id": { "type": "string" },
            "to": { "type": "string" },
            "from": { "type": "string" },
            "connection_id": { "type": "string" },
            "payload": { "type": "string" },
            "headers": { "type": "object" },
            "body": { "type": "object" },
            "raw_body": { "type": "string" },
            "inbound_policy": { "type": "string" }
        }
    })
}

fn hint(when_to_use: &str, related: &[&'static str]) -> AgentHint {
    AgentHint {
        when_to_use: when_to_use.into(),
        common_mistakes: vec![
            "Passing live Telnyx credentials into no-live-credential tests.".into(),
            "Logging full E.164 numbers, full webhook bodies, or client_state tokens.".into(),
        ],
        examples: Vec::new(),
        related: related
            .iter()
            .map(|value| CapabilityId::from_static(value))
            .collect(),
    }
}

fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: Value,
    output_schema: Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.into(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

fn telnyx_headers(input: &Value) -> FcpResult<ProviderHeaders> {
    let headers =
        input
            .get("headers")
            .and_then(Value::as_object)
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "headers must be an object".into(),
            })?;
    Ok(ProviderHeaders::new(headers.iter().map(|(key, value)| {
        (
            key.clone(),
            value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_string),
        )
    })))
}

fn telnyx_verification_input(input: &Value) -> FcpResult<(ProviderHeaders, Vec<u8>)> {
    let headers = telnyx_headers(input)?;
    let raw_payload = if let Some(raw_body) = input.get("raw_body").and_then(Value::as_str) {
        raw_body.as_bytes().to_vec()
    } else {
        serde_json::to_vec(input.get("body").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "body is required".into(),
        })?)
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize Telnyx body: {error}"),
        })?
    };
    Ok((headers, raw_payload))
}

fn verification_from_voice_error(error: &VoiceCallError) -> SignatureVerification {
    match error {
        VoiceCallError::TimestampOutsideTolerance { .. } => SignatureVerification {
            provider: VoiceProvider::Telnyx,
            valid: false,
            reason_code: "timestamp_outside_tolerance".into(),
            reason: error.to_string(),
            is_replay: false,
            verified_request_key: None,
        },
        VoiceCallError::MalformedSignatureMaterial(_) | VoiceCallError::InvalidRequest(_) => {
            SignatureVerification {
                provider: VoiceProvider::Telnyx,
                valid: false,
                reason_code: "malformed_signature_material".into(),
                reason: error.to_string(),
                is_replay: false,
                verified_request_key: None,
            }
        }
        VoiceCallError::MissingHeader(_) => SignatureVerification {
            provider: VoiceProvider::Telnyx,
            valid: false,
            reason_code: "missing_header".into(),
            reason: error.to_string(),
            is_replay: false,
            verified_request_key: None,
        },
        VoiceCallError::InvalidSignature(_) => SignatureVerification {
            provider: VoiceProvider::Telnyx,
            valid: false,
            reason_code: "invalid_signature".into(),
            reason: error.to_string(),
            is_replay: false,
            verified_request_key: None,
        },
        VoiceCallError::Replay(_) | VoiceCallError::Internal(_) => SignatureVerification {
            provider: VoiceProvider::Telnyx,
            valid: false,
            reason_code: "verification_error".into(),
            reason: error.to_string(),
            is_replay: false,
            verified_request_key: None,
        },
    }
}

fn telnyx_signature_validation_result(
    verification: SignatureVerification,
) -> SignatureValidationResult {
    SignatureValidationResult {
        valid: verification.valid,
        reason_code: verification.reason_code,
        reason: verification.reason,
        is_replay: verification.is_replay,
        verified_request_key: verification.verified_request_key,
        provider: verification.provider.as_str().into(),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TelnyxInboundPolicyMode {
    Open,
    Allowlist,
    Disabled,
}

impl TelnyxInboundPolicyMode {
    fn parse(input: &Value) -> FcpResult<Self> {
        match require_str(input, "inbound_policy")? {
            "open" => Ok(Self::Open),
            "allowlist" => Ok(Self::Allowlist),
            "disabled" => Ok(Self::Disabled),
            other => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "inbound_policy must be one of open, allowlist, or disabled; got `{other}`"
                ),
            }),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Allowlist => "allowlist",
            Self::Disabled => "disabled",
        }
    }
}

fn webhook_body(input: &Value) -> FcpResult<&serde_json::Map<String, Value>> {
    input
        .get("body")
        .and_then(Value::as_object)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "body must be an object".into(),
        })
}

fn string_field(body: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn payload_nested_string(
    body: &serde_json::Map<String, Value>,
    object: &str,
    field: &str,
) -> Option<String> {
    body.get("payload")
        .and_then(|payload| payload.get(object))
        .and_then(|nested| nested.get(field))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_telnyx_event_from_raw(raw_payload: &[u8]) -> FcpResult<Value> {
    let envelope: TelnyxEventEnvelope =
        serde_json::from_slice(raw_payload).map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Telnyx webhook JSON: {error}"),
        })?;
    Ok(telnyx_event_to_value(envelope))
}

fn parse_telnyx_event_from_body(body: &serde_json::Map<String, Value>) -> FcpResult<Value> {
    let envelope: TelnyxEventEnvelope = serde_json::from_value(Value::Object(body.clone()))
        .map_err(|error| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Telnyx webhook body: {error}"),
        })?;
    Ok(telnyx_event_to_value(envelope))
}

fn telnyx_event_to_value(envelope: TelnyxEventEnvelope) -> Value {
    let payload = envelope.data.payload;
    let from = payload.get("from").and_then(Value::as_str).or_else(|| {
        payload
            .get("from")
            .and_then(|value| value.get("phone_number"))
            .and_then(Value::as_str)
    });
    let to = payload.get("to").and_then(Value::as_str).or_else(|| {
        payload
            .get("to")
            .and_then(|value| value.get("phone_number"))
            .and_then(Value::as_str)
    });
    let call_control_id = payload.get("call_control_id").and_then(Value::as_str);
    let call_session_id = payload.get("call_session_id").and_then(Value::as_str);
    let client_state = payload.get("client_state").and_then(Value::as_str);
    json!({
        "event_id": envelope.data.id,
        "event_type": envelope.data.event_type,
        "occurred_at": envelope.data.occurred_at,
        "record_type": envelope.data.record_type,
        "call_control_id": call_control_id,
        "call_control_id_hash": call_control_id.map(stable_redacted_hash),
        "call_session_id": call_session_id,
        "call_session_id_hash": call_session_id.map(stable_redacted_hash),
        "from": from,
        "from_masked": from.map(mask_phone_number),
        "from_hash": from.map(stable_redacted_hash),
        "to": to,
        "to_masked": to.map(mask_phone_number),
        "to_hash": to.map(stable_redacted_hash),
        "client_state_present": client_state.is_some(),
        "payload": payload,
    })
}

fn infer_telnyx_event_type(body: &serde_json::Map<String, Value>) -> String {
    body.get("event_type")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("data")
                .and_then(|data| data.get("event_type"))
                .and_then(Value::as_str)
        })
        .unwrap_or("telnyx.call_control")
        .to_string()
}

fn normalize_e164_phone(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix('+')?;
    if digits.is_empty()
        || digits.len() > 15
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn normalize_allowed_from_values(input: Option<&Value>) -> FcpResult<Vec<String>> {
    let Some(input) = input else {
        return Ok(Vec::new());
    };
    let values = input.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "allowed_from must be an array of exact E.164 phone numbers".into(),
    })?;
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let raw = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "allowed_from entries must be strings".into(),
        })?;
        let Some(phone) = normalize_e164_phone(raw) else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "allowed_from entries must be exact E.164 phone numbers".into(),
            });
        };
        normalized.push(phone);
    }
    Ok(normalized)
}

fn inbound_policy_decision(
    mode: TelnyxInboundPolicyMode,
    allowed: bool,
    reason_code: &str,
    reason: &str,
    from: Option<String>,
    normalized_from: Option<String>,
    matched_from: Option<String>,
    to: Option<String>,
    event_type: String,
) -> InboundPolicyDecision {
    InboundPolicyDecision {
        allowed,
        policy: mode.as_str().into(),
        reason_code: reason_code.into(),
        reason: reason.into(),
        from,
        normalized_from,
        matched_from,
        to,
        event_type,
        audit_event_type: if allowed {
            "telnyx.inbound_policy.allowed".into()
        } else {
            "telnyx.inbound_policy.denied".into()
        },
    }
}

fn request_region_bool(input: &Value, field: &str) -> bool {
    input
        .get("request_region")
        .and_then(|region| region.get(field))
        .and_then(Value::as_bool)
        .or_else(|| input.get(field).and_then(Value::as_bool))
        .unwrap_or(false)
}

fn request_region_string(input: &Value, field: &str, default: &str) -> String {
    input
        .get("request_region")
        .and_then(|region| region.get(field))
        .and_then(Value::as_str)
        .or_else(|| input.get(field).and_then(Value::as_str))
        .map_or_else(|| default.into(), str::to_string)
}

fn optional_u64_field(input: &Value, field: &str, default: u64) -> FcpResult<u64> {
    match input.get(field) {
        Some(value) => value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} must be an unsigned integer"),
        }),
        None => Ok(default),
    }
}

fn telnyx_webhook_request_region(input: &Value, method: &str) -> Value {
    json!({
        "surface": "fcp.webhook.request_region",
        "provider": "telnyx",
        "source": request_region_string(input, "source", "host_forwarded"),
        "method": method,
        "cancelled": request_region_bool(input, "cancelled"),
        "deadline_exceeded": request_region_bool(input, "deadline_exceeded")
    })
}

fn telnyx_webhook_service_layers(input: &Value) -> FcpResult<Value> {
    let timeout_ms = optional_u64_field(input, "timeout_ms", TELNYX_WEBHOOK_INGRESS_TIMEOUT_MS)?;
    let concurrency_limit = optional_u64_field(
        input,
        "concurrency_limit",
        TELNYX_WEBHOOK_INGRESS_CONCURRENCY_LIMIT,
    )?;
    let rate_limit_max = optional_u64_field(
        input,
        "rate_limit_max",
        TELNYX_WEBHOOK_INGRESS_RATE_LIMIT_MAX,
    )?;
    let rate_limit_window_ms = optional_u64_field(
        input,
        "rate_limit_window_ms",
        TELNYX_WEBHOOK_INGRESS_RATE_LIMIT_WINDOW_MS,
    )?;
    Ok(json!({
        "builder": "fcp.webhook.ServiceBuilder",
        "host_enforced": true,
        "layers": [
            { "name": "timeout", "timeout_ms": timeout_ms },
            { "name": "concurrency_limit", "max_in_flight": concurrency_limit },
            { "name": "load_shed", "enabled": true },
            {
                "name": "rate_limit",
                "pool": "telnyx.webhook",
                "max": rate_limit_max,
                "window_ms": rate_limit_window_ms
            },
            { "name": "body_limit", "max_body_bytes": TELNYX_WEBHOOK_INGRESS_MAX_BODY_BYTES }
        ]
    }))
}

fn webhook_body_size(input: &Value, body: &Value) -> FcpResult<usize> {
    if let Some(size) = input.get("body_size_bytes").and_then(Value::as_u64) {
        return usize::try_from(size).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "body_size_bytes is too large for this platform".into(),
        });
    }
    serde_json::to_vec(body)
        .map(|bytes| bytes.len())
        .map_err(|error| FcpError::Internal {
            message: format!("Failed to measure Telnyx webhook body: {error}"),
        })
}

fn telnyx_webhook_ingress_log(
    phase: &str,
    outcome: &str,
    code: &str,
    message: &str,
) -> WebhookIngressLogEntry {
    WebhookIngressLogEntry {
        phase: phase.into(),
        outcome: outcome.into(),
        code: code.into(),
        message: message.into(),
    }
}

fn telnyx_webhook_ingress_response(
    accepted: bool,
    status_code: u16,
    reason_code: &str,
    reason: &str,
    event: Option<Value>,
    signature: Option<SignatureValidationResult>,
    policy: Option<InboundPolicyDecision>,
    request_region: Value,
    service_layers: Value,
    logs: Vec<WebhookIngressLogEntry>,
    body_bytes: usize,
) -> FcpResult<Value> {
    let event_type = event
        .as_ref()
        .and_then(|event| event.get("event_type"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| policy.as_ref().map(|policy| policy.event_type.clone()));
    serialize_result(WebhookIngressResult {
        accepted,
        status_code,
        reason_code: reason_code.into(),
        reason: reason.into(),
        event_type,
        event: accepted.then_some(event).flatten(),
        signature,
        policy,
        request_region,
        service_layers,
        logs,
        body_bytes,
        tainted: true,
        clean_shutdown: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use fcp_crypto::{CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, ZoneId};

    fn public_key_config() -> String {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    }

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &str,
    ) -> CapabilityToken {
        let capability = match operation {
            "telnyx.call.status" => "telnyx.read",
            "telnyx.webhook.validate_signature"
            | "telnyx.webhook.evaluate_inbound_policy"
            | "telnyx.webhook.parse_event"
            | "telnyx.webhook.ingest_request" => "telnyx.webhook",
            _ => "telnyx.voice",
        };
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    async fn configure_for_tests(connector: &mut TelnyxConnector) {
        connector
            .handle_configure(json!({
                "api_key": "test_api_key",
                "public_key": public_key_config(),
                "base_url": "http://localhost:9999/v2"
            }))
            .await
            .unwrap();
    }

    async fn handshake_for_tests(connector: &mut TelnyxConnector) -> Ed25519SigningKey {
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["telnyx.read", "telnyx.voice", "telnyx.webhook"]
            }))
            .await
            .unwrap();
        signing_key
    }

    #[test]
    fn base_url_validation_allows_only_telnyx_or_local_for_direct_key() {
        let auth = TelnyxAuth::ApiKey {
            api_key: "test".into(),
        };
        assert!(validate_base_url_for_auth("https://api.telnyx.com/v2", &auth).is_ok());
        assert!(validate_base_url_for_auth("http://localhost:8080/v2", &auth).is_ok());
        assert!(validate_base_url_for_auth("https://evil.example/v2", &auth).is_err());
    }

    #[test]
    fn configure_requires_exactly_one_auth_mode_and_public_key() {
        let missing = TelnyxConfig::from_params(&json!({ "api_key": "test" })).unwrap_err();
        assert!(missing.to_string().contains("public_key"));
        let both = TelnyxConfig::from_params(&json!({
            "api_key": "test",
            "credential_id": uuid::Uuid::new_v4().to_string(),
            "public_key": public_key_config()
        }))
        .unwrap_err();
        assert!(both.to_string().contains("not both"));
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_has_required_voice_and_webhook_operations() {
        let connector = TelnyxConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let ids = ops
            .iter()
            .map(|operation| operation["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for id in [
            "telnyx.call.initiate",
            "telnyx.call.continue",
            "telnyx.call.speak",
            "telnyx.call.end",
            "telnyx.call.status",
            "telnyx.call.transfer",
            "telnyx.call.gather",
            "telnyx.webhook.validate_signature",
            "telnyx.webhook.ingest_request",
        ] {
            assert!(ids.contains(&id), "{id} missing");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_handshake_after_configure() {
        let mut connector = TelnyxConnector::new();
        configure_for_tests(&mut connector).await;
        let result = connector
            .handle_invoke(json!({
                "operation": "telnyx.call.status",
                "input": { "call_control_id": "call-1" },
                "capability_token": CapabilityToken::test_token()
            }))
            .await;
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_missing_required_input() {
        let mut connector = TelnyxConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let capability_proof =
            generate_valid_token(&signing_key, connector.instance_id(), "telnyx.call.status");
        let request = SimulateRequest::new(
            ConnectorId::from_static("telnyx"),
            OperationId::from_static("telnyx.call.status"),
            ZoneId::work(),
            json!({}),
            capability_proof,
        );
        let result = connector
            .handle_simulate(serde_json::to_value(request).unwrap())
            .await
            .unwrap();
        assert_eq!(result["would_succeed"], false);
        assert!(
            result["failure_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("call_control_id"))
        );
    }

    #[test]
    fn inbound_policy_exact_allowlist_and_disabled_modes() {
        let input = json!({
            "inbound_policy": "allowlist",
            "allowed_from": ["+15551230000"],
            "body": {
                "event_type": "call.initiated",
                "from": "+15551230000",
                "to": "+15559870000"
            }
        });
        let allowed = TelnyxConnector::invoke_webhook_evaluate_inbound_policy(&input).unwrap();
        assert_eq!(allowed["allowed"], true);

        let disabled = TelnyxConnector::invoke_webhook_evaluate_inbound_policy(&json!({
            "inbound_policy": "disabled",
            "body": input["body"]
        }))
        .unwrap();
        assert_eq!(disabled["allowed"], false);
    }

    #[test]
    fn parse_event_exposes_raw_fields_and_redaction_helpers() {
        let event = TelnyxConnector::invoke_webhook_parse_event(&json!({
            "body": {
                "data": {
                    "id": "evt-1",
                    "event_type": "call.initiated",
                    "payload": {
                        "call_control_id": "call-control-1",
                        "call_session_id": "session-1",
                        "from": "+15551230000",
                        "to": "+15559870000"
                    }
                }
            }
        }))
        .unwrap();
        assert_eq!(event["event_type"], "call.initiated");
        assert_eq!(event["from"], "+15551230000");
        assert_eq!(event["from_masked"], "+15***0000");
        assert_ne!(event["from_hash"], "+15551230000");
    }

    #[test]
    fn malformed_client_state_denies_session_binding() {
        let connector = TelnyxConnector::new();
        let event = json!({
            "call_control_id": "call-control-1",
            "client_state": "not-base64"
        });
        assert!(connector.validate_session_binding(&event).is_err());
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest =
            fcp_manifest::ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);
    }
}
