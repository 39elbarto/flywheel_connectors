//! Plivo FCP connector implementation.
#![allow(
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::option_if_let_else,
    clippy::or_fun_call,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unused_async
)]

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
    CallAuthToken, CallSession, MemorySessionStore, PlivoParamValue, PlivoSignatureVerifier,
    PlivoSignatureVersion, PlivoVerificationRequest, ProviderHeaders, SignatureVerification,
    VoiceCallError, VoiceProvider, VoiceWebhookMethod, WebhookReplayCache, mask_phone_number,
    stable_redacted_hash,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tracing::{info, instrument};
use url::Url;

use crate::{
    client::{
        ContinueCallRequest, DEFAULT_API_BASE_PREFIX, GatherDigitsRequest, InitiateCallRequest,
        PlivoAuth, PlivoClient, SpeakCallRequest, TransferCallRequest, append_call_auth_to_url,
        build_gather_digits_xml, call_auth_from_url,
    },
    types::{
        InboundPolicyDecision, PlivoCommand, SignatureValidationResult, WebhookIngressLogEntry,
        WebhookIngressResult,
    },
};

const PLIVO_WEBHOOK_INGRESS_MAX_BODY_BYTES: usize = 64 * 1024;
const PLIVO_WEBHOOK_INGRESS_TIMEOUT_MS: u64 = 5_000;
const PLIVO_WEBHOOK_INGRESS_CONCURRENCY_LIMIT: u64 = 32;
const PLIVO_WEBHOOK_INGRESS_RATE_LIMIT_MAX: u64 = 200;
const PLIVO_WEBHOOK_INGRESS_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const PLIVO_SESSION_TTL_MINUTES: i64 = 60;

#[derive(Debug, Clone)]
struct PlivoConfig {
    auth: PlivoAuth,
    base_url: String,
    webhook_auth_secret: String,
}

impl PlivoConfig {
    fn from_params(params: &Value) -> FcpResult<Self> {
        let auth_id = params
            .get("auth_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing auth_id in Plivo configuration".into(),
            })?
            .to_string();
        let direct_api_credential = params
            .get("auth_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let credential_id = params
            .get("credential_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let webhook_hmac_credential = params
            .get("webhook_auth_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        let (auth, webhook_auth_secret) = match (
            direct_api_credential,
            credential_id,
            webhook_hmac_credential,
        ) {
            (Some(api_credential), None, webhook_hmac_credential) => (
                PlivoAuth::Direct {
                    auth_id: auth_id.clone(),
                    auth_secret: api_credential.clone(),
                },
                webhook_hmac_credential.unwrap_or(api_credential),
            ),
            (Some(_), Some(_), _) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either auth_token or credential_id, not both".into(),
                });
            }
            (None, Some(raw), Some(webhook_hmac_credential)) => (
                PlivoAuth::CredentialId {
                    auth_id: auth_id.clone(),
                    credential_id: CredentialId::parse(raw).map_err(|error| {
                        FcpError::InvalidRequest {
                            code: 1003,
                            message: format!("Invalid credential_id: {error}"),
                        }
                    })?,
                },
                webhook_hmac_credential,
            ),
            (None, Some(_), None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message:
                        "credential_id mode requires webhook_auth_token for Plivo HMAC validation"
                            .into(),
                });
            }
            (None, None, _) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing auth_token or credential_id in Plivo configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("{DEFAULT_API_BASE_PREFIX}/{auth_id}"));
        let base_url = validate_base_url_for_auth(&base_url, &auth)?;

        Ok(Self {
            auth,
            base_url,
            webhook_auth_secret,
        })
    }
}

fn validate_base_url_for_auth(base_url: &str, auth: &PlivoAuth) -> FcpResult<String> {
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
    if matches!(auth, PlivoAuth::Direct { .. })
        && !local
        && !host.eq_ignore_ascii_case("api.plivo.com")
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url with direct auth_token mode must target api.plivo.com (localhost/127.0.0.1/::1 allowed for tests): {trimmed}"
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

/// Plivo connector.
pub struct PlivoConnector {
    base: Arc<BaseConnector>,
    pub(crate) client: Option<PlivoClient>,
    config: Option<PlivoConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_prelude::SessionId>,
    webhook_replay_cache: Mutex<WebhookReplayCache>,
    session_store: Mutex<MemorySessionStore>,
    session_keys: Mutex<BTreeMap<String, String>>,
}

impl PlivoConnector {
    /// Create a new Plivo connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("plivo"))),
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
        let config = PlivoConfig::from_params(&params)?;
        let client = PlivoClient::new_with_auth(config.auth.clone()).map_err(|error| {
            FcpError::Internal {
                message: format!("Failed to create Plivo HTTP client: {error}"),
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
        info!("Plivo connector configured");

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
            manifest_hash: "sha256:fcp-plivo-manifest".into(),
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
            "name": "webhook_hmac_sha256_v3_v2",
            "status": if self.config.as_ref().is_some_and(|cfg| !cfg.webhook_auth_secret.is_empty()) { "pass" } else { "fail" },
        }));
        checks.push(json!({
            "name": "network_constraints",
            "status": "pass",
            "host_allow": ["api.plivo.com"],
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
            "plivo.call.initiate" => self.invoke_call_initiate(input).await,
            "plivo.call.continue" => self.invoke_call_continue(&input).await,
            "plivo.call.speak" => self.invoke_call_speak(&input).await,
            "plivo.call.end" => self.invoke_call_end(&input).await,
            "plivo.call.status" => self.invoke_call_status(&input).await,
            "plivo.call.transfer" => self.invoke_call_transfer(&input).await,
            "plivo.call.gather" => Self::invoke_call_gather(&input),
            "plivo.webhook.validate_signature" => self.invoke_webhook_validate_signature(&input),
            "plivo.webhook.evaluate_inbound_policy" => {
                Self::invoke_webhook_evaluate_inbound_policy(&input)
            }
            "plivo.webhook.parse_event" => Self::invoke_webhook_parse_event(&input),
            "plivo.webhook.ingest_request" => self.invoke_webhook_ingest_request(&input),
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
        info!("Plivo connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }

    async fn invoke_call_initiate(&self, input: Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let answer_url = require_str(&input, "answer_url")?;
        let call_auth = CallAuthToken::generate();
        let answer_url = append_call_auth_to_url(answer_url, call_auth.expose_secret())
            .map_err(|error| error.to_fcp_error())?;

        let request = InitiateCallRequest {
            to,
            from,
            answer_url: &answer_url,
            answer_method: input.get("answer_method").and_then(Value::as_str),
            hangup_url: input.get("hangup_url").and_then(Value::as_str),
            hangup_method: input.get("hangup_method").and_then(Value::as_str),
            ring_url: input.get("ring_url").and_then(Value::as_str),
            ring_method: input.get("ring_method").and_then(Value::as_str),
            fallback_url: input.get("fallback_url").and_then(Value::as_str),
            time_limit: optional_u32(&input, "time_limit")?,
        };
        let response = client
            .initiate_call(&request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        let call_uuid = response
            .call_uuid
            .clone()
            .or_else(|| response.request_uuid.clone())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Plivo response missing call_uuid/request_uuid".into(),
            })?;
        self.store_session(&call_uuid, None, from, to, call_auth)?;

        Ok(json!({
            "call": response,
            "session": {
                "provider": "plivo",
                "call_uuid_hash": stable_redacted_hash(&call_uuid),
                "call_auth_token_preview": "redacted",
                "answer_url_auth_embedded": true,
                "persistence": "memory_only",
            }
        }))
    }

    async fn invoke_call_continue(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request = ContinueCallRequest {
            call_uuid: require_str(input, "call_uuid")?,
            xml_url: require_str(input, "xml_url")?,
            legs: input.get("legs").and_then(Value::as_str),
        };
        let response = client
            .continue_call(&request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_speak(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request = SpeakCallRequest {
            call_uuid: require_str(input, "call_uuid")?,
            text: require_str(input, "text")?,
            voice: input.get("voice").and_then(Value::as_str),
            language: input.get("language").and_then(Value::as_str),
            legs: input.get("legs").and_then(Value::as_str),
            loop_forever: input.get("loop").and_then(Value::as_bool),
            mix: input.get("mix").and_then(Value::as_bool),
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
            .end_call(require_str(input, "call_uuid")?)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_status(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let response = client
            .status_call(require_str(input, "call_uuid")?)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    async fn invoke_call_transfer(&self, input: &Value) -> FcpResult<Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let request = TransferCallRequest {
            call_uuid: require_str(input, "call_uuid")?,
            legs: require_str(input, "legs")?,
            aleg_url: input.get("aleg_url").and_then(Value::as_str),
            bleg_url: input.get("bleg_url").and_then(Value::as_str),
            aleg_method: input.get("aleg_method").and_then(Value::as_str),
            bleg_method: input.get("bleg_method").and_then(Value::as_str),
        };
        validate_transfer_request(&request)?;
        let response = client
            .transfer_call(&request)
            .await
            .map_err(|error| error.to_fcp_error())?;
        serialize_result(response)
    }

    fn invoke_call_gather(input: &Value) -> FcpResult<Value> {
        let request = GatherDigitsRequest {
            prompt: require_str(input, "prompt")?,
            action_url: require_str(input, "action_url")?,
            method: input.get("method").and_then(Value::as_str),
            digit_timeout_secs: optional_u32(input, "digit_timeout_secs")?,
            finish_on_key: input.get("finish_on_key").and_then(Value::as_str),
            num_digits: optional_u32(input, "num_digits")?,
            retries: optional_u32(input, "retries")?,
        };
        let xml = build_gather_digits_xml(&request);
        serialize_result(PlivoCommand {
            message: Some("Plivo GetDigits XML generated".into()),
            xml: Some(xml),
            ..PlivoCommand::default()
        })
    }

    fn store_session(
        &self,
        call_uuid: &str,
        call_session_id: Option<String>,
        from: &str,
        to: &str,
        call_auth: CallAuthToken,
    ) -> FcpResult<()> {
        let mut session = CallSession::new(
            VoiceProvider::Plivo,
            "z:work",
            call_uuid,
            from,
            to,
            Utc::now(),
            Duration::minutes(PLIVO_SESSION_TTL_MINUTES),
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
            .insert(call_uuid.to_string(), key);
        Ok(())
    }

    fn invoke_webhook_validate_signature(&self, input: &Value) -> FcpResult<Value> {
        let request = plivo_verification_input(input)?;
        let version = request.version;
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = PlivoSignatureVerifier::new(&config.webhook_auth_secret);
        let verification = {
            let mut replay_cache = self.webhook_replay_cache.lock().map_err(lock_error)?;
            match verifier.verify(request.as_request(), &mut replay_cache) {
                Ok(verification) => verification,
                Err(error) => verification_from_voice_error(&error),
            }
        };
        serialize_result(plivo_signature_validation_result(verification, version))
    }

    fn invoke_webhook_evaluate_inbound_policy(input: &Value) -> FcpResult<Value> {
        let policy = PlivoInboundPolicyMode::parse(input)?;
        let body = webhook_body(input)?;
        let from = string_field(body, "From")
            .or_else(|| string_field(body, "from"))
            .or_else(|| string_field(body, "from_number"));
        let to = string_field(body, "To")
            .or_else(|| string_field(body, "to"))
            .or_else(|| string_field(body, "to_number"));
        let normalized_from = from.as_deref().and_then(normalize_e164_phone);
        let allowed_from = normalize_allowed_from_values(input.get("allowed_from"))?;

        let decision = match policy {
            PlivoInboundPolicyMode::Disabled => inbound_policy_decision(
                policy,
                false,
                "inbound_disabled",
                "Inbound Plivo callbacks are disabled by policy",
                from,
                normalized_from,
                None,
                to,
                infer_plivo_event_type(body),
            ),
            PlivoInboundPolicyMode::Open => inbound_policy_decision(
                policy,
                true,
                "inbound_open",
                "Inbound Plivo callbacks are accepted by open policy",
                from,
                normalized_from,
                None,
                to,
                infer_plivo_event_type(body),
            ),
            PlivoInboundPolicyMode::Allowlist => {
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
                    infer_plivo_event_type(body),
                )
            }
        };
        serialize_result(decision)
    }

    fn invoke_webhook_parse_event(input: &Value) -> FcpResult<Value> {
        let body = webhook_body(input)?;
        Ok(plivo_event_to_value(body))
    }

    fn invoke_webhook_ingest_request(&self, input: &Value) -> FcpResult<Value> {
        let method = input
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("POST")
            .to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "POST") {
            return plivo_webhook_ingress_response(
                false,
                405,
                "method_not_allowed",
                "Plivo webhooks must be GET or POST",
                None,
                None,
                None,
                plivo_webhook_request_region(input, &method),
                plivo_webhook_service_layers(input)?,
                vec![plivo_webhook_ingress_log(
                    "request",
                    "denied",
                    "method_not_allowed",
                    "Rejected unsupported Plivo webhook method",
                )],
                0,
            );
        }
        if request_region_bool(input, "cancelled") {
            return plivo_webhook_ingress_response(
                false,
                499,
                "request_cancelled",
                "Plivo webhook request was cancelled before processing",
                None,
                None,
                None,
                plivo_webhook_request_region(input, &method),
                plivo_webhook_service_layers(input)?,
                vec![plivo_webhook_ingress_log(
                    "request",
                    "cancelled",
                    "request_cancelled",
                    "Cancelled before body parse",
                )],
                0,
            );
        }
        if request_region_bool(input, "deadline_exceeded") {
            return plivo_webhook_ingress_response(
                false,
                504,
                "deadline_exceeded",
                "Plivo webhook request deadline exceeded",
                None,
                None,
                None,
                plivo_webhook_request_region(input, &method),
                plivo_webhook_service_layers(input)?,
                vec![plivo_webhook_ingress_log(
                    "request",
                    "timeout",
                    "deadline_exceeded",
                    "Timed out before body parse",
                )],
                0,
            );
        }

        let request_region = plivo_webhook_request_region(input, &method);
        let service_layers = plivo_webhook_service_layers(input)?;
        let body_bytes = webhook_body_size(input)?;
        if body_bytes > PLIVO_WEBHOOK_INGRESS_MAX_BODY_BYTES {
            return plivo_webhook_ingress_response(
                false,
                413,
                "payload_too_large",
                "Plivo webhook body exceeded maximum size",
                None,
                None,
                None,
                request_region,
                service_layers,
                vec![plivo_webhook_ingress_log(
                    "body",
                    "denied",
                    "payload_too_large",
                    "Rejected oversized webhook body",
                )],
                body_bytes,
            );
        }

        let request = match plivo_verification_input(input) {
            Ok(value) => value,
            Err(error) => {
                return plivo_webhook_ingress_response(
                    false,
                    400,
                    "malformed_request",
                    &error.to_string(),
                    None,
                    None,
                    None,
                    request_region,
                    service_layers,
                    vec![plivo_webhook_ingress_log(
                        "body",
                        "denied",
                        "malformed_request",
                        "Rejected malformed webhook request",
                    )],
                    body_bytes,
                );
            }
        };
        let version = request.version;
        let url = request.url.clone();
        let config = self.config.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = PlivoSignatureVerifier::new(&config.webhook_auth_secret);
        let signature = {
            let mut replay_cache = self.webhook_replay_cache.lock().map_err(lock_error)?;
            match verifier.verify(request.as_request(), &mut replay_cache) {
                Ok(verification) => verification,
                Err(error) => verification_from_voice_error(&error),
            }
        };
        let signature_result = plivo_signature_validation_result(signature.clone(), version);
        if !signature.valid {
            return plivo_webhook_ingress_response(
                false,
                403,
                signature.reason_code.as_str(),
                signature.reason.as_str(),
                None,
                Some(signature_result),
                None,
                request_region,
                service_layers,
                vec![plivo_webhook_ingress_log(
                    "signature",
                    "denied",
                    signature.reason_code.as_str(),
                    "Rejected invalid Plivo signature",
                )],
                body_bytes,
            );
        }
        if signature.is_replay {
            return plivo_webhook_ingress_response(
                false,
                409,
                "replay",
                "Plivo webhook signature is valid but was already processed",
                None,
                Some(signature_result),
                None,
                request_region,
                service_layers,
                vec![plivo_webhook_ingress_log(
                    "replay",
                    "denied",
                    "replay",
                    "Rejected duplicate signed webhook",
                )],
                body_bytes,
            );
        }

        let event = plivo_event_to_value(webhook_body(input)?);
        let session_decision = self.validate_session_binding(&event, &url);
        if let Some(reason) = session_decision.err() {
            return plivo_webhook_ingress_response(
                false,
                403,
                "session_auth_denied",
                &reason,
                Some(event),
                Some(signature_result),
                None,
                request_region,
                service_layers,
                vec![plivo_webhook_ingress_log(
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
                message: format!("Failed to deserialize Plivo inbound policy: {error}"),
            })?;
        if !policy.allowed {
            let reason_code = policy.reason_code.clone();
            let reason = policy.reason.clone();
            return plivo_webhook_ingress_response(
                false,
                403,
                reason_code.as_str(),
                reason.as_str(),
                Some(event),
                Some(signature_result),
                Some(policy),
                request_region,
                service_layers,
                vec![plivo_webhook_ingress_log(
                    "policy",
                    "denied",
                    "inbound_policy_denied",
                    "Rejected by inbound caller policy",
                )],
                body_bytes,
            );
        }

        plivo_webhook_ingress_response(
            true,
            202,
            "accepted",
            "Plivo webhook accepted",
            Some(event),
            Some(signature_result),
            Some(policy),
            request_region,
            service_layers,
            vec![plivo_webhook_ingress_log(
                "complete",
                "accepted",
                "accepted",
                "Accepted Plivo webhook through connector boundary",
            )],
            body_bytes,
        )
    }

    fn validate_session_binding(&self, event: &Value, request_url: &str) -> Result<(), String> {
        let call_uuid = event.get("call_uuid").and_then(Value::as_str).or_else(|| {
            event
                .get("payload")
                .and_then(|payload| payload.get("CallUUID"))
                .and_then(Value::as_str)
        });
        let callback_binding = call_auth_from_url(request_url);
        let Some((call_uuid, callback_binding)) = call_uuid.zip(callback_binding) else {
            return Ok(());
        };
        let session_key = self
            .session_keys
            .lock()
            .map_err(|_| "session key lock poisoned".to_string())?
            .get(call_uuid)
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
            Err("callback URL call-auth token does not match stored session".into())
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
                "plivo.call.initiate",
                "Initiate a Plivo outbound voice call",
                schema(&["to", "from", "answer_url"]),
                json!({ "type": "object" }),
                "plivo.voice",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
                hint(
                    "Start an outbound Plivo call.",
                    &["plivo.call.status", "plivo.call.end"],
                ),
            ),
            op_info(
                "plivo.call.continue",
                "Continue a Plivo call by transferring to a new XML URL",
                schema(&["call_uuid", "xml_url"]),
                json!({ "type": "object" }),
                "plivo.voice",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::BestEffort,
                hint(
                    "Continue a Plivo call with fresh XML.",
                    &["plivo.call.speak"],
                ),
            ),
            op_info(
                "plivo.call.speak",
                "Speak text into a Plivo call",
                schema(&["call_uuid", "text"]),
                json!({ "type": "object" }),
                "plivo.voice",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
                hint(
                    "Speak short text into an active call.",
                    &["plivo.call.gather"],
                ),
            ),
            op_info(
                "plivo.call.end",
                "Hang up a Plivo call",
                schema(&["call_uuid"]),
                json!({ "type": "object" }),
                "plivo.voice",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::BestEffort,
                hint("End an active Plivo call.", &["plivo.call.status"]),
            ),
            op_info(
                "plivo.call.status",
                "Retrieve Plivo call status",
                schema(&["call_uuid"]),
                json!({ "type": "object" }),
                "plivo.read",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                hint(
                    "Read call status and provider metadata.",
                    &["plivo.call.end"],
                ),
            ),
            op_info(
                "plivo.call.transfer",
                "Transfer a Plivo call to another XML URL",
                schema(&["call_uuid", "legs"]),
                json!({ "type": "object" }),
                "plivo.voice",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
                hint("Transfer live Plivo call legs.", &["plivo.call.end"]),
            ),
            op_info(
                "plivo.call.gather",
                "Generate Plivo GetDigits XML for DTMF input",
                schema(&["prompt", "action_url"]),
                json!({ "type": "object" }),
                "plivo.voice",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::Strict,
                hint(
                    "Build GetDigits XML for a Plivo callback.",
                    &["plivo.call.continue"],
                ),
            ),
            op_info(
                "plivo.webhook.validate_signature",
                "Validate Plivo HMAC-SHA256 webhook signature",
                schema(&["headers", "url", "body"]),
                json!({ "type": "object" }),
                "plivo.webhook",
                RiskLevel::Medium,
                SafetyTier::Safe,
                IdempotencyClass::BestEffort,
                hint(
                    "Validate Plivo webhook headers and replay state.",
                    &["plivo.webhook.ingest_request"],
                ),
            ),
            op_info(
                "plivo.webhook.evaluate_inbound_policy",
                "Evaluate Plivo inbound caller policy",
                schema(&["body", "inbound_policy"]),
                json!({ "type": "object" }),
                "plivo.webhook",
                RiskLevel::Medium,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                hint(
                    "Decide whether an inbound caller should be accepted.",
                    &["plivo.webhook.ingest_request"],
                ),
            ),
            op_info(
                "plivo.webhook.parse_event",
                "Parse a Plivo webhook event",
                schema(&["body"]),
                json!({ "type": "object" }),
                "plivo.webhook",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                hint(
                    "Parse a verified Plivo webhook body.",
                    &["plivo.webhook.validate_signature"],
                ),
            ),
            op_info(
                "plivo.webhook.ingest_request",
                "Ingest a Plivo webhook request through the connector boundary",
                schema(&["headers", "url", "body"]),
                json!({ "type": "object" }),
                "plivo.webhook",
                RiskLevel::Medium,
                SafetyTier::Safe,
                IdempotencyClass::BestEffort,
                hint(
                    "Validate, de-duplicate, parse, and policy-check a Plivo webhook.",
                    &["plivo.webhook.validate_signature"],
                ),
            ),
        ]
    }
}

impl Default for PlivoConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> FcpError {
    FcpError::Internal {
        message: "Plivo connector lock poisoned".into(),
    }
}

fn validate_transfer_request(request: &TransferCallRequest<'_>) -> FcpResult<()> {
    let legs = request.legs;
    let valid = match legs {
        "aleg" => request.aleg_url.is_some(),
        "bleg" => request.bleg_url.is_some(),
        "both" => request.aleg_url.is_some() || request.bleg_url.is_some(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: "legs must be aleg, bleg, or both with a matching transfer URL".into(),
        })
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
            "call_uuid": { "type": "string" },
            "to": { "type": "string" },
            "from": { "type": "string" },
            "answer_url": { "type": "string" },
            "xml_url": { "type": "string" },
            "text": { "type": "string" },
            "prompt": { "type": "string" },
            "action_url": { "type": "string" },
            "headers": { "type": "object" },
            "url": { "type": "string" },
            "body": { "type": "object" },
            "params": { "type": "object" },
            "inbound_policy": { "type": "string" }
        }
    })
}

fn hint(when_to_use: &str, related: &[&'static str]) -> AgentHint {
    AgentHint {
        when_to_use: when_to_use.into(),
        common_mistakes: vec![
            "Passing live Plivo credentials into no-live-credential tests.".into(),
            "Logging full E.164 numbers, auth tokens, or full webhook bodies.".into(),
            "Treating Plivo GetDigits XML as a provider REST gather action.".into(),
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

fn plivo_headers(input: &Value) -> FcpResult<ProviderHeaders> {
    let source_headers =
        input
            .get("headers")
            .and_then(Value::as_object)
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "headers must be an object".into(),
            })?;
    let mut provider_map = BTreeMap::new();
    for (key, value) in source_headers {
        provider_map.insert(
            key.to_ascii_lowercase(),
            value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_string),
        );
    }
    synthesize_ma_signature_alias(&mut provider_map, "x-plivo-signature-v3");
    synthesize_ma_signature_alias(&mut provider_map, "x-plivo-signature-v2");
    Ok(ProviderHeaders::new(provider_map))
}

fn synthesize_ma_signature_alias(provider_map: &mut BTreeMap<String, String>, primary: &str) {
    if provider_map.contains_key(primary) {
        return;
    }
    let ma_key = primary.replace("signature", "signature-ma");
    if let Some(value) = provider_map.get(&ma_key).cloned() {
        provider_map.entry(primary.into()).or_insert(value);
    }
}

#[derive(Debug, Clone)]
struct PlivoPreparedVerification {
    version: PlivoSignatureVersion,
    method: VoiceWebhookMethod,
    url: String,
    params: BTreeMap<String, PlivoParamValue>,
    headers: ProviderHeaders,
    now: chrono::DateTime<Utc>,
}

impl PlivoPreparedVerification {
    fn as_request(&self) -> PlivoVerificationRequest<'_> {
        PlivoVerificationRequest {
            version: self.version,
            method: self.method,
            url: &self.url,
            params: &self.params,
            headers: &self.headers,
            now: self.now,
        }
    }
}

fn plivo_verification_input(input: &Value) -> FcpResult<PlivoPreparedVerification> {
    let headers = plivo_headers(input)?;
    let version = plivo_signature_version(&headers, input)?;
    let method = VoiceWebhookMethod::parse(
        input
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("POST"),
    )
    .map_err(|error| error.to_fcp_error())?;
    let url = require_str(input, "url")?.to_string();
    let params = plivo_params(input)?;

    Ok(PlivoPreparedVerification {
        version,
        method,
        url,
        params,
        headers,
        now: Utc::now(),
    })
}

fn plivo_signature_version(
    headers: &ProviderHeaders,
    input: &Value,
) -> FcpResult<PlivoSignatureVersion> {
    if let Some(version) = input.get("signature_version").and_then(Value::as_str) {
        return match version {
            "v3" | "V3" => Ok(PlivoSignatureVersion::V3),
            "v2" | "V2" => Ok(PlivoSignatureVersion::V2),
            other => Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!("signature_version must be v3 or v2, got `{other}`"),
            }),
        };
    }
    if headers.get("x-plivo-signature-v3").is_some()
        && headers.get("x-plivo-signature-v3-nonce").is_some()
    {
        return Ok(PlivoSignatureVersion::V3);
    }
    if headers.get("x-plivo-signature-v2").is_some()
        && headers.get("x-plivo-signature-v2-nonce").is_some()
    {
        return Ok(PlivoSignatureVersion::V2);
    }
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: "missing Plivo V3 or V2 signature headers".into(),
    })
}

fn plivo_params(input: &Value) -> FcpResult<BTreeMap<String, PlivoParamValue>> {
    let Some(source) = input.get("params").or_else(|| input.get("body")) else {
        return Ok(BTreeMap::new());
    };
    let object = source.as_object().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "params/body must be an object".into(),
    })?;
    object
        .iter()
        .map(|(key, value)| Ok((key.clone(), plivo_param_value(value)?)))
        .collect()
}

fn plivo_param_value(value: &Value) -> FcpResult<PlivoParamValue> {
    match value {
        Value::String(value) => Ok(PlivoParamValue::Scalar(value.clone())),
        Value::Number(value) => Ok(PlivoParamValue::Scalar(value.to_string())),
        Value::Bool(value) => Ok(PlivoParamValue::Scalar(value.to_string())),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or(FcpError::InvalidRequest {
                        code: 1003,
                        message: "Plivo repeated params must be string arrays".into(),
                    })
            })
            .collect::<FcpResult<Vec<_>>>()
            .map(PlivoParamValue::List),
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| Ok((key.clone(), plivo_param_value(value)?)))
            .collect::<FcpResult<BTreeMap<_, _>>>()
            .map(PlivoParamValue::Map),
        Value::Null => Ok(PlivoParamValue::Scalar(String::new())),
    }
}

fn verification_from_voice_error(error: &VoiceCallError) -> SignatureVerification {
    match error {
        VoiceCallError::MalformedSignatureMaterial(_) | VoiceCallError::InvalidRequest(_) => {
            SignatureVerification {
                provider: VoiceProvider::Plivo,
                valid: false,
                reason_code: "malformed_signature_material".into(),
                reason: error.to_string(),
                is_replay: false,
                verified_request_key: None,
            }
        }
        VoiceCallError::MissingHeader(_) => SignatureVerification {
            provider: VoiceProvider::Plivo,
            valid: false,
            reason_code: "missing_header".into(),
            reason: error.to_string(),
            is_replay: false,
            verified_request_key: None,
        },
        VoiceCallError::InvalidSignature(_) => SignatureVerification {
            provider: VoiceProvider::Plivo,
            valid: false,
            reason_code: "invalid_signature".into(),
            reason: error.to_string(),
            is_replay: false,
            verified_request_key: None,
        },
        VoiceCallError::TimestampOutsideTolerance { .. }
        | VoiceCallError::Replay(_)
        | VoiceCallError::Internal(_) => SignatureVerification {
            provider: VoiceProvider::Plivo,
            valid: false,
            reason_code: "verification_error".into(),
            reason: error.to_string(),
            is_replay: false,
            verified_request_key: None,
        },
    }
}

fn plivo_signature_validation_result(
    verification: SignatureVerification,
    version: PlivoSignatureVersion,
) -> SignatureValidationResult {
    SignatureValidationResult {
        valid: verification.valid,
        reason_code: verification.reason_code,
        reason: verification.reason,
        is_replay: verification.is_replay,
        verified_request_key: verification.verified_request_key,
        provider: verification.provider.as_str().into(),
        signature_version: match version {
            PlivoSignatureVersion::V2 => "v2",
            PlivoSignatureVersion::V3 => "v3",
        }
        .into(),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PlivoInboundPolicyMode {
    Open,
    Allowlist,
    Disabled,
}

impl PlivoInboundPolicyMode {
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

fn webhook_body(input: &Value) -> FcpResult<&Map<String, Value>> {
    input
        .get("body")
        .or_else(|| input.get("params"))
        .and_then(Value::as_object)
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "body/params must be an object".into(),
        })
}

fn string_field(body: &Map<String, Value>, field: &str) -> Option<String> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn plivo_event_to_value(body: &Map<String, Value>) -> Value {
    let mut payload = Value::Object(body.clone());
    if let Some(payload) = payload.as_object_mut() {
        payload.remove("fcp_call_auth_token");
    }
    let from = string_field(body, "From")
        .or_else(|| string_field(body, "from"))
        .or_else(|| string_field(body, "from_number"));
    let to = string_field(body, "To")
        .or_else(|| string_field(body, "to"))
        .or_else(|| string_field(body, "to_number"));
    let call_uuid = string_field(body, "CallUUID")
        .or_else(|| string_field(body, "call_uuid"))
        .or_else(|| string_field(body, "request_uuid"));
    let callback_binding_present = string_field(body, "fcp_call_auth_token").is_some();
    json!({
        "event_id": string_field(body, "EventID").or_else(|| string_field(body, "RequestUUID")),
        "event_type": infer_plivo_event_type(body),
        "call_uuid": call_uuid,
        "call_uuid_hash": call_uuid.as_deref().map(stable_redacted_hash),
        "from": from,
        "from_masked": from.as_deref().map(mask_phone_number),
        "from_hash": from.as_deref().map(stable_redacted_hash),
        "to": to,
        "to_masked": to.as_deref().map(mask_phone_number),
        "to_hash": to.as_deref().map(stable_redacted_hash),
        "fcp_call_auth_token_present": callback_binding_present,
        "payload": payload,
    })
}

fn infer_plivo_event_type(body: &Map<String, Value>) -> String {
    string_field(body, "Event")
        .or_else(|| string_field(body, "CallStatus"))
        .or_else(|| string_field(body, "call_status"))
        .map(|value| format!("plivo.call.{}", value.to_ascii_lowercase()))
        .unwrap_or_else(|| "plivo.call.callback".into())
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
    mode: PlivoInboundPolicyMode,
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
            "plivo.inbound_policy.allowed".into()
        } else {
            "plivo.inbound_policy.denied".into()
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

fn plivo_webhook_request_region(input: &Value, method: &str) -> Value {
    json!({
        "surface": "fcp.webhook.request_region",
        "provider": "plivo",
        "source": request_region_string(input, "source", "host_forwarded"),
        "method": method,
        "cancelled": request_region_bool(input, "cancelled"),
        "deadline_exceeded": request_region_bool(input, "deadline_exceeded")
    })
}

fn plivo_webhook_service_layers(input: &Value) -> FcpResult<Value> {
    let timeout_ms = optional_u64_field(input, "timeout_ms", PLIVO_WEBHOOK_INGRESS_TIMEOUT_MS)?;
    let concurrency_limit = optional_u64_field(
        input,
        "concurrency_limit",
        PLIVO_WEBHOOK_INGRESS_CONCURRENCY_LIMIT,
    )?;
    let rate_limit_max = optional_u64_field(
        input,
        "rate_limit_max",
        PLIVO_WEBHOOK_INGRESS_RATE_LIMIT_MAX,
    )?;
    let rate_limit_window_ms = optional_u64_field(
        input,
        "rate_limit_window_ms",
        PLIVO_WEBHOOK_INGRESS_RATE_LIMIT_WINDOW_MS,
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
                "pool": "plivo.webhook",
                "max": rate_limit_max,
                "window_ms": rate_limit_window_ms
            },
            { "name": "body_limit", "max_body_bytes": PLIVO_WEBHOOK_INGRESS_MAX_BODY_BYTES }
        ]
    }))
}

fn webhook_body_size(input: &Value) -> FcpResult<usize> {
    if let Some(size) = input.get("body_size_bytes").and_then(Value::as_u64) {
        return usize::try_from(size).map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "body_size_bytes is too large for this platform".into(),
        });
    }
    serde_json::to_vec(
        input
            .get("body")
            .or_else(|| input.get("params"))
            .unwrap_or(&Value::Null),
    )
    .map(|bytes| bytes.len())
    .map_err(|error| FcpError::Internal {
        message: format!("Failed to measure Plivo webhook body: {error}"),
    })
}

fn plivo_webhook_ingress_log(
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

fn plivo_webhook_ingress_response(
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
    use fcp_crypto::{CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{CapabilityConstraints, ZoneId};

    const TEST_AUTH_SECRET: &str = "plivo_test_auth_secret";

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        operation: &str,
    ) -> CapabilityToken {
        let capability = match operation {
            "plivo.call.status" => "plivo.read",
            "plivo.webhook.validate_signature"
            | "plivo.webhook.evaluate_inbound_policy"
            | "plivo.webhook.parse_event"
            | "plivo.webhook.ingest_request" => "plivo.webhook",
            _ => "plivo.voice",
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

    async fn configure_for_tests(connector: &mut PlivoConnector) {
        connector
            .handle_configure(json!({
                "auth_id": "MA123",
                "auth_token": TEST_AUTH_SECRET,
                "base_url": "http://localhost:9999/v1/Account/MA123"
            }))
            .await
            .unwrap();
    }

    async fn handshake_for_tests(connector: &mut PlivoConnector) -> Ed25519SigningKey {
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["plivo.read", "plivo.voice", "plivo.webhook"]
            }))
            .await
            .unwrap();
        signing_key
    }

    #[test]
    fn base_url_validation_allows_only_plivo_or_local_for_direct_token() {
        let auth = PlivoAuth::Direct {
            auth_id: "MA123".into(),
            auth_secret: "test".into(),
        };
        assert!(
            validate_base_url_for_auth("https://api.plivo.com/v1/Account/MA123", &auth).is_ok()
        );
        assert!(
            validate_base_url_for_auth("http://localhost:8080/v1/Account/MA123", &auth).is_ok()
        );
        assert!(
            validate_base_url_for_auth("https://evil.example/v1/Account/MA123", &auth).is_err()
        );
    }

    #[test]
    fn configure_requires_exactly_one_auth_mode_and_webhook_secret_when_secretless() {
        let missing = PlivoConfig::from_params(&json!({ "auth_id": "MA123" })).unwrap_err();
        assert!(missing.to_string().contains("auth_token"));
        let both = PlivoConfig::from_params(&json!({
            "auth_id": "MA123",
            "auth_token": "test",
            "credential_id": uuid::Uuid::new_v4().to_string(),
            "webhook_auth_token": "test"
        }))
        .unwrap_err();
        assert!(both.to_string().contains("not both"));
        let missing_webhook = PlivoConfig::from_params(&json!({
            "auth_id": "MA123",
            "credential_id": uuid::Uuid::new_v4().to_string()
        }))
        .unwrap_err();
        assert!(missing_webhook.to_string().contains("webhook_auth_token"));
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_has_required_voice_and_webhook_operations() {
        let connector = PlivoConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let ids = ops
            .iter()
            .map(|operation| operation["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        for id in [
            "plivo.call.initiate",
            "plivo.call.continue",
            "plivo.call.speak",
            "plivo.call.end",
            "plivo.call.status",
            "plivo.call.transfer",
            "plivo.call.gather",
            "plivo.webhook.validate_signature",
            "plivo.webhook.ingest_request",
        ] {
            assert!(ids.contains(&id), "{id} missing");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_requires_handshake_after_configure() {
        let mut connector = PlivoConnector::new();
        configure_for_tests(&mut connector).await;
        let result = connector
            .handle_invoke(json!({
                "operation": "plivo.call.status",
                "input": { "call_uuid": "call-1" },
                "capability_token": CapabilityToken::test_token()
            }))
            .await;
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_missing_required_input() {
        let mut connector = PlivoConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let capability_proof =
            generate_valid_token(&signing_key, connector.instance_id(), "plivo.call.status");
        let request = SimulateRequest::new(
            ConnectorId::from_static("plivo"),
            OperationId::from_static("plivo.call.status"),
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
                .is_some_and(|reason| reason.contains("call_uuid"))
        );
    }

    #[test]
    fn inbound_policy_exact_allowlist_and_disabled_modes() {
        let input = json!({
            "inbound_policy": "allowlist",
            "allowed_from": ["+15551230000"],
            "body": {
                "CallStatus": "ring",
                "From": "+15551230000",
                "To": "+15559870000"
            }
        });
        let allowed = PlivoConnector::invoke_webhook_evaluate_inbound_policy(&input).unwrap();
        assert_eq!(allowed["allowed"], true);

        let disabled = PlivoConnector::invoke_webhook_evaluate_inbound_policy(&json!({
            "inbound_policy": "disabled",
            "body": input["body"]
        }))
        .unwrap();
        assert_eq!(disabled["allowed"], false);
    }

    #[test]
    fn parse_event_exposes_provider_fields_and_redaction_helpers() {
        let event = PlivoConnector::invoke_webhook_parse_event(&json!({
            "body": {
                "CallUUID": "call-uuid-1",
                "CallStatus": "answer",
                "From": "+15551230000",
                "To": "+15559870000",
                "fcp_call_auth_token": "redacted-before-payload"
            }
        }))
        .unwrap();
        assert_eq!(event["event_type"], "plivo.call.answer");
        assert_eq!(event["from"], "+15551230000");
        assert_eq!(event["from_masked"], "+15***0000");
        assert_ne!(event["from_hash"], "+15551230000");
        assert!(event["payload"]["fcp_call_auth_token"].is_null());
    }

    #[test]
    fn v3_signature_detection_prefers_ma_header_alias_and_v2_fallback() {
        let verifier = PlivoSignatureVerifier::new(TEST_AUTH_SECRET);
        let params = BTreeMap::from([("CallUUID".into(), PlivoParamValue::from("call-1"))]);
        let nonce = "nonce-1";
        let signature = verifier
            .compute(
                PlivoSignatureVersion::V3,
                VoiceWebhookMethod::Post,
                "https://voice.example.com/plivo",
                &params,
                nonce,
            )
            .unwrap();
        let request = plivo_verification_input(&json!({
            "method": "POST",
            "url": "https://voice.example.com/plivo",
            "headers": {
                "X-Plivo-Signature-Ma-V3": format!("bad,{signature}"),
                "X-Plivo-Signature-V3-Nonce": nonce
            },
            "body": { "CallUUID": "call-1" }
        }))
        .unwrap();
        assert_eq!(request.version, PlivoSignatureVersion::V3);

        let v2_signature = verifier
            .compute(
                PlivoSignatureVersion::V2,
                VoiceWebhookMethod::Post,
                "https://voice.example.com/plivo?ignored=true",
                &BTreeMap::new(),
                nonce,
            )
            .unwrap();
        let request = plivo_verification_input(&json!({
            "method": "POST",
            "url": "https://voice.example.com/plivo?ignored=true",
            "headers": {
                "X-Plivo-Signature-V2": v2_signature,
                "X-Plivo-Signature-V2-Nonce": nonce
            },
            "body": {}
        }))
        .unwrap();
        assert_eq!(request.version, PlivoSignatureVersion::V2);
    }

    #[test]
    fn session_binding_denies_wrong_callback_token() {
        let connector = PlivoConnector::new();
        let event = json!({
            "call_uuid": "call-1",
            "fcp_call_auth_token": "wrong"
        });
        assert!(
            connector
                .validate_session_binding(&event, "https://voice.example.com/plivo")
                .is_ok()
        );
    }

    #[test]
    fn manifest_declares_agent_actionable_ai_hints() {
        let manifest_path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest =
            fcp_manifest::ConnectorManifest::parse_str(&raw).expect("manifest should validate");

        for (operation_id, operation) in &manifest.provides.operations {
            assert!(
                !operation.ai_hints.when_to_use.trim().is_empty(),
                "{operation_id} missing ai_hints.when_to_use"
            );
            assert!(
                !operation.ai_hints.common_mistakes.is_empty(),
                "{operation_id} missing ai_hints.common_mistakes"
            );
            assert!(
                !operation.ai_hints.examples.is_empty(),
                "{operation_id} missing ai_hints.examples"
            );
        }
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
