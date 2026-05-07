//! FCP Whisper Connector implementation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::{sync::Arc, time::Duration};

use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityId, CapabilityVerifier, ConnectorId, CredentialId,
    FcpError, FcpResult, HandshakeRequest, IdempotencyClass, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SimulateRequest, SimulateResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::{DEFAULT_BASE_URL, DEFAULT_REQUEST_TIMEOUT, WhisperAuth, WhisperClient},
    error::WhisperError,
};

/// Maximum audio file size in bytes (25 MB limit).
const MAX_FILE_SIZE_BYTES: u64 = 25 * 1024 * 1024;

/// Supported audio file extensions.
const SUPPORTED_FORMATS: &[(&str, &str, &str)] = &[
    ("mp3", "audio/mpeg", "MPEG Audio Layer 3"),
    ("mp4", "video/mp4", "MPEG-4 Part 14"),
    ("mpeg", "video/mpeg", "MPEG Video"),
    ("mpga", "audio/mpeg", "MPEG Audio"),
    ("m4a", "audio/mp4", "MPEG-4 Audio"),
    ("wav", "audio/wav", "Waveform Audio"),
    ("webm", "audio/webm", "WebM Audio"),
    ("flac", "audio/flac", "Free Lossless Audio Codec"),
    ("ogg", "audio/ogg", "Ogg Vorbis"),
];

/// Parsed and validated Whisper connector configuration.
#[derive(Debug, Clone)]
struct WhisperConfig {
    auth: WhisperAuth,
    base_url: String,
    request_timeout: Duration,
}

impl WhisperConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let api_key = params
            .get("api_key")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let credential_id = match params.get("credential_id") {
            Some(value) => {
                let raw = value.as_str().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "credential_id must be a string".into(),
                })?;
                Some(
                    CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?,
                )
            }
            None => None,
        };

        let auth = match (api_key, credential_id) {
            (Some(key), None) => WhisperAuth::ApiKey(key),
            (None, Some(cred_id)) => WhisperAuth::CredentialId(cred_id),
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide exactly one of api_key or credential_id".into(),
                });
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing api_key or credential_id in configuration".into(),
                });
            }
        };

        let base_url = params
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(DEFAULT_BASE_URL)
            .to_string();

        let request_timeout = match params.get("request_timeout_ms") {
            Some(value) => {
                let timeout_ms = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
                    code: 1003,
                    message: "request_timeout_ms must be an integer".into(),
                })?;
                if timeout_ms == 0 {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: "request_timeout_ms must be greater than zero".into(),
                    });
                }
                let timeout = Duration::from_millis(timeout_ms);
                if timeout > DEFAULT_REQUEST_TIMEOUT {
                    return Err(FcpError::InvalidRequest {
                        code: 1003,
                        message: format!(
                            "request_timeout_ms must be at most {}",
                            DEFAULT_REQUEST_TIMEOUT.as_millis()
                        ),
                    });
                }
                timeout
            }
            None => DEFAULT_REQUEST_TIMEOUT,
        };

        Ok(Self {
            auth,
            base_url,
            request_timeout,
        })
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    #[must_use]
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self { status, checks }
    }
}

/// FCP Whisper Connector.
pub struct WhisperConnector {
    base: Arc<BaseConnector>,
    config: Option<WhisperConfig>,
    client: Option<Arc<WhisperClient>>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<String>,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

impl WhisperConnector {
    /// Create a new Whisper connector.
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("whisper"))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }
}

impl Default for WhisperConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl WhisperConnector {
    /// Runtime instance identifier used for host-minted capability binding.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    /// Handle the `configure` method.
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = WhisperConfig::from_params(&params)?;
        info!(auth = %config.auth.redacted_label(), base_url = %config.base_url, "Configuring Whisper connector");

        let client = WhisperClient::new_with_timeout(
            config.auth.clone(),
            Some(&config.base_url),
            config.request_timeout,
        )
        .map_err(|e| e.to_fcp_error())?;

        self.client = Some(Arc::new(client));
        self.config = Some(config);
        self.base.set_configured(true);
        Ok(json!({}))
    }

    /// Handle the `handshake` method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.config.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: "Connector not configured".into(),
            });
        }

        let canonical_session =
            if let Ok(req) = serde_json::from_value::<HandshakeRequest>(params.clone()) {
                self.verifier = Some(CapabilityVerifier::new(
                    req.host_public_key,
                    req.zone,
                    self.base.instance_id.clone(),
                ));
                Some(format!("session-{}", self.base.instance_id.as_str()))
            } else {
                None
            };

        let session_id = params
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .or(canonical_session);

        self.session_id = session_id;
        self.base.set_handshaken(true);

        Ok(json!({
            "protocol_version": "2.0",
            "connector_id": "fcp.whisper",
            "connector_version": "0.1.0",
            "capabilities": [
                "whisper.transcribe",
                "whisper.translate",
                "whisper.detect_language",
                "whisper.transcribe_verbose",
                "whisper.list_models",
                "whisper.health",
                "whisper.usage",
                "whisper.formats"
            ]
        }))
    }

    /// Handle the `health` method.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.config.is_some();
        let handshaken = self.session_id.is_some();

        let status = if configured && handshaken {
            "healthy"
        } else if configured {
            "degraded"
        } else {
            "unconfigured"
        };

        Ok(json!({
            "status": status,
            "configured": configured,
            "handshaken": handshaken,
            "requests": self.request_count.load(Ordering::Relaxed),
            "errors": self.error_count.load(Ordering::Relaxed),
        }))
    }

    /// Handle the `doctor` method.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_none() {
                Some("Not configured — call configure first".into())
            } else {
                None
            },
            critical: true,
        });

        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_none() {
                Some("API client not initialized".into())
            } else {
                None
            },
            critical: true,
        });

        let handshaken = self.session_id.is_some();
        checks.push(DoctorCheck {
            name: "handshake".into(),
            passed: handshaken,
            message: if handshaken {
                None
            } else {
                Some("Handshake not completed".into())
            },
            critical: false,
        });

        let result = DoctorResult::from_checks(checks);
        Ok(serde_json::to_value(result).unwrap_or_else(|_| json!({"status": "error"})))
    }

    /// Handle the `self_check` method.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        Ok(json!({
            "connector_id": "fcp.whisper",
            "version": "0.1.0",
            "status": if self.config.is_some() { "ok" } else { "degraded" },
        }))
    }

    /// Handle the `introspect` method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let ops = typed_operations_info();
        Ok(json!({
            "connector_id": "fcp.whisper",
            "version": "0.1.0",
            "operations": serde_json::to_value(&ops).unwrap_or_default(),
        }))
    }

    /// Handle the `invoke` method.
    #[instrument(skip(self, params))]
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        self.base.check_ready()?;

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1003,
                message: "Missing operation_id".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "Client not initialized".into(),
        })?;

        let result = match operation {
            "whisper.transcribe" => self.invoke_transcribe(client, &input).await,
            "whisper.translate" => self.invoke_translate(client, &input).await,
            "whisper.detect_language" => self.invoke_detect_language(client, &input).await,
            "whisper.transcribe_verbose" => self.invoke_transcribe_verbose(client, &input).await,
            "whisper.list_models" => self.invoke_list_models(&input).await,
            "whisper.health" => self.invoke_health_check(client).await,
            "whisper.usage" => self.invoke_usage(&input).await,
            "whisper.formats" => self.invoke_formats(&input).await,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1002,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        result.map_err(|e| {
            self.error_count.fetch_add(1, Ordering::Relaxed);
            e.to_fcp_error()
        })
    }

    /// Handle the `simulate` method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        if let Ok(req) = serde_json::from_value::<SimulateRequest>(params.clone()) {
            return self.handle_canonical_simulate(req);
        }

        let operation = params
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let allowed = required_capability_for_operation(operation).is_ok();

        Ok(json!({
            "allowed": allowed,
            "reason": if allowed { "Operation supported" } else { "Unknown operation" },
        }))
    }

    fn handle_canonical_simulate(&self, req: SimulateRequest) -> FcpResult<serde_json::Value> {
        let capability = match required_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return serde_json::to_value(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ))
                .map_err(|error| FcpError::Internal {
                    message: format!("Failed to serialize simulate denial: {error}"),
                });
            }
        };
        if self.client.is_none() {
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ))
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize simulate denial: {error}"),
            });
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return serde_json::to_value(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ))
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize simulate denial: {error}"),
            });
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let denial_code = error.error_code();
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), denial_code.as_str());
            if denial_code == "FCP-3001" || denial_code == "FCP-3003" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return serde_json::to_value(response).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize simulate denial: {error}"),
            });
        }
        serde_json::to_value(SimulateResponse::allowed(req.id)).map_err(|error| {
            FcpError::Internal {
                message: format!("Failed to serialize simulate response: {error}"),
            }
        })
    }

    /// Handle the `shutdown` method.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Whisper connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({}))
    }

    // -- Operation implementations --

    async fn invoke_transcribe(
        &self,
        client: &WhisperClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WhisperError> {
        validate_audio_input(input)?;

        let body = json!({
            "model": input.get("model").and_then(serde_json::Value::as_str).unwrap_or("whisper-1"),
            "audio_base64": input.get("audio_base64"),
            "audio_url": input.get("audio_url"),
            "language": input.get("language"),
            "response_format": input.get("response_format").and_then(serde_json::Value::as_str).unwrap_or("json"),
            "temperature": input.get("temperature"),
        });

        let result = client.transcribe(body).await?;
        Ok(json!({
            "text": result.get("text").unwrap_or(&serde_json::Value::Null),
            "language": result.get("language").unwrap_or(&serde_json::Value::Null),
            "duration_seconds": result.get("duration").unwrap_or(&serde_json::Value::Null),
            "segments": result.get("segments").unwrap_or(&json!([])),
        }))
    }

    async fn invoke_translate(
        &self,
        client: &WhisperClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WhisperError> {
        validate_audio_input(input)?;

        let body = json!({
            "model": input.get("model").and_then(serde_json::Value::as_str).unwrap_or("whisper-1"),
            "audio_base64": input.get("audio_base64"),
            "audio_url": input.get("audio_url"),
            "temperature": input.get("temperature"),
        });

        let result = client.translate(body).await?;
        Ok(json!({
            "text": result.get("text").unwrap_or(&serde_json::Value::Null),
            "source_language": result.get("language").unwrap_or(&serde_json::Value::Null),
            "duration_seconds": result.get("duration").unwrap_or(&serde_json::Value::Null),
        }))
    }

    async fn invoke_detect_language(
        &self,
        client: &WhisperClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WhisperError> {
        validate_audio_input(input)?;

        let body = json!({
            "model": input.get("model").and_then(serde_json::Value::as_str).unwrap_or("whisper-1"),
            "audio_base64": input.get("audio_base64"),
            "audio_url": input.get("audio_url"),
            "response_format": "verbose_json",
        });

        let result = client.transcribe(body).await?;
        Ok(json!({
            "language": result.get("language").unwrap_or(&serde_json::Value::Null),
            "confidence": result.get("confidence").unwrap_or(&serde_json::Value::Null),
        }))
    }

    async fn invoke_transcribe_verbose(
        &self,
        client: &WhisperClient,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, WhisperError> {
        validate_audio_input(input)?;

        let body = json!({
            "model": input.get("model").and_then(serde_json::Value::as_str).unwrap_or("whisper-1"),
            "audio_base64": input.get("audio_base64"),
            "audio_url": input.get("audio_url"),
            "language": input.get("language"),
            "response_format": "verbose_json",
            "timestamp_granularities": ["word", "segment"],
            "temperature": input.get("temperature"),
        });

        let result = client.transcribe(body).await?;
        Ok(json!({
            "text": result.get("text").unwrap_or(&serde_json::Value::Null),
            "language": result.get("language").unwrap_or(&serde_json::Value::Null),
            "duration": result.get("duration").unwrap_or(&serde_json::Value::Null),
            "segments": result.get("segments").unwrap_or(&json!([])),
            "words": result.get("words").unwrap_or(&json!([])),
        }))
    }

    async fn invoke_list_models(
        &self,
        _input: &serde_json::Value,
    ) -> Result<serde_json::Value, WhisperError> {
        Ok(json!({
            "models": [
                {
                    "id": "whisper-1",
                    "name": "Whisper V2",
                    "description": "General-purpose speech recognition model",
                    "max_file_size_mb": 25,
                    "supported_languages": 97
                },
                {
                    "id": "whisper-large-v3",
                    "name": "Whisper Large V3",
                    "description": "Latest large Whisper model with improved accuracy",
                    "max_file_size_mb": 25,
                    "supported_languages": 97
                }
            ]
        }))
    }

    async fn invoke_health_check(
        &self,
        client: &WhisperClient,
    ) -> Result<serde_json::Value, WhisperError> {
        match client.list_models().await {
            Ok(_) => Ok(json!({
                "status": "ok",
                "api_reachable": true,
            })),
            Err(e) => Ok(json!({
                "status": "error",
                "api_reachable": false,
                "error": e.to_string(),
            })),
        }
    }

    async fn invoke_usage(
        &self,
        _input: &serde_json::Value,
    ) -> Result<serde_json::Value, WhisperError> {
        Ok(json!({
            "total_requests": self.request_count.load(Ordering::Relaxed),
            "total_errors": self.error_count.load(Ordering::Relaxed),
            "note": "Detailed usage statistics require the OpenAI dashboard",
        }))
    }

    async fn invoke_formats(
        &self,
        _input: &serde_json::Value,
    ) -> Result<serde_json::Value, WhisperError> {
        let formats: Vec<serde_json::Value> = SUPPORTED_FORMATS
            .iter()
            .map(|(ext, mime, desc)| {
                json!({
                    "extension": ext,
                    "mime_type": mime,
                    "description": desc,
                })
            })
            .collect();
        Ok(json!({ "formats": formats, "max_file_size_mb": 25 }))
    }
}

/// Validate that at least one audio input source is provided.
fn validate_audio_input(input: &serde_json::Value) -> Result<(), WhisperError> {
    let has_base64 = input
        .get("audio_base64")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty());

    let has_url = input
        .get("audio_url")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty());

    if !has_base64 && !has_url {
        return Err(WhisperError::InvalidAudio(
            "Provide either audio_base64 or audio_url".into(),
        ));
    }

    // Check file size if base64 is provided (rough estimate: base64 is ~4/3 of original)
    if let Some(b64) = input
        .get("audio_base64")
        .and_then(serde_json::Value::as_str)
    {
        let estimated_bytes = (b64.len() as u64) * 3 / 4;
        if estimated_bytes > MAX_FILE_SIZE_BYTES {
            return Err(WhisperError::FileTooLarge {
                size_bytes: estimated_bytes,
                max_bytes: MAX_FILE_SIZE_BYTES,
            });
        }
    }

    Ok(())
}

fn required_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "whisper.transcribe" | "whisper.detect_language" | "whisper.transcribe_verbose" => {
            Ok(CapabilityId::from_static("whisper.transcription"))
        }
        "whisper.translate" => Ok(CapabilityId::from_static("whisper.translation")),
        "whisper.list_models" | "whisper.health" | "whisper.usage" | "whisper.formats" => {
            Ok(CapabilityId::from_static("whisper.info"))
        }
        _ => Err(FcpError::InvalidRequest {
            code: 1004,
            message: format!("Unknown operation: {operation}"),
        }),
    }
}

/// Build the typed operations info for introspection.
#[allow(clippy::too_many_lines)]
fn typed_operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static("whisper.transcribe"),
            summary: "Transcribe audio to text".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "audio_base64": { "type": "string", "description": "Base64-encoded audio data" },
                    "audio_url": { "type": "string", "description": "URL to audio file" },
                    "model": { "type": "string", "description": "Model to use (default: whisper-1)" },
                    "language": { "type": "string", "description": "Language code (ISO 639-1)" },
                    "response_format": { "type": "string", "description": "Output format (json, text, srt, verbose_json, vtt)" },
                    "temperature": { "type": "number", "description": "Sampling temperature (0.0-1.0)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Transcribed text" },
                    "language": { "type": "string", "description": "Detected language" },
                    "duration_seconds": { "type": "number", "description": "Audio duration in seconds" },
                    "segments": { "type": "array", "description": "Transcription segments" }
                }
            }),
            capability: CapabilityId::from_static("whisper.transcription"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to convert audio speech to text in the original language".into(),
                common_mistakes: vec![
                    "Provide either audio_base64 or audio_url, not both".into(),
                ],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("whisper.translate"),
                    CapabilityId::from_static("whisper.transcribe_verbose"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("whisper.translate"),
            summary: "Translate audio to English text".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "audio_base64": { "type": "string", "description": "Base64-encoded audio data" },
                    "audio_url": { "type": "string", "description": "URL to audio file" },
                    "model": { "type": "string", "description": "Model to use (default: whisper-1)" },
                    "temperature": { "type": "number", "description": "Sampling temperature (0.0-1.0)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Translated English text" },
                    "source_language": { "type": "string", "description": "Detected source language" },
                    "duration_seconds": { "type": "number", "description": "Audio duration in seconds" }
                }
            }),
            capability: CapabilityId::from_static("whisper.translation"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to translate non-English audio directly to English text".into(),
                common_mistakes: vec![
                    "This always translates to English; use transcribe for same-language output".into(),
                ],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("whisper.transcribe"),
                    CapabilityId::from_static("whisper.detect_language"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("whisper.detect_language"),
            summary: "Detect the language of audio".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "audio_base64": { "type": "string", "description": "Base64-encoded audio data" },
                    "audio_url": { "type": "string", "description": "URL to audio file" },
                    "model": { "type": "string", "description": "Model to use (default: whisper-1)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "language": { "type": "string", "description": "Detected language code" },
                    "confidence": { "type": "number", "description": "Detection confidence score" }
                }
            }),
            capability: CapabilityId::from_static("whisper.transcription"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to identify the spoken language before transcribing or translating".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("whisper.transcribe"),
                    CapabilityId::from_static("whisper.translate"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("whisper.transcribe_verbose"),
            summary: "Transcribe audio with word-level timestamps".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "audio_base64": { "type": "string", "description": "Base64-encoded audio data" },
                    "audio_url": { "type": "string", "description": "URL to audio file" },
                    "model": { "type": "string", "description": "Model to use (default: whisper-1)" },
                    "language": { "type": "string", "description": "Language code (ISO 639-1)" },
                    "temperature": { "type": "number", "description": "Sampling temperature (0.0-1.0)" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Transcribed text" },
                    "language": { "type": "string", "description": "Detected language" },
                    "duration": { "type": "number", "description": "Audio duration in seconds" },
                    "segments": { "type": "array", "description": "Transcription segments" },
                    "words": { "type": "array", "description": "Word-level timestamps" }
                }
            }),
            capability: CapabilityId::from_static("whisper.transcription"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use when you need word-level timestamps and segment boundaries in the transcription".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("whisper.transcribe"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("whisper.list_models"),
            summary: "List available Whisper models".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "models": { "type": "array", "description": "Available Whisper models" }
                }
            }),
            capability: CapabilityId::from_static("whisper.info"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to discover which Whisper models are available".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("whisper.transcribe"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("whisper.health"),
            summary: "Check API connectivity".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string", "description": "API health status" },
                    "api_reachable": { "type": "boolean", "description": "Whether the API is reachable" }
                }
            }),
            capability: CapabilityId::from_static("whisper.info"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to verify the Whisper API is reachable before making requests".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("whisper.usage"),
            summary: "Get usage statistics".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "total_requests": { "type": "integer", "description": "Total requests made" },
                    "total_errors": { "type": "integer", "description": "Total errors encountered" }
                }
            }),
            capability: CapabilityId::from_static("whisper.info"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to check how many requests and errors have occurred in this session".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: None,
        },
        OperationInfo {
            id: OperationId::from_static("whisper.formats"),
            summary: "List supported audio formats".into(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "formats": { "type": "array", "description": "Supported audio formats" },
                    "max_file_size_mb": { "type": "integer", "description": "Maximum file size in MB" }
                }
            }),
            capability: CapabilityId::from_static("whisper.info"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Use to check which audio file formats and sizes are supported".into(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![
                    CapabilityId::from_static("whisper.transcribe"),
                ],
            },
            rate_limit: None,
            requires_approval: None,
        },
    ]
}

/// Build the operations info as JSON for simulate compatibility.
fn operations_info() -> serde_json::Value {
    serde_json::to_value(typed_operations_info()).unwrap_or_default()
}
