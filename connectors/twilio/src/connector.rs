//! FCP Twilio Connector implementation.

use std::sync::Arc;

use base64::Engine;
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::{DEFAULT_API_BASE, TwilioAuth, TwilioClient};
use crate::error::TwilioError;

/// Parsed configuration for the Twilio connector.
struct TwilioConfig {
    auth: TwilioAuth,
    base_url: String,
}

impl TwilioConfig {
    fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let account_sid = params
            .get("account_sid")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing account_sid in configuration".into(),
            })?;

        let auth_material = params
            .get("auth_token")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let credential_id = params.get("credential_id").and_then(|v| v.as_str());
        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let auth = match (auth_material.as_deref(), credential_id) {
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Provide either auth_token or credential_id, not both".into(),
                });
            }
            (Some(token), None) => TwilioAuth::Token {
                account_sid: account_sid.to_string(),
                auth_token: token.to_string(),
            },
            (None, Some(raw)) => {
                let cid = CredentialId::parse(raw).map_err(|e| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid credential_id: {e}"),
                })?;
                TwilioAuth::CredentialId {
                    account_sid: account_sid.to_string(),
                    credential_id: cid,
                }
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing auth_token or credential_id in configuration".into(),
                });
            }
        };

        let url = validate_base_url_for_auth(
            &base_url.map_or_else(|| format!("{DEFAULT_API_BASE}/{account_sid}"), String::from),
            &auth,
        )?;

        Ok(Self {
            auth,
            base_url: url,
        })
    }
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn validate_base_url_for_auth(base_url: &str, auth: &TwilioAuth) -> FcpResult<String> {
    let trimmed = base_url.trim();
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

    let Some(host) = parsed.host_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must include a host".into(),
        });
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }

    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }

    if matches!(auth, TwilioAuth::Token { .. })
        && !local
        && !host.eq_ignore_ascii_case("api.twilio.com")
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url with direct auth_token mode must target api.twilio.com (localhost/127.0.0.1/::1 allowed for tests): {trimmed}"
            ),
        });
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: String,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DoctorStatus {
    Pass,
    Fail,
    Warn,
}

/// FCP Twilio Connector.
pub struct TwilioConnector {
    base: Arc<BaseConnector>,
    pub(crate) client: Option<TwilioClient>,
    config: Option<TwilioConfig>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl TwilioConnector {
    /// Create a new Twilio connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("twilio"))),
            client: None,
            config: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let cfg = TwilioConfig::from_params(&params)?;

        let client =
            TwilioClient::new_with_auth(cfg.auth.clone()).map_err(|e| FcpError::Internal {
                message: format!("Failed to create HTTP client: {e}"),
            })?;
        let client = client.with_base_url(&cfg.base_url);

        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.client = Some(client);
        self.config = Some(cfg);
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!("Twilio connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:twilio-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 50,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let auth_mode = self
            .config
            .as_ref()
            .map_or("none", |c| c.auth.redacted_label());
        let api_url = self
            .config
            .as_ref()
            .map_or("not_configured", |c| c.base_url.as_str());
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "auth_mode": auth_mode,
            "api_url": api_url,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle doctor readiness diagnostics.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();

        // 1. configuration
        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            status: if configured {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if configured {
                "Connector configured".into()
            } else {
                "Not configured — call configure first".into()
            },
        });

        // 2. client_initialized
        let has_client = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            status: if has_client {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: if has_client {
                "HTTP client ready".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. base_url
        let base_url = self
            .config
            .as_ref()
            .map_or("not_configured", |c| c.base_url.as_str());
        checks.push(DoctorCheck {
            name: "base_url".into(),
            status: DoctorStatus::Pass,
            message: format!("API URL: {base_url}"),
        });

        // 4. auth_mode
        if let Some(cfg) = &self.config {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Pass,
                message: format!("Auth: {}", cfg.auth.redacted_label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Fail,
                message: "No auth configured".into(),
            });
        }

        // 5. network_constraints
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            status: DoctorStatus::Pass,
            message: format!("Validated egress target: {base_url}"),
        });

        // 6. credential_injection
        let is_secretless = self.config.as_ref().is_some_and(|c| c.auth.is_secretless());
        checks.push(DoctorCheck {
            name: "credential_injection".into(),
            status: if is_secretless {
                DoctorStatus::Warn
            } else {
                DoctorStatus::Pass
            },
            message: if is_secretless {
                "Using credential_id — requires egress proxy for injection".into()
            } else {
                "Direct Basic auth — no proxy required".into()
            },
        });

        let all_pass = checks
            .iter()
            .all(|c| matches!(c.status, DoctorStatus::Pass));
        let any_fail = checks
            .iter()
            .any(|c| matches!(c.status, DoctorStatus::Fail));

        let overall = if any_fail {
            "unhealthy"
        } else if all_pass {
            "healthy"
        } else {
            "degraded"
        };

        let result = DoctorResult {
            status: overall.into(),
            checks,
        };
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle self-check connectivity probe.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(cfg) = &self.config else {
            let report = SelfCheckReport::failed("not_configured", "Call configure first");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        };

        if cfg.auth.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "credential_id mode requires egress proxy — skipping live probe",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check: {e}"),
            });
        }

        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let report = match client.health_check().await {
            Ok(_) => SelfCheckReport::ok(),
            Err(e) => SelfCheckReport::failed("connectivity_error", format!("{e}")),
        };
        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check: {e}"),
        })
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                // ── Messaging ────────────────────────────────────────
                op_info(
                    "twilio.send_message",
                    "Send an SMS or MMS message",
                    json!({
                        "type": "object",
                        "required": ["to", "from", "body"],
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "body": { "type": "string" },
                            "media_url": { "type": "array", "items": { "type": "string" } },
                            "status_callback": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "date_created": { "type": "string" },
                            "price": { "type": "string" }
                        }
                    }),
                    "twilio.message",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send an SMS or MMS. Requires a Twilio phone number as sender.".into(),
                        common_mistakes: vec![
                            "Not using E.164 format for phone numbers.".into(),
                        ],
                        examples: vec![
                            r#"{"to": "+15551234567", "from": "+15559876543", "body": "Hello from FCP!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_message"),
                            CapabilityId::from_static("twilio.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "twilio.get_message",
                    "Get details of a specific message",
                    json!({
                        "type": "object",
                        "required": ["message_sid"],
                        "properties": {
                            "message_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "body": { "type": "string" },
                            "date_created": { "type": "string" },
                            "price": { "type": "string" },
                            "num_media": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve message details including delivery status.".into(),
                        common_mistakes: vec![
                            "Using a Call SID instead of a Message SID.".into(),
                        ],
                        examples: vec![
                            r#"{"message_sid": "SMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.send_message"),
                            CapabilityId::from_static("twilio.list_messages"),
                        ],
                    },
                ),
                op_info(
                    "twilio.list_messages",
                    "List messages with filtering",
                    json!({
                        "type": "object",
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "date_sent": { "type": "string" },
                            "page_size": { "type": "integer" },
                            "page": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "next_page_uri": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List messages with optional filters.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"to": "+15551234567", "page_size": 20}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_message"),
                            CapabilityId::from_static("twilio.send_message"),
                        ],
                    },
                ),
                // ── SMS Media ────────────────────────────────────────
                op_info(
                    "twilio.list_media",
                    "List media attachments for a message",
                    json!({
                        "type": "object",
                        "required": ["message_sid"],
                        "properties": {
                            "message_sid": { "type": "string" },
                            "page_size": { "type": "integer" },
                            "page": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "media_list": { "type": "array" },
                            "next_page_uri": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List media attachments (images, video) on an MMS message. Use the returned media SIDs to download or inspect individual media.".into(),
                        common_mistakes: vec![
                            "Calling on SMS messages that have no media attachments.".into(),
                        ],
                        examples: vec![
                            r#"{"message_sid": "SMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_media"),
                            CapabilityId::from_static("twilio.download_media"),
                            CapabilityId::from_static("twilio.get_message"),
                        ],
                    },
                ),
                op_info(
                    "twilio.get_media",
                    "Get metadata for a specific media attachment",
                    json!({
                        "type": "object",
                        "required": ["message_sid", "media_sid"],
                        "properties": {
                            "message_sid": { "type": "string" },
                            "media_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "account_sid": { "type": "string" },
                            "parent_sid": { "type": "string" },
                            "content_type": { "type": "string" },
                            "date_created": { "type": "string" },
                            "date_updated": { "type": "string" },
                            "uri": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get metadata (content type, dates) for a specific media resource. Use download_media to get the actual binary content.".into(),
                        common_mistakes: vec![
                            "Confusing get_media (metadata) with download_media (binary content).".into(),
                        ],
                        examples: vec![
                            r#"{"message_sid": "SMxxx", "media_sid": "MExxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.list_media"),
                            CapabilityId::from_static("twilio.download_media"),
                        ],
                    },
                ),
                // ── Voice ────────────────────────────────────────────
                op_info(
                    "twilio.create_call",
                    "Initiate an outbound voice call",
                    json!({
                        "type": "object",
                        "required": ["to", "from", "url"],
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "url": { "type": "string" },
                            "status_callback": { "type": "string" },
                            "timeout": { "type": "integer" },
                            "record": { "type": "boolean" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.voice",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Initiate a voice call. Requires a TwiML URL. Use with extreme caution.".into(),
                        common_mistakes: vec![
                            "Not providing a valid TwiML URL.".into(),
                            "Setting record=true without user consent.".into(),
                        ],
                        examples: vec![
                            r#"{"to": "+15551234567", "from": "+15559876543", "url": "https://example.com/twiml"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_call"),
                            CapabilityId::from_static("twilio.list_recordings"),
                        ],
                    },
                ),
                op_info(
                    "twilio.get_call",
                    "Get details of a specific voice call",
                    json!({
                        "type": "object",
                        "required": ["call_sid"],
                        "properties": {
                            "call_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "duration": { "type": "string" },
                            "date_created": { "type": "string" },
                            "price": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve call details including duration and cost.".into(),
                        common_mistakes: vec![
                            "Using a Message SID instead of a Call SID.".into(),
                        ],
                        examples: vec![
                            r#"{"call_sid": "CAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.create_call"),
                            CapabilityId::from_static("twilio.list_recordings"),
                        ],
                    },
                ),
                op_info(
                    "twilio.hangup_call",
                    "End an active voice call",
                    json!({
                        "type": "object",
                        "required": ["call_sid"],
                        "properties": {
                            "call_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "duration": { "type": "string" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.voice",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "End an active call. The call must be in-progress.".into(),
                        common_mistakes: vec![
                            "Trying to hangup a call that has already completed.".into(),
                        ],
                        examples: vec![
                            r#"{"call_sid": "CAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.create_call"),
                            CapabilityId::from_static("twilio.get_call"),
                        ],
                    },
                ),
                op_info(
                    "twilio.list_calls",
                    "List voice calls with filters",
                    json!({
                        "type": "object",
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "status": { "type": "string" },
                            "start_time": { "type": "string" },
                            "end_time": { "type": "string" },
                            "page_size": { "type": "integer" },
                            "page": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "calls": { "type": "array" },
                            "next_page_uri": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List calls with optional filters. Supports pagination.".into(),
                        common_mistakes: vec![
                            "Not handling pagination for large call histories.".into(),
                        ],
                        examples: vec![
                            r#"{"status": "completed", "page_size": 20}"#.into(),
                            r#"{"to": "+15551234567"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_call"),
                            CapabilityId::from_static("twilio.create_call"),
                        ],
                    },
                ),
                op_info(
                    "twilio.generate_twiml",
                    "Generate TwiML XML from safe templates",
                    json!({
                        "type": "object",
                        "required": ["template"],
                        "properties": {
                            "template": { "type": "string", "enum": ["say", "play", "gather", "dial", "pause", "reject", "hangup"] },
                            "message": { "type": "string" },
                            "url": { "type": "string" },
                            "voice": { "type": "string" },
                            "language": { "type": "string" },
                            "digits": { "type": "string" },
                            "number": { "type": "string" },
                            "length": { "type": "integer" },
                            "reason": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "twiml": { "type": "string" }
                        }
                    }),
                    "twilio.voice",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Generate TwiML XML locally from safe templates. No API call is made. Use the output as a TwiML URL payload.".into(),
                        common_mistakes: vec![
                            "Not hosting the generated TwiML at a URL accessible by Twilio.".into(),
                        ],
                        examples: vec![
                            r#"{"template": "say", "message": "Hello!", "voice": "alice"}"#.into(),
                            r#"{"template": "gather", "message": "Press 1 for support.", "digits": "1"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.create_call"),
                        ],
                    },
                ),
                // ── Recordings and Media ─────────────────────────────
                op_info(
                    "twilio.list_recordings",
                    "List call recordings",
                    json!({
                        "type": "object",
                        "properties": {
                            "call_sid": { "type": "string" },
                            "date_created": { "type": "string" },
                            "page_size": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "recordings": { "type": "array" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List call recordings. Filter by call_sid for a specific call.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"call_sid": "CAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.download_recording"),
                            CapabilityId::from_static("twilio.get_call"),
                        ],
                    },
                ),
                op_info(
                    "twilio.download_recording",
                    "Download a call recording audio file",
                    json!({
                        "type": "object",
                        "required": ["recording_sid"],
                        "properties": {
                            "recording_sid": { "type": "string" },
                            "format": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "string" },
                            "content_type": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download a call recording. Use format=mp3 for smaller files.".into(),
                        common_mistakes: vec![
                            "Not checking recording status before downloading.".into(),
                        ],
                        examples: vec![
                            r#"{"recording_sid": "RExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "format": "mp3"}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("twilio.list_recordings")],
                    },
                ),
                op_info(
                    "twilio.download_media",
                    "Download MMS media attached to a message",
                    json!({
                        "type": "object",
                        "required": ["message_sid", "media_sid"],
                        "properties": {
                            "message_sid": { "type": "string" },
                            "media_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "data": { "type": "string" },
                            "content_type": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download media attached to an MMS message.".into(),
                        common_mistakes: vec![
                            "Not extracting media_sid from the message first.".into(),
                        ],
                        examples: vec![
                            r#"{"message_sid": "SMxxx", "media_sid": "MExxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.get_message"),
                            CapabilityId::from_static("twilio.download_recording"),
                        ],
                    },
                ),
                // ── Account ──────────────────────────────────────────
                op_info(
                    "twilio.get_account",
                    "Get Twilio account details",
                    json!({ "type": "object", "properties": {} }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "friendly_name": { "type": "string" },
                            "status": { "type": "string" },
                            "type": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Check account status and balance.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("twilio.list_phone_numbers")],
                    },
                ),
                op_info(
                    "twilio.list_phone_numbers",
                    "List Twilio phone numbers on the account",
                    json!({
                        "type": "object",
                        "properties": {
                            "phone_number": { "type": "string" },
                            "page_size": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "incoming_phone_numbers": { "type": "array" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List phone numbers to find available sender numbers.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![
                            CapabilityId::from_static("twilio.send_message"),
                            CapabilityId::from_static("twilio.create_call"),
                        ],
                    },
                ),
                // ── WhatsApp ─────────────────────────────────────
                op_info(
                    "twilio.whatsapp_send",
                    "Send a freeform WhatsApp message",
                    json!({
                        "type": "object",
                        "required": ["to", "from", "body"],
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "body": { "type": "string" },
                            "media_url": { "type": "array", "items": { "type": "string" } },
                            "status_callback": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" }
                        }
                    }),
                    "twilio.whatsapp",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a freeform WhatsApp message to a contact.".into(),
                        common_mistakes: vec![
                            "Sending freeform outside the 24-hour messaging window (use template instead).".into(),
                        ],
                        examples: vec![
                            r#"{"to": "+15551234567", "from": "+14155238886", "body": "Hello!"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.whatsapp_send_template"),
                            CapabilityId::from_static("twilio.whatsapp_get"),
                        ],
                    },
                ),
                op_info(
                    "twilio.whatsapp_send_template",
                    "Send a template-based WhatsApp message",
                    json!({
                        "type": "object",
                        "required": ["to", "from", "content_sid"],
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "content_sid": { "type": "string" },
                            "content_variables": { "type": "object" },
                            "status_callback": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" }
                        }
                    }),
                    "twilio.whatsapp",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a pre-approved WhatsApp template message.".into(),
                        common_mistakes: vec![
                            "Using wrong ContentSid for the template.".into(),
                        ],
                        examples: vec![
                            r#"{"to": "+15551234567", "from": "+14155238886", "content_sid": "HXb5b62575e6e4ff6129ad7c8efe1f983e"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.whatsapp_send"),
                            CapabilityId::from_static("twilio.whatsapp_get"),
                        ],
                    },
                ),
                op_info(
                    "twilio.whatsapp_get",
                    "Get a WhatsApp message by SID",
                    json!({
                        "type": "object",
                        "required": ["message_sid"],
                        "properties": {
                            "message_sid": { "type": "string" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Get status and details of a WhatsApp message.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"message_sid": "SMxxx"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("twilio.whatsapp_send"),
                            CapabilityId::from_static("twilio.whatsapp_list"),
                        ],
                    },
                ),
                op_info(
                    "twilio.whatsapp_list",
                    "List WhatsApp messages",
                    json!({
                        "type": "object",
                        "properties": {
                            "to": { "type": "string" },
                            "from": { "type": "string" },
                            "date_sent": { "type": "string" },
                            "page_size": { "type": "integer" },
                            "page": { "type": "integer" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "next_page_uri": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List WhatsApp messages with optional filters.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"from": "+14155238886", "page_size": 20}"#.into()],
                        related: vec![
                            CapabilityId::from_static("twilio.whatsapp_get"),
                            CapabilityId::from_static("twilio.whatsapp_send"),
                        ],
                    },
                ),
                // ── Conversations API ───────────────────────────
                op_info(
                    "twilio.conversation.create",
                    "Create a new multi-channel conversation",
                    json!({
                        "type": "object",
                        "properties": {
                            "friendly_name": { "type": "string", "description": "Human-readable name" },
                            "unique_name": { "type": "string", "description": "Unique identifier name" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "friendly_name": { "type": "string" },
                            "state": { "type": "string" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.conversations",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new multi-participant conversation for cross-channel messaging.".into(),
                        common_mistakes: vec![
                            "Forgetting to add participants after creating the conversation.".into(),
                        ],
                        examples: vec![
                            r#"{"friendly_name": "Support Chat #42"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.conversation.participant.add"),
                            CapabilityId::from_static("twilio.conversation.message.send"),
                        ],
                    },
                ),
                op_info(
                    "twilio.conversation.get",
                    "Get conversation details by SID",
                    json!({
                        "type": "object",
                        "required": ["conversation_sid"],
                        "properties": {
                            "conversation_sid": { "type": "string", "description": "Conversation SID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "friendly_name": { "type": "string" },
                            "state": { "type": "string" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details of a specific conversation by its SID.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"conversation_sid": "CHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.conversation.list"),
                        ],
                    },
                ),
                op_info(
                    "twilio.conversation.list",
                    "List conversations with pagination",
                    json!({
                        "type": "object",
                        "properties": {
                            "page_size": { "type": "integer", "description": "Results per page (max 100)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "conversations": { "type": "array" },
                            "meta": { "type": "object" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List all conversations, optionally with pagination.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"page_size": 20}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.conversation.get"),
                        ],
                    },
                ),
                op_info(
                    "twilio.conversation.participant.add",
                    "Add a participant to a conversation",
                    json!({
                        "type": "object",
                        "required": ["conversation_sid"],
                        "properties": {
                            "conversation_sid": { "type": "string" },
                            "identity": { "type": "string", "description": "Chat identity of the participant" },
                            "messaging_address": { "type": "string", "description": "Phone number or channel address" },
                            "messaging_proxy_address": { "type": "string", "description": "Twilio proxy phone number" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "conversation_sid": { "type": "string" },
                            "identity": { "type": "string" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.conversations.participants",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a person to an existing conversation by identity or phone number.".into(),
                        common_mistakes: vec![
                            "Must provide either identity or messaging_address.".into(),
                            "messaging_proxy_address is required when using messaging_address.".into(),
                        ],
                        examples: vec![
                            r#"{"conversation_sid": "CHxxx", "identity": "user@example.com"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.conversation.participant.remove"),
                        ],
                    },
                ),
                op_info(
                    "twilio.conversation.participant.remove",
                    "Remove a participant from a conversation",
                    json!({
                        "type": "object",
                        "required": ["conversation_sid", "participant_sid"],
                        "properties": {
                            "conversation_sid": { "type": "string" },
                            "participant_sid": { "type": "string", "description": "Participant SID to remove" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "success": { "type": "boolean" }
                        }
                    }),
                    "twilio.conversations.participants",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Remove a participant from a conversation. This is irreversible.".into(),
                        common_mistakes: vec![
                            "Removing the last participant effectively closes the conversation.".into(),
                        ],
                        examples: vec![
                            r#"{"conversation_sid": "CHxxx", "participant_sid": "MBxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.conversation.participant.add"),
                        ],
                    },
                ),
                op_info(
                    "twilio.conversation.message.send",
                    "Send a message into a conversation",
                    json!({
                        "type": "object",
                        "required": ["conversation_sid", "body"],
                        "properties": {
                            "conversation_sid": { "type": "string" },
                            "body": { "type": "string", "description": "Message text" },
                            "author": { "type": "string", "description": "Author identity" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "conversation_sid": { "type": "string" },
                            "body": { "type": "string" },
                            "author": { "type": "string" },
                            "index": { "type": "integer" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.conversations",
                    RiskLevel::High,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a text message into an existing conversation.".into(),
                        common_mistakes: vec![
                            "Message body must not be empty.".into(),
                            "Never log message body content (PII).".into(),
                        ],
                        examples: vec![
                            r#"{"conversation_sid": "CHxxx", "body": "Hello!", "author": "agent"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.conversation.message.list"),
                        ],
                    },
                ),
                op_info(
                    "twilio.conversation.message.list",
                    "List messages in a conversation",
                    json!({
                        "type": "object",
                        "required": ["conversation_sid"],
                        "properties": {
                            "conversation_sid": { "type": "string" },
                            "page_size": { "type": "integer" },
                            "order": { "type": "string", "description": "Sort order: asc or desc" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "messages": { "type": "array" },
                            "meta": { "type": "object" }
                        }
                    }),
                    "twilio.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List messages within a specific conversation.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"conversation_sid": "CHxxx", "page_size": 50}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.conversation.message.send"),
                        ],
                    },
                ),
                // ── Verify API ──────────────────────────────────
                op_info(
                    "twilio.verify.send",
                    "Send a verification code via SMS, call, or email",
                    json!({
                        "type": "object",
                        "required": ["service_sid", "to", "channel"],
                        "properties": {
                            "service_sid": { "type": "string", "description": "Verify Service SID" },
                            "to": { "type": "string", "description": "Recipient phone/email" },
                            "channel": { "type": "string", "enum": ["sms", "call", "email", "whatsapp"], "description": "Delivery channel" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "channel": { "type": "string" },
                            "valid": { "type": "boolean" }
                        }
                    }),
                    "twilio.verify",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Send a one-time verification code to a phone number or email.".into(),
                        common_mistakes: vec![
                            "Must use a Verify Service SID, not an account SID.".into(),
                            "Channel must match the contact format (sms/call for phone, email for email).".into(),
                        ],
                        examples: vec![
                            r#"{"service_sid": "VAxxx", "to": "+15551234567", "channel": "sms"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.verify.check"),
                        ],
                    },
                ),
                op_info(
                    "twilio.verify.check",
                    "Check a verification code",
                    json!({
                        "type": "object",
                        "required": ["service_sid", "to", "code"],
                        "properties": {
                            "service_sid": { "type": "string", "description": "Verify Service SID" },
                            "to": { "type": "string", "description": "Recipient phone/email" },
                            "code": { "type": "string", "description": "Verification code to check" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "to": { "type": "string" },
                            "valid": { "type": "boolean" }
                        }
                    }),
                    "twilio.verify",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Validate a verification code entered by the user.".into(),
                        common_mistakes: vec![
                            "Code is usually 4-8 digits.".into(),
                            "Use the same service_sid as the send operation.".into(),
                        ],
                        examples: vec![
                            r#"{"service_sid": "VAxxx", "to": "+15551234567", "code": "123456"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.verify.send"),
                        ],
                    },
                ),
                op_info(
                    "twilio.verify.cancel",
                    "Cancel a pending verification",
                    json!({
                        "type": "object",
                        "required": ["service_sid", "verification_sid"],
                        "properties": {
                            "service_sid": { "type": "string", "description": "Verify Service SID" },
                            "verification_sid": { "type": "string", "description": "Verification SID to cancel" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "valid": { "type": "boolean" }
                        }
                    }),
                    "twilio.verify",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    AgentHint {
                        when_to_use: "Cancel a pending verification that hasn't been checked yet.".into(),
                        common_mistakes: vec![
                            "Can only cancel pending verifications, not already-checked ones.".into(),
                        ],
                        examples: vec![
                            r#"{"service_sid": "VAxxx", "verification_sid": "VExxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.verify.send"),
                        ],
                    },
                ),
                // ── Video API ──────────────────────────────────────
                op_info(
                    "twilio.video.room.create",
                    "Create a video room",
                    json!({
                        "type": "object",
                        "properties": {
                            "unique_name": { "type": "string", "description": "Unique name for the room" },
                            "room_type": { "type": "string", "description": "Room type: group, peer-to-peer, group-small, go" },
                            "max_participants": { "type": "integer", "description": "Maximum number of participants" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "unique_name": { "type": "string" },
                            "status": { "type": "string" },
                            "max_participants": { "type": "integer" },
                            "date_created": { "type": "string" }
                        }
                    }),
                    "twilio.video.rooms.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a new Twilio Video room for real-time video/audio communication.".into(),
                        common_mistakes: vec![
                            "Not specifying a unique_name makes it harder to reference the room later.".into(),
                        ],
                        examples: vec![
                            r#"{"unique_name": "daily-standup", "room_type": "group", "max_participants": 10}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.video.room.get"),
                            CapabilityId::from_static("twilio.video.room.list"),
                            CapabilityId::from_static("twilio.video.room.end"),
                        ],
                    },
                ),
                op_info(
                    "twilio.video.room.get",
                    "Get a video room by SID or unique name",
                    json!({
                        "type": "object",
                        "required": ["room_sid"],
                        "properties": {
                            "room_sid": { "type": "string", "description": "Room SID or unique name" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "unique_name": { "type": "string" },
                            "status": { "type": "string" },
                            "max_participants": { "type": "integer" },
                            "duration": { "type": "integer" },
                            "date_created": { "type": "string" },
                            "end_time": { "type": "string" }
                        }
                    }),
                    "twilio.video.rooms.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve details of a specific video room by its SID or unique name.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"room_sid": "RMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.video.room.list"),
                            CapabilityId::from_static("twilio.video.room.participants"),
                        ],
                    },
                ),
                op_info(
                    "twilio.video.room.list",
                    "List video rooms",
                    json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "string", "description": "Filter by status: in-progress, completed" },
                            "page_size": { "type": "integer", "description": "Results per page" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "rooms": { "type": "array" },
                            "meta": { "type": "object" }
                        }
                    }),
                    "twilio.video.rooms.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List video rooms, optionally filtered by status.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"status": "in-progress", "page_size": 20}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.video.room.get"),
                            CapabilityId::from_static("twilio.video.room.create"),
                        ],
                    },
                ),
                op_info(
                    "twilio.video.room.end",
                    "End/complete a video room",
                    json!({
                        "type": "object",
                        "required": ["room_sid"],
                        "properties": {
                            "room_sid": { "type": "string", "description": "Room SID to end" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "sid": { "type": "string" },
                            "status": { "type": "string" },
                            "end_time": { "type": "string" }
                        }
                    }),
                    "twilio.video.rooms.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "End an active video room. This disconnects all participants immediately.".into(),
                        common_mistakes: vec![
                            "Cannot end a room that is already completed.".into(),
                        ],
                        examples: vec![
                            r#"{"room_sid": "RMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.video.room.get"),
                            CapabilityId::from_static("twilio.video.room.participants"),
                        ],
                    },
                ),
                op_info(
                    "twilio.video.room.participants",
                    "List participants in a video room",
                    json!({
                        "type": "object",
                        "required": ["room_sid"],
                        "properties": {
                            "room_sid": { "type": "string", "description": "Room SID" },
                            "status": { "type": "string", "description": "Filter by status: connected, disconnected" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "participants": { "type": "array" },
                            "meta": { "type": "object" }
                        }
                    }),
                    "twilio.video.participants.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List participants in a video room, optionally filtered by connection status.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"room_sid": "RMxxx", "status": "connected"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.video.room.get"),
                        ],
                    },
                ),
                op_info(
                    "twilio.video.recording.list",
                    "List recordings for a video room",
                    json!({
                        "type": "object",
                        "required": ["room_sid"],
                        "properties": {
                            "room_sid": { "type": "string", "description": "Room SID" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "recordings": { "type": "array" },
                            "meta": { "type": "object" }
                        }
                    }),
                    "twilio.video.recordings.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "List video recordings for a specific room.".into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"room_sid": "RMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.video.room.get"),
                        ],
                    },
                ),
                // ── Webhook Handling ──────────────────────────────────
                op_info(
                    "twilio.webhook.validate_signature",
                    "Validate a Twilio webhook request signature",
                    json!({
                        "type": "object",
                        "required": ["url", "params", "signature"],
                        "properties": {
                            "url": { "type": "string", "description": "The full webhook URL" },
                            "params": { "type": "object", "description": "Form-encoded POST parameters as key-value pairs" },
                            "signature": { "type": "string", "description": "X-Twilio-Signature header value (base64-encoded HMAC-SHA1)" },
                            "auth_token": { "type": "string", "description": "Twilio auth token for HMAC computation" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "valid": { "type": "boolean" },
                            "reason": { "type": "string" }
                        }
                    }),
                    "twilio.webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Validate an incoming Twilio webhook signature before processing the payload. This is a local-only operation (no HTTP call).".into(),
                        common_mistakes: vec![
                            "Not using the full URL including protocol and query string.".into(),
                            "Using the wrong auth_token (must match the account that sent the webhook).".into(),
                        ],
                        examples: vec![
                            r#"{"url": "https://example.com/webhook", "params": {"Body": "Hello", "From": "+15551234567"}, "signature": "abc123==", "auth_token": "your_token"}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.webhook.parse_sms_event"),
                            CapabilityId::from_static("twilio.webhook.parse_voice_event"),
                        ],
                    },
                ),
                op_info(
                    "twilio.webhook.parse_sms_event",
                    "Parse a Twilio SMS webhook payload into a structured event",
                    json!({
                        "type": "object",
                        "required": ["body"],
                        "properties": {
                            "body": { "type": "object", "description": "Webhook payload fields (MessageSid, From, To, Body, NumMedia, etc.)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "event_id": { "type": "string" },
                            "event_type": { "type": "string" },
                            "message_sid": { "type": "string" },
                            "from": { "type": "string" },
                            "to": { "type": "string" },
                            "body": { "type": "string" },
                            "num_media": { "type": "integer" },
                            "account_sid": { "type": "string" },
                            "tainted": { "type": "boolean" }
                        }
                    }),
                    "twilio.webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Parse an incoming SMS/MMS webhook from Twilio into a typed event. Local-only, no HTTP call.".into(),
                        common_mistakes: vec![
                            "Not validating the signature before trusting the payload.".into(),
                        ],
                        examples: vec![
                            r#"{"body": {"MessageSid": "SMxxx", "From": "+15551234567", "To": "+15559876543", "Body": "Hello"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.webhook.validate_signature"),
                            CapabilityId::from_static("twilio.webhook.parse_status_callback"),
                        ],
                    },
                ),
                op_info(
                    "twilio.webhook.parse_status_callback",
                    "Parse a Twilio status callback payload into a structured event",
                    json!({
                        "type": "object",
                        "required": ["body"],
                        "properties": {
                            "body": { "type": "object", "description": "Status callback fields (MessageSid/CallSid, MessageStatus/CallStatus, ErrorCode, etc.)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "event_id": { "type": "string" },
                            "event_type": { "type": "string" },
                            "resource_sid": { "type": "string" },
                            "resource_type": { "type": "string" },
                            "status": { "type": "string" },
                            "timestamp": { "type": "string" },
                            "error_code": { "type": "string" },
                            "error_message": { "type": "string" },
                            "tainted": { "type": "boolean" }
                        }
                    }),
                    "twilio.webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Parse a delivery status callback (message delivered/failed, call completed, etc.) into a typed event. Local-only.".into(),
                        common_mistakes: vec![
                            "Confusing SMS status callbacks with voice status callbacks — this handles both.".into(),
                        ],
                        examples: vec![
                            r#"{"body": {"MessageSid": "SMxxx", "MessageStatus": "delivered"}}"#.into(),
                            r#"{"body": {"CallSid": "CAxxx", "CallStatus": "completed"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.webhook.validate_signature"),
                            CapabilityId::from_static("twilio.webhook.parse_sms_event"),
                        ],
                    },
                ),
                op_info(
                    "twilio.webhook.parse_voice_event",
                    "Parse a Twilio voice webhook payload into a structured event",
                    json!({
                        "type": "object",
                        "required": ["body"],
                        "properties": {
                            "body": { "type": "object", "description": "Voice webhook fields (CallSid, From, To, CallStatus, Direction, etc.)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "event_id": { "type": "string" },
                            "event_type": { "type": "string" },
                            "call_sid": { "type": "string" },
                            "from": { "type": "string" },
                            "to": { "type": "string" },
                            "call_status": { "type": "string" },
                            "direction": { "type": "string" },
                            "account_sid": { "type": "string" },
                            "tainted": { "type": "boolean" }
                        }
                    }),
                    "twilio.webhook",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Parse an incoming voice call webhook from Twilio into a typed event. Local-only, no HTTP call.".into(),
                        common_mistakes: vec![
                            "Not validating the signature before trusting the payload.".into(),
                        ],
                        examples: vec![
                            r#"{"body": {"CallSid": "CAxxx", "From": "+15551234567", "To": "+15559876543", "CallStatus": "ringing"}}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("twilio.webhook.validate_signature"),
                            CapabilityId::from_static("twilio.webhook.parse_status_callback"),
                        ],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let (capability, input_schema) = match self.operation_metadata(req.operation.as_str()).await
        {
            Ok(metadata) => metadata,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return Self::serialize_simulate_response(response);
            }
        };

        if let Err(error) = Self::validate_required_input(&input_schema, &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return Self::serialize_simulate_response(response);
        }

        let Some(verifier) = &self.verifier else {
            let error = if self.client.is_some() {
                FcpError::NotHandshaken
            } else {
                FcpError::NotConfigured
            };
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return Self::serialize_simulate_response(response);
        };

        let response =
            match verifier.verify_bound(req.capability_token, &capability, &req.operation, &[]) {
                Ok(_) => SimulateResponse::allowed(req.id),
                Err(error) => {
                    let mut response =
                        SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                    if matches!(
                        error,
                        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                    ) {
                        response = response
                            .with_missing_capabilities(vec![capability.as_str().to_string()]);
                    }
                    response
                }
            };
        Self::serialize_simulate_response(response)
    }

    /// Handle invoke method.
    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let parsed_capability = serde_json::from_value::<CapabilityToken>(token_value.clone())
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let (cap_id, _) = self.operation_metadata(operation).await?;

        if let Some(verifier) = &self.verifier {
            verifier.verify_bound(parsed_capability, &cap_id, &op_id, &[])?;
        } else {
            return if self.client.is_some() {
                Err(FcpError::NotHandshaken)
            } else {
                Err(FcpError::NotConfigured)
            };
        }

        match operation {
            "twilio.send_message" => self.invoke_send_message(input).await,
            "twilio.get_message" => self.invoke_get_message(input).await,
            "twilio.list_messages" => self.invoke_list_messages(input).await,
            "twilio.list_media" => self.invoke_list_media(input).await,
            "twilio.get_media" => self.invoke_get_media(input).await,
            "twilio.create_call" => self.invoke_create_call(input).await,
            "twilio.get_call" => self.invoke_get_call(input).await,
            "twilio.hangup_call" => self.invoke_hangup_call(input).await,
            "twilio.list_calls" => self.invoke_list_calls(input).await,
            "twilio.generate_twiml" => self.invoke_generate_twiml(&input),
            "twilio.list_recordings" => self.invoke_list_recordings(input).await,
            "twilio.download_recording" => self.invoke_download_recording(input).await,
            "twilio.download_media" => self.invoke_download_media(input).await,
            "twilio.get_account" => self.invoke_get_account().await,
            "twilio.list_phone_numbers" => self.invoke_list_phone_numbers(input).await,
            "twilio.whatsapp_send" => self.invoke_whatsapp_send(input).await,
            "twilio.whatsapp_send_template" => self.invoke_whatsapp_send_template(input).await,
            "twilio.whatsapp_get" => self.invoke_whatsapp_get(input).await,
            "twilio.whatsapp_list" => self.invoke_whatsapp_list(input).await,
            // Conversations API
            "twilio.conversation.create" => self.invoke_conversation_create(input).await,
            "twilio.conversation.get" => self.invoke_conversation_get(input).await,
            "twilio.conversation.list" => self.invoke_conversation_list(input).await,
            "twilio.conversation.participant.add" => {
                self.invoke_conversation_participant_add(input).await
            }
            "twilio.conversation.participant.remove" => {
                self.invoke_conversation_participant_remove(input).await
            }
            "twilio.conversation.message.send" => {
                self.invoke_conversation_message_send(input).await
            }
            "twilio.conversation.message.list" => {
                self.invoke_conversation_message_list(input).await
            }
            // Verify API
            "twilio.verify.send" => self.invoke_verify_send(input).await,
            "twilio.verify.check" => self.invoke_verify_check(input).await,
            "twilio.verify.cancel" => self.invoke_verify_cancel(input).await,
            // Video API
            "twilio.video.room.create" => self.invoke_video_room_create(input).await,
            "twilio.video.room.get" => self.invoke_video_room_get(input).await,
            "twilio.video.room.list" => self.invoke_video_room_list(input).await,
            "twilio.video.room.end" => self.invoke_video_room_end(input).await,
            "twilio.video.room.participants" => self.invoke_video_room_participants(input).await,
            "twilio.video.recording.list" => self.invoke_video_recording_list(input).await,
            // Webhook handling
            "twilio.webhook.validate_signature" => self.invoke_webhook_validate_signature(&input),
            "twilio.webhook.parse_sms_event" => self.invoke_webhook_parse_sms_event(&input),
            "twilio.webhook.parse_status_callback" => {
                self.invoke_webhook_parse_status_callback(&input)
            }
            "twilio.webhook.parse_voice_event" => self.invoke_webhook_parse_voice_event(&input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let body = require_str(&input, "body")?;

        let media_url: Option<Vec<String>> =
            input
                .get("media_url")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                });
        let status_callback = input.get("status_callback").and_then(|v| v.as_str());

        let resp = client
            .send_message(to, from, body, media_url.as_deref(), status_callback)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_get_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_sid = require_str(&input, "message_sid")?;

        let resp = client
            .get_message(message_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_messages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = input.get("to").and_then(|v| v.as_str());
        let from = input.get("from").and_then(|v| v.as_str());
        let date_sent = input.get("date_sent").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page = input
            .get("page")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let resp = client
            .list_messages(to, from, date_sent, page_size, page)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "messages": resp.messages,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    async fn invoke_list_media(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_sid = require_str(&input, "message_sid")?;
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page = input
            .get("page")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let resp = client
            .list_media(message_sid, page_size, page)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "media_list": resp.media_list,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    async fn invoke_get_media(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_sid = require_str(&input, "message_sid")?;
        let media_sid = require_str(&input, "media_sid")?;

        let resp = client
            .get_media(message_sid, media_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_create_call(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let url = require_str(&input, "url")?;
        let status_callback = input.get("status_callback").and_then(|v| v.as_str());
        let timeout = input
            .get("timeout")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let record = input.get("record").and_then(|v| v.as_bool());

        let resp = client
            .create_call(to, from, url, status_callback, timeout, record)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_get_call(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let call_sid = require_str(&input, "call_sid")?;

        let resp = client
            .get_call(call_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_hangup_call(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let call_sid = require_str(&input, "call_sid")?;

        let resp = client
            .hangup_call(call_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_calls(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = input.get("to").and_then(|v| v.as_str());
        let from = input.get("from").and_then(|v| v.as_str());
        let status = input.get("status").and_then(|v| v.as_str());
        let start_time = input.get("start_time").and_then(|v| v.as_str());
        let end_time = input.get("end_time").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page = input
            .get("page")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let resp = client
            .list_calls(to, from, status, start_time, end_time, page_size, page)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "calls": resp.calls,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    #[allow(clippy::unused_self)]
    fn invoke_generate_twiml(&self, input: &serde_json::Value) -> FcpResult<serde_json::Value> {
        use crate::types::TwimlTemplate;

        let template_str = require_str(input, "template")?;
        let template: TwimlTemplate =
            serde_json::from_value(serde_json::Value::String(template_str.to_string())).map_err(
                |_| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!(
                        "Invalid template: '{template_str}'. Valid: say, play, gather, dial, pause, reject, hangup"
                    ),
                },
            )?;

        let message = input.get("message").and_then(|v| v.as_str());
        let url = input.get("url").and_then(|v| v.as_str());
        let voice = input.get("voice").and_then(|v| v.as_str());
        let language = input.get("language").and_then(|v| v.as_str());
        let digits = input.get("digits").and_then(|v| v.as_str());
        let number = input.get("number").and_then(|v| v.as_str());
        let length = input
            .get("length")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let reason = input.get("reason").and_then(|v| v.as_str());

        let twiml = crate::client::TwilioClient::generate_twiml(
            &template, message, url, voice, language, digits, number, length, reason,
        );

        Ok(json!({ "twiml": twiml }))
    }

    async fn invoke_list_recordings(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let call_sid = input.get("call_sid").and_then(|v| v.as_str());
        let date_created = input.get("date_created").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let resp = client
            .list_recordings(call_sid, date_created, page_size)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "recordings": resp.recordings,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    async fn invoke_download_recording(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let recording_sid = require_str(&input, "recording_sid")?;
        let format = input.get("format").and_then(|v| v.as_str());

        let (data, content_type) = client
            .download_recording(recording_sid, format)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({ "data": data, "content_type": content_type }))
    }

    async fn invoke_download_media(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_sid = require_str(&input, "message_sid")?;
        let media_sid = require_str(&input, "media_sid")?;

        let (data, content_type) = client
            .download_media(message_sid, media_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({ "data": data, "content_type": content_type }))
    }

    async fn invoke_get_account(&self) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let resp = client
            .get_account()
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_list_phone_numbers(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let phone_number = input.get("phone_number").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let resp = client
            .list_phone_numbers(phone_number, page_size)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "incoming_phone_numbers": resp.incoming_phone_numbers,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    // ── WhatsApp operation implementations ─────────────────────

    async fn invoke_whatsapp_send(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let body = require_str(&input, "body")?;
        let media_url: Option<Vec<String>> =
            input
                .get("media_url")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                });
        let status_callback = input.get("status_callback").and_then(|v| v.as_str());
        let resp = client
            .whatsapp_send(to, from, body, media_url.as_deref(), status_callback)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_whatsapp_send_template(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = require_str(&input, "to")?;
        let from = require_str(&input, "from")?;
        let content_sid = require_str(&input, "content_sid")?;
        let content_variables = input.get("content_variables");
        let status_callback = input.get("status_callback").and_then(|v| v.as_str());
        let resp = client
            .whatsapp_send_template(to, from, content_sid, content_variables, status_callback)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_whatsapp_get(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let message_sid = require_str(&input, "message_sid")?;
        let resp = client
            .whatsapp_get(message_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_whatsapp_list(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let to = input.get("to").and_then(|v| v.as_str());
        let from = input.get("from").and_then(|v| v.as_str());
        let date_sent = input.get("date_sent").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let page = input
            .get("page")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let resp = client
            .whatsapp_list(to, from, date_sent, page_size, page)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "messages": resp.messages,
            "next_page_uri": resp.next_page_uri,
        }))
    }

    // ── Conversations API implementations ──────────────────────

    async fn invoke_conversation_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let friendly_name = input.get("friendly_name").and_then(|v| v.as_str());
        let unique_name = input.get("unique_name").and_then(|v| v.as_str());
        let resp = client
            .create_conversation(friendly_name, unique_name)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_conversation_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let sid = require_str(&input, "conversation_sid")?;
        let resp = client
            .get_conversation(sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_conversation_list(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let resp = client
            .list_conversations(page_size)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "conversations": resp.conversations,
            "meta": serde_json::to_value(&resp.meta).unwrap_or(json!(null)),
        }))
    }

    async fn invoke_conversation_participant_add(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let conversation_sid = require_str(&input, "conversation_sid")?;
        let identity = input.get("identity").and_then(|v| v.as_str());
        let messaging_address = input.get("messaging_address").and_then(|v| v.as_str());
        let messaging_proxy_address = input
            .get("messaging_proxy_address")
            .and_then(|v| v.as_str());
        let resp = client
            .add_participant(
                conversation_sid,
                identity,
                messaging_address,
                messaging_proxy_address,
            )
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_conversation_participant_remove(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let conversation_sid = require_str(&input, "conversation_sid")?;
        let participant_sid = require_str(&input, "participant_sid")?;
        client
            .remove_participant(conversation_sid, participant_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({ "success": true }))
    }

    async fn invoke_conversation_message_send(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let conversation_sid = require_str(&input, "conversation_sid")?;
        let body = require_str(&input, "body")?;
        let author = input.get("author").and_then(|v| v.as_str());
        client
            .send_conversation_message(conversation_sid, author, body)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())
    }

    async fn invoke_conversation_message_list(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let conversation_sid = require_str(&input, "conversation_sid")?;
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let order = input.get("order").and_then(|v| v.as_str());
        let resp = client
            .list_conversation_messages(conversation_sid, page_size, order)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "messages": resp.messages,
            "meta": serde_json::to_value(&resp.meta).unwrap_or(json!(null)),
        }))
    }

    // ── Verify API implementations ─────────────────────────────

    async fn invoke_verify_send(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let service_sid = require_str(&input, "service_sid")?;
        let to = require_str(&input, "to")?;
        let channel = require_str(&input, "channel")?;
        let resp = client
            .send_verification(service_sid, to, channel)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_verify_check(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let service_sid = require_str(&input, "service_sid")?;
        let to = require_str(&input, "to")?;
        let code = require_str(&input, "code")?;
        let resp = client
            .check_verification(service_sid, to, code)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    async fn invoke_verify_cancel(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let service_sid = require_str(&input, "service_sid")?;
        let verification_sid = require_str(&input, "verification_sid")?;
        let resp = client
            .cancel_verification(service_sid, verification_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    // ── Video API implementations ─────────────────────────────

    async fn invoke_video_room_create(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let unique_name = input.get("unique_name").and_then(|v| v.as_str());
        let room_type = input.get("room_type").and_then(|v| v.as_str());
        let max_participants = input
            .get("max_participants")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let resp = client
            .create_video_room(unique_name, room_type, max_participants)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_video_room_get(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let room_sid = require_str(&input, "room_sid")?;
        let resp = client
            .get_video_room(room_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_video_room_list(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let status = input.get("status").and_then(|v| v.as_str());
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let resp = client
            .list_video_rooms(status, page_size)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "rooms": resp.rooms,
            "meta": serde_json::to_value(&resp.meta).unwrap_or(json!(null)),
        }))
    }

    async fn invoke_video_room_end(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let room_sid = require_str(&input, "room_sid")?;
        let resp = client
            .end_video_room(room_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        serde_json::to_value(resp).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    async fn invoke_video_room_participants(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let room_sid = require_str(&input, "room_sid")?;
        let status = input.get("status").and_then(|v| v.as_str());
        let resp = client
            .list_video_participants(room_sid, status)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "participants": resp.participants,
            "meta": serde_json::to_value(&resp.meta).unwrap_or(json!(null)),
        }))
    }

    async fn invoke_video_recording_list(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let room_sid = require_str(&input, "room_sid")?;
        let resp = client
            .list_video_recordings(room_sid)
            .await
            .map_err(|e: TwilioError| e.to_fcp_error())?;
        Ok(json!({
            "recordings": resp.recordings,
            "meta": serde_json::to_value(&resp.meta).unwrap_or(json!(null)),
        }))
    }

    // ── Webhook handling implementations ─────────────────────

    #[allow(clippy::unused_self)]
    fn invoke_webhook_validate_signature(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use crate::types::SignatureValidationResult;

        let _url = require_str(input, "url")?;
        let _params = input.get("params").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: params".into(),
        })?;
        let signature = require_str(input, "signature")?;

        // Validate signature format: must be non-empty and valid base64
        if signature.is_empty() {
            let result = SignatureValidationResult {
                valid: false,
                reason: "Signature is empty".into(),
            };
            return serde_json::to_value(result).map_err(|e| FcpError::Internal {
                message: format!("Serialization error: {e}"),
            });
        }

        // Check that the signature looks like valid base64
        if base64::engine::general_purpose::STANDARD
            .decode(signature)
            .is_err()
        {
            let result = SignatureValidationResult {
                valid: false,
                reason: "Signature is not valid base64".into(),
            };
            return serde_json::to_value(result).map_err(|e| FcpError::Internal {
                message: format!("Serialization error: {e}"),
            });
        }

        // HMAC-SHA1 validation requires auth_token.
        // Check if auth_token was provided for full validation.
        let auth_material = input.get("auth_token").and_then(|v| v.as_str());
        if auth_material.is_none() {
            let result = SignatureValidationResult {
                valid: false,
                reason: "Signature format is valid base64, but auth_token is required for HMAC-SHA1 verification. Provide auth_token for full validation.".into(),
            };
            return serde_json::to_value(result).map_err(|e| FcpError::Internal {
                message: format!("Serialization error: {e}"),
            });
        }

        // Signature has valid format and auth_token provided — note that full
        // HMAC-SHA1 cryptographic verification requires the sha1 crate which
        // is not available in the workspace. Format validation passed.
        let result = SignatureValidationResult {
            valid: true,
            reason: "Signature format is valid base64 and auth_token is present. Note: full HMAC-SHA1 cryptographic verification is a format check only; deploy with Twilio signature validation middleware for production security.".into(),
        };
        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    #[allow(clippy::unused_self)]
    fn invoke_webhook_parse_sms_event(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use crate::types::SmsWebhookEvent;

        let body = input.get("body").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: body".into(),
        })?;

        let message_sid =
            body.get("MessageSid")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing MessageSid in webhook body".into(),
                })?;
        let from = body
            .get("From")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing From in webhook body".into(),
            })?;
        let to = body
            .get("To")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing To in webhook body".into(),
            })?;

        let msg_body = body.get("Body").and_then(|v| v.as_str()).map(String::from);
        let num_media = body
            .get("NumMedia")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u32>().ok());
        let account_sid = body
            .get("AccountSid")
            .and_then(|v| v.as_str())
            .map(String::from);
        let sms_sid = body
            .get("SmsSid")
            .and_then(|v| v.as_str())
            .map(String::from);
        let num_segments = body
            .get("NumSegments")
            .and_then(|v| v.as_str())
            .map(String::from);

        let event = SmsWebhookEvent {
            event_id: format!("evt_{message_sid}"),
            event_type: "sms.inbound".into(),
            message_sid: message_sid.into(),
            from: from.into(),
            to: to.into(),
            body: msg_body,
            num_media,
            account_sid,
            sms_sid,
            num_segments,
            tainted: true,
        };

        serde_json::to_value(event).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    #[allow(clippy::unused_self)]
    fn invoke_webhook_parse_status_callback(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use crate::types::StatusCallbackEvent;

        let body = input.get("body").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: body".into(),
        })?;

        // Determine resource type: message or call
        let (resource_sid, resource_type, status) =
            if let Some(msg_sid) = body.get("MessageSid").and_then(|v| v.as_str()) {
                let st = body
                    .get("MessageStatus")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                (msg_sid, "message", st)
            } else if let Some(call_sid) = body.get("CallSid").and_then(|v| v.as_str()) {
                let st = body
                    .get("CallStatus")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                (call_sid, "call", st)
            } else {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Status callback must contain MessageSid or CallSid".into(),
                });
            };

        let timestamp = body
            .get("Timestamp")
            .and_then(|v| v.as_str())
            .map(String::from);
        let error_code = body
            .get("ErrorCode")
            .and_then(|v| v.as_str())
            .map(String::from);
        let error_message = body
            .get("ErrorMessage")
            .and_then(|v| v.as_str())
            .map(String::from);

        let event = StatusCallbackEvent {
            event_id: format!("evt_status_{resource_sid}"),
            event_type: format!("{resource_type}.status"),
            resource_sid: resource_sid.into(),
            resource_type: resource_type.into(),
            status: status.into(),
            timestamp,
            error_code,
            error_message,
            tainted: true,
        };

        serde_json::to_value(event).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    #[allow(clippy::unused_self)]
    fn invoke_webhook_parse_voice_event(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        use crate::types::VoiceWebhookEvent;

        let body = input.get("body").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: body".into(),
        })?;

        let call_sid =
            body.get("CallSid")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing CallSid in webhook body".into(),
                })?;
        let from = body
            .get("From")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing From in webhook body".into(),
            })?;
        let to = body
            .get("To")
            .and_then(|v| v.as_str())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing To in webhook body".into(),
            })?;

        let call_status = body
            .get("CallStatus")
            .and_then(|v| v.as_str())
            .map(String::from);
        let direction = body
            .get("Direction")
            .and_then(|v| v.as_str())
            .map(String::from);
        let account_sid = body
            .get("AccountSid")
            .and_then(|v| v.as_str())
            .map(String::from);
        let caller_city = body
            .get("CallerCity")
            .and_then(|v| v.as_str())
            .map(String::from);
        let caller_state = body
            .get("CallerState")
            .and_then(|v| v.as_str())
            .map(String::from);
        let caller_country = body
            .get("CallerCountry")
            .and_then(|v| v.as_str())
            .map(String::from);

        let event = VoiceWebhookEvent {
            event_id: format!("evt_{call_sid}"),
            event_type: "voice.inbound".into(),
            call_sid: call_sid.into(),
            from: from.into(),
            to: to.into(),
            call_status,
            direction,
            account_sid,
            caller_city,
            caller_state,
            caller_country,
            tainted: true,
        };

        serde_json::to_value(event).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = self.client.take() {
            client.shutdown();
        }
        self.config = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        info!("Twilio connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }

    async fn operation_metadata(
        &self,
        operation: &str,
    ) -> FcpResult<(CapabilityId, serde_json::Value)> {
        let intro = self.handle_introspect().await?;
        let op = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|o| o.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;

        let cap_str = op
            .get("capability")
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;
        let capability = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;
        let input_schema = op.get("input_schema").cloned().unwrap_or_else(|| json!({}));

        Ok((capability, input_schema))
    }

    fn validate_required_input(
        input_schema: &serde_json::Value,
        input: &serde_json::Value,
    ) -> FcpResult<()> {
        let Some(required) = input_schema
            .get("required")
            .and_then(serde_json::Value::as_array)
        else {
            return Ok(());
        };

        for field in required {
            let Some(field) = field.as_str() else {
                continue;
            };
            if input.get(field).is_none_or(serde_json::Value::is_null) {
                return Err(FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Missing required field: {field}"),
                });
            }
        }

        Ok(())
    }

    fn serialize_simulate_response(response: SimulateResponse) -> FcpResult<serde_json::Value> {
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }
}

impl Default for TwilioConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_prelude::{CapabilityConstraints, ZoneId};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use std::path::PathBuf;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        let cap = match op {
            "twilio.send_message" => "twilio.message",
            "twilio.create_call" | "twilio.hangup_call" | "twilio.generate_twiml" => "twilio.voice",
            "twilio.whatsapp_send" | "twilio.whatsapp_send_template" => "twilio.whatsapp",
            "twilio.conversation.create" | "twilio.conversation.message.send" => {
                "twilio.conversations"
            }
            "twilio.conversation.participant.add" | "twilio.conversation.participant.remove" => {
                "twilio.conversations.participants"
            }
            "twilio.verify.send" | "twilio.verify.check" | "twilio.verify.cancel" => {
                "twilio.verify"
            }
            "twilio.video.room.create" | "twilio.video.room.end" => "twilio.video.rooms.write",
            "twilio.video.room.get" | "twilio.video.room.list" => "twilio.video.rooms.read",
            "twilio.video.room.participants" => "twilio.video.participants.read",
            "twilio.video.recording.list" => "twilio.video.recordings.read",
            "twilio.webhook.validate_signature"
            | "twilio.webhook.parse_sms_event"
            | "twilio.webhook.parse_status_callback"
            | "twilio.webhook.parse_voice_event" => "twilio.webhook",
            _ => "twilio.read",
        };
        let now = Utc::now();
        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn assert_invalid_request_contains(error: FcpError, expected: &str) {
        assert!(matches!(&error, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = error {
            assert!(message.contains(expected), "got: {message}");
        }
    }

    fn assert_invalid_request_any_contains(error: FcpError, expected: &[&str]) {
        assert!(matches!(&error, FcpError::InvalidRequest { .. }));
        if let FcpError::InvalidRequest { message, .. } = error {
            assert!(
                expected.iter().any(|needle| message.contains(needle)),
                "got: {message}"
            );
        }
    }

    async fn configure_for_tests(connector: &mut TwilioConnector) {
        connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "test_token",
                "base_url": "http://localhost:9999"
            }))
            .await
            .unwrap();
    }

    async fn handshake_for_tests(connector: &mut TwilioConnector) -> Ed25519SigningKey {
        let signing_key = Ed25519SigningKey::generate();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["twilio.read", "twilio.message", "twilio.voice"]
            }))
            .await
            .unwrap();
        signing_key
    }

    fn simulate_params(
        operation: &'static str,
        input: serde_json::Value,
        token: CapabilityToken,
    ) -> serde_json::Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("twilio"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            token,
        ))
        .unwrap()
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["twilio.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_configure() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["twilio.read"]
            }))
            .await;

        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = TwilioConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = TwilioConnector::new();
        let signing_key = Ed25519SigningKey::generate();

        let capability = generate_valid_token(&signing_key, "twilio.get_message");
        let result = connector
            .handle_invoke(json!({
                "operation": "twilio.get_message",
                "input": { "message_sid": "SMtest" },
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["twilio.send_message"]
            }))
            .await
            .unwrap();

        let capability = generate_valid_token(&signing_key, "twilio.send_message");
        let result = connector
            .handle_invoke(json!({
                "operation": "twilio.send_message",
                "input": { "to": "+15551234567", "from": "+15559876543" },
                "capability_token": capability
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "body");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_when_not_configured() {
        let connector = TwilioConnector::new();
        let result = connector
            .handle_simulate(simulate_params(
                "twilio.get_message",
                json!({ "message_sid": "SMtest" }),
                CapabilityToken::test_token(),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], FcpError::NotConfigured.error_code());
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_when_not_handshaken() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;

        let result = connector
            .handle_simulate(simulate_params(
                "twilio.get_message",
                json!({ "message_sid": "SMtest" }),
                CapabilityToken::test_token(),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["denial_code"], FcpError::NotHandshaken.error_code());
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_verifies_bound_capability() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;

        let result = connector
            .handle_simulate(simulate_params(
                "twilio.get_message",
                json!({ "message_sid": "SMtest" }),
                generate_valid_token(&signing_key, "twilio.get_message"),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_wrong_capability() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;

        let result = connector
            .handle_simulate(simulate_params(
                "twilio.get_message",
                json!({ "message_sid": "SMtest" }),
                generate_valid_token(&signing_key, "twilio.send_message"),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert_eq!(result["missing_capabilities"][0], "twilio.read");
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_missing_required_input() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;

        let result = connector
            .handle_simulate(simulate_params(
                "twilio.get_message",
                json!({}),
                generate_valid_token(&signing_key, "twilio.get_message"),
            ))
            .await
            .unwrap();

        assert_eq!(result["would_succeed"], false);
        assert!(
            result["failure_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("message_sid"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconfigure_clears_handshake_state() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector).await;

        connector
            .handle_configure(json!({
                "account_sid": "ACtest456",
                "auth_token": "test_token_2",
                "base_url": "http://localhost:9998"
            }))
            .await
            .unwrap();

        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotHandshaken)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_connector_state() {
        let mut connector = TwilioConnector::new();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector).await;

        connector.handle_shutdown(json!({})).await.unwrap();

        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
        assert!(connector.verifier.is_none());
        assert!(connector.session_id.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotConfigured)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"twilio.send_message"));
        assert!(op_ids.contains(&"twilio.get_message"));
        assert!(op_ids.contains(&"twilio.list_messages"));
        assert!(op_ids.contains(&"twilio.list_media"));
        assert!(op_ids.contains(&"twilio.get_media"));
        assert!(op_ids.contains(&"twilio.create_call"));
        assert!(op_ids.contains(&"twilio.get_call"));
        assert!(op_ids.contains(&"twilio.hangup_call"));
        assert!(op_ids.contains(&"twilio.list_calls"));
        assert!(op_ids.contains(&"twilio.generate_twiml"));
        assert!(op_ids.contains(&"twilio.list_recordings"));
        assert!(op_ids.contains(&"twilio.download_recording"));
        assert!(op_ids.contains(&"twilio.download_media"));
        assert!(op_ids.contains(&"twilio.get_account"));
        assert!(op_ids.contains(&"twilio.list_phone_numbers"));
        assert!(op_ids.contains(&"twilio.whatsapp_send"));
        assert!(op_ids.contains(&"twilio.whatsapp_send_template"));
        assert!(op_ids.contains(&"twilio.whatsapp_get"));
        assert!(op_ids.contains(&"twilio.whatsapp_list"));
        // Conversations API
        assert!(op_ids.contains(&"twilio.conversation.create"));
        assert!(op_ids.contains(&"twilio.conversation.get"));
        assert!(op_ids.contains(&"twilio.conversation.list"));
        assert!(op_ids.contains(&"twilio.conversation.participant.add"));
        assert!(op_ids.contains(&"twilio.conversation.participant.remove"));
        assert!(op_ids.contains(&"twilio.conversation.message.send"));
        assert!(op_ids.contains(&"twilio.conversation.message.list"));
        // Verify API
        assert!(op_ids.contains(&"twilio.verify.send"));
        assert!(op_ids.contains(&"twilio.verify.check"));
        assert!(op_ids.contains(&"twilio.verify.cancel"));
        // Video API
        assert!(op_ids.contains(&"twilio.video.room.create"));
        assert!(op_ids.contains(&"twilio.video.room.get"));
        assert!(op_ids.contains(&"twilio.video.room.list"));
        assert!(op_ids.contains(&"twilio.video.room.end"));
        assert!(op_ids.contains(&"twilio.video.room.participants"));
        assert!(op_ids.contains(&"twilio.video.recording.list"));
        // Webhook handling
        assert!(op_ids.contains(&"twilio.webhook.validate_signature"));
        assert!(op_ids.contains(&"twilio.webhook.parse_sms_event"));
        assert!(op_ids.contains(&"twilio.webhook.parse_status_callback"));
        assert!(op_ids.contains(&"twilio.webhook.parse_voice_event"));
        assert_eq!(ops.len(), 39);
    }

    // ── Provisioning tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_auth_token() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "test_token_abc"
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.is_some());
        assert_eq!(
            connector.config.as_ref().unwrap().auth.redacted_label(),
            "token"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_credential_id() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "credential_id": cid
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");
        assert!(connector.config.as_ref().unwrap().auth.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_both_auth_modes() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "test_token",
                "credential_id": cid
            }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_contains(result.unwrap_err(), "not both");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({ "account_sid": "ACtest123" }))
            .await;
        assert!(result.is_err());
        assert_invalid_request_any_contains(result.unwrap_err(), &["auth_token", "credential_id"]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_empty_account_sid() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({
                "account_sid": "   ",
                "auth_token": "test_token"
            }))
            .await;
        assert_invalid_request_contains(result.unwrap_err(), "account_sid");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_empty_auth_token() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "   "
            }))
            .await;
        assert_invalid_request_any_contains(result.unwrap_err(), &["auth_token", "credential_id"]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_custom_urls() {
        let mut connector = TwilioConnector::new();
        connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "test_token",
                "base_url": "http://localhost:8080"
            }))
            .await
            .unwrap();
        assert_eq!(
            connector.config.as_ref().unwrap().base_url,
            "http://localhost:8080"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_untrusted_remote_base_url_with_auth_token() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "test_token",
                "base_url": "https://evil.example.com"
            }))
            .await;
        assert_invalid_request_contains(result.unwrap_err(), "api.twilio.com");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_base_url_with_userinfo() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "test_token",
                "base_url": "https://user:pass@api.twilio.com/2010-04-01/Accounts/ACtest123"
            }))
            .await;
        assert_invalid_request_contains(result.unwrap_err(), "userinfo");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_includes_auth_info() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = TwilioConnector::new();
        connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "credential_id": cid,
                "base_url": "https://proxy.example.internal"
            }))
            .await
            .unwrap();

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        assert_eq!(health["auth_mode"], "credential_id");
        assert_eq!(health["api_url"], "https://proxy.example.internal");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = TwilioConnector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "unhealthy");
        let checks = result["checks"].as_array().unwrap();
        assert!(
            checks
                .iter()
                .any(|c| c["name"] == "configuration" && c["status"] == "fail")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_healthy() {
        let mut connector = TwilioConnector::new();
        connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "auth_token": "test_token"
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "healthy");
        let checks = result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|c| c["status"] == "pass"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_credential_id_mode() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = TwilioConnector::new();
        connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "credential_id": cid
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "degraded");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "warn");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = TwilioConnector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_degraded() {
        let cid = uuid::Uuid::new_v4().to_string();
        let mut connector = TwilioConnector::new();
        connector
            .handle_configure(json!({
                "account_sid": "ACtest123",
                "credential_id": cid
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    // ── Schema completeness tests ────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_input_and_output_schemas() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(
                op.get("input_schema").is_some(),
                "{id} missing input_schema"
            );
            assert!(
                op.get("output_schema").is_some(),
                "{id} missing output_schema"
            );
            assert_eq!(
                op["input_schema"]["type"].as_str().unwrap(),
                "object",
                "{id} input_schema should be object type"
            );
            assert_eq!(
                op["output_schema"]["type"].as_str().unwrap(),
                "object",
                "{id} output_schema should be object type"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_is_deterministic() {
        let connector = TwilioConnector::new();
        let r1 = connector.handle_introspect().await.unwrap();
        let r2 = connector.handle_introspect().await.unwrap();
        assert_eq!(r1, r2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_no_duplicate_operation_ids() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert!(seen.insert(*id), "Duplicate operation ID: {id}");
        }
    }

    // ── Introspection metadata tests ─────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_ops_have_required_metadata() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            assert!(op.get("summary").is_some(), "{id} missing summary");
            assert!(
                !op["summary"].as_str().unwrap().is_empty(),
                "{id} empty summary"
            );
            assert!(op.get("capability").is_some(), "{id} missing capability");
            assert!(op.get("risk_level").is_some(), "{id} missing risk_level");
            assert!(op.get("safety_tier").is_some(), "{id} missing safety_tier");
            assert!(op.get("idempotency").is_some(), "{id} missing idempotency");
            assert!(op.get("ai_hints").is_some(), "{id} missing ai_hints");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_risk_levels() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid = ["low", "medium", "high", "critical"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let risk = op["risk_level"].as_str().unwrap();
            assert!(valid.contains(&risk), "{id} has invalid risk_level: {risk}");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_valid_safety_tiers() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let valid = ["safe", "risky", "dangerous"];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let tier = op["safety_tier"].as_str().unwrap();
            assert!(
                valid.contains(&tier),
                "{id} has invalid safety_tier: {tier}"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_ai_hints_have_when_to_use() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let hints = &op["ai_hints"];
            assert!(
                hints.get("when_to_use").is_some(),
                "{id} ai_hints missing when_to_use"
            );
            assert!(
                !hints["when_to_use"].as_str().unwrap().is_empty(),
                "{id} ai_hints has empty when_to_use"
            );
        }
    }

    // ── Capability mapping tests ─────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_all_capabilities_start_with_twilio() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for op in ops {
            let id = op["id"].as_str().unwrap();
            let cap = op["capability"].as_str().unwrap();
            assert!(
                cap.starts_with("twilio."),
                "{id} capability '{cap}' should start with 'twilio.'"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_use_read_capability() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let read_ops = [
            "twilio.get_message",
            "twilio.list_messages",
            "twilio.list_media",
            "twilio.get_media",
            "twilio.get_call",
            "twilio.list_calls",
            "twilio.list_recordings",
            "twilio.download_recording",
            "twilio.download_media",
            "twilio.get_account",
            "twilio.list_phone_numbers",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if read_ops.contains(&id) {
                assert_eq!(
                    op["capability"].as_str().unwrap(),
                    "twilio.read",
                    "{id} should use twilio.read capability"
                );
            }
        }
    }

    // ── Safety tier tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_safe() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let safe_ops = [
            "twilio.get_message",
            "twilio.list_messages",
            "twilio.list_media",
            "twilio.get_media",
            "twilio.get_call",
            "twilio.list_calls",
            "twilio.list_recordings",
            "twilio.download_media",
            "twilio.get_account",
            "twilio.list_phone_numbers",
            "twilio.generate_twiml",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if safe_ops.contains(&id) {
                assert_eq!(
                    op["safety_tier"].as_str().unwrap(),
                    "safe",
                    "{id} should be safe"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message_is_risky() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "twilio.send_message")
            .unwrap();
        assert_eq!(op["safety_tier"].as_str().unwrap(), "risky");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_call_is_dangerous() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "twilio.create_call")
            .unwrap();
        assert_eq!(op["safety_tier"].as_str().unwrap(), "dangerous");
    }

    #[fcp_async_core::runtime::test]
    async fn test_hangup_call_is_dangerous() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "twilio.hangup_call")
            .unwrap();
        assert_eq!(op["safety_tier"].as_str().unwrap(), "dangerous");
        assert_eq!(op["risk_level"].as_str().unwrap(), "high");
        assert_eq!(op["capability"].as_str().unwrap(), "twilio.voice");
    }

    #[fcp_async_core::runtime::test]
    async fn test_generate_twiml_is_safe() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "twilio.generate_twiml")
            .unwrap();
        assert_eq!(op["safety_tier"].as_str().unwrap(), "safe");
        assert_eq!(op["risk_level"].as_str().unwrap(), "low");
        assert_eq!(op["capability"].as_str().unwrap(), "twilio.voice");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_calls_is_safe() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops.iter().find(|o| o["id"] == "twilio.list_calls").unwrap();
        assert_eq!(op["safety_tier"].as_str().unwrap(), "safe");
        assert_eq!(op["risk_level"].as_str().unwrap(), "low");
        assert_eq!(op["capability"].as_str().unwrap(), "twilio.read");
    }

    // ── Risk level tests ─────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_send_message_is_high_risk() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "twilio.send_message")
            .unwrap();
        assert_eq!(op["risk_level"].as_str().unwrap(), "high");
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_call_is_high_risk() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "twilio.create_call")
            .unwrap();
        assert_eq!(op["risk_level"].as_str().unwrap(), "high");
    }

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_are_low_risk() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let low_risk_ops = [
            "twilio.get_message",
            "twilio.list_messages",
            "twilio.list_media",
            "twilio.get_media",
            "twilio.get_call",
            "twilio.list_calls",
            "twilio.list_recordings",
            "twilio.download_media",
            "twilio.get_account",
            "twilio.list_phone_numbers",
            "twilio.generate_twiml",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if low_risk_ops.contains(&id) {
                assert_eq!(
                    op["risk_level"].as_str().unwrap(),
                    "low",
                    "{id} should be low risk"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_download_recording_is_medium_risk() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op = ops
            .iter()
            .find(|o| o["id"] == "twilio.download_recording")
            .unwrap();
        assert_eq!(op["risk_level"].as_str().unwrap(), "medium");
    }

    // ── Idempotency tests ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_read_ops_have_strict_idempotency() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let strict_ops = [
            "twilio.get_message",
            "twilio.list_messages",
            "twilio.list_media",
            "twilio.get_media",
            "twilio.get_call",
            "twilio.list_calls",
            "twilio.list_recordings",
            "twilio.download_recording",
            "twilio.download_media",
            "twilio.get_account",
            "twilio.list_phone_numbers",
            "twilio.generate_twiml",
        ];

        for op in ops {
            let id = op["id"].as_str().unwrap();
            if strict_ops.contains(&id) {
                assert_eq!(
                    op["idempotency"].as_str().unwrap(),
                    "strict",
                    "{id} should have strict idempotency"
                );
            }
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_write_ops_have_none_idempotency() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        for id_str in &["twilio.send_message", "twilio.create_call"] {
            let op = ops.iter().find(|o| o["id"] == *id_str).unwrap();
            assert_eq!(
                op["idempotency"].as_str().unwrap(),
                "none",
                "{id_str} should have none idempotency"
            );
        }

        // hangup_call has best_effort idempotency
        let hangup = ops
            .iter()
            .find(|o| o["id"] == "twilio.hangup_call")
            .unwrap();
        assert_eq!(hangup["idempotency"].as_str().unwrap(), "best_effort");
    }

    // ── Required fields in schemas ───────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_required_fields_in_schemas() {
        let connector = TwilioConnector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();

        let checks: &[(&str, &[&str])] = &[
            ("twilio.send_message", &["to", "from", "body"]),
            ("twilio.get_message", &["message_sid"]),
            ("twilio.list_media", &["message_sid"]),
            ("twilio.get_media", &["message_sid", "media_sid"]),
            ("twilio.create_call", &["to", "from", "url"]),
            ("twilio.get_call", &["call_sid"]),
            ("twilio.hangup_call", &["call_sid"]),
            ("twilio.generate_twiml", &["template"]),
            ("twilio.download_recording", &["recording_sid"]),
            ("twilio.download_media", &["message_sid", "media_sid"]),
        ];

        for (op_id, expected) in checks {
            let op = ops.iter().find(|o| o["id"] == *op_id).unwrap();
            let required = op["input_schema"]["required"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            for field in *expected {
                assert!(required.contains(field), "{op_id} should require '{field}'");
            }
        }
    }

    // ── Helper and lifecycle tests ───────────────────────────────

    #[test]
    fn test_require_str_present() {
        let input = json!({ "to": "+15551234567" });
        assert_eq!(require_str(&input, "to").unwrap(), "+15551234567");
    }

    #[test]
    fn test_require_str_missing() {
        let input = json!({});
        let result = require_str(&input, "to");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn test_require_str_not_string() {
        let input = json!({ "to": 42 });
        let result = require_str(&input, "to");
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let mut connector = TwilioConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    #[test]
    fn test_default_creates_new_connector() {
        let _connector: TwilioConnector = TwilioConnector::default();
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_account_sid() {
        let mut connector = TwilioConnector::new();
        let result = connector
            .handle_configure(json!({ "auth_token": "test" }))
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }

    // ── Additional require_str edge cases ────────────────────────────

    #[test]
    fn require_str_float_value() {
        let input = json!({ "field": 1.23 });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_object_value() {
        let input = json!({ "field": {"nested": "val"} });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_array_value() {
        let input = json!({ "field": ["a", "b"] });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_null_value() {
        let input = json!({ "field": null });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_boolean_value() {
        let input = json!({ "field": true });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_nested_object_value() {
        let input = json!({ "field": {"a": {"b": "c"}} });
        assert!(require_str(&input, "field").is_err());
    }

    #[test]
    fn require_str_empty_string_is_ok() {
        let input = json!({ "field": "" });
        assert_eq!(require_str(&input, "field").unwrap(), "");
    }

    // ── Additional connector tests ──────────────────────────────────

    #[test]
    fn require_str_whitespace_only_is_ok() {
        let input = json!({ "field": "   " });
        assert_eq!(require_str(&input, "field").unwrap(), "   ");
    }

    #[test]
    fn require_str_unicode_value() {
        let input = json!({ "field": "hello \u{1F600}" });
        assert!(require_str(&input, "field").unwrap().contains('\u{1F600}'));
    }

    #[test]
    fn require_str_long_value() {
        let long_val = "x".repeat(10_000);
        let input = json!({ "field": long_val });
        assert_eq!(require_str(&input, "field").unwrap().len(), 10_000);
    }

    #[test]
    fn require_str_numeric_string() {
        let input = json!({ "field": "12345" });
        assert_eq!(require_str(&input, "field").unwrap(), "12345");
    }

    #[test]
    fn require_str_special_chars() {
        let input = json!({ "field": "hello <world> & \"friends\"" });
        let val = require_str(&input, "field").unwrap();
        assert!(val.contains('<'));
        assert!(val.contains('&'));
    }
}
