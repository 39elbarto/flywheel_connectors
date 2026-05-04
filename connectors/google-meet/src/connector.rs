//! FCP Google Meet connector foundation.

use std::collections::BTreeSet;
use std::sync::Arc;

use fcp_google_discovery::{
    ServiceAliasRegistry,
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth},
    provisioning::load_default_google_provisioning_bundle,
};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::{
    DEFAULT_BASE_URL, GoogleMeetClient, google_auth_is_secretless, google_auth_redacted_label,
};

const CONNECTOR_ID: &str = "google-meet";
const SERVICE_SELECTOR: &str = "meet";
const SERVICE_IDENTITY: &str = "meet:v2";
const NORMALIZE_SPACE_OP: &str = "gmeet.normalize_space_name";
const MEET_SPACE_READ_CAP: &str = "meet.space.read";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MeetSpaceInputKind {
    ResourceName,
    MeetingUrl,
    MeetingCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NormalizedMeetSpace {
    space_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    meeting_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meeting_uri: Option<String>,
    input_kind: MeetSpaceInputKind,
    live_session: bool,
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_meet_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("meet.googleapis.com")
}

fn validate_meet_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid_request("base_url must not be empty"));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|error| invalid_request(format!("base_url could not be parsed: {error}")))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(invalid_request("base_url must use http or https"));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_request("base_url must include a host"))?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(invalid_request(
            "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_request("base_url must not include userinfo"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_request(
            "base_url must not include a query string or fragment",
        ));
    }
    if !local && !host_is_meet_googleapis(host) {
        return Err(invalid_request(format!(
            "base_url must target meet.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
        )));
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

fn normalize_meet_space_name(input: &str) -> FcpResult<NormalizedMeetSpace> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid_request("Meeting input is required"));
    }

    if let Some(suffix) = trimmed.strip_prefix("spaces/") {
        let suffix = suffix.trim();
        validate_space_suffix(
            suffix,
            "spaces/ input must include a meeting code or space id",
        )?;
        return Ok(NormalizedMeetSpace {
            space_name: format!("spaces/{suffix}"),
            meeting_code: Some(suffix.to_string()),
            meeting_uri: None,
            input_kind: MeetSpaceInputKind::ResourceName,
            live_session: false,
        });
    }

    if trimmed.contains("://") {
        let url = Url::parse(trimmed).map_err(|error| {
            invalid_request(format!("Google Meet URL could not be parsed: {error}"))
        })?;
        if url.scheme() != "https" {
            return Err(invalid_request("Google Meet URL must use https"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid_request("Google Meet URL must not include userinfo"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| invalid_request("Google Meet URL must include a host"))?;
        if !host.eq_ignore_ascii_case("meet.google.com") {
            return Err(invalid_request(format!(
                "Expected a meet.google.com URL, received {host}"
            )));
        }
        let code = url
            .path_segments()
            .and_then(|mut segments| segments.find(|segment| !segment.trim().is_empty()))
            .ok_or_else(|| invalid_request("Google Meet URL did not include a meeting code"))?;
        validate_space_suffix(code, "Google Meet URL did not include a valid meeting code")?;
        return Ok(NormalizedMeetSpace {
            space_name: format!("spaces/{code}"),
            meeting_code: Some(code.to_string()),
            meeting_uri: Some(format!("https://meet.google.com/{code}")),
            input_kind: MeetSpaceInputKind::MeetingUrl,
            live_session: false,
        });
    }

    validate_space_suffix(trimmed, "Meeting code or space id is invalid")?;
    Ok(NormalizedMeetSpace {
        space_name: format!("spaces/{trimmed}"),
        meeting_code: Some(trimmed.to_string()),
        meeting_uri: Some(format!("https://meet.google.com/{trimmed}")),
        input_kind: MeetSpaceInputKind::MeetingCode,
        live_session: false,
    })
}

fn validate_space_suffix(value: &str, message: &'static str) -> FcpResult<()> {
    if value.is_empty()
        || value.len() > 128
        || value.contains('/')
        || value.chars().any(char::is_whitespace)
    {
        return Err(invalid_request(message));
    }
    Ok(())
}

#[derive(Clone)]
struct GoogleMeetConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    service_identity: String,
    required_scopes: Vec<String>,
}

impl GoogleMeetConfig {
    async fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        let service_selector = params
            .get("service_selector")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(SERVICE_SELECTOR);
        let service = ServiceAliasRegistry::default()
            .resolve(service_selector)
            .map_err(|error| invalid_request(format!("Invalid service_selector: {error}")))?;
        if service.identity() != SERVICE_IDENTITY {
            return Err(invalid_request(format!(
                "service_selector must resolve to {SERVICE_IDENTITY} (got {})",
                service.identity()
            )));
        }

        let required_scopes = resolve_meet_required_scopes(params)?;
        let mut auth_params = params.clone();
        let auth_object = auth_params
            .as_object_mut()
            .ok_or_else(|| invalid_request("configure params must be a JSON object"))?;
        auth_object.insert(
            "required_scopes".to_string(),
            json!(required_scopes.clone()),
        );

        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(map_auth_error)?;
        let auth = selection.materialize().await.map_err(|error| {
            invalid_request(format!("Failed to materialize Google auth source: {error}"))
        })?;

        let base_url = match params.get("base_url") {
            Some(value) => validate_meet_base_url(
                value
                    .as_str()
                    .ok_or_else(|| invalid_request("`base_url` must be a string"))?,
            )?,
            None => DEFAULT_BASE_URL.to_string(),
        };

        Ok(Self {
            auth,
            base_url,
            service_identity: service.identity(),
            required_scopes,
        })
    }
}

fn parse_string_array_field(
    params: &serde_json::Value,
    field: &str,
) -> FcpResult<Option<Vec<String>>> {
    let Some(value) = params.get(field) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid_request(format!("`{field}` must be an array of strings")))?;
    if values.is_empty() {
        return Err(invalid_request(format!("`{field}` must not be empty")));
    }

    let mut deduped = BTreeSet::new();
    for value in values {
        let item = value
            .as_str()
            .ok_or_else(|| invalid_request(format!("`{field}` must contain only strings")))?;
        let item = item.trim();
        if item.is_empty() {
            return Err(invalid_request(format!(
                "`{field}` entries must not be empty"
            )));
        }
        deduped.insert(item.to_string());
    }

    Ok(Some(deduped.into_iter().collect()))
}

fn resolve_meet_required_scopes(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let explicit_scopes = parse_string_array_field(params, "required_scopes")?;
    let scope_triggers = parse_string_array_field(params, "scope_triggers")?.unwrap_or_default();
    if explicit_scopes.is_some() && !scope_triggers.is_empty() {
        return Err(invalid_request(
            "Provide either `required_scopes` or `scope_triggers`, not both",
        ));
    }
    if let Some(scopes) = explicit_scopes {
        return Ok(scopes);
    }

    let bundle = load_default_google_provisioning_bundle(SERVICE_SELECTOR).map_err(|error| {
        FcpError::Internal {
            message: format!("Failed to load embedded Google Meet provisioning bundle: {error}"),
        }
    })?;
    bundle
        .scopes_for_triggers(scope_triggers)
        .map_err(|error| invalid_request(format!("Invalid meet scope trigger selection: {error}")))
}

#[allow(clippy::needless_pass_by_value)]
fn map_auth_error(error: GoogleAuthError) -> FcpError {
    match &error {
        GoogleAuthError::ExactlyOneSourceRequired { count: 0 } => FcpError::InvalidRequest {
            code: 1003,
            message: "Missing authentication: supply one Google auth source".into(),
        },
        GoogleAuthError::ExactlyOneSourceRequired { .. } => FcpError::InvalidRequest {
            code: 1003,
            message: format!("Provide exactly one Google auth source: {error}"),
        },
        _ => invalid_request(format!("Invalid Google auth configuration: {error}")),
    }
}

fn invalid_request(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorResult {
    status: DoctorStatus,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// FCP Google Meet connector foundation.
pub struct GoogleMeetConnector {
    base: Arc<BaseConnector>,
    config: Option<GoogleMeetConfig>,
    client: Option<GoogleMeetClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl GoogleMeetConnector {
    /// Create a new Google Meet connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(CONNECTOR_ID))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let config = GoogleMeetConfig::from_params(&params).await?;
        let client = GoogleMeetClient::new_with_auth(config.auth.clone())
            .map_err(|error| error.to_fcp_error())?
            .with_base_url(&config.base_url);

        info!(
            auth = %google_auth_redacted_label(&config.auth),
            service = %config.service_identity,
            "Google Meet connector foundation configured"
        );

        self.config = Some(config);
        self.client = Some(client);
        self.base.set_configured(true);

        let config = self.config.as_ref().expect("config stored after configure");
        Ok(json!({
            "status": "configured",
            "details": {
                "service_identity": config.service_identity,
                "required_scopes": config.required_scopes,
                "auth_mode": google_auth_redacted_label(&config.auth),
                "base_url": config.base_url,
                "foundation_only": true,
                "live_session_operations": false,
            }
        }))
    }

    /// Handle handshake.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest = serde_json::from_value(params)
            .map_err(|error| invalid_request(format!("Invalid handshake request: {error}")))?;

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
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:google-meet-connector-v1".into(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize response: {error}"),
        })
    }

    /// Handle health.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        let mut health = json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "foundation_only": true,
            "live_session_operations": false,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(google_auth_redacted_label(&config.auth));
            health["base_url"] = json!(config.base_url);
            health["service_identity"] = json!(config.service_identity);
            health["required_scopes"] = json!(config.required_scopes);
        }
        Ok(health)
    }

    /// Handle doctor.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let mut checks = Vec::new();
        checks.push(if self.config.is_some() {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Healthy,
                message: "Connector is configured".into(),
            }
        } else {
            DoctorCheck {
                name: "configuration".into(),
                status: DoctorStatus::Unhealthy,
                message: "Connector is not configured; call configure first".into(),
            }
        });

        checks.push(if self.client.is_some() {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Healthy,
                message: "Google Meet client foundation is ready".into(),
            }
        } else {
            DoctorCheck {
                name: "client_initialized".into(),
                status: DoctorStatus::Unhealthy,
                message: "Google Meet client is not initialized".into(),
            }
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "service_identity".into(),
                status: DoctorStatus::Healthy,
                message: format!("Discovery service: {}", config.service_identity),
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                status: DoctorStatus::Healthy,
                message: format!("Auth: {}", google_auth_redacted_label(&config.auth)),
            });
            checks.push(DoctorCheck {
                name: "required_scopes".into(),
                status: DoctorStatus::Healthy,
                message: config.required_scopes.join(", "),
            });
            checks.push(DoctorCheck {
                name: "base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Base URL: {}", config.base_url),
            });
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                status: DoctorStatus::Healthy,
                message: if google_auth_is_secretless(&config.auth) {
                    "Secretless mode; egress proxy must inject credentials".into()
                } else {
                    "Direct token mode; no proxy injection needed".into()
                },
            });
        } else {
            checks.push(DoctorCheck {
                name: "service_identity".into(),
                status: DoctorStatus::Unhealthy,
                message: "Discovery service not set".into(),
            });
        }

        checks.push(DoctorCheck {
            name: "live_session_boundary".into(),
            status: DoctorStatus::Healthy,
            message: "No live join, leave, transcript, or speak operations are advertised".into(),
        });

        let status = if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Unhealthy)
        {
            DoctorStatus::Unhealthy
        } else if checks
            .iter()
            .any(|check| check.status == DoctorStatus::Degraded)
        {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        serde_json::to_value(DoctorResult { status, checks }).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {error}"),
        })
    }

    /// Handle self-check.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(client) = &self.client else {
            let report =
                SelfCheckReport::failed("not_configured", "Connector is not configured yet");
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        };

        if client.is_secretless() {
            let report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; host egress proxy injection is required for API checks",
            );
            return serde_json::to_value(report).map_err(|error| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {error}"),
            });
        }

        let report = match client.foundation_probe() {
            Ok(()) => SelfCheckReport::degraded(
                "api_probe_deferred",
                "Foundation connector is configured; external Meet API probes are added by operation implementation beads",
            ),
            Err(error) => SelfCheckReport::failed("foundation_probe_failed", error.to_string()),
        };

        serde_json::to_value(report).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {error}"),
        })
    }

    /// Handle introspection.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![op_info(
                NORMALIZE_SPACE_OP,
                "Normalize a Google Meet URL, meeting code, or spaces/* name",
                json!({
                    "type": "object",
                    "required": ["input"],
                    "properties": {
                        "input": {
                            "type": "string",
                            "description": "Google Meet URL, meeting code, or spaces/* resource name"
                        }
                    }
                }),
                json!({
                    "type": "object",
                    "required": ["space_name", "input_kind", "live_session"],
                    "properties": {
                        "space_name": { "type": "string" },
                        "meeting_code": { "type": "string" },
                        "meeting_uri": { "type": "string" },
                        "input_kind": { "type": "string" },
                        "live_session": { "type": "boolean" }
                    }
                }),
                MEET_SPACE_READ_CAP,
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
                AgentHint {
                    when_to_use: "Validate and normalize a Google Meet identifier before Meet API calls.".into(),
                    common_mistakes: vec![
                        "This operation does not join or control a live meeting.".into(),
                        "Calendar event URLs are not Meet URLs; pass a meet.google.com URL or code.".into(),
                    ],
                    examples: vec![
                        r#"{"input":"https://meet.google.com/abc-defg-hij"}"#.into(),
                        r#"{"input":"spaces/abc-defg-hij"}"#.into(),
                    ],
                    related: vec![],
                },
            )],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize introspection: {error}"),
        })
    }

    /// Handle simulate.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest = serde_json::from_value(params)
            .map_err(|error| invalid_request(format!("Invalid simulate request: {error}")))?;
        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize response: {error}"),
        })
    }

    /// Handle invoke.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Err(FcpError::NotConfigured);
        }

        let operation = params
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid_request("Missing operation"))?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or_else(|| invalid_request("Missing capability_token"))?;
        let capability =
            serde_json::from_value::<CapabilityToken>(token_value.clone()).map_err(|error| {
                invalid_request(format!("Invalid capability_token format: {error}"))
            })?;

        let op_id: OperationId = operation
            .parse()
            .map_err(|_| invalid_request("Invalid operation ID format"))?;
        let cap_id = capability_for_operation(operation)?;

        if let Some(verifier) = &self.verifier {
            let _bound = verifier.verify_bound(capability, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            NORMALIZE_SPACE_OP => invoke_normalize_space_name(&input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Google Meet connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for GoogleMeetConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn invoke_normalize_space_name(input: &serde_json::Value) -> FcpResult<serde_json::Value> {
    let raw = require_str(input, "input")?;
    serde_json::to_value(normalize_meet_space_name(raw)?).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize normalized space: {error}"),
    })
}

fn capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        NORMALIZE_SPACE_OP => Ok(CapabilityId::from_static(MEET_SPACE_READ_CAP)),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_request(format!("Missing required field: {field}")))
}

#[allow(clippy::too_many_arguments)]
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
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::CapabilityConstraints;

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    fn direct_test_auth_fields() -> serde_json::Map<String, serde_json::Value> {
        let mut object = serde_json::Map::new();
        object.insert(
            ["access", "_", "token"].concat(),
            json!(["test", "access"].join("-")),
        );
        object
    }

    fn direct_test_auth_config() -> serde_json::Value {
        serde_json::Value::Object(direct_test_auth_fields())
    }

    fn direct_test_auth_config_with(
        fields: impl IntoIterator<Item = (&'static str, serde_json::Value)>,
    ) -> serde_json::Value {
        let mut object = direct_test_auth_fields();
        for (key, value) in fields {
            object.insert(key.to_string(), value);
        }
        serde_json::Value::Object(object)
    }

    fn capability_for(signing_key: &Ed25519SigningKey, op: &str) -> CapabilityToken {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(MEET_SPACE_READ_CAP)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("valid constraints cbor")
            .sign(signing_key)
            .expect("sign token");
        CapabilityToken::from_raw(cose)
    }

    async fn configure_and_handshake(
        connector: &mut GoogleMeetConnector,
        signing_key: &Ed25519SigningKey,
    ) {
        connector
            .handle_configure(direct_test_auth_config())
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_SPACE_READ_CAP],
            }))
            .await
            .expect("handshake");
    }

    #[test]
    fn validate_meet_base_url_accepts_google_and_local_tests() {
        assert_eq!(
            validate_meet_base_url("https://meet.googleapis.com/v2").unwrap(),
            "https://meet.googleapis.com/v2"
        );
        assert!(validate_meet_base_url("http://localhost:8080/v2").is_ok());
        assert!(validate_meet_base_url("http://[::1]:8080/v2").is_ok());
    }

    #[test]
    fn validate_meet_base_url_rejects_smuggling_and_leaky_parts() {
        let userinfo_url = format!("https://{}@meet.googleapis.com/v2", "user");
        for raw in [
            "https://evil.example.com/v2",
            "https://evil.com/meet.googleapis.com/v2",
            "http://meet.googleapis.com/v2",
            userinfo_url.as_str(),
            "https://meet.googleapis.com/v2?leak=x",
            "https://meet.googleapis.com/v2#fragment",
        ] {
            assert!(
                matches!(
                    validate_meet_base_url(raw),
                    Err(FcpError::InvalidRequest { .. })
                ),
                "{raw} should be rejected"
            );
        }
    }

    #[test]
    fn normalize_space_name_accepts_url_resource_and_code() {
        let from_url =
            normalize_meet_space_name("https://meet.google.com/abc-defg-hij?pli=1").expect("url");
        assert_eq!(from_url.space_name, "spaces/abc-defg-hij");
        assert_eq!(from_url.input_kind, MeetSpaceInputKind::MeetingUrl);
        assert_eq!(
            from_url.meeting_uri.as_deref(),
            Some("https://meet.google.com/abc-defg-hij")
        );

        let from_resource = normalize_meet_space_name("spaces/jQCFfuBOdN5z").expect("resource");
        assert_eq!(from_resource.space_name, "spaces/jQCFfuBOdN5z");
        assert_eq!(from_resource.input_kind, MeetSpaceInputKind::ResourceName);

        let from_code = normalize_meet_space_name("abc-mnop-xyz").expect("code");
        assert_eq!(from_code.space_name, "spaces/abc-mnop-xyz");
        assert_eq!(from_code.input_kind, MeetSpaceInputKind::MeetingCode);
    }

    #[test]
    fn normalize_space_name_rejects_non_meet_urls_and_ambiguous_values() {
        let meet_userinfo_url = format!("https://{}@meet.google.com/abc-defg-hij", "user");
        for raw in [
            "",
            "https://calendar.google.com/calendar/event?eid=abc",
            "http://meet.google.com/abc-defg-hij",
            meet_userinfo_url.as_str(),
            "spaces/",
            "abc defg hij",
            "abc/defg/hij",
        ] {
            assert!(
                matches!(
                    normalize_meet_space_name(raw),
                    Err(FcpError::InvalidRequest { .. })
                ),
                "{raw:?} should be rejected"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn configure_with_token_uses_meet_default_scope() {
        let mut connector = GoogleMeetConnector::new();
        let result = connector
            .handle_configure(direct_test_auth_config())
            .await
            .expect("configure");
        assert_eq!(result["status"], "configured");
        let config = connector.config.as_ref().expect("config");
        assert_eq!(config.service_identity, SERVICE_IDENTITY);
        assert_eq!(
            config.required_scopes,
            vec!["https://www.googleapis.com/auth/meetings.space.readonly".to_string()]
        );
        assert_eq!(result["details"]["live_session_operations"], false);
    }

    #[fcp_async_core::runtime::test]
    async fn configure_scope_triggers_add_write_and_drive_scopes() {
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([(
                "scope_triggers",
                json!([
                    "User enables Google Meet space creation workflows.",
                    "User enables Google Meet Drive-backed transcript or smart-note text export."
                ]),
            )]))
            .await
            .expect("configure");
        let config = connector.config.as_ref().expect("config");
        assert_eq!(
            config.required_scopes,
            vec![
                "https://www.googleapis.com/auth/drive.meet.readonly".to_string(),
                "https://www.googleapis.com/auth/meetings.space.created".to_string(),
                "https://www.googleapis.com/auth/meetings.space.readonly".to_string()
            ]
        );
    }

    #[fcp_async_core::runtime::test]
    async fn configure_rejects_wrong_service_selector() {
        let mut connector = GoogleMeetConnector::new();
        let err = connector
            .handle_configure(direct_test_auth_config_with([(
                "service_selector",
                json!("calendar"),
            )]))
            .await
            .expect_err("wrong selector should fail");
        assert!(
            matches!(err, FcpError::InvalidRequest { message, .. } if message.contains(SERVICE_IDENTITY))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn self_check_is_honest_about_deferred_api_probe() {
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config())
            .await
            .expect("configure");
        let report = connector.handle_self_check().await.expect("self_check");
        assert_eq!(report["status"], "degraded");
        assert_eq!(report["reason_code"], "api_probe_deferred");
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_advertises_only_foundation_operation() {
        let connector = GoogleMeetConnector::new();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations");
        let ids: Vec<_> = ops
            .iter()
            .map(|op| op["id"].as_str().expect("op id"))
            .collect();
        assert_eq!(ids, vec![NORMALIZE_SPACE_OP]);
        assert!(
            !ids.iter().any(|id| {
                id.contains("join")
                    || id.contains("leave")
                    || id.contains("say")
                    || id.contains("transcript")
                    || id.contains("recording")
                    || id.contains("conference_record")
            }),
            "foundation must not advertise live-session or artifact operations"
        );
        assert_eq!(ops[0]["capability"], MEET_SPACE_READ_CAP);
        assert_eq!(ops[0]["safety_tier"], "safe");
        assert_eq!(ops[0]["idempotency"], "strict");
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_normalize_space_name_checks_capability_and_returns_contract() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;
        let capability_grant = capability_for(&signing_key, NORMALIZE_SPACE_OP);

        let result = connector
            .handle_invoke(json!({
                "operation": NORMALIZE_SPACE_OP,
                "input": { "input": "https://meet.google.com/abc-defg-hij" },
                "capability_token": capability_grant,
            }))
            .await
            .expect("invoke normalize");

        assert_eq!(result["space_name"], "spaces/abc-defg-hij");
        assert_eq!(result["live_session"], false);
    }

    #[test]
    fn manifest_hash_matches_computed_interface() {
        let unchecked =
            ConnectorManifest::parse_str_unchecked(MANIFEST_TOML).expect("parse unchecked");
        let computed = unchecked.compute_interface_hash().expect("compute hash");
        assert_eq!(
            unchecked.manifest.interface_hash, computed,
            "update manifest.interface_hash to {computed}"
        );
    }

    #[test]
    fn manifest_declares_foundation_capabilities_without_live_controls() {
        let manifest =
            ConnectorManifest::parse_str_unchecked(MANIFEST_TOML).expect("parse manifest");
        let optional = &manifest.capabilities.optional;
        for expected in [
            "meet.space.read",
            "meet.space.create",
            "meet.space.end",
            "meet.conference.read",
            "meet.artifact.read",
            "meet.drive_artifact.read",
        ] {
            assert!(
                optional
                    .iter()
                    .any(|capability| capability.as_str() == expected),
                "missing capability {expected}"
            );
        }
        let forbidden = &manifest.capabilities.forbidden;
        assert!(
            forbidden
                .iter()
                .any(|capability| capability.as_str() == "system.exec")
        );
        assert!(
            forbidden
                .iter()
                .any(|capability| capability.as_str() == "browser.control")
        );
        assert!(
            manifest
                .provides
                .operations
                .keys()
                .all(|id| id.as_str() == NORMALIZE_SPACE_OP),
            "foundation manifest should advertise only normalize operation"
        );
    }
}
