//! FCP Google Meet connector foundation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use fcp_google_discovery::{
    ServiceAliasRegistry,
    auth::{GoogleAuthError, GoogleAuthSelection, GoogleMaterializedAuth},
    provisioning::load_default_google_provisioning_bundle,
};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel,
    SafetyTier, SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, instrument};

use crate::client::{
    DEFAULT_BASE_URL, DEFAULT_DRIVE_EXPORT_BASE_URL, GoogleMeetAttendanceRow, GoogleMeetClient,
    GoogleMeetConferenceRecord, GoogleMeetDocsDestination, GoogleMeetParticipant,
    GoogleMeetParticipantSession, GoogleMeetRecording, GoogleMeetSmartNote, GoogleMeetSpaceConfig,
    GoogleMeetTranscript, extract_docs_destination_document_id, google_auth_is_secretless,
    google_auth_redacted_label, validate_drive_document_id,
};
use crate::error::{GoogleMeetError, GoogleMeetResult};

const CONNECTOR_ID: &str = "google-meet";
const SERVICE_SELECTOR: &str = "meet";
const SERVICE_IDENTITY: &str = "meet:v2";
const NORMALIZE_SPACE_OP: &str = "gmeet.normalize_space_name";
const MEET_SPACE_READ_CAP: &str = "meet.space.read";
const MEET_SPACE_CREATE_CAP: &str = "meet.space.create";
const MEET_SPACE_END_CAP: &str = "meet.space.end";
const MEET_CONFERENCE_READ_CAP: &str = "meet.conference.read";
const MEET_ARTIFACT_READ_CAP: &str = "meet.artifact.read";
const MEET_DRIVE_ARTIFACT_READ_CAP: &str = "meet.drive_artifact.read";
const SPACE_GET_OP: &str = "gmeet.space.get";
const SPACE_CREATE_OP: &str = "gmeet.space.create";
const SPACE_END_ACTIVE_CONFERENCE_OP: &str = "gmeet.space.end_active_conference";
const CONFERENCE_RECORD_GET_OP: &str = "gmeet.conference_record.get";
const CONFERENCE_RECORDS_LIST_OP: &str = "gmeet.conference_records.list";
const CONFERENCE_RECORD_LATEST_OP: &str = "gmeet.conference_record.latest";
const PARTICIPANTS_LIST_OP: &str = "gmeet.participants.list";
const PARTICIPANT_SESSIONS_LIST_OP: &str = "gmeet.participant_sessions.list";
const ATTENDANCE_LIST_OP: &str = "gmeet.attendance.list";
const RECORDINGS_LIST_OP: &str = "gmeet.recordings.list";
const TRANSCRIPTS_LIST_OP: &str = "gmeet.transcripts.list";
const TRANSCRIPT_ENTRIES_LIST_OP: &str = "gmeet.transcript_entries.list";
const SMART_NOTES_LIST_OP: &str = "gmeet.smart_notes.list";
const TRANSCRIPTS_WITH_TEXT_LIST_OP: &str = "gmeet.transcripts.with_text.list";
const SMART_NOTES_WITH_TEXT_LIST_OP: &str = "gmeet.smart_notes.with_text.list";
const DRIVE_DOCUMENT_TEXT_EXPORT_OP: &str = "gmeet.drive_document_text.export";
const DEFAULT_PAGE_SIZE: u32 = 100;
const MAX_CONFERENCE_RECORD_PAGE_SIZE: u32 = 100;
const MAX_PARTICIPANT_PAGE_SIZE: u32 = 250;
const MAX_ARTIFACT_PAGE_SIZE: u32 = 100;
const DEFAULT_MAX_ITEMS: usize = 100;
const MAX_ITEMS_CAP: usize = 1_000;
const DEFAULT_DRIVE_EXPORT_MAX_BYTES: usize = 1_048_576;
const MAX_DRIVE_EXPORT_BYTES: usize = 10 * 1_048_576;
const MEETINGS_SPACE_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/meetings.space.readonly";
const MEETINGS_SPACE_CREATED_SCOPE: &str = "https://www.googleapis.com/auth/meetings.space.created";
const MEETINGS_SPACE_SETTINGS_SCOPE: &str =
    "https://www.googleapis.com/auth/meetings.space.settings";
const MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/meetings.conference.media.readonly";
const DRIVE_MEET_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/drive.meet.readonly";

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

fn host_is_drive_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("www.googleapis.com")
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

fn validate_drive_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid_request("drive_base_url must not be empty"));
    }

    let parsed = Url::parse(trimmed)
        .map_err(|error| invalid_request(format!("drive_base_url could not be parsed: {error}")))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(invalid_request("drive_base_url must use http or https"));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_request("drive_base_url must include a host"))?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(invalid_request(
            "drive_base_url must use https unless targeting localhost/127.0.0.1/::1 for tests",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_request("drive_base_url must not include userinfo"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_request(
            "drive_base_url must not include a query string or fragment",
        ));
    }
    if !local && !host_is_drive_googleapis(host) {
        return Err(invalid_request(format!(
            "drive_base_url must target www.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
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

fn normalize_space_config(input: &serde_json::Value) -> FcpResult<Option<GoogleMeetSpaceConfig>> {
    let Some(value) = input.get("config") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid_request("`config` must be an object when provided"))?;
    let allowed = [
        "access_type",
        "accessType",
        "entry_point_access",
        "entryPointAccess",
    ];
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid_request(format!(
                "`config.{key}` is not supported for Google Meet space creation"
            )));
        }
    }

    let access_type = optional_config_enum(
        object,
        "access_type",
        "accessType",
        "config.access_type",
        &["OPEN", "TRUSTED", "RESTRICTED"],
    )?;
    let entry_point_access = optional_config_enum(
        object,
        "entry_point_access",
        "entryPointAccess",
        "config.entry_point_access",
        &["ALL", "CREATOR_APP_ONLY"],
    )?;

    if access_type.is_none() && entry_point_access.is_none() {
        return Ok(None);
    }

    Ok(Some(GoogleMeetSpaceConfig {
        access_type,
        entry_point_access,
    }))
}

fn optional_config_enum(
    object: &serde_json::Map<String, serde_json::Value>,
    snake_key: &str,
    camel_key: &str,
    label: &str,
    allowed: &[&'static str],
) -> FcpResult<Option<String>> {
    let snake = object.get(snake_key);
    let camel = object.get(camel_key);
    if snake.is_some() && camel.is_some() {
        return Err(invalid_request(format!(
            "Provide only one of `{snake_key}` or `{camel_key}`"
        )));
    }
    let Some(value) = snake.or(camel) else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| invalid_request(format!("`{label}` must be a string")))?;
    let normalized = raw.trim().replace('-', "_").to_ascii_uppercase();
    if allowed.contains(&normalized.as_str()) {
        Ok(Some(normalized))
    } else {
        Err(invalid_request(format!(
            "`{label}` must be one of {}",
            allowed.join(", ")
        )))
    }
}

fn create_space_required_scopes(config: Option<&GoogleMeetSpaceConfig>) -> Vec<&'static str> {
    let mut scopes = vec![MEETINGS_SPACE_CREATED_SCOPE];
    if config
        .is_some_and(|config| config.access_type.is_some() || config.entry_point_access.is_some())
    {
        scopes.push(MEETINGS_SPACE_SETTINGS_SCOPE);
    }
    scopes
}

#[derive(Clone)]
struct GoogleMeetConfig {
    auth: GoogleMaterializedAuth,
    base_url: String,
    drive_base_url: String,
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
        let drive_base_url = match params.get("drive_base_url") {
            Some(value) => validate_drive_base_url(
                value
                    .as_str()
                    .ok_or_else(|| invalid_request("`drive_base_url` must be a string"))?,
            )?,
            None => DEFAULT_DRIVE_EXPORT_BASE_URL.to_string(),
        };

        Ok(Self {
            auth,
            base_url,
            drive_base_url,
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

fn scope_doctor_check(
    name: &str,
    configured_scopes: &[String],
    scope: &'static str,
    missing_message: &'static str,
) -> DoctorCheck {
    if configured_scopes.iter().any(|configured| configured == scope) {
        DoctorCheck {
            name: name.into(),
            status: DoctorStatus::Healthy,
            message: format!("Configured scope: {scope}"),
        }
    } else {
        DoctorCheck {
            name: name.into(),
            status: DoctorStatus::Degraded,
            message: missing_message.into(),
        }
    }
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
            .with_base_url(&config.base_url)
            .with_drive_base_url(&config.drive_base_url);

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
                "drive_base_url": config.drive_base_url,
                "foundation_only": false,
                "api_read_operations": true,
                "artifact_operations": true,
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
            "foundation_only": false,
            "api_read_operations": true,
            "live_session_operations": false,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        });
        if let Some(config) = &self.config {
            health["auth_mode"] = json!(google_auth_redacted_label(&config.auth));
            health["base_url"] = json!(config.base_url);
            health["drive_base_url"] = json!(config.drive_base_url);
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
                name: "drive_base_url".into(),
                status: DoctorStatus::Healthy,
                message: format!("Drive export base URL: {}", config.drive_base_url),
            });
            checks.push(scope_doctor_check(
                "meet_artifact_scope",
                &config.required_scopes,
                MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE,
                "Recording, transcript, transcript-entry, and smart-note reads require the Meet conference media readonly scope; 401/403 can also mean restricted-scope review, developer-preview enrollment, or workspace policy denial.",
            ));
            checks.push(scope_doctor_check(
                "drive_artifact_scope",
                &config.required_scopes,
                DRIVE_MEET_READONLY_SCOPE,
                "Drive-backed transcript and smart-note text export requires drive.meet.readonly; 401/403 can also mean restricted-scope review or workspace policy denial.",
            ));
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
            message: "No live join, leave, or speak operations are advertised; artifact reads only target completed conference resources".into(),
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
                "Google Meet read and artifact API operations are configured; invoke a read operation or loopback e2e for API proof",
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
            operations: meet_operation_catalog(),
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
        let response = self.simulate_request(req);
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize response: {error}"),
        })
    }

    fn simulate_request(&self, req: SimulateRequest) -> SimulateResponse {
        let cap_id = match capability_for_operation(req.operation.as_str()) {
            Ok(cap_id) => cap_id,
            Err(error) => {
                return SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            }
        };

        if self.client.is_none() {
            return SimulateResponse::denied(
                req.id,
                FcpError::NotConfigured.to_string(),
                FcpError::NotConfigured.error_code(),
            );
        }

        let Some(verifier) = &self.verifier else {
            return SimulateResponse::denied(
                req.id,
                FcpError::NotHandshaken.to_string(),
                FcpError::NotHandshaken.error_code(),
            );
        };

        if let Err(error) =
            verifier.verify_bound(req.capability_token, &cap_id, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if matches!(
                &error,
                FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
            ) {
                response = response.with_missing_capabilities(vec![cap_id.as_str().to_string()]);
            }
            return response;
        }

        SimulateResponse::allowed(req.id)
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
            SPACE_GET_OP => self.invoke_get_space(&input).await,
            SPACE_CREATE_OP => self.invoke_create_space(&input).await,
            SPACE_END_ACTIVE_CONFERENCE_OP => self.invoke_end_active_conference(&input).await,
            CONFERENCE_RECORD_GET_OP => self.invoke_get_conference_record(&input).await,
            CONFERENCE_RECORDS_LIST_OP => self.invoke_list_conference_records(&input).await,
            CONFERENCE_RECORD_LATEST_OP => self.invoke_latest_conference_record(&input).await,
            PARTICIPANTS_LIST_OP => self.invoke_list_participants(&input).await,
            PARTICIPANT_SESSIONS_LIST_OP => self.invoke_list_participant_sessions(&input).await,
            ATTENDANCE_LIST_OP => self.invoke_list_attendance(&input).await,
            RECORDINGS_LIST_OP => self.invoke_list_recordings(&input).await,
            TRANSCRIPTS_LIST_OP => self.invoke_list_transcripts(&input).await,
            TRANSCRIPT_ENTRIES_LIST_OP => self.invoke_list_transcript_entries(&input).await,
            SMART_NOTES_LIST_OP => self.invoke_list_smart_notes(&input).await,
            TRANSCRIPTS_WITH_TEXT_LIST_OP => self.invoke_list_transcripts_with_text(&input).await,
            SMART_NOTES_WITH_TEXT_LIST_OP => self.invoke_list_smart_notes_with_text(&input).await,
            DRIVE_DOCUMENT_TEXT_EXPORT_OP => self.invoke_export_drive_document_text(&input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn ensure_configured_scopes(
        &self,
        operation: &str,
        required_scopes: &[&'static str],
    ) -> FcpResult<()> {
        let Some(config) = &self.config else {
            return Err(FcpError::NotConfigured);
        };
        let missing: Vec<_> = required_scopes
            .iter()
            .copied()
            .filter(|scope| {
                !config
                    .required_scopes
                    .iter()
                    .any(|configured| configured == scope)
            })
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(invalid_request(format!(
                "{operation} requires Google OAuth scope(s): {}. Reconfigure with required_scopes or scope_triggers before invoking.",
                missing.join(", ")
            )))
        }
    }

    fn ensure_any_configured_scope(
        &self,
        operation: &str,
        allowed_scopes: &[&'static str],
    ) -> FcpResult<()> {
        let Some(config) = &self.config else {
            return Err(FcpError::NotConfigured);
        };
        if allowed_scopes.iter().any(|scope| {
            config
                .required_scopes
                .iter()
                .any(|configured| configured == scope)
        }) {
            Ok(())
        } else {
            Err(invalid_request(format!(
                "{operation} requires one configured Google OAuth scope from: {}. Reconfigure with required_scopes or scope_triggers before invoking.",
                allowed_scopes.join(", ")
            )))
        }
    }

    async fn invoke_get_space(&self, input: &serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_any_configured_scope(
            SPACE_GET_OP,
            &[
                MEETINGS_SPACE_CREATED_SCOPE,
                MEETINGS_SPACE_READONLY_SCOPE,
                MEETINGS_SPACE_SETTINGS_SCOPE,
            ],
        )?;
        let raw = require_space_input(input)?;
        let normalized = normalize_meet_space_name(raw)?;
        let space = client
            .get_space(&normalized.space_name)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "input": raw,
            "space_name": normalized.space_name,
            "space": space,
        }))
    }

    async fn invoke_create_space(&self, input: &serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let config = normalize_space_config(input)?;
        let required_scopes = create_space_required_scopes(config.as_ref());
        self.ensure_configured_scopes(SPACE_CREATE_OP, &required_scopes)?;
        let space = client
            .create_space(config.clone())
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "space": space,
            "requested_config": config,
            "required_scopes": required_scopes,
        }))
    }

    async fn invoke_end_active_conference(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(
            SPACE_END_ACTIVE_CONFERENCE_OP,
            &[MEETINGS_SPACE_CREATED_SCOPE],
        )?;
        let raw = require_space_input(input)?;
        let normalized = normalize_meet_space_name(raw)?;
        let resolved_space = client
            .get_space(&normalized.space_name)
            .await
            .map_err(|error| error.to_fcp_error())?;
        let response = client
            .end_active_conference(&resolved_space.name)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "input": raw,
            "space_name": normalized.space_name,
            "resolved_space": resolved_space,
            "ended": true,
            "response": response,
        }))
    }

    async fn invoke_get_conference_record(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let record = client
            .get_conference_record(require_str(input, "conference_record")?)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({ "conference_record": record }))
    }

    async fn invoke_list_conference_records(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_size = parse_page_size(input, MAX_CONFERENCE_RECORD_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let meeting = optional_str(input, "meeting")?;
        let records = client
            .list_conference_records(meeting, page_size, Some(max_items))
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "meeting": meeting,
            "conference_records": records,
            "count": records.len(),
            "max_items": max_items,
        }))
    }

    async fn invoke_latest_conference_record(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let meeting = require_str(input, "meeting")?;
        let space = normalize_meet_space_name(meeting)?;
        let records = client
            .list_conference_records(Some(&space.space_name), Some(1), Some(1))
            .await
            .map_err(|error| error.to_fcp_error())?;
        let record = records.into_iter().next();
        Ok(json!({
            "input": meeting,
            "space_name": space.space_name,
            "conference_record": record,
        }))
    }

    async fn invoke_list_participants(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_size = parse_page_size(input, MAX_PARTICIPANT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let participants = client
            .list_participants(
                require_str(input, "conference_record")?,
                page_size,
                Some(max_items),
            )
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "participants": participants,
            "count": participants.len(),
            "max_items": max_items,
        }))
    }

    async fn invoke_list_participant_sessions(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_size = parse_page_size(input, MAX_PARTICIPANT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let sessions = client
            .list_participant_sessions(
                require_str(input, "participant")?,
                page_size,
                Some(max_items),
            )
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "participant_sessions": sessions,
            "count": sessions.len(),
            "max_items": max_items,
        }))
    }

    async fn invoke_list_attendance(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let page_size = parse_page_size(input, MAX_PARTICIPANT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let merge = parse_optional_bool(input, "merge_duplicate_participants")?.unwrap_or(true);
        let late_after_minutes =
            parse_optional_u64(input, "late_after_minutes", 0, 24 * 60)?.unwrap_or(5);
        let early_before_minutes =
            parse_optional_u64(input, "early_before_minutes", 0, 24 * 60)?.unwrap_or(5);
        let all_records = parse_optional_bool(input, "all_conference_records")?.unwrap_or(false);

        let (input_label, space_name, records) =
            if let Some(record) = optional_str(input, "conference_record")? {
                let record = client
                    .get_conference_record(record)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (Some(record.name.clone()), None, vec![record])
            } else {
                let meeting = require_str(input, "meeting")?;
                let space = normalize_meet_space_name(meeting)?;
                let limit = if all_records { max_items } else { 1 };
                let record_page_size = clamp_page_size(page_size, MAX_CONFERENCE_RECORD_PAGE_SIZE);
                let records = client
                    .list_conference_records(Some(&space.space_name), record_page_size, Some(limit))
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                (Some(meeting.to_string()), Some(space.space_name), records)
            };

        let mut rows = Vec::new();
        let mut participant_evidence = Vec::new();
        for record in &records {
            let participants = client
                .list_participants(&record.name, page_size, Some(max_items))
                .await
                .map_err(|error| error.to_fcp_error())?;
            let mut unmerged = Vec::new();
            for participant in &participants {
                let sessions = client
                    .list_participant_sessions(&participant.name, page_size, Some(max_items))
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                unmerged.push(attendance_row_for_participant(
                    record,
                    participant,
                    sessions,
                ));
            }
            let merged = merge_attendance_rows(
                unmerged,
                record,
                AttendanceOptions {
                    merge_duplicate_participants: merge,
                    late_after_minutes,
                    early_before_minutes,
                },
            );
            rows.extend(merged);
            participant_evidence.push(json!({
                "conference_record": record.name,
                "participants": participants,
            }));
        }

        Ok(json!({
            "input": input_label,
            "space_name": space_name,
            "conference_records": records,
            "attendance": rows,
            "participant_evidence": participant_evidence,
            "merge_duplicate_participants": merge,
            "late_after_minutes": late_after_minutes,
            "early_before_minutes": early_before_minutes,
        }))
    }

    async fn invoke_list_recordings(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(
            RECORDINGS_LIST_OP,
            &[MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE],
        )?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let recordings = client
            .list_recordings(conference_record, page_size, Some(max_items))
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "conference_record": conference_record,
            "recordings": recordings,
            "count": recordings.len(),
            "max_items": max_items,
        }))
    }

    async fn invoke_list_transcripts(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(
            TRANSCRIPTS_LIST_OP,
            &[MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE],
        )?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let transcripts = client
            .list_transcripts(conference_record, page_size, Some(max_items))
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "conference_record": conference_record,
            "transcripts": transcripts,
            "count": transcripts.len(),
            "max_items": max_items,
        }))
    }

    async fn invoke_list_transcript_entries(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(
            TRANSCRIPT_ENTRIES_LIST_OP,
            &[MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE],
        )?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let transcript = require_str(input, "transcript")?;
        let mut entries = client
            .list_transcript_entries(transcript, page_size, Some(max_items))
            .await
            .map_err(|error| error.to_fcp_error())?;
        entries.sort_by_key(|entry| {
            (
                parse_timestamp_ms(entry.start_time.as_deref()).unwrap_or_default(),
                entry.name.clone(),
            )
        });
        Ok(json!({
            "transcript": transcript,
            "transcript_entries": entries,
            "count": entries.len(),
            "max_items": max_items,
        }))
    }

    async fn invoke_list_smart_notes(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(
            SMART_NOTES_LIST_OP,
            &[MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE],
        )?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let smart_notes = client
            .list_smart_notes(conference_record, page_size, Some(max_items))
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "conference_record": conference_record,
            "smart_notes": smart_notes,
            "count": smart_notes.len(),
            "max_items": max_items,
        }))
    }

    async fn invoke_list_transcripts_with_text(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(
            TRANSCRIPTS_WITH_TEXT_LIST_OP,
            &[
                MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE,
                DRIVE_MEET_READONLY_SCOPE,
            ],
        )?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let max_document_bytes = parse_max_document_bytes(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let transcripts = client
            .list_transcripts(conference_record, page_size, Some(max_items))
            .await
            .map_err(|error| error.to_fcp_error())?;
        let transcripts =
            attach_transcript_document_texts(client, transcripts, max_document_bytes).await;
        Ok(json!({
            "conference_record": conference_record,
            "transcripts": transcripts,
            "count": transcripts.len(),
            "max_items": max_items,
            "max_document_bytes": max_document_bytes,
        }))
    }

    async fn invoke_list_smart_notes_with_text(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(
            SMART_NOTES_WITH_TEXT_LIST_OP,
            &[
                MEETINGS_CONFERENCE_MEDIA_READONLY_SCOPE,
                DRIVE_MEET_READONLY_SCOPE,
            ],
        )?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let max_document_bytes = parse_max_document_bytes(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let smart_notes = client
            .list_smart_notes(conference_record, page_size, Some(max_items))
            .await
            .map_err(|error| error.to_fcp_error())?;
        let smart_notes =
            attach_smart_note_document_texts(client, smart_notes, max_document_bytes).await;
        Ok(json!({
            "conference_record": conference_record,
            "smart_notes": smart_notes,
            "count": smart_notes.len(),
            "max_items": max_items,
            "max_document_bytes": max_document_bytes,
        }))
    }

    async fn invoke_export_drive_document_text(
        &self,
        input: &serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        self.ensure_configured_scopes(DRIVE_DOCUMENT_TEXT_EXPORT_OP, &[DRIVE_MEET_READONLY_SCOPE])?;
        let document_id = drive_document_id_from_input(input)?;
        let max_document_bytes = parse_max_document_bytes(input)?;
        let text = client
            .export_drive_document_text(&document_id, max_document_bytes)
            .await
            .map_err(|error| error.to_fcp_error())?;
        Ok(json!({
            "document_id": document_id,
            "text": text,
            "bytes": text.len(),
            "max_document_bytes": max_document_bytes,
        }))
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

fn meet_operation_catalog() -> Vec<OperationInfo> {
    vec![
        op_info(
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
                when_to_use:
                    "Validate and normalize a Google Meet identifier before Meet API calls.".into(),
                common_mistakes: vec![
                    "This operation does not join or control a live meeting.".into(),
                    "Calendar event URLs are not Meet URLs; pass a meet.google.com URL or code."
                        .into(),
                ],
                examples: vec![
                    r#"{"input":"https://meet.google.com/abc-defg-hij"}"#.into(),
                    r#"{"input":"spaces/abc-defg-hij"}"#.into(),
                ],
                related: vec![],
            },
        ),
        op_info(
            SPACE_GET_OP,
            "Fetch one Google Meet meeting space by resource name, code, or URL",
            json!({
                "type": "object",
                "required": ["space"],
                "properties": {
                    "space": {
                        "type": "string",
                        "description": "Google Meet URL, meeting code, or spaces/* resource name"
                    }
                }
            }),
            json!({
                "type": "object",
                "required": ["space_name", "space"],
                "properties": {
                    "input": { "type": "string" },
                    "space_name": { "type": "string" },
                    "space": { "type": "object" }
                }
            }),
            MEET_SPACE_READ_CAP,
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use:
                    "Resolve a Meet URL/code into the current Google Meet spaces/* resource details."
                        .into(),
                common_mistakes: vec![
                    "Do not use meeting codes as durable identifiers; Google can reuse them.".into(),
                    "This is a read-only space metadata lookup, not a live meeting join.".into(),
                ],
                examples: vec![r#"{"space":"https://meet.google.com/abc-defg-hij"}"#.into()],
                related: vec![CapabilityId::from_static(NORMALIZE_SPACE_OP)],
            },
        ),
        space_mutation_op_info(
            SPACE_CREATE_OP,
            "Create a Google Meet meeting space",
            json!({
                "type": "object",
                "properties": {
                    "config": {
                        "type": "object",
                        "properties": {
                            "access_type": {
                                "type": "string",
                                "enum": ["OPEN", "TRUSTED", "RESTRICTED"]
                            },
                            "entry_point_access": {
                                "type": "string",
                                "enum": ["ALL", "CREATOR_APP_ONLY"]
                            }
                        }
                    }
                }
            }),
            json!({
                "type": "object",
                "required": ["space", "required_scopes"],
                "properties": {
                    "space": { "type": "object" },
                    "requested_config": { "type": "object" },
                    "required_scopes": { "type": "array" }
                }
            }),
            MEET_SPACE_CREATE_CAP,
            AgentHint {
                when_to_use: "Create a Meet space through the Meet API before sharing its meetingUri.".into(),
                common_mistakes: vec![
                    "Creating with access/entry-point config needs the meetings.space.settings OAuth scope in addition to meetings.space.created.".into(),
                    "This does not start or join a live conference.".into(),
                ],
                examples: vec![
                    r#"{}"#.into(),
                    r#"{"config":{"access_type":"TRUSTED","entry_point_access":"ALL"}}"#.into(),
                ],
                related: vec![CapabilityId::from_static(SPACE_GET_OP)],
            },
        ),
        space_mutation_op_info(
            SPACE_END_ACTIVE_CONFERENCE_OP,
            "End the active conference for a Google Meet space",
            json!({
                "type": "object",
                "required": ["space"],
                "properties": {
                    "space": {
                        "type": "string",
                        "description": "Google Meet spaces/* resource, meeting code, or meet.google.com URL"
                    }
                }
            }),
            json!({
                "type": "object",
                "required": ["resolved_space", "ended", "response"],
                "properties": {
                    "input": { "type": "string" },
                    "space_name": { "type": "string" },
                    "resolved_space": { "type": "object" },
                    "ended": { "type": "boolean" },
                    "response": { "type": "object" }
                }
            }),
            MEET_SPACE_END_CAP,
            AgentHint {
                when_to_use: "Terminate the currently active conference for a space created/owned by the calling app.".into(),
                common_mistakes: vec![
                    "The connector resolves the space first; the Google API and meetings.space.created scope enforce created-space ownership.".into(),
                    "This is a side-effecting operation and should stay approval-policy gated.".into(),
                ],
                examples: vec![r#"{"space":"spaces/jQCFfuBOdN5z"}"#.into()],
                related: vec![CapabilityId::from_static(SPACE_GET_OP)],
            },
        ),
        read_api_op_info(
            CONFERENCE_RECORD_GET_OP,
            "Fetch one Google Meet conference record by resource name or id",
            json!({
                "type": "object",
                "required": ["conference_record"],
                "properties": {
                    "conference_record": { "type": "string" }
                }
            }),
        ),
        read_api_op_info(
            CONFERENCE_RECORDS_LIST_OP,
            "List Google Meet conference records, optionally filtered by meeting space",
            paged_input_schema(&json!({
                "meeting": { "type": "string" }
            })),
        ),
        read_api_op_info(
            CONFERENCE_RECORD_LATEST_OP,
            "Fetch the latest Google Meet conference record for a meeting space",
            json!({
                "type": "object",
                "required": ["meeting"],
                "properties": {
                    "meeting": { "type": "string" }
                }
            }),
        ),
        read_api_op_info(
            PARTICIPANTS_LIST_OP,
            "List participants for a Google Meet conference record",
            paged_input_schema(&json!({
                "conference_record": { "type": "string" }
            })),
        ),
        read_api_op_info(
            PARTICIPANT_SESSIONS_LIST_OP,
            "List participant sessions for a Google Meet participant resource",
            paged_input_schema(&json!({
                "participant": { "type": "string" }
            })),
        ),
        read_api_op_info(
            ATTENDANCE_LIST_OP,
            "Build attendance rows from Google Meet participants and participant sessions",
            paged_input_schema(&json!({
                "meeting": { "type": "string" },
                "conference_record": { "type": "string" },
                "all_conference_records": { "type": "boolean" },
                "merge_duplicate_participants": { "type": "boolean" },
                "late_after_minutes": { "type": "integer" },
                "early_before_minutes": { "type": "integer" }
            })),
        ),
        artifact_op_info(
            RECORDINGS_LIST_OP,
            "List Google Meet recording artifacts for a conference record",
            paged_input_schema(&json!({
                "conference_record": { "type": "string" }
            })),
        ),
        artifact_op_info(
            TRANSCRIPTS_LIST_OP,
            "List Google Meet transcript artifacts for a conference record",
            paged_input_schema(&json!({
                "conference_record": { "type": "string" }
            })),
        ),
        artifact_op_info(
            TRANSCRIPT_ENTRIES_LIST_OP,
            "List transcript entries for one Google Meet transcript resource",
            paged_input_schema(&json!({
                "transcript": { "type": "string" }
            })),
        ),
        artifact_op_info(
            SMART_NOTES_LIST_OP,
            "List Google Meet smart-note artifacts for a conference record",
            paged_input_schema(&json!({
                "conference_record": { "type": "string" }
            })),
        ),
        drive_artifact_op_info(
            TRANSCRIPTS_WITH_TEXT_LIST_OP,
            "List transcript artifacts and attach Drive-backed docsDestination text when available",
            paged_input_schema(&json!({
                "conference_record": { "type": "string" },
                "max_document_bytes": { "type": "integer" }
            })),
        ),
        drive_artifact_op_info(
            SMART_NOTES_WITH_TEXT_LIST_OP,
            "List smart-note artifacts and attach Drive-backed docsDestination text when available",
            paged_input_schema(&json!({
                "conference_record": { "type": "string" },
                "max_document_bytes": { "type": "integer" }
            })),
        ),
        drive_artifact_op_info(
            DRIVE_DOCUMENT_TEXT_EXPORT_OP,
            "Export text/plain from a Drive docsDestination document id",
            json!({
                "type": "object",
                "properties": {
                    "document_id": { "type": "string" },
                    "docs_destination": { "type": "object" },
                    "max_document_bytes": { "type": "integer" }
                }
            }),
        ),
    ]
}

fn paged_input_schema(extra_properties: &serde_json::Value) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    if let Some(extra) = extra_properties.as_object() {
        for (key, value) in extra {
            properties.insert(key.clone(), value.clone());
        }
    }
    properties.insert("page_size".to_string(), json!({ "type": "integer" }));
    properties.insert("max_items".to_string(), json!({ "type": "integer" }));
    json!({
        "type": "object",
        "properties": properties
    })
}

fn read_api_op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
) -> OperationInfo {
    op_info(
        id,
        summary,
        input_schema,
        json!({
            "type": "object",
            "additionalProperties": true
        }),
        MEET_CONFERENCE_READ_CAP,
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        AgentHint {
            when_to_use: "Read Google Meet API conference metadata and attendance evidence.".into(),
            common_mistakes: vec![
                "These operations do not create, end, join, or control a live meeting.".into(),
                "Use recording/transcript sibling operations for media artifacts.".into(),
            ],
            examples: vec![
                r#"{"conference_record":"conferenceRecords/abc"}"#.into(),
                r#"{"meeting":"https://meet.google.com/abc-defg-hij","max_items":10}"#.into(),
            ],
            related: vec![],
        },
    )
}

fn artifact_op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
) -> OperationInfo {
    op_info(
        id,
        summary,
        input_schema,
        json!({
            "type": "object",
            "additionalProperties": true
        }),
        MEET_ARTIFACT_READ_CAP,
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        AgentHint {
            when_to_use: "Read completed Google Meet recording, transcript, transcript-entry, or smart-note artifacts.".into(),
            common_mistakes: vec![
                "These operations require Meet conference media readonly OAuth scope and may be restricted or developer-preview gated.".into(),
                "Use the Drive text export operation only for docsDestination document ids; do not scrape arbitrary Drive files.".into(),
            ],
            examples: vec![
                r#"{"conference_record":"conferenceRecords/abc","max_items":10}"#.into(),
                r#"{"transcript":"conferenceRecords/abc/transcripts/t1"}"#.into(),
            ],
            related: vec![],
        },
    )
}

fn drive_artifact_op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
) -> OperationInfo {
    op_info(
        id,
        summary,
        input_schema,
        json!({
            "type": "object",
            "additionalProperties": true
        }),
        MEET_DRIVE_ARTIFACT_READ_CAP,
        RiskLevel::Low,
        SafetyTier::Safe,
        IdempotencyClass::Strict,
        AgentHint {
            when_to_use: "Export Drive-backed text for Meet transcript or smart-note docsDestination documents.".into(),
            common_mistakes: vec![
                "This is limited to docsDestination document ids and text/plain Drive export.".into(),
                "Missing drive.meet.readonly or Workspace restricted-scope policy appears as an authorization error, not a parsing failure.".into(),
            ],
            examples: vec![
                r#"{"document_id":"1DocIdFromMeet","max_document_bytes":1048576}"#.into(),
                r#"{"conference_record":"conferenceRecords/abc","max_items":10}"#.into(),
            ],
            related: vec![],
        },
    )
}

fn space_mutation_op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    ai_hints: AgentHint,
) -> OperationInfo {
    let mut info = op_info(
        id,
        summary,
        input_schema,
        output_schema,
        capability,
        RiskLevel::High,
        SafetyTier::Risky,
        IdempotencyClass::BestEffort,
        ai_hints,
    );
    info.requires_approval = Some(ApprovalMode::Policy);
    info
}

fn invoke_normalize_space_name(input: &serde_json::Value) -> FcpResult<serde_json::Value> {
    let raw = require_str(input, "input")?;
    serde_json::to_value(normalize_meet_space_name(raw)?).map_err(|error| FcpError::Internal {
        message: format!("Failed to serialize normalized space: {error}"),
    })
}

#[derive(Debug, Clone, Copy)]
struct AttendanceOptions {
    merge_duplicate_participants: bool,
    late_after_minutes: u64,
    early_before_minutes: u64,
}

fn attendance_row_for_participant(
    conference_record: &GoogleMeetConferenceRecord,
    participant: &GoogleMeetParticipant,
    sessions: Vec<GoogleMeetParticipantSession>,
) -> GoogleMeetAttendanceRow {
    GoogleMeetAttendanceRow {
        conference_record: conference_record.name.clone(),
        participant: participant.name.clone(),
        participants: vec![participant.name.clone()],
        display_name: participant_display_name(participant),
        user: participant_user(participant),
        earliest_start_time: participant.earliest_start_time.clone(),
        latest_end_time: participant.latest_end_time.clone(),
        first_join_time: None,
        last_leave_time: None,
        duration_ms: None,
        late: None,
        late_by_ms: None,
        early_leave: None,
        early_leave_by_ms: None,
        sessions,
    }
}

fn merge_attendance_rows(
    rows: Vec<GoogleMeetAttendanceRow>,
    conference_record: &GoogleMeetConferenceRecord,
    options: AttendanceOptions,
) -> Vec<GoogleMeetAttendanceRow> {
    if !options.merge_duplicate_participants {
        return rows
            .into_iter()
            .map(|row| decorate_attendance_row(row, conference_record, options))
            .collect();
    }

    let mut grouped = BTreeMap::<String, GoogleMeetAttendanceRow>::new();
    for mut row in rows {
        let key = attendance_merge_key(&row);
        if let Some(existing) = grouped.get_mut(&key) {
            if !existing.participants.contains(&row.participant) {
                existing.participants.push(row.participant.clone());
            }
            existing.sessions.append(&mut row.sessions);
            if existing.display_name.is_none() {
                existing.display_name = row.display_name;
            }
            if existing.user.is_none() {
                existing.user = row.user;
            }
            existing.earliest_start_time = min_timestamp([
                existing.earliest_start_time.as_deref(),
                row.earliest_start_time.as_deref(),
            ]);
            existing.latest_end_time = max_timestamp([
                existing.latest_end_time.as_deref(),
                row.latest_end_time.as_deref(),
            ]);
        } else {
            grouped.insert(key, row);
        }
    }

    grouped
        .into_values()
        .map(|row| decorate_attendance_row(row, conference_record, options))
        .collect()
}

fn decorate_attendance_row(
    mut row: GoogleMeetAttendanceRow,
    conference_record: &GoogleMeetConferenceRecord,
    options: AttendanceOptions,
) -> GoogleMeetAttendanceRow {
    row.sessions.sort_by_key(|session| {
        parse_timestamp_ms(session.start_time.as_deref()).unwrap_or_default()
    });
    let first_join = min_timestamp(
        row.earliest_start_time
            .as_deref()
            .into_iter()
            .map(Some)
            .chain(
                row.sessions
                    .iter()
                    .map(|session| session.start_time.as_deref()),
            ),
    );
    let last_leave = max_timestamp(
        row.latest_end_time.as_deref().into_iter().map(Some).chain(
            row.sessions
                .iter()
                .map(|session| session.end_time.as_deref()),
        ),
    );
    let duration_ms =
        sum_session_duration_ms(&row.sessions, first_join.as_deref(), last_leave.as_deref());
    let late_by_ms = diff_ms(
        conference_record.start_time.as_deref(),
        first_join.as_deref(),
    );
    let early_by_ms = diff_ms(last_leave.as_deref(), conference_record.end_time.as_deref());
    let late_grace_ms = options.late_after_minutes.saturating_mul(60_000);
    let early_grace_ms = options.early_before_minutes.saturating_mul(60_000);

    row.earliest_start_time = first_join.clone().or(row.earliest_start_time);
    row.latest_end_time = last_leave.clone().or(row.latest_end_time);
    row.first_join_time = first_join;
    row.last_leave_time = last_leave;
    row.duration_ms = duration_ms;
    if let Some(value) = late_by_ms {
        row.late = Some(value > late_grace_ms);
        if value > late_grace_ms {
            row.late_by_ms = Some(value);
        }
    }
    if let Some(value) = early_by_ms {
        row.early_leave = Some(value > early_grace_ms);
        if value > early_grace_ms {
            row.early_leave_by_ms = Some(value);
        }
    }
    row
}

fn participant_display_name(participant: &GoogleMeetParticipant) -> Option<String> {
    participant
        .signedin_user
        .as_ref()
        .and_then(|identity| identity.display_name.clone())
        .or_else(|| {
            participant
                .anonymous_user
                .as_ref()
                .and_then(|identity| identity.display_name.clone())
        })
        .or_else(|| {
            participant
                .phone_user
                .as_ref()
                .and_then(|identity| identity.display_name.clone())
        })
}

fn participant_user(participant: &GoogleMeetParticipant) -> Option<String> {
    participant
        .signedin_user
        .as_ref()
        .and_then(|identity| identity.user.clone())
}

fn attendance_merge_key(row: &GoogleMeetAttendanceRow) -> String {
    row.user
        .as_deref()
        .or(row.display_name.as_deref())
        .unwrap_or(&row.participant)
        .trim()
        .to_ascii_lowercase()
}

fn parse_timestamp_ms(value: Option<&str>) -> Option<i64> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.timestamp_millis())
}

fn iso_from_ms(value: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp_millis(value)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn min_timestamp<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<String> {
    values
        .into_iter()
        .filter_map(parse_timestamp_ms)
        .min()
        .and_then(iso_from_ms)
}

fn max_timestamp<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<String> {
    values
        .into_iter()
        .filter_map(parse_timestamp_ms)
        .max()
        .and_then(iso_from_ms)
}

fn sum_session_duration_ms(
    sessions: &[GoogleMeetParticipantSession],
    fallback_start: Option<&str>,
    fallback_end: Option<&str>,
) -> Option<u64> {
    let total = sessions.iter().fold(0_u64, |total, session| {
        match (
            parse_timestamp_ms(session.start_time.as_deref()),
            parse_timestamp_ms(session.end_time.as_deref()),
        ) {
            (Some(start), Some(end)) if end > start => {
                total.saturating_add(u64::try_from(end - start).unwrap_or(u64::MAX))
            }
            _ => total,
        }
    });
    if total > 0 {
        return Some(total);
    }
    diff_ms(fallback_start, fallback_end)
}

async fn attach_transcript_document_texts(
    client: &GoogleMeetClient,
    mut transcripts: Vec<GoogleMeetTranscript>,
    max_document_bytes: usize,
) -> Vec<GoogleMeetTranscript> {
    for transcript in &mut transcripts {
        match document_id_from_destination(transcript.docs_destination.as_ref()) {
            Ok(Some(document_id)) => {
                transcript.document_id = Some(document_id.clone());
                match client
                    .export_drive_document_text(&document_id, max_document_bytes)
                    .await
                {
                    Ok(text) => transcript.document_text = Some(text),
                    Err(error) => transcript.document_text_error = Some(public_google_error(&error)),
                }
            }
            Ok(None) => {
                transcript.document_text_error =
                    Some("docsDestination did not include a supported document id".into());
            }
            Err(error) => transcript.document_text_error = Some(public_google_error(&error)),
        }
    }
    transcripts
}

async fn attach_smart_note_document_texts(
    client: &GoogleMeetClient,
    mut smart_notes: Vec<GoogleMeetSmartNote>,
    max_document_bytes: usize,
) -> Vec<GoogleMeetSmartNote> {
    for smart_note in &mut smart_notes {
        match document_id_from_destination(smart_note.docs_destination.as_ref()) {
            Ok(Some(document_id)) => {
                smart_note.document_id = Some(document_id.clone());
                match client
                    .export_drive_document_text(&document_id, max_document_bytes)
                    .await
                {
                    Ok(text) => smart_note.document_text = Some(text),
                    Err(error) => {
                        smart_note.document_text_error = Some(public_google_error(&error));
                    }
                }
            }
            Ok(None) => {
                smart_note.document_text_error =
                    Some("docsDestination did not include a supported document id".into());
            }
            Err(error) => smart_note.document_text_error = Some(public_google_error(&error)),
        }
    }
    smart_notes
}

fn document_id_from_destination(
    destination: Option<&GoogleMeetDocsDestination>,
) -> GoogleMeetResult<Option<String>> {
    destination.map_or(Ok(None), extract_docs_destination_document_id)
}

fn drive_document_id_from_input(input: &serde_json::Value) -> FcpResult<String> {
    if let Some(document_id) = optional_str(input, "document_id")? {
        return validate_drive_document_id(document_id).map_err(|error| error.to_fcp_error());
    }
    let Some(destination) = input.get("docs_destination") else {
        return Err(invalid_request(
            "Missing required field: document_id or docs_destination",
        ));
    };
    let destination: GoogleMeetDocsDestination =
        serde_json::from_value(destination.clone()).map_err(|error| {
            invalid_request(format!("`docs_destination` must be a Meet docsDestination object: {error}"))
        })?;
    extract_docs_destination_document_id(&destination)
        .map_err(|error| error.to_fcp_error())?
        .ok_or_else(|| invalid_request("docs_destination did not include a supported document id"))
}

fn parse_max_document_bytes(input: &serde_json::Value) -> FcpResult<usize> {
    parse_optional_u64(
        input,
        "max_document_bytes",
        1,
        u64::try_from(MAX_DRIVE_EXPORT_BYTES).unwrap_or(u64::MAX),
    )?
    .map(usize::try_from)
    .transpose()
    .map_err(|_| invalid_request("`max_document_bytes` is too large"))?
    .map_or(Ok(DEFAULT_DRIVE_EXPORT_MAX_BYTES), Ok)
}

fn public_google_error(error: &GoogleMeetError) -> String {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("authorization")
        || lower.contains("bearer ")
        || lower.contains("access_token")
        || lower.contains("refresh_token")
    {
        "Google API request failed; credentials redacted".to_string()
    } else {
        message
    }
}

fn diff_ms(start: Option<&str>, end: Option<&str>) -> Option<u64> {
    let start = parse_timestamp_ms(start)?;
    let end = parse_timestamp_ms(end)?;
    if end > start {
        u64::try_from(end - start).ok()
    } else {
        Some(0)
    }
}

fn capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        NORMALIZE_SPACE_OP | SPACE_GET_OP => Ok(CapabilityId::from_static(MEET_SPACE_READ_CAP)),
        SPACE_CREATE_OP => Ok(CapabilityId::from_static(MEET_SPACE_CREATE_CAP)),
        SPACE_END_ACTIVE_CONFERENCE_OP => Ok(CapabilityId::from_static(MEET_SPACE_END_CAP)),
        CONFERENCE_RECORD_GET_OP
        | CONFERENCE_RECORDS_LIST_OP
        | CONFERENCE_RECORD_LATEST_OP
        | PARTICIPANTS_LIST_OP
        | PARTICIPANT_SESSIONS_LIST_OP
        | ATTENDANCE_LIST_OP => Ok(CapabilityId::from_static(MEET_CONFERENCE_READ_CAP)),
        RECORDINGS_LIST_OP
        | TRANSCRIPTS_LIST_OP
        | TRANSCRIPT_ENTRIES_LIST_OP
        | SMART_NOTES_LIST_OP => Ok(CapabilityId::from_static(MEET_ARTIFACT_READ_CAP)),
        TRANSCRIPTS_WITH_TEXT_LIST_OP
        | SMART_NOTES_WITH_TEXT_LIST_OP
        | DRIVE_DOCUMENT_TEXT_EXPORT_OP => {
            Ok(CapabilityId::from_static(MEET_DRIVE_ARTIFACT_READ_CAP))
        }
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

fn require_space_input(input: &serde_json::Value) -> FcpResult<&str> {
    optional_str(input, "space")?
        .or(optional_str(input, "meeting")?)
        .ok_or_else(|| invalid_request("Missing required field: space"))
}

fn optional_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<Option<&'a str>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid_request(format!("`{field}` must be a string")))?;
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value))
}

fn parse_max_items(input: &serde_json::Value) -> FcpResult<usize> {
    parse_optional_u64(
        input,
        "max_items",
        1,
        u64::try_from(MAX_ITEMS_CAP).unwrap_or(u64::MAX),
    )?
    .map(usize::try_from)
    .transpose()
    .map_err(|_| invalid_request("`max_items` is too large"))?
    .map_or(Ok(DEFAULT_MAX_ITEMS), Ok)
}

fn parse_page_size(input: &serde_json::Value, max: u32) -> FcpResult<Option<u32>> {
    Ok(Some(
        parse_optional_u32(input, "page_size", 1, max)?.unwrap_or(DEFAULT_PAGE_SIZE),
    ))
}

fn clamp_page_size(page_size: Option<u32>, max: u32) -> Option<u32> {
    page_size.map(|value| value.min(max))
}

fn parse_optional_u32(
    input: &serde_json::Value,
    field: &str,
    min: u32,
    max: u32,
) -> FcpResult<Option<u32>> {
    parse_optional_u64(input, field, u64::from(min), u64::from(max))?
        .map(u32::try_from)
        .transpose()
        .map_err(|_| invalid_request(format!("`{field}` is too large")))
}

fn parse_optional_u64(
    input: &serde_json::Value,
    field: &str,
    min: u64,
    max: u64,
) -> FcpResult<Option<u64>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| invalid_request(format!("`{field}` must be an unsigned integer")))?;
    if value < min || value > max {
        return Err(invalid_request(format!(
            "`{field}` must be between {min} and {max}"
        )));
    }
    Ok(Some(value))
}

fn parse_optional_bool(input: &serde_json::Value, field: &str) -> FcpResult<Option<bool>> {
    input
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid_request(format!("`{field}` must be a boolean")))
        })
        .transpose()
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration as StdDuration, Instant};

    use super::*;
    use crate::client::{
        GoogleMeetUserIdentity, encode_resource_name_for_path, normalize_conference_record_name,
        normalize_participant_name, normalize_transcript_name,
    };
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityConstraints, RequestId, ZoneId};

    const MANIFEST_TOML: &str = include_str!("../manifest.toml");

    #[derive(Debug, Clone)]
    struct StubResponse {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: String,
    }

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        target: String,
        authorization: Option<String>,
        body: String,
    }

    fn json_response(body: impl serde::Serialize) -> StubResponse {
        StubResponse {
            status: 200,
            headers: vec![("content-type", "application/json".to_string())],
            body: serde_json::to_string(&body).expect("serialize JSON response"),
        }
    }

    fn text_response(body: impl Into<String>) -> StubResponse {
        StubResponse {
            status: 200,
            headers: vec![("content-type", "text/plain".to_string())],
            body: body.into(),
        }
    }

    fn error_response(
        status: u16,
        body: impl serde::Serialize,
        headers: Vec<(&'static str, String)>,
    ) -> StubResponse {
        StubResponse {
            status,
            headers,
            body: serde_json::to_string(&body).expect("serialize JSON response"),
        }
    }

    fn spawn_loopback(
        responses: Vec<StubResponse>,
    ) -> (
        String,
        Arc<Mutex<Vec<RecordedRequest>>>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener
            .set_nonblocking(true)
            .expect("set loopback nonblocking");
        let addr = listener.local_addr().expect("loopback addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + StdDuration::from_secs(5);
            let mut responses = responses.into_iter();
            while Instant::now() < deadline {
                let Some(response) = responses.next() else {
                    return;
                };
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _peer)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "timed out waiting for loopback request"
                            );
                            thread::sleep(StdDuration::from_millis(10));
                        }
                        Err(error) => {
                            assert_eq!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock,
                                "accept loopback request: {error}"
                            );
                        }
                    }
                };
                stream
                    .set_nonblocking(false)
                    .expect("set loopback stream blocking");
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(1)))
                    .expect("set read timeout");
                let mut buffer = [0_u8; 8192];
                let mut received = Vec::new();
                loop {
                    let count = stream.read(&mut buffer).expect("read request");
                    if count == 0 {
                        break;
                    }
                    received.extend_from_slice(&buffer[..count]);
                    if received.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let header_end = received
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .expect("request headers terminator");
                let header_bytes = &received[..header_end];
                let mut body = received[header_end..].to_vec();
                let request = String::from_utf8_lossy(header_bytes);
                let mut request_line = request
                    .lines()
                    .next()
                    .expect("request line")
                    .split_whitespace();
                let method = request_line.next().expect("request method").to_string();
                let target = request_line.next().expect("request target").to_string();
                let authorization = request.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_string())
                });
                let content_length = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content-length"))
                    })
                    .unwrap_or(0);
                while body.len() < content_length {
                    let count = stream.read(&mut buffer).expect("read request body");
                    if count == 0 {
                        break;
                    }
                    body.extend_from_slice(&buffer[..count]);
                }
                recorded
                    .lock()
                    .expect("record requests")
                    .push(RecordedRequest {
                        method,
                        target,
                        authorization,
                        body: String::from_utf8_lossy(&body[..content_length.min(body.len())])
                            .to_string(),
                    });
                let reason = match response.status {
                    200 => "OK",
                    400 => "Bad Request",
                    429 => "Too Many Requests",
                    _ => "Stubbed",
                };
                let mut headers = String::new();
                for (name, value) in response.headers {
                    headers.push_str(name);
                    headers.push_str(": ");
                    headers.push_str(&value);
                    headers.push_str("\r\n");
                }
                let wire = format!(
                    "HTTP/1.1 {} {}\r\n{}content-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.status,
                    reason,
                    headers,
                    response.body.len(),
                    response.body
                );
                stream
                    .write_all(wire.as_bytes())
                    .expect("write loopback response");
            }
            assert!(
                responses.next().is_none(),
                "loopback server did not receive every expected request"
            );
        });
        (format!("http://{addr}/v2"), requests, handle)
    }

    fn finish_loopback(handle: thread::JoinHandle<()>) {
        handle.join().expect("loopback server finished");
    }

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

    fn capability_for_cap(
        connector: &GoogleMeetConnector,
        signing_key: &Ed25519SigningKey,
        op: &str,
        capability_id: &str,
    ) -> CapabilityToken {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability_id)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[op])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .expect("valid constraints cbor")
            .target_instance(connector.base.instance_id.as_str())
            .sign(signing_key)
            .expect("sign token");
        CapabilityToken::from_raw(cose)
    }

    fn capability_for(
        connector: &GoogleMeetConnector,
        signing_key: &Ed25519SigningKey,
        op: &str,
    ) -> CapabilityToken {
        capability_for_cap(connector, signing_key, op, MEET_SPACE_READ_CAP)
    }

    fn simulate_request_json(
        connector: &GoogleMeetConnector,
        signing_key: &Ed25519SigningKey,
        operation: &str,
        capability_id: &str,
    ) -> serde_json::Value {
        serde_json::to_value(SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new(format!("sim-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::new(operation).expect("valid operation id"),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: capability_for_cap(connector, signing_key, operation, capability_id),
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        })
        .expect("serialize simulate request")
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
                "capabilities_requested": [MEET_SPACE_READ_CAP, MEET_CONFERENCE_READ_CAP],
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

    #[test]
    fn normalize_space_config_accepts_only_supported_access_and_entry_point_enums() {
        let config = normalize_space_config(&json!({
            "config": {
                "access_type": "trusted",
                "entryPointAccess": "creator-app-only"
            }
        }))
        .expect("space config")
        .expect("config present");
        assert_eq!(config.access_type.as_deref(), Some("TRUSTED"));
        assert_eq!(
            config.entry_point_access.as_deref(),
            Some("CREATOR_APP_ONLY")
        );

        for input in [
            json!({ "config": { "accessType": "PUBLIC" } }),
            json!({ "config": { "entry_point_access": "OWNER_ONLY" } }),
            json!({ "config": { "moderation": "ON" } }),
            json!({ "config": [] }),
        ] {
            assert!(
                matches!(
                    normalize_space_config(&input),
                    Err(FcpError::InvalidRequest { .. })
                ),
                "config should be rejected: {input}"
            );
        }
    }

    #[test]
    fn create_space_scope_requirements_depend_on_config_presence() {
        assert_eq!(
            create_space_required_scopes(None),
            vec![MEETINGS_SPACE_CREATED_SCOPE]
        );
        let config = GoogleMeetSpaceConfig {
            access_type: Some("OPEN".to_string()),
            entry_point_access: None,
        };
        assert_eq!(
            create_space_required_scopes(Some(&config)),
            vec![MEETINGS_SPACE_CREATED_SCOPE, MEETINGS_SPACE_SETTINGS_SCOPE]
        );
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
            vec![MEETINGS_SPACE_READONLY_SCOPE.to_string()]
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
                MEETINGS_SPACE_CREATED_SCOPE.to_string(),
                MEETINGS_SPACE_READONLY_SCOPE.to_string()
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
    async fn introspection_advertises_space_conference_artifact_and_space_mutation_operations() {
        let connector = GoogleMeetConnector::new();
        let result = connector.handle_introspect().await.expect("introspect");
        let ops = result["operations"].as_array().expect("operations");
        let ids: Vec<_> = ops
            .iter()
            .map(|op| op["id"].as_str().expect("op id"))
            .collect();
        assert_eq!(
            ids,
            vec![
                NORMALIZE_SPACE_OP,
                SPACE_GET_OP,
                SPACE_CREATE_OP,
                SPACE_END_ACTIVE_CONFERENCE_OP,
                CONFERENCE_RECORD_GET_OP,
                CONFERENCE_RECORDS_LIST_OP,
                CONFERENCE_RECORD_LATEST_OP,
                PARTICIPANTS_LIST_OP,
                PARTICIPANT_SESSIONS_LIST_OP,
                ATTENDANCE_LIST_OP,
                RECORDINGS_LIST_OP,
                TRANSCRIPTS_LIST_OP,
                TRANSCRIPT_ENTRIES_LIST_OP,
                SMART_NOTES_LIST_OP,
                TRANSCRIPTS_WITH_TEXT_LIST_OP,
                SMART_NOTES_WITH_TEXT_LIST_OP,
                DRIVE_DOCUMENT_TEXT_EXPORT_OP,
            ]
        );
        assert!(
            !ids.iter().any(|id| {
                id.contains("join") || id.contains("leave") || id.contains("say")
            }),
            "artifact reads must not advertise live-session control operations"
        );
        assert_eq!(ops[0]["capability"], MEET_SPACE_READ_CAP);
        assert_eq!(ops[0]["safety_tier"], "safe");
        assert_eq!(ops[0]["idempotency"], "strict");
        assert_eq!(ops[1]["capability"], MEET_SPACE_READ_CAP);
        assert_eq!(ops[1]["safety_tier"], "safe");
        assert_eq!(ops[2]["capability"], MEET_SPACE_CREATE_CAP);
        assert_eq!(ops[2]["safety_tier"], "risky");
        assert_eq!(ops[2]["requires_approval"], "policy");
        assert_eq!(ops[3]["capability"], MEET_SPACE_END_CAP);
        assert_eq!(ops[3]["safety_tier"], "risky");
        assert_eq!(ops[3]["requires_approval"], "policy");
        for op in &ops[4..] {
            if [
                RECORDINGS_LIST_OP,
                TRANSCRIPTS_LIST_OP,
                TRANSCRIPT_ENTRIES_LIST_OP,
                SMART_NOTES_LIST_OP,
            ]
            .contains(&op["id"].as_str().expect("op id"))
            {
                assert_eq!(op["capability"], MEET_ARTIFACT_READ_CAP);
                assert_eq!(op["safety_tier"], "safe");
                assert_eq!(op["idempotency"], "strict");
                continue;
            }
            if [
                TRANSCRIPTS_WITH_TEXT_LIST_OP,
                SMART_NOTES_WITH_TEXT_LIST_OP,
                DRIVE_DOCUMENT_TEXT_EXPORT_OP,
            ]
            .contains(&op["id"].as_str().expect("op id"))
            {
                assert_eq!(op["capability"], MEET_DRIVE_ARTIFACT_READ_CAP);
                assert_eq!(op["safety_tier"], "safe");
                assert_eq!(op["idempotency"], "strict");
                continue;
            }
            assert_eq!(op["capability"], MEET_CONFERENCE_READ_CAP);
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["idempotency"], "strict");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_normalize_space_name_checks_capability_and_returns_contract() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;
        let capability_grant = capability_for(&connector, &signing_key, NORMALIZE_SPACE_OP);

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

    #[fcp_async_core::runtime::test]
    async fn space_operations_use_google_spaces_api_with_scope_and_config_guards() {
        let (base_url, requests, server) = spawn_loopback(vec![
            json_response(json!({
                "name": "spaces/abc-defg-hij",
                "meetingUri": "https://meet.google.com/abc-defg-hij",
                "meetingCode": "abc-defg-hij"
            })),
            json_response(json!({
                "name": "spaces/jQCFfuBOdN5z",
                "meetingUri": "https://meet.google.com/new-meet-code",
                "meetingCode": "new-meet-code",
                "config": {
                    "accessType": "TRUSTED",
                    "entryPointAccess": "CREATOR_APP_ONLY"
                }
            })),
            json_response(json!({
                "name": "spaces/jQCFfuBOdN5z",
                "meetingUri": "https://meet.google.com/new-meet-code",
                "activeConference": {
                    "conferenceRecord": "conferenceRecords/rec-active"
                }
            })),
            json_response(json!({})),
        ]);
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([
                ("base_url", json!(base_url)),
                (
                    "required_scopes",
                    json!([
                        MEETINGS_SPACE_READONLY_SCOPE,
                        MEETINGS_SPACE_CREATED_SCOPE,
                        MEETINGS_SPACE_SETTINGS_SCOPE
                    ]),
                ),
            ]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [
                    MEET_SPACE_READ_CAP,
                    MEET_SPACE_CREATE_CAP,
                    MEET_SPACE_END_CAP,
                    MEET_CONFERENCE_READ_CAP
                ],
            }))
            .await
            .expect("handshake");

        let get_result = connector
            .handle_invoke(json!({
                "operation": SPACE_GET_OP,
                "input": { "space": "https://meet.google.com/abc-defg-hij" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    SPACE_GET_OP,
                    MEET_SPACE_READ_CAP
                ),
            }))
            .await
            .expect("get space");
        assert_eq!(get_result["space_name"], "spaces/abc-defg-hij");
        assert_eq!(
            get_result["space"]["meetingUri"],
            "https://meet.google.com/abc-defg-hij"
        );

        let create_result = connector
            .handle_invoke(json!({
                "operation": SPACE_CREATE_OP,
                "input": {
                    "config": {
                        "access_type": "trusted",
                        "entryPointAccess": "creator_app_only"
                    }
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    SPACE_CREATE_OP,
                    MEET_SPACE_CREATE_CAP
                ),
            }))
            .await
            .expect("create space");
        assert_eq!(create_result["space"]["name"], "spaces/jQCFfuBOdN5z");
        assert_eq!(
            create_result["required_scopes"],
            json!([MEETINGS_SPACE_CREATED_SCOPE, MEETINGS_SPACE_SETTINGS_SCOPE])
        );

        let end_result = connector
            .handle_invoke(json!({
                "operation": SPACE_END_ACTIVE_CONFERENCE_OP,
                "input": { "space": "spaces/jQCFfuBOdN5z" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    SPACE_END_ACTIVE_CONFERENCE_OP,
                    MEET_SPACE_END_CAP
                ),
            }))
            .await
            .expect("end active conference");
        assert_eq!(end_result["ended"], true);
        assert_eq!(
            end_result["resolved_space"]["activeConference"]["conferenceRecord"],
            "conferenceRecords/rec-active"
        );
        finish_loopback(server);

        let recorded = requests.lock().expect("requests").clone();
        assert_eq!(recorded.len(), 4, "loopback transcript: {recorded:#?}");
        assert_eq!(recorded[0].method, "GET");
        assert_eq!(recorded[0].target, "/v2/spaces/abc%2Ddefg%2Dhij");
        assert_eq!(recorded[1].method, "POST");
        assert_eq!(recorded[1].target, "/v2/spaces");
        let create_body: serde_json::Value =
            serde_json::from_str(&recorded[1].body).expect("create body JSON");
        assert_eq!(create_body["config"]["accessType"], "TRUSTED");
        assert_eq!(
            create_body["config"]["entryPointAccess"],
            "CREATOR_APP_ONLY"
        );
        assert_eq!(recorded[2].method, "GET");
        assert_eq!(recorded[2].target, "/v2/spaces/jQCFfuBOdN5z");
        assert_eq!(recorded[3].method, "POST");
        assert_eq!(
            recorded[3].target,
            "/v2/spaces/jQCFfuBOdN5z:endActiveConference"
        );
        assert_eq!(recorded[3].body, "");
        assert!(
            recorded
                .iter()
                .all(|request| request.authorization.as_deref() == Some("Bearer test-access")),
            "every Meet API request must carry injected auth"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn space_mutations_reject_missing_scopes_before_network_io() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;

        let err = connector
            .handle_invoke(json!({
                "operation": SPACE_CREATE_OP,
                "input": {},
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    SPACE_CREATE_OP,
                    MEET_SPACE_CREATE_CAP
                ),
            }))
            .await
            .expect_err("missing created scope should fail");
        assert!(
            matches!(err, FcpError::InvalidRequest { message, .. } if message.contains(MEETINGS_SPACE_CREATED_SCOPE))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn space_create_rejects_missing_name_or_meeting_uri() {
        let (base_url, _requests, server) = spawn_loopback(vec![json_response(json!({
            "name": "spaces/jQCFfuBOdN5z"
        }))]);
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([
                ("base_url", json!(base_url)),
                ("required_scopes", json!([MEETINGS_SPACE_CREATED_SCOPE])),
            ]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_SPACE_CREATE_CAP],
            }))
            .await
            .expect("handshake");

        let err = connector
            .handle_invoke(json!({
                "operation": SPACE_CREATE_OP,
                "input": {},
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    SPACE_CREATE_OP,
                    MEET_SPACE_CREATE_CAP
                ),
            }))
            .await
            .expect_err("space without meetingUri must fail");
        finish_loopback(server);
        assert!(
            matches!(err, FcpError::InvalidRequest { message, .. } if message.contains("without meetingUri"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_unknown_live_session_operation() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;

        let result = connector
            .handle_simulate(simulate_request_json(
                &connector,
                &signing_key,
                "gmeet.live.join",
                "meeting.live_join",
            ))
            .await
            .expect("simulate response");

        assert_eq!(result["would_succeed"], false);
        assert!(
            result["failure_reason"]
                .as_str()
                .expect("failure reason")
                .contains("gmeet.live.join")
        );
        assert!(
            result["missing_capabilities"]
                .as_array()
                .expect("missing capabilities")
                .is_empty()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_allows_supported_read_operation_with_capability() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;

        let result = connector
            .handle_simulate(simulate_request_json(
                &connector,
                &signing_key,
                CONFERENCE_RECORD_GET_OP,
                MEET_CONFERENCE_READ_CAP,
            ))
            .await
            .expect("simulate response");

        assert_eq!(result["would_succeed"], true);
        assert!(result.get("failure_reason").is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn simulate_denies_supported_read_operation_without_required_capability() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;

        let result = connector
            .handle_simulate(simulate_request_json(
                &connector,
                &signing_key,
                CONFERENCE_RECORD_GET_OP,
                MEET_SPACE_READ_CAP,
            ))
            .await
            .expect("simulate response");

        assert_eq!(result["would_succeed"], false);
        assert_eq!(
            result["missing_capabilities"]
                .as_array()
                .expect("missing capabilities")
                .first()
                .and_then(serde_json::Value::as_str),
            Some(MEET_CONFERENCE_READ_CAP)
        );
    }

    #[test]
    fn google_resource_helpers_preserve_parent_child_shape() {
        assert_eq!(
            normalize_conference_record_name("rec-1").expect("record id"),
            "conferenceRecords/rec-1"
        );
        assert_eq!(
            normalize_conference_record_name("conferenceRecords/rec-1").expect("record resource"),
            "conferenceRecords/rec-1"
        );
        assert_eq!(
            normalize_participant_name("conferenceRecords/rec-1/participants/p1")
                .expect("participant resource"),
            "conferenceRecords/rec-1/participants/p1"
        );
        assert_eq!(
            encode_resource_name_for_path("conferenceRecords/rec 1/participants/user@example.com"),
            "conferenceRecords/rec%201/participants/user%40example%2Ecom"
        );
        for raw in [
            "",
            "rec-1/extra",
            "conferenceRecordsx/rec-1",
            "conferenceRecords/",
            "conferenceRecords/rec-1/extra",
            "conferenceRecords/rec 1",
            "conferenceRecords/rec-1?alt=json",
            "conferenceRecords/rec-1/participants/p1",
        ] {
            assert!(
                normalize_conference_record_name(raw).is_err(),
                "{raw:?} should reject as a conference record"
            );
        }
        for raw in [
            "conferenceRecords/rec-1",
            "conferenceRecordsx/rec-1/participants/p1",
            "conferenceRecords/rec-1/participants/",
            "conferenceRecords/rec-1/foo/p1",
            "conferenceRecords/rec-1/participants/p1/extra",
            "conferenceRecords/rec-1/participants/p1/participantSessions/s1",
        ] {
            assert!(
                normalize_participant_name(raw).is_err(),
                "{raw:?} should reject as a participant resource"
            );
        }
    }

    #[test]
    fn page_size_caps_follow_meet_collection_limits() {
        assert_eq!(
            parse_page_size(
                &json!({ "page_size": MAX_CONFERENCE_RECORD_PAGE_SIZE }),
                MAX_CONFERENCE_RECORD_PAGE_SIZE
            )
            .expect("conference page size"),
            Some(MAX_CONFERENCE_RECORD_PAGE_SIZE)
        );
        assert!(
            matches!(
                parse_page_size(
                    &json!({ "page_size": MAX_CONFERENCE_RECORD_PAGE_SIZE + 1 }),
                    MAX_CONFERENCE_RECORD_PAGE_SIZE
                ),
                Err(FcpError::InvalidRequest { .. })
            ),
            "conferenceRecords.list should not request above Google's documented cap"
        );
        assert_eq!(
            parse_page_size(
                &json!({ "page_size": MAX_PARTICIPANT_PAGE_SIZE }),
                MAX_PARTICIPANT_PAGE_SIZE
            )
            .expect("participant page size"),
            Some(MAX_PARTICIPANT_PAGE_SIZE)
        );
        assert_eq!(
            clamp_page_size(
                Some(MAX_PARTICIPANT_PAGE_SIZE),
                MAX_CONFERENCE_RECORD_PAGE_SIZE
            ),
            Some(MAX_CONFERENCE_RECORD_PAGE_SIZE)
        );
    }

    #[test]
    fn attendance_merge_and_timing_matches_conference_bounds() {
        let record = GoogleMeetConferenceRecord {
            name: "conferenceRecords/rec-1".to_string(),
            space: Some("spaces/abc-defg-hij".to_string()),
            start_time: Some("2026-05-04T10:00:00Z".to_string()),
            end_time: Some("2026-05-04T11:00:00Z".to_string()),
            expire_time: None,
            extra: BTreeMap::new(),
        };
        let participant_one = GoogleMeetParticipant {
            name: "conferenceRecords/rec-1/participants/p1".to_string(),
            earliest_start_time: None,
            latest_end_time: None,
            signedin_user: Some(GoogleMeetUserIdentity {
                user: Some("users/alice".to_string()),
                display_name: Some("Alice Example".to_string()),
            }),
            anonymous_user: None,
            phone_user: None,
            extra: BTreeMap::new(),
        };
        let participant_two = GoogleMeetParticipant {
            name: "conferenceRecords/rec-1/participants/p2".to_string(),
            earliest_start_time: None,
            latest_end_time: None,
            signedin_user: Some(GoogleMeetUserIdentity {
                user: Some("users/alice".to_string()),
                display_name: Some("Alice Example".to_string()),
            }),
            anonymous_user: None,
            phone_user: None,
            extra: BTreeMap::new(),
        };
        let rows = vec![
            attendance_row_for_participant(
                &record,
                &participant_one,
                vec![GoogleMeetParticipantSession {
                    name: "conferenceRecords/rec-1/participants/p1/participantSessions/s1"
                        .to_string(),
                    start_time: Some("2026-05-04T10:10:00Z".to_string()),
                    end_time: Some("2026-05-04T10:30:00Z".to_string()),
                    extra: BTreeMap::new(),
                }],
            ),
            attendance_row_for_participant(
                &record,
                &participant_two,
                vec![GoogleMeetParticipantSession {
                    name: "conferenceRecords/rec-1/participants/p2/participantSessions/s2"
                        .to_string(),
                    start_time: Some("2026-05-04T10:40:00Z".to_string()),
                    end_time: Some("2026-05-04T10:50:00Z".to_string()),
                    extra: BTreeMap::new(),
                }],
            ),
        ];

        let merged = merge_attendance_rows(
            rows,
            &record,
            AttendanceOptions {
                merge_duplicate_participants: true,
                late_after_minutes: 5,
                early_before_minutes: 5,
            },
        );

        assert_eq!(merged.len(), 1);
        let row = &merged[0];
        assert_eq!(
            row.participants,
            vec![
                "conferenceRecords/rec-1/participants/p1",
                "conferenceRecords/rec-1/participants/p2",
            ]
        );
        assert_eq!(row.participant, "conferenceRecords/rec-1/participants/p1");
        assert_eq!(row.display_name.as_deref(), Some("Alice Example"));
        assert_eq!(row.user.as_deref(), Some("users/alice"));
        assert_eq!(
            row.first_join_time.as_deref(),
            Some("2026-05-04T10:10:00.000Z")
        );
        assert_eq!(
            row.last_leave_time.as_deref(),
            Some("2026-05-04T10:50:00.000Z")
        );
        assert_eq!(row.duration_ms, Some(1_800_000));
        assert_eq!(row.late, Some(true));
        assert_eq!(row.late_by_ms, Some(600_000));
        assert_eq!(row.early_leave, Some(true));
        assert_eq!(row.early_leave_by_ms, Some(600_000));
    }

    #[fcp_async_core::runtime::test]
    async fn read_operations_cover_loopback_pagination_and_bounded_stop() {
        let (base_url, requests, server) = spawn_loopback(vec![
            json_response(json!({
                "conferenceRecords": [{
                    "name": "conferenceRecords/rec-1",
                    "space": "spaces/abc-defg-hij"
                }],
                "nextPageToken": "page-2"
            })),
            json_response(json!({
                "conferenceRecords": [{
                    "name": "conferenceRecords/rec-2",
                    "space": "spaces/abc-defg-hij"
                }]
            })),
            json_response(json!({
                "conferenceRecords": [{
                    "name": "conferenceRecords/rec-latest",
                    "space": "spaces/abc-defg-hij"
                }]
            })),
            json_response(json!({
                "name": "conferenceRecords/rec-1",
                "space": "spaces/abc-defg-hij"
            })),
            json_response(json!({
                "participants": [{
                    "name": "conferenceRecords/rec-1/participants/p1",
                    "signedinUser": {
                        "user": "users/alice",
                        "displayName": "Alice Example"
                    }
                }]
            })),
            json_response(json!({
                "participantSessions": [{
                    "name": "conferenceRecords/rec-1/participants/p1/participantSessions/s1",
                    "startTime": "2026-05-04T10:02:00Z",
                    "endTime": "2026-05-04T10:40:00Z"
                }]
            })),
            json_response(json!({
                "conferenceRecords": [
                    { "name": "conferenceRecords/rec-stop-1" },
                    { "name": "conferenceRecords/rec-stop-2" }
                ],
                "nextPageToken": "must-not-be-requested"
            })),
        ]);
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([(
                "base_url",
                json!(base_url),
            )]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_SPACE_READ_CAP, MEET_CONFERENCE_READ_CAP],
            }))
            .await
            .expect("handshake");

        let list_result = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORDS_LIST_OP,
                "input": {
                    "meeting": "spaces/abc-defg-hij",
                    "page_size": 2,
                    "max_items": 2
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    CONFERENCE_RECORDS_LIST_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect("list conference records");
        assert_eq!(list_result["count"], 2);

        let latest_result = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORD_LATEST_OP,
                "input": { "meeting": "https://meet.google.com/abc-defg-hij" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    CONFERENCE_RECORD_LATEST_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect("latest conference record");
        assert_eq!(
            latest_result["conference_record"]["name"],
            "conferenceRecords/rec-latest"
        );

        let get_result = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORD_GET_OP,
                "input": { "conference_record": "conferenceRecords/rec-1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    CONFERENCE_RECORD_GET_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect("get conference record");
        assert_eq!(
            get_result["conference_record"]["name"],
            "conferenceRecords/rec-1"
        );

        let participants_result = connector
            .handle_invoke(json!({
                "operation": PARTICIPANTS_LIST_OP,
                "input": {
                    "conference_record": "conferenceRecords/rec-1",
                    "page_size": 5,
                    "max_items": 10
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    PARTICIPANTS_LIST_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect("list participants");
        assert_eq!(
            participants_result["participants"][0]["signedinUser"]["user"],
            "users/alice"
        );

        let sessions_result = connector
            .handle_invoke(json!({
                "operation": PARTICIPANT_SESSIONS_LIST_OP,
                "input": {
                    "participant": "conferenceRecords/rec-1/participants/p1",
                    "page_size": 5,
                    "max_items": 10
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    PARTICIPANT_SESSIONS_LIST_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect("list participant sessions");
        assert_eq!(
            sessions_result["participant_sessions"]
                .as_array()
                .expect("sessions")
                .len(),
            1
        );

        let bounded_result = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORDS_LIST_OP,
                "input": {
                    "page_size": 2,
                    "max_items": 1
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    CONFERENCE_RECORDS_LIST_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect("bounded list conference records");
        assert_eq!(bounded_result["count"], 1);
        finish_loopback(server);

        let recorded = requests.lock().expect("requests").clone();
        assert_eq!(recorded.len(), 7, "loopback transcript: {recorded:#?}");
        let first_url =
            Url::parse(&format!("http://loopback.test{}", recorded[0].target)).expect("first URL");
        let first_query: BTreeMap<_, _> = first_url.query_pairs().into_owned().collect();
        assert_eq!(first_url.path(), "/v2/conferenceRecords");
        assert_eq!(first_query.get("pageSize"), Some(&"2".to_string()));
        assert_eq!(
            first_query.get("filter"),
            Some(&"space.name = \"spaces/abc-defg-hij\"".to_string())
        );
        let second_url =
            Url::parse(&format!("http://loopback.test{}", recorded[1].target)).expect("second URL");
        let second_query: BTreeMap<_, _> = second_url.query_pairs().into_owned().collect();
        assert_eq!(second_query.get("pageToken"), Some(&"page-2".to_string()));
        let latest_url =
            Url::parse(&format!("http://loopback.test{}", recorded[2].target)).expect("latest URL");
        let latest_query: BTreeMap<_, _> = latest_url.query_pairs().into_owned().collect();
        assert_eq!(latest_query.get("pageSize"), Some(&"1".to_string()));
        assert_eq!(recorded[3].target, "/v2/conferenceRecords/rec%2D1");
        assert_eq!(
            recorded[4].target,
            "/v2/conferenceRecords/rec%2D1/participants?pageSize=5"
        );
        assert_eq!(
            recorded[5].target,
            "/v2/conferenceRecords/rec%2D1/participants/p1/participantSessions?pageSize=5"
        );
        assert!(
            !recorded
                .iter()
                .any(|request| request.target.contains("must-not-be-requested")),
            "max_items must stop before following the next page token"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_attendance_uses_google_conference_records_loopback_with_logging() {
        let (base_url, requests, server) = spawn_loopback(vec![
            json_response(json!({
                "conferenceRecords": [{
                    "name": "conferenceRecords/rec-1",
                    "space": "spaces/abc-defg-hij",
                    "startTime": "2026-05-04T10:00:00Z",
                    "endTime": "2026-05-04T11:00:00Z"
                }]
            })),
            json_response(json!({
                "participants": [
                    {
                        "name": "conferenceRecords/rec-1/participants/p1",
                        "signedinUser": {
                            "user": "users/alice",
                            "displayName": "Alice Example"
                        }
                    },
                    {
                        "name": "conferenceRecords/rec-1/participants/p2",
                        "signedinUser": {
                            "user": "users/bob",
                            "displayName": "Bob Example"
                        }
                    }
                ]
            })),
            json_response(json!({
                "participantSessions": [{
                    "name": "conferenceRecords/rec-1/participants/p1/participantSessions/s1",
                    "startTime": "2026-05-04T10:02:00Z",
                    "endTime": "2026-05-04T10:40:00Z"
                }]
            })),
            json_response(json!({
                "participantSessions": [{
                    "name": "conferenceRecords/rec-1/participants/p2/participantSessions/s1",
                    "startTime": "2026-05-04T10:15:00Z",
                    "endTime": "2026-05-04T10:45:00Z"
                }]
            })),
        ]);
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([(
                "base_url",
                json!(base_url),
            )]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_SPACE_READ_CAP, MEET_CONFERENCE_READ_CAP],
            }))
            .await
            .expect("handshake");
        let capability = capability_for_cap(
            &connector,
            &signing_key,
            ATTENDANCE_LIST_OP,
            MEET_CONFERENCE_READ_CAP,
        );

        let result = connector
            .handle_invoke(json!({
                "operation": ATTENDANCE_LIST_OP,
                "input": {
                    "meeting": "https://meet.google.com/abc-defg-hij",
                    "max_items": 10
                },
                "capability_token": capability,
            }))
            .await
            .expect("attendance invoke");
        finish_loopback(server);

        let attendance = result["attendance"].as_array().expect("attendance rows");
        assert_eq!(attendance.len(), 2);
        assert_eq!(
            attendance[0]["conference_record"],
            "conferenceRecords/rec-1"
        );
        assert_eq!(
            result["participant_evidence"][0]["participants"]
                .as_array()
                .expect("participants")
                .len(),
            2
        );

        let recorded = requests.lock().expect("requests").clone();
        assert_eq!(recorded.len(), 4, "loopback requests: {recorded:#?}");
        assert!(
            recorded
                .iter()
                .all(|request| request.authorization.as_deref() == Some("Bearer test-access")),
            "every Meet API request must carry injected auth"
        );
        let first_url =
            Url::parse(&format!("http://loopback.test{}", recorded[0].target)).expect("first URL");
        assert_eq!(first_url.path(), "/v2/conferenceRecords");
        let query: BTreeMap<_, _> = first_url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("filter"),
            Some(&"space.name = \"spaces/abc-defg-hij\"".to_string())
        );
        assert_eq!(query.get("pageSize"), Some(&DEFAULT_PAGE_SIZE.to_string()));
        assert!(
            recorded[1].target.contains("participants"),
            "participant request path: {}",
            recorded[1].target
        );
        assert_eq!(
            recorded
                .iter()
                .filter(|request| request.target.contains("participantSessions"))
                .count(),
            2
        );
    }

    #[fcp_async_core::runtime::test]
    async fn read_api_rate_limit_preserves_retry_after() {
        let (base_url, _requests, server) = spawn_loopback(vec![error_response(
            429,
            json!({ "error": { "message": "quota exceeded" } }),
            vec![("retry-after", "3".to_string())],
        )]);
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([(
                "base_url",
                json!(base_url),
            )]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_SPACE_READ_CAP, MEET_CONFERENCE_READ_CAP],
            }))
            .await
            .expect("handshake");
        let capability = capability_for_cap(
            &connector,
            &signing_key,
            CONFERENCE_RECORDS_LIST_OP,
            MEET_CONFERENCE_READ_CAP,
        );

        let err = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORDS_LIST_OP,
                "input": { "meeting": "spaces/abc-defg-hij" },
                "capability_token": capability,
            }))
            .await
            .expect_err("rate limit should fail");
        finish_loopback(server);

        assert!(matches!(
            err,
            FcpError::RateLimited {
                retry_after_ms: 3000,
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn read_api_rejects_missing_names_and_malformed_json() {
        let (base_url, _requests, server) = spawn_loopback(vec![
            json_response(json!({
                "participants": [{
                    "signedinUser": {
                        "user": "users/alice",
                        "displayName": "Alice Example"
                    }
                }]
            })),
            StubResponse {
                status: 200,
                headers: vec![("content-type", "application/json".to_string())],
                body: "{not-json".to_string(),
            },
        ]);
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([(
                "base_url",
                json!(base_url),
            )]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_SPACE_READ_CAP, MEET_CONFERENCE_READ_CAP],
            }))
            .await
            .expect("handshake");

        let missing_name = connector
            .handle_invoke(json!({
                "operation": PARTICIPANTS_LIST_OP,
                "input": { "conference_record": "conferenceRecords/rec-1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    PARTICIPANTS_LIST_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect_err("participants without names must fail");
        assert!(
            matches!(missing_name, FcpError::InvalidRequest { message, .. } if message.contains("without name"))
        );

        let malformed_json = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORD_GET_OP,
                "input": { "conference_record": "conferenceRecords/rec-1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    CONFERENCE_RECORD_GET_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect_err("malformed JSON must fail");
        finish_loopback(server);
        assert!(matches!(malformed_json, FcpError::Internal { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn read_api_rejects_malformed_collection_payload() {
        let (base_url, _requests, server) = spawn_loopback(vec![json_response(json!({
            "conferenceRecords": { "name": "not-an-array" }
        }))]);
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([(
                "base_url",
                json!(base_url),
            )]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_SPACE_READ_CAP, MEET_CONFERENCE_READ_CAP],
            }))
            .await
            .expect("handshake");
        let capability = capability_for_cap(
            &connector,
            &signing_key,
            CONFERENCE_RECORDS_LIST_OP,
            MEET_CONFERENCE_READ_CAP,
        );

        let err = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORDS_LIST_OP,
                "input": { "meeting": "spaces/abc-defg-hij" },
                "capability_token": capability,
            }))
            .await
            .expect_err("malformed collection should fail");
        finish_loopback(server);

        assert!(
            matches!(err, FcpError::InvalidRequest { message, .. } if message.contains("non-array collection"))
        );
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
    fn manifest_declares_read_api_capabilities_without_live_controls() {
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
            manifest.provides.operations.keys().all(|id| {
                matches!(
                    id.as_str(),
                    NORMALIZE_SPACE_OP
                        | SPACE_GET_OP
                        | SPACE_CREATE_OP
                        | SPACE_END_ACTIVE_CONFERENCE_OP
                        | CONFERENCE_RECORD_GET_OP
                        | CONFERENCE_RECORDS_LIST_OP
                        | CONFERENCE_RECORD_LATEST_OP
                        | PARTICIPANTS_LIST_OP
                        | PARTICIPANT_SESSIONS_LIST_OP
                        | ATTENDANCE_LIST_OP
                )
            }),
            "manifest should advertise only the spaces and conference-read operations"
        );
        assert_eq!(manifest.provides.operations.len(), 10);
        assert_eq!(
            manifest
                .provides
                .operations
                .iter()
                .find(|(id, _operation)| id.as_str() == SPACE_CREATE_OP)
                .map(|(_id, operation)| operation)
                .expect("space create op")
                .capability
                .as_str(),
            MEET_SPACE_CREATE_CAP
        );
        assert_eq!(
            manifest
                .provides
                .operations
                .iter()
                .find(|(id, _operation)| id.as_str() == CONFERENCE_RECORDS_LIST_OP)
                .map(|(_id, operation)| operation)
                .expect("conference list op")
                .capability
                .as_str(),
            MEET_CONFERENCE_READ_CAP
        );
    }
}
