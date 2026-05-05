//! FCP Google Meet connector foundation.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use chrono::{DateTime, SecondsFormat, Utc};
use fcp_async_core::{AsyncError, Cx, ExecutionContext, compatibility_cx};
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
    GoogleMeetParticipantSession, GoogleMeetSmartNote, GoogleMeetSpaceConfig, GoogleMeetTranscript,
    extract_docs_destination_document_id, google_auth_is_secretless, google_auth_redacted_label,
    validate_drive_document_id,
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
const MEET_LIVE_JOIN_CAP: &str = "meeting.live_join";
const MEET_LIVE_READ_CAP: &str = "meeting.live_read";
const MEET_LIVE_LEAVE_CAP: &str = "meeting.live_leave";
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
const LIVE_JOIN_OP: &str = "gmeet.live.join";
const LIVE_STATUS_OP: &str = "gmeet.live.status";
const LIVE_TRANSCRIPT_OP: &str = "gmeet.live.transcript";
const LIVE_LEAVE_OP: &str = "gmeet.live.leave";
const DEFAULT_PAGE_SIZE: u32 = 100;
const MAX_CONFERENCE_RECORD_PAGE_SIZE: u32 = 100;
const MAX_PARTICIPANT_PAGE_SIZE: u32 = 250;
const MAX_ARTIFACT_PAGE_SIZE: u32 = 100;
const DEFAULT_MAX_ITEMS: usize = 100;
const MAX_ITEMS_CAP: usize = 1_000;
const DEFAULT_DRIVE_EXPORT_MAX_BYTES: usize = 1_048_576;
const MAX_DRIVE_EXPORT_BYTES: usize = 10 * 1_048_576;
const ARTIFACT_OPERATION_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const DEFAULT_LIVE_SESSION_DURATION_MINUTES: u64 = 60;
const MAX_LIVE_SESSION_DURATION_MINUTES: u64 = 8 * 60;
const MEETINGS_SPACE_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/meetings.space.readonly";
const MEETINGS_SPACE_CREATED_SCOPE: &str = "https://www.googleapis.com/auth/meetings.space.created";
const MEETINGS_SPACE_SETTINGS_SCOPE: &str =
    "https://www.googleapis.com/auth/meetings.space.settings";
const DRIVE_MEET_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/drive.meet.readonly";
const MEET_REST_READ_SCOPES: &[&str] =
    &[MEETINGS_SPACE_CREATED_SCOPE, MEETINGS_SPACE_READONLY_SCOPE];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GoogleMeetLiveMode {
    Transcribe,
    Realtime,
}

impl GoogleMeetLiveMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Transcribe => "transcribe",
            Self::Realtime => "realtime",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleMeetStopReason {
    code: String,
    message: String,
    stopped_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleMeetLiveSession {
    session_id: String,
    meeting_url: String,
    meeting_code: String,
    mode: GoogleMeetLiveMode,
    max_duration_minutes: u64,
    started_at: String,
    browser_handoff: serde_json::Value,
    transcript: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleMeetStoppedSession {
    session: GoogleMeetLiveSession,
    stop_reason: GoogleMeetStopReason,
}

#[derive(Debug, Clone, Default)]
struct GoogleMeetLiveState {
    active: Option<GoogleMeetLiveSession>,
    last_stopped: Option<GoogleMeetStoppedSession>,
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

fn validate_live_meet_url(input: &str) -> FcpResult<NormalizedMeetSpace> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid_request("meeting_url is required"));
    }

    let url = Url::parse(trimmed)
        .map_err(|error| invalid_request(format!("meeting_url could not be parsed: {error}")))?;
    if url.scheme() != "https" {
        return Err(invalid_request("meeting_url must use https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid_request("meeting_url must not include userinfo"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid_request("meeting_url must include a host"))?;
    if !host.eq_ignore_ascii_case("meet.google.com") {
        return Err(invalid_request(format!(
            "meeting_url must target canonical meet.google.com, received {host}"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_request(
            "meeting_url must not include a query string or fragment",
        ));
    }

    let segments: Vec<_> = url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.trim().is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if segments.len() != 1 {
        return Err(invalid_request(
            "meeting_url must be a canonical https://meet.google.com/<meeting-code> URL",
        ));
    }
    let code = segments
        .first()
        .copied()
        .ok_or_else(|| invalid_request("meeting_url did not include a valid meeting code"))?;
    validate_space_suffix(code, "meeting_url did not include a valid meeting code")?;

    Ok(NormalizedMeetSpace {
        space_name: format!("spaces/{code}"),
        meeting_code: Some(code.to_string()),
        meeting_uri: Some(format!("https://meet.google.com/{code}")),
        input_kind: MeetSpaceInputKind::MeetingUrl,
        live_session: true,
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

fn artifact_operation_context() -> ExecutionContext {
    ExecutionContext::request_scoped(ARTIFACT_OPERATION_TIMEOUT)
}

fn artifact_operation_cx(operation: &'static str) -> Cx {
    let cx = compatibility_cx();
    cx.set_task_type(operation);
    cx
}

fn artifact_checkpoint(cx: &Cx, checkpoint: impl Into<String>) -> FcpResult<()> {
    let checkpoint = checkpoint.into();
    cx.checkpoint_with(checkpoint.clone())
        .map_err(|error| FcpError::External {
            service: "google-meet".into(),
            message: format!("{checkpoint} async checkpoint failed: {error}"),
            status_code: None,
            retryable: true,
            retry_after: None,
        })
}

async fn run_google_artifact<T, Fut>(
    ctx: &ExecutionContext,
    cx: &Cx,
    future: Fut,
    operation: &'static str,
) -> FcpResult<T>
where
    Fut: Future<Output = GoogleMeetResult<T>>,
{
    artifact_checkpoint(cx, format!("{operation}: enter timeout budget"))?;
    let result = ctx
        .run(future)
        .await
        .map_err(|error| map_artifact_async_error(error, operation))?
        .map_err(|error| error.to_fcp_error())?;
    artifact_checkpoint(cx, format!("{operation}: leave timeout budget"))?;
    Ok(result)
}

fn map_artifact_async_error(error: AsyncError, operation: &'static str) -> FcpError {
    match error {
        AsyncError::Timeout { timeout_ms } => FcpError::External {
            service: "google-meet".into(),
            message: format!("{operation} timed out after {timeout_ms}ms"),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        AsyncError::Cancelled => FcpError::External {
            service: "google-meet".into(),
            message: format!("{operation} was cancelled before completion"),
            status_code: None,
            retryable: true,
            retry_after: None,
        },
        other => FcpError::Internal {
            message: format!("{operation} async substrate failure: {other}"),
        },
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
    if configured_scopes
        .iter()
        .any(|configured| configured == scope)
    {
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

fn scope_any_doctor_check(
    name: &str,
    configured_scopes: &[String],
    scopes: &[&'static str],
    missing_message: &'static str,
) -> DoctorCheck {
    if scopes.iter().any(|scope| {
        configured_scopes
            .iter()
            .any(|configured| configured == scope)
    }) {
        DoctorCheck {
            name: name.into(),
            status: DoctorStatus::Healthy,
            message: format!("Configured scope: one of {}", scopes.join(", ")),
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
    live_state: Mutex<GoogleMeetLiveState>,
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
            live_state: Mutex::new(GoogleMeetLiveState::default()),
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
                "live_session_operations": true,
                "live_session_contract": "browser_handoff_only",
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
            "live_session_operations": true,
            "live_session_contract": "browser_handoff_only",
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
            checks.push(scope_any_doctor_check(
                "meet_rest_read_scope",
                &config.required_scopes,
                MEET_REST_READ_SCOPES,
                "Conference records, participants, recordings, transcripts, transcript entries, and smart notes require meetings.space.readonly or meetings.space.created; 401/403 can also mean restricted-scope review, developer-preview enrollment, or workspace policy denial.",
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
            message: "Live join/status/transcript/leave are available as a browser-handoff contract; browser automation remains delegated to fcp.browser and live speak remains deferred".into(),
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
            LIVE_JOIN_OP => self.invoke_live_join(&input),
            LIVE_STATUS_OP => self.invoke_live_status(),
            LIVE_TRANSCRIPT_OP => self.invoke_live_transcript(&input),
            LIVE_LEAVE_OP => self.invoke_live_leave(&input),
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    fn invoke_live_join(&self, input: &serde_json::Value) -> FcpResult<serde_json::Value> {
        let normalized = validate_live_meet_url(require_str(input, "meeting_url")?)?;
        let mode = parse_live_mode(input)?;
        let max_duration_minutes = parse_optional_u64(
            input,
            "max_duration_minutes",
            1,
            MAX_LIVE_SESSION_DURATION_MINUTES,
        )?
        .unwrap_or(DEFAULT_LIVE_SESSION_DURATION_MINUTES);
        let session_id = SessionId::new().to_string();
        let meeting_url = normalized
            .meeting_uri
            .ok_or_else(|| invalid_request("meeting_url did not normalize to a Meet URL"))?;
        let meeting_code = normalized
            .meeting_code
            .ok_or_else(|| invalid_request("meeting_url did not normalize to a meeting code"))?;
        let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let browser_handoff =
            browser_handoff_contract(&session_id, &meeting_url, mode, max_duration_minutes);
        let session = GoogleMeetLiveSession {
            session_id,
            meeting_url,
            meeting_code,
            mode,
            max_duration_minutes,
            started_at,
            browser_handoff,
            transcript: Vec::new(),
        };

        let replaced_session = {
            let mut state = self.live_state.lock().map_err(|_| FcpError::Internal {
                message: "Google Meet live-session state lock poisoned".into(),
            })?;
            let replaced_session = state.active.take().map(|previous| {
                let stopped = GoogleMeetStoppedSession {
                    session: previous,
                    stop_reason: stop_reason(
                        "replaced_by_new_join",
                        "Previous live session was replaced by a new join request",
                    ),
                };
                let value = stopped_session_json(&stopped);
                state.last_stopped = Some(stopped);
                value
            });
            state.active = Some(session.clone());
            replaced_session
        };

        Ok(json!({
            "accepted": true,
            "status": "active",
            "session": live_session_json(&session),
            "browser_handoff": session.browser_handoff,
            "replaced_session": replaced_session,
        }))
    }

    fn invoke_live_status(&self) -> FcpResult<serde_json::Value> {
        let state = self.live_state.lock().map_err(|_| FcpError::Internal {
            message: "Google Meet live-session state lock poisoned".into(),
        })?;
        Ok(live_state_json(&state))
    }

    fn invoke_live_transcript(&self, input: &serde_json::Value) -> FcpResult<serde_json::Value> {
        let session_filter = optional_str(input, "session_id")?;
        let session_payload = {
            let state = self.live_state.lock().map_err(|_| FcpError::Internal {
                message: "Google Meet live-session state lock poisoned".into(),
            })?;
            state
                .active
                .as_ref()
                .filter(|session| {
                    session_filter.is_none_or(|expected| expected == session.session_id)
                })
                .map(|session| {
                    (
                        true,
                        live_session_summary_json(session),
                        session.transcript.clone(),
                        session.transcript.len(),
                    )
                })
                .or_else(|| {
                    state.last_stopped.as_ref().and_then(|stopped| {
                        session_filter
                            .is_none_or(|expected| expected == stopped.session.session_id)
                            .then(|| {
                                (
                                    false,
                                    live_session_summary_json(&stopped.session),
                                    stopped.session.transcript.clone(),
                                    stopped.session.transcript.len(),
                                )
                            })
                    })
                })
        };
        let Some((active, session, entries, entry_count)) = session_payload else {
            return Ok(json!({
                "active": false,
                "session": null,
                "entries": [],
                "entry_count": 0,
            }));
        };
        Ok(json!({
            "active": active,
            "session": session,
            "entries": entries,
            "entry_count": entry_count,
        }))
    }

    fn invoke_live_leave(&self, input: &serde_json::Value) -> FcpResult<serde_json::Value> {
        enum LeaveOutcome {
            NoActive {
                stop_reason: Option<serde_json::Value>,
            },
            Stopped {
                stopped_session: serde_json::Value,
            },
        }

        let session_filter = optional_str(input, "session_id")?;
        let outcome = {
            let mut state = self.live_state.lock().map_err(|_| FcpError::Internal {
                message: "Google Meet live-session state lock poisoned".into(),
            })?;
            let mismatch = state.active.as_ref().and_then(|active| {
                session_filter.filter(|expected| *expected != active.session_id)
            });
            if let Some(expected) = mismatch {
                let expected = expected.to_string();
                drop(state);
                return Err(invalid_request(format!(
                    "session_id {expected} does not match active Google Meet live session"
                )));
            }
            if let Some(active) = state.active.take() {
                let stopped = GoogleMeetStoppedSession {
                    session: active,
                    stop_reason: stop_reason(
                        "leave_requested",
                        "Live session was stopped by an explicit leave request",
                    ),
                };
                let stopped_session = stopped_session_json(&stopped);
                state.last_stopped = Some(stopped);
                drop(state);
                LeaveOutcome::Stopped { stopped_session }
            } else {
                let stop_reason = state
                    .last_stopped
                    .as_ref()
                    .map(|stopped| stop_reason_json(&stopped.stop_reason));
                drop(state);
                LeaveOutcome::NoActive { stop_reason }
            }
        };
        match outcome {
            LeaveOutcome::NoActive { stop_reason } => Ok(json!({
                "accepted": true,
                "status": "stopped",
                "active": false,
                "session": null,
                "stop_reason": stop_reason,
            })),
            LeaveOutcome::Stopped { stopped_session } => Ok(json!({
                "accepted": true,
                "status": "stopped",
                "active": false,
                "stopped_session": stopped_session,
            })),
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

    fn ensure_meet_rest_read_scope(&self, operation: &str) -> FcpResult<()> {
        self.ensure_any_configured_scope(operation, MEET_REST_READ_SCOPES)
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
        self.ensure_meet_rest_read_scope(CONFERENCE_RECORD_GET_OP)?;
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
        self.ensure_meet_rest_read_scope(CONFERENCE_RECORDS_LIST_OP)?;
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
        self.ensure_meet_rest_read_scope(CONFERENCE_RECORD_LATEST_OP)?;
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
        self.ensure_meet_rest_read_scope(PARTICIPANTS_LIST_OP)?;
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
        self.ensure_meet_rest_read_scope(PARTICIPANT_SESSIONS_LIST_OP)?;
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
        self.ensure_meet_rest_read_scope(ATTENDANCE_LIST_OP)?;
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
        self.ensure_meet_rest_read_scope(RECORDINGS_LIST_OP)?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let ctx = artifact_operation_context();
        let cx = artifact_operation_cx(RECORDINGS_LIST_OP);
        let recordings = run_google_artifact(
            &ctx,
            &cx,
            client.list_recordings_with_cx(&cx, conference_record, page_size, Some(max_items)),
            RECORDINGS_LIST_OP,
        )
        .await?;
        artifact_checkpoint(&cx, format!("{RECORDINGS_LIST_OP}: assemble response"))?;
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
        self.ensure_meet_rest_read_scope(TRANSCRIPTS_LIST_OP)?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let ctx = artifact_operation_context();
        let cx = artifact_operation_cx(TRANSCRIPTS_LIST_OP);
        let transcripts = run_google_artifact(
            &ctx,
            &cx,
            client.list_transcripts_with_cx(&cx, conference_record, page_size, Some(max_items)),
            TRANSCRIPTS_LIST_OP,
        )
        .await?;
        artifact_checkpoint(&cx, format!("{TRANSCRIPTS_LIST_OP}: assemble response"))?;
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
        self.ensure_meet_rest_read_scope(TRANSCRIPT_ENTRIES_LIST_OP)?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let transcript = require_str(input, "transcript")?;
        let ctx = artifact_operation_context();
        let cx = artifact_operation_cx(TRANSCRIPT_ENTRIES_LIST_OP);
        let mut entries = run_google_artifact(
            &ctx,
            &cx,
            client.list_transcript_entries_with_cx(&cx, transcript, page_size, Some(max_items)),
            TRANSCRIPT_ENTRIES_LIST_OP,
        )
        .await?;
        artifact_checkpoint(&cx, format!("{TRANSCRIPT_ENTRIES_LIST_OP}: sort entries"))?;
        entries.sort_by_key(|entry| {
            (
                parse_timestamp_ms(entry.start_time.as_deref()).unwrap_or_default(),
                entry.name.clone(),
            )
        });
        artifact_checkpoint(
            &cx,
            format!("{TRANSCRIPT_ENTRIES_LIST_OP}: assemble response"),
        )?;
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
        self.ensure_meet_rest_read_scope(SMART_NOTES_LIST_OP)?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let ctx = artifact_operation_context();
        let cx = artifact_operation_cx(SMART_NOTES_LIST_OP);
        let smart_notes = run_google_artifact(
            &ctx,
            &cx,
            client.list_smart_notes_with_cx(&cx, conference_record, page_size, Some(max_items)),
            SMART_NOTES_LIST_OP,
        )
        .await?;
        artifact_checkpoint(&cx, format!("{SMART_NOTES_LIST_OP}: assemble response"))?;
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
        self.ensure_meet_rest_read_scope(TRANSCRIPTS_WITH_TEXT_LIST_OP)?;
        self.ensure_configured_scopes(TRANSCRIPTS_WITH_TEXT_LIST_OP, &[DRIVE_MEET_READONLY_SCOPE])?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let max_document_bytes = parse_max_document_bytes(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let ctx = artifact_operation_context();
        let cx = artifact_operation_cx(TRANSCRIPTS_WITH_TEXT_LIST_OP);
        let transcripts = run_google_artifact(
            &ctx,
            &cx,
            client.list_transcripts_with_cx(&cx, conference_record, page_size, Some(max_items)),
            TRANSCRIPTS_WITH_TEXT_LIST_OP,
        )
        .await?;
        let transcripts =
            attach_transcript_document_texts(&ctx, &cx, client, transcripts, max_document_bytes)
                .await;
        artifact_checkpoint(
            &cx,
            format!("{TRANSCRIPTS_WITH_TEXT_LIST_OP}: assemble response"),
        )?;
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
        self.ensure_meet_rest_read_scope(SMART_NOTES_WITH_TEXT_LIST_OP)?;
        self.ensure_configured_scopes(SMART_NOTES_WITH_TEXT_LIST_OP, &[DRIVE_MEET_READONLY_SCOPE])?;
        let page_size = parse_page_size(input, MAX_ARTIFACT_PAGE_SIZE)?;
        let max_items = parse_max_items(input)?;
        let max_document_bytes = parse_max_document_bytes(input)?;
        let conference_record = require_str(input, "conference_record")?;
        let ctx = artifact_operation_context();
        let cx = artifact_operation_cx(SMART_NOTES_WITH_TEXT_LIST_OP);
        let smart_notes = run_google_artifact(
            &ctx,
            &cx,
            client.list_smart_notes_with_cx(&cx, conference_record, page_size, Some(max_items)),
            SMART_NOTES_WITH_TEXT_LIST_OP,
        )
        .await?;
        let smart_notes =
            attach_smart_note_document_texts(&ctx, &cx, client, smart_notes, max_document_bytes)
                .await;
        artifact_checkpoint(
            &cx,
            format!("{SMART_NOTES_WITH_TEXT_LIST_OP}: assemble response"),
        )?;
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
        let ctx = artifact_operation_context();
        let cx = artifact_operation_cx(DRIVE_DOCUMENT_TEXT_EXPORT_OP);
        let text = run_google_artifact(
            &ctx,
            &cx,
            client.export_drive_document_text_with_cx(&cx, &document_id, max_document_bytes),
            DRIVE_DOCUMENT_TEXT_EXPORT_OP,
        )
        .await?;
        artifact_checkpoint(
            &cx,
            format!("{DRIVE_DOCUMENT_TEXT_EXPORT_OP}: assemble response"),
        )?;
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

fn parse_live_mode(input: &serde_json::Value) -> FcpResult<GoogleMeetLiveMode> {
    let Some(raw) = optional_str(input, "mode")? else {
        return Ok(GoogleMeetLiveMode::Transcribe);
    };
    match raw {
        "transcribe" => Ok(GoogleMeetLiveMode::Transcribe),
        "realtime" => Ok(GoogleMeetLiveMode::Realtime),
        _ => Err(invalid_request(
            "`mode` must be either `transcribe` or `realtime`",
        )),
    }
}

fn stop_reason(code: &str, message: &str) -> GoogleMeetStopReason {
    GoogleMeetStopReason {
        code: code.to_string(),
        message: message.to_string(),
        stopped_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    }
}

fn stop_reason_json(reason: &GoogleMeetStopReason) -> serde_json::Value {
    json!({
        "code": &reason.code,
        "message": &reason.message,
        "stopped_at": &reason.stopped_at,
    })
}

fn live_session_summary_json(session: &GoogleMeetLiveSession) -> serde_json::Value {
    json!({
        "session_id": &session.session_id,
        "meeting_url": &session.meeting_url,
        "meeting_code": &session.meeting_code,
        "mode": session.mode.as_str(),
        "max_duration_minutes": session.max_duration_minutes,
        "started_at": &session.started_at,
    })
}

fn live_session_json(session: &GoogleMeetLiveSession) -> serde_json::Value {
    let mut value = live_session_summary_json(session);
    value["browser_handoff"] = session.browser_handoff.clone();
    value["transcript_entry_count"] = json!(session.transcript.len());
    value
}

fn stopped_session_json(stopped: &GoogleMeetStoppedSession) -> serde_json::Value {
    json!({
        "session": live_session_summary_json(&stopped.session),
        "stop_reason": stop_reason_json(&stopped.stop_reason),
    })
}

fn live_state_json(state: &GoogleMeetLiveState) -> serde_json::Value {
    json!({
        "active": state.active.is_some(),
        "session": state.active.as_ref().map(live_session_json),
        "last_stopped": state.last_stopped.as_ref().map(stopped_session_json),
    })
}

fn browser_handoff_contract(
    session_id: &str,
    meeting_url: &str,
    mode: GoogleMeetLiveMode,
    max_duration_minutes: u64,
) -> serde_json::Value {
    json!({
        "contract_version": "gmeet_live_browser_handoff.v1",
        "target_connector": "fcp.browser",
        "target_capabilities": [
            "browser.navigate",
            "browser.capture",
            "browser.extract",
            "browser.interact"
        ],
        "local_control_policy": {
            "bind": "loopback_only",
            "remote_exposure": "deny_by_default",
            "secret_files": "avoid",
            "owner_only_files_required": true
        },
        "session": {
            "session_id": session_id,
            "meeting_url": meeting_url,
            "mode": mode.as_str(),
            "max_duration_minutes": max_duration_minutes
        },
        "worker_plan": [
            {
                "operation": "browser.navigate",
                "input": {
                    "url": meeting_url,
                    "wait_until": "domcontentloaded",
                    "timeout_ms": 30000
                }
            },
            {
                "operation": "browser.wait_for_selector",
                "input": {
                    "selector": "body",
                    "timeout_ms": 30000
                }
            },
            {
                "operation": "browser.extract_text",
                "input": {
                    "selector": "body",
                    "timeout_ms": 5000
                }
            }
        ],
        "audit": {
            "source_connector": CONNECTOR_ID,
            "reason": "google_meet_live_session_handoff",
            "no_embedded_browser_runtime": true
        }
    })
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
                    r"{}".into(),
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
        live_join_op_info(),
        live_read_op_info(
            LIVE_STATUS_OP,
            "Return the active Google Meet live-session status and latest stop reason",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
        live_read_op_info(
            LIVE_TRANSCRIPT_OP,
            "Return the transcript buffer for the active or most recently stopped live session",
            json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                }
            }),
        ),
        live_leave_op_info(),
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
                "These operations require meetings.space.readonly or meetings.space.created OAuth scope and may be restricted or developer-preview gated.".into(),
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

fn live_join_op_info() -> OperationInfo {
    let mut info = op_info(
        LIVE_JOIN_OP,
        "Create or replace a Google Meet live-session browser handoff contract",
        json!({
            "type": "object",
            "required": ["meeting_url"],
            "properties": {
                "meeting_url": {
                    "type": "string",
                    "description": "Canonical https://meet.google.com/<meeting-code> URL"
                },
                "mode": {
                    "type": "string",
                    "enum": ["transcribe", "realtime"],
                    "default": "transcribe"
                },
                "max_duration_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_LIVE_SESSION_DURATION_MINUTES
                }
            }
        }),
        json!({
            "type": "object",
            "required": ["accepted", "status", "session", "browser_handoff"],
            "properties": {
                "accepted": { "type": "boolean" },
                "status": { "type": "string" },
                "session": { "type": "object" },
                "browser_handoff": { "type": "object" },
                "replaced_session": { "type": ["object", "null"] }
            }
        }),
        MEET_LIVE_JOIN_CAP,
        RiskLevel::High,
        SafetyTier::Dangerous,
        IdempotencyClass::BestEffort,
        AgentHint {
            when_to_use: "Request a supervised browser-connector handoff for an active Google Meet session after explicit user consent.".into(),
            common_mistakes: vec![
                "Passing Calendar or redirect URLs; only canonical https://meet.google.com/<meeting-code> URLs are accepted.".into(),
                "Assuming this connector embeds a browser runtime; the response is a strict fcp.browser handoff contract.".into(),
            ],
            examples: vec![
                r#"{"meeting_url":"https://meet.google.com/abc-defg-hij","mode":"transcribe"}"#.into(),
            ],
            related: vec![CapabilityId::from_static(LIVE_STATUS_OP)],
        },
    );
    info.requires_approval = Some(ApprovalMode::Interactive);
    info
}

fn live_read_op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
) -> OperationInfo {
    let mut info = op_info(
        id,
        summary,
        input_schema,
        json!({
            "type": "object",
            "additionalProperties": true
        }),
        MEET_LIVE_READ_CAP,
        RiskLevel::Medium,
        SafetyTier::Risky,
        IdempotencyClass::Strict,
        AgentHint {
            when_to_use: "Inspect an authorized Google Meet live-session control contract or transcript buffer.".into(),
            common_mistakes: vec![
                "Treating live transcript reads like completed artifact reads; live content uses a separate capability.".into(),
                "Expecting browser automation side effects from status or transcript reads.".into(),
            ],
            examples: vec![r"{}".into()],
            related: vec![CapabilityId::from_static(LIVE_JOIN_OP)],
        },
    );
    info.requires_approval = Some(ApprovalMode::Policy);
    info
}

fn live_leave_op_info() -> OperationInfo {
    let mut info = op_info(
        LIVE_LEAVE_OP,
        "Stop the active Google Meet live-session handoff contract",
        json!({
            "type": "object",
            "properties": {
                "session_id": { "type": "string" }
            }
        }),
        json!({
            "type": "object",
            "required": ["accepted", "status", "active"],
            "properties": {
                "accepted": { "type": "boolean" },
                "status": { "type": "string" },
                "active": { "type": "boolean" },
                "stopped_session": { "type": "object" }
            }
        }),
        MEET_LIVE_LEAVE_CAP,
        RiskLevel::Medium,
        SafetyTier::Risky,
        IdempotencyClass::BestEffort,
        AgentHint {
            when_to_use: "Leave the currently active Google Meet browser handoff session and preserve a structured stop reason.".into(),
            common_mistakes: vec![
                "Calling leave with a stale session_id after a replacement join has already stopped that session.".into(),
            ],
            examples: vec![r#"{"session_id":"<session-id>"}"#.into()],
            related: vec![CapabilityId::from_static(LIVE_STATUS_OP)],
        },
    );
    info.requires_approval = Some(ApprovalMode::Policy);
    info
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
    ctx: &ExecutionContext,
    cx: &Cx,
    client: &GoogleMeetClient,
    mut transcripts: Vec<GoogleMeetTranscript>,
    max_document_bytes: usize,
) -> Vec<GoogleMeetTranscript> {
    for transcript in &mut transcripts {
        if let Err(error) = cx.checkpoint_with(format!(
            "{TRANSCRIPTS_WITH_TEXT_LIST_OP}: assemble transcript document text"
        )) {
            transcript.document_text_error = Some(format!(
                "{TRANSCRIPTS_WITH_TEXT_LIST_OP} async checkpoint failed during partial assembly: {error}"
            ));
            break;
        }
        match document_id_from_destination(transcript.docs_destination.as_ref()) {
            Ok(Some(document_id)) => {
                transcript.document_id = Some(document_id.clone());
                match ctx
                    .run(client.export_drive_document_text_with_cx(
                        cx,
                        &document_id,
                        max_document_bytes,
                    ))
                    .await
                {
                    Ok(Ok(text)) => transcript.document_text = Some(text),
                    Ok(Err(error)) => {
                        transcript.document_text_error = Some(public_google_error(&error));
                    }
                    Err(error) => {
                        transcript.document_text_error =
                            Some(public_async_error(&error, TRANSCRIPTS_WITH_TEXT_LIST_OP));
                    }
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
    ctx: &ExecutionContext,
    cx: &Cx,
    client: &GoogleMeetClient,
    mut smart_notes: Vec<GoogleMeetSmartNote>,
    max_document_bytes: usize,
) -> Vec<GoogleMeetSmartNote> {
    for smart_note in &mut smart_notes {
        if let Err(error) = cx.checkpoint_with(format!(
            "{SMART_NOTES_WITH_TEXT_LIST_OP}: assemble smart-note document text"
        )) {
            smart_note.document_text_error = Some(format!(
                "{SMART_NOTES_WITH_TEXT_LIST_OP} async checkpoint failed during partial assembly: {error}"
            ));
            break;
        }
        match document_id_from_destination(smart_note.docs_destination.as_ref()) {
            Ok(Some(document_id)) => {
                smart_note.document_id = Some(document_id.clone());
                match ctx
                    .run(client.export_drive_document_text_with_cx(
                        cx,
                        &document_id,
                        max_document_bytes,
                    ))
                    .await
                {
                    Ok(Ok(text)) => smart_note.document_text = Some(text),
                    Ok(Err(error)) => {
                        smart_note.document_text_error = Some(public_google_error(&error));
                    }
                    Err(error) => {
                        smart_note.document_text_error =
                            Some(public_async_error(&error, SMART_NOTES_WITH_TEXT_LIST_OP));
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
    let destination: GoogleMeetDocsDestination = serde_json::from_value(destination.clone())
        .map_err(|error| {
            invalid_request(format!(
                "`docs_destination` must be a Meet docsDestination object: {error}"
            ))
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

fn public_async_error(error: &AsyncError, operation: &'static str) -> String {
    match error {
        AsyncError::Timeout { timeout_ms } => format!("{operation} timed out after {timeout_ms}ms"),
        AsyncError::Cancelled => format!("{operation} was cancelled before completion"),
        other => format!("{operation} async substrate failure: {other}"),
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
        LIVE_JOIN_OP => Ok(CapabilityId::from_static(MEET_LIVE_JOIN_CAP)),
        LIVE_STATUS_OP | LIVE_TRANSCRIPT_OP => Ok(CapabilityId::from_static(MEET_LIVE_READ_CAP)),
        LIVE_LEAVE_OP => Ok(CapabilityId::from_static(MEET_LIVE_LEAVE_CAP)),
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
        response_status: u16,
        response_body_bytes: usize,
        response_retry_after_ms: Option<u64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct GoogleMeetArtifactHarnessLog {
        schema_version: String,
        bead_id: String,
        connector_id: String,
        correlation_id: String,
        operation: String,
        method: String,
        path: String,
        normalized_resource: String,
        scope_family: String,
        pagination_token: Option<String>,
        retry_backoff_ms: Option<u64>,
        latency_ms: u64,
        response_byte_count: usize,
        cancellation_checkpoint: String,
        redaction_decision: String,
        outcome: String,
        http_status: u16,
        error_code: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct GoogleMeetArtifactHarnessSkip {
        schema_version: String,
        bead_id: String,
        connector_id: String,
        correlation_id: String,
        operation: String,
        missing_prerequisite: String,
        reason: String,
        outcome: String,
    }

    struct HarnessInvoke<'a> {
        connector: &'a GoogleMeetConnector,
        signing_key: &'a Ed25519SigningKey,
        operation: &'static str,
        capability_id: &'static str,
        input: serde_json::Value,
        normalized_resource: &'static str,
        expected_outcome: &'static str,
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
                let response_status = response.status;
                let response_body_bytes = response.body.len();
                let response_retry_after_ms = response.headers.iter().find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("retry-after")
                        .then(|| value.parse::<u64>().expect("retry-after seconds") * 1_000)
                });
                recorded
                    .lock()
                    .expect("record requests")
                    .push(RecordedRequest {
                        method,
                        target,
                        authorization,
                        body: String::from_utf8_lossy(&body[..content_length.min(body.len())])
                            .to_string(),
                        response_status,
                        response_body_bytes,
                        response_retry_after_ms,
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
            json!(["sample", "value"].join("-")),
        );
        object
    }

    fn direct_test_auth_config() -> serde_json::Value {
        direct_test_auth_config_with([("required_scopes", json!([MEETINGS_SPACE_READONLY_SCOPE]))])
    }

    fn direct_test_bearer_header() -> String {
        let scheme = ["Bear", "er"].concat();
        let value = ["sample", "value"].join("-");
        format!("{scheme} {value}")
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

    fn harness_log_for_request(
        request: &RecordedRequest,
        spec: &HarnessInvoke<'_>,
        correlation_id: &str,
        latency_ms: u64,
        error_code: Option<String>,
    ) -> GoogleMeetArtifactHarnessLog {
        GoogleMeetArtifactHarnessLog {
            schema_version: "google_meet_artifact_loopback.v1".to_string(),
            bead_id: "flywheel_connectors-4kw5f.5.1.1.1.5".to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            operation: spec.operation.to_string(),
            method: request.method.clone(),
            path: request.target.clone(),
            normalized_resource: spec.normalized_resource.to_string(),
            scope_family: spec.capability_id.to_string(),
            pagination_token: query_value(&request.target, "pageToken"),
            retry_backoff_ms: request.response_retry_after_ms,
            latency_ms,
            response_byte_count: request.response_body_bytes,
            cancellation_checkpoint: "connector_boundary_invoke_completed".to_string(),
            redaction_decision: if request.authorization.is_some() {
                "authorization_header_redacted"
            } else {
                "no_authorization_header"
            }
            .to_string(),
            outcome: spec.expected_outcome.to_string(),
            http_status: request.response_status,
            error_code,
        }
    }

    fn harness_skip(
        correlation_id: &str,
        operation: &str,
        missing_prerequisite: &str,
        reason: &str,
    ) -> GoogleMeetArtifactHarnessSkip {
        GoogleMeetArtifactHarnessSkip {
            schema_version: "google_meet_artifact_loopback.skip.v1".to_string(),
            bead_id: "flywheel_connectors-4kw5f.5.1.1.1.5".to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            operation: operation.to_string(),
            missing_prerequisite: missing_prerequisite.to_string(),
            reason: reason.to_string(),
            outcome: "skip".to_string(),
        }
    }

    fn query_value(target: &str, key: &str) -> Option<String> {
        Url::parse(&format!("http://loopback.test{target}"))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
            })
    }

    fn elapsed_millis(start: Instant) -> u64 {
        u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    async fn invoke_harness_operation(
        requests: &Arc<Mutex<Vec<RecordedRequest>>>,
        logs: &mut Vec<GoogleMeetArtifactHarnessLog>,
        correlation_id: &str,
        spec: HarnessInvoke<'_>,
    ) -> Option<serde_json::Value> {
        let before = requests.lock().expect("request log").len();
        let start = Instant::now();
        let result = spec
            .connector
            .handle_invoke(json!({
                "operation": spec.operation,
                "input": spec.input,
                "capability_token": capability_for_cap(
                    spec.connector,
                    spec.signing_key,
                    spec.operation,
                    spec.capability_id
                ),
            }))
            .await;
        let latency_ms = elapsed_millis(start);
        let error_code = result.as_ref().err().map(FcpError::error_code);
        let recorded = requests.lock().expect("request log").clone();
        assert!(
            recorded.len() > before,
            "{} should cross the loopback connector boundary",
            spec.operation
        );
        for request in &recorded[before..] {
            logs.push(harness_log_for_request(
                request,
                &spec,
                correlation_id,
                latency_ms,
                error_code.clone(),
            ));
        }

        if spec.expected_outcome == "pass" {
            Some(result.expect("harness operation should pass"))
        } else {
            assert!(
                result.is_err(),
                "{} should produce {}",
                spec.operation,
                spec.expected_outcome
            );
            None
        }
    }

    fn assert_log_schema(entry: &GoogleMeetArtifactHarnessLog) {
        let value = serde_json::to_value(entry).expect("log entry JSON");
        for field in [
            "schema_version",
            "bead_id",
            "connector_id",
            "correlation_id",
            "operation",
            "method",
            "path",
            "normalized_resource",
            "scope_family",
            "latency_ms",
            "response_byte_count",
            "cancellation_checkpoint",
            "redaction_decision",
            "outcome",
            "http_status",
        ] {
            assert!(value.get(field).is_some(), "missing log field {field}");
        }
        assert_eq!(entry.schema_version, "google_meet_artifact_loopback.v1");
        assert_eq!(entry.bead_id, "flywheel_connectors-4kw5f.5.1.1.1.5");
        assert!(!entry.correlation_id.trim().is_empty());
        assert!(!entry.operation.trim().is_empty());
        assert!(!entry.method.trim().is_empty());
        assert!(!entry.path.trim().is_empty());
        assert!(!entry.normalized_resource.trim().is_empty());
        assert!(!entry.scope_family.trim().is_empty());
    }

    fn assert_skip_schema(entry: &GoogleMeetArtifactHarnessSkip) {
        let value = serde_json::to_value(entry).expect("skip artifact JSON");
        for field in [
            "schema_version",
            "bead_id",
            "connector_id",
            "correlation_id",
            "operation",
            "missing_prerequisite",
            "reason",
            "outcome",
        ] {
            assert!(value.get(field).is_some(), "missing skip field {field}");
        }
        assert_eq!(
            entry.schema_version,
            "google_meet_artifact_loopback.skip.v1"
        );
        assert_eq!(entry.outcome, "skip");
        assert!(!entry.missing_prerequisite.trim().is_empty());
        assert!(!entry.reason.trim().is_empty());
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
    fn validate_live_meet_url_accepts_only_canonical_meet_urls() {
        let normalized =
            validate_live_meet_url("https://meet.google.com/abc-defg-hij").expect("live url");
        assert_eq!(normalized.space_name, "spaces/abc-defg-hij");
        assert_eq!(
            normalized.meeting_uri.as_deref(),
            Some("https://meet.google.com/abc-defg-hij")
        );
        assert!(normalized.live_session);

        let meet_userinfo_url = format!("https://{}@meet.google.com/abc-defg-hij", "user");
        for raw in [
            "",
            "http://meet.google.com/abc-defg-hij",
            "https://calendar.google.com/calendar/event?eid=abc",
            "https://meet.google.com.evil.example/abc-defg-hij",
            meet_userinfo_url.as_str(),
            "https://meet.google.com/abc-defg-hij?pli=1",
            "https://meet.google.com/abc-defg-hij#frag",
            "https://meet.google.com/lookup/abc-defg-hij",
            "https://meet.google.com/",
        ] {
            assert!(
                matches!(
                    validate_live_meet_url(raw),
                    Err(FcpError::InvalidRequest { .. })
                ),
                "{raw:?} should be rejected for live control"
            );
        }
    }

    #[test]
    fn live_mode_and_duration_bounds_are_strict() {
        assert_eq!(
            parse_live_mode(&json!({})).expect("default mode"),
            GoogleMeetLiveMode::Transcribe
        );
        assert_eq!(
            parse_live_mode(&json!({ "mode": "realtime" })).expect("realtime mode"),
            GoogleMeetLiveMode::Realtime
        );
        assert!(parse_live_mode(&json!({ "mode": "voice" })).is_err());
        assert!(
            parse_optional_u64(
                &json!({ "max_duration_minutes": MAX_LIVE_SESSION_DURATION_MINUTES + 1 }),
                "max_duration_minutes",
                1,
                MAX_LIVE_SESSION_DURATION_MINUTES
            )
            .is_err()
        );
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
        assert_eq!(result["details"]["live_session_operations"], true);
        assert_eq!(
            result["details"]["live_session_contract"],
            "browser_handoff_only"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn health_and_doctor_make_live_session_deferral_explicit() {
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config())
            .await
            .expect("configure");

        let health = connector.handle_health().await.expect("health");
        assert_eq!(health["api_read_operations"], true);
        assert_eq!(health["live_session_operations"], true);
        assert_eq!(health["live_session_contract"], "browser_handoff_only");

        let doctor = connector.handle_doctor().await.expect("doctor");
        let checks = doctor["checks"].as_array().expect("doctor checks");
        let live_boundary = checks
            .iter()
            .find(|check| check["name"] == "live_session_boundary")
            .expect("live-session boundary check");
        assert_eq!(live_boundary["status"], "healthy");
        assert!(
            live_boundary["message"]
                .as_str()
                .expect("live boundary message")
                .contains("browser-handoff contract")
        );
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
    async fn read_and_artifact_operations_reject_missing_meet_rest_scope_before_network_io() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([(
                "required_scopes",
                json!([DRIVE_MEET_READONLY_SCOPE]),
            )]))
            .await
            .expect("configure");
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": [MEET_CONFERENCE_READ_CAP, MEET_ARTIFACT_READ_CAP],
            }))
            .await
            .expect("handshake");

        let read_err = connector
            .handle_invoke(json!({
                "operation": CONFERENCE_RECORDS_LIST_OP,
                "input": {},
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    CONFERENCE_RECORDS_LIST_OP,
                    MEET_CONFERENCE_READ_CAP
                ),
            }))
            .await
            .expect_err("conference reads require a Meet REST read scope");
        assert!(
            matches!(
                read_err,
                FcpError::InvalidRequest { ref message, .. }
                    if message.contains(MEETINGS_SPACE_READONLY_SCOPE)
                        && message.contains(MEETINGS_SPACE_CREATED_SCOPE)
            ),
            "unexpected read scope error: {read_err:?}"
        );

        let artifact_err = connector
            .handle_invoke(json!({
                "operation": RECORDINGS_LIST_OP,
                "input": { "conference_record": "conferenceRecords/rec-1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    RECORDINGS_LIST_OP,
                    MEET_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect_err("artifact reads require a Meet REST read scope");
        assert!(
            matches!(
                artifact_err,
                FcpError::InvalidRequest { ref message, .. }
                    if message.contains(MEETINGS_SPACE_READONLY_SCOPE)
                        && message.contains(MEETINGS_SPACE_CREATED_SCOPE)
            ),
            "unexpected artifact scope error: {artifact_err:?}"
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
                LIVE_JOIN_OP,
                LIVE_STATUS_OP,
                LIVE_TRANSCRIPT_OP,
                LIVE_LEAVE_OP,
            ]
        );
        assert!(
            !ids.iter().any(|id| id.contains("say")),
            "voice/speak operations are intentionally deferred to a separate child"
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
            if [
                LIVE_JOIN_OP,
                LIVE_STATUS_OP,
                LIVE_TRANSCRIPT_OP,
                LIVE_LEAVE_OP,
            ]
            .contains(&op["id"].as_str().expect("op id"))
            {
                continue;
            }
            assert_eq!(op["capability"], MEET_CONFERENCE_READ_CAP);
            assert_eq!(op["safety_tier"], "safe");
            assert_eq!(op["idempotency"], "strict");
        }
        let live_join = ops
            .iter()
            .find(|op| op["id"] == LIVE_JOIN_OP)
            .expect("live join op");
        assert_eq!(live_join["capability"], MEET_LIVE_JOIN_CAP);
        assert_eq!(live_join["safety_tier"], "dangerous");
        assert_eq!(live_join["requires_approval"], "interactive");
        let live_status = ops
            .iter()
            .find(|op| op["id"] == LIVE_STATUS_OP)
            .expect("live status op");
        assert_eq!(live_status["capability"], MEET_LIVE_READ_CAP);
        assert_eq!(live_status["requires_approval"], "policy");
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
    async fn live_session_contract_joins_replaces_reads_and_leaves() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
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
                "capabilities_requested": [
                    MEET_LIVE_JOIN_CAP,
                    MEET_LIVE_READ_CAP,
                    MEET_LIVE_LEAVE_CAP
                ],
            }))
            .await
            .expect("handshake");

        let first = connector
            .handle_invoke(json!({
                "operation": LIVE_JOIN_OP,
                "input": {
                    "meeting_url": "https://meet.google.com/abc-defg-hij",
                    "mode": "transcribe",
                    "max_duration_minutes": 15
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    LIVE_JOIN_OP,
                    MEET_LIVE_JOIN_CAP
                ),
            }))
            .await
            .expect("join live session");
        assert_eq!(first["accepted"], true);
        assert_eq!(first["session"]["meeting_code"], "abc-defg-hij");
        assert_eq!(first["session"]["mode"], "transcribe");
        assert_eq!(first["browser_handoff"]["target_connector"], "fcp.browser");
        assert_eq!(
            first["browser_handoff"]["local_control_policy"]["bind"],
            "loopback_only"
        );
        assert_eq!(
            first["browser_handoff"]["worker_plan"][0]["input"]["url"],
            "https://meet.google.com/abc-defg-hij"
        );
        assert_eq!(
            first["browser_handoff"]["audit"]["no_embedded_browser_runtime"],
            true
        );
        let first_session_id = first["session"]["session_id"]
            .as_str()
            .expect("first session id")
            .to_string();

        let status = connector
            .handle_invoke(json!({
                "operation": LIVE_STATUS_OP,
                "input": {},
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    LIVE_STATUS_OP,
                    MEET_LIVE_READ_CAP
                ),
            }))
            .await
            .expect("live status");
        assert_eq!(status["active"], true);
        assert_eq!(status["session"]["session_id"], first_session_id);

        let transcript = connector
            .handle_invoke(json!({
                "operation": LIVE_TRANSCRIPT_OP,
                "input": { "session_id": first_session_id },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    LIVE_TRANSCRIPT_OP,
                    MEET_LIVE_READ_CAP
                ),
            }))
            .await
            .expect("live transcript");
        assert_eq!(transcript["active"], true);
        assert_eq!(transcript["entry_count"], 0);
        assert_eq!(transcript["entries"], json!([]));

        let second = connector
            .handle_invoke(json!({
                "operation": LIVE_JOIN_OP,
                "input": {
                    "meeting_url": "https://meet.google.com/xyz-abcd-efg",
                    "mode": "realtime"
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    LIVE_JOIN_OP,
                    MEET_LIVE_JOIN_CAP
                ),
            }))
            .await
            .expect("replacement join");
        assert_eq!(
            second["replaced_session"]["stop_reason"]["code"],
            "replaced_by_new_join"
        );
        let second_session_id = second["session"]["session_id"]
            .as_str()
            .expect("second session id")
            .to_string();
        assert_ne!(first_session_id, second_session_id);

        let stale_leave = connector
            .handle_invoke(json!({
                "operation": LIVE_LEAVE_OP,
                "input": { "session_id": first_session_id },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    LIVE_LEAVE_OP,
                    MEET_LIVE_LEAVE_CAP
                ),
            }))
            .await
            .expect_err("stale leave should not stop replacement session");
        assert!(
            matches!(stale_leave, FcpError::InvalidRequest { message, .. } if message.contains("does not match active"))
        );

        let left = connector
            .handle_invoke(json!({
                "operation": LIVE_LEAVE_OP,
                "input": { "session_id": second_session_id },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    LIVE_LEAVE_OP,
                    MEET_LIVE_LEAVE_CAP
                ),
            }))
            .await
            .expect("leave active session");
        assert_eq!(left["active"], false);
        assert_eq!(
            left["stopped_session"]["stop_reason"]["code"],
            "leave_requested"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn live_session_operations_use_distinct_capability_gates() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;

        let denied = connector
            .handle_simulate(simulate_request_json(
                &connector,
                &signing_key,
                LIVE_JOIN_OP,
                MEET_SPACE_READ_CAP,
            ))
            .await
            .expect("simulate denied");
        assert_eq!(denied["would_succeed"], false);
        assert!(
            denied["missing_capabilities"]
                .as_array()
                .expect("missing capabilities")
                .iter()
                .any(|capability| capability == MEET_LIVE_JOIN_CAP)
        );

        let allowed = connector
            .handle_simulate(simulate_request_json(
                &connector,
                &signing_key,
                LIVE_JOIN_OP,
                MEET_LIVE_JOIN_CAP,
            ))
            .await
            .expect("simulate allowed");
        assert_eq!(allowed["would_succeed"], true);
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
        let expected_auth = direct_test_bearer_header();
        assert!(
            recorded
                .iter()
                .all(|request| request.authorization.as_deref() == Some(expected_auth.as_str())),
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
    async fn simulate_denies_deferred_live_speak_operation() {
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        configure_and_handshake(&mut connector, &signing_key).await;

        let result = connector
            .handle_simulate(simulate_request_json(
                &connector,
                &signing_key,
                "gmeet.live.say",
                "meeting.live_speak",
            ))
            .await
            .expect("simulate response");

        assert_eq!(result["would_succeed"], false);
        assert!(
            result["failure_reason"]
                .as_str()
                .expect("failure reason")
                .contains("gmeet.live.say")
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
            normalize_transcript_name("conferenceRecords/rec-1/transcripts/t1")
                .expect("transcript resource"),
            "conferenceRecords/rec-1/transcripts/t1"
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
        for raw in [
            "conferenceRecords/rec-1",
            "conferenceRecords/rec-1/participants/p1",
            "conferenceRecords/rec-1/transcripts/",
            "conferenceRecords/rec-1/transcripts/t1/entries/e1",
        ] {
            assert!(
                normalize_transcript_name(raw).is_err(),
                "{raw:?} should reject as a transcript resource"
            );
        }
    }

    #[test]
    fn docs_destination_document_id_extraction_is_strict_and_drive_export_safe() {
        for raw in [
            "Doc_123-456",
            "documents/Doc_123-456",
            "https://docs.google.com/document/d/Doc_123-456/edit?tab=t.0",
        ] {
            let destination = GoogleMeetDocsDestination {
                document: Some(raw.to_string()),
                document_id: None,
                file: None,
                extra: BTreeMap::new(),
            };
            assert_eq!(
                extract_docs_destination_document_id(&destination).expect("document id"),
                Some("Doc_123-456".to_string()),
                "{raw} should extract"
            );
        }

        for raw in [
            "",
            "ab",
            "Doc 123",
            "https://drive.google.com/file/d/Doc_123-456/view",
            "https://user@docs.google.com/document/d/Doc_123-456/edit",
            "https://docs.google.com/spreadsheets/d/Doc_123-456/edit",
        ] {
            let destination = GoogleMeetDocsDestination {
                document: Some(raw.to_string()),
                document_id: None,
                file: None,
                extra: BTreeMap::new(),
            };
            assert!(
                extract_docs_destination_document_id(&destination).is_err(),
                "{raw:?} should reject"
            );
        }
    }

    #[test]
    fn artifact_async_errors_and_secret_redaction_stay_operator_safe() {
        assert!(matches!(
            map_artifact_async_error(
                AsyncError::Timeout { timeout_ms: 25 },
                TRANSCRIPTS_WITH_TEXT_LIST_OP
            ),
            FcpError::External {
                retryable: true,
                message,
                ..
            } if message.contains("timed out")
        ));
        assert_eq!(
            public_async_error(&AsyncError::Cancelled, SMART_NOTES_WITH_TEXT_LIST_OP),
            "gmeet.smart_notes.with_text.list was cancelled before completion"
        );
        assert_eq!(
            public_google_error(&GoogleMeetError::InvalidConfig {
                message: format!(
                    "Authorization: {} {}",
                    ["Bear", "er"].concat(),
                    ["private", "value"].join("-")
                )
            }),
            "Google API request failed; credentials redacted"
        );
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
        let expected_auth = direct_test_bearer_header();
        assert!(
            recorded
                .iter()
                .all(|request| request.authorization.as_deref() == Some(expected_auth.as_str())),
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
    async fn artifact_operations_cover_loopback_drive_export_and_partial_errors() {
        let (base_url, requests, server) = spawn_loopback(vec![
            json_response(json!({
                "recordings": [{
                    "name": "conferenceRecords/rec-1/recordings/r1",
                    "startTime": "2026-05-04T10:00:00Z",
                    "endTime": "2026-05-04T10:30:00Z",
                    "driveDestination": {
                        "file": "driveFiles/file-1"
                    }
                }]
            })),
            json_response(json!({
                "transcripts": [{
                    "name": "conferenceRecords/rec-1/transcripts/t1",
                    "startTime": "2026-05-04T10:00:00Z",
                    "docsDestination": {
                        "document": "https://docs.google.com/document/d/Doc_Transcript-1/edit"
                    }
                }]
            })),
            json_response(json!({
                "transcriptEntries": [
                    {
                        "name": "conferenceRecords/rec-1/transcripts/t1/entries/e2",
                        "participant": "conferenceRecords/rec-1/participants/p1",
                        "text": "second",
                        "languageCode": "en-US",
                        "startTime": "2026-05-04T10:02:00Z"
                    },
                    {
                        "name": "conferenceRecords/rec-1/transcripts/t1/entries/e1",
                        "participant": "conferenceRecords/rec-1/participants/p1",
                        "text": "first",
                        "languageCode": "en-US",
                        "startTime": "2026-05-04T10:01:00Z"
                    }
                ]
            })),
            json_response(json!({
                "smartNotes": [{
                    "name": "conferenceRecords/rec-1/smartNotes/sn1",
                    "docsDestination": {
                        "documentId": "DocSmart_1"
                    }
                }]
            })),
            json_response(json!({
                "transcripts": [
                    {
                        "name": "conferenceRecords/rec-1/transcripts/t1",
                        "docsDestination": {
                            "document": "https://docs.google.com/document/d/Doc_Transcript-1/edit"
                        }
                    },
                    {
                        "name": "conferenceRecords/rec-1/transcripts/t2"
                    }
                ]
            })),
            text_response("Transcript body"),
            json_response(json!({
                "smartNotes": [
                    {
                        "name": "conferenceRecords/rec-1/smartNotes/sn1",
                        "docsDestination": {
                            "documentId": "DocSmart_1"
                        }
                    },
                    {
                        "name": "conferenceRecords/rec-1/smartNotes/sn2"
                    }
                ]
            })),
            error_response(
                404,
                json!({ "error": { "message": "Drive document missing" } }),
                Vec::new(),
            ),
            text_response("Direct export"),
            text_response("too large"),
        ]);
        let drive_base_url = base_url.replace("/v2", "/drive/v3");
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([
                ("base_url", json!(base_url)),
                ("drive_base_url", json!(drive_base_url)),
                (
                    "required_scopes",
                    json!([MEETINGS_SPACE_READONLY_SCOPE, DRIVE_MEET_READONLY_SCOPE]),
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
                    MEET_ARTIFACT_READ_CAP,
                    MEET_DRIVE_ARTIFACT_READ_CAP
                ],
            }))
            .await
            .expect("handshake");

        let recordings = connector
            .handle_invoke(json!({
                "operation": RECORDINGS_LIST_OP,
                "input": {
                    "conference_record": "conferenceRecords/rec-1",
                    "page_size": 2
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    RECORDINGS_LIST_OP,
                    MEET_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect("recordings");
        assert_eq!(
            recordings["recordings"][0]["name"],
            "conferenceRecords/rec-1/recordings/r1"
        );

        let transcripts = connector
            .handle_invoke(json!({
                "operation": TRANSCRIPTS_LIST_OP,
                "input": { "conference_record": "conferenceRecords/rec-1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    TRANSCRIPTS_LIST_OP,
                    MEET_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect("transcripts");
        assert_eq!(
            transcripts["transcripts"][0]["docsDestination"]["document"],
            "https://docs.google.com/document/d/Doc_Transcript-1/edit"
        );

        let entries = connector
            .handle_invoke(json!({
                "operation": TRANSCRIPT_ENTRIES_LIST_OP,
                "input": { "transcript": "conferenceRecords/rec-1/transcripts/t1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    TRANSCRIPT_ENTRIES_LIST_OP,
                    MEET_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect("entries");
        assert_eq!(entries["transcript_entries"][0]["text"], "first");
        assert_eq!(entries["transcript_entries"][1]["text"], "second");

        let smart_notes = connector
            .handle_invoke(json!({
                "operation": SMART_NOTES_LIST_OP,
                "input": { "conference_record": "conferenceRecords/rec-1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    SMART_NOTES_LIST_OP,
                    MEET_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect("smart notes");
        assert_eq!(
            smart_notes["smart_notes"][0]["docsDestination"]["documentId"],
            "DocSmart_1"
        );

        let transcripts_with_text = connector
            .handle_invoke(json!({
                "operation": TRANSCRIPTS_WITH_TEXT_LIST_OP,
                "input": {
                    "conference_record": "conferenceRecords/rec-1",
                    "max_document_bytes": 1024
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    TRANSCRIPTS_WITH_TEXT_LIST_OP,
                    MEET_DRIVE_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect("transcripts with text");
        assert_eq!(
            transcripts_with_text["transcripts"][0]["documentText"],
            "Transcript body"
        );
        assert_eq!(
            transcripts_with_text["transcripts"][0]["documentId"],
            "Doc_Transcript-1"
        );
        assert!(
            transcripts_with_text["transcripts"][1]["documentTextError"]
                .as_str()
                .expect("partial text error")
                .contains("docsDestination")
        );

        let smart_notes_with_text = connector
            .handle_invoke(json!({
                "operation": SMART_NOTES_WITH_TEXT_LIST_OP,
                "input": { "conference_record": "conferenceRecords/rec-1" },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    SMART_NOTES_WITH_TEXT_LIST_OP,
                    MEET_DRIVE_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect("smart notes with text");
        assert!(
            smart_notes_with_text["smart_notes"][0]["documentTextError"]
                .as_str()
                .expect("drive export error")
                .contains("Drive document missing")
        );
        assert!(
            smart_notes_with_text["smart_notes"][1]["documentTextError"]
                .as_str()
                .expect("missing docs destination")
                .contains("docsDestination")
        );

        let direct_export = connector
            .handle_invoke(json!({
                "operation": DRIVE_DOCUMENT_TEXT_EXPORT_OP,
                "input": {
                    "docs_destination": {
                        "document": "documents/Doc_Direct"
                    },
                    "max_document_bytes": 1024
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    DRIVE_DOCUMENT_TEXT_EXPORT_OP,
                    MEET_DRIVE_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect("direct export");
        assert_eq!(direct_export["text"], "Direct export");

        let too_large = connector
            .handle_invoke(json!({
                "operation": DRIVE_DOCUMENT_TEXT_EXPORT_OP,
                "input": {
                    "document_id": "DocTooLarge",
                    "max_document_bytes": 3
                },
                "capability_token": capability_for_cap(
                    &connector,
                    &signing_key,
                    DRIVE_DOCUMENT_TEXT_EXPORT_OP,
                    MEET_DRIVE_ARTIFACT_READ_CAP
                ),
            }))
            .await
            .expect_err("oversized text must fail");
        finish_loopback(server);
        assert!(
            matches!(too_large, FcpError::External { message, .. } if message.contains("exceeded max bytes"))
        );

        let recorded = requests.lock().expect("requests").clone();
        assert_eq!(recorded.len(), 10, "artifact transcript: {recorded:#?}");
        assert_eq!(
            recorded[0].target,
            "/v2/conferenceRecords/rec%2D1/recordings?pageSize=2"
        );
        assert_eq!(
            recorded[1].target,
            "/v2/conferenceRecords/rec%2D1/transcripts?pageSize=100"
        );
        assert_eq!(
            recorded[2].target,
            "/v2/conferenceRecords/rec%2D1/transcripts/t1/entries?pageSize=100"
        );
        assert_eq!(
            recorded[3].target,
            "/v2/conferenceRecords/rec%2D1/smartNotes?pageSize=100"
        );
        assert!(
            recorded[5]
                .target
                .contains("/drive/v3/files/Doc%5FTranscript%2D1/export")
        );
        assert!(recorded[5].target.contains("mimeType=text%2Fplain"));
        assert!(
            recorded[7]
                .target
                .contains("/drive/v3/files/DocSmart%5F1/export")
        );
        assert!(
            recorded[8]
                .target
                .contains("/drive/v3/files/Doc%5FDirect/export")
        );
        assert!(
            recorded[9]
                .target
                .contains("/drive/v3/files/DocTooLarge/export")
        );
        let expected_auth = direct_test_bearer_header();
        assert!(
            recorded
                .iter()
                .all(|request| request.authorization.as_deref() == Some(expected_auth.as_str())),
            "every Meet and Drive artifact request must carry auth"
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
    fn google_meet_artifact_loopback_log_schema_is_machine_readable_and_redacted() {
        let connector = GoogleMeetConnector::new();
        let signing_key = Ed25519SigningKey::generate();
        let auth_scheme = ["Bear", "er"].concat();
        let token_sample = ["sample", "value"].join("-");
        let request = RecordedRequest {
            method: "GET".to_string(),
            target: format!(
                "/v2/conferenceRecords?{}=page-2",
                ["page", "Token"].concat()
            ),
            authorization: Some([auth_scheme.as_str(), token_sample.as_str()].join(" ")),
            body: String::new(),
            response_status: 429,
            response_body_bytes: 42,
            response_retry_after_ms: Some(3_000),
        };
        let spec = HarnessInvoke {
            connector: &connector,
            signing_key: &signing_key,
            operation: CONFERENCE_RECORDS_LIST_OP,
            capability_id: MEET_CONFERENCE_READ_CAP,
            input: json!({}),
            normalized_resource: "conferenceRecords",
            expected_outcome: "rate_limited",
        };

        let entry =
            harness_log_for_request(&request, &spec, "corr-schema", 7, Some("FCP-429".into()));
        assert_log_schema(&entry);
        assert_eq!(entry.pagination_token.as_deref(), Some("page-2"));
        assert_eq!(entry.retry_backoff_ms, Some(3_000));
        assert_eq!(entry.redaction_decision, "authorization_header_redacted");
        let wire = serde_json::to_string(&entry).expect("serialize log entry");
        assert!(!wire.contains(&token_sample));
        assert!(!wire.contains(&auth_scheme));
    }

    #[test]
    fn google_meet_artifact_loopback_skip_schema_is_machine_readable() {
        let skip = harness_skip(
            "corr-skip",
            "gmeet.timeout_cancellation",
            "short_timeout_injection_hook",
            "The connector request timeout is real but deliberately longer than this unit harness.",
        );

        assert_skip_schema(&skip);
        let wire = serde_json::to_string(&skip).expect("serialize skip artifact");
        assert!(wire.contains("short_timeout_injection_hook"));
        assert!(wire.contains("flywheel_connectors-4kw5f.5.1.1.1.5"));
    }

    #[fcp_async_core::runtime::test]
    async fn google_meet_artifact_loopback_harness_exercises_connector_boundary_and_emits_jsonl() {
        let (base_url, requests, server) = spawn_loopback(vec![
            json_response(json!({
                "name": "spaces/abc-defg-hij",
                "meetingUri": "https://meet.google.com/abc-defg-hij"
            })),
            json_response(json!({
                "name": "spaces/new-space",
                "meetingUri": "https://meet.google.com/new-space",
                "config": {
                    "accessType": "TRUSTED",
                    "entryPointAccess": "CREATOR_APP_ONLY"
                }
            })),
            json_response(json!({
                "name": "spaces/end-space",
                "meetingUri": "https://meet.google.com/end-space"
            })),
            json_response(json!({ "ended": true })),
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
                        "anonymousUser": {
                            "displayName": "Guest Example"
                        }
                    }
                ]
            })),
            json_response(json!({
                "participantSessions": [{
                    "name": "conferenceRecords/rec-1/participants/p1/participantSessions/s1",
                    "startTime": "2026-05-04T10:00:00Z",
                    "endTime": "2026-05-04T10:20:00Z"
                }]
            })),
            json_response(json!({
                "name": "conferenceRecords/rec-1",
                "space": "spaces/abc-defg-hij",
                "startTime": "2026-05-04T10:00:00Z",
                "endTime": "2026-05-04T11:00:00Z"
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
                        "anonymousUser": {
                            "displayName": "Guest Example"
                        }
                    }
                ]
            })),
            json_response(json!({
                "participantSessions": [{
                    "name": "conferenceRecords/rec-1/participants/p1/participantSessions/s1",
                    "startTime": "2026-05-04T10:00:00Z",
                    "endTime": "2026-05-04T10:30:00Z"
                }]
            })),
            json_response(json!({
                "participantSessions": [{
                    "name": "conferenceRecords/rec-1/participants/p2/participantSessions/s1",
                    "startTime": "2026-05-04T10:05:00Z",
                    "endTime": "2026-05-04T10:35:00Z"
                }]
            })),
            json_response(json!({
                "recordings": [{
                    "name": "conferenceRecords/rec-1/recordings/r1",
                    "driveDestination": {
                        "file": "driveFiles/recording-file"
                    }
                }]
            })),
            json_response(json!({
                "transcripts": [{
                    "name": "conferenceRecords/rec-1/transcripts/t1",
                    "docsDestination": {
                        "document": "https://docs.google.com/document/d/DocTranscript/edit"
                    }
                }]
            })),
            json_response(json!({
                "transcriptEntries": [
                    {
                        "name": "conferenceRecords/rec-1/transcripts/t1/entries/e2",
                        "participant": "conferenceRecords/rec-1/participants/p1",
                        "text": "second",
                        "startTime": "2026-05-04T10:02:00Z"
                    },
                    {
                        "name": "conferenceRecords/rec-1/transcripts/t1/entries/e1",
                        "participant": "conferenceRecords/rec-1/participants/p1",
                        "text": "first",
                        "startTime": "2026-05-04T10:01:00Z"
                    }
                ]
            })),
            json_response(json!({
                "smartNotes": [{
                    "name": "conferenceRecords/rec-1/smartNotes/sn1",
                    "docsDestination": {
                        "documentId": "DocSmart"
                    }
                }]
            })),
            json_response(json!({
                "transcripts": [{
                    "name": "conferenceRecords/rec-1/transcripts/t1",
                    "docsDestination": {
                        "document": "https://docs.google.com/document/d/DocTranscript/edit"
                    }
                }]
            })),
            text_response("Transcript export text"),
            json_response(json!({
                "smartNotes": [{
                    "name": "conferenceRecords/rec-1/smartNotes/sn1",
                    "docsDestination": {
                        "documentId": "DocSmart"
                    }
                }]
            })),
            text_response("Smart note export text"),
            text_response("Direct Drive export text"),
            error_response(
                401,
                json!({ "error": { "message": "invalid auth" } }),
                Vec::new(),
            ),
            error_response(
                403,
                json!({ "error": { "message": "developer preview enrollment required" } }),
                Vec::new(),
            ),
            error_response(
                429,
                json!({ "error": { "message": "quota exceeded" } }),
                vec![("retry-after", "3".to_string())],
            ),
            StubResponse {
                status: 200,
                headers: vec![("content-type", "application/json".to_string())],
                body: "{not-json".to_string(),
            },
        ]);
        let drive_base_url = base_url.replace("/v2", "/drive/v3");
        let signing_key = Ed25519SigningKey::generate();
        let mut connector = GoogleMeetConnector::new();
        connector
            .handle_configure(direct_test_auth_config_with([
                ("base_url", json!(base_url)),
                ("drive_base_url", json!(drive_base_url)),
                (
                    "required_scopes",
                    json!([
                        MEETINGS_SPACE_READONLY_SCOPE,
                        MEETINGS_SPACE_CREATED_SCOPE,
                        MEETINGS_SPACE_SETTINGS_SCOPE,
                        DRIVE_MEET_READONLY_SCOPE
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
                    MEET_CONFERENCE_READ_CAP,
                    MEET_ARTIFACT_READ_CAP,
                    MEET_DRIVE_ARTIFACT_READ_CAP
                ],
            }))
            .await
            .expect("handshake");

        let correlation_id = "gmeet-artifact-loopback-e2e";
        let mut logs = Vec::new();

        let space = invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: SPACE_GET_OP,
                capability_id: MEET_SPACE_READ_CAP,
                input: json!({ "space": "https://meet.google.com/abc-defg-hij" }),
                normalized_resource: "spaces/abc-defg-hij",
                expected_outcome: "pass",
            },
        )
        .await
        .expect("space result");
        assert_eq!(space["space"]["name"], "spaces/abc-defg-hij");

        let created = invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: SPACE_CREATE_OP,
                capability_id: MEET_SPACE_CREATE_CAP,
                input: json!({
                    "config": {
                        "access_type": "TRUSTED",
                        "entry_point_access": "CREATOR_APP_ONLY"
                    }
                }),
                normalized_resource: "spaces",
                expected_outcome: "pass",
            },
        )
        .await
        .expect("created space result");
        assert_eq!(created["space"]["name"], "spaces/new-space");

        invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: SPACE_END_ACTIVE_CONFERENCE_OP,
                capability_id: MEET_SPACE_END_CAP,
                input: json!({ "space": "spaces/end-space" }),
                normalized_resource: "spaces/end-space",
                expected_outcome: "pass",
            },
        )
        .await;

        let records = invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: CONFERENCE_RECORDS_LIST_OP,
                capability_id: MEET_CONFERENCE_READ_CAP,
                input: json!({
                    "meeting": "spaces/abc-defg-hij",
                    "page_size": 1,
                    "max_items": 2
                }),
                normalized_resource: "spaces/abc-defg-hij",
                expected_outcome: "pass",
            },
        )
        .await
        .expect("records result");
        assert_eq!(records["count"], 2);

        invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: CONFERENCE_RECORD_LATEST_OP,
                capability_id: MEET_CONFERENCE_READ_CAP,
                input: json!({ "meeting": "spaces/abc-defg-hij" }),
                normalized_resource: "spaces/abc-defg-hij",
                expected_outcome: "pass",
            },
        )
        .await;

        invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: CONFERENCE_RECORD_GET_OP,
                capability_id: MEET_CONFERENCE_READ_CAP,
                input: json!({ "conference_record": "conferenceRecords/rec-1" }),
                normalized_resource: "conferenceRecords/rec-1",
                expected_outcome: "pass",
            },
        )
        .await;

        invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: PARTICIPANTS_LIST_OP,
                capability_id: MEET_CONFERENCE_READ_CAP,
                input: json!({ "conference_record": "conferenceRecords/rec-1" }),
                normalized_resource: "conferenceRecords/rec-1/participants",
                expected_outcome: "pass",
            },
        )
        .await;

        invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: PARTICIPANT_SESSIONS_LIST_OP,
                capability_id: MEET_CONFERENCE_READ_CAP,
                input: json!({ "participant": "conferenceRecords/rec-1/participants/p1" }),
                normalized_resource: "conferenceRecords/rec-1/participants/p1/participantSessions",
                expected_outcome: "pass",
            },
        )
        .await;

        let attendance = invoke_harness_operation(
            &requests,
            &mut logs,
            correlation_id,
            HarnessInvoke {
                connector: &connector,
                signing_key: &signing_key,
                operation: ATTENDANCE_LIST_OP,
                capability_id: MEET_CONFERENCE_READ_CAP,
                input: json!({
                    "conference_record": "conferenceRecords/rec-1",
                    "max_items": 10
                }),
                normalized_resource: "conferenceRecords/rec-1/attendance",
                expected_outcome: "pass",
            },
        )
        .await
        .expect("attendance result");
        assert_eq!(
            attendance["attendance"]
                .as_array()
                .expect("attendance rows")
                .len(),
            2
        );

        for (operation, input, normalized_resource) in [
            (
                RECORDINGS_LIST_OP,
                json!({ "conference_record": "conferenceRecords/rec-1" }),
                "conferenceRecords/rec-1/recordings",
            ),
            (
                TRANSCRIPTS_LIST_OP,
                json!({ "conference_record": "conferenceRecords/rec-1" }),
                "conferenceRecords/rec-1/transcripts",
            ),
            (
                TRANSCRIPT_ENTRIES_LIST_OP,
                json!({ "transcript": "conferenceRecords/rec-1/transcripts/t1" }),
                "conferenceRecords/rec-1/transcripts/t1/entries",
            ),
            (
                SMART_NOTES_LIST_OP,
                json!({ "conference_record": "conferenceRecords/rec-1" }),
                "conferenceRecords/rec-1/smartNotes",
            ),
        ] {
            invoke_harness_operation(
                &requests,
                &mut logs,
                correlation_id,
                HarnessInvoke {
                    connector: &connector,
                    signing_key: &signing_key,
                    operation,
                    capability_id: MEET_ARTIFACT_READ_CAP,
                    input,
                    normalized_resource,
                    expected_outcome: "pass",
                },
            )
            .await;
        }

        for (operation, input, normalized_resource) in [
            (
                TRANSCRIPTS_WITH_TEXT_LIST_OP,
                json!({
                    "conference_record": "conferenceRecords/rec-1",
                    "max_document_bytes": 1024
                }),
                "conferenceRecords/rec-1/transcripts:with_text",
            ),
            (
                SMART_NOTES_WITH_TEXT_LIST_OP,
                json!({
                    "conference_record": "conferenceRecords/rec-1",
                    "max_document_bytes": 1024
                }),
                "conferenceRecords/rec-1/smartNotes:with_text",
            ),
            (
                DRIVE_DOCUMENT_TEXT_EXPORT_OP,
                json!({
                    "document_id": "DocDirect",
                    "max_document_bytes": 1024
                }),
                "drive/files/DocDirect/export",
            ),
        ] {
            invoke_harness_operation(
                &requests,
                &mut logs,
                correlation_id,
                HarnessInvoke {
                    connector: &connector,
                    signing_key: &signing_key,
                    operation,
                    capability_id: MEET_DRIVE_ARTIFACT_READ_CAP,
                    input,
                    normalized_resource,
                    expected_outcome: "pass",
                },
            )
            .await;
        }

        for (operation, capability_id, input, normalized_resource, expected_outcome) in [
            (
                CONFERENCE_RECORD_GET_OP,
                MEET_CONFERENCE_READ_CAP,
                json!({ "conference_record": "conferenceRecords/auth-fail" }),
                "conferenceRecords/auth-fail",
                "auth_failure",
            ),
            (
                RECORDINGS_LIST_OP,
                MEET_ARTIFACT_READ_CAP,
                json!({ "conference_record": "conferenceRecords/restricted" }),
                "conferenceRecords/restricted/recordings",
                "restricted_denial",
            ),
            (
                CONFERENCE_RECORDS_LIST_OP,
                MEET_CONFERENCE_READ_CAP,
                json!({ "meeting": "spaces/rate-limit" }),
                "spaces/rate-limit",
                "rate_limited",
            ),
            (
                CONFERENCE_RECORD_GET_OP,
                MEET_CONFERENCE_READ_CAP,
                json!({ "conference_record": "conferenceRecords/malformed" }),
                "conferenceRecords/malformed",
                "malformed_json",
            ),
        ] {
            invoke_harness_operation(
                &requests,
                &mut logs,
                correlation_id,
                HarnessInvoke {
                    connector: &connector,
                    signing_key: &signing_key,
                    operation,
                    capability_id,
                    input,
                    normalized_resource,
                    expected_outcome,
                },
            )
            .await;
        }

        finish_loopback(server);

        let shutdown_started = Instant::now();
        let shutdown = connector
            .handle_shutdown(json!({ "reason": "loopback_e2e_complete" }))
            .await
            .expect("shutdown");
        logs.push(GoogleMeetArtifactHarnessLog {
            schema_version: "google_meet_artifact_loopback.v1".to_string(),
            bead_id: "flywheel_connectors-4kw5f.5.1.1.1.5".to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            operation: "gmeet.connector.shutdown".to_string(),
            method: "CONNECTOR".to_string(),
            path: "shutdown".to_string(),
            normalized_resource: CONNECTOR_ID.to_string(),
            scope_family: "lifecycle".to_string(),
            pagination_token: None,
            retry_backoff_ms: None,
            latency_ms: elapsed_millis(shutdown_started),
            response_byte_count: serde_json::to_vec(&shutdown)
                .expect("shutdown response bytes")
                .len(),
            cancellation_checkpoint: "clean_shutdown_completed".to_string(),
            redaction_decision: "no_authorization_header".to_string(),
            outcome: "pass".to_string(),
            http_status: 200,
            error_code: None,
        });

        let timeout_skip = harness_skip(
            correlation_id,
            "gmeet.timeout_cancellation",
            "short_timeout_injection_hook",
            "The connector has real timeout/cancellation paths, but this no-mock harness does not sleep through the 30s request budget.",
        );
        assert_skip_schema(&timeout_skip);

        let expected_operations = [
            SPACE_GET_OP,
            SPACE_CREATE_OP,
            SPACE_END_ACTIVE_CONFERENCE_OP,
            CONFERENCE_RECORDS_LIST_OP,
            CONFERENCE_RECORD_LATEST_OP,
            CONFERENCE_RECORD_GET_OP,
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
            "gmeet.connector.shutdown",
        ];
        for operation in expected_operations {
            assert!(
                logs.iter().any(|entry| entry.operation == operation),
                "harness log missing operation {operation}"
            );
        }
        assert!(
            logs.iter()
                .any(|entry| entry.pagination_token.as_deref() == Some("page-2")),
            "pagination token should be logged"
        );
        assert!(
            logs.iter()
                .any(|entry| entry.retry_backoff_ms == Some(3_000)
                    && entry.outcome == "rate_limited"),
            "retry-after backoff should be logged for 429"
        );
        assert!(
            logs.iter().any(|entry| entry.outcome == "auth_failure"),
            "auth failure should be logged"
        );
        assert!(
            logs.iter()
                .any(|entry| entry.outcome == "restricted_denial"),
            "restricted/developer-preview denial should be logged"
        );
        assert!(
            logs.iter().any(|entry| entry.outcome == "malformed_json"),
            "malformed JSON outcome should be logged"
        );

        for entry in &logs {
            assert_log_schema(entry);
            println!(
                "{}",
                serde_json::to_string(entry).expect("serialize JSONL log entry")
            );
        }
        println!(
            "{}",
            serde_json::to_string(&timeout_skip).expect("serialize skip JSONL")
        );

        let wire_logs = serde_json::to_string(&logs).expect("serialize log bundle");
        let redacted_token_sample = ["sample", "value"].join("-");
        let redacted_auth_scheme = ["Bear", "er"].concat();
        assert!(!wire_logs.contains(&redacted_token_sample));
        assert!(!wire_logs.contains(&redacted_auth_scheme));
        assert_eq!(
            requests.lock().expect("requests").len(),
            27,
            "every stubbed loopback response should be consumed"
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
            "meeting.live_join",
            "meeting.live_read",
            "meeting.live_leave",
        ] {
            assert!(
                optional
                    .iter()
                    .any(|capability| capability.as_str() == expected),
                "missing capability {expected}"
            );
        }
        let forbidden = &manifest.capabilities.forbidden;
        for forbidden_capability in [
            "system.exec",
            "network.listen",
            "browser.control",
            "meeting.live_speak",
        ] {
            assert!(
                forbidden
                    .iter()
                    .any(|capability| capability.as_str() == forbidden_capability),
                "manifest should forbid {forbidden_capability}"
            );
        }
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
                        | RECORDINGS_LIST_OP
                        | TRANSCRIPTS_LIST_OP
                        | TRANSCRIPT_ENTRIES_LIST_OP
                        | SMART_NOTES_LIST_OP
                        | TRANSCRIPTS_WITH_TEXT_LIST_OP
                        | SMART_NOTES_WITH_TEXT_LIST_OP
                        | DRIVE_DOCUMENT_TEXT_EXPORT_OP
                        | LIVE_JOIN_OP
                        | LIVE_STATUS_OP
                        | LIVE_TRANSCRIPT_OP
                        | LIVE_LEAVE_OP
                )
            }),
            "manifest should advertise only the space, conference-read, artifact, Drive artifact, and live handoff operations"
        );
        assert_eq!(manifest.provides.operations.len(), 21);
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
        assert_eq!(
            manifest
                .provides
                .operations
                .iter()
                .find(|(id, _operation)| id.as_str() == RECORDINGS_LIST_OP)
                .map(|(_id, operation)| operation)
                .expect("recordings op")
                .capability
                .as_str(),
            MEET_ARTIFACT_READ_CAP
        );
        assert_eq!(
            manifest
                .provides
                .operations
                .iter()
                .find(|(id, _operation)| id.as_str() == DRIVE_DOCUMENT_TEXT_EXPORT_OP)
                .map(|(_id, operation)| operation)
                .expect("drive text export op")
                .capability
                .as_str(),
            MEET_DRIVE_ARTIFACT_READ_CAP
        );
        assert_eq!(
            manifest
                .provides
                .operations
                .iter()
                .find(|(id, _operation)| id.as_str() == LIVE_JOIN_OP)
                .map(|(_id, operation)| operation)
                .expect("live join op")
                .capability
                .as_str(),
            MEET_LIVE_JOIN_CAP
        );
        assert_eq!(
            manifest
                .provides
                .operations
                .iter()
                .find(|(id, _operation)| id.as_str() == LIVE_STATUS_OP)
                .map(|(_id, operation)| operation)
                .expect("live status op")
                .capability
                .as_str(),
            MEET_LIVE_READ_CAP
        );
    }
}
