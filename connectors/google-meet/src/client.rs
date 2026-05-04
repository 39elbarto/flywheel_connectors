//! Google Meet API client foundation.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, StatusCode, Url, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::error::{GoogleMeetError, GoogleMeetResult};

/// Default Google Meet API base URL.
pub const DEFAULT_BASE_URL: &str = "https://meet.googleapis.com/v2";

/// Render a redacted auth label suitable for logs and diagnostics.
#[must_use]
pub fn google_auth_redacted_label(auth: &GoogleMaterializedAuth) -> String {
    auth.credential_id().map_or_else(
        || "google_auth:bearer:redacted".to_string(),
        |credential_id| format!("google_auth:credential_id:{credential_id}"),
    )
}

/// Whether this auth mode requires host-side credential injection.
#[must_use]
pub const fn google_auth_is_secretless(auth: &GoogleMaterializedAuth) -> bool {
    auth.credential_id().is_some()
}

/// Minimal client state shared by later Meet API operation Beads.
pub struct GoogleMeetClient {
    auth: GoogleMaterializedAuth,
    base_url: String,
    http: Client,
}

impl fmt::Debug for GoogleMeetClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleMeetClient")
            .field("auth", &google_auth_redacted_label(&self.auth))
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl GoogleMeetClient {
    /// Create a client with an `OAuth2` access token.
    pub fn new(token: impl Into<String>) -> GoogleMeetResult<Self> {
        Self::new_with_auth(GoogleMaterializedAuth::BearerToken {
            access_token: token.into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        })
    }

    /// Create a client with shared Google auth material.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> GoogleMeetResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        let http = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-meet/0.1.0")
            .build()
            .map_err(GoogleMeetError::Http)?;

        Ok(Self {
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
            http,
        })
    }

    /// Set the base URL for tests or approved host routing.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Base URL used by future Meet API calls.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Redacted auth label for diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        google_auth_redacted_label(&self.auth)
    }

    /// Whether this client is waiting on host credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        google_auth_is_secretless(&self.auth)
    }

    /// Placeholder shutdown hook for future supervised request/runtime state.
    pub const fn shutdown(&self) {}

    /// Foundation readiness deliberately avoids a fake network call.
    pub fn foundation_probe(&self) -> GoogleMeetResult<()> {
        if self.base_url.trim().is_empty() {
            Err(GoogleMeetError::InvalidConfig {
                message: "base_url must not be empty".to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// Fetch one conference record by resource name or id.
    pub async fn get_conference_record(
        &self,
        conference_record: &str,
    ) -> GoogleMeetResult<GoogleMeetConferenceRecord> {
        let name = normalize_conference_record_name(conference_record)?;
        let record = self
            .get_json::<GoogleMeetConferenceRecord>(&encode_resource_name_for_path(&name), &[])
            .await?;
        ensure_named(&record, "conferenceRecords.get")?;
        Ok(record)
    }

    /// List conference records, optionally filtering to a Meet space.
    pub async fn list_conference_records(
        &self,
        meeting: Option<&str>,
        page_size: Option<u32>,
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<GoogleMeetConferenceRecord>> {
        let mut query = Vec::new();
        if let Some(size) = page_size {
            query.push(("pageSize", size.to_string()));
        }
        if let Some(input) = meeting {
            query.push((
                "filter",
                format!("space.name = \"{}\"", normalize_meet_space_name(input)?),
            ));
        }
        self.list_collection("conferenceRecords", "conferenceRecords", &query, max_items)
            .await
    }

    /// List participants for a conference record.
    pub async fn list_participants(
        &self,
        conference_record: &str,
        page_size: Option<u32>,
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<GoogleMeetParticipant>> {
        let parent = normalize_conference_record_name(conference_record)?;
        let path = format!("{}/participants", encode_resource_name_for_path(&parent));
        let mut query = Vec::new();
        if let Some(size) = page_size {
            query.push(("pageSize", size.to_string()));
        }
        self.list_collection(&path, "participants", &query, max_items)
            .await
    }

    /// List participant sessions for one participant resource.
    pub async fn list_participant_sessions(
        &self,
        participant: &str,
        page_size: Option<u32>,
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<GoogleMeetParticipantSession>> {
        let participant = normalize_participant_name(participant)?;
        let path = format!(
            "{}/participantSessions",
            encode_resource_name_for_path(&participant)
        );
        let mut query = Vec::new();
        if let Some(size) = page_size {
            query.push(("pageSize", size.to_string()));
        }
        self.list_collection(&path, "participantSessions", &query, max_items)
            .await
    }

    async fn list_collection<T>(
        &self,
        path: &str,
        collection_key: &str,
        query: &[(&str, String)],
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<T>>
    where
        T: DeserializeOwned + NamedGoogleMeetResource,
    {
        let mut items = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut page_query = query.to_vec();
            if let Some(token) = &page_token {
                page_query.push(("pageToken", token.clone()));
            }
            let payload = self.get_json::<Value>(path, &page_query).await?;
            let page_items_value = payload
                .get(collection_key)
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            if !page_items_value.is_array() {
                return Err(GoogleMeetError::InvalidConfig {
                    message: format!(
                        "Google Meet response for {collection_key} contained a non-array collection"
                    ),
                });
            }
            let page_items: Vec<T> =
                serde_json::from_value(page_items_value).map_err(GoogleMeetError::Json)?;
            for item in page_items {
                ensure_named(&item, collection_key)?;
                items.push(item);
                if max_items.is_some_and(|limit| items.len() >= limit) {
                    return Ok(items);
                }
            }
            page_token = payload
                .get("nextPageToken")
                .and_then(Value::as_str)
                .map(str::to_string);
            if page_token.is_none() {
                return Ok(items);
            }
        }
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> GoogleMeetResult<T> {
        let url = self.build_url(path, query)?;
        let mut request = self.http.get(url);
        for (name, value) in auth_header_pairs(&self.auth)? {
            request = request.header(name, value);
        }
        let response = request.send().await.map_err(GoogleMeetError::Http)?;
        decode_response(response).await
    }

    fn build_url(&self, path: &str, query: &[(&str, String)]) -> GoogleMeetResult<Url> {
        let base = format!("{}/", self.base_url.trim_end_matches('/'));
        let mut url = Url::parse(&base).map_err(|error| GoogleMeetError::InvalidConfig {
            message: format!("invalid Google Meet base_url `{}`: {error}", self.base_url),
        })?;
        url = url.join(path.trim_start_matches('/')).map_err(|error| {
            GoogleMeetError::InvalidConfig {
                message: format!("invalid Google Meet request path `{path}`: {error}"),
            }
        })?;
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url)
    }
}

/// Google Meet conference record resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetConferenceRecord {
    /// Resource name, `conferenceRecords/{conference_record}`.
    pub name: String,
    /// Associated space resource when provided by the API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    /// Conference start time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Conference end time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_time: Option<String>,
    /// Preserve fields added by Google before FCP models them explicitly.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Google Meet participant resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetParticipant {
    /// Resource name.
    pub name: String,
    /// Earliest observed start time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_start_time: Option<String>,
    /// Latest observed end time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_end_time: Option<String>,
    /// Signed-in user identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signedin_user: Option<GoogleMeetUserIdentity>,
    /// Anonymous user identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymous_user: Option<GoogleMeetDisplayIdentity>,
    /// Phone user identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_user: Option<GoogleMeetDisplayIdentity>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Signed-in Google Meet participant identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetUserIdentity {
    /// User resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Anonymous or phone Google Meet participant identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetDisplayIdentity {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Google Meet participant session resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetParticipantSession {
    /// Resource name.
    pub name: String,
    /// Session start time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Session end time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// One attendance row after optional participant merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleMeetAttendanceRow {
    /// Conference record resource.
    pub conference_record: String,
    /// Primary participant resource.
    pub participant: String,
    /// Participant resources merged into this row.
    pub participants: Vec<String>,
    /// Display name when supplied by Meet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Signed-in user resource when supplied by Meet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Earliest participant start or session start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_start_time: Option<String>,
    /// Latest participant end or session end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_end_time: Option<String>,
    /// First join time derived from sessions and participant bounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_join_time: Option<String>,
    /// Last leave time derived from sessions and participant bounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_leave_time: Option<String>,
    /// Total attended session duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Whether the participant arrived after the configured grace period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub late: Option<bool>,
    /// Arrival delay if marked late.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub late_by_ms: Option<u64>,
    /// Whether the participant left before the configured grace period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_leave: Option<bool>,
    /// Early leave delta if marked early.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub early_leave_by_ms: Option<u64>,
    /// Raw participant sessions used for this row.
    pub sessions: Vec<GoogleMeetParticipantSession>,
}

pub trait NamedGoogleMeetResource {
    /// Resource name.
    fn resource_name(&self) -> &str;
}

impl NamedGoogleMeetResource for GoogleMeetConferenceRecord {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

impl NamedGoogleMeetResource for GoogleMeetParticipant {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

impl NamedGoogleMeetResource for GoogleMeetParticipantSession {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

/// Normalize a Meet space input into `spaces/*`.
pub fn normalize_meet_space_name(input: &str) -> GoogleMeetResult<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(GoogleMeetError::InvalidConfig {
            message: "Meeting input is required".to_string(),
        });
    }
    if let Some(suffix) = trimmed.strip_prefix("spaces/") {
        validate_resource_suffix(
            suffix,
            "spaces/ input must include a meeting code or space id",
        )?;
        return Ok(format!("spaces/{}", suffix.trim()));
    }
    if trimmed.contains("://") {
        let url = Url::parse(trimmed).map_err(|error| GoogleMeetError::InvalidConfig {
            message: format!("Google Meet URL could not be parsed: {error}"),
        })?;
        if url.scheme() != "https" {
            return Err(GoogleMeetError::InvalidConfig {
                message: "Google Meet URL must use https".to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(GoogleMeetError::InvalidConfig {
                message: "Google Meet URL must not include userinfo".to_string(),
            });
        }
        let host = url
            .host_str()
            .ok_or_else(|| GoogleMeetError::InvalidConfig {
                message: "Google Meet URL must include a host".to_string(),
            })?;
        if !host.eq_ignore_ascii_case("meet.google.com") {
            return Err(GoogleMeetError::InvalidConfig {
                message: format!("Expected a meet.google.com URL, received {host}"),
            });
        }
        let code = url
            .path_segments()
            .and_then(|mut segments| segments.find(|segment| !segment.trim().is_empty()))
            .ok_or_else(|| GoogleMeetError::InvalidConfig {
                message: "Google Meet URL did not include a meeting code".to_string(),
            })?;
        validate_resource_suffix(code, "Google Meet URL did not include a valid meeting code")?;
        return Ok(format!("spaces/{code}"));
    }
    validate_resource_suffix(trimmed, "Meeting code or space id is invalid")?;
    Ok(format!("spaces/{trimmed}"))
}

/// Normalize a conference record input into `conferenceRecords/*`.
pub fn normalize_conference_record_name(input: &str) -> GoogleMeetResult<String> {
    let trimmed = input.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(GoogleMeetError::InvalidConfig {
            message: "Conference record is required".to_string(),
        });
    }
    let name = if trimmed.starts_with("conferenceRecords/") {
        trimmed.to_string()
    } else {
        format!("conferenceRecords/{trimmed}")
    };
    validate_resource_name(&name, "conferenceRecords")?;
    Ok(name)
}

/// Normalize a participant input into `conferenceRecords/*/participants/*`.
pub fn normalize_participant_name(input: &str) -> GoogleMeetResult<String> {
    let trimmed = input.trim().trim_start_matches('/');
    validate_resource_name(trimmed, "conferenceRecords")?;
    if !trimmed.contains("/participants/") || trimmed.contains("/participantSessions/") {
        return Err(GoogleMeetError::InvalidConfig {
            message: "participant must be a conferenceRecords/*/participants/* resource"
                .to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Percent-encode a Google resource name one path segment at a time.
#[must_use]
pub fn encode_resource_name_for_path(name: &str) -> String {
    name.trim()
        .split('/')
        .map(|segment| utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn validate_resource_name(name: &str, expected_prefix: &str) -> GoogleMeetResult<()> {
    if !name.starts_with(expected_prefix)
        || name.contains('?')
        || name.contains('#')
        || name.chars().any(char::is_whitespace)
        || name.split('/').any(str::is_empty)
    {
        return Err(GoogleMeetError::InvalidConfig {
            message: format!("invalid Google Meet resource name `{name}`"),
        });
    }
    Ok(())
}

fn validate_resource_suffix(value: &str, message: &'static str) -> GoogleMeetResult<()> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.contains('/')
        || value.chars().any(char::is_whitespace)
    {
        return Err(GoogleMeetError::InvalidConfig {
            message: message.to_string(),
        });
    }
    Ok(())
}

fn ensure_named<T: NamedGoogleMeetResource>(resource: &T, context: &str) -> GoogleMeetResult<()> {
    if resource.resource_name().trim().is_empty() {
        return Err(GoogleMeetError::InvalidConfig {
            message: format!("Google Meet {context} response included a resource without name"),
        });
    }
    Ok(())
}

fn auth_header_pairs(auth: &GoogleMaterializedAuth) -> GoogleMeetResult<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    auth.apply_headers(&mut pairs);
    for (name, value) in &pairs {
        header::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            GoogleMeetError::InvalidConfig {
                message: format!("invalid Google auth header name `{name}`: {error}"),
            }
        })?;
        header::HeaderValue::from_str(value).map_err(|error| GoogleMeetError::InvalidConfig {
            message: format!("invalid Google auth header value for `{name}`: {error}"),
        })?;
    }
    Ok(pairs)
}

async fn decode_response<T: DeserializeOwned>(response: reqwest::Response) -> GoogleMeetResult<T> {
    let status = response.status();
    if status.is_success() {
        let body = response.bytes().await.map_err(GoogleMeetError::Http)?;
        return serde_json::from_slice(&body).map_err(GoogleMeetError::Json);
    }
    let retry_after_secs = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let body = response.text().await.unwrap_or_default();
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(GoogleMeetError::RateLimited {
            retry_after_secs: retry_after_secs.unwrap_or(60),
        });
    }
    let message = google_api_error_message(&body).unwrap_or_else(|| {
        if body.trim().is_empty() {
            format!("Google Meet API returned HTTP {}", status.as_u16())
        } else {
            body
        }
    });
    Err(GoogleMeetError::Api {
        code: u32::from(status.as_u16()),
        message,
    })
}

fn google_api_error_message(body: &str) -> Option<String> {
    let payload: Value = serde_json::from_str(body).ok()?;
    payload
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| payload.get("message").and_then(Value::as_str))
        .map(str::to_string)
}
