//! Google Meet API client foundation.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, StatusCode, Url, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::error::{GoogleMeetError, GoogleMeetResult};

/// Default Google Meet API base URL.
pub const DEFAULT_BASE_URL: &str = "https://meet.googleapis.com/v2";

/// Default Google Drive API base URL used for Meet docsDestination exports.
pub const DEFAULT_DRIVE_EXPORT_BASE_URL: &str = "https://www.googleapis.com/drive/v3";

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
    drive_base_url: String,
    http: Client,
}

impl fmt::Debug for GoogleMeetClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleMeetClient")
            .field("auth", &google_auth_redacted_label(&self.auth))
            .field("base_url", &self.base_url)
            .field("drive_base_url", &self.drive_base_url)
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
            drive_base_url: DEFAULT_DRIVE_EXPORT_BASE_URL.to_string(),
            http,
        })
    }

    /// Set the base URL for tests or approved host routing.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Set the Drive API base URL for tests or approved host routing.
    #[must_use]
    pub fn with_drive_base_url(mut self, drive_base_url: impl Into<String>) -> Self {
        self.drive_base_url = drive_base_url.into();
        self
    }

    /// Base URL used by future Meet API calls.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Base URL used by Drive-backed text export calls.
    #[must_use]
    pub fn drive_base_url(&self) -> &str {
        &self.drive_base_url
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
        } else if self.drive_base_url.trim().is_empty() {
            Err(GoogleMeetError::InvalidConfig {
                message: "drive_base_url must not be empty".to_string(),
            })
        } else {
            Ok(())
        }
    }

    /// Fetch one meeting space by resource name, meeting code, or Meet URL.
    pub async fn get_space(&self, meeting: &str) -> GoogleMeetResult<GoogleMeetSpace> {
        let name = normalize_meet_space_name(meeting)?;
        let space = self
            .get_json::<GoogleMeetSpace>(&encode_resource_name_for_path(&name), &[])
            .await?;
        ensure_named(&space, "spaces.get")?;
        Ok(space)
    }

    /// Create a meeting space with optional Meet API `SpaceConfig`.
    pub async fn create_space(
        &self,
        config: Option<GoogleMeetSpaceConfig>,
    ) -> GoogleMeetResult<GoogleMeetSpace> {
        let body = config.map_or_else(|| json!({}), |config| json!({ "config": config }));
        let space = self.post_json::<GoogleMeetSpace>("spaces", &body).await?;
        ensure_named(&space, "spaces.create")?;
        if space.meeting_uri.as_deref().is_none_or(str::is_empty) {
            return Err(GoogleMeetError::InvalidConfig {
                message: "Google Meet spaces.create response included a space without meetingUri"
                    .to_string(),
            });
        }
        Ok(space)
    }

    /// End the currently active conference for a meeting space.
    pub async fn end_active_conference(&self, space_name: &str) -> GoogleMeetResult<Value> {
        let name = normalize_meet_space_name(space_name)?;
        let path = format!(
            "{}:endActiveConference",
            encode_resource_name_for_path(&name)
        );
        self.post_empty_json(&path).await
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

    /// List recordings for a conference record.
    pub async fn list_recordings(
        &self,
        conference_record: &str,
        page_size: Option<u32>,
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<GoogleMeetRecording>> {
        let parent = normalize_conference_record_name(conference_record)?;
        let path = format!("{}/recordings", encode_resource_name_for_path(&parent));
        let mut query = Vec::new();
        if let Some(size) = page_size {
            query.push(("pageSize", size.to_string()));
        }
        self.list_collection(&path, "recordings", &query, max_items)
            .await
    }

    /// List transcripts for a conference record.
    pub async fn list_transcripts(
        &self,
        conference_record: &str,
        page_size: Option<u32>,
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<GoogleMeetTranscript>> {
        let parent = normalize_conference_record_name(conference_record)?;
        let path = format!("{}/transcripts", encode_resource_name_for_path(&parent));
        let mut query = Vec::new();
        if let Some(size) = page_size {
            query.push(("pageSize", size.to_string()));
        }
        self.list_collection(&path, "transcripts", &query, max_items)
            .await
    }

    /// List transcript entries for one transcript resource.
    pub async fn list_transcript_entries(
        &self,
        transcript: &str,
        page_size: Option<u32>,
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<GoogleMeetTranscriptEntry>> {
        let transcript = normalize_transcript_name(transcript)?;
        let path = format!("{}/entries", encode_resource_name_for_path(&transcript));
        let mut query = Vec::new();
        if let Some(size) = page_size {
            query.push(("pageSize", size.to_string()));
        }
        self.list_collection(&path, "transcriptEntries", &query, max_items)
            .await
    }

    /// List smart notes for a conference record.
    pub async fn list_smart_notes(
        &self,
        conference_record: &str,
        page_size: Option<u32>,
        max_items: Option<usize>,
    ) -> GoogleMeetResult<Vec<GoogleMeetSmartNote>> {
        let parent = normalize_conference_record_name(conference_record)?;
        let path = format!("{}/smartNotes", encode_resource_name_for_path(&parent));
        let mut query = Vec::new();
        if let Some(size) = page_size {
            query.push(("pageSize", size.to_string()));
        }
        self.list_collection(&path, "smartNotes", &query, max_items)
            .await
    }

    /// Export Drive-backed docsDestination text for a Meet artifact.
    pub async fn export_drive_document_text(
        &self,
        document_id: &str,
        max_bytes: usize,
    ) -> GoogleMeetResult<String> {
        let document_id = validate_drive_document_id(document_id)?;
        let path = format!(
            "files/{}/export",
            utf8_percent_encode(&document_id, NON_ALPHANUMERIC)
        );
        let url = self.build_drive_url(&path, &[("mimeType", "text/plain".to_string())])?;
        let mut request = self.http.get(url).header(header::ACCEPT, "text/plain");
        let auth_headers = auth_headers(&self.auth)?;
        if !auth_headers.is_empty() {
            request = request.headers(auth_headers);
        }
        let response = request.send().await.map_err(GoogleMeetError::Http)?;
        decode_text_response(response, "Google Drive files.export", max_bytes).await
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
        let mut next_page_cursor: Option<String> = None;

        loop {
            let mut page_query = query.to_vec();
            if let Some(cursor) = &next_page_cursor {
                page_query.push(("pageToken", cursor.clone()));
            }
            let page_body = self.get_json::<Value>(path, &page_query).await?;
            let page_items_value = page_body
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
            next_page_cursor = page_body
                .get("nextPageToken")
                .and_then(Value::as_str)
                .map(str::to_string);
            if next_page_cursor.is_none() {
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
        let auth_headers = auth_headers(&self.auth)?;
        if !auth_headers.is_empty() {
            request = request.headers(auth_headers);
        }
        let response = request.send().await.map_err(GoogleMeetError::Http)?;
        decode_response(response).await
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> GoogleMeetResult<T> {
        let url = self.build_url(path, &[])?;
        let mut request = self.http.post(url).json(body);
        let auth_headers = auth_headers(&self.auth)?;
        if !auth_headers.is_empty() {
            request = request.headers(auth_headers);
        }
        let response = request.send().await.map_err(GoogleMeetError::Http)?;
        decode_response(response).await
    }

    async fn post_empty_json<T: DeserializeOwned>(&self, path: &str) -> GoogleMeetResult<T> {
        let url = self.build_url(path, &[])?;
        let mut request = self.http.post(url);
        let auth_headers = auth_headers(&self.auth)?;
        if !auth_headers.is_empty() {
            request = request.headers(auth_headers);
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
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url)
    }

    fn build_drive_url(&self, path: &str, query: &[(&str, String)]) -> GoogleMeetResult<Url> {
        let base = format!("{}/", self.drive_base_url.trim_end_matches('/'));
        let mut url = Url::parse(&base).map_err(|error| GoogleMeetError::InvalidConfig {
            message: format!(
                "invalid Google Drive drive_base_url `{}`: {error}",
                self.drive_base_url
            ),
        })?;
        url = url.join(path.trim_start_matches('/')).map_err(|error| {
            GoogleMeetError::InvalidConfig {
                message: format!("invalid Google Drive request path `{path}`: {error}"),
            }
        })?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url)
    }
}

/// Google Meet meeting space resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetSpace {
    /// Resource name, `spaces/{space}`.
    #[serde(default)]
    pub name: String,
    /// Join URI returned by Google Meet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meeting_uri: Option<String>,
    /// Typeable meeting code alias.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meeting_code: Option<String>,
    /// Meeting space configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<GoogleMeetSpaceConfig>,
    /// Active conference pointer when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_conference: Option<GoogleMeetActiveConference>,
    /// Preserve fields added by Google before FCP models them explicitly.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Google Meet meeting space configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetSpaceConfig {
    /// Access type: OPEN, TRUSTED, or RESTRICTED.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_type: Option<String>,
    /// Entry point policy: ALL or CREATOR_APP_ONLY.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_access: Option<String>,
}

/// Google Meet active conference pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetActiveConference {
    /// Conference record resource name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conference_record: Option<String>,
}

/// Google Meet conference record resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetConferenceRecord {
    /// Resource name, `conferenceRecords/{conference_record}`.
    #[serde(default)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetParticipant {
    /// Resource name.
    #[serde(default)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetParticipantSession {
    /// Resource name.
    #[serde(default)]
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

/// Google Meet recording artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetRecording {
    /// Resource name.
    #[serde(default)]
    pub name: String,
    /// Recording start time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Recording end time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Drive destination for the recording file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive_destination: Option<GoogleMeetDriveDestination>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Google Meet Drive destination pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetDriveDestination {
    /// Drive file pointer when provided by Google.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Export URI when provided by Google.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_uri: Option<String>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Google Meet transcript artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetTranscript {
    /// Resource name.
    #[serde(default)]
    pub name: String,
    /// Transcript start time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Transcript end time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Docs destination for transcript text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_destination: Option<GoogleMeetDocsDestination>,
    /// Strictly extracted Drive document id when text export was attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    /// Exported Drive document text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_text: Option<String>,
    /// Non-fatal Drive export or extraction error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_text_error: Option<String>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Google Meet transcript entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetTranscriptEntry {
    /// Resource name.
    #[serde(default)]
    pub name: String,
    /// Participant resource referenced by this utterance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant: Option<String>,
    /// Transcript text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// BCP-47 language code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language_code: Option<String>,
    /// Entry start time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Entry end time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Google Meet smart note artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetSmartNote {
    /// Resource name.
    #[serde(default)]
    pub name: String,
    /// Smart note start time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    /// Smart note end time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    /// Docs destination for smart-note text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_destination: Option<GoogleMeetDocsDestination>,
    /// Strictly extracted Drive document id when text export was attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    /// Exported Drive document text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_text: Option<String>,
    /// Non-fatal Drive export or extraction error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_text_error: Option<String>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// Google Meet Docs destination pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleMeetDocsDestination {
    /// Google Docs document pointer or URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
    /// Raw document id used by some Meet API previews.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    /// File pointer used by some previews.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Preserve future fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

/// One attendance row after optional participant merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl NamedGoogleMeetResource for GoogleMeetSpace {
    fn resource_name(&self) -> &str {
        &self.name
    }
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

impl NamedGoogleMeetResource for GoogleMeetRecording {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

impl NamedGoogleMeetResource for GoogleMeetTranscript {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

impl NamedGoogleMeetResource for GoogleMeetTranscriptEntry {
    fn resource_name(&self) -> &str {
        &self.name
    }
}

impl NamedGoogleMeetResource for GoogleMeetSmartNote {
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
    validate_resource_name(&name, "conferenceRecords", 2)?;
    Ok(name)
}

/// Normalize a participant input into `conferenceRecords/*/participants/*`.
pub fn normalize_participant_name(input: &str) -> GoogleMeetResult<String> {
    let trimmed = input.trim().trim_start_matches('/');
    validate_resource_name(trimmed, "conferenceRecords", 4)?;
    let parts = resource_segments(trimmed);
    if parts.get(2) != Some(&"participants") {
        return Err(GoogleMeetError::InvalidConfig {
            message: "participant must be a conferenceRecords/*/participants/* resource"
                .to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Normalize a transcript input into `conferenceRecords/*/transcripts/*`.
pub fn normalize_transcript_name(input: &str) -> GoogleMeetResult<String> {
    let trimmed = input.trim().trim_start_matches('/');
    validate_resource_name(trimmed, "conferenceRecords", 4)?;
    let parts = resource_segments(trimmed);
    if parts.get(2) != Some(&"transcripts") {
        return Err(GoogleMeetError::InvalidConfig {
            message: "transcript must be a conferenceRecords/*/transcripts/* resource".to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Extract a strict Drive document id from a Meet docsDestination.
pub fn extract_docs_destination_document_id(
    destination: &GoogleMeetDocsDestination,
) -> GoogleMeetResult<Option<String>> {
    for value in [
        destination.document.as_deref(),
        destination.document_id.as_deref(),
        destination.file.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        return parse_docs_destination_document_id(value).map(Some);
    }
    Ok(None)
}

/// Validate a Drive document id accepted by Drive `files.export`.
pub fn validate_drive_document_id(document_id: &str) -> GoogleMeetResult<String> {
    let trimmed = document_id.trim();
    if is_valid_drive_document_id(trimmed) {
        Ok(trimmed.to_string())
    } else {
        Err(GoogleMeetError::InvalidConfig {
            message: "Drive document id must be 3-256 chars of ASCII letters, digits, '_' or '-'"
                .to_string(),
        })
    }
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

fn validate_resource_name(
    name: &str,
    expected_prefix: &str,
    expected_segments: usize,
) -> GoogleMeetResult<()> {
    let segments = resource_segments(name);
    if segments.first() != Some(&expected_prefix)
        || name.contains('?')
        || name.contains('#')
        || name.chars().any(char::is_whitespace)
        || segments.iter().any(|segment| segment.is_empty())
        || segments.len() != expected_segments
    {
        return Err(GoogleMeetError::InvalidConfig {
            message: format!("invalid Google Meet resource name `{name}`"),
        });
    }
    Ok(())
}

fn resource_segments(name: &str) -> Vec<&str> {
    name.split('/').collect()
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

fn parse_docs_destination_document_id(raw: &str) -> GoogleMeetResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(GoogleMeetError::InvalidConfig {
            message: "docsDestination document id is empty".to_string(),
        });
    }
    if let Some(suffix) = trimmed.strip_prefix("documents/") {
        return validate_drive_document_id(suffix);
    }
    if trimmed.contains("://") {
        let url = Url::parse(trimmed).map_err(|error| GoogleMeetError::InvalidConfig {
            message: format!("docsDestination document URL could not be parsed: {error}"),
        })?;
        if url.scheme() != "https" {
            return Err(GoogleMeetError::InvalidConfig {
                message: "docsDestination document URL must use https".to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(GoogleMeetError::InvalidConfig {
                message: "docsDestination document URL must not include userinfo".to_string(),
            });
        }
        let host = url
            .host_str()
            .ok_or_else(|| GoogleMeetError::InvalidConfig {
                message: "docsDestination document URL must include a host".to_string(),
            })?;
        if !host.eq_ignore_ascii_case("docs.google.com") {
            return Err(GoogleMeetError::InvalidConfig {
                message: format!(
                    "docsDestination document URL must target docs.google.com, got {host}"
                ),
            });
        }
        let segments: Vec<_> = url
            .path_segments()
            .map(|segments| segments.collect())
            .unwrap_or_default();
        let document_id = segments
            .windows(3)
            .find_map(|window| (window[0] == "document" && window[1] == "d").then_some(window[2]));
        return validate_drive_document_id(document_id.ok_or_else(|| {
            GoogleMeetError::InvalidConfig {
                message: "docsDestination URL must include /document/d/{document_id}".to_string(),
            }
        })?);
    }
    validate_drive_document_id(trimmed)
}

fn is_valid_drive_document_id(value: &str) -> bool {
    (3..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn ensure_named<T: NamedGoogleMeetResource>(resource: &T, context: &str) -> GoogleMeetResult<()> {
    if resource.resource_name().trim().is_empty() {
        return Err(GoogleMeetError::InvalidConfig {
            message: format!("Google Meet {context} response included a resource without name"),
        });
    }
    Ok(())
}

fn auth_headers(auth: &GoogleMaterializedAuth) -> GoogleMeetResult<header::HeaderMap> {
    let mut pairs = Vec::new();
    auth.apply_headers(&mut pairs);
    let mut headers = header::HeaderMap::new();
    for (name, value) in pairs {
        let name = header::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            GoogleMeetError::InvalidConfig {
                message: format!("invalid Google auth header name `{name}`: {error}"),
            }
        })?;
        let value = header::HeaderValue::from_str(&value).map_err(|error| {
            GoogleMeetError::InvalidConfig {
                message: format!("invalid Google auth header value for `{name}`: {error}"),
            }
        })?;
        headers.insert(name, value);
    }
    Ok(headers)
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

async fn decode_text_response(
    response: reqwest::Response,
    context: &str,
    max_bytes: usize,
) -> GoogleMeetResult<String> {
    let status = response.status();
    if status.is_success() {
        let body = response.bytes().await.map_err(GoogleMeetError::Http)?;
        if body.len() > max_bytes {
            return Err(GoogleMeetError::ResponseTooLarge {
                context: context.to_string(),
                max_bytes,
            });
        }
        return String::from_utf8(body.to_vec()).map_err(|error| GoogleMeetError::InvalidConfig {
            message: format!("{context} returned non-UTF-8 text/plain: {error}"),
        });
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
            format!("{context} returned HTTP {}", status.as_u16())
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
