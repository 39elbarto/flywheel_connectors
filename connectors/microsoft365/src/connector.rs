//! FCP Microsoft 365 Connector implementation.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL},
};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, CredentialId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, SimulateRequest, SimulateResponse,
};
use percent_encoding::percent_decode_str;
use quick_xml::{Reader, escape::unescape, events::Event};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument, warn};
use zip::{CompressionMethod, ZipArchive, write::FileOptions};

use crate::{
    client::{DEFAULT_API_URL, M365Auth, M365Client},
    error::M365Error,
    onenote::{
        CreatePageInput, GetPageContentInput, GetPageInput, ListNotebooksInput, ListPagesInput,
        ListSectionsInput, OneNotePageContent, UpdatePageInput,
    },
    types::DriveItem,
};

const DEFAULT_AUTH_URL: &str = "https://login.microsoftonline.com";
const DEFAULT_CLIENT_CREDENTIAL_SCOPE: &str = "https://graph.microsoft.com/.default";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const M365_SYNC_STATE_FILE: &str = "m365_sync_state.json";
const M365_SYNC_LEASE_FILE: &str = "m365_sync_lease.json";
const M365_SYNC_LEASE_TTL_SECONDS: u64 = 120;
const M365_NOTIFICATION_REPLAY_MAX_ENTRIES: usize = 1024;
const M365_NOTIFICATION_VALIDATION_TOKEN_MAX_BYTES: usize = 2048;
const M365_NOTIFICATION_DEFAULT_ACK_TIMEOUT_MS: u64 = 10_000;
const M365_NOTIFICATION_RENEWAL_WINDOW_SECONDS: i64 = 60 * 60;
const WORD_EXTRACT_DEFAULT_MAX_CHARS: usize = 20_000;
const WORD_EXTRACT_MAX_CHARS_LIMIT: usize = 100_000;
const WORD_EXTRACT_MAX_BYTES: usize = 8 * 1024 * 1024;
const WORD_EXPORT_MAX_BYTES: usize = 25 * 1024 * 1024;
const WORD_SIMPLE_UPLOAD_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
struct M365Config {
    auth_mode: M365AuthMode,
    api_url: String,
    required_permissions: Vec<String>,
    token_permissions: Option<TokenPermissions>,
}

#[derive(Debug, Clone)]
enum M365AuthMode {
    AccessToken,
    ClientCredentials {
        tenant_id: String,
        client_id: String,
        scope: String,
    },
    CredentialId(CredentialId),
}

impl M365AuthMode {
    fn label(&self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::ClientCredentials { .. } => "client_credentials",
            Self::CredentialId(_) => "credential_id",
        }
    }

    fn summary(&self) -> serde_json::Value {
        match self {
            Self::AccessToken => json!({ "mode": "access_token" }),
            Self::ClientCredentials {
                tenant_id,
                client_id,
                scope,
            } => {
                let prefix = client_id.chars().take(8).collect::<String>();
                json!({
                    "mode": "client_credentials",
                    "tenant_id": tenant_id,
                    "client_id_prefix": prefix,
                    "scope": scope,
                })
            }
            Self::CredentialId(credential_id) => json!({
                "mode": "credential_id",
                "credential_id": credential_id,
            }),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct TokenPermissions {
    scopes: Vec<String>,
    roles: Vec<String>,
}

impl TokenPermissions {
    fn parse(token: &str) -> FcpResult<Self> {
        let mut parts = token.split('.');
        let _header = parts.next().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "access_token is not a JWT (missing header)".into(),
        })?;
        let payload_b64 = parts.next().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "access_token is not a JWT (missing payload)".into(),
        })?;

        let payload_bytes = BASE64_URL
            .decode(payload_b64)
            .or_else(|_| BASE64.decode(payload_b64))
            .map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "access_token payload is not valid base64".into(),
            })?;

        let payload_json: serde_json::Value =
            serde_json::from_slice(&payload_bytes).map_err(|_| FcpError::InvalidRequest {
                code: 1003,
                message: "access_token payload is not valid JSON".into(),
            })?;

        let scopes = payload_json
            .get("scp")
            .and_then(|v| v.as_str())
            .map(|raw| {
                raw.split_whitespace()
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let roles = payload_json
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if scopes.is_empty() && roles.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "access_token is missing both scp and roles claims".into(),
            });
        }

        Ok(Self { scopes, roles })
    }

    fn all(&self) -> Vec<String> {
        let mut perms = self.scopes.clone();
        perms.extend(self.roles.iter().cloned());
        perms
    }

    fn missing_required(&self, required_permissions: &[String]) -> Vec<String> {
        let available = self.all();
        required_permissions
            .iter()
            .filter(|required| !available.iter().any(|present| present == *required))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppCredentialsConfig {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    #[serde(default = "default_client_credential_scope")]
    scope: String,
}

fn default_client_credential_scope() -> String {
    DEFAULT_CLIENT_CREDENTIAL_SCOPE.to_string()
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

impl std::fmt::Debug for OAuthTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokenResponse")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

fn write_json_file_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    fs::write(&tmp_path, payload)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn read_json_file_if_exists<T>(path: &Path) -> io::Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(bytes) => {
            let parsed = serde_json::from_slice::<T>(&bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            Ok(Some(parsed))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn current_unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct M365SyncState {
    #[serde(default)]
    delta_tokens: BTreeMap<String, String>,
    #[serde(default)]
    subscriptions: BTreeMap<String, M365SubscriptionState>,
    #[serde(default)]
    seen_notification_keys: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct M365SubscriptionState {
    resource: Option<String>,
    change_type: Option<String>,
    notification_url: Option<String>,
    client_state: Option<String>,
    expiration_datetime: Option<String>,
}

impl M365SubscriptionState {
    fn from_graph_payload(payload: &serde_json::Value) -> Self {
        Self {
            resource: payload
                .get("resource")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            change_type: payload
                .get("changeType")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            notification_url: payload
                .get("notificationUrl")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            client_state: payload
                .get("clientState")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            expiration_datetime: payload
                .get("expirationDateTime")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        }
    }

    fn with_client_state(mut self, client_state: Option<&str>) -> Self {
        if let Some(client_state) = client_state {
            self.client_state = Some(client_state.to_string());
        }
        self
    }
}

#[derive(Debug, Clone)]
struct M365NotificationIngestRequest {
    validation_token: Option<String>,
    payload: Option<serde_json::Value>,
    expected_client_state: Option<String>,
    retry_after_seconds: Option<u64>,
    ack_timeout_ms: u64,
    cancelled: bool,
}

#[derive(Debug, Clone)]
struct M365GraphNotification {
    subscription_id: String,
    client_state: String,
    change_type: Option<String>,
    lifecycle_event: Option<String>,
    resource: Option<String>,
    resource_id: Option<String>,
    tenant_id: Option<String>,
    expiration_datetime: Option<String>,
    replay_key: String,
}

impl M365NotificationIngestRequest {
    fn parse(input: serde_json::Value) -> FcpResult<Self> {
        let validation_token = notification_string_field(&input, &[
            "validation_token",
            "validationToken",
        ])
        .or_else(|| {
            input
                .get("query")
                .and_then(|query| notification_string_field(query, &[
                    "validationToken",
                    "validation_token",
                ]))
        })
        .map(normalize_validation_token)
        .transpose()?;

        let payload = input
            .get("payload")
            .or_else(|| input.get("body"))
            .cloned();
        if validation_token.is_some() == payload.is_some() {
            return Err(invalid_request(
                "m365.notifications.ingest requires exactly one of validation_token or payload",
            ));
        }

        let expected_client_state = notification_string_field(&input, &[
            "expected_client_state",
            "expectedClientState",
        ])
        .map(|value| value.to_string());
        let retry_after_seconds = retry_after_seconds_from_input(&input)?;
        let ack_timeout_ms = input
            .get("ack_timeout_ms")
            .or_else(|| input.get("ackTimeoutMs"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(M365_NOTIFICATION_DEFAULT_ACK_TIMEOUT_MS);
        let cancelled = input
            .get("cancelled")
            .or_else(|| input.get("cancellation_requested"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        Ok(Self {
            validation_token,
            payload,
            expected_client_state,
            retry_after_seconds,
            ack_timeout_ms,
            cancelled,
        })
    }
}

impl M365GraphNotification {
    fn parse(
        value: &serde_json::Value,
        state: &M365SyncState,
        expected_client_state: Option<&str>,
    ) -> FcpResult<Self> {
        let object = value.as_object().ok_or_else(|| {
            invalid_request("Graph notification entries must be JSON objects")
        })?;
        let subscription_id = object
            .get("subscriptionId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| invalid_request("Graph notification missing subscriptionId"))?;
        let known_subscription =
            state
                .subscriptions
                .get(subscription_id)
                .ok_or_else(|| FcpError::ResourceNotFound {
                    resource: format!("m365 subscription '{subscription_id}'"),
                })?;

        let state_client_state = known_subscription.client_state.as_deref();
        if let (Some(stored), Some(provided)) = (state_client_state, expected_client_state)
            && stored != provided
        {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: "expected_client_state does not match stored subscription clientState"
                    .into(),
            });
        }
        let expected = state_client_state
            .or(expected_client_state)
            .ok_or_else(|| FcpError::Unauthorized {
                code: 2001,
                message: format!(
                    "No clientState secret is available for subscription '{subscription_id}'"
                ),
            })?;
        let client_state = object
            .get("clientState")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FcpError::Unauthorized {
                    code: 2001,
                    message: format!(
                        "Graph notification for subscription '{subscription_id}' missing clientState"
                    ),
                }
            })?;
        if client_state != expected {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: format!(
                    "Graph notification clientState mismatch for subscription '{subscription_id}'"
                ),
            });
        }

        let change_type = notification_string_field(value, &["changeType"]).map(str::to_string);
        let lifecycle_event =
            notification_string_field(value, &["lifecycleEvent"]).map(str::to_string);
        match (change_type.as_ref(), lifecycle_event.as_ref()) {
            (None, None) => {
                return Err(invalid_request(
                    "Graph notification requires changeType or lifecycleEvent",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(invalid_request(
                    "Graph notification cannot include both changeType and lifecycleEvent",
                ));
            }
            (Some(_), None) | (None, Some(_)) => {}
        }
        if let Some(event) = lifecycle_event.as_deref() {
            validate_lifecycle_event(event)?;
        }

        let resource = notification_string_field(value, &["resource"])
            .map(str::to_string)
            .or_else(|| known_subscription.resource.clone());
        let resource_id = value
            .get("resourceData")
            .and_then(|resource_data| notification_string_field(resource_data, &["id"]))
            .map(str::to_string);
        let tenant_id = notification_string_field(value, &["tenantId"]).map(str::to_string);
        let expiration_datetime =
            notification_string_field(value, &["subscriptionExpirationDateTime"])
                .map(str::to_string)
                .or_else(|| known_subscription.expiration_datetime.clone());
        let replay_key = notification_replay_key(
            subscription_id,
            change_type.as_deref(),
            lifecycle_event.as_deref(),
            resource.as_deref(),
            resource_id.as_deref(),
            tenant_id.as_deref(),
            value,
        );

        Ok(Self {
            subscription_id: subscription_id.to_string(),
            client_state: client_state.to_string(),
            change_type,
            lifecycle_event,
            resource,
            resource_id,
            tenant_id,
            expiration_datetime,
            replay_key,
        })
    }
}

fn notification_string_field<'a>(
    value: &'a serde_json::Value,
    fields: &[&str],
) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|field| value.get(*field).and_then(serde_json::Value::as_str))
        .filter(|value| !value.trim().is_empty())
}

fn normalize_validation_token(raw: &str) -> FcpResult<String> {
    if raw.len() > M365_NOTIFICATION_VALIDATION_TOKEN_MAX_BYTES {
        return Err(invalid_request("validation_token exceeds maximum length"));
    }
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| invalid_request("validation_token is not valid UTF-8 after URL decoding"))?;
    if decoded.trim().is_empty() {
        return Err(invalid_request("validation_token must not be empty"));
    }
    if decoded.chars().any(char::is_control) {
        return Err(invalid_request(
            "validation_token must not contain control characters",
        ));
    }
    Ok(decoded.into_owned())
}

fn retry_after_seconds_from_input(input: &serde_json::Value) -> FcpResult<Option<u64>> {
    if let Some(retry_after) = input
        .get("retry_after_seconds")
        .or_else(|| input.get("retryAfterSeconds"))
    {
        return retry_after.as_u64().map(Some).ok_or_else(|| {
            invalid_request("retry_after_seconds must be an unsigned integer")
        });
    }

    let Some(headers) = input.get("headers").and_then(serde_json::Value::as_object) else {
        return Ok(None);
    };
    let retry_after = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.as_str());
    retry_after
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                invalid_request("Retry-After header must be an unsigned integer number of seconds")
            })
        })
        .transpose()
}

fn validate_lifecycle_event(event: &str) -> FcpResult<()> {
    match event {
        "reauthorizationRequired" | "subscriptionRemoved" | "missed" => Ok(()),
        other => Err(invalid_request(format!(
            "Unsupported Graph lifecycleEvent: {other}"
        ))),
    }
}

fn notification_replay_key(
    subscription_id: &str,
    change_type: Option<&str>,
    lifecycle_event: Option<&str>,
    resource: Option<&str>,
    resource_id: Option<&str>,
    tenant_id: Option<&str>,
    raw: &serde_json::Value,
) -> String {
    if let Some(id) = notification_string_field(raw, &["id"]) {
        return format!("{subscription_id}|id:{id}");
    }

    let mut hasher = Sha256::new();
    hasher.update(subscription_id.as_bytes());
    hasher.update(b"|");
    hasher.update(change_type.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(lifecycle_event.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(resource.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(resource_id.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(tenant_id.unwrap_or("").as_bytes());
    if resource_id.is_none() {
        hasher.update(b"|");
        hasher.update(raw.to_string().as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn prune_notification_replay_cache(cache: &mut BTreeMap<String, u64>) {
    if cache.len() <= M365_NOTIFICATION_REPLAY_MAX_ENTRIES {
        return;
    }
    let remove_count = cache.len() - M365_NOTIFICATION_REPLAY_MAX_ENTRIES;
    let mut entries = cache
        .iter()
        .map(|(key, seen_at)| (key.clone(), *seen_at))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, seen_at)| *seen_at);
    for (key, _) in entries.into_iter().take(remove_count) {
        cache.remove(&key);
    }
}

fn notification_delta_resource(
    notification: &M365GraphNotification,
    state: &M365SyncState,
) -> FcpResult<String> {
    state
        .subscriptions
        .get(&notification.subscription_id)
        .and_then(|subscription| subscription.resource.clone())
        .or_else(|| notification.resource.clone())
        .ok_or_else(|| {
            invalid_request(format!(
                "No delta resource available for subscription '{}'",
                notification.subscription_id
            ))
        })
}

fn lifecycle_action(
    notification: &M365GraphNotification,
    state: &M365SyncState,
) -> FcpResult<Option<serde_json::Value>> {
    let Some(event) = notification.lifecycle_event.as_deref() else {
        return Ok(None);
    };
    let resource = notification_delta_resource(notification, state)?;
    let action = match event {
        "reauthorizationRequired" => json!({
            "type": "reauthorize_and_renew",
            "operation": "m365.subscriptions.renew",
            "subscription_id": notification.subscription_id,
            "resource": resource,
            "expiration_datetime": notification.expiration_datetime,
        }),
        "subscriptionRemoved" => json!({
            "type": "recreate_subscription",
            "operation": "m365.subscriptions.create",
            "subscription_id": notification.subscription_id,
            "resource": resource,
        }),
        "missed" => json!({
            "type": "run_delta_sync",
            "operation": "m365.delta.sync",
            "subscription_id": notification.subscription_id,
            "resource": resource,
        }),
        _ => return Ok(None),
    };
    Ok(Some(action))
}

fn renewal_due(expiration_datetime: Option<&str>) -> bool {
    let Some(expiration_datetime) = expiration_datetime else {
        return false;
    };
    chrono::DateTime::parse_from_rfc3339(expiration_datetime).is_ok_and(|expiration| {
        let now = chrono::Utc::now();
        let expires_at = expiration.with_timezone(&chrono::Utc);
        expires_at <= now + chrono::Duration::seconds(M365_NOTIFICATION_RENEWAL_WINDOW_SECONDS)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct M365SyncLeaseRecord {
    holder_instance_id: String,
    lease_seq: u64,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct M365SyncLease {
    path: PathBuf,
    holder_instance_id: String,
    lease_seq: u64,
}

impl M365SyncLease {
    fn acquire(path: PathBuf, holder_instance_id: String, ttl_seconds: u64) -> FcpResult<Self> {
        let now = current_unix_timestamp_secs();
        let previous = read_json_file_if_exists::<M365SyncLeaseRecord>(&path).map_err(|err| {
            FcpError::Internal {
                message: format!(
                    "Failed to read m365 sync lease file '{}': {err}",
                    path.display()
                ),
            }
        })?;

        if let Some(record) = previous.as_ref()
            && record.expires_at > now
            && record.holder_instance_id != holder_instance_id
        {
            return Err(FcpError::ResourceExhausted {
                resource: format!(
                    "m365 sync lease held by '{}' (lease_seq={}) until {}",
                    record.holder_instance_id, record.lease_seq, record.expires_at
                ),
            });
        }

        let lease_seq = previous.map_or(1, |record| record.lease_seq.saturating_add(1));
        let record = M365SyncLeaseRecord {
            holder_instance_id: holder_instance_id.clone(),
            lease_seq,
            expires_at: now.saturating_add(ttl_seconds),
        };
        write_json_file_atomic(&path, &record).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to persist m365 sync lease file '{}': {err}",
                path.display()
            ),
        })?;

        Ok(Self {
            path,
            holder_instance_id,
            lease_seq,
        })
    }

    fn release(&self) -> FcpResult<()> {
        let existing =
            read_json_file_if_exists::<M365SyncLeaseRecord>(&self.path).map_err(|err| {
                FcpError::Internal {
                    message: format!(
                        "Failed to read m365 sync lease file '{}': {err}",
                        self.path.display()
                    ),
                }
            })?;

        if let Some(record) = existing
            && record.holder_instance_id == self.holder_instance_id
            && record.lease_seq == self.lease_seq
            && let Err(err) = fs::remove_file(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            return Err(FcpError::Internal {
                message: format!(
                    "Failed to release m365 sync lease file '{}': {err}",
                    self.path.display()
                ),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
struct ThreadSummary {
    thread_id: String,
    message_count: u64,
    unread_count: u64,
    latest_received_datetime: Option<String>,
    last_message_id: Option<String>,
    subject_preview: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListWordDocumentsInput {
    user_id: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetWordDocumentInput {
    user_id: String,
    item_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractWordTextInput {
    user_id: String,
    item_id: String,
    #[serde(default)]
    max_chars: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateWordDocumentInput {
    user_id: String,
    path: String,
    content: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateWordDocumentInput {
    user_id: String,
    item_id: String,
    content: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportWordDocumentInput {
    user_id: String,
    item_id: String,
    format: String,
}

#[derive(Debug, Clone, Serialize)]
struct WordDocumentMetadata {
    id: Option<String>,
    name: Option<String>,
    size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_date_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_modified_date_time: Option<String>,
    supports_text_extraction: bool,
    supports_content_replace: bool,
    supports_pdf_export: bool,
}

#[derive(Debug, Clone, Serialize)]
struct WordAuditEvent {
    timestamp: String,
    action: String,
    user_id: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_id: Option<String>,
    content_chars: usize,
}

impl ListWordDocumentsInput {
    fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.word.list_documents")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_optional_non_empty(parsed.path.as_deref(), "path")?;
        Ok(parsed)
    }
}

impl GetWordDocumentInput {
    fn parse(value: serde_json::Value, operation: &str) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, operation)?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.item_id, "item_id")?;
        Ok(parsed)
    }
}

impl ExtractWordTextInput {
    fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.word.extract_text")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.item_id, "item_id")?;
        validate_max_chars(parsed.max_chars)?;
        Ok(parsed)
    }
}

impl CreateWordDocumentInput {
    fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.word.create_document")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.path, "path")?;
        validate_non_empty(&parsed.content, "content")?;
        ensure_docx_path(&parsed.path, "path")?;
        Ok(parsed)
    }
}

impl UpdateWordDocumentInput {
    fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.word.update_document")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.item_id, "item_id")?;
        validate_non_empty(&parsed.content, "content")?;
        Ok(parsed)
    }
}

impl ExportWordDocumentInput {
    fn parse(value: serde_json::Value) -> FcpResult<Self> {
        let parsed: Self = parse_input(value, "m365.word.export_document")?;
        validate_non_empty(&parsed.user_id, "user_id")?;
        validate_non_empty(&parsed.item_id, "item_id")?;
        validate_export_format(&parsed.format)?;
        Ok(parsed)
    }
}

impl WordDocumentMetadata {
    fn from_drive_item(item: &DriveItem) -> Self {
        let extension = item.file_extension().map(str::to_ascii_lowercase);
        let supports_text_extraction = extension
            .as_deref()
            .is_some_and(is_docx_text_extractable_extension);
        let supports_content_replace = extension.as_deref() == Some("docx");

        Self {
            id: item.id.clone(),
            name: item.name.clone(),
            size: item.size,
            web_url: item.web_url.clone(),
            mime_type: item.mime_type().map(str::to_string),
            extension,
            created_date_time: item.created_date_time.clone(),
            last_modified_date_time: item.last_modified_date_time.clone(),
            supports_text_extraction,
            supports_content_replace,
            supports_pdf_export: item.is_word_document(),
        }
    }
}

impl WordAuditEvent {
    fn new(
        action: &str,
        user_id: &str,
        target: String,
        item_id: Option<String>,
        content_chars: usize,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: action.to_string(),
            user_id: user_id.to_string(),
            target,
            item_id,
            content_chars,
        }
    }
}

fn readiness_profile(
    auth_mode: &M365AuthMode,
) -> (&'static str, Option<&'static str>, &'static str) {
    match auth_mode {
        M365AuthMode::CredentialId(_) => (
            "degraded",
            Some("credential_injection_required"),
            "Configured for secretless credential injection; readiness depends on host-provided Graph credentials at runtime.",
        ),
        M365AuthMode::AccessToken => (
            "healthy",
            None,
            "Delegated access token configured for direct Graph requests.",
        ),
        M365AuthMode::ClientCredentials { .. } => (
            "healthy",
            None,
            "Client-credentials mode configured for app-only Graph requests.",
        ),
    }
}

fn operator_action_for_auth_mode(auth_mode: &M365AuthMode) -> &'static str {
    match auth_mode {
        M365AuthMode::CredentialId(_) => {
            "Inject the referenced credential through the host egress proxy before relying on readiness."
        }
        M365AuthMode::AccessToken => {
            "Re-run doctor or self_check after refreshing the delegated token and confirming the required mailbox permissions."
        }
        M365AuthMode::ClientCredentials { .. } => {
            "Verify the app registration has the intended Microsoft Graph application permissions for the target mailbox and calendar surfaces."
        }
    }
}

fn classify_self_check_error(err: &M365Error) -> (&'static str, bool) {
    match err {
        M365Error::RateLimit { .. } => ("graph_rate_limited", true),
        M365Error::Api {
            status_code: Some(401),
            ..
        } => ("token_invalid_or_expired", false),
        M365Error::Api {
            status_code: Some(403),
            ..
        } => ("permissions_or_consent_missing", false),
        M365Error::Api {
            status_code: Some(404),
            ..
        } => ("graph_resource_not_found", false),
        _ if err.is_retryable() => ("self_check_retryable", true),
        _ => ("self_check_failed", false),
    }
}

fn health_probe_summary(payload: &serde_json::Value) -> serde_json::Value {
    if let Some(upn) = payload
        .get("userPrincipalName")
        .and_then(|value| value.as_str())
    {
        json!({
            "target": "/me",
            "mode": "delegated",
            "user_principal_name": upn,
        })
    } else if let Some(name) = payload.get("displayName").and_then(|value| value.as_str()) {
        json!({
            "target": "/organization",
            "mode": "application",
            "display_name": name,
        })
    } else {
        json!({
            "target": "unknown",
            "mode": "unknown",
        })
    }
}

/// FCP Microsoft 365 Connector.
pub struct M365Connector {
    base: Arc<BaseConnector>,
    config: Option<M365Config>,
    client: Option<M365Client>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
    zone_dir: Option<PathBuf>,
}

impl M365Connector {
    /// Create a new Microsoft 365 connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "fcp.microsoft365",
            ))),
            config: None,
            client: None,
            verifier: None,
            session_id: None,
            zone_dir: None,
        }
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Handle configure method.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let allow_test_endpoints = params
            .get("allow_test_api_url")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let api_url = params
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_API_URL);
        let api_url = validate_endpoint(
            api_url,
            &["graph.microsoft.com"],
            allow_test_endpoints,
            "api_url",
        )?;

        let auth_url = params
            .get("auth_url")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_AUTH_URL);
        let auth_url = validate_endpoint(
            auth_url,
            &["login.microsoftonline.com"],
            allow_test_endpoints,
            "auth_url",
        )?;

        let required_permissions = parse_required_permissions(&params)?;

        let access_token = parse_access_token(&params);
        let credential_id = parse_credential_id(&params)?;
        let app_credentials = parse_app_credentials(&params)?;

        let selected = [
            access_token.is_some(),
            credential_id.is_some(),
            app_credentials.is_some(),
        ]
        .into_iter()
        .filter(|selected_mode| *selected_mode)
        .count();

        if selected != 1 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide exactly one auth source: access_token, credential_id, or app_credentials".into(),
            });
        }

        let (auth_mode, auth, token_permissions) = if let Some(token) = access_token {
            let permissions = TokenPermissions::parse(&token)?;
            ensure_required_permissions(&permissions, &required_permissions)?;
            (
                M365AuthMode::AccessToken,
                M365Auth::AccessToken(token),
                Some(permissions),
            )
        } else if let Some(credential_id) = credential_id {
            (
                M365AuthMode::CredentialId(credential_id),
                M365Auth::CredentialId(credential_id),
                None,
            )
        } else if let Some(app_cfg) = app_credentials {
            let token = exchange_client_credentials(&auth_url, &app_cfg).await?;
            let permissions = TokenPermissions::parse(&token)?;
            ensure_required_permissions(&permissions, &required_permissions)?;
            (
                M365AuthMode::ClientCredentials {
                    tenant_id: app_cfg.tenant_id,
                    client_id: app_cfg.client_id,
                    scope: app_cfg.scope,
                },
                M365Auth::AccessToken(token),
                Some(permissions),
            )
        } else {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "No supported auth mode selected".into(),
            });
        };

        let auth_label = auth.redacted_label();
        let mut client = M365Client::new_with_auth(auth).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;
        client = client.with_api_url(&api_url);

        self.config = Some(M365Config {
            auth_mode,
            api_url: api_url.clone(),
            required_permissions,
            token_permissions,
        });
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, api_url = %api_url, "Microsoft 365 connector configured");

        Ok(json!({
            "status": "configured",
            "auth": auth_label,
            "api_url": api_url
        }))
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

        self.zone_dir = req.zone_dir.clone().map(PathBuf::from);
        if let Some(zone_dir) = self.zone_dir.as_ref() {
            fs::create_dir_all(zone_dir).map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to prepare Microsoft 365 zone_dir '{}': {err}",
                    zone_dir.display()
                ),
            })?;
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
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    fn sync_state_path(&self) -> FcpResult<PathBuf> {
        let zone_dir = self.zone_dir.as_ref().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required for m365 sync state persistence".into(),
        })?;
        Ok(zone_dir.join(M365_SYNC_STATE_FILE))
    }

    fn sync_lease_path(&self) -> FcpResult<PathBuf> {
        let zone_dir = self.zone_dir.as_ref().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Handshake zone_dir is required for m365 singleton-writer lease".into(),
        })?;
        Ok(zone_dir.join(M365_SYNC_LEASE_FILE))
    }

    fn sync_lease_holder_id(&self) -> FcpResult<String> {
        let session_id = self.session_id.as_ref().ok_or(FcpError::NotConfigured)?;
        Ok(session_id.to_string())
    }

    fn acquire_sync_lease(&self) -> FcpResult<M365SyncLease> {
        let lease_path = self.sync_lease_path()?;
        let holder = self.sync_lease_holder_id()?;
        M365SyncLease::acquire(lease_path, holder, M365_SYNC_LEASE_TTL_SECONDS)
    }

    fn load_sync_state(path: &Path) -> FcpResult<M365SyncState> {
        read_json_file_if_exists::<M365SyncState>(path)
            .map(|state| state.unwrap_or_default())
            .map_err(|err| FcpError::Internal {
                message: format!(
                    "Failed to read m365 sync state file '{}': {err}",
                    path.display()
                ),
            })
    }

    fn persist_sync_state(path: &Path, state: &M365SyncState) -> FcpResult<()> {
        write_json_file_atomic(path, state).map_err(|err| FcpError::Internal {
            message: format!(
                "Failed to write m365 sync state file '{}': {err}",
                path.display()
            ),
        })
    }

    /// Handle health check.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let metrics = self.base.metrics();
        let Some(config) = &self.config else {
            return Ok(json!({
                "status": "not_configured",
                "reason_code": "not_configured",
                "auth_mode": "unconfigured",
                "api_url": serde_json::Value::Null,
                "required_permissions": [],
                "permissions": [],
                "readiness": {
                    "message": "Connector is not configured yet.",
                    "operator_action": "Call configure with access_token, credential_id, or app_credentials before invoking Outlook/Exchange operations.",
                },
                "metrics": {
                    "requests_total": metrics.requests_total,
                    "requests_error": metrics.requests_error,
                }
            }));
        };

        let permissions = config
            .token_permissions
            .as_ref()
            .map(TokenPermissions::all)
            .unwrap_or_default();
        let (status, reason_code, readiness_message) = readiness_profile(&config.auth_mode);
        Ok(json!({
            "status": status,
            "reason_code": reason_code,
            "auth_mode": config.auth_mode.label(),
            "api_url": config.api_url,
            "required_permissions": config.required_permissions,
            "permissions": permissions,
            "readiness": {
                "message": readiness_message,
                "operator_action": operator_action_for_auth_mode(&config.auth_mode),
            },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: build_operations(),
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

        let operation_info = match operation_info_for(req.operation.as_str()) {
            Ok(operation_info) => operation_info,
            Err(error) => {
                let response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                });
            }
        };

        if let Err(error) = validate_simulate_input(&operation_info, &req.input) {
            let response = SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        if self.config.is_none() || self.client.is_none() {
            let response = SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        }

        let Some(verifier) = &self.verifier else {
            let response = SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            );
            return serde_json::to_value(response).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize response: {e}"),
            });
        };

        let capability = operation_info.capability;
        let response =
            match verifier.verify_bound(req.capability_token, &capability, &req.operation, &[]) {
                Ok(_) => SimulateResponse::allowed(req.id),
                Err(error) => {
                    let is_grant_mismatch = matches!(
                        error,
                        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                    );
                    let mut response =
                        SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                    if is_grant_mismatch {
                        response =
                            response.with_missing_capabilities(vec![capability.as_str().into()]);
                    }
                    response
                }
            };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle doctor readiness checks.
    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        #[derive(Serialize)]
        struct DoctorResult {
            status: &'static str,
            checks: Vec<DoctorCheck>,
        }
        #[derive(Serialize)]
        struct DoctorCheck {
            name: &'static str,
            status: &'static str,
            message: String,
        }

        let mut checks = Vec::new();

        // 1. Configuration
        let config_ok = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration",
            status: if config_ok { "pass" } else { "fail" },
            message: if config_ok {
                "Connector is configured".into()
            } else {
                "Connector is not configured — call 'configure' first".into()
            },
        });

        // 2. Client initialized
        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized",
            status: if client_ok { "pass" } else { "fail" },
            message: if client_ok {
                "HTTP client initialized".into()
            } else {
                "HTTP client not initialized".into()
            },
        });

        // 3. Base URL
        if let Some(ref config) = self.config {
            checks.push(DoctorCheck {
                name: "base_url",
                status: "pass",
                message: format!(
                    "Egress target: graph.microsoft.com (via {})",
                    config.api_url
                ),
            });
        } else {
            checks.push(DoctorCheck {
                name: "base_url",
                status: "warn",
                message: "No configuration — cannot determine base URL".into(),
            });
        }

        // 4. Auth mode
        if let Some(ref config) = self.config {
            checks.push(DoctorCheck {
                name: "auth_mode",
                status: "pass",
                message: format!("Auth: {}", config.auth_mode.label()),
            });
        } else {
            checks.push(DoctorCheck {
                name: "auth_mode",
                status: "fail",
                message: "No auth configured".into(),
            });
        }

        // 5. Required permissions
        if let Some(ref config) = self.config {
            let (status, message) = match config.token_permissions.as_ref() {
                Some(permissions) => {
                    let missing = permissions.missing_required(&config.required_permissions);
                    if missing.is_empty() {
                        (
                            "pass",
                            format!(
                                "Token covers required permissions: {}",
                                if config.required_permissions.is_empty() {
                                    "<implicit>".to_string()
                                } else {
                                    config.required_permissions.join(", ")
                                }
                            ),
                        )
                    } else {
                        (
                            "fail",
                            format!(
                                "Token is missing required permissions: {}",
                                missing.join(", ")
                            ),
                        )
                    }
                }
                None if config.required_permissions.is_empty() => (
                    "warn",
                    "No explicit required_permissions configured; permission surface is implicit."
                        .to_string(),
                ),
                None => (
                    "warn",
                    format!(
                        "Required permissions cannot be verified locally in {} mode: {}",
                        config.auth_mode.label(),
                        config.required_permissions.join(", ")
                    ),
                ),
            };
            checks.push(DoctorCheck {
                name: "required_permissions",
                status,
                message,
            });
        } else {
            checks.push(DoctorCheck {
                name: "required_permissions",
                status: "fail",
                message: "No auth configured".into(),
            });
        }

        // 6. Network constraints
        checks.push(DoctorCheck {
            name: "network_constraints",
            status: "pass",
            message: "Egress targets: graph.microsoft.com, login.microsoftonline.com (HTTPS)"
                .into(),
        });

        // 7. Credential injection / readiness model
        if let Some(ref config) = self.config {
            let (status, _reason_code, readiness_message) = readiness_profile(&config.auth_mode);
            checks.push(DoctorCheck {
                name: "credential_injection",
                status: if status == "healthy" { "pass" } else { "warn" },
                message: readiness_message.into(),
            });
            checks.push(DoctorCheck {
                name: "operator_guidance",
                status: "warn",
                message: operator_action_for_auth_mode(&config.auth_mode).into(),
            });
        } else {
            checks.push(DoctorCheck {
                name: "credential_injection",
                status: "fail",
                message: "No auth configured".into(),
            });
        }

        let overall = if checks.iter().any(|c| c.status == "fail") {
            "fail"
        } else if checks.iter().any(|c| c.status == "warn") {
            "warn"
        } else {
            "pass"
        };

        serde_json::to_value(DoctorResult {
            status: overall,
            checks,
        })
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize doctor result: {e}"),
        })
    }

    /// Handle connector self-check for host doctor/readiness.
    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        let Some(config) = &self.config else {
            let report = SelfCheckReport::degraded("not_configured", "Connector is not configured");
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        let Some(client) = &self.client else {
            let report = SelfCheckReport::failed(
                "client_not_initialized",
                "Connector is configured but HTTP client is unavailable",
            );
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        };

        if matches!(config.auth_mode, M365AuthMode::CredentialId(_)) {
            let mut report = SelfCheckReport::degraded(
                "credential_injection_required",
                "Configured with credential_id; readiness depends on egress proxy credential injection",
            );
            report.details = Some(json!({
                "auth_mode": config.auth_mode.summary(),
                "required_permissions": config.required_permissions,
                "operator_action": operator_action_for_auth_mode(&config.auth_mode),
            }));
            return serde_json::to_value(report).map_err(|e| FcpError::Internal {
                message: format!("Failed to serialize self-check report: {e}"),
            });
        }

        let report = match client.health_check().await {
            Ok(payload) => {
                let mut report = SelfCheckReport::ok();
                report.details = Some(json!({
                    "auth_mode": config.auth_mode.summary(),
                    "required_permissions": config.required_permissions,
                    "permissions": config.token_permissions.as_ref().map(TokenPermissions::all).unwrap_or_default(),
                    "health_probe": health_probe_summary(&payload),
                    "operator_action": operator_action_for_auth_mode(&config.auth_mode),
                }));
                report
            }
            Err(err) => {
                let (reason_code, degraded) = classify_self_check_error(&err);
                let mut report = if degraded {
                    SelfCheckReport::degraded(reason_code, err.to_string())
                } else {
                    SelfCheckReport::failed(reason_code, err.to_string())
                };
                report.details = Some(json!({
                    "auth_mode": config.auth_mode.summary(),
                    "required_permissions": config.required_permissions,
                    "permissions": config.token_permissions.as_ref().map(TokenPermissions::all).unwrap_or_default(),
                    "operator_action": operator_action_for_auth_mode(&config.auth_mode),
                }));
                report
            }
        };

        serde_json::to_value(report).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize self-check report: {e}"),
        })
    }

    /// Handle invoke method.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
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

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id = required_capability_for_operation(operation)?;
        self.base.check_ready()?;

        let verifier = self.verifier.as_ref().ok_or(FcpError::NotHandshaken)?;
        verifier.verify_bound(token, &cap_id, &op_id, &[])?;

        match operation {
            // ── Mail ─────────────────────────────────────────
            "m365.mail.list_messages" => self.invoke_list_messages(input).await,
            "m365.mail.search_messages" => self.invoke_search_messages(input).await,
            "m365.mail.list_threads" => self.invoke_list_threads(input).await,
            "m365.mail.get_message" => self.invoke_get_message(input).await,
            "m365.mail.send_message" => self.invoke_send_message(input).await,
            "m365.mail.create_draft" => self.invoke_create_draft(input).await,
            "m365.mail.reply_message" => self.invoke_reply_message(input).await,
            "m365.mail.forward_message" => self.invoke_forward_message(input).await,
            "m365.mail.list_attachments" => self.invoke_list_attachments(input).await,
            "m365.mail.add_attachment" => self.invoke_add_attachment(input).await,
            // ── Files ────────────────────────────────────────
            "m365.files.list_items" => self.invoke_list_items(input).await,
            "m365.files.get_item" => self.invoke_get_item(input).await,
            "m365.files.download_file" => self.invoke_download_file(input).await,
            "m365.files.upload_file" => self.invoke_upload_file(input).await,
            "m365.files.delete_item" => self.invoke_delete_item(input).await,
            "m365.files.search" => self.invoke_search_files(input).await,
            "m365.files.create_share_link" => self.invoke_create_share_link(input).await,
            // ── Word ─────────────────────────────────────────
            "m365.word.list_documents" => self.invoke_word_list_documents(input).await,
            "m365.word.get_document" => self.invoke_word_get_document(input).await,
            "m365.word.extract_text" => self.invoke_word_extract_text(input).await,
            "m365.word.create_document" => self.invoke_word_create_document(input).await,
            "m365.word.update_document" => self.invoke_word_update_document(input).await,
            "m365.word.export_document" => self.invoke_word_export_document(input).await,
            // ── OneNote ──────────────────────────────────────
            "m365.onenote.list_notebooks" => self.invoke_list_notebooks(input).await,
            "m365.onenote.list_sections" => self.invoke_list_sections(input).await,
            "m365.onenote.list_pages" => self.invoke_list_pages(input).await,
            "m365.onenote.get_page" => self.invoke_get_page(input).await,
            "m365.onenote.get_page_content" => self.invoke_get_page_content(input).await,
            "m365.onenote.create_page" => self.invoke_create_page(input).await,
            "m365.onenote.update_page" => self.invoke_update_page(input).await,
            // ── Calendar ─────────────────────────────────────
            "m365.calendar.list_events" => self.invoke_list_events(input).await,
            "m365.calendar.create_event" => self.invoke_create_event(input).await,
            "m365.calendar.delete_event" => self.invoke_delete_event(input).await,
            "m365.calendar.get_event" => self.invoke_get_event(input).await,
            "m365.calendar.update_event" => self.invoke_update_event(input).await,
            "m365.calendar.get_freebusy" => self.invoke_get_freebusy(input).await,
            // ── Tasks ────────────────────────────────────────
            "m365.tasks.list_task_lists" => self.invoke_list_task_lists(input).await,
            "m365.tasks.list_tasks" => self.invoke_list_tasks(input).await,
            "m365.tasks.create_task" => self.invoke_create_task(input).await,
            // ── Subscriptions ────────────────────────────────
            "m365.subscriptions.create" => self.invoke_create_subscription(input).await,
            "m365.subscriptions.renew" => self.invoke_renew_subscription(input).await,
            "m365.subscriptions.delete" => self.invoke_delete_subscription(input).await,
            // ── Notifications ────────────────────────────────
            "m365.notifications.ingest" => self.invoke_ingest_notification(input).await,
            // ── Delta ────────────────────────────────────────
            "m365.delta.sync" => self.invoke_delta_sync(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Mail operation implementations ───────────────────────────

    async fn invoke_list_messages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let folder_id = input.get("folder_id").and_then(|v| v.as_str());
        let top = input
            .get("top")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let skip = input
            .get("skip")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let filter = input.get("filter").and_then(|v| v.as_str());
        let result = client
            .list_messages(user_id, folder_id, top, skip, filter)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "messages": result.value }))
    }

    async fn invoke_get_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message_id = require_str(&input, "message_id")?;
        let message = client
            .get_message(user_id, message_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "message": message }))
    }

    async fn invoke_send_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message = input.get("message").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: message".into(),
        })?;
        client
            .send_message(user_id, message)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "sent" }))
    }

    async fn invoke_create_draft(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message = input.get("message").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: message".into(),
        })?;
        let draft = client
            .create_draft(user_id, message)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "message": draft }))
    }

    async fn invoke_search_messages(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let query = require_str(&input, "query")?;
        let top = input
            .get("top")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let skip = input
            .get("skip")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let result = client
            .search_messages(user_id, query, top, skip)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "messages": result.value }))
    }

    async fn invoke_list_threads(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let folder_id = input.get("folder_id").and_then(|v| v.as_str());
        let top = input
            .get("top")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let skip = input
            .get("skip")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let filter = input.get("filter").and_then(|v| v.as_str());
        let result = client
            .list_messages(user_id, folder_id, top, skip, filter)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;

        let source_message_count = result.value.len();
        let mut grouped: BTreeMap<String, ThreadSummary> = BTreeMap::new();
        for message in result.value {
            let thread_id = message
                .get("conversationId")
                .and_then(|v| v.as_str())
                .or_else(|| message.get("id").and_then(|v| v.as_str()))
                .unwrap_or("unknown")
                .to_string();

            let entry = grouped
                .entry(thread_id.clone())
                .or_insert_with(|| ThreadSummary {
                    thread_id: thread_id.clone(),
                    message_count: 0,
                    unread_count: 0,
                    latest_received_datetime: None,
                    last_message_id: None,
                    subject_preview: message
                        .get("subject")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string),
                });

            entry.message_count += 1;
            if message.get("isRead").and_then(|v| v.as_bool()) == Some(false) {
                entry.unread_count += 1;
            }

            if let Some(received) = message.get("receivedDateTime").and_then(|v| v.as_str()) {
                let should_update = match entry.latest_received_datetime.as_deref() {
                    Some(current) => received > current,
                    None => true,
                };
                if should_update {
                    entry.latest_received_datetime = Some(received.to_string());
                    entry.last_message_id = message
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string);
                }
            }
        }

        let threads: Vec<ThreadSummary> = grouped.into_values().collect();
        Ok(json!({
            "threads": threads,
            "source_message_count": source_message_count
        }))
    }

    async fn invoke_reply_message(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message_id = require_str(&input, "message_id")?;
        let comment = input.get("comment").and_then(|v| v.as_str());
        let message = input.get("message");
        if comment.is_none() && message.is_none() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Provide at least one of: comment, message".into(),
            });
        }
        client
            .reply_message(user_id, message_id, comment, message)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "replied" }))
    }

    async fn invoke_forward_message(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message_id = require_str(&input, "message_id")?;
        let comment = input.get("comment").and_then(|v| v.as_str());
        let to_recipients = input
            .get("to_recipients")
            .and_then(|v| v.as_array())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: to_recipients (must be an array)".into(),
            })?;
        client
            .forward_message(user_id, message_id, comment, to_recipients)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "forwarded" }))
    }

    async fn invoke_list_attachments(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message_id = require_str(&input, "message_id")?;
        let top = input
            .get("top")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let skip = input
            .get("skip")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        let result = client
            .list_attachments(user_id, message_id, top, skip)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "attachments": result.value }))
    }

    async fn invoke_add_attachment(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let message_id = require_str(&input, "message_id")?;
        let attachment = input.get("attachment").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: attachment".into(),
        })?;
        let result = client
            .add_attachment(user_id, message_id, attachment)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "attachment": result }))
    }

    // ── Files operation implementations ──────────────────────────

    async fn invoke_list_items(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let path = input.get("path").and_then(|v| v.as_str());
        let result = client
            .list_items(user_id, path)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "items": result.value }))
    }

    async fn invoke_download_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let item_id = require_str(&input, "item_id")?;
        let (content, metadata) = client
            .download_file(user_id, item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({
            "content": content,
            "name": metadata.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            "size": metadata.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
        }))
    }

    async fn invoke_upload_file(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let path = require_str(&input, "path")?;
        let content_b64 = require_str(&input, "content")?;
        let content = BASE64
            .decode(content_b64)
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid base64 content: {e}"),
            })?;
        let item = client
            .upload_file(user_id, path, &content)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "item": item }))
    }

    async fn invoke_delete_item(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let item_id = require_str(&input, "item_id")?;
        client
            .delete_item(user_id, item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "deleted" }))
    }

    async fn invoke_get_item(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let item_id = require_str(&input, "item_id")?;
        let item = client
            .get_item(user_id, item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "item": item }))
    }

    async fn invoke_search_files(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let query = require_str(&input, "query")?;
        let result = client
            .search_files(user_id, query)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "items": result.value }))
    }

    async fn invoke_create_share_link(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let item_id = require_str(&input, "item_id")?;
        let link_type = require_str(&input, "type")?;
        let scope = input.get("scope").and_then(|v| v.as_str());
        let link = client
            .create_share_link(user_id, item_id, link_type, scope)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "link": link }))
    }

    // ── Word operation implementations ───────────────────────────

    async fn invoke_word_list_documents(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = ListWordDocumentsInput::parse(input)?;
        let result = client
            .list_items(&input.user_id, input.path.as_deref())
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;

        let documents = result
            .value
            .iter()
            .map(|item| parse_drive_item(item, "m365.word.list_documents"))
            .filter_map(|item| match item {
                Ok(item) if item.is_word_document() => {
                    Some(Ok(WordDocumentMetadata::from_drive_item(&item)))
                }
                Ok(_) => None,
                Err(err) => Some(Err(err)),
            })
            .collect::<FcpResult<Vec<_>>>()?;

        Ok(json!({ "documents": documents }))
    }

    async fn invoke_word_get_document(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = GetWordDocumentInput::parse(input, "m365.word.get_document")?;
        let item = client
            .get_item(&input.user_id, &input.item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        let drive_item = parse_drive_item(&item, "m365.word.get_document")?;
        let document = ensure_word_document(&drive_item, "m365.word.get_document")?;
        Ok(json!({ "document": document }))
    }

    async fn invoke_word_extract_text(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = ExtractWordTextInput::parse(input)?;
        let item = client
            .get_item(&input.user_id, &input.item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        let drive_item = parse_drive_item(&item, "m365.word.extract_text")?;
        let document = ensure_word_document(&drive_item, "m365.word.extract_text")?;
        ensure_text_extraction_supported(&document)?;
        enforce_word_document_size(&document, WORD_EXTRACT_MAX_BYTES, "text extraction")?;

        let (bytes, _) = client
            .download_file_raw(&input.user_id, &input.item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        if bytes.len() > WORD_EXTRACT_MAX_BYTES {
            return Err(invalid_request(format!(
                "Document exceeds the {WORD_EXTRACT_MAX_BYTES}-byte limit for text extraction"
            )));
        }

        let extracted = extract_docx_text(&bytes)?;
        let (text, truncated) = truncate_text(
            &extracted,
            input.max_chars.unwrap_or(WORD_EXTRACT_DEFAULT_MAX_CHARS),
        );

        Ok(json!({
            "document": document,
            "text": text,
            "truncated": truncated,
            "extracted_chars": extracted.chars().count(),
        }))
    }

    async fn invoke_word_create_document(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = CreateWordDocumentInput::parse(input)?;
        let content_chars = input.content.chars().count();
        let bytes = build_docx_document(&input.content)?;
        if bytes.len() > WORD_SIMPLE_UPLOAD_MAX_BYTES {
            return Err(invalid_request(format!(
                "Generated .docx payload exceeds the {WORD_SIMPLE_UPLOAD_MAX_BYTES}-byte simple upload limit"
            )));
        }

        let item = client
            .upload_file(&input.user_id, &input.path, &bytes)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        let drive_item = parse_drive_item(&item, "m365.word.create_document")?;
        let document = ensure_word_document(&drive_item, "m365.word.create_document")?;
        let audit = WordAuditEvent::new(
            "create_document",
            &input.user_id,
            input.path.clone(),
            document.id.clone(),
            content_chars,
        );

        info!(
            operation = "m365.word.create_document",
            user_id = %input.user_id,
            path = %input.path,
            content_chars,
            item_id = ?document.id,
            "created Word document"
        );

        Ok(json!({
            "document": document,
            "audit": audit,
        }))
    }

    async fn invoke_word_update_document(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = UpdateWordDocumentInput::parse(input)?;
        let existing_item = client
            .get_item(&input.user_id, &input.item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        let existing_drive_item = parse_drive_item(&existing_item, "m365.word.update_document")?;
        let existing_document =
            ensure_word_document(&existing_drive_item, "m365.word.update_document")?;
        ensure_content_replace_supported(&existing_document)?;

        let content_chars = input.content.chars().count();
        let bytes = build_docx_document(&input.content)?;
        if bytes.len() > WORD_SIMPLE_UPLOAD_MAX_BYTES {
            return Err(invalid_request(format!(
                "Generated .docx payload exceeds the {WORD_SIMPLE_UPLOAD_MAX_BYTES}-byte simple upload limit"
            )));
        }

        let item = client
            .update_item_content(&input.user_id, &input.item_id, &bytes)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        let drive_item = parse_drive_item(&item, "m365.word.update_document")?;
        let document = ensure_word_document(&drive_item, "m365.word.update_document")?;
        let audit = WordAuditEvent::new(
            "update_document",
            &input.user_id,
            input.item_id.clone(),
            document.id.clone().or(existing_document.id.clone()),
            content_chars,
        );

        info!(
            operation = "m365.word.update_document",
            user_id = %input.user_id,
            item_id = %input.item_id,
            content_chars,
            "updated Word document"
        );

        Ok(json!({
            "document": document,
            "audit": audit,
        }))
    }

    async fn invoke_word_export_document(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = ExportWordDocumentInput::parse(input)?;
        let item = client
            .get_item(&input.user_id, &input.item_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        let drive_item = parse_drive_item(&item, "m365.word.export_document")?;
        let document = ensure_word_document(&drive_item, "m365.word.export_document")?;
        enforce_word_document_size(&document, WORD_EXPORT_MAX_BYTES, "export")?;

        let (bytes, _) = client
            .download_file_as(&input.user_id, &input.item_id, &input.format)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        if bytes.len() > WORD_EXPORT_MAX_BYTES {
            return Err(invalid_request(format!(
                "Exported document exceeds the {WORD_EXPORT_MAX_BYTES}-byte limit"
            )));
        }

        let exported_name = replace_extension(document.name.as_deref(), &input.format)
            .unwrap_or_else(|| format!("document.{}", input.format));

        Ok(json!({
            "document": document,
            "format": input.format,
            "name": exported_name,
            "size": bytes.len(),
            "content": BASE64.encode(bytes),
        }))
    }

    // ── OneNote operation implementations ───────────────────────

    async fn invoke_list_notebooks(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = ListNotebooksInput::parse(input)?;
        let result = client
            .list_notebooks(&input.user_id, input.top)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "notebooks": result.value }))
    }

    async fn invoke_list_sections(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = ListSectionsInput::parse(input)?;
        let result = client
            .list_sections(
                &input.user_id,
                input.notebook_id.as_deref(),
                input.section_group_id.as_deref(),
                input.top,
            )
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "sections": result.value }))
    }

    async fn invoke_list_pages(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = ListPagesInput::parse(input)?;
        let result = client
            .list_pages(&input.user_id, &input.section_id, input.top)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "pages": result.value }))
    }

    async fn invoke_get_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = GetPageInput::parse(input)?;
        let page = client
            .get_page(&input.user_id, &input.page_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "page": page }))
    }

    async fn invoke_get_page_content(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = GetPageContentInput::parse(input)?;
        let html = client
            .get_page_content(&input.user_id, &input.page_id, input.include_ids)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        let content = OneNotePageContent::from_html(html);
        Ok(json!({ "page_content": content }))
    }

    async fn invoke_create_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = CreatePageInput::parse(input)?;
        let page = client
            .create_page(&input.user_id, &input.section_id, &input.html)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "page": page }))
    }

    async fn invoke_update_page(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let input = UpdatePageInput::parse(input)?;
        client
            .update_page(&input.user_id, &input.page_id, &input.commands)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "updated" }))
    }

    // ── Calendar operation implementations ───────────────────────

    async fn invoke_list_events(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let start = input.get("start_datetime").and_then(|v| v.as_str());
        let end = input.get("end_datetime").and_then(|v| v.as_str());
        let result = client
            .list_events(user_id, start, end)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "events": result.value }))
    }

    async fn invoke_create_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let subject = require_str(&input, "subject")?;
        let start = input.get("start").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: start".into(),
        })?;
        let end = input.get("end").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: end".into(),
        })?;
        let mut event = json!({
            "subject": subject,
            "start": start,
            "end": end,
        });
        if let Some(body) = input.get("body") {
            event["body"] = body.clone();
        }
        if let Some(location) = input.get("location") {
            event["location"] = location.clone();
        }
        if let Some(attendees) = input.get("attendees") {
            event["attendees"] = attendees.clone();
        }
        let created = client
            .create_event(user_id, &event)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "event": created }))
    }

    async fn invoke_delete_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let event_id = require_str(&input, "event_id")?;
        client
            .delete_event(user_id, event_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "status": "deleted" }))
    }

    async fn invoke_get_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let event_id = require_str(&input, "event_id")?;
        let event = client
            .get_event(user_id, event_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "event": event }))
    }

    async fn invoke_update_event(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let event_id = require_str(&input, "event_id")?;

        let mut updates = input.clone();
        // Remove routing fields from the update payload
        if let Some(obj) = updates.as_object_mut() {
            obj.remove("user_id");
            obj.remove("event_id");
        }

        let event = client
            .update_event(user_id, event_id, &updates)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "event": event }))
    }

    async fn invoke_get_freebusy(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let schedules_val = input.get("schedules").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: schedules".into(),
        })?;
        let schedules: Vec<String> = schedules_val
            .as_array()
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "schedules must be an array".into(),
            })?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        let start_time = input.get("start_time").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: start_time".into(),
        })?;
        let end_time = input.get("end_time").ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "Missing required field: end_time".into(),
        })?;
        let result = client
            .get_freebusy(&schedules, start_time, end_time)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "schedules": result.get("value").cloned().unwrap_or(json!([])) }))
    }

    // ── Tasks operation implementations ──────────────────────────

    async fn invoke_list_task_lists(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let result = client
            .list_task_lists(user_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "task_lists": result.value }))
    }

    async fn invoke_list_tasks(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let task_list_id = require_str(&input, "task_list_id")?;
        let result = client
            .list_tasks(user_id, task_list_id)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "tasks": result.value }))
    }

    async fn invoke_create_task(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let user_id = require_str(&input, "user_id")?;
        let task_list_id = require_str(&input, "task_list_id")?;
        let title = require_str(&input, "title")?;
        let mut task = json!({ "title": title });
        if let Some(body) = input.get("body") {
            task["body"] = body.clone();
        }
        if let Some(due) = input.get("due_datetime").and_then(|v| v.as_str()) {
            task["dueDateTime"] = json!({
                "dateTime": due,
                "timeZone": "UTC",
            });
        }
        let created = client
            .create_task(user_id, task_list_id, &task)
            .await
            .map_err(|e: M365Error| e.to_fcp_error())?;
        Ok(json!({ "task": created }))
    }

    // ── Subscription operation implementations ───────────────────

    async fn invoke_create_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let change_type = require_str(&input, "change_type")?;
        let notification_url = require_str(&input, "notification_url")?;
        let resource = require_str(&input, "resource")?;
        let expiration = require_str(&input, "expiration_datetime")?;
        let client_state = input.get("client_state").and_then(|value| value.as_str());
        let result = async {
            let mut sub = json!({
                "changeType": change_type,
                "notificationUrl": notification_url,
                "resource": resource,
                "expirationDateTime": expiration,
            });
            if let Some(client_state) = client_state {
                sub["clientState"] = json!(client_state);
            }
            let created = client
                .create_subscription(&sub)
                .await
                .map_err(|e: M365Error| e.to_fcp_error())?;

            if let Some(subscription_id) = created.get("id").and_then(|value| value.as_str()) {
                let mut state = Self::load_sync_state(&state_path)?;
                state.subscriptions.insert(
                    subscription_id.to_string(),
                    M365SubscriptionState::from_graph_payload(&created)
                        .with_client_state(client_state),
                );
                Self::persist_sync_state(&state_path, &state)?;
            }

            Ok(json!({ "subscription": created }))
        }
        .await;
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release m365 sync lease after create_subscription");
        }
        result
    }

    async fn invoke_renew_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let subscription_id = require_str(&input, "subscription_id")?;
        let expiration = require_str(&input, "expiration_datetime")?;
        let result = async {
            let renewed = client
                .renew_subscription(subscription_id, expiration)
                .await
                .map_err(|e: M365Error| e.to_fcp_error())?;

            let mut state = Self::load_sync_state(&state_path)?;
            let state_key = renewed
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or(subscription_id);
            let existing_client_state = state
                .subscriptions
                .get(subscription_id)
                .and_then(|subscription| subscription.client_state.as_deref());
            state.subscriptions.insert(
                state_key.to_string(),
                M365SubscriptionState::from_graph_payload(&renewed)
                    .with_client_state(existing_client_state),
            );
            Self::persist_sync_state(&state_path, &state)?;

            Ok(json!({ "subscription": renewed }))
        }
        .await;
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release m365 sync lease after renew_subscription");
        }
        result
    }

    async fn invoke_delete_subscription(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let subscription_id = require_str(&input, "subscription_id")?;
        let result = async {
            client
                .delete_subscription(subscription_id)
                .await
                .map_err(|e: M365Error| e.to_fcp_error())?;

            let mut state = Self::load_sync_state(&state_path)?;
            state.subscriptions.remove(subscription_id);
            Self::persist_sync_state(&state_path, &state)?;

            Ok(json!({ "status": "deleted" }))
        }
        .await;
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release m365 sync lease after delete_subscription");
        }
        result
    }

    async fn invoke_ingest_notification(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let request = M365NotificationIngestRequest::parse(input)?;
        if request.cancelled {
            return Err(FcpError::ConnectorUnavailable {
                code: 5003,
                message: "Host cancelled Microsoft Graph notification delivery".into(),
            });
        }
        if request.ack_timeout_ms == 0 {
            return Err(FcpError::UpstreamTimeout {
                service: "microsoft_graph_notification_delivery".into(),
            });
        }

        if let Some(validation_token) = request.validation_token {
            return Ok(json!({
                "status": "validation_challenge",
                "ack": {
                    "http_status": 200,
                    "content_type": "text/plain",
                    "body": validation_token,
                    "timeout_ms": request.ack_timeout_ms,
                },
                "retry_after_seconds": request.retry_after_seconds,
            }));
        }

        let payload = request.payload.ok_or_else(|| {
            invalid_request("m365.notifications.ingest missing notification payload")
        })?;
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let result = Self::ingest_notification_payload(
            &state_path,
            &payload,
            request.expected_client_state.as_deref(),
            request.retry_after_seconds,
            request.ack_timeout_ms,
        );
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release m365 sync lease after notifications.ingest");
        }
        result
    }

    fn ingest_notification_payload(
        state_path: &Path,
        payload: &serde_json::Value,
        expected_client_state: Option<&str>,
        retry_after_seconds: Option<u64>,
        ack_timeout_ms: u64,
    ) -> FcpResult<serde_json::Value> {
        let notifications = payload
            .get("value")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                invalid_request("Graph notification payload must contain a value array")
            })?;
        if notifications.is_empty() {
            return Err(invalid_request(
                "Graph notification payload value array must not be empty",
            ));
        }

        let mut state = Self::load_sync_state(state_path)?;
        let parsed = notifications
            .iter()
            .map(|notification| {
                M365GraphNotification::parse(notification, &state, expected_client_state)
            })
            .collect::<FcpResult<Vec<_>>>()?;
        let now = current_unix_timestamp_secs();

        let mut accepted = Vec::new();
        let mut duplicates = Vec::new();
        let mut delta_handoffs = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut renewal_actions = Vec::new();

        for notification in parsed {
            if state
                .seen_notification_keys
                .contains_key(&notification.replay_key)
            {
                duplicates.push(json!({
                    "subscription_id": notification.subscription_id,
                    "replay_key": notification.replay_key,
                }));
                continue;
            }

            let delta_resource = notification_delta_resource(&notification, &state)?;
            if notification.change_type.is_some() {
                delta_handoffs.push(json!({
                    "operation": "m365.delta.sync",
                    "subscription_id": notification.subscription_id.clone(),
                    "resource": delta_resource,
                    "reason": notification.change_type.clone(),
                    "resource_id": notification.resource_id.clone(),
                    "tenant_id": notification.tenant_id.clone(),
                }));
            }
            if let Some(action) = lifecycle_action(&notification, &state)? {
                lifecycle_actions.push(action);
            }
            if renewal_due(notification.expiration_datetime.as_deref()) {
                renewal_actions.push(json!({
                    "operation": "m365.subscriptions.renew",
                    "subscription_id": notification.subscription_id.clone(),
                    "expiration_datetime": notification.expiration_datetime.clone(),
                }));
            }

            state
                .seen_notification_keys
                .insert(notification.replay_key.clone(), now);
            accepted.push(json!({
                "subscription_id": notification.subscription_id,
                "change_type": notification.change_type,
                "lifecycle_event": notification.lifecycle_event,
                "resource": notification.resource,
                "resource_id": notification.resource_id,
                "tenant_id": notification.tenant_id,
                "client_state_validated": !notification.client_state.is_empty(),
                "replay_key": notification.replay_key,
            }));
        }

        prune_notification_replay_cache(&mut state.seen_notification_keys);
        Self::persist_sync_state(state_path, &state)?;

        Ok(json!({
            "status": "accepted",
            "ack": {
                "http_status": 202,
                "content_type": "application/json",
                "timeout_ms": ack_timeout_ms,
            },
            "accepted": accepted,
            "duplicates": duplicates,
            "delta_handoffs": delta_handoffs,
            "lifecycle_actions": lifecycle_actions,
            "renewal_actions": renewal_actions,
            "retry_after_seconds": retry_after_seconds,
        }))
    }

    // ── Delta operation implementations ──────────────────────────

    async fn invoke_delta_sync(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let state_path = self.sync_state_path()?;
        let sync_lease = self.acquire_sync_lease()?;
        let resource = require_str(&input, "resource")?;
        let result = async {
            let mut state = Self::load_sync_state(&state_path)?;
            let effective_delta_token = input
                .get("delta_token")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .or_else(|| state.delta_tokens.get(resource).cloned());

            let result = client
                .delta_sync(resource, effective_delta_token.as_deref())
                .await
                .map_err(|e: M365Error| e.to_fcp_error())?;

            // Extract delta token from deltaLink if present
            let token = result
                .delta_link
                .as_deref()
                .and_then(|link| {
                    link.split("$deltatoken=")
                        .nth(1)
                        .map(std::string::ToString::to_string)
                })
                .unwrap_or_default();

            if !token.is_empty() {
                state
                    .delta_tokens
                    .insert(resource.to_string(), token.clone());
                Self::persist_sync_state(&state_path, &state)?;
            }

            Ok(json!({
                "changes": result.value,
                "delta_token": token,
            }))
        }
        .await;
        if let Err(err) = sync_lease.release() {
            warn!(error = %err, "Failed to release m365 sync lease after delta_sync");
        }
        result
    }

    /// Handle shutdown.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Microsoft 365 connector shutting down");
        if let Some(client) = &self.client {
            client.shutdown();
        }
        Ok(json!({ "status": "shutdown" }))
    }
}

fn parse_access_token(params: &serde_json::Value) -> Option<String> {
    let top_level = params
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);

    top_level.or_else(|| {
        params
            .get("oauth")
            .and_then(|oauth| oauth.get("access_token"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

fn parse_credential_id(params: &serde_json::Value) -> FcpResult<Option<CredentialId>> {
    let Some(raw) = params.get("credential_id") else {
        return Ok(None);
    };
    let raw = raw.as_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "credential_id must be a string".into(),
    })?;
    let parsed = CredentialId::parse(raw).map_err(|_| FcpError::InvalidRequest {
        code: 1003,
        message: "credential_id must be a valid UUID".into(),
    })?;
    Ok(Some(parsed))
}

fn parse_app_credentials(params: &serde_json::Value) -> FcpResult<Option<AppCredentialsConfig>> {
    let Some(raw) = params.get("app_credentials") else {
        return Ok(None);
    };
    let config: AppCredentialsConfig =
        serde_json::from_value(raw.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid app_credentials object: {e}"),
        })?;

    if config.tenant_id.trim().is_empty()
        || config.client_id.trim().is_empty()
        || config.client_secret.trim().is_empty()
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "app_credentials tenant_id, client_id, and client_secret are required".into(),
        });
    }

    Ok(Some(config))
}

fn parse_required_permissions(params: &serde_json::Value) -> FcpResult<Vec<String>> {
    let Some(raw) = params.get("required_permissions") else {
        return Ok(Vec::new());
    };
    let values = raw.as_array().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "required_permissions must be an array of strings".into(),
    })?;

    let mut required = Vec::new();
    for value in values {
        let permission = value.as_str().ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: "required_permissions entries must be strings".into(),
        })?;
        let permission = permission.trim();
        if permission.is_empty() {
            continue;
        }
        if !required.iter().any(|existing| existing == permission) {
            required.push(permission.to_string());
        }
    }
    Ok(required)
}

fn ensure_required_permissions(
    token_permissions: &TokenPermissions,
    required_permissions: &[String],
) -> FcpResult<()> {
    if required_permissions.is_empty() {
        return Ok(());
    }
    let missing = token_permissions.missing_required(required_permissions);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Token is missing required permissions: {}",
                missing.join(", ")
            ),
        })
    }
}

fn validate_endpoint(
    raw_url: &str,
    allowed_hosts: &[&str],
    allow_test_endpoints: bool,
    field_name: &str,
) -> FcpResult<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field_name} cannot be empty"),
        });
    }

    let parsed = reqwest::Url::parse(trimmed).map_err(|e| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {field_name}: {e}"),
    })?;

    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: format!("{field_name} must include a host"),
    })?;

    if !allow_test_endpoints && parsed.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field_name} must use https in production mode"),
        });
    }

    if host.parse::<std::net::IpAddr>().is_ok() && !allow_test_endpoints {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field_name} must not use an IP literal"),
        });
    }

    let host_lower = host.to_ascii_lowercase();
    let allowed = allowed_hosts
        .iter()
        .any(|allowed_host| host_lower == *allowed_host);
    if !(allowed || (allow_test_endpoints && is_local_test_host(&host_lower))) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "{field_name} host '{host}' is not allowed by connector NetworkConstraints"
            ),
        });
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

async fn exchange_client_credentials(
    auth_url: &str,
    config: &AppCredentialsConfig,
) -> FcpResult<String> {
    let token_endpoint = format!(
        "{}/{}/oauth2/v2.0/token",
        auth_url.trim_end_matches('/'),
        config.tenant_id
    );

    let form_body = encode_form_body(&[
        ("grant_type", "client_credentials"),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("scope", config.scope.as_str()),
    ]);

    let response = reqwest::Client::builder()
        .build()
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to build OAuth HTTP client: {e}"),
        })?
        .post(&token_endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body)
        .send()
        .await
        .map_err(|e| FcpError::External {
            service: "microsoft365_oauth".into(),
            message: e.to_string(),
            status_code: e.status().map(|status| status.as_u16()),
            retryable: e.is_timeout() || e.is_connect(),
            retry_after: None,
        })?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no-body>".to_string());
        return Err(FcpError::Unauthorized {
            code: 2001,
            message: format!(
                "Client credentials token exchange failed: HTTP {} ({})",
                status.as_u16(),
                body.chars().take(256).collect::<String>()
            ),
        });
    }

    let payload: OAuthTokenResponse =
        response
            .json()
            .await
            .map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("OAuth token response was invalid JSON: {e}"),
            })?;
    if payload.access_token.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "OAuth token response did not include access_token".into(),
        });
    }

    Ok(payload.access_token)
}

fn encode_form_body(params: &[(&str, &str)]) -> String {
    let mut body = String::new();
    for (index, (key, value)) in params.iter().enumerate() {
        if index > 0 {
            body.push('&');
        }

        append_form_component(&mut body, key);
        body.push('=');
        append_form_component(&mut body, value);
    }

    body
}

fn append_form_component(target: &mut String, value: &str) {
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                target.push(byte as char);
            }
            b' ' => target.push('+'),
            _ => {
                let _ = write!(target, "%{byte:02X}");
            }
        }
    }
}

impl Default for M365Connector {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_input<T>(value: serde_json::Value, operation: &str) -> FcpResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid {operation} input: {error}"),
    })
}

fn validate_non_empty(value: &str, field: &str) -> FcpResult<()> {
    if value.trim().is_empty() {
        return Err(invalid_request(format!("{field} must not be empty")));
    }
    Ok(())
}

fn validate_optional_non_empty(value: Option<&str>, field: &str) -> FcpResult<()> {
    if let Some(value) = value {
        validate_non_empty(value, field)?;
    }
    Ok(())
}

fn validate_max_chars(max_chars: Option<usize>) -> FcpResult<()> {
    if let Some(max_chars) = max_chars
        && !(1..=WORD_EXTRACT_MAX_CHARS_LIMIT).contains(&max_chars)
    {
        return Err(invalid_request(format!(
            "max_chars must be between 1 and {WORD_EXTRACT_MAX_CHARS_LIMIT}"
        )));
    }
    Ok(())
}

fn validate_export_format(format: &str) -> FcpResult<()> {
    if !format.eq_ignore_ascii_case("pdf") {
        return Err(invalid_request(
            "format must be 'pdf' for m365.word.export_document",
        ));
    }
    Ok(())
}

fn ensure_docx_path(path: &str, field: &str) -> FcpResult<()> {
    if path
        .rsplit('.')
        .next()
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("docx"))
    {
        return Err(invalid_request(format!(
            "{field} must end with .docx for Word document creation"
        )));
    }
    Ok(())
}

fn invalid_request(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    }
}

fn parse_drive_item(value: &serde_json::Value, operation: &str) -> FcpResult<DriveItem> {
    serde_json::from_value(value.clone()).map_err(|error| FcpError::Internal {
        message: format!("Failed to parse drive item for {operation}: {error}"),
    })
}

fn ensure_word_document(item: &DriveItem, operation: &str) -> FcpResult<WordDocumentMetadata> {
    if !item.is_word_document() {
        return Err(invalid_request(format!(
            "{operation} requires a Word-compatible document"
        )));
    }
    Ok(WordDocumentMetadata::from_drive_item(item))
}

fn ensure_text_extraction_supported(document: &WordDocumentMetadata) -> FcpResult<()> {
    if !document.supports_text_extraction {
        return Err(invalid_request(
            "Text extraction currently supports OOXML Word documents (.docx, .docm, .dotx, .dotm) only",
        ));
    }
    Ok(())
}

fn ensure_content_replace_supported(document: &WordDocumentMetadata) -> FcpResult<()> {
    if !document.supports_content_replace {
        return Err(invalid_request(
            "Content replacement currently supports .docx documents only",
        ));
    }
    Ok(())
}

fn enforce_word_document_size(
    document: &WordDocumentMetadata,
    max_bytes: usize,
    operation_label: &str,
) -> FcpResult<()> {
    let max_bytes = i64::try_from(max_bytes).map_err(|_| FcpError::Internal {
        message: format!("Document size limit {max_bytes} exceeds supported range"),
    })?;
    if let Some(size) = document.size
        && size > max_bytes
    {
        return Err(invalid_request(format!(
            "Document exceeds the {max_bytes}-byte limit for {operation_label}"
        )));
    }
    Ok(())
}

fn truncate_text(text: &str, max_chars: usize) -> (String, bool) {
    let total_chars = text.chars().count();
    if total_chars <= max_chars {
        return (text.to_string(), false);
    }

    let truncated = text.chars().take(max_chars).collect::<String>();
    (truncated, true)
}

fn is_docx_text_extractable_extension(extension: &str) -> bool {
    matches!(extension, "docx" | "docm" | "dotx" | "dotm")
}

fn build_docx_document(content: &str) -> FcpResult<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);
    {
        let mut archive = zip::ZipWriter::new(&mut cursor);

        let files = [
            (
                "[Content_Types].xml",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#,
            ),
            (
                "_rels/.rels",
                r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#,
            ),
        ];

        for (path, body) in files {
            archive
                .start_file(path, options)
                .map_err(|error| FcpError::Internal {
                    message: format!("Failed to start DOCX entry {path}: {error}"),
                })?;
            archive
                .write_all(body.as_bytes())
                .map_err(|error| FcpError::Internal {
                    message: format!("Failed to write DOCX entry {path}: {error}"),
                })?;
        }

        archive
            .start_file("word/document.xml", options)
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to start DOCX document.xml: {error}"),
            })?;
        archive
            .write_all(render_docx_document_xml(content).as_bytes())
            .map_err(|error| FcpError::Internal {
                message: format!("Failed to write DOCX document.xml: {error}"),
            })?;

        archive.finish().map_err(|error| FcpError::Internal {
            message: format!("Failed to finalize DOCX payload: {error}"),
        })?;
    }
    Ok(cursor.into_inner())
}

fn render_docx_document_xml(content: &str) -> String {
    let normalized = content.replace("\r\n", "\n").replace('\r', "\n");
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
 xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
 xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
 xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"
 xmlns:v="urn:schemas-microsoft-com:vml"
 xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing"
 xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
 xmlns:w10="urn:schemas-microsoft-com:office:word"
 xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"
 xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
 xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk"
 xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml"
 xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
 mc:Ignorable="w14 wp14"><w:body>"#,
    );

    if normalized.is_empty() {
        xml.push_str("<w:p/>");
    } else {
        for paragraph in normalized.split('\n') {
            if paragraph.is_empty() {
                xml.push_str("<w:p/>");
                continue;
            }

            xml.push_str("<w:p><w:r><w:t xml:space=\"preserve\">");
            xml.push_str(&escape_xml_text(paragraph));
            xml.push_str("</w:t></w:r></w:p>");
        }
    }

    xml.push_str("</w:body></w:document>");
    xml
}

fn escape_xml_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn extract_docx_text(bytes: &[u8]) -> FcpResult<String> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|error| {
        invalid_request(format!("Document is not a valid .docx package: {error}"))
    })?;
    let mut document_xml = String::new();
    archive
        .by_name("word/document.xml")
        .map_err(|error| {
            invalid_request(format!("Document is missing word/document.xml: {error}"))
        })?
        .read_to_string(&mut document_xml)
        .map_err(|error| invalid_request(format!("Failed to read word/document.xml: {error}")))?;

    let mut reader = Reader::from_reader(document_xml.as_bytes());
    reader.config_mut().trim_text(false);

    let mut buffer = Vec::new();
    let mut text = String::new();
    let mut paragraph_has_content = false;

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) if event.name().as_ref() == b"w:p" => {
                paragraph_has_content = false;
            }
            Ok(Event::End(event)) if event.name().as_ref() == b"w:p" => {
                if paragraph_has_content || !text.is_empty() {
                    text.push('\n');
                }
                paragraph_has_content = false;
            }
            Ok(Event::Empty(event)) if event.name().as_ref() == b"w:tab" => {
                text.push('\t');
                paragraph_has_content = true;
            }
            Ok(Event::Empty(event)) if matches!(event.name().as_ref(), b"w:br" | b"w:cr") => {
                text.push('\n');
                paragraph_has_content = true;
            }
            Ok(Event::Text(event)) => {
                let raw =
                    std::str::from_utf8(event.as_ref()).map_err(|error| FcpError::Internal {
                        message: format!("Invalid UTF-8 in Word document XML: {error}"),
                    })?;
                let decoded = unescape(raw).map_err(|error| FcpError::Internal {
                    message: format!("Invalid XML escape sequence in Word document XML: {error}"),
                })?;
                if !decoded.is_empty() {
                    text.push_str(decoded.as_ref());
                    paragraph_has_content = true;
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                return Err(FcpError::Internal {
                    message: format!("Failed to parse Word document XML: {error}"),
                });
            }
        }
        buffer.clear();
    }

    Ok(normalize_extracted_text(&text))
}

fn normalize_extracted_text(input: &str) -> String {
    let mut normalized = String::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !normalized.is_empty() {
            normalized.push('\n');
        }

        normalized.push_str(trimmed);
    }

    normalized
}

fn replace_extension(name: Option<&str>, new_extension: &str) -> Option<String> {
    let name = name?;
    let (stem, _) = name.rsplit_once('.')?;
    Some(format!("{stem}.{new_extension}"))
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

fn operation_info_for(operation: &str) -> FcpResult<OperationInfo> {
    build_operations()
        .into_iter()
        .find(|operation_info| operation_info.id.as_str() == operation)
        .ok_or_else(|| FcpError::OperationNotGranted {
            operation: operation.into(),
        })
}

fn required_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    Ok(operation_info_for(operation)?.capability)
}

fn input_has_required_fields(input: &serde_json::Value, required: &[serde_json::Value]) -> bool {
    required
        .iter()
        .filter_map(|field| field.as_str())
        .all(|field| input.get(field).is_some_and(|value| !value.is_null()))
}

fn validate_simulate_input(
    operation_info: &OperationInfo,
    input: &serde_json::Value,
) -> FcpResult<()> {
    let schema = &operation_info.input_schema;
    if let Some(required) = schema.get("required").and_then(|value| value.as_array())
        && !input_has_required_fields(input, required)
    {
        let fields = required
            .iter()
            .filter_map(|field| field.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "Missing required field for {}: {fields}",
                operation_info.id.as_str()
            ),
        });
    }

    if let Some(any_of) = schema.get("anyOf").and_then(|value| value.as_array()) {
        let required_groups = any_of
            .iter()
            .filter_map(|entry| entry.get("required").and_then(|value| value.as_array()))
            .collect::<Vec<_>>();
        if !required_groups.is_empty()
            && !required_groups
                .iter()
                .any(|required| input_has_required_fields(input, required))
        {
            let groups = required_groups
                .iter()
                .map(|required| {
                    required
                        .iter()
                        .filter_map(|field| field.as_str())
                        .collect::<Vec<_>>()
                        .join(" + ")
                })
                .collect::<Vec<_>>()
                .join(" or ");
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Missing one required field set for {}: {groups}",
                    operation_info.id.as_str()
                ),
            });
        }
    }

    Ok(())
}

fn build_operations() -> Vec<OperationInfo> {
    vec![
        // ── Mail operations ──────────────────────────────────────
        op_info(
            "m365.mail.list_messages",
            "List messages in a mailbox folder with optional filtering",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "folder_id": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "skip": { "type": "integer" },
                    "filter": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "messages": { "type": "array" } } }),
            "m365.mail.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List email messages in a user's mailbox. Supports OData filters for search.".into(),
                common_mistakes: vec![
                    "Not using $filter for targeted queries, resulting in large responses.".into(),
                    "Forgetting to handle @odata.nextLink for pagination.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "folder_id": "inbox", "top": 25}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.mail.get_message"),
                    CapabilityId::from_static("m365.mail.send_message"),
                ],
            },
        ),
        op_info(
            "m365.mail.get_message",
            "Get a specific email message with headers and body",
            json!({
                "type": "object",
                "required": ["user_id", "message_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
            "m365.mail.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read a specific email message by ID.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me", "message_id": "AAMkAG..."}"#.into()],
                related: vec![CapabilityId::from_static("m365.mail.list_messages")],
            },
        ),
        op_info(
            "m365.mail.send_message",
            "Send an email message",
            json!({
                "type": "object",
                "required": ["user_id", "message"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message": { "type": "object" }
                }
            }),
            json!({ "type": "object" }),
            "m365.mail.send",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Send an email via Outlook/Microsoft 365. Triggers real email delivery.".into(),
                common_mistakes: vec![
                    "Sending without confirming recipients with the user first.".into(),
                    "Not setting saveToSentItems to true (default is true, but be explicit).".into(),
                ],
                examples: vec![
                    r#"{"user_id": "me", "message": {"subject": "Hello", "body": {"contentType": "Text", "content": "Hi there"}, "toRecipients": [{"emailAddress": {"address": "bob@contoso.com"}}]}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("m365.mail.create_draft"),
                    CapabilityId::from_static("m365.mail.list_messages"),
                ],
            },
        ),
        op_info(
            "m365.mail.create_draft",
            "Create a draft email message",
            json!({
                "type": "object",
                "required": ["user_id", "message"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message": { "type": "object" }
                }
            }),
            json!({ "type": "object", "properties": { "message": { "type": "object" } } }),
            "m365.mail.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a draft email without sending it. Safer for review workflows.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me", "message": {"subject": "Draft", "body": {"contentType": "Text", "content": "Review before sending"}}}"#.into()],
                related: vec![CapabilityId::from_static("m365.mail.send_message")],
            },
        ),
        op_info(
            "m365.mail.search_messages",
            "Search email messages using Graph full-text query",
            json!({
                "type": "object",
                "required": ["user_id", "query"],
                "properties": {
                    "user_id": { "type": "string" },
                    "query": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "skip": { "type": "integer" }
                }
            }),
            json!({ "type": "object", "properties": { "messages": { "type": "array" } } }),
            "m365.mail.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Find messages by content/subject/sender using Graph search semantics."
                    .into(),
                common_mistakes: vec![
                    "Passing empty search queries that match everything.".into(),
                    "Ignoring pagination and truncating results.".into(),
                ],
                examples: vec![r#"{"user_id":"me","query":"incident report","top":25}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.mail.list_messages"),
                    CapabilityId::from_static("m365.mail.get_message"),
                ],
            },
        ),
        op_info(
            "m365.mail.list_threads",
            "List mailbox conversation threads grouped by conversation ID",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "folder_id": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "skip": { "type": "integer" },
                    "filter": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "threads": { "type": "array" },
                    "source_message_count": { "type": "integer" }
                }
            }),
            "m365.mail.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use:
                    "Summarize mailbox conversations before drilling into individual messages."
                        .into(),
                common_mistakes: vec![
                    "Assuming conversation ordering is stable without checking timestamps.".into(),
                ],
                examples: vec![r#"{"user_id":"me","folder_id":"inbox","top":100}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.mail.list_messages"),
                    CapabilityId::from_static("m365.mail.get_message"),
                ],
            },
        ),
        op_info(
            "m365.mail.reply_message",
            "Reply to an existing message",
            json!({
                "type": "object",
                "required": ["user_id", "message_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message_id": { "type": "string" },
                    "comment": { "type": "string" },
                    "message": { "type": "object" }
                },
                "anyOf": [
                    { "required": ["comment"] },
                    { "required": ["message"] }
                ]
            }),
            json!({ "type": "object", "properties": { "status": { "type": "string" } } }),
            "m365.mail.send",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Reply to a specific email thread.".into(),
                common_mistakes: vec![
                    "Replying without confirming recipients and quoted content.".into(),
                ],
                examples: vec![
                    r#"{"user_id":"me","message_id":"AAMkAG...","comment":"Thanks, will do."}"#
                        .into(),
                ],
                related: vec![
                    CapabilityId::from_static("m365.mail.get_message"),
                    CapabilityId::from_static("m365.mail.forward_message"),
                ],
            },
        ),
        op_info(
            "m365.mail.forward_message",
            "Forward an existing message to new recipients",
            json!({
                "type": "object",
                "required": ["user_id", "message_id", "to_recipients"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message_id": { "type": "string" },
                    "comment": { "type": "string" },
                    "to_recipients": { "type": "array" }
                }
            }),
            json!({ "type": "object", "properties": { "status": { "type": "string" } } }),
            "m365.mail.send",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Forward a message while preserving original context.".into(),
                common_mistakes: vec![
                    "Forwarding sensitive content without redaction review.".into(),
                    "Omitting recipients in to_recipients.".into(),
                ],
                examples: vec![
                    r#"{"user_id":"me","message_id":"AAMkAG...","to_recipients":[{"emailAddress":{"address":"ops@contoso.com"}}]}"#
                        .into(),
                ],
                related: vec![
                    CapabilityId::from_static("m365.mail.get_message"),
                    CapabilityId::from_static("m365.mail.reply_message"),
                ],
            },
        ),
        op_info(
            "m365.mail.list_attachments",
            "List attachments for a message",
            json!({
                "type": "object",
                "required": ["user_id", "message_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message_id": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "skip": { "type": "integer" }
                }
            }),
            json!({ "type": "object", "properties": { "attachments": { "type": "array" } } }),
            "m365.mail.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Inspect message attachments before download or forwarding.".into(),
                common_mistakes: vec![
                    "Assuming attachment list is complete without pagination.".into(),
                ],
                examples: vec![r#"{"user_id":"me","message_id":"AAMkAG..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.mail.get_message"),
                    CapabilityId::from_static("m365.mail.add_attachment"),
                ],
            },
        ),
        op_info(
            "m365.mail.add_attachment",
            "Attach a file/item to an existing message or draft",
            json!({
                "type": "object",
                "required": ["user_id", "message_id", "attachment"],
                "properties": {
                    "user_id": { "type": "string" },
                    "message_id": { "type": "string" },
                    "attachment": { "type": "object" }
                }
            }),
            json!({ "type": "object", "properties": { "attachment": { "type": "object" } } }),
            "m365.mail.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Add a prepared attachment to a draft before sending.".into(),
                common_mistakes: vec![
                    "Passing non-Graph attachment payloads without @odata.type.".into(),
                ],
                examples: vec![
                    r##"{"user_id":"me","message_id":"AAMkAG...","attachment":{"@odata.type":"#microsoft.graph.fileAttachment","name":"report.pdf","contentBytes":"dGVzdA=="}}"##
                        .into(),
                ],
                related: vec![
                    CapabilityId::from_static("m365.mail.list_attachments"),
                    CapabilityId::from_static("m365.mail.send_message"),
                ],
            },
        ),
        // ── Files operations ─────────────────────────────────────
        op_info(
            "m365.files.list_items",
            "List files and folders in a OneDrive path or drive root",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "path": { "type": "string" },
                    "drive_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "items": { "type": "array" } } }),
            "m365.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Browse files and folders in OneDrive or SharePoint document libraries.".into(),
                common_mistakes: vec!["Not handling pagination for large directories.".into()],
                examples: vec![r#"{"user_id": "me", "path": "/Documents"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.download_file"),
                    CapabilityId::from_static("m365.files.upload_file"),
                ],
            },
        ),
        op_info(
            "m365.files.download_file",
            "Download a file from OneDrive",
            json!({
                "type": "object",
                "required": ["user_id", "item_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["content"],
                "properties": {
                    "content": { "type": "string" },
                    "name": { "type": "string" },
                    "size": { "type": "integer" }
                }
            }),
            "m365.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Download a file from OneDrive by item ID.".into(),
                common_mistakes: vec!["Downloading very large files without checking size first.".into()],
                examples: vec![r#"{"user_id": "me", "item_id": "01ABCDEF..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.list_items"),
                    CapabilityId::from_static("m365.files.upload_file"),
                ],
            },
        ),
        op_info(
            "m365.files.upload_file",
            "Upload a file to OneDrive (simple upload for files up to 4 MB)",
            json!({
                "type": "object",
                "required": ["user_id", "path", "content"],
                "properties": {
                    "user_id": { "type": "string" },
                    "path": { "type": "string" },
                    "content": { "type": "string" },
                    "conflict_behavior": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "item": { "type": "object" } } }),
            "m365.files.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Upload a file to OneDrive. For files >4 MB, use a resumable upload session.".into(),
                common_mistakes: vec![
                    "Uploading files >4 MB via simple upload (use upload session instead).".into(),
                    "Not specifying conflict_behavior, which defaults to fail on existing files.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "path": "/Documents/notes.txt", "content": "SGVsbG8gV29ybGQ="}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.download_file"),
                    CapabilityId::from_static("m365.files.list_items"),
                ],
            },
        ),
        op_info(
            "m365.files.delete_item",
            "Delete a file or folder from OneDrive",
            json!({
                "type": "object",
                "required": ["user_id", "item_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "m365.files.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Permanently delete a file or folder. Items go to the recycle bin first.".into(),
                common_mistakes: vec!["Deleting folders with contents without user confirmation.".into()],
                examples: vec![r#"{"user_id": "me", "item_id": "01ABCDEF..."}"#.into()],
                related: vec![CapabilityId::from_static("m365.files.list_items")],
            },
        ),
        op_info(
            "m365.files.get_item",
            "Get metadata for a single file or folder by ID",
            json!({
                "type": "object",
                "required": ["user_id", "item_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User principal name or 'me'" },
                    "item_id": { "type": "string", "description": "Drive item ID" }
                }
            }),
            json!({ "type": "object", "required": ["item"], "properties": { "item": { "type": "object" } } }),
            "m365.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Get full metadata for a specific file or folder by item ID.".into(),
                common_mistakes: vec!["Using a stale item_id after the item has been moved or deleted.".into()],
                examples: vec![r#"{"user_id": "me", "item_id": "01ABCDEF..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.list_items"),
                    CapabilityId::from_static("m365.files.download_file"),
                ],
            },
        ),
        op_info(
            "m365.files.search",
            "Search for files and folders in OneDrive",
            json!({
                "type": "object",
                "required": ["user_id", "query"],
                "properties": {
                    "user_id": { "type": "string", "description": "User principal name or 'me'" },
                    "query": { "type": "string", "description": "Search query string" }
                }
            }),
            json!({ "type": "object", "required": ["items"], "properties": { "items": { "type": "array" } } }),
            "m365.files.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Search for files by name, content, or metadata across OneDrive.".into(),
                common_mistakes: vec!["Using overly broad queries that return too many results.".into()],
                examples: vec![r#"{"user_id": "me", "query": "quarterly report"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.list_items"),
                    CapabilityId::from_static("m365.files.get_item"),
                ],
            },
        ),
        op_info(
            "m365.files.create_share_link",
            "Create a sharing link for a file or folder",
            json!({
                "type": "object",
                "required": ["user_id", "item_id", "type"],
                "properties": {
                    "user_id": { "type": "string", "description": "User principal name or 'me'" },
                    "item_id": { "type": "string", "description": "Drive item ID to share" },
                    "type": { "type": "string", "description": "Link type: view, edit, or embed" },
                    "scope": { "type": "string", "description": "Link scope: anonymous or organization" }
                }
            }),
            json!({ "type": "object", "required": ["link"], "properties": { "link": { "type": "object" } } }),
            "m365.files.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a shareable link for a file or folder. Grants access to anyone with the link.".into(),
                common_mistakes: vec![
                    "Creating anonymous links without user confirmation (exposes data externally).".into(),
                    "Not distinguishing between view and edit links.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "item_id": "01ABCDEF...", "type": "view", "scope": "organization"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.files.get_item"),
                    CapabilityId::from_static("m365.files.list_items"),
                ],
            },
        ),
        // ── Word operations ──────────────────────────────────────
        op_info(
            "m365.word.list_documents",
            "List Word-compatible documents in a OneDrive path",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "path": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["documents"],
                "properties": {
                    "documents": { "type": "array" }
                }
            }),
            "m365.word.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Find Word-compatible documents in a OneDrive folder before extracting or exporting content.".into(),
                common_mistakes: vec![
                    "Assuming every drive item is a document; folders are filtered out automatically.".into(),
                    "Forgetting that legacy .doc files are exportable but not directly text-extractable.".into(),
                ],
                examples: vec![r#"{"user_id":"me","path":"/Documents"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.word.get_document"),
                    CapabilityId::from_static("m365.word.extract_text"),
                ],
            },
        ),
        op_info(
            "m365.word.get_document",
            "Get metadata for a Word-compatible document",
            json!({
                "type": "object",
                "required": ["user_id", "item_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["document"],
                "properties": {
                    "document": { "type": "object" }
                }
            }),
            "m365.word.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Inspect a single Word document to confirm its type and supported operations.".into(),
                common_mistakes: vec![
                    "Passing a non-document item_id such as a folder.".into(),
                ],
                examples: vec![r#"{"user_id":"me","item_id":"01ABCDEF..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.word.list_documents"),
                    CapabilityId::from_static("m365.word.export_document"),
                ],
            },
        ),
        op_info(
            "m365.word.extract_text",
            "Extract bounded plain text from a supported Word document",
            json!({
                "type": "object",
                "required": ["user_id", "item_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" },
                    "max_chars": { "type": "integer", "minimum": 1, "maximum": WORD_EXTRACT_MAX_CHARS_LIMIT }
                }
            }),
            json!({
                "type": "object",
                "required": ["document", "text", "truncated", "extracted_chars"],
                "properties": {
                    "document": { "type": "object" },
                    "text": { "type": "string" },
                    "truncated": { "type": "boolean" },
                    "extracted_chars": { "type": "integer" }
                }
            }),
            "m365.word.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read document body text without exposing the original binary payload.".into(),
                common_mistakes: vec![
                    "Using extract_text for legacy .doc files; this operation only parses OOXML packages.".into(),
                    "Requesting unbounded output instead of setting max_chars for large documents.".into(),
                ],
                examples: vec![r#"{"user_id":"me","item_id":"01ABCDEF...","max_chars":4000}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.word.get_document"),
                    CapabilityId::from_static("m365.word.export_document"),
                ],
            },
        ),
        op_info(
            "m365.word.create_document",
            "Create a new .docx document from plain text content",
            json!({
                "type": "object",
                "required": ["user_id", "path", "content"],
                "properties": {
                    "user_id": { "type": "string" },
                    "path": { "type": "string", "description": "Destination path ending in .docx" },
                    "content": { "type": "string", "description": "Plain text document body" }
                }
            }),
            json!({
                "type": "object",
                "required": ["document", "audit"],
                "properties": {
                    "document": { "type": "object" },
                    "audit": { "type": "object" }
                }
            }),
            "m365.word.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Create a Word document when the user explicitly wants new persistent content written to OneDrive.".into(),
                common_mistakes: vec![
                    "Omitting the .docx extension in path.".into(),
                    "Writing sensitive content without confirming the destination folder.".into(),
                ],
                examples: vec![r#"{"user_id":"me","path":"/Documents/meeting-notes.docx","content":"Agenda\n- Introductions\n- Risks"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.word.update_document"),
                    CapabilityId::from_static("m365.word.list_documents"),
                ],
            },
        ),
        op_info(
            "m365.word.update_document",
            "Replace the contents of an existing .docx document",
            json!({
                "type": "object",
                "required": ["user_id", "item_id", "content"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" },
                    "content": { "type": "string", "description": "Plain text document body" }
                }
            }),
            json!({
                "type": "object",
                "required": ["document", "audit"],
                "properties": {
                    "document": { "type": "object" },
                    "audit": { "type": "object" }
                }
            }),
            "m365.word.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Replace a Word document body when the user wants a full-content rewrite.".into(),
                common_mistakes: vec![
                    "Attempting to update legacy .doc files; content replacement is limited to .docx.".into(),
                    "Overwriting a document without first confirming the target item_id.".into(),
                ],
                examples: vec![r#"{"user_id":"me","item_id":"01ABCDEF...","content":"Updated draft\n\nApproved."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.word.get_document"),
                    CapabilityId::from_static("m365.word.extract_text"),
                ],
            },
        ),
        op_info(
            "m365.word.export_document",
            "Export a Word-compatible document to PDF",
            json!({
                "type": "object",
                "required": ["user_id", "item_id", "format"],
                "properties": {
                    "user_id": { "type": "string" },
                    "item_id": { "type": "string" },
                    "format": { "type": "string", "enum": ["pdf"] }
                }
            }),
            json!({
                "type": "object",
                "required": ["document", "format", "name", "size", "content"],
                "properties": {
                    "document": { "type": "object" },
                    "format": { "type": "string" },
                    "name": { "type": "string" },
                    "size": { "type": "integer" },
                    "content": { "type": "string" }
                }
            }),
            "m365.word.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Convert a Word document into PDF bytes for downstream review or delivery.".into(),
                common_mistakes: vec![
                    "Assuming export preserves editable Word structure; PDF is read-only output.".into(),
                    "Ignoring response size when exporting large documents.".into(),
                ],
                examples: vec![r#"{"user_id":"me","item_id":"01ABCDEF...","format":"pdf"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.word.get_document"),
                    CapabilityId::from_static("m365.word.extract_text"),
                ],
            },
        ),
        // ── OneNote operations ───────────────────────────────────
        op_info(
            "m365.onenote.list_notebooks",
            "List OneNote notebooks for a user",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 100 }
                }
            }),
            json!({ "type": "object", "properties": { "notebooks": { "type": "array" } } }),
            "m365.onenote.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Discover available OneNote notebooks before drilling into sections or pages.".into(),
                common_mistakes: vec![
                    "Skipping notebook discovery and guessing notebook IDs.".into(),
                    "Requesting more than 100 notebooks in a single page.".into(),
                ],
                examples: vec![r#"{"user_id":"me","top":25}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.onenote.list_sections"),
                    CapabilityId::from_static("m365.onenote.list_pages"),
                ],
            },
        ),
        op_info(
            "m365.onenote.list_sections",
            "List OneNote sections, optionally scoped to a notebook or section group",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "notebook_id": { "type": "string" },
                    "section_group_id": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 100 }
                }
            }),
            json!({ "type": "object", "properties": { "sections": { "type": "array" } } }),
            "m365.onenote.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Enumerate sections inside a OneNote notebook or section group.".into(),
                common_mistakes: vec![
                    "Confusing notebook IDs with section IDs.".into(),
                    "Expecting list_sections to return page content.".into(),
                ],
                examples: vec![r#"{"user_id":"me","notebook_id":"notebook-123","top":50}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.onenote.list_notebooks"),
                    CapabilityId::from_static("m365.onenote.list_pages"),
                ],
            },
        ),
        op_info(
            "m365.onenote.list_pages",
            "List OneNote pages in a section",
            json!({
                "type": "object",
                "required": ["user_id", "section_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "section_id": { "type": "string" },
                    "top": { "type": "integer", "minimum": 1, "maximum": 100 }
                }
            }),
            json!({ "type": "object", "properties": { "pages": { "type": "array" } } }),
            "m365.onenote.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List note pages within a specific OneNote section.".into(),
                common_mistakes: vec![
                    "Passing a notebook ID where a section ID is required.".into(),
                    "Ignoring page-level pagination when sections are large.".into(),
                ],
                examples: vec![r#"{"user_id":"me","section_id":"section-123","top":25}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.onenote.list_sections"),
                    CapabilityId::from_static("m365.onenote.get_page"),
                ],
            },
        ),
        op_info(
            "m365.onenote.get_page",
            "Get OneNote page metadata by page ID",
            json!({
                "type": "object",
                "required": ["user_id", "page_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "page_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
            "m365.onenote.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Fetch metadata for a OneNote page before reading or updating content.".into(),
                common_mistakes: vec![
                    "Expecting get_page to include the HTML body; use get_page_content for that.".into(),
                ],
                examples: vec![r#"{"user_id":"me","page_id":"page-123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.onenote.get_page_content"),
                    CapabilityId::from_static("m365.onenote.update_page"),
                ],
            },
        ),
        op_info(
            "m365.onenote.get_page_content",
            "Get OneNote page HTML content with extracted plain text",
            json!({
                "type": "object",
                "required": ["user_id", "page_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "page_id": { "type": "string" },
                    "include_ids": { "type": "boolean" }
                }
            }),
            json!({
                "type": "object",
                "properties": {
                    "page_content": {
                        "type": "object",
                        "properties": {
                            "html": { "type": "string" },
                            "plain_text": { "type": "string" }
                        }
                    }
                }
            }),
            "m365.onenote.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Read the actual HTML body of a OneNote page and get a plain-text extract for LLM-friendly consumption.".into(),
                common_mistakes: vec![
                    "Assuming the extracted plain_text preserves every formatting detail.".into(),
                    "Forgetting include_ids when downstream HTML patch targets need stable DOM IDs.".into(),
                ],
                examples: vec![r#"{"user_id":"me","page_id":"page-123","include_ids":true}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.onenote.get_page"),
                    CapabilityId::from_static("m365.onenote.update_page"),
                ],
            },
        ),
        op_info(
            "m365.onenote.create_page",
            "Create a OneNote page in a section from HTML content",
            json!({
                "type": "object",
                "required": ["user_id", "section_id", "html"],
                "properties": {
                    "user_id": { "type": "string" },
                    "section_id": { "type": "string" },
                    "html": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
            "m365.onenote.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a new OneNote page when you already have the full HTML payload to submit.".into(),
                common_mistakes: vec![
                    "Passing fragmentary text instead of valid page HTML.".into(),
                    "Creating pages in the wrong section because section discovery was skipped.".into(),
                ],
                examples: vec![r#"{"user_id":"me","section_id":"section-123","html":"<html><body><p>Daily notes</p></body></html>"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.onenote.list_sections"),
                    CapabilityId::from_static("m365.onenote.update_page"),
                ],
            },
        ),
        op_info(
            "m365.onenote.update_page",
            "Patch OneNote page content using Graph content commands",
            json!({
                "type": "object",
                "required": ["user_id", "page_id", "commands"],
                "properties": {
                    "user_id": { "type": "string" },
                    "page_id": { "type": "string" },
                    "commands": { "type": "array" }
                }
            }),
            json!({ "type": "object", "properties": { "status": { "type": "string" } } }),
            "m365.onenote.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Apply targeted content changes to an existing OneNote page without recreating it.".into(),
                common_mistakes: vec![
                    "Sending an empty commands array.".into(),
                    "Using unstable targets because get_page_content was fetched without include_ids.".into(),
                ],
                examples: vec![r#"{"user_id":"me","page_id":"page-123","commands":[{"target":"body","action":"append","content":"<p>Follow-up</p>"}]}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.onenote.get_page_content"),
                    CapabilityId::from_static("m365.onenote.create_page"),
                ],
            },
        ),
        // ── Calendar operations ──────────────────────────────────
        op_info(
            "m365.calendar.list_events",
            "List calendar events within a time range",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "start_datetime": { "type": "string" },
                    "end_datetime": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "events": { "type": "array" } } }),
            "m365.calendar.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List calendar events. Use calendarView for expanded recurring events.".into(),
                common_mistakes: vec![
                    "Not using calendarView endpoint for recurring events (list only returns master events).".into(),
                    "Querying unbounded time ranges.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "start_datetime": "2026-03-01T00:00:00Z", "end_datetime": "2026-03-08T00:00:00Z"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.create_event"),
                    CapabilityId::from_static("m365.calendar.get_freebusy"),
                ],
            },
        ),
        op_info(
            "m365.calendar.create_event",
            "Create a calendar event with optional attendees",
            json!({
                "type": "object",
                "required": ["user_id", "subject", "start", "end"],
                "properties": {
                    "user_id": { "type": "string" },
                    "subject": { "type": "string" },
                    "start": { "type": "object" },
                    "end": { "type": "object" },
                    "body": { "type": "object" },
                    "location": { "type": "object" },
                    "attendees": { "type": "array" }
                }
            }),
            json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
            "m365.calendar.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a calendar event. Adding attendees sends meeting invitations.".into(),
                common_mistakes: vec![
                    "Adding attendees without user confirmation (sends real meeting invites).".into(),
                    "Not specifying timeZone in start/end objects.".into(),
                ],
                examples: vec![r#"{"user_id": "me", "subject": "Team Standup", "start": {"dateTime": "2026-03-03T09:00:00", "timeZone": "America/Chicago"}, "end": {"dateTime": "2026-03-03T09:30:00", "timeZone": "America/Chicago"}}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.list_events"),
                    CapabilityId::from_static("m365.calendar.delete_event"),
                ],
            },
        ),
        op_info(
            "m365.calendar.delete_event",
            "Delete a calendar event",
            json!({
                "type": "object",
                "required": ["user_id", "event_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "event_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "m365.calendar.write",
            RiskLevel::High,
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Delete a calendar event. Sends cancellation notices to attendees.".into(),
                common_mistakes: vec!["Deleting recurring event master instead of a single instance.".into()],
                examples: vec![r#"{"user_id": "me", "event_id": "AAMkAG..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.list_events"),
                    CapabilityId::from_static("m365.calendar.create_event"),
                ],
            },
        ),
        op_info(
            "m365.calendar.get_event",
            "Get a single calendar event by ID",
            json!({
                "type": "object",
                "required": ["user_id", "event_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User principal name or 'me'" },
                    "event_id": { "type": "string", "description": "Event ID" }
                }
            }),
            json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
            "m365.calendar.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Retrieve full details of a specific calendar event.".into(),
                common_mistakes: vec!["Using display name instead of user principal name for user_id.".into()],
                examples: vec![r#"{"user_id": "me", "event_id": "AAMkAGI2..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.list_events"),
                    CapabilityId::from_static("m365.calendar.update_event"),
                ],
            },
        ),
        op_info(
            "m365.calendar.update_event",
            "Update an existing calendar event",
            json!({
                "type": "object",
                "required": ["user_id", "event_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User principal name or 'me'" },
                    "event_id": { "type": "string", "description": "Event ID to update" },
                    "subject": { "type": "string", "description": "New event subject" },
                    "body": { "type": "object", "description": "New event body" },
                    "start": { "type": "object", "description": "New start time" },
                    "end": { "type": "object", "description": "New end time" },
                    "location": { "type": "object", "description": "New location" }
                }
            }),
            json!({ "type": "object", "properties": { "event": { "type": "object" } } }),
            "m365.calendar.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Update fields of an existing calendar event. Only specified fields are changed.".into(),
                common_mistakes: vec!["Forgetting to include the event_id.".into()],
                examples: vec![r#"{"user_id": "me", "event_id": "AAMkAGI2...", "subject": "Updated Meeting"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.get_event"),
                    CapabilityId::from_static("m365.calendar.create_event"),
                ],
            },
        ),
        op_info(
            "m365.calendar.get_freebusy",
            "Check free/busy availability for one or more users",
            json!({
                "type": "object",
                "required": ["schedules", "start_time", "end_time"],
                "properties": {
                    "schedules": { "type": "array" },
                    "start_time": { "type": "object" },
                    "end_time": { "type": "object" }
                }
            }),
            json!({ "type": "object", "properties": { "schedules": { "type": "array" } } }),
            "m365.calendar.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Check when users are free or busy to schedule meetings.".into(),
                common_mistakes: vec!["Querying too many schedules at once (max 20 per request).".into()],
                examples: vec![r#"{"schedules": ["alice@contoso.com"], "start_time": {"dateTime": "2026-03-03T08:00:00", "timeZone": "UTC"}, "end_time": {"dateTime": "2026-03-03T18:00:00", "timeZone": "UTC"}}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.calendar.create_event"),
                    CapabilityId::from_static("m365.calendar.list_events"),
                ],
            },
        ),
        // ── Tasks operations ─────────────────────────────────────
        op_info(
            "m365.tasks.list_task_lists",
            "List all To Do task lists",
            json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "task_lists": { "type": "array" } } }),
            "m365.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List all To Do task lists for a user.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me"}"#.into()],
                related: vec![CapabilityId::from_static("m365.tasks.list_tasks")],
            },
        ),
        op_info(
            "m365.tasks.list_tasks",
            "List tasks in a To Do task list",
            json!({
                "type": "object",
                "required": ["user_id", "task_list_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "task_list_id": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "tasks": { "type": "array" } } }),
            "m365.tasks.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "List tasks from a Microsoft To Do list.".into(),
                common_mistakes: vec!["Not listing task lists first to get the correct task_list_id.".into()],
                examples: vec![r#"{"user_id": "me", "task_list_id": "AAMkAG..."}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.tasks.create_task"),
                    CapabilityId::from_static("m365.tasks.list_task_lists"),
                ],
            },
        ),
        op_info(
            "m365.tasks.create_task",
            "Create a new task in a To Do list",
            json!({
                "type": "object",
                "required": ["user_id", "task_list_id", "title"],
                "properties": {
                    "user_id": { "type": "string" },
                    "task_list_id": { "type": "string" },
                    "title": { "type": "string" },
                    "body": { "type": "object" },
                    "due_datetime": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "task": { "type": "object" } } }),
            "m365.tasks.write",
            RiskLevel::Low,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Create a task in Microsoft To Do.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"user_id": "me", "task_list_id": "AAMkAG...", "title": "Review PR #42", "due_datetime": "2026-03-05T17:00:00Z"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.tasks.list_tasks"),
                    CapabilityId::from_static("m365.tasks.list_task_lists"),
                ],
            },
        ),
        // ── Subscription operations ──────────────────────────────
        op_info(
            "m365.subscriptions.create",
            "Create a Graph API webhook subscription for change notifications",
            json!({
                "type": "object",
                "required": ["change_type", "notification_url", "resource", "expiration_datetime"],
                "properties": {
                    "change_type": { "type": "string" },
                    "client_state": { "type": "string" },
                    "notification_url": { "type": "string" },
                    "resource": { "type": "string" },
                    "expiration_datetime": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "subscription": { "type": "object" } } }),
            "m365.subscriptions.write",
            RiskLevel::Medium,
            SafetyTier::Risky,
            IdempotencyClass::None,
            AgentHint {
                when_to_use: "Subscribe to change notifications for mail, calendar, files, etc.".into(),
                common_mistakes: vec![
                    "Not implementing the validation endpoint that Graph calls during creation.".into(),
                    "Setting expirationDateTime beyond the resource's max (e.g., 4230 min for messages).".into(),
                ],
                examples: vec![r#"{"change_type": "created,updated", "notification_url": "https://webhook.example.com/m365", "resource": "/me/messages", "expiration_datetime": "2026-03-04T00:00:00Z"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.subscriptions.renew"),
                    CapabilityId::from_static("m365.subscriptions.delete"),
                ],
            },
        ),
        op_info(
            "m365.subscriptions.renew",
            "Renew (extend) a Graph API webhook subscription before it expires",
            json!({
                "type": "object",
                "required": ["subscription_id", "expiration_datetime"],
                "properties": {
                    "subscription_id": { "type": "string" },
                    "expiration_datetime": { "type": "string" }
                }
            }),
            json!({ "type": "object", "properties": { "subscription": { "type": "object" } } }),
            "m365.subscriptions.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Renew a webhook subscription before it expires to maintain continuous notifications.".into(),
                common_mistakes: vec!["Letting subscriptions expire; implement proactive renewal timers.".into()],
                examples: vec![r#"{"subscription_id": "sub-123", "expiration_datetime": "2026-03-07T00:00:00Z"}"#.into()],
                related: vec![CapabilityId::from_static("m365.subscriptions.create")],
            },
        ),
        op_info(
            "m365.subscriptions.delete",
            "Delete a Graph API webhook subscription",
            json!({
                "type": "object",
                "required": ["subscription_id"],
                "properties": {
                    "subscription_id": { "type": "string" }
                }
            }),
            json!({ "type": "object" }),
            "m365.subscriptions.write",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Remove a webhook subscription when no longer needed.".into(),
                common_mistakes: vec![],
                examples: vec![r#"{"subscription_id": "sub-123"}"#.into()],
                related: vec![
                    CapabilityId::from_static("m365.subscriptions.create"),
                    CapabilityId::from_static("m365.subscriptions.renew"),
                ],
            },
        ),
        // ── Notification ingress operations ─────────────────────
        op_info(
            "m365.notifications.ingest",
            "Process a host-forwarded Microsoft Graph notification or validation challenge",
            json!({
                "type": "object",
                "properties": {
                    "validation_token": { "type": "string" },
                    "validationToken": { "type": "string" },
                    "query": { "type": "object" },
                    "payload": { "type": "object" },
                    "body": { "type": "object" },
                    "expected_client_state": { "type": "string" },
                    "retry_after_seconds": { "type": "integer", "minimum": 0 },
                    "headers": { "type": "object" },
                    "ack_timeout_ms": { "type": "integer", "minimum": 0 },
                    "cancelled": { "type": "boolean" }
                },
                "anyOf": [
                    { "required": ["validation_token"] },
                    { "required": ["validationToken"] },
                    { "required": ["query"] },
                    { "required": ["payload"] },
                    { "required": ["body"] }
                ]
            }),
            json!({
                "type": "object",
                "required": ["status", "ack"],
                "properties": {
                    "status": { "type": "string" },
                    "ack": { "type": "object" },
                    "accepted": { "type": "array" },
                    "duplicates": { "type": "array" },
                    "delta_handoffs": { "type": "array" },
                    "lifecycle_actions": { "type": "array" },
                    "renewal_actions": { "type": "array" },
                    "retry_after_seconds": { "type": ["integer", "null"] }
                }
            }),
            "m365.notifications.ingest",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::BestEffort,
            AgentHint {
                when_to_use: "Use when the host has already accepted a Microsoft Graph webhook request and needs the connector to validate clientState, suppress duplicate notifications, and schedule delta handoff work.".into(),
                common_mistakes: vec![
                    "Letting the connector listen on a public socket; this operation is host-forwarded and keeps network.listen forbidden.".into(),
                    "Processing notifications before validating clientState against the persisted subscription secret.".into(),
                    "Treating resource change payloads as complete state instead of using m365.delta.sync for the authoritative catch-up.".into(),
                ],
                examples: vec![
                    r#"{"validation_token": "opaque-token-from-query"}"#.into(),
                    r#"{"payload": {"value": [{"subscriptionId": "sub-123", "clientState": "secret", "changeType": "updated", "resource": "/me/messages/msg-1", "resourceData": {"id": "msg-1"}}]}}"#.into(),
                ],
                related: vec![
                    CapabilityId::from_static("m365.subscriptions.create"),
                    CapabilityId::from_static("m365.delta.sync"),
                ],
            },
        ),
        // ── Delta operations ─────────────────────────────────────
        op_info(
            "m365.delta.sync",
            "Perform incremental delta query to get changes since last sync",
            json!({
                "type": "object",
                "required": ["resource"],
                "properties": {
                    "resource": { "type": "string" },
                    "delta_token": { "type": "string" }
                }
            }),
            json!({
                "type": "object",
                "required": ["changes", "delta_token"],
                "properties": {
                    "changes": { "type": "array" },
                    "delta_token": { "type": "string" }
                }
            }),
            "m365.delta.read",
            RiskLevel::Low,
            SafetyTier::Safe,
            IdempotencyClass::Strict,
            AgentHint {
                when_to_use: "Incrementally sync changes for mail, calendar, or files since last sync.".into(),
                common_mistakes: vec![
                    "Not persisting delta_token between syncs (forces full re-sync).".into(),
                    "Not handling @removed items in the delta response.".into(),
                ],
                examples: vec![
                    r#"{"resource": "/me/messages"}"#.into(),
                    r#"{"resource": "/me/events", "delta_token": "opaquetoken123"}"#.into(),
                ],
                related: vec![CapabilityId::from_static("m365.subscriptions.create")],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityConstraints, ZoneId};
    use std::path::PathBuf;
    use uuid::Uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    fn generate_valid_token(
        signing_key: &Ed25519SigningKey,
        connector: &M365Connector,
        op: &str,
    ) -> CapabilityToken {
        let cap = required_capability_for_operation(op).map_or_else(
            |_| "m365.mail.read".to_string(),
            |capability| capability.as_str().to_string(),
        );
        generate_token_with_cap(signing_key, connector, cap.as_str(), &[op])
    }

    fn generate_token_with_cap(
        signing_key: &Ed25519SigningKey,
        connector: &M365Connector,
        cap: &str,
        operations: &[&str],
    ) -> CapabilityToken {
        let now = Utc::now();
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
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .target_instance(connector.base.instance_id.as_str())
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        operation: &'static str,
        input: serde_json::Value,
        capability: CapabilityToken,
    ) -> serde_json::Value {
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("fcp.microsoft365"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            capability,
        ))
        .unwrap()
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).unwrap()
    }

    async fn configured_m365_connector() -> M365Connector {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read"], &[]);
        connector
            .handle_configure(json!({
                "allow_test_api_url": true,
                "api_url": "http://localhost:9999",
                "access_token": token
            }))
            .await
            .unwrap();
        connector
    }

    async fn handshaken_m365_connector() -> (M365Connector, Ed25519SigningKey) {
        let mut connector = configured_m365_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.mail.read", "m365.mail.send", "m365.calendar.write"]
            }))
            .await
            .unwrap();
        (connector, signing_key)
    }

    fn make_access_token(scopes: &[&str], roles: &[&str]) -> String {
        let header = BASE64_URL.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "scp": scopes.join(" "),
            "roles": roles,
        });
        let payload = BASE64_URL.encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{payload}.signature")
    }

    fn unique_zone_dir(label: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("fcp-m365-{label}-{}", Uuid::new_v4()));
        path.to_string_lossy().into_owned()
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = M365Connector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.mail.read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "accepted");
        assert_eq!(result["manifest_hash"], M365Connector::manifest_hash());
    }

    #[fcp_async_core::runtime::test]
    async fn test_sync_operations_require_zone_dir() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read"], &[]);
        connector
            .handle_configure(json!({
                "allow_test_api_url": true,
                "api_url": "http://localhost:9999",
                "access_token": token
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.delta.sync"]
            }))
            .await
            .unwrap();

        let cap = generate_valid_token(&signing_key, &connector, "m365.delta.sync");
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.delta.sync",
                "input": {"resource": "/me/messages"},
                "capability_token": cap
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("zone_dir"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_delta_sync_uses_persisted_token_when_input_missing() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages/delta"))
            .and(query_param("$deltatoken", "seed-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{ "id": "first" }],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=opaque123"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/me/messages/delta"))
            .and(query_param("$deltatoken", "opaque123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{ "id": "second" }],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=opaque456"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let zone_dir = unique_zone_dir("delta-state");
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read"], &[]);
        connector
            .handle_configure(json!({
                "allow_test_api_url": true,
                "api_url": mock_server.uri(),
                "access_token": token
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.delta.sync"]
            }))
            .await
            .unwrap();

        let cap = generate_valid_token(&signing_key, &connector, "m365.delta.sync");
        let first = connector
            .handle_invoke(json!({
                "operation": "m365.delta.sync",
                "input": {
                    "resource": "/me/messages",
                    "delta_token": "seed-token"
                },
                "capability_token": cap
            }))
            .await
            .unwrap();
        assert_eq!(first["delta_token"], "opaque123");

        let cap = generate_valid_token(&signing_key, &connector, "m365.delta.sync");
        let second = connector
            .handle_invoke(json!({
                "operation": "m365.delta.sync",
                "input": {
                    "resource": "/me/messages"
                },
                "capability_token": cap
            }))
            .await
            .unwrap();
        assert_eq!(second["delta_token"], "opaque456");

        let state_path = PathBuf::from(zone_dir).join(M365_SYNC_STATE_FILE);
        let state = read_json_file_if_exists::<M365SyncState>(&state_path)
            .unwrap()
            .unwrap();
        assert_eq!(
            state.delta_tokens.get("/me/messages").map(String::as_str),
            Some("opaque456")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_subscription_state_persists_and_deletes() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "sub-123",
                "resource": "/me/messages",
                "changeType": "created,updated",
                "notificationUrl": "https://hooks.example.test/m365",
                "expirationDateTime": "2026-03-10T00:00:00Z"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/subscriptions/sub-123"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock_server)
            .await;

        let zone_dir = unique_zone_dir("sub-state");
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read"], &[]);
        connector
            .handle_configure(json!({
                "allow_test_api_url": true,
                "api_url": mock_server.uri(),
                "access_token": token
            }))
            .await
            .unwrap();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "zone_dir": zone_dir,
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.subscriptions.create", "m365.subscriptions.delete"]
            }))
            .await
            .unwrap();

        let create_cap =
            generate_valid_token(&signing_key, &connector, "m365.subscriptions.create");
        let created = connector
            .handle_invoke(json!({
                "operation": "m365.subscriptions.create",
                "input": {
                    "change_type": "created,updated",
                    "notification_url": "https://hooks.example.test/m365",
                    "resource": "/me/messages",
                    "expiration_datetime": "2026-03-10T00:00:00Z"
                },
                "capability_token": create_cap
            }))
            .await
            .unwrap();
        assert_eq!(created["subscription"]["id"], "sub-123");

        let state_path = PathBuf::from(&zone_dir).join(M365_SYNC_STATE_FILE);
        let state = read_json_file_if_exists::<M365SyncState>(&state_path)
            .unwrap()
            .unwrap();
        assert!(state.subscriptions.contains_key("sub-123"));

        let delete_cap =
            generate_valid_token(&signing_key, &connector, "m365.subscriptions.delete");
        connector
            .handle_invoke(json!({
                "operation": "m365.subscriptions.delete",
                "input": {
                    "subscription_id": "sub-123"
                },
                "capability_token": delete_cap
            }))
            .await
            .unwrap();

        let state = read_json_file_if_exists::<M365SyncState>(&state_path)
            .unwrap()
            .unwrap();
        assert!(!state.subscriptions.contains_key("sub-123"));
    }

    #[test]
    fn test_m365_sync_lease_fences_second_holder() {
        let lease_root = PathBuf::from(unique_zone_dir("lease-fence"));
        std::fs::create_dir_all(&lease_root).unwrap();
        let lease_path = lease_root.join(M365_SYNC_LEASE_FILE);

        let first = M365SyncLease::acquire(
            lease_path.clone(),
            "holder-a".to_string(),
            M365_SYNC_LEASE_TTL_SECONDS,
        )
        .unwrap();
        let second = M365SyncLease::acquire(
            lease_path,
            "holder-b".to_string(),
            M365_SYNC_LEASE_TTL_SECONDS,
        );
        assert!(matches!(second, Err(FcpError::ResourceExhausted { .. })));
        first.release().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = M365Connector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
        assert_eq!(result["reason_code"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_access_token_permissions() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read", "Calendars.Read"], &[]);
        let result = connector
            .handle_configure(json!({
                "access_token": token,
                "required_permissions": ["Mail.Read"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["auth_mode"], "access_token");
        assert_eq!(health["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_missing_required_permissions() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["User.Read"], &[]);
        let result = connector
            .handle_configure(json!({
                "access_token": token,
                "required_permissions": ["Mail.Read"]
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("missing required permissions"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_with_app_credentials_exchanges_token() {
        let token_server = MockServer::start().await;
        let token = make_access_token(&[], &["Mail.Read.All"]);

        Mock::given(method("POST"))
            .and(path("/tenant-id/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&token_server)
            .await;

        let mut connector = M365Connector::new();
        let result = connector
            .handle_configure(json!({
                "allow_test_api_url": true,
                "auth_url": token_server.uri(),
                "app_credentials": {
                    "tenant_id": "tenant-id",
                    "client_id": "11111111-2222-3333-4444-555555555555",
                    "client_secret": "secret-value"
                },
                "required_permissions": ["Mail.Read.All"]
            }))
            .await
            .unwrap();
        assert_eq!(result["status"], "configured");

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["auth_mode"], "client_credentials");
        assert_eq!(health["status"], "healthy");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_degraded_for_credential_id_mode() {
        let mut connector = M365Connector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .unwrap();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_classifies_invalid_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let mut connector = M365Connector::new();
        connector
            .handle_configure(json!({
                "allow_test_api_url": true,
                "api_url": mock_server.uri(),
                "access_token": make_access_token(&["Mail.Read"], &[])
            }))
            .await
            .unwrap();

        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["reason_code"], "token_invalid_or_expired");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_degraded_for_credential_id_mode() {
        let mut connector = M365Connector::new();
        connector
            .handle_configure(json!({
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await
            .unwrap();

        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "credential_injection_required");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_list_threads_groups_conversations() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {
                        "id": "msg-1",
                        "conversationId": "conv-1",
                        "subject": "Incident update",
                        "isRead": false,
                        "receivedDateTime": "2026-03-01T10:00:00Z"
                    },
                    {
                        "id": "msg-2",
                        "conversationId": "conv-1",
                        "subject": "Incident update",
                        "isRead": true,
                        "receivedDateTime": "2026-03-01T11:00:00Z"
                    },
                    {
                        "id": "msg-3",
                        "conversationId": "conv-2",
                        "subject": "Weekly report",
                        "isRead": true,
                        "receivedDateTime": "2026-03-01T09:00:00Z"
                    }
                ]
            })))
            .mount(&mock_server)
            .await;

        let mut connector = M365Connector::new();
        connector.client = Some(
            M365Client::new("test_token")
                .unwrap()
                .with_api_url(&mock_server.uri()),
        );

        let result = connector
            .invoke_list_threads(json!({ "user_id": "me" }))
            .await
            .unwrap();
        assert_eq!(result["source_message_count"], 3);
        let threads = result["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 2);
        let conv_1 = threads
            .iter()
            .find(|value| value["thread_id"] == "conv-1")
            .unwrap();
        assert_eq!(conv_1["message_count"], 2);
        assert_eq!(conv_1["unread_count"], 1);
        assert_eq!(conv_1["last_message_id"], "msg-2");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_get_page_content_extracts_plain_text() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/onenote/pages/page-123/content"))
            .and(query_param("includeIDs", "true"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(
                        "<html><body><h1>Launch Notes</h1><p>Status: <b>green</b></p></body></html>",
                    ),
            )
            .mount(&mock_server)
            .await;

        let mut connector = M365Connector::new();
        connector.client = Some(
            M365Client::new("test_token")
                .unwrap()
                .with_api_url(&mock_server.uri()),
        );

        let result = connector
            .invoke_get_page_content(json!({
                "user_id": "me",
                "page_id": "page-123",
                "include_ids": true
            }))
            .await
            .unwrap();
        assert_eq!(
            result["page_content"]["plain_text"],
            "Launch Notes\nStatus: green"
        );
        assert!(
            result["page_content"]["html"]
                .as_str()
                .unwrap()
                .contains("Launch Notes")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = M365Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.mail.get_message"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, &connector, "m365.mail.get_message");
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.mail.get_message",
                "input": { "user_id": "me", "message_id": "msg_123" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_before_handshake_returns_not_handshaken() {
        let connector = configured_m365_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, &connector, "m365.mail.get_message");
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.mail.get_message",
                "input": { "user_id": "me", "message_id": "msg_123" },
                "capability_token": token
            }))
            .await;
        assert!(matches!(result.unwrap_err(), FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = M365Connector::new();
        connector.client = Some(
            M365Client::new("test_token")
                .unwrap()
                .with_api_url("http://localhost:9999"),
        );
        connector.base.set_configured(true);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.calendar.create_event"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, &connector, "m365.calendar.create_event");
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.calendar.create_event",
                "input": { "user_id": "me", "subject": "Test" },
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => assert!(message.contains("start")),
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = M365Connector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        // Mail (10)
        assert!(op_ids.contains(&"m365.mail.list_messages"));
        assert!(op_ids.contains(&"m365.mail.search_messages"));
        assert!(op_ids.contains(&"m365.mail.list_threads"));
        assert!(op_ids.contains(&"m365.mail.get_message"));
        assert!(op_ids.contains(&"m365.mail.send_message"));
        assert!(op_ids.contains(&"m365.mail.create_draft"));
        assert!(op_ids.contains(&"m365.mail.reply_message"));
        assert!(op_ids.contains(&"m365.mail.forward_message"));
        assert!(op_ids.contains(&"m365.mail.list_attachments"));
        assert!(op_ids.contains(&"m365.mail.add_attachment"));
        // Files (7)
        assert!(op_ids.contains(&"m365.files.list_items"));
        assert!(op_ids.contains(&"m365.files.get_item"));
        assert!(op_ids.contains(&"m365.files.download_file"));
        assert!(op_ids.contains(&"m365.files.upload_file"));
        assert!(op_ids.contains(&"m365.files.delete_item"));
        assert!(op_ids.contains(&"m365.files.search"));
        assert!(op_ids.contains(&"m365.files.create_share_link"));
        // Word (6)
        assert!(op_ids.contains(&"m365.word.list_documents"));
        assert!(op_ids.contains(&"m365.word.get_document"));
        assert!(op_ids.contains(&"m365.word.extract_text"));
        assert!(op_ids.contains(&"m365.word.create_document"));
        assert!(op_ids.contains(&"m365.word.update_document"));
        assert!(op_ids.contains(&"m365.word.export_document"));
        // OneNote (7)
        assert!(op_ids.contains(&"m365.onenote.list_notebooks"));
        assert!(op_ids.contains(&"m365.onenote.list_sections"));
        assert!(op_ids.contains(&"m365.onenote.list_pages"));
        assert!(op_ids.contains(&"m365.onenote.get_page"));
        assert!(op_ids.contains(&"m365.onenote.get_page_content"));
        assert!(op_ids.contains(&"m365.onenote.create_page"));
        assert!(op_ids.contains(&"m365.onenote.update_page"));
        // Calendar (6)
        assert!(op_ids.contains(&"m365.calendar.list_events"));
        assert!(op_ids.contains(&"m365.calendar.create_event"));
        assert!(op_ids.contains(&"m365.calendar.delete_event"));
        assert!(op_ids.contains(&"m365.calendar.get_event"));
        assert!(op_ids.contains(&"m365.calendar.update_event"));
        assert!(op_ids.contains(&"m365.calendar.get_freebusy"));
        // Tasks (3)
        assert!(op_ids.contains(&"m365.tasks.list_task_lists"));
        assert!(op_ids.contains(&"m365.tasks.list_tasks"));
        assert!(op_ids.contains(&"m365.tasks.create_task"));
        // Subscriptions (3)
        assert!(op_ids.contains(&"m365.subscriptions.create"));
        assert!(op_ids.contains(&"m365.subscriptions.renew"));
        assert!(op_ids.contains(&"m365.subscriptions.delete"));
        // Notifications (1)
        assert!(op_ids.contains(&"m365.notifications.ingest"));
        // Delta (1)
        assert!(op_ids.contains(&"m365.delta.sync"));

        assert_eq!(ops.len(), 44);
    }

    #[fcp_async_core::runtime::test]
    async fn test_calendar_list_events_contract_stays_primary_calendar_only() {
        let connector = M365Connector::new();
        let result = connector.handle_introspect().await.unwrap();
        let ops = result["operations"].as_array().unwrap();
        let list_events = ops
            .iter()
            .find(|op| op["id"] == "m365.calendar.list_events")
            .expect("m365.calendar.list_events operation should exist");
        let properties = list_events["input_schema"]["properties"]
            .as_object()
            .expect("input schema properties object");

        assert!(
            !properties.contains_key("calendar_id"),
            "list_events should remain primary-calendar scoped until runtime support exists"
        );
        assert!(properties.contains_key("user_id"));
        assert!(properties.contains_key("start_datetime"));
        assert!(properties.contains_key("end_datetime"));
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

    // ── Doctor tests ─────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_doctor_not_configured() {
        let connector = M365Connector::new();
        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "fail");
        let checks = result["checks"].as_array().unwrap();
        assert!(checks.len() >= 6);
        assert_eq!(checks[0]["name"], "configuration");
        assert_eq!(checks[0]["status"], "fail");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_access_token() {
        let mut connector = M365Connector::new();
        // access_token auth mode
        connector
            .handle_configure(json!({
                "access_token": make_access_token(&["User.Read"], &[])
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        // warn because direct token mode
        assert_eq!(result["status"], "warn");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "pass");
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_configured_credential_id() {
        let mut connector = M365Connector::new();
        let cred_id = uuid::Uuid::new_v4().to_string();
        connector
            .handle_configure(json!({
                "credential_id": cred_id
            }))
            .await
            .unwrap();

        let result = connector.handle_doctor().await.unwrap();
        assert_eq!(result["status"], "warn");
        let checks = result["checks"].as_array().unwrap();
        let cred_check = checks
            .iter()
            .find(|c| c["name"] == "credential_injection")
            .unwrap();
        assert_eq!(cred_check["status"], "warn");
    }

    // ── Schema completeness tests ─────────────────────────────────

    #[test]
    fn all_operations_have_input_and_output_schemas() {
        let ops = build_operations();
        for op in &ops {
            assert_eq!(
                op.input_schema["type"], "object",
                "op {} input_schema should be object",
                op.id
            );
            assert_eq!(
                op.output_schema["type"], "object",
                "op {} output_schema should be object",
                op.id
            );
        }
    }

    #[test]
    fn all_operations_have_summaries() {
        let ops = build_operations();
        for op in &ops {
            assert!(
                !op.summary.is_empty(),
                "op {} should have a non-empty summary",
                op.id
            );
        }
    }

    #[test]
    fn read_operations_have_safe_risk_levels() {
        let ops = build_operations();
        let safe_ops = [
            "m365.mail.list_messages",
            "m365.mail.get_message",
            "m365.mail.search_messages",
            "m365.mail.list_threads",
            "m365.mail.list_attachments",
            "m365.files.list_items",
            "m365.files.get_item",
            "m365.files.download_file",
            "m365.files.search",
            "m365.word.list_documents",
            "m365.word.get_document",
            "m365.word.extract_text",
            "m365.word.export_document",
            "m365.onenote.list_notebooks",
            "m365.onenote.list_sections",
            "m365.onenote.list_pages",
            "m365.onenote.get_page",
            "m365.onenote.get_page_content",
            "m365.calendar.list_events",
            "m365.calendar.get_event",
            "m365.calendar.get_freebusy",
            "m365.tasks.list_task_lists",
            "m365.tasks.list_tasks",
            "m365.notifications.ingest",
            "m365.delta.sync",
        ];
        for op in &ops {
            let id_str = op.id.to_string();
            if safe_ops.contains(&id_str.as_str()) {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "read op {} should be Low risk",
                    op.id
                );
            }
        }
    }

    #[test]
    fn dangerous_operations_have_high_risk() {
        let ops = build_operations();
        let dangerous_ops = [
            "m365.mail.send_message",
            "m365.mail.reply_message",
            "m365.mail.forward_message",
            "m365.files.delete_item",
            "m365.word.create_document",
            "m365.word.update_document",
            "m365.calendar.delete_event",
        ];
        for op in &ops {
            let id_str = op.id.to_string();
            if dangerous_ops.contains(&id_str.as_str()) {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::High,
                    "dangerous op {} should be High risk",
                    op.id
                );
                assert_eq!(
                    op.safety_tier,
                    SafetyTier::Dangerous,
                    "dangerous op {} should have Dangerous safety tier",
                    op.id
                );
            }
        }
    }

    #[test]
    fn operations_are_deterministic() {
        let ops1 = build_operations();
        let ops2 = build_operations();
        assert_eq!(ops1.len(), ops2.len());
        for (a, b) in ops1.iter().zip(ops2.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.summary, b.summary);
        }
    }

    #[test]
    fn operation_count_matches_expected() {
        let ops = build_operations();
        // Mail: 10, Files: 7, Word: 6, OneNote: 7, Calendar: 6, Tasks: 3, Subscriptions: 3, Notifications: 1, Delta: 1 = 44
        assert_eq!(ops.len(), 44);
    }

    // ── Helper function tests ─────────────────────────────────────

    #[test]
    fn validate_endpoint_allows_graph_microsoft_com() {
        let result = validate_endpoint(
            "https://graph.microsoft.com/v1.0",
            &["graph.microsoft.com"],
            false,
            "api_url",
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://graph.microsoft.com/v1.0");
    }

    #[test]
    fn validate_endpoint_strips_trailing_slash() {
        let result = validate_endpoint(
            "https://graph.microsoft.com/v1.0/",
            &["graph.microsoft.com"],
            false,
            "api_url",
        );
        assert!(result.is_ok());
        assert!(!result.unwrap().ends_with('/'));
    }

    #[test]
    fn validate_endpoint_rejects_empty() {
        let result = validate_endpoint("", &["graph.microsoft.com"], false, "api_url");
        assert!(result.is_err());
    }

    #[test]
    fn validate_endpoint_rejects_non_https_in_production() {
        let result = validate_endpoint(
            "http://graph.microsoft.com/v1.0",
            &["graph.microsoft.com"],
            false,
            "api_url",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("https"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_endpoint_allows_http_in_test_mode() {
        let result = validate_endpoint(
            "http://localhost:8080",
            &["graph.microsoft.com"],
            true,
            "api_url",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_endpoint_rejects_ip_literal_in_production() {
        let result = validate_endpoint(
            "https://192.168.1.1/v1",
            &["graph.microsoft.com"],
            false,
            "api_url",
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_endpoint_rejects_unauthorized_host() {
        let result = validate_endpoint(
            "https://evil.com/v1.0",
            &["graph.microsoft.com"],
            false,
            "api_url",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("not allowed"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn is_local_test_host_recognizes_localhost() {
        assert!(is_local_test_host("localhost"));
        assert!(is_local_test_host("127.0.0.1"));
        assert!(is_local_test_host("::1"));
        assert!(!is_local_test_host("example.com"));
        assert!(!is_local_test_host("10.0.0.1"));
    }

    #[test]
    fn parse_access_token_from_top_level() {
        let params = json!({ "access_token": "my-jwt-token" });
        assert_eq!(parse_access_token(&params), Some("my-jwt-token".into()));
    }

    #[test]
    fn parse_access_token_from_oauth_nested() {
        let params = json!({ "oauth": { "access_token": "nested-token" } });
        assert_eq!(parse_access_token(&params), Some("nested-token".into()));
    }

    #[test]
    fn parse_access_token_prefers_top_level() {
        let params = json!({
            "access_token": "top-level",
            "oauth": { "access_token": "nested" }
        });
        assert_eq!(parse_access_token(&params), Some("top-level".into()));
    }

    #[test]
    fn parse_access_token_ignores_empty_and_whitespace() {
        let params = json!({ "access_token": "" });
        assert_eq!(parse_access_token(&params), None);

        let params = json!({ "access_token": "   " });
        assert_eq!(parse_access_token(&params), None);
    }

    #[test]
    fn parse_access_token_missing_returns_none() {
        let params = json!({});
        assert_eq!(parse_access_token(&params), None);
    }

    #[test]
    fn parse_required_permissions_deduplicates() {
        let params = json!({ "required_permissions": ["Mail.Read", "Mail.Read", "Calendar.Read"] });
        let result = parse_required_permissions(&params).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"Mail.Read".to_string()));
        assert!(result.contains(&"Calendar.Read".to_string()));
    }

    #[test]
    fn parse_required_permissions_skips_empty_strings() {
        let params = json!({ "required_permissions": ["Mail.Read", "", "  "] });
        let result = parse_required_permissions(&params).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "Mail.Read");
    }

    #[test]
    fn parse_required_permissions_returns_empty_when_absent() {
        let params = json!({});
        let result = parse_required_permissions(&params).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_required_permissions_rejects_non_array() {
        let params = json!({ "required_permissions": "not an array" });
        assert!(parse_required_permissions(&params).is_err());
    }

    #[test]
    fn parse_credential_id_valid_uuid() {
        let params = json!({ "credential_id": "11223344-5566-7788-99aa-bbccddeeff00" });
        let result = parse_credential_id(&params).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn parse_credential_id_invalid_uuid() {
        let params = json!({ "credential_id": "not-a-uuid" });
        assert!(parse_credential_id(&params).is_err());
    }

    #[test]
    fn parse_credential_id_missing() {
        let params = json!({});
        let result = parse_credential_id(&params).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_credential_id_non_string() {
        let params = json!({ "credential_id": 42 });
        assert!(parse_credential_id(&params).is_err());
    }

    #[test]
    fn parse_app_credentials_valid() {
        let params = json!({
            "app_credentials": {
                "tenant_id": "t-123",
                "client_id": "c-456",
                "client_secret": "secret"
            }
        });
        let result = parse_app_credentials(&params).unwrap();
        assert!(result.is_some());
        let config = result.unwrap();
        assert_eq!(config.tenant_id, "t-123");
        assert_eq!(config.scope, DEFAULT_CLIENT_CREDENTIAL_SCOPE);
    }

    #[test]
    fn parse_app_credentials_rejects_empty_fields() {
        let params = json!({
            "app_credentials": {
                "tenant_id": "",
                "client_id": "c-456",
                "client_secret": "secret"
            }
        });
        assert!(parse_app_credentials(&params).is_err());
    }

    #[test]
    fn parse_app_credentials_missing_returns_none() {
        let params = json!({});
        let result = parse_app_credentials(&params).unwrap();
        assert!(result.is_none());
    }

    // ── TokenPermissions tests ────────────────────────────────────

    #[test]
    fn token_permissions_parse_with_scopes() {
        let token = make_access_token(&["Mail.Read", "Calendar.Read"], &[]);
        let perms = TokenPermissions::parse(&token).unwrap();
        assert_eq!(perms.scopes.len(), 2);
        assert!(perms.scopes.contains(&"Mail.Read".to_string()));
        assert!(perms.roles.is_empty());
    }

    #[test]
    fn token_permissions_parse_with_roles() {
        let token = make_access_token(&[], &["Mail.Read.All"]);
        let perms = TokenPermissions::parse(&token).unwrap();
        assert!(perms.scopes.is_empty());
        assert_eq!(perms.roles.len(), 1);
    }

    #[test]
    fn token_permissions_parse_rejects_no_claims() {
        let header = BASE64_URL.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = BASE64_URL.encode(r#"{"sub":"user"}"#);
        let token = format!("{header}.{payload}.sig");
        assert!(TokenPermissions::parse(&token).is_err());
    }

    #[test]
    fn token_permissions_parse_rejects_non_jwt() {
        assert!(TokenPermissions::parse("not-a-jwt").is_err());
    }

    #[test]
    fn token_permissions_missing_required() {
        let token = make_access_token(&["User.Read"], &[]);
        let perms = TokenPermissions::parse(&token).unwrap();
        let missing = perms.missing_required(&["User.Read".to_string(), "Mail.Read".to_string()]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], "Mail.Read");
    }

    #[test]
    fn token_permissions_all_combines_scopes_and_roles() {
        let token = make_access_token(&["Mail.Read"], &["Calendar.Read.All"]);
        let perms = TokenPermissions::parse(&token).unwrap();
        let all = perms.all();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&"Mail.Read".to_string()));
        assert!(all.contains(&"Calendar.Read.All".to_string()));
    }

    // ── M365AuthMode tests ───────────────────────────────────────

    #[test]
    fn auth_mode_labels() {
        assert_eq!(M365AuthMode::AccessToken.label(), "access_token");
        let cred_mode = M365AuthMode::ClientCredentials {
            tenant_id: "t".into(),
            client_id: "c".into(),
            scope: "s".into(),
        };
        assert_eq!(cred_mode.label(), "client_credentials");
    }

    #[test]
    fn auth_mode_summary_redacts_client_id() {
        let mode = M365AuthMode::ClientCredentials {
            tenant_id: "tenant-123".into(),
            client_id: "11111111-2222-3333-4444-555555555555".into(),
            scope: "https://graph.microsoft.com/.default".into(),
        };
        let summary = mode.summary();
        assert_eq!(summary["mode"], "client_credentials");
        // Only prefix of client_id should be present
        assert_eq!(summary["client_id_prefix"], "11111111");
    }

    // ── encode_form_body tests ───────────────────────────────────

    #[test]
    fn encode_form_body_basic() {
        let result = encode_form_body(&[("key", "value"), ("foo", "bar")]);
        assert_eq!(result, "key=value&foo=bar");
    }

    #[test]
    fn encode_form_body_encodes_special_chars() {
        let result = encode_form_body(&[("scope", "https://graph.microsoft.com/.default")]);
        assert!(result.contains("https%3A%2F%2F"));
        assert!(!result.contains("://"));
    }

    #[test]
    fn encode_form_body_encodes_spaces_as_plus() {
        let result = encode_form_body(&[("q", "hello world")]);
        assert_eq!(result, "q=hello+world");
    }

    #[test]
    fn encode_form_body_empty_input() {
        let result = encode_form_body(&[]);
        assert!(result.is_empty());
    }

    // ── Configure edge cases ─────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_multiple_auth_sources() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read"], &[]);
        let result = connector
            .handle_configure(json!({
                "access_token": token,
                "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("exactly one auth source"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_no_auth_source() {
        let mut connector = M365Connector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_unauthorized_api_url() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read"], &[]);
        let result = connector
            .handle_configure(json!({
                "access_token": token,
                "api_url": "https://evil.com/v1.0"
            }))
            .await;
        assert!(result.is_err());
    }

    // ── Simulate test ────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_simulate_returns_allowed() {
        let (connector, signing_key) = handshaken_m365_connector().await;
        let token = generate_valid_token(&signing_key, &connector, "m365.mail.list_messages");
        let result = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "m365.mail.list_messages",
                    json!({ "user_id": "me" }),
                    token,
                ))
                .await
                .unwrap(),
        );
        assert!(result.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_before_configure_denied() {
        let connector = M365Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, &connector, "m365.mail.list_messages");
        let result = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "m365.mail.list_messages",
                    json!({ "user_id": "me" }),
                    token,
                ))
                .await
                .unwrap(),
        );
        assert!(!result.would_succeed);
        assert_eq!(
            result.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_before_handshake_denied() {
        let connector = configured_m365_connector().await;
        let signing_key = Ed25519SigningKey::generate();
        let token = generate_valid_token(&signing_key, &connector, "m365.mail.list_messages");
        let result = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "m365.mail.list_messages",
                    json!({ "user_id": "me" }),
                    token,
                ))
                .await
                .unwrap(),
        );
        assert!(!result.would_succeed);
        assert_eq!(
            result.denial_code,
            Some(FcpError::NotHandshaken.error_code())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_wrong_capability_denied() {
        let (connector, signing_key) = handshaken_m365_connector().await;
        let token = generate_token_with_cap(
            &signing_key,
            &connector,
            "m365.mail.send",
            &["m365.mail.list_messages"],
        );
        let result = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "m365.mail.list_messages",
                    json!({ "user_id": "me" }),
                    token,
                ))
                .await
                .unwrap(),
        );
        assert!(!result.would_succeed);
        assert_eq!(result.missing_capabilities, vec!["m365.mail.read"]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_missing_required_input_denied() {
        let (connector, signing_key) = handshaken_m365_connector().await;
        let token = generate_valid_token(&signing_key, &connector, "m365.mail.list_messages");
        let result = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "m365.mail.list_messages",
                    json!({}),
                    token,
                ))
                .await
                .unwrap(),
        );
        assert!(!result.would_succeed);
        assert_eq!(
            result.denial_code,
            Some(
                FcpError::InvalidRequest {
                    code: 1003,
                    message: String::new(),
                }
                .error_code()
            )
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_unknown_operation_denied() {
        let (connector, signing_key) = handshaken_m365_connector().await;
        let token = generate_token_with_cap(
            &signing_key,
            &connector,
            "m365.mail.read",
            &["m365.unknown.operation"],
        );
        let result = parse_simulate_response(
            connector
                .handle_simulate(simulate_request(
                    "m365.unknown.operation",
                    json!({ "user_id": "me" }),
                    token,
                ))
                .await
                .unwrap(),
        );
        assert!(!result.would_succeed);
        assert_eq!(
            result.denial_code,
            Some(
                FcpError::OperationNotGranted {
                    operation: "m365.unknown.operation".into()
                }
                .error_code()
            )
        );
    }

    // ── Shutdown test ────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_returns_status() {
        let connector = M365Connector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }

    // ── Self-check edge cases ────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_self_check_not_configured() {
        let connector = M365Connector::new();
        let result = connector.handle_self_check().await.unwrap();
        assert_eq!(result["status"], "degraded");
        assert_eq!(result["reason_code"], "not_configured");
    }

    // ── Invoke edge cases ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let mut connector = M365Connector::new();
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector.client = Some(
            M365Client::new("test_token")
                .unwrap()
                .with_api_url("http://localhost:9999"),
        );

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.nonexistent.op"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, &connector, "m365.nonexistent.op");
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.nonexistent.op",
                "input": {},
                "capability_token": token
            }))
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FcpError::OperationNotGranted { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_operation() {
        let connector = M365Connector::new();
        let result = connector.handle_invoke(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("Missing operation"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_capability_token() {
        let connector = M365Connector::new();
        let result = connector
            .handle_invoke(json!({
                "operation": "m365.mail.list_messages",
                "input": { "user_id": "me" }
            }))
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("capability_token"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    // ── Handshake details ────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_handshake_sets_session_and_capabilities() {
        let mut connector = M365Connector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["m365.mail.read", "m365.files.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
        let grants = result["capabilities_granted"].as_array().unwrap();
        assert_eq!(grants.len(), 2);
        assert!(result["session_id"].is_string());
        // streaming events
        assert_eq!(result["event_caps"]["streaming"], true);
        assert_eq!(result["event_caps"]["replay"], false);
    }

    // ── Word helper tests ────────────────────────────────────────

    #[test]
    fn word_document_metadata_flags_docx_support() {
        let item = DriveItem {
            id: Some("doc-1".into()),
            name: Some("draft.docx".into()),
            size: Some(2048),
            web_url: Some("https://example.invalid/doc-1".into()),
            folder: None,
            file: Some(crate::types::FileFacet {
                mime_type: Some(
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                        .into(),
                ),
            }),
            created_date_time: None,
            last_modified_date_time: None,
        };

        let metadata = WordDocumentMetadata::from_drive_item(&item);
        assert!(metadata.supports_text_extraction);
        assert!(metadata.supports_content_replace);
        assert!(metadata.supports_pdf_export);
        assert_eq!(metadata.extension.as_deref(), Some("docx"));
    }

    #[test]
    fn build_docx_document_roundtrips_text() {
        let bytes = build_docx_document("Quarterly Review\nLine two").unwrap();
        let extracted = extract_docx_text(&bytes).unwrap();
        assert_eq!(extracted, "Quarterly Review\nLine two");
    }

    #[test]
    fn create_word_document_input_rejects_non_docx_paths() {
        let result = CreateWordDocumentInput::parse(json!({
            "user_id": "me",
            "path": "/Documents/notes.txt",
            "content": "hello"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn extract_word_text_input_rejects_large_max_chars() {
        let result = ExtractWordTextInput::parse(json!({
            "user_id": "me",
            "item_id": "doc-1",
            "max_chars": WORD_EXTRACT_MAX_CHARS_LIMIT + 1
        }));
        assert!(result.is_err());
    }

    #[test]
    fn replace_extension_swaps_suffix() {
        assert_eq!(
            replace_extension(Some("report.docx"), "pdf").as_deref(),
            Some("report.pdf")
        );
    }

    // ── require_str tests ────────────────────────────────────────

    #[test]
    fn require_str_present() {
        let input = json!({ "user_id": "me" });
        assert_eq!(require_str(&input, "user_id").unwrap(), "me");
    }

    #[test]
    fn require_str_missing() {
        let input = json!({});
        assert!(require_str(&input, "user_id").is_err());
    }

    #[test]
    fn require_str_non_string() {
        let input = json!({ "user_id": 42 });
        assert!(require_str(&input, "user_id").is_err());
    }

    // ── Health after configure ───────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn test_health_shows_permissions_after_configure() {
        let mut connector = M365Connector::new();
        let token = make_access_token(&["Mail.Read", "Calendar.Read"], &["User.Read.All"]);
        connector
            .handle_configure(json!({ "access_token": token }))
            .await
            .unwrap();

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        let permissions = health["permissions"].as_array().unwrap();
        assert_eq!(permissions.len(), 3);
    }
}
