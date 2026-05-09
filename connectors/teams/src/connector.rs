//! Teams connector implementation.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt::Write as _,
    sync::{Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_prelude::{
    BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId, EventCaps,
    EventData, EventEnvelope, EventInfo, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    Principal, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    ThreadInfo, ThreadKind, TrustLevel,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

use crate::client::TeamsClient;
use crate::error::TeamsError;
use crate::types::{
    Activity, ActivityAccount, TeamsAuth, TeamsConversationScope, TeamsConversationState,
    TeamsIngressPolicy,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/teams_connector/<timestamp>";

// Operation IDs
const OP_LIST_TEAMS: &str = "teams.list_teams";
const OP_GET_TEAM: &str = "teams.get_team";
const OP_LIST_CHANNELS: &str = "teams.list_channels";
const OP_GET_CHANNEL: &str = "teams.get_channel";
const OP_SEND_CHANNEL_MSG: &str = "teams.send_channel_message";
const OP_LIST_CHATS: &str = "teams.list_chats";
const OP_SEND_CHAT_MSG: &str = "teams.send_chat_message";
const OP_LIST_CHAT_MSGS: &str = "teams.list_chat_messages";
const OP_SEND_CARD: &str = "teams.send_card";
const OP_REPLY_MSG: &str = "teams.reply_message";
const OP_UPDATE_MSG: &str = "teams.update_message";
const OP_INGEST_ACTIVITY: &str = "teams.ingest_activity";
const OP_GET_CONVERSATION_STATE: &str = "teams.get_conversation_state";
const OPERATION_ORDER: [&str; 13] = [
    OP_LIST_TEAMS,
    OP_GET_TEAM,
    OP_LIST_CHANNELS,
    OP_GET_CHANNEL,
    OP_SEND_CHANNEL_MSG,
    OP_LIST_CHATS,
    OP_SEND_CHAT_MSG,
    OP_LIST_CHAT_MSGS,
    OP_SEND_CARD,
    OP_REPLY_MSG,
    OP_UPDATE_MSG,
    OP_INGEST_ACTIVITY,
    OP_GET_CONVERSATION_STATE,
];

// Capability IDs
const CAP_READ: &str = "teams.read";
const CAP_WRITE: &str = "teams.write";

const IDEMPOTENT_RESPONSE_LIMIT: usize = 512;
const ACTIVITY_DEDUP_LIMIT: usize = 1024;

#[derive(Debug)]
struct BoundedJsonCache {
    limit: usize,
    order: VecDeque<String>,
    entries: HashMap<String, Value>,
}

impl BoundedJsonCache {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            order: VecDeque::with_capacity(limit),
            entries: HashMap::with_capacity(limit),
        }
    }

    fn get(&self, key: &str) -> Option<Value> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: String, value: Value) {
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.entries.entry(key.clone())
        {
            entry.insert(value);
            return;
        }

        self.order.push_back(key.clone());
        self.entries.insert(key, value);

        while self.order.len() > self.limit {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }
}

#[derive(Debug)]
struct BoundedKeySet {
    limit: usize,
    order: VecDeque<String>,
    entries: HashSet<String>,
}

impl BoundedKeySet {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            order: VecDeque::with_capacity(limit),
            entries: HashSet::with_capacity(limit),
        }
    }

    fn contains(&self, key: &str) -> bool {
        self.entries.contains(key)
    }

    fn insert(&mut self, key: String) {
        if self.entries.contains(&key) {
            return;
        }

        self.order.push_back(key.clone());
        self.entries.insert(key);

        while self.order.len() > self.limit {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    auth_mode: &'static str,
    requires_credential_injection: bool,
    credential_material_configured: bool,
    uses_client_credentials: bool,
    full_connector_surface_supported: bool,
    full_connector_surface_message: String,
    graph_base_url: String,
    graph_network_ok: bool,
    graph_network_message: String,
    bot_service_url: String,
    bot_service_url_ok: bool,
    bot_service_url_message: String,
    tenant_hint_configured: bool,
    retry: HttpRetryConfig,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    common_remediation: Vec<RemediationHint>,
    rerun_commands: Vec<&'static str>,
    artifact_root_hint: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemediationHint {
    code: &'static str,
    symptom: &'static str,
    action: &'static str,
}

/// Doctor check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub status: DoctorStatus,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
}

/// Single doctor check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let ready = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        let status = if checks.iter().any(|check| check.critical && !check.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|check| !check.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            ready,
            status,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
        }
    }

    const fn status_label(&self) -> &'static str {
        match self.status {
            DoctorStatus::Healthy => "healthy",
            DoctorStatus::Degraded => "degraded",
            DoctorStatus::Unhealthy => "unhealthy",
        }
    }
}

fn is_local_test_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

const MICROSOFT_GRAPH_HOSTS: &[&str] = &[
    "graph.microsoft.com",
    "graph.microsoft.us",
    "dod-graph.microsoft.us",
    "microsoftgraph.chinacloudapi.cn",
];

fn is_allowed_graph_host(host: &str) -> bool {
    MICROSOFT_GRAPH_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

const fn auth_mode_label(auth: &TeamsAuth) -> &'static str {
    match auth {
        TeamsAuth::AccessToken { .. } => "access_token",
        TeamsAuth::ClientCredentials { .. } => "client_credentials",
        TeamsAuth::CredentialId { .. } => "credential_id",
    }
}

fn graph_base_url_policy(base_url: &str) -> (bool, String) {
    let parsed = match reqwest::Url::parse(base_url) {
        Ok(url) => url,
        Err(error) => {
            return (
                false,
                format!("graph_base_url must be an absolute URL: {error}"),
            );
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "graph_base_url must include a host".into());
    };

    #[cfg(test)]
    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test Graph endpoint accepted for verification: {base_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if !is_allowed_graph_host(host) {
        problems.push(format!(
            "host must be one of {}, got {host}",
            MICROSOFT_GRAPH_HOSTS.join(", ")
        ));
    }
    if parsed.port().is_some_and(|port| port != 443) {
        problems.push(format!(
            "port must be 443 when specified, got {}",
            parsed.port().unwrap_or_default()
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        problems.push("userinfo is not allowed in graph_base_url".into());
    }
    if !matches!(parsed.path(), "/v1.0" | "/v1.0/" | "/beta" | "/beta/") {
        problems.push(format!(
            "path must be /v1.0 or /beta, got {}",
            parsed.path()
        ));
    }
    if parsed.query().is_some() {
        problems.push("query strings are not allowed in graph_base_url".into());
    }
    if parsed.fragment().is_some() {
        problems.push("fragments are not allowed in graph_base_url".into());
    }

    if problems.is_empty() {
        (true, "Microsoft Graph endpoint accepted".into())
    } else {
        (false, problems.join("; "))
    }
}

fn bot_service_url_policy(bot_service_url: &str) -> (bool, String) {
    let parsed = match reqwest::Url::parse(bot_service_url) {
        Ok(url) => url,
        Err(error) => {
            return (
                false,
                format!("bot_service_url must be an absolute URL: {error}"),
            );
        }
    };

    let Some(host) = parsed.host_str() else {
        return (false, "bot_service_url must include a host".into());
    };

    if is_local_test_host(host) {
        return (
            true,
            format!("localhost test Bot Framework endpoint accepted: {bot_service_url}"),
        );
    }

    let mut problems = Vec::new();
    if parsed.scheme() != "https" {
        problems.push(format!("scheme must be https, got {}", parsed.scheme()));
    }
    if parsed.port().is_some_and(|port| port != 443) {
        problems.push(format!(
            "port must be 443 when specified, got {}",
            parsed.port().unwrap_or_default()
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        problems.push("embedded credentials are not allowed in bot_service_url".into());
    }
    if parsed.query().is_some() {
        problems.push("query strings are not allowed in bot_service_url".into());
    }
    if parsed.fragment().is_some() {
        problems.push("fragments are not allowed in bot_service_url".into());
    }

    if problems.is_empty() {
        (
            true,
            "Bot Framework service origin accepted; inbound activities must still match this host at runtime".into(),
        )
    } else {
        (false, problems.join("; "))
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a dedicated non-production Microsoft 365 tenant, team, channel, and chat for verification.",
            "Register an Azure AD application with the exact Microsoft Graph permissions required for the operations you plan to exercise.",
            "Prefer delegated user tokens for `/me`-backed list/read flows and standard send/reply/update message operations.",
        ],
        dedicated_environment: "Do not point verification at production teams or chats. Message send, reply, and update operations are live mutations and should only target disposable collaboration surfaces.",
        redaction_rules: vec![
            "Never log access_token, client_secret, or injected bearer token values.",
            "Treat credential_id values as sensitive internal references; do not paste them into shared transcripts.",
            "Avoid publishing private tenant IDs, team IDs, channel IDs, chat IDs, or Bot Framework service URLs from internal environments.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "credential_injection_required",
                symptom: "doctor/health/self_check reports that a token is missing in credential_id mode",
                action: "Have the host or egress proxy inject a concrete bearer token at runtime, then rerun self_check before invoking live operations.",
            },
            RemediationHint {
                code: "delegated_user_context_required",
                symptom: "client_credentials mode is configured but `/me`-backed flows or standard send/reply/update operations cannot be proven ready",
                action: "Use a delegated user bearer token (directly or via credential injection) for full connector readiness. App-only tokens are limited to a narrower Graph surface and Teams message send application permissions are reserved for migration scenarios.",
            },
            RemediationHint {
                code: "admin_consent_or_permission_missing",
                symptom: "Graph returns 403, insufficient privileges, or admin approval / consent errors",
                action: "Grant tenant admin consent for the required Microsoft Graph application permissions, then verify the token contains the expected scopes or roles before rerunning self_check.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor or self_check reports invalid Graph or Bot Framework endpoint policy",
                action: "Use https://graph.microsoft.com/v1.0 (or /beta only when intentionally testing beta APIs) and a clean HTTPS Bot Framework service origin, or localhost-only mocks during deterministic verification.",
            },
            RemediationHint {
                code: "graph_rate_limited",
                symptom: "self_check or invoke receives HTTP 429 / Retry-After from Microsoft Graph",
                action: "Honor Retry-After, reduce concurrent probes, and rerun verification after the throttle window expires.",
            },
            RemediationHint {
                code: "token_invalid_or_expired",
                symptom: "Graph returns 401 or invalid/expired authentication errors",
                action: "Refresh or reacquire the delegated token, confirm the tenant matches the target environment, and rerun self_check.",
            },
        ],
        rerun_commands: vec![
            "rch exec -- cargo run -p fwc -- manifest fix connectors/teams/manifest.toml --check --json",
            "rch exec -- cargo test -p fcp-teams -- --nocapture",
            "rch exec -- cargo clippy -p fcp-teams --all-targets -- -D warnings",
        ],
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

/// Microsoft Teams connector.
#[derive(Debug)]
pub struct TeamsConnector {
    base: BaseConnector,
    config: Option<crate::types::TeamsConfig>,
    client: Option<TeamsClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
    conversation_states: Mutex<HashMap<String, TeamsConversationState>>,
    idempotent_results: Mutex<BoundedJsonCache>,
    seen_activity_ids: Mutex<BoundedKeySet>,
}

impl TeamsConnector {
    fn uses_response_cache(operation: &str) -> bool {
        matches!(
            operation,
            OP_SEND_CHANNEL_MSG
                | OP_SEND_CHAT_MSG
                | OP_SEND_CARD
                | OP_REPLY_MSG
                | OP_UPDATE_MSG
                | OP_INGEST_ACTIVITY
        )
    }

    fn response_cache_key(operation: &str, idempotency_key: &str) -> String {
        format!("{operation}:{idempotency_key}")
    }

    fn cached_output(&self, operation: &str, req: &InvokeRequest) -> Option<Value> {
        let key = req.idempotency_key.as_deref()?;
        lock_unpoisoned(&self.idempotent_results).get(&Self::response_cache_key(operation, key))
    }

    fn remember_output(&self, operation: &str, req: &InvokeRequest, output: &Value) {
        let Some(key) = req.idempotency_key.as_deref() else {
            return;
        };
        lock_unpoisoned(&self.idempotent_results)
            .insert(Self::response_cache_key(operation, key), output.clone());
    }

    fn normalize_content_type(input: &Value) -> &'static str {
        match optional_str(input, "content_type") {
            Some("html") => "html",
            _ => "text",
        }
    }

    #[allow(clippy::too_many_lines)]
    fn build_message_payload(input: &Value) -> FcpResult<Value> {
        let mut content_type = Self::normalize_content_type(input);
        let mut rendered_content = optional_str(input, "content")
            .unwrap_or_default()
            .to_string();
        let mut attachments = Vec::new();

        if let Some(raw_attachments) = input.get("attachments") {
            let attachment_items =
                raw_attachments
                    .as_array()
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "attachments must be an array".into(),
                    })?;

            for attachment in attachment_items {
                let attachment_id = optional_str(attachment, "id").map_or_else(
                    || format!("att_{}", Uuid::new_v4().simple()),
                    ToOwned::to_owned,
                );
                let attachment_type =
                    optional_str(attachment, "content_type").ok_or_else(|| {
                        FcpError::InvalidRequest {
                            code: 1005,
                            message: "attachments[].content_type is required".into(),
                        }
                    })?;
                let attachment_content =
                    match attachment.get("content") {
                        Some(Value::String(content)) => Some(content.clone()),
                        Some(other) => Some(serde_json::to_string(other).map_err(|err| {
                            FcpError::Internal {
                                message: format!(
                                    "Failed to serialize Teams attachment content: {err}"
                                ),
                            }
                        })?),
                        None => None,
                    };
                let attachment_url = optional_str(attachment, "content_url");
                if attachment_content.is_none() && attachment_url.is_none() {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "attachments[] must include either content or content_url".into(),
                    });
                }

                attachments.push(json!({
                    "id": attachment_id,
                    "contentType": attachment_type,
                    "contentUrl": attachment_url,
                    "content": attachment_content,
                    "name": optional_str(attachment, "name"),
                }));

                if !rendered_content.contains(&attachment_id) {
                    let _ = write!(
                        rendered_content,
                        "<attachment id=\"{attachment_id}\"></attachment>"
                    );
                }
                content_type = "html";
            }
        }

        if let Some(card) = input.get("adaptive_card") {
            let attachment_id = optional_str(input, "adaptive_card_attachment_id").map_or_else(
                || format!("card_{}", Uuid::new_v4().simple()),
                ToOwned::to_owned,
            );
            let card_content = serde_json::to_string(card).map_err(|err| FcpError::Internal {
                message: format!("Failed to serialize adaptive card payload: {err}"),
            })?;

            attachments.push(json!({
                "id": attachment_id,
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card_content,
            }));
            if !rendered_content.contains(&attachment_id) {
                let _ = write!(
                    rendered_content,
                    "<attachment id=\"{attachment_id}\"></attachment>"
                );
            }
            content_type = "html";
        }

        let mentions = input
            .get("mentions")
            .map(|mentions| {
                if mentions.is_array() {
                    Ok(mentions.clone())
                } else {
                    Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "mentions must be an array".into(),
                    })
                }
            })
            .transpose()?
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let mention_items = mentions.as_array().cloned().unwrap_or_default();
        if !mention_items.is_empty() {
            content_type = "html";
        }

        if rendered_content.trim().is_empty() && attachments.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "content, attachments, or adaptive_card is required".into(),
            });
        }

        Ok(json!({
            "body": {
                "contentType": content_type,
                "content": rendered_content,
            },
            "attachments": attachments,
            "mentions": mention_items,
        }))
    }

    fn activity_topic(activity: &Activity) -> String {
        match activity.r#type.as_str() {
            "message" => "teams.message.received".into(),
            "installationUpdate" => activity.action.as_deref().map_or_else(
                || "teams.installation_update".into(),
                |action| format!("teams.installation_update.{action}"),
            ),
            "conversationUpdate" => activity
                .channel_data
                .as_ref()
                .and_then(|channel_data| channel_data.event_type.as_deref())
                .map_or_else(
                    || "teams.conversation_update".into(),
                    |event_type| format!("teams.conversation_update.{event_type}"),
                ),
            other => format!("teams.activity.{other}"),
        }
    }

    fn allowlist_allows(allowed: &[String], candidate: Option<&str>) -> bool {
        allowed.is_empty()
            || candidate.is_some_and(|candidate| allowed.iter().any(|item| item == candidate))
    }

    fn ingress_policy(&self) -> TeamsIngressPolicy {
        self.config
            .as_ref()
            .map(|config| config.ingress_policy.clone())
            .unwrap_or_default()
    }

    fn activity_team_id(activity: &Activity) -> Option<&str> {
        activity
            .channel_data
            .as_ref()
            .and_then(|channel_data| channel_data.team.as_ref())
            .map(|team| team.id.as_str())
    }

    fn activity_channel_id<'a>(
        activity: &'a Activity,
        conversation: &'a crate::types::ConversationAccount,
    ) -> Option<&'a str> {
        activity
            .channel_data
            .as_ref()
            .and_then(|channel_data| {
                channel_data
                    .channel
                    .as_ref()
                    .map(|channel| channel.id.as_str())
                    .or_else(|| {
                        channel_data
                            .settings
                            .as_ref()
                            .and_then(|settings| settings.selected_channel.as_ref())
                            .map(|channel| channel.id.as_str())
                    })
            })
            .or(Some(conversation.id.as_str()))
    }

    fn activity_tenant_id(activity: &Activity) -> Option<&str> {
        activity
            .conversation
            .as_ref()
            .and_then(|conversation| conversation.tenant_id.as_deref())
            .or_else(|| {
                activity
                    .channel_data
                    .as_ref()
                    .and_then(|channel_data| channel_data.tenant.as_ref())
                    .map(|tenant| tenant.id.as_str())
            })
    }

    fn diagnostic(code: &str, message: &str) -> Value {
        json!({
            "code": code,
            "message": message,
        })
    }

    fn ingress_skip_diagnostic(
        &self,
        activity: &Activity,
        conversation: &crate::types::ConversationAccount,
    ) -> Option<Value> {
        let policy = self.ingress_policy();
        let from = activity.from.as_ref();
        let sender_id = from.map(|from| from.id.as_str());
        let aad_object_id = from.and_then(|from| from.aad_object_id.as_deref());

        if policy
            .bot_user_id
            .as_deref()
            .is_some_and(|bot_id| Some(bot_id) == sender_id || Some(bot_id) == aad_object_id)
        {
            return Some(Self::diagnostic(
                "bot_self_message",
                "Teams activity sender matched the configured bot user ID",
            ));
        }

        let sender_lists_configured =
            !policy.allowed_sender_ids.is_empty() || !policy.allowed_aad_object_ids.is_empty();
        let sender_allowed = !sender_lists_configured
            || Self::allowlist_allows(&policy.allowed_sender_ids, sender_id)
            || Self::allowlist_allows(&policy.allowed_aad_object_ids, aad_object_id);
        if !sender_allowed {
            return Some(Self::diagnostic(
                "sender_not_allowed",
                "Teams activity sender is outside the configured allowlist",
            ));
        }

        if !Self::allowlist_allows(&policy.allowed_team_ids, Self::activity_team_id(activity)) {
            return Some(Self::diagnostic(
                "team_not_allowed",
                "Teams activity team is outside the configured allowlist",
            ));
        }

        if !Self::allowlist_allows(
            &policy.allowed_channel_ids,
            Self::activity_channel_id(activity, conversation),
        ) {
            return Some(Self::diagnostic(
                "channel_not_allowed",
                "Teams activity channel is outside the configured allowlist",
            ));
        }

        if Self::is_file_consent_activity(activity) && !policy.accept_file_consent {
            return Some(Self::diagnostic(
                "file_consent_denied",
                "Teams file consent upload is not accepted by this host-forwarded connector policy",
            ));
        }

        None
    }

    fn is_file_consent_activity(activity: &Activity) -> bool {
        activity.r#type == "invoke" && activity.name.as_deref() == Some("fileConsent/invoke")
    }

    fn file_consent_diagnostic(&self, activity: &Activity) -> Option<Value> {
        if !Self::is_file_consent_activity(activity) {
            return None;
        }
        let policy = self.ingress_policy();
        let action = activity
            .value
            .as_ref()
            .and_then(|value| value.get("action"))
            .and_then(Value::as_str)
            .unwrap_or("decline");
        Some(json!({
            "kind": "file_consent",
            "accepted_by_policy": policy.accept_file_consent,
            "action": if action == "accept" { "accept" } else { "decline" },
            "upload_info_present": activity
                .value
                .as_ref()
                .and_then(|value| value.get("uploadInfo"))
                .is_some(),
        }))
    }

    fn attachment_diagnostics(activity: &Activity) -> Vec<Value> {
        activity
            .attachments
            .iter()
            .map(|attachment| {
                let content_type = attachment.content_type.as_deref().unwrap_or("unknown");
                let disposition = if content_type
                    == "application/vnd.microsoft.teams.card.file.consent"
                {
                    "file_consent_card"
                } else if content_type.starts_with("image/") && attachment.content_url.is_some() {
                    "image_reference"
                } else if attachment.content_url.is_some() {
                    "metadata_reference"
                } else {
                    "inline_content"
                };
                json!({
                    "content_type": content_type,
                    "name": attachment.name.as_deref(),
                    "content_url_present": attachment.content_url.is_some(),
                    "content_present": attachment.content.is_some(),
                    "disposition": disposition,
                })
            })
            .collect()
    }

    fn conversation_reference(activity: &Activity, state: &TeamsConversationState) -> Value {
        json!({
            "conversation_id": state.conversation_id.as_str(),
            "service_url": activity.service_url.as_deref(),
            "bot_id": activity.recipient.as_ref().map(|recipient| recipient.id.as_str()),
            "user_id": activity.from.as_ref().map(|from| from.id.as_str()),
            "aad_object_id": activity
                .from
                .as_ref()
                .and_then(|from| from.aad_object_id.as_deref()),
            "tenant_id": Self::activity_tenant_id(activity),
            "reply_to_id": activity.reply_to_id.as_deref(),
        })
    }

    fn skipped_ingress_output(activity: &Activity, diagnostic: &Value) -> Value {
        json!({
            "accepted": false,
            "duplicate": false,
            "diagnostic": diagnostic,
            "event": Value::Null,
            "conversation_state": Value::Null,
            "conversation_reference": Value::Null,
            "attachments": Self::attachment_diagnostics(activity),
            "file_consent": Value::Null,
        })
    }

    fn validate_activity_service_url(&self, activity: &Activity) -> FcpResult<()> {
        let Some(service_url) = activity.service_url.as_deref() else {
            return Ok(());
        };
        let Some(config) = &self.config else {
            return Ok(());
        };
        let configured_url = config.bot_service_url.trim_end_matches('/');
        if service_url.starts_with(configured_url) {
            return Ok(());
        }

        match (
            reqwest::Url::parse(configured_url),
            reqwest::Url::parse(service_url),
        ) {
            (Ok(configured), Ok(actual))
                if actual.scheme() == "https"
                    && configured.scheme() == actual.scheme()
                    && configured.host_str() == actual.host_str() =>
            {
                Ok(())
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1001,
                message: format!(
                    "Unexpected Teams activity serviceUrl: {service_url}; expected host compatible with {}",
                    config.bot_service_url
                ),
            }),
        }
    }

    fn conversation_scope(activity: &Activity) -> TeamsConversationScope {
        match activity
            .conversation
            .as_ref()
            .and_then(|conversation| conversation.conversation_type.as_deref())
        {
            Some("personal") => TeamsConversationScope::Personal,
            Some("channel") => TeamsConversationScope::Channel,
            Some("groupChat") => TeamsConversationScope::GroupChat,
            Some("meeting") => TeamsConversationScope::Meeting,
            _ if activity
                .channel_data
                .as_ref()
                .and_then(|data| data.meeting.as_ref())
                .is_some() =>
            {
                TeamsConversationScope::Meeting
            }
            _ => TeamsConversationScope::Unknown,
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    fn empty_state(
        conversation_id: String,
        scope: TeamsConversationScope,
    ) -> TeamsConversationState {
        TeamsConversationState {
            conversation_id,
            scope,
            installed: false,
            last_sequence: 0,
            team_id: None,
            channel_id: None,
            chat_id: None,
            tenant_id: None,
            service_url: None,
            installation_scope: None,
            selected_channel_id: None,
            last_activity_id: None,
            last_activity_type: None,
            last_activity_timestamp: None,
            last_message_id: None,
            last_message_text: None,
            reply_to_id: None,
            last_from_id: None,
            last_from_name: None,
            members: Vec::new(),
            channel_data: None,
        }
    }

    fn update_state_for_outbound_message(
        &self,
        target: MessageTarget<'_>,
        input: &Value,
        message_id: Option<&str>,
        activity_type: &str,
    ) {
        let mut states = lock_unpoisoned(&self.conversation_states);
        let entry = states
            .entry(target.conversation_id().to_string())
            .or_insert_with(|| {
                Self::empty_state(
                    target.conversation_id().to_string(),
                    match target {
                        MessageTarget::Channel { .. } => TeamsConversationScope::Channel,
                        MessageTarget::Chat { .. } => TeamsConversationScope::GroupChat,
                    },
                )
            });

        entry.last_activity_type = Some(activity_type.to_string());
        entry
            .last_message_id
            .clone_from(&message_id.map(ToOwned::to_owned));
        entry
            .last_message_text
            .clone_from(&optional_str(input, "content").map(ToOwned::to_owned));
        entry
            .reply_to_id
            .clone_from(&optional_str(input, "message_id").map(ToOwned::to_owned));
        match target {
            MessageTarget::Channel {
                team_id,
                channel_id,
            } => {
                entry.team_id = Some(team_id.to_string());
                entry.channel_id = Some(channel_id.to_string());
            }
            MessageTarget::Chat { chat_id } => {
                entry.chat_id = Some(chat_id.to_string());
            }
        }
        drop(states);
    }

    fn build_event_from_activity(
        &self,
        req: &InvokeRequest,
        activity: &Activity,
        state: &TeamsConversationState,
    ) -> FcpResult<EventEnvelope> {
        let principal = activity.from.as_ref().map_or_else(
            || Principal {
                kind: "service".into(),
                id: "teams.system".into(),
                trust: TrustLevel::Untrusted,
                display: Some("Microsoft Teams".into()),
            },
            |from| Principal {
                kind: "user".into(),
                id: from.id.clone(),
                trust: if from.aad_object_id.is_some() {
                    TrustLevel::Paired
                } else {
                    TrustLevel::Untrusted
                },
                display: from.name.clone(),
            },
        );

        let mut resource_uris = vec![format!("teams://conversations/{}", state.conversation_id)];
        if let Some(activity_id) = activity.id.as_deref() {
            resource_uris.push(format!("teams://activities/{activity_id}"));
        }

        let payload = serde_json::to_value(activity).map_err(|err| FcpError::Internal {
            message: format!("Failed to serialize Teams activity: {err}"),
        })?;
        let mut data = EventData::new(
            self.base.id.clone(),
            self.base.instance_id.clone(),
            req.zone_id.clone(),
            principal,
            payload,
        )
        .with_resource_uris(resource_uris);
        if let Some(correlation_id) = req.correlation_id.clone() {
            data = data.with_correlation_id(correlation_id);
        }
        if let Some(reply_to_id) = activity.reply_to_id.as_deref() {
            data = data.with_thread_info(
                ThreadInfo::new(reply_to_id.to_string(), ThreadKind::Reply)
                    .with_parent_id(state.conversation_id.clone()),
            );
        }

        let mut envelope = EventEnvelope::new(Self::activity_topic(activity), data)
            .with_seq(state.last_sequence)
            .with_cursor(
                activity
                    .id
                    .clone()
                    .unwrap_or_else(|| state.last_sequence.to_string()),
            )
            .with_stream_key(state.conversation_id.clone())
            .with_ordering(fcp_core::OrderingPolicy::PerKey);
        envelope.requires_ack = false;
        Ok(envelope)
    }

    #[allow(clippy::too_many_lines)]
    fn normalize_activity(&self, req: &InvokeRequest, activity: &Activity) -> FcpResult<Value> {
        self.validate_activity_service_url(activity)?;
        let conversation =
            activity
                .conversation
                .as_ref()
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: "Teams activity is missing conversation metadata".into(),
                })?;
        if let Some(diagnostic) = self.ingress_skip_diagnostic(activity, conversation) {
            let mut output = Self::skipped_ingress_output(activity, &diagnostic);
            if let Some(file_consent) = self.file_consent_diagnostic(activity) {
                output["file_consent"] = file_consent;
            }
            return Ok(output);
        }
        let conversation_id = conversation.id.clone();
        let scope = Self::conversation_scope(activity);

        let duplicate = activity.id.as_deref().is_some_and(|activity_id| {
            lock_unpoisoned(&self.seen_activity_ids).contains(activity_id)
        });
        if !duplicate && let Some(activity_id) = activity.id.clone() {
            lock_unpoisoned(&self.seen_activity_ids).insert(activity_id);
        }

        let mut states = lock_unpoisoned(&self.conversation_states);
        let state = states
            .entry(conversation_id.clone())
            .or_insert_with(|| Self::empty_state(conversation_id.clone(), scope));

        state.scope = scope;
        if !duplicate {
            state.last_sequence = state.last_sequence.saturating_add(1);
        }
        state.service_url.clone_from(&activity.service_url);
        state.last_activity_id.clone_from(&activity.id);
        state.last_activity_type = Some(activity.r#type.clone());
        state
            .last_activity_timestamp
            .clone_from(&activity.timestamp);
        state.last_message_id.clone_from(&activity.id);
        state.last_message_text.clone_from(&activity.text);
        state.reply_to_id.clone_from(&activity.reply_to_id);
        state.last_from_id = activity.from.as_ref().map(|from| from.id.clone());
        state.last_from_name = activity.from.as_ref().and_then(|from| from.name.clone());
        state.tenant_id = activity
            .conversation
            .as_ref()
            .and_then(|conversation| conversation.tenant_id.clone())
            .or_else(|| {
                activity
                    .channel_data
                    .as_ref()
                    .and_then(|channel_data| channel_data.tenant.as_ref())
                    .map(|tenant| tenant.id.clone())
            });

        if let Some(channel_data) = &activity.channel_data {
            state.team_id = channel_data.team.as_ref().map(|team| team.id.clone());
            state.channel_id = channel_data
                .channel
                .as_ref()
                .map(|channel| channel.id.clone())
                .or_else(|| {
                    channel_data
                        .settings
                        .as_ref()
                        .and_then(|settings| settings.selected_channel.as_ref())
                        .map(|channel| channel.id.clone())
                });
            state.selected_channel_id = channel_data
                .settings
                .as_ref()
                .and_then(|settings| settings.selected_channel.as_ref())
                .map(|channel| channel.id.clone())
                .or_else(|| {
                    channel_data
                        .channel
                        .as_ref()
                        .map(|channel| channel.id.clone())
                });
            state.channel_data =
                Some(
                    serde_json::to_value(channel_data).map_err(|err| FcpError::Internal {
                        message: format!("Failed to serialize Teams channelData: {err}"),
                    })?,
                );
        }
        if matches!(
            scope,
            TeamsConversationScope::Personal
                | TeamsConversationScope::GroupChat
                | TeamsConversationScope::Meeting
        ) {
            state.chat_id = Some(conversation.id.clone());
        }

        if activity.r#type == "installationUpdate" {
            match activity.action.as_deref() {
                Some("add" | "add-upgrade") => state.installed = true,
                Some("remove" | "remove-upgrade") => state.installed = false,
                _ => {}
            }
            state.installation_scope = Some(match scope {
                TeamsConversationScope::Channel => "team".into(),
                TeamsConversationScope::Personal => "personal".into(),
                TeamsConversationScope::GroupChat => "group_chat".into(),
                TeamsConversationScope::Meeting => "meeting".into(),
                TeamsConversationScope::Unknown => "unknown".into(),
            });
        } else if activity.r#type == "conversationUpdate" {
            let bot_id = activity
                .recipient
                .as_ref()
                .map(|recipient| recipient.id.as_str());
            if activity
                .members_added
                .iter()
                .any(|member| Some(member.id.as_str()) == bot_id)
            {
                state.installed = true;
            }
            if activity
                .members_removed
                .iter()
                .any(|member| Some(member.id.as_str()) == bot_id)
            {
                state.installed = false;
            }
        }

        Self::apply_member_deltas(
            &mut state.members,
            &activity.members_added,
            &activity.members_removed,
        );

        let state_snapshot = state.clone();
        drop(states);

        let event = self.build_event_from_activity(req, activity, &state_snapshot)?;
        let diagnostic = if duplicate {
            Self::diagnostic(
                "duplicate_activity",
                "Teams activity ID was already ingested; state sequence was not advanced",
            )
        } else {
            Value::Null
        };
        Ok(json!({
            "accepted": true,
            "duplicate": duplicate,
            "diagnostic": diagnostic,
            "event": event,
            "conversation_state": state_snapshot,
            "conversation_reference": Self::conversation_reference(activity, &state_snapshot),
            "attachments": Self::attachment_diagnostics(activity),
            "file_consent": self.file_consent_diagnostic(activity),
        }))
    }

    fn apply_member_deltas(
        members: &mut Vec<ActivityAccount>,
        added: &[ActivityAccount],
        removed: &[ActivityAccount],
    ) {
        for added_member in added {
            if let Some(existing) = members
                .iter_mut()
                .find(|member| member.id == added_member.id)
            {
                *existing = added_member.clone();
            } else {
                members.push(added_member.clone());
            }
        }

        if !removed.is_empty() {
            members.retain(|member| {
                !removed
                    .iter()
                    .any(|removed_member| removed_member.id == member.id)
            });
        }
    }

    async fn invoke_send_operation(
        &self,
        client: &TeamsClient,
        req: &InvokeRequest,
    ) -> FcpResult<Value> {
        let target = MessageTarget::from_input(&req.input)?;
        let payload = Self::build_message_payload(&req.input)?;
        let message = match target {
            MessageTarget::Channel {
                team_id,
                channel_id,
            } => client
                .send_channel_message_payload(team_id, channel_id, &payload)
                .await
                .map_err(|err| err.to_fcp_error())?,
            MessageTarget::Chat { chat_id } => client
                .send_chat_message_payload(chat_id, &payload)
                .await
                .map_err(|err| err.to_fcp_error())?,
        };
        self.update_state_for_outbound_message(
            target,
            &req.input,
            message.id.as_deref(),
            "outbound_send",
        );

        Ok(json!({
            "message_id": message.id.unwrap_or_default(),
            "target": target.label(),
            "conversation_id": target.conversation_id(),
        }))
    }

    async fn invoke_reply_operation(
        &self,
        client: &TeamsClient,
        req: &InvokeRequest,
    ) -> FcpResult<Value> {
        let target = MessageTarget::from_input(&req.input)?;
        let message_id = require_str(&req.input, "message_id")?;
        let payload = Self::build_message_payload(&req.input)?;
        let (reply, delivery_mode, fallback_diagnostic) =
            match Self::send_threaded_reply(client, target, message_id, &payload).await {
                Ok(reply) => (reply, "threaded", None),
                Err(error) => {
                    let Some(diagnostic) = Self::threaded_reply_fallback_diagnostic(&error) else {
                        return Err(error.to_fcp_error());
                    };
                    warn!(
                        event = "teams.reply.threaded_fallback",
                        target = target.label(),
                        status_code = diagnostic.status_code,
                        provider_code = diagnostic.code,
                        "Teams threaded reply rejected; trying flat message fallback"
                    );
                    let reply = Self::send_flat_reply_fallback(client, target, &payload)
                        .await
                        .map_err(|fallback_error| fallback_error.to_fcp_error())?;
                    (reply, "flat_fallback", Some(diagnostic.to_json()))
                }
            };
        let activity_type = if delivery_mode == "flat_fallback" {
            "outbound_reply_flat_fallback"
        } else {
            "outbound_reply"
        };
        self.update_state_for_outbound_message(
            target,
            &req.input,
            reply.id.as_deref(),
            activity_type,
        );

        Ok(json!({
            "message_id": reply.id.unwrap_or_default(),
            "reply_to_id": message_id,
            "target": target.label(),
            "conversation_id": target.conversation_id(),
            "threaded_attempted": true,
            "delivery_mode": delivery_mode,
            "fallback_diagnostic": fallback_diagnostic,
        }))
    }

    async fn send_threaded_reply(
        client: &TeamsClient,
        target: MessageTarget<'_>,
        message_id: &str,
        payload: &Value,
    ) -> Result<crate::types::ChatMessage, TeamsError> {
        match target {
            MessageTarget::Channel {
                team_id,
                channel_id,
            } => {
                client
                    .reply_to_channel_message(team_id, channel_id, message_id, payload)
                    .await
            }
            MessageTarget::Chat { chat_id } => {
                client
                    .reply_with_quote(chat_id, &[message_id.to_string()], payload)
                    .await
            }
        }
    }

    async fn send_flat_reply_fallback(
        client: &TeamsClient,
        target: MessageTarget<'_>,
        payload: &Value,
    ) -> Result<crate::types::ChatMessage, TeamsError> {
        match target {
            MessageTarget::Channel {
                team_id,
                channel_id,
            } => {
                client
                    .send_channel_message_payload(team_id, channel_id, payload)
                    .await
            }
            MessageTarget::Chat { chat_id } => {
                client.send_chat_message_payload(chat_id, payload).await
            }
        }
    }

    fn threaded_reply_fallback_diagnostic(
        error: &TeamsError,
    ) -> Option<ThreadedReplyFallbackDiagnostic<'_>> {
        match error {
            TeamsError::Graph {
                code,
                status_code: 400,
                ..
            } => Some(ThreadedReplyFallbackDiagnostic {
                status_code: 400,
                code,
            }),
            _ => None,
        }
    }

    async fn invoke_update_operation(
        &self,
        client: &TeamsClient,
        req: &InvokeRequest,
    ) -> FcpResult<Value> {
        let target = MessageTarget::from_input(&req.input)?;
        let message_id = require_str(&req.input, "message_id")?;
        let payload = Self::build_message_payload(&req.input)?;
        match target {
            MessageTarget::Channel {
                team_id,
                channel_id,
            } => {
                if let Some(reply_id) = optional_str(&req.input, "reply_id") {
                    client
                        .update_channel_reply(team_id, channel_id, message_id, reply_id, &payload)
                        .await
                        .map_err(|err| err.to_fcp_error())?;
                } else {
                    client
                        .update_channel_message(team_id, channel_id, message_id, &payload)
                        .await
                        .map_err(|err| err.to_fcp_error())?;
                }
            }
            MessageTarget::Chat { chat_id } => client
                .update_chat_message(chat_id, message_id, &payload)
                .await
                .map_err(|err| err.to_fcp_error())?,
        }

        self.update_state_for_outbound_message(
            target,
            &req.input,
            Some(message_id),
            "outbound_update",
        );
        Ok(json!({
            "status": "updated",
            "target": target.label(),
            "conversation_id": target.conversation_id(),
        }))
    }

    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.teams")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
            conversation_states: Mutex::new(HashMap::new()),
            idempotent_results: Mutex::new(BoundedJsonCache::new(IDEMPOTENT_RESPONSE_LIMIT)),
            seen_activity_ids: Mutex::new(BoundedKeySet::new(ACTIVITY_DEDUP_LIMIT)),
        }
    }

    /// Return this connector instance identifier for bound capability tokens.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| {
            let (graph_network_ok, graph_network_message) =
                graph_base_url_policy(&config.graph_base_url);
            let (bot_service_url_ok, bot_service_url_message) =
                bot_service_url_policy(&config.bot_service_url);
            let requires_credential_injection =
                matches!(&config.auth, TeamsAuth::CredentialId { .. });
            let uses_client_credentials =
                matches!(&config.auth, TeamsAuth::ClientCredentials { .. });
            let full_connector_surface_message = match &config.auth {
                TeamsAuth::AccessToken { .. } => "Delegated bearer token can satisfy `/me`-backed list/read flows and standard send/reply/update operations, assuming the Graph scopes are granted.".into(),
                TeamsAuth::CredentialId { .. } => "Host-side credential injection is required. Inject a delegated user bearer token if you need `/me`-backed list/read flows and standard send/reply/update operations; app-only injection is only suitable for a narrower subset plus migration APIs.".into(),
                TeamsAuth::ClientCredentials { .. } => "client_credentials acquires an app-only token, but this connector's `/me` readiness/list flows and standard send/reply/update operations require delegated user context. Microsoft Graph application permissions for Teams message sends are limited to migration scenarios, so app-only auth does not prove full connector readiness.".into(),
            };

            ProvisioningReadiness {
                auth_mode: auth_mode_label(&config.auth),
                requires_credential_injection,
                credential_material_configured: !requires_credential_injection,
                uses_client_credentials,
                full_connector_surface_supported: !uses_client_credentials,
                full_connector_surface_message,
                graph_base_url: config.graph_base_url.clone(),
                graph_network_ok,
                graph_network_message,
                bot_service_url: config.bot_service_url.clone(),
                bot_service_url_ok,
                bot_service_url_message,
                tenant_hint_configured: config.tenant_id.is_some(),
                retry: self.retry_config.clone(),
            }
        })
    }

    fn observability_payload(&self, provisioning: Option<&ProvisioningReadiness>) -> Value {
        let conversation_state_count = lock_unpoisoned(&self.conversation_states).len();
        let idempotent_cache_entries = lock_unpoisoned(&self.idempotent_results).entries.len();
        let seen_activity_id_count = lock_unpoisoned(&self.seen_activity_ids).entries.len();

        json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": provisioning,
            "operator_guidance": operator_guidance(),
            "observability": {
                "conversation_state_count": conversation_state_count,
                "idempotent_cache_entries": idempotent_cache_entries,
                "seen_activity_id_count": seen_activity_id_count,
                "retry_config": self.retry_config.clone(),
            },
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        provisioning: Option<&ProvisioningReadiness>,
    ) -> SelfCheckReport {
        report.details = Some(self.observability_payload(provisioning));
        report
    }

    fn classify_self_check_error(error: &TeamsError) -> SelfCheckReport {
        match error {
            TeamsError::Unauthorized(message) => SelfCheckReport::failed(
                "token_invalid_or_expired",
                format!("Microsoft Graph rejected the bearer token: {message}"),
            ),
            TeamsError::Forbidden(message) => {
                let normalized = message.to_ascii_lowercase();
                let reason_code = if normalized.contains("consent")
                    || normalized.contains("insufficient")
                    || normalized.contains("privilege")
                    || normalized.contains("permission")
                    || normalized.contains("authorization_requestdenied")
                {
                    "admin_consent_or_permission_missing"
                } else {
                    "graph_forbidden"
                };
                SelfCheckReport::failed(reason_code, message.clone())
            }
            TeamsError::RateLimited { retry_after_ms } => SelfCheckReport::degraded(
                "graph_rate_limited",
                format!(
                    "Microsoft Graph throttled the Teams readiness probe; retry after {retry_after_ms}ms"
                ),
            ),
            TeamsError::NotFound(message) => {
                SelfCheckReport::failed("graph_endpoint_not_found", message.clone())
            }
            other if other.is_retryable() => {
                SelfCheckReport::degraded("self_check_retryable", other.to_string())
            }
            other => SelfCheckReport::failed("self_check_failed", other.to_string()),
        }
    }

    /// Run connector diagnostics.
    #[must_use]
    pub fn doctor(&self) -> DoctorResult {
        let provisioning = self.provisioning_readiness();
        let mut checks = Vec::new();

        let configured = self.config.is_some();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: configured,
            message: Some(if configured {
                "Configuration loaded".into()
            } else {
                "Not configured - run configure first".into()
            }),
            critical: true,
        });

        let client_ok = self.client.is_some();
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: client_ok,
            message: Some(if client_ok {
                "Graph API client initialized".into()
            } else {
                "Graph client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime_initialized".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "ConnectorRuntime missing; re-run configure".into()
            }),
            critical: true,
        });

        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "graph_network_constraints".into(),
                passed: readiness.graph_network_ok,
                message: Some(readiness.graph_network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "bot_service_url_policy".into(),
                passed: readiness.bot_service_url_ok,
                message: Some(readiness.bot_service_url_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "credential_injection".into(),
                passed: readiness.credential_material_configured,
                message: Some(if readiness.requires_credential_injection {
                    "Credential injection required via host or egress proxy before live readiness can be proven".into()
                } else {
                    "Credential material configured directly".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth_surface_compatibility".into(),
                passed: readiness.full_connector_surface_supported,
                message: Some(readiness.full_connector_surface_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "tenant_hint".into(),
                passed: true,
                message: Some(if readiness.tenant_hint_configured {
                    "tenant_id hint configured for bot activity or tenant-scoped routing".into()
                } else {
                    "tenant_id hint not configured; acceptable unless your host routing depends on explicit tenant scoping".into()
                }),
                critical: false,
            });
        }

        let result = DoctorResult::from_checks(checks, provisioning);
        let failed_checks = result.checks.iter().filter(|check| !check.passed).count();
        info!(
            event = "teams.provisioning.doctor",
            status = result.status_label(),
            check_count = result.checks.len(),
            failed_checks,
            "Teams doctor checks completed"
        );
        result
    }
}

impl Default for TeamsConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default, Deserialize)]
struct TeamsManifestOperationCatalog {
    #[serde(default)]
    provides: TeamsManifestProvides,
}

#[derive(Debug, Default, Deserialize)]
struct TeamsManifestProvides {
    #[serde(default)]
    operations: BTreeMap<String, fcp_manifest::OperationSection>,
}

fn manifest_operation_catalog() -> Result<BTreeMap<String, fcp_manifest::OperationSection>, String>
{
    toml::from_str::<TeamsManifestOperationCatalog>(MANIFEST_TOML)
        .map(|manifest| manifest.provides.operations)
        .map_err(|error| format!("embedded Teams manifest operation catalog is invalid: {error}"))
}

/// Build the typed operations catalog from `manifest.toml`.
///
/// # Panics
///
/// Panics if the embedded Teams manifest operation catalog cannot be parsed or
/// contains an invalid operation identifier.
#[must_use]
pub fn operations_info() -> Vec<OperationInfo> {
    try_operations_info().expect("embedded Teams manifest operations must parse")
}

fn try_operations_info() -> Result<Vec<OperationInfo>, String> {
    let mut operations: Vec<_> = manifest_operation_catalog()?.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(&id, operation))
        .collect()
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(OPERATION_ORDER.len())
}

fn operation_info_from_manifest(
    id: &str,
    operation: fcp_manifest::OperationSection,
) -> Result<OperationInfo, String> {
    let summary = teams_operation_summary(id, &operation.description);
    let operation_id = OperationId::new(id.to_string())
        .map_err(|error| format!("manifest operation `{id}` has invalid ID: {error}"))?;
    Ok(OperationInfo {
        id: operation_id,
        summary,
        description: Some(operation.description),
        input_schema: operation.input_schema,
        output_schema: operation.output_schema,
        capability: operation.capability,
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints,
        rate_limit: operation
            .rate_limit
            .map(|rate_limit| rate_limit.as_inner().clone()),
        requires_approval: Some(operation.requires_approval.into()),
    })
}

fn teams_operation_summary(operation_id: &str, fallback: &str) -> String {
    match operation_id {
        OP_LIST_TEAMS => "List joined teams",
        OP_GET_TEAM => "Get team details",
        OP_LIST_CHANNELS => "List channels in a team",
        OP_GET_CHANNEL => "Get channel details",
        OP_SEND_CHANNEL_MSG => "Send a message to a channel",
        OP_LIST_CHATS => "List user's chats",
        OP_SEND_CHAT_MSG => "Send a chat message",
        OP_LIST_CHAT_MSGS => "List messages in a chat",
        OP_SEND_CARD => "Send an adaptive card",
        OP_REPLY_MSG => "Reply to a Teams message",
        OP_UPDATE_MSG => "Update a Teams message",
        OP_INGEST_ACTIVITY => "Normalize an inbound Teams activity",
        OP_GET_CONVERSATION_STATE => "Get cached Teams conversation state",
        _ => fallback,
    }
    .to_owned()
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' field"),
        })
}

fn optional_str<'a>(input: &'a Value, field: &str) -> Option<&'a str> {
    input.get(field).and_then(|value| value.as_str())
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy)]
struct ThreadedReplyFallbackDiagnostic<'a> {
    status_code: u16,
    code: &'a str,
}

impl ThreadedReplyFallbackDiagnostic<'_> {
    fn to_json(self) -> Value {
        json!({
            "reason": "threaded_reply_rejected",
            "provider": "microsoft_graph",
            "status_code": self.status_code,
            "code": self.code,
        })
    }
}

#[derive(Clone, Copy)]
enum MessageTarget<'a> {
    Channel {
        team_id: &'a str,
        channel_id: &'a str,
    },
    Chat {
        chat_id: &'a str,
    },
}

impl<'a> MessageTarget<'a> {
    fn from_input(input: &'a Value) -> FcpResult<Self> {
        match (
            optional_str(input, "team_id"),
            optional_str(input, "channel_id"),
            optional_str(input, "chat_id"),
        ) {
            (Some(team_id), Some(channel_id), None) => Ok(Self::Channel {
                team_id,
                channel_id,
            }),
            (None, None, Some(chat_id)) => Ok(Self::Chat { chat_id }),
            _ => Err(FcpError::InvalidRequest {
                code: 1005,
                message:
                    "Provide either chat_id or both team_id and channel_id for Teams message routing"
                        .into(),
            }),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Channel { .. } => "channel",
            Self::Chat { .. } => "chat",
        }
    }

    const fn conversation_id(self) -> &'a str {
        match self {
            Self::Channel { channel_id, .. } => channel_id,
            Self::Chat { chat_id } => chat_id,
        }
    }
}

fcp_core::impl_fcp_sealed!(TeamsConnector);

#[async_trait]
impl FcpConnector for TeamsConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: crate::types::TeamsConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Teams config: {e}"),
            })?;
        let (graph_base_url_ok, graph_base_url_message) =
            graph_base_url_policy(&config.graph_base_url);
        if !graph_base_url_ok {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Invalid Teams graph_base_url: {graph_base_url_message}"),
            });
        }

        self.retry_config = config.retry.clone();
        self.runtime = Some(ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(config.timeout_ms)),
        ));

        let timeout = Duration::from_millis(config.timeout_ms);
        let client = match &config.auth {
            TeamsAuth::AccessToken { access_token } => {
                TeamsClient::new(&config.graph_base_url, access_token, timeout).map_err(|e| {
                    FcpError::Internal {
                        message: format!("Failed to create Teams client: {e}"),
                    }
                })?
            }
            TeamsAuth::CredentialId { credential_id } => {
                TeamsClient::new_secretless(&config.graph_base_url, credential_id, timeout)
                    .map_err(|e| FcpError::Internal {
                        message: format!("Failed to create Teams client: {e}"),
                    })?
            }
            TeamsAuth::ClientCredentials {
                client_id,
                client_secret,
                tenant_id,
            } => TeamsClient::from_client_credentials(
                &config.graph_base_url,
                client_id,
                client_secret,
                tenant_id,
                timeout,
            )
            .await
            .map_err(|e| FcpError::Internal {
                message: format!("Failed to create Teams client: {e}"),
            })?,
        };

        self.client = Some(client);
        self.config = Some(config);
        lock_unpoisoned(&self.conversation_states).clear();
        *lock_unpoisoned(&self.idempotent_results) =
            BoundedJsonCache::new(IDEMPOTENT_RESPONSE_LIMIT);
        *lock_unpoisoned(&self.seen_activity_ids) = BoundedKeySet::new(ACTIVITY_DEDUP_LIMIT);
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self.provisioning_readiness();
        let mut snapshot = match &provisioning {
            Some(readiness) if !readiness.graph_network_ok || !readiness.bot_service_url_ok => {
                HealthSnapshot::error("network constraints invalid")
            }
            Some(readiness) if readiness.uses_client_credentials => {
                HealthSnapshot::degraded("delegated user context required")
            }
            Some(readiness) if readiness.requires_credential_injection => {
                HealthSnapshot::degraded("credential injection required")
            }
            Some(_) if self.client.is_some() && self.runtime.is_some() => HealthSnapshot::ready(),
            Some(_) | None => HealthSnapshot::degraded("not configured"),
        };
        snapshot.details = Some(self.observability_payload(provisioning.as_ref()));
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };
        let provisioning = self.provisioning_readiness();
        let Some(readiness) = provisioning.clone() else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };

        if !readiness.graph_network_ok || !readiness.bot_service_url_ok {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "network_constraints_invalid",
                    format!(
                        "{}; {}",
                        readiness.graph_network_message, readiness.bot_service_url_message
                    ),
                ),
                Some(&readiness),
            ));
        }

        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Teams Graph client not initialized; re-run configure",
                ),
                Some(&readiness),
            ));
        };

        if self.runtime.is_none() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(&readiness),
            ));
        }

        if client.is_secretless() {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "credential_injection_required",
                    "Configured in credential_id mode; the host or egress proxy must inject a delegated bearer token before Teams live readiness can be proven",
                ),
                Some(&readiness),
            ));
        }

        // Microsoft Graph `/me` endpoints are delegated-only, and standard Teams
        // message send/reply/update application permissions are reserved for
        // migration scenarios. App-only tokens therefore cannot prove full
        // connector readiness for this surface.
        if matches!(&config.auth, TeamsAuth::ClientCredentials { .. }) {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded(
                    "delegated_user_context_required",
                    "client_credentials acquires an app-only token, but this connector's `/me` readiness/list flows and standard send/reply/update operations require delegated user context",
                ),
                Some(&readiness),
            ));
        }

        let report = match client.health_check().await {
            Ok(()) => SelfCheckReport::ok(),
            Err(error) => Self::classify_self_check_error(&error),
        };
        let report = self.attach_self_check_details(report, Some(&readiness));
        info!(
            event = "teams.provisioning.self_check",
            status = ?report.status,
            reason_code = report.reason_code.as_deref().unwrap_or("ok"),
            "Teams self_check completed"
        );
        Ok(report)
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: vec![
                EventInfo {
                    topic: "teams.message.received".into(),
                    schema: json!({ "type": "object" }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "teams.conversation_update".into(),
                    schema: json!({ "type": "object" }),
                    requires_ack: false,
                },
                EventInfo {
                    topic: "teams.installation_update".into(),
                    schema: json!({ "type": "object" }),
                    requires_ack: false,
                },
            ],
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl TeamsConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        req.validate_idempotency_key()
            .map_err(|err| FcpError::InvalidRequest {
                code: 1005,
                message: err.to_string(),
            })?;

        let operation = req.operation.as_str();
        let required_cap = match operation {
            OP_LIST_TEAMS
            | OP_GET_TEAM
            | OP_LIST_CHANNELS
            | OP_GET_CHANNEL
            | OP_LIST_CHATS
            | OP_LIST_CHAT_MSGS
            | OP_GET_CONVERSATION_STATE => CapabilityId::from_static(CAP_READ),
            OP_SEND_CHANNEL_MSG | OP_SEND_CHAT_MSG | OP_SEND_CARD | OP_REPLY_MSG
            | OP_UPDATE_MSG | OP_INGEST_ACTIVITY => CapabilityId::from_static(CAP_WRITE),
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        let verifier = self.verifier.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing capability verifier".into(),
        })?;
        let _bound = verifier.verify_bound(
            req.capability_token.clone(),
            &required_cap,
            &req.operation,
            &[],
        )?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Teams client".into(),
        })?;

        if Self::uses_response_cache(operation)
            && let Some(cached) = self.cached_output(operation, &req)
        {
            return Ok(InvokeResponse::ok(req.id, cached));
        }

        let output = match operation {
            OP_LIST_TEAMS => {
                let teams = client.list_my_teams().await.map_err(|e| e.to_fcp_error())?;
                json!({ "teams": teams })
            }
            OP_GET_TEAM => {
                let team_id = require_str(&req.input, "team_id")?;
                let team = client
                    .get_team(team_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&team).map_err(|e| FcpError::Internal {
                    message: format!("Serialization error: {e}"),
                })?
            }
            OP_LIST_CHANNELS => {
                let team_id = require_str(&req.input, "team_id")?;
                let channels = client
                    .list_channels(team_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "channels": channels })
            }
            OP_GET_CHANNEL => {
                let team_id = require_str(&req.input, "team_id")?;
                let channel_id = require_str(&req.input, "channel_id")?;
                let channel = client
                    .get_channel(team_id, channel_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&channel).map_err(|e| FcpError::Internal {
                    message: format!("Serialization error: {e}"),
                })?
            }
            OP_LIST_CHATS => {
                let chats = client.list_my_chats().await.map_err(|e| e.to_fcp_error())?;
                json!({ "chats": chats })
            }
            OP_SEND_CHANNEL_MSG | OP_SEND_CHAT_MSG => {
                self.invoke_send_operation(client, &req).await?
            }
            OP_LIST_CHAT_MSGS => {
                let chat_id = require_str(&req.input, "chat_id")?;
                let messages = client
                    .list_chat_messages(chat_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({ "messages": messages })
            }
            OP_SEND_CARD => {
                if req.input.get("adaptive_card").is_none() {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "adaptive_card is required for teams.send_card".into(),
                    });
                }
                self.invoke_send_operation(client, &req).await?
            }
            OP_REPLY_MSG => self.invoke_reply_operation(client, &req).await?,
            OP_UPDATE_MSG => self.invoke_update_operation(client, &req).await?,
            OP_INGEST_ACTIVITY => {
                let activity: Activity =
                    serde_json::from_value(req.input.clone()).map_err(|err| {
                        FcpError::InvalidRequest {
                            code: 1001,
                            message: format!("Invalid Teams activity payload: {err}"),
                        }
                    })?;
                self.normalize_activity(&req, &activity)?
            }
            OP_GET_CONVERSATION_STATE => {
                let conversation_id = require_str(&req.input, "conversation_id")?;
                let states = lock_unpoisoned(&self.conversation_states);
                let state = states.get(conversation_id).cloned().ok_or_else(|| {
                    FcpError::InvalidRequest {
                        code: 1004,
                        message: format!("Unknown conversation_id: {conversation_id}"),
                    }
                })?;
                drop(states);
                json!({ "conversation_state": state })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        if Self::uses_response_cache(operation) {
            self.remember_output(operation, &req, &output);
        }

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::{IdempotencyClass, SafetyTier};
    use std::collections::BTreeSet;

    fn manually_configured_connector(
        auth: TeamsAuth,
        client: TeamsClient,
        graph_base_url: &str,
    ) -> TeamsConnector {
        let mut connector = TeamsConnector::new();
        connector.config = Some(crate::types::TeamsConfig {
            graph_base_url: graph_base_url.into(),
            bot_service_url: "https://smba.trafficmanager.net/amer".into(),
            auth,
            tenant_id: None,
            ingress_policy: TeamsIngressPolicy::default(),
            retry: HttpRetryConfig::default(),
            timeout_ms: 1_000,
        });
        connector.client = Some(client);
        connector.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));
        connector.base.set_configured(true);
        connector
    }

    fn reply_request(input: Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_reply"),
            connector_id: ConnectorId::from_static("fcp.teams"),
            operation: OperationId::from_static(OP_REPLY_MSG),
            zone_id: ZoneId::work(),
            input,
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 13);
    }

    #[test]
    fn manifest_declares_teams_operation_metadata() {
        let operations =
            manifest_operation_catalog().expect("embedded manifest operation catalog should parse");
        assert_eq!(operations.len(), OPERATION_ORDER.len());

        let manifest_ids = operations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let runtime_ids = OPERATION_ORDER.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(manifest_ids, runtime_ids);

        for operation_id in OPERATION_ORDER {
            let operation = operations
                .get(operation_id)
                .expect("operation should be declared in manifest");
            assert!(operation.input_schema.is_object());
            assert!(operation.output_schema.is_object());
            assert!(!operation.ai_hints.when_to_use.is_empty());
        }

        for operation_id in [
            OP_LIST_TEAMS,
            OP_GET_TEAM,
            OP_LIST_CHANNELS,
            OP_GET_CHANNEL,
            OP_SEND_CHANNEL_MSG,
            OP_LIST_CHATS,
            OP_SEND_CHAT_MSG,
            OP_LIST_CHAT_MSGS,
            OP_SEND_CARD,
            OP_REPLY_MSG,
            OP_UPDATE_MSG,
        ] {
            let operation = operations
                .get(operation_id)
                .expect("Graph operation should be declared");
            let network_constraints = operation
                .network_constraints
                .as_ref()
                .expect("Graph operation should declare network metadata");
            assert_eq!(network_constraints.host_allow, vec!["graph.microsoft.com"]);
            assert_eq!(network_constraints.port_allow, vec![443]);
            assert!(network_constraints.require_sni);
            assert!(network_constraints.deny_localhost);
            assert!(network_constraints.deny_private_ranges);
            assert!(network_constraints.deny_tailnet_ranges);
            assert!(network_constraints.deny_ip_literals);
            assert_eq!(network_constraints.max_redirects, 0);
        }

        for operation_id in [OP_INGEST_ACTIVITY, OP_GET_CONVERSATION_STATE] {
            let operation = operations
                .get(operation_id)
                .expect("local operation should be declared");
            let network_constraints = operation
                .network_constraints
                .as_ref()
                .expect("local operation should declare no-egress network metadata");
            assert_eq!(network_constraints.host_allow, vec!["none.invalid"]);
            assert_eq!(network_constraints.port_allow, vec![0]);
            assert!(!network_constraints.require_sni);
            assert!(network_constraints.deny_localhost);
            assert!(network_constraints.deny_private_ranges);
            assert!(network_constraints.deny_tailnet_ranges);
            assert!(network_constraints.deny_ip_literals);
            assert_eq!(network_constraints.dns_max_ips, 0);
            assert_eq!(network_constraints.max_redirects, 0);
        }

        let send = operations
            .get(OP_SEND_CHANNEL_MSG)
            .expect("send channel operation should be declared");
        assert_eq!(send.capability.as_str(), CAP_WRITE);
        assert_eq!(
            send.input_schema["required"],
            json!(["team_id", "channel_id", "content"])
        );

        let ingest = operations
            .get(OP_INGEST_ACTIVITY)
            .expect("ingest activity operation should be declared");
        assert_eq!(ingest.capability.as_str(), CAP_WRITE);
        assert_eq!(
            ingest.output_schema["properties"]["accepted"]["type"],
            json!("boolean")
        );
        assert_eq!(
            ingest.output_schema["properties"]["attachments"]["type"],
            json!("array")
        );
    }

    #[test]
    fn operations_info_uses_manifest_operation_metadata() {
        let operations =
            manifest_operation_catalog().expect("embedded manifest operation catalog should parse");
        let runtime_operations = operations_info();
        assert_eq!(runtime_operations.len(), operations.len());

        for (index, operation_id) in OPERATION_ORDER.iter().enumerate() {
            let manifest_operation = operations
                .get(*operation_id)
                .expect("operation should be declared in manifest");
            let runtime_operation = runtime_operations
                .get(index)
                .expect("operation should use manifest order");
            assert_eq!(runtime_operation.id.as_str(), *operation_id);
            assert_eq!(
                runtime_operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(
                runtime_operation.capability.as_str(),
                manifest_operation.capability.as_str()
            );
            assert_eq!(runtime_operation.risk_level, manifest_operation.risk_level);
            assert_eq!(
                runtime_operation.safety_tier,
                manifest_operation.safety_tier
            );
            assert_eq!(
                runtime_operation.idempotency,
                manifest_operation.idempotency
            );
            assert_eq!(
                &runtime_operation.input_schema,
                &manifest_operation.input_schema
            );
            assert_eq!(
                &runtime_operation.output_schema,
                &manifest_operation.output_schema
            );
            assert_eq!(
                runtime_operation.ai_hints.when_to_use,
                manifest_operation.ai_hints.when_to_use
            );
        }
    }

    #[test]
    fn test_operations_have_ai_hints() {
        for op in &operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_send_operations_are_risky() {
        let ops = operations_info();
        let send_ch = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_CHANNEL_MSG)
            .unwrap();
        assert_eq!(send_ch.safety_tier, SafetyTier::Risky);
        assert_eq!(send_ch.idempotency, IdempotencyClass::None);

        let send_chat = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_CHAT_MSG)
            .unwrap();
        assert_eq!(send_chat.safety_tier, SafetyTier::Risky);

        let send_card = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SEND_CARD)
            .unwrap();
        assert_eq!(send_card.idempotency, IdempotencyClass::BestEffort);
    }

    #[test]
    fn test_read_operations_are_safe() {
        let ops = operations_info();
        let list_teams = ops
            .iter()
            .find(|op| op.id.as_str() == OP_LIST_TEAMS)
            .unwrap();
        assert_eq!(list_teams.safety_tier, SafetyTier::Safe);
        assert_eq!(list_teams.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_introspection() {
        let connector = TeamsConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 13);
        assert_eq!(intro.events.len(), 3);
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
    }

    #[test]
    fn test_build_message_payload_promotes_adaptive_card_to_html() {
        let payload = TeamsConnector::build_message_payload(&json!({
            "adaptive_card": {
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [{ "type": "TextBlock", "text": "Hello" }]
            }
        }))
        .unwrap();
        assert_eq!(payload["body"]["contentType"], "html");
        assert_eq!(
            payload["attachments"][0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
    }

    #[test]
    fn test_reply_message_schema_exposes_fallback_diagnostics() {
        let ops = operations_info();
        let reply = ops
            .iter()
            .find(|op| op.id.as_str() == OP_REPLY_MSG)
            .unwrap();
        assert_eq!(
            reply.output_schema["properties"]["delivery_mode"]["type"],
            "string"
        );
        assert_eq!(
            reply.output_schema["properties"]["threaded_attempted"]["type"],
            "boolean"
        );
        assert_eq!(
            reply.output_schema["properties"]["fallback_diagnostic"]["type"],
            "object"
        );
    }

    #[test]
    fn test_message_target_parses_channel_and_chat_routes() {
        let channel_input = json!({
            "team_id": "team_1",
            "channel_id": "channel_1",
        });
        let channel = MessageTarget::from_input(&channel_input).unwrap();
        assert_eq!(channel.label(), "channel");
        assert_eq!(channel.conversation_id(), "channel_1");

        let chat_input = json!({
            "chat_id": "chat_1",
        });
        let chat = MessageTarget::from_input(&chat_input).unwrap();
        assert_eq!(chat.label(), "chat");
        assert_eq!(chat.conversation_id(), "chat_1");

        let ambiguous_input = json!({
            "team_id": "team_1",
            "channel_id": "channel_1",
            "chat_id": "chat_1",
        });
        assert!(MessageTarget::from_input(&ambiguous_input).is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_reply_operation_reports_threaded_channel_delivery() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/teams/team_1/channels/channel_1/messages/root_1/replies",
            ))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(json!({
                "id": "reply_1",
                "replyToId": "root_1",
                "body": { "contentType": "text", "content": "threaded" }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let connector = TeamsConnector::new();
        let output = connector
            .invoke_reply_operation(
                &client,
                &reply_request(json!({
                    "team_id": "team_1",
                    "channel_id": "channel_1",
                    "message_id": "root_1",
                    "content": "threaded",
                })),
            )
            .await
            .unwrap();

        assert_eq!(output["message_id"], "reply_1");
        assert_eq!(output["reply_to_id"], "root_1");
        assert_eq!(output["delivery_mode"], "threaded");
        assert_eq!(output["threaded_attempted"], json!(true));
        assert!(output["fallback_diagnostic"].is_null());
    }

    #[fcp_async_core::runtime::test]
    async fn test_reply_operation_channel_falls_back_to_flat_send_on_graph_400() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/teams/team_1/channels/channel_1/messages/root_1/replies",
            ))
            .respond_with(wiremock::ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "code": "BadRequest",
                    "message": "Threaded replies are not supported in this conversation"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/teams/team_1/channels/channel_1/messages",
            ))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(json!({
                "id": "flat_1",
                "body": { "contentType": "text", "content": "fallback" }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let connector = TeamsConnector::new();
        let output = connector
            .invoke_reply_operation(
                &client,
                &reply_request(json!({
                    "team_id": "team_1",
                    "channel_id": "channel_1",
                    "message_id": "root_1",
                    "content": "fallback",
                })),
            )
            .await
            .unwrap();

        assert_eq!(output["message_id"], "flat_1");
        assert_eq!(output["reply_to_id"], "root_1");
        assert_eq!(output["delivery_mode"], "flat_fallback");
        assert_eq!(output["fallback_diagnostic"]["status_code"], 400);
        assert_eq!(output["fallback_diagnostic"]["code"], "BadRequest");
        assert!(output["fallback_diagnostic"].get("message").is_none());

        let state = lock_unpoisoned(&connector.conversation_states)
            .get("channel_1")
            .cloned()
            .unwrap();
        assert_eq!(
            state.last_activity_type.as_deref(),
            Some("outbound_reply_flat_fallback")
        );
        assert_eq!(state.reply_to_id.as_deref(), Some("root_1"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_reply_operation_chat_falls_back_to_flat_send_on_graph_400() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/chats/chat_1/messages/replyWithQuote",
            ))
            .respond_with(wiremock::ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "code": "BadRequest",
                    "message": "Reply with quote is unavailable"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/chats/chat_1/messages"))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(json!({
                "id": "flat_chat_1",
                "chatId": "chat_1",
                "body": { "contentType": "text", "content": "fallback" }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let connector = TeamsConnector::new();
        let output = connector
            .invoke_reply_operation(
                &client,
                &reply_request(json!({
                    "chat_id": "chat_1",
                    "message_id": "root_1",
                    "content": "fallback",
                })),
            )
            .await
            .unwrap();

        assert_eq!(output["message_id"], "flat_chat_1");
        assert_eq!(output["target"], "chat");
        assert_eq!(output["conversation_id"], "chat_1");
        assert_eq!(output["delivery_mode"], "flat_fallback");
    }

    #[fcp_async_core::runtime::test]
    async fn test_reply_operation_does_not_fallback_on_rate_limit() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/teams/team_1/channels/channel_1/messages/root_1/replies",
            ))
            .respond_with(wiremock::ResponseTemplate::new(429))
            .expect(1)
            .mount(&mock_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/teams/team_1/channels/channel_1/messages",
            ))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(json!({
                "id": "must_not_send"
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let connector = TeamsConnector::new();
        let error = connector
            .invoke_reply_operation(
                &client,
                &reply_request(json!({
                    "team_id": "team_1",
                    "channel_id": "channel_1",
                    "message_id": "root_1",
                    "content": "do not fallback",
                })),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, FcpError::RateLimited { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_reply_operation_does_not_fallback_on_forbidden() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/teams/team_1/channels/channel_1/messages/root_1/replies",
            ))
            .respond_with(wiremock::ResponseTemplate::new(403).set_body_json(json!({
                "error": {
                    "code": "Forbidden",
                    "message": "Insufficient privileges to complete the operation."
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/teams/team_1/channels/channel_1/messages",
            ))
            .respond_with(wiremock::ResponseTemplate::new(201).set_body_json(json!({
                "id": "must_not_send"
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let connector = TeamsConnector::new();
        let error = connector
            .invoke_reply_operation(
                &client,
                &reply_request(json!({
                    "team_id": "team_1",
                    "channel_id": "channel_1",
                    "message_id": "root_1",
                    "content": "do not fallback",
                })),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, FcpError::Unauthorized { code: 2003, .. }));
    }

    #[test]
    fn test_normalize_activity_tracks_installation_state() {
        let connector = TeamsConnector::new();
        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_ingest"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_INGEST_ACTIVITY),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: Some("ingest-1".into()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let activity: Activity = serde_json::from_value(json!({
            "type": "installationUpdate",
            "id": "act_install",
            "timestamp": "2026-01-01T00:00:00Z",
            "serviceUrl": "https://smba.trafficmanager.net/amer/",
            "action": "add",
            "conversation": {
                "id": "19:channel@thread.tacv2",
                "conversationType": "channel",
                "tenantId": "tenant_1"
            },
            "recipient": { "id": "28:bot", "name": "Test Bot" },
            "channelData": {
                "tenant": { "id": "tenant_1" },
                "team": { "id": "19:team@thread.tacv2" },
                "channel": { "id": "19:channel@thread.tacv2" },
                "settings": {
                    "selectedChannel": { "id": "19:selected@thread.tacv2" }
                }
            }
        }))
        .unwrap();

        let output = connector.normalize_activity(&req, &activity).unwrap();
        assert_eq!(output["duplicate"], false);
        assert_eq!(output["conversation_state"]["installed"], true);
        assert_eq!(
            output["conversation_state"]["selectedChannelId"],
            "19:selected@thread.tacv2"
        );
    }

    #[test]
    fn test_normalize_activity_deduplicates_activity_id() {
        let connector = TeamsConnector::new();
        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_ingest_dup"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_INGEST_ACTIVITY),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: Some("ingest-dup".into()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let activity: Activity = serde_json::from_value(json!({
            "type": "message",
            "id": "act_dup",
            "timestamp": "2026-01-01T00:00:00Z",
            "serviceUrl": "https://smba.trafficmanager.net/amer/",
            "text": "hello",
            "from": { "id": "29:user", "name": "Alice", "aadObjectId": "aad_1" },
            "conversation": {
                "id": "chat_1",
                "conversationType": "personal",
                "tenantId": "tenant_1"
            }
        }))
        .unwrap();

        let first = connector.normalize_activity(&req, &activity).unwrap();
        let second = connector.normalize_activity(&req, &activity).unwrap();
        assert_eq!(first["duplicate"], false);
        assert_eq!(second["duplicate"], true);
        assert_eq!(second["conversation_state"]["lastSequence"], 1);
    }

    #[test]
    fn test_normalize_activity_conversation_update_applies_member_deltas() {
        let connector = TeamsConnector::new();
        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_members"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_INGEST_ACTIVITY),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: Some("members-1".into()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let added: Activity = serde_json::from_value(json!({
            "type": "conversationUpdate",
            "id": "act_members_added",
            "timestamp": "2026-01-01T00:00:00Z",
            "conversation": {
                "id": "chat_members",
                "conversationType": "groupChat"
            },
            "membersAdded": [
                { "id": "user_a", "name": "Alice" },
                { "id": "user_b", "name": "Bob" }
            ]
        }))
        .unwrap();
        let removed: Activity = serde_json::from_value(json!({
            "type": "conversationUpdate",
            "id": "act_members_removed",
            "timestamp": "2026-01-01T00:01:00Z",
            "conversation": {
                "id": "chat_members",
                "conversationType": "groupChat"
            },
            "membersRemoved": [
                { "id": "user_a", "name": "Alice" }
            ]
        }))
        .unwrap();

        let added_state = connector.normalize_activity(&req, &added).unwrap();
        let removed_state = connector.normalize_activity(&req, &removed).unwrap();

        assert_eq!(
            added_state["conversation_state"]["members"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let remaining = removed_state["conversation_state"]["members"]
            .as_array()
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0]["id"], "user_b");
        assert_eq!(removed_state["conversation_state"]["lastSequence"], 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_normalize_activity_rejects_insecure_service_url() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "token" },
                "bot_service_url": "https://smba.trafficmanager.net/amer"
            }))
            .await
            .unwrap();

        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_service_url"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_INGEST_ACTIVITY),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: Some("service-url-1".into()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let activity: Activity = serde_json::from_value(json!({
            "type": "message",
            "id": "act_insecure",
            "serviceUrl": "http://smba.trafficmanager.net/amer/",
            "conversation": {
                "id": "chat_1",
                "conversationType": "personal"
            }
        }))
        .unwrap();

        let error = connector.normalize_activity(&req, &activity).unwrap_err();
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_access_token() {
        let mut connector = TeamsConnector::new();
        let result = connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok_123" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(connector.config.is_some());
        assert!(connector.client.is_some());
    }

    #[test]
    fn test_graph_base_url_policy_accepts_microsoft_clouds() {
        for graph_base_url in [
            "https://graph.microsoft.com/v1.0",
            "https://graph.microsoft.com/beta",
            "https://graph.microsoft.us/v1.0",
            "https://dod-graph.microsoft.us/v1.0",
            "https://microsoftgraph.chinacloudapi.cn/v1.0",
        ] {
            let (accepted, message) = graph_base_url_policy(graph_base_url);
            assert!(accepted, "{graph_base_url} rejected: {message}");
        }
    }

    #[test]
    fn test_graph_base_url_policy_rejects_untrusted_endpoint() {
        let (accepted, message) = graph_base_url_policy("https://graph.microsoft.com.evil/v1.0");
        assert!(!accepted);
        assert!(message.contains("host must be one of"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_malicious_graph_endpoint_access_token() {
        let mut connector = TeamsConnector::new();
        let result = connector
            .configure(json!({
                "graph_base_url": "https://graph.microsoft.com.evil/v1.0",
                "auth": { "mode": "access_token", "access_token": "tok_123" }
            }))
            .await;

        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1002, .. })
        ));
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_malicious_graph_endpoint_client_credentials() {
        let mut connector = TeamsConnector::new();
        let result = connector
            .configure(json!({
                "graph_base_url": "https://evil.example/v1.0",
                "auth": {
                    "mode": "client_credentials",
                    "client_id": "app_id",
                    "client_secret": "secret",
                    "tenant_id": "550e8400-e29b-41d4-a716-446655440000"
                }
            }))
            .await;

        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1002, .. })
        ));
        assert!(connector.config.is_none());
        assert!(connector.client.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_credential_id() {
        let mut connector = TeamsConnector::new();
        let result = connector
            .configure(json!({
                "auth": { "mode": "credential_id", "credential_id": "cred_1" }
            }))
            .await;
        assert!(result.is_ok());
        assert!(connector.client.as_ref().unwrap().is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_invalid() {
        let mut connector = TeamsConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = TeamsConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
        assert!(health.details.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_after_configure() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Ready));
        let details = health.details.unwrap();
        assert_eq!(details["configured"], true);
        assert_eq!(details["provisioning"]["auth_mode"], "access_token");
        assert!(details["operator_guidance"]["common_remediation"].is_array());
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = TeamsConnector::new();
        let report = connector.doctor();
        assert!(!report.ready);
        assert_eq!(report.status, DoctorStatus::Unhealthy);
    }

    #[fcp_async_core::runtime::test]
    async fn test_doctor_after_configure() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();
        let report = connector.doctor();
        assert!(report.ready);
        assert_eq!(report.status, DoctorStatus::Healthy);
        assert_eq!(
            report.provisioning.as_ref().unwrap().graph_base_url,
            "https://graph.microsoft.com/v1.0"
        );
    }

    #[test]
    fn test_doctor_flags_client_credentials_as_not_full_surface_ready() {
        let client = TeamsClient::new(
            "https://graph.microsoft.com/v1.0",
            "tok",
            Duration::from_secs(1),
        )
        .unwrap();
        let connector = manually_configured_connector(
            TeamsAuth::ClientCredentials {
                client_id: "client".into(),
                client_secret: "secret".into(),
                tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            },
            client,
            "https://graph.microsoft.com/v1.0",
        );

        let report = connector.doctor();
        assert!(!report.ready);
        assert_eq!(report.status, DoctorStatus::Unhealthy);
        let compatibility = report
            .checks
            .iter()
            .find(|check| check.name == "auth_surface_compatibility")
            .unwrap();
        assert!(!compatibility.passed);
        assert!(
            compatibility
                .message
                .as_deref()
                .unwrap()
                .contains("delegated user context")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_client_credentials_is_degraded() {
        let client = TeamsClient::new(
            "https://graph.microsoft.com/v1.0",
            "tok",
            Duration::from_secs(1),
        )
        .unwrap();
        let connector = manually_configured_connector(
            TeamsAuth::ClientCredentials {
                client_id: "client".into(),
                client_secret: "secret".into(),
                tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            },
            client,
            "https://graph.microsoft.com/v1.0",
        );

        let health = connector.health().await;
        assert!(matches!(
            &health.status,
            HealthState::Degraded { reason } if reason == "delegated user context required"
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_invalid_graph_url_is_error() {
        let client = TeamsClient::new(
            "http://graph.microsoft.com/v1.0",
            "tok",
            Duration::from_secs(1),
        )
        .unwrap();
        let connector = manually_configured_connector(
            TeamsAuth::AccessToken {
                access_token: "tok".into(),
            },
            client,
            "http://graph.microsoft.com/v1.0",
        );

        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Error { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = TeamsConnector::new();
        let req = HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_READ),
                CapabilityId::from_static(CAP_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };
        let result = connector.handshake(req).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status, "accepted");
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let h1 = TeamsConnector::manifest_hash();
        let h2 = TeamsConnector::manifest_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = TeamsConnector::new();
        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_LIST_TEAMS),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate() {
        let connector = TeamsConnector::new();
        let req = SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_LIST_TEAMS),
            ZoneId::work(),
            json!({}),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = TeamsConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
        assert!(report.details.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_requires_handshake_after_configure() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();

        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_2"),
            connector_id: connector.id().clone(),
            operation: OperationId::from_static(OP_LIST_TEAMS),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };

        let err = connector.invoke(req).await.unwrap_err();
        assert!(matches!(err, FcpError::NotHandshaken));
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_unauthorized_is_failed() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "error": {
                        "code": "InvalidAuthenticationToken",
                        "message": "Access token has expired."
                    }
                })),
            )
            .mount(&mock_server)
            .await;

        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "graph_base_url": mock_server.uri(),
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();

        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("token_invalid_or_expired")
        );
        assert!(report.details.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_credential_id_requires_injection() {
        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "auth": { "mode": "credential_id", "credential_id": "cred_1" }
            }))
            .await
            .unwrap();

        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("credential_injection_required")
        );
        assert!(report.details.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_client_credentials_requires_delegated_context() {
        let client = TeamsClient::new(
            "https://graph.microsoft.com/v1.0",
            "tok",
            Duration::from_secs(1),
        )
        .unwrap();
        let connector = manually_configured_connector(
            TeamsAuth::ClientCredentials {
                client_id: "client".into(),
                client_secret: "secret".into(),
                tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            },
            client,
            "https://graph.microsoft.com/v1.0",
        );

        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("delegated_user_context_required")
        );
        assert!(report.details.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_forbidden_maps_admin_consent_remediation() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(403).set_body_json(serde_json::json!({
                    "error": {
                        "code": "Authorization_RequestDenied",
                        "message": "Insufficient privileges to complete the operation. Admin consent is required."
                    }
                })),
            )
            .mount(&mock_server)
            .await;

        let mut connector = TeamsConnector::new();
        connector
            .configure(json!({
                "graph_base_url": mock_server.uri(),
                "auth": { "mode": "access_token", "access_token": "tok" }
            }))
            .await
            .unwrap();

        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Failed);
        assert_eq!(
            report.reason_code.as_deref(),
            Some("admin_consent_or_permission_missing")
        );
        assert!(report.details.is_some());
    }
}
