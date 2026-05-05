//! Feishu connector implementation.

use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, AuthCaps, BaseConnector, CapabilityGrant, CapabilityId,
    CapabilityVerifier, ConnectorId, EventCaps, EventInfo, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, OperationId, OperationInfo, ResourceTypeInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
};
use fcp_sdk::migration::{ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig};
use fcp_sdk::prelude::*;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::client::FeishuClient;
use crate::types::{ReplyMessageRequest, SendMessageRequest};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const FEISHU_CN_HOST: &str = "open.feishu.cn";
const FEISHU_GLOBAL_HOST: &str = "open.larksuite.com";
const FEISHU_TENANT_APP_BOUNDARY: &str = "This connector acts as one installed tenant app; it does not impersonate arbitrary users or cross tenant boundaries.";
const FEISHU_IMPLEMENTATION_STATUS: &str = "first_slice";
const FEISHU_BINDING_MODEL: &str = "single_tenant_app";
const FEISHU_AUTH_MODEL: &str = "tenant_app_credentials";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/feishu_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/feishu_connector/<timestamp>";
const VERIFY_COMMANDS: [&str; 7] = [
    "scripts/e2e/feishu_connector_verification.sh",
    "rch exec -- cargo run -q -p fwc -- manifest fix connectors/feishu/manifest.toml --check --json",
    "rch exec -- cargo check -p fcp-feishu --all-targets",
    "rch exec -- cargo fmt --manifest-path connectors/feishu/Cargo.toml --check",
    "rch exec -- cargo test -p fcp-feishu --test integration -- --nocapture",
    "rch exec -- cargo test -p fcp-feishu -- --nocapture",
    "rch exec -- cargo clippy -p fcp-feishu --all-targets -- -D warnings",
];
const MAX_CHATS_PAGE_SIZE: u32 = 200;
const FEISHU_WEBHOOK_MAX_BODY_BYTES: usize = 1024 * 1024;
const ALLOWED_RECEIVE_ID_TYPES: &[&str] = &["open_id", "user_id", "union_id", "email", "chat_id"];
const ALLOWED_USER_ID_TYPES: &[&str] = &["open_id", "user_id", "union_id"];

// Operation IDs
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const OP_MESSAGES_REPLY: &str = "feishu.messages.reply";
const OP_MESSAGES_GET: &str = "feishu.messages.get";
const OP_CHATS_LIST: &str = "feishu.chats.list";
const OP_CHATS_GET: &str = "feishu.chats.get";
const OP_USERS_GET: &str = "feishu.users.get";
const OP_DOCS_GET: &str = "feishu.docs.get";
const OP_SHEETS_GET: &str = "feishu.sheets.get";
const OP_CALENDAR_EVENTS: &str = "feishu.calendar.events";
const OP_WEBHOOK_INGEST_REQUEST: &str = "feishu.webhook.ingest_request";
const OP_HEALTH: &str = "feishu.health";

// Capability IDs
const CAP_MSG_WRITE: &str = "feishu.messages.write";
const CAP_MSG_READ: &str = "feishu.messages.read";
const CAP_CHATS_READ: &str = "feishu.chats.read";
const CAP_USERS_READ: &str = "feishu.users.read";
const CAP_DOCS_READ: &str = "feishu.docs.read";
const CAP_CALENDAR_READ: &str = "feishu.calendar.read";
const CAP_WEBHOOK_INGEST: &str = "feishu.webhook.ingest";

/// Feishu connector configuration.
#[derive(Clone, Deserialize)]
struct FeishuConfig {
    #[serde(default = "default_base_url")]
    base_url: String,
    app_id: String,
    app_secret: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_request_timeout_ms")]
    request_timeout_ms: u64,
}

impl std::fmt::Debug for FeishuConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuConfig")
            .field("base_url", &self.base_url)
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

fn default_base_url() -> String {
    "https://open.feishu.cn".into()
}

const fn default_request_timeout_ms() -> u64 {
    30_000
}

fn is_local_test_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1")
}

fn parse_base_url(base_url: &str) -> FcpResult<reqwest::Url> {
    reqwest::Url::parse(base_url).map_err(|err| FcpError::InvalidRequest {
        code: 1001,
        message: format!("Invalid base_url `{base_url}`: {err}"),
    })
}

fn validate_base_url(base_url: &reqwest::Url) -> FcpResult<()> {
    let host = base_url.host_str().ok_or(FcpError::InvalidRequest {
        code: 1001,
        message: "base_url must include a host".into(),
    })?;
    let is_local_host = is_local_test_host(host);

    if !base_url.username().is_empty() || base_url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include embedded credentials".into(),
        });
    }

    if host != FEISHU_CN_HOST && host != FEISHU_GLOBAL_HOST && !is_local_host {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "base_url host `{host}` is not allowed; use https://{FEISHU_CN_HOST}, https://{FEISHU_GLOBAL_HOST}, or localhost/127.0.0.1 for tests"
            ),
        });
    }

    if !is_local_host && base_url.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production Feishu/Lark base_url must use https".into(),
        });
    }

    if !is_local_host && base_url.port_or_known_default() != Some(443) {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "Production Feishu/Lark base_url must use port 443".into(),
        });
    }

    if base_url.path() != "/" && !base_url.path().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include a path segment".into(),
        });
    }

    if base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "base_url must not include query or fragment components".into(),
        });
    }

    Ok(())
}

fn validate_config(config: &FeishuConfig) -> FcpResult<()> {
    if config.app_id.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "app_id must not be empty".into(),
        });
    }

    if config.app_secret.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "app_secret must not be empty".into(),
        });
    }

    if config.request_timeout_ms == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "request_timeout_ms must be greater than zero".into(),
        });
    }

    let base_url = parse_base_url(&config.base_url)?;
    validate_base_url(&base_url)
}

fn base_url_diagnostic(base_url: &str) -> (bool, String) {
    match parse_base_url(base_url).and_then(|url| {
        validate_base_url(&url)?;
        Ok(url)
    }) {
        Ok(url) => {
            let host = url.host_str().unwrap_or_default();
            let message = if is_local_test_host(host) {
                "Base URL uses a localhost test override".into()
            } else {
                format!("Base URL matches allowed Feishu/Lark host `{host}`")
            };
            (true, message)
        }
        Err(FcpError::InvalidRequest { message, .. }) => (false, message),
        Err(err) => (false, err.to_string()),
    }
}

fn validate_receive_id_type(receive_id_type: &str) -> FcpResult<&str> {
    if ALLOWED_RECEIVE_ID_TYPES.contains(&receive_id_type) {
        Ok(receive_id_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "receive_id_type must be one of: {}",
                ALLOWED_RECEIVE_ID_TYPES.join(", ")
            ),
        })
    }
}

fn validate_user_id_type(user_id_type: &str) -> FcpResult<&str> {
    if ALLOWED_USER_ID_TYPES.contains(&user_id_type) {
        Ok(user_id_type)
    } else {
        Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "user_id_type must be one of: {}",
                ALLOWED_USER_ID_TYPES.join(", ")
            ),
        })
    }
}

fn validate_chats_page_size(page_size: u64) -> FcpResult<u32> {
    if !(1..=u64::from(MAX_CHATS_PAGE_SIZE)).contains(&page_size) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("page_size must be between 1 and {MAX_CHATS_PAGE_SIZE}"),
        });
    }
    Ok(page_size as u32)
}

fn required_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    let capability = match operation {
        OP_MESSAGES_SEND | OP_MESSAGES_REPLY => CAP_MSG_WRITE,
        OP_MESSAGES_GET => CAP_MSG_READ,
        OP_CHATS_LIST | OP_CHATS_GET => CAP_CHATS_READ,
        OP_USERS_GET | OP_HEALTH => CAP_USERS_READ,
        OP_DOCS_GET | OP_SHEETS_GET => CAP_DOCS_READ,
        OP_CALENDAR_EVENTS => CAP_CALENDAR_READ,
        OP_WEBHOOK_INGEST_REQUEST => CAP_WEBHOOK_INGEST,
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };
    Ok(CapabilityId::from_static(capability))
}

fn required_string_input<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' field"),
        })
}

fn required_object_input<'a>(input: &'a Value, field: &str) -> FcpResult<&'a Map<String, Value>> {
    input
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Missing '{field}' object"),
        })
}

fn validate_webhook_input(input: &Value) -> FcpResult<()> {
    required_string_input(input, "method")?;
    required_object_input(input, "headers")?;
    required_string_input(input, "raw_body")?;
    required_string_input(input, "verification_token")?;
    required_string_input(input, "encrypt_key")?;
    required_object_input(input, "policy")?;

    if let Some(max_body_bytes) = input.get("max_body_bytes").and_then(Value::as_u64)
        && (max_body_bytes == 0 || max_body_bytes > FEISHU_WEBHOOK_MAX_BODY_BYTES as u64)
    {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "max_body_bytes must be between 1 and {FEISHU_WEBHOOK_MAX_BODY_BYTES}"
            ),
        });
    }

    Ok(())
}

fn validate_operation_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    match operation {
        OP_MESSAGES_SEND => {
            required_string_input(input, "receive_id")?;
            required_string_input(input, "msg_type")?;
            required_string_input(input, "content")?;
            let receive_id_type = input
                .get("receive_id_type")
                .and_then(|value| value.as_str())
                .unwrap_or("open_id");
            validate_receive_id_type(receive_id_type)?;
        }
        OP_MESSAGES_REPLY => {
            required_string_input(input, "message_id")?;
            required_string_input(input, "msg_type")?;
            required_string_input(input, "content")?;
        }
        OP_MESSAGES_GET => {
            required_string_input(input, "message_id")?;
        }
        OP_CHATS_LIST => {
            if let Some(page_size) = input.get("page_size").and_then(|value| value.as_u64()) {
                validate_chats_page_size(page_size)?;
            }
        }
        OP_CHATS_GET => {
            required_string_input(input, "chat_id")?;
        }
        OP_USERS_GET => {
            required_string_input(input, "user_id")?;
            let user_id_type = input
                .get("user_id_type")
                .and_then(|value| value.as_str())
                .unwrap_or("open_id");
            validate_user_id_type(user_id_type)?;
        }
        OP_DOCS_GET => {
            required_string_input(input, "document_id")?;
        }
        OP_SHEETS_GET => {
            required_string_input(input, "spreadsheet_token")?;
        }
        OP_CALENDAR_EVENTS => {
            required_string_input(input, "calendar_id")?;
        }
        OP_WEBHOOK_INGEST_REQUEST => {
            validate_webhook_input(input)?;
        }
        OP_HEALTH => {}
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            });
        }
    }

    Ok(())
}

fn header_value<'a>(headers: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(key, value)| {
        if !key.eq_ignore_ascii_case(name) {
            return None;
        }
        value.as_str().or_else(|| {
            value
                .as_array()
                .and_then(|values| values.iter().find_map(Value::as_str))
        })
    })
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for component in path {
        current = current.get(*component)?;
    }
    Some(current)
}

fn string_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at_path(value, path).and_then(Value::as_str)
}

fn array_contains_string(value: &Value, field: &str, needle: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|item| item == needle)
        })
}

fn optional_bool(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn feishu_signature_hex(timestamp: &str, nonce: &str, encrypt_key: &str, raw_body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(encrypt_key.as_bytes());
    hasher.update(raw_body.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_hex_eq(expected_hex: &str, provided_hex: &str) -> bool {
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let Ok(provided) = hex::decode(provided_hex) else {
        return false;
    };
    bool::from(expected.ct_eq(&provided))
}

fn verify_webhook_signature(
    headers: &Map<String, Value>,
    encrypt_key: &str,
    raw_body: &str,
) -> Result<(), &'static str> {
    let Some(timestamp) = header_value(headers, "x-lark-request-timestamp") else {
        return Err("missing_signature_timestamp");
    };
    let Some(nonce) = header_value(headers, "x-lark-request-nonce") else {
        return Err("missing_signature_nonce");
    };
    let Some(signature) = header_value(headers, "x-lark-signature") else {
        return Err("missing_signature");
    };
    let expected = feishu_signature_hex(timestamp, nonce, encrypt_key, raw_body);
    if constant_time_hex_eq(&expected, signature) {
        Ok(())
    } else {
        Err("invalid_signature")
    }
}

fn webhook_response(
    status_code: u16,
    reason_code: &str,
    body_bytes: usize,
    logs: Vec<Value>,
    response_body: Value,
) -> Value {
    json!({
        "accepted": status_code < 400,
        "status_code": status_code,
        "reason_code": reason_code,
        "event_emitted": false,
        "event_id": Value::Null,
        "event_type": Value::Null,
        "dedupe_key": Value::Null,
        "normalized_event": Value::Null,
        "policy_decision": Value::Null,
        "response_body": response_body,
        "body_bytes": body_bytes,
        "request_region": {
            "method_checked": true,
            "signature_verified": status_code < 400 || reason_code != "invalid_signature",
            "max_body_bytes": FEISHU_WEBHOOK_MAX_BODY_BYTES,
            "transport": "host_forwarded_request",
        },
        "logs": logs,
    })
}

fn webhook_rejection(
    status_code: u16,
    reason_code: &str,
    body_bytes: usize,
    logs: Vec<Value>,
) -> Value {
    webhook_response(status_code, reason_code, body_bytes, logs, json!({}))
}

fn webhook_event_id(payload: &Value, raw_body: &str) -> String {
    string_at_path(payload, &["header", "event_id"])
        .or_else(|| string_at_path(payload, &["event", "message", "message_id"]))
        .or_else(|| string_at_path(payload, &["event", "message_id"]))
        .or_else(|| string_at_path(payload, &["event", "comment_id"]))
        .map(str::to_string)
        .unwrap_or_else(|| {
            let mut hasher = Sha256::new();
            hasher.update(raw_body.as_bytes());
            format!("sha256:{}", hex::encode(hasher.finalize()))
        })
}

fn webhook_event_type(payload: &Value) -> &str {
    string_at_path(payload, &["header", "event_type"])
        .or_else(|| payload.get("type").and_then(Value::as_str))
        .unwrap_or("unknown")
}

fn feishu_topic_for_event_type(event_type: &str) -> &'static str {
    match event_type {
        "im.message.receive_v1" => "feishu.webhook.message_received",
        "im.message.message_read_v1" => "feishu.webhook.message_read",
        "im.message.reaction.created_v1" => "feishu.webhook.reaction_created",
        "im.message.reaction.deleted_v1" => "feishu.webhook.reaction_deleted",
        "drive.notice.comment_add_v1" => "feishu.webhook.document_comment_added",
        _ => "feishu.webhook.unknown_event",
    }
}

fn event_section(payload: &Value) -> &Value {
    payload.get("event").unwrap_or(payload)
}

fn actor_open_id(event: &Value) -> Option<&str> {
    string_at_path(event, &["sender", "sender_id", "open_id"])
        .or_else(|| string_at_path(event, &["operator", "operator_id", "open_id"]))
        .or_else(|| string_at_path(event, &["operator_id", "open_id"]))
        .or_else(|| string_at_path(event, &["user_id", "open_id"]))
        .or_else(|| string_at_path(event, &["user", "open_id"]))
        .or_else(|| string_at_path(event, &["comment", "user_id", "open_id"]))
        .or_else(|| string_at_path(event, &["comment", "user", "open_id"]))
}

fn chat_id(event: &Value) -> Option<&str> {
    string_at_path(event, &["message", "chat_id"])
        .or_else(|| string_at_path(event, &["chat_id"]))
        .or_else(|| string_at_path(event, &["chat", "chat_id"]))
}

fn message_id(event: &Value) -> Option<&str> {
    string_at_path(event, &["message", "message_id"])
        .or_else(|| string_at_path(event, &["message_id"]))
}

fn mentions_bot(event: &Value, bot_open_id: &str) -> bool {
    let Some(mentions) = value_at_path(event, &["message", "mentions"]).and_then(Value::as_array)
    else {
        return false;
    };

    mentions.iter().any(|mention| {
        string_at_path(mention, &["id", "open_id"]) == Some(bot_open_id)
            || string_at_path(mention, &["id", "user_id"]) == Some(bot_open_id)
            || mention.get("open_id").and_then(Value::as_str) == Some(bot_open_id)
            || mention.get("key").and_then(Value::as_str) == Some("@_all")
    })
}

fn normalize_message_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    let message = event.get("message").unwrap_or(event);
    let content_present = message
        .get("content")
        .and_then(Value::as_str)
        .is_some_and(|content| !content.trim().is_empty());
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "message_id": message_id(event),
        "chat_id": chat_id(event),
        "chat_type": message.get("chat_type").and_then(Value::as_str),
        "message_type": message.get("message_type").and_then(Value::as_str),
        "sender_open_id": actor_open_id(event),
        "content_present": content_present,
        "raw_content_included": false,
    })
}

fn normalize_read_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "message_id": message_id(event),
        "chat_id": chat_id(event),
        "reader_open_id": actor_open_id(event),
    })
}

fn normalize_reaction_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "message_id": message_id(event),
        "chat_id": chat_id(event),
        "operator_open_id": actor_open_id(event),
        "reaction_type": string_at_path(event, &["reaction", "emoji_type"])
            .or_else(|| string_at_path(event, &["reaction", "reaction_type"])),
    })
}

fn normalize_comment_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    json!({
        "topic": feishu_topic_for_event_type(event_type),
        "event_type": event_type,
        "event_id": event_id,
        "file_token": event.get("file_token").and_then(Value::as_str)
            .or_else(|| string_at_path(event, &["file", "token"])),
        "file_type": event.get("file_type").and_then(Value::as_str)
            .or_else(|| string_at_path(event, &["file", "type"])),
        "comment_id": event.get("comment_id").and_then(Value::as_str)
            .or_else(|| string_at_path(event, &["comment", "comment_id"])),
        "reply_id": event.get("reply_id").and_then(Value::as_str)
            .or_else(|| string_at_path(event, &["comment", "reply_id"])),
        "actor_open_id": actor_open_id(event),
    })
}

fn normalize_webhook_event(event_type: &str, event_id: &str, event: &Value) -> Value {
    match event_type {
        "im.message.receive_v1" => normalize_message_event(event_type, event_id, event),
        "im.message.message_read_v1" => normalize_read_event(event_type, event_id, event),
        "im.message.reaction.created_v1" | "im.message.reaction.deleted_v1" => {
            normalize_reaction_event(event_type, event_id, event)
        }
        "drive.notice.comment_add_v1" => normalize_comment_event(event_type, event_id, event),
        _ => json!({
            "topic": feishu_topic_for_event_type(event_type),
            "event_type": event_type,
            "event_id": event_id,
            "actor_open_id": actor_open_id(event),
            "chat_id": chat_id(event),
            "raw_payload_included": false,
        }),
    }
}

fn policy_array_contains(policy: &Value, field: &str, value: Option<&str>) -> bool {
    value.is_some_and(|needle| array_contains_string(policy, field, needle))
}

fn comment_policy_decision(policy: &Value, event: &Value) -> (bool, Value) {
    let comment_policy = policy
        .get("comment")
        .or_else(|| policy.get("comment_rules"))
        .unwrap_or(&Value::Null);

    if comment_policy.is_null() {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_policy_required",
            }),
        );
    }
    if comment_policy.get("enabled").and_then(Value::as_bool) == Some(false) {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_policy_disabled",
            }),
        );
    }

    let actor = actor_open_id(event);
    let document_ref = event
        .get("file_token")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(event, &["file", "token"]));
    if comment_policy
        .get("document_allowlist")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
        && !policy_array_contains(comment_policy, "document_allowlist", document_ref)
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "comment_document_not_allowed",
                "file_token": document_ref,
            }),
        );
    }

    if policy_array_contains(comment_policy, "allow_from_open_ids", actor)
        || policy_array_contains(comment_policy, "allow_from", actor)
    {
        return (
            true,
            json!({
                "allowed": true,
                "reason_code": "comment_allowlist_match",
                "actor_open_id": actor,
                "policy": comment_policy.get("policy").and_then(Value::as_str).unwrap_or("allowlist"),
            }),
        );
    }

    let mode = comment_policy
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or("pairing");
    if mode == "pairing" && policy_array_contains(comment_policy, "paired_open_ids", actor) {
        return (
            true,
            json!({
                "allowed": true,
                "reason_code": "comment_pairing_match",
                "actor_open_id": actor,
                "policy": "pairing",
            }),
        );
    }

    (
        false,
        json!({
            "allowed": false,
            "reason_code": "comment_actor_not_allowed",
            "actor_open_id": actor,
            "policy": mode,
        }),
    )
}

fn webhook_policy_decision(event_type: &str, event: &Value, policy: &Value) -> (bool, Value) {
    let actor = actor_open_id(event);
    let chat = chat_id(event);
    let bot_open_id = policy.get("bot_open_id").and_then(Value::as_str);

    if bot_open_id.is_some() && actor == bot_open_id {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "self_or_bot_sender",
                "actor_open_id": actor,
            }),
        );
    }
    if policy
        .get("allowed_sender_open_ids")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
        && !policy_array_contains(policy, "allowed_sender_open_ids", actor)
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "sender_not_allowed",
                "actor_open_id": actor,
            }),
        );
    }
    if policy
        .get("allowed_chat_ids")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
        && !policy_array_contains(policy, "allowed_chat_ids", chat)
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "chat_not_allowed",
                "chat_id": chat,
            }),
        );
    }
    if optional_bool(policy, "require_mention")
        && event_type == "im.message.receive_v1"
        && bot_open_id.is_none_or(|bot| !mentions_bot(event, bot))
    {
        return (
            false,
            json!({
                "allowed": false,
                "reason_code": "mention_required",
                "bot_open_id": bot_open_id,
            }),
        );
    }
    if event_type == "drive.notice.comment_add_v1" {
        return comment_policy_decision(policy, event);
    }

    (
        true,
        json!({
            "allowed": true,
            "reason_code": "policy_allowed",
            "actor_open_id": actor,
            "chat_id": chat,
        }),
    )
}

fn seen_event_ids(input: &Value, event_id: &str) -> bool {
    input
        .get("seen_event_ids")
        .and_then(Value::as_array)
        .is_some_and(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .any(|id| id == event_id)
        })
}

fn feishu_event_caps() -> EventCaps {
    EventCaps {
        streaming: false,
        replay: true,
        min_buffer_events: 0,
        requires_ack: false,
    }
}

fn feishu_events_info() -> Vec<EventInfo> {
    vec![
        EventInfo {
            topic: "feishu.webhook.message_received".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.message_read".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.reaction_created".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.reaction_deleted".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
        EventInfo {
            topic: "feishu.webhook.document_comment_added".into(),
            schema: json!({ "type": "object", "required": ["event_id", "event_type"] }),
            requires_ack: false,
        },
    ]
}

fn invoke_webhook_ingest_request(input: &Value) -> FcpResult<Value> {
    validate_webhook_input(input)?;
    let method = required_string_input(input, "method")?;
    let headers = required_object_input(input, "headers")?;
    let raw_body = required_string_input(input, "raw_body")?;
    let expected_verifier = required_string_input(input, "verification_token")?;
    let encrypt_key = required_string_input(input, "encrypt_key")?;
    let policy = required_object_input(input, "policy")?;
    let body_bytes = raw_body.len();
    let mut logs = vec![json!({
        "layer": "request_region",
        "code": "received",
        "method": method,
        "body_bytes": body_bytes,
    })];

    if !method.eq_ignore_ascii_case("POST") {
        logs.push(json!({"layer": "request_region", "code": "method_not_allowed"}));
        return Ok(webhook_rejection(
            405,
            "method_not_allowed",
            body_bytes,
            logs,
        ));
    }
    let max_body_bytes = input
        .get("max_body_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(FEISHU_WEBHOOK_MAX_BODY_BYTES);
    if body_bytes > max_body_bytes {
        logs.push(json!({"layer": "request_region", "code": "body_too_large"}));
        return Ok(webhook_rejection(413, "body_too_large", body_bytes, logs));
    }
    if optional_bool(input, "deadline_exceeded") {
        logs.push(json!({"layer": "request_region", "code": "body_timeout"}));
        return Ok(webhook_rejection(408, "body_timeout", body_bytes, logs));
    }
    if optional_bool(input, "rate_limited") {
        logs.push(json!({"layer": "request_region", "code": "rate_limited"}));
        return Ok(webhook_rejection(429, "rate_limited", body_bytes, logs));
    }

    if let Err(reason) = verify_webhook_signature(headers, encrypt_key, raw_body) {
        logs.push(json!({"layer": "security", "code": reason}));
        return Ok(webhook_rejection(401, reason, body_bytes, logs));
    }
    logs.push(json!({"layer": "security", "code": "signature_verified"}));

    let payload: Value = match serde_json::from_str(raw_body) {
        Ok(payload) => payload,
        Err(err) => {
            logs.push(
                json!({"layer": "parser", "code": "malformed_json", "error": err.to_string()}),
            );
            return Ok(webhook_rejection(400, "malformed_json", body_bytes, logs));
        }
    };

    let presented_verifier = payload
        .get("token")
        .and_then(Value::as_str)
        .or_else(|| string_at_path(&payload, &["header", "token"]));
    if presented_verifier != Some(expected_verifier) {
        logs.push(json!({"layer": "security", "code": "invalid_verification_token"}));
        return Ok(webhook_rejection(
            401,
            "invalid_verification_token",
            body_bytes,
            logs,
        ));
    }
    logs.push(json!({"layer": "security", "code": "verification_token_matched"}));

    if payload.get("encrypt").is_some() {
        logs.push(json!({"layer": "security", "code": "encrypted_payload_unsupported"}));
        return Ok(webhook_rejection(
            415,
            "encrypted_payload_unsupported",
            body_bytes,
            logs,
        ));
    }

    if payload.get("type").and_then(Value::as_str) == Some("url_verification") {
        let Some(challenge) = payload.get("challenge").and_then(Value::as_str) else {
            logs.push(json!({"layer": "parser", "code": "missing_challenge"}));
            return Ok(webhook_rejection(
                400,
                "missing_challenge",
                body_bytes,
                logs,
            ));
        };
        logs.push(json!({"layer": "dispatcher", "code": "challenge_response"}));
        return Ok(webhook_response(
            200,
            "challenge_response",
            body_bytes,
            logs,
            json!({ "challenge": challenge }),
        ));
    }

    let event_type = webhook_event_type(&payload);
    let event_id = webhook_event_id(&payload, raw_body);
    let event = event_section(&payload);
    let dedupe_key = format!("feishu:{event_type}:{event_id}");
    if seen_event_ids(input, &event_id) {
        logs.push(json!({
            "layer": "dedupe",
            "code": "duplicate_event",
            "mode": "caller_supplied_seen_event_ids",
        }));
        let mut duplicate = webhook_response(200, "duplicate_event", body_bytes, logs, json!({}));
        duplicate["event_id"] = json!(event_id);
        duplicate["event_type"] = json!(event_type);
        duplicate["dedupe_key"] = json!(dedupe_key);
        return Ok(duplicate);
    }

    let normalized_event = normalize_webhook_event(event_type, &event_id, event);
    let (allowed, policy_decision) =
        webhook_policy_decision(event_type, event, &Value::Object(policy.clone()));
    if !allowed {
        logs.push(json!({"layer": "policy", "code": "event_denied"}));
        let mut denied = webhook_response(
            200,
            policy_decision
                .get("reason_code")
                .and_then(Value::as_str)
                .unwrap_or("policy_denied"),
            body_bytes,
            logs,
            json!({}),
        );
        denied["event_id"] = json!(event_id);
        denied["event_type"] = json!(event_type);
        denied["dedupe_key"] = json!(dedupe_key);
        denied["normalized_event"] = normalized_event;
        denied["policy_decision"] = policy_decision;
        return Ok(denied);
    }

    logs.push(json!({"layer": "dispatcher", "code": "event_normalized"}));
    Ok(json!({
        "accepted": true,
        "status_code": 200,
        "reason_code": "event_accepted",
        "event_emitted": true,
        "event_id": event_id,
        "event_type": event_type,
        "dedupe_key": dedupe_key,
        "normalized_event": normalized_event,
        "policy_decision": policy_decision,
        "response_body": {},
        "body_bytes": body_bytes,
        "request_region": {
            "method_checked": true,
            "signature_verified": true,
            "max_body_bytes": max_body_bytes,
            "transport": "host_forwarded_request",
        },
        "logs": logs,
    }))
}

// Doctor types
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisioningReadiness>,
    operator_guidance: OperatorGuidance,
    verification_script: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>, provisioning: Option<ProvisioningReadiness>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self {
            ready: passed,
            passed,
            checks,
            provisioning,
            operator_guidance: operator_guidance(),
            verification_script: VERIFICATION_SCRIPT_PATH,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct RetryReadiness {
    max_retries: u32,
    initial_delay_ms: u64,
    max_delay_ms: u64,
    jitter_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ProvisioningReadiness {
    base_url: String,
    auth_mode: &'static str,
    request_timeout_ms: u64,
    retry: RetryReadiness,
    network_ok: bool,
    network_message: String,
    credentials_configured: bool,
    authenticated_identity_probe: &'static str,
    risky_mutations: Vec<&'static str>,
    supported_hosts: Vec<&'static str>,
    tenant_app_boundary: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OperatorGuidance {
    prerequisites: Vec<&'static str>,
    dedicated_environment: &'static str,
    redaction_rules: Vec<&'static str>,
    limitations: Vec<&'static str>,
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

fn auth_mode_label(config: &FeishuConfig) -> &'static str {
    if config.app_id.trim().is_empty() || config.app_secret.trim().is_empty() {
        "unconfigured"
    } else {
        FEISHU_AUTH_MODEL
    }
}

fn operator_guidance() -> OperatorGuidance {
    OperatorGuidance {
        prerequisites: vec![
            "Use a disposable Feishu/Lark tenant app or a localhost mock server before running readiness verification.",
            "Grant the tenant app the scopes needed for the message, chat, directory, docs, sheets, and calendar surfaces you plan to exercise.",
            "Configure exactly one app_id/app_secret pair per connector instance and keep base_url on the CN or global production host unless the verification bundle is pointed at localhost.",
        ],
        dedicated_environment: "Prefer a sandbox tenant or a localhost fixture. feishu.messages.send and feishu.messages.reply are live side effects and should not target production chats during verification.",
        redaction_rules: vec![
            "Never print app_secret, tenant access tokens, Authorization headers, or copied auth-endpoint payloads.",
            "Treat app_id, message IDs, chat IDs, user IDs, document IDs, spreadsheet tokens, calendar IDs, and raw content bodies as sensitive tenant metadata.",
            "If verification captures live Feishu/Lark responses, redact message content, display names, email addresses, and tenant-specific URLs before sharing artifacts.",
        ],
        limitations: vec![
            "This first slice is tenant-app bound and does not impersonate arbitrary users or cross tenant boundaries.",
            "Webhook ingestion is host-forwarded request processing only; embedded listener lifecycle, websocket event delivery, Drive search/export/write, and calendar mutations remain explicit non-goals.",
            "Known-token reads are supported for docs, sheets, and calendar events, but this connector does not discover or enumerate those resources globally.",
        ],
        common_remediation: vec![
            RemediationHint {
                code: "not_configured",
                symptom: "health or self_check reports that the connector is not configured",
                action: "Configure app_id, app_secret, request_timeout_ms, retry policy, and an allowed base_url, then rerun self_check.",
            },
            RemediationHint {
                code: "network_constraints_invalid",
                symptom: "doctor or self_check reports that base_url violates the Feishu/Lark host policy",
                action: "Use https://open.feishu.cn or https://open.larksuite.com for live verification, or an explicit localhost / 127.0.0.1 override for deterministic tests.",
            },
            RemediationHint {
                code: "feishu_auth_rejected",
                symptom: "the tenant-access-token probe returns 401 or 403",
                action: "Rotate the tenant app secret, confirm the app_id/app_secret pair is valid for the target tenant, and rerun the verification bundle.",
            },
            RemediationHint {
                code: "self_check_retryable",
                symptom: "self_check reports rate limiting, transport timeouts, or transient 5xx errors from Feishu/Lark",
                action: "Respect the upstream retry window or increase request_timeout_ms and retry settings before rerunning verification.",
            },
        ],
        rerun_commands: VERIFY_COMMANDS.to_vec(),
        artifact_root_hint: ARTIFACT_ROOT_HINT,
    }
}

fn contract_details(config: Option<&FeishuConfig>) -> serde_json::Value {
    json!({
        "implementation": {
            "api": "feishu_open_platform",
            "status": FEISHU_IMPLEMENTATION_STATUS,
            "notes": [
                "The connector is bound to one installed tenant app and uses the tenant access token internal auth endpoint.",
                "Read operations cover messages, chats, users, known docs, known spreadsheets, and known calendar event lists.",
                "Webhook support is a host-forwarded request ingestion operation; this connector does not open a listening socket.",
            ],
        },
        "auth_boundary": {
            "binding": FEISHU_BINDING_MODEL,
            "token_type": FEISHU_AUTH_MODEL,
            "credential_mode": config.map(auth_mode_label).unwrap_or("unconfigured"),
            "base_url": config.map(|cfg| cfg.base_url.clone()),
            "cross_tenant_supported": false,
            "user_impersonation_supported": false,
            "webhook_receiver_included": true,
            "webhook_transport": "host_forwarded_request_operation",
            "websocket_events_included": false,
        },
        "service_inventory": {
            "messages": [OP_MESSAGES_SEND, OP_MESSAGES_REPLY, OP_MESSAGES_GET],
            "chats": [OP_CHATS_LIST, OP_CHATS_GET],
            "directory": [OP_USERS_GET],
            "docs": [OP_DOCS_GET, OP_SHEETS_GET],
            "calendar": [OP_CALENDAR_EVENTS],
            "webhook": [OP_WEBHOOK_INGEST_REQUEST],
            "health": [OP_HEALTH],
        },
        "non_goals": [
            "Embedded webhook listener lifecycle and websocket event delivery",
            "Encrypted Feishu webhook payload decryption",
            "Automated document-comment reply workflow",
            "Cross-tenant brokering or arbitrary user impersonation",
            "Drive search, export, folder traversal, and write operations",
            "Calendar mutation or subscription setup"
        ]
    })
}

/// Feishu connector state.
#[derive(Debug)]
pub struct FeishuConnector {
    base: BaseConnector,
    config: Option<FeishuConfig>,
    client: Option<FeishuClient>,
    runtime: Option<ConnectorRuntime>,
    retry_config: HttpRetryConfig,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl FeishuConnector {
    /// Create a new connector instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.feishu")),
            config: None,
            client: None,
            runtime: None,
            retry_config: HttpRetryConfig::default(),
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Return this connector instance ID for host-issued capability token binding.
    #[must_use]
    pub fn instance_id(&self) -> &InstanceId {
        &self.base.instance_id
    }

    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn provisioning_readiness(&self) -> Option<ProvisioningReadiness> {
        self.config.as_ref().map(|config| {
            let (network_ok, network_message) = base_url_diagnostic(&config.base_url);
            ProvisioningReadiness {
                base_url: config.base_url.clone(),
                auth_mode: auth_mode_label(config),
                request_timeout_ms: config.request_timeout_ms,
                retry: RetryReadiness {
                    max_retries: config.retry.max_retries,
                    initial_delay_ms: config.retry.initial_delay_ms,
                    max_delay_ms: config.retry.max_delay_ms,
                    jitter_enabled: config.retry.jitter_enabled,
                },
                network_ok,
                network_message,
                credentials_configured: !config.app_id.trim().is_empty()
                    && !config.app_secret.trim().is_empty(),
                authenticated_identity_probe: "POST /open-apis/auth/v3/tenant_access_token/internal",
                risky_mutations: vec![
                    OP_MESSAGES_SEND,
                    OP_MESSAGES_REPLY,
                    OP_WEBHOOK_INGEST_REQUEST,
                ],
                supported_hosts: vec![FEISHU_CN_HOST, FEISHU_GLOBAL_HOST],
                tenant_app_boundary: FEISHU_TENANT_APP_BOUNDARY,
            }
        })
    }

    fn diagnostic_details(&self, live_probe: Option<serde_json::Value>) -> serde_json::Value {
        json!({
            "configured": self.config.is_some(),
            "client_initialized": self.client.is_some(),
            "runtime_initialized": self.runtime.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "auth_mode": self.config.as_ref().map(auth_mode_label),
            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
            "base_url_validation": self.config.as_ref().map(|config| {
                match parse_base_url(&config.base_url) {
                    Ok(url) => json!({
                        "host": url.host_str(),
                        "scheme": url.scheme(),
                        "local_test_host": url.host_str().is_some_and(is_local_test_host),
                    }),
                    Err(err) => json!({
                        "valid": false,
                        "error": err.to_string(),
                    }),
                }
            }),
            "request_timeout_ms": self.config.as_ref().map(|config| config.request_timeout_ms),
            "verification_script": VERIFICATION_SCRIPT_PATH,
            "artifact_root_hint": ARTIFACT_ROOT_HINT,
            "provisioning": self.provisioning_readiness(),
            "operator_guidance": operator_guidance(),
            "contract": contract_details(self.config.as_ref()),
            "live_probe": live_probe,
        })
    }

    fn attach_self_check_details(
        &self,
        mut report: SelfCheckReport,
        live_probe: Option<serde_json::Value>,
    ) -> SelfCheckReport {
        report.details = Some(self.diagnostic_details(live_probe));
        report
    }

    /// Run connector diagnostics.
    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        let provisioning = self.provisioning_readiness();

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
                "HTTP client initialized".into()
            } else {
                "HTTP client missing; re-run configure".into()
            }),
            critical: true,
        });

        let runtime_ok = self.runtime.is_some();
        checks.push(DoctorCheck {
            name: "runtime".into(),
            passed: runtime_ok,
            message: Some(if runtime_ok {
                "ConnectorRuntime initialized".into()
            } else {
                "Runtime missing".into()
            }),
            critical: true,
        });

        if let Some(readiness) = &provisioning {
            checks.push(DoctorCheck {
                name: "endpoint_policy".into(),
                passed: readiness.network_ok,
                message: Some(readiness.network_message.clone()),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "auth_mode".into(),
                passed: true,
                message: Some(format!("Auth mode: {}", readiness.auth_mode)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "secret_material".into(),
                passed: readiness.credentials_configured,
                message: Some(if readiness.credentials_configured {
                    "Concrete tenant app credentials configured".into()
                } else {
                    "App ID or secret missing".into()
                }),
                critical: true,
            });
            checks.push(DoctorCheck {
                name: "tenant_boundary".into(),
                passed: true,
                message: Some(readiness.tenant_app_boundary.into()),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks, provisioning)
    }
}

impl Default for FeishuConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn feishu_auth_caps() -> AuthCaps {
    AuthCaps {
        methods: vec![
            "app_id_secret".to_string(),
            "tenant_access_token_internal".to_string(),
        ],
        oauth: None,
    }
}

fn feishu_resource_types() -> Vec<ResourceTypeInfo> {
    vec![
        ResourceTypeInfo {
            name: "feishu.message".into(),
            uri_pattern: "feishu://messages/{message_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string" },
                    "chat_id": { "type": "string" },
                    "msg_type": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.chat".into(),
            uri_pattern: "feishu://chats/{chat_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.user".into(),
            uri_pattern: "feishu://users/{user_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.document".into(),
            uri_pattern: "feishu://docs/{document_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": { "type": "string" },
                    "document": { "type": "object" },
                    "body": { "type": "object" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.spreadsheet".into(),
            uri_pattern: "feishu://sheets/{spreadsheet_token}".into(),
            schema: json!({
                "type": "object",
                "required": ["spreadsheet_token"],
                "properties": {
                    "spreadsheet_token": { "type": "string" },
                    "title": { "type": "string" },
                    "sheets": { "type": "array" }
                }
            }),
        },
        ResourceTypeInfo {
            name: "feishu.calendar_event".into(),
            uri_pattern: "feishu://calendars/{calendar_id}/events/{event_id}".into(),
            schema: json!({
                "type": "object",
                "required": ["calendar_id", "event_id"],
                "properties": {
                    "calendar_id": { "type": "string" },
                    "event_id": { "type": "string" },
                    "summary": { "type": "string" },
                    "start_time": { "type": "string" },
                    "end_time": { "type": "string" }
                }
            }),
        },
    ]
}

/// Build the typed operations catalog.
pub fn operations_info() -> Vec<OperationInfo> {
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_SEND),
            summary: "Send a message via Feishu".into(),
            description: Some(
                "Sends a bot-authored message through the installed tenant app to one visible user or chat; custom webhook bots, user impersonation, and cross-tenant fan-out are out of scope for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["receive_id", "msg_type", "content"],
                "properties": {
                    "receive_id": { "type": "string", "description": "Receiver ID (user open_id or chat_id)" },
                    "receive_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id, email, chat_id", "default": "open_id" },
                    "msg_type": { "type": "string", "description": "Message type: text, post, image, interactive, etc." },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When you need to send a message to a Feishu user or group chat"
                    .into(),
                common_mistakes: vec![
                    "Content must be JSON-encoded string matching msg_type schema".into(),
                    "receive_id_type defaults to open_id if not specified".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MSG_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_REPLY),
            summary: "Reply to a Feishu message".into(),
            description: Some(
                "Replies to an existing message visible to the installed tenant app; this does not provide general thread syncing or inbound event delivery.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_id", "msg_type", "content"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to reply to" },
                    "msg_type": { "type": "string", "description": "Message type" },
                    "content": { "type": "string", "description": "JSON-encoded message content" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: AgentHint {
                when_to_use: "When replying to an existing message in a thread".into(),
                common_mistakes: vec![
                    "message_id must be valid and accessible".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_MSG_WRITE)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_MESSAGES_GET),
            summary: "Get a Feishu message by ID".into(),
            description: Some(
                "Retrieves one message visible to the installed tenant app. Webhook and websocket delivery surfaces remain explicit non-goals in this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string", "description": "Message ID to retrieve" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": { "type": "string" },
                    "msg_type": { "type": "string" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_MSG_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read the content of a specific message".into(),
                common_mistakes: vec![
                    "This first slice only reads messages already visible to the installed app."
                        .into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_LIST),
            summary: "List Feishu chats".into(),
            description: Some(
                "Lists chats visible to the installed tenant app with pagination. Direct-message discovery and global workspace search beyond bot visibility are out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page_token": { "type": "string", "description": "Pagination token" },
                    "page_size": { "type": "integer", "description": "Page size (max 200)", "default": 20 }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list all chats the bot has access to".into(),
                common_mistakes: vec![
                    "Use page_token from response for subsequent pages".into(),
                    "The result set is limited to chats visible to the installed app.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_CHATS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CHATS_GET),
            summary: "Get Feishu chat details".into(),
            description: Some(
                "Retrieves metadata for one chat visible to the installed tenant app.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["chat_id"],
                "properties": {
                    "chat_id": { "type": "string", "description": "Chat ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "chat_id": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CHATS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need details about a specific chat".into(),
                common_mistakes: vec![
                    "chat_id must refer to a conversation visible to the installed app.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_CHATS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_USERS_GET),
            summary: "Get Feishu user info".into(),
            description: Some(
                "Retrieves directory information for one tenant user identifier. Cross-tenant lookup, admin writes, and provisioning flows are out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["user_id"],
                "properties": {
                    "user_id": { "type": "string", "description": "User ID" },
                    "user_id_type": { "type": "string", "description": "Type: open_id, user_id, union_id", "default": "open_id" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "user_id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to look up user information".into(),
                common_mistakes: vec![
                    "user_id_type must match the format of user_id provided".into(),
                    FEISHU_TENANT_APP_BOUNDARY.into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_DOCS_GET),
            summary: "Get Feishu document content".into(),
            description: Some(
                "Retrieves the raw content of one known Feishu docx document. Drive search, export, folder traversal, and writes are explicit non-goals for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["document_id"],
                "properties": {
                    "document_id": { "type": "string", "description": "Document ID" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "document": { "type": "object" },
                    "body": { "type": "object" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu document's content".into(),
                common_mistakes: vec![
                    "This operation expects a known docx document token; it does not search Drive."
                        .into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_DOCS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_SHEETS_GET),
            summary: "Get Feishu spreadsheet info".into(),
            description: Some(
                "Retrieves spreadsheet metadata and sheet inventory for one known token. Cell mutation, formula writes, and bulk export remain out of scope.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["spreadsheet_token"],
                "properties": {
                    "spreadsheet_token": { "type": "string", "description": "Spreadsheet token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "spreadsheet_token": { "type": "string" },
                    "title": { "type": "string" },
                    "sheets": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_DOCS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to read a Feishu spreadsheet's structure and data"
                    .into(),
                common_mistakes: vec![
                    "This first slice returns spreadsheet metadata and sheet inventory, not write handles."
                        .into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_DOCS_READ)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CALENDAR_EVENTS),
            summary: "List Feishu calendar events".into(),
            description: Some(
                "Lists events from one known calendar within the bound tenant app. Calendar mutations and push subscriptions are explicit non-goals for this first slice.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["calendar_id"],
                "properties": {
                    "calendar_id": { "type": "string", "description": "Calendar ID" },
                    "page_token": { "type": "string", "description": "Pagination token" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "items": { "type": "array" },
                    "page_token": { "type": "string" },
                    "has_more": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_CALENDAR_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When you need to list events from a Feishu calendar".into(),
                common_mistakes: vec![
                    "calendar_id is required, not the same as user_id".into(),
                    "Event subscriptions are not part of this first implementation.".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_WEBHOOK_INGEST_REQUEST),
            summary: "Ingest a host-forwarded Feishu webhook request".into(),
            description: Some(
                "Validates a Feishu/Lark webhook request already accepted by host ingress, verifies token and signature, rejects encrypted payloads, normalizes supported message/read/reaction/document-comment events, and applies caller-supplied sender/chat/comment policy before returning an event record.".into(),
            ),
            input_schema: json!({
                "type": "object",
                "required": ["method", "headers", "raw_body", "verification_token", "encrypt_key", "policy"],
                "properties": {
                    "method": { "type": "string", "description": "Forwarded HTTP method; only POST is accepted" },
                    "headers": { "type": "object", "description": "Forwarded request headers including x-lark-request-timestamp, x-lark-request-nonce, and x-lark-signature" },
                    "raw_body": { "type": "string", "description": "Exact raw JSON body bytes decoded as UTF-8; required for Feishu signature verification" },
                    "verification_token": { "type": "string", "description": "Configured Feishu verification token" },
                    "encrypt_key": { "type": "string", "description": "Configured Feishu encrypt key used by Feishu signature construction; encrypted payloads are still rejected by this slice" },
                    "policy": { "type": "object", "description": "Sender/chat/mention/comment policy evaluated before event emission" },
                    "seen_event_ids": { "type": "array", "items": { "type": "string" }, "description": "Caller-supplied dedupe set for idempotent retry handling" },
                    "max_body_bytes": { "type": "integer", "minimum": 1, "maximum": FEISHU_WEBHOOK_MAX_BODY_BYTES },
                    "deadline_exceeded": { "type": "boolean", "description": "Host request-region timeout signal for deterministic tests and admission handling" },
                    "rate_limited": { "type": "boolean", "description": "Host request-region rate-limit signal for deterministic tests and admission handling" }
                }
            }),
            output_schema: json!({
                "type": "object",
                "required": ["accepted", "status_code", "reason_code", "event_emitted", "logs"],
                "properties": {
                    "accepted": { "type": "boolean" },
                    "status_code": { "type": "integer" },
                    "reason_code": { "type": "string" },
                    "event_emitted": { "type": "boolean" },
                    "event_id": { "type": ["string", "null"] },
                    "event_type": { "type": ["string", "null"] },
                    "dedupe_key": { "type": ["string", "null"] },
                    "normalized_event": { "type": ["object", "null"] },
                    "policy_decision": { "type": ["object", "null"] },
                    "response_body": { "type": "object" },
                    "logs": { "type": "array" }
                }
            }),
            capability: CapabilityId::from_static(CAP_WEBHOOK_INGEST),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: AgentHint {
                when_to_use: "When host ingress forwards a Feishu/Lark webhook request for validation, normalization, and policy gating.".into(),
                common_mistakes: vec![
                    "Pass the exact raw JSON body string used for signature verification.".into(),
                    "Do not use this operation as an embedded HTTP listener; host ingress owns the socket.".into(),
                    "Encrypted Feishu webhook payloads are deliberately rejected in this slice.".into(),
                ],
                examples: Vec::new(),
                related: vec![CapabilityId::from_static(CAP_WEBHOOK_INGEST)],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Feishu API health check".into(),
            description: Some(
                "Verifies that the configured app_id/app_secret can reach the internal tenant access token endpoint on the Feishu CN or Lark global API host.".into(),
            ),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "status": { "type": "string" }
                }
            }),
            capability: CapabilityId::from_static(CAP_USERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When checking if the Feishu API connection is healthy".into(),
                common_mistakes: vec![
                    "Health proves host reachability and credential validity, not every optional product scope.".into(),
                ],
                examples: Vec::new(),
                related: Vec::new(),
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(FeishuConnector);

#[async_trait]
impl FcpConnector for FeishuConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let config: FeishuConfig =
            serde_json::from_value(config).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid Feishu config: {e}"),
            })?;
        validate_config(&config)?;

        let request_timeout = Duration::from_millis(config.request_timeout_ms);
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default().with_request_timeout(request_timeout),
        );

        let client = FeishuClient::new(
            &config.base_url,
            &config.app_id,
            &config.app_secret,
            config.retry.clone(),
            request_timeout,
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Failed to create Feishu client: {e}"),
        })?;

        // Attempt to obtain a tenant access token on configure
        if let Ok(token) = client.obtain_tenant_access_token().await {
            tracing::info!(
                "Feishu tenant access token obtained (length={})",
                token.len()
            );
        } else {
            tracing::warn!(
                "Failed to obtain Feishu tenant access token; will retry on first request"
            );
        }

        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
        self.retry_config = config.retry.clone();
        self.runtime = Some(runtime);
        self.client = Some(client);
        self.config = Some(config);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if self.config.is_none() || self.client.is_none() || self.runtime.is_none() {
            return Err(FcpError::NotConfigured);
        }

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
            event_caps: Some(feishu_event_caps()),
            auth_caps: Some(feishu_auth_caps()),
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let provisioning = self.provisioning_readiness();
        let ready = self.config.is_some()
            && self.client.is_some()
            && self.runtime.is_some()
            && provisioning
                .as_ref()
                .is_none_or(|readiness| readiness.network_ok && readiness.credentials_configured);
        let mut snapshot = if ready {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot.details = Some(self.diagnostic_details(None));
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let provisioning = self.provisioning_readiness();
        let Some(client) = &self.client else {
            return Ok(self.attach_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
            ));
        };

        if let Some(readiness) = &provisioning {
            if !readiness.network_ok {
                return Ok(self.attach_self_check_details(
                    SelfCheckReport::failed(
                        "network_constraints_invalid",
                        readiness.network_message.clone(),
                    ),
                    None,
                ));
            }
            if !readiness.credentials_configured {
                return Ok(self.attach_self_check_details(
                    SelfCheckReport::degraded(
                        "missing_credentials",
                        "App ID or secret not configured",
                    ),
                    None,
                ));
            }
        }

        match client.health_check().await {
            Ok(()) => Ok(self.attach_self_check_details(
                SelfCheckReport::ok(),
                Some(json!({
                    "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                    "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                    "status": "ok",
                })),
            )),
            Err(err) => {
                if err.is_retryable() {
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::degraded("self_check_retryable", err.to_string()),
                        Some(json!({
                            "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                            "status": "retryable_error",
                            "retryable": true,
                            "retry_after_ms": err.retry_after().map(|duration| duration.as_millis() as u64),
                            "error": err.to_string(),
                        })),
                    ))
                } else {
                    let reason_code = if matches!(
                        err,
                        crate::error::FeishuError::Unauthorized(_)
                            | crate::error::FeishuError::HttpStatus {
                                status: 401 | 403,
                                ..
                            }
                    ) {
                        "feishu_auth_rejected"
                    } else {
                        "self_check_failed"
                    };
                    Ok(self.attach_self_check_details(
                        SelfCheckReport::failed(reason_code, err.to_string()),
                        Some(json!({
                            "endpoint": "POST /open-apis/auth/v3/tenant_access_token/internal",
                            "base_url": self.config.as_ref().map(|config| config.base_url.clone()),
                            "status": "error",
                            "retryable": false,
                            "error": err.to_string(),
                        })),
                    ))
                }
            }
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let required_cap = match required_capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        if let Err(error) = validate_operation_input(req.operation.as_str(), &req.input) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        if let Err(error) = self.base.check_ready() {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let verifier = match self.verifier.as_ref() {
            Some(verifier) => verifier,
            None => {
                let error = FcpError::Internal {
                    message: "Capability verifier missing after successful handshake".into(),
                };
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        match verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[]) {
            Ok(_) => Ok(SimulateResponse::allowed(req.id)),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) {
                    response =
                        response.with_missing_capabilities(vec![required_cap.as_str().to_string()]);
                }
                Ok(response)
            }
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: feishu_events_info(),
            resource_types: feishu_resource_types(),
            auth_caps: Some(feishu_auth_caps()),
            event_caps: Some(feishu_event_caps()),
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

impl FeishuConnector {
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();

        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Capability verifier missing after successful handshake".into(),
        })?;
        let required_cap = required_capability_for_operation(operation)?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let runtime = self.runtime.as_ref().ok_or(FcpError::Internal {
            message: "Connector runtime missing after configure".into(),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::Internal {
            message: "Feishu client missing after configure".into(),
        })?;

        let output = match operation {
            OP_MESSAGES_SEND => {
                let receive_id = req.input.get("receive_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'receive_id' field".into(),
                    },
                )?;
                let msg_type = req.input.get("msg_type").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    },
                )?;
                let content = req.input.get("content").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    },
                )?;
                let receive_id_type = req
                    .input
                    .get("receive_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");
                let receive_id_type = validate_receive_id_type(receive_id_type)?;

                let send_req = SendMessageRequest {
                    receive_id: receive_id.into(),
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let resp = client
                    .send_message(runtime, receive_id_type, &send_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_MESSAGES_REPLY => {
                let message_id = req.input.get("message_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    },
                )?;
                let msg_type = req.input.get("msg_type").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'msg_type' field".into(),
                    },
                )?;
                let content = req.input.get("content").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'content' field".into(),
                    },
                )?;

                let reply_req = ReplyMessageRequest {
                    msg_type: msg_type.into(),
                    content: content.into(),
                };
                let resp = client
                    .reply_message(runtime, message_id, &reply_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_MESSAGES_GET => {
                let message_id = req.input.get("message_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'message_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_message(runtime, message_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_LIST => {
                let pagination_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let page_size = req
                    .input
                    .get("page_size")
                    .and_then(|v| v.as_u64())
                    .map(validate_chats_page_size)
                    .transpose()?;
                let resp = client
                    .list_chats(runtime, pagination_cursor, page_size)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CHATS_GET => {
                let chat_id = req.input.get("chat_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'chat_id' field".into(),
                    },
                )?;
                let resp = client
                    .get_chat(runtime, chat_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_USERS_GET => {
                let user_id = req.input.get("user_id").and_then(|v| v.as_str()).ok_or(
                    FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'user_id' field".into(),
                    },
                )?;
                let user_id_type = req
                    .input
                    .get("user_id_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("open_id");
                let user_id_type = validate_user_id_type(user_id_type)?;
                let resp = client
                    .get_user(runtime, user_id, user_id_type)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_DOCS_GET => {
                let document_id = req
                    .input
                    .get("document_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'document_id' field".into(),
                    })?;
                let resp = client
                    .get_document(runtime, document_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_SHEETS_GET => {
                let spreadsheet_ref = req
                    .input
                    .get("spreadsheet_token")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'spreadsheet_token' field".into(),
                    })?;
                let resp = client
                    .get_spreadsheet(runtime, spreadsheet_ref)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_CALENDAR_EVENTS => {
                let calendar_id = req
                    .input
                    .get("calendar_id")
                    .and_then(|v| v.as_str())
                    .ok_or(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing 'calendar_id' field".into(),
                    })?;
                let pagination_cursor = req.input.get("page_token").and_then(|v| v.as_str());
                let resp = client
                    .list_calendar_events(runtime, calendar_id, pagination_cursor)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(resp).map_err(|e| FcpError::Internal {
                    message: format!("Failed to serialize response: {e}"),
                })?
            }
            OP_WEBHOOK_INGEST_REQUEST => invoke_webhook_ingest_request(&req.input)?,
            OP_HEALTH => {
                client.health_check().await.map_err(|e| e.to_fcp_error())?;
                json!({ "status": "healthy" })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::CapabilityConstraints;

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        capability: &'static str,
        operation: &'static str,
        instance_id: &InstanceId,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
        let raw = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id.as_str())
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(raw)
    }

    async fn configure_for_tests(connector: &mut FeishuConnector) {
        connector
            .configure(json!({
                "base_url": "http://127.0.0.1:9",
                "app_id": "cli_test",
                "app_secret": "secret",
                "request_timeout_ms": 100
            }))
            .await
            .unwrap();
    }

    async fn handshake_for_tests(connector: &mut FeishuConnector) -> Ed25519SigningKey {
        let signing_key = Ed25519SigningKey::generate();
        let mut request = base_handshake();
        request.host_public_key = signing_key.verifying_key().to_bytes();
        connector.handshake(request).await.unwrap();
        signing_key
    }

    fn simulate_request(
        connector: &FeishuConnector,
        operation: &'static str,
        input: serde_json::Value,
        capability_token: CapabilityToken,
    ) -> SimulateRequest {
        SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            capability_token,
        )
    }

    fn base_handshake() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_MSG_WRITE),
                CapabilityId::from_static(CAP_MSG_READ),
                CapabilityId::from_static(CAP_CHATS_READ),
                CapabilityId::from_static(CAP_USERS_READ),
                CapabilityId::from_static(CAP_DOCS_READ),
                CapabilityId::from_static(CAP_CALENDAR_READ),
                CapabilityId::from_static(CAP_WEBHOOK_INGEST),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn base_invoke(connector_id: &ConnectorId, operation: &'static str) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_1"),
            connector_id: connector_id.clone(),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
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

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let result = connector.handshake(base_handshake()).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_requires_configure() {
        let mut connector = FeishuConnector::new();
        let result = connector.handshake(base_handshake()).await;
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_fields() {
        let mut connector = FeishuConnector::new();
        let result = connector.configure(json!({})).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_accepts_localhost_http_for_tests() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "http://127.0.0.1:9",
                "app_id": "cli_test",
                "app_secret": "secret"
            }))
            .await;
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_zero_timeout() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "app_id": "cli_test",
                "app_secret": "secret",
                "request_timeout_ms": 0
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_rejects_base_url_path() {
        let mut connector = FeishuConnector::new();
        let result = connector
            .configure(json!({
                "base_url": "https://open.feishu.cn/open-apis",
                "app_id": "cli_test",
                "app_secret": "secret"
            }))
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_before_configure() {
        let connector = FeishuConnector::new();
        let health = connector.health().await;
        assert!(matches!(health.status, HealthState::Degraded { .. }));
    }

    #[test]
    fn test_doctor_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.doctor();
        assert!(!report.passed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_self_check_before_configure() {
        let connector = FeishuConnector::new();
        let report = connector.self_check().await.unwrap();
        assert_eq!(report.status, SelfCheckStatus::Degraded);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_configure() {
        let connector = FeishuConnector::new();
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotConfigured.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_denies_before_handshake() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            CapabilityToken::test_token(),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.denial_code, Some(FcpError::NotHandshaken.error_code()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_allows_valid_bound_capability() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            signed_token(
                &signing_key,
                CAP_MSG_WRITE,
                OP_MESSAGES_SEND,
                connector.instance_id(),
            ),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(resp.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_wrong_capability() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_test",
                "msg_type": "text",
                "content": "{\"text\":\"hello\"}"
            }),
            signed_token(
                &signing_key,
                CAP_CHATS_READ,
                OP_CHATS_LIST,
                connector.instance_id(),
            ),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert_eq!(resp.missing_capabilities, vec![CAP_MSG_WRITE.to_string()]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_simulate_rejects_missing_required_input() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let signing_key = handshake_for_tests(&mut connector).await;
        let req = simulate_request(
            &connector,
            OP_MESSAGES_SEND,
            json!({}),
            signed_token(
                &signing_key,
                CAP_MSG_WRITE,
                OP_MESSAGES_SEND,
                connector.instance_id(),
            ),
        );
        let resp = connector.simulate(req).await.unwrap();
        assert!(!resp.would_succeed);
        assert!(resp.failure_reason.unwrap().contains("receive_id"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_reconfigure_clears_handshake_state() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector).await;

        connector
            .configure(json!({
                "base_url": "http://127.0.0.1:9",
                "app_id": "cli_test_2",
                "app_secret": "secret_2",
                "request_timeout_ms": 100
            }))
            .await
            .unwrap();

        assert!(connector.verifier.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotHandshaken)
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown_clears_connector_state() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        handshake_for_tests(&mut connector).await;

        connector
            .shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 1000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();

        assert!(connector.client.is_none());
        assert!(connector.config.is_none());
        assert!(connector.runtime.is_none());
        assert!(connector.verifier.is_none());
        assert!(matches!(
            connector.base.check_ready(),
            Err(FcpError::NotConfigured)
        ));
    }

    #[test]
    fn test_introspection_operations() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 11);
        let op_ids: Vec<&str> = intro.operations.iter().map(|op| op.id.as_str()).collect();
        assert!(op_ids.contains(&OP_MESSAGES_SEND));
        assert!(op_ids.contains(&OP_MESSAGES_REPLY));
        assert!(op_ids.contains(&OP_MESSAGES_GET));
        assert!(op_ids.contains(&OP_CHATS_LIST));
        assert!(op_ids.contains(&OP_CHATS_GET));
        assert!(op_ids.contains(&OP_USERS_GET));
        assert!(op_ids.contains(&OP_DOCS_GET));
        assert!(op_ids.contains(&OP_SHEETS_GET));
        assert!(op_ids.contains(&OP_CALENDAR_EVENTS));
        assert!(op_ids.contains(&OP_WEBHOOK_INGEST_REQUEST));
        assert!(op_ids.contains(&OP_HEALTH));
    }

    #[test]
    fn test_operations_info_count() {
        let ops = operations_info();
        assert_eq!(ops.len(), 11);
    }

    #[test]
    fn test_introspection_advertises_tenant_app_auth() {
        let intro = FeishuConnector::new().introspect();
        let auth = intro.auth_caps.expect("auth caps");
        assert!(auth.methods.contains(&"app_id_secret".to_string()));
        assert!(
            auth.methods
                .contains(&"tenant_access_token_internal".to_string())
        );
        assert!(auth.oauth.is_none());
    }

    #[test]
    fn test_introspection_exposes_first_slice_resource_inventory() {
        let intro = FeishuConnector::new().introspect();
        let names: Vec<&str> = intro
            .resource_types
            .iter()
            .map(|ty| ty.name.as_str())
            .collect();
        assert!(names.contains(&"feishu.message"));
        assert!(names.contains(&"feishu.chat"));
        assert!(names.contains(&"feishu.user"));
        assert!(names.contains(&"feishu.document"));
        assert!(names.contains(&"feishu.spreadsheet"));
        assert!(names.contains(&"feishu.calendar_event"));
    }

    #[test]
    fn test_operations_have_ai_hints() {
        let ops = operations_info();
        for op in &ops {
            assert!(!op.ai_hints.when_to_use.is_empty());
        }
    }

    #[test]
    fn test_messages_send_is_risky() {
        let ops = operations_info();
        let send = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_SEND)
            .unwrap();
        assert_eq!(send.safety_tier, SafetyTier::Risky);
        assert_eq!(send.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_messages_get_is_safe() {
        let ops = operations_info();
        let get = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_GET)
            .unwrap();
        assert_eq!(get.safety_tier, SafetyTier::Safe);
    }

    #[test]
    fn test_health_op_is_safe_and_strict() {
        let ops = operations_info();
        let health = ops.iter().find(|op| op.id.as_str() == OP_HEALTH).unwrap();
        assert_eq!(health.safety_tier, SafetyTier::Safe);
        assert_eq!(health.idempotency, IdempotencyClass::Strict);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let hash1 = FeishuConnector::manifest_hash();
        let hash2 = FeishuConnector::manifest_hash();
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_streaming_not_supported() {
        let connector = FeishuConnector::new();
        let intro = connector.introspect();
        assert!(!intro.event_caps.as_ref().unwrap().streaming);
        assert!(intro.event_caps.as_ref().unwrap().replay);
        assert!(
            intro
                .events
                .iter()
                .any(|event| event.topic == "feishu.webhook.message_received")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_unknown_operation() {
        let connector = FeishuConnector::new();
        // Can't test with full configure (needs network), just verify unconfigured case
        let req = base_invoke(connector.id(), "feishu.nonexistent");
        let result = connector.invoke(req).await;
        assert!(result.is_err()); // Not configured
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_configure() {
        let connector = FeishuConnector::new();
        let req = base_invoke(connector.id(), OP_MESSAGES_SEND);
        let result = connector.invoke(req).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_impl() {
        let connector = FeishuConnector::default();
        assert_eq!(connector.id().as_str(), "fcp.feishu");
    }

    #[test]
    fn test_config_debug_redacts_secret() {
        let config = FeishuConfig {
            base_url: "https://open.feishu.cn".into(),
            app_id: "cli_test".into(),
            app_secret: "secret_value_here".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains("secret_value_here"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_chats_list_capability() {
        let ops = operations_info();
        let cl = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CHATS_LIST)
            .unwrap();
        assert_eq!(cl.capability, CapabilityId::from_static(CAP_CHATS_READ));
    }

    #[test]
    fn test_docs_get_capability() {
        let ops = operations_info();
        let dg = ops.iter().find(|op| op.id.as_str() == OP_DOCS_GET).unwrap();
        assert_eq!(dg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_sheets_get_capability() {
        let ops = operations_info();
        let sg = ops
            .iter()
            .find(|op| op.id.as_str() == OP_SHEETS_GET)
            .unwrap();
        assert_eq!(sg.capability, CapabilityId::from_static(CAP_DOCS_READ));
    }

    #[test]
    fn test_calendar_events_capability() {
        let ops = operations_info();
        let ce = ops
            .iter()
            .find(|op| op.id.as_str() == OP_CALENDAR_EVENTS)
            .unwrap();
        assert_eq!(ce.capability, CapabilityId::from_static(CAP_CALENDAR_READ));
    }

    #[test]
    fn test_users_get_capability() {
        let ops = operations_info();
        let ug = ops
            .iter()
            .find(|op| op.id.as_str() == OP_USERS_GET)
            .unwrap();
        assert_eq!(ug.capability, CapabilityId::from_static(CAP_USERS_READ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake_grants_capabilities() {
        let mut connector = FeishuConnector::new();
        configure_for_tests(&mut connector).await;
        let result = connector.handshake(base_handshake()).await.unwrap();
        assert_eq!(result.capabilities_granted.len(), 7);
        assert!(result.event_caps.unwrap().replay);
        assert!(result.auth_caps.is_some());
    }

    #[test]
    fn test_messages_reply_is_risky() {
        let ops = operations_info();
        let reply = ops
            .iter()
            .find(|op| op.id.as_str() == OP_MESSAGES_REPLY)
            .unwrap();
        assert_eq!(reply.safety_tier, SafetyTier::Risky);
        assert_eq!(reply.idempotency, IdempotencyClass::None);
    }

    #[test]
    fn test_no_dangerous_operations() {
        // Feishu connector has no dangerous operations (no delete endpoints)
        let ops = operations_info();
        assert!(ops.iter().all(|op| op.safety_tier != SafetyTier::Dangerous));
    }

    #[test]
    fn test_all_safe_operations_are_low_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Safe {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Low,
                    "Op {} should be low risk",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn test_all_risky_operations_are_medium_risk() {
        let ops = operations_info();
        for op in &ops {
            if op.safety_tier == SafetyTier::Risky {
                assert_eq!(
                    op.risk_level,
                    RiskLevel::Medium,
                    "Op {} should be medium risk",
                    op.id.as_str()
                );
            }
        }
    }

    #[test]
    fn test_read_operations_are_strictly_idempotent() {
        let ops = operations_info();
        for operation_id in [
            OP_MESSAGES_GET,
            OP_CHATS_LIST,
            OP_CHATS_GET,
            OP_USERS_GET,
            OP_DOCS_GET,
            OP_SHEETS_GET,
            OP_CALENDAR_EVENTS,
            OP_HEALTH,
        ] {
            let op = ops
                .iter()
                .find(|candidate| candidate.id.as_str() == operation_id)
                .unwrap();
            assert_eq!(
                op.idempotency,
                IdempotencyClass::Strict,
                "operation {} should be strictly idempotent",
                op.id.as_str()
            );
        }
    }

    #[test]
    fn test_doctor_accepts_larksuite_global_host() {
        let mut connector = FeishuConnector::new();
        connector.config = Some(FeishuConfig {
            base_url: "https://open.larksuite.com".into(),
            app_id: "app_id".into(),
            app_secret: "app_secret".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: default_request_timeout_ms(),
        });
        connector.client = Some(
            FeishuClient::new(
                "https://open.larksuite.com",
                "app_id",
                "app_secret",
                HttpRetryConfig::default(),
                Duration::from_millis(default_request_timeout_ms()),
            )
            .expect("client"),
        );
        connector.runtime = Some(ConnectorRuntime::new(ConnectorRuntimeConfig::default()));
        let report = connector.doctor();
        let host_check = report
            .checks
            .iter()
            .find(|check| check.name == "endpoint_policy")
            .expect("endpoint_policy check");
        assert!(host_check.passed);
    }

    #[test]
    fn test_validate_receive_id_type_rejects_unknown_value() {
        assert!(validate_receive_id_type("tenant_key").is_err());
    }

    #[test]
    fn test_validate_user_id_type_rejects_unknown_value() {
        assert!(validate_user_id_type("email").is_err());
    }

    #[test]
    fn test_validate_chats_page_size_bounds() {
        assert!(validate_chats_page_size(0).is_err());
        assert!(validate_chats_page_size(201).is_err());
        assert_eq!(validate_chats_page_size(200).unwrap(), 200);
    }

    fn signed_webhook_input(raw_body: String, policy: Value) -> Value {
        let timestamp = "1715000000";
        let nonce = "nonce-123";
        let encrypt_key = "encrypt-key";
        let signature = feishu_signature_hex(timestamp, nonce, encrypt_key, &raw_body);
        json!({
            "method": "POST",
            "headers": {
                "x-lark-request-timestamp": timestamp,
                "x-lark-request-nonce": nonce,
                "x-lark-signature": signature,
            },
            "raw_body": raw_body,
            "verification_token": "verify-token",
            "encrypt_key": encrypt_key,
            "policy": policy,
        })
    }

    fn message_event_body(sender: &str, chat: &str) -> String {
        serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-message-1",
                "event_type": "im.message.receive_v1",
                "token": "verify-token",
            },
            "event": {
                "sender": { "sender_id": { "open_id": sender } },
                "message": {
                    "message_id": "om_1",
                    "chat_id": chat,
                    "chat_type": "group",
                    "message_type": "text",
                    "content": "{\"text\":\"hello\"}",
                    "mentions": [{ "id": { "open_id": "ou_bot" } }]
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn test_webhook_challenge_response() {
        let raw_body = serde_json::to_string(&json!({
            "type": "url_verification",
            "token": "verify-token",
            "challenge": "challenge-value",
        }))
        .unwrap();
        let output = invoke_webhook_ingest_request(&signed_webhook_input(raw_body, json!({})))
            .expect("webhook challenge should process");

        assert_eq!(output["status_code"], 200);
        assert_eq!(output["reason_code"], "challenge_response");
        assert_eq!(output["response_body"]["challenge"], "challenge-value");
        assert_eq!(output["event_emitted"], false);
    }

    #[test]
    fn test_webhook_rejects_invalid_signature() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut input = signed_webhook_input(raw_body, json!({}));
        input["headers"]["x-lark-signature"] = json!("not-hex");

        let output = invoke_webhook_ingest_request(&input).expect("webhook should return response");
        assert_eq!(output["status_code"], 401);
        assert_eq!(output["reason_code"], "invalid_signature");
        assert_eq!(output["event_emitted"], false);
    }

    #[test]
    fn test_webhook_rejects_encrypted_payload() {
        let raw_body = serde_json::to_string(&json!({
            "encrypt": "ciphertext",
            "token": "verify-token",
        }))
        .unwrap();
        let output = invoke_webhook_ingest_request(&signed_webhook_input(raw_body, json!({})))
            .expect("encrypted payload should return explicit denial");

        assert_eq!(output["status_code"], 415);
        assert_eq!(output["reason_code"], "encrypted_payload_unsupported");
    }

    #[test]
    fn test_webhook_normalizes_message_event_with_policy() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let output = invoke_webhook_ingest_request(&signed_webhook_input(
            raw_body,
            json!({
                "allowed_sender_open_ids": ["ou_allowed"],
                "allowed_chat_ids": ["oc_allowed"],
                "require_mention": true,
                "bot_open_id": "ou_bot",
            }),
        ))
        .expect("message event should process");

        assert_eq!(output["status_code"], 200);
        assert_eq!(output["reason_code"], "event_accepted");
        assert_eq!(output["event_emitted"], true);
        assert_eq!(output["event_id"], "evt-message-1");
        assert_eq!(
            output["normalized_event"]["topic"],
            "feishu.webhook.message_received"
        );
        assert_eq!(output["normalized_event"]["raw_content_included"], false);
    }

    #[test]
    fn test_webhook_denies_sender_policy_before_emission() {
        let raw_body = message_event_body("ou_denied", "oc_allowed");
        let output = invoke_webhook_ingest_request(&signed_webhook_input(
            raw_body,
            json!({
                "allowed_sender_open_ids": ["ou_allowed"],
                "allowed_chat_ids": ["oc_allowed"],
            }),
        ))
        .expect("policy denial should return webhook response");

        assert_eq!(output["status_code"], 200);
        assert_eq!(output["event_emitted"], false);
        assert_eq!(output["reason_code"], "sender_not_allowed");
        assert_eq!(output["policy_decision"]["allowed"], false);
    }

    #[test]
    fn test_webhook_duplicate_uses_caller_supplied_dedupe() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut input = signed_webhook_input(raw_body, json!({}));
        input["seen_event_ids"] = json!(["evt-message-1"]);

        let output = invoke_webhook_ingest_request(&input).expect("duplicate should process");
        assert_eq!(output["status_code"], 200);
        assert_eq!(output["reason_code"], "duplicate_event");
        assert_eq!(output["event_emitted"], false);
        assert_eq!(
            output["dedupe_key"],
            "feishu:im.message.receive_v1:evt-message-1"
        );
    }

    #[test]
    fn test_webhook_comment_policy_pairing() {
        let raw_body = serde_json::to_string(&json!({
            "schema": "2.0",
            "header": {
                "event_id": "evt-comment-1",
                "event_type": "drive.notice.comment_add_v1",
                "token": "verify-token",
            },
            "event": {
                "file_token": "doc_1",
                "file_type": "docx",
                "comment_id": "comment_1",
                "user_id": { "open_id": "ou_commenter" }
            }
        }))
        .unwrap();

        let denied =
            invoke_webhook_ingest_request(&signed_webhook_input(raw_body.clone(), json!({})))
                .expect("missing comment policy should deny");
        assert_eq!(denied["event_emitted"], false);
        assert_eq!(denied["reason_code"], "comment_policy_required");

        let allowed = invoke_webhook_ingest_request(&signed_webhook_input(
            raw_body,
            json!({
                "comment": {
                    "enabled": true,
                    "policy": "pairing",
                    "document_allowlist": ["doc_1"],
                    "paired_open_ids": ["ou_commenter"]
                }
            }),
        ))
        .expect("paired comment should pass");
        assert_eq!(allowed["event_emitted"], true);
        assert_eq!(
            allowed["normalized_event"]["topic"],
            "feishu.webhook.document_comment_added"
        );
    }

    #[test]
    fn test_webhook_request_region_signals() {
        let raw_body = message_event_body("ou_allowed", "oc_allowed");
        let mut body_limit = signed_webhook_input(raw_body.clone(), json!({}));
        body_limit["max_body_bytes"] = json!(1);
        let output = invoke_webhook_ingest_request(&body_limit).expect("body limit should respond");
        assert_eq!(output["status_code"], 413);
        assert_eq!(output["reason_code"], "body_too_large");

        let mut timeout = signed_webhook_input(raw_body.clone(), json!({}));
        timeout["deadline_exceeded"] = json!(true);
        let output = invoke_webhook_ingest_request(&timeout).expect("timeout should respond");
        assert_eq!(output["status_code"], 408);
        assert_eq!(output["reason_code"], "body_timeout");

        let mut rate = signed_webhook_input(raw_body, json!({}));
        rate["rate_limited"] = json!(true);
        let output = invoke_webhook_ingest_request(&rate).expect("rate limit should respond");
        assert_eq!(output["status_code"], 429);
        assert_eq!(output["reason_code"], "rate_limited");
    }
}
