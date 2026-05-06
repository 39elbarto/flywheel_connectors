//! Telnyx API and connector-facing types.

use serde::{Deserialize, Serialize};

/// Telnyx call object. The API shape varies by command, so unknown fields stay
/// available in `extra` without hard-coding unstable fields.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelnyxCall {
    pub call_control_id: Option<String>,
    pub call_leg_id: Option<String>,
    pub call_session_id: Option<String>,
    pub client_state: Option<String>,
    pub direction: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub status: Option<String>,
    pub record_type: Option<String>,
    pub is_alive: Option<bool>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Telnyx command response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelnyxCommand {
    pub result: Option<String>,
    pub call_control_id: Option<String>,
    pub call_leg_id: Option<String>,
    pub call_session_id: Option<String>,
    pub record_type: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Standard Telnyx envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnyxEnvelope<T> {
    pub data: T,
}

/// Telnyx API error envelope.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelnyxApiErrorEnvelope {
    pub errors: Vec<TelnyxApiError>,
}

/// Telnyx API error object.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelnyxApiError {
    pub code: Option<String>,
    pub title: Option<String>,
    pub detail: Option<String>,
}

/// Parsed Telnyx event envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnyxEventEnvelope {
    pub data: TelnyxEventData,
}

/// Telnyx event data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnyxEventData {
    pub id: Option<String>,
    pub event_type: String,
    pub occurred_at: Option<String>,
    pub record_type: Option<String>,
    #[serde(default)]
    pub payload: serde_json::Map<String, serde_json::Value>,
}

/// Connector-facing signature validation result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureValidationResult {
    pub valid: bool,
    pub reason_code: String,
    pub reason: String,
    pub is_replay: bool,
    pub verified_request_key: Option<String>,
    pub provider: String,
}

/// Inbound caller policy result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundPolicyDecision {
    pub allowed: bool,
    pub policy: String,
    pub reason_code: String,
    pub reason: String,
    pub from: Option<String>,
    pub normalized_from: Option<String>,
    pub matched_from: Option<String>,
    pub to: Option<String>,
    pub event_type: String,
    pub audit_event_type: String,
}

/// Redaction-safe webhook ingest log entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookIngressLogEntry {
    pub phase: String,
    pub outcome: String,
    pub code: String,
    pub message: String,
}

/// Production-boundary webhook ingest result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookIngressResult {
    pub accepted: bool,
    pub status_code: u16,
    pub reason_code: String,
    pub reason: String,
    pub event_type: Option<String>,
    pub event: Option<serde_json::Value>,
    pub signature: Option<SignatureValidationResult>,
    pub policy: Option<InboundPolicyDecision>,
    pub request_region: serde_json::Value,
    pub service_layers: serde_json::Value,
    pub logs: Vec<WebhookIngressLogEntry>,
    pub body_bytes: usize,
    pub tainted: bool,
    pub clean_shutdown: bool,
}
