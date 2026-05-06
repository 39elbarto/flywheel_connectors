//! Plivo API and connector-facing types.

use serde::{Deserialize, Serialize};

/// Plivo call object. Unknown provider fields remain available in `extra`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlivoCall {
    pub call_uuid: Option<String>,
    pub request_uuid: Option<String>,
    pub from_number: Option<String>,
    pub to_number: Option<String>,
    pub call_direction: Option<String>,
    pub call_state: Option<String>,
    pub call_status: Option<String>,
    pub call_duration: Option<u64>,
    pub api_id: Option<String>,
    pub message: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Plivo command response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlivoCommand {
    pub message: Option<String>,
    pub api_id: Option<String>,
    pub request_uuid: Option<String>,
    pub call_uuid: Option<String>,
    pub status_code: Option<u16>,
    pub xml: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Flexible Plivo API error envelope.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlivoApiErrorEnvelope {
    pub error: Option<String>,
    pub message: Option<String>,
    pub api_id: Option<String>,
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
    pub signature_version: String,
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
