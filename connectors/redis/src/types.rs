//! Redis connector types.

use serde::{Deserialize, Serialize};

/// Options for the SET command.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetOptions {
    /// Time-to-live in seconds. If set, applies EX option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Only set the key if it does not already exist (NX).
    #[serde(default)]
    pub nx: bool,
    /// Only set the key if it already exists (XX).
    #[serde(default)]
    pub xx: bool,
}

/// Upstash-style Redis REST API response.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstashResponse {
    /// The result value on success.
    pub result: Option<serde_json::Value>,
    /// The error message on failure.
    pub error: Option<String>,
}

/// Upstash-style Redis REST API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from the Redis API.
    pub error: Option<String>,
}
