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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn set_options_defaults_do_not_apply_ttl_or_conditions() {
        let options = SetOptions::default();

        assert_eq!(options.ttl_seconds, None);
        assert!(!options.nx);
        assert!(!options.xx);
    }

    #[test]
    fn set_options_deserializes_ttl_and_exclusive_condition() {
        let options: SetOptions = serde_json::from_value(json!({
            "ttl_seconds": 60,
            "nx": true
        }))
        .expect("valid set options should deserialize");

        assert_eq!(options.ttl_seconds, Some(60));
        assert!(options.nx);
        assert!(!options.xx);
    }

    #[test]
    fn set_options_serializes_absent_ttl_without_null() {
        let value = serde_json::to_value(SetOptions {
            ttl_seconds: None,
            nx: false,
            xx: true,
        })
        .expect("set options should serialize");

        assert_eq!(value, json!({"nx": false, "xx": true}));
    }

    #[test]
    fn upstash_response_decodes_result_without_error() {
        let response: UpstashResponse = serde_json::from_value(json!({
            "result": ["alpha", "beta"],
            "error": null
        }))
        .expect("success envelope should deserialize");

        assert_eq!(response.result, Some(json!(["alpha", "beta"])));
        assert!(response.error.is_none());
    }

    #[test]
    fn api_error_response_treats_missing_error_as_none() {
        let response: ApiErrorResponse =
            serde_json::from_value(json!({})).expect("empty error envelope should deserialize");

        assert!(response.error.is_none());
    }
}
