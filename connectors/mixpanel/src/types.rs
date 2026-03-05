//! Mixpanel API types.

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

/// A Mixpanel funnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Funnel {
    pub funnel_id: u64,
    pub name: Option<String>,
}

/// An Mixpanel event query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQueryResult {
    pub data: Option<serde_json::Value>,
    pub computed_at: Option<String>,
}

/// An Mixpanel insights query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightsQueryResult {
    pub data: Option<serde_json::Value>,
    pub computed_at: Option<String>,
}

/// Mixpanel API error response body.
///
/// Mixpanel returns `{"error": "message"}` or `{"message": "..."}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message.
    pub error: Option<String>,
    /// Alternative message field.
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn funnel_roundtrip() {
        let f: Funnel = serde_json::from_value(json!({
            "funnel_id": 12345,
            "name": "Signup Funnel",
        }))
        .unwrap();
        assert_eq!(f.funnel_id, 12345);
        assert_eq!(f.name, Some("Signup Funnel".into()));
        let re = serde_json::to_value(&f).unwrap();
        assert_eq!(re["name"], "Signup Funnel");
    }

    #[test]
    fn funnel_minimal() {
        let f: Funnel = serde_json::from_value(json!({"funnel_id": 1})).unwrap();
        assert_eq!(f.funnel_id, 1);
        assert!(f.name.is_none());
    }

    #[test]
    fn event_query_result_roundtrip() {
        let e: EventQueryResult = serde_json::from_value(json!({
            "data": {"values": {"signup": {"2025-01-01": 100}}},
            "computed_at": "2025-01-02T00:00:00Z",
        }))
        .unwrap();
        assert!(e.data.is_some());
        assert_eq!(e.computed_at, Some("2025-01-02T00:00:00Z".into()));
    }

    #[test]
    fn event_query_result_minimal() {
        let e: EventQueryResult = serde_json::from_value(json!({})).unwrap();
        assert!(e.data.is_none());
        assert!(e.computed_at.is_none());
    }

    #[test]
    fn insights_query_result_roundtrip() {
        let i: InsightsQueryResult = serde_json::from_value(json!({
            "data": {"series": [1, 2, 3]},
            "computed_at": "2025-01-15T12:00:00Z",
        }))
        .unwrap();
        assert!(i.data.is_some());
        assert_eq!(i.computed_at, Some("2025-01-15T12:00:00Z".into()));
    }

    #[test]
    fn insights_query_result_minimal() {
        let i: InsightsQueryResult = serde_json::from_value(json!({})).unwrap();
        assert!(i.data.is_none());
        assert!(i.computed_at.is_none());
    }

    #[test]
    fn api_error_response_with_error_field() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Invalid date range",
        }))
        .unwrap();
        assert_eq!(e.error, Some("Invalid date range".into()));
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_with_message_field() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Unauthorized",
        }))
        .unwrap();
        assert!(e.error.is_none());
        assert_eq!(e.message, Some("Unauthorized".into()));
    }

    #[test]
    fn api_error_response_with_both_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Bad Request",
            "message": "Invalid query",
        }))
        .unwrap();
        assert_eq!(e.error, Some("Bad Request".into()));
        assert_eq!(e.message, Some("Invalid query".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn funnel_extra_fields_ignored() {
        let f: Funnel = serde_json::from_value(json!({
            "funnel_id": 42,
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(f.funnel_id, 42);
        assert_eq!(f.name, Some("Test".into()));
    }

    #[test]
    fn event_query_result_extra_fields_ignored() {
        let e: EventQueryResult = serde_json::from_value(json!({
            "data": {},
            "extra": true,
        }))
        .unwrap();
        assert!(e.data.is_some());
    }

    #[test]
    fn insights_query_result_extra_fields_ignored() {
        let i: InsightsQueryResult = serde_json::from_value(json!({
            "data": {},
            "extra": true,
        }))
        .unwrap();
        assert!(i.data.is_some());
    }

    #[test]
    fn funnel_serialize_roundtrip() {
        let f = Funnel {
            funnel_id: 999,
            name: Some("Onboarding".into()),
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["funnel_id"], 999);
        assert_eq!(v["name"], "Onboarding");
    }
}
