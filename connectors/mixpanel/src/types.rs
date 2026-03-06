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

    #[test]
    fn funnel_clone() {
        let f = Funnel {
            funnel_id: 42,
            name: Some("Clone Test".into()),
        };
        let f2 = f.clone();
        assert_eq!(f.funnel_id, f2.funnel_id);
        assert_eq!(f.name, f2.name);
    }

    #[test]
    fn funnel_debug() {
        let f = Funnel {
            funnel_id: 1,
            name: None,
        };
        let dbg = format!("{f:?}");
        assert!(dbg.contains("Funnel"));
        assert!(dbg.contains("funnel_id"));
    }

    #[test]
    fn funnel_name_none_serializes_as_null() {
        let f = Funnel {
            funnel_id: 10,
            name: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert!(v["name"].is_null());
    }

    #[test]
    fn funnel_large_id() {
        let f: Funnel =
            serde_json::from_value(json!({"funnel_id": 9999999999u64})).unwrap();
        assert_eq!(f.funnel_id, 9999999999);
    }

    #[test]
    fn event_query_result_clone() {
        let e = EventQueryResult {
            data: Some(json!({"key": "value"})),
            computed_at: Some("2025-01-01T00:00:00Z".into()),
        };
        let e2 = e.clone();
        assert_eq!(e.data, e2.data);
        assert_eq!(e.computed_at, e2.computed_at);
    }

    #[test]
    fn event_query_result_debug() {
        let e = EventQueryResult {
            data: None,
            computed_at: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EventQueryResult"));
    }

    #[test]
    fn event_query_result_serialize_with_null_data() {
        let e = EventQueryResult {
            data: None,
            computed_at: Some("2025-06-01".into()),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert!(v["data"].is_null());
        assert_eq!(v["computed_at"], "2025-06-01");
    }

    #[test]
    fn insights_query_result_clone() {
        let i = InsightsQueryResult {
            data: Some(json!([1, 2, 3])),
            computed_at: None,
        };
        let i2 = i.clone();
        assert_eq!(i.data, i2.data);
    }

    #[test]
    fn insights_query_result_debug() {
        let i = InsightsQueryResult {
            data: None,
            computed_at: None,
        };
        let dbg = format!("{i:?}");
        assert!(dbg.contains("InsightsQueryResult"));
    }

    #[test]
    fn insights_query_result_data_nested() {
        let i: InsightsQueryResult = serde_json::from_value(json!({
            "data": {"series": [{"date": "2025-01-01", "value": 100}]},
            "computed_at": "2025-01-02",
        }))
        .unwrap();
        assert!(i.data.unwrap()["series"].is_array());
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            error: Some("err".into()),
            message: Some("msg".into()),
        };
        let e2 = e.clone();
        assert_eq!(e.error, e2.error);
        assert_eq!(e.message, e2.message);
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            error: None,
            message: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn funnel_json_string_roundtrip() {
        let f = Funnel {
            funnel_id: 55,
            name: Some("String Test".into()),
        };
        let s = serde_json::to_string(&f).unwrap();
        let f2: Funnel = serde_json::from_str(&s).unwrap();
        assert_eq!(f2.funnel_id, 55);
        assert_eq!(f2.name, Some("String Test".into()));
    }

    #[test]
    fn event_query_result_json_string_roundtrip() {
        let e = EventQueryResult {
            data: Some(json!({"x": 1})),
            computed_at: Some("ts".into()),
        };
        let s = serde_json::to_string(&e).unwrap();
        let e2: EventQueryResult = serde_json::from_str(&s).unwrap();
        assert_eq!(e2.computed_at, Some("ts".into()));
    }

    #[test]
    fn insights_query_result_json_string_roundtrip() {
        let i = InsightsQueryResult {
            data: Some(json!({"metric": 42})),
            computed_at: Some("2025-06-01".into()),
        };
        let s = serde_json::to_string(&i).unwrap();
        let i2: InsightsQueryResult = serde_json::from_str(&s).unwrap();
        assert!(i2.data.is_some());
        assert_eq!(i2.computed_at, Some("2025-06-01".into()));
    }

    #[test]
    fn api_error_response_extra_fields_ignored() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Bad Request",
            "message": "Invalid",
            "details": "extra info",
        }))
        .unwrap();
        assert_eq!(e.error, Some("Bad Request".into()));
        assert_eq!(e.message, Some("Invalid".into()));
    }

    #[test]
    fn funnel_zero_id() {
        let f: Funnel = serde_json::from_value(json!({"funnel_id": 0})).unwrap();
        assert_eq!(f.funnel_id, 0);
    }
}
