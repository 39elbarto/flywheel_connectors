//! `PostHog` API types.

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

/// A `PostHog` event row from HogQL query results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub event: Option<String>,
    pub timestamp: Option<String>,
    pub distinct_id: Option<String>,
    pub properties: Option<serde_json::Value>,
}

/// A `PostHog` insight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Insight {
    pub id: Option<u64>,
    pub short_id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub filters: Option<serde_json::Value>,
    pub last_refresh: Option<String>,
    pub created_at: Option<String>,
}

/// A `PostHog` feature flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    pub id: Option<u64>,
    pub key: Option<String>,
    pub name: Option<String>,
    pub active: Option<bool>,
    pub filters: Option<serde_json::Value>,
    pub created_at: Option<String>,
    pub rollout_percentage: Option<f64>,
}

/// `PostHog` API error response body.
///
/// PostHog returns `{"type": "...", "code": "...", "detail": "message", "attr": ...}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error detail message from PostHog.
    pub detail: Option<String>,
    /// The error type (e.g., `"authentication_error"`).
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    /// The error code.
    pub code: Option<String>,
    /// Optional attribute name that caused the error.
    pub attr: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_row_roundtrip() {
        let e: EventRow = serde_json::from_value(json!({
            "event": "$pageview",
            "timestamp": "2026-03-05T12:00:00Z",
            "distinct_id": "user_123",
            "properties": {"$browser": "Chrome"},
        }))
        .unwrap();
        assert_eq!(e.event, Some("$pageview".into()));
        assert_eq!(e.timestamp, Some("2026-03-05T12:00:00Z".into()));
        assert_eq!(e.distinct_id, Some("user_123".into()));
        assert!(e.properties.is_some());
        let re = serde_json::to_value(&e).unwrap();
        assert_eq!(re["event"], "$pageview");
    }

    #[test]
    fn event_row_minimal() {
        let e: EventRow = serde_json::from_value(json!({})).unwrap();
        assert!(e.event.is_none());
        assert!(e.timestamp.is_none());
        assert!(e.distinct_id.is_none());
        assert!(e.properties.is_none());
    }

    #[test]
    fn insight_roundtrip() {
        let i: Insight = serde_json::from_value(json!({
            "id": 42,
            "short_id": "abc123",
            "name": "Weekly Active Users",
            "description": "Track WAU over time",
            "filters": {"events": [{"id": "$pageview"}]},
            "last_refresh": "2026-03-05T10:00:00Z",
            "created_at": "2026-01-01T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(i.id, Some(42));
        assert_eq!(i.short_id, Some("abc123".into()));
        assert_eq!(i.name, Some("Weekly Active Users".into()));
        assert_eq!(i.description, Some("Track WAU over time".into()));
        assert!(i.filters.is_some());
        assert_eq!(i.last_refresh, Some("2026-03-05T10:00:00Z".into()));
        let re = serde_json::to_value(&i).unwrap();
        assert_eq!(re["name"], "Weekly Active Users");
    }

    #[test]
    fn insight_minimal() {
        let i: Insight = serde_json::from_value(json!({})).unwrap();
        assert!(i.id.is_none());
        assert!(i.short_id.is_none());
        assert!(i.name.is_none());
        assert!(i.description.is_none());
        assert!(i.filters.is_none());
    }

    #[test]
    fn feature_flag_roundtrip() {
        let f: FeatureFlag = serde_json::from_value(json!({
            "id": 7,
            "key": "new-dashboard",
            "name": "New Dashboard Feature",
            "active": true,
            "filters": {"groups": [{"rollout_percentage": 50}]},
            "created_at": "2026-02-15T08:00:00Z",
            "rollout_percentage": 50.0,
        }))
        .unwrap();
        assert_eq!(f.id, Some(7));
        assert_eq!(f.key, Some("new-dashboard".into()));
        assert_eq!(f.name, Some("New Dashboard Feature".into()));
        assert_eq!(f.active, Some(true));
        assert!(f.filters.is_some());
        assert_eq!(f.rollout_percentage, Some(50.0));
        let re = serde_json::to_value(&f).unwrap();
        assert_eq!(re["key"], "new-dashboard");
    }

    #[test]
    fn feature_flag_minimal() {
        let f: FeatureFlag = serde_json::from_value(json!({})).unwrap();
        assert!(f.id.is_none());
        assert!(f.key.is_none());
        assert!(f.name.is_none());
        assert!(f.active.is_none());
        assert!(f.rollout_percentage.is_none());
    }

    #[test]
    fn feature_flag_inactive() {
        let f: FeatureFlag = serde_json::from_value(json!({
            "id": 3,
            "key": "old-feature",
            "active": false,
        }))
        .unwrap();
        assert_eq!(f.active, Some(false));
    }

    #[test]
    fn feature_flag_serialize_roundtrip() {
        let f = FeatureFlag {
            id: Some(1),
            key: Some("beta-feature".into()),
            name: Some("Beta Feature".into()),
            active: Some(true),
            filters: None,
            created_at: None,
            rollout_percentage: Some(25.0),
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["id"], 1);
        assert_eq!(v["key"], "beta-feature");
        assert_eq!(v["rollout_percentage"], 25.0);
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "authentication_error",
            "code": "not_authenticated",
            "detail": "Authentication credentials were not provided.",
            "attr": null,
        }))
        .unwrap();
        assert_eq!(
            e.detail,
            Some("Authentication credentials were not provided.".into())
        );
        assert_eq!(e.error_type, Some("authentication_error".into()));
        assert_eq!(e.code, Some("not_authenticated".into()));
        assert!(e.attr.is_none());
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.detail.is_none());
        assert!(e.error_type.is_none());
        assert!(e.code.is_none());
        assert!(e.attr.is_none());
    }

    #[test]
    fn api_error_response_detail_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "detail": "Not found.",
        }))
        .unwrap();
        assert_eq!(e.detail, Some("Not found.".into()));
        assert!(e.error_type.is_none());
    }

    #[test]
    fn event_row_extra_fields_ignored() {
        let e: EventRow = serde_json::from_value(json!({
            "event": "$pageview",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(e.event, Some("$pageview".into()));
    }

    #[test]
    fn insight_extra_fields_ignored() {
        let i: Insight = serde_json::from_value(json!({
            "id": 1,
            "name": "Test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(i.id, Some(1));
        assert_eq!(i.name, Some("Test".into()));
    }

    #[test]
    fn feature_flag_extra_fields_ignored() {
        let f: FeatureFlag = serde_json::from_value(json!({
            "id": 1,
            "key": "test",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(f.id, Some(1));
        assert_eq!(f.key, Some("test".into()));
    }

    // -- Additional types tests --

    #[test]
    fn event_row_clone() {
        let e: EventRow = serde_json::from_value(json!({
            "event": "$pageview",
            "distinct_id": "user1"
        }))
        .unwrap();
        let cloned = e.clone();
        assert_eq!(e.event, Some("$pageview".into()));
        assert_eq!(cloned.distinct_id, Some("user1".into()));
    }

    #[test]
    fn event_row_debug() {
        let e: EventRow = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EventRow"));
    }

    #[test]
    fn event_row_serialize_with_properties() {
        let e = EventRow {
            event: Some("$click".into()),
            timestamp: Some("2026-01-01T00:00:00Z".into()),
            distinct_id: Some("uid".into()),
            properties: Some(json!({"$browser": "Firefox", "page": "/home"})),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event"], "$click");
        assert_eq!(v["properties"]["$browser"], "Firefox");
    }

    #[test]
    fn event_row_null_properties() {
        let e: EventRow = serde_json::from_value(json!({
            "event": "test",
            "properties": null
        }))
        .unwrap();
        assert!(e.properties.is_none());
    }

    #[test]
    fn insight_clone() {
        let i: Insight = serde_json::from_value(json!({
            "id": 10,
            "name": "Test"
        }))
        .unwrap();
        let cloned = i.clone();
        assert_eq!(i.id, Some(10));
        assert_eq!(cloned.name, Some("Test".into()));
    }

    #[test]
    fn insight_debug() {
        let i: Insight = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{i:?}");
        assert!(dbg.contains("Insight"));
    }

    #[test]
    fn insight_serialize_roundtrip() {
        let i = Insight {
            id: Some(99),
            short_id: Some("xyz".into()),
            name: Some("My Insight".into()),
            description: None,
            filters: Some(json!({"events": []})),
            last_refresh: None,
            created_at: Some("2026-01-01".into()),
        };
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["id"], 99);
        assert_eq!(v["short_id"], "xyz");
        assert!(v["description"].is_null());
    }

    #[test]
    fn feature_flag_clone() {
        let f: FeatureFlag = serde_json::from_value(json!({
            "id": 5,
            "key": "beta"
        }))
        .unwrap();
        let cloned = f.clone();
        assert_eq!(f.id, Some(5));
        assert_eq!(cloned.key, Some("beta".into()));
    }

    #[test]
    fn feature_flag_debug() {
        let f: FeatureFlag = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("FeatureFlag"));
    }

    #[test]
    fn feature_flag_rollout_zero() {
        let f: FeatureFlag = serde_json::from_value(json!({
            "rollout_percentage": 0.0
        }))
        .unwrap();
        assert_eq!(f.rollout_percentage, Some(0.0));
    }

    #[test]
    fn feature_flag_rollout_hundred() {
        let f: FeatureFlag = serde_json::from_value(json!({
            "rollout_percentage": 100.0
        }))
        .unwrap();
        assert_eq!(f.rollout_percentage, Some(100.0));
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "detail": "err",
            "type": "validation_error"
        }))
        .unwrap();
        let cloned = e.clone();
        assert_eq!(e.detail, Some("err".into()));
        assert_eq!(cloned.error_type, Some("validation_error".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_with_attr() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "attr": "email",
            "detail": "Invalid email"
        }))
        .unwrap();
        assert_eq!(e.attr, Some("email".into()));
    }

    #[test]
    fn api_error_response_with_code() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "code": "permission_denied",
            "detail": "You do not have permission"
        }))
        .unwrap();
        assert_eq!(e.code, Some("permission_denied".into()));
    }

    #[test]
    fn event_row_all_none_serializes() {
        let e = EventRow {
            event: None,
            timestamp: None,
            distinct_id: None,
            properties: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert!(v["event"].is_null());
        assert!(v["timestamp"].is_null());
    }

    #[test]
    fn insight_all_none_serializes() {
        let i = Insight {
            id: None,
            short_id: None,
            name: None,
            description: None,
            filters: None,
            last_refresh: None,
            created_at: None,
        };
        let v = serde_json::to_value(&i).unwrap();
        assert!(v["id"].is_null());
    }

    #[test]
    fn feature_flag_all_none_serializes() {
        let f = FeatureFlag {
            id: None,
            key: None,
            name: None,
            active: None,
            filters: None,
            created_at: None,
            rollout_percentage: None,
        };
        let v = serde_json::to_value(&f).unwrap();
        assert!(v["id"].is_null());
        assert!(v["key"].is_null());
    }

    #[test]
    fn event_row_properties_complex_object() {
        let e: EventRow = serde_json::from_value(json!({
            "event": "$identify",
            "properties": {
                "$set": {"email": "test@example.com"},
                "$set_once": {"first_seen": "2026-01-01"},
                "nested": {"deeply": {"value": 42}}
            }
        }))
        .unwrap();
        let props = e.properties.unwrap();
        assert_eq!(props["$set"]["email"], "test@example.com");
        assert_eq!(props["nested"]["deeply"]["value"], 42);
    }

    #[test]
    fn event_row_properties_array() {
        let e: EventRow = serde_json::from_value(json!({
            "event": "$autocapture",
            "properties": [1, 2, 3]
        }))
        .unwrap();
        let props = e.properties.unwrap();
        assert!(props.is_array());
        assert_eq!(props.as_array().unwrap().len(), 3);
    }

    #[test]
    fn insight_filters_complex_structure() {
        let i: Insight = serde_json::from_value(json!({
            "id": 100,
            "filters": {
                "events": [
                    {"id": "$pageview", "type": "events"},
                    {"id": "$identify", "type": "events"}
                ],
                "display": "ActionsLineGraph",
                "interval": "week"
            }
        }))
        .unwrap();
        let filters = i.filters.unwrap();
        assert_eq!(filters["events"].as_array().unwrap().len(), 2);
        assert_eq!(filters["display"], "ActionsLineGraph");
    }

    #[test]
    fn feature_flag_filters_with_groups() {
        let f: FeatureFlag = serde_json::from_value(json!({
            "id": 50,
            "key": "multi-group-flag",
            "filters": {
                "groups": [
                    {"properties": [{"key": "country", "value": "US"}], "rollout_percentage": 75},
                    {"properties": [{"key": "plan", "value": "pro"}], "rollout_percentage": 100}
                ]
            }
        }))
        .unwrap();
        let filters = f.filters.unwrap();
        assert_eq!(filters["groups"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn api_error_response_all_fields_present() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "validation_error",
            "code": "invalid_input",
            "detail": "Field 'email' is required",
            "attr": "email"
        }))
        .unwrap();
        assert_eq!(e.error_type, Some("validation_error".into()));
        assert_eq!(e.code, Some("invalid_input".into()));
        assert_eq!(e.detail, Some("Field 'email' is required".into()));
        assert_eq!(e.attr, Some("email".into()));
    }

    #[test]
    fn event_row_roundtrip_preserves_all_fields() {
        let original = EventRow {
            event: Some("$screen".into()),
            timestamp: Some("2026-06-15T09:30:00Z".into()),
            distinct_id: Some("device_abc".into()),
            properties: Some(json!({"$screen_name": "Dashboard"})),
        };
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: EventRow = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.event, Some("$screen".into()));
        assert_eq!(deserialized.timestamp, Some("2026-06-15T09:30:00Z".into()));
        assert_eq!(deserialized.distinct_id, Some("device_abc".into()));
        assert_eq!(
            deserialized.properties.unwrap()["$screen_name"],
            "Dashboard"
        );
    }

    #[test]
    fn insight_large_id() {
        let i: Insight = serde_json::from_value(json!({
            "id": 999_999_999,
            "short_id": "zzz999"
        }))
        .unwrap();
        assert_eq!(i.id, Some(999_999_999));
        assert_eq!(i.short_id, Some("zzz999".into()));
    }
}
