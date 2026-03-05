//! Segment API types.

use serde::{Deserialize, Serialize};

/// A Segment source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub name: Option<String>,
    pub slug: Option<String>,
    pub enabled: Option<bool>,
}

/// A Segment destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    pub id: String,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub connection_mode: Option<String>,
}

/// A Segment track event request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackEvent {
    pub user_id: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

/// Response from a Segment track call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackResponse {
    pub success: bool,
}

/// Segment API error response body.
///
/// Segment returns `{"error": {"message": "...", "code": "..."}}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error object.
    pub error: Option<ApiError>,
}

/// Inner error detail from a Segment API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    /// The error message.
    pub message: Option<String>,
    /// The error code.
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn source_roundtrip() {
        let s: Source = serde_json::from_value(json!({
            "id": "src_abc123",
            "name": "Website",
            "slug": "website",
            "enabled": true,
        }))
        .unwrap();
        assert_eq!(s.id, "src_abc123");
        assert_eq!(s.name, Some("Website".into()));
        assert_eq!(s.slug, Some("website".into()));
        assert_eq!(s.enabled, Some(true));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "Website");
    }

    #[test]
    fn source_minimal() {
        let s: Source = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(s.id, "x");
        assert!(s.name.is_none());
        assert!(s.slug.is_none());
        assert!(s.enabled.is_none());
    }

    #[test]
    fn source_extra_fields_ignored() {
        let s: Source = serde_json::from_value(json!({
            "id": "s1",
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(s.id, "s1");
        assert_eq!(s.name, Some("Test".into()));
    }

    #[test]
    fn destination_roundtrip() {
        let d: Destination = serde_json::from_value(json!({
            "id": "dst_abc123",
            "name": "Google Analytics",
            "enabled": true,
            "connection_mode": "cloud",
        }))
        .unwrap();
        assert_eq!(d.id, "dst_abc123");
        assert_eq!(d.name, Some("Google Analytics".into()));
        assert_eq!(d.enabled, Some(true));
        assert_eq!(d.connection_mode, Some("cloud".into()));
        let re = serde_json::to_value(&d).unwrap();
        assert_eq!(re["name"], "Google Analytics");
    }

    #[test]
    fn destination_minimal() {
        let d: Destination = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(d.id, "x");
        assert!(d.name.is_none());
        assert!(d.enabled.is_none());
        assert!(d.connection_mode.is_none());
    }

    #[test]
    fn destination_extra_fields_ignored() {
        let d: Destination = serde_json::from_value(json!({
            "id": "d1",
            "name": "Test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(d.id, "d1");
        assert_eq!(d.name, Some("Test".into()));
    }

    #[test]
    fn track_event_roundtrip() {
        let t: TrackEvent = serde_json::from_value(json!({
            "user_id": "user_123",
            "event": "Item Purchased",
            "properties": {"price": 9.99, "item": "Widget"},
        }))
        .unwrap();
        assert_eq!(t.user_id, "user_123");
        assert_eq!(t.event, "Item Purchased");
        assert!(t.properties.is_some());
        let props = t.properties.unwrap();
        assert_eq!(props["price"], 9.99);
        assert_eq!(props["item"], "Widget");
    }

    #[test]
    fn track_event_minimal() {
        let t: TrackEvent = serde_json::from_value(json!({
            "user_id": "u1",
            "event": "click",
        }))
        .unwrap();
        assert_eq!(t.user_id, "u1");
        assert_eq!(t.event, "click");
        assert!(t.properties.is_none());
    }

    #[test]
    fn track_event_serialize_skips_none_properties() {
        let t = TrackEvent {
            user_id: "u1".into(),
            event: "click".into(),
            properties: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["user_id"], "u1");
        assert_eq!(v["event"], "click");
        assert!(v.get("properties").is_none());
    }

    #[test]
    fn track_event_serialize_includes_properties() {
        let t = TrackEvent {
            user_id: "u1".into(),
            event: "click".into(),
            properties: Some(json!({"key": "value"})),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["properties"]["key"], "value");
    }

    #[test]
    fn track_response_roundtrip() {
        let r: TrackResponse = serde_json::from_value(json!({"success": true})).unwrap();
        assert!(r.success);
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["success"], true);
    }

    #[test]
    fn track_response_false() {
        let r: TrackResponse = serde_json::from_value(json!({"success": false})).unwrap();
        assert!(!r.success);
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {
                "message": "Unauthorized",
                "code": "AUTH_FAILED",
            }
        }))
        .unwrap();
        let err = e.error.unwrap();
        assert_eq!(err.message, Some("Unauthorized".into()));
        assert_eq!(err.code, Some("AUTH_FAILED".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_error_only_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {
                "message": "Rate limit exceeded",
            }
        }))
        .unwrap();
        let err = e.error.unwrap();
        assert_eq!(err.message, Some("Rate limit exceeded".into()));
        assert!(err.code.is_none());
    }

    #[test]
    fn api_error_empty_inner() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {}
        }))
        .unwrap();
        let err = e.error.unwrap();
        assert!(err.message.is_none());
        assert!(err.code.is_none());
    }

    #[test]
    fn source_serialize_roundtrip() {
        let s = Source {
            id: "s1".into(),
            name: Some("My Source".into()),
            slug: None,
            enabled: Some(false),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["id"], "s1");
        assert_eq!(v["name"], "My Source");
        assert_eq!(v["enabled"], false);
    }

    #[test]
    fn destination_serialize_roundtrip() {
        let d = Destination {
            id: "d1".into(),
            name: Some("Amplitude".into()),
            enabled: None,
            connection_mode: Some("device".into()),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["id"], "d1");
        assert_eq!(v["name"], "Amplitude");
        assert_eq!(v["connection_mode"], "device");
    }
}
