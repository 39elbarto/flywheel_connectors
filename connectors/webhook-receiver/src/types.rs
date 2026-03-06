//! Webhook Receiver types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A registered webhook endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Unique identifier for this endpoint.
    pub endpoint_id: String,
    /// URL path this endpoint listens on.
    pub path: String,
    /// HMAC signing secret for payload verification.
    pub signing_secret: String,
    /// Optional IP CIDR ranges allowed to send webhooks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_sources: Vec<String>,
    /// Full URL where this endpoint is reachable.
    pub url: String,
    /// When this endpoint was created.
    pub created_at: DateTime<Utc>,
    /// Whether this endpoint is currently active.
    pub active: bool,
}

impl WebhookEndpoint {
    /// Create a new webhook endpoint with a generated ID.
    pub fn new(path: String, signing_secret: String, allowed_sources: Vec<String>) -> Self {
        let endpoint_id = format!("ep_{}", Uuid::new_v4());
        let url = format!("http://localhost:8080{path}");
        Self {
            endpoint_id,
            path,
            signing_secret,
            allowed_sources,
            url,
            created_at: Utc::now(),
            active: true,
        }
    }
}

/// A received webhook event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Unique event identifier.
    pub event_id: String,
    /// The endpoint that received this event.
    pub endpoint_id: String,
    /// When the event was received.
    pub received_at: DateTime<Utc>,
    /// HTTP headers from the webhook request (selected).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub headers: std::collections::HashMap<String, String>,
    /// The raw payload body.
    pub payload: serde_json::Value,
    /// Whether the signature was valid.
    pub signature_valid: bool,
    /// Source IP address if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}

impl WebhookEvent {
    /// Create a new webhook event with a generated ID.
    pub fn new(
        endpoint_id: String,
        payload: serde_json::Value,
        signature_valid: bool,
        source_ip: Option<String>,
    ) -> Self {
        Self {
            event_id: format!("evt_{}", Uuid::new_v4()),
            endpoint_id,
            received_at: Utc::now(),
            headers: std::collections::HashMap::new(),
            payload,
            signature_valid,
            source_ip,
        }
    }
}

/// Summary of an endpoint for list operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub endpoint_id: String,
    pub path: String,
    pub url: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub event_count: usize,
}

impl EndpointSummary {
    /// Create a summary from an endpoint and its event count.
    pub fn from_endpoint(ep: &WebhookEndpoint, event_count: usize) -> Self {
        Self {
            endpoint_id: ep.endpoint_id.clone(),
            path: ep.path.clone(),
            url: ep.url.clone(),
            active: ep.active,
            created_at: ep.created_at,
            event_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn endpoint_new_generates_uuid() {
        let ep = WebhookEndpoint::new(
            "/hooks/github".into(),
            "whsec_abc123".into(),
            vec![],
        );
        assert!(ep.endpoint_id.starts_with("ep_"));
        assert_eq!(ep.path, "/hooks/github");
        assert_eq!(ep.signing_secret, "whsec_abc123");
        assert!(ep.url.contains("/hooks/github"));
        assert!(ep.active);
        assert!(ep.allowed_sources.is_empty());
    }

    #[test]
    fn endpoint_new_with_allowed_sources() {
        let ep = WebhookEndpoint::new(
            "/hooks/stripe".into(),
            "whsec_xyz".into(),
            vec!["10.0.0.0/8".into()],
        );
        assert_eq!(ep.allowed_sources.len(), 1);
        assert_eq!(ep.allowed_sources[0], "10.0.0.0/8");
    }

    #[test]
    fn endpoint_ids_are_unique() {
        let a = WebhookEndpoint::new("/a".into(), "s".into(), vec![]);
        let b = WebhookEndpoint::new("/b".into(), "s".into(), vec![]);
        assert_ne!(a.endpoint_id, b.endpoint_id);
    }

    #[test]
    fn endpoint_serialization_roundtrip() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "secret".into(), vec![]);
        let json = serde_json::to_value(&ep).unwrap();
        assert_eq!(json["path"], "/hooks/test");
        assert_eq!(json["active"], true);
        let deser: WebhookEndpoint = serde_json::from_value(json).unwrap();
        assert_eq!(deser.endpoint_id, ep.endpoint_id);
        assert_eq!(deser.path, ep.path);
    }

    #[test]
    fn endpoint_url_format() {
        let ep = WebhookEndpoint::new("/webhooks/v1".into(), "s".into(), vec![]);
        assert_eq!(ep.url, "http://localhost:8080/webhooks/v1");
    }

    #[test]
    fn endpoint_skips_empty_allowed_sources() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let json = serde_json::to_value(&ep).unwrap();
        assert!(json.get("allowed_sources").is_none());
    }

    #[test]
    fn endpoint_includes_nonempty_allowed_sources() {
        let ep = WebhookEndpoint::new(
            "/hooks/test".into(),
            "s".into(),
            vec!["192.168.0.0/16".into()],
        );
        let json = serde_json::to_value(&ep).unwrap();
        assert!(json.get("allowed_sources").is_some());
        assert_eq!(json["allowed_sources"][0], "192.168.0.0/16");
    }

    #[test]
    fn event_new_generates_uuid() {
        let evt = WebhookEvent::new(
            "ep_abc".into(),
            json!({"type": "push"}),
            true,
            Some("1.2.3.4".into()),
        );
        assert!(evt.event_id.starts_with("evt_"));
        assert_eq!(evt.endpoint_id, "ep_abc");
        assert_eq!(evt.payload["type"], "push");
        assert!(evt.signature_valid);
        assert_eq!(evt.source_ip, Some("1.2.3.4".into()));
    }

    #[test]
    fn event_new_no_source_ip() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), false, None);
        assert!(evt.source_ip.is_none());
        assert!(!evt.signature_valid);
    }

    #[test]
    fn event_ids_are_unique() {
        let a = WebhookEvent::new("ep_1".into(), json!({}), true, None);
        let b = WebhookEvent::new("ep_1".into(), json!({}), true, None);
        assert_ne!(a.event_id, b.event_id);
    }

    #[test]
    fn event_serialization_roundtrip() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({"key": "value"}), true, None);
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["endpoint_id"], "ep_abc");
        assert_eq!(json["payload"]["key"], "value");
        assert_eq!(json["signature_valid"], true);
        let deser: WebhookEvent = serde_json::from_value(json).unwrap();
        assert_eq!(deser.event_id, evt.event_id);
    }

    #[test]
    fn event_skips_null_source_ip() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), true, None);
        let json = serde_json::to_value(&evt).unwrap();
        assert!(json.get("source_ip").is_none());
    }

    #[test]
    fn event_includes_source_ip_when_present() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), true, Some("10.0.0.1".into()));
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["source_ip"], "10.0.0.1");
    }

    #[test]
    fn event_skips_empty_headers() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), true, None);
        let json = serde_json::to_value(&evt).unwrap();
        assert!(json.get("headers").is_none());
    }

    #[test]
    fn event_with_headers() {
        let mut evt = WebhookEvent::new("ep_abc".into(), json!({}), true, None);
        evt.headers
            .insert("content-type".into(), "application/json".into());
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["headers"]["content-type"], "application/json");
    }

    #[test]
    fn endpoint_summary_from_endpoint() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 42);
        assert_eq!(summary.endpoint_id, ep.endpoint_id);
        assert_eq!(summary.path, "/hooks/test");
        assert_eq!(summary.url, ep.url);
        assert!(summary.active);
        assert_eq!(summary.event_count, 42);
    }

    #[test]
    fn endpoint_summary_serialization() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 10);
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["event_count"], 10);
        assert_eq!(json["active"], true);
        let deser: EndpointSummary = serde_json::from_value(json).unwrap();
        assert_eq!(deser.event_count, 10);
    }

    #[test]
    fn endpoint_summary_zero_events() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 0);
        assert_eq!(summary.event_count, 0);
    }

    #[test]
    fn endpoint_deserialization_from_json() {
        let json = json!({
            "endpoint_id": "ep_test",
            "path": "/hooks/github",
            "signing_secret": "secret123",
            "url": "http://localhost:8080/hooks/github",
            "created_at": "2026-01-15T10:30:00Z",
            "active": true,
        });
        let ep: WebhookEndpoint = serde_json::from_value(json).unwrap();
        assert_eq!(ep.endpoint_id, "ep_test");
        assert_eq!(ep.path, "/hooks/github");
        assert_eq!(ep.signing_secret, "secret123");
        assert!(ep.allowed_sources.is_empty());
    }

    #[test]
    fn event_deserialization_from_json() {
        let json = json!({
            "event_id": "evt_test",
            "endpoint_id": "ep_abc",
            "received_at": "2026-01-15T10:30:00Z",
            "payload": {"action": "created"},
            "signature_valid": true,
        });
        let evt: WebhookEvent = serde_json::from_value(json).unwrap();
        assert_eq!(evt.event_id, "evt_test");
        assert_eq!(evt.endpoint_id, "ep_abc");
        assert_eq!(evt.payload["action"], "created");
    }

    #[test]
    fn endpoint_debug_format() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let dbg = format!("{ep:?}");
        assert!(dbg.contains("WebhookEndpoint"));
        assert!(dbg.contains("/hooks/test"));
    }

    #[test]
    fn event_debug_format() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), true, None);
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("WebhookEvent"));
        assert!(dbg.contains("ep_abc"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn endpoint_clone() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "secret".into(), vec!["10.0.0.0/8".into()]);
        let cloned = ep.clone();
        assert_eq!(cloned.endpoint_id, ep.endpoint_id);
        assert_eq!(cloned.path, "/hooks/test");
        assert_eq!(cloned.signing_secret, "secret");
        assert_eq!(cloned.allowed_sources.len(), 1);
        assert!(cloned.active);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn event_clone() {
        let evt = WebhookEvent::new("ep_1".into(), json!({"key": "val"}), true, Some("1.2.3.4".into()));
        let cloned = evt.clone();
        assert_eq!(cloned.event_id, evt.event_id);
        assert_eq!(cloned.endpoint_id, "ep_1");
        assert_eq!(cloned.payload["key"], "val");
        assert!(cloned.signature_valid);
        assert_eq!(cloned.source_ip, Some("1.2.3.4".into()));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn endpoint_summary_clone() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 5);
        let cloned = summary.clone();
        assert_eq!(cloned.endpoint_id, summary.endpoint_id);
        assert_eq!(cloned.event_count, 5);
    }

    #[test]
    fn endpoint_summary_debug() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 0);
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("EndpointSummary"));
    }

    #[test]
    fn endpoint_with_multiple_allowed_sources() {
        let ep = WebhookEndpoint::new(
            "/hooks/multi".into(),
            "s".into(),
            vec!["10.0.0.0/8".into(), "172.16.0.0/12".into(), "192.168.0.0/16".into()],
        );
        assert_eq!(ep.allowed_sources.len(), 3);
        let json = serde_json::to_value(&ep).unwrap();
        assert_eq!(json["allowed_sources"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn endpoint_deserialization_with_allowed_sources() {
        let json = json!({
            "endpoint_id": "ep_test",
            "path": "/hooks/github",
            "signing_secret": "secret123",
            "allowed_sources": ["10.0.0.0/8", "192.168.0.0/16"],
            "url": "http://localhost:8080/hooks/github",
            "created_at": "2026-01-15T10:30:00Z",
            "active": true,
        });
        let ep: WebhookEndpoint = serde_json::from_value(json).unwrap();
        assert_eq!(ep.allowed_sources.len(), 2);
        assert_eq!(ep.allowed_sources[0], "10.0.0.0/8");
    }

    #[test]
    fn endpoint_inactive_deserialization() {
        let json = json!({
            "endpoint_id": "ep_test",
            "path": "/hooks/test",
            "signing_secret": "s",
            "url": "http://localhost:8080/hooks/test",
            "created_at": "2026-01-15T10:30:00Z",
            "active": false,
        });
        let ep: WebhookEndpoint = serde_json::from_value(json).unwrap();
        assert!(!ep.active);
    }

    #[test]
    fn event_with_complex_payload() {
        let payload = json!({
            "action": "push",
            "repository": {"id": 123, "name": "my-repo"},
            "commits": [{"sha": "abc123"}, {"sha": "def456"}],
        });
        let evt = WebhookEvent::new("ep_1".into(), payload, true, None);
        assert_eq!(evt.payload["action"], "push");
        assert_eq!(evt.payload["commits"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn event_with_null_payload() {
        let evt = WebhookEvent::new("ep_1".into(), json!(null), true, None);
        assert!(evt.payload.is_null());
    }

    #[test]
    fn event_with_array_payload() {
        let evt = WebhookEvent::new("ep_1".into(), json!([1, 2, 3]), true, None);
        assert!(evt.payload.is_array());
        assert_eq!(evt.payload.as_array().unwrap().len(), 3);
    }

    #[test]
    fn event_serialization_with_headers() {
        let mut evt = WebhookEvent::new("ep_1".into(), json!({"x": 1}), true, Some("10.0.0.1".into()));
        evt.headers.insert("content-type".into(), "application/json".into());
        evt.headers.insert("x-hub-signature".into(), "sha256=abc".into());
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["headers"]["content-type"], "application/json");
        assert_eq!(json["headers"]["x-hub-signature"], "sha256=abc");
        assert_eq!(json["source_ip"], "10.0.0.1");
    }

    #[test]
    fn event_deserialization_with_headers() {
        let json = json!({
            "event_id": "evt_test",
            "endpoint_id": "ep_abc",
            "received_at": "2026-01-15T10:30:00Z",
            "headers": {"content-type": "application/json"},
            "payload": {},
            "signature_valid": true,
            "source_ip": "192.168.1.1",
        });
        let evt: WebhookEvent = serde_json::from_value(json).unwrap();
        assert_eq!(evt.headers.get("content-type").unwrap(), "application/json");
        assert_eq!(evt.source_ip, Some("192.168.1.1".into()));
    }

    #[test]
    fn endpoint_json_string_roundtrip() {
        let ep = WebhookEndpoint::new("/hooks/stripe".into(), "whsec_xyz".into(), vec!["1.2.3.4/32".into()]);
        let s = serde_json::to_string(&ep).unwrap();
        let ep2: WebhookEndpoint = serde_json::from_str(&s).unwrap();
        assert_eq!(ep2.endpoint_id, ep.endpoint_id);
        assert_eq!(ep2.path, "/hooks/stripe");
        assert_eq!(ep2.signing_secret, "whsec_xyz");
        assert_eq!(ep2.allowed_sources.len(), 1);
    }

    #[test]
    fn event_json_string_roundtrip() {
        let evt = WebhookEvent::new("ep_test".into(), json!({"key": "val"}), false, Some("10.0.0.1".into()));
        let s = serde_json::to_string(&evt).unwrap();
        let evt2: WebhookEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(evt2.event_id, evt.event_id);
        assert_eq!(evt2.endpoint_id, "ep_test");
        assert!(!evt2.signature_valid);
        assert_eq!(evt2.source_ip, Some("10.0.0.1".into()));
    }

    #[test]
    fn endpoint_summary_json_string_roundtrip() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 42);
        let s = serde_json::to_string(&summary).unwrap();
        let summary2: EndpointSummary = serde_json::from_str(&s).unwrap();
        assert_eq!(summary2.event_count, 42);
        assert_eq!(summary2.path, "/hooks/test");
    }

    #[test]
    fn endpoint_summary_preserves_url() {
        let ep = WebhookEndpoint::new("/api/webhooks".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 0);
        assert_eq!(summary.url, "http://localhost:8080/api/webhooks");
    }

    #[test]
    fn endpoint_summary_preserves_created_at() {
        let ep = WebhookEndpoint::new("/hooks/test".into(), "s".into(), vec![]);
        let summary = EndpointSummary::from_endpoint(&ep, 0);
        assert_eq!(summary.created_at, ep.created_at);
    }

    #[test]
    fn event_empty_headers_default() {
        let evt = WebhookEvent::new("ep_1".into(), json!({}), true, None);
        assert!(evt.headers.is_empty());
    }
}
