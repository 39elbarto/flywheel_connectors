//! Datadog API types.

use serde::{Deserialize, Serialize};

/// A Datadog event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Option<i64>,
    pub title: Option<String>,
    pub text: Option<String>,
    pub date_happened: Option<i64>,
    pub priority: Option<String>,
    pub alert_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub host: Option<String>,
    pub source: Option<String>,
    pub url: Option<String>,
}

/// Wrapper for event creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventCreateResponse {
    pub event: Option<Event>,
    pub status: Option<String>,
}

/// Wrapper for event list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventListResponse {
    #[serde(default)]
    pub events: Vec<Event>,
}

/// A time-series data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub metric: Option<String>,
    #[serde(default)]
    pub pointlist: Vec<Vec<f64>>,
    pub scope: Option<String>,
    pub expression: Option<String>,
    pub unit: Option<serde_json::Value>,
    pub display_name: Option<String>,
    #[serde(rename = "tag_set")]
    pub tag_set: Option<Vec<String>>,
}

/// Response from metrics query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsQueryResponse {
    pub status: Option<String>,
    #[serde(default)]
    pub series: Vec<MetricSeries>,
    pub from_date: Option<i64>,
    pub to_date: Option<i64>,
    pub query: Option<String>,
    pub group_by: Option<Vec<String>>,
}

/// A metric series for submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSubmitSeries {
    pub metric: String,
    #[serde(default)]
    pub points: Vec<Vec<f64>>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub host: Option<String>,
}

/// Response from metric submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSubmitResponse {
    pub status: Option<String>,
}

/// A Datadog monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Monitor {
    pub id: Option<i64>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub monitor_type: Option<String>,
    pub query: Option<String>,
    pub message: Option<String>,
    pub overall_state: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub creator: Option<serde_json::Value>,
    pub options: Option<serde_json::Value>,
}

/// A log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: Option<String>,
    pub content: Option<LogContent>,
}

/// Log content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogContent {
    pub timestamp: Option<String>,
    pub message: Option<String>,
    pub host: Option<String>,
    pub service: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub attributes: Option<serde_json::Value>,
}

/// Response from log search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSearchResponse {
    #[serde(default)]
    pub logs: Vec<LogEntry>,
    pub next_log_id: Option<String>,
    pub status: Option<String>,
}

/// Datadog API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default)]
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_roundtrip() {
        let e: Event = serde_json::from_value(json!({
            "id": 12345,
            "title": "Deploy v2.0",
            "text": "Deployed to production",
            "date_happened": 1709251200,
            "priority": "normal",
            "alert_type": "info",
            "tags": ["env:production", "service:api"],
            "host": "web-01",
            "source": "deploy"
        }))
        .unwrap();
        assert_eq!(e.id, Some(12345));
        assert_eq!(e.title.as_deref(), Some("Deploy v2.0"));
        assert_eq!(e.tags.len(), 2);
        let re = serde_json::to_value(&e).unwrap();
        assert_eq!(re["host"], "web-01");
    }

    #[test]
    fn event_minimal() {
        let e: Event = serde_json::from_value(json!({})).unwrap();
        assert!(e.id.is_none());
        assert!(e.title.is_none());
        assert!(e.tags.is_empty());
    }

    #[test]
    fn event_create_response_deserialization() {
        let r: EventCreateResponse = serde_json::from_value(json!({
            "event": {"id": 1, "title": "test"},
            "status": "ok"
        }))
        .unwrap();
        assert_eq!(r.status.as_deref(), Some("ok"));
        assert!(r.event.is_some());
    }

    #[test]
    fn event_list_response_deserialization() {
        let r: EventListResponse = serde_json::from_value(json!({
            "events": [
                {"id": 1, "title": "e1"},
                {"id": 2, "title": "e2"},
            ]
        }))
        .unwrap();
        assert_eq!(r.events.len(), 2);
    }

    #[test]
    fn metric_series_deserialization() {
        let s: MetricSeries = serde_json::from_value(json!({
            "metric": "system.cpu.user",
            "pointlist": [[1709251200000.0, 42.5], [1709251260000.0, 43.0]],
            "scope": "host:web-01",
            "display_name": "CPU User",
            "tag_set": ["env:prod"]
        }))
        .unwrap();
        assert_eq!(s.metric.as_deref(), Some("system.cpu.user"));
        assert_eq!(s.pointlist.len(), 2);
        assert_eq!(s.tag_set.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn metrics_query_response_deserialization() {
        let r: MetricsQueryResponse = serde_json::from_value(json!({
            "status": "ok",
            "series": [
                {"metric": "cpu", "pointlist": [[1.0, 2.0]]}
            ],
            "from_date": 1709251200,
            "to_date": 1709337600,
            "query": "avg:system.cpu.user{*}"
        }))
        .unwrap();
        assert_eq!(r.status.as_deref(), Some("ok"));
        assert_eq!(r.series.len(), 1);
    }

    #[test]
    fn metric_submit_series_roundtrip() {
        let s: MetricSubmitSeries = serde_json::from_value(json!({
            "metric": "custom.latency",
            "points": [[1709251200.0, 42.0]],
            "type": "gauge",
            "tags": ["env:staging"]
        }))
        .unwrap();
        assert_eq!(s.metric, "custom.latency");
        assert_eq!(s.metric_type.as_deref(), Some("gauge"));
        assert_eq!(s.points.len(), 1);
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["type"], "gauge");
    }

    #[test]
    fn metric_submit_response() {
        let r: MetricSubmitResponse =
            serde_json::from_value(json!({"status": "ok"})).unwrap();
        assert_eq!(r.status.as_deref(), Some("ok"));
    }

    #[test]
    fn monitor_full_deserialization() {
        let m: Monitor = serde_json::from_value(json!({
            "id": 12345,
            "name": "High CPU",
            "type": "metric alert",
            "query": "avg(last_5m):avg:system.cpu.user{*} > 90",
            "message": "CPU is high @pagerduty",
            "overall_state": "OK",
            "tags": ["env:production"],
            "created": "2026-01-01T00:00:00+00:00",
            "modified": "2026-03-01T00:00:00+00:00",
        }))
        .unwrap();
        assert_eq!(m.id, Some(12345));
        assert_eq!(m.name.as_deref(), Some("High CPU"));
        assert_eq!(m.monitor_type.as_deref(), Some("metric alert"));
        assert_eq!(m.overall_state.as_deref(), Some("OK"));
        assert_eq!(m.tags.len(), 1);
    }

    #[test]
    fn monitor_minimal() {
        let m: Monitor = serde_json::from_value(json!({})).unwrap();
        assert!(m.id.is_none());
        assert!(m.name.is_none());
        assert!(m.tags.is_empty());
    }

    #[test]
    fn log_entry_deserialization() {
        let l: LogEntry = serde_json::from_value(json!({
            "id": "abc123",
            "content": {
                "timestamp": "2026-03-01T00:00:00Z",
                "message": "Error processing request",
                "host": "web-01",
                "service": "api",
                "status": "error",
                "tags": ["env:production"],
                "attributes": {"http.method": "GET"}
            }
        }))
        .unwrap();
        assert_eq!(l.id.as_deref(), Some("abc123"));
        let content = l.content.unwrap();
        assert_eq!(content.service.as_deref(), Some("api"));
        assert_eq!(content.status.as_deref(), Some("error"));
        assert_eq!(content.tags.len(), 1);
    }

    #[test]
    fn log_search_response_deserialization() {
        let r: LogSearchResponse = serde_json::from_value(json!({
            "logs": [
                {"id": "1", "content": {"message": "m1"}},
                {"id": "2", "content": {"message": "m2"}},
            ],
            "next_log_id": "cursor-abc",
            "status": "done"
        }))
        .unwrap();
        assert_eq!(r.logs.len(), 2);
        assert_eq!(r.next_log_id.as_deref(), Some("cursor-abc"));
    }

    #[test]
    fn api_error_response_with_errors() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"errors": ["Bad Request", "Invalid query"]})).unwrap();
        assert_eq!(e.errors.len(), 2);
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.errors.is_empty());
    }
}
