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
        let r: MetricSubmitResponse = serde_json::from_value(json!({"status": "ok"})).unwrap();
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

    // ── Clone / Debug trait tests ─────────────────────────────────

    #[test]
    fn event_clone() {
        let e = Event {
            id: Some(1),
            title: Some("t".into()),
            text: None,
            date_happened: None,
            priority: None,
            alert_type: None,
            tags: vec!["a".into()],
            host: None,
            source: None,
            url: None,
        };
        let cloned = e.clone();
        assert_eq!(e.id, Some(1));
        assert_eq!(cloned.id, Some(1));
        assert_eq!(cloned.tags.len(), 1);
    }

    #[test]
    fn event_debug() {
        let e: Event = serde_json::from_value(json!({"title": "test"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Event"));
        assert!(dbg.contains("test"));
    }

    #[test]
    fn monitor_clone_and_debug() {
        let m: Monitor = serde_json::from_value(json!({
            "id": 99,
            "name": "Test Monitor",
        }))
        .unwrap();
        let cloned = m.clone();
        assert_eq!(m.id, Some(99));
        assert_eq!(cloned.id, Some(99));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("Monitor"));
        assert!(dbg.contains("Test Monitor"));
    }

    #[test]
    fn log_content_clone_and_debug() {
        let c: LogContent = serde_json::from_value(json!({
            "message": "hello",
            "service": "api",
        }))
        .unwrap();
        let cloned = c.clone();
        assert_eq!(c.service.as_deref(), Some("api"));
        assert_eq!(cloned.message.as_deref(), Some("hello"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("LogContent"));
    }

    #[test]
    fn metric_series_clone_and_debug() {
        let s: MetricSeries = serde_json::from_value(json!({
            "metric": "test.metric",
            "pointlist": [[1.0, 2.0]],
        }))
        .unwrap();
        let cloned = s.clone();
        assert_eq!(s.pointlist.len(), 1);
        assert_eq!(cloned.metric.as_deref(), Some("test.metric"));
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("MetricSeries"));
    }

    // ── Default vec behavior ──────────────────────────────────────

    #[test]
    fn event_tags_default_empty() {
        let e: Event = serde_json::from_value(json!({"title": "no tags"})).unwrap();
        assert!(e.tags.is_empty());
    }

    #[test]
    fn event_list_response_events_default_empty() {
        let r: EventListResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.events.is_empty());
    }

    #[test]
    fn metrics_query_response_series_default_empty() {
        let r: MetricsQueryResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.series.is_empty());
    }

    #[test]
    fn metric_submit_series_points_default_empty() {
        let s: MetricSubmitSeries = serde_json::from_value(json!({"metric": "m"})).unwrap();
        assert!(s.points.is_empty());
        assert!(s.tags.is_empty());
    }

    #[test]
    fn monitor_tags_default_empty() {
        let m: Monitor = serde_json::from_value(json!({})).unwrap();
        assert!(m.tags.is_empty());
    }

    #[test]
    fn log_content_tags_default_empty() {
        let c: LogContent = serde_json::from_value(json!({})).unwrap();
        assert!(c.tags.is_empty());
    }

    #[test]
    fn log_search_response_logs_default_empty() {
        let r: LogSearchResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.logs.is_empty());
    }

    // ── Serialize roundtrips ──────────────────────────────────────

    #[test]
    fn event_create_response_roundtrip() {
        let r = EventCreateResponse {
            event: Some(Event {
                id: Some(10),
                title: Some("ev".into()),
                text: None,
                date_happened: None,
                priority: None,
                alert_type: None,
                tags: vec![],
                host: None,
                source: None,
                url: None,
            }),
            status: Some("ok".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["event"]["id"], 10);
        let back: EventCreateResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.status.as_deref(), Some("ok"));
    }

    #[test]
    fn log_search_response_roundtrip() {
        let r = LogSearchResponse {
            logs: vec![LogEntry {
                id: Some("log1".into()),
                content: Some(LogContent {
                    timestamp: None,
                    message: Some("msg".into()),
                    host: None,
                    service: None,
                    status: None,
                    tags: vec![],
                    attributes: None,
                }),
            }],
            next_log_id: Some("cursor".into()),
            status: Some("done".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["logs"][0]["id"], "log1");
        assert_eq!(v["next_log_id"], "cursor");
    }

    #[test]
    fn metric_submit_response_roundtrip() {
        let r = MetricSubmitResponse {
            status: Some("ok".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        let back: MetricSubmitResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.status.as_deref(), Some("ok"));
    }

    #[test]
    fn metrics_query_response_roundtrip() {
        let r = MetricsQueryResponse {
            status: Some("ok".into()),
            series: vec![],
            from_date: Some(1000),
            to_date: Some(2000),
            query: Some("avg:cpu{*}".into()),
            group_by: Some(vec!["host".into()]),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["query"], "avg:cpu{*}");
        let back: MetricsQueryResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.from_date, Some(1000));
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn event_with_null_fields() {
        let e: Event = serde_json::from_value(json!({
            "id": null,
            "title": null,
            "text": null,
        }))
        .unwrap();
        assert!(e.id.is_none());
        assert!(e.title.is_none());
    }

    #[test]
    fn monitor_with_options_json() {
        let m: Monitor = serde_json::from_value(json!({
            "id": 1,
            "options": {"thresholds": {"critical": 90.0}},
            "creator": {"name": "admin", "email": "a@b.com"},
        }))
        .unwrap();
        assert!(m.options.is_some());
        assert!(m.creator.is_some());
    }

    #[test]
    fn api_error_response_single_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"errors": ["one"]})).unwrap();
        assert_eq!(e.errors.len(), 1);
        assert_eq!(e.errors[0], "one");
    }

    #[test]
    fn log_entry_minimal() {
        let l: LogEntry = serde_json::from_value(json!({})).unwrap();
        assert!(l.id.is_none());
        assert!(l.content.is_none());
    }

    #[test]
    fn metric_series_minimal() {
        let s: MetricSeries = serde_json::from_value(json!({})).unwrap();
        assert!(s.metric.is_none());
        assert!(s.pointlist.is_empty());
        assert!(s.tag_set.is_none());
    }

    #[test]
    fn metric_submit_series_type_rename() {
        let s = MetricSubmitSeries {
            metric: "test".into(),
            points: vec![],
            metric_type: Some("count".into()),
            tags: vec![],
            host: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        // The field is serialized as "type", not "metric_type"
        assert_eq!(v["type"], "count");
        assert!(v.get("metric_type").is_none());
    }

    #[test]
    fn monitor_type_rename() {
        let m: Monitor = serde_json::from_value(json!({
            "type": "metric alert"
        }))
        .unwrap();
        assert_eq!(m.monitor_type.as_deref(), Some("metric alert"));
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["type"], "metric alert");
    }

    #[test]
    fn metric_series_tag_set_rename() {
        let s: MetricSeries = serde_json::from_value(json!({
            "tag_set": ["env:prod", "region:us"]
        }))
        .unwrap();
        assert_eq!(s.tag_set.as_ref().unwrap().len(), 2);
    }

    // ── Additional serde / edge-case tests ──────────────────────

    #[test]
    fn event_with_all_fields() {
        let e = Event {
            id: Some(42),
            title: Some("title".into()),
            text: Some("body text".into()),
            date_happened: Some(1000),
            priority: Some("low".into()),
            alert_type: Some("warning".into()),
            tags: vec!["a".into(), "b".into()],
            host: Some("host-1".into()),
            source: Some("src".into()),
            url: Some("https://example.com".into()),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["id"], 42);
        assert_eq!(v["url"], "https://example.com");
        assert_eq!(v["tags"].as_array().unwrap().len(), 2);
        let back: Event = serde_json::from_value(v).unwrap();
        assert_eq!(back.priority.as_deref(), Some("low"));
    }

    #[test]
    fn event_create_response_without_event() {
        let r: EventCreateResponse = serde_json::from_value(json!({
            "status": "accepted"
        }))
        .unwrap();
        assert!(r.event.is_none());
        assert_eq!(r.status.as_deref(), Some("accepted"));
    }

    #[test]
    fn event_list_response_with_many_events() {
        let r: EventListResponse = serde_json::from_value(json!({
            "events": [
                {"id": 1},
                {"id": 2},
                {"id": 3},
                {"id": 4},
                {"id": 5},
            ]
        }))
        .unwrap();
        assert_eq!(r.events.len(), 5);
    }

    #[test]
    fn metric_series_with_expression() {
        let s: MetricSeries = serde_json::from_value(json!({
            "metric": "cpu",
            "expression": "avg:system.cpu{*}",
            "pointlist": [[1.0, 50.0]],
        }))
        .unwrap();
        assert_eq!(s.expression.as_deref(), Some("avg:system.cpu{*}"));
    }

    #[test]
    fn metric_series_with_unit() {
        let s: MetricSeries = serde_json::from_value(json!({
            "metric": "mem",
            "pointlist": [],
            "unit": [{"name": "byte"}, null],
        }))
        .unwrap();
        assert!(s.unit.is_some());
    }

    #[test]
    fn metric_submit_series_with_host() {
        let s = MetricSubmitSeries {
            metric: "custom.req".into(),
            points: vec![vec![1.0, 100.0]],
            metric_type: Some("rate".into()),
            tags: vec!["service:web".into()],
            host: Some("web-01".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["host"], "web-01");
        assert_eq!(v["type"], "rate");
    }

    #[test]
    fn monitor_with_all_optional_fields() {
        let m = Monitor {
            id: Some(10),
            name: Some("Mon".into()),
            monitor_type: Some("service check".into()),
            query: Some("\"ntp.in_sync\".over(\"*\")".into()),
            message: Some("NTP desync @ops".into()),
            overall_state: Some("Alert".into()),
            tags: vec!["team:infra".into()],
            created: Some("2026-01-01".into()),
            modified: Some("2026-03-01".into()),
            creator: Some(json!({"name": "admin"})),
            options: Some(json!({"notify_no_data": true})),
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["type"], "service check");
        assert_eq!(v["tags"][0], "team:infra");
        let back: Monitor = serde_json::from_value(v).unwrap();
        assert_eq!(back.overall_state.as_deref(), Some("Alert"));
    }

    #[test]
    fn log_content_with_attributes() {
        let c: LogContent = serde_json::from_value(json!({
            "timestamp": "2026-03-01T00:00:00Z",
            "message": "request completed",
            "host": "api-01",
            "service": "backend",
            "status": "info",
            "tags": ["env:staging"],
            "attributes": {"http.status_code": 200, "http.method": "POST"}
        }))
        .unwrap();
        assert_eq!(c.host.as_deref(), Some("api-01"));
        assert!(c.attributes.is_some());
        let attrs = c.attributes.unwrap();
        assert_eq!(attrs["http.status_code"], 200);
    }

    #[test]
    fn log_entry_clone_and_debug() {
        let l = LogEntry {
            id: Some("log-abc".into()),
            content: Some(LogContent {
                timestamp: None,
                message: Some("test".into()),
                host: None,
                service: None,
                status: None,
                tags: vec![],
                attributes: None,
            }),
        };
        let cloned = l.clone();
        assert_eq!(l.id.as_deref(), Some("log-abc"));
        assert_eq!(cloned.id.as_deref(), Some("log-abc"));
        let dbg = format!("{l:?}");
        assert!(dbg.contains("LogEntry"));
    }

    #[test]
    fn api_error_response_debug_format() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"errors": ["err1"]})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
        assert!(dbg.contains("err1"));
    }
}
