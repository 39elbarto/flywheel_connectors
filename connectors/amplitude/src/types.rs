//! `Amplitude` API types.

use serde::{Deserialize, Serialize};

/// Chart query response from `Amplitude`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChartQueryResponse {
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(rename = "xValues")]
    pub x_values: Option<Vec<String>>,
    #[serde(rename = "seriesLabels")]
    pub series_labels: Option<Vec<String>>,
    #[serde(rename = "seriesCollapsed")]
    pub series_collapsed: Option<Vec<Vec<serde_json::Value>>>,
}

/// A cohort entry from `Amplitude`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cohort {
    pub id: String,
    pub name: String,
    #[serde(rename = "appId")]
    pub app_id: Option<i64>,
    pub description: Option<String>,
    #[serde(rename = "lastComputed")]
    pub last_computed: Option<String>,
    #[serde(rename = "lastMod")]
    pub last_mod: Option<String>,
    pub published: Option<bool>,
    pub archived: Option<bool>,
    pub size: Option<i64>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "type")]
    pub cohort_type: Option<String>,
    pub owner: Option<String>,
}

/// Cohorts list response from `Amplitude`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CohortsListResponse {
    #[serde(default)]
    pub cohorts: Vec<serde_json::Value>,
}

/// An exported event from `Amplitude`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedEvent {
    pub event_type: Option<String>,
    pub event_time: Option<String>,
    pub user_id: Option<String>,
    pub device_id: Option<String>,
    pub session_id: Option<i64>,
    pub event_properties: Option<serde_json::Value>,
    pub user_properties: Option<serde_json::Value>,
    pub platform: Option<String>,
    pub os_name: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub ip_address: Option<String>,
    #[serde(rename = "amplitude_id")]
    pub amplitude_id: Option<i64>,
}

/// Events export response from `Amplitude`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventsExportResponse {
    #[serde(default)]
    pub data: Vec<serde_json::Value>,
}

/// `Amplitude` API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
    pub code: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chart_query_response_full() {
        let r: ChartQueryResponse = serde_json::from_value(json!({
            "data": {"series": [[100, 200, 300]]},
            "xValues": ["2025-01-01", "2025-01-02", "2025-01-03"],
            "seriesLabels": ["Active Users"],
            "seriesCollapsed": [[100, 200, 300]]
        }))
        .unwrap();
        assert!(r.data.is_object());
        assert_eq!(r.x_values.as_ref().unwrap().len(), 3);
        assert_eq!(r.series_labels.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn chart_query_response_minimal() {
        let r: ChartQueryResponse = serde_json::from_value(json!({
            "data": {}
        }))
        .unwrap();
        assert!(r.data.is_object());
        assert!(r.x_values.is_none());
        assert!(r.series_labels.is_none());
        assert!(r.series_collapsed.is_none());
    }

    #[test]
    fn chart_query_response_serialize_roundtrip() {
        let original = ChartQueryResponse {
            data: json!({"series": [[1, 2, 3]]}),
            x_values: Some(vec!["day1".into(), "day2".into()]),
            series_labels: Some(vec!["Users".into()]),
            series_collapsed: None,
        };
        let v = serde_json::to_value(&original).unwrap();
        assert_eq!(v["xValues"].as_array().unwrap().len(), 2);
        let back: ChartQueryResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.x_values.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn chart_query_response_with_null_data() {
        let r: ChartQueryResponse = serde_json::from_value(json!({
            "data": null
        }))
        .unwrap();
        assert!(r.data.is_null());
    }

    #[test]
    fn cohort_full() {
        let c: Cohort = serde_json::from_value(json!({
            "id": "coh123",
            "name": "Active Users",
            "appId": 12345,
            "description": "Users active in last 7 days",
            "lastComputed": "2025-06-15T00:00:00Z",
            "lastMod": "2025-06-14T00:00:00Z",
            "published": true,
            "archived": false,
            "size": 50000,
            "createdAt": "2025-01-01T00:00:00Z",
            "type": "behavioral",
            "owner": "user@example.com"
        }))
        .unwrap();
        assert_eq!(c.id, "coh123");
        assert_eq!(c.name, "Active Users");
        assert_eq!(c.app_id, Some(12345));
        assert_eq!(c.description, Some("Users active in last 7 days".into()));
        assert_eq!(c.published, Some(true));
        assert_eq!(c.archived, Some(false));
        assert_eq!(c.size, Some(50000));
        assert_eq!(c.cohort_type, Some("behavioral".into()));
        assert_eq!(c.owner, Some("user@example.com".into()));
    }

    #[test]
    fn cohort_minimal() {
        let c: Cohort = serde_json::from_value(json!({
            "id": "coh1",
            "name": "Test"
        }))
        .unwrap();
        assert_eq!(c.id, "coh1");
        assert_eq!(c.name, "Test");
        assert!(c.app_id.is_none());
        assert!(c.description.is_none());
        assert!(c.size.is_none());
        assert!(c.cohort_type.is_none());
    }

    #[test]
    fn cohort_serialize_roundtrip() {
        let original = Cohort {
            id: "c1".into(),
            name: "Power Users".into(),
            app_id: Some(999),
            description: Some("Top users".into()),
            last_computed: None,
            last_mod: None,
            published: Some(true),
            archived: Some(false),
            size: Some(1000),
            created_at: Some("2025-01-01T00:00:00Z".into()),
            cohort_type: Some("behavioral".into()),
            owner: None,
        };
        let v = serde_json::to_value(&original).unwrap();
        assert_eq!(v["id"], "c1");
        assert_eq!(v["appId"], 999);
        let back: Cohort = serde_json::from_value(v).unwrap();
        assert_eq!(back.id, "c1");
        assert_eq!(back.app_id, Some(999));
    }

    #[test]
    fn cohorts_list_response_roundtrip() {
        let r: CohortsListResponse = serde_json::from_value(json!({
            "cohorts": [
                {"id": "c1", "name": "Active"},
                {"id": "c2", "name": "Churned"}
            ]
        }))
        .unwrap();
        assert_eq!(r.cohorts.len(), 2);
    }

    #[test]
    fn cohorts_list_response_empty() {
        let r: CohortsListResponse = serde_json::from_value(json!({
            "cohorts": []
        }))
        .unwrap();
        assert!(r.cohorts.is_empty());
    }

    #[test]
    fn exported_event_full() {
        let e: ExportedEvent = serde_json::from_value(json!({
            "event_type": "page_view",
            "event_time": "2025-06-15 12:00:00.000",
            "user_id": "user123",
            "device_id": "dev456",
            "session_id": 1718443200000i64,
            "event_properties": {"page": "/home"},
            "user_properties": {"plan": "pro"},
            "platform": "Web",
            "os_name": "macOS",
            "country": "US",
            "city": "San Francisco",
            "region": "California",
            "ip_address": "203.0.113.1",
            "amplitude_id": 9876543210i64
        }))
        .unwrap();
        assert_eq!(e.event_type, Some("page_view".into()));
        assert_eq!(e.user_id, Some("user123".into()));
        assert_eq!(e.platform, Some("Web".into()));
        assert_eq!(e.country, Some("US".into()));
        assert_eq!(e.amplitude_id, Some(9876543210));
    }

    #[test]
    fn exported_event_minimal() {
        let e: ExportedEvent = serde_json::from_value(json!({})).unwrap();
        assert!(e.event_type.is_none());
        assert!(e.user_id.is_none());
        assert!(e.session_id.is_none());
        assert!(e.platform.is_none());
    }

    #[test]
    fn exported_event_serialize_roundtrip() {
        let original = ExportedEvent {
            event_type: Some("click".into()),
            event_time: Some("2025-06-15 12:00:00.000".into()),
            user_id: Some("u1".into()),
            device_id: None,
            session_id: Some(12345),
            event_properties: Some(json!({"button": "signup"})),
            user_properties: None,
            platform: Some("iOS".into()),
            os_name: None,
            country: Some("UK".into()),
            city: None,
            region: None,
            ip_address: None,
            amplitude_id: None,
        };
        let v = serde_json::to_value(&original).unwrap();
        assert_eq!(v["event_type"], "click");
        assert_eq!(v["platform"], "iOS");
        let back: ExportedEvent = serde_json::from_value(v).unwrap();
        assert_eq!(back.event_type, Some("click".into()));
    }

    #[test]
    fn events_export_response_roundtrip() {
        let r: EventsExportResponse = serde_json::from_value(json!({
            "data": [
                {"event_type": "page_view", "user_id": "u1"},
                {"event_type": "click", "user_id": "u2"}
            ]
        }))
        .unwrap();
        assert_eq!(r.data.len(), 2);
    }

    #[test]
    fn events_export_response_empty() {
        let r: EventsExportResponse = serde_json::from_value(json!({
            "data": []
        }))
        .unwrap();
        assert!(r.data.is_empty());
    }

    #[test]
    fn events_export_response_large() {
        let events: Vec<serde_json::Value> = (0..100)
            .map(|i| json!({"event_type": format!("event_{i}"), "user_id": format!("u{i}")}))
            .collect();
        let r: EventsExportResponse = serde_json::from_value(json!({
            "data": events
        }))
        .unwrap();
        assert_eq!(r.data.len(), 100);
    }

    #[test]
    fn api_error_response_with_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Invalid API key",
            "code": 401
        }))
        .unwrap();
        assert_eq!(e.error, Some("Invalid API key".into()));
        assert_eq!(e.code, Some(401));
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Chart not found",
            "code": 404
        }))
        .unwrap();
        assert_eq!(e.message, Some("Chart not found".into()));
        assert_eq!(e.code, Some(404));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
        assert!(e.code.is_none());
    }

    #[test]
    fn api_error_response_both_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Bad Request",
            "message": "Missing required field",
            "code": 400
        }))
        .unwrap();
        assert_eq!(e.error, Some("Bad Request".into()));
        assert_eq!(e.message, Some("Missing required field".into()));
    }

    #[test]
    fn cohort_archived_field() {
        let c: Cohort = serde_json::from_value(json!({
            "id": "c1",
            "name": "Old Cohort",
            "archived": true
        }))
        .unwrap();
        assert_eq!(c.archived, Some(true));
    }

    #[test]
    fn cohort_with_owner() {
        let c: Cohort = serde_json::from_value(json!({
            "id": "c1",
            "name": "Test",
            "owner": "admin@company.com"
        }))
        .unwrap();
        assert_eq!(c.owner, Some("admin@company.com".into()));
    }

    #[test]
    fn exported_event_with_properties() {
        let e: ExportedEvent = serde_json::from_value(json!({
            "event_properties": {"key": "value", "count": 42},
            "user_properties": {"plan": "enterprise", "age": 30}
        }))
        .unwrap();
        let ep = e.event_properties.unwrap();
        assert_eq!(ep["key"], "value");
        assert_eq!(ep["count"], 42);
        let up = e.user_properties.unwrap();
        assert_eq!(up["plan"], "enterprise");
    }

    #[test]
    fn chart_query_response_nested_data() {
        let r: ChartQueryResponse = serde_json::from_value(json!({
            "data": {
                "series": [[100, 200], [300, 400]],
                "seriesLabels": [0, 1],
                "xValues": ["2025-01-01", "2025-01-02"]
            }
        }))
        .unwrap();
        assert!(r.data["series"].is_array());
        assert_eq!(r.data["series"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn cohorts_list_response_serialize() {
        let r = CohortsListResponse {
            cohorts: vec![json!({"id": "c1", "name": "Test"})],
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["cohorts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn events_export_response_serialize() {
        let r = EventsExportResponse {
            data: vec![json!({"event_type": "test"})],
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["data"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn exported_event_geo_fields() {
        let e: ExportedEvent = serde_json::from_value(json!({
            "country": "DE",
            "city": "Berlin",
            "region": "Berlin",
            "ip_address": "192.0.2.1"
        }))
        .unwrap();
        assert_eq!(e.country, Some("DE".into()));
        assert_eq!(e.city, Some("Berlin".into()));
        assert_eq!(e.region, Some("Berlin".into()));
        assert_eq!(e.ip_address, Some("192.0.2.1".into()));
    }

    #[test]
    fn cohort_last_timestamps() {
        let c: Cohort = serde_json::from_value(json!({
            "id": "c1",
            "name": "Test",
            "lastComputed": "2025-06-01T00:00:00Z",
            "lastMod": "2025-06-02T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(c.last_computed, Some("2025-06-01T00:00:00Z".into()));
        assert_eq!(c.last_mod, Some("2025-06-02T00:00:00Z".into()));
    }

    // -- Additional ChartQueryResponse tests --

    #[test]
    fn chart_query_response_debug_format() {
        let r = ChartQueryResponse {
            data: json!({}),
            x_values: None,
            series_labels: None,
            series_collapsed: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ChartQueryResponse"));
    }

    #[test]
    fn chart_query_response_clone() {
        let r = ChartQueryResponse {
            data: json!({"series": [[1, 2]]}),
            x_values: Some(vec!["d1".into()]),
            series_labels: Some(vec!["Users".into()]),
            series_collapsed: Some(vec![vec![json!(1)]]),
        };
        let cloned = r.clone();
        // Use original after clone
        assert!(r.data.is_object());
        assert_eq!(cloned.x_values.as_ref().unwrap().len(), 1);
        assert_eq!(cloned.series_labels.as_ref().unwrap()[0], "Users");
    }

    #[test]
    fn chart_query_response_with_array_data() {
        let r: ChartQueryResponse = serde_json::from_value(json!({
            "data": [1, 2, 3]
        }))
        .unwrap();
        assert!(r.data.is_array());
    }

    // -- Additional Cohort tests --

    #[test]
    fn cohort_debug_format() {
        let c = Cohort {
            id: "c1".into(),
            name: "Test".into(),
            app_id: None,
            description: None,
            last_computed: None,
            last_mod: None,
            published: None,
            archived: None,
            size: None,
            created_at: None,
            cohort_type: None,
            owner: None,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Cohort"));
        assert!(dbg.contains("c1"));
    }

    #[test]
    fn cohort_clone() {
        let c = Cohort {
            id: "c1".into(),
            name: "Power Users".into(),
            app_id: Some(42),
            description: Some("desc".into()),
            last_computed: None,
            last_mod: None,
            published: Some(true),
            archived: Some(false),
            size: Some(100),
            created_at: None,
            cohort_type: Some("behavioral".into()),
            owner: Some("admin".into()),
        };
        let cloned = c.clone();
        // Use original after clone
        assert_eq!(c.id, "c1");
        assert_eq!(cloned.id, "c1");
        assert_eq!(cloned.app_id, Some(42));
        assert_eq!(cloned.cohort_type, Some("behavioral".into()));
    }

    #[test]
    fn cohort_json_string_roundtrip() {
        let c = Cohort {
            id: "c1".into(),
            name: "Test".into(),
            app_id: Some(1),
            description: None,
            last_computed: None,
            last_mod: None,
            published: None,
            archived: None,
            size: Some(50),
            created_at: None,
            cohort_type: None,
            owner: None,
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: Cohort = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, "c1");
        assert_eq!(back.size, Some(50));
    }

    // -- Additional ExportedEvent tests --

    #[test]
    fn exported_event_debug_format() {
        let e = ExportedEvent {
            event_type: Some("click".into()),
            event_time: None,
            user_id: None,
            device_id: None,
            session_id: None,
            event_properties: None,
            user_properties: None,
            platform: None,
            os_name: None,
            country: None,
            city: None,
            region: None,
            ip_address: None,
            amplitude_id: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ExportedEvent"));
        assert!(dbg.contains("click"));
    }

    #[test]
    fn exported_event_clone() {
        let e = ExportedEvent {
            event_type: Some("test".into()),
            event_time: Some("2025-01-01".into()),
            user_id: Some("u1".into()),
            device_id: Some("d1".into()),
            session_id: Some(100),
            event_properties: Some(json!({"k": "v"})),
            user_properties: None,
            platform: Some("Web".into()),
            os_name: Some("macOS".into()),
            country: Some("US".into()),
            city: Some("SF".into()),
            region: Some("CA".into()),
            ip_address: Some("1.2.3.4".into()),
            amplitude_id: Some(999),
        };
        let cloned = e.clone();
        // Use original after clone
        assert_eq!(e.event_type, Some("test".into()));
        assert_eq!(cloned.event_type, Some("test".into()));
        assert_eq!(cloned.amplitude_id, Some(999));
    }

    #[test]
    fn exported_event_with_os_name() {
        let e: ExportedEvent = serde_json::from_value(json!({
            "os_name": "Windows"
        }))
        .unwrap();
        assert_eq!(e.os_name, Some("Windows".into()));
    }

    #[test]
    fn exported_event_with_device_id() {
        let e: ExportedEvent = serde_json::from_value(json!({
            "device_id": "device_abc_123"
        }))
        .unwrap();
        assert_eq!(e.device_id, Some("device_abc_123".into()));
    }

    // -- Additional ApiErrorResponse tests --

    #[test]
    fn api_error_response_debug_format() {
        let e = ApiErrorResponse {
            error: Some("test".into()),
            message: None,
            code: Some(500),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            error: Some("err".into()),
            message: Some("msg".into()),
            code: Some(400),
        };
        let cloned = e.clone();
        // Use original after clone
        assert_eq!(e.code, Some(400));
        assert_eq!(cloned.error, Some("err".into()));
        assert_eq!(cloned.message, Some("msg".into()));
        assert_eq!(cloned.code, Some(400));
    }

    #[test]
    fn api_error_response_only_code() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"code": 503})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
        assert_eq!(e.code, Some(503));
    }

    // -- CohortsListResponse additional --

    #[test]
    fn cohorts_list_response_debug() {
        let r = CohortsListResponse { cohorts: vec![] };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CohortsListResponse"));
    }

    #[test]
    fn cohorts_list_response_clone() {
        let r = CohortsListResponse {
            cohorts: vec![json!({"id": "c1"})],
        };
        let cloned = r.clone();
        // Use original after clone
        assert_eq!(r.cohorts.len(), 1);
        assert_eq!(cloned.cohorts.len(), 1);
    }

    // -- EventsExportResponse additional --

    #[test]
    fn events_export_response_debug() {
        let r = EventsExportResponse { data: vec![] };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("EventsExportResponse"));
    }

    #[test]
    fn events_export_response_clone() {
        let r = EventsExportResponse {
            data: vec![json!({"event_type": "test"})],
        };
        let cloned = r.clone();
        // Use original after clone
        assert_eq!(r.data.len(), 1);
        assert_eq!(cloned.data.len(), 1);
    }
}
