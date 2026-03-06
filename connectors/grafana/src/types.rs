//! Grafana API types.

use serde::{Deserialize, Serialize};

/// A Grafana dashboard search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSearchResult {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub title: Option<String>,
    pub uri: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "type")]
    pub result_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(rename = "isStarred")]
    pub is_starred: Option<bool>,
    #[serde(rename = "folderId")]
    pub folder_id: Option<i64>,
    #[serde(rename = "folderUid")]
    pub folder_uid: Option<String>,
    #[serde(rename = "folderTitle")]
    pub folder_title: Option<String>,
    #[serde(rename = "folderUrl")]
    pub folder_url: Option<String>,
}

/// Full dashboard response from GET.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardFullResponse {
    pub dashboard: Option<serde_json::Value>,
    pub meta: Option<DashboardMeta>,
}

/// Dashboard metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMeta {
    #[serde(rename = "isStarred")]
    pub is_starred: Option<bool>,
    pub slug: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "folderId")]
    pub folder_id: Option<i64>,
    #[serde(rename = "folderUid")]
    pub folder_uid: Option<String>,
    #[serde(rename = "folderTitle")]
    pub folder_title: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    #[serde(rename = "createdBy")]
    pub created_by: Option<String>,
    #[serde(rename = "updatedBy")]
    pub updated_by: Option<String>,
    pub version: Option<i64>,
}

/// Dashboard save response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSaveResponse {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub url: Option<String>,
    pub status: Option<String>,
    pub version: Option<i64>,
    pub slug: Option<String>,
}

/// A Grafana datasource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Datasource {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub datasource_type: Option<String>,
    pub url: Option<String>,
    pub access: Option<String>,
    #[serde(rename = "isDefault")]
    pub is_default: Option<bool>,
    pub database: Option<String>,
    #[serde(rename = "readOnly")]
    pub read_only: Option<bool>,
}

/// Datasource query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasourceQueryResponse {
    pub results: Option<serde_json::Value>,
}

/// A Grafana alert rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: Option<i64>,
    pub uid: Option<String>,
    pub title: Option<String>,
    pub condition: Option<String>,
    #[serde(default)]
    pub data: Vec<serde_json::Value>,
    #[serde(rename = "ruleGroup")]
    pub rule_group: Option<String>,
    #[serde(rename = "folderUID")]
    pub folder_uid: Option<String>,
    #[serde(rename = "noDataState")]
    pub no_data_state: Option<String>,
    #[serde(rename = "execErrState")]
    pub exec_err_state: Option<String>,
    #[serde(rename = "for")]
    pub for_duration: Option<String>,
    #[serde(default)]
    pub labels: serde_json::Value,
    #[serde(default)]
    pub annotations: serde_json::Value,
}

/// An annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: Option<i64>,
    #[serde(rename = "dashboardId")]
    pub dashboard_id: Option<i64>,
    #[serde(rename = "dashboardUID")]
    pub dashboard_uid: Option<String>,
    #[serde(rename = "panelId")]
    pub panel_id: Option<i64>,
    pub text: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub time: Option<i64>,
    #[serde(rename = "timeEnd")]
    pub time_end: Option<i64>,
    pub created: Option<i64>,
    pub updated: Option<i64>,
}

/// Annotation create response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationCreateResponse {
    pub id: Option<i64>,
    pub message: Option<String>,
}

/// Grafana API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dashboard_search_result_roundtrip() {
        let d: DashboardSearchResult = serde_json::from_value(json!({
            "id": 1, "uid": "abc", "title": "My Dashboard",
            "type": "dash-db", "tags": ["prod"], "isStarred": true,
            "folderId": 5, "folderUid": "folder-1", "folderTitle": "General"
        }))
        .unwrap();
        assert_eq!(d.uid.as_deref(), Some("abc"));
        assert_eq!(d.result_type.as_deref(), Some("dash-db"));
        assert!(d.is_starred.unwrap());
        assert_eq!(d.tags.len(), 1);
    }

    #[test]
    fn dashboard_search_result_minimal() {
        let d: DashboardSearchResult = serde_json::from_value(json!({})).unwrap();
        assert!(d.id.is_none());
        assert!(d.tags.is_empty());
    }

    #[test]
    fn dashboard_full_response() {
        let d: DashboardFullResponse = serde_json::from_value(json!({
            "dashboard": {"title": "Test", "panels": []},
            "meta": {"slug": "test", "version": 3, "isStarred": false}
        }))
        .unwrap();
        assert!(d.dashboard.is_some());
        assert_eq!(d.meta.as_ref().unwrap().version, Some(3));
    }

    #[test]
    fn dashboard_meta_full() {
        let m: DashboardMeta = serde_json::from_value(json!({
            "isStarred": false, "slug": "my-dash", "url": "/d/abc/my-dash",
            "folderId": 1, "folderUid": "f1", "folderTitle": "General",
            "created": "2026-01-01", "updated": "2026-03-01",
            "createdBy": "admin", "updatedBy": "admin", "version": 5
        }))
        .unwrap();
        assert_eq!(m.slug.as_deref(), Some("my-dash"));
        assert_eq!(m.version, Some(5));
    }

    #[test]
    fn dashboard_save_response() {
        let r: DashboardSaveResponse = serde_json::from_value(json!({
            "id": 1, "uid": "abc", "url": "/d/abc/", "status": "success", "version": 1
        }))
        .unwrap();
        assert_eq!(r.uid.as_deref(), Some("abc"));
        assert_eq!(r.status.as_deref(), Some("success"));
    }

    #[test]
    fn datasource_roundtrip() {
        let d: Datasource = serde_json::from_value(json!({
            "id": 1, "uid": "prometheus", "name": "Prometheus",
            "type": "prometheus", "url": "http://prometheus:9090",
            "access": "proxy", "isDefault": true
        }))
        .unwrap();
        assert_eq!(d.datasource_type.as_deref(), Some("prometheus"));
        assert!(d.is_default.unwrap());
    }

    #[test]
    fn datasource_minimal() {
        let d: Datasource = serde_json::from_value(json!({})).unwrap();
        assert!(d.id.is_none());
        assert!(d.is_default.is_none());
    }

    #[test]
    fn alert_rule_full() {
        let a: AlertRule = serde_json::from_value(json!({
            "id": 1, "uid": "alert-1", "title": "High CPU",
            "condition": "A", "data": [{"refId": "A"}],
            "ruleGroup": "default", "folderUID": "folder-1",
            "noDataState": "OK", "execErrState": "Error",
            "for": "5m", "labels": {"severity": "critical"},
            "annotations": {"summary": "CPU is high"}
        }))
        .unwrap();
        assert_eq!(a.uid.as_deref(), Some("alert-1"));
        assert_eq!(a.data.len(), 1);
        assert_eq!(a.for_duration.as_deref(), Some("5m"));
    }

    #[test]
    fn alert_rule_minimal() {
        let a: AlertRule = serde_json::from_value(json!({})).unwrap();
        assert!(a.uid.is_none());
        assert!(a.data.is_empty());
    }

    #[test]
    fn annotation_roundtrip() {
        let a: Annotation = serde_json::from_value(json!({
            "id": 42, "dashboardId": 1, "dashboardUID": "abc",
            "panelId": 2, "text": "Deploy v2.0",
            "tags": ["deploy", "production"],
            "time": 1709251200000_i64, "timeEnd": 1709251260000_i64
        }))
        .unwrap();
        assert_eq!(a.id, Some(42));
        assert_eq!(a.text.as_deref(), Some("Deploy v2.0"));
        assert_eq!(a.tags.len(), 2);
    }

    #[test]
    fn annotation_minimal() {
        let a: Annotation = serde_json::from_value(json!({})).unwrap();
        assert!(a.id.is_none());
        assert!(a.tags.is_empty());
    }

    #[test]
    fn annotation_create_response() {
        let r: AnnotationCreateResponse =
            serde_json::from_value(json!({"id": 99, "message": "Annotation added"})).unwrap();
        assert_eq!(r.id, Some(99));
    }

    #[test]
    fn api_error_response() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"message": "Not found", "status": "404"})).unwrap();
        assert_eq!(e.message.as_deref(), Some("Not found"));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
    }

    // ── Clone trait tests ───────────────────────────────────────

    #[test]
    fn dashboard_search_result_clone() {
        let d: DashboardSearchResult = serde_json::from_value(json!({
            "id": 1, "uid": "abc", "title": "Test", "tags": ["a"]
        }))
        .unwrap();
        let c = d.clone();
        assert_eq!(c.uid, d.uid);
        assert_eq!(c.tags, d.tags);
    }

    #[test]
    fn dashboard_full_response_clone() {
        let d: DashboardFullResponse = serde_json::from_value(json!({
            "dashboard": {"title": "T"},
            "meta": {"slug": "t"}
        }))
        .unwrap();
        let c = d.clone();
        assert_eq!(c.meta.as_ref().unwrap().slug, d.meta.as_ref().unwrap().slug);
    }

    #[test]
    fn datasource_clone() {
        let d: Datasource = serde_json::from_value(json!({
            "id": 1, "name": "prom", "type": "prometheus"
        }))
        .unwrap();
        let c = d.clone();
        assert_eq!(c.name, d.name);
    }

    #[test]
    fn alert_rule_clone() {
        let a: AlertRule = serde_json::from_value(json!({
            "uid": "a1", "title": "CPU", "data": [{"refId": "A"}]
        }))
        .unwrap();
        let c = a.clone();
        assert_eq!(c.uid, a.uid);
        assert_eq!(c.data.len(), 1);
    }

    #[test]
    fn annotation_clone() {
        let a: Annotation = serde_json::from_value(json!({
            "id": 1, "text": "test", "tags": ["deploy"]
        }))
        .unwrap();
        let c = a.clone();
        assert_eq!(c.text, a.text);
        assert_eq!(c.tags.len(), 1);
    }

    // ── Debug trait tests ───────────────────────────────────────

    #[test]
    fn dashboard_search_result_debug() {
        let d: DashboardSearchResult = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("DashboardSearchResult"));
    }

    #[test]
    fn datasource_debug() {
        let d: Datasource = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Datasource"));
    }

    #[test]
    fn annotation_debug() {
        let a: Annotation = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Annotation"));
    }

    // ── Serialize roundtrip tests ───────────────────────────────

    #[test]
    fn dashboard_search_result_serialize_roundtrip() {
        let d: DashboardSearchResult = serde_json::from_value(json!({
            "id": 7, "uid": "xyz", "title": "RT Test",
            "type": "dash-db", "tags": ["t1", "t2"],
            "isStarred": false, "folderId": 3
        }))
        .unwrap();
        let serialized = serde_json::to_value(&d).unwrap();
        let back: DashboardSearchResult = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.uid, d.uid);
        assert_eq!(back.tags, d.tags);
        assert_eq!(back.folder_id, d.folder_id);
    }

    #[test]
    fn dashboard_meta_serialize_roundtrip() {
        let m: DashboardMeta = serde_json::from_value(json!({
            "isStarred": true, "slug": "test-slug", "version": 10,
            "created": "2026-01-01", "createdBy": "admin"
        }))
        .unwrap();
        let serialized = serde_json::to_value(&m).unwrap();
        let back: DashboardMeta = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.slug, m.slug);
        assert_eq!(back.version, m.version);
        assert_eq!(back.is_starred, Some(true));
    }

    #[test]
    fn dashboard_save_response_serialize_roundtrip() {
        let r: DashboardSaveResponse = serde_json::from_value(json!({
            "id": 42, "uid": "uid_1", "url": "/d/uid_1", "status": "success",
            "version": 3, "slug": "my-dash"
        }))
        .unwrap();
        let serialized = serde_json::to_value(&r).unwrap();
        let back: DashboardSaveResponse = serde_json::from_value(serialized).unwrap();
        assert_eq!(back.slug, r.slug);
        assert_eq!(back.version, Some(3));
    }

    #[test]
    fn datasource_query_response_roundtrip() {
        let r: DatasourceQueryResponse = serde_json::from_value(json!({
            "results": {"A": {"frames": []}}
        }))
        .unwrap();
        assert!(r.results.is_some());
        let serialized = serde_json::to_value(&r).unwrap();
        let back: DatasourceQueryResponse = serde_json::from_value(serialized).unwrap();
        assert!(back.results.is_some());
    }

    #[test]
    fn datasource_query_response_minimal() {
        let r: DatasourceQueryResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.results.is_none());
    }

    #[test]
    fn annotation_create_response_minimal() {
        let r: AnnotationCreateResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.id.is_none());
        assert!(r.message.is_none());
    }

    // ── Edge cases ──────────────────────────────────────────────

    #[test]
    fn dashboard_search_result_empty_strings() {
        let d: DashboardSearchResult = serde_json::from_value(json!({
            "uid": "", "title": "", "uri": "", "url": "",
            "type": "", "tags": []
        }))
        .unwrap();
        assert_eq!(d.uid.as_deref(), Some(""));
        assert_eq!(d.title.as_deref(), Some(""));
        assert!(d.tags.is_empty());
    }

    #[test]
    fn dashboard_search_result_many_tags() {
        let tags: Vec<String> = (0..100).map(|i| format!("tag-{i}")).collect();
        let d: DashboardSearchResult = serde_json::from_value(json!({
            "tags": tags
        }))
        .unwrap();
        assert_eq!(d.tags.len(), 100);
    }

    #[test]
    fn alert_rule_empty_data_vec() {
        let a: AlertRule = serde_json::from_value(json!({"data": []})).unwrap();
        assert!(a.data.is_empty());
    }

    #[test]
    fn alert_rule_labels_annotations_default() {
        let a: AlertRule = serde_json::from_value(json!({})).unwrap();
        // labels and annotations default to json Value (null)
        assert!(a.labels.is_null());
        assert!(a.annotations.is_null());
    }

    #[test]
    fn annotation_empty_tags_default() {
        let a: Annotation = serde_json::from_value(json!({})).unwrap();
        assert!(a.tags.is_empty());
    }

    #[test]
    fn annotation_time_boundaries() {
        let a: Annotation = serde_json::from_value(json!({
            "time": 0, "timeEnd": i64::MAX
        }))
        .unwrap();
        assert_eq!(a.time, Some(0));
        assert_eq!(a.time_end, Some(i64::MAX));
    }

    #[test]
    fn dashboard_meta_all_none() {
        let m: DashboardMeta = serde_json::from_value(json!({})).unwrap();
        assert!(m.is_starred.is_none());
        assert!(m.slug.is_none());
        assert!(m.url.is_none());
        assert!(m.folder_id.is_none());
        assert!(m.folder_uid.is_none());
        assert!(m.folder_title.is_none());
        assert!(m.created.is_none());
        assert!(m.updated.is_none());
        assert!(m.created_by.is_none());
        assert!(m.updated_by.is_none());
        assert!(m.version.is_none());
    }

    #[test]
    fn dashboard_save_response_minimal() {
        let r: DashboardSaveResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.id.is_none());
        assert!(r.uid.is_none());
        assert!(r.url.is_none());
        assert!(r.status.is_none());
        assert!(r.version.is_none());
        assert!(r.slug.is_none());
    }

    #[test]
    fn datasource_all_fields() {
        let d: Datasource = serde_json::from_value(json!({
            "id": 5, "uid": "ds1", "name": "My DS",
            "type": "influxdb", "url": "http://influx:8086",
            "access": "direct", "isDefault": false,
            "database": "mydb", "readOnly": true
        }))
        .unwrap();
        assert_eq!(d.database.as_deref(), Some("mydb"));
        assert_eq!(d.read_only, Some(true));
        assert_eq!(d.access.as_deref(), Some("direct"));
    }

    #[test]
    fn api_error_response_status_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"status": "error"})).unwrap();
        assert_eq!(e.status.as_deref(), Some("error"));
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "fail"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn dashboard_search_result_rename_type() {
        // Verify the #[serde(rename = "type")] works bidirectionally
        let d = DashboardSearchResult {
            id: None,
            uid: None,
            title: None,
            uri: None,
            url: None,
            result_type: Some("dash-db".into()),
            tags: vec![],
            is_starred: None,
            folder_id: None,
            folder_uid: None,
            folder_title: None,
            folder_url: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["type"], "dash-db");
        assert!(v.get("result_type").is_none());
    }
}
