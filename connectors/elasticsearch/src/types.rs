//! Elasticsearch API types.

use serde::{Deserialize, Serialize};

/// Search response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub took: Option<i64>,
    pub timed_out: Option<bool>,
    pub hits: Option<SearchHits>,
    #[serde(rename = "_shards")]
    pub shards: Option<serde_json::Value>,
}

/// Search hits wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHits {
    pub total: Option<serde_json::Value>,
    pub max_score: Option<f64>,
    #[serde(default)]
    pub hits: Vec<SearchHit>,
}

/// Individual search hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    #[serde(rename = "_index")]
    pub index: Option<String>,
    #[serde(rename = "_id")]
    pub id: Option<String>,
    #[serde(rename = "_score")]
    pub score: Option<f64>,
    #[serde(rename = "_source")]
    pub source: Option<serde_json::Value>,
}

/// Get document response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDocumentResponse {
    #[serde(rename = "_index")]
    pub index: Option<String>,
    #[serde(rename = "_id")]
    pub id: Option<String>,
    #[serde(rename = "_version")]
    pub version: Option<i64>,
    pub found: Option<bool>,
    #[serde(rename = "_source")]
    pub source: Option<serde_json::Value>,
}

/// Index document response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDocumentResponse {
    #[serde(rename = "_index")]
    pub index: Option<String>,
    #[serde(rename = "_id")]
    pub id: Option<String>,
    #[serde(rename = "_version")]
    pub version: Option<i64>,
    pub result: Option<String>,
    #[serde(rename = "_shards")]
    pub shards: Option<serde_json::Value>,
    #[serde(rename = "_seq_no")]
    pub seq_no: Option<i64>,
    #[serde(rename = "_primary_term")]
    pub primary_term: Option<i64>,
}

/// Bulk response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResponse {
    pub took: Option<i64>,
    pub errors: Option<bool>,
    #[serde(default)]
    pub items: Vec<serde_json::Value>,
}

/// Index info from _cat/indices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
    pub health: Option<String>,
    pub status: Option<String>,
    pub index: Option<String>,
    pub uuid: Option<String>,
    pub pri: Option<String>,
    pub rep: Option<String>,
    #[serde(rename = "docs.count")]
    pub docs_count: Option<String>,
    #[serde(rename = "docs.deleted")]
    pub docs_deleted: Option<String>,
    #[serde(rename = "store.size")]
    pub store_size: Option<String>,
    #[serde(rename = "pri.store.size")]
    pub pri_store_size: Option<String>,
}

/// Cluster health response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealthResponse {
    pub cluster_name: Option<String>,
    pub status: Option<String>,
    pub timed_out: Option<bool>,
    pub number_of_nodes: Option<i64>,
    pub number_of_data_nodes: Option<i64>,
    pub active_primary_shards: Option<i64>,
    pub active_shards: Option<i64>,
    pub relocating_shards: Option<i64>,
    pub initializing_shards: Option<i64>,
    pub unassigned_shards: Option<i64>,
    pub delayed_unassigned_shards: Option<i64>,
    pub number_of_pending_tasks: Option<i64>,
    pub number_of_in_flight_fetch: Option<i64>,
    pub task_max_waiting_in_queue_millis: Option<i64>,
    pub active_shards_percent_as_number: Option<f64>,
}

/// Delete index response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteIndexResponse {
    pub acknowledged: Option<bool>,
}

/// Elasticsearch API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<ApiError>,
    pub status: Option<i64>,
}

/// Elasticsearch error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub reason: Option<String>,
    pub root_cause: Option<Vec<serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn search_response_roundtrip() {
        let r: SearchResponse = serde_json::from_value(json!({
            "took": 15,
            "timed_out": false,
            "hits": {
                "total": {"value": 100, "relation": "eq"},
                "max_score": 1.5,
                "hits": [
                    {"_index": "logs", "_id": "1", "_score": 1.5, "_source": {"msg": "hello"}}
                ]
            }
        }))
        .unwrap();
        assert_eq!(r.took, Some(15));
        assert_eq!(r.hits.as_ref().unwrap().hits.len(), 1);
    }

    #[test]
    fn search_response_minimal() {
        let r: SearchResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.took.is_none());
        assert!(r.hits.is_none());
    }

    #[test]
    fn search_hit_fields() {
        let h: SearchHit = serde_json::from_value(json!({
            "_index": "products",
            "_id": "abc",
            "_score": 2.3,
            "_source": {"name": "Widget"}
        }))
        .unwrap();
        assert_eq!(h.index.as_deref(), Some("products"));
        assert_eq!(h.id.as_deref(), Some("abc"));
    }

    #[test]
    fn get_document_response() {
        let r: GetDocumentResponse = serde_json::from_value(json!({
            "_index": "products",
            "_id": "1",
            "_version": 3,
            "found": true,
            "_source": {"name": "Widget", "price": 9.99}
        }))
        .unwrap();
        assert_eq!(r.id.as_deref(), Some("1"));
        assert!(r.found.unwrap());
        assert!(r.source.is_some());
    }

    #[test]
    fn get_document_not_found() {
        let r: GetDocumentResponse = serde_json::from_value(json!({
            "_index": "products",
            "_id": "missing",
            "found": false
        }))
        .unwrap();
        assert!(!r.found.unwrap());
        assert!(r.source.is_none());
    }

    #[test]
    fn index_document_response() {
        let r: IndexDocumentResponse = serde_json::from_value(json!({
            "_index": "products",
            "_id": "1",
            "_version": 1,
            "result": "created",
            "_seq_no": 0,
            "_primary_term": 1
        }))
        .unwrap();
        assert_eq!(r.result.as_deref(), Some("created"));
        assert_eq!(r.version, Some(1));
    }

    #[test]
    fn bulk_response_with_errors() {
        let r: BulkResponse = serde_json::from_value(json!({
            "took": 30,
            "errors": true,
            "items": [
                {"index": {"_index": "test", "_id": "1", "status": 201}},
                {"index": {"_index": "test", "_id": "2", "status": 400, "error": {"type": "mapper_parsing_exception"}}}
            ]
        }))
        .unwrap();
        assert!(r.errors.unwrap());
        assert_eq!(r.items.len(), 2);
    }

    #[test]
    fn bulk_response_no_errors() {
        let r: BulkResponse = serde_json::from_value(json!({
            "took": 10,
            "errors": false,
            "items": []
        }))
        .unwrap();
        assert!(!r.errors.unwrap());
        assert!(r.items.is_empty());
    }

    #[test]
    fn index_info_roundtrip() {
        let i: IndexInfo = serde_json::from_value(json!({
            "health": "green",
            "status": "open",
            "index": "logs-2026.03",
            "uuid": "abc123",
            "pri": "1",
            "rep": "1",
            "docs.count": "1000",
            "store.size": "5mb"
        }))
        .unwrap();
        assert_eq!(i.health.as_deref(), Some("green"));
        assert_eq!(i.index.as_deref(), Some("logs-2026.03"));
    }

    #[test]
    fn index_info_minimal() {
        let i: IndexInfo = serde_json::from_value(json!({})).unwrap();
        assert!(i.health.is_none());
        assert!(i.index.is_none());
    }

    #[test]
    fn cluster_health_response() {
        let r: ClusterHealthResponse = serde_json::from_value(json!({
            "cluster_name": "my-cluster",
            "status": "green",
            "timed_out": false,
            "number_of_nodes": 3,
            "number_of_data_nodes": 2,
            "active_primary_shards": 10,
            "active_shards": 20,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 0,
            "active_shards_percent_as_number": 100.0
        }))
        .unwrap();
        assert_eq!(r.cluster_name.as_deref(), Some("my-cluster"));
        assert_eq!(r.status.as_deref(), Some("green"));
        assert_eq!(r.number_of_nodes, Some(3));
    }

    #[test]
    fn cluster_health_minimal() {
        let r: ClusterHealthResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.cluster_name.is_none());
    }

    #[test]
    fn delete_index_response() {
        let r: DeleteIndexResponse =
            serde_json::from_value(json!({"acknowledged": true})).unwrap();
        assert!(r.acknowledged.unwrap());
    }

    #[test]
    fn api_error_response() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {
                "type": "index_not_found_exception",
                "reason": "no such index [missing]",
                "root_cause": [{"type": "index_not_found_exception", "reason": "no such index [missing]"}]
            },
            "status": 404
        }))
        .unwrap();
        assert_eq!(
            e.error.as_ref().unwrap().error_type.as_deref(),
            Some("index_not_found_exception")
        );
        assert_eq!(e.status, Some(404));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.status.is_none());
    }
}
