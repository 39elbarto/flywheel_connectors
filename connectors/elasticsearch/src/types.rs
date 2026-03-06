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

    // ── SearchResponse extended tests ───────────────────────────────

    #[test]
    fn search_response_with_shards() {
        let r: SearchResponse = serde_json::from_value(json!({
            "took": 5,
            "_shards": {"total": 5, "successful": 5, "skipped": 0, "failed": 0}
        }))
        .unwrap();
        assert!(r.shards.is_some());
        assert_eq!(r.took, Some(5));
    }

    #[test]
    fn search_response_clone() {
        let r: SearchResponse = serde_json::from_value(json!({"took": 10})).unwrap();
        let r2 = r.clone();
        assert_eq!(r.took, Some(10));
        assert!(r2.hits.is_none());
    }

    #[test]
    fn search_response_debug() {
        let r: SearchResponse = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("SearchResponse"));
    }

    #[test]
    fn search_response_serialize_roundtrip() {
        let r: SearchResponse = serde_json::from_value(json!({
            "took": 42,
            "timed_out": false,
            "hits": {"total": {"value": 0}, "hits": []}
        }))
        .unwrap();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["took"], 42);
        assert_eq!(v["timed_out"], false);
    }

    // ── SearchHits extended tests ───────────────────────────────────

    #[test]
    fn search_hits_empty() {
        let h: SearchHits = serde_json::from_value(json!({"hits": []})).unwrap();
        assert!(h.hits.is_empty());
        assert!(h.max_score.is_none());
    }

    #[test]
    fn search_hits_clone() {
        let h: SearchHits = serde_json::from_value(json!({
            "max_score": 4.25,
            "hits": [{"_id": "1"}]
        }))
        .unwrap();
        let h2 = h.clone();
        assert_eq!(h.max_score, Some(4.25));
        assert_eq!(h2.hits.len(), 1);
    }

    #[test]
    fn search_hits_debug() {
        let h: SearchHits = serde_json::from_value(json!({"hits": []})).unwrap();
        let dbg = format!("{h:?}");
        assert!(dbg.contains("SearchHits"));
    }

    #[test]
    fn search_hits_default_vec() {
        // Tests the #[serde(default)] on hits field
        let h: SearchHits = serde_json::from_value(json!({})).unwrap();
        assert!(h.hits.is_empty());
    }

    // ── SearchHit extended tests ────────────────────────────────────

    #[test]
    fn search_hit_minimal() {
        let h: SearchHit = serde_json::from_value(json!({})).unwrap();
        assert!(h.index.is_none());
        assert!(h.id.is_none());
        assert!(h.score.is_none());
        assert!(h.source.is_none());
    }

    #[test]
    fn search_hit_clone() {
        let h: SearchHit = serde_json::from_value(json!({"_id": "hit1", "_score": 1.0})).unwrap();
        let h2 = h.clone();
        assert_eq!(h.id, Some("hit1".into()));
        assert_eq!(h2.score, Some(1.0));
    }

    #[test]
    fn search_hit_debug() {
        let h: SearchHit = serde_json::from_value(json!({"_id": "dbg-hit"})).unwrap();
        let dbg = format!("{h:?}");
        assert!(dbg.contains("SearchHit"));
    }

    #[test]
    fn search_hit_serialize_preserves_renames() {
        let h: SearchHit = serde_json::from_value(json!({
            "_index": "logs",
            "_id": "x",
            "_score": 2.5,
            "_source": {"field": "value"}
        }))
        .unwrap();
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(v["_index"], "logs");
        assert_eq!(v["_id"], "x");
        assert!(v.get("index").is_none());
        assert!(v.get("id").is_none());
    }

    // ── GetDocumentResponse extended tests ──────────────────────────

    #[test]
    fn get_document_response_minimal() {
        let r: GetDocumentResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.index.is_none());
        assert!(r.id.is_none());
        assert!(r.version.is_none());
        assert!(r.found.is_none());
        assert!(r.source.is_none());
    }

    #[test]
    fn get_document_response_clone() {
        let r: GetDocumentResponse = serde_json::from_value(json!({
            "_index": "test",
            "_id": "doc1",
            "found": true
        }))
        .unwrap();
        let r2 = r.clone();
        assert_eq!(r.id, Some("doc1".into()));
        assert!(r2.found.unwrap());
    }

    #[test]
    fn get_document_response_debug() {
        let r: GetDocumentResponse = serde_json::from_value(json!({"_id": "dbg"})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("GetDocumentResponse"));
    }

    #[test]
    fn get_document_serialize_renames() {
        let r: GetDocumentResponse = serde_json::from_value(json!({
            "_index": "idx",
            "_id": "d1",
            "_version": 5,
            "_source": {"k": "v"}
        }))
        .unwrap();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["_index"], "idx");
        assert_eq!(v["_version"], 5);
        assert!(v.get("index").is_none());
    }

    // ── IndexDocumentResponse extended tests ────────────────────────

    #[test]
    fn index_document_response_minimal() {
        let r: IndexDocumentResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.index.is_none());
        assert!(r.result.is_none());
    }

    #[test]
    fn index_document_response_clone() {
        let r: IndexDocumentResponse = serde_json::from_value(json!({
            "_id": "id1",
            "result": "updated"
        }))
        .unwrap();
        let r2 = r.clone();
        assert_eq!(r.id, Some("id1".into()));
        assert_eq!(r2.result, Some("updated".into()));
    }

    #[test]
    fn index_document_response_debug() {
        let r: IndexDocumentResponse = serde_json::from_value(json!({"result": "created"})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("IndexDocumentResponse"));
    }

    #[test]
    fn index_document_response_all_fields() {
        let r: IndexDocumentResponse = serde_json::from_value(json!({
            "_index": "products",
            "_id": "p1",
            "_version": 3,
            "result": "updated",
            "_shards": {"total": 2, "successful": 1, "failed": 0},
            "_seq_no": 10,
            "_primary_term": 2
        }))
        .unwrap();
        assert_eq!(r.version, Some(3));
        assert_eq!(r.seq_no, Some(10));
        assert_eq!(r.primary_term, Some(2));
        assert!(r.shards.is_some());
    }

    // ── BulkResponse extended tests ─────────────────────────────────

    #[test]
    fn bulk_response_minimal() {
        let r: BulkResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.took.is_none());
        assert!(r.errors.is_none());
        assert!(r.items.is_empty());
    }

    #[test]
    fn bulk_response_clone() {
        let r: BulkResponse = serde_json::from_value(json!({
            "took": 5,
            "errors": false,
            "items": [{"index": {"_id": "1"}}]
        }))
        .unwrap();
        let r2 = r.clone();
        assert_eq!(r.took, Some(5));
        assert_eq!(r2.items.len(), 1);
    }

    #[test]
    fn bulk_response_debug() {
        let r: BulkResponse = serde_json::from_value(json!({"items": []})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("BulkResponse"));
    }

    // ── IndexInfo extended tests ────────────────────────────────────

    #[test]
    fn index_info_all_fields() {
        let i: IndexInfo = serde_json::from_value(json!({
            "health": "yellow",
            "status": "open",
            "index": "test-idx",
            "uuid": "uuid-abc",
            "pri": "3",
            "rep": "2",
            "docs.count": "5000",
            "docs.deleted": "100",
            "store.size": "10mb",
            "pri.store.size": "5mb"
        }))
        .unwrap();
        assert_eq!(i.health.as_deref(), Some("yellow"));
        assert_eq!(i.rep.as_deref(), Some("2"));
        assert_eq!(i.docs_deleted.as_deref(), Some("100"));
        assert_eq!(i.pri_store_size.as_deref(), Some("5mb"));
    }

    #[test]
    fn index_info_clone() {
        let i: IndexInfo = serde_json::from_value(json!({"index": "cloned"})).unwrap();
        let i2 = i.clone();
        assert_eq!(i.index, Some("cloned".into()));
        assert!(i2.health.is_none());
    }

    #[test]
    fn index_info_debug() {
        let i: IndexInfo = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{i:?}");
        assert!(dbg.contains("IndexInfo"));
    }

    // ── ClusterHealthResponse extended tests ────────────────────────

    #[test]
    fn cluster_health_all_fields() {
        let r: ClusterHealthResponse = serde_json::from_value(json!({
            "cluster_name": "full-cluster",
            "status": "yellow",
            "timed_out": true,
            "number_of_nodes": 5,
            "number_of_data_nodes": 3,
            "active_primary_shards": 20,
            "active_shards": 40,
            "relocating_shards": 1,
            "initializing_shards": 2,
            "unassigned_shards": 3,
            "delayed_unassigned_shards": 0,
            "number_of_pending_tasks": 1,
            "number_of_in_flight_fetch": 0,
            "task_max_waiting_in_queue_millis": 100,
            "active_shards_percent_as_number": 95.5
        }))
        .unwrap();
        assert_eq!(r.timed_out, Some(true));
        assert_eq!(r.number_of_data_nodes, Some(3));
        assert_eq!(r.relocating_shards, Some(1));
        assert_eq!(r.initializing_shards, Some(2));
        assert_eq!(r.unassigned_shards, Some(3));
        assert_eq!(r.delayed_unassigned_shards, Some(0));
        assert_eq!(r.number_of_pending_tasks, Some(1));
        assert_eq!(r.number_of_in_flight_fetch, Some(0));
        assert_eq!(r.task_max_waiting_in_queue_millis, Some(100));
        assert_eq!(r.active_shards_percent_as_number, Some(95.5));
    }

    #[test]
    fn cluster_health_clone() {
        let r: ClusterHealthResponse = serde_json::from_value(json!({"status": "green"})).unwrap();
        let r2 = r.clone();
        assert_eq!(r.status, Some("green".into()));
        assert!(r2.cluster_name.is_none());
    }

    #[test]
    fn cluster_health_debug() {
        let r: ClusterHealthResponse = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ClusterHealthResponse"));
    }

    // ── DeleteIndexResponse extended tests ──────────────────────────

    #[test]
    fn delete_index_response_false() {
        let r: DeleteIndexResponse = serde_json::from_value(json!({"acknowledged": false})).unwrap();
        assert!(!r.acknowledged.unwrap());
    }

    #[test]
    fn delete_index_response_minimal() {
        let r: DeleteIndexResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.acknowledged.is_none());
    }

    #[test]
    fn delete_index_response_clone() {
        let r: DeleteIndexResponse = serde_json::from_value(json!({"acknowledged": true})).unwrap();
        let r2 = r.clone();
        assert!(r.acknowledged.unwrap());
        assert!(r2.acknowledged.unwrap());
    }

    #[test]
    fn delete_index_response_debug() {
        let r: DeleteIndexResponse = serde_json::from_value(json!({"acknowledged": true})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DeleteIndexResponse"));
    }

    // ── ApiErrorResponse extended tests ─────────────────────────────

    #[test]
    fn api_error_response_with_status_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"status": 500})).unwrap();
        assert_eq!(e.status, Some(500));
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": {"type": "index_not_found", "reason": "no such index"},
            "status": 404
        }))
        .unwrap();
        let e2 = e.clone();
        assert_eq!(e.status, Some(404));
        assert_eq!(e2.error.unwrap().error_type, Some("index_not_found".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    // ── ApiError extended tests ─────────────────────────────────────

    #[test]
    fn api_error_minimal() {
        let e: ApiError = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_type.is_none());
        assert!(e.reason.is_none());
        assert!(e.root_cause.is_none());
    }

    #[test]
    fn api_error_with_root_cause() {
        let e: ApiError = serde_json::from_value(json!({
            "type": "search_phase_execution_exception",
            "reason": "all shards failed",
            "root_cause": [
                {"type": "query_shard_exception", "reason": "query failed"}
            ]
        }))
        .unwrap();
        assert_eq!(e.error_type, Some("search_phase_execution_exception".into()));
        assert_eq!(e.root_cause.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn api_error_clone() {
        let e: ApiError = serde_json::from_value(json!({
            "type": "mapper_parsing_exception",
            "reason": "failed to parse"
        }))
        .unwrap();
        let e2 = e.clone();
        assert_eq!(e.error_type, Some("mapper_parsing_exception".into()));
        assert_eq!(e2.reason, Some("failed to parse".into()));
    }

    #[test]
    fn api_error_debug() {
        let e: ApiError = serde_json::from_value(json!({"type": "test_err"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiError"));
    }

    // ── Serialize roundtrip tests ───────────────────────────────────

    #[test]
    fn index_info_serialize_roundtrip() {
        let i: IndexInfo = serde_json::from_value(json!({
            "health": "green",
            "status": "open",
            "index": "my-index",
            "docs.count": "100"
        }))
        .unwrap();
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["health"], "green");
        assert_eq!(v["docs.count"], "100");
        assert!(v.get("docs_count").is_none());
    }

    #[test]
    fn bulk_response_serialize_roundtrip() {
        let r: BulkResponse = serde_json::from_value(json!({
            "took": 20,
            "errors": false,
            "items": [{"index": {"_id": "1", "status": 201}}]
        }))
        .unwrap();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["took"], 20);
        assert_eq!(v["errors"], false);
    }
}
