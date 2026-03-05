//! `Algolia` API types.

use serde::{Deserialize, Serialize};

/// An `Algolia` search hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    #[serde(rename = "objectID")]
    pub object_id: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Search response from `Algolia`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub hits: Vec<serde_json::Value>,
    #[serde(rename = "nbHits")]
    pub nb_hits: Option<i64>,
    pub page: Option<i64>,
    #[serde(rename = "nbPages")]
    pub nb_pages: Option<i64>,
    #[serde(rename = "hitsPerPage")]
    pub hits_per_page: Option<i64>,
    pub query: Option<String>,
    #[serde(rename = "processingTimeMS")]
    pub processing_time_ms: Option<i64>,
}

/// An `Algolia` index entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    pub entries: Option<i64>,
    #[serde(rename = "dataSize")]
    pub data_size: Option<i64>,
    #[serde(rename = "lastBuildTimeS")]
    pub last_build_time_s: Option<i64>,
}

/// List indices response from `Algolia`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicesListResponse {
    pub items: Vec<serde_json::Value>,
    #[serde(rename = "nbPages")]
    pub nb_pages: Option<i64>,
}

/// A record (object) from an `Algolia` index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    #[serde(rename = "objectID")]
    pub object_id: String,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Delete record response from `Algolia`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    #[serde(rename = "deletedAt")]
    pub deleted_at: Option<String>,
    #[serde(rename = "taskID")]
    pub task_id: Option<i64>,
}

/// `Algolia` API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub status: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn search_hit_roundtrip() {
        let h: SearchHit = serde_json::from_value(json!({
            "objectID": "abc123",
            "title": "Laptop",
            "price": 999
        }))
        .unwrap();
        assert_eq!(h.object_id, "abc123");
        let re = serde_json::to_value(&h).unwrap();
        assert_eq!(re["title"], "Laptop");
        assert_eq!(re["objectID"], "abc123");
    }

    #[test]
    fn search_hit_minimal() {
        let h: SearchHit = serde_json::from_value(json!({"objectID": "x"})).unwrap();
        assert_eq!(h.object_id, "x");
    }

    #[test]
    fn search_response_roundtrip() {
        let r: SearchResponse = serde_json::from_value(json!({
            "hits": [{"objectID": "h1", "name": "Widget"}],
            "nbHits": 1,
            "page": 0,
            "nbPages": 1,
            "hitsPerPage": 20,
            "query": "widget",
            "processingTimeMS": 3
        }))
        .unwrap();
        assert_eq!(r.hits.len(), 1);
        assert_eq!(r.nb_hits, Some(1));
        assert_eq!(r.query, Some("widget".into()));
        assert_eq!(r.processing_time_ms, Some(3));
    }

    #[test]
    fn search_response_minimal() {
        let r: SearchResponse = serde_json::from_value(json!({
            "hits": []
        }))
        .unwrap();
        assert!(r.hits.is_empty());
        assert!(r.nb_hits.is_none());
        assert!(r.query.is_none());
    }

    #[test]
    fn index_entry_roundtrip() {
        let e: IndexEntry = serde_json::from_value(json!({
            "name": "products",
            "createdAt": "2025-01-01T00:00:00Z",
            "updatedAt": "2025-06-15T12:00:00Z",
            "entries": 5000,
            "dataSize": 1048576,
            "lastBuildTimeS": 12
        }))
        .unwrap();
        assert_eq!(e.name, "products");
        assert_eq!(e.entries, Some(5000));
        assert_eq!(e.data_size, Some(1048576));
        let re = serde_json::to_value(&e).unwrap();
        assert_eq!(re["name"], "products");
    }

    #[test]
    fn index_entry_minimal() {
        let e: IndexEntry = serde_json::from_value(json!({"name": "idx"})).unwrap();
        assert_eq!(e.name, "idx");
        assert!(e.created_at.is_none());
        assert!(e.entries.is_none());
    }

    #[test]
    fn indices_list_response_roundtrip() {
        let r: IndicesListResponse = serde_json::from_value(json!({
            "items": [{"name": "products"}, {"name": "articles"}],
            "nbPages": 1
        }))
        .unwrap();
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.nb_pages, Some(1));
    }

    #[test]
    fn indices_list_response_empty() {
        let r: IndicesListResponse = serde_json::from_value(json!({
            "items": []
        }))
        .unwrap();
        assert!(r.items.is_empty());
    }

    #[test]
    fn record_roundtrip() {
        let r: Record = serde_json::from_value(json!({
            "objectID": "rec1",
            "title": "Test Record",
            "score": 42
        }))
        .unwrap();
        assert_eq!(r.object_id, "rec1");
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["title"], "Test Record");
        assert_eq!(re["score"], 42);
    }

    #[test]
    fn record_minimal() {
        let r: Record = serde_json::from_value(json!({"objectID": "min"})).unwrap();
        assert_eq!(r.object_id, "min");
    }

    #[test]
    fn delete_response_roundtrip() {
        let d: DeleteResponse = serde_json::from_value(json!({
            "deletedAt": "2025-06-15T12:00:00Z",
            "taskID": 12345
        }))
        .unwrap();
        assert_eq!(d.deleted_at, Some("2025-06-15T12:00:00Z".into()));
        assert_eq!(d.task_id, Some(12345));
    }

    #[test]
    fn delete_response_minimal() {
        let d: DeleteResponse = serde_json::from_value(json!({})).unwrap();
        assert!(d.deleted_at.is_none());
        assert!(d.task_id.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Index not found",
            "status": 404
        }))
        .unwrap();
        assert_eq!(e.message, Some("Index not found".into()));
        assert_eq!(e.status, Some(404));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.status.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"message": "Invalid API key"})).unwrap();
        assert_eq!(e.message, Some("Invalid API key".into()));
        assert!(e.status.is_none());
    }

    #[test]
    fn search_response_with_many_hits() {
        let hits: Vec<serde_json::Value> = (0..100)
            .map(|i| json!({"objectID": format!("h{i}"), "score": i}))
            .collect();
        let r: SearchResponse = serde_json::from_value(json!({
            "hits": hits,
            "nbHits": 100,
            "hitsPerPage": 100
        }))
        .unwrap();
        assert_eq!(r.hits.len(), 100);
        assert_eq!(r.nb_hits, Some(100));
    }

    #[test]
    fn index_entry_serialize_deserialize() {
        let original = IndexEntry {
            name: "test_index".into(),
            created_at: Some("2025-01-01T00:00:00Z".into()),
            updated_at: None,
            entries: Some(100),
            data_size: None,
            last_build_time_s: Some(5),
        };
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["name"], "test_index");
        assert_eq!(json["entries"], 100);
        let back: IndexEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.name, "test_index");
        assert_eq!(back.entries, Some(100));
    }
}
