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

    #[test]
    fn search_hit_clone() {
        let h = SearchHit {
            object_id: "h1".into(),
            extra: json!({"score": 42}),
        };
        let c = h.clone();
        assert_eq!(c.object_id, "h1");
        assert_eq!(h.object_id, "h1");
    }

    #[test]
    fn search_hit_debug() {
        let h = SearchHit {
            object_id: "dbg1".into(),
            extra: json!({}),
        };
        let dbg = format!("{h:?}");
        assert!(dbg.contains("dbg1"));
    }

    #[test]
    fn search_response_clone() {
        let r = SearchResponse {
            hits: vec![json!({"objectID": "x"})],
            nb_hits: Some(1),
            page: Some(0),
            nb_pages: Some(1),
            hits_per_page: Some(20),
            query: Some("test".into()),
            processing_time_ms: Some(5),
        };
        let c = r.clone();
        assert_eq!(c.hits.len(), 1);
        assert_eq!(c.query, Some("test".into()));
        assert_eq!(r.nb_hits, Some(1));
    }

    #[test]
    fn search_response_debug() {
        let r = SearchResponse {
            hits: vec![],
            nb_hits: None,
            page: None,
            nb_pages: None,
            hits_per_page: None,
            query: Some("debug_query".into()),
            processing_time_ms: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("debug_query"));
    }

    #[test]
    fn index_entry_clone() {
        let e = IndexEntry {
            name: "idx".into(),
            created_at: Some("2025-01-01".into()),
            updated_at: None,
            entries: Some(10),
            data_size: Some(100),
            last_build_time_s: None,
        };
        let c = e.clone();
        assert_eq!(c.name, "idx");
        assert_eq!(c.entries, Some(10));
        assert_eq!(e.data_size, Some(100));
    }

    #[test]
    fn index_entry_debug() {
        let e = IndexEntry {
            name: "debug_idx".into(),
            created_at: None,
            updated_at: None,
            entries: None,
            data_size: None,
            last_build_time_s: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("debug_idx"));
    }

    #[test]
    fn indices_list_response_clone() {
        let r = IndicesListResponse {
            items: vec![json!({"name": "idx1"})],
            nb_pages: Some(1),
        };
        let c = r.clone();
        assert_eq!(c.items.len(), 1);
        assert_eq!(r.nb_pages, Some(1));
    }

    #[test]
    fn indices_list_response_debug() {
        let r = IndicesListResponse {
            items: vec![],
            nb_pages: Some(0),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("IndicesListResponse"));
    }

    #[test]
    fn record_clone() {
        let r = Record {
            object_id: "rec1".into(),
            extra: json!({"title": "Test"}),
        };
        let c = r.clone();
        assert_eq!(c.object_id, "rec1");
        assert_eq!(r.object_id, "rec1");
    }

    #[test]
    fn record_debug() {
        let r = Record {
            object_id: "rec_dbg".into(),
            extra: json!({}),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("rec_dbg"));
    }

    #[test]
    fn delete_response_clone() {
        let d = DeleteResponse {
            deleted_at: Some("2025-01-01T00:00:00Z".into()),
            task_id: Some(999),
        };
        let c = d.clone();
        assert_eq!(c.task_id, Some(999));
        assert_eq!(d.deleted_at, Some("2025-01-01T00:00:00Z".into()));
    }

    #[test]
    fn delete_response_debug() {
        let d = DeleteResponse {
            deleted_at: None,
            task_id: Some(123),
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("123"));
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("err".into()),
            status: Some(400),
        };
        let c = e.clone();
        assert_eq!(c.message, Some("err".into()));
        assert_eq!(c.status, Some(400));
        assert_eq!(e.message, Some("err".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            message: Some("debug_msg".into()),
            status: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("debug_msg"));
    }

    #[test]
    fn search_response_serialize_roundtrip() {
        let r = SearchResponse {
            hits: vec![json!({"objectID": "h1", "name": "Widget"})],
            nb_hits: Some(1),
            page: Some(0),
            nb_pages: Some(1),
            hits_per_page: Some(20),
            query: Some("widget".into()),
            processing_time_ms: Some(3),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["query"], "widget");
        assert_eq!(v["nbHits"], 1);
        let back: SearchResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.query, Some("widget".into()));
    }

    #[test]
    fn record_serialize_roundtrip() {
        let r = Record {
            object_id: "r-ser".into(),
            extra: json!({"price": 42.5}),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["objectID"], "r-ser");
        assert_eq!(v["price"], 42.5);
        let back: Record = serde_json::from_value(v).unwrap();
        assert_eq!(back.object_id, "r-ser");
    }

    #[test]
    fn delete_response_serialize_roundtrip() {
        let d = DeleteResponse {
            deleted_at: Some("2025-06-15T12:00:00Z".into()),
            task_id: Some(42),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["deletedAt"], "2025-06-15T12:00:00Z");
        assert_eq!(v["taskID"], 42);
        let back: DeleteResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.task_id, Some(42));
    }

    #[test]
    fn search_hit_with_nested_extra() {
        let h: SearchHit = serde_json::from_value(json!({
            "objectID": "nested1",
            "category": {"name": "Electronics", "id": 5},
            "tags": ["sale", "new"]
        }))
        .unwrap();
        assert_eq!(h.object_id, "nested1");
    }

    #[test]
    fn index_entry_zero_entries() {
        let e: IndexEntry = serde_json::from_value(json!({
            "name": "empty_index",
            "entries": 0,
        }))
        .unwrap();
        assert_eq!(e.entries, Some(0));
    }

    #[test]
    fn index_entry_large_data_size() {
        let e: IndexEntry = serde_json::from_value(json!({
            "name": "big_index",
            "dataSize": 1_073_741_824_i64,
        }))
        .unwrap();
        assert_eq!(e.data_size, Some(1_073_741_824));
    }

    #[test]
    fn search_response_empty_query() {
        let r: SearchResponse = serde_json::from_value(json!({
            "hits": [],
            "query": "",
        }))
        .unwrap();
        assert_eq!(r.query, Some(String::new()));
    }

    #[test]
    fn indices_list_response_serialize_roundtrip() {
        let r = IndicesListResponse {
            items: vec![json!({"name": "idx1"}), json!({"name": "idx2"})],
            nb_pages: Some(2),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        assert_eq!(v["nbPages"], 2);
        let back: IndicesListResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.nb_pages, Some(2));
    }

    #[test]
    fn search_response_extra_fields_ignored() {
        let r: SearchResponse = serde_json::from_value(json!({
            "hits": [],
            "nbHits": 0,
            "exhaustiveNbHits": true,
            "params": "query=test",
        }))
        .unwrap();
        assert!(r.hits.is_empty());
        assert_eq!(r.nb_hits, Some(0));
    }

    #[test]
    fn record_extra_fields_preserved() {
        let r: Record = serde_json::from_value(json!({
            "objectID": "r1",
            "custom1": "value1",
            "custom2": 42,
        }))
        .unwrap();
        assert_eq!(r.object_id, "r1");
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["custom1"], "value1");
        assert_eq!(re["custom2"], 42);
    }
}
