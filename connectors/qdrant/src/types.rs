//! Qdrant API types.

use serde::{Deserialize, Serialize};

/// A Qdrant collection summary (returned by list_collections).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub name: String,
}

/// Detailed collection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionInfo {
    pub status: String,
    pub optimizer_status: Option<serde_json::Value>,
    pub vectors_count: Option<u64>,
    pub indexed_vectors_count: Option<u64>,
    pub points_count: Option<u64>,
    pub segments_count: Option<u64>,
    pub config: Option<serde_json::Value>,
}

/// A point in a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// A search result with score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: serde_json::Value,
    pub version: Option<u64>,
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<serde_json::Value>,
}

/// Scroll result containing points and optional next page offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollResult {
    pub points: Vec<serde_json::Value>,
    pub next_page_offset: Option<serde_json::Value>,
}

/// Count result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountResult {
    pub count: u64,
}

/// Qdrant API response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct QdrantResponse {
    pub status: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub time: Option<f64>,
}

/// Qdrant list collections response.
#[derive(Debug, Clone, Deserialize)]
pub struct ListCollectionsResponse {
    pub status: Option<String>,
    pub result: Option<ListCollectionsResult>,
}

/// Inner result of list collections.
#[derive(Debug, Clone, Deserialize)]
pub struct ListCollectionsResult {
    pub collections: Vec<Collection>,
}

/// Qdrant operation status response (for upsert, delete).
#[derive(Debug, Clone, Deserialize)]
pub struct OperationResponse {
    pub status: Option<String>,
    pub result: Option<serde_json::Value>,
}

/// Audit receipt for side-effecting operations.
#[derive(Debug, Clone, Serialize)]
pub struct OperationReceipt {
    pub operation: String,
    pub effect: String,
    pub resource: String,
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Collection ─────────────────────────────────────────────────────

    #[test]
    fn collection_serde() {
        let c = Collection {
            name: "my_collection".into(),
        };
        let json_str = serde_json::to_string(&c).unwrap();
        let back: Collection = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "my_collection");
    }

    #[test]
    fn collection_roundtrip() {
        let c = Collection {
            name: "roundtrip_test".into(),
        };
        let val = serde_json::to_value(&c).unwrap();
        let back: Collection = serde_json::from_value(val).unwrap();
        assert_eq!(back.name, c.name);
    }

    #[test]
    fn collection_clone() {
        let c = Collection {
            name: "original".into(),
        };
        let cloned = c.clone();
        assert_eq!(cloned.name, "original");
        assert_eq!(c.name, "original");
    }

    #[test]
    fn collection_debug() {
        let c = Collection {
            name: "debug_test".into(),
        };
        let debug = format!("{c:?}");
        assert!(debug.contains("Collection"));
        assert!(debug.contains("debug_test"));
    }

    #[test]
    fn collection_empty_name() {
        let c = Collection {
            name: String::new(),
        };
        let json_str = serde_json::to_string(&c).unwrap();
        let back: Collection = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "");
    }

    #[test]
    fn collection_unicode_name() {
        let c = Collection {
            name: "коллекция_日本語".into(),
        };
        let json_str = serde_json::to_string(&c).unwrap();
        let back: Collection = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "коллекция_日本語");
    }

    #[test]
    fn collection_deserialize_extra_fields_ignored() {
        let json = json!({"name": "test", "extra": 42});
        let c: Collection = serde_json::from_value(json).unwrap();
        assert_eq!(c.name, "test");
    }

    // ── CollectionInfo ─────────────────────────────────────────────────

    #[test]
    fn collection_info_serde() {
        let json = json!({
            "status": "green",
            "vectors_count": 1000,
            "points_count": 500,
            "segments_count": 2
        });
        let info: CollectionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.status, "green");
        assert_eq!(info.vectors_count, Some(1000));
        assert!(info.optimizer_status.is_none());
    }

    #[test]
    fn collection_info_all_none_optionals() {
        let json = json!({"status": "yellow"});
        let info: CollectionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.status, "yellow");
        assert!(info.optimizer_status.is_none());
        assert!(info.vectors_count.is_none());
        assert!(info.indexed_vectors_count.is_none());
        assert!(info.points_count.is_none());
        assert!(info.segments_count.is_none());
        assert!(info.config.is_none());
    }

    #[test]
    fn collection_info_all_fields_present() {
        let json = json!({
            "status": "green",
            "optimizer_status": {"status": "ok"},
            "vectors_count": 2000,
            "indexed_vectors_count": 1500,
            "points_count": 1000,
            "segments_count": 4,
            "config": {"params": {"vectors": {"size": 768}}}
        });
        let info: CollectionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.status, "green");
        assert!(info.optimizer_status.is_some());
        assert_eq!(info.vectors_count, Some(2000));
        assert_eq!(info.indexed_vectors_count, Some(1500));
        assert_eq!(info.points_count, Some(1000));
        assert_eq!(info.segments_count, Some(4));
        assert!(info.config.is_some());
    }

    #[test]
    fn collection_info_roundtrip() {
        let info = CollectionInfo {
            status: "green".into(),
            optimizer_status: Some(json!({"status": "ok"})),
            vectors_count: Some(100),
            indexed_vectors_count: Some(90),
            points_count: Some(50),
            segments_count: Some(1),
            config: Some(json!({"key": "val"})),
        };
        let val = serde_json::to_value(&info).unwrap();
        let back: CollectionInfo = serde_json::from_value(val).unwrap();
        assert_eq!(back.status, "green");
        assert_eq!(back.vectors_count, Some(100));
        assert_eq!(back.indexed_vectors_count, Some(90));
    }

    #[test]
    fn collection_info_clone() {
        let info = CollectionInfo {
            status: "green".into(),
            optimizer_status: None,
            vectors_count: Some(42),
            indexed_vectors_count: None,
            points_count: None,
            segments_count: None,
            config: None,
        };
        let cloned = info.clone();
        assert_eq!(cloned.status, "green");
        assert_eq!(cloned.vectors_count, Some(42));
        assert_eq!(info.status, "green");
    }

    #[test]
    fn collection_info_debug() {
        let info = CollectionInfo {
            status: "red".into(),
            optimizer_status: None,
            vectors_count: None,
            indexed_vectors_count: None,
            points_count: None,
            segments_count: None,
            config: None,
        };
        let debug = format!("{info:?}");
        assert!(debug.contains("CollectionInfo"));
        assert!(debug.contains("red"));
    }

    #[test]
    fn collection_info_zero_counts() {
        let json = json!({
            "status": "green",
            "vectors_count": 0,
            "points_count": 0,
            "segments_count": 0
        });
        let info: CollectionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.vectors_count, Some(0));
        assert_eq!(info.points_count, Some(0));
        assert_eq!(info.segments_count, Some(0));
    }

    // ── Point ──────────────────────────────────────────────────────────

    #[test]
    fn point_serde_skip_none() {
        let p = Point {
            id: json!(42),
            vector: None,
            payload: None,
        };
        let json_str = serde_json::to_string(&p).unwrap();
        assert!(!json_str.contains("vector"));
        assert!(!json_str.contains("payload"));
    }

    #[test]
    fn point_with_data() {
        let p = Point {
            id: json!("abc-123"),
            vector: Some(json!([0.1, 0.2, 0.3])),
            payload: Some(json!({"color": "red"})),
        };
        let json_str = serde_json::to_string(&p).unwrap();
        let back: Point = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, json!("abc-123"));
        assert!(back.vector.is_some());
    }

    #[test]
    fn point_skip_serializing_vector_none() {
        let p = Point {
            id: json!(1),
            vector: None,
            payload: Some(json!({"key": "val"})),
        };
        let val = serde_json::to_value(&p).unwrap();
        assert!(val.get("vector").is_none());
        assert!(val.get("payload").is_some());
    }

    #[test]
    fn point_skip_serializing_payload_none() {
        let p = Point {
            id: json!(1),
            vector: Some(json!([1.0, 2.0])),
            payload: None,
        };
        let val = serde_json::to_value(&p).unwrap();
        assert!(val.get("vector").is_some());
        assert!(val.get("payload").is_none());
    }

    #[test]
    fn point_both_optional_present() {
        let p = Point {
            id: json!(99),
            vector: Some(json!([0.5])),
            payload: Some(json!({"x": 1})),
        };
        let val = serde_json::to_value(&p).unwrap();
        assert!(val.get("vector").is_some());
        assert!(val.get("payload").is_some());
        assert_eq!(val["id"], 99);
    }

    #[test]
    fn point_roundtrip_with_all_fields() {
        let p = Point {
            id: json!({"uuid": "abc-def"}),
            vector: Some(json!([0.1, 0.2, 0.3, 0.4])),
            payload: Some(json!({"category": "test", "score": 0.99})),
        };
        let json_str = serde_json::to_string(&p).unwrap();
        let back: Point = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, json!({"uuid": "abc-def"}));
        assert_eq!(back.vector.unwrap().as_array().unwrap().len(), 4);
        assert_eq!(back.payload.unwrap()["category"], "test");
    }

    #[test]
    fn point_integer_id() {
        let p = Point {
            id: json!(12345),
            vector: None,
            payload: None,
        };
        let val = serde_json::to_value(&p).unwrap();
        assert_eq!(val["id"], 12345);
    }

    #[test]
    fn point_string_id() {
        let p = Point {
            id: json!("string-id-value"),
            vector: None,
            payload: None,
        };
        let val = serde_json::to_value(&p).unwrap();
        assert_eq!(val["id"], "string-id-value");
    }

    #[test]
    fn point_clone() {
        let p = Point {
            id: json!(42),
            vector: Some(json!([1.0])),
            payload: Some(json!({"a": "b"})),
        };
        let cloned = p.clone();
        assert_eq!(cloned.id, json!(42));
        assert_eq!(cloned.vector, Some(json!([1.0])));
        assert_eq!(p.id, json!(42));
    }

    #[test]
    fn point_debug() {
        let p = Point {
            id: json!(7),
            vector: None,
            payload: None,
        };
        let debug = format!("{p:?}");
        assert!(debug.contains("Point"));
    }

    #[test]
    fn point_deserialize_missing_optionals() {
        let json = json!({"id": 42});
        let p: Point = serde_json::from_value(json).unwrap();
        assert_eq!(p.id, json!(42));
        assert!(p.vector.is_none());
        assert!(p.payload.is_none());
    }

    #[test]
    fn point_deserialize_explicit_null_optionals() {
        let json = json!({"id": 1, "vector": null, "payload": null});
        let p: Point = serde_json::from_value(json).unwrap();
        assert!(p.vector.is_none());
        assert!(p.payload.is_none());
    }

    #[test]
    fn point_named_vectors() {
        // Qdrant supports named vectors as an object
        let p = Point {
            id: json!(1),
            vector: Some(json!({"text": [0.1, 0.2], "image": [0.3, 0.4, 0.5]})),
            payload: None,
        };
        let val = serde_json::to_value(&p).unwrap();
        let back: Point = serde_json::from_value(val).unwrap();
        let vec_val = back.vector.unwrap();
        assert!(vec_val.get("text").is_some());
        assert!(vec_val.get("image").is_some());
    }

    // ── SearchResult ───────────────────────────────────────────────────

    #[test]
    fn search_result_serde() {
        let json = json!({
            "id": 1,
            "score": 0.95,
            "version": 3
        });
        let sr: SearchResult = serde_json::from_value(json).unwrap();
        assert!((sr.score - 0.95).abs() < f64::EPSILON);
        assert_eq!(sr.version, Some(3));
        assert!(sr.payload.is_none());
    }

    #[test]
    fn search_result_all_optionals_missing() {
        let json = json!({"id": 1, "score": 0.5});
        let sr: SearchResult = serde_json::from_value(json).unwrap();
        assert!(sr.version.is_none());
        assert!(sr.payload.is_none());
        assert!(sr.vector.is_none());
    }

    #[test]
    fn search_result_all_fields_present() {
        let json = json!({
            "id": "abc",
            "score": 0.99,
            "version": 7,
            "payload": {"key": "value"},
            "vector": [0.1, 0.2, 0.3]
        });
        let sr: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.id, json!("abc"));
        assert!((sr.score - 0.99).abs() < f64::EPSILON);
        assert_eq!(sr.version, Some(7));
        assert!(sr.payload.is_some());
        assert!(sr.vector.is_some());
    }

    #[test]
    fn search_result_skip_serializing_none_fields() {
        let sr = SearchResult {
            id: json!(1),
            version: None,
            score: 0.8,
            payload: None,
            vector: None,
        };
        let val = serde_json::to_value(&sr).unwrap();
        assert!(val.get("payload").is_none());
        assert!(val.get("vector").is_none());
        // version is not skip_serializing_if, so it should be present as null
        assert!(val.get("version").is_some());
    }

    #[test]
    fn search_result_roundtrip() {
        let sr = SearchResult {
            id: json!(42),
            version: Some(5),
            score: 0.777,
            payload: Some(json!({"data": true})),
            vector: Some(json!([0.5, 0.6])),
        };
        let json_str = serde_json::to_string(&sr).unwrap();
        let back: SearchResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, json!(42));
        assert!((back.score - 0.777).abs() < f64::EPSILON);
        assert_eq!(back.version, Some(5));
    }

    #[test]
    fn search_result_clone() {
        let sr = SearchResult {
            id: json!(1),
            version: Some(1),
            score: 0.5,
            payload: None,
            vector: None,
        };
        let cloned = sr.clone();
        assert_eq!(cloned.id, json!(1));
        assert!((cloned.score - 0.5).abs() < f64::EPSILON);
        assert_eq!(sr.version, Some(1));
    }

    #[test]
    fn search_result_debug() {
        let sr = SearchResult {
            id: json!(1),
            version: None,
            score: 0.1,
            payload: None,
            vector: None,
        };
        let debug = format!("{sr:?}");
        assert!(debug.contains("SearchResult"));
    }

    #[test]
    fn search_result_negative_score() {
        let json = json!({"id": 1, "score": -0.5});
        let sr: SearchResult = serde_json::from_value(json).unwrap();
        assert!((sr.score - (-0.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn search_result_zero_score() {
        let json = json!({"id": 1, "score": 0.0});
        let sr: SearchResult = serde_json::from_value(json).unwrap();
        assert!((sr.score).abs() < f64::EPSILON);
    }

    // ── ScrollResult ───────────────────────────────────────────────────

    #[test]
    fn scroll_result_serde() {
        let json = json!({"points": [{"id": 1}], "next_page_offset": 42});
        let sr: ScrollResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.points.len(), 1);
        assert!(sr.next_page_offset.is_some());
    }

    #[test]
    fn scroll_result_no_next_page() {
        let json = json!({"points": [{"id": 1}, {"id": 2}]});
        let sr: ScrollResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.points.len(), 2);
        assert!(sr.next_page_offset.is_none());
    }

    #[test]
    fn scroll_result_empty_points() {
        let json = json!({"points": []});
        let sr: ScrollResult = serde_json::from_value(json).unwrap();
        assert!(sr.points.is_empty());
        assert!(sr.next_page_offset.is_none());
    }

    #[test]
    fn scroll_result_null_next_page_offset() {
        let json = json!({"points": [], "next_page_offset": null});
        let sr: ScrollResult = serde_json::from_value(json).unwrap();
        assert!(sr.next_page_offset.is_none());
    }

    #[test]
    fn scroll_result_string_offset() {
        // Qdrant can use string UUIDs as offsets
        let json = json!({"points": [], "next_page_offset": "abc-def-123"});
        let sr: ScrollResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.next_page_offset, Some(json!("abc-def-123")));
    }

    #[test]
    fn scroll_result_roundtrip() {
        let sr = ScrollResult {
            points: vec![json!({"id": 1}), json!({"id": 2})],
            next_page_offset: Some(json!(3)),
        };
        let val = serde_json::to_value(&sr).unwrap();
        let back: ScrollResult = serde_json::from_value(val).unwrap();
        assert_eq!(back.points.len(), 2);
        assert_eq!(back.next_page_offset, Some(json!(3)));
    }

    #[test]
    fn scroll_result_clone() {
        let sr = ScrollResult {
            points: vec![json!({"id": 1})],
            next_page_offset: Some(json!(99)),
        };
        let cloned = sr.clone();
        assert_eq!(cloned.points.len(), 1);
        assert_eq!(cloned.next_page_offset, Some(json!(99)));
        assert_eq!(sr.points.len(), 1);
    }

    #[test]
    fn scroll_result_debug() {
        let sr = ScrollResult {
            points: vec![],
            next_page_offset: None,
        };
        let debug = format!("{sr:?}");
        assert!(debug.contains("ScrollResult"));
    }

    // ── CountResult ────────────────────────────────────────────────────

    #[test]
    fn count_result_serde() {
        let cr = CountResult { count: 999 };
        let json_str = serde_json::to_string(&cr).unwrap();
        let back: CountResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.count, 999);
    }

    #[test]
    fn count_result_zero() {
        let json = json!({"count": 0});
        let cr: CountResult = serde_json::from_value(json).unwrap();
        assert_eq!(cr.count, 0);
    }

    #[test]
    fn count_result_large_value() {
        let json = json!({"count": 18446744073709551615_u64});
        let cr: CountResult = serde_json::from_value(json).unwrap();
        assert_eq!(cr.count, u64::MAX);
    }

    #[test]
    fn count_result_roundtrip() {
        let cr = CountResult { count: 42 };
        let val = serde_json::to_value(&cr).unwrap();
        let back: CountResult = serde_json::from_value(val).unwrap();
        assert_eq!(back.count, 42);
    }

    #[test]
    fn count_result_clone() {
        let cr = CountResult { count: 10 };
        let cloned = cr.clone();
        assert_eq!(cloned.count, 10);
        assert_eq!(cr.count, 10);
    }

    #[test]
    fn count_result_debug() {
        let cr = CountResult { count: 77 };
        let debug = format!("{cr:?}");
        assert!(debug.contains("CountResult"));
        assert!(debug.contains("77"));
    }

    // ── QdrantResponse ─────────────────────────────────────────────────

    #[test]
    fn qdrant_response_serde() {
        let json = json!({"status": "ok", "result": {"count": 5}, "time": 0.001});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        assert!(resp.time.is_some());
    }

    #[test]
    fn qdrant_response_all_none() {
        let json = json!({});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        assert!(resp.status.is_none());
        assert!(resp.result.is_none());
        assert!(resp.time.is_none());
    }

    #[test]
    fn qdrant_response_null_result() {
        let json = json!({"status": "ok", "result": null, "time": 0.0});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        assert!(resp.result.is_none());
    }

    #[test]
    fn qdrant_response_status_as_object() {
        // Qdrant sometimes returns status as an object
        let json = json!({"status": {"error": "something"}, "result": null});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        assert!(resp.status.is_some());
        let status_val = resp.status.unwrap();
        assert!(status_val.is_object());
    }

    #[test]
    fn qdrant_response_clone() {
        let json = json!({"status": "ok", "result": [1, 2], "time": 0.5});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert!(cloned.time.is_some());
        assert!((cloned.time.unwrap() - 0.5).abs() < f64::EPSILON);
        assert!(resp.status.is_some());
    }

    #[test]
    fn qdrant_response_debug() {
        let json = json!({"status": "ok"});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        let debug = format!("{resp:?}");
        assert!(debug.contains("QdrantResponse"));
    }

    // ── ListCollectionsResponse ────────────────────────────────────────

    #[test]
    fn list_collections_response_serde() {
        let json = json!({
            "status": "ok",
            "result": {"collections": [{"name": "test"}]}
        });
        let resp: ListCollectionsResponse = serde_json::from_value(json).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result.collections.len(), 1);
        assert_eq!(result.collections[0].name, "test");
    }

    #[test]
    fn list_collections_response_empty_collections() {
        let json = json!({
            "status": "ok",
            "result": {"collections": []}
        });
        let resp: ListCollectionsResponse = serde_json::from_value(json).unwrap();
        let result = resp.result.unwrap();
        assert!(result.collections.is_empty());
    }

    #[test]
    fn list_collections_response_no_result() {
        let json = json!({"status": "ok"});
        let resp: ListCollectionsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.result.is_none());
    }

    #[test]
    fn list_collections_response_multiple_collections() {
        let json = json!({
            "status": "ok",
            "result": {
                "collections": [
                    {"name": "alpha"},
                    {"name": "beta"},
                    {"name": "gamma"}
                ]
            }
        });
        let resp: ListCollectionsResponse = serde_json::from_value(json).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result.collections.len(), 3);
        assert_eq!(result.collections[2].name, "gamma");
    }

    #[test]
    fn list_collections_response_clone() {
        let json = json!({
            "status": "ok",
            "result": {"collections": [{"name": "c1"}]}
        });
        let resp: ListCollectionsResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.status, Some("ok".into()));
        assert!(resp.result.is_some());
    }

    #[test]
    fn list_collections_response_debug() {
        let json = json!({"status": "ok", "result": {"collections": []}});
        let resp: ListCollectionsResponse = serde_json::from_value(json).unwrap();
        let debug = format!("{resp:?}");
        assert!(debug.contains("ListCollectionsResponse"));
    }

    // ── ListCollectionsResult ──────────────────────────────────────────

    #[test]
    fn list_collections_result_clone() {
        let result = ListCollectionsResult {
            collections: vec![
                Collection { name: "a".into() },
                Collection { name: "b".into() },
            ],
        };
        let cloned = result.clone();
        assert_eq!(cloned.collections.len(), 2);
        assert_eq!(cloned.collections[0].name, "a");
        assert_eq!(result.collections.len(), 2);
    }

    #[test]
    fn list_collections_result_debug() {
        let result = ListCollectionsResult {
            collections: vec![],
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("ListCollectionsResult"));
    }

    // ── OperationResponse ──────────────────────────────────────────────

    #[test]
    fn operation_response_serde() {
        let json = json!({"status": "ok", "result": true});
        let resp: OperationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status.as_deref(), Some("ok"));
    }

    #[test]
    fn operation_response_no_status() {
        let json = json!({"result": {"operation_id": 1}});
        let resp: OperationResponse = serde_json::from_value(json).unwrap();
        assert!(resp.status.is_none());
        assert!(resp.result.is_some());
    }

    #[test]
    fn operation_response_all_none() {
        let json = json!({});
        let resp: OperationResponse = serde_json::from_value(json).unwrap();
        assert!(resp.status.is_none());
        assert!(resp.result.is_none());
    }

    #[test]
    fn operation_response_clone() {
        let json = json!({"status": "acknowledged", "result": true});
        let resp: OperationResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.status.as_deref(), Some("acknowledged"));
        assert!(resp.result.is_some());
    }

    #[test]
    fn operation_response_debug() {
        let json = json!({"status": "ok"});
        let resp: OperationResponse = serde_json::from_value(json).unwrap();
        let debug = format!("{resp:?}");
        assert!(debug.contains("OperationResponse"));
    }

    // ── OperationReceipt ───────────────────────────────────────────────

    #[test]
    fn operation_receipt_serialize() {
        let receipt = OperationReceipt {
            operation: "upsert".into(),
            effect: "created 10 points".into(),
            resource: "my_collection".into(),
            timestamp: "2026-03-03T00:00:00Z".into(),
        };
        let json_str = serde_json::to_string(&receipt).unwrap();
        assert!(json_str.contains("upsert"));
        assert!(json_str.contains("my_collection"));
    }

    #[test]
    fn operation_receipt_all_fields_serialized() {
        let receipt = OperationReceipt {
            operation: "delete".into(),
            effect: "removed 5 points".into(),
            resource: "test_col".into(),
            timestamp: "2026-01-01T12:00:00Z".into(),
        };
        let val = serde_json::to_value(&receipt).unwrap();
        assert_eq!(val["operation"], "delete");
        assert_eq!(val["effect"], "removed 5 points");
        assert_eq!(val["resource"], "test_col");
        assert_eq!(val["timestamp"], "2026-01-01T12:00:00Z");
    }

    #[test]
    fn operation_receipt_clone() {
        let receipt = OperationReceipt {
            operation: "create_collection".into(),
            effect: "created".into(),
            resource: "new_col".into(),
            timestamp: "2026-03-04T00:00:00Z".into(),
        };
        let cloned = receipt.clone();
        assert_eq!(cloned.operation, "create_collection");
        assert_eq!(cloned.resource, "new_col");
        assert_eq!(receipt.effect, "created");
    }

    #[test]
    fn operation_receipt_debug() {
        let receipt = OperationReceipt {
            operation: "upsert".into(),
            effect: "ok".into(),
            resource: "col".into(),
            timestamp: "now".into(),
        };
        let debug = format!("{receipt:?}");
        assert!(debug.contains("OperationReceipt"));
        assert!(debug.contains("upsert"));
    }

    #[test]
    fn operation_receipt_empty_fields() {
        let receipt = OperationReceipt {
            operation: String::new(),
            effect: String::new(),
            resource: String::new(),
            timestamp: String::new(),
        };
        let val = serde_json::to_value(&receipt).unwrap();
        assert_eq!(val["operation"], "");
        assert_eq!(val["effect"], "");
    }

    // ── Deserialization error cases ────────────────────────────────────

    #[test]
    fn collection_missing_name_fails() {
        let json = json!({});
        let result = serde_json::from_value::<Collection>(json);
        assert!(result.is_err());
    }

    #[test]
    fn collection_info_missing_status_fails() {
        let json = json!({"vectors_count": 10});
        let result = serde_json::from_value::<CollectionInfo>(json);
        assert!(result.is_err());
    }

    #[test]
    fn point_missing_id_fails() {
        let json = json!({"vector": [1.0]});
        let result = serde_json::from_value::<Point>(json);
        assert!(result.is_err());
    }

    #[test]
    fn search_result_missing_score_fails() {
        let json = json!({"id": 1});
        let result = serde_json::from_value::<SearchResult>(json);
        assert!(result.is_err());
    }

    #[test]
    fn search_result_missing_id_fails() {
        let json = json!({"score": 0.5});
        let result = serde_json::from_value::<SearchResult>(json);
        assert!(result.is_err());
    }

    #[test]
    fn scroll_result_missing_points_fails() {
        let json = json!({"next_page_offset": 1});
        let result = serde_json::from_value::<ScrollResult>(json);
        assert!(result.is_err());
    }

    #[test]
    fn count_result_missing_count_fails() {
        let json = json!({});
        let result = serde_json::from_value::<CountResult>(json);
        assert!(result.is_err());
    }

    // ── Additional types tests (2026-03-07) ──────────────────────────────

    #[test]
    fn collection_special_characters_name() {
        let c = Collection {
            name: "test-collection_v2.1".into(),
        };
        let json_str = serde_json::to_string(&c).unwrap();
        let back: Collection = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "test-collection_v2.1");
    }

    #[test]
    fn collection_info_large_counts() {
        let json = json!({
            "status": "green",
            "vectors_count": 999_999_999,
            "indexed_vectors_count": 888_888_888,
            "points_count": 777_777_777,
            "segments_count": 100
        });
        let info: CollectionInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.vectors_count, Some(999_999_999));
        assert_eq!(info.indexed_vectors_count, Some(888_888_888));
        assert_eq!(info.points_count, Some(777_777_777));
    }

    #[test]
    fn collection_info_config_nested_structure() {
        let json = json!({
            "status": "green",
            "config": {
                "params": {
                    "vectors": {"size": 1536, "distance": "Cosine"},
                    "hnsw_config": {"m": 16, "ef_construct": 100}
                }
            }
        });
        let info: CollectionInfo = serde_json::from_value(json).unwrap();
        let config = info.config.unwrap();
        assert_eq!(config["params"]["vectors"]["size"], 1536);
    }

    #[test]
    fn point_empty_payload_object() {
        let p = Point {
            id: json!(1),
            vector: None,
            payload: Some(json!({})),
        };
        let val = serde_json::to_value(&p).unwrap();
        assert!(val.get("payload").is_some());
        assert!(val["payload"].as_object().unwrap().is_empty());
    }

    #[test]
    fn point_high_dimensional_vector() {
        let vec_data: Vec<f64> = (0..768).map(|i| f64::from(i) * 0.001).collect();
        let p = Point {
            id: json!("hd-1"),
            vector: Some(json!(vec_data)),
            payload: None,
        };
        let val = serde_json::to_value(&p).unwrap();
        let back: Point = serde_json::from_value(val).unwrap();
        assert_eq!(back.vector.unwrap().as_array().unwrap().len(), 768);
    }

    #[test]
    fn point_uuid_id() {
        let p = Point {
            id: json!("550e8400-e29b-41d4-a716-446655440000"),
            vector: None,
            payload: None,
        };
        let val = serde_json::to_value(&p).unwrap();
        assert_eq!(val["id"], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn search_result_high_score() {
        let sr = SearchResult {
            id: json!(1),
            version: Some(10),
            score: 1.0,
            payload: None,
            vector: None,
        };
        let json_str = serde_json::to_string(&sr).unwrap();
        let back: SearchResult = serde_json::from_str(&json_str).unwrap();
        assert!((back.score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn search_result_very_small_score() {
        let sr = SearchResult {
            id: json!(99),
            version: None,
            score: 0.00001,
            payload: None,
            vector: None,
        };
        assert!((sr.score - 0.00001).abs() < f64::EPSILON);
    }

    #[test]
    fn scroll_result_many_points() {
        let points: Vec<serde_json::Value> = (0..100).map(|i| json!({"id": i})).collect();
        let sr = ScrollResult {
            points,
            next_page_offset: Some(json!(100)),
        };
        assert_eq!(sr.points.len(), 100);
        assert_eq!(sr.next_page_offset, Some(json!(100)));
    }

    #[test]
    fn scroll_result_integer_offset() {
        let json = json!({"points": [{"id": 1}], "next_page_offset": 42});
        let sr: ScrollResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.next_page_offset, Some(json!(42)));
    }

    #[test]
    fn qdrant_response_with_error_status() {
        let json = json!({"status": {"error": "collection not found"}, "time": 0.001});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        let status = resp.status.unwrap();
        assert_eq!(status["error"], "collection not found");
    }

    #[test]
    fn qdrant_response_status_as_string() {
        let json = json!({"status": "ok", "result": [1, 2, 3]});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status.unwrap().as_str(), Some("ok"));
    }

    #[test]
    fn list_collections_result_debug_with_entries() {
        let result = ListCollectionsResult {
            collections: vec![
                Collection { name: "x".into() },
                Collection { name: "y".into() },
            ],
        };
        let debug = format!("{result:?}");
        assert!(debug.contains('x'));
        assert!(debug.contains('y'));
    }

    #[test]
    fn operation_response_result_object() {
        let json = json!({"status": "ok", "result": {"operation_id": 42, "status": "completed"}});
        let resp: OperationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.result.unwrap()["operation_id"], 42);
    }

    #[test]
    fn operation_receipt_long_timestamp() {
        let receipt = OperationReceipt {
            operation: "upsert".into(),
            effect: "inserted".into(),
            resource: "test_col".into(),
            timestamp: "2026-03-07T12:34:56.789012345Z".into(),
        };
        let val = serde_json::to_value(&receipt).unwrap();
        assert!(val["timestamp"].as_str().unwrap().contains("789012345"));
    }

    #[test]
    fn collection_info_optimizer_status_object() {
        let json = json!({
            "status": "green",
            "optimizer_status": {"status": "ok", "message": "all segments optimized"}
        });
        let info: CollectionInfo = serde_json::from_value(json).unwrap();
        let opt = info.optimizer_status.unwrap();
        assert_eq!(opt["status"], "ok");
    }

    #[test]
    fn point_complex_payload() {
        let p = Point {
            id: json!(1),
            vector: None,
            payload: Some(json!({
                "text": "hello world",
                "tags": ["rust", "ai"],
                "metadata": {"source": "wiki", "page": 42}
            })),
        };
        let val = serde_json::to_value(&p).unwrap();
        let payload = &val["payload"];
        assert_eq!(payload["tags"].as_array().unwrap().len(), 2);
        assert_eq!(payload["metadata"]["page"], 42);
    }

    #[test]
    fn search_result_with_named_vectors() {
        let sr = SearchResult {
            id: json!(1),
            version: Some(1),
            score: 0.85,
            payload: None,
            vector: Some(json!({"text": [0.1, 0.2], "image": [0.3, 0.4]})),
        };
        let val = serde_json::to_value(&sr).unwrap();
        let vec_val = &val["vector"];
        assert!(vec_val.get("text").is_some());
        assert!(vec_val.get("image").is_some());
    }
}
