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
    fn scroll_result_serde() {
        let json = json!({"points": [{"id": 1}], "next_page_offset": 42});
        let sr: ScrollResult = serde_json::from_value(json).unwrap();
        assert_eq!(sr.points.len(), 1);
        assert!(sr.next_page_offset.is_some());
    }

    #[test]
    fn count_result_serde() {
        let cr = CountResult { count: 999 };
        let json_str = serde_json::to_string(&cr).unwrap();
        let back: CountResult = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.count, 999);
    }

    #[test]
    fn qdrant_response_serde() {
        let json = json!({"status": "ok", "result": {"count": 5}, "time": 0.001});
        let resp: QdrantResponse = serde_json::from_value(json).unwrap();
        assert!(resp.time.is_some());
    }

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
    fn operation_response_serde() {
        let json = json!({"status": "ok", "result": true});
        let resp: OperationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.status.as_deref(), Some("ok"));
    }

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
}
