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
