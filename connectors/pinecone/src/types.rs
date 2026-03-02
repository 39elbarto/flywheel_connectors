//! Pinecone API types.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A Pinecone index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub name: String,
    pub dimension: u32,
    pub metric: String,
    pub host: Option<String>,
    pub status: Option<IndexStatus>,
    pub spec: Option<serde_json::Value>,
}

/// Index status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStatus {
    pub ready: Option<bool>,
    pub state: Option<String>,
}

/// Index statistics response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub namespaces: Option<HashMap<String, NamespaceStats>>,
    pub dimension: Option<u32>,
    #[serde(default)]
    pub index_fullness: f64,
    #[serde(default)]
    pub total_vector_count: u64,
}

/// Per-namespace statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceStats {
    #[serde(default)]
    pub vector_count: u64,
}

/// A vector for upsert/fetch operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector {
    pub id: String,
    pub values: Option<Vec<f32>>,
    pub metadata: Option<serde_json::Value>,
    pub sparse_values: Option<SparseValues>,
}

/// Sparse vector values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseValues {
    pub indices: Vec<u32>,
    pub values: Vec<f32>,
}

/// A query match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub id: String,
    pub score: Option<f64>,
    pub values: Option<Vec<f32>>,
    pub metadata: Option<serde_json::Value>,
    pub sparse_values: Option<SparseValues>,
}

/// Response from a query operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub matches: Vec<Match>,
    pub namespace: Option<String>,
}

/// Response from a fetch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    pub vectors: HashMap<String, Vector>,
    pub namespace: Option<String>,
}

/// Response from an upsert operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertResponse {
    #[serde(default)]
    pub upserted_count: u64,
}

/// List indexes response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListIndexesResponse {
    #[serde(default)]
    pub indexes: Vec<Index>,
}

/// Pinecone API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub status: Option<u16>,
    pub error: Option<ApiErrorDetail>,
    pub message: Option<String>,
}

/// Pinecone error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorDetail {
    pub code: Option<String>,
    pub message: Option<String>,
}
