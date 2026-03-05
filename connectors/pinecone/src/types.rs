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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn index_serde() {
        let idx = Index {
            name: "my-index".into(),
            dimension: 1536,
            metric: "cosine".into(),
            host: Some("my-index-abc.svc.pinecone.io".into()),
            status: Some(IndexStatus {
                ready: Some(true),
                state: Some("Ready".into()),
            }),
            spec: None,
        };
        let json_str = serde_json::to_string(&idx).unwrap();
        let back: Index = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.dimension, 1536);
        assert!(back.status.unwrap().ready.unwrap());
    }

    #[test]
    fn index_stats_defaults() {
        let json = json!({});
        let stats: IndexStats = serde_json::from_value(json).unwrap();
        assert!((stats.index_fullness - 0.0).abs() < f64::EPSILON);
        assert_eq!(stats.total_vector_count, 0);
        assert!(stats.namespaces.is_none());
    }

    #[test]
    fn index_stats_full() {
        let json = json!({
            "namespaces": {"ns1": {"vector_count": 100}},
            "dimension": 768,
            "index_fullness": 0.5,
            "total_vector_count": 100
        });
        let stats: IndexStats = serde_json::from_value(json).unwrap();
        assert_eq!(stats.total_vector_count, 100);
        let ns = stats.namespaces.unwrap();
        assert_eq!(ns["ns1"].vector_count, 100);
    }

    #[test]
    fn vector_serde() {
        let v = Vector {
            id: "vec-1".into(),
            values: Some(vec![0.1, 0.2, 0.3]),
            metadata: Some(json!({"genre": "sci-fi"})),
            sparse_values: None,
        };
        let json_str = serde_json::to_string(&v).unwrap();
        let back: Vector = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.values.unwrap().len(), 3);
    }

    #[test]
    fn sparse_values_serde() {
        let sv = SparseValues {
            indices: vec![0, 3, 7],
            values: vec![0.5, 0.8, 0.1],
        };
        let json_str = serde_json::to_string(&sv).unwrap();
        let back: SparseValues = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.indices.len(), 3);
    }

    #[test]
    fn match_serde() {
        let json = json!({
            "id": "vec-1",
            "score": 0.99,
            "metadata": {"label": "test"}
        });
        let m: Match = serde_json::from_value(json).unwrap();
        assert_eq!(m.id, "vec-1");
        assert!(m.score.unwrap() > 0.98);
    }

    #[test]
    fn query_response_serde() {
        let json = json!({
            "matches": [{"id": "v1", "score": 0.9}],
            "namespace": "default"
        });
        let resp: QueryResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.matches.len(), 1);
        assert_eq!(resp.namespace.as_deref(), Some("default"));
    }

    #[test]
    fn fetch_response_serde() {
        let json = json!({
            "vectors": {"v1": {"id": "v1", "values": [0.1]}},
            "namespace": "ns"
        });
        let resp: FetchResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.vectors.len(), 1);
        assert!(resp.vectors.contains_key("v1"));
    }

    #[test]
    fn upsert_response_default() {
        let json = json!({});
        let resp: UpsertResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.upserted_count, 0);
    }

    #[test]
    fn list_indexes_response_default() {
        let json = json!({});
        let resp: ListIndexesResponse = serde_json::from_value(json).unwrap();
        assert!(resp.indexes.is_empty());
    }

    #[test]
    fn api_error_response_serde() {
        let json = json!({
            "status": 400,
            "error": {"code": "INVALID_ARGUMENT", "message": "Bad vector"},
            "message": "Bad request"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.status, Some(400));
        let detail = err.error.unwrap();
        assert_eq!(detail.code.as_deref(), Some("INVALID_ARGUMENT"));
    }
}
