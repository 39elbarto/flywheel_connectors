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

    // ── Index edge cases ───────────────────────────────────────────

    #[test]
    fn index_minimal_fields() {
        let json = json!({
            "name": "idx",
            "dimension": 128,
            "metric": "euclidean"
        });
        let idx: Index = serde_json::from_value(json).unwrap();
        assert_eq!(idx.name, "idx");
        assert_eq!(idx.dimension, 128);
        assert_eq!(idx.metric, "euclidean");
        assert!(idx.host.is_none());
        assert!(idx.status.is_none());
        assert!(idx.spec.is_none());
    }

    #[test]
    fn index_with_spec() {
        let json = json!({
            "name": "my-idx",
            "dimension": 1536,
            "metric": "cosine",
            "spec": {"serverless": {"cloud": "aws", "region": "us-east-1"}}
        });
        let idx: Index = serde_json::from_value(json).unwrap();
        let spec = idx.spec.unwrap();
        assert_eq!(spec["serverless"]["cloud"], "aws");
    }

    #[test]
    fn index_roundtrip() {
        let idx = Index {
            name: "roundtrip".into(),
            dimension: 256,
            metric: "dotproduct".into(),
            host: Some("host.pinecone.io".into()),
            status: Some(IndexStatus {
                ready: Some(false),
                state: Some("Initializing".into()),
            }),
            spec: Some(json!({"pod": {"pods": 1}})),
        };
        let serialized = serde_json::to_string(&idx).unwrap();
        let back: Index = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.name, "roundtrip");
        assert_eq!(back.dimension, 256);
        assert_eq!(back.metric, "dotproduct");
        assert_eq!(back.host.as_deref(), Some("host.pinecone.io"));
        assert!(!back.status.unwrap().ready.unwrap());
    }

    #[test]
    fn index_clone() {
        let idx = Index {
            name: "cloned".into(),
            dimension: 512,
            metric: "cosine".into(),
            host: None,
            status: None,
            spec: None,
        };
        let cloned = idx.clone();
        assert_eq!(cloned.name, "cloned");
        assert_eq!(cloned.dimension, 512);
        // use original to prove clone independence
        assert_eq!(idx.name, "cloned");
    }

    #[test]
    fn index_debug() {
        let idx = Index {
            name: "dbg".into(),
            dimension: 64,
            metric: "cosine".into(),
            host: None,
            status: None,
            spec: None,
        };
        let debug = format!("{idx:?}");
        assert!(debug.contains("dbg"), "got: {debug}");
        assert!(debug.contains("64"), "got: {debug}");
    }

    // ── IndexStatus edge cases ─────────────────────────────────────

    #[test]
    fn index_status_all_none() {
        let json = json!({});
        let status: IndexStatus = serde_json::from_value(json).unwrap();
        assert!(status.ready.is_none());
        assert!(status.state.is_none());
    }

    #[test]
    fn index_status_ready_false() {
        let json = json!({"ready": false, "state": "ScalingDown"});
        let status: IndexStatus = serde_json::from_value(json).unwrap();
        assert_eq!(status.ready, Some(false));
        assert_eq!(status.state.as_deref(), Some("ScalingDown"));
    }

    #[test]
    fn index_status_clone_debug() {
        let status = IndexStatus {
            ready: Some(true),
            state: Some("Ready".into()),
        };
        let cloned = status.clone();
        assert_eq!(cloned.ready, Some(true));
        let debug = format!("{status:?}");
        assert!(debug.contains("Ready"), "got: {debug}");
    }

    // ── IndexStats edge cases ──────────────────────────────────────

    #[test]
    fn index_stats_empty_namespaces_map() {
        let json = json!({"namespaces": {}});
        let stats: IndexStats = serde_json::from_value(json).unwrap();
        assert!(stats.namespaces.unwrap().is_empty());
    }

    #[test]
    fn index_stats_multiple_namespaces() {
        let json = json!({
            "namespaces": {
                "": {"vector_count": 100},
                "ns-a": {"vector_count": 200},
                "ns-b": {"vector_count": 300}
            },
            "dimension": 1536,
            "index_fullness": 0.75,
            "total_vector_count": 600
        });
        let stats: IndexStats = serde_json::from_value(json).unwrap();
        let ns = stats.namespaces.unwrap();
        assert_eq!(ns.len(), 3);
        assert_eq!(ns[""].vector_count, 100);
        assert_eq!(ns["ns-a"].vector_count, 200);
        assert_eq!(ns["ns-b"].vector_count, 300);
        assert_eq!(stats.dimension, Some(1536));
        assert!((stats.index_fullness - 0.75).abs() < f64::EPSILON);
        assert_eq!(stats.total_vector_count, 600);
    }

    #[test]
    fn index_stats_clone() {
        let stats = IndexStats {
            namespaces: Some(HashMap::new()),
            dimension: Some(128),
            index_fullness: 0.0,
            total_vector_count: 0,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.dimension, Some(128));
        assert_eq!(stats.total_vector_count, 0);
    }

    #[test]
    fn index_stats_roundtrip() {
        let mut ns = HashMap::new();
        ns.insert("test".to_string(), NamespaceStats { vector_count: 42 });
        let stats = IndexStats {
            namespaces: Some(ns),
            dimension: Some(768),
            index_fullness: 0.33,
            total_vector_count: 42,
        };
        let json_str = serde_json::to_string(&stats).unwrap();
        let back: IndexStats = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.total_vector_count, 42);
        assert_eq!(back.namespaces.unwrap()["test"].vector_count, 42);
    }

    // ── NamespaceStats ─────────────────────────────────────────────

    #[test]
    fn namespace_stats_default_zero() {
        let json = json!({});
        let ns: NamespaceStats = serde_json::from_value(json).unwrap();
        assert_eq!(ns.vector_count, 0);
    }

    #[test]
    fn namespace_stats_clone_debug() {
        let ns = NamespaceStats { vector_count: 999 };
        let cloned = ns.clone();
        assert_eq!(cloned.vector_count, 999);
        let debug = format!("{ns:?}");
        assert!(debug.contains("999"), "got: {debug}");
    }

    // ── Vector edge cases ──────────────────────────────────────────

    #[test]
    fn vector_minimal() {
        let json = json!({"id": "v1"});
        let v: Vector = serde_json::from_value(json).unwrap();
        assert_eq!(v.id, "v1");
        assert!(v.values.is_none());
        assert!(v.metadata.is_none());
        assert!(v.sparse_values.is_none());
    }

    #[test]
    fn vector_with_sparse_values() {
        let v = Vector {
            id: "sparse-1".into(),
            values: None,
            metadata: None,
            sparse_values: Some(SparseValues {
                indices: vec![1, 5, 10],
                values: vec![0.1, 0.5, 0.9],
            }),
        };
        let json_str = serde_json::to_string(&v).unwrap();
        let back: Vector = serde_json::from_str(&json_str).unwrap();
        let sv = back.sparse_values.unwrap();
        assert_eq!(sv.indices, vec![1, 5, 10]);
        assert_eq!(sv.values.len(), 3);
    }

    #[test]
    fn vector_with_metadata_complex() {
        let v = Vector {
            id: "meta-1".into(),
            values: Some(vec![0.0]),
            metadata: Some(json!({
                "tags": ["a", "b"],
                "nested": {"key": 123},
                "flag": true
            })),
            sparse_values: None,
        };
        let json_str = serde_json::to_string(&v).unwrap();
        let back: Vector = serde_json::from_str(&json_str).unwrap();
        let meta = back.metadata.unwrap();
        assert_eq!(meta["tags"][0], "a");
        assert_eq!(meta["nested"]["key"], 123);
        assert_eq!(meta["flag"], true);
    }

    #[test]
    fn vector_empty_values_array() {
        let json = json!({"id": "empty", "values": []});
        let v: Vector = serde_json::from_value(json).unwrap();
        assert!(v.values.unwrap().is_empty());
    }

    #[test]
    fn vector_clone_debug() {
        let v = Vector {
            id: "clone-me".into(),
            values: Some(vec![1.0, 2.0]),
            metadata: None,
            sparse_values: None,
        };
        let cloned = v.clone();
        assert_eq!(cloned.id, "clone-me");
        assert_eq!(cloned.values.unwrap(), vec![1.0, 2.0]);
        let debug = format!("{v:?}");
        assert!(debug.contains("clone-me"), "got: {debug}");
    }

    #[test]
    fn vector_roundtrip_all_fields() {
        let v = Vector {
            id: "full".into(),
            values: Some(vec![0.1, 0.2, 0.3]),
            metadata: Some(json!({"k": "v"})),
            sparse_values: Some(SparseValues {
                indices: vec![0],
                values: vec![1.0],
            }),
        };
        let json_str = serde_json::to_string(&v).unwrap();
        let back: Vector = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, "full");
        assert_eq!(back.values.unwrap().len(), 3);
        assert_eq!(back.metadata.unwrap()["k"], "v");
        assert_eq!(back.sparse_values.unwrap().indices, vec![0]);
    }

    // ── SparseValues edge cases ────────────────────────────────────

    #[test]
    fn sparse_values_empty() {
        let sv = SparseValues {
            indices: vec![],
            values: vec![],
        };
        let json_str = serde_json::to_string(&sv).unwrap();
        let back: SparseValues = serde_json::from_str(&json_str).unwrap();
        assert!(back.indices.is_empty());
        assert!(back.values.is_empty());
    }

    #[test]
    fn sparse_values_clone_debug() {
        let sv = SparseValues {
            indices: vec![42],
            values: vec![0.7],
        };
        let cloned = sv.clone();
        assert_eq!(cloned.indices, vec![42]);
        let debug = format!("{sv:?}");
        assert!(debug.contains("42"), "got: {debug}");
    }

    // ── Match edge cases ───────────────────────────────────────────

    #[test]
    fn match_minimal() {
        let json = json!({"id": "m1"});
        let m: Match = serde_json::from_value(json).unwrap();
        assert_eq!(m.id, "m1");
        assert!(m.score.is_none());
        assert!(m.values.is_none());
        assert!(m.metadata.is_none());
        assert!(m.sparse_values.is_none());
    }

    #[test]
    fn match_with_all_fields() {
        let json = json!({
            "id": "m-full",
            "score": 0.999,
            "values": [0.1, 0.2],
            "metadata": {"type": "doc"},
            "sparse_values": {"indices": [3], "values": [0.5]}
        });
        let m: Match = serde_json::from_value(json).unwrap();
        assert_eq!(m.id, "m-full");
        assert!((m.score.unwrap() - 0.999).abs() < 0.001);
        assert_eq!(m.values.unwrap().len(), 2);
        assert_eq!(m.metadata.unwrap()["type"], "doc");
        assert_eq!(m.sparse_values.unwrap().indices, vec![3]);
    }

    #[test]
    fn match_clone_debug() {
        let m = Match {
            id: "clonable".into(),
            score: Some(0.5),
            values: None,
            metadata: None,
            sparse_values: None,
        };
        let cloned = m.clone();
        assert_eq!(cloned.id, "clonable");
        let debug = format!("{m:?}");
        assert!(debug.contains("clonable"), "got: {debug}");
    }

    #[test]
    fn match_roundtrip() {
        let m = Match {
            id: "rt".into(),
            score: Some(0.75),
            values: Some(vec![1.0]),
            metadata: Some(json!(null)),
            sparse_values: None,
        };
        let json_str = serde_json::to_string(&m).unwrap();
        let back: Match = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.id, "rt");
        assert!((back.score.unwrap() - 0.75).abs() < f64::EPSILON);
    }

    // ── QueryResponse edge cases ───────────────────────────────────

    #[test]
    fn query_response_empty_matches() {
        let json = json!({"matches": []});
        let resp: QueryResponse = serde_json::from_value(json).unwrap();
        assert!(resp.matches.is_empty());
        assert!(resp.namespace.is_none());
    }

    #[test]
    fn query_response_clone_debug() {
        let resp = QueryResponse {
            matches: vec![Match {
                id: "a".into(),
                score: Some(1.0),
                values: None,
                metadata: None,
                sparse_values: None,
            }],
            namespace: Some("ns1".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.matches.len(), 1);
        assert_eq!(cloned.namespace.as_deref(), Some("ns1"));
        let debug = format!("{resp:?}");
        assert!(debug.contains("QueryResponse"), "got: {debug}");
    }

    #[test]
    fn query_response_roundtrip() {
        let resp = QueryResponse {
            matches: vec![
                Match {
                    id: "v1".into(),
                    score: Some(0.9),
                    values: None,
                    metadata: None,
                    sparse_values: None,
                },
                Match {
                    id: "v2".into(),
                    score: Some(0.8),
                    values: None,
                    metadata: None,
                    sparse_values: None,
                },
            ],
            namespace: Some("default".into()),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: QueryResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.matches.len(), 2);
        assert_eq!(back.matches[0].id, "v1");
    }

    // ── FetchResponse edge cases ───────────────────────────────────

    #[test]
    fn fetch_response_empty_vectors() {
        let json = json!({"vectors": {}});
        let resp: FetchResponse = serde_json::from_value(json).unwrap();
        assert!(resp.vectors.is_empty());
        assert!(resp.namespace.is_none());
    }

    #[test]
    fn fetch_response_clone_debug() {
        let mut vectors = HashMap::new();
        vectors.insert(
            "v1".to_string(),
            Vector {
                id: "v1".into(),
                values: Some(vec![0.5]),
                metadata: None,
                sparse_values: None,
            },
        );
        let resp = FetchResponse {
            vectors,
            namespace: Some("test".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.vectors.len(), 1);
        let debug = format!("{resp:?}");
        assert!(debug.contains("FetchResponse"), "got: {debug}");
    }

    #[test]
    fn fetch_response_roundtrip() {
        let mut vectors = HashMap::new();
        vectors.insert(
            "k1".to_string(),
            Vector {
                id: "k1".into(),
                values: Some(vec![1.0, 2.0]),
                metadata: Some(json!({"a": 1})),
                sparse_values: None,
            },
        );
        let resp = FetchResponse {
            vectors,
            namespace: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: FetchResponse = serde_json::from_str(&json_str).unwrap();
        assert!(back.vectors.contains_key("k1"));
        assert!(back.namespace.is_none());
    }

    // ── UpsertResponse edge cases ──────────────────────────────────

    #[test]
    fn upsert_response_with_count() {
        let json = json!({"upserted_count": 42});
        let resp: UpsertResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.upserted_count, 42);
    }

    #[test]
    fn upsert_response_clone_debug() {
        let resp = UpsertResponse { upserted_count: 10 };
        let cloned = resp.clone();
        assert_eq!(cloned.upserted_count, 10);
        let debug = format!("{resp:?}");
        assert!(debug.contains("10"), "got: {debug}");
    }

    #[test]
    fn upsert_response_roundtrip() {
        let resp = UpsertResponse {
            upserted_count: 100,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: UpsertResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.upserted_count, 100);
    }

    // ── ListIndexesResponse edge cases ─────────────────────────────

    #[test]
    fn list_indexes_response_with_indexes() {
        let json = json!({
            "indexes": [
                {"name": "a", "dimension": 100, "metric": "cosine"},
                {"name": "b", "dimension": 200, "metric": "euclidean"}
            ]
        });
        let resp: ListIndexesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.indexes.len(), 2);
        assert_eq!(resp.indexes[0].name, "a");
        assert_eq!(resp.indexes[1].dimension, 200);
    }

    #[test]
    fn list_indexes_response_clone_debug() {
        let resp = ListIndexesResponse {
            indexes: vec![Index {
                name: "test".into(),
                dimension: 64,
                metric: "cosine".into(),
                host: None,
                status: None,
                spec: None,
            }],
        };
        let cloned = resp.clone();
        assert_eq!(cloned.indexes.len(), 1);
        let debug = format!("{resp:?}");
        assert!(debug.contains("ListIndexesResponse"), "got: {debug}");
    }

    #[test]
    fn list_indexes_response_roundtrip() {
        let resp = ListIndexesResponse {
            indexes: vec![Index {
                name: "rt".into(),
                dimension: 768,
                metric: "dotproduct".into(),
                host: Some("h.io".into()),
                status: None,
                spec: None,
            }],
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        let back: ListIndexesResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.indexes.len(), 1);
        assert_eq!(back.indexes[0].name, "rt");
    }

    // ── ApiErrorResponse edge cases ────────────────────────────────

    #[test]
    fn api_error_response_all_none() {
        let json = json!({});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.status.is_none());
        assert!(err.error.is_none());
        assert!(err.message.is_none());
    }

    #[test]
    fn api_error_response_only_message() {
        let json = json!({"message": "Something went wrong"});
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.status.is_none());
        assert!(err.error.is_none());
        assert_eq!(err.message.as_deref(), Some("Something went wrong"));
    }

    #[test]
    fn api_error_response_clone_debug() {
        let err = ApiErrorResponse {
            status: Some(500),
            error: Some(ApiErrorDetail {
                code: Some("INTERNAL".into()),
                message: Some("oops".into()),
            }),
            message: None,
        };
        let cloned = err.clone();
        assert_eq!(cloned.status, Some(500));
        let debug = format!("{err:?}");
        assert!(debug.contains("INTERNAL"), "got: {debug}");
    }

    // ── ApiErrorDetail edge cases ──────────────────────────────────

    #[test]
    fn api_error_detail_all_none() {
        let json = json!({});
        let detail: ApiErrorDetail = serde_json::from_value(json).unwrap();
        assert!(detail.code.is_none());
        assert!(detail.message.is_none());
    }

    #[test]
    fn api_error_detail_clone_debug() {
        let detail = ApiErrorDetail {
            code: Some("QUOTA_EXCEEDED".into()),
            message: Some("Rate limit hit".into()),
        };
        let cloned = detail.clone();
        assert_eq!(cloned.code.as_deref(), Some("QUOTA_EXCEEDED"));
        let debug = format!("{detail:?}");
        assert!(debug.contains("QUOTA_EXCEEDED"), "got: {debug}");
    }

    // ── Deserialize unknown fields tolerance ───────────────────────

    #[test]
    fn index_ignores_unknown_fields() {
        let json = json!({
            "name": "idx",
            "dimension": 128,
            "metric": "cosine",
            "unknown_field": "surprise",
            "another": 42
        });
        // serde default allows unknown fields; verify no error
        let idx: Index = serde_json::from_value(json).unwrap();
        assert_eq!(idx.name, "idx");
    }

    #[test]
    fn query_response_ignores_extra_fields() {
        let json = json!({
            "matches": [],
            "namespace": "ns",
            "usage": {"read_units": 5}
        });
        let resp: QueryResponse = serde_json::from_value(json).unwrap();
        assert!(resp.matches.is_empty());
        assert_eq!(resp.namespace.as_deref(), Some("ns"));
    }

    #[test]
    fn upsert_response_ignores_extra_fields() {
        let json = json!({
            "upserted_count": 3,
            "extra": "ignored"
        });
        let resp: UpsertResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.upserted_count, 3);
    }

    // ── Serialize skip_serializing_if / defaults ───────────────────

    #[test]
    fn index_stats_serializes_zero_defaults() {
        let stats = IndexStats {
            namespaces: None,
            dimension: None,
            index_fullness: 0.0,
            total_vector_count: 0,
        };
        let json_str = serde_json::to_string(&stats).unwrap();
        // Default fields should still be serialized (no skip_serializing_if on them)
        assert!(json_str.contains("\"index_fullness\""), "got: {json_str}");
        assert!(
            json_str.contains("\"total_vector_count\""),
            "got: {json_str}"
        );
    }

    #[test]
    fn namespace_stats_serializes_zero_count() {
        let ns = NamespaceStats { vector_count: 0 };
        let json_str = serde_json::to_string(&ns).unwrap();
        assert!(json_str.contains("\"vector_count\":0"), "got: {json_str}");
    }

    #[test]
    fn vector_serializes_none_as_null() {
        let v = Vector {
            id: "v".into(),
            values: None,
            metadata: None,
            sparse_values: None,
        };
        let val: serde_json::Value = serde_json::to_value(&v).unwrap();
        // None fields serialize as null (not skipped, since no skip_serializing_if)
        assert!(val.get("values").is_some());
        assert!(val["values"].is_null());
    }

    #[test]
    fn match_serializes_none_score() {
        let m = Match {
            id: "m".into(),
            score: None,
            values: None,
            metadata: None,
            sparse_values: None,
        };
        let val: serde_json::Value = serde_json::to_value(&m).unwrap();
        assert!(val["score"].is_null());
    }

    // ── Clone with drop(original) pattern ───────────────────────────────

    #[test]
    fn index_clone_drop_original() {
        let original = Index {
            name: "drop-idx".into(),
            dimension: 768,
            metric: "cosine".into(),
            host: Some("host.io".into()),
            status: Some(IndexStatus {
                ready: Some(true),
                state: Some("Ready".into()),
            }),
            spec: Some(json!({"pod": {"pods": 2}})),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.name, "drop-idx");
        assert_eq!(cloned.dimension, 768);
        assert!(cloned.status.unwrap().ready.unwrap());
    }

    #[test]
    fn index_status_clone_drop_original() {
        let original = IndexStatus {
            ready: Some(false),
            state: Some("ScalingUp".into()),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.ready, Some(false));
        assert_eq!(cloned.state.as_deref(), Some("ScalingUp"));
    }

    #[test]
    fn index_stats_clone_drop_original() {
        let mut ns = HashMap::new();
        ns.insert("ns1".to_string(), NamespaceStats { vector_count: 500 });
        let original = IndexStats {
            namespaces: Some(ns),
            dimension: Some(256),
            index_fullness: 0.42,
            total_vector_count: 500,
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.total_vector_count, 500);
        assert_eq!(cloned.namespaces.unwrap()["ns1"].vector_count, 500);
    }

    #[test]
    fn namespace_stats_clone_preserves_fields() {
        let original = NamespaceStats { vector_count: 1234 };
        let cloned = original.clone();
        assert_eq!(original.vector_count, cloned.vector_count);
        assert_eq!(cloned.vector_count, 1234);
    }

    #[test]
    fn vector_clone_drop_original() {
        let original = Vector {
            id: "drop-v".into(),
            values: Some(vec![0.1, 0.2, 0.3]),
            metadata: Some(json!({"key": "val"})),
            sparse_values: Some(SparseValues {
                indices: vec![0, 5],
                values: vec![0.5, 0.9],
            }),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.id, "drop-v");
        assert_eq!(cloned.values.unwrap().len(), 3);
        assert_eq!(cloned.sparse_values.unwrap().indices.len(), 2);
    }

    #[test]
    fn sparse_values_clone_drop_original() {
        let original = SparseValues {
            indices: vec![1, 2, 3],
            values: vec![0.1, 0.2, 0.3],
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.indices, vec![1, 2, 3]);
        assert_eq!(cloned.values.len(), 3);
    }

    #[test]
    fn match_clone_drop_original() {
        let original = Match {
            id: "drop-m".into(),
            score: Some(0.99),
            values: Some(vec![1.0]),
            metadata: Some(json!({"tag": "test"})),
            sparse_values: None,
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.id, "drop-m");
        assert!((cloned.score.unwrap() - 0.99).abs() < 0.001);
    }

    #[test]
    fn query_response_clone_drop_original() {
        let original = QueryResponse {
            matches: vec![Match {
                id: "m1".into(),
                score: Some(0.8),
                values: None,
                metadata: None,
                sparse_values: None,
            }],
            namespace: Some("drop-ns".into()),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.matches.len(), 1);
        assert_eq!(cloned.namespace.as_deref(), Some("drop-ns"));
    }

    #[test]
    fn fetch_response_clone_drop_original() {
        let mut vectors = HashMap::new();
        vectors.insert(
            "v1".to_string(),
            Vector {
                id: "v1".into(),
                values: Some(vec![0.5]),
                metadata: None,
                sparse_values: None,
            },
        );
        let original = FetchResponse {
            vectors,
            namespace: Some("drop-ns".into()),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.vectors.len(), 1);
    }

    #[test]
    fn upsert_response_clone_preserves_fields() {
        let original = UpsertResponse { upserted_count: 42 };
        let cloned = original.clone();
        assert_eq!(original.upserted_count, cloned.upserted_count);
        assert_eq!(cloned.upserted_count, 42);
    }

    #[test]
    fn list_indexes_response_clone_drop_original() {
        let original = ListIndexesResponse {
            indexes: vec![Index {
                name: "drop-list".into(),
                dimension: 64,
                metric: "cosine".into(),
                host: None,
                status: None,
                spec: None,
            }],
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.indexes.len(), 1);
        assert_eq!(cloned.indexes[0].name, "drop-list");
    }

    #[test]
    fn api_error_response_clone_drop_original() {
        let original = ApiErrorResponse {
            status: Some(400),
            error: Some(ApiErrorDetail {
                code: Some("INVALID".into()),
                message: Some("bad input".into()),
            }),
            message: Some("Bad request".into()),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.status, Some(400));
        assert_eq!(cloned.error.unwrap().code.as_deref(), Some("INVALID"));
    }

    #[test]
    fn api_error_detail_clone_drop_original() {
        let original = ApiErrorDetail {
            code: Some("EXCEEDED".into()),
            message: Some("Limit hit".into()),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.code.as_deref(), Some("EXCEEDED"));
        assert_eq!(cloned.message.as_deref(), Some("Limit hit"));
    }

    // ── Additional serde edge cases ─────────────────────────────────────

    #[test]
    fn index_missing_required_name_fails() {
        let json = json!({"dimension": 128, "metric": "cosine"});
        assert!(serde_json::from_value::<Index>(json).is_err());
    }

    #[test]
    fn index_missing_required_dimension_fails() {
        let json = json!({"name": "idx", "metric": "cosine"});
        assert!(serde_json::from_value::<Index>(json).is_err());
    }

    #[test]
    fn index_missing_required_metric_fails() {
        let json = json!({"name": "idx", "dimension": 128});
        assert!(serde_json::from_value::<Index>(json).is_err());
    }

    #[test]
    fn vector_missing_required_id_fails() {
        let json = json!({"values": [0.1, 0.2]});
        assert!(serde_json::from_value::<Vector>(json).is_err());
    }

    #[test]
    fn match_missing_required_id_fails() {
        let json = json!({"score": 0.9});
        assert!(serde_json::from_value::<Match>(json).is_err());
    }

    #[test]
    fn sparse_values_missing_required_fields_fails() {
        let json = json!({"indices": [1, 2]});
        assert!(serde_json::from_value::<SparseValues>(json).is_err());
    }

    #[test]
    fn sparse_values_only_values_fails() {
        let json = json!({"values": [0.1, 0.2]});
        assert!(serde_json::from_value::<SparseValues>(json).is_err());
    }

    #[test]
    fn namespace_stats_roundtrip() {
        let ns = NamespaceStats { vector_count: 999 };
        let json_str = serde_json::to_string(&ns).unwrap();
        let back: NamespaceStats = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.vector_count, 999);
    }

    #[test]
    fn match_score_negative() {
        let json = json!({"id": "neg", "score": -0.5});
        let m: Match = serde_json::from_value(json).unwrap();
        assert!((m.score.unwrap() - (-0.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn match_score_zero() {
        let json = json!({"id": "zero", "score": 0.0});
        let m: Match = serde_json::from_value(json).unwrap();
        assert!((m.score.unwrap()).abs() < f64::EPSILON);
    }
}
