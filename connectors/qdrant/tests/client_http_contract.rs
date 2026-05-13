use fcp_qdrant::{client::QdrantClient, error::QdrantError};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[fcp_async_core::test]
async fn client_lists_collections() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": {
                "collections": [
                    { "name": "docs" },
                    { "name": "images" }
                ]
            },
            "time": 0.001
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let result = client.list_collections().await.unwrap();
    assert_eq!(result.collections.len(), 2);
    assert_eq!(result.collections[0].name, "docs");
    assert_eq!(result.collections[1].name, "images");
}

#[fcp_async_core::test]
async fn client_reads_collection_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/collections/docs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": {
                "status": "green",
                "vectors_count": 1000,
                "points_count": 500,
                "segments_count": 2,
                "config": { "params": { "vectors": { "size": 384, "distance": "Cosine" } } }
            },
            "time": 0.002
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let info = client.collection_info("docs").await.unwrap();
    assert_eq!(info.status, "green");
    assert_eq!(info.vectors_count, Some(1000));
    assert_eq!(info.points_count, Some(500));
}

#[fcp_async_core::test]
async fn client_creates_collection() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/collections/docs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": { "status": "acknowledged" },
            "time": 0.01
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let body = json!({
        "vectors": { "size": 3, "distance": "Cosine" }
    });
    let result = client.create_collection("docs", &body).await.unwrap();
    assert_eq!(result["status"], "ok");
}

#[fcp_async_core::test]
async fn client_deletes_collection() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/collections/docs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": { "status": "completed" },
            "time": 0.01
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();
    let result = client.delete_collection("docs").await.unwrap();
    assert_eq!(result["status"], "ok");
}

#[fcp_async_core::test]
async fn client_searches_points() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": [
                { "id": 1, "version": 1, "score": 0.95, "payload": { "text": "hello" } },
                { "id": 2, "version": 1, "score": 0.85, "payload": { "text": "world" } }
            ],
            "time": 0.01
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let body = json!({
        "vector": [0.1, 0.2, 0.3],
        "limit": 10,
        "with_payload": true
    });
    let result = client.search("docs", &body).await.unwrap();
    assert_eq!(result.len(), 2);
}

#[fcp_async_core::test]
async fn client_queries_points_from_object_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": {
                "points": [
                    { "id": 1, "score": 0.92, "payload": { "text": "hello" } },
                    { "id": 2, "score": 0.88, "payload": { "text": "world" } }
                ]
            },
            "time": 0.01
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();
    let body = json!({
        "query": [0.1, 0.2, 0.3],
        "limit": 2,
        "with_payload": true
    });
    let result = client.query_points("docs", &body).await.unwrap();
    assert_eq!(result.len(), 2);
}

#[fcp_async_core::test]
async fn client_queries_points_from_array_result() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": [
                { "id": 11, "score": 0.91 },
                { "id": 12, "score": 0.84 }
            ],
            "time": 0.01
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();
    let body = json!({
        "query": [0.1, 0.2, 0.3],
        "limit": 2
    });
    let result = client.query_points("docs", &body).await.unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0]["id"], 11);
}

#[fcp_async_core::test]
async fn client_batches_query_points() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points/query/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": [
                { "points": [{ "id": 1, "score": 0.9 }] },
                { "points": [{ "id": 2, "score": 0.8 }] }
            ],
            "time": 0.02
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();
    let queries = vec![
        json!({ "query": [0.1, 0.2, 0.3], "limit": 1 }),
        json!({ "query": [0.4, 0.5, 0.6], "limit": 1 }),
    ];
    let result = client.batch_query_points("docs", &queries).await.unwrap();
    assert_eq!(result.len(), 2);
}

#[fcp_async_core::test]
async fn client_gets_points() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": [
                { "id": 1, "payload": { "text": "hello" } },
                { "id": 2, "payload": { "text": "world" } }
            ],
            "time": 0.005
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let body = json!({ "ids": [1, 2], "with_payload": true });
    let result = client.get_points("docs", &body).await.unwrap();
    assert_eq!(result.len(), 2);
}

#[fcp_async_core::test]
async fn client_scrolls_points() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points/scroll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": {
                "points": [
                    { "id": 1, "payload": { "text": "hello" } }
                ],
                "next_page_offset": 2
            },
            "time": 0.003
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let body = json!({ "limit": 1, "with_payload": true });
    let result = client.scroll("docs", &body).await.unwrap();
    assert_eq!(result.points.len(), 1);
    assert!(result.next_page_offset.is_some());
}

#[fcp_async_core::test]
async fn client_counts_points() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points/count"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": { "count": 42 },
            "time": 0.001
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let body = json!({ "exact": true });
    let result = client.count("docs", &body).await.unwrap();
    assert_eq!(result.count, 42);
}

#[fcp_async_core::test]
async fn client_upserts_points() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/collections/docs/points"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": { "operation_id": 1, "status": "completed" },
            "time": 0.05
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let body = json!({
        "points": [
            { "id": 1, "vector": [0.1, 0.2, 0.3], "payload": { "text": "hello" } }
        ]
    });
    let result = client.upsert_points("docs", &body).await.unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::test]
async fn client_deletes_points() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/collections/docs/points/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": { "operation_id": 2, "status": "completed" },
            "time": 0.02
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();

    let body = json!({ "points": [1, 2, 3] });
    let result = client.delete_points("docs", &body).await.unwrap();
    assert!(result.get("result").is_some());
}

#[fcp_async_core::test]
async fn client_maps_unauthorized_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = QdrantClient::new("bad-key", &server.uri())
        .unwrap()
        .with_retry_config(0);

    let result = client.list_collections().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        QdrantError::Api {
            status_code: Some(401),
            ..
        }
    ));
}

#[fcp_async_core::test]
async fn client_maps_not_found_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/collections/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "status": { "error": "Not found" },
            "result": null,
            "time": 0.0
        })))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri())
        .unwrap()
        .with_retry_config(0);

    let result = client.collection_info("missing").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        QdrantError::Api {
            status_code: Some(404),
            ..
        }
    ));
}

#[fcp_async_core::test]
async fn client_maps_rate_limit_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri())
        .unwrap()
        .with_retry_config(1);

    let result = client.list_collections().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), QdrantError::RateLimit { .. }));
}

#[fcp_async_core::test]
async fn client_rejects_invalid_json_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let client = QdrantClient::new("test-key", &server.uri()).unwrap();
    let result = client.list_collections().await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), QdrantError::Serialization(_)));
}
