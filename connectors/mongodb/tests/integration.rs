//! Integration tests for the FCP `MongoDB` Atlas Data API connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_mongodb::connector::MongoDbConnector;

async fn setup_connector(mock_url: &str) -> MongoDbConnector {
    let mut c = MongoDbConnector::new();
    c.handle_configure(json!({
        "api_key": "test-api-key-123",
        "base_url": mock_url,
        "data_source": "TestCluster"
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[tokio::test]
async fn lifecycle_health_unconfigured() {
    let c = MongoDbConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = MongoDbConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[tokio::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
}

#[tokio::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 9);
}

#[tokio::test]
async fn lifecycle_handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = MongoDbConnector::new();
    c.handle_configure(json!({
        "api_key": "test-key",
        "base_url": &server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.mongodb");
    let caps = hs["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 9);
}

// -- find_one --

#[tokio::test]
async fn find_one_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/findOne"))
        .and(header("apiKey", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "document": {"_id": "abc123", "name": "Alice", "age": 30}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.find_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "filter": {"name": "Alice"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["document"]["name"], "Alice");
}

#[tokio::test]
async fn find_one_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/findOne"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "document": null })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.find_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "filter": {"name": "Nobody"}
            }
        }))
        .await
        .unwrap();
    assert!(result["document"].is_null());
}

#[tokio::test]
async fn find_one_missing_database() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.find_one",
            "input": {"collection": "users"}
        }))
        .await
        .is_err()
    );
}

// -- find --

#[tokio::test]
async fn find_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/find"))
        .and(header("apiKey", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "documents": [
                {"_id": "1", "name": "Alice"},
                {"_id": "2", "name": "Bob"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.find",
            "input": {
                "database": "mydb",
                "collection": "users"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["documents"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn find_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "documents": [] })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.find",
            "input": {
                "database": "mydb",
                "collection": "users"
            }
        }))
        .await
        .unwrap();
    assert!(result["documents"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn find_missing_collection() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.find",
            "input": {"database": "mydb"}
        }))
        .await
        .is_err()
    );
}

// -- insert_one --

#[tokio::test]
async fn insert_one_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/insertOne"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "insertedId": "new_id_123"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.insert_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "document": {"name": "Charlie", "age": 25}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["insertedId"], "new_id_123");
}

#[tokio::test]
async fn insert_one_missing_document() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.insert_one",
            "input": {
                "database": "mydb",
                "collection": "users"
            }
        }))
        .await
        .is_err()
    );
}

// -- insert_many --

#[tokio::test]
async fn insert_many_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/insertMany"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "insertedIds": ["id1", "id2"]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.insert_many",
            "input": {
                "database": "mydb",
                "collection": "users",
                "documents": [
                    {"name": "Alice"},
                    {"name": "Bob"}
                ]
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["insertedIds"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn insert_many_missing_documents() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.insert_many",
            "input": {
                "database": "mydb",
                "collection": "users"
            }
        }))
        .await
        .is_err()
    );
}

// -- update_one --

#[tokio::test]
async fn update_one_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/updateOne"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matchedCount": 1,
            "modifiedCount": 1
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.update_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "filter": {"name": "Alice"},
                "update": {"$set": {"age": 31}}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["matchedCount"], 1);
    assert_eq!(result["modifiedCount"], 1);
}

#[tokio::test]
async fn update_one_missing_filter() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.update_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "update": {"$set": {"age": 31}}
            }
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn update_one_missing_update() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.update_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "filter": {"name": "Alice"}
            }
        }))
        .await
        .is_err()
    );
}

// -- update_many --

#[tokio::test]
async fn update_many_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/updateMany"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matchedCount": 5,
            "modifiedCount": 3
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.update_many",
            "input": {
                "database": "mydb",
                "collection": "users",
                "filter": {"status": "inactive"},
                "update": {"$set": {"archived": true}}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["matchedCount"], 5);
    assert_eq!(result["modifiedCount"], 3);
}

// -- delete_one --

#[tokio::test]
async fn delete_one_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/deleteOne"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deletedCount": 1
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.delete_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "filter": {"_id": "abc123"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["deletedCount"], 1);
}

#[tokio::test]
async fn delete_one_missing_filter() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.delete_one",
            "input": {
                "database": "mydb",
                "collection": "users"
            }
        }))
        .await
        .is_err()
    );
}

// -- delete_many --

#[tokio::test]
async fn delete_many_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/deleteMany"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deletedCount": 7
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.delete_many",
            "input": {
                "database": "mydb",
                "collection": "users",
                "filter": {"status": "inactive"}
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["deletedCount"], 7);
}

#[tokio::test]
async fn delete_many_missing_filter() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.delete_many",
            "input": {
                "database": "mydb",
                "collection": "users"
            }
        }))
        .await
        .is_err()
    );
}

// -- aggregate --

#[tokio::test]
async fn aggregate_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/aggregate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "documents": [
                {"_id": "product_a", "total": 1500},
                {"_id": "product_b", "total": 2300},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "mongodb.aggregate",
            "input": {
                "database": "mydb",
                "collection": "orders",
                "pipeline": [
                    {"$match": {"status": "completed"}},
                    {"$group": {"_id": "$product", "total": {"$sum": "$amount"}}}
                ]
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["documents"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn aggregate_missing_pipeline() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.aggregate",
            "input": {
                "database": "mydb",
                "collection": "orders"
            }
        }))
        .await
        .is_err()
    );
}

// -- Error handling --

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/find"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error": "unauthorized", "error_code": "InvalidSession"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.find",
            "input": {"database": "mydb", "collection": "users"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/find"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error": "forbidden", "error_code": "AccessDenied"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.find",
            "input": {"database": "mydb", "collection": "users"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/findOne"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error": "app not found", "error_code": "AppNotFound"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.find_one",
            "input": {"database": "mydb", "collection": "users", "filter": {}}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/find"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error": "too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.find",
            "input": {"database": "mydb", "collection": "users"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/insertOne"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.insert_one",
            "input": {
                "database": "mydb",
                "collection": "users",
                "document": {"name": "Test"}
            }
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "mongodb.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "mongodb.find"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "mongodb.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[tokio::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"documents": []})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "mongodb.find",
        "input": {"database": "mydb", "collection": "users"}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[tokio::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/action/find"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "mongodb.find",
            "input": {"database": "mydb", "collection": "users"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- All requests are POST --

#[tokio::test]
async fn all_requests_use_post() {
    let server = MockServer::start().await;

    // Mount a POST-only mock; if the connector used GET it would fail
    Mock::given(method("POST"))
        .and(path("/action/findOne"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"document": null})))
        .expect(1)
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "mongodb.find_one",
        "input": {"database": "db", "collection": "col", "filter": {}}
    }))
    .await
    .unwrap();
}
