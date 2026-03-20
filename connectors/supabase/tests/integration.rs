//! Integration tests for the FCP `Supabase` connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_supabase::connector::SupabaseConnector;

async fn setup_connector(mock_url: &str) -> SupabaseConnector {
    let mut connector = SupabaseConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "sb_secret_key",
            "project_url": mock_url,
            "schema": "public",
        }))
        .await
        .unwrap();
    connector
        .handle_handshake(json!({"session_id": "test-session"}))
        .await
        .unwrap();
    connector
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let connector = SupabaseConnector::new();
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let connector = setup_connector(&server.uri()).await;
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn handshake_before_configure_fails() {
    let mut connector = SupabaseConnector::new();
    assert!(connector.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn query_invokes_postgrest_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/todos"))
        .and(query_param("select", "id,title"))
        .and(query_param("status", "eq.open"))
        .and(query_param("limit", "5"))
        .and(query_param("order", "id.desc"))
        .and(header("authorization", "Bearer sb_secret_key"))
        .and(header("apikey", "sb_secret_key"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-range", "0-1/2")
                .set_body_json(json!([
                    {"id": 2, "title": "b"},
                    {"id": 1, "title": "a"}
                ])),
        )
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.query",
            "input": {
                "table": "todos",
                "select": "id,title",
                "filters": [{"column": "status", "operator": "eq", "value": "open"}],
                "order": [{"column": "id", "ascending": false}],
                "limit": 5
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 2);
    assert_eq!(result["data"][0]["id"], 2);
}

#[fcp_async_core::runtime::test]
async fn query_single_uses_object_accept_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/profiles"))
        .and(query_param("select", "*"))
        .and(query_param("id", "eq.user_1"))
        .and(header("accept", "application/vnd.pgrst.object+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user_1",
            "display_name": "Pink Hollow"
        })))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.query",
            "input": {
                "table": "profiles",
                "filters": [{"column": "id", "operator": "eq", "value": "user_1"}],
                "single": true
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["data"]["id"], "user_1");
}

#[fcp_async_core::runtime::test]
async fn insert_posts_rows() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/v1/todos"))
        .and(header("prefer", "return=representation"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!([
            {"id": 10, "title": "Ship connector"}
        ])))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.insert",
            "input": {
                "table": "todos",
                "rows": [{"title": "Ship connector"}]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["data"][0]["id"], 10);
}

#[fcp_async_core::runtime::test]
async fn update_requires_filter() {
    let server = MockServer::start().await;
    let connector = setup_connector(&server.uri()).await;
    assert!(
        connector
            .handle_invoke(json!({
                "operation_id": "supabase.update",
                "input": {
                    "table": "todos",
                    "values": {"status": "done"}
                }
            }))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn update_patches_rows() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/rest/v1/todos"))
        .and(query_param("id", "eq.42"))
        .and(header("prefer", "return=representation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 42, "status": "done"}
        ])))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.update",
            "input": {
                "table": "todos",
                "values": {"status": "done"},
                "filters": [{"column": "id", "operator": "eq", "value": 42}]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["data"][0]["status"], "done");
}

#[fcp_async_core::runtime::test]
async fn upsert_uses_conflict_preferences() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/v1/profiles"))
        .and(query_param("on_conflict", "id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "user_1", "display_name": "Pink Hollow"}
        ])))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.upsert",
            "input": {
                "table": "profiles",
                "rows": [{"id": "user_1", "display_name": "Pink Hollow"}],
                "on_conflict": ["id"]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["data"][0]["id"], "user_1");
}

#[fcp_async_core::runtime::test]
async fn delete_sends_filtered_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/rest/v1/todos"))
        .and(query_param("id", "eq.9"))
        .and(header("prefer", "return=representation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 9, "deleted": true}
        ])))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.delete",
            "input": {
                "table": "todos",
                "filters": [{"column": "id", "operator": "eq", "value": 9}]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["data"][0]["id"], 9);
}

#[fcp_async_core::runtime::test]
async fn rpc_posts_args() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/v1/rpc/search_todos"))
        .and(header("prefer", "return=representation"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "title": "connector task"}
        ])))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.rpc",
            "input": {
                "function": "search_todos",
                "args": {"q": "connector"}
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["data"][0]["title"], "connector task");
}

#[fcp_async_core::runtime::test]
async fn schema_tables_reads_openapi_root() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "info": {"title": "PostgREST API", "version": "13.0"},
            "paths": {
                "/profiles": {"get": {}, "post": {}, "patch": {}, "delete": {}},
                "/todos": {"get": {}, "post": {}},
                "/rpc/search_todos": {"post": {}}
            }
        })))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.schema.tables",
            "input": {}
        }))
        .await
        .unwrap();

    assert_eq!(result["tables"].as_array().unwrap().len(), 2);
    assert_eq!(result["tables"][0]["name"], "profiles");
}

#[fcp_async_core::runtime::test]
async fn storage_upload_posts_object() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(
            "/storage/v1/object/artifacts/reports/out(\\.txt|%2Etxt)",
        ))
        .and(header("x-upsert", "true"))
        .and(header("content-type", "text/plain"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Key": "artifacts/reports/out.txt"
        })))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.storage.upload",
            "input": {
                "bucket": "artifacts",
                "path": "reports/out.txt",
                "content_base64": BASE64_STANDARD.encode("hello"),
                "content_type": "text/plain",
                "upsert": true
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["object"]["Key"], "artifacts/reports/out.txt");
}

#[fcp_async_core::runtime::test]
async fn storage_download_reads_authenticated_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(
            "/storage/v1/object/authenticated/artifacts/reports/out(\\.txt|%2Etxt)",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .insert_header("etag", "\"abc123\"")
                .set_body_bytes(b"hello".to_vec()),
        )
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.storage.download",
            "input": {
                "bucket": "artifacts",
                "path": "reports/out.txt"
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["content_type"], "text/plain");
    assert_eq!(result["content_base64"], BASE64_STANDARD.encode("hello"));
}

#[fcp_async_core::runtime::test]
async fn storage_delete_removes_single_object() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path_regex(
            "/storage/v1/object/artifacts/reports/out(\\.txt|%2Etxt)",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "Successfully deleted"
        })))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.storage.delete",
            "input": {
                "bucket": "artifacts",
                "path": "reports/out.txt"
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["message"], "Successfully deleted");
}

#[fcp_async_core::runtime::test]
async fn health_reads_openapi_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "info": {"title": "PostgREST API", "version": "13.0"},
            "paths": {}
        })))
        .mount(&server)
        .await;

    let connector = setup_connector(&server.uri()).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "supabase.health",
            "input": {}
        }))
        .await
        .unwrap();

    assert_eq!(result["health"]["status"], "ok");
    assert_eq!(result["health"]["openapi_version"], "13.0");
}
