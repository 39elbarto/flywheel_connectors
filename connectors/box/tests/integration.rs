//! Integration tests for the FCP `Box` connector.

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
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_box::connector::BoxConnector;

async fn setup_connector(mock_url: &str) -> BoxConnector {
    let mut c = BoxConnector::new();
    c.handle_configure(json!({
        "access_token": "test-token",
        "base_url": mock_url,
        "upload_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle ----------------------------------------------------------------

#[tokio::test]
async fn lifecycle_health_unconfigured() {
    let c = BoxConnector::new();
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
    let mut c = BoxConnector::new();
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
async fn lifecycle_self_check_unconfigured() {
    let c = BoxConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_doctor_unconfigured() {
    let c = BoxConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[tokio::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn lifecycle_handshake_response_fields() {
    let server = MockServer::start().await;
    let mut c = BoxConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.box");
    assert_eq!(hs["protocol_version"], "2.0");
    assert!(hs["capabilities"].as_array().unwrap().len() >= 4);
}

// -- Files Get ----------------------------------------------------------------

#[tokio::test]
async fn files_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/files/123456"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123456",
            "type": "file",
            "name": "report.pdf",
            "size": 2048,
            "sha1": "abc123def456",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {"file_id": "123456"}
        }))
        .await
        .unwrap();
    assert_eq!(result["id"], "123456");
    assert_eq!(result["name"], "report.pdf");
    assert_eq!(result["size"], 2048);
}

#[tokio::test]
async fn files_get_missing_file_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Files Upload -------------------------------------------------------------

#[tokio::test]
async fn files_upload() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/content"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "total_count": 1,
            "entries": [{"id": "new789", "type": "file", "name": "doc.txt"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "box.files.upload",
            "input": {"folder_id": "0", "name": "doc.txt"}
        }))
        .await
        .unwrap();
    assert_eq!(result["entries"][0]["id"], "new789");
}

#[tokio::test]
async fn files_upload_missing_folder_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.upload",
            "input": {"name": "doc.txt"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn files_upload_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.upload",
            "input": {"folder_id": "0"}
        }))
        .await
        .is_err()
    );
}

// -- Files Delete -------------------------------------------------------------

#[tokio::test]
async fn files_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/files/123456"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "box.files.delete",
            "input": {"file_id": "123456"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[tokio::test]
async fn files_delete_missing_file_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Folders List -------------------------------------------------------------

#[tokio::test]
async fn folders_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/folders/.*/items.*"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 3,
            "entries": [
                {"id": "f1", "type": "file", "name": "a.txt"},
                {"id": "f2", "type": "file", "name": "b.txt"},
                {"id": "d1", "type": "folder", "name": "Docs"},
            ],
            "offset": 0,
            "limit": 100,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "box.folders.list",
            "input": {"folder_id": "0"}
        }))
        .await
        .unwrap();
    assert_eq!(result["entries"].as_array().unwrap().len(), 3);
    assert_eq!(result["total_count"], 3);
}

#[tokio::test]
async fn folders_list_with_pagination() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/folders/.*/items.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 100,
            "entries": [{"id": "f10", "type": "file"}],
            "offset": 10,
            "limit": 1,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "box.folders.list",
            "input": {"folder_id": "0", "limit": 1, "offset": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["entries"].as_array().unwrap().len(), 1);
    assert_eq!(result["total_count"], 100);
}

#[tokio::test]
async fn folders_list_missing_folder_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.folders.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Sharing List -------------------------------------------------------------

#[tokio::test]
async fn sharing_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/files/123456/collaborations"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 2,
            "entries": [
                {"id": "c1", "type": "collaboration", "role": "editor"},
                {"id": "c2", "type": "collaboration", "role": "viewer"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "box.sharing.list",
            "input": {"file_id": "123456"}
        }))
        .await
        .unwrap();
    assert_eq!(result["entries"].as_array().unwrap().len(), 2);
    assert_eq!(result["total_count"], 2);
}

#[tokio::test]
async fn sharing_list_missing_file_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.sharing.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Error handling -----------------------------------------------------------

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/files/.*"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"type": "error", "status": 401, "message": "Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {"file_id": "123"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/files/.*"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"type": "error", "status": 403, "message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {"file_id": "123"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/files/.*"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "type": "error",
            "status": 404,
            "message": "Not Found",
            "code": "not_found"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {"file_id": "missing"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_409_conflict() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/content"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "type": "error",
            "status": 409,
            "message": "Item with the same name already exists",
            "code": "item_name_in_use"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.upload",
            "input": {"folder_id": "0", "name": "existing.txt"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/files/.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(
                    json!({"type": "error", "status": 429, "message": "Too many requests"}),
                )
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {"file_id": "123"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/folders/.*/items.*"))
        .respond_with(ResponseTemplate::new(500).set_body_json(
            json!({"type": "error", "status": 500, "message": "Internal Server Error"}),
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.folders.list",
            "input": {"folder_id": "0"}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate ----------------------------------------------------

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "box.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn simulate_known_files_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let sim = c
        .handle_simulate(json!({"operation_id": "box.files.get"}))
        .await
        .unwrap();
    assert!(sim["allowed"].as_bool().unwrap());
}

#[tokio::test]
async fn simulate_known_folders_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let sim = c
        .handle_simulate(json!({"operation_id": "box.folders.list"}))
        .await
        .unwrap();
    assert!(sim["allowed"].as_bool().unwrap());
}

#[tokio::test]
async fn simulate_known_sharing_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let sim = c
        .handle_simulate(json!({"operation_id": "box.sharing.list"}))
        .await
        .unwrap();
    assert!(sim["allowed"].as_bool().unwrap());
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let sim = c
        .handle_simulate(json!({"operation_id": "box.nope"}))
        .await
        .unwrap();
    assert!(!sim["allowed"].as_bool().unwrap());
}

// -- Counters -----------------------------------------------------------------

#[tokio::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/files/123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "123",
            "type": "file",
            "name": "test.txt",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "box.files.get",
        "input": {"file_id": "123"}
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
    Mock::given(method("GET"))
        .and(path_regex("/files/.*"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"type": "error", "message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {"file_id": "123"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[tokio::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/files/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1",
            "type": "file",
            "name": "x.txt",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "box.files.get",
            "input": {"file_id": "1"}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}
