//! Integration tests for the FCP Dropbox connector.

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
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_dropbox::connector::DropboxConnector;

async fn setup_connector(mock_url: &str) -> DropboxConnector {
    let mut c = DropboxConnector::new();
    c.handle_configure(json!({
        "access_token": "test-token",
        "base_url": mock_url,
        "content_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle ----------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = DropboxConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = DropboxConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = DropboxConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
    assert_eq!(check["reason_code"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = DropboxConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 10);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_response_fields() {
    let server = MockServer::start().await;
    let mut c = DropboxConnector::new();
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
    assert_eq!(hs["connector_id"], "fcp.dropbox");
    assert_eq!(hs["protocol_version"], "2.0");
    assert!(hs["capabilities"].as_array().unwrap().len() >= 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = DropboxConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": &server.uri(),
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Files List ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_list() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .and(header("Authorization", "Bearer test-token"))
        .and(body_json(json!({"path": "/Documents"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [
                {".tag": "file", "name": "a.txt", "path_display": "/Documents/a.txt", "size": 100},
                {".tag": "folder", "name": "Subfolder", "path_display": "/Documents/Subfolder"},
            ],
            "cursor": "cursor123",
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": "/Documents"}
        }))
        .await
        .unwrap();
    assert_eq!(result["entries"].as_array().unwrap().len(), 2);
    assert_eq!(result["has_more"], false);
}

#[fcp_async_core::runtime::test]
async fn files_list_root() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .and(body_json(json!({"path": ""})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [
                {".tag": "folder", "name": "Documents", "path_display": "/Documents"},
            ],
            "cursor": "root_cursor",
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": ""}
        }))
        .await
        .unwrap();
    assert_eq!(result["entries"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn files_list_missing_path() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Files List Continue ------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_list_continue() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder/continue"))
        .and(body_json(json!({"cursor": "cursor_abc"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [
                {".tag": "file", "name": "more.txt"},
            ],
            "cursor": "cursor_def",
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.list_continue",
            "input": {"cursor": "cursor_abc"}
        }))
        .await
        .unwrap();
    assert_eq!(result["entries"].as_array().unwrap().len(), 1);
    assert_eq!(result["cursor"], "cursor_def");
}

#[fcp_async_core::runtime::test]
async fn files_list_continue_missing_cursor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.list_continue",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Files Get Metadata -------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_get_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/get_metadata"))
        .and(header("Authorization", "Bearer test-token"))
        .and(body_json(json!({"path": "/Documents/report.pdf"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            ".tag": "file",
            "name": "report.pdf",
            "path_display": "/Documents/report.pdf",
            "id": "id:abc123",
            "size": 2048,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.get_metadata",
            "input": {"path": "/Documents/report.pdf"}
        }))
        .await
        .unwrap();
    assert_eq!(result["name"], "report.pdf");
    assert_eq!(result["size"], 2048);
}

#[fcp_async_core::runtime::test]
async fn files_get_metadata_missing_path() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.get_metadata",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Files Create Folder ------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_create_folder() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/create_folder_v2"))
        .and(body_json(
            json!({"path": "/NewFolder", "autorename": false}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "metadata": {
                "name": "NewFolder",
                "path_display": "/NewFolder",
                "id": "id:new_folder_123",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.create_folder",
            "input": {"path": "/NewFolder"}
        }))
        .await
        .unwrap();
    assert!(result["metadata"].is_object());
}

#[fcp_async_core::runtime::test]
async fn files_create_folder_missing_path() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.create_folder",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Files Delete -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_delete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/delete_v2"))
        .and(body_json(json!({"path": "/old_file.txt"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "metadata": {
                "name": "old_file.txt",
                "path_display": "/old_file.txt",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.delete",
            "input": {"path": "/old_file.txt"}
        }))
        .await
        .unwrap();
    assert!(result.is_object());
}

#[fcp_async_core::runtime::test]
async fn files_delete_missing_path() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Files Move ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_move() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/move_v2"))
        .and(body_json(json!({
            "from_path": "/old/file.txt",
            "to_path": "/new/file.txt"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "metadata": {
                "name": "file.txt",
                "path_display": "/new/file.txt",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.move",
            "input": {"from_path": "/old/file.txt", "to_path": "/new/file.txt"}
        }))
        .await
        .unwrap();
    assert!(result["metadata"].is_object());
}

#[fcp_async_core::runtime::test]
async fn files_move_missing_from_path() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.move",
            "input": {"to_path": "/new/file.txt"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn files_move_missing_to_path() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.move",
            "input": {"from_path": "/old/file.txt"}
        }))
        .await
        .is_err()
    );
}

// -- Files Copy ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_copy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/copy_v2"))
        .and(body_json(json!({
            "from_path": "/src/file.txt",
            "to_path": "/dst/file.txt"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "metadata": {
                "name": "file.txt",
                "path_display": "/dst/file.txt",
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.copy",
            "input": {"from_path": "/src/file.txt", "to_path": "/dst/file.txt"}
        }))
        .await
        .unwrap();
    assert!(result["metadata"].is_object());
}

#[fcp_async_core::runtime::test]
async fn files_copy_missing_from_path() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.copy",
            "input": {"to_path": "/dst/file.txt"}
        }))
        .await
        .is_err()
    );
}

// -- Files Search -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn files_search() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/search_v2"))
        .and(body_json(json!({"query": "report"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [
                {"metadata": {".tag": "metadata", "metadata": {"name": "report.pdf"}}},
                {"metadata": {".tag": "metadata", "metadata": {"name": "report_v2.pdf"}}},
            ],
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.search",
            "input": {"query": "report"}
        }))
        .await
        .unwrap();
    assert_eq!(result["matches"].as_array().unwrap().len(), 2);
    assert_eq!(result["has_more"], false);
}

#[fcp_async_core::runtime::test]
async fn files_search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.search",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Account: Space Usage -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn account_get_space_usage() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/users/get_space_usage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "used": 314159265,
            "allocation": {
                ".tag": "individual",
                "allocated": 2147483648_u64,
            },
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.account.get_space_usage",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["used"], 314159265);
}

// -- Account: Get Current -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn account_get_current() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/users/get_current_account"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
            "name": {
                "given_name": "Franz",
                "surname": "Ferdinand",
                "display_name": "Franz Ferdinand",
            },
            "email": "franz@dropbox.com",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.account.get_current",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["email"], "franz@dropbox.com");
    assert_eq!(result["name"]["display_name"], "Franz Ferdinand");
}

// -- Error handling -----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error_summary": "invalid_access_token/..."})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": "/Documents"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"error_summary": "access_denied/..."})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": "/Documents"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_409_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/get_metadata"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error_summary": "path/not_found/...",
            "error": {".tag": "path", "path": {".tag": "not_found"}},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.get_metadata",
            "input": {"path": "/nonexistent"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_409_conflict() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/create_folder_v2"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error_summary": "path/conflict/folder/...",
            "error": {".tag": "path", "path": {".tag": "conflict"}},
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.create_folder",
            "input": {"path": "/existing_folder"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"error_summary": "too_many_requests/..."}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": "/Documents"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": "/Documents"}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate ----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "dropbox.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "dropbox.files.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_search() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "dropbox.files.search"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_account() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "dropbox.account.get_current"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "dropbox.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters -----------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [],
            "cursor": "c",
            "has_more": false,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "dropbox.files.list",
        "input": {"path": ""}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/files/list_folder"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "dropbox.files.list",
            "input": {"path": ""}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- Auth header verification -------------------------------------------------

#[fcp_async_core::runtime::test]
async fn bearer_token_sent_in_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/users/get_current_account"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "account_id": "dbid:test",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "dropbox.account.get_current",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["account_id"], "dbid:test");
}
