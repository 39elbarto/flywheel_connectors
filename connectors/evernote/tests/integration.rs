//! Integration tests for the FCP `Evernote` connector.

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

use fcp_evernote::connector::EvernoteConnector;

async fn setup_connector(mock_url: &str) -> EvernoteConnector {
    let mut c = EvernoteConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = EvernoteConnector::new();
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
    let mut c = EvernoteConnector::new();
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
    assert_eq!(check["status"], "ready");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = EvernoteConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = EvernoteConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 5);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_connector_id() {
    let c = EvernoteConnector::new();
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["connector_id"], "fcp.evernote");
}

// -- Notebooks List ---------------------------------------------------

#[fcp_async_core::runtime::test]
async fn notebooks_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "notebooks": [
                {"id": "nb1", "name": "Work Notes"},
                {"id": "nb2", "name": "Personal"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "evernote.notebooks.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["notebooks"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn notebooks_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "notebooks": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "evernote.notebooks.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["notebooks"].as_array().unwrap().is_empty());
}

// -- Notes List -------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn notes_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks/nb-abc123/notes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "notes": [
                {"noteId": "n1", "title": "Meeting Notes"},
                {"noteId": "n2", "title": "Ideas"},
            ],
            "total_count": 2,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "evernote.notes.list",
            "input": {"notebook_id": "nb-abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["notes"].as_array().unwrap().len(), 2);
    assert_eq!(result["total_count"], 2);
}

#[fcp_async_core::runtime::test]
async fn notes_list_missing_notebook_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notes.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Notes Get --------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn notes_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notes/note-abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "noteId": "note-abc123",
            "title": "Meeting Notes",
            "content": "Discussed roadmap items.",
            "notebookId": "nb-abc123",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "evernote.notes.get",
            "input": {"note_id": "note-abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["noteId"], "note-abc123");
    assert_eq!(result["title"], "Meeting Notes");
    assert_eq!(result["content"], "Discussed roadmap items.");
}

#[fcp_async_core::runtime::test]
async fn notes_get_missing_note_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notes.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Notes Create -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn notes_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/notes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "noteId": "note-new123",
            "title": "New Note",
            "notebookId": "nb-abc123",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "evernote.notes.create",
            "input": {"notebook_id": "nb-abc123", "title": "New Note", "content": "Some content"}
        }))
        .await
        .unwrap();
    assert_eq!(result["noteId"], "note-new123");
}

#[fcp_async_core::runtime::test]
async fn notes_create_missing_notebook_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notes.create",
            "input": {"title": "New Note"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn notes_create_missing_title() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notes.create",
            "input": {"notebook_id": "nb-abc123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn notes_create_minimal() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/notes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "noteId": "note-min",
            "title": "Title Only",
            "notebookId": "nb-1",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "evernote.notes.create",
            "input": {"notebook_id": "nb-1", "title": "Title Only"}
        }))
        .await
        .unwrap();
    assert_eq!(result["noteId"], "note-min");
}

// -- Notes Delete -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn notes_delete() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/notes/note-abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "evernote.notes.delete",
            "input": {"note_id": "note-abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn notes_delete_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notes.delete",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Error Handling ---------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"errorCode": 8, "message": "Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notebooks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"errorCode": 13, "message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notebooks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/notes/.*"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"errorCode": 2, "message": "Not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notes.get",
            "input": {"note_id": "missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"errorCode": 19, "message": "Rate limit exceeded"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notebooks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"errorCode": 0, "message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.notebooks.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown Op / Simulate --------------------------------------------

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "evernote.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_notebooks_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "evernote.notebooks.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_notes_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "evernote.notes.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_notes_create() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "evernote.notes.create"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_notes_delete() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "evernote.notes.delete"}))
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
        !c.handle_simulate(json!({"operation_id": "evernote.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters ---------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "notebooks": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "evernote.notebooks.list",
        "input": {}
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
    Mock::given(method("GET"))
        .and(path("/notebooks"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"errorCode": 0, "message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "evernote.notebooks.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- Handshake --------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = EvernoteConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": server.uri() }))
        .await
        .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.evernote");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn handshake_without_session_id() {
    let server = MockServer::start().await;
    let mut c = EvernoteConnector::new();
    c.handle_configure(json!({ "access_token": "tok", "base_url": server.uri() }))
        .await
        .unwrap();
    let hs = c.handle_handshake(json!({})).await.unwrap();
    assert_eq!(hs["connector_id"], "fcp.evernote");
}

// -- Health Degraded --------------------------------------------------

#[fcp_async_core::runtime::test]
async fn health_degraded_when_configured_but_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = EvernoteConnector::new();
    c.handle_configure(json!({ "access_token": "tok", "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}
