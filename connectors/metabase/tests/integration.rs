//! Integration tests for the FCP `Metabase` connector.

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

use fcp_metabase::connector::MetabaseConnector;

async fn setup_connector(mock_url: &str) -> MetabaseConnector {
    let mut c = MetabaseConnector::new();
    c.handle_configure(json!({
        "session_token": "test-session-token",
        "base_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = MetabaseConnector::new();
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
    let mut c = MetabaseConnector::new();
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
    let c = MetabaseConnector::new();
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
    let c = MetabaseConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let mut c = MetabaseConnector::new();
    c.handle_configure(json!({
        "session_token": "tok",
        "base_url": "https://example.com/api",
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Dashboards List ---------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn dashboards_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .and(header("X-Metabase-Session", "test-session-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "id": 1,
                "name": "Sales Dashboard",
                "description": "Monthly sales",
                "collection_id": 5,
                "archived": false,
            },
            {
                "id": 2,
                "name": "Marketing Dashboard",
                "description": null,
                "archived": false,
            },
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["dashboards"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn dashboards_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["dashboards"].as_array().unwrap().is_empty());
}

// -- Questions List ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn questions_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/card"))
        .and(header("X-Metabase-Session", "test-session-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "id": 10,
                "name": "Total Revenue",
                "description": "Sum of all revenue",
                "display": "scalar",
                "database_id": 1,
                "archived": false,
            },
            {
                "id": 20,
                "name": "Users by Country",
                "display": "bar",
                "archived": false,
            },
            {
                "id": 30,
                "name": "Monthly Signups",
                "display": "line",
                "archived": false,
            },
        ])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "metabase.questions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["questions"].as_array().unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn questions_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/card"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "metabase.questions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(result["questions"].as_array().unwrap().is_empty());
}

// -- Questions Run -----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn questions_run_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/card/42/query"))
        .and(header("X-Metabase-Session", "test-session-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "rows": [
                    [1, "Alice", 500],
                    [2, "Bob", 300],
                ],
                "cols": [
                    {"name": "id", "display_name": "ID", "base_type": "type/Integer"},
                    {"name": "name", "display_name": "Name", "base_type": "type/Text"},
                    {"name": "amount", "display_name": "Amount", "base_type": "type/Integer"},
                ],
            },
            "database_id": 1,
            "row_count": 2,
            "running_time": 45,
            "status": "completed",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "metabase.questions.run",
            "input": {"card_id": "42"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"]["rows"].as_array().unwrap().len(), 2);
    assert_eq!(result["status"], "completed");
}

#[fcp_async_core::runtime::test]
async fn questions_run_empty_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/card/99/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "rows": [],
                "cols": [{"name": "id"}],
            },
            "row_count": 0,
            "status": "completed",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "metabase.questions.run",
            "input": {"card_id": "99"}
        }))
        .await
        .unwrap();
    assert!(result["data"]["rows"].as_array().unwrap().is_empty());
    assert_eq!(result["status"], "completed");
}

#[fcp_async_core::runtime::test]
async fn questions_run_missing_card_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.questions.run",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn questions_run_numeric_card_id_fails() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    // card_id must be a string per the schema
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.questions.run",
            "input": {"card_id": 42}
        }))
        .await
        .is_err()
    );
}

// -- Error handling ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "Unauthenticated"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
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
        .and(path("/dashboard"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/card/.*/query"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Card not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.questions.run",
            "input": {"card_id": "99999"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
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
        .and(path("/dashboard"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal server error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_with_error_message_field() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/card"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"error-message": "You don't have permissions"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.questions.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate ---------------------------------------------------

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_dashboards_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "metabase.dashboards.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_questions_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "metabase.questions.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_questions_run() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "metabase.questions.run"}))
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
        !c.handle_simulate(json!({"operation_id": "metabase.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters ----------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "metabase.dashboards.list",
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
        .and(path("/dashboard"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

#[fcp_async_core::runtime::test]
async fn counters_multiple_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .unwrap();
    }
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 3);
    assert_eq!(h["errors"], 0);
}

// -- Handshake response ------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn handshake_returns_capabilities() {
    let server = MockServer::start().await;
    let mut c = MetabaseConnector::new();
    c.handle_configure(json!({
        "session_token": "tok",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.metabase");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "metabase.dashboards.read"));
    assert!(caps.iter().any(|c| c == "metabase.questions.read"));
}

// -- Invoke before ready -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = MetabaseConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Mixed operations --------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn mixed_operations_sequence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "name": "Dash 1"},
        ])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/card"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 10, "name": "Question 1"},
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/card/10/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"rows": [[42]], "cols": [{"name": "result"}]},
            "status": "completed",
        })))
        .mount(&server)
        .await;

    let conn = setup_connector(&server.uri()).await;

    // List dashboards
    let dash_result = conn
        .handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(dash_result["dashboards"].as_array().unwrap().len(), 1);

    // List questions
    let question_result = conn
        .handle_invoke(json!({
            "operation_id": "metabase.questions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(question_result["questions"].as_array().unwrap().len(), 1);

    // Run a question
    let run_result = conn
        .handle_invoke(json!({
            "operation_id": "metabase.questions.run",
            "input": {"card_id": "10"}
        }))
        .await
        .unwrap();
    assert_eq!(run_result["status"], "completed");

    // Verify counters
    let health = conn.handle_health().await.unwrap();
    assert_eq!(health["requests"], 3);
    assert_eq!(health["errors"], 0);
}

// -- Reconfigure -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn reconfigure_resets_client() {
    let server1 = MockServer::start().await;
    let server2 = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "name": "Server1 Dashboard"},
        ])))
        .mount(&server1)
        .await;
    Mock::given(method("GET"))
        .and(path("/dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 2, "name": "Server2 Dashboard"},
        ])))
        .mount(&server2)
        .await;

    let mut c = MetabaseConnector::new();
    // Configure with server1
    c.handle_configure(json!({
        "session_token": "tok1",
        "base_url": server1.uri(),
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();

    let r1 = c
        .handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(r1["dashboards"][0]["name"], "Server1 Dashboard");

    // Reconfigure with server2
    c.handle_configure(json!({
        "session_token": "tok2",
        "base_url": server2.uri(),
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "s2"}))
        .await
        .unwrap();

    let r2 = c
        .handle_invoke(json!({
            "operation_id": "metabase.dashboards.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(r2["dashboards"][0]["name"], "Server2 Dashboard");
}
