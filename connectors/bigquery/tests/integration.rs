//! Integration tests for the FCP `BigQuery` connector.

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
use wiremock::matchers::{bearer_token, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_bigquery::connector::BigQueryConnector;

async fn setup_connector(mock_url: &str) -> BigQueryConnector {
    let mut c = BigQueryConnector::new();
    c.handle_configure(json!({
        "access_token": "test-access-token",
        "project_id": "test-project",
        "base_url": mock_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

async fn setup_connector_no_project(mock_url: &str) -> BigQueryConnector {
    let mut c = BigQueryConnector::new();
    c.handle_configure(json!({
        "access_token": "test-access-token",
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
    let c = BigQueryConnector::new();
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
    let mut c = BigQueryConnector::new();
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
    let c = BigQueryConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = BigQueryConnector::new();
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 4);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_configured_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = BigQueryConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- Datasets List -----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn datasets_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets"))
        .and(bearer_token("test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#datasetList",
            "datasets": [
                {
                    "id": "test-project:analytics",
                    "datasetReference": {"datasetId": "analytics", "projectId": "test-project"},
                    "location": "US"
                },
                {
                    "id": "test-project:billing",
                    "datasetReference": {"datasetId": "billing", "projectId": "test-project"},
                    "location": "EU"
                }
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .unwrap();
    assert_eq!(result["datasets"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn datasets_list_uses_config_project_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "datasets": [{"id": "test-project:ds1"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["datasets"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn datasets_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#datasetList"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .unwrap();
    // BigQuery response may have no "datasets" key when empty; the raw JSON is returned
    assert!(result.get("datasets").is_none() || result["datasets"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn datasets_list_missing_project_id_no_config() {
    let server = MockServer::start().await;
    let c = setup_connector_no_project(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Tables List -------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn tables_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets/analytics/tables"))
        .and(bearer_token("test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#tableList",
            "tables": [
                {
                    "tableReference": {"tableId": "events", "datasetId": "analytics"},
                    "type": "TABLE"
                },
                {
                    "tableReference": {"tableId": "sessions", "datasetId": "analytics"},
                    "type": "VIEW"
                }
            ],
            "totalItems": 2
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.tables.list",
            "input": {"project_id": "test-project", "dataset_id": "analytics"}
        }))
        .await
        .unwrap();
    assert_eq!(result["tables"].as_array().unwrap().len(), 2);
    assert_eq!(result["totalItems"], 2);
}

#[fcp_async_core::runtime::test]
async fn tables_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets/empty_ds/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#tableList",
            "totalItems": 0
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.tables.list",
            "input": {"project_id": "test-project", "dataset_id": "empty_ds"}
        }))
        .await
        .unwrap();
    assert!(result.get("tables").is_none() || result["tables"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn tables_list_missing_dataset_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.tables.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn tables_list_uses_config_project_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets/ds1/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [{"tableReference": {"tableId": "t1"}}],
            "totalItems": 1
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.tables.list",
            "input": {"dataset_id": "ds1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["tables"].as_array().unwrap().len(), 1);
}

// -- Jobs List ---------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn jobs_list_basic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/jobs"))
        .and(bearer_token("test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#jobList",
            "jobs": [
                {
                    "id": "test-project:US.job_abc",
                    "jobReference": {"jobId": "job_abc", "projectId": "test-project"},
                    "status": {"state": "DONE"}
                },
                {
                    "id": "test-project:US.job_def",
                    "jobReference": {"jobId": "job_def", "projectId": "test-project"},
                    "status": {"state": "RUNNING"}
                }
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.jobs.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .unwrap();
    assert_eq!(result["jobs"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn jobs_list_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#jobList"
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.jobs.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .unwrap();
    assert!(result.get("jobs").is_none() || result["jobs"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn jobs_list_uses_config_project_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jobs": [{"id": "test-project:j1"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.jobs.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["jobs"].as_array().unwrap().len(), 1);
}

// -- Jobs Query --------------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn jobs_query_basic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/test-project/queries"))
        .and(bearer_token("test-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#queryResponse",
            "schema": {
                "fields": [
                    {"name": "id", "type": "INTEGER"},
                    {"name": "name", "type": "STRING"}
                ]
            },
            "rows": [
                {"f": [{"v": "1"}, {"v": "Alice"}]},
                {"f": [{"v": "2"}, {"v": "Bob"}]}
            ],
            "totalRows": "2",
            "totalBytesProcessed": "1024",
            "jobComplete": true,
            "cacheHit": false
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.jobs.query",
            "input": {
                "project_id": "test-project",
                "query": "SELECT id, name FROM users LIMIT 10"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["rows"].as_array().unwrap().len(), 2);
    assert_eq!(result["totalRows"], "2");
    assert_eq!(result["jobComplete"], true);
}

#[fcp_async_core::runtime::test]
async fn jobs_query_empty_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/test-project/queries"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "bigquery#queryResponse",
            "schema": {"fields": [{"name": "id", "type": "INTEGER"}]},
            "rows": [],
            "totalRows": "0",
            "jobComplete": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.jobs.query",
            "input": {
                "project_id": "test-project",
                "query": "SELECT id FROM empty_table"
            }
        }))
        .await
        .unwrap();
    assert!(result["rows"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn jobs_query_missing_query_string() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.jobs.query",
            "input": {"project_id": "test-project"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn jobs_query_uses_config_project_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/test-project/queries"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rows": [{"f": [{"v": "x"}]}],
            "totalRows": "1",
            "jobComplete": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.jobs.query",
            "input": {"query": "SELECT 1"}
        }))
        .await
        .unwrap();
    assert_eq!(result["totalRows"], "1");
}

#[fcp_async_core::runtime::test]
async fn jobs_query_with_legacy_sql() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/projects/test-project/queries"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rows": [],
            "totalRows": "0",
            "jobComplete": true
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.jobs.query",
            "input": {
                "project_id": "test-project",
                "query": "SELECT * FROM [dataset.table]",
                "use_legacy_sql": true
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["jobComplete"], true);
}

// -- Error handling ----------------------------------------------------------

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": 401,
                "message": "Request had invalid authentication credentials.",
                "status": "UNAUTHENTICATED"
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": {
                "code": 403,
                "message": "Access Denied: Project test-project",
                "status": "FORBIDDEN"
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/projects/.*/datasets/.*/tables"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": 404,
                "message": "Not found: Dataset test-project:missing_ds",
                "status": "NOT_FOUND"
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.tables.list",
            "input": {"project_id": "test-project", "dataset_id": "missing_ds"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "error": {
                        "code": 429,
                        "message": "Exceeded rate limits",
                        "status": "RESOURCE_EXHAUSTED"
                    }
                }))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/test-project/datasets"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": {
                "code": 500,
                "message": "Internal error",
                "status": "INTERNAL"
            }
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
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
            "operation_id": "bigquery.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_datasets_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "bigquery.datasets.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_tables_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "bigquery.tables.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_jobs_list() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "bigquery.jobs.list"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known_jobs_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "bigquery.jobs.query"}))
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
        !c.handle_simulate(json!({"operation_id": "bigquery.nope"}))
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
        .and(path("/projects/test-project/datasets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "datasets": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "bigquery.datasets.list",
        "input": {"project_id": "test-project"}
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
        .and(path("/projects/test-project/datasets"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": {"message": "Internal error", "code": 500}})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
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
        .and(path("/projects/test-project/datasets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "datasets": [],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    for _ in 0..3 {
        c.handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "test-project"}
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
    let mut c = BigQueryConnector::new();
    c.handle_configure(json!({
        "access_token": "tok",
        "base_url": server.uri(),
    }))
    .await
    .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["connector_id"], "fcp.bigquery");
    assert_eq!(hs["protocol_version"], "2.0");
    let caps = hs["capabilities"].as_array().unwrap();
    assert!(caps.iter().any(|c| c == "bigquery.datasets.read"));
    assert!(caps.iter().any(|c| c == "bigquery.tables.read"));
    assert!(caps.iter().any(|c| c == "bigquery.jobs.read"));
    assert!(caps.iter().any(|c| c == "bigquery.jobs.write"));
}

// -- Invoke before ready -----------------------------------------------------

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let c = BigQueryConnector::new();
    assert!(
        c.handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "proj"}
        }))
        .await
        .is_err()
    );
}

// -- Project ID override in input --------------------------------------------

#[fcp_async_core::runtime::test]
async fn input_project_id_overrides_config() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/projects/override-project/datasets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "datasets": [{"id": "override-project:ds1"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "bigquery.datasets.list",
            "input": {"project_id": "override-project"}
        }))
        .await
        .unwrap();
    assert_eq!(result["datasets"].as_array().unwrap().len(), 1);
}
