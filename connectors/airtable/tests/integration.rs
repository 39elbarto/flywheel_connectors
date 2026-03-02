//! Integration tests for the Airtable connector.
//!
//! Covers error taxonomy mapping, credential redaction, client operations
//! (bases, records, schema, attachments), and connector-level invoke routing.

use std::time::Duration;

use chrono::Utc;
use fcp_airtable::{client::AirtableClient, connector::AirtableConnector, error::AirtableError};
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use serde_json::json;
use wiremock::matchers::{bearer_token, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Helpers ──────────────────────────────────────────────────────────

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[cap])
        .issuer("node:test")
        .validity(now, now + chrono::Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    CapabilityToken { raw: cose }
}

async fn setup_handshake(
    connector: &mut AirtableConnector,
    signing_key: &Ed25519SigningKey,
    capabilities: &[&str],
) {
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .unwrap();
}

async fn setup_configure(connector: &mut AirtableConnector, api_url: &str) {
    connector
        .handle_configure(json!({
            "token": "pat_test_token_123",
            "base_url": api_url
        }))
        .await
        .unwrap();
}

fn record_json(id: &str, fields: &serde_json::Value) -> serde_json::Value {
    json!({
        "id": id,
        "fields": fields,
        "createdTime": "2025-01-01T00:00:00.000Z"
    })
}

// ── Error taxonomy ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_http_maps_to_external() {
    let err = AirtableError::Http(
        reqwest::Client::new()
            .get("http://[::ffff:0.0.0.0]:1")
            .send()
            .await
            .unwrap_err(),
    );
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::External { service, .. } if service == "airtable"));
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_json_maps_to_internal() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let err = AirtableError::Json(bad.unwrap_err());
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Internal { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_auth_maps_to_unauthorized() {
    let err = AirtableError::Api {
        error_type: "AUTHENTICATION_REQUIRED".into(),
        message: "Invalid key".into(),
        status_code: Some(401),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_not_found_maps_to_resource_not_found() {
    let err = AirtableError::Api {
        error_type: "NOT_FOUND".into(),
        message: "Could not find record".into(),
        status_code: Some(404),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::ResourceNotFound { .. }));
}

#[fcp_async_core::runtime::test]
async fn error_api_server_error_is_retryable() {
    let err = AirtableError::Api {
        error_type: "SERVER_ERROR".into(),
        message: "Internal server error".into(),
        status_code: Some(500),
    };
    assert!(err.is_retryable());
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::External { retryable, .. } if retryable));
}

#[fcp_async_core::runtime::test]
async fn error_rate_limited_maps_to_fcp_rate_limited() {
    let err = AirtableError::RateLimited {
        retry_after_secs: 30,
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::RateLimited {
            retry_after_ms: 30000,
            ..
        }
    ));
    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(Duration::from_secs(30)));
}

#[fcp_async_core::runtime::test]
async fn error_unauthorized_maps_to_fcp_unauthorized() {
    let err = AirtableError::Unauthorized;
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_not_found_variants_map_to_resource_not_found() {
    let base_err = AirtableError::BaseNotFound {
        base_id: "appXXX".into(),
    };
    assert!(
        matches!(base_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("appXXX"))
    );

    let record_err = AirtableError::RecordNotFound {
        record_id: "recYYY".into(),
    };
    assert!(
        matches!(record_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("recYYY"))
    );

    let table_err = AirtableError::TableNotFound {
        table_id: "tblZZZ".into(),
    };
    assert!(
        matches!(table_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("tblZZZ"))
    );
}

// ── Redaction ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_display_does_not_leak_token() {
    let err = AirtableError::Unauthorized;
    let msg = err.to_string();
    assert!(!msg.contains("pat_test_token_123"));
}

#[fcp_async_core::runtime::test]
async fn api_error_display_does_not_leak_token() {
    let err = AirtableError::Api {
        error_type: "INVALID_API_KEY".into(),
        message: "The API key is invalid".into(),
        status_code: Some(401),
    };
    let msg = err.to_string();
    assert!(!msg.contains("pat_test_token_123"));
}

// ── Client operations ───────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_list_bases() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bases": [
                { "id": "appABC", "name": "Projects", "permissionLevel": "create" },
                { "id": "appDEF", "name": "CRM", "permissionLevel": "read" }
            ]
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client.list_bases(None).await.unwrap();
    assert_eq!(result.bases.len(), 2);
    assert_eq!(result.bases[0].id, "appABC");
    assert_eq!(result.bases[1].name, "CRM");
}

#[fcp_async_core::runtime::test]
async fn client_get_base_schema() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC/tables"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [{
                "id": "tbl001",
                "name": "Tasks",
                "fields": [
                    { "id": "fldA", "name": "Name", "type": "singleLineText" },
                    { "id": "fldB", "name": "Status", "type": "singleSelect" }
                ],
                "views": [
                    { "id": "viw1", "name": "Grid view", "type": "grid" }
                ]
            }]
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client.get_base_schema("appABC").await.unwrap();
    assert_eq!(result.tables.len(), 1);
    assert_eq!(result.tables[0].name, "Tasks");
    assert_eq!(result.tables[0].fields.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn client_list_records() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("rec001", &json!({"Name": "Alpha"})),
                record_json("rec002", &json!({"Name": "Beta"}))
            ],
            "offset": "itr123"
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .list_records("appABC", "tblXYZ", None, None, None, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].id, "rec001");
    assert_eq!(result.offset.as_deref(), Some("itr123"));
}

#[fcp_async_core::runtime::test]
async fn client_get_record() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/appABC/tblXYZ/rec001"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(record_json(
            "rec001",
            &json!({"Name": "Alpha", "Status": "Active"}),
        )))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let record = client
        .get_record("appABC", "tblXYZ", "rec001")
        .await
        .unwrap();
    assert_eq!(record.id, "rec001");
    assert_eq!(record.fields["Name"], "Alpha");
}

#[fcp_async_core::runtime::test]
async fn client_create_record() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/appABC/tblXYZ"))
        .and(bearer_token("test_tok"))
        .and(header("content-type", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(record_json("recNEW", &json!({"Name": "New Item"}))),
        )
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let fields = json!({"Name": "New Item"});
    let record = client
        .create_record("appABC", "tblXYZ", &fields, None)
        .await
        .unwrap();
    assert_eq!(record.id, "recNEW");
}

#[fcp_async_core::runtime::test]
async fn client_update_record() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/appABC/tblXYZ/recUPD"))
        .and(bearer_token("test_tok"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(record_json("recUPD", &json!({"Status": "Done"}))),
        )
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let fields = json!({"Status": "Done"});
    let record = client
        .update_record("appABC", "tblXYZ", "recUPD", &fields, None)
        .await
        .unwrap();
    assert_eq!(record.id, "recUPD");
    assert_eq!(record.fields["Status"], "Done");
}

#[fcp_async_core::runtime::test]
async fn client_replace_record() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/appABC/tblXYZ/recREP"))
        .and(bearer_token("test_tok"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(record_json("recREP", &json!({"Name": "Replaced"}))),
        )
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let fields = json!({"Name": "Replaced"});
    let record = client
        .replace_record("appABC", "tblXYZ", "recREP", &fields)
        .await
        .unwrap();
    assert_eq!(record.id, "recREP");
}

#[fcp_async_core::runtime::test]
async fn client_delete_record() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/appABC/tblXYZ/recDEL"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "recDEL",
            "deleted": true
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .delete_record("appABC", "tblXYZ", "recDEL")
        .await
        .unwrap();
    assert!(result.deleted);
    assert_eq!(result.id, "recDEL");
}

#[fcp_async_core::runtime::test]
async fn client_create_records_batch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/appABC/tblXYZ"))
        .and(bearer_token("test_tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recB1", &json!({"Name": "Batch 1"})),
                record_json("recB2", &json!({"Name": "Batch 2"}))
            ]
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let records = vec![
        json!({"fields": {"Name": "Batch 1"}}),
        json!({"fields": {"Name": "Batch 2"}}),
    ];
    let result = client
        .create_records("appABC", "tblXYZ", &records, None)
        .await
        .unwrap();
    assert_eq!(result.records.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn client_rate_limit_no_retry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "45"))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(0, 100, 100);
    let result = client.list_bases(None).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AirtableError::RateLimited {
            retry_after_secs: 45
        }
    ));
}

#[fcp_async_core::runtime::test]
async fn client_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": { "type": "AUTHENTICATION_REQUIRED", "message": "Invalid API key" }
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("bad_token")
        .unwrap()
        .with_base_url(server.uri());
    let result = client.list_bases(None).await;
    assert!(matches!(result.unwrap_err(), AirtableError::Unauthorized));
}

// ── Connector-level invoke ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_list_bases_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bases": [{ "id": "appABC", "name": "Test Base" }]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.list_bases"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_bases");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_bases",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["bases"][0]["id"], "appABC");
}

#[fcp_async_core::runtime::test]
async fn invoke_get_record_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/appABC/tblXYZ/rec001"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(record_json("rec001", &json!({"Name": "Test"}))),
        )
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.get_record"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.get_record");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.get_record",
            "input": {
                "base_id": "appABC",
                "table_id": "tblXYZ",
                "record_id": "rec001"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["id"], "rec001");
    assert_eq!(result["fields"]["Name"], "Test");
}

#[fcp_async_core::runtime::test]
async fn invoke_create_record_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/appABC/tblXYZ"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(record_json("recNEW", &json!({"Name": "Created"}))),
        )
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.create_record"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.create_record");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.create_record",
            "input": {
                "base_id": "appABC",
                "table_id": "tblXYZ",
                "fields": { "Name": "Created" }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["id"], "recNEW");
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_record_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/appABC/tblXYZ/recDEL"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "recDEL",
            "deleted": true
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.delete_record"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.delete_record");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.delete_record",
            "input": {
                "base_id": "appABC",
                "table_id": "tblXYZ",
                "record_id": "recDEL"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn invoke_wrong_capability_rejected() {
    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.read"]).await;
    setup_configure(&mut connector, "http://localhost:1").await;

    // Token is for airtable.read, but we're invoking a write operation
    let token = generate_valid_token(&signing_key, "airtable.read");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.create_record",
            "input": {
                "base_id": "appABC",
                "table_id": "tblXYZ",
                "fields": { "Name": "Fail" }
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_rejected() {
    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.nonexistent"]).await;
    setup_configure(&mut connector, "http://localhost:1").await;

    let token = generate_valid_token(&signing_key, "airtable.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FcpError::OperationNotGranted { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_required_field_rejected() {
    let server = MockServer::start().await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.get_record"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.get_record");
    // Missing table_id and record_id
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.get_record",
            "input": { "base_id": "appABC" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("table_id"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
