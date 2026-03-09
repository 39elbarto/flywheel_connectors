//! Integration tests for the Airtable connector.
//!
//! Covers error taxonomy mapping, credential redaction, client operations
//! (bases, records, schema, attachments), and connector-level invoke routing.

use std::time::Duration;

use chrono::Utc;
use fcp_airtable::{
    client::AirtableClient, connector::AirtableConnector, error::AirtableError, types::SortSpec,
};
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use serde_json::json;
use wiremock::matchers::{bearer_token, body_json, header, method, path, query_param};
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

fn field_named<'a>(fields: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    fields
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["name"] == name)
        .unwrap()
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
async fn error_api_invalid_formula_maps_to_invalid_request() {
    let err = AirtableError::Api {
        error_type: "INVALID_REQUEST_UNKNOWN".into(),
        message: "Unknown field names in formula".into(),
        status_code: Some(422),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::InvalidRequest { code: 1003, message }
            if message == "Unknown field names in formula"
    ));
}

#[fcp_async_core::runtime::test]
async fn error_invalid_attachment_url_maps_to_invalid_request() {
    let err = AirtableError::InvalidAttachmentUrl {
        message: "Attachment URL must use https".into(),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::InvalidRequest { code: 1003, message }
            if message == "Attachment URL must use https"
    ));
}

#[fcp_async_core::runtime::test]
async fn error_attachment_too_large_maps_to_invalid_request() {
    let err = AirtableError::AttachmentTooLarge { max_bytes: 4096 };
    let fcp = err.to_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::InvalidRequest { code: 1003, message }
            if message.contains("4096")
    ));
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
async fn client_list_records_encodes_view_filter_and_sort_params() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/appABC/tblXYZ"))
        .and(bearer_token("test_tok"))
        .and(query_param("fields[]", "Name"))
        .and(query_param("filterByFormula", "{Status} = \"Active\""))
        .and(query_param("maxRecords", "25"))
        .and(query_param("pageSize", "10"))
        .and(query_param("sort[0][field]", "Priority"))
        .and(query_param("sort[0][direction]", "desc"))
        .and(query_param("view", "viwOPEN"))
        .and(query_param("offset", "itrNEXT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [record_json("rec001", &json!({"Name": "Alpha"}))],
            "offset": "itrNEXT"
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let fields = vec!["Name".to_string()];
    let sort = vec![SortSpec {
        field: "Priority".into(),
        direction: "desc".into(),
    }];
    let result = client
        .list_records(
            "appABC",
            "tblXYZ",
            Some(&fields),
            Some("{Status} = \"Active\""),
            Some(25),
            Some(10),
            Some(&sort),
            Some("viwOPEN"),
            Some("itrNEXT"),
        )
        .await
        .unwrap();

    assert_eq!(result.records.len(), 1);
    assert_eq!(result.offset.as_deref(), Some("itrNEXT"));
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
async fn client_update_records_batch() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/appABC/tblXYZ"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recU1", &json!({"Status": "Done"})),
                record_json("recU2", &json!({"Status": "Done"}))
            ]
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .update_records(
            "appABC",
            "tblXYZ",
            &[
                json!({"id": "recU1", "fields": {"Status": "Done"}}),
                json!({"id": "recU2", "fields": {"Status": "Done"}}),
            ],
            Some(true),
        )
        .await
        .unwrap();
    assert_eq!(result.records.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn client_upsert_records_batch() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/appABC/tblXYZ"))
        .and(body_json(json!({
            "records": [
                { "fields": { "External ID": "ext-1", "Name": "Alpha" } }
            ],
            "performUpsert": {
                "fieldsToMergeOn": ["External ID"]
            },
            "typecast": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recUPS", &json!({"External ID": "ext-1", "Name": "Alpha"}))
            ],
            "createdRecords": ["recUPS"],
            "updatedRecords": []
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .upsert_records(
            "appABC",
            "tblXYZ",
            &[json!({"fields": {"External ID": "ext-1", "Name": "Alpha"}})],
            &[String::from("External ID")],
            Some(true),
        )
        .await
        .unwrap();
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.created_records, vec!["recUPS"]);
    assert!(result.updated_records.is_empty());
}

#[fcp_async_core::runtime::test]
async fn client_delete_records_batch() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/appABC/tblXYZ"))
        .and(query_param("records[]", "recDEL1"))
        .and(query_param("records[]", "recDEL2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                { "id": "recDEL1", "deleted": true },
                { "id": "recDEL2", "deleted": true }
            ]
        })))
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let result = client
        .delete_records(
            "appABC",
            "tblXYZ",
            &[String::from("recDEL1"), String::from("recDEL2")],
        )
        .await
        .unwrap();
    assert_eq!(result.records.len(), 2);
    assert!(result.records.iter().all(|record| record.deleted));
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

#[fcp_async_core::runtime::test]
async fn client_download_attachment_rejects_disallowed_host_without_leaking_query() {
    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url("https://api.airtable.com/v0");

    let result = client
        .download_attachment("https://evil.example.com/file.txt?sig=super-secret-token")
        .await;

    let err = result.unwrap_err();
    let rendered = err.to_string();
    assert!(matches!(err, AirtableError::InvalidAttachmentUrl { .. }));
    assert!(rendered.contains("evil.example.com"));
    assert!(!rendered.contains("super-secret-token"));
    assert!(!rendered.contains("file.txt?"));
}

#[fcp_async_core::runtime::test]
async fn client_download_attachment_rejects_oversized_content_length() {
    use fcp_async_core::io::AsyncWriteExt;

    let listener = fcp_async_core::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = fcp_async_core::task::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 104857601\r\n\r\n",
            )
            .await
            .unwrap();
    });

    let base_url = format!("http://{addr}");
    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(&base_url);
    let url = format!("{base_url}/attachment.bin");
    let result = client.download_attachment(&url).await;

    assert!(matches!(
        result.unwrap_err(),
        AirtableError::AttachmentTooLarge {
            max_bytes: 104_857_600
        }
    ));
    server.await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn client_download_attachment_follows_local_redirects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/final/attachment.txt"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/final/attachment.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .insert_header(
                    "content-disposition",
                    "attachment; filename=\"attachment.txt\"",
                )
                .set_body_bytes(b"hello airtable".to_vec()),
        )
        .mount(&server)
        .await;

    let client = AirtableClient::new("test_tok")
        .unwrap()
        .with_base_url(server.uri());
    let url = format!("{}/redirect", server.uri());
    let result = client.download_attachment(&url).await.unwrap();

    assert_eq!(result.content_type, "text/plain");
    assert_eq!(result.filename.as_deref(), Some("attachment.txt"));
    assert_eq!(result.data, "aGVsbG8gYWlydGFibGU=");
}

// ── Connector-level invoke ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_download_attachment_rejects_disallowed_host() {
    let server = MockServer::start().await;
    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(
        &mut connector,
        &signing_key,
        &["airtable.download_attachment"],
    )
    .await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.download_attachment");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.download_attachment",
            "input": {
                "url": "https://evil.example.com/file.txt?sig=super-secret-token"
            },
            "capability_token": token
        }))
        .await;

    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("evil.example.com"));
            assert!(!message.contains("super-secret-token"));
        }
        other => panic!("Expected InvalidRequest, got {other:?}"),
    }
}

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
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblXYZ",
                    "name": "Tasks",
                    "fields": [{ "id": "fldNAME", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblXYZ/rec001"))
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
                "base_id": "appABC123",
                "table_id": "Tasks",
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
async fn invoke_get_record_expands_linked_records_and_marks_missing_targets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldNAME", "name": "Name", "type": "singleLineText" },
                        {
                            "id": "fldPROJ",
                            "name": "Project",
                            "type": "multipleRecordLinks",
                            "options": { "linkedTableId": "tblPROJ" }
                        },
                        { "id": "fldROLL", "name": "Rollup Score", "type": "rollup" }
                    ],
                    "views": []
                },
                {
                    "id": "tblPROJ",
                    "name": "Projects",
                    "fields": [
                        { "id": "fldPNAME", "name": "Name", "type": "singleLineText" }
                    ],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK/rec001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(record_json(
            "rec001",
            &json!({
                "Name": "Task Alpha",
                "Project": ["recPROJ1", "recMISS1"],
                "Rollup Score": 42
            }),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblPROJ/recPROJ1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(record_json("recPROJ1", &json!({ "Name": "Project One" }))),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblPROJ/recMISS1"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "type": "NOT_FOUND", "message": "Could not find record recMISS1" }
        })))
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
                "base_id": "appABC123",
                "table_id": "Tasks",
                "record_id": "rec001",
                "expand_linked_records": true,
                "linked_field_refs": ["Project"],
                "linked_record_depth": 2,
                "linked_record_limit": 5
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["field_metadata"]["Rollup Score"]["read_only"], true);
    assert_eq!(
        result["field_metadata"]["Project"]["linked_table"]["id"],
        "tblPROJ"
    );
    assert_eq!(
        result["linked_records"]["Project"]["records"][0]["field_metadata"]["Name"]["field_type"],
        "singleLineText"
    );
    assert_eq!(
        result["linked_records"]["Project"]["records"][1]["id"],
        "recMISS1"
    );
    assert_eq!(
        result["linked_records"]["Project"]["records"][1]["status"],
        "missing"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_list_tables_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldA", "name": "Name", "type": "singleLineText" }],
                    "views": [{ "id": "viwA", "name": "Grid", "type": "grid" }],
                    "primaryFieldId": "fldA"
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.list_tables"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_tables");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_tables",
            "input": { "base_id": "appABC123" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["tables"][0]["id"], "tblTASK");
    assert_eq!(result["tables"][0]["name"], "Tasks");
    assert_eq!(result["tables"][0]["fieldCount"], 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_get_table_rejects_ambiguous_table_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tbl1",
                    "name": "Tasks",
                    "fields": [{ "id": "fld1", "name": "Name", "type": "singleLineText" }],
                    "views": []
                },
                {
                    "id": "tbl2",
                    "name": "Tasks",
                    "fields": [{ "id": "fld2", "name": "Title", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.get_table"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.get_table");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.get_table",
            "input": { "base_id": "appABC123", "table_ref": "Tasks" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("Ambiguous table_ref"));
        }
        other => panic!("Expected InvalidRequest, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_list_fields_resolves_ids_and_names() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldA", "name": "Name", "type": "singleLineText" },
                        { "id": "fldB", "name": "Status", "type": "singleSelect" }
                    ],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.list_fields"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_fields");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_fields",
            "input": {
                "base_id": "appABC123",
                "table_ref": "tblTASK",
                "field_refs": ["fldA", "Status"]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["fields"][0]["id"], "fldA");
    assert_eq!(result["fields"][1]["name"], "Status");
}

#[fcp_async_core::runtime::test]
async fn invoke_get_base_schema_marks_formula_and_system_fields_read_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldNAME", "name": "Name", "type": "singleLineText" },
                        { "id": "fldFORM", "name": "Formula Score", "type": "formula" },
                        {
                            "id": "fldLOOK",
                            "name": "Project Name",
                            "type": "lookup",
                            "options": { "linkedTableId": "tblPROJ" }
                        },
                        { "id": "fldAUTO", "name": "Autonumber", "type": "autoNumber" }
                    ],
                    "views": []
                },
                {
                    "id": "tblPROJ",
                    "name": "Projects",
                    "fields": [{ "id": "fldP", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.get_base_schema"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.get_base_schema");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.get_base_schema",
            "input": { "base_id": "appABC123" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let fields = &result["tables"][0]["fields"];
    let formula = field_named(fields, "Formula Score");
    assert_eq!(formula["read_only"], true);
    assert_eq!(formula["computed"], true);
    assert_eq!(formula["computed_kind"], "formula");
    assert_eq!(formula["read_only_reason"], "computed");

    let lookup = field_named(fields, "Project Name");
    assert_eq!(lookup["computed"], true);
    assert_eq!(lookup["linked_table"]["id"], "tblPROJ");

    let auto_number = field_named(fields, "Autonumber");
    assert_eq!(auto_number["read_only"], true);
    assert_eq!(auto_number["computed"], false);
    assert_eq!(auto_number["read_only_reason"], "system_managed");
}

#[fcp_async_core::runtime::test]
async fn invoke_list_views_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldA", "name": "Name", "type": "singleLineText" }],
                    "views": [
                        { "id": "viwGRID", "name": "Grid", "type": "grid" },
                        { "id": "viwOPEN", "name": "Open Tasks", "type": "grid" }
                    ]
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.list_views"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_views");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_views",
            "input": { "base_id": "appABC123", "table_ref": "tblTASK" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["table"]["id"], "tblTASK");
    assert_eq!(result["views"].as_array().unwrap().len(), 2);
    assert_eq!(result["views"][1]["id"], "viwOPEN");
}

#[fcp_async_core::runtime::test]
async fn invoke_get_view_rejects_ambiguous_view_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldA", "name": "Name", "type": "singleLineText" }],
                    "views": [
                        { "id": "viwONE", "name": "Grid", "type": "grid" },
                        { "id": "viwTWO", "name": "Grid", "type": "calendar" }
                    ]
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.get_view"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.get_view");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.get_view",
            "input": {
                "base_id": "appABC123",
                "table_ref": "tblTASK",
                "view_ref": "Grid"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("Ambiguous view_ref"));
        }
        other => panic!("Expected InvalidRequest, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_list_view_records_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldA", "name": "Name", "type": "singleLineText" },
                        { "id": "fldB", "name": "Status", "type": "singleSelect" }
                    ],
                    "views": [
                        { "id": "viwOPEN", "name": "Open Tasks", "type": "grid" }
                    ]
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK"))
        .and(query_param("fields[]", "Name"))
        .and(query_param("fields[]", "Status"))
        .and(query_param("view", "viwOPEN"))
        .and(query_param("filterByFormula", "{Status} = \"Open\""))
        .and(query_param("pageSize", "2"))
        .and(query_param("offset", "itr123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("rec001", &json!({"Name": "Alpha", "Status": "Open"})),
                record_json("rec002", &json!({"Name": "Beta", "Status": "Open"}))
            ],
            "offset": "itr456"
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(
        &mut connector,
        &signing_key,
        &["airtable.list_view_records"],
    )
    .await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_view_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_view_records",
            "input": {
                "base_id": "appABC123",
                "table_ref": "tblTASK",
                "view_ref": "Open Tasks",
                "fields": ["fldA", "Status"],
                "filter_by_formula": "{Status} = \"Open\"",
                "page_size": 2,
                "offset": "itr123"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["table"]["id"], "tblTASK");
    assert_eq!(result["view"]["id"], "viwOPEN");
    assert_eq!(result["records"].as_array().unwrap().len(), 2);
    assert_eq!(result["offset"], "itr456");
}

#[fcp_async_core::runtime::test]
async fn invoke_list_view_records_requires_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldA", "name": "Name", "type": "singleLineText" }],
                    "views": [{ "id": "viwOPEN", "name": "Open Tasks", "type": "grid" }]
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(
        &mut connector,
        &signing_key,
        &["airtable.list_view_records"],
    )
    .await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_view_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_view_records",
            "input": {
                "base_id": "appABC123",
                "table_ref": "tblTASK",
                "view_ref": "viwOPEN"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("fields"));
        }
        other => panic!("Expected InvalidRequest, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_list_records_rejects_control_chars_in_filter_formula() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldA", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.list_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "tblTASK",
                "filter_by_formula": "{Name} = \"Alpha\"\nOR(1,1)"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("control characters"));
        }
        other => panic!("Expected InvalidRequest, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_list_records_marks_formula_field_metadata_and_maps_formula_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldNAME", "name": "Name", "type": "singleLineText" },
                        { "id": "fldFORM", "name": "Formula Score", "type": "formula" }
                    ],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK"))
        .and(query_param("filterByFormula", "{Formula Score} > 10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("rec001", &json!({
                    "Name": "Alpha",
                    "Formula Score": 42
                }))
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.list_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "tblTASK",
                "fields": ["Name", "Formula Score"],
                "filter_by_formula": "{Formula Score} > 10"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["field_metadata"]["Formula Score"]["read_only"], true);
    assert_eq!(result["field_metadata"]["Formula Score"]["computed"], true);
    assert_eq!(
        result["field_metadata"]["Formula Score"]["computed_kind"],
        "formula"
    );
    assert_eq!(
        result["field_metadata"]["Formula Score"]["read_only_reason"],
        "computed"
    );

    let failing_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldNAME", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&failing_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK"))
        .and(query_param(
            "filterByFormula",
            "{Missing Field} = \"Alpha\"",
        ))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "error": {
                "type": "INVALID_REQUEST_UNKNOWN",
                "message": "Unknown field names in formula"
            }
        })))
        .mount(&failing_server)
        .await;

    let mut failing_connector = AirtableConnector::new();
    setup_handshake(
        &mut failing_connector,
        &signing_key,
        &["airtable.list_records"],
    )
    .await;
    setup_configure(&mut failing_connector, &failing_server.uri()).await;

    let failing_result = failing_connector
        .handle_invoke(json!({
            "operation": "airtable.list_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "tblTASK",
                "filter_by_formula": "{Missing Field} = \"Alpha\""
            },
            "capability_token": token
        }))
        .await;

    assert!(matches!(
        failing_result,
        Err(FcpError::InvalidRequest { code: 1003, message })
            if message == "Unknown field names in formula"
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_list_records_expands_linked_cycles_without_refetching_root() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldNAME", "name": "Name", "type": "singleLineText" },
                        {
                            "id": "fldPARENT",
                            "name": "Parent Task",
                            "type": "multipleRecordLinks",
                            "options": { "linkedTableId": "tblTASK" }
                        }
                    ],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recA", &json!({
                    "Name": "Task A",
                    "Parent Task": ["recB"]
                }))
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK/recB"))
        .respond_with(ResponseTemplate::new(200).set_body_json(record_json(
            "recB",
            &json!({
                "Name": "Task B",
                "Parent Task": ["recA"]
            }),
        )))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.list_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "tblTASK",
                "expand_linked_records": true,
                "linked_field_refs": ["Parent Task"],
                "linked_record_depth": 2
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(
        result["field_metadata"]["Parent Task"]["linked_table"]["id"],
        "tblTASK"
    );
    assert_eq!(
        result["records"][0]["linked_records"]["Parent Task"]["records"][0]["id"],
        "recB"
    );
    assert_eq!(
        result["records"][0]["linked_records"]["Parent Task"]["records"][0]["linked_records"]["Parent Task"]
            ["records"][0]["id"],
        "recA"
    );
    assert_eq!(
        result["records"][0]["linked_records"]["Parent Task"]["records"][0]["linked_records"]["Parent Task"]
            ["records"][0]["status"],
        "cycle"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_list_records_marks_truncated_linked_records_when_limit_is_exhausted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldNAME", "name": "Name", "type": "singleLineText" },
                        {
                            "id": "fldCHILD",
                            "name": "Child Tasks",
                            "type": "multipleRecordLinks",
                            "options": { "linkedTableId": "tblTASK" }
                        }
                    ],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recROOT", &json!({
                    "Name": "Root",
                    "Child Tasks": ["recCHILD1", "recCHILD2"]
                }))
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/appABC123/tblTASK/recCHILD1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(record_json("recCHILD1", &json!({ "Name": "Child One" }))),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.list_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.list_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "tblTASK",
                "expand_linked_records": true,
                "linked_field_refs": ["Child Tasks"],
                "linked_record_depth": 1,
                "linked_record_limit": 1
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(
        result["records"][0]["linked_records"]["Child Tasks"]["partial"],
        true
    );
    assert_eq!(
        result["records"][0]["linked_records"]["Child Tasks"]["records"][0]["id"],
        "recCHILD1"
    );
    assert_eq!(
        result["records"][0]["linked_records"]["Child Tasks"]["records"][1]["id"],
        "recCHILD2"
    );
    assert_eq!(
        result["records"][0]["linked_records"]["Child Tasks"]["records"][1]["status"],
        "truncated"
    );
}

#[fcp_async_core::runtime::test]
async fn discovery_ops_reuse_schema_cache_within_ttl() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldA", "name": "Name", "type": "singleLineText" }
                    ],
                    "views": []
                }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(
        &mut connector,
        &signing_key,
        &["airtable.list_tables", "airtable.list_fields"],
    )
    .await;
    setup_configure(&mut connector, &server.uri()).await;

    let list_tables_token = generate_valid_token(&signing_key, "airtable.list_tables");
    connector
        .handle_invoke(json!({
            "operation": "airtable.list_tables",
            "input": { "base_id": "appABC123" },
            "capability_token": list_tables_token
        }))
        .await
        .unwrap();

    let list_fields_token = generate_valid_token(&signing_key, "airtable.list_fields");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.list_fields",
            "input": { "base_id": "appABC123", "table_ref": "tblTASK" },
            "capability_token": list_fields_token
        }))
        .await
        .unwrap();

    assert_eq!(result["fields"][0]["id"], "fldA");
}

#[fcp_async_core::runtime::test]
async fn invoke_create_record_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblXYZ",
                    "name": "Tasks",
                    "fields": [{ "id": "fldNAME", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/appABC123/tblXYZ"))
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
                "base_id": "appABC123",
                "table_id": "Tasks",
                "fields": { "Name": "Created" }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["id"], "recNEW");
}

#[fcp_async_core::runtime::test]
async fn invoke_create_records_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblXYZ",
                    "name": "Tasks",
                    "fields": [{ "id": "fldNAME", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/appABC123/tblXYZ"))
        .and(body_json(json!({
            "records": [
                { "fields": { "Name": "Created A" } },
                { "fields": { "Name": "Created B" } }
            ]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recA", &json!({"Name": "Created A"})),
                record_json("recB", &json!({"Name": "Created B"}))
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["airtable.create_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.create_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.create_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "Tasks",
                "records": [
                    { "fields": { "Name": "Created A" } },
                    { "fields": { "Name": "Created B" } }
                ]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["records"].as_array().unwrap().len(), 2);
    assert_eq!(result["records"][0]["id"], "recA");
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_record_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblXYZ",
                    "name": "Tasks",
                    "fields": [{ "id": "fldNAME", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/appABC123/tblXYZ/recDEL"))
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
                "base_id": "appABC123",
                "table_id": "Tasks",
                "record_id": "recDEL"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn invoke_update_records_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldSTAT", "name": "Status", "type": "singleSelect" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/appABC123/tblTASK"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recU1", &json!({"Status": "Done"})),
                record_json("recU2", &json!({"Status": "Done"}))
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.update_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.update_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.update_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "Tasks",
                "records": [
                    {"id": "recU1", "fields": {"Status": "Done"}},
                    {"id": "recU2", "fields": {"Status": "Done"}}
                ],
                "typecast": true
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["records"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn invoke_upsert_records_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [
                        { "id": "fldEXT", "name": "External ID", "type": "singleLineText" },
                        { "id": "fldNAME", "name": "Name", "type": "singleLineText" }
                    ],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/appABC123/tblTASK"))
        .and(body_json(json!({
            "records": [
                { "fields": { "External ID": "ext-1", "Name": "Alpha" } }
            ],
            "performUpsert": {
                "fieldsToMergeOn": ["External ID"]
            },
            "typecast": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                record_json("recUPS", &json!({"External ID": "ext-1", "Name": "Alpha"}))
            ],
            "createdRecords": ["recUPS"],
            "updatedRecords": []
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.upsert_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.upsert_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.upsert_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "Tasks",
                "fields_to_merge_on": ["fldEXT"],
                "records": [
                    {"fields": {"External ID": "ext-1", "Name": "Alpha"}}
                ],
                "typecast": true
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["createdRecords"][0], "recUPS");
    assert_eq!(result["records"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_records_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldNAME", "name": "Name", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/appABC123/tblTASK"))
        .and(query_param("records[]", "recDEL1"))
        .and(query_param("records[]", "recDEL2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "records": [
                { "id": "recDEL1", "deleted": true },
                { "id": "recDEL2", "deleted": true }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.delete_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.delete_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.delete_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "Tasks",
                "record_ids": ["recDEL1", "recDEL2"]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["records"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn invoke_upsert_records_requires_merge_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/meta/bases/appABC123/tables"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tables": [
                {
                    "id": "tblTASK",
                    "name": "Tasks",
                    "fields": [{ "id": "fldEXT", "name": "External ID", "type": "singleLineText" }],
                    "views": []
                }
            ]
        })))
        .mount(&server)
        .await;

    let mut connector = AirtableConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    setup_handshake(&mut connector, &signing_key, &["airtable.upsert_records"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "airtable.upsert_records");
    let result = connector
        .handle_invoke(json!({
            "operation": "airtable.upsert_records",
            "input": {
                "base_id": "appABC123",
                "table_id": "Tasks",
                "fields_to_merge_on": [],
                "records": [{"fields": {"External ID": "ext-1"}}]
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("fields_to_merge_on"));
        }
        other => panic!("Expected InvalidRequest, got {other:?}"),
    }
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
