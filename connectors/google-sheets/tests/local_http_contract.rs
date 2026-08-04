use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_discovery::auth::{
    FCP_CREDENTIAL_ID_HEADER, GOOGLE_AUTHORIZATION_HEADER, GoogleAuthSourceKind,
    GoogleMaterializedAuth,
};
use fcp_google_sheets::client::SheetsClient;
use fcp_google_sheets::connector::SheetsConnector;
use fcp_google_sheets::types::{BatchUpdateValuesRequest, ValueRange};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest, InstanceId,
    ZoneId,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn fixture_bearer() -> String {
    "test-token".to_owned()
}

#[fcp_async_core::runtime::test]
async fn bearer_token_requests_use_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "properties": { "title": "Auth Header" },
            "sheets": [],
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/sheet123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
        access_token: fixture_bearer(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: Vec::new(),
        quota_project_id: None,
    })
    .expect("client")
    .with_base_url(format!("{}/v4", server.uri()));

    let spreadsheet = client
        .get_spreadsheet("sheet123")
        .await
        .expect("spreadsheet response");
    assert_eq!(spreadsheet.spreadsheet_id, "sheet123");
}

#[fcp_async_core::runtime::test]
async fn credential_reference_requests_use_fcp_credential_header() {
    let server = MockServer::start().await;
    let credential_id = fcp_core::CredentialId::new();
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .and(header(FCP_CREDENTIAL_ID_HEADER, credential_id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "properties": { "title": "Credential Header" },
            "sheets": [],
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/sheet123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
        credential_id,
        quota_project_id: None,
    })
    .expect("client")
    .with_base_url(format!("{}/v4", server.uri()));

    let spreadsheet = client
        .get_spreadsheet("sheet123")
        .await
        .expect("spreadsheet response");
    assert_eq!(spreadsheet.spreadsheet_id, "sheet123");
}

fn test_client(server: &MockServer) -> SheetsClient {
    SheetsClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
        access_token: fixture_bearer(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: Vec::new(),
        quota_project_id: None,
    })
    .expect("client")
    .with_base_url(format!("{}/v4", server.uri()))
}

async fn configured_connector_token(
    server: &MockServer,
    capability: &'static str,
    operations: &[&'static str],
) -> (SheetsConnector, CapabilityToken) {
    let mut connector = SheetsConnector::new();
    connector
        .handle_configure(json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/v4", server.uri()),
        }))
        .await
        .unwrap();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .handle_handshake(
            serde_json::to_value(HandshakeRequest {
                protocol_version: "2.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [7_u8; 32],
                capabilities_requested: vec![CapabilityId::from_static(capability)],
                host: None,
                transport_caps: None,
                requested_instance_id: Some(instance_id.clone()),
            })
            .unwrap(),
        )
        .await
        .unwrap();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["google-sheets:spreadsheet:sheet123".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .target_instance(instance_id.as_str())
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(&signing_key)
            .unwrap(),
    );
    (connector, token)
}

#[fcp_async_core::runtime::test]
async fn batch_values_preserves_formulas_and_atomic_payload() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v4/spreadsheets/sheet123/values:batchUpdate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "totalUpdatedRows": 2,
            "totalUpdatedColumns": 2,
            "totalUpdatedCells": 4,
            "totalUpdatedSheets": 1,
            "responses": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = test_client(&server)
        .batch_update_values(
            "sheet123",
            &BatchUpdateValuesRequest {
                value_input_option: "USER_ENTERED".into(),
                data: vec![ValueRange {
                    range: "Sheet1!A1:B2".into(),
                    major_dimension: "ROWS".into(),
                    values: vec![vec![json!("=SUM(B1:B2)"), json!(42)]],
                }],
                include_values_in_response: true,
                response_value_render_option: Some("FORMULA".into()),
                response_date_time_render_option: Some("SERIAL_NUMBER".into()),
            },
        )
        .await
        .expect("batch values response");
    assert_eq!(response.total_updated_cells, 4);
}

#[fcp_async_core::runtime::test]
async fn paged_values_cover_explicit_range_once_and_reject_tampered_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values/Sheet1%21A1%3AB2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "range": "Sheet1!A1:B2",
            "majorDimension": "ROWS",
            "values": [["r1", 1], ["r2", 2]]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values/Sheet1%21A3%3AB4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "range": "Sheet1!A3:B4",
            "majorDimension": "ROWS",
            "values": [["r3", 3], ["r4", 4]]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, token) =
        configured_connector_token(&server, "sheets.read", &["sheets.get_values_page"]).await;
    let first = connector
        .handle_invoke(json!({
            "operation": "sheets.get_values_page",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:B4",
                "page_size_rows": 2
            },
            "capability_token": token.clone()
        }))
        .await
        .expect("first bounded page");
    assert_eq!(first["values"], json!([["r1", 1], ["r2", 2]]));
    assert_eq!(first["page"]["complete"], false);
    let page_token = first["page"]["page_token"]
        .as_str()
        .expect("continuation token")
        .to_string();

    let second = connector
        .handle_invoke(json!({
            "operation": "sheets.get_values_page",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:B4",
                "page_size_rows": 2,
                "page_token": page_token
            },
            "capability_token": token.clone()
        }))
        .await
        .expect("second bounded page");
    assert_eq!(second["values"], json!([["r3", 3], ["r4", 4]]));
    assert_eq!(second["page"]["complete"], true);
    assert!(second["page"]["page_token"].is_null());

    let mismatch = connector
        .handle_invoke(json!({
            "operation": "sheets.get_values_page",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:B4",
                "page_size_rows": 1,
                "page_token": first["page"]["page_token"]
            },
            "capability_token": token.clone()
        }))
        .await
        .expect_err("page token must reject mismatched paging options");
    assert!(matches!(mismatch, FcpError::InvalidRequest { .. }));

    let mut tampered = first["page"]["page_token"]
        .as_str()
        .expect("token")
        .as_bytes()
        .to_vec();
    tampered[0] = if tampered[0] == b'a' { b'b' } else { b'a' };
    let error = connector
        .handle_invoke(json!({
            "operation": "sheets.get_values_page",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:B4",
                "page_token": std::str::from_utf8(&tampered).unwrap()
            },
            "capability_token": token.clone()
        }))
        .await
        .expect_err("tampered page token must fail before provider I/O");
    assert!(matches!(error, FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn default_metadata_request_never_selects_grid_data() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "properties": {"title": "Metadata only"},
            "sheets": [{"properties": {"sheetId": 0, "title": "Sheet1"}}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, token) =
        configured_connector_token(&server, "sheets.read", &["sheets.get_spreadsheet"]).await;
    connector
        .handle_invoke(json!({
            "operation": "sheets.get_spreadsheet",
            "input": {"spreadsheet_id": "sheet123"},
            "capability_token": token
        }))
        .await
        .expect("metadata-only request");
    let requests = server.received_requests().await.unwrap();
    let fields = requests[0]
        .url
        .query_pairs()
        .find_map(|(key, value)| (key == "fields").then(|| value.into_owned()))
        .expect("explicit metadata field mask");
    assert!(!fields.contains("charts,data"));
    assert!(!fields.contains("sheets(data"));
    assert_eq!(
        requests[0]
            .url
            .query_pairs()
            .find_map(|(key, value)| (key == "includeGridData").then(|| value.into_owned())),
        Some("false".to_string())
    );
    let error = connector
        .handle_invoke(json!({
            "operation": "sheets.get_spreadsheet",
            "input": {
                "spreadsheet_id": "sheet123",
                "ranges": ["Sheet1!A1:B2"],
                "include_grid_data": true
            },
            "capability_token": token
        }))
        .await
        .expect_err("grid data must use an explicit values operation");
    assert!(matches!(error, FcpError::InvalidRequest { .. }));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn paged_values_shrink_provider_and_connector_results_to_bounded_pages() {
    let server = MockServer::start().await;
    let large_cell = "x".repeat(14_000);
    Mock::given(method("GET"))
        .and(path(
            "/v4/spreadsheets/sheet123/values/Sheet1%21A1%3AA4",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "range": "Sheet1!A1:A4",
            "majorDimension": "ROWS",
            "values": [[large_cell.clone()], [large_cell.clone()], [large_cell.clone()], [large_cell.clone()]]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values/Sheet1%21A1%3AA2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "range": "Sheet1!A1:A2",
            "majorDimension": "ROWS",
            "values": [[large_cell.clone()], [large_cell]]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, token) =
        configured_connector_token(&server, "sheets.read", &["sheets.get_values_page"]).await;
    let result = connector
        .handle_invoke(json!({
            "operation": "sheets.get_values_page",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:A4",
                "page_size_rows": 4
            },
            "capability_token": token
        }))
        .await
        .expect("connector should halve an oversized result page");
    assert_eq!(result["page"]["row_span"], 2);
    assert_eq!(result["values"].as_array().unwrap().len(), 2);
    assert!(serde_json::to_vec(&result).unwrap().len() <= 48 * 1024);
}

#[fcp_async_core::runtime::test]
async fn paged_values_retry_a_smaller_provider_range_after_ten_mib_limit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values/Sheet1%21A1%3AA2"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 10 * 1024 * 1024 + 1]))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values/Sheet1%21A1%3AA1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "range": "Sheet1!A1:A1",
            "majorDimension": "ROWS",
            "values": [["bounded"]]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values/Sheet1%21A2%3AA2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "range": "Sheet1!A2:A2",
            "majorDimension": "ROWS",
            "values": [["complete"]]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, token) =
        configured_connector_token(&server, "sheets.read", &["sheets.get_values_page"]).await;
    let result = connector
        .handle_invoke(json!({
            "operation": "sheets.get_values_page",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:A2",
                "page_size_rows": 2
            },
            "capability_token": token.clone()
        }))
        .await
        .expect("provider overflow should retry one smaller range");
    assert_eq!(result["page"]["row_span"], 1);
    assert_eq!(result["values"], json!([["bounded"]]));
    let continuation = result["page"]["page_token"]
        .as_str()
        .expect("continuation after adaptive shrink");
    let final_page = connector
        .handle_invoke(json!({
            "operation": "sheets.get_values_page",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:A2",
                "page_size_rows": 2,
                "page_token": continuation
            },
            "capability_token": token
        }))
        .await
        .expect("adaptive continuation completes the original range");
    assert_eq!(final_page["values"], json!([["complete"]]));
    assert_eq!(final_page["page"]["complete"], true);
}

#[fcp_async_core::runtime::test]
async fn oversized_structural_batch_is_rejected_before_atomic_provider_io() {
    let server = MockServer::start().await;
    let (mut connector, token) = configured_connector_token(
        &server,
        "sheets.structure.write",
        &["sheets.batch_update_spreadsheet"],
    )
    .await;
    let error = connector
        .handle_invoke(json!({
            "operation": "sheets.batch_update_spreadsheet",
            "input": {
                "spreadsheet_id": "sheet123",
                "requests": [{
                    "repeatCell": {
                        "range": {"sheetId": 0},
                        "cell": {"note": "x".repeat(50_000)},
                        "fields": "note"
                    }
                }]
            },
            "capability_token": token
        }))
        .await
        .expect_err("oversized atomic request must fail locally");
    assert!(matches!(error, FcpError::InvalidRequest { .. }));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn chunked_values_verify_each_chunk_and_stop_on_uncertain_provider_failure() {
    let server = MockServer::start().await;
    let writes = Arc::new(AtomicUsize::new(0));
    let writes_for_response = Arc::clone(&writes);
    Mock::given(method("POST"))
        .and(path("/v4/spreadsheets/sheet123/values:batchUpdate"))
        .respond_with(move |_request: &wiremock::Request| {
            if writes_for_response.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "spreadsheetId": "sheet123",
                    "totalUpdatedRows": 1,
                    "totalUpdatedColumns": 1,
                    "totalUpdatedCells": 1,
                    "totalUpdatedSheets": 1,
                    "responses": []
                }))
            } else {
                ResponseTemplate::new(500).set_body_json(json!({
                    "error": {"code": 500, "message": "synthetic uncertain write"}
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values:batchGet"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "valueRanges": [{
                "range": "Sheet1!A1:A1",
                "majorDimension": "ROWS",
                "values": [["one"]]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, token) = configured_connector_token(
        &server,
        "sheets.values.write",
        &["sheets.batch_update_values_chunked"],
    )
    .await;
    let result = connector
        .handle_invoke(json!({
            "operation": "sheets.batch_update_values_chunked",
            "input": {
                "spreadsheet_id": "sheet123",
                "data": [
                    {"range": "Sheet1!A1:A1", "values": [["one"]]},
                    {"range": "Sheet1!A2:A2", "values": [["two"]]}
                ],
                "chunk_size_ranges": 1,
                "confirm_independent_chunks": true
            },
            "capability_token": token
        }))
        .await
        .expect("uncertain chunk returns a non-retryable reconciliation receipt");
    assert_eq!(result["status"], "outcome_uncertain");
    assert_eq!(result["completed_chunks"], json!([0]));
    assert_eq!(result["failed_chunk"], 1);
    assert_eq!(result["readback"]["required"], true);
    assert_eq!(result["resume_safe"], false);
    assert!(result["resume_token"].is_null());
    assert_eq!(writes.load(Ordering::SeqCst), 2);
    assert_eq!(connector.provider_telemetry().7, 2);
}

#[fcp_async_core::runtime::test]
async fn chunked_values_provider_rejection_returns_target_bound_resume_token() {
    let server = MockServer::start().await;
    let writes = Arc::new(AtomicUsize::new(0));
    let writes_for_response = Arc::clone(&writes);
    Mock::given(method("POST"))
        .and(path("/v4/spreadsheets/sheet123/values:batchUpdate"))
        .respond_with(move |_request: &wiremock::Request| {
            if writes_for_response.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(400).set_body_json(json!({
                    "error": {"code": 400, "message": "synthetic invalid range"}
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "spreadsheetId": "sheet123",
                    "totalUpdatedRows": 1,
                    "totalUpdatedColumns": 1,
                    "totalUpdatedCells": 1,
                    "totalUpdatedSheets": 1,
                    "responses": []
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values:batchGet"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "valueRanges": [{
                "range": "Sheet1!A1:A1",
                "majorDimension": "ROWS",
                "values": [["one"]]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (mut connector, token) = configured_connector_token(
        &server,
        "sheets.values.write",
        &["sheets.batch_update_values_chunked"],
    )
    .await;
    let result = connector
        .handle_invoke(json!({
            "operation": "sheets.batch_update_values_chunked",
            "input": {
                "spreadsheet_id": "sheet123",
                "data": [{"range": "Sheet1!A1:A1", "values": [["one"]]}],
                "chunk_size_ranges": 1,
                "confirm_independent_chunks": true
            },
            "capability_token": token.clone()
        }))
        .await
        .expect("provider rejection returns resumable progress receipt");
    assert_eq!(result["status"], "provider_rejected");
    assert_eq!(result["resume_safe"], true);
    let resume_token = result["resume_token"]
        .as_str()
        .expect("safe resume token")
        .to_string();
    assert_eq!(result["readback"]["required"], false);

    let resumed = connector
        .handle_invoke(json!({
            "operation": "sheets.batch_update_values_chunked",
            "input": {
                "spreadsheet_id": "sheet123",
                "data": [{"range": "Sheet1!A1:A1", "values": [["one"]]}],
                "chunk_size_ranges": 1,
                "confirm_independent_chunks": true,
                "resume_token": resume_token
            },
            "capability_token": token
        }))
        .await
        .expect("same bound chunk plan resumes after explicit rejection");
    assert_eq!(resumed["status"], "applied_and_verified");
    assert_eq!(resumed["completed_chunks"], json!([0]));
    assert_eq!(writes.load(Ordering::SeqCst), 2);
}

#[fcp_async_core::runtime::test]
async fn structural_batch_and_copy_use_only_fixed_sheets_endpoints() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v4/spreadsheets/sheet123:batchUpdate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "replies": [{}, {"addSheet": {"properties": {"sheetId": 9}}}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v4/spreadsheets/sheet123/sheets/9:copyTo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sheetId": 10,
            "title": "Copy of Summary"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = test_client(&server);
    let response = client
        .batch_update_spreadsheet(
            "sheet123",
            &json!({
                "requests": [
                    {"repeatCell": {"range": {"sheetId": 0}, "cell": {"userEnteredFormat": {"textFormat": {"bold": true}}}, "fields": "userEnteredFormat.textFormat.bold"}},
                    {"addSheet": {"properties": {"title": "Summary"}}}
                ]
            }),
        )
        .await
        .expect("structural batch response");
    assert_eq!(response["replies"].as_array().unwrap().len(), 2);

    let copied = client
        .copy_sheet("sheet123", 9, "destination456")
        .await
        .expect("copy response");
    assert_eq!(copied["sheetId"], 10);
}

#[fcp_async_core::runtime::test]
async fn high_risk_clear_and_structural_delete_require_confirmation_and_read_back() {
    let clear_server = MockServer::start().await;
    let (mut clear_connector, clear_token) = configured_connector_token(
        &clear_server,
        "sheets.values.write",
        &["sheets.clear_values"],
    )
    .await;
    let denied_clear = clear_connector
        .handle_invoke(json!({
            "operation": "sheets.clear_values",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:B2"
            },
            "capability_token": clear_token.clone()
        }))
        .await
        .expect_err("clear without confirmation must fail before provider I/O");
    assert!(matches!(denied_clear, FcpError::InvalidRequest { .. }));
    assert!(clear_server.received_requests().await.unwrap().is_empty());

    let clear_reads = Arc::new(AtomicUsize::new(0));
    let clear_reads_for_response = Arc::clone(&clear_reads);
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123/values/Sheet1%21A1%3AB2"))
        .respond_with(move |_request: &wiremock::Request| {
            if clear_reads_for_response.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "range": "Sheet1!A1:B2",
                    "majorDimension": "ROWS",
                    "values": [["keep-a-copy", 42]]
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "range": "Sheet1!A1:B2",
                    "majorDimension": "ROWS",
                    "values": []
                }))
            }
        })
        .expect(2)
        .mount(&clear_server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v4/spreadsheets/sheet123/values/Sheet1%21A1%3AB2:clear",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "clearedRange": "Sheet1!A1:B2"
        })))
        .expect(1)
        .mount(&clear_server)
        .await;
    let clear_result = clear_connector
        .handle_invoke(json!({
            "operation": "sheets.clear_values",
            "input": {
                "spreadsheet_id": "sheet123",
                "range": "Sheet1!A1:B2",
                "confirm_clear": true
            },
            "capability_token": clear_token
        }))
        .await
        .expect("confirmed clear with preflight and readback");
    assert_eq!(
        clear_result["preflight"]["values"],
        json!([["keep-a-copy", 42]])
    );
    assert_eq!(clear_result["readback"]["values"], json!([]));
    assert_eq!(clear_reads.load(Ordering::SeqCst), 2);

    let structure_server = MockServer::start().await;
    let (mut structure_connector, structure_token) = configured_connector_token(
        &structure_server,
        "sheets.structure.write",
        &["sheets.batch_update_spreadsheet"],
    )
    .await;
    let delete_request = json!({"deleteSheet": {"sheetId": 7}});
    let denied_delete = structure_connector
        .handle_invoke(json!({
            "operation": "sheets.batch_update_spreadsheet",
            "input": {
                "spreadsheet_id": "sheet123",
                "requests": [delete_request.clone()]
            },
            "capability_token": structure_token.clone()
        }))
        .await
        .expect_err("structural delete without confirmation must fail before provider I/O");
    assert!(matches!(denied_delete, FcpError::InvalidRequest { .. }));
    assert!(
        structure_server
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );

    let metadata_reads = Arc::new(AtomicUsize::new(0));
    let metadata_reads_for_response = Arc::clone(&metadata_reads);
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .respond_with(move |_request: &wiremock::Request| {
            if metadata_reads_for_response.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "spreadsheetId": "sheet123",
                    "properties": {"title": "Safety fixture"},
                    "sheets": [{"properties": {"sheetId": 7, "title": "Delete me"}}]
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "spreadsheetId": "sheet123",
                    "properties": {"title": "Safety fixture"},
                    "sheets": []
                }))
            }
        })
        .expect(2)
        .mount(&structure_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v4/spreadsheets/sheet123:batchUpdate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "replies": [{}]
        })))
        .expect(1)
        .mount(&structure_server)
        .await;
    let delete_result = structure_connector
        .handle_invoke(json!({
            "operation": "sheets.batch_update_spreadsheet",
            "input": {
                "spreadsheet_id": "sheet123",
                "requests": [delete_request],
                "confirm_destructive": true
            },
            "capability_token": structure_token
        }))
        .await
        .expect("confirmed structural delete with preflight and readback");
    assert_eq!(delete_result["destructive"], true);
    assert_eq!(
        delete_result["preflight"]["sheets"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        delete_result["readback"]["sheets"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(metadata_reads.load(Ordering::SeqCst), 2);
}

#[fcp_async_core::runtime::test]
async fn collaborator_conflict_and_malformed_response_fail_closed() {
    let conflict_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v4/spreadsheets/sheet123:batchUpdate"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": {"code": 409, "message": "concurrent collaborator update"}
        })))
        .expect(1)
        .mount(&conflict_server)
        .await;
    let conflict = test_client(&conflict_server)
        .batch_update_spreadsheet("sheet123", &json!({"requests": []}))
        .await
        .expect_err("conflict must fail");
    assert!(
        conflict
            .to_string()
            .contains("concurrent collaborator update")
    );

    let malformed_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .expect(1)
        .mount(&malformed_server)
        .await;
    assert!(
        test_client(&malformed_server)
            .get_spreadsheet("sheet123")
            .await
            .is_err()
    );

    let oversized_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 10 * 1024 * 1024 + 1]))
        .expect(1)
        .mount(&oversized_server)
        .await;
    let oversized = test_client(&oversized_server)
        .get_spreadsheet("sheet123")
        .await
        .expect_err("oversized response must fail");
    assert!(oversized.to_string().contains("exceeds"));
}

#[fcp_async_core::runtime::test]
async fn append_idempotency_key_prevents_duplicate_provider_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/v4/spreadsheets/sheet123/values/Sheet1:append",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "tableRange": "Sheet1!A1:B2",
            "updates": {"spreadsheetId": "sheet123", "updatedRange": "Sheet1!A3:B3", "updatedCells": 2}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = SheetsConnector::new();
    connector
        .handle_configure(json!({
            "access_token": fixture_bearer(),
            "base_url": format!("{}/v4", server.uri()),
        }))
        .await
        .unwrap();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .handle_handshake(
            serde_json::to_value(HandshakeRequest {
                protocol_version: "2.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [7_u8; 32],
                capabilities_requested: vec![CapabilityId::from_static("sheets.values.write")],
                host: None,
                transport_caps: None,
                requested_instance_id: Some(instance_id.clone()),
            })
            .unwrap(),
        )
        .await
        .unwrap();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["google-sheets:spreadsheet:sheet123".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id("sheets.values.write")
            .zone_id("z:work")
            .target_instance(instance_id.as_str())
            .principal("user:test")
            .operations(&["sheets.append_values"])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(&signing_key)
            .unwrap(),
    );
    let invoke = json!({
        "operation": "sheets.append_values",
        "input": {
            "spreadsheet_id": "sheet123",
            "range": "Sheet1",
            "values": [["Ada", 42]],
            "idempotency_key": "append-test-001"
        },
        "capability_token": token,
    });
    let first = connector.handle_invoke(invoke.clone()).await.unwrap();
    let second = connector.handle_invoke(invoke).await.unwrap();
    assert_eq!(first["replayed"], false);
    assert_eq!(second["replayed"], true);
}
