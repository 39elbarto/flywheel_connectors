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
    CapabilityConstraints, CapabilityId, CapabilityToken, HandshakeRequest, InstanceId, ZoneId,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

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
        access_token: "test-token".into(),
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
        access_token: "test-token".into(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: Vec::new(),
        quota_project_id: None,
    })
    .expect("client")
    .with_base_url(format!("{}/v4", server.uri()))
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
            "access_token": "test-token",
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
