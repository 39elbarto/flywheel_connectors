use fcp_google_discovery::auth::{
    FCP_CREDENTIAL_ID_HEADER, GOOGLE_AUTHORIZATION_HEADER, GoogleAuthSourceKind,
    GoogleMaterializedAuth,
};
use fcp_google_sheets::client::SheetsClient;
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
