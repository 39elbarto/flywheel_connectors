//! Integration tests for the FCP `DocuSign` connector.

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
use wiremock::matchers::{header, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_docusign::connector::DocuSignConnector;

async fn setup_connector(mock_url: &str) -> DocuSignConnector {
    let mut c = DocuSignConnector::new();
    c.handle_configure(json!({ "access_token": "test-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = DocuSignConnector::new();
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
    let mut c = DocuSignConnector::new();
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
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 15);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configured_but_not_handshaken() {
    let mut c = DocuSignConnector::new();
    c.handle_configure(json!({ "access_token": "tok", "base_url": "http://localhost:9999" }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

// -- List Envelopes --

#[fcp_async_core::runtime::test]
async fn list_envelopes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes.*"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopes": [
                {"envelopeId": "e1", "status": "completed"},
                {"envelopeId": "e2", "status": "sent"},
            ],
            "resultSetSize": "2",
            "totalSetSize": "100",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.list_envelopes",
            "input": {"account_id": "acct-123", "from_date": "2026-01-01T00:00:00Z"}
        }))
        .await
        .unwrap();
    assert_eq!(result["envelopes"].as_array().unwrap().len(), 2);
    assert_eq!(result["totalSetSize"], "100");
}

#[fcp_async_core::runtime::test]
async fn list_envelopes_missing_account_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.list_envelopes",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Get Envelope --

#[fcp_async_core::runtime::test]
async fn get_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes/env-001.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopeId": "env-001",
            "status": "completed",
            "emailSubject": "Please sign",
            "recipients": {
                "signers": [{"name": "Alice", "email": "alice@example.com", "status": "completed"}]
            },
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.get_envelope",
            "input": {"account_id": "acct-123", "envelope_id": "env-001", "include": "recipients"}
        }))
        .await
        .unwrap();
    assert_eq!(result["envelope"]["envelopeId"], "env-001");
    assert_eq!(result["envelope"]["status"], "completed");
}

#[fcp_async_core::runtime::test]
async fn get_envelope_missing_envelope_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.get_envelope",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

// -- Create Envelope --

#[fcp_async_core::runtime::test]
async fn create_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(".*/envelopes"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "envelopeId": "env-new",
            "status": "created",
            "uri": "/envelopes/env-new",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.create_envelope",
            "input": {
                "account_id": "acct-123",
                "envelope_definition": {
                    "emailSubject": "Please sign this",
                    "documents": [{"documentId": "1", "name": "contract.pdf"}],
                    "recipients": {"signers": [{"email": "signer@example.com", "name": "Bob", "recipientId": "1"}]},
                    "status": "created"
                }
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["envelopeId"], "env-new");
    assert_eq!(result["status"], "created");
}

#[fcp_async_core::runtime::test]
async fn create_envelope_missing_definition() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.create_envelope",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

// -- Send Envelope --

#[fcp_async_core::runtime::test]
async fn send_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path_regex(".*/envelopes/env-draft"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopeId": "env-draft",
            "status": "sent",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.send_envelope",
            "input": {"account_id": "acct-123", "envelope_id": "env-draft"}
        }))
        .await
        .unwrap();
    assert_eq!(result["envelopeId"], "env-draft");
    assert_eq!(result["status"], "sent");
}

#[fcp_async_core::runtime::test]
async fn send_envelope_missing_envelope_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.send_envelope",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

// -- Void Envelope --

#[fcp_async_core::runtime::test]
async fn void_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path_regex(".*/envelopes/env-sent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopeId": "env-sent",
            "status": "voided",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.void_envelope",
            "input": {
                "account_id": "acct-123",
                "envelope_id": "env-sent",
                "voided_reason": "Document needs revision"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["status"], "voided");
}

#[fcp_async_core::runtime::test]
async fn void_envelope_missing_reason() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.void_envelope",
            "input": {"account_id": "acct-123", "envelope_id": "env-sent"}
        }))
        .await
        .is_err()
    );
}

// -- Add Recipients --

#[fcp_async_core::runtime::test]
async fn add_recipients() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(".*/envelopes/env-draft/recipients"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "signers": [{"recipientId": "2", "name": "Charlie", "email": "charlie@example.com"}],
            "recipientCount": "2",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.add_recipients",
            "input": {
                "account_id": "acct-123",
                "envelope_id": "env-draft",
                "recipients": {
                    "signers": [{"email": "charlie@example.com", "name": "Charlie", "recipientId": "2"}]
                }
            }
        }))
        .await
        .unwrap();
    assert!(result["recipients"].is_object());
}

#[fcp_async_core::runtime::test]
async fn add_recipients_missing_recipients() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.add_recipients",
            "input": {"account_id": "acct-123", "envelope_id": "env-draft"}
        }))
        .await
        .is_err()
    );
}

// -- List Templates --

#[fcp_async_core::runtime::test]
async fn list_templates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/templates.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopeTemplates": [
                {"templateId": "t1", "name": "NDA"},
                {"templateId": "t2", "name": "Sales Contract"},
            ],
            "resultSetSize": "2",
            "totalSetSize": "2",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.list_templates",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["envelopeTemplates"].as_array().unwrap().len(), 2);
}

// -- Get Template --

#[fcp_async_core::runtime::test]
async fn get_template() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/templates/tmpl-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "templateId": "tmpl-001",
            "name": "NDA Template",
            "description": "Standard non-disclosure agreement",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.get_template",
            "input": {"account_id": "acct-123", "template_id": "tmpl-001"}
        }))
        .await
        .unwrap();
    assert_eq!(result["template"]["templateId"], "tmpl-001");
    assert_eq!(result["template"]["name"], "NDA Template");
}

#[fcp_async_core::runtime::test]
async fn get_template_missing_template_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.get_template",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

// -- Download Documents --

#[fcp_async_core::runtime::test]
async fn download_documents() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes/env-001/documents/combined"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"%PDF-1.4 fake content".to_vec()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.download_documents",
            "input": {"account_id": "acct-123", "envelope_id": "env-001"}
        }))
        .await
        .unwrap();
    let doc = result["document"].as_str().unwrap();
    assert!(!doc.is_empty());
    // Check it's base64-encoded
    assert!(
        doc.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    );
}

#[fcp_async_core::runtime::test]
async fn download_documents_missing_envelope_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.download_documents",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

// -- Stream Connect Events --

#[fcp_async_core::runtime::test]
async fn stream_connect_events() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.stream_connect_events",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .unwrap();
    assert!(result["events"].as_array().unwrap().is_empty());
    assert_eq!(result["streaming"], true);
}

#[fcp_async_core::runtime::test]
async fn stream_connect_events_with_since_ts() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.stream_connect_events",
            "input": {"account_id": "acct-123", "since_ts": "2026-03-01T00:00:00Z"}
        }))
        .await
        .unwrap();
    assert_eq!(result["since_ts"], "2026-03-01T00:00:00Z");
}

// -- Error Handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes.*"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"errorCode": "UNAUTHORIZED", "message": "Unauthorized"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.list_envelopes",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes.*"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"errorCode": "FORBIDDEN", "message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.list_envelopes",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes.*"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"errorCode": "ENVELOPE_DOES_NOT_EXIST", "message": "The envelope does not exist"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.get_envelope",
            "input": {"account_id": "acct-123", "envelope_id": "missing"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"errorCode": "HOURLY_APIINVOCATIONLIMIT_EXCEEDED", "message": "Rate limit exceeded"}))
                .insert_header("retry-after", "120"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.list_envelopes",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(".*/envelopes"))
        .respond_with(ResponseTemplate::new(500).set_body_json(
            json!({"errorCode": "INTERNAL_SERVER_ERROR", "message": "Internal server error"}),
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.create_envelope",
            "input": {
                "account_id": "acct-123",
                "envelope_definition": {"emailSubject": "Test", "status": "created"}
            }
        }))
        .await
        .is_err()
    );
}

// -- Unknown Op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.nope",
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
        c.handle_simulate(json!({"operation_id": "docusign.list_envelopes"}))
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
        !c.handle_simulate(json!({"operation_id": "docusign.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_all_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let ops = [
        "docusign.list_envelopes",
        "docusign.get_envelope",
        "docusign.create_envelope",
        "docusign.send_envelope",
        "docusign.void_envelope",
        "docusign.add_recipients",
        "docusign.list_templates",
        "docusign.get_template",
        "docusign.download_documents",
        "docusign.stream_connect_events",
        "docusign.update_recipients",
        "docusign.add_tabs",
        "docusign.resend_envelope",
        "docusign.list_documents",
        "docusign.create_from_template",
    ];
    for op in ops {
        let result = c
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert!(
            result["allowed"].as_bool().unwrap(),
            "op {op} should be allowed"
        );
    }
}

// -- Update Recipients --

#[fcp_async_core::runtime::test]
async fn update_recipients() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path_regex(".*/envelopes/env-draft/recipients"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "signers": [{"recipientId": "1", "name": "Updated Name", "email": "new@example.com"}],
            "recipientCount": "1",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.update_recipients",
            "input": {
                "account_id": "acct-123",
                "envelope_id": "env-draft",
                "recipients": {
                    "signers": [{"recipientId": "1", "email": "new@example.com", "name": "Updated Name"}]
                }
            }
        }))
        .await
        .unwrap();
    assert!(result["recipients"].is_object());
}

#[fcp_async_core::runtime::test]
async fn update_recipients_missing_recipients() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.update_recipients",
            "input": {"account_id": "acct-123", "envelope_id": "env-draft"}
        }))
        .await
        .is_err()
    );
}

// -- Add Tabs --

#[fcp_async_core::runtime::test]
async fn add_tabs() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(".*/envelopes/env-draft/recipients/1/tabs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "signHereTabs": [{"tabId": "tab-1", "documentId": "1", "pageNumber": "1"}],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.add_tabs",
            "input": {
                "account_id": "acct-123",
                "envelope_id": "env-draft",
                "recipient_id": "1",
                "tabs": {
                    "signHereTabs": [{"documentId": "1", "pageNumber": "1", "xPosition": "100", "yPosition": "200"}]
                }
            }
        }))
        .await
        .unwrap();
    assert!(result["tabs"].is_object());
}

#[fcp_async_core::runtime::test]
async fn add_tabs_missing_tabs() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.add_tabs",
            "input": {"account_id": "acct-123", "envelope_id": "env-draft", "recipient_id": "1"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn add_tabs_missing_recipient_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.add_tabs",
            "input": {"account_id": "acct-123", "envelope_id": "env-draft", "tabs": {"signHereTabs": []}}
        }))
        .await
        .is_err()
    );
}

// -- Resend Envelope --

#[fcp_async_core::runtime::test]
async fn resend_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path_regex(".*/envelopes/env-sent.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopeId": "env-sent",
            "status": "sent",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.resend_envelope",
            "input": {"account_id": "acct-123", "envelope_id": "env-sent"}
        }))
        .await
        .unwrap();
    assert_eq!(result["envelopeId"], "env-sent");
}

#[fcp_async_core::runtime::test]
async fn resend_envelope_missing_envelope_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.resend_envelope",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

// -- List Documents --

#[fcp_async_core::runtime::test]
async fn list_documents() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes/env-001/documents$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopeId": "env-001",
            "envelopeDocuments": [
                {"documentId": "1", "name": "contract.pdf", "type": "content"},
                {"documentId": "certificate", "name": "Summary", "type": "summary"},
            ],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.list_documents",
            "input": {"account_id": "acct-123", "envelope_id": "env-001"}
        }))
        .await
        .unwrap();
    assert!(result["documents"].is_object());
    assert_eq!(
        result["documents"]["envelopeDocuments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[fcp_async_core::runtime::test]
async fn list_documents_missing_envelope_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.list_documents",
            "input": {"account_id": "acct-123"}
        }))
        .await
        .is_err()
    );
}

// -- Create From Template --

#[fcp_async_core::runtime::test]
async fn create_from_template() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(".*/envelopes"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "envelopeId": "env-from-tmpl",
            "status": "created",
            "uri": "/envelopes/env-from-tmpl",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.create_from_template",
            "input": {
                "account_id": "acct-123",
                "template_id": "tmpl-789",
                "template_roles": [
                    {"roleName": "Signer", "name": "Alice", "email": "alice@example.com"}
                ],
                "status": "created"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["envelopeId"], "env-from-tmpl");
    assert_eq!(result["status"], "created");
}

#[fcp_async_core::runtime::test]
async fn create_from_template_missing_template_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.create_from_template",
            "input": {
                "account_id": "acct-123",
                "template_roles": [{"roleName": "Signer", "name": "Bob", "email": "bob@example.com"}]
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_from_template_missing_roles() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "docusign.create_from_template",
            "input": {
                "account_id": "acct-123",
                "template_id": "tmpl-789"
            }
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn create_from_template_default_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(".*/envelopes"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "envelopeId": "env-default",
            "status": "created",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "docusign.create_from_template",
            "input": {
                "account_id": "acct-123",
                "template_id": "tmpl-789",
                "template_roles": [
                    {"roleName": "Signer", "name": "Charlie", "email": "charlie@example.com"}
                ]
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["status"], "created");
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*/envelopes.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "envelopes": [],
            "resultSetSize": "0",
            "totalSetSize": "0",
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "docusign.list_envelopes",
        "input": {"account_id": "acct-123"}
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
        .and(path_regex(".*/envelopes.*"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"errorCode": "INTERNAL", "message": "error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "docusign.list_envelopes",
            "input": {"account_id": "acct-123"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
