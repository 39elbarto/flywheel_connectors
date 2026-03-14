//! Google migration acceptance suite for Calendar.
//!
//! Validates that the shared `fcp-google-discovery` substrate correctly
//! integrates with the Google Calendar connector.
//!
//! Required by bead `lszk.45.2.6`.

#![allow(clippy::too_many_lines)]

use fcp_core::{CredentialId, FcpError};
use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
use serde_json::json;

use fcp_google_calendar::{client::GoogleCalendarClient, connector::GoogleCalendarConnector};

// ── Shared substrate auth integration ────────────────────────────────

#[test]
fn calendar_client_accepts_shared_bearer_auth() {
    let auth = GoogleMaterializedAuth::BearerToken {
        access_token: "ya29.test-token".into(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: vec!["https://www.googleapis.com/auth/calendar".into()],
        quota_project_id: None,
    };
    let client = GoogleCalendarClient::new_with_auth(auth);
    assert!(client.is_ok(), "Bearer auth should create a valid client");
}

#[test]
fn calendar_client_accepts_shared_credential_ref() {
    let auth = GoogleMaterializedAuth::CredentialReference {
        credential_id: CredentialId::new(),
        quota_project_id: Some("test-project".into()),
    };
    let client = GoogleCalendarClient::new_with_auth(auth);
    assert!(
        client.is_ok(),
        "Credential reference auth should create a valid client"
    );
}

// ── Introspection surface validation ─────────────────────────────────

#[fcp_async_core::runtime::test]
async fn calendar_introspect_has_required_operations() {
    let connector = GoogleCalendarConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    // Core Calendar operations that must survive migration.
    let required = [
        "calendar.list_events",
        "calendar.get_event",
        "calendar.create_event",
    ];

    for op in &required {
        assert!(
            op_ids.contains(op),
            "Missing required Calendar operation: {op}. Available: {op_ids:?}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn calendar_introspect_operations_have_capability() {
    let connector = GoogleCalendarConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().expect("operations array");

    for op in ops {
        let id = op["id"].as_str().unwrap();
        let cap = op["capability"].as_str();
        assert!(
            cap.is_some(),
            "Operation {id} is missing capability field"
        );
        assert!(
            !cap.unwrap().is_empty(),
            "Operation {id} has empty capability"
        );
    }
}

// ── Configure with shared auth ───────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn calendar_configure_with_access_token_succeeds() {
    let mut connector = GoogleCalendarConnector::new();
    let result = connector
        .handle_configure(json!({
            "access_token": "ya29.test-integration-token",
        }))
        .await;
    assert!(
        result.is_ok(),
        "Configure with shared auth should succeed: {:?}",
        result.err()
    );
    let value = result.unwrap();
    assert_eq!(value["status"], "configured");
}

#[fcp_async_core::runtime::test]
async fn calendar_configure_with_credential_id_succeeds() {
    let mut connector = GoogleCalendarConnector::new();
    let cred_id = fcp_core::CredentialId::new();
    let result = connector
        .handle_configure(json!({
            "credential_id": cred_id.to_string(),
        }))
        .await;
    assert!(
        result.is_ok(),
        "Configure with credential_id should succeed: {:?}",
        result.err()
    );
}

#[fcp_async_core::runtime::test]
async fn calendar_configure_rejects_no_auth() {
    let mut connector = GoogleCalendarConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert!(result.is_err(), "Configure with no auth should fail");
}

// ── Error taxonomy preserved ─────────────────────────────────────────

#[test]
fn calendar_error_unauthorized_maps_correctly() {
    use fcp_google_calendar::error::GoogleCalendarError;
    let err = GoogleCalendarError::Unauthorized;
    let fcp = err.to_fcp_error();
    assert!(
        matches!(fcp, FcpError::Unauthorized { .. }),
        "Unauthorized should map correctly, got {fcp:?}"
    );
}
