//! Integration tests for the FCP Plaid connector (flywheel_connectors-38h.5).
//!
//! All tests are deterministic (mock-only, no real API calls).
//!
//! Coverage areas:
//! - Request/response parsing (link token, token exchange, accounts, transactions sync, balance)
//! - Error taxonomy mapping (`PlaidError` -> `FcpError`)
//! - Redaction (no `client_id`, secret, or access tokens in error messages)
//! - Cursor advancement logic (`transactions_sync` pagination)
//! - Connector dispatch (full invoke pipeline with capability tokens)

use chrono::{Duration, Utc};
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_plaid::{client::PlaidClient, connector::PlaidConnector, error::PlaidError};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[cap])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .sign(signing_key)
        .unwrap();
    CapabilityToken { raw: cose }
}

async fn setup_handshake(connector: &mut PlaidConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps,
        }))
        .await
        .expect("handshake");
    signing_key
}

async fn setup_configure(connector: &mut PlaidConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "client_id": "test_client_id",
            "secret": "test_secret",
            "base_url": base_url,
        }))
        .await
        .expect("configure");
}

// ============================================================================
// 1. Request/response parsing
// ============================================================================

/// Parse `link_token_create` response correctly.
#[fcp_async_core::runtime::test]
async fn parse_link_token_create_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/link/token/create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "link_token": "link-sandbox-abc123",
            "expiration": "2026-03-02T23:59:59Z",
            "request_id": "req-lt-1"
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url());

    let result = client
        .link_token_create(
            "TestApp",
            &["transactions".to_string()],
            &["US".to_string()],
            "en",
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.link_token, "link-sandbox-abc123");
    assert_eq!(result.expiration, "2026-03-02T23:59:59Z");
}

/// Parse `token_exchange` response correctly.
#[fcp_async_core::runtime::test]
async fn parse_token_exchange_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/item/public_token/exchange"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-sandbox-abc123",
            "item_id": "item-abc",
            "request_id": "req-te-1"
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url());

    let result = client.token_exchange("public-sandbox-xyz").await.unwrap();
    assert_eq!(result.access_token, "access-sandbox-abc123");
    assert_eq!(result.item_id, "item-abc");
}

/// Parse `accounts_get` response with account details.
#[fcp_async_core::runtime::test]
async fn parse_accounts_get_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-1",
                "balances": {
                    "available": 1000.0,
                    "current": 1100.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "1234",
                "name": "Plaid Savings",
                "official_name": "Plaid Gold Savings",
                "subtype": "savings",
                "type": "depository"
            }],
            "item": {
                "item_id": "item-1",
                "institution_id": "ins_109508",
                "available_products": ["balance", "auth"],
                "billed_products": ["transactions"]
            }
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url());

    let (accounts, item) = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account_id, "acc-1");
    assert_eq!(accounts[0].name, "Plaid Savings");
    assert_eq!(accounts[0].balances.available, Some(1000.0));
    assert_eq!(
        accounts[0].balances.iso_currency_code.as_deref(),
        Some("USD")
    );
    assert_eq!(item.item_id, "item-1");
    assert_eq!(item.institution_id.as_deref(), Some("ins_109508"));
}

/// Parse `transactions_sync` response with cursor and transactions.
#[fcp_async_core::runtime::test]
async fn parse_transactions_sync_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-1",
                "account_id": "acc-1",
                "amount": 42.50,
                "iso_currency_code": "USD",
                "date": "2026-02-28",
                "name": "Grocery Store",
                "merchant_name": "Whole Foods",
                "pending": false,
                "category": ["Food and Drink", "Groceries"],
                "category_id": "19047000"
            }],
            "modified": [],
            "removed": [{ "transaction_id": "tx-old" }],
            "next_cursor": "cursor-page2",
            "has_more": true
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url());

    let result = client
        .transactions_sync("access-sandbox-xxx", Some("cursor-page1"), Some(100))
        .await
        .unwrap();
    assert_eq!(result.added.len(), 1);
    assert_eq!(result.added[0].transaction_id, "tx-1");
    assert_eq!(
        result.added[0].merchant_name.as_deref(),
        Some("Whole Foods")
    );
    assert!(result.modified.is_empty());
    assert_eq!(result.removed.len(), 1);
    assert_eq!(result.removed[0].transaction_id, "tx-old");
    assert_eq!(result.next_cursor, "cursor-page2");
    assert!(result.has_more);
}

/// Parse `accounts_balance_get` response.
#[fcp_async_core::runtime::test]
async fn parse_accounts_balance_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/balance/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-1",
                "balances": {
                    "available": 500.0,
                    "current": 510.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "5678",
                "name": "Checking",
                "official_name": null,
                "subtype": "checking",
                "type": "depository"
            }]
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url());

    let accounts = client
        .accounts_balance_get("access-sandbox-xxx", None)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].balances.available, Some(500.0));
    assert_eq!(accounts[0].balances.current, Some(510.0));
}

// ============================================================================
// 2. Error taxonomy mapping
// ============================================================================

/// 401 Unauthorized -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error_type": "INVALID_INPUT",
            "error_code": "INVALID_API_KEYS",
            "error_message": "invalid client_id or secret provided"
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("bad_id", "bad_secret")
        .unwrap()
        .with_base_url(&mock.base_url())
        .with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error_type": "INVALID_REQUEST",
            "error_code": "ACCESS_NOT_GRANTED",
            "error_message": "access not granted for this product"
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url())
        .with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 429 Too Many Requests -> `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(429))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url())
        .with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::RateLimited { .. }),
        "expected RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error -> `FcpError::External` (retryable).
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external_retryable() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url())
        .with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    match fcp_err {
        FcpError::External {
            service, retryable, ..
        } => {
            assert_eq!(service, "plaid");
            assert!(retryable);
        }
        other => panic!("expected External, got: {other:?}"),
    }
}

/// `InvalidConfig` -> `FcpError::Internal`.
#[test]
fn error_invalid_config_maps_to_internal() {
    let err = PlaidError::InvalidConfig("missing credentials".into());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Internal { .. }),
        "expected Internal, got: {fcp_err:?}"
    );
}

// ============================================================================
// 3. Redaction -- no client_id, secret, or access tokens in errors
// ============================================================================

/// `client_id` must not appear in error messages produced by the connector.
#[fcp_async_core::runtime::test]
async fn client_id_not_in_error_messages() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("SENSITIVE_CLIENT_ID", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url())
        .with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("SENSITIVE_CLIENT_ID"),
        "client_id leaked in error: {msg}"
    );
}

/// `secret` must not appear in error messages produced by the connector.
#[fcp_async_core::runtime::test]
async fn secret_not_in_error_messages() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "SUPERSECRET_VALUE_9876")
        .unwrap()
        .with_base_url(&mock.base_url())
        .with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("SUPERSECRET_VALUE_9876"),
        "secret leaked in error: {msg}"
    );
}

/// Access token must not appear in connector invoke error messages.
#[fcp_async_core::runtime::test]
async fn access_token_not_in_invoke_errors() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error_type": "INVALID_REQUEST",
            "error_code": "INVALID_ACCESS_TOKEN",
            "error_message": "the access token is invalid"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.accounts_get"]).await;
    let token = generate_valid_token(&signing_key, "plaid.accounts_get");

    let err = connector
        .handle_invoke(json!({
            "operation": "plaid.accounts_get",
            "input": { "access_token": "access-sandbox-REDACTME-xyz" },
            "capability_token": token
        }))
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("access-sandbox-REDACTME-xyz"),
        "access_token leaked in invoke error: {msg}"
    );
}

// ============================================================================
// 4. Cursor advancement logic
// ============================================================================

/// Cursor advances from initial (empty) to `next_cursor`.
#[fcp_async_core::runtime::test]
async fn transactions_sync_cursor_advances() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-new-1",
                "account_id": "acc-1",
                "amount": 15.00,
                "iso_currency_code": "USD",
                "date": "2026-03-01",
                "name": "Coffee",
                "merchant_name": null,
                "pending": false,
                "category": ["Food and Drink"],
                "category_id": "13000000"
            }],
            "modified": [],
            "removed": [],
            "next_cursor": "cursor-after-initial-sync",
            "has_more": false
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url());

    // Initial sync with no cursor
    let result = client
        .transactions_sync("access-sandbox-xxx", None, Some(100))
        .await
        .unwrap();
    assert!(!result.next_cursor.is_empty(), "next_cursor should be set");
    assert_eq!(result.next_cursor, "cursor-after-initial-sync");
    assert!(!result.has_more);
}

/// Pagination: `has_more=true` signals more pages to fetch.
#[fcp_async_core::runtime::test]
async fn transactions_sync_has_more_pagination() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-page2-1",
                "account_id": "acc-1",
                "amount": 99.99,
                "iso_currency_code": "USD",
                "date": "2026-03-01",
                "name": "Electronics Store",
                "merchant_name": "Best Buy",
                "pending": false,
                "category": ["Shops"],
                "category_id": "19000000"
            }],
            "modified": [{
                "transaction_id": "tx-modified-1",
                "account_id": "acc-1",
                "amount": 50.00,
                "iso_currency_code": "USD",
                "date": "2026-02-28",
                "name": "Updated Merchant",
                "merchant_name": "Updated",
                "pending": false,
                "category": ["Shops"],
                "category_id": "19000000"
            }],
            "removed": [{ "transaction_id": "tx-deleted-1" }],
            "next_cursor": "cursor-page3",
            "has_more": true
        })))
        .mount(mock.inner())
        .await;

    let client = PlaidClient::new("test_id", "test_secret")
        .unwrap()
        .with_base_url(&mock.base_url());

    let result = client
        .transactions_sync("access-sandbox-xxx", Some("cursor-page2"), Some(50))
        .await
        .unwrap();
    assert_eq!(result.added.len(), 1);
    assert_eq!(result.modified.len(), 1);
    assert_eq!(result.removed.len(), 1);
    assert!(result.has_more, "has_more should be true for mid-sync page");
    assert_eq!(result.next_cursor, "cursor-page3");
}

// ============================================================================
// 5. Connector dispatch (full invoke pipeline with capability tokens)
// ============================================================================

/// Dispatch `accounts_get` through the full invoke pipeline.
#[fcp_async_core::runtime::test]
async fn dispatch_accounts_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-dispatch-1",
                "balances": {
                    "available": 250.0,
                    "current": 250.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "0001",
                "name": "Dispatch Checking",
                "official_name": null,
                "subtype": "checking",
                "type": "depository"
            }],
            "item": {
                "item_id": "item-dispatch",
                "institution_id": "ins_1"
            }
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.accounts_get"]).await;
    let token = generate_valid_token(&signing_key, "plaid.accounts_get");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.accounts_get",
            "input": { "access_token": "access-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke accounts_get should succeed");
    let accounts = result["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["account_id"], "acc-dispatch-1");
}

/// Dispatch `transactions_sync` through the full invoke pipeline.
#[fcp_async_core::runtime::test]
async fn dispatch_transactions_sync_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-dispatch-1",
                "account_id": "acc-1",
                "amount": 12.34,
                "iso_currency_code": "USD",
                "date": "2026-03-01",
                "name": "Test Merchant",
                "merchant_name": "TestCo",
                "pending": false,
                "category": ["Food and Drink"],
                "category_id": "13000000"
            }],
            "modified": [],
            "removed": [],
            "next_cursor": "cursor-dispatch-2",
            "has_more": false
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.transactions_sync"]).await;
    let token = generate_valid_token(&signing_key, "plaid.transactions_sync");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.transactions_sync",
            "input": {
                "access_token": "access-sandbox-dispatch",
                "cursor": "",
                "count": 100
            },
            "capability_token": token
        }))
        .await
        .expect("invoke transactions_sync should succeed");
    assert_eq!(result["next_cursor"], "cursor-dispatch-2");
    assert_eq!(result["has_more"], false);
    let added = result["added"].as_array().expect("added array");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["transaction_id"], "tx-dispatch-1");
}

/// Dispatch `link_token_create` through the full invoke pipeline.
#[fcp_async_core::runtime::test]
async fn dispatch_link_token_create_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/link/token/create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "link_token": "link-sandbox-dispatch-abc",
            "expiration": "2026-03-03T00:00:00Z",
            "request_id": "req-dispatch-1"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.link_token_create"]).await;
    let token = generate_valid_token(&signing_key, "plaid.link_token_create");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.link_token_create",
            "input": {
                "client_name": "TestApp",
                "products": ["transactions"],
                "country_codes": ["US"],
                "language": "en"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke link_token_create should succeed");
    assert_eq!(result["link_token"], "link-sandbox-dispatch-abc");
}
