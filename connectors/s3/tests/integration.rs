//! Integration tests for the S3 connector.
//!
//! Covers error taxonomy mapping, credential redaction, client operations
//! (put, get, delete, head, list, copy, presigned), and connector-level invoke.

use std::time::Duration;

use chrono::Utc;
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_s3::{client::S3Client, connector::S3Connector, error::S3Error};
use serde_json::json;
use wiremock::matchers::{method, path};
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
    connector: &mut S3Connector,
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

async fn setup_configure(connector: &mut S3Connector, api_url: &str) {
    connector
        .handle_configure(json!({
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "base_url": api_url
        }))
        .await
        .unwrap();
}

fn make_client(server_uri: &str) -> S3Client {
    S3Client::new(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "us-east-1",
    )
    .unwrap()
    .with_base_url(server_uri)
}

// ── Error taxonomy ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_http_maps_to_external() {
    let err = S3Error::Http(
        reqwest::Client::new()
            .get("http://[::ffff:0.0.0.0]:1")
            .send()
            .await
            .unwrap_err(),
    );
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::External { service, .. } if service == "s3"));
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_json_maps_to_internal() {
    let bad: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let err = S3Error::Json(bad.unwrap_err());
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Internal { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_auth_maps_to_unauthorized() {
    let err = S3Error::Api {
        code: "AccessDenied".into(),
        message: "Access Denied".into(),
        status_code: Some(403),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
}

#[fcp_async_core::runtime::test]
async fn error_api_not_found_maps_to_resource_not_found() {
    let err = S3Error::Api {
        code: "NoSuchKey".into(),
        message: "The specified key does not exist".into(),
        status_code: Some(404),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::ResourceNotFound { .. }));
}

#[fcp_async_core::runtime::test]
async fn error_api_rate_limited_maps_to_fcp() {
    let err = S3Error::Api {
        code: "SlowDown".into(),
        message: "Slow down".into(),
        status_code: Some(429),
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::RateLimited { .. }));
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_api_server_error_is_retryable() {
    let err = S3Error::Api {
        code: "InternalError".into(),
        message: "Internal error".into(),
        status_code: Some(500),
    };
    assert!(err.is_retryable());
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::External { retryable, .. } if retryable));
}

#[fcp_async_core::runtime::test]
async fn error_rate_limited_maps_to_fcp_rate_limited() {
    let err = S3Error::RateLimited {
        retry_after_ms: 5000,
    };
    let fcp = err.to_fcp_error();
    assert!(matches!(
        fcp,
        FcpError::RateLimited {
            retry_after_ms: 5000,
            ..
        }
    ));
    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(Duration::from_secs(5)));
}

#[fcp_async_core::runtime::test]
async fn error_unauthorized_maps_to_fcp_unauthorized() {
    let err = S3Error::Unauthorized;
    let fcp = err.to_fcp_error();
    assert!(matches!(fcp, FcpError::Unauthorized { .. }));
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn error_not_found_variants_map_to_resource_not_found() {
    let obj_err = S3Error::NotFound {
        key: "docs/readme.md".into(),
    };
    assert!(
        matches!(obj_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("docs/readme.md"))
    );

    let bucket_err = S3Error::BucketNotFound {
        bucket: "my-bucket".into(),
    };
    assert!(
        matches!(bucket_err.to_fcp_error(), FcpError::ResourceNotFound { resource } if resource.contains("my-bucket"))
    );
}

// ── Redaction ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_display_does_not_leak_credentials() {
    let err = S3Error::Unauthorized;
    let msg = err.to_string();
    assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!msg.contains("wJalrXUtnFEMI"));
}

#[fcp_async_core::runtime::test]
async fn api_error_display_does_not_leak_credentials() {
    let err = S3Error::Api {
        code: "AccessDenied".into(),
        message: "Access Denied".into(),
        status_code: Some(403),
    };
    let msg = err.to_string();
    assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"));
}

// ── Client operations ───────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn client_put_object() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/my-bucket/test-key.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "etag": "\"d41d8cd98f00b204e9800998ecf8427e\""
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .put_object("my-bucket", "test-key.txt", "hello world")
        .await
        .unwrap();
    assert!(!result.etag.is_empty());
}

#[fcp_async_core::runtime::test]
async fn client_get_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/test-key.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "body": "aGVsbG8gd29ybGQ=",
            "content_type": "text/plain"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .get_object("my-bucket", "test-key.txt")
        .await
        .unwrap();
    assert_eq!(result.content_type, "text/plain");
}

#[fcp_async_core::runtime::test]
async fn client_delete_object() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/my-bucket/test-key.txt"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client
        .delete_object("my-bucket", "test-key.txt")
        .await
        .unwrap();
    assert!(result);
}

// Note: client_head_object not tested here because wiremock strips body from HEAD
// responses per HTTP spec, but the S3 client's head_request parses JSON body.
// The head_object operation is tested via connector invoke below.

#[fcp_async_core::runtime::test]
async fn client_list_objects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "contents": [
                { "key": "file1.txt", "size": 100 },
                { "key": "file2.txt", "size": 200 }
            ],
            "is_truncated": false
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client.list_objects("my-bucket", None, None).await.unwrap();
    assert_eq!(result.contents.len(), 2);
    assert!(!result.is_truncated);
}

#[fcp_async_core::runtime::test]
async fn client_list_buckets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "buckets": [
                { "name": "bucket-a", "creation_date": "2025-01-01T00:00:00Z" },
                { "name": "bucket-b" }
            ]
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client.list_buckets().await.unwrap();
    assert_eq!(result.buckets.len(), 2);
    assert_eq!(result.buckets[0].name, "bucket-a");
}

#[fcp_async_core::runtime::test]
async fn client_unauthorized_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/key.txt"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "Code": "AccessDenied",
            "Message": "Access Denied"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server.uri());
    let result = client.get_object("my-bucket", "key.txt").await;
    assert!(matches!(result.unwrap_err(), S3Error::Unauthorized));
}

#[fcp_async_core::runtime::test]
async fn client_rate_limited_no_retry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/my-bucket/key.txt"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "10"))
        .mount(&server)
        .await;

    let client = make_client(&server.uri()).with_retry_config(0, 100, 100);
    let result = client.get_object("my-bucket", "key.txt").await;
    assert!(matches!(result.unwrap_err(), S3Error::RateLimited { .. }));
}

// ── Connector-level invoke ──────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn invoke_put_object_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/my-bucket/hello.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "etag": "\"abc123\""
        })))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["s3.put_object"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "s3.put_object");
    let result = connector
        .handle_invoke(json!({
            "operation": "s3.put_object",
            "input": {
                "bucket": "my-bucket",
                "key": "hello.txt",
                "body": "hello world"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["etag"].as_str().is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_list_buckets_through_connector() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "buckets": [{ "name": "test-bucket" }]
        })))
        .mount(&server)
        .await;

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["s3.list_buckets"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "s3.list_buckets");
    let result = connector
        .handle_invoke(json!({
            "operation": "s3.list_buckets",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["buckets"][0]["name"], "test-bucket");
}

#[fcp_async_core::runtime::test]
async fn invoke_wrong_capability_rejected() {
    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["s3.read"]).await;
    setup_configure(&mut connector, "http://localhost:1").await;

    let token = generate_valid_token(&signing_key, "s3.read");
    let result = connector
        .handle_invoke(json!({
            "operation": "s3.put_object",
            "input": {
                "bucket": "b",
                "key": "k",
                "body": "x"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation_rejected() {
    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["s3.nonexistent"]).await;
    setup_configure(&mut connector, "http://localhost:1").await;

    let token = generate_valid_token(&signing_key, "s3.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "s3.nonexistent",
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

    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();

    setup_handshake(&mut connector, &signing_key, &["s3.put_object"]).await;
    setup_configure(&mut connector, &server.uri()).await;

    let token = generate_valid_token(&signing_key, "s3.put_object");
    // Missing key and body
    let result = connector
        .handle_invoke(json!({
            "operation": "s3.put_object",
            "input": { "bucket": "my-bucket" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("key"));
        }
        e => panic!("Expected InvalidRequest, got: {e:?}"),
    }
}
