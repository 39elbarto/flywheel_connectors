//! Connector-local no-mock Redis integration proof.
//!
//! These tests exercise the real Redis connector against a local
//! Upstash-compatible HTTP server. No live Redis or Upstash service is called.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_prelude::FcpError;
use fcp_redis::client::{RedisAuth, RedisClient};
use fcp_redis::connector::RedisConnector;
use fcp_redis::error::RedisError;
use fcp_sdk::migration::ConnectorErrorMapping;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "redis-token-for-tests";

async fn configured_connector(server: &MockServer) -> RedisConnector {
    let mut connector = RedisConnector::new();
    connector
        .handle_configure(json!({
            "api_token": TEST_TOKEN,
            "base_url": server.uri()
        }))
        .await
        .expect("local fake Redis API should configure");
    connector
        .handle_handshake(json!({ "session_id": "redis-integration-proof" }))
        .await
        .expect("configured connector should handshake");
    connector
}

async fn invoke(connector: &RedisConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input
        }))
        .await
        .expect("fake Redis API should satisfy operation")
}

async fn expect_command(server: &MockServer, command: Value, response: Value) {
    Mock::given(method("POST"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(header("Content-Type", "application/json"))
        .and(body_json(command))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(server)
        .await;
}

#[fcp_async_core::test]
async fn string_hash_list_set_and_ttl_commands_use_upstash_contracts() {
    tracing::info!(
        scenario = "redis_success_contracts",
        "starting Redis command-shape integration proof",
    );

    let server = MockServer::start().await;

    expect_command(
        &server,
        json!(["SET", "cache:key", "value", "EX", "60", "NX"]),
        json!({ "result": "OK" }),
    )
    .await;
    expect_command(
        &server,
        json!(["GET", "cache:key"]),
        json!({ "result": "value" }),
    )
    .await;
    expect_command(
        &server,
        json!(["TTL", "cache:key"]),
        json!({ "result": 60 }),
    )
    .await;
    expect_command(
        &server,
        json!(["EXPIRE", "cache:key", "120"]),
        json!({ "result": 1 }),
    )
    .await;
    expect_command(&server, json!(["DEL", "cache:key"]), json!({ "result": 1 })).await;
    expect_command(
        &server,
        json!(["HSET", "hash:key", "field", "value"]),
        json!({ "result": 1 }),
    )
    .await;
    expect_command(
        &server,
        json!(["HGETALL", "hash:key"]),
        json!({ "result": { "field": "value" } }),
    )
    .await;
    expect_command(
        &server,
        json!(["LPUSH", "queue:key", "first", "second"]),
        json!({ "result": 2 }),
    )
    .await;
    expect_command(
        &server,
        json!(["LRANGE", "queue:key", "0", "-1"]),
        json!({ "result": ["second", "first"] }),
    )
    .await;
    expect_command(
        &server,
        json!(["SADD", "set:key", "member-a", "member-b"]),
        json!({ "result": 2 }),
    )
    .await;
    expect_command(
        &server,
        json!(["SMEMBERS", "set:key"]),
        json!({ "result": ["member-a", "member-b"] }),
    )
    .await;

    let connector = configured_connector(&server).await;

    let set = invoke(
        &connector,
        "redis.set",
        json!({
            "key": "cache:key",
            "value": "value",
            "ttl_seconds": 60,
            "nx": true
        }),
    )
    .await;
    assert_eq!(set["result"], "OK");

    let get = invoke(&connector, "redis.get", json!({ "key": "cache:key" })).await;
    assert_eq!(get["value"], "value");

    let ttl = invoke(&connector, "redis.ttl", json!({ "key": "cache:key" })).await;
    assert_eq!(ttl["ttl"], 60);

    let expire = invoke(
        &connector,
        "redis.expire",
        json!({ "key": "cache:key", "seconds": 120 }),
    )
    .await;
    assert_eq!(expire["result"], 1);

    let deleted = invoke(&connector, "redis.del", json!({ "keys": ["cache:key"] })).await;
    assert_eq!(deleted["deleted"], 1);

    let hset = invoke(
        &connector,
        "redis.hset",
        json!({ "key": "hash:key", "fields": { "field": "value" } }),
    )
    .await;
    assert_eq!(hset["result"], 1);

    let hgetall = invoke(&connector, "redis.hgetall", json!({ "key": "hash:key" })).await;
    assert_eq!(hgetall["fields"]["field"], "value");

    let lpush = invoke(
        &connector,
        "redis.lpush",
        json!({ "key": "queue:key", "elements": ["first", "second"] }),
    )
    .await;
    assert_eq!(lpush["length"], 2);

    let lrange = invoke(&connector, "redis.lrange", json!({ "key": "queue:key" })).await;
    assert_eq!(lrange["values"], json!(["second", "first"]));

    let sadd = invoke(
        &connector,
        "redis.sadd",
        json!({ "key": "set:key", "members": ["member-a", "member-b"] }),
    )
    .await;
    assert_eq!(sadd["added"], 2);

    let smembers = invoke(&connector, "redis.smembers", json!({ "key": "set:key" })).await;
    assert_eq!(smembers["members"], json!(["member-a", "member-b"]));
}

#[fcp_async_core::test]
async fn auth_rate_command_and_malformed_json_failures_are_typed() {
    tracing::info!(
        scenario = "redis_error_taxonomy",
        "starting Redis error-taxonomy integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!(["GET", "auth"])))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!(["GET", "rate"])))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "3")
                .set_body_json(json!({ "error": "too many requests" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!(["GET", "malformed"])))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(header("Authorization", format!("Bearer {TEST_TOKEN}")))
        .and(body_json(json!(["GET", "wrongtype"])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "error": "WRONGTYPE Operation against a key holding the wrong kind of value"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_connector(&server).await;

    let unauthorized = connector
        .handle_invoke(json!({
            "operation_id": "redis.get",
            "input": { "key": "auth" }
        }))
        .await
        .unwrap_err();
    assert!(matches!(
        unauthorized,
        FcpError::External {
            service,
            status_code: Some(401),
            retryable: false,
            ..
        } if service == "redis"
    ));

    let rate_limited = connector
        .handle_invoke(json!({
            "operation_id": "redis.get",
            "input": { "key": "rate" }
        }))
        .await
        .unwrap_err();
    assert!(matches!(
        &rate_limited,
        FcpError::External {
            service,
            status_code: Some(429),
            retryable: true,
            ..
        } if service == "redis"
    ));
    if let FcpError::External { retry_after, .. } = rate_limited {
        assert_eq!(retry_after, Some(Duration::from_secs(3)));
    }

    let malformed = connector
        .handle_invoke(json!({
            "operation_id": "redis.get",
            "input": { "key": "malformed" }
        }))
        .await
        .unwrap_err();
    assert!(matches!(
        malformed,
        FcpError::Internal { message } if message.contains("JSON error")
    ));

    let command_error = connector
        .handle_invoke(json!({
            "operation_id": "redis.get",
            "input": { "key": "wrongtype" }
        }))
        .await
        .unwrap_err();
    assert!(matches!(
        command_error,
        FcpError::External {
            service,
            message,
            status_code: None,
            retryable: false,
            ..
        } if service == "redis" && message.contains("WRONGTYPE")
    ));
}

#[test]
fn async_timeout_and_cancellation_mapping_stays_retryable_and_bounded() {
    let timeout = RedisError::from_async_error(AsyncError::Timeout { timeout_ms: 250 });
    assert!(matches!(timeout, RedisError::Timeout(_)));
    assert!(timeout.is_retryable());

    let cancelled = RedisError::from_async_error(AsyncError::Cancelled);
    assert!(matches!(
        cancelled,
        RedisError::Api {
            status_code: 499,
            ..
        }
    ));
    assert!(!cancelled.is_retryable());
}

#[fcp_async_core::test]
async fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let mut connector = RedisConnector::new();
    connector
        .handle_configure(json!({ "api_token": TEST_TOKEN }))
        .await
        .expect("default endpoint configuration should succeed");
    let handshake = connector
        .handle_handshake(json!({ "session_id": "redis-catalog-proof" }))
        .await
        .expect("configured connector should handshake");
    assert_eq!(handshake["connector_id"], "fcp.redis");

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize operation catalog");
    let operations = introspection["operations"]
        .as_array()
        .expect("operations should be serialized as an array");
    let operation = |id: &str| {
        operations
            .iter()
            .find(|entry| entry["id"] == id)
            .expect("operation catalog should contain required Redis operation")
    };

    assert_eq!(operation("redis.get")["capability"], "redis.read");
    assert_eq!(operation("redis.get")["risk_level"], "low");
    assert_eq!(operation("redis.get")["safety_tier"], "safe");
    assert_eq!(operation("redis.del")["capability"], "redis.write");
    assert_eq!(operation("redis.del")["risk_level"], "high");
    assert_eq!(operation("redis.del")["safety_tier"], "risky");
    assert_eq!(operation("redis.del")["idempotency"], "none");
    assert_eq!(operation("redis.hset")["capability"], "redis.write");
    assert_eq!(operation("redis.lrange")["capability"], "redis.read");
    assert_eq!(operation("redis.smembers")["capability"], "redis.read");

    let capability_section = manifest_capability_section();
    assert!(capability_section.contains("\"network.egress\""));
    assert!(capability_section.contains("\"network.tls.sni\""));
    assert!(capability_section.contains("\"system.exec\""));
    assert!(capability_section.contains("\"network.listen\""));

    let client = RedisClient::new(
        RedisAuth::ApiToken("super-secret-redis-token".into()),
        Some("https://example.upstash.io"),
    )
    .expect("redaction proof client should build");
    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains("super-secret-redis-token"));
    assert!(debug_output.contains("<redacted>"));
}

fn manifest_capability_section() -> &'static str {
    let manifest = include_str!("../manifest.toml");
    let (_, capabilities) = manifest
        .split_once("[capabilities]")
        .expect("Redis manifest should define capabilities");
    let (capability_section, _) = capabilities
        .split_once("# \u{2500}")
        .expect("Redis manifest should separate capability declarations from operations");
    capability_section
}
