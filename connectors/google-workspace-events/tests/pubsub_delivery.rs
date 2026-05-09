use std::future::Future;

use fcp_google_workspace_events::connector::WorkspaceEventsConnector;
use fcp_prelude::FcpError;
use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn run_async_test<F>(future: F) -> F::Output
where
    F: Future,
{
    fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
}

async fn configured_connector(server: &MockServer) -> WorkspaceEventsConnector {
    let mut connector = WorkspaceEventsConnector::new();
    connector
        .handle_configure(json!({
            "access_token": "test-token",
            "events_base_url": format!("{}/v1", server.uri()),
            "pubsub_base_url": format!("{}/v1", server.uri()),
        }))
        .await
        .expect("configure should accept loopback base URLs");
    connector
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).expect("missing expected JSON field")
}

fn array_field<'a>(value: &'a Value, name: &str) -> &'a Vec<Value> {
    field(value, name)
        .as_array()
        .expect("expected JSON field to be an array")
}

fn operation_ids(introspection: &Value) -> Vec<&str> {
    array_field(introspection, "operations")
        .iter()
        .filter_map(|operation| field(operation, "id").as_str())
        .collect()
}

fn manifest_declares_operation(manifest: &str, id: &str) -> bool {
    manifest
        .lines()
        .any(|line| line.starts_with("[provides.operations.") && line.contains(id))
}

const SCHEMA_OPERATION_IDS: [&str; 8] = [
    "workspace_events.describe_provisioning",
    "workspace_events.list_subscriptions",
    "workspace_events.get_subscription",
    "workspace_events.create_subscription",
    "workspace_events.reactivate_subscription",
    "workspace_events.delete_subscription",
    "workspace_events.pull_events",
    "workspace_events.ack_events",
];

fn workspace_events_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml"))
        .expect("Google Workspace Events manifest TOML should parse")
}

fn manifest_operations(manifest: &toml::Value) -> &toml::Table {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should contain provides.operations")
}

fn manifest_operation_schema(
    manifest: &toml::Value,
    operation_id: &str,
    schema_key: &str,
) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_id)
        .and_then(|operation| operation.get(schema_key))
        .expect("operation should define requested schema");

    serde_json::to_value(schema).expect("manifest schema should convert to JSON")
}

fn manifest_operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_id: &str,
) -> &'a toml::Table {
    manifest_operations(manifest)
        .get(operation_id)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .expect("operation should define network_constraints")
}

fn network_string_array<'a>(network_constraints: &'a toml::Table, key: &str) -> Vec<&'a str> {
    network_constraints
        .get(key)
        .and_then(toml::Value::as_array)
        .expect("network constraint should be an array")
        .iter()
        .map(|value| value.as_str().expect("network constraint should be string"))
        .collect()
}

fn network_integer_array(network_constraints: &toml::Table, key: &str) -> Vec<i64> {
    network_constraints
        .get(key)
        .and_then(toml::Value::as_array)
        .expect("network constraint should be an array")
        .iter()
        .map(|value| {
            value
                .as_integer()
                .expect("network constraint should be integer")
        })
        .collect()
}

fn assert_network_bool(network_constraints: &toml::Table, key: &str, expected: bool) {
    assert_eq!(
        network_constraints.get(key).and_then(toml::Value::as_bool),
        Some(expected),
        "{key} should be {expected}"
    );
}

fn assert_network_integer(network_constraints: &toml::Table, key: &str, expected: i64) {
    assert_eq!(
        network_constraints
            .get(key)
            .and_then(toml::Value::as_integer),
        Some(expected),
        "{key} should be {expected}"
    );
}

fn assert_common_network_denials(network_constraints: &toml::Table) {
    for key in [
        "deny_localhost",
        "deny_private_ranges",
        "deny_tailnet_ranges",
        "deny_ip_literals",
        "require_host_canonicalization",
    ] {
        assert_network_bool(network_constraints, key, true);
    }
    assert_network_integer(network_constraints, "max_redirects", 0);
}

fn assert_external_https_network_constraints(
    manifest: &toml::Value,
    operation_id: &str,
    expected_host: &str,
) {
    let network_constraints = manifest_operation_network_constraints(manifest, operation_id);
    assert_eq!(
        network_string_array(network_constraints, "host_allow"),
        vec![expected_host],
        "{operation_id} should restrict egress to its provider host"
    );
    assert_eq!(
        network_integer_array(network_constraints, "port_allow"),
        vec![443],
        "{operation_id} should restrict egress to HTTPS"
    );
    assert_common_network_denials(network_constraints);
    assert_network_bool(network_constraints, "require_sni", true);
    assert_network_integer(network_constraints, "dns_max_ips", 16);
}

fn introspection_operation<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
    array_field(introspection, "operations")
        .iter()
        .find(|operation| field(operation, "id") == operation_id)
        .expect("introspection should include operation")
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema should accept payload {payload:#}: {errors:#?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        !errors.is_empty(),
        "schema should reject payload {payload:#}"
    );
}

fn assert_manifest_runtime_schema_parity(manifest: &toml::Value, introspection: &Value) {
    let manifest_ops = manifest_operations(manifest);
    assert_eq!(
        manifest_ops.len(),
        SCHEMA_OPERATION_IDS.len(),
        "manifest operation count should match schema coverage set"
    );

    for operation_id in SCHEMA_OPERATION_IDS {
        let operation = introspection_operation(introspection, operation_id);
        let input_schema = manifest_operation_schema(manifest, operation_id, "input_schema");
        let output_schema = manifest_operation_schema(manifest, operation_id, "output_schema");

        assert_eq!(
            &input_schema,
            field(operation, "input_schema"),
            "{operation_id} manifest input_schema should match runtime introspection"
        );
        assert_eq!(
            &output_schema,
            field(operation, "output_schema"),
            "{operation_id} manifest output_schema should match runtime introspection"
        );
        assert!(
            jsonschema::validator_for(&input_schema).is_ok(),
            "{operation_id} manifest input_schema should compile"
        );
        assert!(
            jsonschema::validator_for(&output_schema).is_ok(),
            "{operation_id} manifest output_schema should compile"
        );
    }
}

fn assert_catalog_input_schema_examples(manifest: &toml::Value) {
    let describe = manifest_operation_schema(
        manifest,
        "workspace_events.describe_provisioning",
        "input_schema",
    );
    assert_schema_accepts(&describe, &json!({}));
    assert_schema_accepts(
        &describe,
        &json!({ "scope_triggers": ["User selects Chat message events"] }),
    );
    assert_schema_rejects(&describe, &json!({ "scope_triggers": [] }));
    assert_schema_rejects(&describe, &json!({ "unexpected": true }));

    let list = manifest_operation_schema(
        manifest,
        "workspace_events.list_subscriptions",
        "input_schema",
    );
    assert_schema_accepts(&list, &json!({}));
    assert_schema_accepts(&list, &json!({ "page_size": 25, "page_token": "token-1" }));
    assert_schema_rejects(&list, &json!({ "page_size": -1 }));
    assert_schema_rejects(&list, &json!({ "page_size": 25, "extra": true }));

    let get = manifest_operation_schema(
        manifest,
        "workspace_events.get_subscription",
        "input_schema",
    );
    assert_schema_accepts(&get, &json!({ "subscription_name": "subscriptions/sub-1" }));
    assert_schema_rejects(&get, &json!({}));
}

fn assert_lifecycle_input_schema_examples(manifest: &toml::Value) {
    let create = manifest_operation_schema(
        manifest,
        "workspace_events.create_subscription",
        "input_schema",
    );
    assert_schema_accepts(
        &create,
        &json!({
            "target_resource": "//chat.googleapis.com/spaces/AAAA",
            "event_types": ["google.workspace.chat.message.v1.created"],
            "pubsub_topic": "projects/demo/topics/workspace-events",
            "ttl": "86400s",
            "include_resource": true,
            "field_mask": "message"
        }),
    );
    assert_schema_rejects(
        &create,
        &json!({
            "target_resource": "//chat.googleapis.com/spaces/AAAA",
            "event_types": [],
            "pubsub_topic": "projects/demo/topics/workspace-events"
        }),
    );
    assert_schema_rejects(
        &create,
        &json!({
            "target_resource": "//chat.googleapis.com/spaces/AAAA",
            "event_types": ["google.workspace.chat.message.v1.created"],
            "pubsub_topic": "projects/demo/topics/workspace-events",
            "extra": true
        }),
    );

    let reactivate = manifest_operation_schema(
        manifest,
        "workspace_events.reactivate_subscription",
        "input_schema",
    );
    assert_schema_accepts(
        &reactivate,
        &json!({ "subscription_name": "subscriptions/sub-1", "ttl": "86400s" }),
    );
    assert_schema_rejects(&reactivate, &json!({}));

    let delete = manifest_operation_schema(
        manifest,
        "workspace_events.delete_subscription",
        "input_schema",
    );
    assert_schema_accepts(
        &delete,
        &json!({ "subscription_name": "subscriptions/sub-1", "validate_only": true }),
    );
    assert_schema_rejects(
        &delete,
        &json!({ "subscription_name": "subscriptions/sub-1", "validate_only": "true" }),
    );
}

fn assert_delivery_input_schema_examples(manifest: &toml::Value) {
    let pull = manifest_operation_schema(manifest, "workspace_events.pull_events", "input_schema");
    assert_schema_accepts(
        &pull,
        &json!({
            "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
            "max_messages": 10
        }),
    );
    assert_schema_accepts(
        &pull,
        &json!({ "pubsub_subscription": "projects/demo/subscriptions/workspace-events" }),
    );
    assert_schema_rejects(
        &pull,
        &json!({
            "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
            "max_messages": 0
        }),
    );

    let ack = manifest_operation_schema(manifest, "workspace_events.ack_events", "input_schema");
    assert_schema_accepts(
        &ack,
        &json!({
            "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
            "ack_ids": ["ack-1", "ack-2"]
        }),
    );
    assert_schema_rejects(
        &ack,
        &json!({
            "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
            "ack_ids": []
        }),
    );
}

fn assert_input_schema_examples(manifest: &toml::Value) {
    assert_catalog_input_schema_examples(manifest);
    assert_lifecycle_input_schema_examples(manifest);
    assert_delivery_input_schema_examples(manifest);
}

fn assert_output_schema_examples(manifest: &toml::Value) {
    let describe = manifest_operation_schema(
        manifest,
        "workspace_events.describe_provisioning",
        "output_schema",
    );
    assert_schema_accepts(
        &describe,
        &json!({ "bundle": {}, "effective_scopes": ["https://www.googleapis.com/auth/chat.messages.readonly"] }),
    );
    assert_schema_rejects(&describe, &json!({ "bundle": {} }));

    let list = manifest_operation_schema(
        manifest,
        "workspace_events.list_subscriptions",
        "output_schema",
    );
    assert_schema_accepts(
        &list,
        &json!({ "subscriptions": [{ "name": "subscriptions/sub-1" }], "next_page_token": "" }),
    );
    assert_schema_rejects(&list, &json!({ "subscriptions": [] }));

    let get = manifest_operation_schema(
        manifest,
        "workspace_events.get_subscription",
        "output_schema",
    );
    assert_schema_accepts(
        &get,
        &json!({ "subscription": { "name": "subscriptions/sub-1" } }),
    );
    assert_schema_rejects(
        &get,
        &json!({ "subscription": { "name": "subscriptions/sub-1" }, "extra": true }),
    );

    for operation_id in [
        "workspace_events.create_subscription",
        "workspace_events.reactivate_subscription",
        "workspace_events.delete_subscription",
    ] {
        let schema = manifest_operation_schema(manifest, operation_id, "output_schema");
        assert_schema_accepts(&schema, &json!({ "operation": { "name": "operations/1" } }));
        assert_schema_rejects(&schema, &json!({}));
    }

    let pull = manifest_operation_schema(manifest, "workspace_events.pull_events", "output_schema");
    assert_schema_accepts(
        &pull,
        &json!({ "received_messages": [], "decoded_events": [] }),
    );
    assert_schema_rejects(&pull, &json!({ "received_messages": [] }));

    let ack = manifest_operation_schema(manifest, "workspace_events.ack_events", "output_schema");
    assert_schema_accepts(&ack, &json!({ "status": "acked", "acked_count": 2 }));
    assert_schema_rejects(&ack, &json!({ "status": "ok", "acked_count": 2 }));
}

async fn mount_subscription_list(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/subscriptions"))
        .and(query_param("pageSize", "2"))
        .and(query_param("pageToken", "token-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "subscriptions": [
                {
                    "name": "subscriptions/sub-1",
                    "state": "ACTIVE",
                    "targetResource": "//chat.googleapis.com/spaces/AAAA",
                    "notificationEndpoint": {
                        "pubsubTopic": "projects/demo/topics/workspace-events"
                    }
                }
            ],
            "nextPageToken": "token-2"
        })))
        .mount(server)
        .await;
}

async fn mount_subscription_create(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/subscriptions"))
        .and(body_string_contains("//chat.googleapis.com/spaces/AAAA"))
        .and(body_string_contains(
            "google.workspace.chat.message.v1.created",
        ))
        .and(body_string_contains(
            "projects/demo/topics/workspace-events",
        ))
        .and(body_string_contains("86400s"))
        .and(body_string_contains("message"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "operations/create-1",
            "done": false
        })))
        .mount(server)
        .await;
}

async fn assert_introspection_matches_manifest(connector: &WorkspaceEventsConnector) {
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let ids = operation_ids(&introspection);
    for id in [
        "workspace_events.create_subscription",
        "workspace_events.list_subscriptions",
        "workspace_events.pull_events",
        "workspace_events.ack_events",
    ] {
        assert!(ids.contains(&id), "introspection missing operation {id}");
    }
    assert_eq!(
        field(field(&introspection, "event_caps"), "requires_ack"),
        true
    );

    let manifest = include_str!("../manifest.toml");
    for id in ids {
        assert!(
            manifest_declares_operation(manifest, id),
            "manifest missing introspected operation {id}"
        );
    }
    assert!(
        manifest.contains("Pub/Sub-backed event delivery"),
        "manifest should describe Pub/Sub-backed Workspace Events delivery"
    );
}

#[test]
fn manifest_declares_scoped_network_constraints() {
    let manifest = workspace_events_manifest();
    let manifest_ops = manifest_operations(&manifest);
    assert_eq!(
        manifest_ops.len(),
        SCHEMA_OPERATION_IDS.len(),
        "manifest operation count should match network-constraint coverage set"
    );

    let local_only =
        manifest_operation_network_constraints(&manifest, "workspace_events.describe_provisioning");
    assert_eq!(
        network_string_array(local_only, "host_allow"),
        vec!["none.invalid"],
        "local provisioning metadata should declare no external egress"
    );
    assert_eq!(
        network_integer_array(local_only, "port_allow"),
        vec![0],
        "local provisioning metadata should use the no-egress port sentinel"
    );
    assert!(
        network_string_array(local_only, "ip_allow").is_empty(),
        "local provisioning metadata should not allow direct IP egress"
    );
    assert!(
        network_string_array(local_only, "cidr_deny").is_empty(),
        "local provisioning metadata should keep CIDR denies explicit and empty"
    );
    assert!(
        network_string_array(local_only, "spki_pins").is_empty(),
        "local provisioning metadata should not pin certificates without TLS egress"
    );
    assert_common_network_denials(local_only);
    assert_network_bool(local_only, "require_sni", false);
    assert_network_integer(local_only, "dns_max_ips", 0);
    assert_network_integer(local_only, "connect_timeout_ms", 1000);
    assert_network_integer(local_only, "total_timeout_ms", 10000);
    assert_network_integer(local_only, "max_response_bytes", 65536);

    for operation_id in [
        "workspace_events.list_subscriptions",
        "workspace_events.get_subscription",
        "workspace_events.create_subscription",
        "workspace_events.reactivate_subscription",
        "workspace_events.delete_subscription",
    ] {
        assert_external_https_network_constraints(
            &manifest,
            operation_id,
            "workspaceevents.googleapis.com",
        );
    }

    for operation_id in [
        "workspace_events.pull_events",
        "workspace_events.ack_events",
    ] {
        assert_external_https_network_constraints(&manifest, operation_id, "pubsub.googleapis.com");
    }
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    run_async_test(async {
        let manifest = workspace_events_manifest();
        let connector = WorkspaceEventsConnector::new();
        let introspection = connector
            .handle_introspect()
            .await
            .expect("introspection should serialize");

        assert_manifest_runtime_schema_parity(&manifest, &introspection);
        assert_input_schema_examples(&manifest);
        assert_output_schema_examples(&manifest);
    });
}

#[test]
fn list_create_and_introspection_match_manifest_pubsub_contract() {
    run_async_test(async {
        let server = MockServer::start().await;
        mount_subscription_list(&server).await;
        mount_subscription_create(&server).await;

        let mut connector = configured_connector(&server).await;
        let listed = connector
            .handle_invoke(json!({
                "operation": "workspace_events.list_subscriptions",
                "input": {
                    "page_size": 2,
                    "page_token": "token-1"
                }
            }))
            .await
            .expect("paginated subscription listing should succeed");
        assert_eq!(field(&listed, "next_page_token"), "token-2");
        let subscription = array_field(&listed, "subscriptions")
            .first()
            .expect("subscription");
        assert_eq!(
            field(field(subscription, "notificationEndpoint"), "pubsubTopic"),
            "projects/demo/topics/workspace-events"
        );

        let created = connector
            .handle_invoke(json!({
                "operation": "workspace_events.create_subscription",
                "input": {
                    "target_resource": "//chat.googleapis.com/spaces/AAAA",
                    "event_types": ["google.workspace.chat.message.v1.created"],
                    "pubsub_topic": "projects/demo/topics/workspace-events",
                    "ttl": "86400s",
                    "include_resource": true,
                    "field_mask": "message"
                }
            }))
            .await
            .expect("subscription creation should post the Pub/Sub endpoint shape");
        assert_eq!(
            field(field(&created, "operation"), "name"),
            "operations/create-1"
        );

        let err = connector
            .handle_invoke(json!({
                "operation": "workspace_events.create_subscription",
                "input": {
                    "target_resource": "//chat.googleapis.com/spaces/AAAA",
                    "event_types": ["   "],
                    "pubsub_topic": "projects/demo/topics/workspace-events"
                }
            }))
            .await
            .expect_err("blank event type identifiers must be rejected before the API call");
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("event_types")),
            "expected InvalidRequest for blank event_types, got {err:?}"
        );

        assert_introspection_matches_manifest(&connector).await;
    });
}

#[test]
fn reactivate_and_delete_subscription_use_workspace_events_control_plane() {
    run_async_test(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/subscriptions/sub-1:reactivate"))
            .and(body_string_contains("86400s"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "operations/reactivate-1",
                "done": false
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/v1/subscriptions/sub-1"))
            .and(query_param("validateOnly", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "operations/delete-1",
                "done": true
            })))
            .mount(&server)
            .await;

        let mut connector = configured_connector(&server).await;
        let reactivated = connector
            .handle_invoke(json!({
                "operation": "workspace_events.reactivate_subscription",
                "input": {
                    "subscription_name": "subscriptions/sub-1",
                    "ttl": "86400s"
                }
            }))
            .await
            .expect("reactivate should succeed");
        assert_eq!(
            field(field(&reactivated, "operation"), "name"),
            "operations/reactivate-1"
        );

        let deleted = connector
            .handle_invoke(json!({
                "operation": "workspace_events.delete_subscription",
                "input": {
                    "subscription_name": "subscriptions/sub-1",
                    "validate_only": true
                }
            }))
            .await
            .expect("delete validate-only should succeed");
        assert_eq!(
            field(field(&deleted, "operation"), "name"),
            "operations/delete-1"
        );
    });
}

#[test]
fn pull_events_reports_empty_batches_and_malformed_payloads() {
    run_async_test(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/demo/subscriptions/workspace-events:pull",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "receivedMessages": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/demo/subscriptions/malformed-events:pull",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "receivedMessages": [
                    {
                        "ackId": "ack-bad",
                        "deliveryAttempt": 2,
                        "message": {
                            "data": "not base64!",
                            "messageId": "msg-bad",
                            "publishTime": "2026-05-06T00:00:00Z",
                            "attributes": {"eventType": "google.workspace.chat.message.v1.created"}
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let mut connector = configured_connector(&server).await;
        let empty = connector
            .handle_invoke(json!({
                "operation": "workspace_events.pull_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                    "max_messages": 10
                }
            }))
            .await
            .expect("empty pull should succeed");
        assert!(array_field(&empty, "received_messages").is_empty());
        assert!(array_field(&empty, "decoded_events").is_empty());

        let malformed = connector
            .handle_invoke(json!({
                "operation": "workspace_events.pull_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/malformed-events",
                    "max_messages": 1
                }
            }))
            .await
            .expect("malformed payload should be reported without dropping envelope metadata");
        let decoded_events = array_field(&malformed, "decoded_events");
        let decoded = decoded_events
            .first()
            .expect("malformed message should keep decoded envelope metadata");
        assert_eq!(field(decoded, "ack_id"), "ack-bad");
        assert_eq!(field(decoded, "delivery_attempt"), 2);
        assert_eq!(field(decoded, "message_id"), "msg-bad");
        assert_eq!(
            field(field(decoded, "attributes"), "eventType"),
            "google.workspace.chat.message.v1.created"
        );
        assert!(
            field(decoded, "decode_error")
                .as_str()
                .is_some_and(|message| message.contains("invalid base64")),
            "expected structured decode error, got {decoded:?}"
        );
    });
}

#[test]
fn pull_events_preserves_duplicate_delivery_and_decoded_payloads() {
    run_async_test(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/demo/subscriptions/duplicate-events:pull",
            ))
            .and(body_string_contains(r#""maxMessages":2"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "receivedMessages": [
                    {
                        "ackId": "ack-first",
                        "deliveryAttempt": 1,
                        "message": {
                            "data": base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                br#"{"event":"created","delivery":"first"}"#
                            ),
                            "messageId": "msg-dup",
                            "publishTime": "2026-05-06T00:00:00Z",
                            "attributes": {"eventType": "google.workspace.chat.message.v1.created"}
                        }
                    },
                    {
                        "ackId": "ack-redelivery",
                        "deliveryAttempt": 2,
                        "message": {
                            "data": base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                br#"{"event":"created","delivery":"second"}"#
                            ),
                            "messageId": "msg-dup",
                            "publishTime": "2026-05-06T00:00:01Z",
                            "attributes": {"eventType": "google.workspace.chat.message.v1.created"}
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let mut connector = configured_connector(&server).await;
        let result = connector
            .handle_invoke(json!({
                "operation": "workspace_events.pull_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/duplicate-events",
                    "max_messages": 2
                }
            }))
            .await
            .expect("duplicate delivery batch should preserve both envelopes");
        let decoded_events = array_field(&result, "decoded_events");
        assert_eq!(decoded_events.len(), 2);
        assert_eq!(field(&decoded_events[0], "message_id"), "msg-dup");
        assert_eq!(field(&decoded_events[1], "message_id"), "msg-dup");
        assert_eq!(field(&decoded_events[0], "ack_id"), "ack-first");
        assert_eq!(field(&decoded_events[1], "ack_id"), "ack-redelivery");
        assert_eq!(
            field(field(&decoded_events[1], "decoded_json"), "delivery"),
            "second"
        );
    });
}

#[test]
fn pubsub_rate_limit_and_auth_failures_surface_structured_errors() {
    run_async_test(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/demo/subscriptions/rate-limited:pull"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "7")
                    .set_body_json(json!({
                        "error": {
                            "message": "quota exhausted"
                        }
                    })),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/demo/subscriptions/auth-failed:pull"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": {
                    "message": "invalid credentials"
                }
            })))
            .mount(&server)
            .await;

        let mut connector = configured_connector(&server).await;
        let rate_limited = connector
            .handle_invoke(json!({
                "operation": "workspace_events.pull_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/rate-limited",
                    "max_messages": 1
                }
            }))
            .await
            .expect_err("429 must surface as rate limited");
        assert!(
            matches!(
                rate_limited,
                FcpError::RateLimited {
                    retry_after_ms: 7_000,
                    ..
                }
            ),
            "expected Retry-After to be preserved, got {rate_limited:?}"
        );

        let unauthorized = connector
            .handle_invoke(json!({
                "operation": "workspace_events.pull_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/auth-failed",
                    "max_messages": 1
                }
            }))
            .await
            .expect_err("401 must surface as unauthorized");
        assert!(
            matches!(unauthorized, FcpError::Unauthorized { .. }),
            "expected Unauthorized, got {unauthorized:?}"
        );
    });
}

#[test]
fn ack_events_posts_ack_ids_and_rejects_blank_ack_ids() {
    run_async_test(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/v1/projects/demo/subscriptions/workspace-events:acknowledge",
            ))
            .and(body_string_contains("ack-1"))
            .and(body_string_contains("ack-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let mut connector = configured_connector(&server).await;
        let acked = connector
            .handle_invoke(json!({
                "operation": "workspace_events.ack_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                    "ack_ids": ["ack-1", " ack-2 "]
                }
            }))
            .await
            .expect("ack should succeed");
        assert_eq!(field(&acked, "status"), "acked");
        assert_eq!(field(&acked, "acked_count"), 2);

        let err = connector
            .handle_invoke(json!({
                "operation": "workspace_events.ack_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                    "ack_ids": ["   "]
                }
            }))
            .await
            .expect_err("blank ack IDs must be rejected before Pub/Sub call");
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("ack_ids")),
            "expected InvalidRequest for blank ack_ids, got {err:?}"
        );
    });
}

#[test]
fn pull_events_rejects_zero_max_messages() {
    run_async_test(async {
        let server = MockServer::start().await;
        let mut connector = configured_connector(&server).await;
        let err = connector
            .handle_invoke(json!({
                "operation": "workspace_events.pull_events",
                "input": {
                    "pubsub_subscription": "projects/demo/subscriptions/workspace-events",
                    "max_messages": 0
                }
            }))
            .await
            .expect_err("max_messages=0 must be rejected before Pub/Sub call");
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("max_messages")),
            "expected InvalidRequest for max_messages, got {err:?}"
        );
    });
}

#[test]
fn shutdown_reports_graceful_connector_stop() {
    run_async_test(async {
        let server = MockServer::start().await;
        let mut connector = configured_connector(&server).await;
        let result = connector
            .handle_shutdown(json!({}))
            .await
            .expect("shutdown should be graceful");
        assert_eq!(field(&result, "status"), "shutdown");
    });
}
