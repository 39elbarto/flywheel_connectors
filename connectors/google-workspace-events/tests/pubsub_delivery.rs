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
