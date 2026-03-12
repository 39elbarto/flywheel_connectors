//! Integration tests for the FCP Cron connector.

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

use fcp_cron::connector::CronConnector;

async fn setup_connector() -> CronConnector {
    let mut c = CronConnector::new();
    c.handle_configure(json!({})).await.unwrap();
    c.handle_handshake(json!({"session_id": "test-session"}))
        .await
        .unwrap();
    c
}

// ==========================================================================
// Lifecycle tests
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = CronConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
    assert_eq!(h["configured"], false);
    assert_eq!(h["handshaken"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure() {
    let mut c = CronConnector::new();
    let result = c.handle_configure(json!({})).await;
    assert!(result.is_ok());
    let configured = result.unwrap();
    assert_eq!(configured["status"], "configured");
    assert_eq!(configured["state_store"]["backend"], "memory");
    assert_eq!(configured["state_store"]["persist_to_disk"], false);
    assert_eq!(configured["clock"]["source"], "system_utc");
    assert_eq!(configured["clock"]["timezone"], "UTC");
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded"); // configured but not handshaken
    assert_eq!(h["configured"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_with_custom_policy() {
    let mut c = CronConnector::new();
    let configured = c
        .handle_configure(json!({
            "state_store": {
                "backend": "memory",
                "max_schedules": 123,
                "max_executions": 456,
                "persist_to_disk": false
            },
            "clock": {
                "source": "system_utc",
                "timezone": "utc",
                "max_clock_skew_seconds": 120
            }
        }))
        .await
        .unwrap();

    assert_eq!(configured["state_store"]["max_schedules"], 123);
    assert_eq!(configured["state_store"]["max_executions"], 456);
    assert_eq!(configured["clock"]["timezone"], "UTC");
    assert_eq!(configured["clock"]["max_clock_skew_seconds"], 120);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_rejects_disk_persistence() {
    let mut c = CronConnector::new();
    let result = c
        .handle_configure(json!({
            "state_store": {
                "backend": "memory",
                "persist_to_disk": true
            }
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_rejects_non_utc_timezone() {
    let mut c = CronConnector::new();
    let result = c
        .handle_configure(json!({
            "clock": {
                "source": "system_utc",
                "timezone": "America/New_York",
                "max_clock_skew_seconds": 30
            }
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let c = setup_connector().await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
    assert_eq!(h["configured"], true);
    assert_eq!(h["handshaken"], true);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = CronConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let mut c = setup_connector().await;
    c.handle_shutdown(json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_configured() {
    let c = setup_connector().await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert_eq!(check["connector_id"], "fcp.cron");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check_unconfigured() {
    let c = CronConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_healthy() {
    let c = setup_connector().await;
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "healthy");
    let checks = doc["checks"].as_array().unwrap();
    assert!(checks.iter().any(|c| c["name"] == "state_store"));
    assert!(checks.iter().any(|c| c["name"] == "clock_policy"));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_unconfigured() {
    let c = CronConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "unhealthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_configured_not_handshaken() {
    let mut c = CronConnector::new();
    c.handle_configure(json!({})).await.unwrap();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let c = setup_connector().await;
    let intro = c.handle_introspect().await.unwrap();
    let ops = intro["operations"].as_array().expect("operations array");
    assert!(!ops.is_empty(), "introspect should list operations");
    assert!(ops[0]["id"].is_string());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_shows_counts() {
    let c = setup_connector().await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["schedules"], 0);
    assert_eq!(h["executions"], 0);
    assert_eq!(h["requests"], 0);
    assert_eq!(h["errors"], 0);
}

// ==========================================================================
// Simulate tests
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn simulate_known_operation() {
    let c = setup_connector().await;
    let sim = c
        .handle_simulate(json!({"operation_id": "cron.schedules.list"}))
        .await
        .unwrap();
    assert_eq!(sim["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation() {
    let c = setup_connector().await;
    let sim = c
        .handle_simulate(json!({"operation_id": "unknown.op"}))
        .await
        .unwrap();
    assert_eq!(sim["allowed"], false);
}

#[fcp_async_core::runtime::test]
async fn simulate_all_operations() {
    let c = setup_connector().await;
    let ops = [
        "cron.schedules.list",
        "cron.schedules.create",
        "cron.schedules.delete",
        "cron.trigger",
        "cron.executions.list",
    ];
    for op in ops {
        let sim = c
            .handle_simulate(json!({"operation_id": op}))
            .await
            .unwrap();
        assert_eq!(sim["allowed"], true, "operation {op} should be allowed");
    }
}

// ==========================================================================
// Invoke: schedules.create
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "hourly-sync",
                "expression": "0 * * * *",
                "target_operation": "slack.channels.list"
            }
        }))
        .await
        .unwrap();
    assert!(
        result["schedule_id"]
            .as_str()
            .unwrap()
            .starts_with("sched_")
    );
    assert_eq!(c.schedule_count(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule_with_payload() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "payload-job",
                "expression": "*/5 * * * *",
                "target_operation": "slack.channels.list",
                "payload": {"channel": "general"}
            }
        }))
        .await
        .unwrap();
    assert!(result["schedule_id"].as_str().is_some());
}

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule_disabled() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.create",
        "input": {
            "name": "disabled-job",
            "expression": "0 0 * * *",
            "target_operation": "op.test",
            "enabled": false
        }
    }))
    .await
    .unwrap();
    assert_eq!(c.schedule_count(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule_invalid_expression() {
    let mut c = setup_connector().await;
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "bad",
                "expression": "not valid",
                "target_operation": "op.test"
            }
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule_duplicate_name() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.create",
        "input": {
            "name": "dup",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }
    }))
    .await
    .unwrap();

    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "dup",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule_missing_name() {
    let mut c = setup_connector().await;
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule_missing_expression() {
    let mut c = setup_connector().await;
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "test",
                "target_operation": "op.test"
            }
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_create_schedule_missing_target_operation() {
    let mut c = setup_connector().await;
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "test",
                "expression": "0 * * * *"
            }
        }))
        .await;
    assert!(err.is_err());
}

// ==========================================================================
// Invoke: schedules.list
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn invoke_list_schedules_empty() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["schedules"].as_array().unwrap().len(), 0);
}

#[fcp_async_core::runtime::test]
async fn invoke_list_schedules_after_create() {
    let mut c = setup_connector().await;
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.create",
        "input": {
            "name": "a",
            "expression": "0 * * * *",
            "target_operation": "op.a"
        }
    }))
    .await
    .unwrap();
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.create",
        "input": {
            "name": "b",
            "expression": "0 0 * * *",
            "target_operation": "op.b"
        }
    }))
    .await
    .unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.list",
            "input": {}
        }))
        .await
        .unwrap();
    let schedules = result["schedules"].as_array().unwrap();
    assert_eq!(schedules.len(), 2);
    assert!(schedules.iter().any(|s| s["name"] == "a"));
    assert!(schedules.iter().any(|s| s["name"] == "b"));
}

// ==========================================================================
// Invoke: schedules.delete
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn invoke_delete_schedule() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "to-delete",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }
        }))
        .await
        .unwrap();
    let sched_id = created["schedule_id"].as_str().unwrap();

    c.handle_invoke(json!({
        "operation_id": "cron.schedules.delete",
        "input": { "schedule_id": sched_id }
    }))
    .await
    .unwrap();
    assert_eq!(c.schedule_count(), 0);
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_schedule_not_found() {
    let mut c = setup_connector().await;
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.delete",
            "input": { "schedule_id": "nonexistent" }
        }))
        .await;
    assert!(err.is_err());
}

// ==========================================================================
// Invoke: cron.trigger
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn invoke_trigger() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "trigger-me",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }
        }))
        .await
        .unwrap();
    let sched_id = created["schedule_id"].as_str().unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.trigger",
            "input": { "schedule_id": sched_id }
        }))
        .await
        .unwrap();
    assert!(
        result["execution_id"]
            .as_str()
            .unwrap()
            .starts_with("exec_")
    );
    assert_eq!(c.execution_count(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_trigger_nonexistent() {
    let mut c = setup_connector().await;
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.trigger",
            "input": { "schedule_id": "sched_nonexistent" }
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_trigger_multiple_times() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "multi-trigger",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }
        }))
        .await
        .unwrap();
    let sched_id = created["schedule_id"].as_str().unwrap();

    for _ in 0..5 {
        c.handle_invoke(json!({
            "operation_id": "cron.trigger",
            "input": { "schedule_id": sched_id }
        }))
        .await
        .unwrap();
    }
    assert_eq!(c.execution_count(), 5);
}

// ==========================================================================
// Invoke: executions.list
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn invoke_executions_list_empty() {
    let mut c = setup_connector().await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.executions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["executions"].as_array().unwrap().len(), 0);
}

#[fcp_async_core::runtime::test]
async fn invoke_executions_list_after_triggers() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }
        }))
        .await
        .unwrap();
    let sched_id = created["schedule_id"].as_str().unwrap();

    c.handle_invoke(json!({
        "operation_id": "cron.trigger",
        "input": { "schedule_id": sched_id }
    }))
    .await
    .unwrap();
    c.handle_invoke(json!({
        "operation_id": "cron.trigger",
        "input": { "schedule_id": sched_id }
    }))
    .await
    .unwrap();

    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.executions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["executions"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn invoke_executions_list_filter_by_schedule() {
    let mut c = setup_connector().await;

    let s1 = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "a",
                "expression": "0 * * * *",
                "target_operation": "op.a"
            }
        }))
        .await
        .unwrap();
    let s2 = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "b",
                "expression": "0 0 * * *",
                "target_operation": "op.b"
            }
        }))
        .await
        .unwrap();

    let sid1 = s1["schedule_id"].as_str().unwrap();
    let sid2 = s2["schedule_id"].as_str().unwrap();

    c.handle_invoke(json!({
        "operation_id": "cron.trigger",
        "input": { "schedule_id": sid1 }
    }))
    .await
    .unwrap();
    c.handle_invoke(json!({
        "operation_id": "cron.trigger",
        "input": { "schedule_id": sid1 }
    }))
    .await
    .unwrap();
    c.handle_invoke(json!({
        "operation_id": "cron.trigger",
        "input": { "schedule_id": sid2 }
    }))
    .await
    .unwrap();

    let filtered = c
        .handle_invoke(json!({
            "operation_id": "cron.executions.list",
            "input": { "schedule_id": sid1 }
        }))
        .await
        .unwrap();
    assert_eq!(filtered["executions"].as_array().unwrap().len(), 2);

    let filtered2 = c
        .handle_invoke(json!({
            "operation_id": "cron.executions.list",
            "input": { "schedule_id": sid2 }
        }))
        .await
        .unwrap();
    assert_eq!(filtered2["executions"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_executions_list_with_limit() {
    let mut c = setup_connector().await;
    let created = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "test",
                "expression": "0 * * * *",
                "target_operation": "op.test"
            }
        }))
        .await
        .unwrap();
    let sched_id = created["schedule_id"].as_str().unwrap();

    for _ in 0..10 {
        c.handle_invoke(json!({
            "operation_id": "cron.trigger",
            "input": { "schedule_id": sched_id }
        }))
        .await
        .unwrap();
    }

    let result = c
        .handle_invoke(json!({
            "operation_id": "cron.executions.list",
            "input": { "limit": 3 }
        }))
        .await
        .unwrap();
    assert_eq!(result["executions"].as_array().unwrap().len(), 3);
}

// ==========================================================================
// Invoke: unknown operation
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn invoke_unknown_operation() {
    let mut c = setup_connector().await;
    let err = c
        .handle_invoke(json!({
            "operation_id": "unknown.op",
            "input": {}
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_missing_operation_id() {
    let mut c = setup_connector().await;
    let err = c.handle_invoke(json!({"input": {}})).await;
    assert!(err.is_err());
}

// ==========================================================================
// Invoke: not ready
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn invoke_before_configure_fails() {
    let mut c = CronConnector::new();
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.list",
            "input": {}
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn invoke_after_configure_but_before_handshake_fails() {
    let mut c = CronConnector::new();
    c.handle_configure(json!({})).await.unwrap();
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.list",
            "input": {}
        }))
        .await;
    assert!(err.is_err());
}

// ==========================================================================
// End-to-end workflow
// ==========================================================================

#[fcp_async_core::runtime::test]
async fn e2e_create_trigger_list_delete() {
    let mut c = setup_connector().await;

    // Create a schedule
    let created = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.create",
            "input": {
                "name": "e2e-test",
                "expression": "0 * * * *",
                "target_operation": "op.test",
                "payload": {"key": "value"}
            }
        }))
        .await
        .unwrap();
    let sched_id = created["schedule_id"].as_str().unwrap();

    // List schedules
    let list = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(list["schedules"].as_array().unwrap().len(), 1);

    // Trigger the schedule
    let triggered = c
        .handle_invoke(json!({
            "operation_id": "cron.trigger",
            "input": { "schedule_id": sched_id }
        }))
        .await
        .unwrap();
    let exec_id = triggered["execution_id"].as_str().unwrap();
    assert!(exec_id.starts_with("exec_"));

    // List executions
    let execs = c
        .handle_invoke(json!({
            "operation_id": "cron.executions.list",
            "input": { "schedule_id": sched_id }
        }))
        .await
        .unwrap();
    let exec_list = execs["executions"].as_array().unwrap();
    assert_eq!(exec_list.len(), 1);
    assert_eq!(exec_list[0]["status"], "triggered");
    assert_eq!(exec_list[0]["schedule_id"], sched_id);

    // Delete the schedule
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.delete",
        "input": { "schedule_id": sched_id }
    }))
    .await
    .unwrap();
    assert_eq!(c.schedule_count(), 0);

    // Executions persist after schedule delete
    let execs_after = c
        .handle_invoke(json!({
            "operation_id": "cron.executions.list",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(execs_after["executions"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn e2e_shutdown_clears_state_flags() {
    let mut c = setup_connector().await;

    // Create and trigger
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.create",
        "input": {
            "name": "shutdown-test",
            "expression": "0 * * * *",
            "target_operation": "op.test"
        }
    }))
    .await
    .unwrap();

    // Shutdown
    c.handle_shutdown(json!({})).await.unwrap();

    // Should not be able to invoke
    let err = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.list",
            "input": {}
        }))
        .await;
    assert!(err.is_err());
}

#[fcp_async_core::runtime::test]
async fn e2e_reconfigure_after_shutdown() {
    let mut c = setup_connector().await;

    // Create schedule
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.create",
        "input": {
            "name": "test",
            "expression": "0 * * * *",
            "target_operation": "op.test"
        }
    }))
    .await
    .unwrap();

    // Shutdown
    c.handle_shutdown(json!({})).await.unwrap();

    // Reconfigure
    c.handle_configure(json!({})).await.unwrap();
    c.handle_handshake(json!({"session_id": "new-session"}))
        .await
        .unwrap();

    // Should work again, but schedules from before shutdown still present in memory
    let list = c
        .handle_invoke(json!({
            "operation_id": "cron.schedules.list",
            "input": {}
        }))
        .await
        .unwrap();
    // Schedules persist through shutdown (in-memory state not cleared)
    assert_eq!(list["schedules"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn health_counts_increment() {
    let mut c = setup_connector().await;

    // Create a schedule
    c.handle_invoke(json!({
        "operation_id": "cron.schedules.create",
        "input": {
            "name": "counter-test",
            "expression": "0 * * * *",
            "target_operation": "op.test"
        }
    }))
    .await
    .unwrap();

    let h = c.handle_health().await.unwrap();
    assert_eq!(h["schedules"], 1);
    assert_eq!(h["requests"], 1);
}
