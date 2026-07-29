//! Environment-gated live verification for the `Monday.com` connector.

#![allow(
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use fcp_monday::connector::MondayConnector;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const TOKEN_ENV: &str = "MONDAY_SANDBOX_TOKEN";
const BOARD_ID_ENV: &str = "MONDAY_SANDBOX_BOARD_ID";
const BASE_URL_ENV: &str = "MONDAY_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_LIST_BOARDS: &str = "monday.boards.list";
const OP_GET_BOARD: &str = "monday.boards.get";
const OP_CREATE_ITEM: &str = "monday.items.create";
const OP_DELETE_ITEM: &str = "monday.items.delete";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.1.2";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("monday", "Monday.com sandbox")
        .with_env_secret(
            "api_token",
            TOKEN_ENV,
            "Monday.com API token scoped to read boards and create/delete items in the sandbox workspace",
        )
        .with_env_var(
            BOARD_ID_ENV,
            "Monday.com sandbox board id used for the namespaced create/delete item proof",
        )
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_env_var_default(
            BASE_URL_ENV,
            "https://api.monday.com/v2",
            "Monday.com GraphQL API endpoint",
        )
        .with_account_setup(
            "Use a disposable Monday.com workspace with a dedicated board for sandbox item create/delete cleanup proofs plus auth denial.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(1.0, true)
}

fn emit_live_jsonl(
    status: &str,
    reason: &str,
    observed_count: usize,
    cleanup_result: &str,
    auth_denial_result: &str,
    evidence: &Value,
) {
    eprintln!(
        "MONDAY_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "monday_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": TOKEN_ENV,
            "required_env": [BOARD_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_CREATE_ITEM,
            "operations": [OP_LIST_BOARDS, OP_GET_BOARD, OP_CREATE_ITEM, OP_DELETE_ITEM],
            "bead_id": BEAD_ID,
            "status": status,
            "provider": "Monday.com sandbox",
            "environment": "sandbox",
            "resource_class": "namespaced_synthetic_item",
            "observed_count": observed_count,
            "call_ceiling": 5,
            "rate_limit_guidance": "Performs one board listing, one configured-board lookup, one create/delete item pair, and one bad-token denial check against the sandbox workspace.",
            "mutation_expected": true,
            "cleanup_strategy": "prefix_delete",
            "cleanup_result": cleanup_result,
            "auth_denial_result": auth_denial_result,
            "provider_resource_ids_logged": false,
            "board_id_logged": false,
            "secret_values_logged": false,
            "base_url_logged": false,
            "item_name_logged": false,
            "item_id_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

#[fcp_async_core::runtime::test]
async fn monday_live_sandbox_item_flow_or_structured_skip_jsonl()
-> Result<(), Box<dyn std::error::Error>> {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            "not_started",
            "not_started",
            &env.evidence_summary(),
        );
        return Ok(());
    }

    let mut connector = configured_connector(&env).await?;
    let board_listing = match connector
        .handle_invoke(json!({
            "operation_id": OP_LIST_BOARDS,
            "input": {"limit": 1}
        }))
        .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                0,
                "not_started",
                "not_started",
                &env.evidence_summary(),
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            return Err(error);
        }
    };
    env.budget.record_api_call(OP_LIST_BOARDS, 0.0);
    let listed_board_count = board_listing
        .get("boards")
        .and_then(serde_json::Value::as_array)
        .map_or(0, std::vec::Vec::len);

    let board_id = env
        .env_vars
        .get(BOARD_ID_ENV)
        .ok_or("board ID env is ready")?;
    let board_lookup = match connector
        .handle_invoke(json!({
            "operation_id": OP_GET_BOARD,
            "input": {"board_id": board_id}
        }))
        .await
    {
        Ok(value) => value,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                listed_board_count,
                "not_started",
                "not_started",
                &env.evidence_summary(),
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            return Err(error);
        }
    };
    env.budget.record_api_call(OP_GET_BOARD, 0.0);
    let board_seen = board_lookup
        .get("board")
        .and_then(|board| board.get("id"))
        .and_then(Value::as_str)
        .is_some_and(|id| id == board_id);
    if !board_seen {
        emit_live_jsonl(
            "failed",
            "MONDAY_SANDBOX_BOARD_ID was not visible to the sandbox token",
            listed_board_count,
            "not_started",
            "not_started",
            &env.evidence_summary(),
        );
        return Err(std::io::Error::other("Monday.com sandbox board id was not visible").into());
    }

    let item_id = create_sandbox_item(&connector, &env, listed_board_count).await?;
    env.budget.record_api_call(OP_CREATE_ITEM, 0.0);
    delete_sandbox_item(&connector, &env, listed_board_count, &item_id).await?;
    env.budget.record_api_call(OP_DELETE_ITEM, 0.0);

    let auth_denial_result = match verify_bad_token_denied(&env).await {
        Ok(result) => result,
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                listed_board_count + usize::from(board_seen),
                "deleted_created_item",
                "bad_token_denial_failed",
                &env.evidence_summary(),
            );
            return Err(error);
        }
    };

    connector.handle_shutdown(json!({})).await?;

    emit_live_jsonl(
        "passed",
        "",
        listed_board_count + usize::from(board_seen),
        "deleted_created_item",
        auth_denial_result,
        &json!({
            "environment": env.evidence_summary(),
            "operation_result": "boards.list, boards.get, items.create, items.delete, and bad-token denial completed",
            "created_item_id_recorded": false,
        }),
    );
    Ok(())
}

async fn configured_connector(
    env: &LiveEnvironment,
) -> Result<MondayConnector, Box<dyn std::error::Error>> {
    let token = env
        .secrets
        .get("api_token")
        .ok_or("API token env is ready")?;
    let base_url = env
        .env_vars
        .get(BASE_URL_ENV)
        .ok_or("base URL env is ready")?;
    let mut connector = MondayConnector::new();
    connector
        .handle_configure(json!({
            "api_token": token,
            "base_url": base_url
        }))
        .await?;
    connector
        .handle_handshake(json!({
            "session_id": format!("monday-live-{}", env.tenant.run_prefix())
        }))
        .await?;
    Ok(connector)
}

async fn create_sandbox_item(
    connector: &MondayConnector,
    env: &LiveEnvironment,
    observed_count: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let board_id = env
        .env_vars
        .get(BOARD_ID_ENV)
        .ok_or("board ID env is ready")?;
    let run_prefix = env.tenant.run_prefix();
    let item = connector
        .handle_invoke(json!({
            "operation_id": OP_CREATE_ITEM,
            "input": {
                "board_id": board_id,
                "item_name": format!("fcp-sandbox-{run_prefix}"),
            }
        }))
        .await;

    match item {
        Ok(value) => value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .map_or_else(
                || {
                    emit_live_jsonl(
                        "failed",
                        "Monday.com items.create response did not include an item id",
                        observed_count,
                        "not_started",
                        "not_started",
                        &env.evidence_summary(),
                    );
                    Err(std::io::Error::other(
                        "Monday.com items.create response did not include an item id",
                    )
                    .into())
                },
                |item_id| Ok(item_id.to_string()),
            ),
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                observed_count,
                "not_started",
                "not_started",
                &env.evidence_summary(),
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            Err(error)
        }
    }
}

async fn delete_sandbox_item(
    connector: &MondayConnector,
    env: &LiveEnvironment,
    observed_count: usize,
    item_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match connector
        .handle_invoke(json!({
            "operation_id": OP_DELETE_ITEM,
            "input": {
                "item_id": item_id,
            }
        }))
        .await
    {
        Ok(_) => Ok(()),
        Err(error) => {
            emit_live_jsonl(
                "failed",
                &error.to_string(),
                observed_count,
                "delete_failed_for_created_item",
                "not_started",
                &env.evidence_summary(),
            );
            let error: Box<dyn std::error::Error> = Box::new(error);
            Err(error)
        }
    }
}

async fn verify_bad_token_denied(
    env: &LiveEnvironment,
) -> Result<&'static str, Box<dyn std::error::Error>> {
    let base_url = env
        .env_vars
        .get(BASE_URL_ENV)
        .ok_or("base URL env is ready")?;
    let mut connector = MondayConnector::new();
    connector
        .handle_configure(json!({
            "api_token": format!("fcp-invalid-token-{}", env.tenant.run_prefix()),
            "base_url": base_url
        }))
        .await?;
    connector
        .handle_handshake(json!({
            "session_id": format!("monday-live-denied-{}", env.tenant.run_prefix())
        }))
        .await?;

    let denial = connector
        .handle_invoke(json!({
            "operation_id": OP_LIST_BOARDS,
            "input": {"limit": 1}
        }))
        .await;
    env.budget
        .record_api_call("monday.boards.list.bad_token", 0.0);
    connector.handle_shutdown(json!({})).await?;

    match denial {
        Ok(_) => Err(std::io::Error::other("bad Monday.com token unexpectedly authorized").into()),
        Err(error) => {
            let message = error.to_string().to_ascii_lowercase();
            if error.numeric_code() == 2001 || message.contains("auth") {
                Ok("bad_token_denied")
            } else {
                Err(std::io::Error::other(format!(
                    "bad-token check failed with non-auth error: {error}"
                ))
                .into())
            }
        }
    }
}
