mod lease_e2e_support;

use std::fs;
use std::path::{Path, PathBuf};

use fcp_core::{ObjectIdKey, TailscaleNodeId, ZoneId};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_kernel::{ConnectorId, InvokeResponse, InvokeStatus};
use lease_e2e_support::{
    HttpHostProcess, TEST_ADMIN_BEARER_TOKEN, build_invoke_request, capability_public_key_hex,
    host_e2e_lock, http_get_json, http_post_json,
    seed_singleton_writer_connector_state_with_durable_lease,
    singleton_writer_connector_lease_subject_id_for_test,
    singleton_writer_test_connector_config_with_state,
};
use serde::Serialize;
use serde_json::{Value, json};

const HOST_FAILOVER_REPLAY_SCHEMA_VERSION: &str = "1.0.0";
const HOST_FAILOVER_REPLAY_FILE_NAME: &str = "host_failover_replay.jsonl";

#[derive(Debug, Serialize)]
struct HostFailoverReplayEvent {
    schema_version: &'static str,
    phase: &'static str,
    local_node_hash: Option<String>,
    payload: Value,
}

#[derive(Debug, Default)]
struct HostFailoverReplay {
    events: Vec<HostFailoverReplayEvent>,
}

impl HostFailoverReplay {
    fn record(&mut self, phase: &'static str, local_node: Option<&str>, payload: Value) {
        self.events.push(HostFailoverReplayEvent {
            schema_version: HOST_FAILOVER_REPLAY_SCHEMA_VERSION,
            phase,
            local_node_hash: local_node.map(hash_node_label),
            payload,
        });
    }

    fn write_jsonl(&self, root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        fs::create_dir_all(root)?;
        let path = root.join(HOST_FAILOVER_REPLAY_FILE_NAME);
        let lines = self
            .events
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?;
        let mut rendered = lines.join("\n");
        rendered.push('\n');
        fs::write(&path, rendered)?;
        Ok(path)
    }
}

fn hash_node_label(node_label: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-host-lease-handoff-replay-node-v1");
    hasher.update(node_label.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn node_hash_values(nodes: &[&str]) -> Vec<String> {
    nodes.iter().map(|node| hash_node_label(node)).collect()
}

fn redacted_refusal_values(refusals: &[(String, String)]) -> Vec<Value> {
    refusals
        .iter()
        .map(|(node, error)| {
            json!({
                "node_id_hash": hash_node_label(node),
                "not_selected_coordinator": error.contains("NotSelectedCoordinator"),
            })
        })
        .collect()
}

fn assert_no_raw_node_labels(rendered: &str) {
    for raw_node in ["node-a", "node-b", "node-c"] {
        assert!(
            !rendered.contains(raw_node),
            "host failover replay must not expose raw node label {raw_node}: {rendered}"
        );
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn leader_departure_flushes_state_reselects_holder_and_fences_stale_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-failover:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let replay_dir = tempfile::tempdir()?;
    let mut replay = HostFailoverReplay::default();
    let object_id_key = ObjectIdKey::from_bytes([0xC6; 32]);
    let all_nodes = ["node-a", "node-b", "node-c"];
    let initial_eligible_nodes = all_nodes.join(",");
    let initial_eligible_node_ids = all_nodes
        .iter()
        .map(|node| TailscaleNodeId::new(*node))
        .collect::<Vec<_>>();
    let subject_id = singleton_writer_connector_lease_subject_id_for_test(&connector_id, &zone_id);
    let expected_initial_holder =
        fcp_mesh::planner::select_lease_holder(&zone_id, &subject_id, &initial_eligible_node_ids)
            .expect("initial HRW holder should be selected");
    let seeded_state = seed_singleton_writer_connector_state_with_durable_lease(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        expected_initial_holder.clone(),
    )
    .await?;
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Failover",
        &state_root,
        &object_id_key,
    );
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let mut initial_holder: Option<(String, HttpHostProcess)> = None;
    let mut initial_refusals = Vec::new();
    replay.record(
        "initial_candidate_set",
        None,
        json!({
            "eligible_node_hashes": node_hash_values(&all_nodes),
            "durable_lease_seq": seeded_state.lease_seq,
        }),
    );

    for local_node in all_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", initial_eligible_nodes.as_str()),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "10"),
                (
                    "FCP_HOST_CAPABILITY_PUBLIC_KEY",
                    capability_public_key.as_str(),
                ),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    initial_holder.is_none(),
                    "initial HRW routing admitted more than one singleton_writer host launch"
                );
                initial_holder = Some((local_node.to_string(), host));
            }
            Err(error) => initial_refusals.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        initial_holder.is_some(),
        "initial HRW routing should admit one holder; refusals: {initial_refusals:?}"
    );
    assert_eq!(
        initial_refusals.len(),
        2,
        "initial three-node HRW routing should refuse both non-holders"
    );

    let (departed_node, departed_host) =
        initial_holder.expect("initial HRW routing should admit one holder");
    assert_eq!(
        departed_node,
        expected_initial_holder.as_str(),
        "real fcp-host launch should admit the same HRW holder as the durable lease fixture"
    );
    let departed_base_url = departed_host.base_url.clone();
    let lease_status: Value = http_get_json(
        departed_host.client.clone(),
        format!(
            "{}/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            departed_base_url,
            connector_id.as_str()
        ),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(
        lease_status["lease_evidence_source"],
        "canonical-fcp-store-lease-object"
    );
    assert_eq!(
        lease_status["lease_object_id"],
        seeded_state.lease_object_id.to_string()
    );
    assert_eq!(lease_status["fencing_token"], seeded_state.lease_seq);
    assert_eq!(lease_status["durable_lease_seq"], seeded_state.lease_seq);
    assert_eq!(
        lease_status["expiry_unix_secs"],
        seeded_state.lease_expiry_unix_secs
    );
    assert!(
        lease_status["expiry"]
            .as_str()
            .is_some_and(|expiry| expiry.ends_with('Z')),
        "real binary lease status should expose RFC3339 expiry: {lease_status}"
    );
    assert_eq!(lease_status["quorum_signers_count"], 2);
    assert_eq!(lease_status["required_quorum_signers_count"], 2);
    assert_eq!(lease_status["quorum_satisfied"], true);
    assert_eq!(lease_status["durable_validation"]["status"], "valid");
    assert!(
        lease_status["durable_validation"]["validated_at_unix_secs"]
            .as_u64()
            .is_some()
    );
    assert_eq!(lease_status["local_is_holder"], true);
    replay.record(
        "initial_holder_admitted",
        Some(&departed_node),
        json!({
            "expected_holder_hash": hash_node_label(expected_initial_holder.as_str()),
            "refusals": redacted_refusal_values(&initial_refusals),
            "lease_evidence_source": lease_status["lease_evidence_source"].clone(),
            "lease_object_id": lease_status["lease_object_id"].clone(),
            "fencing_token": lease_status["fencing_token"].clone(),
            "quorum_satisfied": lease_status["quorum_satisfied"].clone(),
        }),
    );

    let flush_response = departed_host
        .client
        .post(format!(
            "{}/rpc/admin/connectors/{}/lease/flush-before-yield?zone=z%3Awork",
            departed_base_url,
            connector_id.as_str()
        ))
        .bearer_auth(TEST_ADMIN_BEARER_TOKEN)
        .header("x-fcp-zone", "z:owner")
        .json(&json!({}))
        .send()
        .await?;
    let flush_status = flush_response.status();
    let flush_body = flush_response.text().await?;
    let flush_payload: Value = serde_json::from_str(&flush_body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "departing holder flush-before-yield response should be JSON, got {flush_status}: {flush_body}: {error}"
            ),
        )
    })?;
    assert_eq!(
        flush_status,
        reqwest::StatusCode::OK,
        "departing holder {departed_node} should flush canonical state before removal: {flush_payload}"
    );
    assert_eq!(
        flush_payload["flush"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(flush_payload["flush"]["lease_seq"], seeded_state.lease_seq);
    replay.record(
        "departing_holder_flushed_before_yield",
        Some(&departed_node),
        json!({
            "root_object_id": flush_payload["flush"]["root_object_id"].clone(),
            "lease_seq": flush_payload["flush"]["lease_seq"].clone(),
        }),
    );
    drop(departed_host);

    let remaining_nodes = all_nodes
        .into_iter()
        .filter(|node| *node != departed_node.as_str())
        .collect::<Vec<_>>();
    assert_eq!(remaining_nodes.len(), 2);
    let remaining_eligible_nodes = remaining_nodes.join(",");
    let mut new_holder: Option<(String, HttpHostProcess)> = None;
    let mut new_refusals = Vec::new();

    for local_node in &remaining_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", *local_node),
                (
                    "FCP_HOST_HRW_LEASE_NODES",
                    remaining_eligible_nodes.as_str(),
                ),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "11"),
                (
                    "FCP_HOST_CAPABILITY_PUBLIC_KEY",
                    capability_public_key.as_str(),
                ),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    new_holder.is_none(),
                    "post-departure HRW routing admitted more than one singleton_writer host launch"
                );
                new_holder = Some(((*local_node).to_string(), host));
            }
            Err(error) => new_refusals.push(((*local_node).to_string(), error.to_string())),
        }
    }

    assert!(
        new_holder.is_some(),
        "post-departure HRW routing should admit one replacement holder; refusals: {new_refusals:?}"
    );
    assert_eq!(
        new_refusals.len(),
        1,
        "two-node post-departure HRW routing should refuse one non-holder"
    );
    for (refused_node, refusal) in &new_refusals {
        assert!(
            refusal.contains("NotSelectedCoordinator"),
            "post-departure refusal for {refused_node} should preserve the typed HRW error: {refusal}"
        );
    }

    let (new_holder_node, new_host) =
        new_holder.expect("post-departure HRW routing should admit one replacement holder");
    assert_ne!(
        new_holder_node, departed_node,
        "replacement holder must come from the eligible set after removing the departed node"
    );
    replay.record(
        "replacement_holder_admitted",
        Some(&new_holder_node),
        json!({
            "departed_node_hash": hash_node_label(&departed_node),
            "remaining_node_hashes": node_hash_values(&remaining_nodes),
            "refusals": redacted_refusal_values(&new_refusals),
            "new_fencing_token": 11,
        }),
    );
    let url = |path: &str| format!("{}{path}", new_host.base_url);
    let mut stale_request = build_invoke_request(connector_id.clone(), &capability_signing_key).0;
    stale_request.input = json!({
        "message": "post-failover stale write must be fenced",
        "lease_seq": 10_u64,
    });
    stale_request.lease_seq = Some(10);
    let stale_response = new_host
        .client
        .post(url("/rpc/invoke"))
        .json(&stale_request)
        .send()
        .await?;
    let stale_status = stale_response.status();
    let stale_body = stale_response.text().await?;
    assert_eq!(stale_status, reqwest::StatusCode::FORBIDDEN);
    assert!(
        stale_body.contains(r#""code":"LeaseFenced""#),
        "replacement holder should fence stale pre-handoff writes: {stale_body}"
    );
    assert!(
        stale_body.contains(r#""current_lease_seq":11"#),
        "replacement holder should report the post-departure fence: {stale_body}"
    );
    replay.record(
        "stale_write_fenced_after_handoff",
        Some(&new_holder_node),
        json!({
            "http_status": stale_status.as_u16(),
            "provided_lease_seq": 10,
            "current_lease_seq": 11,
            "lease_fenced": stale_body.contains(r#""code":"LeaseFenced""#),
        }),
    );

    let explain_payload: Value = http_get_json(
        new_host.client.clone(),
        url(&format!(
            "/rpc/admin/connectors/{}/state/explain?zone=z%3Awork",
            connector_id.as_str()
        )),
    )
    .await?;
    assert_eq!(
        explain_payload["canonical_state"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(
        explain_payload["canonical_state"]["head_object_id"],
        seeded_state.head_object_id.to_string()
    );
    assert_eq!(
        explain_payload["canonical_state"]["model"],
        "singleton_writer"
    );
    replay.record(
        "canonical_state_exposed_after_handoff",
        Some(&new_holder_node),
        json!({
            "root_object_id": explain_payload["canonical_state"]["root_object_id"].clone(),
            "head_object_id": explain_payload["canonical_state"]["head_object_id"].clone(),
            "model": explain_payload["canonical_state"]["model"].clone(),
        }),
    );
    let replay_path = replay.write_jsonl(replay_dir.path())?;
    let rendered_replay = fs::read_to_string(replay_path)?;
    assert_no_raw_node_labels(&rendered_replay);
    assert!(
        rendered_replay.contains("canonical_state_exposed_after_handoff"),
        "host failover replay should include the post-handoff canonical-state proof: {rendered_replay}"
    );
    assert_eq!(
        rendered_replay.lines().count(),
        6,
        "host failover replay should include the candidate set plus five handoff phases"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn current_holder_fences_stale_singleton_writer_invoke_before_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-fence:utility:1.0.0");
    let connector_config = lease_e2e_support::singleton_writer_test_connector_config(
        &connector_id,
        "HRW Binary Fence",
    );
    let capability_signing_key = Ed25519SigningKey::generate();
    let capability_public_key = capability_public_key_hex(&capability_signing_key);
    let eligible_nodes = "node-a,node-b,node-c";
    let current_lease_seq = "11";
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in ["node-a", "node-b", "node-c"] {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", current_lease_seq),
                (
                    "FCP_HOST_CAPABILITY_PUBLIC_KEY",
                    capability_public_key.as_str(),
                ),
            ],
        )
        .await
        {
            Ok(host) => {
                assert!(
                    admitted_host.is_none(),
                    "HRW admitted more than one singleton_writer host launch"
                );
                admitted_host = Some((local_node.to_string(), host));
            }
            Err(error) => refusal_messages.push((local_node.to_string(), error.to_string())),
        }
    }

    assert!(
        admitted_host.is_some(),
        "HRW should admit exactly one singleton_writer host launch; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        2,
        "three-node HRW routing should refuse both non-holder launches"
    );
    for (refused_node, refusal) in &refusal_messages {
        assert!(
            refusal.contains("NotSelectedCoordinator"),
            "refusal for {refused_node} should preserve the typed HRW error: {refusal}"
        );
    }

    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    let url = |path: &str| format!("{}{path}", host.base_url);
    let mut stale_request = build_invoke_request(connector_id.clone(), &capability_signing_key).0;
    stale_request.input = json!({
        "message": "stale write must be fenced before dispatch",
        "lease_seq": 10_u64,
    });
    stale_request.lease_seq = Some(10);

    let stale_response = host
        .client
        .post(url("/rpc/invoke"))
        .json(&stale_request)
        .send()
        .await?;
    let stale_status = stale_response.status();
    let stale_body = stale_response.text().await?;
    assert_eq!(stale_status, reqwest::StatusCode::FORBIDDEN);
    assert!(
        stale_body.contains(r#""code":"LeaseFenced""#),
        "stale invoke should be fenced with typed HRW evidence: {stale_body}"
    );
    assert!(
        stale_body.contains(r#""current_lease_seq":11"#),
        "stale invoke should report the current fence: {stale_body}"
    );
    assert!(
        stale_body.contains(r#""provided_lease_seq":10"#),
        "stale invoke should report the provided stale fence: {stale_body}"
    );
    assert!(
        !stale_body.contains("stale write must be fenced before dispatch"),
        "stale invoke body should not include connector echo output: {stale_body}"
    );

    let mut current_request = build_invoke_request(connector_id.clone(), &capability_signing_key).0;
    current_request.input = json!({
        "message": "current fence may dispatch",
        "lease_seq": 11_u64,
    });
    current_request.lease_seq = Some(11);
    let current_response: InvokeResponse =
        http_post_json(host.client.clone(), url("/rpc/invoke"), current_request).await?;
    assert_eq!(current_response.status, InvokeStatus::Ok);
    assert_eq!(
        current_response
            .result
            .as_ref()
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("current fence may dispatch")
    );

    let lease_status: Value = http_get_json(
        host.client.clone(),
        url(&format!(
            "/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            connector_id.as_str()
        )),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(lease_status["local_is_holder"], true);
    assert_eq!(lease_status["fencing_token"], 11);
    assert_eq!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        3
    );
    assert!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .iter()
            .any(|holder| holder["is_local_node"].as_bool() == Some(true)),
        "admitted HRW host {admitted_node} should appear in the holder ladder"
    );

    Ok(())
}
