mod lease_e2e_support;

use fcp_core::{ObjectId, ObjectIdKey, ZoneId};
use fcp_kernel::ConnectorId;
use lease_e2e_support::{
    HttpHostProcess, TEST_ADMIN_BEARER_TOKEN, host_e2e_lock, http_get_json,
    seed_singleton_writer_connector_state, singleton_writer_test_connector_config_with_state,
};
use serde_json::{Value, json};

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn leader_losing_majority_flushes_durable_state_before_yield()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-flush:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let object_id_key = ObjectIdKey::from_bytes([0xB5; 32]);
    let seeded_state = seed_singleton_writer_connector_state(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        ObjectId::from_bytes([0x92; 32]),
    )
    .await?;
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Flush",
        &state_root,
        &object_id_key,
    );
    let eligible_nodes = "node-a,node-b,node-c";
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in ["node-a", "node-b", "node-c"] {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes),
                ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "10"),
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
    let flush_response = host
        .client
        .post(url(&format!(
            "/rpc/admin/connectors/{}/lease/flush-before-yield?zone=z%3Awork",
            connector_id.as_str()
        )))
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
                "flush-before-yield response should be JSON, got {flush_status}: {flush_body}: {error}"
            ),
        )
    })?;

    assert_eq!(
        flush_status,
        reqwest::StatusCode::OK,
        "admitted HRW host {admitted_node} should expose live flush-before-yield payload: {flush_payload}"
    );
    assert_eq!(flush_payload["schema_version"], "1.0.0");
    assert_eq!(flush_payload["source"], "host-canonical-state-flush");
    assert_eq!(flush_payload["connector_id"], connector_id.to_string());
    assert_eq!(flush_payload["zone_id"], zone_id.as_str());
    assert_eq!(flush_payload["flush"]["root_present"], true);
    assert_eq!(
        flush_payload["flush"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(
        flush_payload["flush"]["head_object_id"],
        seeded_state.head_object_id.to_string()
    );
    assert_eq!(flush_payload["flush"]["last_canonical_seq"], 0);
    assert_eq!(flush_payload["flush"]["lease_seq"], seeded_state.lease_seq);
    assert_eq!(
        flush_payload["flush"]["lease_object_id"],
        seeded_state.lease_object_id.to_string()
    );
    assert_eq!(
        flush_payload["telemetry"]["event_name"],
        "fcp.lease.flushed_on_yield"
    );

    let explain_payload: Value = http_get_json(
        host.client.clone(),
        url(&format!(
            "/rpc/admin/connectors/{}/state/explain?zone=z%3Awork",
            connector_id.as_str()
        )),
    )
    .await?;
    assert_eq!(
        explain_payload["source"], "host-canonical-state",
        "admitted HRW host {admitted_node} should expose canonical state after flush: {explain_payload}"
    );
    assert_eq!(explain_payload["canonical_state"]["root_present"], true);
    assert_eq!(
        explain_payload["canonical_state"]["root_object_id"],
        seeded_state.root_object_id.to_string()
    );
    assert_eq!(
        explain_payload["canonical_state"]["head_object_id"],
        seeded_state.head_object_id.to_string()
    );
    assert_eq!(explain_payload["last_canonical_seq"], 0);
    assert_eq!(
        explain_payload["canonical_state"]["model"],
        "singleton_writer"
    );

    Ok(())
}
