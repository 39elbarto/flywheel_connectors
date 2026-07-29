mod lease_e2e_support;

use fcp_core::{ObjectIdKey, TailscaleNodeId, ZoneId};
use fcp_host::DiscoveryResponse;
use fcp_kernel::ConnectorId;
use lease_e2e_support::{
    HttpHostProcess, host_e2e_lock, http_get_json, http_post_json,
    seed_singleton_writer_connector_state_with_durable_lease_signers,
    singleton_writer_connector_lease_subject_id_for_test, singleton_writer_test_connector_config,
    singleton_writer_test_connector_config_with_state,
};
use serde_json::{Value, json};

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn three_node_hrw_coordination_allows_exactly_one_singleton_writer_launch()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-launch:utility:1.0.0");
    let connector_config =
        singleton_writer_test_connector_config(&connector_id, "HRW Binary Launch");
    let eligible_nodes = "node-a,node-b,node-c";
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in ["node-a", "node-b", "node-c"] {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes),
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
            refusal.contains("HRW lease routing refused singleton_writer launch"),
            "refusal for {refused_node} should identify the HRW launch gate: {refusal}"
        );
        assert!(
            refusal.contains("NotSelectedCoordinator"),
            "refusal for {refused_node} should preserve the typed HRW error: {refusal}"
        );
        assert!(
            refusal.contains("wrong_holder"),
            "refusal for {refused_node} should report the wrong-holder transfer reason: {refusal}"
        );
        assert!(
            refusal.contains(refused_node),
            "refusal should name the refused local node {refused_node}: {refusal}"
        );
    }

    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    let url = |path: &str| format!("{}{path}", host.base_url);
    let discovery: DiscoveryResponse =
        http_post_json(host.client.clone(), url("/rpc/discover"), json!({})).await?;
    assert!(
        discovery
            .connectors
            .iter()
            .any(|connector| connector.id == connector_id),
        "admitted HRW host {admitted_node} should serve the singleton_writer connector"
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
    assert!(lease_status["holder_node_id_hash"].as_str().is_some());
    assert_eq!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        3
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn singleton_writer_launch_rejects_below_quorum_hrw_config()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let connector_id = ConnectorId::from_static("fcp.test.hrw-binary-quorum:utility:1.0.0");
    let connector_config =
        singleton_writer_test_connector_config(&connector_id, "HRW Binary Quorum");
    let launch_error = match HttpHostProcess::spawn_with_env(
        vec![connector_config],
        &[
            ("FCP_HOST_HRW_LEASE_LOCAL_NODE", "node-solo"),
            ("FCP_HOST_HRW_LEASE_NODES", "node-solo"),
            ("FCP_HOST_HRW_LEASE_CURRENT_SEQ", "1"),
        ],
    )
    .await
    {
        Ok(_) => {
            return Err(
                "singleton_writer launch must refuse HRW configs below lease quorum".into(),
            );
        }
        Err(error) => error,
    };
    let message = launch_error.to_string();
    let unescaped_message = message.replace('\\', "");

    assert!(
        message.contains("HRW lease routing refused singleton_writer launch"),
        "quorum refusal should identify the HRW launch gate: {message}"
    );
    assert!(
        unescaped_message.contains(r#""code":"LeaseQuorumConfigInvalid""#),
        "quorum refusal should preserve the typed HRW configuration error: {message}"
    );
    assert!(
        unescaped_message.contains(r#""configured_eligible_nodes_count":1"#),
        "quorum refusal should report the configured node count: {message}"
    );
    assert!(
        unescaped_message.contains(r#""required_quorum_signers_count":2"#),
        "quorum refusal should report the required signer count: {message}"
    );
    assert!(
        message.contains("FCP_HOST_HRW_LEASE_NODES"),
        "quorum refusal should point operators at the node-set env var: {message}"
    );

    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn lease_status_reports_invalid_below_quorum_durable_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let connector_id =
        ConnectorId::from_static("fcp.test.hrw-binary-invalid-lease-status:utility:1.0.0");
    let zone_id = ZoneId::work();
    let state_dir = tempfile::tempdir()?;
    let state_root = state_dir.path().join("managed-state");
    let object_id_key = ObjectIdKey::from_bytes([0xD7; 32]);
    let all_nodes = ["node-a", "node-b", "node-c"];
    let eligible_nodes = all_nodes.join(",");
    let eligible_node_ids = all_nodes
        .iter()
        .map(|node| TailscaleNodeId::new(*node))
        .collect::<Vec<_>>();
    let subject_id = singleton_writer_connector_lease_subject_id_for_test(&connector_id, &zone_id);
    let expected_holder =
        fcp_mesh::planner::select_lease_holder(&zone_id, &subject_id, &eligible_node_ids)
            .expect("HRW holder should be selected");
    let seeded_state = seed_singleton_writer_connector_state_with_durable_lease_signers(
        &state_root,
        &connector_id,
        &zone_id,
        object_id_key,
        expected_holder.clone(),
        &["node-a"],
    )
    .await?;
    let connector_config = singleton_writer_test_connector_config_with_state(
        &connector_id,
        "HRW Binary Invalid Lease Status",
        &state_root,
        &object_id_key,
    );
    let mut admitted_host: Option<(String, HttpHostProcess)> = None;
    let mut refusal_messages = Vec::new();

    for local_node in all_nodes {
        match HttpHostProcess::spawn_with_env(
            vec![connector_config.clone()],
            &[
                ("FCP_HOST_HRW_LEASE_LOCAL_NODE", local_node),
                ("FCP_HOST_HRW_LEASE_NODES", eligible_nodes.as_str()),
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
        "HRW should admit one holder even when durable lease evidence is invalid; refusals: {refusal_messages:?}"
    );
    assert_eq!(
        refusal_messages.len(),
        2,
        "three-node HRW routing should refuse both non-holder launches"
    );
    let (admitted_node, host) = admitted_host.expect("one HRW host should be admitted");
    assert_eq!(
        admitted_node,
        expected_holder.as_str(),
        "real fcp-host launch should admit the HRW-selected holder"
    );

    let lease_status: Value = http_get_json(
        host.client.clone(),
        format!(
            "{}/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            host.base_url,
            connector_id.as_str()
        ),
    )
    .await?;
    assert_eq!(lease_status["source"], "host-hrw-routing");
    assert_eq!(lease_status["local_is_holder"], true);
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
    assert_eq!(lease_status["quorum_signers_count"], 1);
    assert_eq!(lease_status["required_quorum_signers_count"], 2);
    assert_eq!(lease_status["quorum_satisfied"], false);
    assert_eq!(lease_status["durable_validation"]["status"], "invalid");
    assert!(
        lease_status["durable_validation"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("insufficient quorum")),
        "below-quorum durable lease should expose validation error: {lease_status}"
    );
    assert!(
        lease_status["durable_validation"]["validated_at_unix_secs"]
            .as_u64()
            .is_some()
    );
    assert_eq!(
        lease_status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        3
    );
    let warnings = lease_status
        .get("warnings")
        .and_then(Value::as_array)
        .expect("lease status warnings should be an array");
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("below the required 2"))),
        "operator status should warn on below-quorum durable lease evidence: {lease_status}"
    );
    assert!(
        warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|warning| warning.contains("failed live lease validation"))),
        "operator status should retain the durable validation failure warning: {lease_status}"
    );

    Ok(())
}
