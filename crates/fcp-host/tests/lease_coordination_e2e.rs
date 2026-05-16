#[path = "lease_e2e_support/mod.rs"]
mod lease_e2e_support;

use fcp_core::ZoneId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_kernel::ConnectorId;
use lease_e2e_support::{
    HttpHostProcess, TestResult, assert_connector_discovered, assert_host_healthy, hrw_env,
    selected_holder, singleton_writer_connector_config, standard_nodes,
};
use serde_json::Value;

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn lease_coordination_e2e_admits_exactly_one_singleton_writer_host() -> TestResult<()> {
    let connector_id = ConnectorId::from_static("fcp.test.lease-coordination-e2e:utility:1.0.0");
    let zone_id = ZoneId::work();
    let nodes = standard_nodes();
    let expected_holder = selected_holder(&connector_id, &zone_id, &nodes);
    let signing_key = Ed25519SigningKey::generate();
    let mut admitted = None;
    let mut refusals = Vec::new();

    for local_node in &nodes {
        let config = singleton_writer_connector_config(&connector_id, "Lease Coordination E2E");
        let env = hrw_env(&signing_key, local_node, &nodes, Some(41));
        match HttpHostProcess::spawn_with_env(vec![config], env).await {
            Ok(host) => {
                assert!(
                    admitted.is_none(),
                    "HRW admitted more than one singleton_writer host"
                );
                admitted = Some((local_node.clone(), host));
            }
            Err(error) => refusals.push((local_node.clone(), error.to_string())),
        }
    }

    assert_eq!(
        refusals.len(),
        nodes.len() - 1,
        "all non-holder hosts must refuse launch: {refusals:?}"
    );
    for (node, refusal) in &refusals {
        assert_ne!(
            node, &expected_holder,
            "selected holder must not refuse launch"
        );
        assert!(
            refusal.contains("NotSelectedCoordinator") && refusal.contains("wrong_holder"),
            "refusal for {} must preserve typed HRW denial, got: {refusal}",
            node.as_str()
        );
    }

    let (admitted_node, host) = admitted.expect("one HRW host should be admitted");
    assert_eq!(admitted_node, expected_holder);
    assert_host_healthy(&host).await?;
    assert_connector_discovered(&host, &connector_id).await?;

    let status: Value = host
        .get_json(&format!(
            "/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            connector_id.as_str()
        ))
        .await?;
    assert_eq!(status["schema_version"], "1.0.0");
    assert_eq!(status["source"], "host-hrw-routing");
    assert_eq!(status["local_is_holder"], true);
    assert_eq!(status["fencing_token"], 41);
    assert_eq!(
        status["ranked_holders"]
            .as_array()
            .expect("lease status should include ranked holders")
            .len(),
        nodes.len()
    );

    Ok(())
}
