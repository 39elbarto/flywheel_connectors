#[path = "lease_e2e_support/mod.rs"]
mod lease_e2e_support;

use fcp_core::{ObjectId, ObjectIdKey, ZoneId};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_kernel::ConnectorId;
use lease_e2e_support::{
    CONNECTOR_STATE_DIR_ENV, CONNECTOR_STATE_OBJECT_ID_KEY_ENV, HttpHostProcess, TestResult,
    hrw_env, seed_connector_state, selected_holder, singleton_writer_connector_config_with_env,
    standard_nodes,
};
use serde_json::Value;

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn lease_flush_on_yield_e2e_reports_canonical_state_barrier() -> TestResult<()> {
    let connector_id = ConnectorId::from_static("fcp.test.lease-flush-e2e:utility:1.0.0");
    let zone_id = ZoneId::work();
    let nodes = standard_nodes();
    let holder = selected_holder(&connector_id, &zone_id, &nodes);
    let signing_key = Ed25519SigningKey::generate();
    let object_id_key = ObjectIdKey::from_bytes([0xD3; 32]);
    let lease_object_id = ObjectId::from_bytes([0xA7; 32]);
    let seeded = seed_connector_state(
        &connector_id,
        &zone_id,
        object_id_key,
        lease_object_id,
        0,
        10,
    )
    .await?;
    let state_root_path = seeded.state_root.path().display().to_string();
    let object_key_hex = hex::encode(seeded.object_id_key.as_bytes());

    let config = singleton_writer_connector_config_with_env(
        &connector_id,
        "Lease Flush E2E",
        &[
            (CONNECTOR_STATE_DIR_ENV, state_root_path),
            (CONNECTOR_STATE_OBJECT_ID_KEY_ENV, object_key_hex),
        ],
    );
    let host = HttpHostProcess::spawn_with_env(
        vec![config],
        hrw_env(&signing_key, &holder, &nodes, Some(seeded.lease_seq)),
    )
    .await?;

    let flush: Value = host
        .post_json(
            &format!(
                "/rpc/admin/connectors/{}/lease/flush-before-yield?zone=z%3Awork",
                connector_id.as_str()
            ),
            serde_json::json!({}),
        )
        .await?;
    assert_eq!(flush["schema_version"], "1.0.0");
    assert_eq!(flush["source"], "host-canonical-state-flush");
    assert_eq!(flush["flush"]["root_present"], true);
    assert_eq!(
        flush["flush"]["root_object_id"],
        seeded.root_object_id.to_string()
    );
    assert_eq!(
        flush["flush"]["head_object_id"],
        seeded.head_object_id.to_string()
    );
    assert_eq!(flush["flush"]["last_canonical_seq"], 0);
    assert_eq!(flush["flush"]["lease_seq"], seeded.lease_seq);
    assert_eq!(
        flush["flush"]["lease_object_id"],
        seeded.lease_object_id.to_string()
    );
    assert_eq!(
        flush["telemetry"]["event_name"],
        "fcp.lease.flushed_on_yield"
    );

    let explain: Value = host
        .get_json(&format!(
            "/rpc/admin/connectors/{}/state/explain?zone=z%3Awork",
            connector_id.as_str()
        ))
        .await?;
    assert_eq!(explain["source"], "host-canonical-state");
    assert_eq!(
        explain["canonical_state"]["root_object_id"],
        seeded.root_object_id.to_string()
    );
    assert_eq!(
        explain["canonical_state"]["head_object_id"],
        seeded.head_object_id.to_string()
    );
    assert_eq!(explain["last_canonical_seq"], 0);

    Ok(())
}
