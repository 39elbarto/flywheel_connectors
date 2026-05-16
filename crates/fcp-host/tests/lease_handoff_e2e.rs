#[path = "lease_e2e_support/mod.rs"]
mod lease_e2e_support;

use fcp_core::ZoneId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_kernel::{ConnectorId, InvokeResponse, InvokeStatus};
use lease_e2e_support::{
    HttpHostProcess, TestResult, build_invoke_request, hrw_env, selected_holder,
    singleton_writer_connector_config, singleton_writer_subject_id, standard_nodes,
};
use serde_json::Value;

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn lease_handoff_e2e_fences_stale_old_holder_and_admits_reselected_holder() -> TestResult<()>
{
    let connector_id = ConnectorId::from_static("fcp.test.lease-handoff-e2e:utility:1.0.0");
    let zone_id = ZoneId::work();
    let full_nodes = standard_nodes();
    let old_holder = selected_holder(&connector_id, &zone_id, &full_nodes);
    let handoff_nodes = full_nodes
        .iter()
        .filter(|node| **node != old_holder)
        .cloned()
        .collect::<Vec<_>>();
    let new_holder = selected_holder(&connector_id, &zone_id, &handoff_nodes);
    assert_ne!(old_holder, new_holder);

    let subject_id = singleton_writer_subject_id(&connector_id, &zone_id);
    fcp_mesh::planner::admit_lease_holder(
        &zone_id,
        &subject_id,
        fcp_core::LeasePurpose::ConnectorStateWrite,
        &handoff_nodes,
        &new_holder,
    )
    .expect("new holder should be HRW-admitted after old holder leaves the online set");

    let signing_key = Ed25519SigningKey::generate();
    let old_host = HttpHostProcess::spawn_with_env(
        vec![singleton_writer_connector_config(
            &connector_id,
            "Lease Handoff Old Holder E2E",
        )],
        hrw_env(&signing_key, &old_holder, &full_nodes, Some(11)),
    )
    .await?;
    let stale_request =
        build_invoke_request(&connector_id, &signing_key, 10, "old holder stale write")?;
    let (status, body) = old_host
        .post_json_status_text("/rpc/invoke", stale_request)
        .await?;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    assert!(body.contains(r#""code":"LeaseFenced""#), "{body}");
    assert!(body.contains(r#""current_lease_seq":11"#), "{body}");
    assert!(body.contains(r#""provided_lease_seq":10"#), "{body}");

    let new_host = HttpHostProcess::spawn_with_env(
        vec![singleton_writer_connector_config(
            &connector_id,
            "Lease Handoff New Holder E2E",
        )],
        hrw_env(&signing_key, &new_holder, &handoff_nodes, Some(11)),
    )
    .await?;
    let status_payload: Value = new_host
        .get_json(&format!(
            "/rpc/admin/connectors/{}/lease/status?zone=z%3Awork",
            connector_id.as_str()
        ))
        .await?;
    assert_eq!(status_payload["local_is_holder"], true);
    assert_eq!(status_payload["fencing_token"], 11);
    assert_eq!(status_payload["ranked_holders"][0]["is_local_node"], true);

    let accepted_request =
        build_invoke_request(&connector_id, &signing_key, 11, "new holder accepted write")?;
    let accepted: InvokeResponse = new_host.post_json("/rpc/invoke", accepted_request).await?;
    assert_eq!(accepted.status, InvokeStatus::Ok);
    assert_eq!(
        accepted
            .result
            .as_ref()
            .and_then(|result| result.get("echo"))
            .and_then(|echo| echo.get("message"))
            .and_then(Value::as_str),
        Some("new holder accepted write")
    );

    Ok(())
}
