use fwc::mesh_cmd::{CutoverGateStatus, MeshCutoverGate, MeshCutoverGateArgs, mesh_cutover_gates};

fn cutover_gate(gate_id: &str) -> MeshCutoverGate {
    mesh_cutover_gates(&MeshCutoverGateArgs::default())
        .into_iter()
        .find(|gate| gate.gate_id == gate_id)
        .unwrap_or_else(|| panic!("missing cutover gate `{gate_id}`"))
}

#[test]
fn cutover_gate_mesh_lifecycle_state_replication_skips_without_state_root_telemetry() {
    let gate = cutover_gate("mesh-lifecycle-state-replication");

    assert_eq!(gate.status, CutoverGateStatus::Skip);
    assert_eq!(
        gate.measured_value["telemetry_state"].as_str(),
        Some("unavailable")
    );
    assert_eq!(
        gate.measured_value["connectors_meeting_predicate"].as_u64(),
        Some(0)
    );
    assert_eq!(
        gate.measured_value["missing_fields"][0].as_str(),
        Some("connector_state_root.replica_count")
    );
    assert_eq!(
        gate.target["connectors_meeting_predicate"].as_u64(),
        Some(3)
    );
    assert_eq!(gate.target["replica_count"].as_u64(), Some(2));
    assert_eq!(
        gate.target["last_replicated_age_seconds_lte"].as_u64(),
        Some(60)
    );
    assert!(gate.predicate_text.contains("ConnectorStateRoot"));
    assert!(
        gate.how_measured
            .iter()
            .any(|command| command.contains("fwc mesh cutover-gates --json"))
    );
}
