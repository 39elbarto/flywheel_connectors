use fwc::mesh_cmd::{CutoverGateStatus, MeshCutoverGate, MeshCutoverGateArgs, mesh_cutover_gates};

fn cutover_gate(gate_id: &str) -> MeshCutoverGate {
    mesh_cutover_gates(&MeshCutoverGateArgs::default())
        .into_iter()
        .find(|gate| gate.gate_id == gate_id)
        .unwrap_or_else(|| panic!("missing cutover gate `{gate_id}`"))
}

#[test]
fn cutover_gate_mesh_inventory_placement_fails_red_without_live_replica_telemetry() {
    let gate = cutover_gate("mesh-inventory-placement");

    assert_eq!(gate.status, CutoverGateStatus::Red);
    assert_eq!(
        gate.measured_value["telemetry_state"].as_str(),
        Some("missing")
    );
    assert_eq!(
        gate.measured_value["connectors_meeting_predicate"].as_u64(),
        Some(0)
    );
    assert_eq!(
        gate.target["connectors_meeting_predicate"].as_u64(),
        Some(3)
    );
    assert_eq!(
        gate.target["placement.has_mesh_replica"].as_bool(),
        Some(true)
    );
    assert_eq!(gate.target["placement.replica_count"].as_u64(), Some(2));
    assert!(
        gate.predicate_text
            .contains("placement.has_mesh_replica=true")
    );
    assert!(
        gate.how_measured
            .iter()
            .any(|command| command.contains("fwc mesh explain-availability"))
    );
}
