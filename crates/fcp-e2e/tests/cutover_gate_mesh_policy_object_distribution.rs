use fwc::mesh_cmd::{CutoverGateStatus, MeshCutoverGate, MeshCutoverGateArgs, mesh_cutover_gates};

fn cutover_gate(gate_id: &str) -> MeshCutoverGate {
    mesh_cutover_gates(&MeshCutoverGateArgs::default())
        .into_iter()
        .find(|gate| gate.gate_id == gate_id)
        .unwrap_or_else(|| panic!("missing cutover gate `{gate_id}`"))
}

#[test]
fn cutover_gate_mesh_policy_object_distribution_skips_without_policy_peer_telemetry() {
    let gate = cutover_gate("mesh-policy-object-distribution");

    assert_eq!(gate.status, CutoverGateStatus::Skip);
    assert_eq!(
        gate.measured_value["telemetry_state"].as_str(),
        Some("unavailable")
    );
    assert_eq!(gate.measured_value["peer_count"].as_u64(), Some(0));
    assert_eq!(
        gate.measured_value["verified_owner_signatures"].as_bool(),
        Some(false)
    );
    assert_eq!(
        gate.measured_value["missing_route"].as_str(),
        Some("fwc policy distribution --json")
    );
    assert_eq!(gate.target["peer_count"].as_u64(), Some(2));
    assert_eq!(
        gate.target["verified_owner_signatures"].as_bool(),
        Some(true)
    );
    assert!(gate.predicate_text.contains("verified owner signatures"));
    assert!(
        gate.how_measured
            .iter()
            .any(|command| command == "fwc policy distribution --json")
    );
}
