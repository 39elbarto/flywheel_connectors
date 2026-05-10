use fwc::mesh_cmd::{CutoverGateStatus, MeshCutoverGate, MeshCutoverGateArgs, mesh_cutover_gates};

fn cutover_gate(gate_id: &str) -> MeshCutoverGate {
    mesh_cutover_gates(&MeshCutoverGateArgs::default())
        .into_iter()
        .find(|gate| gate.gate_id == gate_id)
        .unwrap_or_else(|| panic!("missing cutover gate `{gate_id}`"))
}

#[test]
fn cutover_gate_mesh_audit_chain_quorum_skips_without_quorum_checkpoint_telemetry() {
    let gate = cutover_gate("mesh-audit-chain-quorum");

    assert_eq!(gate.status, CutoverGateStatus::Skip);
    assert_eq!(
        gate.measured_value["telemetry_state"].as_str(),
        Some("unavailable")
    );
    assert_eq!(
        gate.measured_value["quorum_signed_checkpoints"].as_u64(),
        Some(0)
    );
    assert_eq!(gate.measured_value["quorum_signers"].as_u64(), Some(0));
    assert_eq!(
        gate.measured_value["missing_route"].as_str(),
        Some("fwc audit chain status --json")
    );
    assert_eq!(gate.target["quorum_signed_checkpoints"].as_u64(), Some(1));
    assert_eq!(gate.target["quorum_signers"].as_u64(), Some(2));
    assert_eq!(gate.target["checkpoint_age_seconds_lte"].as_u64(), Some(60));
    assert!(gate.predicate_text.contains("quorum_signed_checkpoints"));
    assert!(
        gate.how_measured
            .iter()
            .any(|command| command == "fwc audit chain status --json")
    );
}
