# Mesh Cutover Gates Runbook

> Bead: `flywheel_connectors-hr0rr.2.1`

Use this runbook when `fwc mesh cutover-gates --json` reports non-green gates or
when changing the cutover-gate configuration.

## Rollback

Rollback is a status-label operation, not a destructive data operation:

```bash
fwc mesh cutover-gates --json
```

If any gate is `red` or `skip`, keep the README Mesh-Native Architecture row at
`STEADY-STATE TARGET (NOT YET OPERATIONAL)` and keep production routing on the
host-backed path. Do not flip `fwc invoke` or operator docs to mesh-backed
default until every gate is green from live telemetry.

## Recovery

1. Run `fwc --host <endpoint> mesh cutover-gates --json` and record
   `overall_status`, `data_hash`, `live_telemetry`, `red_gate_ids`, and each
   gate's `measured_value`.
2. Confirm `live_telemetry.reason_code` is
   `direct-cutover-telemetry-available`. If it is
   `direct-cutover-telemetry-unavailable`, the host has no
   `GET /rpc/mesh/cutover-gates` route yet. If it is
   `direct-cutover-telemetry-invalid`, the route exists but did not return the
   four stable gate records.
3. For `mesh-inventory-placement`, run
   `fwc mesh explain-availability <connector> --host <endpoint> --json` for the
   candidate connectors and confirm `placement.has_mesh_replica` plus
   `placement.replica_count` are exposed.
4. For `mesh-lifecycle-state-replication`, inspect the future
   `fwc mesh state status --json` route and confirm `ConnectorStateRoot`
   replica count and sequence age are current.
5. For `mesh-audit-chain-quorum`, inspect
   `fwc audit chain status --json` and confirm quorum signer and checkpoint
   counts.
6. For `mesh-policy-object-distribution`, inspect
   `fwc policy distribution --json` and confirm peer distribution plus owner
   signature verification.

## Common Failures

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| All gates report `skip`. | Live mesh/audit/policy telemetry routes are unavailable to `fwc`. | Wire the missing host routes before using cutover status as a graduation signal. |
| `live_telemetry.state = "unavailable"`. | The host-admin probe failed during evaluation, commonly because the host was down, restarting, or unreachable. | Re-run after host recovery and compare `data_hash`; the same snapshot after restart must keep the same digest. |
| `live_telemetry.reason_code = "direct-cutover-telemetry-invalid"`. | The host returned a direct cutover-gates snapshot that did not contain exactly the four stable gate records. | Fix the `GET /rpc/mesh/cutover-gates` response before treating any gate as green. |
| One gate reports `red`. | The route exists, but the measured value misses its target. | Fix the underlying replication, quorum, or distribution issue; do not lower the target unless the zone SLO explicitly allows it. |
| JSON schema validation fails. | The CLI output changed without a matching schema bump. | Update `crates/fwc/schemas/mesh_cutover_gates.schema.json` and the conformance test in the same change. |

## Redacted Log Examples

```json
{"event_type":"fcp.cutover_gate.evaluated","bead_id":"flywheel_connectors-hr0rr.2.1","actor":"fwc","redaction_scope":"public","correlation_id":"cutover-20260510T000000Z","timestamp":"2026-05-10T00:00:00.000Z","gate_id":"mesh-inventory-placement","status":"skip","measured_value":{"telemetry_state":"unavailable","skip_reason":"host-admin-api-unreachable","live_telemetry":{"source":"host-admin-api","state":"unavailable","reason_code":"host-admin-api-unreachable","direct_gate_telemetry_available":false,"catalog_connector_count":null}},"target":{"connectors_meeting_predicate":3,"placement.replica_count":2},"evaluated_in_ms":3,"metric_name":"fcp_cutover_gate_status","metric_type":"gauge","metric_label_gate_id":"mesh-inventory-placement","metric_value":1}
{"event_type":"fcp.cutover_gate.evaluated","bead_id":"flywheel_connectors-hr0rr.2.1","actor":"fwc","redaction_scope":"public","correlation_id":"cutover-20260510T000001Z","timestamp":"2026-05-10T00:00:01.000Z","gate_id":"mesh-audit-chain-quorum","status":"red","measured_value":{"quorum_signed_checkpoints":0,"quorum_signers":1},"target":{"quorum_signed_checkpoints":1,"quorum_signers":2},"evaluated_in_ms":4,"metric_name":"fcp_cutover_gate_status","metric_type":"gauge","metric_label_gate_id":"mesh-audit-chain-quorum","metric_value":0}
```

The log payload must not contain node private keys, connector credentials,
principal tokens, or raw endpoint secrets. Hash sensitive identifiers with a
`_hash` suffix before logging.
