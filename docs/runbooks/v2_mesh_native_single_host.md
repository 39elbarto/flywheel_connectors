# V2 Mesh-Native Single-Host Runbook

Use this runbook when fcp-host is configured for V2 mesh-native truth precedence
but the host sees too few healthy mesh peers.

## Recommended Production Setting

After mesh cutover gates are green and the operator has confirmed peer setup,
use:

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v2
FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR=refuse-boot
FCP_V2_MIN_HEALTHY_MESH_PEERS=1
```

With zero healthy peers, fcp-host emits
`fcp.host.boot_refused_truth_precedence` and exits with code 78.

## First-Install Safe Default

Unset `FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR` defaults to `degrade-to-v1`.

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v2
```

With zero healthy peers, fcp-host runs effective V1 and emits
`fcp.host.boot_truth_precedence` with
`degraded_from="v2-insufficient-peers"`.

## Intentional Single-Host V2

Use only for test or explicitly accepted single-host V2 deployments:

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v2
FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR=explicit-opt-in
```

If `FCP_TRUTH_PRECEDENCE_DEFAULT=v2` is missing, fcp-host exits with code 78.

## Rollback

Run V1 host-first:

```bash
FCP_TRUTH_PRECEDENCE_DEFAULT=v1
unset FCP_V2_DEFAULT_GRADUATED
```

If your supervisor manages environment files, apply the same two changes there
and restart through the supervisor's normal non-destructive service path.

## Recovery

For `refuse-boot` with zero peers:

1. Check mesh peer health and heartbeat freshness.
2. Verify peer gossip signatures resolve to known `NodeKeyAttestation` records.
3. Confirm `FCP_V2_MIN_HEALTHY_MESH_PEERS` is not set above the intended peer
   count.
4. Restart fcp-host through the normal service path after peer health recovers.

For `degrade-to-v1`, monitor for
`fcp.host.boot_truth_precedence` events with
`degraded_from="v2-insufficient-peers"` and switch to `refuse-boot` once mesh
setup is confirmed.

## Common Failures

`FCP_V2_INSUFFICIENT_PEERS_BEHAVIOR=refus-boot`

Cause: typo. Fix the value to `refuse-boot`. fcp-host exits with code 78.

`FCP_V2_MIN_HEALTHY_MESH_PEERS=0`

Cause: invalid threshold. Use an integer `>= 1`.

`FCP_V2_DEFAULT_GRADUATED=true` plus zero peers and `refuse-boot`

Cause: the graduated flag has highest precedence and requests V2. Either restore
mesh health or unset `FCP_V2_DEFAULT_GRADUATED`.

## Redacted Log Examples

```json
{"event_type":"fcp.host.boot_truth_precedence","bead_id":"flywheel_connectors-hr0rr.2.6","actor":"host","redaction_scope":"public","correlation_id":"boot","precedence_default":"v2_requested","effective_model":"V1-host-first","behavior_chosen":"degrade-to-v1","mesh_peer_count":0,"min_healthy_peers":1,"degraded_from":"v2-insufficient-peers"}
```

```json
{"event_type":"fcp.host.boot_refused_truth_precedence","bead_id":"flywheel_connectors-hr0rr.2.6","actor":"host","redaction_scope":"public","correlation_id":"boot","precedence_default":"v2_requested","behavior_chosen":"refuse-boot","mesh_peer_count":0,"min_healthy_peers":1,"exit_code":78}
```
