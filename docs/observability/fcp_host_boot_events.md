# fcp-host Boot Events

fcp-host emits structured boot events for V2 mesh-native truth-precedence
selection. The events are redaction-safe and include these common fields:

- `event_type`
- `bead_id`
- `actor`
- `redaction_scope`
- `correlation_id`
- `timestamp`

## `fcp.host.boot_truth_precedence`

Emitted when boot selection succeeds. Important fields:

- `precedence_default`: `v1_requested` or `v2_requested`
- `requested_model`
- `effective_model`
- `behavior_chosen`
- `mesh_peer_count`
- `min_healthy_peers`
- `insufficient_peers`
- `explicit_v2_requested`
- `graduated_v2_default`
- `degraded_from`

Example:

```json
{
  "event_type": "fcp.host.boot_truth_precedence",
  "bead_id": "flywheel_connectors-hr0rr.2.6",
  "actor": "host",
  "redaction_scope": "public",
  "correlation_id": "boot",
  "precedence_default": "v2_requested",
  "requested_model": "V2-mesh-native",
  "effective_model": "V1-host-first",
  "behavior_chosen": "degrade-to-v1",
  "mesh_peer_count": 0,
  "min_healthy_peers": 1,
  "insufficient_peers": true,
  "degraded_from": "v2-insufficient-peers"
}
```

## `fcp.host.boot_refused_truth_precedence`

Emitted when fcp-host exits with code 78 due to invalid boot configuration or a
selected `refuse-boot` policy. Important fields:

- `exit_code`
- `env_var`, `env_value`, and `expected` for parse failures
- `behavior_chosen`, `mesh_peer_count`, and `min_healthy_peers` for peer-count
  refusals

No credential, token, principal, or payload bytes are included in either event.
