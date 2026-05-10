# Connector State Externalization Runbook

> Bead: `flywheel_connectors-hr0rr.2.2`

Use this runbook when operating or debugging mesh-native connector state after
local connector state files have become cache-only data and canonical state is
stored through `fcp-store`.

## Runtime Contract

Canonical connector state is a `ConnectorStateRoot` chain in `fcp-store`.
The host may keep local files under the connector state root, but any directory
containing `.fcp-cache-only` is an operator-visible cache and is not the source
of truth.

The expected local cache layout is:

```text
<state-root>/<connector-id>/cache/.fcp-cache-only
<state-root>/<connector-id>/cache/<zone>/.fcp-cache-only
```

Use `fwc connector state explain --connector <id> --json` before treating any
state file as authoritative. The command reports `schema_version: "1.0.0"`,
`canonical_storage`, cache marker evidence, and any live-host downgrade or
offline-inspection warnings.

## Rollback

Rollback is an operational routing choice, not a data deletion operation.

1. Keep `FCP_TRUTH_PRECEDENCE_DEFAULT=v1` or unset the variable so the host uses
   the host-first path.
2. Run:

   ```bash
   fwc connector state explain --connector <id> --json
   ```

3. Confirm `canonical_storage` is `local` or `both` before relying on local
   files for incident recovery.
4. Do not remove mesh objects, cache directories, or `.fcp-cache-only` markers
   during rollback. They are evidence and recovery inputs.

If rollback is needed because a mesh write path is unhealthy, leave the
`fcp-store` object chain intact and switch reads to the host-first cache path
until canonical mesh reads are healthy again.

## Recovery

1. Capture current state:

   ```bash
   fwc connector state explain --connector <id> --json
   ```

   Preserve `schema_version`, `canonical_storage`, `local_cache_present`,
   `local_cache_path`, `local_cache_marker_present`, `cache_marker.present`,
   `last_canonical_seq`, and any `warnings`.

2. If `canonical_storage` is `mesh`, inspect the latest root and snapshot with
   the host or fcp-store diagnostic surface that owns the deployment. The
   recovered head sequence must be at least the last committed sequence that the
   connector acknowledged.

3. If `canonical_storage` is `local`, treat the local path as host-first
   canonical only until the host writes cache markers and proves fcp-store
   replication. Do not edit the file while a connector process is running.

4. If both cache and mesh are unavailable, fail closed. The caller should see a
   typed `ConnectorStateError::StorageUnavailable` or host-level
   connector-state unavailable error rather than stale state.

5. After recovery, run the explain command again and compare
   `last_canonical_seq` and cache marker evidence against the incident snapshot.

## Common Failures

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `canonical_storage = "local"` with no `.fcp-cache-only` marker. | The host has not migrated this connector's state directory to cache-only semantics. | Keep using the host-first path and do not claim mesh-native state recovery for this connector yet. |
| `local_cache_marker_present = false` or `zone.local_cache_marker_present = false` but the path is under `<connector-id>/cache`. | Host cache directory creation was interrupted or the operator inspected a manually created path. | Re-run the host startup path that prepares connector state directories; do not hand-create authority markers in production. |
| `ConnectorStateError::StorageUnavailable`. | The fcp-store object layer is unreachable, missing the referenced object, or failed a storage operation. | Keep local cache reads read-only, restore object-store availability, then re-run `fwc connector state explain --connector <id> --json`. |
| `ConnectorStateError::MalformedState`. | A stored object has invalid canonical CBOR, mismatched connector or zone identity, invalid prev-pointer, or a body/header content-id mismatch. | Quarantine the bad object through the object-store recovery process and restore from the latest valid `ConnectorStateSnapshot`. |
| `ConnectorStateError::SnapshotUnavailable`. | The root references a missing head, no state head exists, or a newly emitted snapshot cannot be reloaded. | Stop compaction, inspect root refs, and restore the latest valid snapshot before resuming writes. |
| `ConnectorStateError::SubscribeUnavailable`. | The change stream lagged or the publisher closed, so a host cache may not have observed all updates. | Drop the local cache view and force the next read through canonical fcp-store before accepting connector output. |

## Verification

For a focused runbook-facing check after changing this surface:

```bash
rch exec -- cargo fmt -p fwc -p fcp-store -- --check
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-connector-state-runbook-rch CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p fwc connector_state_explain --bin fwc -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-connector-state-runbook-rch CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p fcp-store connector_state --lib -- --nocapture
```

When host cache invalidation changes, add the host E2E lane required by the bead:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-connector-state-host-e2e-rch CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p fcp-host connector_state --tests -- --nocapture
```

Use `git diff --check -- docs/runbooks/connector_state_externalization.md` for
the documentation-only slice.

## Redacted Log Examples

```json
{"event_type":"fcp.connector_state.read","bead_id":"flywheel_connectors-hr0rr.2.2","actor":"host","redaction_scope":"public","correlation_id":"state-read-20260510T130000Z","timestamp":"2026-05-10T13:00:00.000Z","connector_id":"github","zone_id":"z:work","operation":"read","result":"hit","latency_seconds":0.0008,"metric_name":"fcp_connector_state_latency_seconds"}
```

```json
{"event_type":"fcp.connector_state.fall_through","bead_id":"flywheel_connectors-hr0rr.2.2","actor":"host","redaction_scope":"public","correlation_id":"state-read-20260510T130001Z","timestamp":"2026-05-10T13:00:01.000Z","connector_id":"github","zone_id":"z:work","local_cache_marker_present":true,"cache_result":"miss","canonical_storage":"mesh","result":"fcp-store-read","metric_name":"fcp_connector_state_fall_through_total"}
```

```json
{"event_type":"fcp.connector_state.snapshot","bead_id":"flywheel_connectors-hr0rr.2.2","actor":"host","redaction_scope":"public","correlation_id":"state-snapshot-20260510T130002Z","timestamp":"2026-05-10T13:00:02.000Z","connector_id":"github","zone_id":"z:work","operation":"snapshot","result":"emitted","covers_seq":1000,"snapshot_reason":"entry-threshold","metric_name":"fcp_connector_state_latency_seconds"}
```

Do not log state CBOR, capability tokens, connector credentials, raw local file
contents, principal private data, or provider response bodies. When an
identifier would expose sensitive data, log a SHA-256 value with a `_hash`
suffix instead.
