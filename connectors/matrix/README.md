# Matrix Connector V3 Readiness Notes

> **Status**: readiness and observability slice in progress
> **Bead**: `flywheel_connectors-j05nu.1.8.5`
> **Connector**: `fcp.matrix`

## Purpose

`fcp.matrix` is the Flywheel Connector Protocol connector for the Matrix Client-Server API. The current crate is a bidirectional room, media, and sync connector for one configured homeserver account at a time.

It supports room creation and membership mutations, message send, timeline and room-state reads, explicit sync polling, an optional supervised sync worker, member listing, and media upload/download. It is not a homeserver admin SDK or a durable bridge.

## Current Runtime Truth

- One connector instance binds to one configured `homeserver_url` and one auth mode.
- Auth is either:
  - direct `access_token`
  - `credential_id`, where the host or egress proxy injects the bearer token at runtime
- The connector maintains an in-memory sync cursor and tracked room summaries by default. Durable resume is host-managed: persist the redaction-safe `tracked_state` returned by `matrix.sync` outside the connector and pass it back through `state_persistence` on the next configure.
- Manual `matrix.sync` remains the fallback path. Operators may call it explicitly to advance the cursor, inspect deltas, and drive event delivery.
- `supervised_sync.enabled` is disabled by default. When enabled, a validated FCP `subscribe` call starts a bounded background sync worker that shares the same in-memory cursor, inbound-policy projection, event fanout, retry/backoff budget, and shutdown path as manual sync.
- FCP `subscribe` is supported for manual and supervised fanout. Matching policy-projected deltas are emitted as `EventEnvelope` items on `matrix.message.authorized`, `matrix.event.dropped`, `matrix.reaction`, and `matrix.encrypted`.
- Event fanout is de-duplicated by Matrix event identity at the connector boundary so repeated sync responses do not re-emit the same event.
- `matrix.sync` preserves raw room deltas and also returns the same inbound-policy projection: authorized messages, dropped-event metadata, reaction events, and encrypted-event metadata.
- Authorized message projections now carry workflow context: mention presence, stripped delivery body, free-response/direct-message/thread reasons, dynamic DM detection, and bounded media metadata. Raw Matrix body and media bytes are not required for routing decisions.
- Reaction projections are sender-policy gated and include approval classification based on configured approval reaction keys. Unauthorized reaction approvals are dropped before agent delivery.
- Reconfiguring the connector resets the in-memory cursor, dynamic DM classifications, participated thread roots, and emitted-event dedupe set unless `state_persistence.enabled=true` restores a host-managed snapshot scoped to zone/account/device metadata.
- Encrypted Matrix timeline events fail closed by default for agent delivery until verified E2EE/device verification is implemented. Operators may choose metadata-only projection, but ciphertext is not emitted.
- `e2ee.verified_decryption_requested=true` is accepted as an explicit readiness request, but it is denied at health/self_check time until an audited Rust Matrix crypto path verifies account identity, stable device ID, device trust, cross-signing, room-key backup, recovery state, and redaction rules. This keeps setup intent visible without silently downgrading to unsafe decrypted or ciphertext delivery.
- Secret material stays in memory. Diagnostics should use room IDs, event IDs, status codes, and retry metadata rather than raw tokens or media bytes.

## Operation Inventory

The current connector exposes:

- `matrix.joined_rooms`
- `matrix.create_room`
- `matrix.join_room`
- `matrix.leave_room`
- `matrix.send_message`
- `matrix.get_messages`
- `matrix.sync`
- `matrix.get_room_state`
- `matrix.list_members`
- `matrix.upload_media`
- `matrix.download_media`

## Readiness Model

`doctor()` now reports:

- configuration, client, and runtime initialization
- homeserver transport policy
- auth mode and whether credential injection is still required
- state-persistence mode, host-managed restore counts, scoped identifier hashes, and the explicit no-connector-local-disk-write posture
- sync delivery model guidance
- supervised sync configuration and worker status when enabled
- E2EE readiness state, including verified-decryption availability, account/device ID shape checks, secretless device-key import status, device-list freshness, own-device verification, cross-signing readiness, recovery and room-key backup status, outgoing crypto maintenance driver state, undecrypted retry/final-failure classification, recovery guidance, and structured skip reasons for crypto-only cases
- sync telemetry including success/failure counts, last duration, last error, and the last tracked token
- inbound-policy telemetry for the most recent sync projection, including authorized, dropped, reaction, encrypted, and emitted event counts
- event stream state, including buffer capacity and currently subscribed topics

`health()` is intentionally truthful:

- `ready` only when the connector is configured, runtime-initialized, using an acceptable homeserver transport, and not waiting on secret injection
- `degraded` when the connector is unconfigured, incomplete, using a non-loopback plain HTTP homeserver, or in `credential_id` mode awaiting injected auth

`self_check()` proves live readiness only for direct bearer-token mode. In `credential_id` mode it returns a degraded report until the host injects the bearer token.

## Transport And Verification Guidance

- Prefer `https://` homeservers for live traffic.
- `http://localhost`, `http://127.0.0.1`, and `http://[::1]` are acceptable for deterministic verification harnesses.
- Use a non-production account and disposable rooms when verifying room creation, joins, leaves, sends, and media mutations.
- Configure `inbound_policy.allowed_users`, `bot_user_id`, `require_mention`, `free_response_rooms`, `direct_message_rooms`, `thread_participation_roots`, and `process_reactions` before treating `matrix.sync` policy projections as agent-delivery input. Direct-message rooms and participated Matrix thread roots bypass mention gating only after sender allowlist checks pass.
- For richer workflow routing, configure `dynamic_direct_message_detection=true` with `bot_user_id` and `direct_message_member_limit` to derive small DM rooms from membership state, `strip_bot_mentions=true` to expose a clean `delivery_body`, `approval_reaction_keys` to classify approval reactions, and `media_max_bytes` to fail closed on oversized inbound media while still logging redacted metadata.
- To preserve sync resume state across connector restarts, configure `state_persistence.enabled=true`, `backend="host_managed_snapshot"`, a non-secret `zone_id`, `account_user_id`, `device_id`, and a `restore` snapshot containing the prior `last_sync_token`, dynamic DM rooms, and participated thread roots. The connector validates scope consistency with E2EE account/device hints, restores those values into memory at configure time, and redacts account/device/sync-token values from doctor state-persistence diagnostics.
- Subscribe to the Matrix event topics before calling `matrix.sync` if the host needs streaming delivery. `persist=false` returns a preview only and does not emit events.
- To use supervised sync, set `supervised_sync.enabled=true` and configure `poll_interval_ms`, `timeout_ms`, and `supervisor` retry/shutdown limits. The worker starts only after subscription succeeds with a valid `matrix.read` capability token.
- To request future verified E2EE delivery, set `e2ee.verified_decryption_requested=true` with `account_user_id`, `device_id`, `trust_state.own_device`, `trust_state.device_keys`, `trust_state.device_list`, `trust_state.cross_signing`, tracked user/room scope, recovery status, room-key backup status, and undecrypted retry policy. Current builds expose a secretless `matrix-sdk-crypto` adapter boundary in doctor/health output, report `e2ee_verified_decryption_unavailable`, and keep encrypted events fail-closed or metadata-only until the later decrypt projection bead lands. The optional `matrix-sdk-crypto-backend` feature compiles the pinned Rust-1.85-compatible `matrix-sdk-crypto` dependency, but this slice still refuses decrypted delivery.
- E2EE outgoing maintenance is now modeled explicitly without storing secrets: `MatrixClient` has dedicated transport methods for `/keys/upload`, `/keys/query`, `/keys/claim`, `/sendToDevice`, `/room_keys/version`, room-key upload, and stale room-key delete. The crypto boundary records mark-sent semantics, retry-budget transitions, non-retryable auth failure, backup-version mismatch denial, stale-key reupload/delete decisions, and key-share-after-initial-sync gating as redaction-safe JSON.
- Use the no-mock loopback harness for detailed JSONL evidence of initial sync, incremental sync, duplicate suppression, policy drops, reaction/encrypted metadata, rate-limit retry, auth-stop, cursor state, and shutdown:

```bash
rch exec -- cargo test -p fcp-matrix --test supervised_sync_loopback_e2e -- --nocapture
```

- Use the workflow policy loopback harness for JSONL evidence of dynamic DM classification, participated-thread follow-up, mention stripping, approval reaction allow/deny, media bounds, read receipt/redaction non-delivery, tracked policy context, and shutdown:

```bash
rch exec -- cargo test -p fcp-matrix --test workflow_policy_loopback_e2e -- --nocapture
```

- Use the structured E2EE status harness for JSONL evidence of default fail-closed behavior, metadata-only projection posture, crypto adapter dependency/version/feature state, requested-decryption denial, skip reasons for unimplemented verified decrypt/trust cases, and shutdown:

```bash
rch exec -- cargo test -p fcp-matrix --test e2ee_status_structured_skip_e2e -- --nocapture
```

- Use the E2EE device-trust harness for JSONL evidence of fresh memory-only store bootstrap, matching host-restored scope, wrong account/device denial, unverified own device, stale device list, missing cross-signing, ready trust-state structured skip, and shutdown:

```bash
rch exec -- cargo test -p fcp-matrix --test e2ee_device_trust_state_e2e -- --nocapture
```

- Use the E2EE outgoing-maintenance harness for JSONL evidence of a raw loopback homeserver request sequence, request body hashes, homeserver response fixtures, retry and final-failure decisions, backup mismatch denial, stale-key reupload/delete paths, recovery guidance redaction, structured crypto skip, and shutdown:

```bash
rch exec -- cargo test -p fcp-matrix --test e2ee_outgoing_requests_retry_e2e -- --nocapture
```

- Use the setup/doctor/state harness for JSONL evidence of direct-token readiness, credential-injection degraded readiness, invalid homeserver transport, state persistence disabled/enabled restore, E2EE recovery warnings, structured crypto skip, and shutdown:

```bash
rch exec -- cargo test -p fcp-matrix --test setup_doctor_state_e2e -- --nocapture
```

- Verify with offloaded Cargo commands only:

```bash
rch exec -- cargo check -p fcp-matrix --all-targets
rch exec -- cargo test -p fcp-matrix
```

## Explicit Non-Goals

This slice does not provide:

- homeserver administration or provisioning
- end-to-end encryption device management
- decrypted E2EE event delivery before account/device/cross-signing/backup/recovery trust is mechanically verified
- connector-local durable storage writes; durable resume is explicitly host-managed snapshot restore
- automatic credential discovery outside host-managed `credential_id` injection
