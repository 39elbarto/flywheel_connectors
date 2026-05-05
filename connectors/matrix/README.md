# Matrix Connector V3 Readiness Notes

> **Status**: readiness and observability slice in progress
> **Bead**: `flywheel_connectors-j05nu.1.8.5`
> **Connector**: `fcp.matrix`

## Purpose

`fcp.matrix` is the Flywheel Connector Protocol connector for the Matrix Client-Server API. The current crate is a bidirectional, host-driven room and media connector for one configured homeserver account at a time.

It supports room creation and membership mutations, message send, timeline and room-state reads, explicit sync polling, member listing, and media upload/download. It is not a background bridge, a homeserver admin SDK, or a long-running event daemon.

## Current Runtime Truth

- One connector instance binds to one configured `homeserver_url` and one auth mode.
- Auth is either:
  - direct `access_token`
  - `credential_id`, where the host or egress proxy injects the bearer token at runtime
- The connector maintains an in-memory sync cursor and tracked room summaries only.
- There is no background receive loop. Operators must call `matrix.sync` explicitly to advance the cursor and inspect deltas.
- `matrix.sync` preserves raw room deltas and also returns a separate inbound-policy projection for future supervised delivery: authorized messages, dropped-event metadata, reaction events, and encrypted-event metadata.
- Encrypted Matrix timeline events fail closed by default for agent delivery until verified E2EE/device verification is implemented. Operators may choose metadata-only projection, but ciphertext is not emitted.
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
- sync delivery model guidance
- sync telemetry including success/failure counts, last duration, last error, and the last tracked token
- inbound-policy telemetry for the most recent sync projection, including authorized, dropped, reaction, and encrypted event counts

`health()` is intentionally truthful:

- `ready` only when the connector is configured, runtime-initialized, using an acceptable homeserver transport, and not waiting on secret injection
- `degraded` when the connector is unconfigured, incomplete, using a non-loopback plain HTTP homeserver, or in `credential_id` mode awaiting injected auth

`self_check()` proves live readiness only for direct bearer-token mode. In `credential_id` mode it returns a degraded report until the host injects the bearer token.

## Transport And Verification Guidance

- Prefer `https://` homeservers for live traffic.
- `http://localhost`, `http://127.0.0.1`, and `http://[::1]` are acceptable for deterministic verification harnesses.
- Use a non-production account and disposable rooms when verifying room creation, joins, leaves, sends, and media mutations.
- Configure `inbound_policy.allowed_users`, `bot_user_id`, `require_mention`, `free_response_rooms`, and `process_reactions` before treating `matrix.sync` policy projections as agent-delivery input.
- Verify with offloaded Cargo commands only:

```bash
rch exec -- cargo check -p fcp-matrix --all-targets
rch exec -- cargo test -p fcp-matrix
```

## Explicit Non-Goals

This slice does not provide:

- a background sync worker or webhook-style event delivery
- homeserver administration or provisioning
- end-to-end encryption device management
- durable connector-local storage beyond in-memory sync tracking
- automatic credential discovery outside host-managed `credential_id` injection
