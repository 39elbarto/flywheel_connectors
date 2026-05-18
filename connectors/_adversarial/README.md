> **Status**: Adversarial test fixture
> **Canonical bead**: `flywheel_connectors-bky21.3.6.55`
> **Verification**: `rch exec -- cargo test -p fcp-adversarial --all-targets -- --nocapture`
> **Upstream docs**: Internal FCP hostile-response fixture; no external provider API.

# FCP Adversarial Test Connector

## Purpose

`fcp.adversarial` is an opt-in fake connector used by FCP conformance and
robustness tests. It deterministically emits hostile provider-response shapes so
host, manifest, policy, and evidence layers can prove fail-closed behavior
without contacting a real external service or allocating dangerous payloads.

This connector is never a production integration. `FCP_DEPLOY_MODE=production`
and `deploy_mode="production"` both fail closed with `ConnectorTrustError`.

## Scope Boundary

In scope:

- Structured hostile response scenarios for parser, resource, timestamp, and
  header-boundary tests.
- In-process operation execution with no provider process and no network egress.
- Health, handshake, introspection, simulate, and shutdown surfaces needed by
  host lifecycle tests.

Out of scope:

- Real provider calls, webhook/listener behavior, streaming, replay, or state.
- Production deployment.
- Secret storage or credential exchange.

## Operation Inventory

| Operation | Capability | Risk | Safety | Idempotency | Behavior |
| --- | --- | --- | --- | --- | --- |
| `adversarial.emit` | `adversarial.emit` | high | dangerous | strict | Accepts one `scenario` string and returns a structured FCP error for that hostile input shape. |

Supported scenarios:

- `oversized_payload`
- `mid_stream_disconnect`
- `time_skew_plus_1y`
- `time_skew_minus_1y`
- `invalid_utf8_header`
- `deeply_nested_json`
- `oversized_json_key`
- `null_byte_injection`
- `header_smuggling`
- `crlf_injection`

Every scenario returns an error response. A successful provider-style payload is
not a valid outcome.

## Auth, Zone, Sandbox, And Network Invariants

- Zone scope is `z:work`; `z:public` and `z:community` are forbidden.
- Optional capability is `adversarial.emit`; no capability is required by
  default.
- Sandbox profile is `strict` with 16 MiB memory, 5 percent CPU, 1000 ms wall
  clock timeout, `deny_exec=true`, and `deny_ptrace=true`.
- Network, DNS, listener, SNI, state storage, and process execution
  capabilities are forbidden.
- The manifest includes a deliberately impossible egress target
  (`adversarial.invalid`) with one millisecond connection and total timeouts so
  tests can verify network policy boundaries without real egress.

## Known Limits

- The connector does not stream. `subscribe` and `unsubscribe` return
  `StreamingNotSupported`.
- It is stateless and does not persist scenario history.
- It uses sentinel values for oversized payload and JSON-key checks; tests must
  assert the sentinel error metadata, not allocate the represented payload.
- It is a fixture connector. Operators should not register it in production
  connector inventories.

## Verification

Use `rch` for Cargo work:

```bash
rch exec -- cargo fmt --manifest-path connectors/_adversarial/Cargo.toml --check
rch exec -- cargo check -p fcp-adversarial --all-targets
rch exec -- cargo test -p fcp-adversarial --all-targets -- --nocapture
rch exec -- cargo clippy -p fcp-adversarial --all-targets -- -D warnings
```

The local non-mock test logs redaction-safe evidence containing the connector
ID, bead ID, in-process route, no-network boundary, scenario IDs, and structured
error classes. Evidence must not include provider response bodies, real secrets,
or allocated hostile payloads.
