# fcp-telemetry

`fcp-telemetry` is the shared host/runtime telemetry layer for Flywheel Connector Protocol. It owns structured tracing helpers, log setup, Prometheus export, trace capture, and optional OpenTelemetry OTLP export.

OTLP export is intentionally a crate-level runtime feature, not a connector binary. Connectors continue to emit `tracing` spans, metrics, and logs through the normal FCP runtime. A host or operator process decides whether to enable export and where to send it.

## Runtime Boundary

OTLP export belongs in this crate because telemetry must observe the host and connector runtime regardless of individual connector capability tokens or zone bindings. Running it as a sandboxed connector would add lifecycle and capability semantics that do not match telemetry delivery.

The public boundary is:

- `TelemetryConfig`: operator-facing telemetry configuration.
- `TelemetryConfig::from_env()`: standard OpenTelemetry environment parsing.
- `init_telemetry(config)`: installs logging, Prometheus, and enabled OTLP exporters.
- `shutdown_telemetry()`: best-effort shutdown and flush for OTLP metrics, traces, and logs.
- `otlp_readiness(&config)`: redaction-safe readiness summary for host/admin surfaces.
- `init_otlp_*_with_options_and_timeout(...)`: lower-level trace, metric, and log exporter initializers used by focused tests and host integrations.

## Feature Flag

Build OTLP support with:

```bash
cargo test -p fcp-telemetry --features otlp
```

Without the `otlp` feature, `TelemetryConfig` and `otlp_readiness` are still available, but exporter initialization reports that the feature is unavailable. This keeps host/admin diagnostics honest in builds that intentionally omit OpenTelemetry exporter dependencies.

## Operator Configuration

`TelemetryConfig::from_env()` recognizes the standard OpenTelemetry variables used by this crate:

| Variable | Purpose |
| --- | --- |
| `OTEL_SERVICE_NAME` | Service name attached to exported resource metadata. |
| `OTEL_RESOURCE_ATTRIBUTES` | Comma-separated resource attributes such as `deployment.environment=prod`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Generic OTLP gRPC endpoint. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Trace-specific endpoint; takes precedence over the generic endpoint. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Generic collector metadata. |
| `OTEL_EXPORTER_OTLP_TRACES_HEADERS` | Trace-specific metadata; merged after generic headers. |

Header and resource values are validated before exporters are initialized. Header names are normalized to lowercase, duplicate keys are overridden by the later value, binary metadata suffixes are rejected, and debug output redacts values.

## Readiness Output

Use `otlp_readiness(&config)` before initializing exporters when surfacing operator status. The readiness payload deliberately reports only redaction-safe fields:

- boundary: always identifies host/runtime OTLP export.
- status: `disabled`, `unavailable`, `fail`, or `ready`.
- endpoint class: `http_plaintext`, `http_loopback`, `https`, `https_loopback`, or `invalid`.
- signal support: traces, metrics, and logs.
- counts for collector headers and resource attributes.
- trace sample-rate class.

It must not expose collector hostnames, header values, API keys, tenant IDs, local paths, prompts, completions, or other sensitive payload data.

Operators can inspect that same contract through `fwc` without contacting a collector:

```bash
fwc telemetry otlp-readiness --json
fwc telemetry otlp-readiness --endpoint http://127.0.0.1:4317 --json
```

The command reads `TelemetryConfig::from_env()` and applies optional CLI overrides for the endpoint, service name, sample rate, collector headers, and resource attributes. Its JSON output carries the readiness status, endpoint class, signal support, header/resource counts, and next actions, but never the raw endpoint or metadata values.

## Failure Behavior

Configuration is validated before side effects. Malformed endpoints, unsafe collector headers, unsafe resource attributes, or zero export timeouts return `TelemetryError::Config`.

Exporter failures map by signal type:

- trace exporter failures: `TelemetryError::TracingInit`
- metric exporter failures: `TelemetryError::MetricsInit`
- log exporter failures: `TelemetryError::LoggingInit`

Unavailable collector tests use timeout-bounded initializers and force flushes so operators get bounded failure behavior instead of an unbounded wait.

## Proof Lanes

The current no-live-credential OTLP proof entrypoint is:

```bash
scripts/e2e/telemetry_otlp_exporter_verification.sh
```

It runs the loopback collector fixture, the unavailable-collector fixture, the
collector-backpressure fixture, and the slow-collector timeout fixture through
`rch`.

Set `FCP_TELEMETRY_OTLP_EVIDENCE=/path/to/evidence.jsonl` to append redaction-safe JSONL evidence. The fixture records command line, git revision, endpoint class, signal type, batch or signal counts, retry decision, dropped count, gRPC status, error mapping, timeout/cancellation checkpoint where applicable, cleanup result, and skip reason.

Focused checks:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-telemetry-otlp \
  cargo test -p fcp-telemetry --test otlp_collector_fixture --features otlp -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-telemetry-otlp-unavailable \
  cargo test -p fcp-telemetry --test otlp_unavailable_fixture --features otlp -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-telemetry-otlp-backpressure \
  cargo test -p fcp-telemetry --test otlp_backpressure_fixture --features otlp -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-telemetry-otlp-timeout \
  cargo test -p fcp-telemetry --test otlp_timeout_fixture --features otlp -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-telemetry-otlp-clippy \
  cargo clippy -p fcp-telemetry --all-targets --features otlp -- -D warnings
```

fwc readiness surface:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-telemetry-readiness \
  cargo test -p fwc execute_telemetry_otlp_readiness -- --nocapture
```

## Current Limits

This crate provides the OTLP exporter and proof fixtures. Host/fwc admin wiring is still tracked by the OTLP bead and should not be implied complete until an operator can query the host readiness surface and see the same redaction-safe readiness contract.

The current fixtures cover successful trace, metric, and log export,
unavailable collector mapping, collector backpressure/drop-accounting, and
timeout-bounded slow-collector cancellation behavior. Remaining closeout work
includes broader retry policy and host/admin integration evidence.
