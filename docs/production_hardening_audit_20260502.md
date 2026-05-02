# Production Hardening Audit - 2026-05-02

Bead: `flywheel_connectors-x0duh`

Agent: GoldenFinch

## Scope

This pass focused on production-readiness gaps in committed production paths:

- panic and unwrap surfaces outside explicit test directories
- external call timeout and retry-budget gaps
- PII or secret-adjacent logging fields
- placeholder, mock, and "not implemented" language in runtime code
- unbounded local process execution

The worktree was already heavily dirty from other active agents, so fixes were
restricted to clean files. Findings in broad or behavioral surfaces were filed
as follow-up beads instead of changing shared work in flight.

## Commands Run

```bash
br update flywheel_connectors-x0duh --status=in_progress --force
git grep -n -E 'panic!\(|todo!\(|unimplemented!\(|unwrap\(\)|expect\("[^"]{0,20}"\)' HEAD -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' 'connectors/*/src/*.rs' 'connectors/*/src/**/*.rs' ':!**/tests/**' ':!**/benches/**'
git grep -n -E 'Client::new\(|Client::builder\(|\.send\(\)\.await|Command::new\(|\.timeout\(' HEAD -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' 'connectors/*/src/*.rs' 'connectors/*/src/**/*.rs' ':!**/tests/**' ':!**/benches/**'
git grep -n -i -E 'TODO|FIXME|HACK|XXX|STUB|PLACEHOLDER|MOCK|DUMMY|FAKE|TEMPORARY|not implemented|not yet implemented|simulate|simulation' HEAD -- 'crates/*/src/*.rs' 'crates/*/src/**/*.rs' 'connectors/*/src/*.rs' 'connectors/*/src/**/*.rs' ':!**/tests/**' ':!**/benches/**'
git grep -n -E 'info!\(|debug!\(|warn!\(|error!\(' HEAD -- 'connectors/*/src/*.rs' 'connectors/*/src/**/*.rs' ':!**/tests/**' ':!**/benches/**' | rg -i 'input\s*=\s*input|query\s*=\s*query|email\s*=|message\s*=|body\s*=|payload\s*=|token\s*=|secret\s*=|password\s*='
```

## Fixed In Place

| ID | File | Finding | Fix |
| --- | --- | --- | --- |
| F1 | `connectors/wolfram/src/client.rs` | `info!(input = input, ...)` logged raw Wolfram user queries in three API methods. The client also created a new `reqwest::Client` for each request, losing pooling. | Replaced raw query logging with `input_len` and stored one client on `WolframClient` for query, short-answer, spoken, and health-check requests. |
| F2 | `connectors/gcp/src/client.rs` | Service-account setup logged raw `client_email`, which can identify a user, service account, or project. | Replaced the field with `service_account_client_email_present = true`. |

## Follow-Up Beads Filed

| Bead | Priority | Finding |
| --- | --- | --- |
| `flywheel_connectors-krxpn` | P1 | Apple Notes and Apple Reminders call `osascript` with `Command::output()` and no timeout or kill boundary. A hung AppleEvent can pin the connector indefinitely. |
| `flywheel_connectors-0a9hv` | P1 | Wolfram carries `ConnectorRuntime` and `HttpRetryConfig`, but external calls still perform a single send. Wire in `RetryLoop` and add retry/terminal tests. |
| `flywheel_connectors-ptb6n` | P1 | Several connector retry paths log full request URLs, which can include resource IDs or query strings. Replace with route templates or redacted path classes and add log-capture tests. |

## Triage Notes

- The broad panic/unwrap scan is noisy because many crates keep inline unit tests in `src/*.rs`. The actionable production items from this pass were the logging and external-call findings above.
- Placeholder searches found many intentional `simulate` handlers and test/mock references. These are part of the FCP connector protocol and test harnesses, not production fake-code findings by themselves.
- `connectors/elasticsearch/src/client.rs` has a documented placeholder default URL (`https://localhost:9200`). It is configuration-facing and was not patched in this pass; it may deserve a separate connector-config hardening review if operators can reach it without explicit base-url configuration.
- A dirty, unstaged `crates/fwc/src/truth.rs` edit in the shared worktree still contains unsafe env-var mutation patterns that block `fwc` tests under `#![deny(unsafe_code)]`. That file was not touched because it belongs to another active lane.

## Verification

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-epsilon cargo test -p fcp-wolfram -p fcp-gcp --all-targets` did not reach Cargo. `rch` completed the large remote sync, then failed with `timeout: failed to execute process: No such file or directory (os error 2)` and returned exit 127 from worker `vmi1152480`.
- Local fallback with the same target dir passed for the touched crate libraries: `env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/fcp-epsilon cargo test -p fcp-wolfram -p fcp-gcp --lib` (fcp-gcp: 115 passed; fcp-wolfram: 53 passed).
- `cargo test -p fcp-wolfram -p fcp-gcp --all-targets` locally reached an existing `fcp-gcp` integration-test manifest issue before the local fallback: `connectors/gcp/tests/connector_suite_happy_path.rs` imports `fcp_e2e`, but `connectors/gcp/Cargo.toml` does not declare an `fcp-e2e` dev-dependency. The relevant manifest/test files were already dirty from another active lane, so this audit did not modify them.
- `git diff --cached --name-status` before commit showed only three x0duh files staged: `connectors/gcp/src/client.rs`, `connectors/wolfram/src/client.rs`, and this audit document.
- `ubs --staged --only=rust` returned exit 1. In this dirty multi-agent checkout it first reported inline test panic/unwrap/expect findings plus heuristic `token` variable-name findings in touched files, then after unrelated pre-existing staged files were removed it still built a 951-file shadow workspace even though the cached diff listed only the three x0duh files. The final UBS run is therefore recorded as a non-green scanner result in a dirty checkout; it also reported formatting clean, no clippy warnings/errors, cargo check clean, and tests build clean for its shadow workspace.
