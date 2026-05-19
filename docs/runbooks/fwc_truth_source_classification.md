# FWC Truth-Source Classification Runbook

> Bead: `flywheel_connectors-hr0rr.2.5`

Use this runbook when an operator or agent needs to know whether a read-only
`fwc` answer came from live mesh state, a host-admin endpoint, node-local
configuration, or offline workspace artifacts.

## Runtime Contract

Read-only `fwc --json` commands that participate in the A.5 truth-source
surface include a top-level `schema_version` and `_truth_source` field. The
shared envelope schema is `fcp.fwc.truth-source.v1` unless the command owns a
more specific payload schema, such as audit-chain status or audit verify.

The operator-facing `_truth_source` tags are:

| Tag | Meaning | Typical commands |
|-----|---------|------------------|
| `mesh` | Mesh-backed distributed truth. This is the intended highest-confidence answer once mesh-native cutover is complete. | Future mesh-backed resolver paths. |
| `host` | Live host-admin truth from a reachable `fcp-host` endpoint. | `fwc list`, `show`, `schema`, `search`, `status`, and live `doctor` paths when a host endpoint is configured. |
| `node-local` | Local CLI configuration rather than host or mesh state. | `fwc context current`, `fwc context list`. |
| `offline` | Workspace manifests, local history, local doctor probes, or local audit-chain artifacts. | `fwc list --offline`, `show --offline`, `schema --offline`, `search --offline`, `history`, local `doctor`, `audit chain status`, `audit verify`. |
| `degraded` | Resolver output produced under a degraded internal state. Treat as lower-confidence than live host truth. | Reserved for resolver surfaces. |
| `fallback-derived` | Inferred fallback output rather than direct runtime truth. Treat as advisory. | Reserved for resolver fallback surfaces. |

Do not infer liveness from command success alone. A successful command with
`_truth_source: "offline"` is useful for inspection, but it is not proof that
the live connector runtime currently has the same state.

## `--require-source`

Use `--require-source` when a workflow must fail closed instead of silently
accepting weaker truth. Supported levels are:

| Requirement | Accepted `_truth_source` values | Rejected examples |
|-------------|---------------------------------|-------------------|
| `mesh` | `mesh` only | `host`, `node-local`, `offline` |
| `mesh-or-host` | `mesh`, `host` | `node-local`, `offline` |
| `any-live` | `mesh`, `host` | `node-local`, `offline` |

When the actual answer does not satisfy the requested floor, JSON output uses:

```json
{
  "status": "error",
  "command": "search",
  "schema_version": "fcp.fwc.truth-source.v1",
  "_truth_source": "offline",
  "error": {
    "type": "truth-source-unavailable",
    "required": "any-live",
    "actual": "offline",
    "recoverable": true
  }
}
```

For production safety, prefer:

```bash
fwc --host <endpoint> list --require-source mesh-or-host --json
fwc --host <endpoint> status --require-source mesh-or-host --json
fwc --host <endpoint> doctor --require-source mesh-or-host --json
```

Use `--require-source mesh` only after the mesh-backed resolver path is known to
be available. In a host-backed deployment, `--require-source mesh` is expected
to fail with `truth-source-unavailable` and `actual: "host"`.

## Command Notes

| Command | Current truth behavior |
|---------|------------------------|
| `fwc list` | Host-backed with `--host` or configured host context; offline with `--offline`; missing host resolves as an offline/unavailable surface. |
| `fwc show <connector>` | Host-backed with live introspection; offline with workspace manifests; connector-resolution failures are also stamped with the resolved source. |
| `fwc schema <connector> [operation]` | Host-backed with live schemas; offline with manifest schemas; operation-resolution failures are stamped offline when using offline artifacts. |
| `fwc search <query>` | Host-backed with live introspection; offline with workspace manifests; missing-host details include the requested source floor. |
| `fwc status [connector]` | Host-backed with a reachable host; missing-host is stamped offline. |
| `fwc doctor` | Host-backed for live host diagnostics; offline for local checks, probes, and self-tests. |
| `fwc context current/list` | Node-local; this reads the active CLI context and does not prove host or mesh liveness. |
| `fwc history` | Offline; history reads the local CLI history store. |
| `fwc audit chain status` | Offline audit-chain artifact truth with `schema_version: "fcp.fwc.audit_chain_status.v1"`. |
| `fwc audit verify` | Offline audit verification truth with `schema_version: "fcp.fwc.audit_verify.v1"`. |

Mutation commands and side-effecting audit commands are not covered by this
read-only truth-source contract. Keep mutation routing on its command-specific
host or policy path.

## Downgrade Triage

1. Re-run with JSON output and inspect `_truth_source`, `schema_version`,
   `error.type`, `error.required`, and `error.actual`.
2. If the source is `offline`, decide whether offline artifacts are sufficient
   for the task. They are acceptable for local discovery, not for live runtime
   assertions.
3. If the source is `node-local`, treat the answer as CLI configuration only.
   It does not prove a host is reachable.
4. If a live answer is required, add `--host <endpoint>` or restore the active
   context, then use `--require-source mesh-or-host` or `--require-source
   any-live`.
5. If `--require-source mesh` fails with `actual: "host"`, use
   `fwc mesh explain-availability --json` and the mesh cutover-gates runbook to
   investigate why mesh-backed truth is unavailable.

## Text Output

The reliable audit surface today is JSON. The A.5 acceptance criteria still
track text-mode footer work for degraded answers. Until that lands, operators
should use `--json` whenever the answer source matters.

## Simulate

`fwc simulate` is not the same thing as a read-only truth-source answer. It
uses the invoke-style dry-run path and history can record entries with
`status: "simulated"`, but that status means no live connector mutation was
performed. It is not currently a top-level `_truth_source: "simulated"` JSON
contract.

For safety-sensitive workflows:

1. Use `fwc simulate` to inspect planned behavior and policy outcomes.
2. Use a read-only command with `--require-source mesh-or-host --json` to prove
   the current runtime source before relying on live state.
3. Do not treat a simulated history entry as evidence that the operation ran.

## Verification

Focused proof lanes for this surface should stay narrow:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --bin fwc required_truth_source -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --bin fwc truth_source -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --bin fwc require_any_live -- --nocapture

rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-fwc-truth-source CARGO_INCREMENTAL=0 \
  cargo test -p fwc --test audit_chain_status_shape -- --nocapture
```

Run `git diff --check -- docs/runbooks/fwc_truth_source_classification.md` for
documentation-only updates.

## Redaction

Truth-source logs and examples must not include connector credentials, bearer
tokens, OAuth codes, private keys, provider response bodies, raw host endpoints
from private deployments, or principal private data. Hash sensitive identifiers
with a `_hash` suffix before placing them in artifacts.
