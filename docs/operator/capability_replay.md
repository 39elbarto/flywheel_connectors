# `fwc capability replay` — Operator Reference

Bead: `flywheel_connectors-angoc.7.3` (Phase M.2)

`fwc capability replay <token>` reconstructs the full predicate-
evaluation trace from the audit chain so operators can answer "why was
this capability accepted or rejected?" without re-running production
traffic. It is the forensic-replay surface for capability decisions and
the operator-facing consumer of the Phase Q.E Datalog provenance
witnesses (when those land in `angoc.11.7`).

## Usage

```bash
fwc capability replay <token>
                      [--since <duration>]
                      [--confirm]
                      [--output <json|jsonl|human>]
```

| Flag | Meaning |
|---|---|
| `<token>` | required; the capability token id (hashable string) whose trace to reconstruct. The implementation MUST hash the token before logging so the raw value never reaches stdout or OTLP. |
| `--since <duration>` | optional; the audit-chain time window to walk. Default 7 days. Wider ranges require `--confirm`. |
| `--confirm` | required when `--since` exceeds the 7-day default cap. Prevents accidental wide scans that load excessive audit entries. |
| `--output` | optional; `json` (default), `jsonl` (one PredicateStep per line), or `human` (operator-readable narrative). |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | trace reconstructed successfully |
| 2 | invalid argument (e.g. `--since 30d` without `--confirm`) |
| 3 | `TokenNotFoundInAuditChain` — the token id has no audit-chain entries in the requested window |
| 4 | audit chain unavailable or corrupted (operator should check `fwc doctor --probe audit_chain`) |

## Output schema

The canonical JSON output is captured by
`crates/fwc/schemas/capability_replay.schema.json` and shaped as:

```json
{
  "token_hash": "blake3:abcd1234…",
  "final_verdict": "accepted" | "rejected_predicate" | "rejected_revocation" | "rejected_expired",
  "total_steps": 7,
  "total_latency_us": 245,
  "audit_chain_range": { "start_seq": 12034, "end_seq": 12040 },
  "trace": [
    {
      "rule_name": "zone_match",
      "inputs_json": { "src_zone": "z:work", "dst_zone": "z:work" },
      "output": true,
      "witness_chain_indices": [12034],
      "evaluator_version": "1.2.0"
    },
    {
      "rule_name": "capability_token_signature_verify",
      "inputs_json": { "alg": "ml-dsa-65", "issuer": "owner-key-v4" },
      "output": true,
      "witness_chain_indices": [12035],
      "evaluator_version": "1.2.0"
    },
    ...
  ]
}
```

Every `trace[i]` element corresponds to a single predicate evaluation
step. `witness_chain_indices` are the audit-chain sequence numbers
that the step's evidence comes from; operators can cross-check via
`fwc audit explain --seq <n>` (Phase M.1).

## Redaction

The output MUST:

- Hash the input token before logging it or emitting it.
- Replace any secret payload that appears in `inputs_json` with
  `{"<redacted>": {"len": N}}` (length only, never the bytes).
- Strip any operator-credential identifier (e.g. service-account key
  fragments) before emission.

A conformance test (`fwc_capability_replay_e2e.rs::test_replay_redacts_
secret_payloads`) MUST assert no secret bytes appear in trace JSON.

## Audit-chain range and the 7-day cap

The default `--since 7d` exists because audit chains grow ~1 MiB/day
on busy hosts; replaying 30 days loads ~30 MiB and can stall the
host's I/O for tens of seconds. The `--confirm` requirement on wider
ranges is the operator's "I know what I'm doing" gate.

When `--since` is omitted, the implementation walks the chain backward
from the most recent entry until either (a) the first audit entry
referencing `token_hash` is found OR (b) the 7-day cap is reached.

## Final-verdict semantics

| Verdict | Meaning |
|---|---|
| `accepted` | every predicate step returned `true`; the capability was honored |
| `rejected_predicate` | at least one non-revocation predicate returned `false`; trace has the offending step at the tail |
| `rejected_revocation` | the token was revoked before use; trace has a RevocationStep at the right seq |
| `rejected_expired` | the token expired before use |

## Cross-references

- `crates/fwc/src/commands/capability_replay.rs` — Rust dispatch (deferred to `angoc.7.3.1`)
- `crates/fcp-audit/src/replay.rs` — backing `reconstruct_predicate_trace` (deferred)
- `crates/fwc/schemas/capability_replay.schema.json` — JSON schema for the output above
- `crates/fwc/tests/fixtures/capability_replay/golden_accepted.json` — golden vector
- `fwc audit explain --seq <n>` (Phase M.1) — cross-references each `witness_chain_indices` entry
- Phase Q.E Datalog provenance (angoc.11.7) — when landed, replaces the
  procedural predicate evaluation with a Datalog rule chain whose
  provenance is naturally enumerable; the output schema above stays
  stable so existing operator tooling continues to work.

## Deferred Rust implementation

Filed as `angoc.7.3.1`. The runtime work is non-trivial: the
audit-chain walker has to skip checkpoint bundles and stitch multi-
chain replays when a token traverses zones. The spec doc + schema +
golden fixture committed here give the runtime team a concrete
contract; the e2e tests in the bead body translate directly into
fixture cases once the dispatch lands.
