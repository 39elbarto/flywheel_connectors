# `fwc agent-bootstrap` — Operator Reference

Bead: `flywheel_connectors-angoc.6.2` (Phase L.2)

`fwc agent-bootstrap <name>` is the one-command onboarding macro for
a fresh AI agent joining the workspace. It registers identity with
the MCP Agent Mail hub, reserves a default file scope, lists ready
beads, emits a commit template, and runs every doctor probe — all
idempotently, so re-running the command on an already-bootstrapped
agent converges to the same state without duplicating identities or
reservations.

This is the operator-facing surface of `angoc.6.2` (Phase L.2). The
Rust dispatch + integration tests are filed as `angoc.6.2.1`
(deferred — requires fwc + agent-mail + beads-DB integration that
currently conflicts with the PQ-hardening track).

## Usage

```bash
fwc agent-bootstrap <name>
                    [--scope <path-glob>]
                    [--ttl-seconds <N>]
                    [--reason <bead-id>]
                    [--output <json|human>]
                    [--dry-run]
```

| Flag | Meaning |
|---|---|
| `<name>` | required; the agent's persona name (e.g. `SunnyMoose`). Used as the agent-mail identity. Pattern: `[A-Z][a-zA-Z]+`. |
| `--scope` | optional; file-glob to reserve. Default `src/**`. Use `none` to skip the reservation step. |
| `--ttl-seconds` | optional; reservation TTL. Default 3600 (1 hour). |
| `--reason` | optional; bead id (e.g. `flywheel_connectors-angoc.6.2`) recorded with the reservation for audit. |
| `--output` | optional; `json` (default) or `human` narrative. |
| `--dry-run` | optional; enumerate the bootstrap plan without performing any side effect. |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | bootstrap complete; report on stdout |
| 2 | invalid argument (e.g. malformed `<name>`) |
| 3 | identity conflict — `<name>` is already registered by a different owner |
| 4 | agent-mail unreachable; degraded-mode bootstrap completed |
| 5 | one or more doctor probes failed |

## Bootstrap steps

The macro executes the following 6 steps in order. Each is
INDIVIDUALLY IDEMPOTENT — re-running converges to the same state.

| Step | Action | Idempotency |
|---|---|---|
| 1 | Register agent identity in agent-mail | `ensure_agent_identity(name)` — registers only if absent; conflict iff existing-owner != self |
| 2 | Reserve default file scope | `file_reservation_paths(name, [scope], ttl, reason)` — repeat call extends TTL rather than duplicating |
| 3 | List ready beads | `br ready --json --owner <name>` — read-only |
| 4 | Emit commit template | writes `.git/info/exclude_template` if absent |
| 5 | Run all doctor probes | `fwc doctor --json --all-probes` — read-only |
| 6 | Print BootstrapReport | structured JSON or human summary |

Step 1's identity conflict (exit 3) is the only HARD FAIL — the
agent cannot proceed under a name owned by another principal. Steps
2-6 are best-effort and surface their status in the BootstrapReport
without blocking earlier successful steps.

## BootstrapReport schema

```json
{
  "agent_name": "SunnyMoose",
  "mode": "fresh" | "rebootstrap" | "degraded",
  "identity": {
    "created": true,
    "agent_mail_status": "registered" | "already_present" | "unreachable",
    "owner_email": "<email>",
    "identity_id": "<uuid-or-name-hash>"
  },
  "reservation": {
    "scope": "src/**",
    "ttl_seconds": 3600,
    "extended": false,
    "reason": "flywheel_connectors-angoc.6.2",
    "expires_at": "2026-05-14T..."
  },
  "ready_beads": [
    {"id": "flywheel_connectors-angoc.7.2.1", "title": "[Phase M.5.1] Deferred Rust impl...", "priority": 3, "score": 0.18}
  ],
  "commit_template": {
    "path": ".git/info/exclude_template",
    "written": true
  },
  "doctor": {
    "probes_run": 12,
    "passed": 11,
    "failed": 0,
    "skipped": 1,
    "by_probe": {
      "agent_mail_health": "pass",
      "disk_pressure": "pass",
      "rch_worker_reachability": "pass",
      "beads_db_integrity": "pass",
      "agent_name_prefix": "pass",
      "recent_commit_signing": "skipped",
      ...
    }
  },
  "total_duration_ms": 1245,
  "exit_code": 0
}
```

`mode` values:

| Value | Meaning |
|---|---|
| `fresh` | every step took its primary path; identity created, reservation created, doctor green |
| `rebootstrap` | identity already present (this name); reservation extended; doctor still ran |
| `degraded` | agent-mail unreachable; identity step skipped without restart per AGENTS.md `am` protection; subsequent steps proceeded best-effort |

## Idempotency invariants

The conformance test asserts:

1. **No duplicate identity**: running `agent-bootstrap SunnyMoose`
   twice produces `identity.created = true` on the first call and
   `identity.created = false` on the second.
2. **No duplicate reservation**: the second call shows
   `reservation.extended = true` rather than two reservations.
3. **Same ready_beads**: between the two calls (assuming no concurrent
   bead changes), the `ready_beads` lists are identical.
4. **Stable identity_id**: the second call returns the same
   `identity_id` as the first.

## Degraded mode

When agent-mail is unreachable (the MCP server isn't responding,
the SQLite store is corrupted per `flywheel_connectors-d5yeb`, etc.),
the bootstrap MUST:

1. Detect the unreachability via a short timeout (default 5s).
2. NOT restart the `am` service (AGENTS.md prohibits this — see
   "AGENT MAIL (am) PROCESS PROTECTION — DO NOT TOUCH").
3. Mark `mode = "degraded"` and `identity.agent_mail_status = "unreachable"`.
4. Skip the reservation step (cannot reserve without identity).
5. Continue with steps 3-5 (ready beads, commit template, doctor).
6. Exit 4 to signal degraded completion.

The agent can still claim beads via `br update --status=in_progress`
in degraded mode — it just can't coordinate via agent-mail until the
hub recovers.

## AGENTS.md prefix gate

The bootstrap MUST verify before any git operation that
`AGENT_NAME=<name>` is set in the environment, per the project's
hook contract. Step 5 (`fwc doctor`) includes an `agent_name_prefix`
probe that asserts the env var matches `<name>`. If not, the doctor
report flags it; the operator can fix by:

```bash
export AGENT_NAME=SunnyMoose
fwc agent-bootstrap SunnyMoose
```

## Conformance test coverage

`crates/fwc/tests/agent_bootstrap_idempotency.rs`:

- `test_bootstrap_idempotent_same_name`: invoke twice with the same
  name; assert second BootstrapReport has `identity.created=false`
  and `reservation.extended=true`.
- `test_bootstrap_fails_on_existing_different_owner`: identity
  exists but registered by a different owner; assert exit 3 +
  `AgentBootstrapError::IdentityConflict`.

`crates/fwc/tests/agent_bootstrap_e2e.rs`:

- `test_fresh_env_full_bootstrap`: fresh tmpdir (no identity, no
  reservations); assert identity in agent-mail, reservation present,
  ready beads JSON, commit template emitted, doctor green.
- `test_bootstrap_degraded_when_am_unreachable`: mock agent-mail
  unreachable; assert `mode="degraded"`, `identity.created=false`,
  NO restart of am service.

`crates/fcp-conformance/tests/agent_bootstrap_macro_completeness.rs`:

- `test_covers_every_agents_md_flow_step`: parses AGENTS.md
  "Typical Agent Flow" section; asserts each enumerated step maps
  to a bootstrap sub-action by name.

## OTLP / observability

Top-level span: `fwc.agent_bootstrap` with attributes:

| Attribute | Value |
|---|---|
| `agent_name` | operator-chosen name (NOT PII — agent personas are public) |
| `mode` | `fresh` / `rebootstrap` / `degraded` |
| `identity_created` | bool |
| `reservations_added` | integer |
| `ready_beads_count` | integer |
| `doctor_passed` | integer |
| `doctor_failed` | integer |
| `total_duration_ms` | integer |

Nested spans per step under `fwc.agent_bootstrap.<step_name>`.

## Cross-references

- `crates/fwc/src/agent_bootstrap.rs` — Rust dispatch (deferred to
  `angoc.6.2.1`)
- `crates/fwc/schemas/agent_bootstrap_report.schema.json` — JSON
  schema for BootstrapReport (this commit)
- `crates/fwc/tests/fixtures/agent_bootstrap/golden_fresh.json` —
  golden vector for the `fresh` mode (this commit)
- `crates/fwc/tests/fixtures/agent_bootstrap/golden_degraded.json` —
  golden vector for the `degraded` mode (this commit)
- AGENTS.md "Typical Agent Flow" — the canonical list of steps this
  macro automates
- AGENTS.md "AGENT MAIL (am) PROCESS PROTECTION" — the no-restart
  rule this macro respects

## Deferred Rust implementation

Filed as `angoc.6.2.1`. The dispatch needs:

1. `crates/fwc/src/agent_bootstrap.rs` with the 6-step macro
2. `crates/fwc/src/commands/agent_bootstrap.rs` CLI arg parser
3. `crates/fwc/tests/agent_bootstrap_idempotency.rs` (2 tests)
4. `crates/fwc/tests/agent_bootstrap_e2e.rs` (2 tests)
5. `crates/fcp-conformance/tests/agent_bootstrap_macro_completeness.rs`
   (1 test)

Estimated 6-8h once fwc compile chain is unblocked.
