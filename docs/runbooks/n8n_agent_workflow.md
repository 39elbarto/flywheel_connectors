# n8n Agent Workflow Coordination Runbook

## Purpose

This runbook is the reproducible operating contract for FCP/n8n work. It keeps
task boundaries, authority, provider safety, review, and coordinator transitions
observable and repeatable. If it is skipped, two agents may write or build at
once, a live operation may be retried without knowing its outcome, or a result
may be accepted without enough evidence.

## Scope

In scope:

- n8n connector, script, approval, release-candidate, and acceptance work;
- source and capability triage, bounded implementation, review, and handoff;
- tracked procedures and redaction-safe evidence for FCP/n8n operations.

Boundaries:

- do not invent new cryptography or change cryptographic authority as part of
  an n8n task;
- do not explore, retry, or release outside the recorded task boundary.

## Dated handoff — 2026-09-21

`handoff_at: 2026-09-21`. The `.23` acceptance is closed at main closeout
`ccbccdadf`. Installed release: rc26,
`release-20260920-02d215cfd-unarchive-introspection-rc26`. Tracked acceptance
runner fix: `4ef0578dc`, with retained evidence at:

- EEC: `/srv/dev-ssd/fcp/nqm81.23/acceptance-eec-20260921-9c42e6a1`;
- Hetzner: `/srv/dev-ssd/fcp/nqm81.23/acceptance-hetzner-NZAx85`.

At that handoff, the planned sequence was `.24` source/capability triage before
any bounded, authorized implementation, then `.25`, then `.26`.

## Default owner and authority

These role and model assignments are defaults for this workflow; direct user
instructions prevail.

| Role | Default launch | Responsibility |
| --- | --- | --- |
| Coordinator | Current user-selected session (currently `gpt-6-luna`, high) | Defines bounded tasks, assigns ownership, accepts evidence-backed results, and coordinates handoffs. It does not micromanage each implementer shell command. |
| Implementer | New Codex worker: `gpt-6-luna`, high effort | Owns assigned files and produces the observable change and tests in the specified checkout. |
| Reviewer | `gpt-6-sol`, medium effort | Reviews the diff and evidence read-only, separating blockers from nonblocking findings. |
| Consultant | Retained Astra/SilverDune session when requested | Gives advisory input when consulted; does not take coordinator authority or live-operation permission. |

These are role defaults, not permanent agent identities. Reuse the already
assigned coordinator/reviewer sessions; do not create duplicates merely to
match a model label. For launches, check that `launch.requested` matches
`launch.effective`; `--terminal` cannot be combined with `--model` or
`--effort`. A user instruction can change the assignment or scope.

Each bounded task designates one live writer, and one shared build runs globally;
assignments may change only through the handoff below. Worktrees isolate Git
files, not provider state, builds, Agent Mail, or other shared services.

## Trigger and prerequisites

Start this workflow for any n8n task that changes a connector, operation,
approval path, provider interaction, release candidate, or acceptance evidence.
Before work begins, confirm all of the following in the task record:

- the exact `cwd`, task branch, verified integration base, and task identifier;
- the exact files or globs the implementer owns, the read-only reviewer, and the coordinator;
- invariants, stop conditions, and tests stated as observable outcomes;
- whether the task is offline, provider-backed, or live, and the exact target if
  it is provider-backed;
- an Agent Mail project, registered handles, and exclusive reservations for
  every file the implementer will edit;
- the approval TTL beside the planned invoke when an approval is required;
- a redaction-safe evidence location; no secret or raw provider/request body may
  be persisted there.

## Procedure

### Step 1: Frame a bounded task

The coordinator records one concrete deliverable and its acceptance evidence. The task
must name its `cwd`, branch, base revision, file ownership, invariants, tests,
provider target (if any), and stop conditions. A valid task can be checked from
the resulting diff, command output, test result, or redacted provider evidence;
it cannot depend on an informal claim that work was done.

### Step 2: Establish ownership and execution order

The coordinator records the current writer and reserves the exact files before editing.
It accepts results rather than prescribing shell commands; the implementer
chooses the commands needed to satisfy the recorded tests and reports commands
and outputs. The reviewer works read-only, and no second build starts while the
one shared global build is in flight.

Record coordination in Agent Mail. Rediscover Agent Mail and terminal handles at
each session or handoff; do not fix IDs permanently in `AGENTS.md`. For the
n8n-specific completion wake and receipt procedure, follow the dedicated rule
in [the n8n Dispatch completion section](#n8n-dispatch-completion-and-coordinator-wake)
below; `input_accepted` is not evidence of `turn_started`.

### n8n Dispatch completion and coordinator wake

Every new Dispatch specification must include the current coordinator terminal
handle. The worker sends `worker_done` exactly once, with the matching
`taskId`, `dispatchId`, and `outcome`. After the durable `worker_done` receipt
succeeds, the worker has one narrow exception to the immediate-stop rule: it
sends exactly one terminal wake to that coordinator handle using
`orca terminal send --enter --wait-submit 10` with a message containing the
actual `taskId` and `dispatchId` (for example,
`worker_done taskId=<id> dispatchId=<id>`), then observes that terminal-send
receipt and stops. The coordinator
consumes, validates, and acknowledges its own Orca delivery.

The wake is only a notification and receipt observation. The worker must not
create tasks, poll, resend `worker_done`, or mutate lifecycle; a queued
coordinator is normal, and `input_accepted` is not `turn_started`. A timeout is
not permission to resend. If transport is ambiguous, use only the retry-request
for the same `requestId`; do not issue a fresh request. A wake failure never
invalidates a successfully received `worker_done`.

After three empty waits, the coordinator inspects `worker-list` and continues
waiting; it never finalizes solely because of a timeout. A queued wake is only
a queued delivery, not proof that an idle coordinator was awakened.

The coordinator treats the wake as a cue only: it verifies the actual Dispatch
and delivery state, and never repeats provider calls.

### Step 3: Implement and verify the bounded change

The implementer works only in the recorded `cwd` and branch, edits only owned files, and
keeps the procedure reproducible in tracked files. Before any provider invoke:

- do not persist secrets, tokens, raw request/response bodies, or private
  approval material;
- do not retry an operation whose outcome is unknown;
- do not use an LLM pause as an approval boundary;
- place the approval TTL next to the invoke and stop if the TTL is missing,
  expired, or cannot be checked;
- do not add new cryptography; use the existing FCP authority and capability
  contracts.

### Owner-key discovery and release signing

For release preparation, obtain the public owner key from the existing
`fwc-n8n-owner-signing` mapping's `public_key_hex` metadata and verify its key
ID against the trusted current release's signed `provision-receipt.json` using
the existing verifier. The current mapping and trusted signer verification
are required. The historical
`/etc/fwc-n8n/approval-public-key.owner-signing-backup-20260914` may corroborate
that binding when available, but its absence is not a blocker. Investigate any
available backup mismatch without changing trust. If the mapping or trusted
receipt is unavailable, ambiguous, or disagrees, fail closed; classify inability
to verify as `verification_error`, not as a key mismatch, and do not change
keys or ask the user to re-approve a known same-key operation.

`fwc-n8n-approval-signing` is a separate approval-signing mapping.
`/etc/fwc-n8n/approval-public-key` is the approval verifier key, not the owner
trust root. Do not substitute one for the other. The owner signing seed is
handled only by the existing protected-FD/stdin signing path; never place it in
arguments, environment, files, logs, or evidence. Store only public identifiers
and paths in tracked material, not key bytes.

Within a task already authorized by the user, routine build/signing with the
same verified owner key does not require another confirmation. User authority
and the task's existing scope still govern; this procedure grants no blanket
permission for provider/live operations, deployment or promotion, or key
rotation. Build a new RC only after evidence proves a binary change, the
dependency closure is checked, and the public owner-key binding matches the
intended binary and release identity. Record those results and the one build
result without recording secrets.

### Step 4: Handle blockers without creating authority drift

Stop at the first invariant violation or unverified provider state and preserve
the redacted evidence. If the same blocker occurs twice with no new evidence,
the coordinator asks a consultant one specific, answerable question containing
the blocker and the evidence already checked. Consultation is advisory; the
coordinator still owns acceptance and the implementer still owns
implementation. A new fact or new evidence must be recorded before treating
the blocker as changed.

### Step 5: Review and accept

The reviewer checks the owned diff, task record, tests, and evidence read-only,
and reports **blockers** separately from **nonblocking** follow-up. The
coordinator accepts the result when blockers are resolved, the recorded observable tests pass, and
the evidence is redaction-safe; acceptance is not an ad hoc shell instruction
stream.

### Step 6: Transfer coordination safely

Use this ordered transition:

`old quiescent -> handoff -> new accept -> old no longer owner`

The old coordinator quiesces new writes, builds, and live actions while bounded
in-flight actions finish and reconcile. It then sends a dated handoff
(`handoff_at` in UTC ISO-8601) containing the old and new owner, task state,
`cwd`, branch, owned files, current evidence, unresolved blockers, and next
acceptance check. The new coordinator explicitly accepts that dated handoff
before taking authority; only then is the old coordinator marked no longer
owner. Preserve Agent Mail history and the tracked task record.

## Verification

The coordinator records the task's `cwd`, branch, owned files, invariants, tests, and
redaction-safe outputs. A live task records one known outcome; an unknown
outcome is a stop state, not a retry. The reviewer's blocker/nonblocking findings, the
RC evidence when applicable, and the dated handoff markers are retained with
the Agent Mail history.

## Failure modes and edge cases

- **Missing or conflicting reservation:** do not edit; narrow the reservation
  or wait for the holder. Never create an untracked parallel copy.
- **Unclear task boundary:** stop until `cwd`, branch, ownership, invariants,
  and tests are recorded.
- **Second writer or build:** stop the newcomer and keep the existing owner and
  build authoritative; do not merge competing evidence.
- **Unknown provider outcome:** mark `unknown`, preserve redacted evidence, and
  do not retry or replay from an assumption of failure or success.
- **Approval pause, missing TTL, or expired TTL:** stop before invoke; an LLM
  conversation is not an approval mechanism.
- **Secret in evidence or logs:** stop publication, quarantine the evidence
  from the tracked result, and escalate through the authorized secret-handling
  path without copying the secret into chat or a report.
- **RC gate not proven:** do not build or label a new RC until binary change,
  dependency closure, and public owner-key binding are checked.
- **Review finding:** blockers stop acceptance; nonblocking findings remain
  visible and do not silently become blockers.
## Rollback and abort

Abort before a provider invoke when any prerequisite or invariant is missing.
Leave the task record and redacted evidence intact so the next owner can
reproduce the decision. For an unknown live outcome, never retry as rollback;
record the unknown state and require a separately bounded decision. For an
unaccepted handoff, the old coordinator remains owner. Any code rollback uses
the project's reviewed, non-destructive Git procedure and does not erase Agent
Mail history or evidence.

## Logs and observability

The source of record is the tracked task diff plus the Agent Mail thread and
handoff history. Terminal dispatch messages provide the direct `turn_started`
trigger and worker outcome. Keep provider/test evidence under the approved
redacted evidence path and record command names, exit statuses, revisions,
operation identifiers, and timestamps only as allowed by the task contract.
Never store secrets, tokens, approval contents, seeds, or raw provider/request
bodies in the repository, Agent Mail, or evidence.

## Review cadence

Apply this runbook to every n8n task. Re-review it whenever an n8n provider
operation, approval contract, release-key binding, role assignment, or
coordination transport changes.
