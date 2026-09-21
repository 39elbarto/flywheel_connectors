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

Out of scope:

- `.24` implementation or live work; `.24` is source/capability triage only;
- inventing new cryptography or changing cryptographic authority as part of an
  n8n task;
- unbounded provider exploration, retry, or release activity outside an
  explicitly bounded task.

## Owner and authority

| Role | Model | Authority and responsibility |
| --- | --- | --- |
| Terra | medium | Coordinator. Frames the task, assigns roles, records evidence, accepts results, and manages handoffs. Terra does not direct shell commands or become a second implementer. |
| Luna | xhigh | Implementer. Owns the assigned files and produces the bounded change and tests. Luna is the only live writer for that task. |
| Sol | medium | Reviewer. Works read-only, checks the diff and evidence, and separates blockers from nonblocking findings. |
| Astra | consultant | Consultant only. Answers a specific question after repeated identical blockers; Astra has no live authority, write authority, approval authority, or release authority. |

One task has one live writer and one build at a time. Worktrees isolate Git
files, not provider state, builds, Agent Mail, or other shared services.

## Trigger and prerequisites

Start this workflow for any n8n task that changes a connector, operation,
approval path, provider interaction, release candidate, or acceptance evidence.
Before work begins, confirm all of the following in the task record:

- the exact `cwd`, task branch, verified integration base, and task identifier;
- the exact files or globs Luna owns, the read-only reviewer, and the coordinator;
- invariants, stop conditions, and tests stated as observable outcomes;
- whether the task is offline, provider-backed, or live, and the exact target if
  it is provider-backed;
- an Agent Mail project, registered handles, and exclusive reservations for
  every file Luna will edit;
- the approval TTL beside the planned invoke when an approval is required;
- a redaction-safe evidence location; no secret or raw provider/request body may
  be persisted there.

Rediscover Agent Mail and terminal handles for each session or handoff. Never
put a permanent agent ID, terminal ID, or dispatch handle in `AGENTS.md`.

## Procedure

### Step 1: Frame a bounded task

Terra records one concrete deliverable and its acceptance evidence. The task
must name its `cwd`, branch, base revision, file ownership, invariants, tests,
provider target (if any), and stop conditions. A valid task can be checked from
the resulting diff, command output, test result, or redacted provider evidence;
it cannot depend on an informal claim that work was done.

Keep `.24` strictly at source/capability triage. If the proposed work would
implement, install, invoke, or otherwise operate `.24`, stop and return it to
triage; do not grant a live exception.

### Step 2: Establish ownership and execution order

Terra assigns Luna as the sole live writer and reserves the exact files before
editing. Terra accepts results rather than prescribing shell commands; Luna
chooses the commands needed to satisfy the recorded tests and reports the
commands and outputs. Sol is read-only, and only one build may run for the task
at a time.

Record coordination in Agent Mail. If a session is idle and needs to resume,
preserve the Agent Mail history and also issue a direct terminal trigger whose
event is `turn_started`. Do not treat a single untracked chat message or a
stale handle as a handoff.

### Step 3: Implement and verify the bounded change

Luna works only in the recorded `cwd` and branch, edits only owned files, and
keeps the procedure reproducible in tracked files. Before any provider invoke:

- do not persist secrets, tokens, raw request/response bodies, or private
  approval material;
- do not retry an operation whose outcome is unknown;
- do not use an LLM pause as an approval boundary;
- place the approval TTL next to the invoke and stop if the TTL is missing,
  expired, or cannot be checked;
- do not add new cryptography; use the existing FCP authority and capability
  contracts.

For a release candidate, require all of the following before building:

1. A proven binary change exists; a version bump or source-only claim is not
   enough.
2. The dependency closure for the changed binary is identified and checked.
3. The public owner-key binding is checked against the intended binary and
   release identity.

Only after these checks pass may the single task build produce a new RC. Record
the binary identity, dependency-closure result, owner-key-binding result, and
build result without recording secrets.

### Step 4: Handle blockers without creating authority drift

Stop at the first invariant violation or unverified provider state and preserve
the redacted evidence. If the same blocker occurs twice with no new evidence,
Terra asks Astra one specific, answerable question containing the blocker and
the evidence already checked. Astra advises only; Terra still owns acceptance,
and Luna still owns implementation. A new fact or new evidence must be
recorded before treating the blocker as changed.

### Step 5: Review and accept

Sol reviews the owned diff, task record, tests, and evidence read-only. The
review must report two separate classes:

- **Blockers:** violations that prevent acceptance or live action;
- **Nonblocking:** concerns that do not prevent the recorded acceptance and are
  retained as follow-up.

Terra accepts only when all blockers are resolved, the observable tests pass,
the ownership boundary was respected, and the evidence is redaction-safe.
Terra records the acceptance and does not turn acceptance into an ad hoc shell
instruction stream.

### Step 6: Transfer coordination safely

Use this ordered transition:

`old quiescent -> handoff -> new accept -> old no longer owner`

The old coordinator first stops writes, builds, and live actions, then sends a
handoff containing the task state, owned files, current evidence, unresolved
blockers, and next acceptance check. The new coordinator explicitly accepts
the handoff before taking authority. Only after that acceptance may the old
coordinator be marked no longer owner. Preserve Agent Mail history and the
tracked task record throughout; if the new coordinator has not accepted, the
old coordinator remains the owner and no split-brain work starts.

## Verification

For each task, Terra records the following checks and their redaction-safe
outputs:

- `cwd`, branch, base revision, file reservations, and current owner;
- the exact diff and the list of changed files;
- the recorded tests and their exit statuses;
- for live work, one known outcome or an explicit `unknown` stop state, never an
  inferred success;
- for a new RC, proof of binary change, dependency closure, public owner-key
  binding, and the one build result;
- Sol's separate blocker/nonblocking review and Terra's acceptance decision;
- for a handoff, the old-quiescent marker, handoff record, new-accept marker,
  and preserved history.

An unknown result, missing TTL, missing owner, second writer, second build, or
unreviewed blocker is a failed verification and stops the workflow.

## Failure modes and edge cases

- **Missing or conflicting reservation:** do not edit; narrow the reservation
  or wait for the holder. Never create an untracked parallel copy.
- **Unclear task boundary:** stop until `cwd`, branch, ownership, invariants,
  and tests are recorded.
- **Second writer or build:** stop the newcomer and keep the existing owner and
  build authoritative; do not merge competing evidence.
- **`.24` scope drift:** stop implementation/live work and return a source or
  capability question to triage.
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
- **Agent Mail outage:** do not restart the shared Agent Mail service. Keep the
  task quiescent until coordination history and ownership can be recorded;
  direct terminal activity alone does not grant authority.

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
coordination transport changes, and before accepting a new release candidate.
