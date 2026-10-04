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

## Current closeout and operating boundary — 2026-10-04

Canonical `.34` is closed at `2026-10-04T03:36:40.074779411Z`: separate Sol
GO accepted final test source `efb3e22f11c5` and 19/19 update tests. Local
integration is `202e5e3924eb183bc01724bf0f8939bee1eed66e`; installed RC43c
runtime source is separately `09cebc4aaa3c968f3704611325a005a3ced7a237`.
Both servers run 2.41.5. EEC uses internal JS (42), with no Python/external-runner
claim; Hetzner uses configured external JS/Python (42/43). Controlled harmless
Webhook publication/unpublication passed on both, with independent GETs and
retained inactive fixtures, no direct webhook or business execution.

Use the [operator summary](../../connectors/n8n/README.md#current-operator-state--2026-10-04)
and [criterion/evidence matrix](../architecture/fwc-n8n-operation-contract.md#34-acceptance-update--2026-10-04)
for primary filenames. The [actual protected route](#reproduced-protected-release-route-rc43c-2026-10-04)
uses admitted, root-owned verified files and direct argv; only ephemeral secret
data is piped. A universal release launcher is not implemented by this runbook.
Metadata/native-pin/closed-diagnostic fixes are actual code; the sequence here
documents the per-release executed mechanism, not new security policy.

Local package upgrade remains UNVERIFIED; recovery is preflight only, no APPLY.
Retired backup payloads cannot be used for rollback. Preserve historical
FAIL/UNKNOWN, the exact `09cebc4`/`0e228bf6` bounded UBS acceptance (100/4115/2305,
not green or transferable), and eight old test Clippy findings. Closure does not
authorize fresh provider writes, cleanup, keys or automatic schema enrollment.

## Dated handoff — 2026-09-21

`handoff_at: 2026-09-21`. The `.23` acceptance is closed at main closeout
`ccbccdadf`. Installed release: rc26,
`release-20260920-02d215cfd-unarchive-introspection-rc26`. Tracked acceptance
runner fix: `4ef0578dc`, with retained evidence at:

- EEC: `/srv/dev-ssd/fcp/nqm81.23/acceptance-eec-20260921-9c42e6a1`;
- Hetzner: `/srv/dev-ssd/fcp/nqm81.23/acceptance-hetzner-NZAx85`.

At that handoff, the planned sequence was `.24` source/capability triage before
any bounded, authorized implementation, then `.25`, then `.26`.

## Plan refinement — 2026-09-30

The dated sequence above is historical: `.24` selected-version lifecycle and
`.25` manual execution are accepted, while production `.26` and complete v1
remain unfinished. The [operation contract](../architecture/fwc-n8n-operation-contract.md#current-delivery-plan-and-evidence-boundary-2026-09-30)
maps remaining original scope to `.33`–`.43`. The later `.34` acceptance and
closure supersede its pending status only; see the current closeout above.
Compatible numeric-version changes must retain usable supported routes without
relaxing signed artifacts, exact approvals, schema/protocol/permission or readback
semantics. Isolate actual conflicts to affected operations where trust permits.

The **2026-09-30 preparation stage** produced an unsigned binary/public-input set
for subsequent assembly. That stage granted no package update, signing, installation, release
switch, provider mutation, secret change, cleanup or profile removal. Retain the
role defaults below and reuse the established coordinator/reviewer sessions.

Extend existing unit/contract/host/CLI coverage and bounded scripts for every
feature. Offline self-tests are separate from acceptance. Evidence retains run
and requested/observed correlation IDs, source/release/schema hashes, timing,
attempts, dispatch certainty, safe error/status classes, independent readback and
teardown. Never retain raw bodies, workflow/Code/execution items, tokens, headers
or customer/patient content. Synthetic redaction canaries cover success/failure;
nonzero exits must preserve safe diagnostics.

`.15` owns final complete-v1 acceptance and proven recovery. Preserve PASS and
UNKNOWN separately; `.32` requires reconciliation or explicit owner disposition.
`.25` fixture restoration is separately approved. `.12`/`.43` gate external update
integration; `.16`–`.18` remain future owner decisions. Add process machinery only
for a concrete delivery risk.

## Default owner and authority

These role and model assignments are defaults for this workflow effective
2026-09-30; direct user instructions prevail.

| Role | Default launch | Responsibility |
| --- | --- | --- |
| Coordinator | Codex `gpt-6.1-sol`, medium effort | Defines bounded tasks, assigns ownership, accepts evidence-backed results, and coordinates handoffs. It does not micromanage each implementer shell command. |
| Implementer | All future Codex implementers: `gpt-6.1-sol`, low effort | Owns assigned files and produces the observable change and tests in the specified checkout. |
| Reviewer | Separate Codex reviewer: `gpt-6.1-sol`, medium effort | Reviews the diff and evidence read-only, separating blockers from nonblocking findings. |
| Consultant | Retained Astra/SilverDune session when requested | Gives advisory input when consulted; does not take coordinator authority or live-operation permission. |

These are role defaults, not permanent agent identities. Reuse active workers
and the already assigned coordinator/reviewer sessions; do not restart them or
create duplicates merely to match a model label. For launches, check that `launch.requested` matches
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

For an artifact replacement already authorized in that task, installing the
exact SHA-256-verified binary at its fixed destination with
`install --backup=numbered` is a reversible in-scope step: no second owner
confirmation is required. Verify the installed digest and owner/group/mode and
the numbered backup's digest afterward. This does not authorize a different
artifact or destination, release promotion, key change, or additional provider
operation.

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

## Bounded manual acceptance for the two disposable `.25` workflows

This section records the user's current explicit `.25` authorization for only
these isolated fixtures; it grants no standing permission. Every write still
requires its own fresh exact approval. Another workflow or a bulk scope needs
separate explicit authorization:

| Server | Workflow ID and approved workflow version | Manual trigger and input |
| --- | --- | --- |
| `eec` | `kXVmpnLGECl1aHLy` / `32385eab-f3ad-4bab-a545-62104f95f42c` | `FWC Acceptance Webhook`; `inputs.webhookData` is exactly `{"method":"POST","query":{},"body":{"fcpAcceptance":"nqm81.25-eec-manual-noop"}}`. |
| `hetzner` | `uQXXNMWE2lzlCgag` / `b22acfe1-ecca-45c8-97a1-b10420dfb241` | `Manual Trigger`; omit `inputs` entirely. |

Run EEC first. Require a fresh full-graph read for the exact fixture: the
workflow is inactive and unarchived, has no credentials or connections, and
matches the recorded safe graph/invariant digests. For Hetzner, require EEC
PASS—including its separate execution readback—before taking a fresh Hetzner
baseline or changing its MCP availability. Recheck the full graph before and
after each fixture's manual execution.

To enable MCP availability, use the typed `n8n.mcp_access.reconcile` operation
with `scope: workflow_ids`, exactly one approved workflow ID, `desired: true`,
and `dryRun: true`. Before any apply, record the original `availableInMCP`
value; if the provider omits it, record the semantic value as `false`. If the
plan says the workflow is already available, record that original state and
skip apply even when its current digest differs from the old false-state
baseline pin. If it is not available, require the exact
approved pre-change workflow version and dry-run digest, issue a fresh approval
with a TTL of at most 45 seconds, parent binding `fwc-n8n://<server>` over the
exact high-level apply input, and a guard containing `approvalRef`, the pinned
`dryRunDigest`, and `idempotencyKey`; then apply once. After any apply result,
independently read the workflow and run a new dry-run readback.
Validate the returned receipt's target and internal digest consistency; the
post-change digest may differ from the pre-change pin. After a proven pre-write
read failure, continue only if evidence shows issuer and apply were not reached,
a scoped read-only GET succeeds, and the coordinator/reviewer explicitly
approves a new claim; preserve the old claim. An unknown apply or readback
outcome stops execution: preserve the claim and evidence, do not retry or
replay, and limit follow-up to read-only reconciliation.

For execution, obtain a fresh approval bound to the server, exact workflow and
version, manual mode, trigger, exact input, and current baseline. Keep FCP's
workflow-version binding in the approval and independent readback; do not add
provider `versionId` or `wait` arguments. Invoke `n8n.workflows.execute` once.
These checks bind the approval and readback to observed values; they do not
promise to eliminate provider-side time-of-check/time-of-use races.
Require a verified response with an execution ID, then issue a separate
`n8n.executions.get` using that execution ID and workflow ID. PASS requires the
readback to match the approved workflow version and manual mode and to show a
terminal successful status. A missing ID, mismatch, timeout, unknown result,
or failed readback is STOP; do not retry or infer that no execution occurred.

Any later MCP disable is a separate typed `desired: false` change with a fresh
approval and readback. Never silently restore availability, especially after
an unknown outcome. Teardown is complete only after owned child, cgroup, and
channel teardown succeeds before reporting success; the installed path uses
anonymous sockets and creates no mutable handshake state directory. Retained
receipts, claims, and fixtures are not cleanup targets. Do not gate this procedure on
the numeric package version; retain the operation-schema, approval, target,
workflow-version, and readback checks above.

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

## `.34` preparation, future read-only acceptance and recovery

The preparation artifact is an **unsigned binary/public-input set**, not an
installable RC. Build only the four runtime binaries from a clean reviewed
commit, using the existing assembler `build_one` arguments, SSD launcher and
dedicated release target. For this unsigned diagnostic compilation, the actual
mapped owner **public** metadata and its decoded SHA-256 identify the build input;
they do not prove trust. The decoded SHA-256 at this checkpoint is
`745a9236846ab0c9523a1f9ac884b740d1886725602af28ac59f94f0d12be12d`.
Never substitute the approval key or read a signing seed. `fwc-n8n status` checks
root-owned bundle hashes, not owner signatures. The follow-up `verify-current`
command verifies the signed full tree using the build-embedded owner public
configuration, with no runtime key/path override. Run it from the explicitly
reviewed build; RC40 does not itself expose this new command. Public mapping
identity does not independently establish the authority of that mapping.
The 2026-09-30 read-only follow-up verified RC40 with the mapped active key and
`signed_current` mode; provider/live acceptance and mandatory non-green static
analysis gates remain separate. Verification covers the signed artifact set,
receipt/provenance/bindings and safe expected directories, not an enumeration
of every unreferenced regular file beneath the release.

Normal assembly retains fixed `/var/lib/fwc-n8n/staging`, fresh official schema
bindings, reviewed originals for semantic profiles, isolated local discovery,
owner signing and provision preflight/promotion. Copied RC40 inventory/policy
is historical input, never fresh approval or proof of current provider semantics.
No signer/issuer, production receipt or provision request belongs in the unsigned
preparation set. Non-green Clippy/UBS evidence permits preparation, not release GO.

### Reproduced protected release route (RC43c, 2026-10-04)

This records the completed RC43c route, not permission to replay its occupied
paths. Reproducibility means exact source, argv, toolchain, dependencies, public
key/schema pins and actual artifact hashes. It does **not** promise identical
binaries across build environments. Runtime source is
`09cebc4aaa3c968f3704611325a005a3ced7a237`; helper-only commit
`e8bd22bc0f43deffa56b7fb6cf0105d255e234b6` is separate. The frozen preparation
packet `rc43c-new-source-admission-packet.json` has SHA-256
`0e228bf62f1af378949489ceda39031650831168f9fd754bc3311caa212e7a5c`.
Keep that observation unchanged and bind the owner's exact source/placement and
bounded residual-analysis decision in a separate admission record. The decision
applies only to this packet; UBS remains NON-GREEN, without a general waiver.

Before a privileged launch, seed request or any required native DCG exception,
complete **all available** checks and retain exact argv/exits/hash receipts:

- Pin the reviewed commit, Git bundle/archive and assembler/controller hashes;
  preserve the compile source separately from the integration snapshot. For
  RC43c, source bundle SHA-256 is
  `e29d4ae02a1a31783cd985b7a9c9c1427f9ae4ef15ea05afb177cc44df757f9a`,
  archive SHA-256 is
  `e5c61fb7159d16ddfcc5753f60baa3a264e476a991250cfc2961f0a557557a4c`,
  and assembler SHA-256 is
  `2442c35b32853f3d621ac2543dec24b5d4472ebfbf56fe342b015616f8685cb5`.
- Exercise the existing producer/consumer metadata boundary: exactly `schema`,
  `release_id`, `git_revision`, with unknown/duplicate fields rejected. Use
  assembler `--emit-release-provenance` and `--check-release-metadata`; compare
  admitted official input/output presence, raw native pins and reviewed profiles
  through `--check-official-baselines` before Cargo. Reuse source-bound evidence
  for the existing 20 producer cases and 38 serialized publication cases
  (66 native parent calls); these are not live acceptance or signing tests.
- Verify exact roots, required absence including virtual private destinations,
  owner/group/modes, current signed release/receipt, mapped public key, toolchain,
  all admitted cache/dependency inputs, outer/inner lock identities and scoped
  mount namespace/ancestor/descendant/propagation identities. Keep full mountinfo
  before/after tables. Unrelated mount changes are diagnostic; unknown or
  overlapping controlled changes deny. Revalidate under the same outer lock
  through the private child and mutations, not merely in an earlier probe.
- Evaluate the **exact literal** final command with native DCG. An actual ALLOW
  requires no invented allow-once. A DENY is a STOP: retain its native pending
  identity/command/cwd/expiry and obtain the owner's actual exception if needed;
  never transfer old grants, self-allow, disable the guard or rewrite the command
  to evade it. Checks needing the actual root/private child cannot be claimed
  completed offline or before that permitted operation.

Place reviewed sources only at new absent paths: exclusive creation, root0:0,
parent0700/file0600, no symlink or overwrite, file/directory fsync and SHA readback.
Clone the pinned bundle with fixed Git argv into its new protected source; leave
old protected sources and archives intact. Use an inspected **root-owned file**
entrypoint, never executable code piped into a root interpreter. The existing
ephemeral owner-seed **data** pipe/FD to the admitted signer stdin is separate:
no controller seed read, secret variable/environment/file/log, new key or issuer
replacement. Fixed public mapping/key8e7 and the approval key are distinct.

The reviewed file hashes are assembly
`746b079efa81044f79a765e3c26776af26c323623b5f98cb3adb175a20aacf6a`,
sign/preflight `519d6f010ee8756403c889afc95970ffebc4a79e6741a83503d813b19e3bb33b`,
and install `b347b5d7dffb86702115910bd8711f9eea659a614896cbcb57abb831242cd021`.

These are the actual direct commands for the recorded release; their exact paths
and O_EXCL receipts now exist, so they are evidence, **not retry commands**:

```bash
sudo -n env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C PYTHONNOUSERSITE=1 /usr/bin/python3 /root/fwc-n8n-rc43c-09cebc4aa/assembly.py assemble
sudo -n env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C PYTHONNOUSERSITE=1 /usr/bin/python3 /root/fwc-n8n-rc43c-09cebc4aa/sign-preflight.py --precheck
sudo -n env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C PYTHONNOUSERSITE=1 /usr/bin/python3 /root/fwc-n8n-rc43c-09cebc4aa/sign-preflight.py
sudo -n env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C PYTHONNOUSERSITE=1 /usr/bin/python3 /root/fwc-n8n-rc43c-09cebc4aa/install-once.py
```

Assembly retains normal Cargo freshness and all package checks, one SSD build at
a time, pinned FD/private MS_MOVE/readonly inputs and distinct locks. It produced
14 unsigned root-owned files; signing added the 15th `provision-receipt.json`.
Native official8/raw16 and local7 checks, owned static smoke and production
manifest tests passed. Actual normal host SHA-256
`b6ec76d4a22abc2aa46c252b179a208dbe3835b9d687f06d12f03b567fda9384`
differs from the diagnostic host; bind actual normal hashes, never promote a
diagnostic identity or old37936 provenance as new09ce evidence.

Keep these primary public packets under `/srv/dev-ssd/fcp/nqm81-34/` (their
protected originals and linked hashes remain authoritative):

| Boundary | Packet | SHA-256 |
|---|---|---|
| Actual unsigned review before seed | `rc43c-actual-unsigned-review-packet.json` | `5fd626deeb4609bef0ce9cfa836e87d8d8c8901c460ebf1decd006db6642f40b` |
| Root shared precheck0, signing and preflight | `rc43c-actual-signed-preflight-packet.json` | `95887247ae01bb12e7b370814c35592fd806e93111d7c1d0271193354d95b7a8` |
| Reviewed one-apply installed result | `rc43c-actual-installed-review-packet.json` | `609d597d8d36fad70716771f97a0a9a224445c62f54c876968b7ff16355f7f36` |
| Actual controlled publish/unpublish | `rc43c-controlled-publication-final-manifest.json` | `8243fc4b0eb88c32e1c889ae81fb587a590d6249b59d16c0d80f83fcb1f79eb5` |

Unsigned artifact review precedes a source-bound **actual root `--precheck` exit0**
with no helper/seed/childmount/sign/apply. Fresh validation then admits one signer
call and normal provision preflight, `currentChanged=false`. Signed/preflight and
exact install-operation review precede one native apply. The candidate wrapper
verified retained RC42 as `signed_rc42_lifecycle`; installed RC43c verifies as
`signed_current`, key8e7, signed receipt BLAKE3
`7cdcde12184f3ab3a205cd15a51653c7ad5d7519df9f8ea2a304b4fd4861fdab`.
Installed15, atomic stage promotion, retained RC42/41/40 and unchanged external
issuer were checked. Recovery **preflight only** used the actual RC43c receipt
against retained RC42/a3f1 with `currentChanged=false` and
`claimsLedgerRewound=false`; this is not a real rollback or permission to apply
recovery. Controlled publication used fresh per-write approvals and independent
GETs; it does not authorize arbitrary workflows or automatic schema enrollment.
Actual installed verification argv is
`/usr/local/lib/fwc-n8n/current/bin/fwc-n8n verify-current`. Recovery argv is the
same installed wrapper with `recovery --mode preflight`, reading only protected
`/root/fwc-n8n-rc43c-09cebc4aa/recovery-preflight.json` on stdin (SHA-256
`4c1ef4fbe37097f75443654dab23111645569f861379cfacd57bf53a13ef5af5`).

On a preparation refusal, preserve the original STOP, source/command correlation,
closed error code (unknown stays unknown), outputs and receipts. Localize the
proven defect and test the **whole remaining path** before a reviewed corrected
attempt or another required grant; never blind-retry mutations or rewrite FAIL
as PASS. The c88 late assembly failure remains failed. RC43b's lost signer stderr
remains unknown; later structural diagnosis does not reconstruct it. This route
changes no general security, trust or permission policy; future changes to those
require a separate owner decision.

Offline commands, run from the task checkout (no provider access):

```bash
bash scripts/e2e/n8n_acceptance_preflight.sh --self-test
bash scripts/e2e/n8n_acceptance_preflight.sh --read-only-self-test
bash scripts/e2e/n8n_acceptance_preflight.sh --actual-read-only-error-self-test /srv/dev-ssd/fcp/targets/n8n/debug/fwc-n8n
bash scripts/e2e/n8n_acceptance_preflight.sh --compatibility-self-test /srv/dev-ssd/fcp/targets/n8n/debug/fwc-n8n
```

Expected: pass JSON with `acceptance:false` (18 preflight, 26 projection cases,
one actual source-CLI error boundary and 7 compatibility cases).
The actual CLI test uses a source binary outside the installed release and must
fail bundle verification before provider/credential dispatch. It checks the real
serialized wrapper error and exact requested correlation, rather than a mock
error envelope. Happy projection fixtures are synthetic and prove no live success.
The compatibility producer test uses synthetic pins; it grants no approval.
Only after separate explicit authorization for installed/provider reads, use
the following commands before and after an independently approved installation.
Set execution/version variables to the exact owner-approved existing harmless
fixtures; do not create, execute or replay workflows to obtain them.

```bash
bash scripts/e2e/n8n_acceptance_preflight.sh --read-only-check local
bash scripts/e2e/n8n_acceptance_preflight.sh --read-only-catalog eec
bash scripts/e2e/n8n_acceptance_preflight.sh --read-only-catalog hetzner
bash scripts/e2e/n8n_acceptance_preflight.sh --read-only-check eec "$EEC_WORKFLOW_ID" "$EEC_EXECUTION_ID" "$EEC_WORKFLOW_VERSION_ID"
bash scripts/e2e/n8n_acceptance_preflight.sh --read-only-check hetzner "$HETZNER_WORKFLOW_ID" "$HETZNER_EXECUTION_ID" "$HETZNER_WORKFLOW_VERSION_ID"
```

Each command makes one wrapper invocation, with bounded framing/deadline and
no retry/fallback. Local knowledge requires successful owned-child teardown;
official discovery only lists tools and emits compact unreviewed schema hashes;
REST execution GET independently compares workflow/execution identity and
`workflowVersionId`, preserving
metadata-only semantics. Evidence contains static verdicts or validated names/
digests, never raw results, graphs, descriptions, headers or credentials.
Nonzero exit emits `read_only_probe_failed`, `read_only_projection_invalid` or
`readback_version_mismatch`; stop without repeating the call. This safe failure
does not prove dispatch certainty or successful teardown after a wrapper failure.
Wrapper failure evidence preserves only closed known codes and a syntactically
validated UUID correlation; arbitrary codes/descriptions are replaced, and raw
stderr is discarded. Malformed output falls back to a static safe failure.
It retains the actual wrapper/guard exit, approved diagnostic/RPC fields and
local result-code/teardown booleans. Local success binds both `local_mcp` provider
and `knowledge_query` operation. The local outer guard reads the fixed public
policy and adds startup + one request + twice shutdown + 20 seconds for framing
and margin (84 seconds for current 30s/30s/2s policy). Guard timeout has its own
static code and **unverified teardown**; it never produces PASS or retry.
Local success additionally requires exactly one object MCP tool result, absent
or boolean-false `isError`, and bounded nonempty text documentation content.
Completed process/teardown alone cannot accept a tool error or malformed result.
Retain command exits plus release/source/package/protocol hashes separately.
Two same-release runs are not an upgrade test; these reads cannot accept risky
write operations. Fresh reviewed schemas and operation-specific acceptance still
remain mandatory.

Retained recovery target:
`/usr/local/lib/fwc-n8n/releases/release-20260929-42a574a62-started-result-rc40`.
Keep its complete four binaries, two manifests, four inventories, two policies,
`receipt.json`, `provenance.json` and signed `provision-receipt.json` together.
The compatible external issuer is `/usr/local/sbin/fcp-n8n-approval-issue`, SHA-256
`48b8167603ffb98d10f9d8f53d981ec3e5031862bb3fc801901ce7866a340c4b`;
retain the associated public approval pin separately from owner trust. Read-only
recovery checks (not a restore or signature proof):

```bash
readlink -e /usr/local/lib/fwc-n8n/current
sha256sum /usr/local/lib/fwc-n8n/releases/release-20260929-42a574a62-started-result-rc40/receipt.json
sha256sum /usr/local/lib/fwc-n8n/releases/release-20260929-42a574a62-started-result-rc40/provision-receipt.json
sha256sum /usr/local/sbin/fcp-n8n-approval-issue /etc/fwc-n8n/approval-public-key
```

The reviewed follow-up CLI exposes `verify-current` and `recovery --mode
preflight|apply`. Recovery stdin is a closed four-field request. Obtain both
signed receipt BLAKE3 pins from verified retained trees; never choose a target
automatically or use an old receipt as a new installation approval. Example
command shapes below are future operator commands, not instructions to execute
real recovery during preparation:

```bash
/srv/dev-ssd/fcp/nqm81-34/followup-verifier-fwc-n8n verify-current
/srv/dev-ssd/fcp/nqm81-34/followup-verifier-fwc-n8n recovery --mode preflight < exact-owner-recovery.json
# Only AFTER reviewed artifact admission/install and separate exact-pair
# owner authorization; current RC40 does not expose this new command:
readlink -e /usr/local/lib/fwc-n8n/current/bin/fwc-n8n
sha256sum /usr/local/lib/fwc-n8n/current/bin/fwc-n8n
stat -c '%u:%g:%a:%F' /usr/local/lib/fwc-n8n/current
stat -Lc '%u:%g:%a:%F' /usr/local/lib/fwc-n8n/current/bin/fwc-n8n
# Stop unless these match the exact admitted artifact and safe root ownership/modes.
sudo -- /usr/local/lib/fwc-n8n/current/bin/fwc-n8n recovery --mode apply < exact-owner-recovery.json
```

The user-writable SSD diagnostic binary is permitted only for read-only checks
and isolated fixtures; never execute it as root for real recovery. Future apply
must use the exact reviewed/admitted root-owned wrapper from the existing
artifact/trust/install workflow. Immediately before execution, independently
match the installed wrapper's exact digest to that approved artifact and verify
the resolved file and pointer ownership/modes (owner/group 0, non-writable by
others, expected executable mode), including fixed current/release binding.
Do not substitute the diagnostic binary's digest or current RC40 admission for
approval of the new command. No new wrapper is installed during preparation.

`exact-owner-recovery.json` contains only `expected_current_release_id`,
`expected_current_receipt_blake3`, `target_release_id`, and
`target_receipt_blake3`. IDs are safe basenames under the fixed releases root;
pins are 64 lowercase hex BLAKE3 digests of the complete signed
`provision-receipt.json` bytes. Equal IDs, paths, unknown fields and key/policy/
owner overrides are rejected. Both signed trees and pins are verified before
planning and again under the same owner lock immediately before atomic rename.
Apply requires explicit owner/root intent for this exact pair; future real
apply requires separate owner authorization. The existing promotion plan's
rollback target restriction remains intact. No claims ledger is rewound; no
global numeric antirollback or replay protection is claimed. An error after
rename/fsync leaves the outcome unverified: re-read exact current pins, never
retry or claim restoration from the error alone.

Reproduce the nine synthetic CLI/assembler producer cases with the tracked
script, a reviewed source binary, and a fresh retained SSD evidence directory:

```bash
mkdir /srv/dev-ssd/fcp/nqm81-34/producer-replay-NEW
bash scripts/fcp_ssd.sh -- bash scripts/e2e/n8n_acceptance_preflight.sh \
  --producer-replay-self-test /path/to/reviewed/fwc-n8n \
  /srv/dev-ssd/fcp/nqm81-34/producer-replay-NEW
```

The script preserves synthetic serialized inputs and exact argv/exit/hash
receipts using exclusive creation. It invokes only schema projection/profile
and assembler offline catalog bindings, never discovery, signing or providers.
The separate `--recovery-parser-self-test /path/to/reviewed/fwc-n8n` mode runs
10 actual CLI refusals as an unprivileged user, including unknown fields,
paths, malformed pins, equal IDs, oversized/concatenated input and root-only
apply denial. It does not admit a real recovery request.
Unknown provider outcomes are reconciled independently, never replayed as rollback.

Integration composition is remote FCP `ee30a7e87424952b8e65645b8432bb821e567155`,
then `b53067c03a444d4dea4f309cd8998ec9bf2f385b` (model defaults),
`938a6511471b84374286b646b383da53a1a7a01d` (reviewed implementation),
`e1071b36d20b90c05e413644bd271b666082ea75` (coordinator Beads snapshot), then the
separately reviewed preparation documentation/script commit. Do not cherry-pick
the old plan JSONL or replace model defaults. VM integration independently uses
existing `5071855711bcdf4013a006a4ccfd4cca017214a4`, whose parent is verified remote
`c6e652ddee29b52fec11e9e5cd09e97203c96b61`; no VM edits are needed. Merge/push and
all installation/recovery actions require their separate authorization.
