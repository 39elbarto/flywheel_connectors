# CircleCI Connector V3 Contract

> **Status**: planning contract
> **Bead**: `flywheel_connectors-j05nu.4.2.1`
> **Unblocks**: `flywheel_connectors-j05nu.4.2.2`
> **Primary upstreams**:
> - https://circleci.com/docs/guides/toolkit/api-developers-guide/
> - https://circleci.com/docs/api/v2/
> - https://circleci.com/docs/guides/toolkit/managing-api-tokens/
> - https://circleci.com/docs/guides/orchestrate/triggers-overview/

## Purpose

This document fixes the first implementation slice for `fcp.circleci` so the follow-on runtime bead can converge on a stable contract instead of inventing CircleCI scope while coding.

The connector targets CircleCI API v2 as a request-response CI/CD control surface. The intended first slice is project discovery plus pipeline, workflow, and job inspection, with a narrow set of risky workflow and pipeline mutation flows.

## Current Runtime Snapshot

The current connector code already exposes these operations:

- `circleci.projects.list`
- `circleci.pipelines.list`
- `circleci.pipelines.get`
- `circleci.pipelines.trigger`
- `circleci.workflows.list`
- `circleci.workflows.get`
- `circleci.workflows.cancel`
- `circleci.workflows.rerun`
- `circleci.jobs.list`
- `circleci.jobs.get`
- `circleci.health`

The current manifest does not fully describe that runtime surface yet. It only declares a subset of the operations, so bead `flywheel_connectors-j05nu.4.2.2` must reconcile manifest and runtime before the connector can claim a truthful V3 implementation.

## First-Slice Scope

The first CircleCI slice is intentionally narrow:

- Read the authenticated user’s accessible projects through `GET /me/collaborations`.
- List and inspect pipelines.
- Trigger a pipeline run for a known project slug.
- List and inspect workflows associated with a pipeline.
- Cancel and rerun workflows.
- List jobs for a workflow and inspect a specific job by project slug and job number.
- Run a simple health probe against `GET /me`.

The connector is `operational` and effectively stateless aside from configuration and retry/runtime wiring.

## Auth And Scope Boundary

- CircleCI API v2 supports personal API tokens, not project tokens.
- The connector authenticates with the `Circle-Token` header and inherits the full read/write authority of that user token.
- The public config contract is one `api_token`, plus `base_url`, retry policy, and bounded request timeout.
- `base_url` defaults to `https://circleci.com/api/v2`. For CircleCI Server, the docs explicitly allow replacing `https://circleci.com` with the server hostname.
- The connector instance is user-scoped, not project-scoped. It can operate on any project the token can access unless a future allowlist is added.
- Project-targeted operations require an explicit `project_slug`.
- CircleCI documents `project_slug` as `vcs-slug/org-name/repo-name`; for GitLab and GitHub App projects the `vcs-slug` becomes `circleci`, with org and project IDs instead of human-readable names.
- The current implementation implicitly tolerates an empty token as a secretless proxy-injection mode, but that is an implementation detail, not a stable public auth contract yet.

## Network And Runtime Invariants

- Base API host: `circleci.com` by default, or a configured CircleCI Server host.
- Base path: `/api/v2`
- Port: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- No cross-host redirects
- API v2 responses may return `429` with `Retry-After`; the runtime must honor that header.
- The connector’s default request timeout is `30_000 ms`.
- `project_slug` is the only path input that legitimately contains `/`; all other IDs are single path segments and should remain sanitized accordingly.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `circleci.projects.read` | Discover projects visible to the authenticated user |
| `circleci.pipelines.read` | List or inspect pipelines |
| `circleci.pipelines.write` | Trigger pipeline runs |
| `circleci.workflows.read` | List or inspect workflows |
| `circleci.workflows.write` | Cancel or rerun workflows |
| `circleci.jobs.read` | List workflow jobs and inspect specific jobs |

## Operation Inventory

| Operation | Endpoint | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------|------------|------------|-----------|-------------|-----------|
| `circleci.projects.list` | `GET /me/collaborations` | `circleci.projects.read` | `Safe` | `Low` | `None` | Read-only discovery of projects the authenticated user can act on. |
| `circleci.pipelines.list` | `GET /project/{project_slug}/pipeline` | `circleci.pipelines.read` | `Safe` | `Low` | `None` | Read-only pipeline enumeration within a known project boundary. |
| `circleci.pipelines.get` | `GET /pipeline/{pipeline_id}` | `circleci.pipelines.read` | `Safe` | `Low` | `None` | Read-only point lookup for a pipeline UUID. |
| `circleci.pipelines.trigger` | `POST /project/{project_slug}/pipeline` | `circleci.pipelines.write` | `Risky` | `High` | `BestEffort` | Triggering a pipeline creates real CI/CD work and can fan out into deployments or external side effects. Repeated requests can create duplicate runs. |
| `circleci.workflows.list` | `GET /pipeline/{pipeline_id}/workflow` | `circleci.workflows.read` | `Safe` | `Low` | `None` | Read-only enumeration of workflows belonging to a pipeline. |
| `circleci.workflows.get` | `GET /workflow/{workflow_id}` | `circleci.workflows.read` | `Safe` | `Low` | `None` | Read-only workflow inspection. |
| `circleci.workflows.cancel` | `POST /workflow/{workflow_id}/cancel` | `circleci.workflows.write` | `Risky` | `Medium` | `Strict` | Canceling a running workflow is a real state mutation but retries are naturally bounded once the workflow stops running. |
| `circleci.workflows.rerun` | `POST /workflow/{workflow_id}/rerun` | `circleci.workflows.write` | `Risky` | `High` | `BestEffort` | Reruns create new execution. The API supports richer rerun options than the current connector exposes, and duplicate reruns are possible. |
| `circleci.jobs.list` | `GET /workflow/{workflow_id}/job` | `circleci.jobs.read` | `Safe` | `Low` | `None` | Read-only job enumeration inside a workflow. |
| `circleci.jobs.get` | `GET /project/{project_slug}/job/{job_number}` | `circleci.jobs.read` | `Safe` | `Low` | `None` | Read-only inspection of a specific job. |
| `circleci.health` | `GET /me` | `circleci.projects.read` | `Safe` | `Low` | `Strict` | Deterministic auth/reachability probe used for configure, doctor, and self-check. |

## Explicit Non-Goals

The first implementation slice does not include these provider surfaces:

- job cancellation by job ID or job number
- job artifacts and test metadata
- pipeline continuation, pipeline config inspection, or pipeline values
- project CRUD, project settings, checkout keys, and environment variables
- approvals for approval jobs
- contexts, policies, usage exports, org-level administration, groups, or rollback
- webhook management
- trigger-definition APIs and schedule APIs
- Insights and usage analytics
- SSH rerun controls, sparse-tree reruns, or rerunning selected jobs only

These are excluded on purpose:

- The first slice should stabilize execution control, not workspace administration.
- Artifact, test, and insights surfaces are useful, but they are downstream observability features rather than core workflow control.
- Schedule and trigger-definition APIs introduce extra project-type branching and deployment semantics that are orthogonal to the minimal CI/CD operator workflow.
- The richer rerun and approval APIs expand mutation semantics beyond what the current connector models safely.

## Implementation Notes For `flywheel_connectors-j05nu.4.2.2`

- Reconcile manifest and runtime so every exposed operation is declared truthfully with typed schemas.
- Fix the current drift between runtime idempotency semantics and actual provider behavior, especially for pipeline trigger and workflow rerun.
- Decide whether the recommended `pipeline/run` trigger endpoint should replace or supplement the current `POST /project/{project_slug}/pipeline` path for supported project types.
- Make the auth contract explicit: either keep pure `api_token` mode or formalize secretless credential injection as a first-class config surface.
- `doctor()` and `self_check()` should report token validity, server-host policy, project-slug expectations, and rerun/cancel caveats explicitly.
- Tests should cover project slug variants, `429 Retry-After`, unauthorized token handling, workflow mutation duplication hazards, and CircleCI Server `base_url` overrides.

## Source Notes

This contract is grounded in CircleCI’s official docs:

- API v2 is personal-token based and uses the `Circle-Token` header.
- The provider documents user, pipeline, job, workflow, project, trigger, schedule, insights, and other categories beyond the current connector slice.
- `GET /me/collaborations` is the correct project discovery surface for user-visible collaborations.
- Workflow rerun supports richer options like `enable_ssh`, `jobs`, and `sparse_tree`, but the current connector intentionally exposes only `from_failed`.
- CircleCI documents multiple `project_slug` forms, including `circleci/<org-id>/<project-id>` for GitLab and GitHub App projects.
