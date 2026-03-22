# Hacker News Connector V3 Contract

> **Status**: planning contract
> **Bead**: `flywheel_connectors-j05nu.8.2.1`
> **Unblocks**: `flywheel_connectors-j05nu.8.2.2`
> **Primary upstream**: Hacker News Firebase API at `https://github.com/HackerNews/API`

## Purpose

This document fixes the first implementation slice for `fcp.hackernews` so the follow-on runtime bead can converge on a stable contract rather than conflating the public Firebase API with other Hacker News data sources such as Algolia search, HTML scraping, or authenticated YC workflows.

The connector is a public, read-only Hacker News Firebase API client for item lookup, user lookup, ranked story feeds, and health checking.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `hackernews.item.get`
- `hackernews.user.get`
- `hackernews.top_stories`
- `hackernews.new_stories`
- `hackernews.best_stories`
- `hackernews.ask_stories`
- `hackernews.show_stories`
- `hackernews.job_stories`
- `hackernews.health`

Important runtime truths that the contract must preserve:

- Authentication is optional because the Firebase API surface used here is public.
- Configuration is only `base_url`, retry policy, and `request_timeout_ms`.
- The default API root is `https://hacker-news.firebaseio.com/v0`.
- `base_url` is overrideable, which is useful for tests or mirrors, but the production contract is the Firebase host.
- `item.get` returns raw Hacker News items by numeric ID and covers stories, comments, jobs, polls, and poll options.
- `item.get` treats Firebase `null` responses as not found.
- Feed operations return numeric IDs only. They do not expand stories into full item payloads.
- `top_stories`, `new_stories`, and `best_stories` can return up to 500 IDs from the provider; `ask_stories`, `show_stories`, and `job_stories` can return up to 200.
- The optional `limit` parameter is applied locally after the feed response is fetched.
- `health` uses the top-stories endpoint as a reachability probe.
- The connector exposes no streaming, replay, or write surface.

## First-Slice Scope

The first Hacker News slice is intentionally narrow:

- Read a single item by numeric ID.
- Read a single user profile by username.
- Read ranked story feed IDs from the public Firebase API.
- Read category-specific Ask HN, Show HN, and Jobs feed IDs.
- Verify API reachability and rate-limit behavior through a health probe.

This slice is intentionally closer to "typed public API mirror" than to "full Hacker News product surface."

## Service Inventory

| Surface | Status in first slice | Notes |
|---------|-----------------------|-------|
| Item lookup | In scope | Reads a single story, comment, job, poll, or poll option by numeric ID. |
| User lookup | In scope | Reads a single public user profile by username. |
| Ranked feeds | In scope | Top, new, best, Ask, Show, and Jobs feed ID lists are implemented. |
| Comments | Partial | Comments are reachable through `item.get`, but there is no recursive thread expansion or tree flattening operation. |
| Search | Out of scope | No Algolia-backed search or query surface exists in the current connector. |
| Writes | Out of scope | No submit, vote, favorite, login, reply, or moderation operations exist. |
| Streaming | Out of scope | No event feed, websocket, polling subscription, or replay surface exists. |

## Auth And Scope Boundary

- There is no external auth flow in the first slice.
- The connector's trust boundary is the configured base URL, the public-zone policy, and the single `hackernews.read` capability.
- All exposed operations require only `hackernews.read`.
- Usernames are sanitized before being inserted into the request path and must not contain `/`, `\\`, `..`, or null bytes.
- Numeric item IDs are the stable primary identifiers for item retrieval.
- The manifest is public/read-only oriented: home zone is `z:public`, allowed sources are `z:public` and `z:work`, allowed targets are `z:public`, required capabilities are `network.dns` and `network.outbound`, and forbidden capabilities include `system.exec` and `system.privileged`.

## Network And Runtime Invariants

- Production host: `hacker-news.firebaseio.com`
- Default path prefix: `/v0`
- Port: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- `deny_tailnet_ranges = true`
- `deny_ip_literals = true`
- `max_redirects = 2`
- Default request timeout is `30_000 ms`
- Runtime uses retry-aware GET logic for normal data fetches, including `429` handling with `Retry-After`
- `health` is a lighter direct GET probe against `topstories.json`

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `hackernews.read` | Read public items, users, feed ID lists, and API health |

## Operation Inventory

| Operation | Provider endpoint target | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|--------------------------|------------|------------|-----------|-------------|-----------|
| `hackernews.item.get` | `GET /item/{id}.json` | `hackernews.read` | `Safe` | `Low` | `Strict` | Deterministic point read of a single public item ID. |
| `hackernews.user.get` | `GET /user/{username}.json` | `hackernews.read` | `Safe` | `Low` | `Strict` | Deterministic point read of one public user profile. |
| `hackernews.top_stories` | `GET /topstories.json` | `hackernews.read` | `Safe` | `Low` | `None` | Read-only ranked feed snapshot returning story IDs only. |
| `hackernews.new_stories` | `GET /newstories.json` | `hackernews.read` | `Safe` | `Low` | `None` | Read-only newest-stories snapshot returning IDs only. |
| `hackernews.best_stories` | `GET /beststories.json` | `hackernews.read` | `Safe` | `Low` | `None` | Read-only best-stories snapshot returning IDs only. |
| `hackernews.ask_stories` | `GET /askstories.json` | `hackernews.read` | `Safe` | `Low` | `None` | Read-only Ask HN feed snapshot returning IDs only. |
| `hackernews.show_stories` | `GET /showstories.json` | `hackernews.read` | `Safe` | `Low` | `None` | Read-only Show HN feed snapshot returning IDs only. |
| `hackernews.job_stories` | `GET /jobstories.json` | `hackernews.read` | `Safe` | `Low` | `None` | Read-only Jobs feed snapshot returning IDs only. |
| `hackernews.health` | `GET /topstories.json` | `hackernews.read` | `Safe` | `Low` | `Strict` | Reachability and rate-limit probe for the public Firebase API. |

## Explicit Non-Goals

The first Hacker News slice does not include these surfaces:

- Algolia search or relevance-ranked query APIs
- authenticated user actions such as submit, vote, favorite, reply, or login
- HTML scraping of `news.ycombinator.com`
- recursive comment-tree expansion or denormalized thread rendering helpers
- item batching, feed enrichment, or automatic expansion from IDs into full story payloads
- moderation, admin, or YC-internal workflows
- streaming subscriptions, polling cursors, or live-update delivery

These are excluded on purpose:

- The current connector does not implement them.
- The public Firebase API is small and stable, which makes it a good first truthful slice.
- Mixing Firebase reads with Algolia or scraped HTML would create a muddled contract with inconsistent semantics and failure modes.

## Implementation Notes For `flywheel_connectors-j05nu.8.2.2`

- Keep the first slice anchored to the Firebase API unless there is an explicit contract revision that adds Algolia as a separate surface.
- Preserve the current distinction between point reads and feed snapshots: feed operations return IDs only, and `item.get` is the expansion primitive.
- Keep username path sanitization mechanical and conservative.
- Preserve retry-aware handling for ordinary fetches and explicit `429 Retry-After` treatment.
- Revisit the current idempotency split intentionally if needed, but keep manifest and runtime aligned if semantics change.
- Tests should cover base URL override behavior, `null` item handling, username sanitization, rate-limit classification, feed limiting, and self-check degradation for retryable failures.

## Readiness And Verification

The readiness closeout for `flywheel_connectors-j05nu.8.2.3` treats Hacker News as a lightweight public-data connector. `health`, `doctor`, and `self_check` should therefore all emit the same operator-facing truths:

- verification is replayed through `scripts/e2e/hackernews_connector_verification.sh`
- evidence artifacts land under `artifacts/e2e/hackernews_connector/<timestamp>`
- the connector is intentionally read-only and public-scope
- search, writes, moderation, and streaming remain out of scope even when the upstream product offers adjacent surfaces elsewhere

### Operator Guidance

- Prefer the public Firebase API or a localhost mock override when rerunning verification.
- If `base_url` is overridden for tests, capture the override in the artifact bundle and keep it on `hacker-news.firebaseio.com` or `localhost`.
- Treat copied item text and user `about` fields as potentially sensitive when sharing artifacts outside the owning team.
- If `self_check` reports `self_check_retryable`, wait for upstream recovery or relax retry and timeout settings before rerunning.
- If `self_check` reports `self_check_failed`, verify that the configured `base_url` still points at a Firebase-compatible Hacker News endpoint.

### Replay Commands

The verification script is the canonical entry point. It replays the same checks a future agent should expect to rerun:

```bash
scripts/e2e/hackernews_connector_verification.sh
```

It captures:

- manifest validation evidence
- readiness and doctor guidance evidence
- successful and retryable self-check evidence
- a token-gated `hackernews.item.get` invoke artifact
- introspection compliance evidence
- targeted integration, crate, and clippy logs

## Source Notes

This contract is grounded in the current connector implementation and manifest:

- `connectors/hackernews/src/client.rs` defines the Firebase endpoint paths, retry behavior, username sanitization, `null` item handling, and health probe behavior.
- `connectors/hackernews/src/connector.rs` defines the public config surface, the single read-capability boundary, and the runtime `OperationInfo` metadata.
- `connectors/hackernews/manifest.toml` defines the public-zone network policy and read-only connector posture.
