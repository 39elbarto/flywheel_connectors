# Test Coverage Inventory and Acceptance Gap Matrix

> Generated: 2026-03-23 | Beads: `flywheel_connectors-49z0b.1`, `flywheel_connectors-49z0b.16.1`
>
> This document supersedes the 2026-01-27 snapshot. It is based on a live scan of
> the current repository tree on 2026-03-23 and is intended to be the planning
> baseline for the testing-completeness program.
>
> Read this inventory together with `docs/V3_Connector_Acceptance_Contract.md`
> Section 6, which defines the normative suite taxonomy and the archetype-by-
> archetype acceptance minimums this matrix is meant to drive.
>
> Addendum: the row-level `Unit`, `NoMock`, and `E2E` cells below remain useful
> as raw scan provenance, but bead `flywheel_connectors-49z0b.16.1` found that
> those legacy columns do not map 1:1 onto the closed suite classes from the V3
> contract. The addendum sections below supersede any contradictory reading of
> those legacy columns until `flywheel_connectors-49z0b.15.1` lands an automated
> suite-class scanner.

## Scope and Interpretation

This matrix covers:

- every current connector directory under `connectors/`
- every current workspace crate under `crates/`
- crate-local unit test signals from `src/**/*.rs`
- crate-local integration test surfaces from `tests/**/*.rs`
- mock or fake reliance signals (`wiremock`, `MockServer`, `MockApiServer`, fixture-driven harnesses)
- `no_mock_integration.rs` presence
- host-backed or subprocess-oriented test signals
- `fcp-e2e` coverage signals
- logging or replay-bundle validation signals
- documented live or provider prerequisites from connector README files

Interpret the columns as follows:

- `Unit`: inline or source-adjacent test signal exists.
- `Int`: a crate-local `tests/` surface exists.
- `Mock`: the current verification path relies on mock servers, fake fixtures, or similar doubles.
- `NoMock`: a `no_mock_integration.rs`-style suite exists.
- `Host`: explicit host-backed or subprocess-oriented verification signal exists.
- `E2E`: connector is covered by `crates/fcp-e2e/tests/*`.
- `Logs`: explicit replay/log/report evidence exists through `fcp-e2e`, `fcp-testkit`, `fwc`, or a documented verification bundle.
- `Live`: the best current non-mock prerequisite signal from the connector README.

For this program, the repository currently has two materially different kinds of confidence:

- `Deterministic contract coverage`: unit tests, crate-local integration tests, and `fcp-e2e` suites driven by mocks or local harnesses.
- `True non-mock acceptance`: `no_mock_integration.rs`, host-backed live verification, or documented verification bundles that require real providers, local devices, or real operator setup.

The most important conclusion from the live scan is that connector coverage is still overwhelmingly in the first bucket.

## Closed Suite Reclassification Addendum

This addendum is the current planning source of truth for `pure_unit`,
`deterministic_contract`, `local_non_mock`, `host_e2e`, and `live`
classification. It exists because the original `.1` scan answered "what test
surfaces exist?" while bead `.16.1` had to answer the stricter question "which
suite class do those surfaces actually belong to under Section 6 of the V3
contract?"

### Reclassification Rules Applied Here

| Existing Signal | Reclassified Meaning |
| --- | --- |
| `src/**/*.rs` tests with no mock or fake imports | `pure_unit` signal |
| `src/**/*.rs` tests with non-comment `wiremock`, `Mock*`, or `Fake*` code signals for boundary peers | `pure_unit` contamination; the file mixes in fake-backed boundary behavior and does not count as a clean unit floor |
| `tests/integration.rs` or `*_compliance_e2e.rs` that still import mock infrastructure | `deterministic_contract`, not `host_e2e` or `live` |
| `tests/no_mock_integration.rs` that still import mocks, fake clients, or fake verifiers | naming violation; currently `deterministic_contract` until a real non-fake boundary exists |
| `tests/no_mock_integration.rs` with no fake signal in the file | provisional `local_non_mock`, pending deeper semantic audit in later beads |

### Current Reclassification Findings

- Connectors with some source-adjacent `#[cfg(test)]` signal: `143/149`. Six scaffolds have zero `src/` tests: `firecrawl`, `huggingface`, `perplexity-search`, `tlon`, `zalo`, `zalouser`.
- Connectors with a clean source-adjacent `pure_unit` floor: `81/149`.
- Connectors with inline mock leakage in `src/**/*.rs`: `62/149`.
- Workspace crates with some source-adjacent `#[cfg(test)]` signal: `27/28`.
- Workspace crates with a clean source-adjacent `pure_unit` floor: `15/28`.
- Workspace crates with inline mock leakage in `src/**/*.rs`: `12/28`.
- Workspace crates with `tests/no_mock_integration.rs`: `18/28`, but `3` of those suites are currently misnamed under the V3 contract.
- `crates/fcp-e2e/tests` currently contains `87` suite files, and `79/87` of them still import `wiremock`, `MockServer`, or `MockApiServer`; `fcp-e2e` presence therefore currently means "connector is covered by a deterministic contract harness" unless the individual file crosses a real host or provider boundary.
- The crate leakage inventory below now ignores comment-only mentions, so prose such as `fcp-async-core`'s runtime-compatibility notes about `wiremock` no longer inflates the suite counts.

### Pure-Unit Floor Gaps and Leakage Inventory

#### Crates With No Source-Adjacent `pure_unit` Signal

- `fcp-async-core-macros`

#### Crates With Inline Mock Leakage in `src/**/*.rs`

The 12 crates below have mock or fake references inside `#[cfg(test)]` modules
in their `src/` files.  They split into two sub-categories that matter for
downstream remediation (verified 2026-03-23):

**wiremock library leakage** (real HTTP mock servers in inline tests — these
tests are clearly `deterministic_contract`, not `pure_unit`):

- `fcp-oauth` — wiremock in `src/oauth2.rs` tests (OAuth token exchange flows)
- `fcp-webhook` — wiremock in `src/provider.rs` tests (webhook registration)
- `fcp-google-discovery` — wiremock in `src/lib.rs` tests (Google API flows)
- `fcp-testkit` — wiremock in `src/mock_server.rs` (by design; test infra crate)
- `fcp-e2e` — wiremock in `src/lib.rs` (by design; E2E harness crate)
- `fwc` — wiremock references in `src/new_cmd.rs` and `src/doc_playbooks.rs`
  (scaffold templates, not live test boundary crossings)

**Local trait-mock leakage** (in-memory Mock* structs implementing internal
traits — no external network/daemon boundary crossed, but still not `pure_unit`
under strict V3 Section 6a reading):

- `fcp-core` — `MockProvisioner` in `src/provisioning.rs`, `fake_token` helpers
  in `src/provenance.rs`
- `fcp-bootstrap` — `MockTokenProvider` in `src/hardware_token.rs`
- `fcp-conformance` — `MockConnector`, `MockClock` in `src/compliance.rs` and
  `src/harness.rs`
- `fcp-registry` — `MockTransparencyVerifier`, `MockTufVerifier`,
  `MockSigstoreVerifier` in `src/lib.rs`
- `fcp-sandbox` — `MockInjector` in `src/egress.rs`
- `fcp-tailscale` — `MockTailscaleClient` in `src/client.rs`

**Downstream guidance for `49z0b.7.1`**: wiremock-leaking crates (`fcp-oauth`,
`fcp-webhook`, `fcp-google-discovery`) need mock extraction to separate
`deterministic_contract` suites from `pure_unit` logic.  `fcp-testkit` and
`fcp-e2e` are test infra by design and do not need remediation.  `fwc` has
template references only, not live leakage.  Local-trait-mock crates are lower
priority: the test doubles exercise in-process logic and may legitimately
remain inline as `pure_unit` helpers if the trait boundary is internal-only.

#### Connectors With Inline Mock Leakage in `src/**/*.rs`

- `airtable`, `anthropic`, `azure`, `browser`, `calendly`, `circleci`, `coda`, `confluence`, `deepgram`, `dingtalk`, `discord`, `feishu`, `figma`, `firebase`, `github`, `gmail`, `google-ai`, `google-chat`, `google-docs`, `google-places`, `google-sheets`, `google-workspace-events`, `hackernews`, `hue`, `imessage`, `jira`, `line`, `linear`, `mastodon`, `matrix`, `microsoft365`, `nextcloud-talk`, `notion`, `openai`, `package-registry`, `paypal`, `pinecone`, `plaid`, `postgresql`, `qdrant`, `qq`, `redis`, `s3`, `signal`, `slack`, `sonos`, `square`, `stripe`, `synology-chat`, `teams`, `telegram`, `twilio`, `twitch`, `twitter`, `vercel`, `wecom`, `whatsapp`, `whisper`, `wolfram`, `youtube`, `zendesk`, `zoom`

### Per-File Mock Leakage Map (Verified 2026-03-23)

This table identifies every `src/` file containing `wiremock`, `MockServer`, or
`MockApiServer` imports inside `#[cfg(test)]` blocks. Downstream beads should
use this to decide, per connector, whether to extract pure-unit tests into a
clean module or to rename the contaminated module as `deterministic_contract`.

| Connector | Leaking `src/` Files | Total `src/` Tests | Leaking `tests/` Files |
| --- | --- | --- | --- |
| `airtable` | `client.rs` | 554 | `integration.rs` |
| `anthropic` | `client.rs`, `connector.rs` | 183 | `v3_lifecycle.rs`, `integration.rs` |
| `azure` | `client.rs` | 69 | `integration.rs` |
| `browser` | `client.rs` | 185 | `integration.rs` |
| `calendly` | `client.rs` | 52 | `integration.rs` |
| `circleci` | `client.rs`, `connector.rs` | 43 | — |
| `coda` | `client.rs` | 57 | `integration.rs` |
| `confluence` | `client.rs` | 44 | — |
| `deepgram` | `connector.rs` | 3 | — |
| `dingtalk` | `client.rs`, `connector.rs` | 62 | — |
| `discord` | `client.rs`, `connector.rs`, `api.rs` | 180 | `integration.rs` |
| `feishu` | `client.rs` | 68 | `integration.rs` |
| `figma` | `client.rs` | 227 | `integration.rs` |
| `firebase` | `client.rs`, `connector.rs` | 10 | `integration.rs` |
| `github` | `client.rs` | 187 | `integration.rs` |
| `gmail` | `connector.rs` | 155 | `integration.rs` |
| `google-ai` | `client.rs`, `connector.rs` | 182 | `integration.rs` |
| `google-chat` | `connector.rs` | 72 | — |
| `google-docs` | `connector.rs` | 70 | — |
| `google-places` | `client.rs` | 15 | `integration.rs` |
| `google-sheets` | `connector.rs` | 51 | — |
| `google-workspace-events` | `connector.rs` | 14 | — |
| `hackernews` | `client.rs` | 47 | `integration.rs` |
| `hue` | `client.rs` | 7 | `integration.rs` |
| `imessage` | `connector.rs` | 65 | — |
| `jira` | `client.rs` | 225 | `integration.rs` |
| `line` | `client.rs` | 52 | `integration.rs` |
| `linear` | `client.rs` | 205 | `integration.rs` |
| `mastodon` | `client.rs` | 44 | — |
| `matrix` | `client.rs`, `connector.rs` | 53 | — |
| `microsoft365` | `client.rs`, `connector.rs` | 635 | `integration.rs` |
| `nextcloud-talk` | `connector.rs` | 22 | — |
| `notion` | `client.rs` | 177 | `integration.rs` |
| `openai` | `client.rs` | 166 | `integration.rs` |
| `package-registry` | `client.rs` | 11 | `integration.rs` |
| `paypal` | `client.rs`, `connector.rs` | 80 | — |
| `pinecone` | `client.rs` | 167 | `integration.rs` |
| `plaid` | `client.rs`, `connector.rs` | 191 | `integration.rs` |
| `postgresql` | `lib.rs` | 187 | — |
| `qdrant` | `client.rs`, `connector.rs` | 161 | `integration.rs` |
| `qq` | `client.rs` | 86 | — |
| `redis` | `lib.rs` | 171 | — |
| `s3` | `client.rs`, `error.rs` | 175 | `integration.rs` |
| `signal` | `bridge.rs`, `client.rs`, `connector.rs` | 109 | — |
| `slack` | `connector.rs` | 172 | `integration.rs` |
| `sonos` | `client.rs` | 3 | — |
| `square` | `connector.rs` | 53 | `integration.rs` |
| `stripe` | `client.rs` | 181 | `integration.rs` |
| `synology-chat` | `client.rs` | 29 | `integration.rs` |
| `teams` | `client.rs`, `connector.rs` | 73 | — |
| `telegram` | `client.rs`, `connector.rs` | 218 | `integration.rs` |
| `twilio` | `client.rs` | 185 | `integration.rs` |
| `twitch` | `client.rs` | 42 | — |
| `twitter` | `client.rs`, `connector.rs` | 336 | `integration.rs` |
| `vercel` | `client.rs`, `client/env_vars.rs`, `client/domains.rs`, `client/projects.rs`, `client/deployments.rs` | 28 | — |
| `wecom` | `client.rs`, `connector.rs` | 29 | — |
| `whatsapp` | `client.rs` | 86 | `integration.rs` |
| `whisper` | `lib.rs` | 161 | — |
| `wolfram` | `client.rs`, `connector.rs` | 24 | — |
| `youtube` | `client.rs` | 176 | `integration.rs` |
| `zendesk` | `client.rs` | 606 | `integration.rs` |
| `zoom` | `connector.rs` | 49 | `integration.rs` |

**Leakage pattern summary**: The dominant leak vector is `client.rs` (47/62
connectors), where HTTP client tests naturally use `wiremock` to verify request
construction. The secondary vector is `connector.rs` (24/62), typically for
`doctor`, `self_check`, or lifecycle tests that spin up a `MockServer`. Only
`vercel` has leakage across more than three files.

**Remediation guidance for downstream beads**:
- **client.rs leaks**: In most connectors these are testing HTTP request
  construction and response parsing. The mock-backed tests should be moved to
  `tests/integration.rs` (or renamed as `deterministic_contract`). Pure struct
  serialization and error mapping tests should remain in `src/`.
- **connector.rs leaks**: Lifecycle and doctor tests often need a mock server.
  Extract them to `tests/` and leave only config parsing, operation info, and
  error mapping tests as `pure_unit`.

### Naming Violations: `no_mock_integration.rs` That Are Not Actually Non-Mock

- `crates/fcp-streaming/tests/no_mock_integration.rs` is currently `deterministic_contract`, not `local_non_mock`, because the file explicitly documents "SSE streaming via wiremock" and imports `wiremock::{Mock, MockServer, ResponseTemplate}`.
- `crates/fcp-tailscale/tests/no_mock_integration.rs` is currently `deterministic_contract`, not `local_non_mock`, because it exercises `MockTailscaleClient` rather than a real daemon or local mesh boundary.
- `crates/fcp-registry/tests/no_mock_integration.rs` is currently mixed and cannot honestly keep the current name as-is, because the file uses `MockTransparencyVerifier`, `MockTufVerifier`, and `MockSigstoreVerifier` for parts of the verification path even though other portions are real in-memory crypto and store flows.

### Backlog-Ready Downstream Consumers

- `flywheel_connectors-49z0b.16.2` should consume the per-file mock leakage
  map (62 connectors, dominated by `client.rs` leaks) plus the 79 mock-backed
  `fcp-e2e` compliance suites and split them into "pure unit extraction" vs
  "deterministic contract rename" work.  The leakage map table above gives
  exact file names and test counts per connector.
- `flywheel_connectors-49z0b.16.3` should consume the `fcp-streaming` and
  `fcp-tailscale` naming violations plus the bridge, daemon, browser, and
  local-platform connectors that need truthful `local_non_mock` or `host_e2e`
  evidence.
- `flywheel_connectors-49z0b.7.1` should consume the crate-level inline-mock
  leaks split into two tiers: (a) the 3 crates with wiremock library leakage
  (`fcp-oauth`, `fcp-webhook`, `fcp-google-discovery`) that need mock
  extraction to separate suites, and (b) the 6 crates with local trait-mock
  leakage that may legitimately keep inline test doubles for internal-only
  trait boundaries.  Also addresses the `fcp-async-core-macros` unit-floor gap.
- `flywheel_connectors-49z0b.15.1` should consume this entire inventory to
  build an automated suite-class scanner that replaces manual file-level
  classification.

## Executive Summary

- Current tree size: 149 connector directories and 28 workspace crates.
- Connector source-adjacent test signal exists in 149/149 connectors, but only 87/149 currently present a clean `pure_unit` floor.
- Connector crate-local `tests/` coverage exists in 100/149 connectors.
- Connector `fcp-e2e` coverage exists in 84/149 connectors.
- Connector `no_mock_integration.rs` coverage exists in 0/149 connectors.
- Inline mock leakage exists in 62 connector crates and 12 workspace crates (of which 3 crates have wiremock library leakage needing extraction, 3 are test infra by design, and 6 have local trait-mock leakage that is lower priority).
- Workspace `no_mock_integration.rs` coverage exists in 18/28 crates, but 3 of those suites are misnamed and still belong to `deterministic_contract`.
- Documented connector verification bundles exist in 8 connectors: `calendly`, `coda`, `feishu`, `hackernews`, `line`, `obsidian`, `square`, `zoom`.
- Host-backed connector references exist for only 10 connectors: `browser`, `discord`, `exa`, `github`, `line`, `make`, `matrix`, `openai`, `signal`, `slack`.
- Logging or replay-bundle evidence exists for 92/149 connectors.
- `fcp-e2e` presence is not acceptance evidence by itself today: 79/87 `crates/fcp-e2e/tests` suites still import mock infrastructure.
- High-risk connector gaps are concentrated in:
- 10 connectors with only source-adjacent or otherwise pre-acceptance coverage and still no truthful acceptance path.
- 36 connectors that are effectively unit-only and have no acceptance path.
- 12 connectors with crate-local integration tests but no `fcp-e2e` coverage and no documented live bundle.
- 8 stateful ingress connectors with no `fcp-e2e` or live-proof path.

## Planning Priorities

### P0: Pre-Acceptance Connectors Still Missing a Truthful Boundary

These connectors still have no crate-local integration tests, no `fcp-e2e`
coverage, and no documented live bundle. Some now have source-adjacent
`#[cfg(test)]` coverage, but none currently cross a truthful acceptance
boundary:

- `brave-search`
- `deepgram`
- `exa`
- `firecrawl`
- `huggingface`
- `perplexity-search`
- `tavily`
- `tlon`
- `zalo`
- `zalouser`

### P1: Stateful ingress without real acceptance proof

These connectors declare `streaming`, `bidirectional`, `polling`, or `webhook` behavior but currently have no `fcp-e2e` coverage or documented live bundle:

- `google-workspace-events`
- `matrix`
- `mattermost`
- `nextcloud-talk`
- `signal`
- `teams`
- `tlon`
- `zalo`

### P2: Integration exists but acceptance is still missing

These connectors have crate-local integration tests but no `fcp-e2e` coverage and no documented live bundle:

- `aws`
- `azure`
- `cloudflare`
- `firebase`
- `google-places`
- `hue`
- `mysql`
- `package-registry`
- `sqlite`
- `supabase`
- `synology-chat`
- `whatsapp`

### P3: Archetype normalization debt

Testing waves need a stable taxonomy, but the current manifest labels are not yet normalized to the V3 closed set. The live scan found one connector with no archetype and multiple connectors using non-V3 labels like `operational`, `knowledge`, `storage`, `local`, `cloud-control-plane`, and `read-only`.

- `google-admin-reports` is currently missing an archetype declaration entirely.

The family tables below therefore group connectors into planning families while preserving the raw manifest archetype values in each row.

## Core Crate Matrix

| Crate | Unit | Tests Dir | Mock/Fake | NoMock | Host | Logs | Benches | Known Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| fcp-async-core | Y | N | N | N | N | N | N | inline-only |
| fcp-async-core-macros | Y | N | N | N | N | N | N | inline-only |
| fcp-audit | Y | N | N | N | N | N | N | inline-only |
| fcp-bootstrap | Y | Y | Y | Y | N | N | N | none |
| fcp-cbor | Y | Y | N | N | N | N | Y | none |
| fcp-conformance | Y | Y | Y | Y | Y | Y | N | none |
| fcp-core | Y | Y | Y | N | N | Y | Y | none |
| fcp-crypto | Y | Y | N | Y | N | N | Y | none |
| fcp-e2e | Y | Y | Y | N | N | Y | N | none |
| fcp-google-discovery | Y | N | Y | N | N | N | N | inline-only |
| fcp-graphql | Y | Y | Y | Y | Y | N | N | none |
| fcp-host | Y | Y | Y | Y | Y | Y | N | none |
| fcp-manifest | Y | Y | Y | Y | N | N | N | none |
| fcp-mesh | Y | Y | Y | Y | N | Y | Y | none |
| fcp-oauth | Y | Y | Y | Y | N | N | N | none |
| fcp-protocol | Y | Y | Y | Y | N | N | Y | none |
| fcp-raptorq | Y | Y | Y | Y | N | Y | N | none |
| fcp-ratelimit | Y | Y | N | N | N | N | N | none |
| fcp-registry | Y | Y | Y | Y | N | N | N | none |
| fcp-sandbox | Y | Y | Y | Y | Y | N | N | none |
| fcp-sdk | Y | Y | Y | Y | N | Y | N | none |
| fcp-store | Y | Y | Y | Y | N | Y | Y | none |
| fcp-streaming | Y | Y | Y | Y | N | N | N | none |
| fcp-tailscale | Y | Y | Y | Y | N | N | N | none |
| fcp-telemetry | Y | Y | N | Y | N | N | N | none |
| fcp-testkit | Y | Y | Y | N | Y | Y | N | none |
| fcp-webhook | Y | Y | Y | Y | Y | N | N | none |
| fwc | Y | Y | Y | N | Y | Y | Y | none |

## Connector Matrix

### Operational / Request

| Connector | Manifest Archetypes | Unit | Int | Mock | NoMock | Host | E2E | Logs | Live | Known Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| bluebubbles | operational | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| brave-search | request-response | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path |
| browser | operational | Y | Y | Y | N | Y | Y | Y | undocumented | mock-backed e2e only |
| calendly | operational | Y | Y | Y | N | N | N | Y | documented verification bundle | bundle only |
| circleci | operational | Y | N | Y | N | N | N | N | mock-first localhost override | unit-only; no acceptance path |
| coda | operational | Y | Y | Y | N | N | N | Y | documented verification bundle | bundle only |
| confluence | operational | Y | N | Y | N | N | N | N | mock-first localhost override | unit-only; no acceptance path |
| cron | operational | Y | Y | N | N | N | Y | Y | undocumented | mock-backed e2e only |
| deepgram | request-response | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path |
| dingtalk | operational | Y | N | Y | N | N | N | N | LAN or device-local runtime | unit-only; no acceptance path |
| dockerhub | operational | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| elevenlabs | request-response | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| email-generic | operational | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| exa | request-response | N | N | N | N | Y | N | N | undocumented | no crate-local tests; no acceptance path |
| feishu | operational | Y | Y | Y | N | N | N | Y | documented verification bundle | bundle only |
| firecrawl | request-response | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path |
| google-admin-reports | missing | Y | N | N | N | N | N | N | undocumented | archetype missing; unit-only; no acceptance path |
| google-chat | operational | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| google-drive | request-response | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| google-people | operational | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| hue | operational | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| huggingface | request-response | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path |
| imessage | operational | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| irc | operational | Y | N | N | N | N | N | N | mock-first localhost override | unit-only; no acceptance path |
| line | operational | Y | Y | Y | N | Y | Y | Y | documented verification bundle | bundle only |
| llm-router | operational | Y | Y | N | N | N | Y | Y | undocumented | mock-backed e2e only |
| mailchimp | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| make | operational | Y | Y | Y | N | Y | Y | Y | undocumented | mock-backed e2e only |
| mastodon | operational | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| mistral | request-response | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| n8n | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| netlify | operational | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| nostr | operational | Y | N | N | N | N | N | N | provider sandbox/account | unit-only; no acceptance path |
| openrouter | request-response | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| package-registry | operational | Y | Y | Y | N | N | N | Y | mock-first localhost override | no acceptance path |
| paypal | operational | Y | N | Y | N | N | N | N | provider sandbox/account | unit-only; no acceptance path |
| perplexity-search | request-response | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path |
| pulumi | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| qq | operational | Y | N | Y | N | N | N | N | LAN or device-local runtime | unit-only; no acceptance path |
| retool | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| segment | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| sendgrid | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| shopify | operational | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| sonos | operational | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| square | operational | Y | Y | Y | N | N | N | Y | documented verification bundle | bundle only |
| synology-chat | operational | Y | Y | Y | N | N | N | N | LAN or device-local runtime | no acceptance path |
| tavily | request-response | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path |
| telegram | messaging, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| terraform | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| twitch | operational | Y | N | Y | N | N | N | N | mock-first localhost override | unit-only; no acceptance path |
| vercel | cloud-control-plane | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| wecom | operational | Y | N | Y | N | N | N | N | provider sandbox/account | unit-only; no acceptance path |
| whatsapp | operational | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| whisper | operational | Y | N | Y | N | N | Y | Y | undocumented | unit-only; mock-backed e2e only |
| wolfram | request-response | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| zapier | operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| zoom | operational | Y | Y | Y | N | N | N | Y | documented verification bundle | bundle only |

### Knowledge / Retrieval

| Connector | Manifest Archetypes | Unit | Int | Mock | NoMock | Host | E2E | Logs | Live | Known Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1password | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| algolia | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| amplitude | knowledge | Y | Y | Y | N | N | Y | Y | mock-first localhost override | mock-backed e2e only |
| annas-archive | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| asana | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| bitbucket | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| bitwarden | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| clickup | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| datadog | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| elasticsearch | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| evernote | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| gitlab | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| google-docs | operational, knowledge | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| google-places | read-only | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| google-sheets | operational, knowledge | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path |
| grafana | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| hackernews | knowledge | Y | Y | Y | N | N | N | Y | documented verification bundle | bundle only |
| intercom | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| linkedin | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| logseq | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| mcp-bridge | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| metabase | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| mixpanel | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| monday | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| obsidian | knowledge, operational | Y | Y | Y | N | N | N | Y | documented verification bundle | bundle only |
| pandadoc | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| pinecone | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| posthog | knowledge | Y | Y | Y | N | N | Y | Y | mock-first localhost override | mock-backed e2e only |
| qdrant | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| redis | knowledge, operational | Y | N | Y | N | N | Y | Y | undocumented | unit-only; mock-backed e2e only |
| roam | knowledge | Y | Y | Y | N | N | Y | Y | LAN or device-local runtime | mock-backed e2e only |
| salesforce | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| semanticscholar | knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| todoist | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| trello | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| youtube | knowledge, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |

### Stateful Ingress

| Connector | Manifest Archetypes | Unit | Int | Mock | NoMock | Host | E2E | Logs | Live | Known Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| anthropic | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| arxiv | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| discord | operational, streaming, bidirectional | Y | Y | Y | N | Y | Y | Y | undocumented | mock-backed e2e only |
| docusign | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| figma | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| github | operational, streaming, knowledge | Y | Y | Y | N | Y | Y | Y | undocumented | mock-backed e2e only |
| gmail | operational, streaming, knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| google-ai | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| google-calendar | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| google-workspace-events | streaming, operational | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path; stateful ingress lacks host/live proof |
| homeassistant | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| hubspot | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| jira | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| kubernetes | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| linear | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| matrix | bidirectional | Y | N | Y | N | Y | N | N | LAN or device-local runtime | unit-only; no acceptance path; stateful ingress lacks host/live proof |
| mattermost | operational, bidirectional | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path; stateful ingress lacks host/live proof |
| nextcloud-talk | operational, bidirectional | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path; stateful ingress lacks host/live proof |
| notion | operational, knowledge, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| openai | operational, streaming | Y | Y | Y | N | Y | Y | Y | undocumented | mock-backed e2e only |
| plaid | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| reddit | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| sentry | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| signal | operational, bidirectional | Y | N | Y | N | Y | N | N | undocumented | unit-only; no acceptance path; stateful ingress lacks host/live proof |
| slack | operational, streaming, bidirectional | Y | Y | Y | N | Y | Y | Y | undocumented | mock-backed e2e only |
| spotify | knowledge, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| stripe | operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| teams | bidirectional | Y | N | Y | N | N | N | N | undocumented | unit-only; no acceptance path; stateful ingress lacks host/live proof |
| tlon | bidirectional | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path; stateful ingress lacks host/live proof |
| twilio | operational, streaming, bidirectional | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| twitter | operational, streaming, bidirectional | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| vectordb | operational, bidirectional | Y | Y | N | N | N | Y | Y | undocumented | mock-backed e2e only |
| webhook-receiver | operational, streaming | Y | Y | N | N | N | Y | Y | undocumented | mock-backed e2e only |
| zalo | bidirectional, polling, webhook | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path; stateful ingress lacks host/live proof |
| zendesk | operational, streaming, knowledge | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |

### Storage / Data

| Connector | Manifest Archetypes | Unit | Int | Mock | NoMock | Host | E2E | Logs | Live | Known Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| airtable | storage, operational, streaming | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| aws | operational, storage | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| azure | operational, storage | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| bigquery | knowledge, storage | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| box | knowledge, storage | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| cloudflare | operational, storage | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| dropbox | knowledge, storage | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| duckdb | knowledge, storage | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| firebase | storage, operational | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| gcp | operational, storage | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| microsoft365 | knowledge, operational, streaming, storage | Y | Y | Y | N | N | Y | Y | mock-first localhost override | mock-backed e2e only |
| mongodb | knowledge, storage | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| mysql | storage, operational | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |
| postgresql | knowledge, storage | Y | N | Y | N | N | Y | Y | undocumented | unit-only; mock-backed e2e only |
| s3 | storage, operational | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| snowflake | knowledge, storage | Y | Y | Y | N | N | Y | Y | undocumented | mock-backed e2e only |
| sqlite | storage, operational | Y | Y | N | N | N | N | N | undocumented | no acceptance path |
| supabase | storage, operational | Y | Y | Y | N | N | N | N | undocumented | no acceptance path |

### Local / Tool

| Connector | Manifest Archetypes | Unit | Int | Mock | NoMock | Host | E2E | Logs | Live | Known Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| apple-notes | local | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| apple-reminders | local | Y | N | N | N | N | N | N | undocumented | unit-only; no acceptance path |
| zalouser | cli-process | N | N | N | N | N | N | N | undocumented | no crate-local tests; no acceptance path |

## Pure-Unit Floor Pattern for Request-Response Connectors

> Added by bead `flywheel_connectors-49z0b.16.2` (2026-03-23).  This section
> defines the pure-unit test floor that downstream family sweeps should enforce.

### Gold-Standard References

- **Netlify** (34 tests, 100% pure) — comprehensive config validation, operation
  contract verification, helper function testing, doctor/health/introspect
  coverage.  Best example of a clean `pure_unit` floor.
- **Shopify** (45 tests, 100% pure) — config + per-operation input validation +
  auth type enforcement + operation contract verification.
- **Slack** (61 tests, 93% pure) — exceptional batch-style operation metadata
  validation.  Only 4 doctor tests use mocks and should move to `tests/`.

### Pure-Unit Floor Checklist

Every request-response connector's `src/` test modules MUST cover the following
without any `wiremock`, `MockServer`, or `MockApiServer` imports:

| Category | Minimum Tests | What To Verify |
| --- | --- | --- |
| Config parsing | 3-5 | Empty/missing fields, type validation, default values, bounds |
| Auth mode enforcement | 2-3 | api_key vs credential_id rejection, both-present error |
| Base URL policy | 2 | Approved hosts, localhost, HTTP rejection |
| Error mapping | 3-5 | `ConnectorErrorMapping::to_fcp_error()`, `is_retryable()`, status codes |
| Operation info | 5-10 | Count, unique IDs, safety tiers, risk levels, idempotency, capabilities |
| Helper functions | 1-3 | `require_str`, path encoding, field extraction |
| Manifest determinism | 1 | Manifest hash is stable across runs |
| Doctor/health unconfigured | 2 | Doctor reports unhealthy, health reports not-ready |

### Leakage Extraction Pattern

For the 62 connectors with inline mock leakage (see per-file map above), the
extraction follows two rules:

1. **`client.rs` leaks** (47/62 connectors): Tests that spin up `MockServer` to
   verify HTTP request construction belong in `tests/integration.rs` as
   `deterministic_contract`.  Pure struct serialization, error mapping, and URL
   encoding tests remain in `src/client.rs`.

2. **`connector.rs` leaks** (24/62 connectors): Tests that mock upstream API for
   `doctor`, `self_check`, or health checks belong in `tests/integration.rs`.
   Config parsing, operation info, handshake field checking, and introspect
   metadata tests remain in `src/connector.rs`.

### Current Floor Quality by Connector (Representative Sample)

| Connector | Tests | Pure % | Config | OpInfo | Auth | Error | Grade |
| --- | --- | --- | --- | --- | --- | --- | --- |
| netlify | 34 | 100% | 13 | 13 | — | — | A |
| shopify | 45 | 100% | 14 | 7 | 7 | — | A- |
| slack | 61 | 93% | — | 45+ | — | — | A |
| anthropic | 80 | 68% | 5 | — | 9 | 15 | B |
| stripe | 42 | 60% | 9 | — | 9 | 1 | B- |
| brave-search | 3 | 100% | 3 | — | — | — | D |

### Downstream Consumer Guidance

- `49z0b.8.*` (messaging family) should use Slack's batch metadata pattern.
- `49z0b.9.*` (productivity family) should use Netlify's config+contract pattern.
- `49z0b.10.*` (dev-platform family) should use Shopify's input validation pattern.
- `49z0b.11.*` (cloud/infra family) should use Stripe's URL safety pattern.
- `49z0b.12.*` (commerce family) should use Shopify + Stripe combined.
- `49z0b.13.*` (AI/search family) should use Anthropic's SSE parsing + error
  classification pattern.

## Pure-Unit Floor Pattern for Stateful, Local, and Bridge Connectors

> Added by bead `flywheel_connectors-49z0b.16.3` (2026-03-23).

### Stateful Connector Floor Checklist

In addition to the request-response floor (config, auth, error mapping,
operation info), stateful connectors MUST test these pure-unit categories:

| Category | Minimum Tests | What To Verify |
| --- | --- | --- |
| Event normalization | 2-5 | Provider event → FCP `EventEnvelope` translation |
| State machine transitions | 3-5 | Connect → Subscribe → Receive → Reconnect → Shutdown |
| Cursor/offset handling | 2-3 | Pagination tokens, timestamp cursors, sequence numbers |
| Config for stateful features | 2-3 | Buffer sizes, reconnect limits, heartbeat intervals |
| Capability/domain mapping | 3-5 | Entity types → capabilities, channel types → permissions |

### Current Floor Quality (Representative Sample)

| Connector | Tests | Pure % | Config | Error | OpInfo | Events | State | Grade |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| discord | 180 | 85% | 14 | 57 | Y | 2 | — | B+ |
| telegram | 218 | 70% | Y | Y | Y | — | — | B- |
| homeassistant | 345 | 100% | Y | Y | 30+ | — | — | B |
| imessage | 65 | 95% | 13 | Y | Y | — | 1 | B |
| mattermost | 106 | 100% | Y | Y | Y | — | — | C+ |
| apple-notes | 38 | 100% | 1 | — | — | — | — | D |

### Critical Stateful Gaps

- **Mattermost**: Socket lifecycle (connect → subscribe → ping → reconnect)
  has zero functional tests despite declaring socket state fields.
- **Telegram**: No cursor/offset tests despite supporting 1000-event buffering.
- **Home Assistant**: No entity control state machine tests despite
  21-variant `EntityDomain` enum.
- **Apple Notes**: Only 1 test (platform check). Needs config, operation
  info, and local-filesystem edge case coverage.

### Downstream Consumer Guidance

- `49z0b.8.*` (messaging) should prioritize socket lifecycle and event
  normalization for Discord, Telegram, Mattermost, Matrix, Signal.
- `49z0b.10.3` (browser/bridge) should prioritize bridge daemon detection
  and local-process lifecycle for iMessage, browser.
- `49z0b.11.2` (databases) should prioritize cursor/pagination and
  connection pool state for PostgreSQL, DuckDB, Elasticsearch.
- `49z0b.11.3` (storage) should prioritize upload/download state machine
  and multipart progress for S3, GCS, Azure Blob.

## HTTP Fixture Adoption Guide

> Added by bead `flywheel_connectors-49z0b.4.3` (2026-03-23).

### How To Use the HTTP Fixture for Connector Acceptance Tests

All types are re-exported through `fcp_e2e`, so connector acceptance tests
need only `fcp-e2e` as a dependency:

```rust
use fcp_e2e::{HttpFixtureServer, HttpFixtureRoute, HttpFixtureResponse};

#[fcp_async_core::runtime::test]
async fn connector_handles_pagination() {
    let fixture = HttpFixtureServer::start().expect("fixture should bind");
    fixture.mount(
        HttpFixtureRoute::get("/v1/items")
            .with_query("page", "1")
            .respond_with(HttpFixtureResponse::json(
                json!({ "items": [1, 2], "next": "2" }),
            )),
    );
    // Point connector at fixture.base_url() instead of real API
    // ... exercise pagination ...
    fixture.assert_request_count(2);
}
```

### Available Fixture Capabilities

| Capability | How |
| --- | --- |
| Auth gating | `.require_header("Authorization", "Bearer tok")` |
| Pagination | `.with_query("page", "N")` — mount one route per page |
| Retry | Queue: `.respond_with(R1).respond_with(R2)` |
| Error envelopes | `HttpFixtureResponse::json_status(500, body)` |
| Redirects | `HttpFixtureResponse::redirect(302, "/new")` |
| Binary upload | `HttpFixtureRoute::post(path)` + recorded body |
| Binary download | `HttpFixtureResponse::binary(bytes, ct)` |
| Timeouts | `.with_delay(Duration::from_secs(5))` |
| Request recording | `fixture.recorded_requests()` |

Streaming: `StreamingFixtureServer` (SSE, JSON-lines, heartbeats, connection
drop, reconnect scripting).  Webhook: `WebhookIngressHarness` +
`WebhookPayloadBuilder` (GitHub/Stripe/Slack signatures, retry, duplicates).
All re-exported via `fcp_e2e`.

## Stateful / Local Fixture Platform Matrix

> Added by bead `flywheel_connectors-49z0b.6.3` (2026-03-23).

Use this section together with `docs/V3_Connector_Acceptance_Contract.md`
Section 6e and `crates/fwc/testdata/host_integration/fixture_matrix.json`.
The contract defines which suite class is required; this matrix says where that
suite may run, what it must preserve, and when later beads must escalate from
`local_non_mock` into `host_e2e`.

### Platform Matrix

| Fixture Family | Minimum Suite Class | Generic CI | Dedicated Host Required When | Mandatory Artifact Bundle | Cleanup Guarantee |
| --- | --- | --- | --- | --- | --- |
| Relational DB / embedded storage | `local_non_mock`; add `host_e2e` for admin, policy, or receipt-heavy flows | Yes when the engine is embedded or containerized | Engine depends on platform services, non-portable filesystem behavior, or host policy enforcement | `logs.jsonl`, `report.json`, `environment.json`, `receipts.json`, `replay.sh`, plus fixture-specific dump/state artifact when needed | Unique DB/schema per run; drop or remove on success; preserve failing namespace and dump path in the bundle |
| Object/blob / key-value / local store | `local_non_mock`; add `host_e2e` when presign, ACL, or sandbox receipts matter | Yes when a truthful local emulator exists | Behavior depends on provider ACL semantics, cloud IAM, or host-bound credential flow | `logs.jsonl`, `report.json`, `environment.json`, `receipts.json`, `replay.sh`, plus uploaded/downloaded artifact paths | Unique bucket/prefix/path per run; remove temporary objects on success; keep captured paths on failure |
| Queue / pub-sub broker | `local_non_mock` + `host_e2e` | Yes for portable brokers or containerized fixtures | Broker or sidecar is device-bound, non-portable, or coupled to host supervision behavior | `logs.jsonl`, `report.json`, `environment.json`, `broker-state.json`, `receipts.json`, `replay.sh`, `session_transcript.json` when scripted delivery/reconnect semantics matter | Purge queues/topics/subscriptions on success; retain broker state and delivery IDs on failure |
| Browser session / browser bridge | `local_non_mock` + `host_e2e` | Yes only on workers with a pinned browser binary, headless dependencies, and writable download directory | Coverage depends on macOS/browser automation, anti-bot flows, real desktop bridges, or non-portable browser install state | `logs.jsonl`, `report.json`, `environment.json`, `bridge-events.jsonl`, `downloads/`, `screenshots/`, `replay.sh`, `session_transcript.json` | Close tabs/sessions, delete ephemeral profile/download dirs on success, preserve artifacts on failure |
| Local process / CLI | `local_non_mock` + `host_e2e` | Yes for hermetic, non-privileged tools | Tool mutates host state, depends on platform-native binaries, or must prove subprocess supervision through `fcp-host` | `logs.jsonl`, `report.json`, `environment.json`, `stdout.txt`, `stderr.txt`, `exit-status.json`, `tmp/`, `replay.sh` | Kill child processes, verify port/socket release, remove temp dir on success, preserve temp dir on failure |
| Bridge / daemon / mobile-desktop helper | `local_non_mock` + `host_e2e` | No by default | Runtime depends on localhost daemons, device bridges, OS services, or socket/RPC boundaries that generic workers do not own | `logs.jsonl`, `report.json`, `environment.json`, `bridge-events.jsonl`, `daemon-stdout.txt`, `daemon-stderr.txt`, `receipts.json`, `replay.sh`, `session_transcript.json` | Assert clean disconnect; stop helper daemon if the suite started it; leftover PID/socket is a failure unless explicitly documented |
| Local-platform / macOS-only automation | `local_non_mock`; add `host_e2e` when the connector is expected to run through `fcp-host` / `fwc` | No | Platform API, entitlement, desktop automation, or physical-device coupling is intrinsic to the connector | `logs.jsonl`, `report.json`, `environment.json`, `replay.sh`, plus platform-specific captured output directory | Never claim generic CI readiness; remove only the ephemeral state created by the test; preserve workstation-only artifacts for rerun |

### Skip Policy

- Skip only for explicit reasons: platform mismatch, missing prerequisite,
  unavailable dedicated host class, or unsafe shared environment.
- Every skip must emit `environment.json` or an equivalent prerequisite record
  naming the failed check, expected platform, and rerun command.
- Use stable skip labels so downstream automation can route correctly:
  `requires_docker`, `requires_browser`, `requires_bridge_daemon`,
  `requires_macos`, `requires_device_lab`, `requires_provider_sandbox`.
- Do not silently downgrade a required `host_e2e` or `live` suite into
  `deterministic_contract`. If the required boundary is unavailable, leave the
  bead open and document the blocker.
- If cleanup cannot be guaranteed in shared CI, quarantine the suite behind a
  dedicated host instead of pretending it is generic-CI safe.

### Cleanup Guarantees

- Namespace every mutable resource by run id: DB/schema names, queue/topic
  names, temp dirs, download dirs, pid files, sandbox workspaces.
- On success, teardown must remove ephemeral state created by the suite and
  verify the helper process, browser session, or container exited cleanly.
- On failure, preserve the run bundle and any temp directory named in the
  report so a future agent can replay rather than guess.
- Destructive `host_e2e` or `live` runs must record the cleanup expectation and
  sandbox identity in redacted form.
- Leaked child processes, bound ports, leftover topics, or undeleted temp
  directories are acceptance failures unless the suite is explicitly documented
  as preservation-only.

### When `host_e2e` Must Be Added On Top Of `local_non_mock`

1. The connector must prove manifest loading, sandbox policy, receipts, or
   `doctor`/readiness output through the real `fcp-host` subprocess boundary.
2. Safety or risk controls live at the host layer rather than inside the
   connector-local fixture alone.
3. Subprocess supervision, stdio/JSON-RPC framing, reconnect handling, or
   restart behavior is part of the truth being verified.
4. Later sweeps need replayable host artifacts (`trace.jsonl`, `summary.json`,
   `environment.json`, `replay.sh`) in addition to the connector-local bundle.

### Practical Adoption Pattern

1. Start with the family-specific `local_non_mock` harness in `fcp-testkit`
   and capture the equivalent artifact bundle named in the matrix above.
2. Reuse the same scenario identifier when promoting that fixture into
   `fcp-e2e` / `fwc`; `crates/fwc/testdata/host_integration/fixture_matrix.json`
   is the seed inventory for host-backed fixture IDs and coverage modes.
3. For `host_e2e`, preserve the host bundle required by the V3 contract:
   `trace.jsonl`, `summary.json`, `environment.json`, and `replay.sh`, plus the
   family-specific local artifacts (`broker-state.json`, `stdout.txt`,
   `bridge-events.jsonl`, `session_transcript.json`, and similar).
4. Promote queue, browser, local-process, and bridge families to
   `host_e2e` by default. Promote DB/storage/local-platform families whenever
   host policy, receipts, risky mutations, or subprocess lifecycle are part of
   the acceptance story.

### Downstream Consumer Guidance

- `49z0b.11.2` and `49z0b.11.3` should treat DB/storage suites as generic-CI
  safe only when a truthful local engine or emulator exists and cleanup is
  deterministic.
- `49z0b.10.3`, `49z0b.8.2`, and `49z0b.8.3` should assume browser/bridge
  coverage requires both `local_non_mock` and `host_e2e`, with dedicated-host
  routing for device-bound or daemon-bound scenarios.
- `49z0b.9.3` should treat Apple Notes, Apple Reminders, and similar
  local-platform connectors as dedicated-host work from the start.
- `49z0b.14.3` should consume the stable skip labels above when building
  quarantine/nightly routing, rather than inventing new reason strings.

## What This Means For Wave Planning

- The next policy bead should treat connector `no_mock` acceptance as essentially absent. The only real connector-side non-mock evidence today is the small verification-bundle set documented above.
- The first implementation waves should target `P0` and `P1` connectors before polishing already well-covered mock-backed request/response surfaces.
- The host, conformance, SDK, store, and `fwc` layers already have strong enough scaffolding to support acceptance expansion without another archaeology pass.
- A later cleanup bead should normalize manifest archetype labels to the V3 contract so these testing waves can align directly with the normative taxonomy instead of this derived grouping.
