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

- Connectors with some source-adjacent `#[cfg(test)]` signal: `149/149`. The old `139/149` number is obsolete.
- Connectors with a clean source-adjacent `pure_unit` floor: `87/149`.
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

- `fcp-bootstrap`
- `fcp-conformance`
- `fcp-core`
- `fcp-e2e`
- `fcp-google-discovery`
- `fcp-oauth`
- `fcp-registry`
- `fcp-sandbox`
- `fcp-tailscale`
- `fcp-testkit`
- `fcp-webhook`
- `fwc`

#### Connectors With Inline Mock Leakage in `src/**/*.rs`

- `airtable`, `anthropic`, `azure`, `browser`, `calendly`, `circleci`, `coda`, `confluence`, `deepgram`, `dingtalk`, `discord`, `feishu`, `figma`, `firebase`, `github`, `gmail`, `google-ai`, `google-chat`, `google-docs`, `google-places`, `google-sheets`, `google-workspace-events`, `hackernews`, `hue`, `imessage`, `jira`, `line`, `linear`, `mastodon`, `matrix`, `microsoft365`, `nextcloud-talk`, `notion`, `openai`, `package-registry`, `paypal`, `pinecone`, `plaid`, `postgresql`, `qdrant`, `qq`, `redis`, `s3`, `signal`, `slack`, `sonos`, `square`, `stripe`, `synology-chat`, `teams`, `telegram`, `twilio`, `twitch`, `twitter`, `vercel`, `wecom`, `whatsapp`, `whisper`, `wolfram`, `youtube`, `zendesk`, `zoom`

### Naming Violations: `no_mock_integration.rs` That Are Not Actually Non-Mock

- `crates/fcp-streaming/tests/no_mock_integration.rs` is currently `deterministic_contract`, not `local_non_mock`, because the file explicitly documents "SSE streaming via wiremock" and imports `wiremock::{Mock, MockServer, ResponseTemplate}`.
- `crates/fcp-tailscale/tests/no_mock_integration.rs` is currently `deterministic_contract`, not `local_non_mock`, because it exercises `MockTailscaleClient` rather than a real daemon or local mesh boundary.
- `crates/fcp-registry/tests/no_mock_integration.rs` is currently mixed and cannot honestly keep the current name as-is, because the file uses `MockTransparencyVerifier`, `MockTufVerifier`, and `MockSigstoreVerifier` for parts of the verification path even though other portions are real in-memory crypto and store flows.

### Backlog-Ready Downstream Consumers

- `flywheel_connectors-49z0b.16.2` should consume the 62-connector inline-mock list plus the 79 mock-backed `fcp-e2e` compliance suites and split them into "pure unit extraction" vs "deterministic contract rename" work.
- `flywheel_connectors-49z0b.16.3` should consume the `fcp-streaming` and `fcp-tailscale` naming violations plus the bridge, daemon, browser, and local-platform connectors that need truthful `local_non_mock` or `host_e2e` evidence.
- `flywheel_connectors-49z0b.7.1` should consume the twelve crate-level inline-mock leaks and the `fcp-async-core-macros` unit-floor gap.

## Executive Summary

- Current tree size: 149 connector directories and 28 workspace crates.
- Connector source-adjacent test signal exists in 149/149 connectors, but only 87/149 currently present a clean `pure_unit` floor.
- Connector crate-local `tests/` coverage exists in 100/149 connectors.
- Connector `fcp-e2e` coverage exists in 84/149 connectors.
- Connector `no_mock_integration.rs` coverage exists in 0/149 connectors.
- Inline mock leakage exists in 62 connector crates and 12 workspace crates.
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

## What This Means For Wave Planning

- The next policy bead should treat connector `no_mock` acceptance as essentially absent. The only real connector-side non-mock evidence today is the small verification-bundle set documented above.
- The first implementation waves should target `P0` and `P1` connectors before polishing already well-covered mock-backed request/response surfaces.
- The host, conformance, SDK, store, and `fwc` layers already have strong enough scaffolding to support acceptance expansion without another archaeology pass.
- A later cleanup bead should normalize manifest archetype labels to the V3 contract so these testing waves can align directly with the normative taxonomy instead of this derived grouping.
