# Live / Nightly Suite Classification

> Generated: 2026-03-23 | Bead: `flywheel_connectors-49z0b.14.1`
>
> This document classifies which connectors genuinely require `live` or
> `nightly_live` suites and why `local_non_mock` is insufficient for each.
> Read it together with `docs/V3_Connector_Acceptance_Contract.md` Section 6e
> and `docs/testing/coverage-inventory.md`.

## Suite Classes Recap

| Suite Class | What It Proves |
| --- | --- |
| `local_non_mock` | Real local fixture boundary: local DB, file store, bridge daemon, browser |
| `host_e2e` | Real fcp-host subprocess lifecycle with manifests and policy enforcement |
| `live` / `nightly_live` | Real provider sandbox or true upstream service |

This document identifies connectors that **cannot truthfully stop at
`local_non_mock`** because the real boundary is a managed SaaS sandbox, a
physical device, or a provider behavior that cannot be emulated safely.

---

## Classification

### Tier A — `local_sufficient` (81 connectors)

These connectors can reach full acceptance coverage with local fixtures
(Docker containers, embedded databases, mock HTTP servers, local daemon
instances). They do NOT require any live provider access for acceptance.

| Archetype Family | Connectors |
| --- | --- |
| **Embedded / local DB** | `duckdb`, `sqlite`, `postgresql`, `mysql`, `mongodb`, `redis`, `elasticsearch`, `qdrant`, `pinecone`, `vectordb` |
| **Object storage (emulatable)** | `s3` (LocalStack/Moto), `supabase` (local dev), `firebase` (emulator) |
| **Cloud platforms (emulatable)** | `gcp` (emulators), `kubernetes` (kind/k3s), `terraform` (local state + mock providers) |
| **LLM / AI (mockable)** | `anthropic`, `openai`, `google-ai`, `mistral`, `openrouter`, `llm-router`, `huggingface` |
| **Search (mockable)** | `algolia`, `exa`, `firecrawl`, `tavily`, `perplexity-search` |
| **Docs / Notes (local files)** | `obsidian`, `logseq`, `roam` |
| **SaaS APIs (REST mock)** | `github`, `gitlab`, `bitbucket`, `jira`, `linear`, `asana`, `trello`, `clickup`, `todoist`, `notion`, `airtable`, `coda`, `pandadoc`, `evernote`, `figma`, `retool`, `n8n` |
| **Email / Comms (mock SMTP/IMAP)** | `gmail`, `email-generic`, `mailchimp`, `sendgrid`, `slack`, `mattermost` |
| **Google APIs (mock HTTP)** | `google-calendar`, `google-chat`, `google-docs`, `google-drive`, `google-people`, `google-sheets`, `google-admin-reports`, `google-workspace-events` |
| **Analytics (mock HTTP)** | `segment`, `metabase` |
| **Automation (mock HTTP)** | `make`, `zapier`, `cron`, `webhook-receiver` |
| **Other (mock HTTP)** | `arxiv`, `annas-archive`, `semanticscholar`, `box`, `dropbox`, `salesforce`, `mcp-bridge`, `package-registry`, `bigquery`, `snowflake`, `browser`, `spotify`, `reddit` |
| **Self-hosted (Docker)** | `matrix` (Synapse), `nextcloud-talk`, `mastodon`, `nostr` |

**Why `local_non_mock` suffices**: These connectors' external boundaries are
either (a) fully emulatable via Docker or embedded runtimes, (b) stateless
REST APIs where request/response contract testing is sufficient, or (c) local
file-based systems with no network dependency.

---

### Tier B — `sandbox_required` (36 connectors)

These connectors need a **provider-specific sandbox or test account** because
either the service has no local emulator, the OAuth flow requires real
provider infrastructure, or the API behavior is sufficiently complex that
mocks cannot capture real-world edge cases.

| Connector | Provider | Why Local Is Insufficient | Minimum Live Boundary |
| --- | --- | --- | --- |
| `aws` | Amazon Web Services | IAM policy evaluation, cross-region behavior, service quotas | AWS test account with limited IAM scope |
| `azure` | Microsoft Azure | AD auth, resource group lifecycle, RBAC | Azure free-tier subscription |
| `cloudflare` | Cloudflare | Worker deployment, DNS propagation, zone behavior | Test zone with subdomain |
| `vercel` | Vercel | Deployment lifecycle, environment variables, domain routing | Test project |
| `netlify` | Netlify | Build hooks, deploy previews, forms | Test site |
| `amplitude` | Amplitude | Event ingestion pipeline, cohort resolution | Test project |
| `datadog` | Datadog | Metric aggregation, monitor evaluation | Test organization |
| `grafana` | Grafana | Dashboard rendering, alerting rules | Test instance (or local Docker) |
| `mixpanel` | Mixpanel | Funnel analysis, event tracking | Test project |
| `posthog` | PostHog | Feature flags, session replay | Test instance (or local Docker) |
| `hubspot` | HubSpot | CRM pipeline, workflow execution | Sandbox portal |
| `intercom` | Intercom | Conversation threading, operator routing | Test workspace |
| `zendesk` | Zendesk | Ticket lifecycle, automation rules | Sandbox account |
| `discord` | Discord | Bot permissions, gateway intents, rate limits | Test server + bot |
| `telegram` | Telegram | Bot API, webhook setup, message formatting | Test bot token |
| `teams` | Microsoft Teams | Teams app permissions, activity feed | Test tenant |
| `stripe` | Stripe | Payment intents, webhook signatures, idempotency | Stripe test mode (test keys) |
| `paypal` | PayPal | Order lifecycle, refund flows | PayPal Sandbox |
| `square` | Square | Payment processing, catalog sync | Square Sandbox |
| `plaid` | Plaid | Institution linking, transaction sync | Plaid Sandbox |
| `shopify` | Shopify | Storefront API, order management | Development store |
| `docusign` | DocuSign | Envelope lifecycle, signing ceremony | Sandbox account |
| `bitwarden` | Bitwarden | Vault access, organization management | Test vault |
| `1password` | 1Password | Secret retrieval, vault listing | Test vault |
| `circleci` | CircleCI | Pipeline triggering, job artifacts | Test project |
| `confluence` | Confluence | Space/page lifecycle, permissions | Test space |
| `dockerhub` | Docker Hub | Image listing, tag management | Test repository |
| `microsoft365` | Microsoft 365 | Graph API, OneDrive, SharePoint | Test tenant |
| `linkedin` | LinkedIn | Profile API, posting | Sandbox API |
| `sentry` | Sentry | Issue grouping, release tracking | Test project |
| `pulumi` | Pulumi | Stack lifecycle, resource preview | Test organization |
| `twilio` | Twilio | SMS delivery, voice calls, webhook | Test credentials |
| `feishu` | Feishu/Lark | App permissions, event subscriptions | Test workspace |
| `calendly` | Calendly | Event type management, scheduling | Test workspace |
| `monday` | Monday.com | Board/item lifecycle, automation | Test workspace |
| `homeassistant` | Home Assistant | Entity state, automation triggers | Local instance (Docker) |

**Why `local_non_mock` is insufficient**: These services have complex
server-side behaviors (auth flows, rate limiting, webhook delivery, payment
processing) that cannot be faithfully replicated by mock servers. The
minimum viable acceptance test requires hitting the provider's test/sandbox
infrastructure with real (but non-production) credentials.

---

### Tier C — `device_required` (8 connectors)

These connectors require **physical hardware**, **platform-specific runtime**,
or **real user accounts** that cannot be virtualized.

| Connector | Requirement | Why | Minimum Live Boundary |
| --- | --- | --- | --- |
| `apple-notes` | macOS | Uses macOS-native APIs (AppleScript/NSAppleScript) | macOS machine |
| `apple-reminders` | macOS | Uses macOS-native Reminders framework | macOS machine |
| `hue` | Philips Hue bridge | Local-network mDNS discovery + bridge authentication | Hue bridge + at least 1 light |
| `sonos` | Sonos speaker | Local-network UPnP/SOAP control protocol | Sonos speaker on LAN |
| `synology-chat` | Synology NAS | Synology-specific webhook/bot API | Synology NAS on LAN |
| `whisper` | Audio hardware | Audio file processing, model loading, GPU optional | Machine with audio capabilities |
| `imessage` / `bluebubbles` | macOS + BlueBubbles | Bridge daemon requires macOS with iMessage account | macOS + BlueBubbles server |
| `signal` | Signal daemon | Signal-CLI bridge, real phone number registration | Signal account + signal-cli |

**Why no local alternative**: These connectors interact with hardware devices,
OS-specific APIs, or services that require real identity verification. Mock
servers cannot replicate device discovery protocols, platform API behaviors,
or message delivery semantics.

---

### Tier D — `live_read_only` (12 connectors)

These connectors can safely query **real public APIs** for read-only
acceptance testing. Write operations (if any) still need sandbox treatment.

| Connector | Public API | Safe Read Operations | Rate Limit Concern |
| --- | --- | --- | --- |
| `arxiv` | arXiv.org | Paper search, metadata retrieval | Low (polite) |
| `semanticscholar` | Semantic Scholar | Paper search, citation graphs | Moderate (API key helps) |
| `hackernews` | Hacker News | Story/comment retrieval | Low |
| `google-places` | Google Places | Place search, details | Moderate (API key required) |
| `brave-search` | Brave Search | Web search queries | Moderate (API key required) |
| `wolfram` | Wolfram Alpha | Knowledge queries | Low (API key required) |
| `deepgram` | Deepgram | Transcription (read) | API key required |
| `elevenlabs` | ElevenLabs | Voice listing (read) | API key required |
| `irc` | IRC networks | Channel listing, message reading | Low |
| `twitter` | X/Twitter API | Public timeline reading | Strict rate limits |
| `youtube` | YouTube Data API | Video/channel metadata | Moderate (quota) |
| `reddit` | Reddit API | Public subreddit reading | Moderate |

**Strategy**: Run read-only live tests on a nightly schedule with rate-limit
awareness. These tests validate real API response shapes and auth flows
without risking data mutation.

---

### Tier E — `live_write_required` (5 connectors)

These connectors have write operations where even the "sandbox" is
effectively a live API, or no sandbox exists at all.

| Connector | Why | Risk Mitigation |
| --- | --- | --- |
| `tlon` | Decentralized Urbit network; no sandbox mode | Use test ship |
| `zalo` | Vietnamese platform; limited international sandbox support | Dedicated test account |
| `zalouser` | Zalo user API; same constraints as `zalo` | Dedicated test account |
| `wecom` | WeCom sandbox has limited feature parity | Dedicated test corp |
| `qq` | QQ platform; limited sandbox support | Dedicated test account |
| `dingtalk` | DingTalk sandbox has limited feature parity | Dedicated test workspace |
| `line` | LINE Messaging API; sandbox has limitations | Test channel |
| `nostr` | Relay behavior varies; mock cannot capture relay diversity | Test relay set |

**Strategy**: Gate write tests behind explicit opt-in environment variables.
Run on a separate nightly schedule with isolated test accounts. Never run
in default CI.

---

## CI / Nightly Schedule Recommendations

| Schedule | What Runs | Gate |
| --- | --- | --- |
| **Every PR** | `pure_unit` + `deterministic_contract` for all connectors | None |
| **Merge to main** | `local_non_mock` + `host_e2e` for Tier A connectors | None |
| **Nightly** | Tier B `sandbox_required` connectors | `FCP_LIVE_SANDBOX=1` + secrets |
| **Nightly** | Tier D `live_read_only` connectors | `FCP_LIVE_READ=1` + API keys |
| **Weekly** | Tier C `device_required` (where device lab available) | Manual trigger |
| **Weekly** | Tier E `live_write_required` | `FCP_LIVE_WRITE=1` + isolated accounts |

## Standard Live-Suite Prerequisites

Bead `49z0b.14.2` standardizes the per-connector prerequisite declaration
through `fcp_testkit::live_suite::EnvironmentManifest`. Connectors in Tier
B/C/D/E should use that layer instead of ad hoc env-var checks or one-off
cleanup notes.

### Required Manifest Fields

Every live-capable connector should declare all of the following:

- connector id and provider name
- tier gate: `sandbox`, `device`, `read_only`, or `live_write`
- required secrets and any required non-secret environment variables
- explicit account setup guidance for the sandbox, test tenant, device lab, or
  dedicated workspace required to run safely
- per-run budget ceiling in USD
- cleanup strategy
- rate-limit guidance when the provider enforces quotas or anti-abuse delays
- optional metadata needed by evidence collectors or nightly orchestration

Use the constructor that matches the classification table:

- Tier A: `EnvironmentManifest::local(...)`
- Tier B: `EnvironmentManifest::sandbox(...)`
- Tier C: `EnvironmentManifest::device(...)`
- Tier D: `EnvironmentManifest::read_only(...)`
- Tier E: `EnvironmentManifest::live_write(...)`

### Gate Mapping

| Tier | Gate | Expected Secret Boundary |
| --- | --- | --- |
| Tier B `sandbox_required` | `FCP_LIVE_SANDBOX=1` | provider sandbox / test account |
| Tier C `device_required` | `FCP_LIVE_DEVICE=1` | dedicated device, lab host, or platform account |
| Tier D `live_read_only` | `FCP_LIVE_READ=1` | read-only or low-risk API key |
| Tier E `live_write_required` | `FCP_LIVE_WRITE=1` | isolated mutation-capable test tenant |

### Safety Rules For Repeated Automated Use

- Never point these suites at production credentials, production tenants, or a
  shared personal account.
- Namespace mutable resources with a synthetic tenant or other run-specific
  prefix so later cleanup and forensic inspection stay deterministic.
- Tier B and Tier E suites must declare a cleanup strategy. Tier C suites may
  use `CleanupStrategy::None` only when the device/local platform boundary does
  not create cloud-side mutable state that the suite itself is responsible for
  removing.
- Rate-limit metadata should be truthful enough for nightly orchestration to
  slow down or quarantine a connector rather than burn quota blindly.
- Missing prerequisites should fail as an explicit gated skip with actionable
  remediation, not as a mysterious auth or network error mid-run.

### Evidence Bundle Expectations

For Tier B/C/D/E runs, `environment.json` or the connector-local equivalent
should preserve enough redaction-safe context to explain why a run was safe and
repeatable:

- suite class and live tier
- redacted secret/env-var presence, not raw values
- account setup or sandbox identity in redacted form
- budget ceiling and observed spend summary
- cleanup expectations and whether mutation was exercised
- synthetic tenant identity or equivalent run namespace
- rate-limit guidance used during the run

## Downstream Consumer Mapping

- `49z0b.14.2`: Use the Tier B/C/D/E classifications to design the secret
  management, account provisioning, and cost tracking layer.
- `49z0b.8.x` through `49z0b.13.x`: Each family sweep should check this
  document to determine whether the connector under test needs sandbox
  credentials or can stop at local fixtures.
- `49z0b.15.1`: The coverage scanner should validate that connectors
  classified as `sandbox_required` or above have the appropriate
  environment-gated test files.
