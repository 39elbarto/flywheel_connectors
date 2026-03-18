# FCP V3 Connector Compliance Audit Matrix

**Date:** 2026-03-18
**Scope:** 89 connectors in `connectors/`
**Method:** Static analysis of manifest.toml, Cargo.toml, and src/ files
**Agent:** SunnyMoose (claude-code, opus-4.6)
**Bead:** j05nu.12.1

---

## Summary Statistics

| Metric | Count | Percentage |
|--------|------:|----------:|
| **Total connectors** | 89 | 100% |
| **FULLY_V3** (10/10 markers) | 75 | 84.3% |
| **PARTIAL_V3** (7-9/10 markers) | 9 | 10.1% |
| **NEEDS_WORK** (<7/10 markers) | 5 | 5.6% |

---

## Compliance Marker Totals

| # | Marker | Present | Missing | Coverage |
|---|--------|--------:|--------:|---------:|
| 1 | Archetype declared in manifest | 84 | 5 | 94.4% |
| 2 | `ConnectorErrorMapping` impl | 79 | 10 | 88.8% |
| 3 | `ConnectorRuntime` usage | 87 | 2 | 97.8% |
| 4 | Typed `OperationInfo` structs | 89 | 0 | 100.0% |
| 5 | Manifest with `provides` sections | 85 | 4 | 95.5% |
| 6 | `deny_localhost` (default-deny) | 82 | 7 | 92.1% |
| 7 | Single-zone `[zones]` binding | 85 | 4 | 95.5% |
| 8 | `fcp-sdk` dependency | 89 | 0 | 100.0% |
| 9 | Tests (inline or `tests/`) | 89 | 0 | 100.0% |
| 10 | `NetworkConstraints` in operations | 83 | 6 | 93.3% |

Three markers at 100%: Typed OperationInfo, fcp-sdk dependency, and Tests.
Weakest: ConnectorErrorMapping at 88.8%.

---

## Categorized Breakdown

### FULLY_V3 (75 connectors - 10/10)

All V3 compliance markers present.

1password, airtable, algolia, amplitude, annas-archive, anthropic, arxiv, asana, bigquery,
bitbucket, bitwarden, box, browser, clickup, cron, datadog, discord, docusign, dropbox,
duckdb, elasticsearch, evernote, figma, github, gitlab, gmail, google-calendar,
google-people, google-workspace-events, grafana, hubspot, intercom, jira, linear, linkedin,
logseq, mailchimp, make, mcp-bridge, metabase, microsoft365, mixpanel, monday, mongodb,
n8n, notion, openai, pandadoc, pinecone, plaid, postgresql, posthog, pulumi, qdrant,
reddit, redis, retool, roam, s3, salesforce, segment, semanticscholar, sendgrid, sentry,
snowflake, spotify, stripe, todoist, trello, twilio, vectordb, whisper, youtube, zapier,
zendesk

### PARTIAL_V3 (9 connectors - 7-9/10)

| Connector | Score | Missing Markers |
|-----------|------:|----------------|
| google-ai | 9/10 | ConnectorErrorMapping |
| homeassistant | 9/10 | ConnectorErrorMapping |
| kubernetes | 9/10 | ConnectorErrorMapping |
| slack | 9/10 | ConnectorErrorMapping |
| twitter | 9/10 | ConnectorErrorMapping |
| terraform | 9/10 | deny_localhost |
| llm-router | 9/10 | ConnectorRuntime |
| webhook-receiver | 9/10 | ConnectorRuntime |
| telegram | 7/10 | ConnectorErrorMapping, deny_localhost, network-constraints |

### NEEDS_WORK (5 connectors - <7/10)

| Connector | Score | Missing Markers |
|-----------|------:|----------------|
| google-drive | 6/10 | archetype, ConnectorErrorMapping, deny_localhost, network-constraints |
| google-admin-reports | 5/10 | archetype, manifest-ops, deny_localhost, zones, network-constraints |
| google-chat | 4/10 | archetype, ConnectorErrorMapping, manifest-ops, deny_localhost, zones, network-constraints |
| google-docs | 4/10 | archetype, ConnectorErrorMapping, manifest-ops, deny_localhost, zones, network-constraints |
| google-sheets | 4/10 | archetype, ConnectorErrorMapping, manifest-ops, deny_localhost, zones, network-constraints |

---

## Top 10 Gap Connectors by Risk

| Rank | Connector | Score | Gaps |
|-----:|-----------|------:|------|
| 1 | google-chat | 4/10 | archetype, ConnectorErrorMapping, manifest-ops, deny_localhost, zones, network-constraints |
| 2 | google-docs | 4/10 | archetype, ConnectorErrorMapping, manifest-ops, deny_localhost, zones, network-constraints |
| 3 | google-sheets | 4/10 | archetype, ConnectorErrorMapping, manifest-ops, deny_localhost, zones, network-constraints |
| 4 | google-admin-reports | 5/10 | archetype, manifest-ops, deny_localhost, zones, network-constraints |
| 5 | google-drive | 6/10 | archetype, ConnectorErrorMapping, deny_localhost, network-constraints |
| 6 | telegram | 7/10 | ConnectorErrorMapping, deny_localhost, network-constraints |
| 7 | google-ai | 9/10 | ConnectorErrorMapping |
| 8 | homeassistant | 9/10 | ConnectorErrorMapping |
| 9 | kubernetes | 9/10 | ConnectorErrorMapping |
| 10 | llm-router | 9/10 | ConnectorRuntime |

---

## Gap Analysis by Category

### Missing ConnectorErrorMapping (10 connectors)

google-ai, google-chat, google-docs, google-drive, google-sheets, homeassistant, kubernetes,
slack, telegram, twitter

**Pattern:** 5 of 10 are newer Google expansion connectors from the lszk.45.3 wave.
The other 5 are original connectors not included in the streaming migration wave (9syku.11.3.2).

### Missing manifest.toml content (4 connectors)

google-admin-reports, google-chat, google-docs, google-sheets — built during Google expansion
wave (lszk.45.3) with minimal/no manifest files. Need full manifests with archetypes, zones,
provides, and network_constraints.

### Missing deny_localhost / NetworkConstraints (7 connectors)

- google-admin-reports, google-chat, google-docs, google-drive, google-sheets (no/minimal manifest)
- telegram, terraform (have manifests but operations lack deny_localhost/deny_private_ranges)

### Missing ConnectorRuntime (2 connectors)

llm-router, webhook-receiver

### Missing archetype declaration (5 connectors)

google-admin-reports, google-chat, google-docs, google-drive (old format), google-sheets

---

## Auth Model Distribution

| Auth Model | Count |
|-----------|------:|
| api-key | 33 |
| oauth | 21 |
| bearer | 16 |
| google-substrate | 10 |
| bot-token | 2 |
| aws-credentials | 1 |
| session-token | 1 |
| none | 3 |

---

## Archetype Distribution

| Archetype | Count |
|-----------|------:|
| operational | 72 |
| knowledge | 45 |
| streaming | 30 |
| storage | 10 |
| bidirectional | 6 |

---

## Tests Coverage

All 89 connectors have inline `#[cfg(test)]` tests. 81/89 also have `tests/` directories.

Missing `tests/` only: google-admin-reports, google-chat, google-drive, google-people,
google-workspace-events, postgresql, redis, whisper

---

## Remediation Priority

| Priority | Action | Connectors | Est. per connector |
|----------|--------|-----------|-------------------|
| **P0** | Create full manifest.toml | google-admin-reports, google-chat, google-docs, google-sheets | 30 min |
| **P1** | Add ConnectorErrorMapping | google-ai, google-chat, google-docs, google-drive, google-sheets, homeassistant, kubernetes, slack, telegram, twitter | 30 min |
| **P2** | Add deny_localhost/network_constraints | telegram, terraform | 15 min |
| **P3** | Fix google-drive manifest format | google-drive | 15 min |
| **P4** | Add ConnectorRuntime | llm-router, webhook-receiver | 20 min |
| **P5** | Add tests/ directory | 8 connectors | 30 min |

### Remediation Wave Plan

**Wave 1 (P0+P1 overlap):** google-chat, google-docs, google-sheets, google-admin-reports, google-drive
These 5 connectors account for most gaps. Fix manifests + add ConnectorErrorMapping in one pass.

**Wave 2 (P1 remaining):** homeassistant, kubernetes, slack, telegram, twitter, google-ai
Add ConnectorErrorMapping trait impl to error.rs.

**Wave 3 (P2-P4):** telegram, terraform (network constraints), llm-router, webhook-receiver (runtime).
