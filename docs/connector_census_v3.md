# FCP Connector Census — V3 Gap Scoring

> Generated: 2026-03-18 by SunnyMoose
> Scope: Historical 89-connector snapshot from 2026-03-18.
> Current inventory note: the live repository has grown beyond this audit snapshot; use `connectors/`, README, or manifest-backed `fwc list --offline` for the current connector inventory.

## Executive Summary

| Metric | Value |
|--------|-------|
| Total connectors | 89 |
| With ConnectorErrorMapping | 82 (92%) |
| With typed OperationInfo | 89 (100%) |
| With manifest.toml | 85 (95%) |
| With fcp-sdk dependency | 89 (100%) |
| Average test count | ~220 |
| V3 maturity ≥ 9/10 | 78 (88%) |
| V3 maturity 7-8/10 | 11 (12%) |

## Gap Priority Matrix

### Critical Gaps (ConnectorErrorMapping missing)

| Connector | Category | Tests | Gap | Remediation |
|-----------|----------|-------|-----|-------------|
| google-ai | AI/LLM | 184 | No ConnectorErrorMapping | Add impl to error.rs |
| slack | Messaging | 172 | No ConnectorErrorMapping | Add impl to error.rs |
| telegram | Messaging | 215 | No ConnectorErrorMapping | Add impl to error.rs |
| twitter | Messaging | 325 | No ConnectorErrorMapping | Add impl to error.rs |
| google-drive | Google | 24 | No ConnectorErrorMapping + low tests | Add impl + expand tests |
| google-docs | Google | 68 | No ConnectorErrorMapping + no manifest | Add impl + create manifest.toml |
| google-sheets | Google | 48 | No ConnectorErrorMapping + no manifest | Add impl + create manifest.toml |
| google-chat | Google | 72 | No ConnectorErrorMapping + no manifest | Add impl + create manifest.toml |

### Moderate Gaps (Missing manifest.toml)

| Connector | Tests | Gap |
|-----------|-------|-----|
| google-admin-reports | 11 | No manifest.toml + very low tests |

### Low Test Coverage (< 50 tests)

| Connector | Tests | V3 Score | Notes |
|-----------|-------|----------|-------|
| google-people | 11 | 8/10 | Has ConnectorErrorMapping |
| google-workspace-events | 14 | 8/10 | Has ConnectorErrorMapping |
| google-admin-reports | 11 | 8/10 | Missing manifest.toml |
| google-drive | 24 | 7/10 | Missing ConnectorErrorMapping |
| google-sheets | 48 | 7/10 | Missing ConnectorErrorMapping + manifest |

## Full Inventory

### AI & LLM (5 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| anthropic | operational, streaming | API key | YES | YES | YES | YES | 183 | 9 |
| openai | operational, streaming | API key | YES | YES | YES | YES | 166 | 9 |
| google-ai | operational, streaming | OAuth2 | **NO** | YES | YES | YES | 184 | 8 |
| llm-router | operational | None (meta) | YES | NO | YES | YES | 161 | 8 |
| whisper | operational, streaming | API key | YES | YES | YES | YES | 161 | 9 |

### Messaging (4 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| slack | operational, streaming, bidir | Bearer | **NO** | YES | YES | YES | 172 | 8 |
| discord | operational, streaming, bidir | Bot token | YES | YES | YES | YES | 160 | 9 |
| telegram | operational, polling | Bot token | **NO** | YES | YES | YES | 215 | 8 |
| twitter | operational, streaming, bidir | OAuth 1.0a | **NO** | YES | YES | YES | 325 | 8 |

### Google Workspace (12 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| gmail | operational, streaming | OAuth2 | YES | YES | YES | YES | 164 | 9 |
| google-calendar | operational | OAuth2 | YES | YES | YES | YES | 177 | 9 |
| google-drive | operational | OAuth2 | **NO** | YES | YES | YES | 24 | 7 |
| google-docs | operational | OAuth2 | **NO** | YES | YES | **NO** | 68 | 7 |
| google-sheets | operational | OAuth2 | **NO** | YES | YES | **NO** | 48 | 7 |
| google-chat | operational | OAuth2 | **NO** | YES | YES | **NO** | 72 | 7 |
| youtube | operational | OAuth2 | YES | YES | YES | YES | 180 | 9 |
| google-people | operational | OAuth2 | YES | YES | YES | YES | 11 | 8 |
| google-workspace-events | operational | OAuth2 | YES | YES | YES | YES | 14 | 8 |
| google-admin-reports | operational | OAuth2 | YES | YES | YES | **NO** | 11 | 8 |
| bigquery | knowledge, storage | OAuth2 | YES | YES | YES | YES | 197 | 9 |
| google-ai | (see AI section) | | | | | | | |

### Dev Tools (9 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| github | operational, streaming | OAuth2 | YES | NO | YES | YES | 173 | 9 |
| gitlab | knowledge, operational | OAuth2 | YES | NO | YES | YES | 197 | 9 |
| bitbucket | knowledge, operational | OAuth2 | YES | NO | YES | YES | 193 | 9 |
| linear | operational, streaming | OAuth2 | YES | NO | YES | YES | 205 | 9 |
| jira | operational, streaming | Bearer | YES | NO | YES | YES | 233 | 9 |
| clickup | knowledge, operational | API key | YES | NO | YES | YES | 186 | 9 |
| todoist | knowledge, operational | API key | YES | NO | YES | YES | 212 | 9 |
| trello | knowledge, operational | API key | YES | NO | YES | YES | 186 | 9 |
| asana | knowledge, operational | Bearer | YES | NO | YES | YES | 192 | 9 |

### Cloud & Infrastructure (7 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| s3 | storage, operational | AWS Keys | YES | NO | YES | YES | 163 | 9 |
| kubernetes | operational, streaming | Bearer | YES | NO | YES | YES | 491 | 9 |
| terraform | operational | Bearer | YES | NO | YES | YES | 1174 | 10 |
| pulumi | operational | Bearer | YES | NO | YES | YES | 200 | 9 |
| datadog | knowledge, operational | API key | YES | NO | YES | YES | 217 | 9 |
| grafana | knowledge, operational | API key | YES | NO | YES | YES | 191 | 9 |
| sentry | knowledge, operational | Bearer | YES | NO | YES | YES | 446 | 9 |

### Databases (9 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| postgresql | knowledge, storage | API key | YES | NO | YES | YES | 174 | 9 |
| redis | knowledge, operational | Bearer | YES | NO | YES | YES | 171 | 9 |
| mongodb | knowledge, storage | Service acct | YES | NO | YES | YES | 188 | 9 |
| elasticsearch | knowledge, operational | API key | YES | NO | YES | YES | 190 | 9 |
| duckdb | knowledge, storage | Service acct | YES | NO | YES | YES | 173 | 9 |
| snowflake | knowledge, storage | OAuth2 | YES | NO | YES | YES | 189 | 9 |
| qdrant | knowledge, operational | API key | YES | NO | YES | YES | 161 | 9 |
| pinecone | knowledge, operational | API key | YES | NO | YES | YES | 166 | 9 |
| vectordb | operational, bidir | Service acct | YES | NO | YES | YES | 168 | 9 |

### Productivity (8 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| notion | operational, knowledge | Bearer | YES | NO | YES | YES | 162 | 9 |
| airtable | storage, operational | Bearer | YES | NO | YES | YES | 552 | 9 |
| figma | knowledge, operational | Bearer | YES | NO | YES | YES | 227 | 9 |
| docusign | operational, streaming | OAuth2 | YES | NO | YES | YES | 807 | 9 |
| pandadoc | knowledge, operational | Bearer | YES | NO | YES | YES | 180 | 9 |
| evernote | knowledge | Bearer | YES | NO | YES | YES | 180 | 9 |
| logseq | knowledge | API key | YES | NO | YES | YES | 189 | 9 |
| roam | knowledge | API key | YES | NO | YES | YES | 206 | 9 |

### Communication (6 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| sendgrid | operational | API key | YES | NO | YES | YES | 182 | 9 |
| twilio | operational | API auth | YES | NO | YES | YES | 185 | 9 |
| mailchimp | operational | API key | YES | NO | YES | YES | 196 | 9 |
| hubspot | operational | OAuth2 | YES | NO | YES | YES | 201 | 9 |
| intercom | operational | Bearer | YES | NO | YES | YES | 195 | 9 |
| zendesk | operational | API key | YES | NO | YES | YES | 604 | 9 |

### Finance (2 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| stripe | operational | API key | YES | NO | YES | YES | 174 | 9 |
| plaid | operational | API key | YES | NO | YES | YES | 191 | 9 |

### Analytics (5 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| mixpanel | operational | API token | YES | NO | YES | YES | 189 | 9 |
| amplitude | operational | API key | YES | NO | YES | YES | 196 | 9 |
| posthog | operational | API key | YES | NO | YES | YES | 204 | 9 |
| segment | operational | Write key | YES | NO | YES | YES | 198 | 9 |
| metabase | operational | Session | YES | NO | YES | YES | 188 | 9 |

### Security (2 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| 1password | operational | Bearer | YES | NO | YES | YES | 167 | 9 |
| bitwarden | operational | OAuth | YES | NO | YES | YES | 170 | 9 |

### Automation (6 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| zapier | operational | OAuth2 | YES | NO | YES | YES | 194 | 9 |
| make | operational | API token | YES | NO | YES | YES | 184 | 9 |
| n8n | operational | API key | YES | NO | YES | YES | 189 | 9 |
| retool | operational | API key | YES | NO | YES | YES | 200 | 9 |
| cron | operational | None | YES | NO | YES | YES | 169 | 9 |
| webhook-receiver | operational | None | YES | NO | YES | YES | 164 | 9 |

### Content (6 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| reddit | operational | OAuth2 | YES | NO | YES | YES | 1221 | 9 |
| linkedin | operational | OAuth2 | YES | NO | YES | YES | 183 | 9 |
| spotify | operational | OAuth2 | YES | NO | YES | YES | 741 | 9 |
| annas-archive | operational | None | YES | NO | YES | YES | 161 | 9 |
| arxiv | operational | None | YES | NO | YES | YES | 312 | 9 |
| semanticscholar | operational | None | YES | NO | YES | YES | 204 | 9 |

### Other (8 connectors)

| Connector | Archetype | Auth | ErrorMapping | Runtime | OperationInfo | Manifest | Tests | V3 |
|-----------|-----------|------|-------------|---------|--------------|----------|-------|-----|
| browser | operational | None | YES | NO | YES | YES | 185 | 9 |
| mcp-bridge | operational | None | YES | NO | YES | YES | 198 | 9 |
| microsoft365 | operational | OAuth2 | YES | NO | YES | YES | 631 | 9 |
| salesforce | operational | OAuth2 | YES | NO | YES | YES | 174 | 9 |
| box | storage | OAuth2 | YES | NO | YES | YES | 196 | 9 |
| dropbox | storage | OAuth2 | YES | NO | YES | YES | 188 | 9 |
| homeassistant | operational | Bearer | YES | NO | YES | YES | 345 | 9 |
| algolia | operational | API key | YES | NO | YES | YES | 181 | 9 |

## Remediation Priority

### Wave 1 — ConnectorErrorMapping (highest blast radius)
1. slack (172 tests, streaming connector)
2. twitter (325 tests, streaming connector)
3. telegram (215 tests, polling connector)
4. google-ai (184 tests, streaming)
5. google-drive, google-docs, google-sheets, google-chat

### Wave 2 — Missing manifest.toml
1. google-docs → create manifest.toml from hardcoded values
2. google-sheets → create manifest.toml
3. google-chat → create manifest.toml
4. google-admin-reports → create manifest.toml

### Wave 3 — Test coverage expansion
1. google-people: 11 → 50+ tests
2. google-workspace-events: 14 → 50+ tests
3. google-admin-reports: 11 → 50+ tests
4. google-drive: 24 → 100+ tests
5. google-sheets: 48 → 100+ tests
