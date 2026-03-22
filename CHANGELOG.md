# Changelog

All notable changes to the **Flywheel Connector Protocol (FCP)** repository are documented here.

This project has no tagged releases or GitHub Releases. Development follows a continuous integration model on `main`, with logical milestones organized by date and capability landing. Commit links point to the canonical repository at `https://github.com/Dicklesworthstone/flywheel_connectors`.

---

## [Unreleased] — as of 2026-03-21

**Current state:** 121 connectors, 30 infrastructure crates, ~1,980 commits, 58,000+ tests.

---

## 2026-03-21 — Connector Expansion Wave 6 and Schema 2.1 Rewrites

### New Connectors
- **Feishu, LINE, Obsidian, Twitch** scaffolded with manifests and typed operations ([0c20a27a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0c20a27aca3c35277d8824af29326b0e3d1ba736))
- **Calendly, Coda, Mastodon, Hacker News** built as full connectors ([4a23a6ae](https://github.com/Dicklesworthstone/flywheel_connectors/commit/4a23a6ae0893a3f3b6fc17ea68c1bc9a19d0523f))
- **CircleCI, Confluence, Zoom, Square** built as Tier 2 connectors ([9671e045](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9671e045c95173c2923261d3d71cdd216880bd22))
- **Coda** expanded to full first-slice implementation with workspace scoping ([991cf8bf](https://github.com/Dicklesworthstone/flywheel_connectors/commit/991cf8bfd6e31bc53264df74b05ed8cd93b5aa1e))

### Manifest Schema 2.1 Rewrites
- **Shopify** auth model refactored; **Square** manifest rewritten to schema 2.1 ([408fef20](https://github.com/Dicklesworthstone/flywheel_connectors/commit/408fef207b4334690b22dd6552ce76ea02d5495c))
- **PayPal** rewritten to schema 2.1 with configurable timeout ([6316f6cf](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6316f6cf55fc71aa74b4bc69a5d22522f353fa07))
- **Cloudflare** rewritten to schema 2.1 with expanded operation surface ([f5cd0fb4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f5cd0fb4fa6b5450f419fc3a93f52cba029c7d73))
- **CircleCI** rewritten to fcp-connector-manifest schema 2.1 ([b2d37f33](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b2d37f33bbf179aa73cb4c255facb254e43d9579))

### Security
- Path traversal and SQL injection sanitization added across 9 connectors ([3cc324fd](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3cc324fd84643fc13a1b6403f668ea00ee791e78))
- Deep audit wave 3: Sentry, Datadog, Grafana, HubSpot, MS365, Zendesk, Intercom, Box, Airtable, Salesforce, DocuSign, Snowflake ([a8354cd9](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a8354cd9abc31eaf3a76347a1bf962a767dbd64d))
- Deep audit wave 2: Telegram, Google, PostgreSQL, BigQuery, DuckDB ([4111672e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/4111672e0e16934b4e42d4e873f6e1f359b2ea61))

### Infrastructure
- **fcp-core**: instance-binding verification and CWT `target_instance` support ([69d8f5f5](https://github.com/Dicklesworthstone/flywheel_connectors/commit/69d8f5f58c10b7afde8c8839b53b82c200768670))
- **fcp-core**: hardened crate internals across crypto, host, mesh, and sandbox ([f237ae93](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f237ae9385ab217f5548b481fb95207726cdc893))
- **fcp-host**: ExponentialBackoff guarded against NaN and zero-initial edge cases ([d381c424](https://github.com/Dicklesworthstone/flywheel_connectors/commit/d381c4244959e15b9d776315cb6368d7406fe3c5))
- Microsoft 365: readiness profiles, error classification, and Graph API path fixes ([117e9000](https://github.com/Dicklesworthstone/flywheel_connectors/commit/117e90007b09d6658dca7601efdb09c8cc1698b7))

---

## 2026-03-20 — Security Deep Audit Wave 1 and Tier 2 Platform Connectors

### New Connectors
- **Firebase, iMessage, Nextcloud Talk, SQLite** ([0deb4b72](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0deb4b72925dda8a5012fd1d285daaf7384002e9))
- **Signal** expanded with group messaging, identity verification, bridge health, and full operation catalog ([afc35ad1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/afc35ad1210a748486a8c39be3ee39fc31623c78), [9892ce94](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9892ce949560b9be40b5fdfda1b21d89f79e4896))

### Security
- Deep audit URL injection fixes across Discord, Twitter, GitHub, Notion, Elasticsearch, Kubernetes, Stripe, S3 ([ec9942fd](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ec9942fd1258a229c9fc98b1160c393376ebb9bf))
- URL encoding and input validation hardening across GitHub, Notion, S3, Stripe, Discord, Elasticsearch, Twitter, Kubernetes ([2a719ae7](https://github.com/Dicklesworthstone/flywheel_connectors/commit/2a719ae778a0b6fac400a3f04a7bdd584430d1b8), [2ddcf0ba](https://github.com/Dicklesworthstone/flywheel_connectors/commit/2ddcf0bae5017269c1a8427217a92331ccaa9378))
- URL path injection prevention across all new connectors and infrastructure crates ([6b7ee7ee](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6b7ee7eeed9438d56708963cd1b2e6b070fb5124), [284d5c31](https://github.com/Dicklesworthstone/flywheel_connectors/commit/284d5c31bc26a7b25c4eb41ff84d3ececaf96b1c))

### Connector Improvements
- **Matrix** expanded with sync, media, state, and room management operations ([1882aa48](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1882aa48b1f6d30b8c258631c52d91d1f5ca6e72))
- **Azure** switched to native XML parsing for blob listing with strict URL validation ([4e465e7f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/4e465e7fcc45c9904272dd0e33fb7cefa1e518d3))
- **Mattermost** hardened configuration validation, added resource types and auth caps ([652eb2ba](https://github.com/Dicklesworthstone/flywheel_connectors/commit/652eb2bae8aafde26f5920023a1d22bf286c9118))
- **MySQL** V3 readiness infrastructure, manifest, and client improvements ([63dff484](https://github.com/Dicklesworthstone/flywheel_connectors/commit/63dff484b1fe88a8720577e699c59a7490358fd5))
- V3 readiness, provisioning, and operator guidance added to AWS, Azure, Firebase, GCP, and Teams connectors ([9c84ea75](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9c84ea7507974b827662c4ad9af862c9cbdc0ffa))

### Testing
- Integration tests and GCP compliance E2E verification scripts ([3fedbfe1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3fedbfe1d59502843fd8ae2600f839ed4249510d))
- Cloudflare and WhatsApp integration tests and E2E verification scripts ([46eb9a83](https://github.com/Dicklesworthstone/flywheel_connectors/commit/46eb9a834af5d2a74135dd8e699aba17e5e92d99))

---

## 2026-03-19 — Cloud Control Plane Wave and Infrastructure Audit

### New Connectors
- **AWS and GCP** cloud control plane connectors ([8d2ca94f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/8d2ca94fc945d4959348f7bd432fe27dd115d597))
- **Azure** with ARM, Blob Storage, and Key Vault ([72e682da](https://github.com/Dicklesworthstone/flywheel_connectors/commit/72e682da9616f689261398f33784ea5f94fc80c2))
- **Supabase** rebuilt with V3-native FcpConnector trait ([5bfd4c1c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/5bfd4c1c4b419343b87f69b7f5604e3bc86f4334))
- **Vercel** deployment platform connector with 10 operations ([9aeccca3](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9aeccca3e1cb8d82f10a98d9d523f21e9d197156))
- **Cloudflare** connector with Workers, Pages, DNS, KV, Zones ([0ef38911](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0ef3891139eebc0f3161827d9fc524992457ab60))
- **Netlify, DockerHub, Shopify, PayPal** built as Tier 2 connectors ([c1f15671](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c1f1567147a0845ebad5f82b144fcf597443a362))

### Security
- Deep audit fixes across connectors and infrastructure crates ([62d594a4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/62d594a47d3d199a6d6e0b7dc0c93a38608d96fb))
- X25519 key validation, supervisor restart backoff, OAuth1 nonce, and SSE parser hardening ([bc69cb5e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/bc69cb5e48368db2dd0ccd8ca9ebe02b30660900))

### Infrastructure
- **fcp-core**: canonical CBOR header included in operation signable bytes ([f6db6a0c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f6db6a0c6b2a09765c636e3bccf4a2065d4b385e))
- **fcp-mesh**: epoch mismatch check removed; object IDs passed to receipt validation ([3ce4c543](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3ce4c5436fe09167b84906c4a5fd7986d0013aab))
- **fcp-webhook**: timestamp context in deterministic event IDs for dedup accuracy ([ad6948d6](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ad6948d64fcaf0b253d0459b4ee77e1eaf9ce73c))
- Credential-ID auth, path encoding, delta URL safety, webhook expansion across connectors ([fe01c7ba](https://github.com/Dicklesworthstone/flywheel_connectors/commit/fe01c7bae28d3dc11c3633b9c3078959dae52cf6))

---

## 2026-03-18 — Messaging Platform Wave (WhatsApp, MySQL, Mattermost, Matrix, Teams)

### New Connectors
- **WhatsApp Business API** with V3 compliance ([fd515dc6](https://github.com/Dicklesworthstone/flywheel_connectors/commit/fd515dc615cd6e899ece02e30c35f9843cb6a19e))
- **MySQL/MariaDB** with V3 compliance ([4f652dca](https://github.com/Dicklesworthstone/flywheel_connectors/commit/4f652dca4f0b11d65144d762e1fdc8fd1d845073))
- **Mattermost** with WebSocket events, threads, files, and reactions ([b7380ff9](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b7380ff9b41d9c242ff3aa8f15fa049868a0e113))
- **Matrix** federated messaging connector ([d1b5ab55](https://github.com/Dicklesworthstone/flywheel_connectors/commit/d1b5ab5554e9fff7281d8c325ad6c12234f5fe27))
- **Teams** connector runtime, manifest, and operations ([1e8803d4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1e8803d45db6df2886312e4debe64f0111bd9457))

### V3 Contract
- V3 acceptance contract, archetype checklists, taxonomy, manifest templates, and scaffold guidance ([6eb23485](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6eb23485afe0f6b5758f83efa04df49eba2d755b))
- V3 connector compliance audit matrix and census gap scoring ([4ab2eb40](https://github.com/Dicklesworthstone/flywheel_connectors/commit/4ab2eb40e2395f902c28c74a4b0a23c86d3921c7))

### Infrastructure
- **fcp-telemetry**: async-aware context scoping, zero-ID normalization, and duplicate header rejection ([20012855](https://github.com/Dicklesworthstone/flywheel_connectors/commit/2001285504e0ed7a3285f0307d2d8d3e8bff0de0))
- **fcp-mesh/fcp-store**: corrected `is_final` for zero-budget responses and GC zone-scoping ([6c876e53](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6c876e53f2dfc8534fcd19531f66e18f768a07a2))
- **fcp-testkit**: Stripe signature fix for lossy UTF-8, improved readiness/webhook helpers ([761c63d1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/761c63d14c8a39b2282ce84998cd068a16227dd6))

---

## 2026-03-17 — FCP Protocol Loop Standardization and SDK Improvements

### Infrastructure
- **fcp-sdk**: `execute_from_attempt` for retry resumption; guard `u32::MAX` attempt overflow ([770f3b42](https://github.com/Dicklesworthstone/flywheel_connectors/commit/770f3b42995d075abf43b8c6ec40d32557055b00))
- **fcp-telemetry**: RAII context guard, lowercase hex enforcement in trace/span IDs ([0d679001](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0d6790014da5cf0b518f5d29acf567de29d83181), [53849cf3](https://github.com/Dicklesworthstone/flywheel_connectors/commit/53849cf3c0d311b4e2e63e5f2b03d62b7d7f0941))
- **fcp-webhook**: panic prevention on DeadLetterQueue push with zero capacity ([c44fa5f8](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c44fa5f876ff82d44ec1582bec839bb808995af4))
- Standardized FCP protocol loop across Anthropic, Datadog, Gmail, Notion, OpenAI, Slack ([e34687da](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e34687da2a512eb666bbeb0b978eb4c799d8316a))
- Anthropic SSE buffer overflow guard; Linear single-sided linkage conflict detection ([1cef5e25](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1cef5e25598c08e76a41cc27adcd754074a00032))

### Documentation
- Full 89-connector catalog and architecture overview in README ([ee972bd1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ee972bd110c7206ead8ef0a3091313479061aa68))

---

## 2026-03-15 — 2026-03-16 — Truthful Metadata, Store Hardening, and Streaming Health

### fwc CLI
- Faceted search fix with empty query; MCP tests migrated to async-core ([2fd27ad1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/2fd27ad1c07cce5114badef9b80b5871d6a73a2c))
- MeshMirror artifact source kind and install repair hints ([c67cf51e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c67cf51e1abfb8dd58089ffaa4904688f3e12ab5))
- Rate forecast batch feasibility with schedulable flag ([7f64c8b1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/7f64c8b14fc04c99bff22d2594d233a96305dc8a))
- Tri-state `MetadataField<bool>` for `supports_simulate` and `has_events` ([aa6bdbaa](https://github.com/Dicklesworthstone/flywheel_connectors/commit/aa6bdbaa80b5c620f159742addcda2888a4f8c68))

### Infrastructure
- **fcp-core**: `FcpConnector::rate_limits()` returns `Option` to preserve unknown state ([9ec9a35e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9ec9a35ecd28d4c4ce0d2797d9af186370b331d2))
- **fcp-host**: discovery capability fields changed from `bool` to `Option<bool>` ([3e1db8a0](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3e1db8a00243d78079e08afb17fd65578911d959))
- **fcp-host**: invoke budget usage recording from response metrics ([0b96550d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0b96550d3c7f5503e84fb78a8262a2d39f787c29))
- **fcp-host**: capability constraints serialized into COSE token claims ([6ef3e92e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6ef3e92ec3f3735ad2b80b93062be90064e35069))
- **fcp-streaming**: StreamHealthTracker state machine for connection liveness ([2ccdf818](https://github.com/Dicklesworthstone/flywheel_connectors/commit/2ccdf81867e655b26d2a2d82ed6a7414133f1add))
- **fcp-store**: truncating `usize`-to-`u32` casts replaced with saturating `try_from` ([78c78df8](https://github.com/Dicklesworthstone/flywheel_connectors/commit/78c78df8eee4a08468d72a1c53c0223355f4cb64))
- **fcp-sandbox**: filesystem path validation at manifest and policy layers ([735d8f7f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/735d8f7f7f879cfb9f17fa1686ec4b729d820d88))
- **fcp-bootstrap**: genesis state write made crash-safe via atomic rename with fsync ([0314805b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0314805b24e73b683f42e3c89c7e819dfd3ad75d))
- **fcp-oauth**: secrets redacted in Debug output; fragment response mode support ([751e464f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/751e464f3bb49d54a0503cf21b3125c70abbcf78))
- **fcp-webhook**: deduplicated routed handlers; deterministic event IDs; Slack event type fix ([388c23b4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/388c23b4ff1d848b90e30e3402d271fb711049c1))
- Anthropic SSE parser hardened with binary buffer, CRLF support, and multiline data ([5d1da645](https://github.com/Dicklesworthstone/flywheel_connectors/commit/5d1da645486fa731084e730b616f6245d77e4ed9))

---

## 2026-03-14 — ConnectorRuntime, Google Workspace, and Retry Centralization

### Connector Runtime
- `ConnectorRuntime` lifecycle wired into all connector structs ([6a240a7a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6a240a7a64606da34c6db2f78c6cff141019ab30))
- `HttpRetryConfig` added to all connector clients ([0a2fe8db](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0a2fe8dbbbfd8cc5a9d6c67f9104ea64fedce151))
- `ConnectorErrorMapping` implemented for all 87 connector error types ([23927756](https://github.com/Dicklesworthstone/flywheel_connectors/commit/239277562f3ffb266e032baf72d2a1df15e50b24))
- 12 connector retry loops migrated to centralized RetryLoop ([1c744665](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1c744665826969e8cb05e2df861a2ec4937bdcf4))

### Google Workspace
- Google Admin Reports, Chat, Docs, People, and Workspace Events connectors scaffolded ([627443c1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/627443c176ce36f37a80112179b280871c3699fc))
- Google Drive and Google Sheets connectors scaffolded ([79075193](https://github.com/Dicklesworthstone/flywheel_connectors/commit/79075193a5649b9825ecea61f5945335bfcfcb9d))

### Infrastructure
- **fcp-async-core**: WebSocket client sub-module; MCP test IO migration ([cd3e734c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/cd3e734c2f07b35a8b71e9569f9ffea5fdf6106b))
- **fcp-async-core**: Lines, stdin/stdout bridges; MCP stdio migrated to async-core ([1d1aecd5](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1d1aecd52c8d8191c37d37ff054d663eb8d31885))
- **fcp-store**: zone-level SLO metrics in repair planner ([eff8567a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/eff8567a919ac8f3dbd558f3ff4598f8a840079b))
- **fcp-store**: power and network-aware adaptive repair budgeting ([ae154b9f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ae154b9f9bd2357032c6258a8ec325a5b237d6c6))
- **fcp-host**: BudgetCheck enforcement step and vector-driven capability tests ([acc5b70d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/acc5b70d992fefdac9fabd25bfd70ed7a87697dc))
- **fwc**: scaffold generates V3-native connectors ([64485fb2](https://github.com/Dicklesworthstone/flywheel_connectors/commit/64485fb220f6ecad35ab83338164e8dc60dcbea9))
- Anthropic v3 lifecycle E2E test and Tokio bridge architecture decision ([1196369e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1196369e9e88fc455e74b9f4dbf266b9aa331f4f))

---

## 2026-03-12 — 2026-03-13 — FCP3 Specification, fwc CLI Expansion, and PCS Zones

### FCP Specification V3
- FCP3 promoted as canonical spec target; V2 demoted to historical reference ([6f428d1a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6f428d1a4e6fa0673582946a01ba85fdc3b80ef6))
- Post-Compromise Security (PCS) zones via TreeKEM ratcheting in fcp-core ([22681fac](https://github.com/Dicklesworthstone/flywheel_connectors/commit/22681fac390bbf4ef756ab5b65d716077148175f))
- Durable state ownership, checkpoint cadence, resume/duplicate-delivery classification ([c9d427db](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c9d427db69df75c02f085271cf18e90da98e9013))

### fwc CLI (Major Expansion)
- Auth verify subcommand with credential diagnostics ([45805b57](https://github.com/Dicklesworthstone/flywheel_connectors/commit/45805b5789eb9bdb7c1cdd094421539c88d42553))
- Mesh availability, explain-availability, and repair-hints subcommands ([bdca5205](https://github.com/Dicklesworthstone/flywheel_connectors/commit/bdca52051b7feb0aff61c644d4f4eae74a5e3729))
- Prerequisite onboarding and mesh targeting modules (+318 tests) ([6746e502](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6746e50258b3dca353fab0121362d66b4dbd6e0a))
- Capability gap analyzer, blocker diagnosis, approval bundle lifecycle, agent/operator playbooks ([b1ee3051](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b1ee3051dc67bd7c5ad3274283510224808ee067))
- Access, setup, mesh command families (+494 tests) ([d1912427](https://github.com/Dicklesworthstone/flywheel_connectors/commit/d191242726adcbae92992c908155aa48fd3107c9))
- Lifecycle CLI with preflight checks and state-machine queries ([b9fa1dd3](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b9fa1dd3a85041d1bf02cdb8e4804d9f42c04bfa))
- Event filtering, history replay, and snapshot test suites (+2058 tests) ([b2551705](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b25517058acdaf8ff05d6c8d9b57fe4aad736cb1))
- Replay, compare, undo, approvals commands ([cc018b29](https://github.com/Dicklesworthstone/flywheel_connectors/commit/cc018b29f2683160b5eff037bf521401897188a1))
- Tail/watch commands for streaming and operation monitoring ([ba9c823d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ba9c823dc0c2a452fc97d7c1dd89e1f0be4177b9))
- OS keychain backend for credential storage with encrypted-file fallback ([f2bd7bbe](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f2bd7bbec26c149e821d9f4ec2a16902c456e348))
- Structured quickstart guide on bare invocation ([15aff32e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/15aff32ec89bdec908fbb03b8869abfcea81e0a5))

### Infrastructure
- **fcp-host**: MCP 2025 agent-facing protocol surface (`agent_api.rs`) ([821286fc](https://github.com/Dicklesworthstone/flywheel_connectors/commit/821286fcecc4350f2a7809fe440033ac4c28aa89))
- **fcp-host**: enforcement pipeline and health check API modules ([c75f9097](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c75f90971a68405310549a4294ebe4ece96939a7))
- **fcp-host**: signal handling for graceful shutdown and config reload ([757af652](https://github.com/Dicklesworthstone/flywheel_connectors/commit/757af652397cfbbf7807658819d3cc2a11c38564))
- **fcp-host**: live `/rpc/simulate` endpoint with capability-gated preflight ([884d2421](https://github.com/Dicklesworthstone/flywheel_connectors/commit/884d24218405727bef49303ed0395f0b7edc58db))
- **fcp-testkit/fcp-e2e**: FCP3 testing doctrine modules ([11d8cc89](https://github.com/Dicklesworthstone/flywheel_connectors/commit/11d8cc89d11511e2d301520925927d9f9498aee1))
- Tokio migration: direct deps migrated to fcp-async-core across 6 crates ([f0545170](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f0545170ee0b14886de2857a99c64f8fa3e6b978))

### Connector Improvements
- YouTube: channel analytics and video upload operations ([53735e35](https://github.com/Dicklesworthstone/flywheel_connectors/commit/53735e35fa8c1e6ea34cb87078852393201f4f84))
- Gmail: migrated to shared fcp-google-discovery substrate ([33afe010](https://github.com/Dicklesworthstone/flywheel_connectors/commit/33afe010c0975bbeaa5a8c287e8f091403bcd9e0))
- Anthropic: hand-rolled retry loop replaced with centralized RetryLoop ([e40efe5d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e40efe5d35afcf34eb956b3fce4416deb6308f9b))
- ConnectorErrorMapping trait implemented across multiple batches of connectors ([55fdf3f8](https://github.com/Dicklesworthstone/flywheel_connectors/commit/55fdf3f897d3def80261982bc53ffa3a8dc8e655), [821c64d7](https://github.com/Dicklesworthstone/flywheel_connectors/commit/821c64d733ed7e3eaf866a587a8058f7a4dab4ae))

---

## 2026-03-10 — 2026-03-11 — Host-First Runtime, fwc Truthfulness, and 40+ Connector Improvements

### fwc CLI Truthfulness Foundation
- Host-first truthfulness with audit chain and package command test suites ([f945f048](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f945f04876a928057419260e811d41aac7602bbc))
- `CommandTruthMode` taxonomy and output semantics ([6ae1d541](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6ae1d541da6eb2d78804498e91844e2515850630))
- `MetadataField<T>` enum for explicit metadata state tracking ([64a6e345](https://github.com/Dicklesworthstone/flywheel_connectors/commit/64a6e345f5b43ea2d728bc380c5ff815250def68))
- Dynamic MCP resource and prompt generation from connector operations ([67c876ac](https://github.com/Dicklesworthstone/flywheel_connectors/commit/67c876acf3dde5bca228dee9195f99fda6add7f2))
- Fuzzy matching for operation discovery with edit-distance budgeting ([bafead3b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/bafead3bd0afe76bdffb9462f9251fad27e5a41f))
- Agent session management with resumable context persistence ([427b84bc](https://github.com/Dicklesworthstone/flywheel_connectors/commit/427b84bc6733e953589379872a6fad1902f85a98))
- Zone-scoped tool filtering for MCP server ([a0c7faec](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a0c7faec0cd0eec90e7c219596721aee13e745b9))

### fcp-host Expansion
- Admin state machine major expansion and host binary ([e2ff02d3](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e2ff02d38563d874637011630656e06693ee52fa))
- Supervisor module with restart policies, resource limits, and connection tracking ([8d5429f4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/8d5429f479723d493d460bc976aac62f3f10c576))
- Operation receipt tracking with persistence and query API ([6e380feb](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6e380feb1df2380c3a5a4b9e6ce94a62c4be8080))
- Connector self-check integration and repair hints ([1b2a8799](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1b2a8799be55ac101cc752d1fe69dbcc01b244ec))
- Config snapshot, validate, apply, and rollback RPC methods ([7c0c87bf](https://github.com/Dicklesworthstone/flywheel_connectors/commit/7c0c87bf1848b0c20cf26fd0e502723d1e45a726))
- Connector drift detection, recovery actions, and status HTTP endpoint ([53e390c6](https://github.com/Dicklesworthstone/flywheel_connectors/commit/53e390c6fa0b5f836e67fa10f382ac636a18646e))
- Connector artifact provenance metadata registration and query ([c56b1734](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c56b1734c4c2e82892e78fd3101a80ac850eb826))
- Log redaction module for secret-safe output ([88822f2e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/88822f2e23cefc50370f12eacdbc87afbe471e80))
- Budget reporting HTTP endpoint ([b8ccd35d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b8ccd35d669d2af64d4d9dd0419921fe5bc7ac7f))

### Connector Improvements
- 40+ connectors improved with feature expansions, formatting, and test coverage ([2ceb1a78](https://github.com/Dicklesworthstone/flywheel_connectors/commit/2ceb1a78035baad1e02bad35e487125dbca1cc10))
- Microsoft 365: OneNote and Word document support ([ff8a3351](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ff8a3351b7e29592e1b84ea535b3fdf64af386bf))
- Google AI: expanded with new capabilities, types, and test coverage ([38dace22](https://github.com/Dicklesworthstone/flywheel_connectors/commit/38dace22566e582b3abfee80a780a455e72e27d7))

### Infrastructure
- **fcp-core**: `NotYetMeasured` and `Unavailable` descriptor status variants ([183d32af](https://github.com/Dicklesworthstone/flywheel_connectors/commit/183d32af3b8f57d5044629bbc95c972cc3429adf))
- **fcp-core**: capability IDs migrated to `Arc<str>` ([22be4cae](https://github.com/Dicklesworthstone/flywheel_connectors/commit/22be4cae7590245501f27ad683d29b7397143fd5))
- **fcp-core**: time-aware device posture validation for audit replay ([ff208069](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ff2080698e1dd81849ee5064672406c63ba25dcc))
- **fcp-registry**: RaptorQ erasure-coded symbol mirroring for resilient binary distribution ([bcaca0b3](https://github.com/Dicklesworthstone/flywheel_connectors/commit/bcaca0b3ce6f2bbd6e98b4d4051a2c887c3e5a05))
- **fcp-sandbox**: CIDR deny rules rejection instead of silent ignoring ([6c16a930](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6c16a9300c7b05765b8a965f71efa444ee4b1d9d))
- Retired fcp-cli crate from workspace ([1db19e34](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1db19e348a2083c79da214161a8cf152e162e8c8))

### FCP Specification V3
- V3 spec expanded with merge algorithm, rich approvals, reconciliation, provenance resolution, sink classification, mesh identity, threshold signing, and security primitives (multiple commits 2026-03-09 through 2026-03-10) ([46550574](https://github.com/Dicklesworthstone/flywheel_connectors/commit/46550574306afe5d84716c850572ad5acbc5698d))

---

## 2026-03-08 — 2026-03-09 — CUAL Modules, Connector Provisioning, and Massive Test Expansion

### fwc CUAL (CLI Unified Access Layer)
- MCP server module with JSON-RPC routing (116 tests) ([0bee8c0b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0bee8c0b9438205aff0a0a52513d90a2eca6403f))
- Agent Mail multi-agent coordination module ([3a3376d4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3a3376d479f222fe4af73f2d3e9e397f533a55a5))
- Zone-scoped MCP tool enforcement ([a6dc11f7](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a6dc11f7260b06a72f68cdc18b56e6df5a1cbc5c))
- Secretless credential injection module ([6250f5ba](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6250f5ba78227eb3f70dea5838f2bdb71d4bd5c4))
- Token rotation tracking and expiry alerts ([b4fc3129](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b4fc3129565b54515118ea0d261d35ddf4d3733f))
- Credential store, event filtering, operation replay modules ([c5c436e5](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c5c436e5723c3deed0c9445f80fa955d19c6fc09))
- Cross-connector semantic operation search engine ([39c9fc1a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/39c9fc1acb87dae795db73691dffc4bbe3bce9db))
- Deep schema navigator + input validation modules ([72503022](https://github.com/Dicklesworthstone/flywheel_connectors/commit/72503022ee117d13d6ed0c2391f0c28ec8f6d6a1))

### Connector Deep Dives
- **Twilio**: Conversations API, Verify 2FA, WhatsApp Business, Programmable Video, SMS media (multiple commits) ([de5a9135](https://github.com/Dicklesworthstone/flywheel_connectors/commit/de5a91352aecd194287aa13a8fc20e06fb08d415))
- **Kubernetes**: log streaming, exec, configmap, secret operations, rollout monitoring, event watching ([ec5c4e4d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ec5c4e4d1681e0cff4214486d34ffee63af09fd7), [0addcf63](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0addcf6373d15b209aa3e42bc05cbdb024d266c2))
- **Jira**: dual Cloud and Server/DC API support, automation rules, worklog/time tracking, Beads sync ([61e6ccbb](https://github.com/Dicklesworthstone/flywheel_connectors/commit/61e6ccbbb5063640dd98a21b58a29bcafec48a69), [865623622](https://github.com/Dicklesworthstone/flywheel_connectors/commit/865623622f4d4b1050c6b9a5a6ea526215d73032))
- **HubSpot**: deal CRUD, company/contact search, pipeline analytics, stage metrics, associations ([2ab75a2d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/2ab75a2d6e67a73c750bb1f89c85b018d49850ae))
- **Sentry**: triage engine, performance monitoring, release tracking, issue management, alert rules ([fd22893c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/fd22893c001efbfd202dc3ed9efd4b25ed6f5f7f))
- **Spotify**: playback control, library management, playlist CRUD, search, podcast operations ([b2df842a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b2df842ac5313283dcc54257be715cbbfe300e89))
- **DocuSign**: envelope creation, document management, recipients, signing, tracking ([a79c73e6](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a79c73e64618f7594510545911a4bc87098b0c55))
- **Reddit**: subreddit, content, posting, moderation, messaging, research modules ([9706e22a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9706e22a0720c616a6423ef602f36175d15427fe))
- **Terraform**: state inspection, plan generation, module management, drift detection, apply lifecycle ([356cd102](https://github.com/Dicklesworthstone/flywheel_connectors/commit/356cd1026cb2c0355e8a40c22c5664c17b208436))
- **Airtable**: records CRUD, attachment handling, webhook automation, schema cache, linked-record expansion ([c32ea875](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c32ea875d48af284e56b43798f79acd79009fd23))
- **Figma**: macro operations, design tokens extraction, resource discovery ([79ce93c9](https://github.com/Dicklesworthstone/flywheel_connectors/commit/79ce93c9432f60b35e0e10ffb2ea91b9183efae2))
- **Zendesk**: SLA tracking, analytics, auto-categorization ([b85bcaa0](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b85bcaa080b461a204b636fab757f3dde38bd072))
- **Microsoft 365**: Planner, SharePoint, and Excel Online modules ([1d1d7a0b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1d1d7a0b5e23006910782cb9625f4b53f1fb076d))
- **Twitter**: streaming ingestion module ([62b8a09b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/62b8a09b71d19bec1ff2f58b4e18cc3bcf63a233))

### Provisioning Automation
- Provisioning automation added in batches to 36+ connectors across multiple commits ([f2e6f43e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f2e6f43e902a0a0dfcc42d7056983c665cb43ccf), [f655652d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f655652d52da733aa561f9426e8e66a6d9ccfb95), [66f9088c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/66f9088ca9b1a26e497abc7af8c3b9479d124c7b))

### Infrastructure
- **fcp-sandbox**: WasiRuntime::invoke(), deterministic WASI clocks, network socket gating, env isolation ([332054f1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/332054f19818d83a35dcbc05271df233815f9368), [8e7ba667](https://github.com/Dicklesworthstone/flywheel_connectors/commit/8e7ba6671735c6153762f2ef2b18ef835e65453c))
- **fcp-core**: stream-key ordering in EventEnvelope ([7a55ac39](https://github.com/Dicklesworthstone/flywheel_connectors/commit/7a55ac39218dfcaa58b70e53addf5d6e6a9c87a3))
- **fcp-e2e**: host resilience E2E flow tests ([8153d295](https://github.com/Dicklesworthstone/flywheel_connectors/commit/8153d29532cabe788cb4688f91ac883e2b4fd0eb))
- **fcp-core**: ConnectorDescriptor metadata model ([b7015642](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b7015642eea66418b213c9cf89d1fc01906f4bef))

### Testing
- Massive test expansion across core crates: 1,145+ tests in a single pass ([e31b261e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e31b261ee81258749eecece14bc804cc73c52678))
- All modules driven to 100+ tests in final sweep ([de0f3347](https://github.com/Dicklesworthstone/flywheel_connectors/commit/de0f334749ffe58a9796ace6117073d30cafd11c))

---

## 2026-03-05 — 2026-03-07 — Bootstrap Ceremony, Mesh Store, and fwc Foundation

### fcp-bootstrap
- Full bootstrap ceremony with genesis, hardware token support, and recovery phrases ([9aaa2823](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9aaa2823a897af81587acb6f5432cf012c68aa1a))

### fcp-store
- Object store implementation with GC, quarantine, and repair planning
- Zone-level SLO metrics, source diversity enforcement, symbol repair orchestration ([b393980361](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b393980361a349a3db9d0e41f9b73eb94989f98a))
- Extreme overcoverage saturation test for coverage_bps ([433d0a38](https://github.com/Dicklesworthstone/flywheel_connectors/commit/433d0a38ffc597f50beaa54a41f2a206e4e381fd))

### fwc CLI Foundation
- Live FCP host integration for batch execution and cancel operations ([fbd2c22c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/fbd2c22cbb9d173c7e7b1390f0d0ba1452b84411))
- `serve-mcp` command with stdio JSON-RPC transport and connector-to-MCP bridge ([0af45e77](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0af45e778d97e20a97fa21f3ff3512a5138fdce6))
- Invoke/simulate dispatch pipeline with `--set` flag support ([a4a0ecce](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a4a0eccef66ec8c0c2d72c4bad6b660c349637ad))
- Seven new CLI command modules for connector lifecycle management ([a1627d77](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a1627d7799815670c0daf3e038f9234b4ce9b635))

### Security
- Overflow safety, DoS protection, and heartbeat correctness across raptorq, registry, streaming, store, sdk ([44db106d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/44db106da9af360bba9b16e070bb1c3da033836f))
- SSRF bypass fix in protocol; unsafe `as u32` casts replaced with checked conversions ([5bab770d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/5bab770d48a3b8682e46bbfec8d6c1a402c3d828))
- IPv4-mapped IPv6 SSRF bypass prevention in sandbox/graphql ([90439d79](https://github.com/Dicklesworthstone/flywheel_connectors/commit/90439d7999970d70eed4df8622da67ab802819ca))
- WASM guest memory limits enforced via wasmtime ResourceLimiter ([acaf3cda](https://github.com/Dicklesworthstone/flywheel_connectors/commit/acaf3cda1f525dad8a278055e57f373dde8f944a))
- CBOR canonicalization recursion depth limit ([b7beec3c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b7beec3c5f7ae55be01b34df50b89a2c10ad715e))

### Infrastructure
- **fcp-async-core**: owned facade over tokio with asupersync timeout ([a52635cd](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a52635cd5045afd7a2d90e19d8759acbde35298b))
- **fcp-webhook**: taint flag propagation for externally injected webhook payloads ([01e796de](https://github.com/Dicklesworthstone/flywheel_connectors/commit/01e796de94b702b35e2b229948d2950bf2552c7f))
- **fcp-conformance**: run_id and scenario_id fields for E2E log schemas ([1a663c2b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1a663c2b1476f260e7411c4573173b0d832257df))
- Deterministic mesh trace replay engine and CLI ([db3d1968](https://github.com/Dicklesworthstone/flywheel_connectors/commit/db3d19681ed7098d7dd5b955c640861e1fb19b43))

---

## 2026-03-01 — 2026-03-02 — Connector Deep Dives and VectorDB

### New Connectors
- **VectorDB** with full invoke handler, operation dispatch, and introspection ([c79bc10e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c79bc10e25d255714bee853295f620f14f800304))
- **LLM Router** meta-connector for multi-provider model selection ([c6395c41](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c6395c41898c16df766036251adf5c9a6ecb77ad))

### Connector Deep Dives
- **Stripe**: CRUD operations, webhook ingestion, idempotency keys, and audit trails ([7adf37a5](https://github.com/Dicklesworthstone/flywheel_connectors/commit/7adf37a5c75e07fe7f6ec2c77b7b5fe7b1556d92))
- **Notion**: search sensitivity, provenance, taint metadata, and PII redaction ([8309d2c1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/8309d2c1fdd7aabd4e8793dc75f626c6aeb5b487))
- **Anthropic**: message streaming, provenance/taint metadata, tool_use preservation ([b9e5227e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b9e5227e21c3a23555acf4390e8e4131d2f71902))
- **OpenAI**: embeddings, images, audio, fine-tuning, and assistants operations ([e8f9156b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e8f9156bb804a29684f9d6b0f62eb3f082b065c9))
- **Discord**: reactions, threads, channel listing, provisioning validation, singleton-writer lease ([b065bb41](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b065bb41e21146a3cadedc39fec00d71c80ec476))
- **Figma**: design tokens extraction, resource discovery operations ([14828a6d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/14828a6d0fae6b23701c689b1430e16102e1be40))
- **Telegram**: singleton-writer lease fencing and polling cursor state persistence ([94b91c61](https://github.com/Dicklesworthstone/flywheel_connectors/commit/94b91c6145fa17addfbf636429a6636d8e72fae4))
- **Microsoft 365**: delta sync state persistence, subscription tracking, singleton-writer lease ([dedfc3e1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/dedfc3e13da50bda497b629706ee69944f43404e))
- **S3**: create_bucket/delete_bucket manifest entries ([c0abc20a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c0abc20a8e059d5c91e7df224656847d36368d66))

### Infrastructure
- **fcp-manifest**: EventSection for streaming connectors ([a25bee85](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a25bee85a5771df27863a6b553887426d56b6f38))

---

## 2026-02-20 — 2026-02-28 — 71-Connector Initial Scaffolding Wave

### New Connectors (Mass Scaffolding)
- 71 connectors scaffolded from specification models covering: productivity (Asana, ClickUp, Monday, Todoist, Trello, Notion, Linear), dev tools (GitHub, GitLab, Bitbucket, Jira), cloud (S3, Snowflake, BigQuery, DuckDB, MongoDB, PostgreSQL, Redis, Elasticsearch, Pinecone, Qdrant), communication (Slack, Gmail, Twilio, SendGrid, Mailchimp), finance (Stripe, Plaid, PayPal), security (1Password, Bitwarden), analytics (Amplitude, Mixpanel, PostHog, Segment, Datadog, Grafana, Sentry), marketing (HubSpot, Salesforce, Intercom), automation (Zapier, Make, n8n, Retool), media (YouTube, Spotify), documents (Dropbox, Box, Google Drive, Google Docs, Google Sheets, Google Calendar, Google AI, Google Chat, Google People, Google Admin Reports, Google Workspace Events), design (Figma), publishing (arXiv, Semantic Scholar), home (Home Assistant), CRM (Zendesk, PandaDoc, DocuSign), infrastructure (Terraform, Pulumi, Kubernetes), notes (Logseq, Roam, Evernote, Obsidian), analytics (Metabase), browser (Browser), scheduling (Cron), MCP bridge, and webhook receiver

Representative commits:
- ([5fb11bbb](https://github.com/Dicklesworthstone/flywheel_connectors/commit/5fb11bbb) — earliest scaffolding batch)
- Anna's Archive connector added with search operations

---

## 2026-01-29 — 2026-01-31 — SDK Runtime, Mesh Networking, and Policy Engine

### Infrastructure
- **fcp-sdk**: async executor and lifecycle hooks ([61afd6c9](https://github.com/Dicklesworthstone/flywheel_connectors/commit/61afd6c91a33c5b4cc288b9d4ef839296f2a1178))
- **fcp-mesh**: gossip bounds checking, best_path(), admission control, batch invocation, and E2E tests ([28eeeae6](https://github.com/Dicklesworthstone/flywheel_connectors/commit/28eeeae6ccad306442cef353ba7139ebca5a431e), [9286f794](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9286f79414f79c13d2c26797ef1fe355b0880e3c))
- **fcp-streaming**: SSE, WebSocket, and reconnection handling expansion ([6f3a5c3f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6f3a5c3fe7a6c13299ca28af1965e18a815e2f74))
- **fcp-sandbox**: egress filtering and WASI support ([ac42ce2c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ac42ce2ce542261e07345974c7e7944826b6b7e8))
- **fcp-oauth**: OAuth 1.0a/2.0 implementation with comprehensive tests ([ffb947af](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ffb947afc20da58e6ef29ba2ae845563f20d0397))
- **fcp-webhook**: expanded webhook handling with signature verification ([3cfafccc](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3cfafcccb384df5002597284afa296645f541658))
- **fcp-core**: capability validation, state machine, and lifecycle tests ([e7f8bf04](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e7f8bf04554b0c63ca24c276061dd655dd4ec130))
- **fcp-store**: source diversity enforcement and symbol coverage verification ([df221501](https://github.com/Dicklesworthstone/flywheel_connectors/commit/df2215018939348b92bd532f480518b1c9c27aaf))
- **fcp-host**: BudgetPolicyEngine for zone-aware preflight budget enforcement ([1343ef7d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1343ef7d51a7cc9536bd094fc2b5b705db619b35))
- **fcp-raptorq**: MTU-safe auto-tuning presets and symbol size calculation ([c4a9b36d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c4a9b36d2d2e7480464ac78df6678030ae4bd904))
- **fcp-cli**: budget command, egress policy explain CLI, doctor self-check ([e4127c2b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e4127c2b08c9f99af5ea418c306cb19b93ca13e9), [e516a354](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e516a35484cc2a226d062c28241d491f635a9289))

### Connectors
- **Twitter**: manifest, streaming, URL-encoded query parameters ([808fd078](https://github.com/Dicklesworthstone/flywheel_connectors/commit/808fd078398be0733c62df8ee2989d758dc5623e))
- **Airtable**: manifest added ([1950a7e6](https://github.com/Dicklesworthstone/flywheel_connectors/commit/1950a7e6ee3817acb3d538086b9004e7acfc9762))
- **VectorDB**: connector scaffold and diversity E2E test ([62d7cc8e](https://github.com/Dicklesworthstone/flywheel_connectors/commit/62d7cc8e50f37eee1a904058621e7b12f3945eb2))

---

## 2026-01-17 — 2026-01-28 — fcp-cli, Conformance Suite, and Platform Maturation

### fcp-cli
- Audit, doctor, explain, and install subcommands ([17e064b4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/17e064b458784ce26b8f1f218d2e6d08e1f26676))
- Policy engine and conformance vector generation ([78120dff](https://github.com/Dicklesworthstone/flywheel_connectors/commit/78120dff77d5147ae3ef2a4737b2b423dda041cb))

### Infrastructure
- **fcp-mesh**: admission, gossip, and symbol request modules ([b50689fa](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b50689fad6606cb36d68050cd71f060493a52039))
- **fcp-raptorq**: memory safety and concurrency improvements ([f7de51c9](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f7de51c94bae7b694a19d909cd881892e3a3b608))
- **fcp-core**: PartialOrd/Ord for ObjectId, LwwMap merge optimization ([06c92331](https://github.com/Dicklesworthstone/flywheel_connectors/commit/06c92331e50296dcb06cebb6d66d067dffb35980))
- **fcp-core**: content-addressed IDs for approval tokens ([b89ad605](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b89ad6054dec7076d8ca783c540f90748dfe13e0))

---

## 2026-01-15 — 2026-01-16 — FCP2 Platform Crates and Protocol Implementation

### Platform Crates (FCP2 Foundation)
- **fcp-core**: FCP2 mesh-native types, revocation types/registry, Trust/Quorum Model, capability verification, error taxonomy with AI recovery hints, zone_keys module, enrollment module, core types with `from_static` API ([15d929b3](https://github.com/Dicklesworthstone/flywheel_connectors/commit/15d929b32d8e8c37769e72b3061df2353d8ac442), [6446d8f2](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6446d8f2d5930daac830fa53d9284f04435a0e5b), [09d3ea48](https://github.com/Dicklesworthstone/flywheel_connectors/commit/09d3ea488c42f9990ce2a4b85fb7384ea7fbf6cd), [00f2977f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/00f2977f329934b137339fb8a7f7b4c35aab7aae), [f1382a33](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f1382a338961b158f823a0e6b9a1a5e5d2bc8fd1))
- **fcp-crypto**: complete crypto primitives with Ed25519, X25519, HPKE, Shamir sharing, FROST threshold signing, benchmarks, and RFC 8032 test vectors ([695c3e20](https://github.com/Dicklesworthstone/flywheel_connectors/commit/695c3e20d6b01a137778d8342cad879afaa00bdf))
- **fcp-cbor**: canonical CBOR serialization with comprehensive test suite and benchmarks ([86a5e7a9](https://github.com/Dicklesworthstone/flywheel_connectors/commit/86a5e7a9546f9f5553d19ff571128fa57cd75ced))
- **fcp-mesh**: FCP2 session layer, DeviceProfile, admission control ([7a30c013](https://github.com/Dicklesworthstone/flywheel_connectors/commit/7a30c01366e16808949391daf6550e1b51575d87))
- **fcp-protocol**: FCPS data plane, FCPC control-plane framing, benchmarks, fuzz targets ([fdf26279](https://github.com/Dicklesworthstone/flywheel_connectors/commit/fdf26279007088ce31d7b66a9c928442251f73a8), [0537c383](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0537c3831d093575a39d887e16b067ce8ae3a57b))
- **fcp-tailscale**: Tailscale integration for mesh identity ([6b57f677](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6b57f67729633c9e5d51a9ef211b38f0a0c5ae85))
- **fcp-registry**: supply-chain verification adapters with transparency logging ([40a09ce1](https://github.com/Dicklesworthstone/flywheel_connectors/commit/40a09ce1036f535a69ddc76b47aa2c0c303256a7))
- **fcp-sandbox**: OS sandbox enforcement for Linux/macOS/Windows, Network Guard egress ([806f9d74](https://github.com/Dicklesworthstone/flywheel_connectors/commit/806f9d74da7061ddf8966c8b730dbd6979e11c6d), [bb23f132](https://github.com/Dicklesworthstone/flywheel_connectors/commit/bb23f13269384aa080adf0b30d7025caf0f64d45))
- **fcp-conformance**: interop test suite, FZPF v0.1 JSON schema, golden vectors ([aee248c5](https://github.com/Dicklesworthstone/flywheel_connectors/commit/aee248c5dadd554477ee9a085721c2a4e82e81fb), [8b8d6bb3](https://github.com/Dicklesworthstone/flywheel_connectors/commit/8b8d6bb382826bab5f6f40c8ee1850393e1922e9))
- **fcp-store**: offline capability tracking ([ff1aff32](https://github.com/Dicklesworthstone/flywheel_connectors/commit/ff1aff328bdabbd02624fe15c94097f905ff095d))
- FCP2 handshake and capability verification added to all existing connectors ([d83b5424](https://github.com/Dicklesworthstone/flywheel_connectors/commit/d83b5424a378aab1f63ef14bd53cb50c45ad708f))
- CI: GitHub Actions workflow for Rust quality gates ([200461b8](https://github.com/Dicklesworthstone/flywheel_connectors/commit/200461b8e58af8f2eab2bda366e0c760de1a4a84))

### Documentation
- FCP2 Requirements Index, Connector Compliance Checklist, Connector Spec Template, Testing/Logging standard, APR workflow ([cbc60040](https://github.com/Dicklesworthstone/flywheel_connectors/commit/cbc600408a8063bd410e1a5ed85461c163145c94), [4afdc375](https://github.com/Dicklesworthstone/flywheel_connectors/commit/4afdc375f676f129459e8d7874a070a7a0c8e30f))

---

## 2026-01-13 — 2026-01-14 — APR Specification Refinement (Rounds 1-6)

- Automated Protocol Review (APR) workflow with GPT Pro 5.2 extended thinking ([c2b0d256](https://github.com/Dicklesworthstone/flywheel_connectors/commit/c2b0d2567aa4d5f56a223b0f65c42607f860cafb))
- Six rounds of spec refinement integrated into FCP V2, with harmonized README, connector guide, and implementation guide after each round ([59b8f45a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/59b8f45a19c410326c7f061ecd2ab51f49c967ad) through [7360dfa6](https://github.com/Dicklesworthstone/flywheel_connectors/commit/7360dfa64e9740de5699c7c16a6768e5260ac667))

---

## 2026-01-12 — FCP V2 Specification

- FCP Specification V2 created, merging V1 spec with mesh-native RFC ([8b25b701](https://github.com/Dicklesworthstone/flywheel_connectors/commit/8b25b7011a0fe33e679dbf6f6b6da0e1a3414062))
- Comprehensive RFC_Mesh_Native_Protocol_V2 mega-document ([6ccef168](https://github.com/Dicklesworthstone/flywheel_connectors/commit/6ccef168bf49df008fe99cf1d478b663893e016f))
- 12 security and architecture improvements applied ([37a0548b](https://github.com/Dicklesworthstone/flywheel_connectors/commit/37a0548bdb7fb77cefcd5d0b0d3335d4e6eaaa2f))
- Multiple rounds of connector model harmonization with V2 spec

---

## 2026-01-11 — Project Genesis

### Specification
- FCP Specification V1 complete document ([f9267ea4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/f9267ea4b097ac56edf60249f60cd66d33654b19))
- FZPF policy format with JSON schema and test vectors ([d81c3458](https://github.com/Dicklesworthstone/flywheel_connectors/commit/d81c3458e035d396e134ae9010e445c7d8e33c21))
- JSON-RPC method reference and spec annotations ([52550541](https://github.com/Dicklesworthstone/flywheel_connectors/commit/525505411027cfab6a5ffbb3f99dbf8b23f8deb0))

### RFCs
- RFC for Universal Fungibility paradigm shift ([a848c381](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a848c381edc2cda4f9dfed103bf1db6d57cdebe3))
- RFC for Mesh-Native Protocol (Tailscale + Universal Fungibility) ([9fbf29ee](https://github.com/Dicklesworthstone/flywheel_connectors/commit/9fbf29ee7b2ce111e9af53fd2556819dacbc228f))
- RFC for RaptorQ erasure coding and Sovereign Mesh architecture ([fadb364f](https://github.com/Dicklesworthstone/flywheel_connectors/commit/fadb364f41a44515682df603bc819ca1f929e0cf))

### First Connectors
- **Telegram and Discord** connector implementations ([17d759a9](https://github.com/Dicklesworthstone/flywheel_connectors/commit/17d759a9f7953ee064bb39ad0ad3e79b8af15f2c))
- **Anthropic Claude API** connector ([3aa159a4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3aa159a4c54b55e4bcf5003e36aae32cea518ffc))
- **OpenAI GPT API** connector ([67a0445d](https://github.com/Dicklesworthstone/flywheel_connectors/commit/67a0445d241524ef87b99689ea50e4cddf0d8589))
- Discord gateway session resumption ([d4844498](https://github.com/Dicklesworthstone/flywheel_connectors/commit/d4844498125b54e85cb6d72f401c319b9ddcf33c))

### First Infrastructure Crates
- **fcp-testkit**: connector testing infrastructure ([3cd7d1e4](https://github.com/Dicklesworthstone/flywheel_connectors/commit/3cd7d1e45d4cd4ab32d88543c7368b6bc6865eeb))
- **fcp-telemetry**: unified observability ([0d77f981](https://github.com/Dicklesworthstone/flywheel_connectors/commit/0d77f981ad34b85aad17303c59882af0f61ada19))
- **fcp-ratelimit**: rate limiting infrastructure ([42c711a7](https://github.com/Dicklesworthstone/flywheel_connectors/commit/42c711a7f670fe9f49ab6af166e0da9645ec5388))
- **fcp-oauth**: unified OAuth support ([a8ea3c34](https://github.com/Dicklesworthstone/flywheel_connectors/commit/a8ea3c3454c4337ac7086b84a7a98b6e17073ce3))
- **fcp-streaming**: real-time data support ([b217a321](https://github.com/Dicklesworthstone/flywheel_connectors/commit/b217a32192aa89fb568efbe3c90114aaa8ecc640))
- **fcp-webhook**: production webhook handling ([00856ca8](https://github.com/Dicklesworthstone/flywheel_connectors/commit/00856ca801a68172bedfd2bcfe95de0cabd75d39))
- **fcp-core**: provenance tracking and protocol types ([4488a60c](https://github.com/Dicklesworthstone/flywheel_connectors/commit/4488a60c92f3bcf96e5e13943a8467fca267bae6))

### Initial Commit
- FCP specification and project documentation ([e5856b9a](https://github.com/Dicklesworthstone/flywheel_connectors/commit/e5856b9a11ad25d4dcbcab0501b5844600dbd31d))

---

## Connector Inventory (121 as of 2026-03-21)

<details>
<summary>Full connector list (alphabetical)</summary>

1Password, Airtable, Algolia, Amplitude, Anna's Archive, Anthropic, arXiv, Asana, AWS, Azure, BigQuery, Bitbucket, Bitwarden, Box, Browser, Calendly, CircleCI, ClickUp, Cloudflare, Coda, Confluence, Cron, Datadog, Discord, DockerHub, DocuSign, Dropbox, DuckDB, Elasticsearch, Evernote, Feishu, Figma, Firebase, GCP, GitHub, GitLab, Gmail, Google Admin Reports, Google AI, Google Calendar, Google Chat, Google Docs, Google Drive, Google People, Google Sheets, Google Workspace Events, Grafana, Hacker News, Home Assistant, HubSpot, iMessage, Intercom, Jira, Kubernetes, LINE, Linear, LinkedIn, LLM Router, Logseq, Mailchimp, Make, Mastodon, Matrix, Mattermost, MCP Bridge, Metabase, Microsoft 365, Mixpanel, Monday, MongoDB, MySQL, n8n, Netlify, Nextcloud Talk, Notion, Obsidian, OpenAI, PandaDoc, PayPal, Pinecone, Plaid, PostgreSQL, PostHog, Pulumi, Qdrant, Reddit, Redis, Retool, Roam, S3, Salesforce, Segment, Semantic Scholar, SendGrid, Sentry, Shopify, Signal, Slack, Snowflake, Spotify, SQLite, Square, Stripe, Supabase, Teams, Telegram, Terraform, Todoist, Trello, Twilio, Twitch, Twitter, VectorDB, Vercel, Webhook Receiver, WhatsApp, Whisper, YouTube, Zapier, Zendesk, Zoom

</details>

## Infrastructure Crates (30)

<details>
<summary>Full crate list</summary>

fcp-async-core, fcp-async-core-macros, fcp-audit, fcp-bootstrap, fcp-cbor, fcp-conformance, fcp-core, fcp-crypto, fcp-e2e, fcp-google-discovery, fcp-graphql, fcp-host, fcp-manifest, fcp-mesh, fcp-oauth, fcp-protocol, fcp-raptorq, fcp-ratelimit, fcp-registry, fcp-sandbox, fcp-sdk, fcp-store, fcp-streaming, fcp-tailscale, fcp-telemetry, fcp-testkit, fcp-webhook, fwc (CLI)

</details>
