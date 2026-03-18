# FCP V3 Archetype-Specific Implementation Checklists

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Date**: 2026-03-18
> **Bead Reference**: `flywheel_connectors-j05nu.11.2`
> **Depends On**: `V3_Connector_Acceptance_Contract.md`

---

## Purpose

These checklists extend the base V3 acceptance contract with archetype-specific requirements. Each checklist answers:
1. What does a correct V3 implementation look like for this archetype?
2. What concrete evidence shows an existing connector is using legacy patterns or incomplete operational truths?

Every checklist assumes the base contract (j05nu.11.1) is satisfied. Items here are additive.

---

## Archetype 1: Request-Response SaaS API

**Exemplar**: `connectors/anthropic/`

### Implementation Checklist

```
[ ] Stateless or near-stateless: no cursor, no polling state, no persistent connections
[ ] Each invoke() is a single HTTP round-trip (or bounded chain of calls)
[ ] Response returned directly from invoke() — no background continuation
[ ] Timeout per request bounded (use request_context_with_timeout)
[ ] ConnectorErrorMapping covers: rate limit (429), auth (401/403), not found (404),
    server error (5xx), timeout, network, malformed response
[ ] RetryLoop wraps all HTTP calls with HttpRetryConfig
[ ] Operations classified: reads are Safe, creates/updates are Risky, deletes are Dangerous
[ ] Input/output JSON schemas match the external API's actual request/response shapes
[ ] AI hints include: when to prefer this operation over alternatives, common parameter mistakes
[ ] Health check: lightweight probe to the service (e.g., GET /status, whoami endpoint)
```

### Legacy Pattern Red Flags

- Hand-rolled `loop { match client.send() { ... } }` instead of `RetryLoop`
- Error type with catch-all `Other(String)` that maps everything to `FcpError::Internal`
- Missing `retry_after()` despite the service returning `Retry-After` headers
- Operations all marked `Safe` even when they create/modify external state
- No input schemas, or schemas that are just `{}` (empty object)

---

## Archetype 2: GraphQL API

**Exemplar**: `connectors/github/` (partial pattern)

### Implementation Checklist

```
[ ] GraphQL client uses typed queries (not raw string interpolation)
[ ] Pagination handled: cursor-based relay pagination with bounded page limits
[ ] Rate limit: respects X-RateLimit-Remaining / cost-based rate limiting
[ ] Mutations classified as Risky or Dangerous (never Safe)
[ ] Queries classified as Safe
[ ] Subscriptions (if supported) use streaming archetype patterns
[ ] Error extraction: parse GraphQL errors array, map to specific FcpError variants
[ ] Partial success handling: some fields may error while others succeed
[ ] Introspection: operations map to distinct GraphQL operations, not a generic "run query"
```

### Legacy Pattern Red Flags

- Single `graphql.query` operation that accepts arbitrary query strings (unsafe)
- No pagination support (only first page returned)
- GraphQL errors silently dropped or mapped to generic `Internal`
- All mutations marked as `Safe`

---

## Archetype 3: Webhook + Bidirectional Messaging

**Exemplar**: `connectors/telegram/`

### Implementation Checklist

```
[ ] Webhook registration automated in provisioning/configure step
[ ] Incoming webhook signatures verified cryptographically
[ ] Inbound events carry provenance (origin_zone, taint flags)
[ ] Outbound message operations are Risky (external side effect)
[ ] Message delete/edit operations are Dangerous
[ ] Idempotent webhook processing: duplicate delivery detection via event ID/timestamp
[ ] Cursor state externalized for polling fallback mode
[ ] Backpressure: bounded inbound event queue, nack when full
[ ] Connection health tracked via StreamHealthTracker or equivalent
[ ] Reconnection with bounded exponential backoff
[ ] Graceful drain: stop accepting new events, flush pending outbound, close connections
[ ] Bot/app identity management: token rotation, profile updates
```

### Legacy Pattern Red Flags

- Webhook signature verification missing or optional
- No duplicate delivery detection (same event processed twice)
- Unbounded inbound queue (memory exhaustion risk)
- No reconnection logic (single failure = permanent disconnect)
- All operations marked Safe (send_message has external side effects)
- Cursor state hidden in process memory (not durable across restarts)

---

## Archetype 4: Bridge/Daemon Connector

**Examples**: Signal (signal-cli bridge), iMessage (BlueBubbles bridge), Matrix (homeserver)

### Implementation Checklist

```
[ ] Bridge process lifecycle documented: what external daemon must be running
[ ] Prerequisites explicitly declared in manifest (e.g., "signal-cli must be installed")
[ ] Health check verifies bridge process is running AND responsive
[ ] Bridge communication protocol documented (HTTP, Unix socket, stdio)
[ ] Failure modes: bridge crash, bridge restart, bridge version mismatch all handled
[ ] Operations accurately reflect bridge capabilities (not the theoretical protocol spec)
[ ] Authentication: bridge credentials separate from connector credentials
[ ] State ownership clear: which state lives in bridge vs connector vs mesh
[ ] Network constraints: bridge-local only (localhost/unix socket)
[ ] Provisioning recipe includes bridge installation and configuration steps
[ ] Doctor command checks bridge version compatibility
```

### Legacy Pattern Red Flags

- Manifest claims no prerequisites but requires external daemon
- Health check returns healthy when bridge process is not running
- Operations assume bridge capabilities that aren't actually available
- No version compatibility check between connector and bridge
- Network constraints allow public internet when bridge is localhost-only

---

## Archetype 5: Database / Storage

**Exemplar**: `connectors/postgresql/`

### Implementation Checklist

```
[ ] Connection pooling with bounded pool size and idle timeout
[ ] Query execution timeout enforced (wall-clock)
[ ] Read queries: Safe, IdempotencyClass::None or BestEffort
[ ] Write queries (INSERT/UPDATE): Risky, IdempotencyClass::Strict where possible
[ ] Destructive queries (DELETE, DROP, TRUNCATE): Dangerous, IdempotencyClass::Strict
[ ] DDL operations: Dangerous or Critical depending on scope
[ ] Schema introspection: returns resource objects for tables/collections/indexes
[ ] No raw SQL string interpolation — parameterized queries only
[ ] Transaction support for multi-statement mutations
[ ] Connection string / credentials never logged
[ ] Network constraints: typically private network / localhost only
[ ] Health check: simple probe query (e.g., SELECT 1)
[ ] Large result sets: bounded by row limit or streaming cursor
```

### Legacy Pattern Red Flags

- Raw SQL construction via `format!()` (SQL injection risk)
- No connection pooling (new connection per query)
- All query operations marked Safe regardless of SQL verb
- No query timeout (runaway query = hung connector)
- Connection string logged in error messages
- No resource objects for schema introspection

---

## Archetype 6: Cloud Infrastructure / Control Plane

**Examples**: AWS, GCP, Azure, Cloudflare, Vercel

### Implementation Checklist

```
[ ] Multi-service: organized by service area (compute, storage, networking, etc.)
[ ] Operations namespaced: `aws.s3.list_objects`, `aws.ec2.describe_instances`
[ ] Read operations: Safe
[ ] Create/modify operations: Risky with Strict idempotency
[ ] Delete/destroy operations: Dangerous with Strict idempotency
[ ] IAM/permission operations: Critical
[ ] Region/project/account scoping explicit in operation inputs
[ ] Pagination: all list operations support pagination with bounded pages
[ ] Rate limiting: per-service rate limit awareness
[ ] Auth: supports multiple credential types (API key, OAuth, IAM role, service account)
[ ] Cost awareness: operations that incur cloud costs are marked appropriately
[ ] Network constraints: provider API endpoints only
[ ] Health check: lightweight API call (e.g., STS GetCallerIdentity, projects.get)
```

### Legacy Pattern Red Flags

- Flat operation namespace (all operations under `aws.execute`)
- Delete operations marked Risky instead of Dangerous
- No IAM/permission operations modeled as Critical
- Missing region/project context in operations
- No pagination (only first page of list results)

---

## Archetype 7: Browser / Process / Local

**Examples**: Browser (CDP), kubectl, terraform, git

### Implementation Checklist

```
[ ] Process execution bounded by wall-clock timeout
[ ] Process output captured in bounded ring buffer
[ ] Environment variable injection is explicit (not inherited from host)
[ ] No child process spawning unless declared in sandbox profile
[ ] stdin/stdout/stderr handling documented
[ ] Operations model actual CLI commands or browser actions, not generic "run command"
[ ] Destructive operations (rm, kubectl delete, terraform destroy): Dangerous
[ ] Read operations (ls, kubectl get, terraform plan): Safe
[ ] State-changing operations (apply, push): Risky or Dangerous
[ ] File system access: constrained to declared paths in sandbox profile
[ ] For browser: CDP connection management, tab lifecycle, navigation timeout
[ ] Health check: verify tool is installed and accessible at expected version
```

### Legacy Pattern Red Flags

- Generic `execute_command(cmd: String)` operation (command injection risk)
- No timeout on process execution
- Environment inherited from host (ambient authority)
- All operations marked Safe
- No sandbox profile or file system constraints
- Browser connector with no navigation timeout

---

## Archetype 8: File/Blob Storage

**Examples**: S3, GCS, Dropbox, Box

### Implementation Checklist

```
[ ] Upload: chunked for large files, bounded total size
[ ] Download: streaming with bounded buffer, partial retrieval support
[ ] List: paginated with cursor, bounded page size
[ ] Delete: Dangerous, with Strict idempotency
[ ] Integrity: checksum verification on upload/download (SHA-256 or equivalent)
[ ] Presigned URLs: if supported, modeled as separate operation with expiry
[ ] Content-type detection: automatic but overridable
[ ] Network constraints: provider storage endpoints only
[ ] Rate limiting: provider-specific (request rate + bandwidth)
```

### Legacy Pattern Red Flags

- No chunking for uploads (memory exhaustion on large files)
- No checksum verification (silent corruption possible)
- Delete marked Risky instead of Dangerous
- No pagination for list operations
- Presigned URL generation not modeled as distinct operation

---

## Using These Checklists

### For New Connector Implementation

1. Identify your connector's primary archetype(s) from the list above.
2. Satisfy every item in the base V3 contract (`V3_Connector_Acceptance_Contract.md`).
3. Satisfy every item in each applicable archetype checklist.
4. Document which archetype checklist(s) you followed in the bead closure comment.

### For Existing Connector Audit

1. Classify the connector by archetype.
2. Walk through the base contract and archetype checklist.
3. For each item: mark PASS, FAIL (with specific finding), or N/A.
4. Check the "Legacy Pattern Red Flags" section for known anti-patterns.
5. File remediation beads for FAIL items; close the audit bead with evidence.

---

## Changelog

- **1.0.0** (2026-03-18): Initial archetype checklists covering 8 archetypes. Derived from V3 spec, README, and implemented exemplar analysis.
