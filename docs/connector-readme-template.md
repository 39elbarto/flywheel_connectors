# Connector README Template

> **Status**: workspace convention template
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Reference exemplar**: `connectors/calendly/README.md`

This is the canonical structural pattern for `connectors/<name>/README.md`.

Each connector should ship a README that gives an operator the full story of the connector: status, scope, auth boundary, operations, network invariants, sandbox profile, verification commands, and remediation. The template below is structural — every section is required, but content is per-connector.

The template is intentionally close to the calendly README pattern (the gold standard at the time of writing). When updating, keep this file in sync with the highest-quality connector README in the workspace.

---

## Template (copy into `connectors/<name>/README.md`)

```markdown
# <Connector display name> Connector V<n> Contract

> **Status**: <implementation-reviewed and verification-backed | first-slice draft | reality-check pending>
> **Bead**: `flywheel_connectors-<bead-id>`
> **Parent**: `flywheel_connectors-<parent-bead-id>`
> **Verification script**: `scripts/e2e/<name>_connector_verification.sh`
> **Primary upstream**: <provider docs URL>

## Purpose

One paragraph: what this connector exposes, what FCP slice it covers, and what makes the current slice safely usable. Avoid marketing language; treat the README as an operator-facing readiness artifact.

## Current Runtime Snapshot

The current crate exposes these operations:

- `<connector>.<op_id_1>`
- `<connector>.<op_id_2>`
- ...

Important runtime truths the contract preserves:

- Configuration shape (e.g., `api_key`, optional `base_url`, retry policy, request timeout).
- Production host(s) and any localhost / mock-server overrides.
- Default principal-resolution behavior (e.g., `users/me`).
- Sentinel handling for `credential_id` proxy-injection mode.
- Path / query sanitization rules.
- Health / self-check semantics.
- Streaming vs request-response posture.

## First-Slice Scope

Bullet list of what's IN scope this slice:

- ...

## Auth And Scope Boundary

- Authentication mechanism (Bearer token / OAuth / setup-token / SigV4 / JWT).
- Per-zone binding semantics (one connector instance, one principal).
- Capability surface (gate per operation):
  - `<connector>.<cap_1>` gates ...
  - `<connector>.<cap_2>` gates ...
- Cross-account / webhook ingest / fanout posture (typically: NOT in this slice).

## Network And Runtime Invariants

- Production base API host(s).
- Production port(s).
- TLS + SNI requirements.
- Manifest network policy: deny private ranges, deny tailnet ranges, deny IP literals, no redirects.
- Localhost overrides explicitly test-only.
- Default request timeout.
- Retry policy summary.
- Replay / streaming surface (typically: none).

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `<connector>.<cap>` | ... |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `<connector>.<op>` | `<METHOD> /<path>` | `<cap>` | `Safe` / `Risky` | `Low` / `Medium` / `High` | `None` / `Strict` | <one-line rationale> |

## Explicit Non-Goals

The first implementation slice does NOT include:

- ...

These are excluded on purpose:

- ...

## Readiness And Verification Surface

`doctor()`, `health()`, and `self_check()` are part of the public closeout contract. They surface:

- Configuration / client / runtime / handshake state.
- Manifest hash and verification script path.
- Artifact root hint for replayable evidence.
- Provisioning details (auth mode, timeout, retry policy, identity probe, risky-mutation inventory).
- Operator guidance (prerequisites, dedicated environments, redaction rules, remediation, rerun commands).

The deterministic integration evidence is anchored on localhost mock-server runs covering:

- ...

## Source Notes

- `connectors/<name>/src/client.rs` defines request construction, retry, error mapping, sanitization, and the readiness probe.
- `connectors/<name>/src/connector.rs` defines the FCP operation inventory, capability boundary, readiness output shape, operator guidance.
- `connectors/<name>/manifest.toml` defines the production network allowlist and sandbox boundary.

## Verification Bundle

The closeout bundle is anchored on `scripts/e2e/<name>_connector_verification.sh`. It writes replayable artifacts under `artifacts/e2e/<name>_connector/<timestamp>` and runs `rch`-offloaded Cargo commands so validation does not contend with local multi-agent sessions.

The bundle captures:

- Manifest validation for `connectors/<name>/manifest.toml`.
- `cargo check -p fcp-<name> --all-targets`.
- Formatting verification for the crate.
- Targeted readiness evidence for `health`, `doctor`, `self_check`, retryable degradation, and any risky mutations.
- Typed introspection compliance evidence.
- The connector integration suite and full crate test suite.
- `cargo clippy -p fcp-<name> --all-targets -- -D warnings`.

## Operator Guidance

**Prerequisites**:

- ...

**Dedicated environment**:

- Prefer a disposable provider account or a localhost mock server. Do not run verification against a live production surface unless side effects are acceptable.

**Redaction rules**:

- Redact API keys, OAuth tokens, `Authorization` headers, proxy-injection hints, and copied request logs before sharing evidence.
- Treat <provider-specific PII fields> as sensitive operational data.

**Common remediation**:

- If `health` reports `not_configured`, ...
- If `self_check` reports `credential_injection_required`, ...
- If `self_check` reports `<provider>_auth_rejected`, ...
- If `doctor` reports `network_constraints_invalid`, ...

**Rerun commands**:

- `scripts/e2e/<name>_connector_verification.sh`
- `fwc manifest fix connectors/<name>/manifest.toml --check --json`
- `rch exec -- cargo fmt --manifest-path connectors/<name>/Cargo.toml --check`
- `rch exec -- cargo check -p fcp-<name> --all-targets`
- `rch exec -- cargo test -p fcp-<name> --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-<name> -- --nocapture`
- `rch exec -- cargo clippy -p fcp-<name> --all-targets -- -D warnings`
```

---

## Why this template exists

Per `flywheel_connectors-4kw5f.12`, 146 of 172 connectors lack any `README.md`. The 26 that do are ad-hoc; some follow the calendly pattern, others diverge.

This template formalizes calendly's pattern as the workspace convention so future connector READMEs are consistent and operators can scan any connector's README to find the same information in the same place.

## Workflow expectations

1. **New connectors**: when scaffolding a connector via the template, populate every section. If a section is intentionally empty (e.g., no risky mutations), say so explicitly: "No risky mutations in this slice."

2. **Existing connectors without README**: file a child bead under `flywheel_connectors-4kw5f.12` per Wave (Wave 1 = newly-scaffolded; Wave 2 = mature high-traffic; Wave 3 = specialty). Each Wave PR ports a small group of READMEs together for review-ability.

3. **Auto-generation helper** (suggested, not mandatory): `fwc connector readme-init <name>` would emit a draft README populated from manifest content + connector code. Humans polish before commit.

## Quality bar

- Every section present.
- Minimum size for the soft conformance ratchet is 500 bytes, but useful
  connector READMEs should normally be much more specific than that floor.
- No AI-generated boilerplate. Specifically: no marketing language, no generic "this is a powerful connector", no hallucinated operator guidance.
- Operation inventory matches manifest exactly (verifiable by `fwc <connector> describe`).
- Verification commands actually work when run.
- Redaction rules name the specific provider PII fields.
- Common remediation entries map to real error variants in `error.rs`.

Soft conformance check:

```bash
rch exec -- cargo test -p fcp-conformance --test readme_presence -- --ignored --nocapture
```

The test is ignored by default until the wave work under
`flywheel_connectors-4kw5f.12` closes; explicit runs emit a redaction-safe JSONL
inventory of connector README gaps.

## Non-goals for this template

- The template does NOT replace per-operation `ai_hints` in manifest. README is operator-facing; ai_hints are agent-facing.
- The template does NOT mandate marketing or onboarding content. Other docs (e.g., docs site, fwc onboarding) cover those.
- The template does NOT enforce structure beyond section presence. Within each section, per-connector content is encouraged where it adds value.
