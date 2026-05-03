# Swarm Session Summary - 2026-05-03

## Scope

This summary consolidates the 2026-05-03 Flywheel Connector Protocol swarm session as observed from the `main` branch commit history through `f894007dd`. The session landed 60 non-merge commits spanning performance profiling, security hardening, conformance harnesses, real-service tests, fuzz/property coverage, golden vectors, and CI/CD review.

## Major Outputs

### Performance and Concurrency

- Added profiling evidence and Criterion coverage for hot paths in `fcp-host`, `fcp-mesh`, `fcp-store`, and `fcp-audit`.
- Shipped sparse high-K symbol-map allocation caps and resource-pool placement lookup optimization.
- Split `DurableSymbolStore::record_mutation` into read-validate and write-publish phases to reduce lock hold time and improve mutation-flow clarity.
- Preserved measured low-EV rejections as beads/evidence for allocation and lock-free proposals that did not clear the performance bar.

Representative commits: `4bca4bd75`, `38cd93962`, `f5727c374`, `daeff669e`, `19f5572e2`.

### Security Hardening

- Enforced HTTPS-or-loopback policy for custom OAuth provider endpoints.
- Moved `/rpc/budget/report` behind the admin-authenticated router.
- Required valid Tailscale zone tags and bounded attestation freshness.
- Rejected registry binary path traversal.
- Improved release workflow posture: least-privilege default permissions, validated manual release versions, removed unnecessary crates.io token exposure from dry-run publishing, and preserved OIDC-based signing/provenance.

Representative commits: `7840f2dee`, `0a5fb074e`, `f140320ad`, `938565004`, `563573a68`, `cf6c5721e`.

### Conformance and Contract Coverage

- Added host conformance harnesses for backpressure actions, resource-pool planner behavior, and invoke-loop end-to-end contract paths.
- Added connector conformance harnesses for GitHub, Slack, Stripe, Discord, Telegram, Gmail, and Anthropic connectors.
- Enriched `fcp-host` MCP tool descriptions for better agent discoverability and parameter clarity.

Representative commits: `817cba87c`, `ab59d5a9d`, `784038a8a`, `6d16bf953`, `54ed09887`, `0323cb1b5`, `e5e9f7d6b`.

### Testing Expansion

- Added metamorphic tests for OAuth endpoint validation, DurableSymbolStore mutation transitions, S3-FIFO cache behavior, and backpressure decisions.
- Added real-service end-to-end tests for OAuth provider validation, DurableSymbolStore fault injection, supply-chain cache concurrency, SSE reconnect storms, webhook retry decisions, GraphQL batch limiting, and concurrent capability enforcement.
- Added golden vectors for OAuth endpoint canonicalization, host backpressure decisions, mesh planner resource-pool decisions, DurableSymbolStore transitions, and capability rejection audit events.

Representative commits: `5f77beeb1`, `09f944947`, `554ee0e90`, `cd3d798bb`, `750bd88d1`, `cdc0a7538`, `a43eecd3e`, `87544f4d5`, `54776a265`, `ffac972b4`, `167d9c812`, `230c8f4dd`, `cbe5a3013`, `da2326b67`, `2e695560a`, `f894007dd`.

### Fuzz and Property Coverage

- Added property/fuzz harnesses for CBOR, protocol parsers, suite negotiation, store WAL replay and writer-side fault sequences, manifest/webhook/crypto surfaces, and host conformal backpressure replay.
- Added deterministic replay and adversarial parser coverage across several high-risk wire formats.

Representative commits: `7c6f83162`, `d4475cd3d`, `1d3e8f261`, `2ace18e83`, `89c34bb4f`, `7f0bd5e7b`, `e7aba6579`.

## CI/CD Review Findings

The workflows under `.github/workflows/` are non-minimal and already include useful release-security primitives: checksum publication, GitHub build provenance attestation, Sigstore keyless signing, and job-scoped OIDC permissions for release publication.

Inline fixes shipped in `cf6c5721e`:

- `ci.yml`: validates and quotes the focused crate input before shell use.
- `ci.yml`: fixes the cross-platform release build job to build the live `fwc` package/bin instead of stale `fcp-cli`.
- `fuzz.yml`: fixes a YAML parse issue in the skip step.
- `fuzz.yml`: fails the job when `cargo fuzz` itself fails without crash artifacts instead of masking infrastructure/build failures.
- `release.yml`: changes top-level default permissions from `contents: write` to `contents: read`; keeps write/OIDC permissions only on the release job.
- `release.yml`: validates manual release versions before writing to `GITHUB_OUTPUT`.
- `release.yml`: removes unnecessary `CARGO_REGISTRY_TOKEN` exposure from the dry-run publish step.

Remaining larger finding: workflows still use mutable action tags, and `release.yml` clones `asupersync` and `toon_rust` from default branches before signing artifacts. The right follow-up is to pin every third-party action and external release dependency checkout to reviewed full SHAs, then add policy enforcement for unpinned workflow inputs.

## Verification Notes

- Workflow YAML parse check passed for `ci.yml`, `fuzz.yml`, and `release.yml`.
- `git diff --check` passed for edited workflow files.
- `actionlint` was not installed in the local environment.
- Cargo/rch verification was not run for the CI-only patch because no Rust source or Cargo metadata changed.

## Operational Notes

- The working tree remained shared and dirty outside the owned workflow/report paths; unrelated staged and modified files were left untouched.
- `br --no-db create` hung repeatedly while attempting to file the remaining SHA-pinning follow-up, so that finding is recorded here with reproduction context and proposed remediation.
