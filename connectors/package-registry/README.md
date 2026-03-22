# Package Registry Connector V3 Contract

> **Status**: planning contract
> **Bead**: `flywheel_connectors-j05nu.4.4.1`
> **Unblocks**: `flywheel_connectors-j05nu.4.4.2`
> **Primary upstreams**:
> - https://api-docs.npmjs.com/
> - https://docs.npmjs.com/cli/v11/using-npm/registry/
> - https://docs.pypi.org/api/json/
> - https://docs.pypi.org/api/index-api/
> - https://docs.pypi.org/api/upload/
> - https://docs.pypi.org/trusted-publishers/using-a-publisher/
> - https://doc.rust-lang.org/cargo/reference/publishing.html
> - https://github.com/rust-lang/crates.io

## Purpose

This document fixes the first implementation slice for `fcp.package-registry` so the follow-on runtime bead can converge on a stable contract instead of inheriting the parent feature's over-broad "one connector that does everything npm, PyPI, and crates.io can do" framing.

The connector is a request-response package registry metadata surface. The first slice is intentionally provider-bound and read-heavy: one connector instance binds to exactly one upstream public registry provider and exposes a shared metadata contract where the providers genuinely overlap.

This is not a generic package manager, dependency solver, installer, publisher, or vulnerability scanner.

## Current Runtime Snapshot

There is now an in-tree connector crate at `connectors/package-registry/` with:

- a provider-bound runtime and manifest for `npm`, `pypi`, or `crates_io`
- typed operations for search, package metadata, versions, dependencies, artifacts, downloads, and health
- readiness surfaces for `health()`, `doctor()`, and `self_check()`
- deterministic crate-local tests plus host-backed integration coverage
- a replayable verification bundle at `scripts/e2e/package_registry_connector_verification.sh`

This README remains the authoritative contract artifact for the package-registry feature, and it deliberately tightens the parent feature bead in three important ways:

- One connector instance binds to exactly one provider: `npm`, `pypi`, or `crates_io`.
- The first slice is read-only metadata plus readiness and health, not package publishing or registry administration.
- Provider-specific gaps stay explicit. The runtime must return unsupported-operation errors where the registries do not actually share a surface.

## First-Slice Scope

The first package-registry slice is intentionally narrow:

- Bind one connector instance to exactly one provider: `npm`, `pypi`, or `crates_io`.
- Search packages on providers that expose a documented first-party search surface in the sources used for this contract.
- Read package metadata for a known package or crate name.
- List versions or releases and expose provider-native tags or release status where available.
- Read dependency metadata for a selected version or release.
- Read release-file or artifact metadata, including hashes and download URLs when the provider exposes them.
- Read provider-native download statistics only where the upstream exposes a stable first-party surface for them.
- Expose a safe readiness and health probe grounded in provider reachability and config sanity.

The first slice explicitly does not include publish, yanking, deletion, owner management, token lifecycle management, trusted publisher configuration, or a normalized vulnerability-audit operation.

The connector is `operational` and effectively stateless aside from configuration, auth material, and retry or timeout policy.

## Provider Coverage Matrix

| Surface | npm | PyPI | crates.io | First-slice status |
|---------|-----|------|-----------|--------------------|
| Catalog search | `GET /-/v1/search` on `registry.npmjs.org` | No comparable public search endpoint is documented in the PyPI API docs used for this contract | `GET /api/v1/crates?q=...` | In scope, but only for npm and crates.io |
| Package metadata | Packument and version metadata on `registry.npmjs.org/{package}` | `GET /pypi/{project}/json` | `GET /api/v1/crates/{crate}` | In scope |
| Versions or releases | Packument `versions` plus `dist-tags` | Project JSON `releases` and release JSON `GET /pypi/{project}/{version}/json` | `GET /api/v1/crates/{crate}/versions` | In scope |
| Dependency metadata | Version manifest fields like `dependencies`, `peerDependencies`, and `optionalDependencies` | `requires_dist` when present in release metadata | `GET /api/v1/crates/{crate}/{version}/dependencies` | In scope, provider-shaped rather than fully normalized |
| Release files or artifacts | Version `dist` metadata, tarball URL, integrity, signatures | JSON API `urls` plus Index API file listings and hashes | Version metadata plus `GET /api/v1/crates/{crate}/{version}/download` link surface | In scope |
| Download statistics | Not committed as a first-slice surface from the sources used here | PyPI docs expose stats APIs, but not the same per-project download surface implied by the parent feature | `GET /api/v1/crates/{crate}/downloads` | In scope only for crates.io |
| Vulnerability or advisory audit | Not included in this slice | Release JSON may include `vulnerabilities`, but that does not justify a normalized cross-provider audit API | Not included in this slice | Out of scope |
| Publish or upload | Real provider surface exists | Real provider surface exists | Real provider surface exists | Out of scope |

Important inference:

- PyPI search is intentionally marked unsupported in the first slice because the official PyPI API documentation used here covers JSON, Index, Upload, Integrity, Stats, and Trusted Publishing, but does not document a public search endpoint comparable to npm or crates.io.

## Auth And Scope Boundary

- The connector instance binds to exactly one provider at configure time.
- The first-slice read surface is public-data oriented and should work without credentials for npm, PyPI, and crates.io.
- Optional credentials may still be configured so the runtime can validate config shape and prepare for later provider-specific expansion, but the first slice does not promise authenticated mutation flows.
- npm's documented auth world includes session tokens, granular access tokens, and OIDC exchange tokens for publishing-related workflows.
- PyPI's documented auth world includes API tokens for uploads and Trusted Publisher OIDC exchange that yields a short-lived API token.
- crates.io's documented publish flow is API-token based and is normally bootstrapped through `cargo login`.
- Because the first slice is read-only, the runtime must not silently exercise write endpoints during configure, doctor, self-check, or health.
- Package identity is registry-native. npm package names may be scoped, such as `@scope/name`, and must be preserved exactly.
- PyPI project identifiers should accept normal user input but canonicalize according to provider expectations when forming API paths.
- crates.io crate names are case-sensitive at the presentation layer but should be treated consistently with provider API behavior.
- A future `allowed_packages` allowlist may be useful, but it is not part of the first public contract.

## Network And Runtime Invariants

- One configured provider per connector instance
- Production host allowlist depends on provider: `npm` -> `registry.npmjs.org`, `pypi` -> `pypi.org`, `crates_io` -> `crates.io`
- Port: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- `deny_tailnet_ranges = true`
- `deny_ip_literals = true`
- No cross-host redirects
- Default request timeout should be bounded, with `30_000 ms` as the recommended starting point
- The first slice reads metadata only. It does not fetch package tarballs or wheel or sdist bodies, so it does not need to follow artifact URLs onto other hosts such as `files.pythonhosted.org`
- A future write-expansion bead would need a new network review for hosts like `upload.pypi.org`

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `registry.search` | Search the configured provider's package catalog where that provider exposes a documented first-party search surface |
| `registry.packages.read` | Read package-level metadata for a known package or crate identifier |
| `registry.versions.read` | Read versions, releases, tags, and provider-native release metadata |
| `registry.dependencies.read` | Read dependency metadata for a selected package version or release |
| `registry.artifacts.read` | Read release-file or artifact metadata, hashes, integrity fields, and download URLs |
| `registry.downloads.read` | Read provider-native download statistics where the configured provider supports them |

## Operation Inventory

| Operation | Provider endpoint target | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|--------------------------|------------|------------|-----------|-------------|-----------|
| `registry.search` | npm: `GET /-/v1/search?text=...`; crates.io: `GET /api/v1/crates?q=...`; PyPI: unsupported in first slice | `registry.search` | `Safe` | `Low` | `None` | Read-only catalog query on providers that actually expose a documented first-party search surface in the sources used for this contract. |
| `registry.packages.get` | npm: `GET /{package}`; PyPI: `GET /pypi/{project}/json`; crates.io: `GET /api/v1/crates/{crate}` | `registry.packages.read` | `Safe` | `Low` | `Strict` | Deterministic point lookup for package-level metadata in one configured provider. |
| `registry.versions.list` | npm: packument `versions` and `dist-tags`; PyPI: project or release JSON; crates.io: `GET /api/v1/crates/{crate}/versions` | `registry.versions.read` | `Safe` | `Low` | `Strict` | Read-only release enumeration and tag inspection. |
| `registry.dependencies.get` | npm: version manifest dependency fields; PyPI: release metadata `requires_dist` when present; crates.io: `GET /api/v1/crates/{crate}/{version}/dependencies` | `registry.dependencies.read` | `Safe` | `Low` | `Strict` | Read-only dependency metadata lookup for one selected version or release. |
| `registry.artifacts.list` | npm: version `dist` metadata; PyPI: JSON `urls` and Simple Index file listings; crates.io: version metadata plus version download link surface | `registry.artifacts.read` | `Safe` | `Low` | `Strict` | Read-only artifact inventory. The first slice returns metadata and URLs, not the artifact bodies themselves. |
| `registry.downloads.get` | crates.io: `GET /api/v1/crates/{crate}/downloads`; npm and PyPI: unsupported in first slice | `registry.downloads.read` | `Safe` | `Low` | `None` | Time-varying statistics surface that is only committed for crates.io in the first slice. |
| `registry.health` | Provider-safe anonymous metadata probe plus local config validation | `registry.packages.read` | `Safe` | `Low` | `Strict` | Deterministic readiness check for host reachability, provider binding, and request-path sanity without touching write surfaces. |

## Explicit Non-Goals

The first implementation slice does not include these provider surfaces:

- single-call cross-provider fanout or aggregation
- package publish, upload, yank, unyank, delete, or deprecate flows
- npm token lifecycle, OTP, trusted publisher config management, or OIDC exchange
- PyPI upload execution, Trusted Publisher mint-token flows, Integrity API handling, or organization-role management
- crates.io publish execution, owner invitation flows, owner mutation, or token management
- a standalone `registry.audit_vulnerabilities` operation
- full artifact downloads, checksum verification, signature verification, or installation workflows
- dependency graph solving, lockfile generation, or semver-resolution logic across ecosystems
- private registries, enterprise mirrors, or self-hosted package indexes

These are excluded on purpose:

- The upstream registries do not share these surfaces cleanly enough for a truthful first implementation slice.
- Publishing semantics differ materially across tarball upload, Python distribution upload, and Cargo crate publish.
- Trust, token, and 2FA flows widen the security boundary from public metadata into real account administration.
- A fake normalized vulnerability API would create more technical debt than value because the provider support is visibly asymmetric.

## Implementation Notes For `flywheel_connectors-j05nu.4.4.2`

- Keep the runtime provider-bound at configure time. Do not build a single connector instance that silently multiplexes requests across all three registries.
- Use a typed `RegistryProvider` enum and make unsupported operations explicit in introspection and runtime errors.
- Treat npm packuments as the source of truth for versions, `dist-tags`, dependency fields, and `dist` artifact metadata.
- Treat PyPI JSON as the primary package or release metadata surface and the Index API as the file-list surface. Do not invent search or publish semantics beyond the official docs.
- Treat crates.io `/api/v1/crates` as the primary search and metadata surface, with dedicated endpoints for versions, dependencies, owners, reverse dependencies, and downloads where needed.
- Keep optional provider-native metadata optional. Maintainers, owners, organization membership, and vulnerability payloads may be surfaced as provider-specific fields, but they must not be promised as universally present.
- `doctor()` and `self_check()` should report the configured provider, supported operation subset, auth mode shape, and unsupported-surface caveats clearly.
- Tests should cover scoped npm package names, PyPI project-name normalization, crates.io pagination and version-detail parsing, unsupported-provider search and downloads behavior, and rejection of artifact-body fetching in the first slice.

## Verification And Operator Guidance

The readiness bead adds a replayable verification bundle:

- Entry point: `scripts/e2e/package_registry_connector_verification.sh`
- Artifact root: `artifacts/e2e/package_registry_connector/<timestamp>`
- Primary rerun commands:
  - `rch exec -- cargo run -q -p fwc -- manifest fix connectors/package-registry/manifest.toml --check --json`
  - `rch exec -- cargo check -p fcp-package-registry --all-targets`
  - `rch exec -- cargo fmt --manifest-path connectors/package-registry/Cargo.toml --check`
  - `rch exec -- cargo test -p fcp-package-registry --test integration -- --nocapture`
  - `rch exec -- cargo clippy -p fcp-package-registry --all-targets -- -D warnings`

Operator constraints for this first slice:

- Prefer public fixture packages or localhost mock registries for verification.
- Redact bearer tokens, Authorization headers, and private mirror hostnames before sharing evidence.
- Treat `base_url` overrides as sensitive when they point at internal registries or package mirrors.
- The first slice is read-only. Verification proves metadata and readiness behavior, not publish, yank, owner mutation, or registry administration flows.

## Source Notes

This contract is grounded in first-party docs and first-party source:

- npm's registry docs state that npm resolves packages through the public registry at `https://registry.npmjs.org` and that the registry also exposes write APIs.
- npm's Registry API docs document multiple bearer-token types, OIDC token exchange, and trusted publisher configuration endpoints for package-scoped write flows.
- The official npm registry host exposes package metadata at `https://registry.npmjs.org/{package}`, version metadata at `/{package}/latest`, and search at `https://registry.npmjs.org/-/v1/search`.
- PyPI's JSON API documents project and release routes, including release-file metadata and release-level `vulnerabilities` and `ownership` fields.
- PyPI's Index API documents project listing and per-project file listing in machine-readable form.
- PyPI's Upload API documents `POST https://upload.pypi.org/legacy/` as the upload surface used by tools such as Twine.
- PyPI's Trusted Publisher docs document `POST https://pypi.org/_/oidc/mint-token`, which exchanges an OIDC token for a short-lived API token.
- Cargo's publishing docs document crates.io account setup, API-token creation, `cargo login`, and `cargo publish`.
- crates.io's first-party API and first-party source expose search and metadata under `/api/v1/crates`, plus dedicated link surfaces for versions, owners, reverse dependencies, version dependencies, downloads, and version downloads.
