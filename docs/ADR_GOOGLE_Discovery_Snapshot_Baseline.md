# ADR: Google Discovery Snapshot Baseline for FCP Connectors

> **Status**: ACCEPTED  
> **Date**: 2026-03-06  
> **Owner Bead**: `flywheel_connectors-lszk.45.1.1`  
> **Addendum Bead**: `flywheel_connectors-lszk.45.1.1.1`  
> **Program Epic**: `flywheel_connectors-lszk.45.1`

---

## 1. Goal

Define the non-negotiable architecture contract for Google-family connectors in FCP:

- Google Discovery remains the upstream source of truth for API shape.
- FCP connectors consume **pinned Discovery snapshots** at intentional build/release boundaries.
- Shipped connector operation surfaces MUST NOT mutate at runtime based on freshly fetched Discovery docs.

This ADR is the baseline for the Google foundation and migration beads under `flywheel_connectors-lszk.45.*`.

---

## 2. Context

The Google connector program is trying to solve two problems at once:

1. Avoid hand-maintaining dozens of Google REST surfaces forever.
2. Preserve FCP's mechanical guarantees around manifests, interface hashes, approvals, tests, and auditability.

Those goals pull in opposite directions if we let Discovery documents alter shipped behavior during connector runtime.

FCP connectors are not generic API explorers. They are signed, reviewable binaries with:

- fixed manifests,
- deterministic `interface_hash` values,
- stable introspection output,
- explicit capability and approval mappings,
- reviewable network constraints,
- reproducible tests and fixture baselines.

The current codebase already leans this way:

- Google connector manifests carry explicit `interface_hash` values.
- Google connectors expose hardcoded `Introspection.operations` lists in code.
- Connector tests assert deterministic interface behavior instead of live external schema drift.

Leaving this principle implicit is dangerous. A future "smart" runtime fetch of Discovery metadata would quietly turn external documentation drift into shipped tool-surface drift.

---

## 3. Decision

### 3.1 Discovery Is Upstream Truth, Not Runtime Control Plane

Google Discovery documents are the canonical upstream input for API coverage, method metadata, schemas, and generator inputs.

They are **not** allowed to directly and opportunistically mutate a connector's runtime-visible operation surface.

The pipeline is:

1. Fetch Discovery from upstream.
2. Normalize and freeze it into a pinned snapshot artifact.
3. Generate connector-facing metadata from that pinned snapshot.
4. Apply explicit handwritten overrides where FCP policy, UX, or safety needs more than raw Discovery can express.
5. Commit the resulting artifacts, regenerate manifests/introspection, review the diff, and ship a new connector version.

### 3.2 Pinned Snapshots Are the Unit of Change

The approved unit of change is a reviewed snapshot update, not a runtime fetch.

That means:

1. Discovery refresh happens in generation/build/release workflows.
2. Snapshot updates are visible in git diffs and code review.
3. Connector releases deliberately absorb upstream API evolution at chosen boundaries.
4. Drift is handled as an explicit update event, not as background runtime behavior.

### 3.3 Runtime Surface Must Stay Stable

Once a connector version is built and released:

1. The manifest contract is fixed.
2. The `interface_hash` is fixed.
3. The introspection/tool catalog is fixed.
4. Capability mappings, risk tiers, approval modes, and network policy are fixed for that version.

Runtime code MAY consume configuration, credentials, and request parameters, but it MUST NOT fetch Discovery and add/remove/reshape operations on the fly.

### 3.4 Handwritten Overrides Sit Above Generated Metadata

Pinned generation is necessary but insufficient on its own. Raw Discovery does not know FCP's:

- capability vocabulary,
- risk/approval model,
- zone guidance,
- operator ergonomics,
- naming conventions,
- policy ceilings,
- AI hint quality bar.

Therefore handwritten overrides are first-class and expected.

Override rules:

1. Overrides augment or constrain generated metadata.
2. Overrides are explicit, reviewable, and versioned in git.
3. Overrides win when Discovery shape and FCP policy/UX requirements differ.
4. Overrides must remain deterministic when replayed over the same pinned snapshot.

### 3.5 Determinism Beats Runtime Cleverness

This decision is specifically meant to preserve:

- **Interface-hash stability**: external docs must not silently change the API surface of an already shipped connector.
- **Manifest auditability**: reviewed manifests must describe the actual shipped surface.
- **Approval predictability**: operators and policy engines need a stable mapping from operation to capability/risk.
- **Deterministic CI and release behavior**: identical inputs should produce identical generated outputs.
- **Reproducible fixtures**: tests must pin against known API shapes instead of today's network response.
- **Operational clarity**: when behavior changes, the change should appear as a commit, a bead, and a release note.

### 3.6 Distribution Channels Are Separate From Runtime Form Factor

The upstream `googleworkspace/cli` project is a useful packaging data point, not a runtime template: it ships a native Rust `gws` binary while also offering convenience distribution paths around prebuilt binaries.

What is worth preserving:

1. A broad Google CLI can still be implemented as a compiled Rust binary.
2. Prebuilt multi-platform artifacts and convenience installers reduce operator friction.
3. Distribution wrappers can exist without turning the actual runtime into an interpreted application.

What FCP must reject:

1. Requiring Node.js, `npm`, or any other interpreted runtime as part of connector execution.
2. Shipping a connector whose operational behavior depends on JavaScript wrapper code at install time or runtime.
3. Treating a package-manager wrapper as part of the trusted connector runtime boundary.

The normative FCP rule stays stricter than upstream:

1. The runtime artifact is still exactly one connector binary plus one manifest file.
2. Any optional installer, package-manager wrapper, or release-channel helper is only a distribution shell around those native artifacts.
3. Wrapper code MUST NOT participate in request handling, auth flow execution, tool-surface generation, or any other runtime connector semantics.
4. A connector install path that requires `npm install` or another interpreted dependency manager is out of policy for FCP.

---

## 4. Rejected Alternatives

### 4.1 Rejected: Live Dynamic All-Google Connector

This alternative would fetch Discovery at runtime and expose a mutable surface based on whatever Google publishes that day.

We reject it because it breaks core FCP expectations:

1. A signed connector binary would no longer imply a stable operation catalog.
2. `interface_hash` and manifest review would stop being trustworthy summaries of shipped behavior.
3. Approval semantics could change without a code review or release.
4. CI and fixture reproducibility would degrade into "works against whatever upstream returned".
5. Operators would face surprise behavior changes from upstream documentation churn rather than intentional upgrades.

This is especially unacceptable for Google because breadth is large, docs evolve frequently, and the cost of accidental behavior drift compounds across many connectors.

### 4.2 Rejected: Purely Handwritten Per-Service Connectors

This alternative avoids runtime drift but throws away the leverage of Discovery as the upstream schema source.

We reject it because it would:

1. duplicate raw HTTP/method/schema maintenance across services,
2. make drift detection slower and more manual,
3. reduce reuse across Gmail, Calendar, Drive, Docs, Sheets, YouTube, and related services.

The correct tradeoff is **Discovery-driven generation on pinned inputs**, not runtime mutation and not purely manual maintenance.

### 4.3 Rejected: npm-Mediated Connector Runtime Boundary

It is acceptable to learn from upstream release ergonomics, but it is not acceptable to import upstream's install-time assumptions into FCP's execution model.

We reject any design where:

1. a connector requires Node.js or package-manager glue to run,
2. wrapper code becomes part of the security-reviewed runtime boundary,
3. multi-file interpreted packaging obscures the actual shipped connector surface.

FCP distribution may borrow convenience. It must not borrow runtime dependency leakage.

---

## 5. Consequences

### 5.1 What Downstream Beads Must Build

The Google foundation must provide:

1. snapshot fetch/parse/normalize/freeze tooling,
2. deterministic generation from pinned inputs,
3. explicit override tables and overlay rules,
4. drift-detection tests and review-friendly diffs,
5. release workflows that make snapshot updates intentional.

### 5.2 What Runtime Connectors Must Not Do

Runtime connectors must not:

1. fetch Discovery to discover new tools live,
2. mutate introspection schemas after build,
3. alter manifest-derived capability or approval contracts from live docs,
4. rely on external Discovery availability to answer what operations exist.

### 5.3 How to Interpret Future Scope

This ADR is not anti-Discovery. It is anti-unreviewed runtime mutation.

We still want:

- broad Google API coverage,
- generator-assisted connector creation,
- snapshot refresh automation,
- fast adoption of upstream API changes.

We just want those changes to happen at intentional update boundaries where FCP's security and audit model still holds.

### 5.4 Packaging Consequence for Google Connector Work

Downstream release/install work may provide operator-friendly delivery paths for Google-family connectors, but those paths must preserve the same audited runtime payload:

1. a native Rust connector binary,
2. a manifest that matches the shipped interface and policy contract,
3. no interpreted runtime dependency in the execution path.

---

## 6. Adoption and References

- This ADR is normative for `flywheel_connectors-lszk.45.1.*` foundation beads.
- `flywheel_connectors-lszk.45.1.1.1` records the packaging/distribution addendum: convenience wrappers may distribute native artifacts, but they do not relax the binary-plus-manifest runtime rule.
- Migration beads under `flywheel_connectors-lszk.45.2.*` MUST assume pinned snapshots, not live runtime Discovery mutation.
- The requirements index records this ADR as the baseline architectural contract for the Google connector platform.
- Update this ADR only through explicit bead-linked changes.
