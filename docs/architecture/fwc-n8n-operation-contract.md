# `fwc-n8n` operation contract

> Status: Phase 0 accepted contract
> Contract version: `1.0.0`
> Bead: `flywheel_connectors-nqm81.1`
> Date: 2026-08-09

This document freezes the accepted public surface for the on-demand n8n
connector and remains normative for the `fwc-n8n` project. Current runtime and
installation evidence is called out explicitly below; the
`connectors/n8n` and `connectors/mcp-bridge` READMEs remain the source of truth
for implementation details.

No provider call, live workflow change, credential change, process stop, or MCP
profile change is authorized by this contract.

## Current delivery plan and evidence boundary (2026-09-30)

The following delivery snapshot is dated history. For the current bounded
`.34` closeout (2026-10-04), see the [criterion matrix](#34-acceptance-update--2026-10-04)
and [operator state](../../connectors/n8n/README.md#current-operator-state--2026-10-04).
Local integration `202e5e3924eb183bc01724bf0f8939bee1eed66e` includes the final
test source `efb3e22f11c5`; installed RC43c runtime remains `09cebc4`, not that tip.

Sections 5, 5.1 and 14 remain the complete v1 feature baseline. Unimplemented
routes remain delivery obligations; Beads owns status and dependencies.

- Historical installed checkpoint: `release-20260929-42a574a62-started-result-rc40`.
  `.25` manual execution passed on EEC (`414677`) and Hetzner (`379754`), with
  independent GET proving manual mode, terminal success and exact approved
  workflow versions. Retained evidence is under
  `/srv/dev-ssd/fcp/nqm81.25/manual-acceptance-rc38-webhookdata-20260929/attempt-05`
  and `/srv/dev-ssd/fcp/nqm81.25/manual-acceptance-rc37-20260929/hetzner/attempt-06`;
  directory names describe the test series, not the installed RC.
- `.24` selected-version publish/unpublish passed under RC33; `.23` REST
  unarchive passed under RC26. These are operation-specific historical results.
  MCP archive was not accepted by `.10`; `.33` owns reversible archive/unarchive.
  `.26` production execution and `.41` test preparation/execution remain separate.
- `.34` owns compatible updates under section 11.2. Source/offline verification
  alone does not establish installed/live acceptance; the later separate live
  results and actual closure are recorded there.
- `.35` owns read/knowledge/validation/status/audit parity; `.36` versions and
  rollback; `.37` data tables; `.38` evaluations; `.39` credential-backed resource
  exploration; `.40` explicit execution detail; `.42` draft/template/autofix parity.
  Each includes every applicable section 5.1 sub-action, public dispatch,
  unit/host/CLI tests and separately authorized provider acceptance. Routing or
  refusal-only behavior is not completion; section 13 destructive scope stays future-only.
- `.15` owns the final operation/server/release/evidence matrix, same-chat UX,
  risk-based regressions, failure drills, zero-idle, fallback and proven recovery
  on one identified candidate. Missing capability remains a gap unless the owner
  changes scope. `.32` UNKNOWN requires reconciliation or explicit owner disposition;
  preserve UNKNOWN history. Fixture availability restoration is separately approved.
- `.11` accepted a trusted update executor, not the whole update service. `.43`
  owns detection/staging/verification/recovery integration; `.12` owns ClickUp/Telegram.
  Both gate integrated rollout separately from `.15`; `.16`–`.18` retain credential
  mutation, legacy key retirement and general permanent deletion as future decisions.

Maintain the final matrix here during `.15`, rather than adding a backlog. Each
feature needs a bounded tracked script with offline self-test, actual CLI tests,
redacted stage/attempt/readback/teardown evidence and distinct source, installed
and live results. No plan authorizes provider writes, installation or cleanup.

**Compatible-update source contract (`flywheel_connectors-nqm81.34`):**
Numeric upstream versions are diagnostic; exact approved staged versions and
artifact/trust hashes remain binding. Local catalog validation covers the whole
response, but compatibility is checked for every requested sequence tool before
the first call. The public callable set remains closed. Unrelated valid catalog
changes do not disable a compatible operation.

The optional immutable `reviewed_schemas` extension carries an explicit
`mcp-schema-descriptions-v1` profile, reviewed original input/output schemas and
serialized input/output compatibility digests. The original raw integrity pins
are checked before compatibility projection. Only `description`, `title` and
`$comment` at actual schema nodes are omitted; user property names, default/const/
enum payloads, references, required fields, output presence and unknown keywords
are never erased. Missing output is distinct from a present invalid null schema.
No live observation is auto-enrolled. Unknown tools gain no authority. A changed
operation/server is blocked independently unless shared trust/transport fails.
Approval bindings, independent readback including exact `workflowVersionId`,
one-attempt/no-fallback semantics and owned-process teardown remain unchanged.

The existing assembler accepts explicit reviewed baseline maps via
`FWC_N8N_REVIEWED_SCHEMA_BASELINES`; `fwc-n8n reviewed-schema-profile` validates
their raw pins and emits the serialized profile for immutable staging. Policies
without reviewed baselines retain raw-only checks.
Local `expected_output_catalog` pins distinguish absence from presence; omitted
legacy entries bind absence. Both raw input and output pins are verified before
minting a local reviewed profile. Observational `schema-projection` cannot mint
one. The assembler's pure `--offline-catalog-bindings SOURCE_BINARY` boundary
uses the same producer as normal staging, with synthetic input and no discovery.
Offline CLI, bundle,
provision, update, supervisor and loopback/process runs validate separate
boundaries. The bounded preflight script's `--compatibility-self-test` reports
`acceptance:false`; it is not live acceptance. The separate installed/live
results and remaining boundaries are recorded in the dated matrix in section 11.2.

## Historical implementation and acceptance packets

The dated packets retain their evidence and limitations. “Current” refers to
the packet date and cannot establish acceptance on a later release.

**Current installed release/read-only smoke boundary (2026-09-18):**
`/usr/local/lib/fwc-n8n/current` resolves to
`release-20260917-74b9b97c0-rc2` (git revision
`74b9b97c0e63cf5c4336becd4a9c393ab4c82e14`), and
`/usr/local/bin/fwc-n8n status` reports `{"bundleAvailable":true}`. The fixed
zero-idle systemd broker is installed and listening on
`/run/fwc/fwc-n8n-secret-broker.sock`; the documented read-only smoke boundary
is `crates/fcp-host/tests/n8n_owned_static_smoke.rs`. The installed local MCP
policy remains pinned to `n8n-mcp` `2.84.4`, protocol `2024-11-05`, and
network-disabled execution. These checks establish installed bundle/broker
readiness only; they do not by themselves authorize or establish lifecycle
writes. The owner-approved `.10` live acceptance is recorded below.

**Current source/main static evidence (2026-09-18; separate from live evidence):**
The current `main` tree is at
`74b9b97c0e63cf5c4336becd4a9c393ab4c82e14`. After the baseline read, a
possible Official MCP `archive_workflow` attempt is followed by at most one
independent REST readback. Readback transport, decode, invalid-state, and
mismatch errors are terminal `unknown_outcome`; the provider attempt's
redaction-safe diagnostic and correlation ID take precedence field-by-field,
with the readback diagnostic and correlation ID as fallback. The boundary
allows exactly one MCP attempt and at most one independent REST readback, with
no retry. A failure known to precede provider dispatch returns immediately and
skips readback and makes no provider attempt. Publish/unpublish behavior is
unchanged: the exact Official MCP call is followed by authoritative independent
REST readback; uncertain or mismatched results are not retried automatically.

The current focused verification passed `21` `official_mcp_lifecycle` tests,
the targeted `fcp-host` filters exited successfully, and `cargo fmt --check`
was clean. This is static source evidence only; it complements, but does not
replace, the retained live evidence below.

**Current `flywheel_connectors-nqm81.10` live acceptance (2026-09-18; PASS):**
The Bead is closed for its bounded scope: one fresh disposable
publish/readback/unpublish/readback cycle on EEC and one existing disposable
cycle on Hetzner. Each cycle used the exact workflow and version target, the
owner-approved official MCP operation, one provider write per transition, an
independent typed REST GET, and no retry after an unknown outcome. Archive/restore,
activation/deactivation, execution, credential mutation, permanent deletion,
and changing `current` remain outside this acceptance.

For EEC, workflow `2k83Mtem1wCvsqpJ`, version
`64fa87fb-8dcf-4a8b-9bc8-4aa4d86677ea`, and draft graph
`blake3-256:a3557027a8a642c2034a2f2ce19f34f4bf2d89c0e46f2aacd2ad1d6cb6b799f3`
were bound before provider I/O. The MCP-access precondition was applied once
under approval `7e96070b-df6e-49ff-8435-4865fb1e1008`. Publish attempt
`23de91b7-0969-447f-9a65-4e078a08014b` and independent GET
`67da6935-15c2-42c3-98f9-48f21f45f2b7` proved the matching active and
published version/graph. Unpublish attempt
`bb7c1500-d210-434e-adb6-a7ea77d19dac` and final independent GET
`f7dc1471-224f-49e0-87b6-c2374a0d8f46` proved the matching inactive,
unpublished, and unarchived final state. Redaction-safe evidence is retained
under `/srv/dev-ssd/fcp/nqm81.30/live-mcp-access-20260918-corrected-7e96070b-df6e-49ff-8435-4865fb1e1008/`,
`/srv/dev-ssd/fcp/nqm81.30/live-eec-publish-20260918-23de91b7-0969-447f-9a65-4e078a08014b/`,
and `/srv/dev-ssd/fcp/nqm81.30/live-eec-unpublish-20260918-bb7c1500-d210-434e-adb6-a7ea77d19dac/`.

The Hetzner cycle is retained under
`/srv/dev-ssd/fcp/nqm81.30/live-hetzner-create-20260917/` and
`/srv/dev-ssd/fcp/nqm81.30/live-hetzner-publish-20260917/`; its exact
publish/unpublish readbacks proved the matching active and final inactive
states. Raw provider bodies, credentials, seeds, and tokens were not persisted.

**Historical bounded Hetzner lifecycle evidence (2026-09-17; PASS):**
Using the installed `release-20260916-5dfb5745-owner-rc2`, a fresh disposable
webhook workflow `Cb7jfMXeDxyHytnY` / version
`2dbce392-dcbd-4b8f-b2bf-da39e3c2b71c` passed the exact inactive, unpublished,
and unarchived baseline. One owner-approved official-MCP `publish_workflow`
wrapper invocation followed by an independent REST GET proved `active=true`, the matching
active version, and matching draft/published graph. Only after that proof, one
owner-approved `unpublish_workflow` wrapper invocation followed by an independent REST GET
proved `active=false`, `activeVersionId=null`, `isArchived=false`,
`published=null`, and the unchanged draft graph. The retained request metadata
binds the publish transition to approval ref
`nqm81.10-hetzner-publish-89fb4d0b-5c9a-43ce-92d3-62e7861ba38c`, wrapper
correlation `09e16ee0-8500-4b80-97d0-ca9d9cec5dee`, and independent GET
correlation `4e7fbd86-1f5c-4f59-a22e-e96b90ef50ca`. It binds the unpublish
transition to approval ref
`nqm81.10-hetzner-unpublish-de91b7a4-6c32-4f85-9a17-2e5d8c3b704f`, wrapper
correlation `0a5fd2c9-8e71-4b34-a6d3-1f7c90e528bd`, and independent GET
correlation `7c1e9a52-4d68-4fb0-b327-8a6c1d5e904f`. The final state digest is
`blake3-256:514bcd74e6a527e21212de8ff87d01f4d8e5a5ad769e3aefe8442d3131196122`.
Redaction-safe evidence is retained under
`/srv/dev-ssd/fcp/nqm81.30/live-hetzner-create-20260917/` and
`/srv/dev-ssd/fcp/nqm81.30/live-hetzner-publish-20260917/`; the publish safe
projection has a reporting defect (`status=verified` with
`response_class=error`), and its GET represented `isArchived=null`; neither is
treated as a clean envelope or normalized to `false`. Exact provider-attempt
counts must come from retained claim/receipt records, not from these safe
projections or exit codes. Raw provider bodies,
credentials, seeds, and tokens were not persisted. The remote Hetzner runtime
reports `2.37.10` while the release policy remains pinned to `2.34.6`; this
observed drift was not changed because it is not a lifecycle-equality gate.
At the time of this packet it proved only the Hetzner half; the later EEC-first
pass is recorded in the current acceptance block above.

**RC11 privileged promotion / external issuer gate checkpoint (2026-09-11;
bounded NO-GO):**
The fresh owner-signed candidate `release-20260911-fcee1784b-rc11` was
validated and promoted using root-shell input redirection. Exactly one
preflight returned `status=preflight_ok` with `currentChanged=false`, followed
by exactly one apply returning `status=promoted` with `currentChanged=true`.
`current` now resolves to
`release-20260911-fcee1784b-rc11`; its signed `fwc.n8n.provision.v1` receipt,
`fwc.n8n.provenance.v1`, bundle status, retained predecessor, and zero matching
build/sign/provision processes all pass independent checks. The former
permission failure was therefore corrected without a source or runtime-binary
change.

The external approval issuer is intentionally separate from the runtime
bundle. The RC11 candidate issuer at the SSD target has SHA-256
`ce4bc4e44a159645b45ff2641786b7703c52342ff3f06a977e6c067e03b25e8b`, but the
fixed installed target `/usr/local/sbin/fcp-n8n-approval-issue` still has the
previous SHA-256
`b556d3311b812aa554c25db2dae4386ed2a7b7a2f192031b356cc0cf5c86d5ca`.
Consequently the promotion gate is **bounded NO-GO** until the separately
approved issuer installation and digest readback are complete. No provider,
API, workflow, credential, or lifecycle operation was attempted.

Redaction-safe evidence is retained at
`/srv/dev-ssd/fcp/nqm81.30/install-rc11-20260911/report.md` (SHA-256
`d9d3903f600d6aa91b0ee3afe8334222569dd1fc51ce663336f23df78b110d4a`). A
future supervised step may replace only the fixed issuer target from the
approved SSD candidate, verify root ownership/mode and both digests, and then
start a new EEC-first acceptance; this packet must not be replayed.

**RC11 release-packet checkpoint (2026-09-11; bounded NO-GO):**
The fresh SSD candidate `release-20260911-fcee1784b-rc11`, built from main
revision `1a12c5449cf4b0be487ee6aad78a065239378e51`, completed one assembler
invocation and the owned static-network smoke passed (`1 passed`). The staged
issuer gate passed exact digest equality at
`ce4bc4e44a159645b45ff2641786b7703c52342ff3f06a977e6c067e03b25e8b`; one
owner-signing operation produced the staged `fwc.n8n.provision.v1` receipt.

The single provision-preflight attempt stopped before entering the candidate
binary because the non-root shell could not read the root-owned approval
request (`permission denied`). No retry was made. Root issuer installation,
apply/promotion, and every provider/API/workflow/credential operation were not
attempted; the predecessor was preserved. `current` remains
`release-20260910-e30ca9f09-rc1`, `fwc-n8n status` reports
`bundleAvailable=true`, and the installed issuer remains SHA-256
`b556d3311b812aa554c25db2dae4386ed2a7b7a2f192031b356cc0cf5c86d5ca`. The
post-stop matching-process check was empty.

Redaction-safe evidence is retained at
`/srv/dev-ssd/fcp/nqm81.30/release-20260911-fcee1784b-rc11/report.md`
(SHA-256
`d859a349d21e624850bbc488c43149adf89db6a46aa87cb9dc3ae8ae8e521c45`). Live
acceptance remains **NO-GO**: EEC and Hetzner publish/readback/unpublish/
final-readback were not attempted. Do not replay this packet or install the
candidate without a separately supervised privileged preflight and fresh
owner-authorized acceptance gates.

**Latest release/acceptance checkpoint (2026-09-11 00:21 UTC; RC8 bounded stop):**
The fresh SSD candidate `release-20260910-fcee1784b-rc8`, built from main
revision `fcee1784b1f51aba6c3dd49db9de5162d8116ae3`, assembled successfully;
the static owned-network smoke passed (`1 passed`). Independent unsigned-tree
and request checks passed, the single owner-signing operation produced a valid
redaction-safe `fwc.n8n.provision.v1` receipt, and the single provision
preflight returned `status=preflight_ok` with `currentChanged=false`.

The release was then stopped fail-closed before issuer installation because
the staged external approval issuer SHA-256 did not equal the approved value
for the installed issuer. The issuer was not executed or installed, apply and
promotion were not attempted, and no provider/API/workflow/systemd action was
performed. `current` remains
`release-20260910-e30ca9f09-rc1`, `fwc-n8n status` reports
`bundleAvailable=true`, and the prior issuer remains unchanged. Post-stop
checks confirmed the candidate was not installed, the prior release was
retained, no matching processes remained, and the source checkout was still
tracked-clean at the RC8 revision.

Redaction-safe evidence is retained at
`/srv/dev-ssd/fcp/nqm81.30/release-20260910-fcee1784b-rc8/report.md` (SHA-256
`8c0702d693571a780da5c3b3a94922c4cc93ce33aa525d3cd4870e38fa057e33`) and the
append-only hash manifest at
`/srv/dev-ssd/fcp/nqm81.30/release-20260910-fcee1784b-rc8/sha256sums.txt`
(SHA-256
`0721106769e5c4ad2db4a26d718f6a04612d5ec1fd8b16496a5d2d457388ec18`). Both
redaction scans passed. Live acceptance remains **NO-GO**: EEC and Hetzner
publish/readback/unpublish/final-readback were not attempted in this packet.
Do not install the mismatching issuer or replay a provider attempt; a future
run requires reconciling the approved issuer digest, then a fresh signed
release and new bounded EEC-first acceptance.

**RC8 issuer-contract diagnosis (2026-09-11 00:44 UTC):**
Read-only inspection confirmed that the approved issuer digest is a deployment
and owner-approval value retained in prior release evidence and this contract,
not a Rust/source constant in the assembler, provisioner, signer, or issuer.
The installed issuer remains SHA-256
`b556d3311b812aa554c25db2dae4386ed2a7b7a2f192031b356cc0cf5c86d5ca`, while the
complete root-owned RC8 staged issuer is SHA-256
`ce4bc4e44a159645b45ff2641786b7703c52342ff3f06a977e6c067e03b25e8`; their
metadata also differs (981848 versus 990584 bytes), so this is a genuine
binary mismatch rather than a path or metadata discrepancy. The RC8 issuer
source closure includes the reviewed `n8n.mcp_access.reconcile` approval
extension and cannot be silently replaced with the old binary or accepted by
overriding the comparison. The redaction-safe diagnosis report is retained at
`/srv/dev-ssd/fcp/nqm81.30/issuer-contract-diagnosis-20260911/report.md`
(SHA-256
`6f19fe67bdef8ef683c2c4bba4014d9683f791acf61e87df37dc234a2ac12137`).

The next owner decision must explicitly either approve the exact RC8 staged
issuer digest for separate installation, or require a fresh candidate whose
issuer independently matches the old approved digest. Either choice requires
a fresh signed release packet, a new issuer gate recording the before/after
digests, and a new bounded EEC-first acceptance; no packet replay or provider
write is authorized by this diagnosis. Current remains RC1 and acceptance
remains **NO-GO**.

**Previous live acceptance checkpoint (2026-09-10 15:32 UTC; RC7):**
`current` resolves to `release-20260910-e30ca9f09-rc1`, built from revision
`e30ca9f0921d8e0db3f3b3ff173427c6a53758a7`, and `fwc-n8n status` reports
`bundleAvailable=true`. The release includes the verified dry-run ledger-bypass
fix. A fresh supervised EEC-first acceptance passed the exact inactive,
unpublished, unarchived baseline and one `n8n.mcp_access.reconcile` dry-run
(`desired=true`, `dryRun=true`, one planned change, zero exceptions, and no
durable ledger claim/commit). The apply gate then stopped fail-closed because
the installed owner issuer has no exact approval representation for
`n8n.mcp_access.reconcile`: `N8nApprovalIssueRequest.operation` is the
`N8nLifecycleOperation` enum, whose supported variants are limited to lifecycle,
archive, draft-create, and disposable-delete operations. No approval request,
seed transport, signed token, MCP-access apply, or lifecycle provider write was
attempted. One independent typed EEC reconciliation GET confirmed the exact
baseline remained unchanged; Hetzner was not started under the EEC-first rule.

The redaction-safe report, evidence, and SHA-256 manifest are retained under
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc7-20260910/` (report SHA-256
`3e4f3360e86b44a3b6a9c0c45ecdd66b13b912bab911341b5a6d7c540b520571`; manifest
check passed; directory mode `0700`, artifacts mode `0600`). Acceptance remains
**NO-GO**. Do not retry the provider or invent a broader approval payload. A
future attempt requires a reviewed exact MCP-access approval schema/issuer
extension, focused offline tests, a freshly assembled and installed signed
release, and a new bounded EEC-then-Hetzner acceptance run.

**Earlier lifecycle checkpoint and completion plan (2026-09-10):**
`current` resolves to `release-20260910-db3924628-rc4`, revision
`db3924628e8ea908f463ab05bafde6c79442405a`. Owner signing, provision preflight,
apply and promotion completed; installed provenance and signed receipt agree,
the bundle contains 12 verified release artifacts, the receipt covers 14
artifacts and both EEC/Hetzner bindings, and `status` reports
`bundleAvailable=true`. This release includes the fixed redaction-safe
lifecycle diagnostics from `d86b439528abe047b44839d3d7203f64e66f3246`.
Workspace compilation, focused lifecycle tests and formatting passed; Clippy
remains blocked by unchanged baseline lint errors. The RC3 predecessor is
preserved and the external approval issuer is installed from the same release
candidate. Redacted RC4 assembly and promotion evidence is retained at
`/srv/dev-ssd/fcp/nqm81.30/release-20260910-db3924628-rc4/report.json`.

Live lifecycle acceptance is still **NO-GO**. The prior fresh EEC publish at
02:32 UTC returned `unknown_outcome`, correlation
`fbc2af96-0cc8-434a-b7f0-b5d4c38d939b`; its independent reconciliation showed no
published version and no state mutation, and it is not being replayed. The
first post-RC2 acceptance dispatch `ctx_9a101b229a88` (06:08--06:15 UTC) made
only the permitted EEC read-only baseline and one final reconciliation, then
stopped before any write because the task's expected EEC `stateDigest` was a
truncated 63-hex value. The provider observed the canonical 64-hex digest
`blake3-256:1b431688626cba116259425ed22acb74fed2bbe423330a7b7f039b1d2908f91c`.
The exact redacted evidence is recorded at
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-20260910T060830Z-b483900a-e190-4eb4-b3f2-a814916782ae/live-acceptance-report.json`;
Hetzner was not started and no provider write was attempted.

The next RC3 acceptance dispatch `ctx_6f263199ee9e` (07:10--07:21 UTC)
performed the corrected EEC read-only baseline and confirmed every required
invariant, including the complete canonical state digest, inactive state,
unarchived state, and no published summary. The fresh approval request then
failed closed with issuer diagnostic `invalid_request`: its expiry was encoded
at nanosecond scale, so no approval token was issued, the lifecycle wrapper was
not called, and no provider write was attempted. One immediate independent EEC
reconciliation remained unchanged and verified; Hetzner was not started. The
redacted report and three-event evidence are retained at
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc3-20260910/live-acceptance-report.json`
and `/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc3-20260910/evidence.jsonl`.
The report records `outcome=bounded_stop`, zero
provider lifecycle writes, no token on disk, no matching processes remaining,
and an unchanged `main` checkout at the RC3 revision. Live acceptance remains
**NO-GO**; a future attempt must correct the expiry representation and start a
new bounded EEC-then-Hetzner run, without replaying this failed approval.

A fresh supervised RC3 acceptance dispatch `ctx_04269ae38c65`
(09:08--09:09 UTC) corrected the previous expiry-unit defect: the request used
13-digit Unix milliseconds (`expires_at_ms`), and the issuer received exactly
32 decoded seed bytes. EEC's exact baseline passed, but the isolated issuer
still failed closed with `invalid_request` before token issuance or any
lifecycle wrapper/provider call. The redacted request metadata records the
official MCP resource as
`fwc-mcp-bridge://eec/tools/publish_workflow`; the issuer contract in
`crates/fcp-host/src/n8n_approval.rs` requires the canonical encoded form
`fwc-mcp-bridge://eec/tools/publish%5Fworkflow` because its resource-segment
encoder escapes `_`. This localizes the new rejection to the request-builder
resource-URI mismatch, not to expiry or seed length. One reconciliation GET
confirmed EEC unchanged (`active=false`, `activeVersionId=null`, unpublished,
unarchived, and the exact draft digests); Hetzner was not started. The report
records `outcome=failed`, `stopReason=publish_approval_error`, two EEC GETs,
zero wrapper/provider writes, one issuer attempt, no matching processes, and
the unchanged RC3 release. Redacted evidence is retained at
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc3-20260910/TurquoiseValley-ctx_04269ae38c65-report.json`,
with report SHA-256
`237440a26c874d642b1a8dfe62b27547f17d89ca550b4f213916fba18649198a`,
evidence SHA-256
`b7eca1a205367e13cbf6f8498e87284c567f891a07d08f9d9fd5623f8d8688e0`, and
manifest SHA-256
`1ef5a0ddfb05fe84364f01640c0e7cee063d1ea719b5d46148254eacb60c75b3`.
Live acceptance remains **NO-GO**. Do not retry the provider lifecycle; a
future acceptance requires a reviewed request-builder/issuer URI correction,
fresh offline proof and release installation, then a new bounded EEC-first
run.

The offline real bridge-process regression passed all five `capability_gate`
tests (dispatch `ctx_25dc04c4179d`), including all four EEC/Hetzner
publish/unpublish paths and fail-closed mismatches. It does not cover the full
host run-once/owned-host path. Package Clippy and formatting passed; workspace
Clippy remains blocked by 11 existing `fcp-sandbox` lints. Live acceptance
remains open pending a corrected, fresh EEC-then-Hetzner lifecycle run.

The fresh fixed-expiry RC4 acceptance dispatch `ctx_6f07730de760` (Orca task
`task_3439a6782bbe`, 11:13--11:22 UTC) corrected the local expiry defect and
passed the exact EEC baseline. Its approval request used the encoded official
MCP resource URI, a 13-digit Unix-millisecond expiry, the canonical parent
binding helper, and the isolated issuer; the single EEC publish wrapper call
then returned `unknown_outcome` (wrapper error, correlation
`2418798a-5c32-471f-9de2-d042b3129d00`). The fail-closed stop rule prevented a
retry, unpublish, or any Hetzner call. One EEC reconciliation GET proved the
workflow remained inactive, unarchived, unpublished, and equal to the exact
baseline; provider lifecycle writes attempted/verified were `1/0`. The
redacted report, evidence, and manifest are retained under
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc4-fixed-20260910/`; the report
SHA-256 is
`5ca276f6d280154bd526de0426160ac9b3ce709883ff2183f8540ac348286558`, its
redaction scan is clean, no matching processes remain, and the RC4 release
pointer is unchanged. Live acceptance remains **NO-GO**; this unknown result
must not be replayed, and no provider side effect may be inferred from it.

The owner authorized completing bead `flywheel_connectors-nqm81.10`, including
necessary tested release installation. Run `run_7f59cff02127` tracks this plan:

1. Diagnose the remaining real host/bridge process boundary from source and
   retained evidence, alongside a bounded read-only EEC log check for this
   attempt; distinguish a local rejection from a proven provider failure.
2. Fix the confirmed cause and add a regression that covers the actual failed
   boundary, then verify and install the resulting signed release.
3. On EEC `oD8zytCtv5PiSYzc`, then Hetzner `oPmF5VkbiVRgIS5S`, prove publish,
   independent readback, unpublish and final independent readback through FCP.
   Each final state must have `active=false`, `activeVersionId=null`,
   `published=null`, `isArchived=false`, and the preserved draft graph/version.
   The canonical EEC baseline state digest is
   `blake3-256:1b431688626cba116259425ed22acb74fed2bbe423330a7b7f039b1d2908f91c`
   (64 lowercase hex characters after the prefix); baseline checks must use
   the complete value.
4. Retain redacted evidence, update Beads according to the actual outcomes,
   and release each completed task-owned worker.

Unknown writes are reconciled before further action and are never replayed
automatically. Archive remains contract-only for this acceptance; workflow
execution, production changes and credential mutation are outside this plan.
Historical checkpoints below describe their stated dates, not the current
installed release.

**Historical host evidence (2026-08-28, read-only):**
`/usr/local/lib/fwc-n8n/current` points to
`release-20260828-d4e8b288e-static` (git revision
`d4e8b288e9415484978ea4a047e575a9ffddd7cb`), whose installed `fwc-n8n status`
reports
`{"bundleAvailable":true}`. The resolved tree contains both `provenance.json`
and `provision-receipt.json`, and their release/revision metadata agrees with
this release. Receipt presence and matching metadata alone do not establish
cryptographic verification, live provider acceptance, or current-release live
acceptance; no such live/API invocation is claimed here. No release switch was
performed by this documentation update.
The source `main` is newer (`2a908c742`); the committed redacted host-error-detail
propagation is not yet installed in `current`.
The historical fixed runtime policy recorded local `n8n-mcp` package version
`2.69.2`; the source update fixtures also pin that exact version for their
historical/update-path tests. This is historical version evidence only, not the
current installed runtime policy and not a live provider check.

Current source boundary: `fwc-n8n` is a thin typed CLI for `resolve`, `route`,
`run-once`, `update-review detect`, the explicit owner-only
`update-review stage-local-mcp <exact-version>` staging review, `provision
[--mode preflight|apply]`, and `status`. `provision` defaults to read-only
`preflight`; mutation requires the explicit owner-gated `provision --mode
apply`. `run-once` supports ten Phase-1
REST reads, guarded REST draft create/update, typed source paths for lifecycle
`publish`/`unpublish` and archive, two local knowledge/validation operations,
and one official-MCP discovery operation, `n8n.capabilities.inspect`, plus the
bounded `n8n.workflows.delete_disposable` cleanup path. The latter is not a
general workflow-delete capability: it requires a host-issued receipt proving
that the same workflow was created through the bounded draft path.
draft-write
packet is source-only: the installed immutable release remains the accepted
read-only/discovery bundle until a separate owner-gated release and disposable
workflow live acceptance with rollback. Official discovery accepts only EEC or Hetzner and
an empty operation input. It requests a separate official-MCP broker purpose,
selects a fixed per-server `fcp.mcp-bridge` inventory, and maps internally only
to `mcp.tools.list`. The host issues a one-call `mcp.tools.read` capability,
injects a request-scoped bearer token over the inherited credential channel,
and reuses owned connector teardown. There is no generic MCP method, remote
tool name, URL, header, or token field on the public surface.
The bridge scans every provider description in blocking mode, then the wrapper
discards all descriptions and raw schemas. The public result retains only
sorted tool names, SHA-256 input/output schema digests, and explicit
`unknown`/`unreviewed` markers until the owner approves a capability policy.

Implementation status snapshot (2026-08-19): the host-side local
`n8n-mcp` update executor and its security primitives are implemented behind
the connector boundary. The public CLI has one explicit root-gated
`update-review stage-local-mcp <exact-version>` path that obtains metadata and
the exact tarball through fixed npm plans, stages only under the fixed local-MCP
  root with scripts/audit/fund/bin-links disabled, emits a retained redacted
  receipt, and strictly verifies metadata/SRI/tarball/canonical registry-only
  lock closure/tree/entrypoint before success. npm and tar run in dedicated
  process groups, and timeout teardown terminates the complete group before
  output readers are joined. It
does not modify the global package, promote an FWC release, call a provider, or
register a capability; no retry occurs after an unknown result. Its separate
explicit `provision --mode apply` path is limited to fixed-root,
proof-carrying, owner-gated immutable release promotion; it is not a generic
live update command. The implementation status
and evidence are maintained in `connectors/n8n/README.md`; this document
continues to define the accepted public contract and owner gates.

The immutable bundle contract requires twelve exact artifacts, including
`fcp-mcp-bridge`, its manifest, and separate EEC/Hetzner official-MCP
inventories. A historical 2026-08-17 acceptance snapshot recorded the
distinct `n8n-eec-mcp` / `n8n-hetzner-mcp` owner entries and 34 discovered tools
per server; that snapshot is not the current release identity. Every discovered
capability remains `unknown`/`unreviewed` and `tools/call` remains unavailable
through the public surface. Bundle verification currently
trusts root ownership, restrictive filesystem modes, and serialized atomic
privileged updates locally. Its path-based checks do not defend against a
concurrent malicious root updater. The source packet verifies an owner-signed
`provision-receipt.json` when a release is evaluated. The installed release
above contains such a receipt with matching release metadata, but filesystem
presence does not by itself prove that signature verification was performed or
that the release was live accepted.
The source-only `fwc_n8n_provision` packet adds a typed fixed-root preflight
for owner-staged releases: it checks the existing twelve-artifact receipt,
the bounded `provision-receipt.json` covering that receipt/provenance and every
staged byte, explicit git-revision provenance, canonical non-symlink paths,
owner/mode and size bounds, strict allowlisted inventory/policy metadata with
secret-like key/value rejection, and exact per-server official-MCP schema
bindings before returning an atomic-promotion plan. `provision-receipt.json`
carries an owner Ed25519 signature over domain-separated release/git/receipt/
provision digests and the canonical complete EEC/Hetzner binding map; the
verifier accepts only explicit owner public-key/key-id configuration and never
reads private key material. `InstallPlan::revalidate` consumes the plan into
an opaque `RevalidatedInstallPlan`; the typed `OwnerAtomicInstaller::promote`
consumes that proof and exposes only fixed read-only stage/release/current/
rollback paths. The owner implementation must revalidate the proof once more
while its root-side concurrency guard is held immediately before promotion.
The Linux `FilesystemOwnerAtomicInstaller` consumes only that proof, derives
the fixed install root from proof paths, takes an exclusive root lock, repeats
proof validation under the lock, uses no-follow directory opens and
`renameat(..., NOREPLACE)` for stage-to-release promotion, fsyncs the affected
directories, and atomically replaces `current` through a temporary relative
symlink. Before reading any receipt or artifact, release-tree validation opens
only the fixed direct children `bin/`, `manifests/`, `inventory/`, and `policy/`
relative to the already validated release root with `NOFOLLOW`; each must keep
its exact relative name and parent, directory type and inode identity, expected
owner (UID 0 in production), non-writable metadata, and canonical no-symlink
traversal. These are constants, never caller-supplied subpaths. Because the
shared validation is
repeated by plan revalidation under the owner lock and after the stage rename,
it covers stage, current/rollback immutable releases, and the promoted target
before `current` changes. Its rollback seam uses the same lock and revalidation
and never deletes releases; a failed `current` promotion leaves the immutable release
and old pointer where possible. Non-Linux fails closed. The `fwc-n8n provision`
CLI provides the narrow owner wiring: it accepts only a bounded
`fwc.n8n.provision-request.v1` envelope with release metadata and the fixed
server binding map. The public trust roots come only from immutable
release-build configuration: stdin cannot select a key ID or public key,
missing or malformed production configuration fails closed, and no private key
is read or generated. During a bounded migration,
`FWC_N8N_OWNER_PUBLIC_KEY_HEX` is the active signing root and the optional
`FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX` preserves exactly one prior rollback
root. Verification selects only a configured root by the receipt key ID; the
signer accepts only the active root, and duplicate roots are rejected. Its
default mode is read-only preflight; `--mode apply` requires
effective UID 0, while the installer seam and both Linux mutation functions
enforce that requirement again independently of the CLI. Promotion accepts
only the exact direct child `/var/lib/fwc-n8n/staging/<release_id>` with a
matching basename; mismatches, nesting/traversal, and symlink aliases fail
before mutation. The existing proof-carrying installer otherwise uses only the
fixed staging/install roots.

The first promotion also has a narrow legacy-bootstrap compatibility path. A
fixed current release without `provision-receipt.json` is accepted only when
the current symlink, direct-child release layout, ownership, provenance, and
the complete old immutable-bundle verifier all pass. This fallback has no
caller-controlled path and is not used when a provision receipt exists but is
invalid. The staged candidate still requires a complete owner-signed provision
receipt.

Migration from an older signed release has a separate, narrower compatibility
mode. When fixed `current` has a structurally valid signed provision receipt
but both EEC and Hetzner lifecycle inventories use the old common
official-MCP schema bindings, validation first attempts the normal per-server
contract and may then revalidate that fixed predecessor in the legacy-schema
mode. The compatibility pass repeats the complete release-tree, provenance,
artifact, ownership, policy, network, archive/execute binding, and signature
checks, and requires both server bindings to match the known old common
lifecycle values. It never applies to a staged candidate. Missing or malformed
receipts, invalid signatures, digest mismatches, and other non-policy integrity
failures do not fall through to this mode. After promotion of the new
candidate, the current pointer must pass the per-server signed provision-
receipt contract, so later promotions cannot continue using the compatibility
mode.

Output is redacted and does not expose signatures, keys, or paths. No sudo,
shell, systemd, release deletion, or live n8n operation is performed; rollback
remains a separate owner-gated boundary. The proof cannot establish atomicity
against an unrelated writer that ignores the owner lock.
The rollback target is subjected to the same complete self-relative artifact,
provenance, provision-receipt, inventory, and policy validation; only its git
revision may differ from the candidate. The remaining trusted-concurrent-root
writer window is documented and requires immediate owner-side revalidation
before the atomic rename/symlink operation. Public-key provisioning, privileged
invocation, live `current` switching, systemd, and rollback acceptance remain
separate owner gates.
The source-only `fwc-n8n-owner-sign` binary is a separate feature-gated
operator boundary, not part of the runtime connector. It accepts only a safe
release identifier, a bounded non-secret `fwc.n8n.provision-request.v1` file,
and an exact Base64 seed on stdin; it derives the fixed
`/var/lib/fwc-n8n/staging/<release_id>` path internally and rejects caller
paths. Before producing a receipt it reuses the complete no-follow unsigned
release validator, including ownership/mode checks, provenance, twelve
artifact digests, inventory/policy semantics, and exact EEC/Hetzner binding
equality. The derived Ed25519 public key and key ID must match the immutable
build-time `FWC_N8N_OWNER_PUBLIC_KEY_HEX` active trust root. A migration
release may additionally embed `FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX` for
rollback verification only; seed bytes are held in zeroizing buffers and never
come from an argument, environment variable, or
the signer’s own KeePass access. The signer emits only the signed receipt and
does not call n8n, write the stage, install a release, switch `current`, or
modify workflows. Placing that receipt into a staged tree and running the
privileged preflight/apply path remain separate owner-controlled steps. This
packet has offline coverage only; it is not live or privileged acceptance.
`n8n.targets.resolve`, `n8n.runtime.status`,
`n8n.node_resources.explore`, and `n8n.evaluations.manage` are not all
representable by that enum yet. `n8n.mcp_access.reconcile` is now represented
as a typed REST intent and host operation for bounded dry-run and guarded apply
reconciliation. The apply path uses only the public workflow REST resource;
n8n requires `name`, `nodes`, `connections`, and `settings` in that transport
payload, while the logical mutation is allow-listed to
`settings.availableInMCP`. Lifecycle fields and graph semantics are excluded
from the mutation and verified by an independent detail readback. Host run-once
adds a server-wide transient lock, UUID idempotency binding, and redacted
intent/outcome receipts. The historical owner-gated bundle passed disposable
enable/disable/readback acceptance on EEC and Hetzner; the release ID and
evidence receipt are not recorded in this contract, so that record is not
current-release acceptance. The private web bulk
endpoint remains an unaccepted provider surface; future workflows require a
later bounded reconciliation run rather than a daemon or implicit policy.
The Phase-3 lifecycle packet represents `n8n.workflows.lifecycle` as typed
`publish`/`unpublish` input with exact workflow targeting, UUID idempotency,
full lifecycle/state-digest preconditions, and current-chat approval binding.
The host now builds only the exact official MCP `publish_workflow` or
`unpublish_workflow` call after fresh `tools/list` discovery and an owner-
reviewed policy entry containing both schema digests; each operation makes one
side-effecting provider attempt and then, whenever the attempt may have started
or an outer response was delivered, performs exactly one independent REST
`GET /workflows/{id}` readback. The provider response and envelope are bounded
advisory data only: opaque, version-specific, or provider-rejection shapes do
not declare success, override the readback, or block reconciliation. The
independent readback is the sole lifecycle state authority. An explicit publish
`versionId` must match it exactly; when that input is omitted, the readback may
select a version only when its active and published version IDs are
unambiguous. The connector's direct REST routes remain an explicit route only
where proven and fail closed otherwise.
Only bounded categories for failures proven before the provider side effect
(`official_mcp_policy_failed`, `official_mcp_capability_failed`, and related
preflight classes) may be exposed without reconciliation. Invocation, timeout,
teardown, malformed/ambiguous response, and all other uncertain cases that may
conceal a provider-side effect receive one reconciliation readback; an exact
readback may prove success, otherwise the result remains non-success and is
never retried automatically. A supervised child may also carry one fixed,
redaction-safe diagnostic label in the error envelope; that label is
classification only and never contains provider text, payload, headers,
credentials, or a retry instruction. Uncertain or mismatched readback is never
retried automatically.
The typed REST `n8n.workflows.unarchive` path is separate from
`restore_workflow_version`: it is the exact no-body
`POST /api/v1/workflows/{workflowId}/unarchive` followed by one independent
`GET /workflows/{id}`. The fwc-n8n envelope carries the host-approved
deadline into fcp-host, whose per-invocation launch snapshot derives and
injects the fixed `FCP_N8N_UNARCHIVE_REQUEST_TIMEOUT_MS` value into the actual
owned connector `ProcessSpec` (managed configuration and operation input
cannot set it), reserving a bounded reconciliation tail across the baseline
GET, one POST, and final GET.
Every POST outcome that could have started the write (including timeout,
disconnect, HTTP error, malformed/advisory response, provider identity or
normalization failure) therefore reaches exactly one GET; readback drift or
failure is terminal `unknown_outcome` with no retry.

The public `n8n.workflows.activate` operation is now source-implemented as a
typed REST contract for EEC and Hetzner only. `active=true` maps only to one
`POST /api/v1/workflows/{id}/publish` (with the optional exact `versionId` in
the input), while `active=false` maps only to one no-body
`POST /api/v1/workflows/{id}/unpublish`; each transition is exactly baseline
GET, one POST, and one independent GET, with no automatic retry. The host binds
the exact original input and approval, fixes credential purpose to REST API,
enforces the 1 MiB HTTPS response policy, and derives a trusted timeout that
reserves the readback tail. Publish succeeds only when readback proves
`active=true`, matching `activeVersionId`, matching `published.versionId` and
published graph digest, while preserving workflow identity, draft graph, and
archive state; unpublish proves `active=false`, `activeVersionId=null`,
`published=null`, and the same identity/draft/archive invariants. A newly
created credential-free Webhook draft is the only acceptance target; the
webhook is never invoked, uncertainty stops the run, and no automatic cleanup
is performed. Source and offline evidence are present, but live acceptance and
release promotion remain unclaimed.

`restore_workflow_version`, versions, execution, credential mutation, and permanent
deletion remain outside this packet; no legacy route is guessed. The bounded
`n8n.workflows.archive` operation separately maps only to the documented
official MCP `archive_workflow` tool, requires an inactive/unarchived baseline,
and verifies archived/inactive state plus unchanged draft/published summaries
through an independent REST GET. Its owner policy must carry both per-server
schema digests and the child tools/list response must match them exactly.
Local, typed REST, local MCP, and any official-MCP operation beyond capability
inspection must remain behind the host-owned boundary; this wrapper does not
accept model-supplied commands, paths, environments, URLs, or upstream tool
names.

## 1. Fixed owner decisions

- One compact `n8n.*` surface is presented to the model. Provider catalogs are
  not loaded wholesale into the chat.
- The connector may route internally to a typed n8n REST adapter, a supervised
  local `czlonkowski/n8n-mcp` process, or the official instance-level n8n MCP.
- EEC Contabo, Hetzner, and legacy LeviLaser are distinct targets. Workflow name
  alone never selects a target.
- Full discovered official MCP functionality is eligible for use only through
  a typed public operation and the policy in this document. There is no generic
  `tools/call` escape hatch.
- Existing opt-in Codex MCP profiles remain a fallback until a separate
  acceptance and retirement decision.
- Credential mutation and general/permanent workflow deletion are future-only.
  The bounded disposable cleanup operation is a separate v1 exception with its
  own host-issued creation receipt and 404 readback contract.
- The local provider target is zero processes and zero provider RSS/PSS/private
  memory while idle.

## 2. Trust and execution boundary

Workflow names, descriptions, graphs, Code node source, execution data,
external responses, templates, MCP instructions, tool descriptions, tool
annotations, release notes, and ClickUp text are untrusted data. They cannot:

- choose or change a server;
- grant a capability or approval;
- cause a shell command, arbitrary HTTP request, secret read, or external write;
- widen a resource URI, provider allowlist, or retry policy;
- authorize a repeated operation after an unknown result.

Only the owner's request, this local policy, an approved capability snapshot,
and mechanically verified metadata may authorize an operation.

The implementation must not expose:

- arbitrary HTTP method, URL, headers, or body;
- arbitrary executable, arguments, environment variables, or `system.exec`;
- arbitrary MCP server URL, tool name, or unvalidated tool arguments;
- raw credential values, OAuth tokens, API keys, or provider headers.

The local `n8n-mcp` adapter may execute only a pinned executable identity at the
configured path, with fixed startup arguments and a generated environment from
trusted configuration. The model cannot supply any of those fields.

## 3. Target identity and resource URIs

### 3.1 Server registry

| Server ID | Meaning | KeePass service | Selection rule |
|---|---|---|---|
| `eec` | EEC Contabo | `n8n-eec` | Explicit server or confirmed project/resource mapping |
| `hetzner` | Hetzner | `n8n-hetzner` | Explicit server or confirmed project/resource mapping |
| `legacy` | Legacy LeviLaser source | `n8n-levilaser-source` | Explicit opt-in only; never an automatic fallback |
| `local` | Local node/template knowledge | none | Only operations that do not contact an n8n instance |

Secrets are referenced by service name only. They are resolved by the host at
execution time and never serialized into a request, result, log, receipt, or
capability snapshot.

The table names the REST API credential. Official MCP uses a separate personal
access-token purpose and the fixed KeePass services `n8n-eec-mcp` and
`n8n-hetzner-mcp`. The broker protocol binds server and purpose; it must reject
REST/MCP substitution and never fall back from one credential class to the
other. The service names alone are not provisioning evidence; the 2026-08-17
broker-backed live discovery readback was historical evidence, without
exposing either value, and is not evidence for the current release.

### 3.2 Canonical URI shapes

Every server resource URI includes the server ID. IDs are UTF-8 percent-encoded
path segments; names are never identity fields.

| Resource | URI shape |
|---|---|
| Instance | `fwc-n8n://{server}` |
| Project | `fwc-n8n://{server}/projects/{projectId}` |
| Folder | `fwc-n8n://{server}/folders/{folderId}` |
| Workflow | `fwc-n8n://{server}/workflows/{workflowId}` |
| Workflow version | `fwc-n8n://{server}/workflows/{workflowId}/versions/{versionId}` |
| Execution | `fwc-n8n://{server}/workflows/{workflowId}/executions/{executionId}` |
| Credential metadata | `fwc-n8n://{server}/credentials/{credentialId}` |
| Data table | `fwc-n8n://{server}/data-tables/{tableId}` |
| Evaluation | `fwc-n8n://{server}/workflows/{workflowId}/evaluations/{evaluationId}` |
| Local node type | `fwc-n8n://local/nodes/{nodeType}` |
| Local template | `fwc-n8n://local/templates/{templateId}` |

### 3.3 Resolver proof order

The resolver accepts a target only when one of these proofs succeeds:

1. the owner explicitly names `eec`, `hetzner`, or `legacy`;
2. a project ID has an existing confirmed server mapping;
3. a full canonical resource URI is supplied;
4. a workflow/execution ID has stored provenance from a prior confirmed read;
5. a bounded read-only search runs on explicitly enumerated servers and the
   owner selects one result.

A bare workflow name, a fuzzy match, a workflow ID that exists on more than one
server, or content inside a workflow is insufficient. Writes require a full
canonical URI even if an earlier read used a looser target reference.

## 4. Common schemas

Schemas use JSON Schema 2020-12 semantics. Unknown fields are rejected unless a
schema explicitly says otherwise.

### 4.1 `TargetRef`

```json
{
  "server": "eec | hetzner | legacy",
  "projectId": "string?",
  "folderId": "string?",
  "workflowId": "string?",
  "executionId": "string?",
  "resourceUri": "string?"
}
```

Constraints:

- `server` is required unless `resourceUri` supplies the server.
- IDs must agree with `resourceUri` when both are present.
- `legacy` requires `legacyOptIn: true` on the operation input.
- workflow writes require `resourceUri` or `server + workflowId`.
- execution reads require both workflow and execution identity; the resolver may
  obtain the workflow ID through a bounded metadata lookup before continuing.

### 4.2 `PageRequest` and detail

```json
{
  "limit": 50,
  "cursor": "opaque-string?"
}
```

- Default `limit` is 50; minimum is 1; public maximum is 200.
- Cursors are opaque, provider-bound, server-bound, and expire with the
  capability snapshot that created them.
- The connector never follows every page automatically unless the owner asks
  for a complete inventory and the operation-specific hard limit permits it.

`detail` is one of `summary`, `standard`, or `full`. Default is `summary`.
`full` is not permission to return secrets, Code source, or unrestricted
execution payloads.

### 4.3 `MutationGuard`

```json
{
  "approvalRef": "string",
  "idempotencyKey": "uuid",
  "precondition": {
    "versionId": "string?",
    "activeVersionId": "string|null?",
    "active": "boolean?",
    "isArchived": "boolean?",
    "stateDigest": "blake3-256:...?"
  }
}
```

All v1 writes require `approvalRef`, `idempotencyKey`, and the read fields that
are meaningful for that action. An approval is one-use, short-lived, and bound
to operation ID, canonical URI, provider route, precondition, proposed change
digest, and expected side-effect class.

For host run-once writes, `approvalRef` is only a reference to the owner/chat-
issued token: it never mints trust. The typed, redaction-safe run-once envelope
must carry an externally signed `approval_token`, verified with
`FCP_HOST_APPROVAL_PUBLIC_KEY` or `_FILE`. Verification requires
`token_id == approvalRef`, the typed `fcp.mcp-bridge` wrapper operation
`n8n.mcp.call`, `z:work`, the canonical official-MCP payload digest, expiry, and
the exact request constraints. The constraints also carry the typed plan digest,
which binds EEC/Hetzner, the canonical workflow resource URI and workflow ID,
the official tool name/payload, lifecycle precondition, UUID idempotency key,
and expiry as one exact owner-confirmation plan. Before credential/provider access,
the host persists a private `token_id` replay marker (after signature and
binding validation) and then the request claim; a second use of that token
fails closed even if its idempotency key differs. Missing, invalid, mismatched,
or already-consumed tokens never reach provider I/O. Official-MCP lifecycle
calls bind the child `fcp.mcp-bridge` payload digest and policy constraints in
the same way. The provider-start marker is fsynced immediately before the single
`invoke_handler_inner` boundary; a restart with a pending claim, provider-start
marker, or missing terminal receipt is `unknown` and never auto-retried. Receipt
and marker fields are digests only and are checked against the reconstructed
typed plan before replay is refused.

The bounded owner-confirmation seam is typed to publish, unpublish, archive,
unarchive, `n8n.workflows.create_draft`, and `n8n.workflows.delete_disposable`. It computes
a redaction-safe plan digest over the exact EEC/Hetzner target, operation,
canonical input and precondition digests, provider binding, UUID idempotency
key, and expiry; confirmation must echo that digest. Lifecycle/archive/unarchive retain
their exact official-MCP tool and payload binding. Draft creation and
disposable deletion use the direct REST `fcp.n8n` token shape with the exact
canonical server/resource/input hash; disposable deletion also requires the
host-issued creation receipt and inactive/unarchived precondition.
`fcp-host` reuses the
existing `ApprovalToken` canonicalization contract through a fail-closed issuer
seam and does not load or accept private key material. This module is not a
second ledger and is not wired as an independent provider gate: the existing
host run-once path remains authoritative for cryptographic verification, full
resource/workflow/input/precondition/idempotency binding, one-use claim,
provider-attempt receipts, `unknown` recovery, and no-retry behavior. Credential
transport does not weaken or replace any of those gates.

#### 4.3.1 Unattended age/KeePass credential broker

The repository-side mandatory path uses the standalone n8n secret broker.
`fwc-n8n` selects exactly one of four closed server-and-purpose mappings:

| Server | Purpose | KeePass service | Field |
|---|---|---|---|
| EEC | REST API | `n8n-eec` | `api_key` |
| Hetzner | REST API | `n8n-hetzner` | `api_key` |
| EEC | official MCP | `n8n-eec-mcp` | `access_token` |
| Hetzner | official MCP | `n8n-hetzner-mcp` | `access_token` |

The client connects only to the fixed root-owned
`/run/fwc/fwc-n8n-secret-broker.sock` socket. Socket path, parent-directory
ownership and modes, socket ownership and mode, and root peer UID are checked
before a request. The root one-shot systemd service receives only the bounded
closed request frame; it reads the root-owned age identity and encrypted master,
decrypts the KeePass database in memory, and returns the selected protected
entry. The operator's KeePass password is not requested during an ordinary FWC
call, and no plaintext master password or API key is placed in an environment
variable, argument, file, diagnostic, or log.

The broker returns the credential through a zeroizing buffer; the wrapper then
uses the existing FCPK inherited-FD frame to the verified `fcp-host
n8n-run-once` bridge. There is one lookup, one provider attempt, no fallback,
and no retry. Approval signature, exact target, full precondition, one-use claim,
provider-start receipt, and independent readback remain authoritative and
unchanged.

The supervised connector child's fixed Linux seccomp filter returns `EPERM`
for `keyctl`, `add_key`, and `request_key`, in addition to its network syscall
denials. Thus the child that handles untrusted provider-facing work cannot
reach the kernel keyring; credential lookup happens only through the fixed
root-owned broker boundary before the bridge launch.

The age identity is a machine-local decryption key for the already encrypted
KeePass master, not a second operator password and not a per-request approval.
It is what makes this host-managed path unattended without duplicating the
provider credentials in plaintext. Existing opt-in MCP profiles are outside the
mandatory path.

### 4.4 Response envelope

```json
{
  "schemaVersion": "1.0",
  "operationId": "n8n.workflows.get",
  "correlationId": "uuid",
  "status": "ok | partial | pending | denied | unknown | error",
  "resourceUri": "fwc-n8n://...? | null",
  "provider": "host | rest | local_mcp | official_mcp",
  "providerFallback": false,
  "data": {},
  "page": { "nextCursor": "string|null", "count": 0, "estimated": false },
  "readback": {},
  "warnings": [],
  "truncated": false,
  "resultBytes": 0
}
```

`data`, `page`, and `readback` appear only when applicable. Provider fallback is
never silent: `providerFallback=true` requires a warning naming the failed
preferred route and the selected route, without provider response content.

### 4.5 Normalized workflow state

```json
{
  "id": "string",
  "name": "string|null",
  "projectId": "string|null",
  "folderId": "string|null",
  "versionId": "string",
  "active": false,
  "activeVersionId": "string|null",
  "isArchived": false,
  "draft": { "versionId": "string", "graphDigest": "blake3-256:..." },
  "published": null,
  "stateDigest": "blake3-256:...",
  "updatedAt": "RFC3339|null"
}
```

`draft` is the currently saved editable graph. `published`, when present, is a
separate graph summary whose version ID equals `activeVersionId`. `active` is a
provider state flag and must be read back; it is not inferred solely from a
name, trigger, or UI label. `isArchived` is independent from both draft and
published state.

Digest contract v1:

- `graphDigest` is a provider-neutral semantic comparison digest. Its preimage
  is deterministic JSON containing exactly `nodes` and `connections`; object
  keys are recursively sorted and array order is preserved. Only the top-level
  `credentials` field on each node is removed. Code source and all other graph
  semantics remain in the preimage. The domain is
  `fwc-n8n.graph-digest.v1`, followed by a zero byte, followed by the canonical
  JSON bytes, hashed with BLAKE3-256.
- `stateDigest` is a separate write-precondition digest. Its preimage includes
  workflow identity and metadata, version/lifecycle/archive fields, timestamps
  and tags, plus complete draft and published graphs including credential
  bindings. Its domain is `fwc-n8n.state-digest.v1` with the same zero-byte
  separation and canonical JSON rules.
- Raw graph values, Code source, credential bindings, pinned data, and digest
  preimages are never returned or logged. An official MCP response that hides
  credential bindings may support semantic comparison through `graphDigest`,
  but cannot be the sole authority for a write guarded by `stateDigest`; typed
  REST readback is required.

## 5. Public operation inventory

`None`, `BestEffort`, and `Strict` below are FCP idempotency classes. A write
with `BestEffort` is never automatically retried: the class describes replay
guarantees, not permission to replay.

| Operation | Capability | Safety / risk | Approval | Idempotency | Primary provider | URI / readback | Model result cap |
|---|---|---|---|---|---|---|---|
| `n8n.targets.resolve` | `n8n.targets.read` | Safe / Low | None | None | REST | instance/project/workflow URI | 32 KiB |
| `n8n.capabilities.inspect` | `n8n.capabilities.read` | Safe / Low | None | None | official MCP | fixed EEC/Hetzner server; compact capability catalog | 64 KiB |
| `n8n.runtime.status` | `n8n.runtime.read` | Safe / Low | None | None | host | local/provider status only | 32 KiB |
| `n8n.knowledge.query` | `n8n.knowledge.read` | Safe / Low | None | None | local MCP | local node/template URI | 256 KiB |
| `n8n.node_resources.explore` | `n8n.credentials.use_read` | Risky / Medium | Interactive | None | official MCP | node/credential metadata; no secret | 256 KiB |
| `n8n.validation.run` | `n8n.validation.read` | Safe / Low | None | None | local MCP | validation subject URI/digest | 256 KiB |
| `n8n.structure.search` | `n8n.structure.read` | Safe / Low | None | None | official MCP | project/folder/tag URIs | 128 KiB |
| `n8n.workflows.search` | `n8n.workflows.read` | Safe / Low | None | None | REST | workflow preview URIs | 128 KiB |
| `n8n.workflows.get` | `n8n.workflows.read` | Safe / Medium | None | None | REST | normalized state fields | 2 MiB full |
| `n8n.workflows.compare` | `n8n.workflows.read` | Safe / Medium | None | None | official MCP | both version URIs/digests | 512 KiB |
| `n8n.workflows.create_draft` | `n8n.workflows.write` | Risky / Medium | Interactive | BestEffort | typed REST | new URI; draft/readback state | 512 KiB |
| `n8n.workflows.update_draft` | `n8n.workflows.write` | Risky / High | Interactive | BestEffort | typed REST | draft version/digest; published unchanged | 512 KiB |
| `n8n.workflows.activate` | `n8n.workflows.write` | Risky / High | Interactive | BestEffort | typed REST publish/unpublish on EEC/Hetzner with independent REST GET readback | active transition with matching published version/graph, or inactive/null active version/null published; draft graph/archive preserved | 1 MiB |
| `n8n.workflows.lifecycle` | `n8n.workflows.lifecycle` | Risky / High | Interactive | BestEffort | official MCP publish/unpublish with independent REST GET readback | all normalized state fields | 256 KiB |
| `n8n.workflows.archive` | `n8n.workflows.lifecycle` | Risky / High | Interactive | BestEffort | official MCP `archive_workflow` with independent REST GET readback | archived/inactive state; draft/published unchanged | 256 KiB |
| `n8n.workflows.unarchive` | `n8n.workflows.lifecycle` | Risky / High | Interactive | BestEffort | typed REST `POST /api/v1/workflows/{workflowId}/unarchive` with independent REST GET readback | unarchived state; draft graph/published/lifecycle state unchanged; draft version rotation allowed | 256 KiB |
| `n8n.workflows.delete_disposable` | `n8n.workflows.write` | Risky / High | Interactive | BestEffort | typed REST `DELETE /workflows/{id}` with independent REST GET requiring 404 | exact host-issued creation receipt; inactive/unarchived precondition | 256 KiB |
| `n8n.workflows.versions` | `n8n.workflows.versions` | action-dependent | action-dependent | action-dependent | local MCP/API | version URI/state readback | 256 KiB |
| `n8n.workflows.execute` | `n8n.executions.start` | Risky / High | Interactive | BestEffort | owner-gated official MCP `execute_workflow` with exact immutable EEC/Hetzner input/output schema bindings | bounded workflow/execution IDs and initial status plus independent typed execution GET readback; post-provider readback failures are terminal unknown/no-retry; live acceptance deferred | 256 KiB |
| `n8n.executions.search` | `n8n.executions.read` | Safe / Medium | None | None | REST | execution preview URIs | 128 KiB |
| `n8n.executions.get` | `n8n.executions.read` | Safe / High | None | None | REST | metadata-only execution status; no query | 1 MiB metadata envelope |
| `n8n.executions.diagnostics` | `n8n.executions.read` | Safe / Low | None | Strict | REST | bounded node error diagnostics via `includeData=true`; no raw data | 256 KiB |
| `n8n.credentials.list` | `n8n.credentials.metadata.read` | Safe / Medium | None | None | official MCP | credential metadata URI | 128 KiB |
| `n8n.data_tables.search` | `n8n.data_tables.read` | Safe / Medium | None | None | official MCP | data-table URI/schema only | 256 KiB |
| `n8n.data_tables.mutate` | `n8n.data_tables.write` | action-dependent | Interactive | BestEffort | official MCP | table/schema/row-count readback | 256 KiB |
| `n8n.evaluations.manage` | `n8n.evaluations.manage` | action-dependent | action-dependent | action-dependent | local MCP | evaluation URI/status | 256 KiB |
| `n8n.audit.inspect` | `n8n.audit.read` | Safe / High | None | None | REST/local MCP | instance URI; redacted findings | 512 KiB |
| `n8n.mcp_access.reconcile` | `n8n.mcp_access.write` | Risky / High | Interactive | BestEffort | typed REST settings adapter | exact server; availability and lifecycle/graph readback | 512 KiB operation-scoped; 60 s all-current budget |

The inventory above is contract-level. The executable surfaces are deliberately
separate:

- **Manifest operations:** the current `fcp.n8n` manifest declares
  `workflows.list`, `workflows.get`, `workflows.activate`, `executions.list`,
  `executions.get`, `executions.diagnostics`, `projects.list`, `credentials.list`, `tags.list`,
  `folders.list`, `folders.get`, `workflows.create_draft`,
  `workflows.update_draft`, `workflows.lifecycle`, `workflows.archive`,
  `workflows.delete_disposable`, `workflows.execute`, and
  `mcp_access.reconcile`. A manifest declaration does
  not override an operation's fail-closed provider gate; the typed REST
  selected-version activation was accepted by `.24` on RC33; later releases
  still need applicable `.15` regression evidence.
- **Wrapper/host-only operations:** `n8n.capabilities.inspect` is absent from
  the connector manifest. The wrapper/host path accepts an empty operation
  input, derives a fixed EEC/Hetzner server from its bounded envelope, and
  maps only to `mcp.tools.list`.
- **Router intents:** the typed router recognizes selection intents such as
  `n8n.knowledge.query`, `n8n.validation.run`, `n8n.workflows.search`,
  `n8n.executions.search`, `n8n.structure.search`, `n8n.workflows.compare`,
  `n8n.data_tables.search`, `n8n.data_tables.mutate`, `n8n.audit.inspect`,
  and `n8n.workflows.versions`. A routing decision is not a provider
  execution path and does not imply that the selected operation is available.
- **Unimplemented v1 execution paths:** `n8n.runtime.status`,
  `n8n.node_resources.explore`, `n8n.evaluations.manage`, and any router intent
  without a corresponding host/connector dispatch remain unimplemented under
  `.35`–`.42`. Version restoration is distinct from unarchive, remains
  fail-closed pending `.36`, and is accepted v1 scope. Credential mutation and
  permanent/general deletion remain future-only. Catalog entries grant no authority.

Historical live acceptance boundary (2026-08-21; release ID and evidence receipt
not recorded here): the then-installed owner-gated bundle
passed read-only and MCP-availability reconciliation checks on EEC and
Hetzner, with disposable workflows removed after exact DELETE/404 readback.
The typed official-MCP lifecycle path is not yet live-accepted: one exact EEC
webhook publish attempt returned `unknown_outcome`, the independent REST
readback remained inactive, and the contract correctly performed no retry.
This does not authorize REST lifecycle/archive fallback, restore_workflow_version, or
activation/execution operations. Archive remains policy- and tools/list-gated;
no live archive acceptance is claimed here.

Current acceptance checkpoint (2026-09-10; main commit
`d86b439528abe047b44839d3d7203f64e66f3246`): the wrapper now emits only fixed,
redaction-safe lifecycle diagnostic categories for provider rejection, response
shape, provider field mismatch, and readback precondition mismatch. The wire
result remains fail-closed (`unknown_outcome` where outcome is not proven); no
provider response body, token, or workflow payload is logged. Focused lifecycle
tests passed 13/13, the workspace compiler check passed, and formatting passed.
Workspace Clippy still stops on the pre-existing 11 findings in
`crates/fcp-sandbox/src/process.rs`; the n8n package retains five pre-existing
Clippy findings outside the wrapper binary.

The URI-corrected RC3 live attempt used the exact EEC baseline and a valid
13-digit millisecond approval request with 32 decoded seed bytes. One publish
attempt still returned `unknown_outcome`; one immediate independent REST
reconciliation proved the EEC workflow unchanged and inactive, so no publish
side effect was claimed. The host receipt's safe result class indicates only
that the child invocation completed; it is not lifecycle-result acceptance.
Hetzner was not started. Evidence remains redacted under
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc3-20260910-uri-fixed/`; the bead
remains `in_progress`/NO-GO until a fresh candidate release proves the complete
EEC then Hetzner publish/readback/unpublish/final-readback sequence.

The fresh RC4 acceptance dispatch `ctx_beda0eb83745` (Orca task
`task_e5e41bebe876`, 10:45--10:58 UTC) verified the exact EEC inactive baseline,
then stopped before creating the publish approval request because local
`expires_at_ms` preparation failed the required 13-digit millisecond-width
check. The canonical parent-binding helper had returned successfully, but no
request file, approval token, lifecycle wrapper call, or provider lifecycle
write was made; the one required EEC reconciliation GET remained unchanged and
exact. Hetzner was not started. The redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc4-20260910/report.json`
(SHA-256
`6550ecc7b13b53f9f65263c6317add6a8d314b149afb1f20b59359a0da47c55e`). Its
redaction scan is clean, the RC4 pointer is unchanged, and no matching
processes remain. Live acceptance remains **NO-GO**; this bounded stop is not to
be replayed, and any future attempt requires correcting the local expiry
preparation before a new explicitly bounded EEC-first run.

The subsequent fixed-expiry RC4 acceptance dispatch `ctx_6f07730de760` (Orca
task `task_3439a6782bbe`, 11:13--11:22 UTC) passed the exact EEC baseline and
completed approval preparation with the encoded official-MCP URI, a 13-digit
millisecond expiry, the parent-binding helper, and the isolated issuer. Its
single EEC publish wrapper call returned `unknown_outcome` with correlation
`2418798a-5c32-471f-9de2-d042b3129d00`; the fail-closed boundary therefore
performed no retry, no unpublish, and no Hetzner call. One reconciliation GET
confirmed the original inactive/unarchived/unpublished EEC state and exact
draft/state digests, with one provider lifecycle write attempted and zero
verified. The redacted report/evidence/manifest are retained under
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc4-fixed-20260910/`; report
SHA-256 is
`5ca276f6d280154bd526de0426160ac9b3ce709883ff2183f8540ac348286558`.
Redaction is clean, the RC4 pointer is unchanged, and no matching processes
remain. Live acceptance remains **NO-GO**; the unknown result is not proof of a
provider side effect and must not be replayed.

The diagnostic-retention fix was integrated at main commit
`427092727a90b4a9b7bd61c8d63e449f6261f27a` and installed as
`release-20260910-42709272-rc1`. The signed provision receipt is
`fwc.n8n.provision.v1` with 14 artifact hashes, two EEC/Hetzner bindings, and
an Ed25519 signature; `bundleAvailable=true`, the RC4 predecessor remains
retained, and the installed external approval issuer SHA-256 is
`b556d3311b812aa554c25db2dae4386ed2a7b7a2f192031b356cc0cf5c86d5ca`.
The release report and independent checks found no matching runtime processes;
the staging path was absent after promotion.

The fresh RC5 live acceptance dispatch `ctx_28e29a0a5126` (Orca task
`task_adeeb86cc583`, 13:09--13:15 UTC) passed the exact EEC baseline and issued
one fresh owner approval with a 13-digit millisecond expiry. Its single EEC
publish invocation returned `unknown_outcome` with the retained safe diagnostic
`lifecycle_provider_rejected` (wrapper correlation
`50881b07-025c-4f84-813f-cbe5e0a835e1`; inner lifecycle correlation
`7b5497e8-df05-4934-9a36-e07240ed1009`). The response body was not retained;
the diagnostic means the decoded official-MCP result indicated a provider
rejection, but does not establish whether n8n rejected the request or which
provider-side condition caused it. One required reconciliation GET matched
the exact inactive, null-active-version, unpublished, unarchived EEC draft and
state digests; provider writes verified were `0`. Under the fail-closed rule no
unpublish and no Hetzner call were attempted. The redacted report
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc5-20260910/live-acceptance-report.json`
has SHA-256
`b666e85015302b1137e32c6f608146f2ba4c2cc3d63b88a1797b93cd102ed0e0`, and its
manifest has SHA-256
`bb2e68dc19200829d97b57758b60f64b9e65011ad19951b3a5de09543d2b7d6d`.
The report is redaction-clean and no matching processes remain. The provider
rejection cause is not proven, so acceptance remains **NO-GO** and this result
must not be replayed; a future attempt requires a separately justified,
redaction-safe provider/host diagnosis and a fresh bounded EEC-first run.

The provider response is bounded advisory data and is not required to contain
typed `active`, `isArchived`, `activeVersionId`, draft/published graph summary,
or `stateDigest` fields. Publish must instead be proven by the independent REST
readback: active publication, `isArchived=false`, preserved draft, published
graph consistency, and either the explicit requested version or an unambiguous
readback-selected version when the input omitted `versionId`. Unpublish must be
proven by inactive/null active version, a null published graph, and preserved
draft/archive state in that same readback. Provider fields, including rejection
markers or contradictory versions, never override the readback. Every possible
provider attempt, including an ambiguous or `unknown_outcome` attempt, gets
exactly one reconciliation readback; known pre-provider failures remain
deterministic, while readback uncertainty or mismatch remains non-success and
is never retried.

Current RC12 live-acceptance checkpoint (2026-09-11; installed release
`release-20260911-fb407a9af-rc12`): the fresh EEC-first run stopped bounded
NO-GO immediately after its baseline GET because the local evidence wrapper
hit the zsh error `read-only variable: status`. Exactly one permitted EEC
reconciliation GET then proved the known target unchanged: inactive,
unarchived, unpublished (`active=false`, `activeVersionId=null`,
`published=null`), with the supplied draft/version and graph/state digest
categories intact. The run made no approval-issuer, lifecycle-wrapper, or
provider write attempt; Hetzner was not selected under the EEC-first rule.
EEC GETs were `2` (initial baseline plus reconciliation), Hetzner GETs were
`0`, and no matching runtime processes remained. The redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc12-20260911/report.md` (SHA-256
`e76e6b6829bd8f36aa9eee9514e513b5ccdfdccac365e702eee80d5a07c9a3f7`). This
local harness failure is not provider lifecycle acceptance; the required
two-server sequence remains `in_progress`/NO-GO and this bounded run is not
replayed.

Current RC13 live-acceptance checkpoint (2026-09-12; installed release
`release-20260911-fb407a9af-rc12`): the fresh EEC-first run passed the exact
inactive, unarchived, unpublished baseline for workflow
`oD8zytCtv5PiSYzc` and version `85f41fbd-96e2-42d0-9022-98592eb35011`.
Two local timestamp/length assertions failed before provider I/O and were
corrected in-memory; no provider action occurred during those diagnostics.
The single authorized EEC publish attempt then issued one owner approval and
returned an advisory error. Its one independent REST readback/reconciliation
GET did not prove exact active publication, so unpublish was not attempted and
Hetzner was not selected under the EEC-first gate. The current RC12 pointer and
bundle status remained unchanged, the final matching-process count was zero,
and the redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc13-20260912/report.md` (SHA-256
`930bd94ce464f1e7f56a347cf73587ba278b4309ac73ef8ce605ccdb3646a078`).
The report is redaction-clean; the required two-server lifecycle remains
`in_progress`/NO-GO, and this bounded run is not replayed.

Current RC14 diagnosis checkpoint (2026-09-12; installed release remains
`release-20260911-fb407a9af-rc12`): a read-only review of the RC13 evidence and
the host/bridge/connector lifecycle path narrowed the proven boundary to one
EEC publish-wrapper attempt that exited with a redacted advisory error and one
independent REST readback that failed exact active-publication verification.
The retained evidence does not identify a provider rejection, host/bridge/
transport failure, or the specific readback field mismatch, and it does not
prove either a provider write or its absence. No provider, approval, issuer,
workflow, release, or repository action was performed during diagnosis; no
unpublish or Hetzner phase is authorized by this result. The redacted diagnosis
report is
`/srv/dev-ssd/fcp/nqm81.30/diagnose-rc13-publish-error-20260912/report.md`
(SHA-256 `3a7e2e6ca96e4c78614e2599cd7b38afd098d56cb1be3a5ff74ee26011437faf`)
with a verified sidecar. The required two-server lifecycle remains
`in_progress`/NO-GO; RC13 is not replayed.

Current RC17 live-acceptance checkpoint (2026-09-12; installed release
`release-20260912-cddd9f168-rc14`): the fresh EEC-first run corrected its local
InvokeResponse parser to accept the optional success `error` field being
omitted and the direct top-level `result` object. The exact EEC baseline and
one reconciliation GET matched the inactive, unarchived, unpublished target
for workflow `oD8zytCtv5PiSYzc`, including the supplied version and complete
graph/state digests. One MCP-access dry-run planned exactly that workflow. The
single fresh approval request and issuer attempt then failed closed with
`issuer_invalid_request` because the locally supplied expiry had 19 digits
instead of the required 13-digit Unix-millisecond value. No token was issued;
MCP-access apply writes, lifecycle writes, and provider writes were all `0`,
and Hetzner was not started under the EEC-first gate. The current RC14 pointer
and `bundleAvailable=true` status remained unchanged, the final matching
process count was zero, and the redacted report is
`/srv/dev-ssd/fcp/nqm81.30/rc17-20260912-CoralMountain/report.json` (SHA-256
`c800dbf25791fef3d4c4b408187f05f652cbca8945e5b4a28032b0b97c1901fc`); its
`SHA256SUMS` verification, redaction scan, and mode-600 evidence checks
passed. The required two-server lifecycle remains `in_progress`/NO-GO; do not
replay this bounded stop. A future attempt requires correcting the local
expiry representation and a fresh explicitly bounded EEC-first run.

Current RC18 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh supervised worker created a
redaction-safe report, but its EEC baseline and reconciliation commands used
the unsupported `fwc-n8n route` entry point instead of the required
`fwc-n8n run-once` host boundary. Both returned a wrapper-level `status=error`
with no retained operation result. No MCP-access approval/apply, lifecycle
write, provider write, or Hetzner phase was attempted. The report directory is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc18-20260912-CoralCove/`; its
checksum manifest, mode-600 files, redaction scan, and no-process check passed.
This is a local harness non-acceptance and provides no provider diagnosis; the
required two-server lifecycle remains `in_progress`/NO-GO. Do not replay RC18;
the next fresh attempt must use only the exact `run-once` envelopes and stop
before provider access if the formal boundary cannot be reached.

Current RC19 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh supervised worker VioletBear used
the required `fwc-n8n run-once` launcher for the first formal EEC baseline. The
redaction-safe typed-state check classified that baseline as
`typed_state_shape_error`; one permitted EEC reconciliation through the same
launcher classified as `reconciliation_unknown` and retained no safe state.
The bounded run therefore stopped before approval issuance, MCP-access apply,
or lifecycle/provider writes: EEC GETs were `1` baseline plus `1`
reconciliation, all EEC write/issuer counts were `0`, Hetzner was not started,
and the provider sequence was not attempted. The report is
`/srv/dev-ssd/fcp/nqm81.30/rc19-20260912-CoralCove2/report.json` (SHA-256
`4856aa1369d45d3e173fd20cc457629f9bd5f35f5543b3e9344a95f9130c8f77`); its
`SHA256SUMS` verification, redaction scan, mode-600 files, mode-700
directories, and no-process check passed. This is a local typed-state
non-acceptance and provides no provider diagnosis; the required two-server
lifecycle remains `in_progress`/NO-GO. Do not replay RC19. A future attempt
requires resolving the actual typed `run-once` state/result contract and a new
explicitly bounded EEC-first run.

Current RC20 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh EEC-first worker used the required
`/usr/local/bin/fwc-n8n run-once` boundary and completed one formal EEC baseline
GET, but the local response collector lost its parent-side PID state before it
could retain the safe projection. Exactly one independent EEC reconciliation GET
through the same launcher parsed as the expected inactive, unarchived,
unpublished typed state. No approval, issuer, MCP-access apply, lifecycle write,
or provider write was attempted; Hetzner was not started. The redacted report
is `/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc20-20260912/report.json`
(SHA-256 `63c867c4fe3e617ebfe7441a618ac6d83a8da675371b5c596ac4c42d82c6a828`);
its checksum, redaction, restrictive-mode, and no-process checks passed. The
independent harness diagnosis is
`/srv/dev-ssd/fcp/reports/nqm81.10-rc20-local-acceptance-harness-diagnosis-20260912.md`
(SHA-256 `03678a550af90bffac8bc21c5fe6e95930c4a60411b1fc5ebcf6358ac92ae1f2`).
RC20 is a valid local bounded NO-GO, not provider lifecycle acceptance, and is
not replayed; the next gate must use ordinary parent-shell PID capture with
fixed redirects/FIFO and an offline fixture regression.

Current RC21 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh worker ran the required offline
collector fixture before any provider, API, credential, or issuer access. The
collector itself passed `bash -n`, ordinary `$!`/parent `wait`, direct-result
projection, and rejection checks, but the hand-written direct-success fixture
was malformed (one closing brace was missing). Both sequential absent-`error`
runs therefore returned parser exit 5 instead of `accepted`; the `error:null`
fixture was accepted and top-level-error, nested-result, and concatenated-JSON
fixtures were rejected. The worker stopped fail-closed before the provider
boundary: EEC and Hetzner GETs, MCP-access, approvals, issuer attempts,
lifecycle calls, and provider writes were all `0`. The redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc21-20260912/report.json`
(SHA-256 `547a6a73901b36b3ee7bcbbc8130f0c012aac050daa96baea18095f1e6061940`);
the 36-entry checksum manifest, redaction scan, restrictive modes, and
matching-process check passed. RC21 is a local fixture-gate NO-GO, not provider
diagnosis, and is not replayed. A subsequent fresh gate must generate fixtures
with a structured JSON encoder such as `jq -cn`, validate each fixture before
the collector, then preserve the same no-retry/EEC-first/one-reconciliation
policy.

Current RC22 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh worker first passed the offline
collector gate. The gate used ordinary Bash parent-shell PID capture and
`wait`, accepted two direct-success fixtures (including an omitted optional
`error` and an explicit `error:null`), and rejected top-level error, nested
`response.result`, and concatenated-JSON fixtures. No provider/API,
credential, or issuer access occurred before that gate. The formal EEC
baseline through `/usr/local/bin/fwc-n8n run-once n8n.workflows.get` proved the
expected inactive, unarchived, unpublished workflow and the MCP-access
dry-run proved one planned enablement with no durable change. The single EEC
MCP-access apply attempt then stopped at the issuer/response boundary
(`issuer_exit=1`, wrapper `response_exit=1`, parser exit `5`; decoded seed
length `32`); no completed MCP-access or provider write is claimed. One
same-server reconciliation GET through the same launcher proved that the
exact EEC baseline remained unchanged. EEC therefore had one baseline GET,
one dry-run, one apply attempt, and one reconciliation GET; lifecycle writes
and Hetzner were not started. No retry was performed.

The redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc22-20260912-c/report.json`
(independently observed SHA-256
`4c18fa04e9e8d4c7457a838cc3dd0c9ad5871463a55522f0e039f01235df1460`); its
checksum manifest, mode-600 files, mode-700 directories, redaction scan, and
no-process check passed. The retained approval request had a 13-digit expiry
that was already past at a later inspection; the evidence does not establish
the exact issuer-call timestamp, so this checkpoint makes no stronger cause
claim. The current release and installed issuer were unchanged, and no raw
provider body, request, seed, or token was retained. RC22 is a local bounded
NO-GO, not provider lifecycle acceptance, and is not replayed. A future fresh
gate must create the approval request and its bounded millisecond expiry
immediately before the single issuer invocation, use integer millisecond time
calculation, and retain the same fail-closed reconciliation/no-retry policy.

Current RC23 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh worker first passed the offline
collector/direct-result fixture gate, then made one formal EEC baseline request
through `/usr/local/bin/fwc-n8n run-once n8n.workflows.get`. A local
classification-path typo caused the typed projection to exit `5` with no safe
state; the worker performed exactly one same-server reconciliation request
through the same launcher, which also exited `5` and retained no safe state.
The bounded run stopped before approval issuance, issuer access, MCP-access
apply, lifecycle/provider writes, and the Hetzner phase. The report records
EEC baseline GET `1`, reconciliation GET `1`, all write/issuer/credential
counts `0`, and redaction-safe output only. This is a local harness
non-acceptance, not provider diagnosis, and the run is not replayed.

The redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc23-20260912/report.json`
(SHA-256
`27bd2f6f408dda4298f3a405c2f72d0c82af29efbc01c6603fc161e86e99b08c`); its
checksum manifest, restrictive modes, offline-gate assertions, redaction scan,
and no-process check passed. The required two-server lifecycle remains
`in_progress`/NO-GO. A future gate must correct the local classification path
before the EEC write boundary, then retain the same EEC-first,
one-reconciliation, no-retry policy.

The follow-up read-only RC23 harness diagnosis proved the local cause: the
collector already held the absolute report root
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc23-20260912/` and then prepended
`/srv/dev-ssd` while reading the classification artifacts, producing
`/srv/dev-ssd/dev-ssd/.../eec-baseline.classification`. The resulting exit `5`
and empty projections were therefore collector misclassification, not n8n or
provider evidence. The diagnosis also confirms the two-layer boundary: the
public `fwc-n8n run-once` wrapper accepts minimal snake_case input and builds
the closed `fwc.n8n.host-run-once.v1` envelope; the host returns one direct
`InvokeResponse` with an object at `.result`.

The redacted diagnosis is
`/srv/dev-ssd/fcp/nqm81.30/diagnose-rc23-classification-20260912/report.md`
(SHA-256
`4dd6d1e475115dc39a50e719c9f73267aaf6afee9bff6630a50e5deab1711e5f`); its
`SHA256SUMS` manifest, restrictive modes, checksum, and redaction checks
passed. No provider or credential process was started by the diagnosis. The
next gate must canonicalize the report root once, assert literal artifact
paths, and project only the direct `.result` before entering the same
EEC-first lifecycle sequence.

Current RC24 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh worker first passed the offline
direct-`InvokeResponse` fixture gate. The gate validated five fixtures, accepted
both omitted and explicit-null success `error` fields, rejected top-level error,
nested-result, and concatenated-JSON shapes, and persisted no raw fixture,
stdout, or stderr. The formal EEC baseline through
`/usr/local/bin/fwc-n8n run-once n8n.workflows.get` proved workflow
`oD8zytCtv5PiSYzc` inactive, unarchived, and unpublished with the expected
version, graph, and state digests. One EEC MCP-access dry-run then planned
exactly one desired enablement with no change and the expected readback digest.

The single EEC MCP-access apply attempt created one fresh approval request,
used one parent-binding helper invocation, one 13-digit millisecond expiry, and
one in-memory 32-byte seed decode. The approval issuer was invoked exactly once
and exited `1` with no stdout, classified as `invalid_request`; no token or
completed provider write was observed. Because the apply result was therefore
unknown, the worker performed exactly one same-server reconciliation GET and
proved the original inactive, unarchived, unpublished EEC state and exact
digests unchanged. Publish, unpublish, and the complete Hetzner phase were not
started under the EEC-first gate. EEC counts were baseline GET `1`, dry-run
`1`, apply attempt `1`, and reconciliation GET `1`; completed MCP-access and
verified provider writes were `0`.

The redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc24-20260912/report.json`
(SHA-256
`8f9385550e3219174eaaee6a83027aa2ca195ba859ab13c7475d8bd4932b6ada`). Its
`SHA256SUMS` verification, restrictive modes, redaction checks, and
matching-process check passed. RC24 is a bounded local/issuer NO-GO, not
provider lifecycle acceptance, and is not replayed. The two-server lifecycle
remains `in_progress`/NO-GO; a future attempt needs a separately justified
diagnosis or correction of the issuer `invalid_request` boundary and a fresh
EEC-first run with the same one-reconciliation/no-retry policy.

Current RC24 issuer-diagnosis checkpoint (2026-09-12; read-only): the retained
evidence proves one EEC MCP-access approval issuer invocation returned
`invalid_request` before token issuance, but it does not identify the rejected
field. The RC24 request body and a bounded shape projection were not retained,
so neither a request-schema mismatch nor installed issuer/source drift is
proven as the cause; the EEC reconciliation still matched the exact inactive,
unarchived, unpublished baseline. The diagnosis report is
`/srv/dev-ssd/fcp/nqm81.30/diagnose-rc24-issuer-invalid-20260912/report.md`
(SHA-256
`46f7418368d89e023f4813aad2e068c0e87dfc99134898fdfe9cd608c00b3bb3`), with a
verified `SHA256SUMS` manifest, restrictive modes, and redaction-clean
contents. A future supervised attempt must regenerate the request against the
current contract, validate and retain only a redaction-safe projection of its
outer/input key sets, JSON types, omitted filters, operation, binding format,
and expiry classification before the single issuer invocation; it must keep
the EEC-first, one-reconciliation, no-retry policy. RC24 is not replayed and
the required two-server lifecycle remains `in_progress`/NO-GO.

Current RC25 live-acceptance checkpoint (2026-09-12; installed release remains
`release-20260912-cddd9f168-rc14`): the fresh supervised worker first passed
the offline direct-`InvokeResponse` request/response gate. Six in-memory
`jq -cn` fixtures were checked: omitted and explicit-null success `error`
fields plus a sequential repeat were accepted, while non-null top-level error,
nested `response.result`, and concatenated JSON were rejected. No provider,
credential, or issuer access occurred before that gate. The formal EEC baseline
through `/usr/local/bin/fwc-n8n run-once n8n.workflows.get` matched workflow
`oD8zytCtv5PiSYzc`'s expected inactive, unarchived, unpublished state and exact
version, graph, and state digests. One EEC `n8n.mcp_access.reconcile` dry-run
then planned exactly one enablement for that workflow, with zero durable
changes and the expected safe readback.

The worker stopped before approval preparation, issuer invocation, credential
access, or any provider write because the local approval-preparation command
was blocked. EEC therefore had one baseline GET and one dry-run; MCP-access
apply, publish, unpublish, reconciliation, all Hetzner operations, and all
provider/issuer/credential counts were `0`. No workflow state changed and no
provider write is claimed. The redacted report is
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-rc25-20260912/report.json`
(SHA-256
`392ed345f689a2d57e70e82a9b5c499246a99260b55e65455af7458312ff8c11`); its
`SHA256SUMS` manifest (`180ea5e305c8bb626af017795c5cb3bf152831a3c99e6e4da7ad7ca10c8b5762`), restrictive modes, redaction scan, and no-process check passed.
RC25 is a local preparation-boundary NO-GO, not provider lifecycle acceptance,
and is not replayed. A future fresh gate must use a short command path without
the blocked heredoc-style preparation, retain the same complete approval-shape
projection, EEC-first ordering, one-reconciliation rule, and no-retry policy.
The required two-server lifecycle remains `in_progress`/NO-GO.

Historical candidate live checkpoint (2026-09-14; installed release
`release-20260914-2855e4545-rc1`): the fresh candidate was assembled from git
revision `2855e4545efbec41ec5c662c7314fcc8561729eb`, passed the static smoke
gate, was owner-signed, passed provision preflight, and was promoted through
the temporary-symlink rename boundary. The installed bundle reports available,
retains the previous immutable release for rollback, and pins the isolated
network-disabled local `n8n-mcp` package to `2.84.4` with protocol
`2024-11-05`.

The fresh EEC-first run then read the exact disposable workflow baseline and
performed one dry-run for `n8n.mcp_access.reconcile`. A single owner-issued
apply restored the previously leaked MCP-access state to `availableInMCP=false`;
the committed ledger receipt is `applied` with one changed-and-verified item.
One independent same-server `n8n.workflows.get` confirmed the exact version and
graph plus `active=false`, `activeVersionId=null`, `published=null`, and
`isArchived=false`. No provider retry was made. This is current-release,
bounded MCP-access evidence, not full lifecycle acceptance: publish/unpublish,
execution, and the complete EEC-then-Hetzner sequence remain
`in_progress`/NO-GO.

Redaction-safe evidence is retained under
`/srv/dev-ssd/fcp/nqm81.30/live-acceptance-20260914-2855e4545-rc1/`, including
the apply and independent reconciliation projections. The approval-request
directory was corrected to mode `0700`, and the fixed owner public-key file was
aligned with KeePass-backed public metadata before the successful apply; no
private seed or token was persisted in the evidence.

**Historical lifecycle-fixture diagnosis (2026-09-14; bounded NO-GO):** The target
disposable draft `oD8zytCtv5PiSYzc` contains only
`n8n-nodes-base.manualTrigger`. The deployed EEC n8n `2.38.4` activation
validator explicitly excludes `manualTrigger` from its activation-eligible
trigger set; publication requires at least one trigger, webhook, or polling
node. The target therefore fails activation validation before the direct legacy
activation update, which is consistent with the absence of a publish-history
row, outbox row, published version, trigger-status row, or state mutation in
EEC. The raw provider error body was not retained, so this record does not
claim its exact response text; the cause is established by the deployed source,
the exact draft graph, and the unchanged database state.

For a future disposable publish/unpublish acceptance, the fixture MUST use a
real activation-eligible trigger. The approved minimal shape is one
credential-free `n8n-nodes-base.webhook` node at `typeVersion: 2.1`, with
`httpMethod: POST`, a fresh non-empty path, `authentication: none`,
`responseMode: onReceived`, `connections: {}`, and
`settings.availableInMCP: false`. This makes the workflow publishable without
introducing spontaneous timer executions. Local validation is necessary but is
not by itself proof of server activation eligibility; a manual-trigger-only
graph remains valid as a draft but is never an acceptable lifecycle fixture.

The next live attempt is additionally blocked by the evidence-build contract:
on 2026-09-14 the required `/srv/dev-ssd` filesystem was not mounted and its
configured UUID was absent. Until that filesystem is restored, no Cargo proof
lane or contract-compliant evidence packet may be claimed, and the
`/srv/hdd500gb-internal` or root filesystem must not be substituted for the
required SSD target. The prior `unknown_outcome` publish is not replayed.

### 5.1 Exact operation inputs and outputs

All inputs reject additional properties and all outputs use the common envelope.
The table specifies the exact operation-specific `data` shape.

**Owner scope revision, 2026-10-15:** cleanup `flywheel_connectors-nqm81.44`
is the prerequisite to resuming `.35`. The supported authoring path is a JSON graph or
template, checked with the existing MCP validator, then saved or tested only
with the operation's separate authorization. Workflow SDK execution and
`workflow_code`/`workflowCode` inputs are withdrawn, including their old refusal
stubs; SDK reference documentation and reading Code nodes are separate retained
features. No custom n8n fork or native credential extension is required.
Historical evidence below describes the attempts that occurred, not pending
SDK implementation or authority to repeat them. Cleanup is not `.35` closure.

Initial cleanup source checkpoint: the reviewed cumulative source diff against
`05f8d3b9656157ec747bd88508bfce5389701353` is
`2ca7713102385691ea67caca24518c882bba9fa8ea2833a95a85591f3b943dc9`.
CLI tests passed 257 cases (12 ignored), host diagnostic tests 19 (3 ignored),
the manifest fixture 4, workspace compilation and formatting passed. Strict
Clippy at that checkpoint was non-green on two bridge tests and five sandbox
tests; the follow-up below records their disposition, not a waiver.
The first new UBS run is partial: Rust exceeded 120 seconds; only Bash completed
with one independently explained warning. Its originals remain under
`/srv/dev-ssd/fcp/nqm81-35/sdk-retirement1/ubs1.*`. The separate affected Rust-only
check used the same 14 Rust files with a finite 600-second module budget and
completed in 306 seconds, exit 1: 85 critical, 11,378 warning and 3,999 info
counts. `ubs2.result.json` SHA256 is
`785860cf67076aca293d3df99f6240ee6c174e65c0860b83e37edf4866fec2a3`;
`ubs2.findings.jsonl` preserves 15,457 actual file records outside the disposable
directory (five additional summary-only info counts have no file record).
This is completed non-green scanning, not a blanket disposition or commit
waiver. Code commits and physical removal were held at that checkpoint; the
owner's subsequent exact authorization and its execution are recorded below.

The subsequent test-only lint correction has source diff SHA256
`5a1d46f9724a917643b75edd217ab3a85b03152641533fe8ad4f4a2c50f18be0`
against the same HEAD (20 source paths). The sandbox production prefixes remain
byte-identical to HEAD; 611 sandbox tests, seven bridge capability tests,
formatting and `git diff --check` passed. Workspace Clippy still exited 101:
seven further pre-existing bridge test-style findings remain at `client.rs:1217`,
`connector.rs:3878,4039,4053,4076,4092` and `protocol.rs:1952`. No production
defect, suppression or workspace-wide success is inferred from this result.
The separate three-file UBS check completed in four seconds with exit 1:
11 critical, 547 warning and 286 info counts (four info are summary-only).
Its `sdk-retirement1/ubs3.result.json` SHA256 is
`a650c0b9b8cd44d10078b80bfd5025957a763eee97379b37b4d83c04890439d1`.
Independent source review explained all 11 critical and the added-line eight
warnings/five info without finding an actionable defect; the other 539 warnings
and 277 file-info records are not declared adjudicated. Earlier UBS2 review
likewise covered all 85 critical and added-line 392 warnings/51 info, leaving
10,986 warnings and 3,948 other info unadjudicated. These non-green results keep
the code-commit gate held under the owner-approved UBS policy until the owner's
explicit exception for this exact source diff. They remain non-green and do not
authorize future changes or releases.

Candidate process checks also passed without provider calls: the dedicated
credentials child test ran 19 synthetic cases (EEC nine, Hetzner ten), including
normal/empty/full-200 metadata and malformed, oversized, schema/body/token/port
and deadline refusals. Each case recorded reaped/absent owned groups; this is
synthetic transport evidence, not server acceptance. Its primary log is
`/srv/dev-ssd/fcp/logs/nqm81-44-credential-child1.log`, SHA256
`69472ea5d479b0418c840d1c8c7cb28d42708029522ec6d5c4e6471a44f24a87`.
The existing local MCP process test passed all seven fixed catalog calls and
teardown/redaction assertions; `nqm81-44-local-mcp-candidate1.log` SHA256 is
`88d9fbe6042972acf742c603c78fc8e0fbc8f68613090ef3ed360399ce46f876`.
Neither check admits an unsigned candidate as an installed release.

**Owner-authorized SDK retirement, 2026-10-15:** message `msg_7b27e3849caf`
confirmed the exact deletion DATA `8f8cd5a68def8092d1726a89cc0abe5499b31f10237ff89f5e70a7d127c2e273`
and command literal `a70cdcb090f0243556c5097aebdce36940fcd2ab69e2b0d85aef240a7c1b67b4`,
without an archive, plus the bounded analyzer exception for source diff `5a1d46`.
All five commands completed with exit 0; 141 listed physical targets and the
separate N worktree are absent, its branch and host registration are removed.
The exact command/output/time record is
`/srv/dev-ssd/fcp/nqm81-35/sdk-retirement1/deletion-execution1.json`, SHA256
`eda95d98b8b275e22d59f90eeef917b29f1abc913bdeef166a2463816996622a`.
It retains the supplementary lsof timing limitation and disjoint FUSE warnings;
no continuous or whole-host preservation proof is claimed. The scoped 24 inputs,
signed-current pointer and public dependency bytes/names matched before/after.
Shared sandbox, FCP SDK, Code reads, JSON validation, signing machinery and
historical FAIL/UNKNOWN evidence were excluded from removal. Post-removal Cargo
metadata resolved all target source files and exposed no retired SDK target.
The installed release is unchanged. This one cleanup/commit exception does not
admit signing, installation, provider mutations or future cleanup.

The same cleanup's four installed local MCP regressions read one minimal node
definition and template `4275` in `nodes_only` mode (20 metadata nodes), then
validated the fixed synthetic valid/URL-empty graph pair. All four processes
completed with exit 0, absent owned groups, joined IO and empty stderr; the
invalid graph retained its original URL diagnostic and complete assessment.
The raw valid/invalid responses equal the previously accepted pair byte for
byte. Before/after signed current and the scoped 24 inputs remained equal.
Primary outputs and requests are in
`/srv/dev-ssd/fcp/nqm81-35/sdk-retirement1/local-mcp-smoke1/`; `result.json` SHA256
is `1c5452b73fa4514fe9b49e072a59b06386106967585bfecfc6dab0169ecf7aaa`.
This checks the unchanged installed `release-20261014-read-parity-4c39cbe7-rc1`
local JSON/knowledge path, with zero remote calls and no workflow/node
execution. It is not acceptance of the uninstalled cleanup source, a deployed
schema-equivalence proof, a global stability claim or completion of `.35`.

| Operation | Required input | Optional input | `data` output |
|---|---|---|---|
| `targets.resolve` | exact URI/ID or explicit server/candidate authority for name reads | `projectId`, `projectName`, `workflowName`, `candidateServers[1..3]`, `legacyOptIn` | `{resolution: resolved\|ambiguous\|not_found, target?: TargetRef, candidates?: [TargetRef]}`; names are lookup inputs, not public output fields |
| `capabilities.inspect` | empty `{}` operation input; fixed server comes from the host envelope | none | `{capabilities:{schema:"fwc.n8n.capabilities.v1",serverId,provider:"official_mcp",toolCount,tools:[{name,inputSchemaDigest,outputSchemaDigest,class:"unknown",status:"unreviewed"}]}}` |
| `runtime.status` | none | `correlationId` | `{idle,activeRuns,providers:[{provider,pid?,pgid?,rssBytes?,pssBytes?,privateBytes?,stopped?}]}` |
| `knowledge.query` | `action`, action fields | `detail`, `limit` | discriminated result matching the action |
| `node_resources.explore` | `target`, `nodeType`, `version`, `methodName`, `methodType`, `credentialId` | `filter`, `paginationToken`, `currentNodeParameters`, `legacyOptIn` | `{results:[{name,value,url?,description?}],paginationToken?,builderHint?}` |
| `validation.run` | `subject`, subject payload | `profile`, `target`, `detail` | `{valid,nativeValid,overallStatus,errors:[{path,code,message,classification?,scope?,nodeIndex?,field?,nativePropertyOrdinal?,schemaPropertyOrdinal?,defaultApplied?,apiVersion?,nodeTypeVersion?,expectedType?,actualType?,structureKind?,unknownReason?,diagnosticStage?,diagnosticSource?,sourceVersion?,binding?,nextDiagnostic?}],warnings:[...],diagnosticBinding?,validationCoverage?,normalizedDigest?}` |
| `structure.search` | `target.server`, `kind` | `query`, `projectId`, `parentFolderId`, `page` | `{items:[{resourceUri,id,name,type,parentUri?}]}` |
| `workflows.search` | `target.server` | `query`, `projectId`, `folderId`, `tags`, `active`, `isArchived`, `page`, `sort` | `{workflows:[{resourceUri,id,name,description?,active,isArchived,updatedAt?,projectId?,availableInMcp?}]}` |
| `workflows.get` | exact workflow target | `detail`, `version=draft|published|both`, `includeCode=false`; true requires the exact pins below and routes before admission to `get_code` | `{workflow: NormalizedWorkflowState,graph?: object,codeNodes?: [{name,digest}]}` for metadata; sensitive route uses the separate result below |
| `workflows.get_code` | exact workflow target, `version=draft|published|both`, `pins` containing exactly each selected label's `versionId` and `graphDigest` | none | `{id,versions:[{version,versionId,graphDigest,codeNodes:[{nodeId,language,source,digest}]}]}`; requires `n8n.workflows.code.read`, not metadata authority |
| `workflows.compare` | exact workflow target, `leftVersion`, `rightVersion` | `detail` | `{leftUri,rightUri,semanticDiff,layoutDiff,validationDelta}` |
| `workflows.create_draft` | target server/project, `name`, `graph`, `guard` | `folderId`, `skillsUsed[]`, `sourceTemplateUri` | `{workflow: NormalizedWorkflowState,created:true,validation}` |
| `workflows.update_draft` | exact workflow target, `operations[1..100]`, `guard` | `skillsUsed[]`, `autofix=false` | `{workflow: NormalizedWorkflowState,appliedOperations,semanticDiff,validation}` |
| `workflows.activate` | exact workflow target, `active`, full `guard.precondition`, UUID idempotency key | publish `versionId` (required for pinned activation), one matching approval | `{before: NormalizedWorkflowState,after: NormalizedWorkflowState,active:true|false}` after one REST POST and independent REST GET readback |
| `workflows.lifecycle` | exact workflow target, `action=publish|unpublish`, full `guard.precondition` | publish `versionId` (optional) | `{before: NormalizedWorkflowState,after: NormalizedWorkflowState}` after one exact official-MCP call and independent REST GET readback |
| `workflows.versions` | exact workflow target, `action` | `versionId`, `guard`, `page` | action-specific version list/get/rollback result |
| `workflows.execute` | exact workflow target, `mode`, `versionId`, `guard` | `inputs` (bounded), `wait=false` | `{status,operation,provider,workflowId,mode,versionId,executionId,initialStatus,retry,readback}`; only bounded identifiers/status are returned. Host admission requires the exact immutable owner-provisioned EEC/Hetzner schema binding; after any provider attempt, readback transport/decode/mismatch is terminal `unknown_outcome` with no automatic retry. |
| `executions.search` | `target.server` | `workflowId`, `status[]`, `startedAfter`, `startedBefore`, `page` | `{executions:[{resourceUri,id,workflowId,status,mode,startedAt?,stoppedAt?}]}` |
| `executions.get` | exact execution target | metadata-only; provider queryless | `{id,finished,workflowId?,status?,mode?,startedAt?,stoppedAt?,workflowVersionId?,retryOf?,retrySuccessId?,waitTill?}` |
| `executions.diagnostics` | exact execution target | fixed `includeData=true`; node/run/message/type/stack bounds | `{id,finished,mode?,startedAt?,stoppedAt?,workflowId?,workflowVersionId?,status?,retryOf?,retrySuccessId?,waitTill?,diagnostics:[{nodeName,nodeType?,errors:[{runIndex,message?,type?,stack?}]}]}` |
| `credentials.list` | `target.server` | `query`, `type`, `projectId`, `onlySharedWithMe`, `limit` (1–200) | `{credentials:[{resourceUri,id,name,type,scopes,isManaged,isGlobal,homeProject?}],count,page:{returnedCount,limit,continuation:"unavailable",completeness:"not_established"}}`; count is returned rows, not a total |
| `data_tables.search` | `target.server` | `query`, `projectId`, `page`, `includeSchema=false` | `{tables:[{resourceUri,id,name,projectId?,columns?,rowCount?}]}` |
| `data_tables.mutate` | exact table target or target project for create, `action`, `guard` | action payload | `{before?,after,affectedRows?,schemaDigest}` |
| `evaluations.manage` | exact workflow target, `action` | `runId`, `status`, `page`, `guard` | action-specific `{evaluationUri?,status?,runs?,cases?,summary?}` |
| `audit.inspect` | `target.server` | `categories[]`, `detail` | `{summary:{categories,fullAudit:false},findings:[{category,severity,resourceUri?,code,message,affectedCount}]}` |
| `mcp_access.reconcile` | `target.server`, `scope`, `desired`, `dryRun` | `guard`, `projectId`, `folderId`, `workflowIds[]` | `{planned,changed,skipped,exceptions,readbackDigest,receipt}` |

`.35` credential implementation boundary (2026-10-04): the public identifier
remains `n8n.credentials.list`. The official `list_credentials` tool accepts
partial name/type filters and project/sharing filters. It supplies scopes,
managed/global flags and nullable home project; the native REST list does not
provide equivalent top-level fields. The remaining REST DTO/list method is an
internal provider surface, not evidence for the public official contract.
The official tool accepts a limit of 1–200 but no cursor. Candidate output
therefore reports `page.returnedCount`, `limit`, `continuation:"unavailable"`
and `completeness:"not_established"`; cursor requests refuse before dispatch.
The native `data,count` result does not establish that `count` is an untruncated
global total. Under the 2026-10-15 owner revision this bounded metadata result is
the required contract, not an obligation to implement provider pagination. At
the limit, report the bound and suggest narrower filters; do not invent a next
cursor, snapshot or complete inventory. REST fields cannot substitute for the
official metadata fields.
The new typed bridge/schema projection is source-only until separately admitted;
installed RC43c does not acquire these capabilities through discovery.

Historical experiment, withdrawn by cleanup `.44`: the 2026-10-15 local
continuation candidate preserved that legacy schema as a
separate profile. A legacy result with the exact native limit of 200 establishes
an observed complete set only when fewer than 200 rows are returned; a saturated
result is refused. The proposed native `bounded-v1` extension collects at most
4097 metadata rows, refuses more than 4096 rows or 4 MiB, and returns explicit
total, end and opaque continuation fields. The FCP mapping selects only the
complete reviewed input/output schema pair, never a mixture or a discovered
replacement. The producer rejects this profile when old retained runtimes are
selected. Provider deployment, mapping admission and installed acceptance remain
pending.

Both candidate profiles bind continuation to the explicit server, filters,
page size and observed metadata. The native extension additionally binds the
instance and authenticated user. Each page recollects the metadata and refuses
a changed observed snapshot; it does not claim a transaction or detection of a
change that was reverted between reads. Metadata values are projected through a
whitelist; secret credential data is never requested. The native 15-second
deadline bounds its response, not cancellation of the underlying database query.
Local fixture evidence is retained in `autonomous1/source-checks/remaining-credentials1`
under the existing `.35` evidence root; it is not provider deployment evidence.
The first candidate used an inactive MCP SDK 1.26 serializer and is retained as
invalid schema-provenance evidence. The selected native source actually uses
MCP server 2, `shapeToStandardSchema` and `zodToDraft202012`. The corrected
derivation runs that registration and tools-list serialization and reproduces
the admitted legacy schema digests before deriving the candidate pair. Tests
that used the first pair are not evidence for the corrected served schemas.

Owner decision, 2026-10-15 (`msg_55b170751bf1`): retire the native `bounded-v1`
tool, upstream schema-validator hook and local synthetic snapshot/cursor path.
The remaining FCP route uses the unchanged official tool and bounded metadata
projection. No complete credential inventory is inferred even from an
unsaturated page without an authoritative provider completeness contract.
Removal of experimental files requires the exact deletion gate; it does not
activate the remaining mapping, grant access or prove installed acceptance.

Validation diagnostic candidate (2026-10-08; local source, not installed): the
shared local, remote-workflow and comparison projector preserves native `valid`
and every error/warning count. For the pinned 2.91.0 package it recognizes only
exact anchored position-shape/value, missing-type-version, empty selected Code
parameter, disconnected no-op node and validator node-type/version-database-limit
forms. Classification also requires the existing verified package metadata
fingerprint `0428c7d49767df9eec57c26d27997021812a1b6faf55e0faef9c14498376e723`;
a version string alone is insufficient. This preserves, rather than expands,
the existing package/transitive trust boundary; metadata does not hash every
transitive module. It emits fixed codes/messages and an
allowlisted `field`; legacy `nodeIndex` is zero-based and emitted only for a
unique native node-name match in the original captured graph. A node named
`workflow` remains unclassified even if a node has that name; the separately
verified derived graph-warning origin described below has no node identity.
The classified fields contain no native names, messages, details, parameter
values or source. Since `4a2d827a`, the separate `nativeDiagnostic` attachment
preserves bounded original message/node/details, source/stage and severity.
It is not classifier authority: unclassified originals remain unclassified.
Each original field has an 8192-byte encoded-content limit and findings share
a 64 KiB content budget; explicit status/truncation fields distinguish missing,
non-text, present and truncated values. Envelope/count/duplicate-key/binding and
validity contradictions still refuse. This is not a promise that originals are
anonymized or always complete; fixtures and retained outputs must be selected
and handled within their authorized scope. The index belongs to this
graph/version, not a stable node identity. Unknown, ambiguous, missing-context
or unsupported-package findings retain their count with `code` and
`classification` equal to `unclassified` and no node index or field.

`diagnosticBinding`, when available, contains `graphDigest`, `layoutDigest`,
`profile`, `packageVersion` and `packageMetadataDigest`; host-owned
remote/comparison results additionally bind the checked `versionId`.
`graphDigest` covers the actual nodes excluding positions plus connections sent
to validation; `layoutDigest` covers the ordered node IDs and positions.
Diagnostic binding alone does not change comparison's
`validationDelta.changed`; graph-local indexes are also excluded from that
comparison, which compares valid and the ordered safe code/classification/field
findings. `validator_support_limit` describes the validator's
database, not a confirmed workflow defect. `input_shape` describes a checked
input property, not a complete workflow assessment. Malformed, oversized and
contradictory envelopes still fail closed. `validator_observation` describes
a checked disconnected no-op node, not a business execution result. General
parameter rules, expression diagnostics, global connection errors using the
reserved fallback, dynamic suggestions and AI-specific diagnostics remain
unclassified; their messages/details cannot be safely inferred by these rules.
Installed RC3's historical generic diagnostics and observed counts remain
unchanged; this candidate needs separate
source and installed admission before ordinary CLI acceptance.

Versioned native producer candidate (2026-10-09; preparation only): the existing
assembler's explicit rootless `--prepare-derived-local-validator INPUT_FILE`
mode makes a new, separately identified 2.91.0 package from an exact registry
tarball and the reviewed fixed dist patch. Every published package file must
match its tar member before patching; the registry updater and ordinary release
mode are unchanged. `fwcDerivedValidation` records the original metadata/tar
identity, patch SHA and complete derived package-file hashes. These are derived
bytes, not upstream registry SRI. Its preparation receipt has `admitted:false`.
Borrowed dependency copies are permitted only for controlled offline tests;
they are neither registry-attested nor production admission.

The native validator selects the exact `node_versions` row for each graph
`typeVersion`, including catalog aliases 1/2/3 for the NocoDB V1 schema. It never
substitutes the latest descriptor. API parameter `version` is a separate
selector; caller `parameters['@version']` cannot override graph `typeVersion`.
Missing exact schemas retain counts and `unsupported_version`/incomplete
coverage. Selected visible resource/operation options use that same schema;
the current-row enhancement cannot replace its result. This pins the native
database's contract, not a physically deployed n8n descriptor or business result.

After ordinary signed-current/package admission, a sealed provider proof gates
structured diagnostics in local graph validation, host remote validation and
both comparison graphs. It binds actual metadata, fixed patch and complete
root-package file map, verifies root-owned non-writable directories/files with
bounded no-follow stable reads, and rechecks before launch. It does not attest
unrelated transitive dependencies. No native response marker or caller JSON can
construct this proof, and no unsigned diagnostic CLI trust override exists.

`required_absent`, `required_null` and `required_trim_empty` emit closed native
origins at their actual error slot. Safe results expose anonymous `nodeIndex`,
`nativePropertyOrdinal`, `schemaPropertyOrdinal`, `defaultApplied`, `apiVersion`
and `nodeTypeVersion`. Special type predicates additionally expose closed
`expectedType`, `actualType` and `structureKind` (for example object versus
string for resourceLocator), never values or native text in classified fields.
The separate bounded `nativeDiagnostic` attachment described above retains its
own original content/status. These remain
`validator_observation`, not confirmed workflow defects. Unknown native rules,
missing origins and the reserved `workflow` node name preserve findings without
invented node indexes. Verified derived origins bind the actual emitted slot
and checked graph index/version before any legacy name lookup; repeated names
at distinct indexes do not erase their causes. Legacy untrusted text still
requires a unique name match. Graph-scoped disabled-target warnings emit the
fixed `graph_connection_disabled_target` code/message and `field:connections`,
without endpoint names or a node index; their origin keeps a null index.
Unreachable-node and legacy-error-handling origins bind actual graph indexes
separately. Unrecognized warnings retain their count.

Every unclassified fallback includes a closed `unknownReason`,
`diagnosticStage`, `diagnosticSource`, `sourceVersion`, and `binding` (null when
unavailable). Reasons distinguish missing context/origin, reserved workflow
scope, unavailable/ambiguous node binding, unrecognized legacy form and
unsupported native rule. The binding contains graph/layout digests, profile
and verified package metadata digest, never names or raw native content.
`nextDiagnostic:authorized_graph_bound_native_diagnostic_required` identifies
an informational requirement for further authorized diagnosis; a bounded
`nativeDiagnostic` may already be present. It grants no execution authority.

Optional `validationCoverage` contains per-node index/version/schema SHA/status,
native source bindings, warning origins, `schemaCoverageComplete`,
`unclassifiedErrors`, `unclassifiedWarnings` and `assessmentComplete`. A true
native `valid` with incomplete coverage is not a complete assessment:
`nativeValid` preserves the same native boolean as `valid`, while
`overallStatus` is explicitly `incomplete`. It is `complete` only when verified
versioned coverage and all finding classifications are complete; legacy and
unbound results remain `incomplete`. This status describes assessment coverage,
not workflow correctness. An invalid
zero-error result is accepted only as explicitly incomplete. Count, shape,
version, profile, ordinal, package and envelope contradictions fail closed.
Existing public operation identifiers, capabilities, profiles, transport and
graph/response limits remain unchanged. The new producer/native/typed tests are
prepared for coordinator execution; no new installed result is claimed here.
For versioned diagnostics, comparison's finding signature also includes closed
expected/actual type, structure kind, default-applied and API-version facts.
It continues to exclude node indexes, schema ordinals and graph/source bindings
from cross-version identity; counts and full per-side observations are retained.

Installed structure baseline (2026-10-04): the coordinator attempted
`n8n.projects.list` with `{}` exactly once on each server through installed
RC43c. Both calls exited 1 with `host_n8n_invoke_failed`; no project data or
successful structure read was established. The closed derivative does not
establish the cause. Primary evidence:
`initial-installed-project-list-20261004.json`, SHA-256
`cb7f036c1da63e09883e02e1ef5d148a0ee9f580abd321f0e10a0253bd97ff33`
in `/srv/dev-ssd/fcp/nqm81-35`. Structure rows remain **needs correction / new
source validation**, including projects, folders and tags. Discovery of native
tools is not admission or successful dispatch; required filters must use their
actual native contracts rather than invented REST fields or local-page sorting.

Historical read-route checkpoint (2026-10-04; superseded for SDK by `.44`):
the closed `mcp.n8n.read` action set maps SDK reference, best practices, SDK code,
node validation, credentials, projects, folders, tags and workflows to fixed
native tools. Generic MCP calls retain their approval gate. Wrapper consumers
accept the bridge's bounded `{serverId,action,data}` projection, with exact
server/action bindings; they do not expect or expose raw MCP transport.
Structure and workflow search use a complete bounded native snapshot before
local filters or snapshot-bound public pagination. Native caps are 100 projects,
100 folders, 500 tags and 200 workflows; a truncated result refuses. This is not
unbounded search parity. Official workflow search excludes archives, so
`isArchived:true` is an explicit unsupported capability, not an empty success.
Native query/project/folder/tag filtering is bound to the same request; active
filtering is applied only after completeness has been established.

Direct FCP credential checkpoint (2026-10-05, LOCAL A source only): the earlier
pre-HTTP refusal remains the default when managed mapping is absent. The new
optional closed `credential_metadata_read` mapping keeps the original
`BoundVerified` token, instance, accepted owned session, principal, zone,
resource, request and caveats. It creates no child token or grant. Only fixed
`list_credentials` arguments and the two observed raw schema pins are accepted;
MCP credential selection must intersect the original `credential_allow` and
the fixed bearer profile/purpose. Generic API-key and bridge guards remain.

Normal producer and signer/provision validation agree on an explicit separately
admitted input. With mapping, only `credentials.list` uses EEC:443 or
Hetzner:8443; every other operation retains REST:443. The signed Hetzner entry
must use exactly `[8443]`, not a union. Null, partial, unknown or drifted mapping
and altered per-operation networks refuse. Historical signed modes cannot gain
this mapping. The portable manifest envelope is not a grant of either port.

`credentials_owned_http_original_authority_and_metadata_success` exercises the
real host HTTP handler, original synthetic authority, a controlled loopback MCP
server, exact query/type/project/sharing filters, projection and refusal cases.
Cancellation is tested before HTTP and while a response is pending; closed
admission prevents subsequent dispatch. This is component/mock transport
evidence, not original connector child-process or installed CLI acceptance.
Pure producer fixtures exercise the native pre-seed validator and synthetic
signed provision validation. Real mapping activation, new source admission and
installed original-invocation acceptance remain OPEN; signed source7592 does
not contain LOCAL A. Native credential continuation was still OPEN at that
checkpoint; the owner later withdrew that requirement in `.44`. Earlier
unbound-token/child-attenuation findings remain historical; this implementation
does not add general delegation or reinterpret them as a successful live call.

Candidate `runtime.status` returns `idle:null` and `activeRuns:null` when the
host has no shared-supervisor observation. Its explicit `observation` reports
sessions and memory as `not_collected`; an empty provider array does not mean
that other invocations are idle or absent. This nullable/unavailable projection
requires contract review and does not prove the later zero-idle criterion.
The retained-owner continuation (`remaining-runtime3-ctx_73622008fd40`, source
checkpoint 6) passed scoped Clippy and ten pure regressions, including final
authorization, freshness and invalidation checks. Its first fixed private
two-CLI fixture instead exited 101 with `WorkerStopped` at the initial actor
handshake, before either CLI ran. `native-fixture-run1.log` and
`native-fixture-run1-result.md` retain this failure; inner actor reap, group
absence and IO joins were not captured and remain unknown. Later process
absence cannot supply those observations. Cross-process and installed runtime
status acceptance therefore remain open while this fixture is corrected.
The corrected fixed-shell fixture later passed its initial handshake but still
exited 101: its first separate CLI helper returned `unknown` instead of active
(`runtime-failure-ctx_f7cd4e198be1/native-diagnostic-run1.log`, SHA256
`66c34225aaa288c33c8a0fa03748cc9c4d2cb872c4dbcb2e7641ca42f545cfc7`).
That helper completed with EOF/reap/group-absence checks; the second CLI and
final actor cleanup assertions were not reached. This is partial transport
evidence with actor cleanup unknown, not a working status scenario.
The later diagnostic with fixed stage/error/timing messages also exited 101
(`runtime-unknown-ctx_98590ebcb0b3/native-diagnostic-run1.log`, SHA256
`fa87b84b7313a1aecdff8bc56ca677700b8ea4c978c9fe96aa72346cdf6da2ce`).
Peer authentication and request reading succeeded, but the authenticated reply
was rejected as `Expired`; the first CLI again returned unknown. Its finalizer
captured actual actor/IO joins, reap and group absence, with TERM but no KILL.
The server thread panicked and the scenario failed. These new cleanup facts
apply only to this attempt. They do not fill earlier unknown cleanup records,
prove active/idle status, or justify extending the original three-second query
deadline or five-second observation age. Timing diagnosis remains in progress.
The subsequent fixed private comparison used only test-build BLAKE3 optimization,
without changing those deadlines, authority or observation rules. Its two CLI
processes passed active, verified idle and stale/EOF/deadline-unknown assertions
(`runtime-unknown-ctx_98590ebcb0b3/blake3-opt3-diagnostic-run1.log`, SHA256
`c8b9425d6905a4b4b9161074ec0af2aaecfc89603e1e53e2b5af64abcb646a1d`;
exit 0, one test, 17.84 seconds). Actor/IO and server joins, reap and group
absence were observed; finalization used TERM, not KILL. This is controlled
cross-process evidence, not installed coverage, global idle or a production
performance guarantee. Earlier failed attempts and unknown cleanup remain
unchanged. The narrow missing-correlation wrapper regression subsequently
passed. The revised private fixture also passed without a caller-supplied CWT
(`runtime-no-cwt-ctx_6b65518aaf29/no-cwt-diagnostic-run1.log`, SHA256
`0c3adf81999c3e2077c760acfa22a4f89aeddd016e3cfc6a1cae4707d83b5786`;
exit 0, one test, 22.07 seconds). It retained a genuinely issued synthetic
read proof, five bounded query outcomes and known actor/IO/server cleanup;
the accepted-close branch still surfaced a deadline fallback, not a distinct
EOF classification. This does not prove automatic production issuance or an
ordinary provider launch. Profile-wide aggregate authorization, enforced
multi-route coverage, role admission and activation remain open.

Local continuation on base `031c6a17` (2026-10-05, not committed or installed):
the original credentials CLI route now separates broker secret purpose from
connector authority. It selects the normal `fcp.n8n` inventory/driver and
`fwc-n8n://server` resource, retains the original operation and accepts only the
closed separately admitted mapping. Other REST operations keep the API-key
credential and port 443. The wrapper validates the original projected metadata,
not a bridge envelope. Normal-builder, driver and projection tests are local
evidence; they do not establish an installed CLI invocation.
The sealed bundle verifier records the separately signed mapping for each
server; the wrapper requires it before requesting the broker secret. Missing,
null, extra-field or drifted mappings refuse before that acquisition. This
early check does not replace original-token, network, purpose or session checks.

An optional safe-read producer accepts only a nonempty subset of seven exact
tools: search workflows/projects/folders, list workflow tags, SDK reference,
best practices and node-config validation. Both server entries require the
fixed raw input/output pins and presence, class `read`, unique names and closed
fields. It is separate from the credentials mapping; `list_credentials`, SDK
code evaluation and instance audit are not enrolled by this input. Absent input
preserves the existing lifecycle/search mode. Producer, pre-seed validation,
synthetic signed provision and runtime-policy fixtures agree. This is not owner
admission or activation of that policy.

The local observer engine uses the existing admin snapshot with a stable lock,
reload-under-lock for ordinary and observer writers, revisions and epoch/boot/
release checks. Actual owned process identity is attached after a one-shot
launch claim; completion requires reap, group absence and successful IO/actor
joins. Retained separate-process tests mix an ordinary lifecycle writer and a
private observer writer. The physical local-session test checks owned process
and IO teardown, not a native MCP invocation. Only a private test factory can
construct observer authority or assert complete epoch coverage. No trusted
installed writer/launch authority exists, so no public global idle claim is
enabled. Principal/zone/server/correlation authorization for observer queries,
complete entrypoint coverage, timestamped global memory observations, reboot/
owner-incarnation and independent crash/descendant/PID-reuse acceptance remain
open. Pending or unfinished records never become idle through Drop or a TTL.

The recommended deployment boundary is the existing host as the sole supervisor,
with every provider child and descendant in a different unprivileged UID/domain.
Proposed supervisor/provider UID/GID 971/972 were absent from the coordinator's
2026-10-05 passwd/group lookup; they are not allocated identities or authority.
A non-root host cannot perform this transition itself. A separately admitted,
immutable fixed launcher must restrict executable, argv, environment and FD
allowlist, drop supplementary groups/capabilities and privilege regain, and
prevent descendant escape. No generic run-as API or same-UID fallback is allowed.
The host must verify the original bound capability, instance/session, principal,
zone, resource, operation, request, caveats, revocation and deadline before a
pending launch or scoped status query. Peer UID and correlation ID alone are not
authorization. Provider children must not inherit writer state/channel FDs or
credentials, access supervisor memory, or mutate the existing snapshot/epoch.
REST connector, MCP bridge, owned local validator and knowledge-process launches
all require registration before spawn and retirement after full reap, group
absence and IO joins. Mixed old epochs, crashed owners and incomplete coverage
remain unknown. The fixed privileged launch channel, scoped query authorization,
cross-UID isolation and complete timestamped global memory coverage are not
implemented or activated; private transaction/process fixtures cannot prove them.
The local launch-policy fixture now binds distinct typed identities, a launcher
digest, all four route artifact/argv/environment digests and a closed FD set.
Missing identity/pins/routes, equal roles and an inherited writer FD refuse.
The synthetic FD contract distinguishes stdio and a single closed provider
invocation-channel FD from observer writer/state/query channels; it does not
prove physical FD isolation or coverage merely by enumerating four routes.
Private query fixtures use the real instance-bound capability verifier and
principal/zone/server/resource/strict expiry checks; unsupported caveats refuse.
Their private synthetic accepted-session proof is bound to the instance and
owner epoch, and unknown sessions/incarnations refuse. No caller session string
can construct that proof in production. Revocation and request-bound production
query admission remain unimplemented, not inferred from the fixture signature.
They do not constitute an accepted-handshake/request-bound production query
channel or cross-UID isolation. Crash/reopening and owner-epoch drift remain
unknown/refused; an empty scoped query never proves global idle. Tests are
`observer_fixture_immutable_launch_policy_requires_isolated_roles_and_all_routes`
and `observer_fixture_bound_query_and_crashed_launch_remain_scope_limited`.
Current broker kernel-peer UID must match the existing database filesystem
owner; proposed supervisor971 cannot reuse the current1000-owned store through
a socket group. A future explicit broker admission must address that boundary
without copying or changing ownership of secrets.

A1 is the selected local lifecycle contract: the host owns/reaps a fixed guardian;
the guardian owns/reaps the namespace PID1 monitor, which owns the provider and
orphan reaping. The private fixture endpoint binds a launch
nonce, invocation, instance/session, artifact and epoch; it is never a provider
endpoint and carries no credentials or store FD. `ready`, bounded `sample`, host
`terminate` and monitor `completed` have a single bounded sequence. Wrong sender,
binding, order, replay or oversized input makes the observation unknown. Provider
reap, descendant absence, completed IO joins and permission success must all be
reported before a separately observed monitor reap can retire the fixture.
Monitor wait alone, disconnect/crash, incomplete cancellation or any missing
completion condition stays unknown. Completion additionally requires confirmed
child exec/identity and closed egress. Host IO joins and actor join are separate
from provider IO and monitor reap; monitor wait alone cannot retire even after
provider completion. Separate guardian wait and read-only accounting
`populated:0` observations are also mandatory; neither can be inferred from
monitor completion. The fixture rejects each missing/false observation and
cannot recreate a lost wait after crash from a later empty-accounting query.
Numeric sample fixtures qualify only message bounds and
ordering, not timestamped current/global memory or availability. These are
`a1_monitor_fixture_*` protocol
tests, not a production constructor, authenticated OS channel or cross-UID proof.
Activation still requires an admitted fixed launcher/lifecycle monitor, retained
signal/inspection authority after privilege drop and LSM checks, and enforced
cross-invocation containment. The existing network-disabled process filter denies
`setsid`/`setpgid` after the initial session setup; this is a partial existing
boundary, not containment for every launch route. Cgroup integration additionally
requires the supervisor gate, appropriate Landlock exclusions and closing cgroup
FDs before target exec; those integrations remain deferred. A process group or
shared provider UID972 alone does not establish containment.

The selected physical A1 SPEC (2026-10-05, AM11476) requires a separate user,
PID and mount namespace per invocation; the user namespace must own the PID/mount
namespaces and its creator must not be caller UID1000. Proposed mappings are
inner UID0 to outer971 for the monitor and inner UID1 to outer972 for the provider,
with narrowly specified GIDs, no outer0/1000, extra ranges or supplementary groups.
Monitor lifecycle capabilities must be confined to that child user namespace.
The selected recommendation retains only KILL and SYS_PTRACE in bounded
permitted/inheritable/ambient and bounding sets across fixed monitor exec,
with locked NOROOT and NO_SETUID_FIXUP, no further ambient raise, KEEP_CAPS off
and no_new_privs. The setup phase creates a blocked provider stub before losing
SETUID/SETGID; the release barrier requires approved maps/mounts/proc,
parent-death/liveness checks and confirmed post-exec identity. Provider inner1
has empty permitted/effective/inheritable/ambient/bounding capabilities and
supplementary groups, locked securebits/no regain, and no setup/control,
namespace, state or broker FDs before fixed exec. PID1 monitor handles TERM;
guardian escalation uses exact pidfd KILL with matching UID971, without retained
root capabilities or cgroup.kill. These are selected SPEC controls, not tested
physical authority, LSM, syscall, FD or crash acceptance. Mounts must be private,
with namespace-local proc, fixed read-only runtime and private temporary storage,
and no host root/proc/sys/cgroup/state/broker/shared-writable paths or inherited
FDs. This applies to REST, MCP and local launches independently of network_disabled.

The selected topology refinement (2026-10-06, AM11486) requires privileged
bootstrap `clone3` with NEWUSER|NEWPID|NEWNS, without CLONE_PARENT. After setup
the guardian uses proposed outer971 with no capabilities; the monitor maps to
outer971. Exact pidfd signaling authority requires matching UID and LSM checks,
not parenthood. Guardian and monitor parent-death signals must be established
after credential/exec transitions, with parent-liveness and a start barrier;
parent death is UNKNOWN. Root-created accounting/event FDs are read-only and
the provider receives no migration/control FD. The broker's UID1000 credential
acquisition still requires a distinct enforced security domain against malicious
caller1000; dumpability, private FDs and peer UID alone do not provide it.
This is a local SPEC and fixture, not implemented bootstrap or kernel proof:
entering a new PID namespace affects future children, so merely execing the
launcher cannot place the existing host Child/monitor in it. PID1 monitor death
and kernel descendant termination are not a completed/reaped/IO-joined proof;
init reaping, signal and session handling need separate qualification. Actual
cross-UID inspection/signals, escapes, crashes and namespace availability remain
pending. No privileged API, OS namespace activation, service or broker change is
implemented by this SPEC or the fixture protocol. The relevant kernel contracts
are [user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
[PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html) and
[capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html); this
selection does not establish production authority or containment.

Current local package identity is a separate observed boundary: the signed
RC43c policy admits `n8n-mcp@2.90.0`, while the public installed package metadata
now reports `2.91.0` (SHA-256
`2b84df1d7f0f043c37a5d7488d163f04798eafcafbce5b19e0f9738d6bbb5f47`).
The normal package identity guard refused the attempted seven-mode process test
before launch. No package/policy update, native SDK call or hash override was
made; the failed logs remain evidence rather than acceptance.

#### Retired SDK investigation — historical results, not future work

The following dated attempts explain the rejected route. Owner decision
`msg_55b170751bf1` withdraws the executor and its fork dependencies; none of the
pending gates described in this historical subsection is an instruction to
resume SDK work. `.44` removes the corresponding source/artifacts without an
archive. Retained ordinary MCP graph validation is unaffected.

Native SDK-code validation effect boundary (2026-10-04): the installed parser
uses a restricted synchronous AST interpreter that invokes supplied SDK graph
builders. This is not static-only parsing or business workflow execution.
Caller functions, loops, dynamic imports, `process` and `fetch` are denied;
the handler forces `generatePinData:false`, and that method is not admitted to
caller SDK code. AST depth, statements and allocation have native limits.
No demonstrated mechanism preempts synchronous SDK work: a client deadline
does not establish server interruption. The reachable SDK callback/getter
effect proof remains incomplete. Native interpreter errors include source
frames; the tool forwards `error.message` to telemetry before public redaction.
Both installed containers omit `N8N_DIAGNOSTICS_ENABLED`, whose native default
is true; actual telemetry initialization or transmission was not observed.
At that checkpoint this row lacked effect/preemption/telemetry admission. No native
SDK validation, attacker code or telemetry request was executed for discovery.
Safe primary derivative: `sdk-validation-effect-boundary-20261004-1.json`,
SHA-256 `406dfbd0e675579ac2bbc4ffb9bbea200d2411e231f8088bd70af47f71bd8902`.
The selected callback/getter follow-up is
`sdk-validation-effect-boundary-20261004-2.json`, SHA-256
`9c6187d06f74dbe048c2bce546d22db7973b8ea3c73e332d7734c31c6b8f9e63`.
Candidate wrapper dispatch and the typed bridge both refuse this action with
`native_workflow_code_effect_admission_pending` before broker/provider calls.
Projection-only invalid-result fixtures do not authorize native evaluation.

The 2026-10-15 local SDK candidate is a separate path, not enrollment of that
remote interpreter. It binds native source `a9c858b4`, SDK `0.34.2`, a fixed
Node image and an exact ELF/library/file closure. The proposed owned process
has no provider credentials or egress channel; a separate exact-image policy
restricts file contents and process/network creation. Path metadata and trusted
same-UID mutation remain explicit limitations. Pure policy/parser tests do not
establish kernel enforcement, Node startup, synchronous interruption or a usable
public route. Those process and integration checks remain pending. Static
qualification retained 7,341 original published schema files (11,593,521 bytes),
with source-bound description/version metadata. The reviewed metadata-only
producer completed locally; it did not evaluate SDK source or schema factories.
The compiler then produced `native-sdk-adapter/package/dist-full-fixed/adapter.cjs`
(39,112,322 bytes, SHA-256
`46d9cd4683dc9ad689aabfeb17c6e78bdf11d4bd3e3f61438c5e04b3438b9f31`).
This is a compiled candidate, not a successful validation or deployed-catalog
equivalence proof. Missing or conservatively qualified node metadata must keep
the affected assessment incomplete; the earlier two-node fixture remains
qualification-only evidence.
The rootless preparation producer copied the three pinned public assets into
`/srv/dev-ssd/fcp/artifacts/native-sdk-candidate1`, preserving originals and
using exclusive private directories. The exact all-asset data test passed
(`native-sdk-adapter/sdk-package-all-assets-data-run1.log`, SHA256
`df6342bb8800d91d18cffacd71da996f19ff291646dcb424268829ef12ae5977`):
it read and qualified ten compiled assets, including the fixed loader/library
closure. This is local package integrity/ELF evidence, not evaluation, signed
package authority or installation; the producer reports admission false.
The first fixed trusted-boot test (`native-sdk-adapter/trusted-boot-run1.json`)
exited 101 during parent-side exact-image admission, before Node was spawned.
It establishes neither kernel enforcement nor successful SDK execution; its
original failed log and source pins remain retained during correction.
After the source correction, `trusted-boot-run2.json` records an actual child
SIGSYS with verified reap/group absence and joined actor workers, but no valid
trusted response. This is failed startup with observed cleanup, not kernel
compatibility or SDK success. The bounded raw trace attributes that failure to
`capget`; it does not show a successful capability query. The host's configured
core handler is a pipe, for which Linux ignores `RLIMIT_CORE` (see
[core(5)](https://man7.org/linux/man-pages/man5/core.5.html)). Post-exec nondump
protection, prevention of an exec-based reset and a trusted readiness check
before sending caller source remain required; `CORE=0` alone is insufficient.
The subsequent fixed guarded startup (`guarded-trusted-boot-run1.json`, SHA256
`ea5de88048b2b438914091bfa84288eb9fcde512c0fd0c998249b1815a0688f8`)
also failed: test exit 101, child SIGSYS before the parent accepted startup,
no caller source sent, and observed reap/group absence with zero captured stderr.
The original log SHA256 is
`947be661dfd949e5711bc64cb56c342d8f03b42364126ebdae0298177f850cd3`.
Its triggering syscall is not established by that result; it does not prove
successful guarded startup, SDK validation or failure of a supplied workflow.
The separate `guarded-boot-trace1.json` (SHA256
`0f7068e04515599025c472a3209215042fe551056c84671fee2e5577d9ad9c8b`)
captured test exit 101 after an actual 21-byte guard acknowledgement. Its raw
trace (SHA256 `1f6ad6363300f1f554a3dc79ef2661179a8661f1b78a511bb146969f64b55971`)
attributes SIGSYS to a later self `prlimit64` NOFILE setter; the child was reaped
and its group absent. This traced attempt does not establish the earlier
untraced child's acknowledgement phase. Tightening the exact-image NOFILE
soft/hard pair to 1024/1024 preserves setter denial and generic sandbox limits.
The corrected fixed boot (`guarded-trusted-boot-run2.json`, SHA256
`b8afca75c426be433fdc95ad8ad0fb2cfb2d6cab9d53b7104dd0c6c6cedb08b4`)
still failed: test exit 101, natural child exit 13 without a signal, 268 stderr
bytes counted but not retained as content, no valid response, and observed
reap/group absence with joined workers and no forced signals. Guard readiness
was accepted in that attempt. The cause of exit 13 remains unproven; successful
startup, synchronous interruption and SDK assessment remain unverified.
The subsequent fixed-fixture stderr diagnostic preserved the complete 268-byte
message: OpenSSL could not open `/etc/ssl/openssl.cnf` because permission was
denied. `trusted-boot-stderr-diagnostic1.log` SHA256
`20d048ba37eed6d35c7bb5efff3f38a3835846d0f0b192a608bb9d249a25fe2d`
and its JSON SHA256
`8ae77af738352f5690b8d9a93147a13970944813c8a8a23fc0fd47dd3697101d`
retain readiness accepted, natural child exit 13, no response, and observed
reap/group absence without forced signals. The diagnostic test exited zero
because capture and cleanup succeeded; it explicitly records
`bootAcceptance:not_assessed`. This proves the ambient OpenSSL configuration
dependency for this attempt, not successful boot or a retroactive diagnosis of
all earlier failures. The separately pinned inert configuration subsequently
passed source, package-data and narrow contract checks. Its one fixed boot
attempt still failed (`owned-config-trusted-boot-run1.log`, SHA256
`ccbaa6a215d39f9b61b399fb67b970aa36cdd9443157ba4c1b70974fee7ce04c`;
JSON SHA256 `70e72d838e1946b71ba2b3671021da9c0d13e2540733ba387750fad506e4fafc`).
The test exited 101, the child received SIGSYS 31 with zero stderr, and reap
and group absence were observed without TERM/KILL. No valid response was
received; the rejected syscall is not yet identified. This new failure does
not establish the phase or cause of older attempts. Access to the mutable
system configuration remains denied, and SDK execution remains unverified.
The separate raw attribution attempt (`owned-config-boot-trace-v1.raw`, SHA256
`0397af1f7e527200341c1c9343a7b82b9ff73048a07fd45486eced75fac716cc`)
then observed syscall 425, `io_uring_setup`, immediately before SIGSYS. The
printed `0x1a9` is the syscall number, not a successful ring descriptor. Its
test still failed, with actual reap/group absence and no forced signals;
the traced launch/acknowledgement failure is not the same observed phase as
the earlier untraced request failure. A source-reviewed exact-image correction
returns EPERM without executing ring creation; enter/register remain killed,
and generic policy is unchanged. All 22 exact-image filter tests subsequently
passed, including that denial, and strict sandbox-library Clippy passed.
The next fixed boot still failed (`owned-config-trusted-boot-harness5-run1.log`,
SHA256 `1814daec1d59a6f96f1aa221a12aff46ded94cd75524e253bca9381228958ea8`;
JSON SHA256 `b1c1289993e460e97a6c729f6a2afbc0f0fe2ecb6f92ce0deadca6535329b0db`):
natural child exit 1, no signal, 786 non-truncated stderr bytes counted without
text, malformed stdout and failed launch/acknowledgement admission. Actual
reap/group absence and actor/IO joins were known without forced signals. Its
stderr text was not preserved in that attempt. The separate bounded diagnostic
(`harness5-stderr-diagnostic1.log`, SHA256
`ffd59650c61a86b9ed95eb10925462da8414a8c24da5f82b5da6940d852cc395`;
JSON SHA256 `76b24eeb343cc4cb96b7ba719dca0d22b8dcbf42244deeb515f770cbed5d3c3b`)
captured its own 786 bytes completely: Node reported `open EPERM` while opening
stdin. Capture passed; boot did not. The subsequent raw-only stdio trace
(`harness5-stdio-trace1.raw`, SHA256
`217d38be15df99a758b8e931a17e7e332258126057de54b35d39209eeaec0c39`;
JSON SHA256 `d90df58a837b38c440f490d684c4dc6e508e9f91f7a78bd8a5acb4b9907d6c10`)
observed the child call `ioctl(0, 0x5421, pointer)` and receive EPERM after its
owned pipes were duplicated onto standard descriptors. Pointer contents were
not decoded. That test still exited 101, with natural child exit 1 and actual
reap/group absence without forced signals. These are distinct attempts, not
reconstruction of the first missing stderr. No successful startup, SDK or
canary result is inferred.
A subsequent source-reviewed exact-image correction admits only canonical
standard-descriptor numbers 0–2 with request `FIONBIO` (`0x5421`); descriptor
and request high-word aliases and all other ioctl requests are refused. This
changes nonblocking state, comparable to the already admitted restricted
`F_SETFL`, and does not prove permanent pipe identity after descriptor rebinding.
Architecture, network, device and generic-profile restrictions are unchanged.
All 23 exact-image filter tests, strict sandbox-library Clippy and scoped
formatting passed. The separately copied harness6 then passed one fixed
guarded trusted-Node startup (`owned-config-trusted-boot-harness6-run1.log`,
SHA256 `59c72ff3e95442bc1c3aec59927bc7bd286b893f621d06aa3229786f127cac1a`;
JSON SHA256 `7dcf787f8d801c99a449ee009753dbac10dd8baa83583ed552806044202940e1`).
The original records an exact reply, natural child exit 0, no signal, no
failure, zero stderr and verified actor/IO joins, reap and group absence,
without TERM/KILL. Independent primary-output review confirmed this narrow
startup result. It does not prove SDK evaluation or adversarial boundaries.
Before running the boundary group, source review found its existing stdout
assertion unsatisfiable: bytes after a valid first frame trigger the stricter
one-frame rejection before the byte cap. A test-only correction separated
trailing data from an oversized first frame; the production prefix remained
identical, and scoped formatting, strict host Clippy with test targets and
compile-only checks passed.
The resulting ten-case group stopped at its sixth case
(`guarded-canaries-harness6-run1.log`, SHA256
`5d5dc4ed2db7ad867c491bcbb8a30781ca739ab1e667af4b8219a8476bbe11ec`;
JSON SHA256 `edaa386f2c171a352f21435e67dbb6ebb8f6c7bd0f06542a2834b53e3ec29647`;
raw trace SHA256 `7e96ed18989f604c7c83e4a55ba7811745c372b011532ac91f1edfc9d6f34349`).
The first five cases proved private-file denial, absent synthetic environment,
closed inherited fd99, and SIGSYS at attempted socket creation and non-thread
clone, with primary actor/IO joins, reap and group absence. Raw `0x29` and
`0x38` are syscall numbers in those killed calls, not successful effects.
The timer case failed teardown with `IdentityMismatch`; its primary completion
and joins were not established. Memory and all three output-boundary cases
were not run, and the final fd99 assertion was not reached. Later process
absence and traced SIGKILL do not repair that missing proof. Review identified
an incompatible source dependency: live teardown reinspects `/proc/PID/exe`
after the guard disables dumpability. The actual failed read/errno was not
captured, so that historical cause remains a hypothesis. The narrow sealed
exact-image correction now retains the admitted image/guard and direct-child
pidfd, consumes the owned ACK/EOF internally before exposing stdin, and avoids
live executable reinspection only for that fixed guarded profile. Generic
identity checks and kernel/resource rules are unchanged. Frozen source/pure
review (`msg_ac4889a61271`) and the copied harness identity
`guarded-lifecycle-harness1-identity.json` SHA256
`d07e356c474ab8da4774a2cc65abec3d0e63ab761abb19bf37395797188ad851`
remain distinct from physical evidence. One subsequent fixed interval-timer
test passed: `guarded-lifecycle-timer-run1.log` (717 bytes, SHA256
`5761c4c9850d547d2b495e7449b675a8a280b210daeae1c9b96479664f258adc`),
result JSON SHA256
`59cdaceea81d99a0043cf89c19d419311b3f4f12009f573d39a270466e94dd90`.
The original five-second deadline produced `Deadline`, actual SIGTERM 15,
reap/group absence, zero stderr and successful stdio/watchdog/actor joins;
the lifecycle measured 5.220445487 seconds including teardown. All 50 held
input pins were preserved; independent primary review is
`msg_4816d32a9192`. This does not repair historical joins, resolve the generic
actor failure or prove synchronous busy-loop interruption, the remaining four
boundary cases or SDK assessment. A separate remaining-boundary group then
stopped at its first memory case: `guarded-boundaries-run1.log` (1,203 bytes,
SHA256 `19b5a2f003096544787e7966836311fa62f819e06a7f9f7c00d49254f130f3b8`),
result SHA256 `e047b676b10be7c352230fc391a59285f2d7cab82637eb8b3a98a2718dc4a69a`.
The child exited with SIGABRT 6 after 428.503982 ms, with `MalformedStdout`
and 1,554 untruncated stderr bytes; the expected caught allocation-refusal
reply was absent. Successful `finish` established primary reap/group absence
and all joins, but stderr text was not captured, so the abort cause is unknown.
The test failed with exit 101; the three output cases and synchronous busy loop
were not reached. All 54 held pins remained unchanged; independent primary
review is `msg_16b597918d0d`. No retry or memory-boundary success is inferred.
A separately scoped fixed-memory diagnostic then retained all 1,556 stderr
bytes and identified a V8 fatal semi-space allocation failure / JavaScript
heap out of memory in that new run (`guarded-memory-diagnostic-run1.log`,
SHA256 `0b4ed8bd08763ea3579e82ab1c57496d0741995c9595e2d1c71d9f9ce9358543`;
result `c55901b1a4c8051c54458e82d3ab43c7a410e69d635fe6d61628876df56a9e0a`).
Diagnostic capture passed with SIGABRT and known cleanup; caught allocation
refusal, the causal kernel limit, measured RSS and the historical abort cause
remain unproved (`msg_504e63ff6f77`). A separate four-fixture group passed
(`guarded-output-boundaries-run1.log`, SHA256
`4488f223837bc516f90a4a44d9abf9a7c2c34a99a162a5951d90ca9beda12543`;
result `0a61f6e577964ff3fcceece0c22dd754ac50d48710c7c0217c3db491627debca`).
It distinguished trailing-frame rejection, oversized-first-frame rejection
and stderr overflow (8,192 bytes, truncated), then interrupted an armed
synchronous loop by the original one-second wall deadline: actual SIGTERM 15
at 1.206254793 seconds, before the five-second CPU soft limit. Each case had
primary reap/group absence and all joins; all 53 held pins were preserved
(`msg_7f2e503e88f1`). These fixed fixtures do not prove full SDK assessment.
A subsequent real `.assess` invocation with the full SDK bundle and a sealed
synthetic signed fixture failed on its first benign source: actual SIGSYS 31,
zero stderr, malformed stdout, primary reap and group absence confirmed.
The invalid and unknown-type cases were not run. The syscall cause is not
established by that result (`guarded-sdk-assess-run1.log`, SHA256
`8fb683f45baf2bfae472c48d672e9e17da859a05a07a2344457eb0e379f9e02d`;
result `e88a89fcb7dcd8f89bb54e5d1c0a9135d40398d32a992b8f76691c6b90b28810`).
All 57 held input pins were preserved; this is a failed local assessment,
not installed SDK acceptance or proof of production package authority.
A separate bounded raw-only trace preserved all 60 expanded pins and again
failed with known primary cleanup. It observed the guard's 21-byte ACK, then
`sched_getparam` (x86-64 syscall 143) on the calling child thread, which the
initial filter's default kill rule rejected. Nearby `mmap` ENOMEM results do
not establish the cause of that call or the earlier untraced failure. The
2,731,732-byte trace is `sdk-assess-trace1.raw`, SHA256
`b977bb8443ffd21793251c9a4095db42142b0725a6743b2d61113a0088ce819b`;
result `87ecd085b0287beaa6693ddf4cba497edfc6bfc27caf7adb5031d45b34718291`.
The resulting local correction returns EPERM for exactly scheduler queries
143/145 in guarded mode without executing either syscall; unguarded kills,
scheduler setters and all other access/resource guards remain unchanged.
Source `linux.rs` SHA256
`4b3d5199b6b4c7a86eb6c93ca20174a279c11619914214126259b49289daacf7`
passed 24 selected exact-image tests; the rebuilt host passed three retained pure tests,
formatting and strict production-library Clippy. Broader test-target Clippy
still failed on five independently verified unchanged HEAD test contexts.
The subsequent real assessment still failed on the first benign source,
now with SIGABRT 6 and 1,022 untruncated stderr bytes, known primary cleanup
and 67 preserved input pins. Its stderr text was not captured, so the abort
cause remains unknown; invalid/unknown cases were not run
(`guarded-sdk-assess-run2.log`, SHA256
`920665a40bd24365d8b420b67d6c7b6b34a79a57013ceabb360f7ffd0f7ad0ac`;
result `18b3dce8d051f5cc9f0e810d0bd5ecaf24fac17eea0ce2a11cb97da0b4ddcb24`;
independent readout `msg_3c55ec401372`). Further SDK-candidate expansion is
frozen under the owner clarification; no later diagnostic was launched.
Source and local evidence are under
`autonomous1/source-checks/remaining-sdk1` and `native-sdk-adapter`; signing,
installation and installed acceptance are separate gates.

#### .35 read-parity implementation matrix — source checkpoint 2026-10-04

The original source checkpoint below is historical, not whole-feature closure.
Current row-specific acceptance is explicitly marked `4c39` below; it does not
upgrade the other rows or their unsupported submodes. The original installed
baseline was RC43c `09cebc4`; the first candidate source was committed as `537b8451`
(README `3168d9c4`, coordinator snapshot `138057a5`). The following useful
workflow-scenario delta is still under source review. Native
catalog/source discovery proves availability and shapes, not a successful
admitted invocation. Tests below are local source tests unless explicitly
identified as retained installed evidence. All new official read actions need
separate signed schema/profile and runtime admission before installed use.

The installed local n8n-mcp 2.91.0 already provides node/template knowledge
and validation of a ready JSON graph. Owner decision `msg_55b170751bf1`
withdraws the experimental SDK executor and native n8n patches; `.44` removes
their source hooks, advertised inputs and SDK-only artifacts without archival.
The checked `sdk_reference` documentation action and sensitive Code-node reads
remain separate features. Provider limitations stay explicit; all other
unproved FCP and authority gates remain. The global observer in the separate
runtime worktree and instance-audit extension are paused, not bundled into this
cleanup or automatically included in a release.

| Required row / submodes | Installed baseline | Candidate route and bounded result | Evidence / remaining boundary |
|---|---|---|---|
| `capabilities.inspect` | Retained EEC/Hetzner catalogs contain 53 tools | Fixed official `tools/list`, bounded name/schema-digest projection; every discovery entry remains unreviewed | `initial-installed-eec-catalog-20261004.json` and Hetzner counterpart; `official_mcp_catalog_*` and schema-export tests cover presence/drift/redaction, not admission or successful invocation of discovered tools |
| `targets.resolve`: exact URI/server, names and ambiguity | Needs installed public-path validation | Canonical URI plus typed existence reads; exact project/workflow name matching over complete unsaturated native snapshots; one shared deadline and exact server/project/resource bindings | `public_targets_*`, `public_target_name_lookup_*`, `public_project_name_lookup_*`; name search native-shaped bridge projection passes the actual wrapper decoder. Installed new-source acceptance remains open |
| `runtime.status` | Host-local observer and controlled two-CLI comparisons checked; installed owner route OPEN | Retained original invocation authority plus independent scoped read authorization; pending/stale/unretained observations are unknown, and idle requires actual owned teardown. Bounded registry saturation does not block the underlying read | Earlier `remaining-runtime2-ctx_177b2c79271e` component evidence remains historical. The explicit-token `runtime-unknown-ctx_98590ebcb0b3/blake3-opt3-diagnostic-run1.log` and no-caller-token `runtime-no-cwt-ctx_6b65518aaf29/no-cwt-diagnostic-run1.log` prove scoped active/idle/unknown through separate private CLI processes with original deadlines and known actor/server cleanup. The missing-correlation regression and later seven-file managed-route source fixes passed 18 selected tests and scoped checks (`msg_95d01a84ca84`; primary `managed-*-ctx_5813827b9c7f-*` logs). Aggregate physical coverage is still OPEN: the prospective distinct-UID profile has no compatible credential-transition, current-image and cross-UID teardown implementation. A separate trusted same-UID design is only conditional proposal data (`msg_170e692be9fe`), not an equivalent isolation claim or admitted fallback. Installed role/admission/activation and global observations remain OPEN |
| Knowledge: tool documentation, node search, templates search/get | CHECKED installed `4c39` local process: standard `get_node` tool documentation, one `webhook` search limited to three rows, one keyword template page and its dependent `nodes_only` read | Fixed local tools, bounded action-specific projection, source/default digests; combined template selectors intersect complete native subsets before paging | `knowledge-continuation1/continuation2/result.json` and `knowledge-templates1/result.json` below prove these exact four public actions; inventory completeness, other selectors/pages and template modes remain open. `combined_template_*` controlled nonempty intersection and fixed-call tests remain local evidence; oversized native subset refusal is distinct from positive installed acceptance |
| `get_node`: info/docs/search_properties/versions/compare/breaking/migrations | CHECKED installed `4c39` local process: HTTP Request info/full, authentication search_properties/full, migrations 3→4.5; other modes retain scoped prior evidence | Full info returns 42 properties, 32 with display options; full property search returns one match; migration result preserves `migrationStrategy`, pair and availability | `local-result.json` below plus `public_get_node_seven_modes_project_serialized_catalog_without_transport_or_values`, `node_catalog_conditions_*`. This fixes the prior full-info acceptance failure for this exact fixture; historical requested-version restrictions remain open |
| SDK reference: all nine public sections; best practices | CHECKED installed `4c39`: all nine reference sections and the 12 documented best-practice techniques on EEC; `patterns` and technique `list` independently on Hetzner as well | Ordinary public CLI → typed official MCP route; nonempty reference/guidance with domain-separated digest and exact selector. These actions use the remote official provider, not local knowledge | Results `261f4781…` and `beaacbbf…` below retain the exact section/technique originals. Five techniques explicitly lack detailed native documentation and are not claimed; remaining Hetzner sections/techniques are not separately installed-tested; native extra `groups` is not enrolled |
| Validation: graph, four profiles | CHECKED installed `4c39`: minimal, ai-friendly and strict on the same nonempty synthetic graph; runtime retains the accepted earlier installed evidence | Fixed network-disabled local validator; exact graph/layout/package/profile bindings and native diagnostic originals. Minimal is complete; ai-friendly/strict retain an unclassified warning and honest incomplete status | `graph-profiles1/continuation1/result.json` SHA256 `353851f710055374384bd07de6b17fc05aaa46b51f83a98ba9dff0bd0362aeb3`, independent `msg_3c55ec401372`: three known-zero processes, 24 pins and signed current preserved; two schemas validated. The parent zero-call precheck failure/current proofs NULL remain historical. This is one fixture per selected profile, not all-input or deployed-schema parity |
| Validation: nodes 1–50/version/subnodes | CHECKED installed `4c39` on EEC and Hetzner: one synthetic Set node, version 3.4, empty parameters | Ordinary public CLI → fixed remote `validate_node_config`; native-default result `valid:true`, zero errors/warnings, no node/workflow execution | Only the one-node native-default fixture is installed acceptance. Counts/version/subnode boundaries retain local tests; unsupported profiles are not simulated. Public errors are deliberately generic/redacted, not retained original native error text |
| Withdrawn: workflow_code | Removed from required scope by owner; never accepted installed | `.44` retires local SDK hooks and inherited remote refusal stubs, not JSON graph validation or SDK documentation | Historical FAIL/UNKNOWN above remain facts, not SDK success. Source retirement and exact SDK-only file deletion are cleanup work, not a fulfilled validation feature |
| Validation: remote_workflow/current draft or published, four profiles | Missing installed public composition | One exact REST GET captured privately; ID/version/digest bound; same selected graph validated by signed local provider with shared deadline/cancel/teardown | `remote_workflow_public_target_*`, `remote_validation_capture_*`, actual ignored local four-profile test; new runtime admission required; historical versions excluded |
| Structure: projects/folders/tags | CHECKED installed `4c39`, separately on EEC and Hetzner, one public row per kind | Fixed official reads; folders project derived only from the actual single returned project. Exact server/resource and folder `parentUri` bindings verified | Both servers return nonempty project/folder/tag pages; folder totals 24/42, tag totals 1/8. One page is not the whole catalog; further cursor pages and additional selectors are not inferred. Native caps 100/100/500 and truncation refusal remain |
| Workflows search: filters/page/sort | REST cannot supply folder/global sort equivalence | Fixed official native search for query/project/folder/tags/sort, complete snapshot before public paging/active filtering | `official_workflow_search_native_query_is_not_replaced_with_page_local_name_filter`; cap 200 and archived search remain explicit capability limits |
| Workflows get: draft/published/both, detail/includeCode | Exact legacy state read exists; new public selectors unproved | Native GET with activeVersion; bounded selected graphs and metadata Code fingerprints. `includeCode:true` routes before admission to distinct pinned `workflows.get_code` / `workflows.code.read`; installed operation and rights remain OPEN | `current_workflow_read_native_active_version_redacts_both_graphs`, `current_workflow_read_public_defaults_and_comparison_binding`, `get_code_production_projection_is_exact_pinned_and_sensitive`, `include_code_routes_before_authoritative_envelope_and_binds_every_pin`, `get_code_original_child_sensitive_authority_and_pins`; actual diagnostic CLI refusal is separate from callback/process fixtures |
| Draft/published compare: semantic/layout/validation | New public composition missing | Same single GET crossbinds both graphs; semantic/layout digests; two owned local validations; no public raw graph | `captured_comparison_graphs` tests and retained native local comparison test; missing published/validator failure is limited outcome, not empty success |
| Executions search/get metadata | Existing metadata routes; new filter parity needs validation | Native workflow/time/status pushdown; running explicitly requested/merged; queryless exact metadata GET, no execution payload | Six `metadata_*` HTTP tests passed; wrong workflow denied; payload/history/rollback remain outside .35 |
| Credentials list query/type/project/sharing/limit | REST lacks required official metadata; installed direct FCP mapping absent | Unchanged official metadata tool, limit1–200, count=returned, continuation unavailable and completeness not established. No synthetic cursor or native extension | `.44` removes bounded-v1 and snapshot-only mechanisms. Earlier local experiments do not prove the simplified route or installed acceptance. Remaining FCP mapping admission and installed acceptance stay OPEN; a limit-sized response requires a visible bound and narrower-filter guidance |
| Audit credentials/database/filesystem/nodes/instance | Source-proved fixed native POST, no installed audit invocation | Four local-read categories retain their capability; instance requests route to distinct `audit.inspect_instance` / `audit.instance.read` before admission. Safe static findings/counts only, always `fullAudit:false` | Local projection, CLI and loopback capability tests passed; reviewed actor/proxy/original-deadline and malformed-location corrections passed focused checks. Shared pending-HTTP tests prove cancellation/owned teardown, not native audit duration or DB-query cancellation. Instance version-service effects and all installed audit admission remain OPEN |

**Installed local knowledge continuation, 2026-10-15:** under
`/srv/dev-ssd/fcp/nqm81-35/execution-metadata-acceptance-20261014-1/autonomous1/knowledge-continuation1/continuation2/`,
`result.json` SHA256
`e3cea25734fca400613c624edd1430f13664002ad924cf5adaf14309625dbaa8`
records two ordinary installed `4c39` local knowledge calls. Original
`documentation.stdout` (1,016 bytes, SHA256
`577e9a76dcf75c03b6e498a4de9f2e2d997e4c777afc33cf4bce1e5f398cb2b0`)
contains 818 bytes of nonempty `get_node` documentation with its checked plain
SHA256 text binding. `node-search.stdout` (587 bytes, SHA256
`e2634ba5c5b2683f1504649e1114acfa48fbd7dbc9cba74ecec14daf9d160900`)
contains three unique metadata rows for the bounded `webhook` query, with exact
canonical local node URIs; no ranking or full-catalog claim follows. Both
processes have known exit 0, joined IO, absent owned groups and zero stderr.
Signed-current before/after remains `4c39` / receipt `66403a8d…`; the scoped
24-file closure is preserved. Three source rows use exact installed-source Git
blob snapshots rather than changed task files. The parent attempt's zero-call
`fixed_signing_guard` precheck failure and missing current proofs remain intact.
Independent primary-output review: `msg_1bda92b1f6a1`; synthetic interpretation
checks remain separate evidence. No workflow/node execution or remote call is
claimed by these two source-bound local routes.

**Installed template continuation:** sibling `knowledge-templates1/result.json`
SHA256 `163d367af0e7891a0c3a993c16edd7ed1a446ee362421db82d0d43c91aa7498e`
records the additional two-call local group. The exact `Asynchronous` keyword
query requested limit 1 / offset 0. Original `search.stdout` (2,317 bytes,
SHA256 `f1ffeea48f4cf583ca8a9d7bfc929279c2a4ca8044ecc209d990676ce17da284`)
returned template 4275, query-local total 28 and `hasMore:true`. Its actual
ID/name/URI bound the following `nodes_only` request; original `get.stdout`
(1,668 bytes, SHA256
`f935dc849861c1191a641499b852f52a1f4118c45e958d3a88177b4a515a92f9`)
contains 20 name/type-only node records, with no parameters, code or graph.
Optional parameter digests were absent; the template digest's native source
preimage was not retained for independent recomputation. Both processes have
known exit 0, joined IO, absent groups, zero stderr and no retry; scoped 24 pins
and signed-current before/after match the preceding release. Independent
primary-output review: `msg_18d34503021b`. This is one keyword page and one
metadata mode, not FTS/LIKE equivalence, a full catalog or template execution.

**Installed v7 acceptance, 2026-10-15:** release
`release-20261014-read-parity-4c39cbe7-rc1`, source `4c39cbe7`, signed receipt
BLAKE3 `66403a8dbd49a7e0fc12873653432b31d2363f9b1bdc5efb7cf9673c7851200a`.
Primary requests and bounded original public responses are under
`/srv/dev-ssd/fcp/nqm81-35/execution-metadata-acceptance-20261014-1/autonomous1/v7-acceptance1/`.
The initial EEC project process succeeded; its capture group stopped on a local
incorrect `page.limit` expectation. That failed result and `current_after:null`
remain unchanged. Correct interpretation reused the saved 405-byte response
SHA256 `408dea94c638c2d18b798fe7f2a553ad74decac701aa9de628989513396495bc`
without repeating the call. `continuation1/eec-result.json` SHA256
`78e8580dc852633e48191e033576cf75232eede014b239c1723c4b73320569cf`
records the remaining five calls; `continuation1/hetzner-result.json` SHA256
`dd76187a58aad718f49ebf659c41078afb97b10703afc4bbcc3616d7774d6dae`
records six calls. All twelve actual processes completed known exit0 with group
absence, joined IO, empty stderr and no retry. Each continuation's current
before/after agrees and its 24 held installed/tool inputs are preserved; this
does not retroactively fill the first group's null proof or establish global
continuous stability. SDK/nodes server binding comes from the fixed request and
typed host decoder; public results do not expose a `serverId` field. This is
narrow installed/live acceptance, not global idle, business validity or `.35`
closure. UBS remains NON_GREEN with its retained scoped dispositions.

The same directory's `local-result.json` SHA256
`650ce2be736be98728395d1d38ced7b4c3becdd782bf38aff89a10a9eab3924f`
records three additional network-disabled local knowledge calls, all known
exit0 with joined IO/group absence, preserved held24 and identical current
proofs. Full-info original SHA256
`30ee61f1113bce90e735cd064f15b5438ca98298ad470e80ac573e011f97039f`
and migration original SHA256
`ecc7351b8ea817d8a8dfaacee9920f80ee00eb293bdcb32b40e649fa9baede03`
are retained without claiming remote validation or node execution.

**Additional reference acceptance:**
`autonomous1/knowledge-sections1/continuation1/result.json`, SHA256
`261f478192b5932e253cfb2e1806f889abe5f3b9168d0b9d14bb1eacc0fbd4f2`,
retains eight EEC reads for the other named SDK sections, each known exit0,
joined IO/group absence and empty stderr. The originals, selector/content
digests and current equality were independently reviewed. The 24 held inputs
include three source snapshots byte-equal to installed-source Git `4c39cbe7`,
replacing mutable task-source paths; their new metadata is not historical inode
or timestamp equality. The preceding zero-call precheck failure and null current
proof remain unchanged. This adds EEC reference coverage, not SDK execution,
Hetzner section coverage or all best-practice techniques.

`autonomous1/knowledge-sections1/techniques1/result.json`, SHA256
`beaacbbff98db0f6ffefac0f0860560a2751bfc16325e8df142e8e569d7fb93b`,
adds 12 EEC detailed-guidance reads selected from the retained native technique
list. All 12 originals (87367 bytes collectively), exact request selectors,
domain-separated content digests and process records were independently checked:
known exit0, joined IO/group absence, empty stderr and no retry. The current
proofs agree and all 24 held inputs were preserved. The native list names 17
techniques but marks monitoring, enrichment, data_analysis, knowledge_base and
human_in_the_loop as lacking detailed documentation; those five were not probed
or counted as successful guidance. Guidance sample code was returned as text,
never executed. This is EEC installed static-knowledge evidence, not Hetzner
technique coverage, SDK validation or workflow execution.

History/rollback (.36), external credential lookup (.39), execution payload (.40)
and authoring (.42) are not implemented or accepted by this matrix. Existing
remote upgrades, signed RC43c and .34 acceptance remain historical facts, not
proof that this candidate is installed. Open rows prevent whole-.35 closure.

Required submode boundaries remain **OPEN**, rather than implicit capability
exclusions:

- `targets.resolve` now performs bounded exact provider-existence reads in
  candidate source, including exact project/workflow names and project-to-workflow
  mapping. Installed acceptance is not established. A saturated 100-project or
  200-workflow result cannot prove
  completeness and refuses rather than returning a false missing result.
- `get_node` compare/breaking/migrations bind native numeric `fromVersion` and
  `toVersion` and expose `available:false` honestly. Missing native version
  metadata leaves that pair unverified. Optional `version` for standard/full
  info binds both the returned native definition and current-version summary;
  coercion, unknown or mismatched versions refuse. The native tool has no info
  version selector: historical requested versions, docs/search_properties and
  minimal info remain OPEN rather than forwarding unsupported arguments.
- Workflow `active` filtering requires a complete native snapshot first.
  `isArchived:true` is refused. Continuation beyond the native 200-workflow
  bound is unsupported; a saturated result of exactly 200 rows is refused
  even when the native count equals the returned length. No per-page
  sort/filter is claimed as global parity.
- Local source adds `workflows.get_code` under distinct
  `n8n.workflows.code.read` authority. Public `workflows.get includeCode:true`
  routes to it before the authoritative envelope, capability acquisition and
  host admission. False/absent retain metadata fingerprints; null/nonboolean
  selectors and direct metadata invocation with true refuse before HTTP.
  Each selected draft/published label requires an exact version ID and graph
  digest in the original resource and request. One fixed REST GET must match
  both before any source is projected. Only selected Code node ID, language,
  source and digest are returned; credentials, other parameters, pin/static
  data are omitted. Source is sensitive output, not a scrub-safe diagnostic.
  Code language/source consistency follows the retained native Code node
  source (`upgrade-target-code-node.ts`, SHA256 `26b388bc93387613253e8f00ab3ea9c3f7ad874577586afdb152c1211d8f6543`):
  versions 1/2, JavaScript default, version-2 Python/legacy Python selectors.
  Unknown versions/selectors and missing/nonstring active source refuse;
  retained inactive-language source is omitted. Bounds are 100
  Code nodes per selected version, 300000 UTF-8 source bytes per node, 600000
  collectively and 4000000 bytes in the complete serialized projection.
  The measured full descriptor is 65607 bytes; n8n's finite descriptor frame is
  128KiB and only `get_code` has a 4MiB frame, with the original deadline.
  Other connectors retain their existing ceilings. Installed operation,
  signed inventory and code-read rights admission remain OPEN.
- Combined template-search selectors use 2–4 fixed sequential calls under the
  existing policy and intersect only complete subsets, each bounded at 100.
  Native frame overflow and incomplete subsets refuse; no limit is raised.
  `local_twenty_node_queries_qualify_proposed_policy_without_activation` runs
  20 bounded synthetic queries through the real network-disabled process using
  an explicitly proposed in-memory max20 policy; network/timeout/size fields
  stay identical. The unchanged seven-call policy refuses before launch.
  This proposed call-limit change is not signed-policy admission or activation.
  Producer commit `980b3c5661ee` retains seven calls by default and supports
  explicit SHA-bound, closed owner-managed input admitting exactly 20 at
  `scripts/n8n_release_assembler.sh` (`max_sequential_calls`). The local producer
  regression verifies default7 and opt-in20 through the signed-policy consumer;
  this does not admit or activate the proposed input in an installed release.
  No existing policy file was changed to qualify the process test.
- Original credential child qualification (2026-10-06): the dedicated
  `n8n-owned-credential-fixture` target reuses the original connector stdin
  configure/handshake/invoke loop and inherited host proxy. Fixed synthetic
  schemas are admitted only by its test constructor; ordinary main remains
  strict even with the test-support feature. The host performs original-token,
  server/resource/request, credential lease/profile and HTTP policy validation
  before its private test transport supplies a response. Exact filters,
  projection/redaction, schema/body/token rejection, replay/closed admission and
  owned reap/group absence pass in `credentials_original_child_inherited_transport`
  (`original-child-host-test-20261006-8.log`, both servers, eleven cases including
  Hetzner old-port refusal and expired-before-dispatch cases). This is actual child/process and
  controlled transport evidence, not installed CLI or live-schema acceptance.
  Retained catalog originals are still required for native production-pin tests.
- Native REST snapshot qualification uses genuine cursor pages and supported
  `projectId`/`active` pushdown; global sorting follows complete bounded
  collection. Its configured collective timer and aggregate byte limit are
  separate from original host invocation cancellation. Unsupported native
  folder/description/archived semantics and saturated official search still
  refuse, rather than returning false-complete pages.
- The earlier private sensitive-Code DTO fixture is historical partial evidence.
  The production route now has original-child controlled-HTTP qualification
  (`get_code_original_child_sensitive_authority_and_pins`) for both servers,
  draft/published/both, metadata omission, original capability/instance/resource/
  request/body binding and same-version graph drift. API-key profile, OAuth and
  absent credential-allow negatives prove zero HTTP and released leases.
  Provider response substitution is test-only after the original authorization
  and HTTP policy checks. It is not installed/live or full public CLI success.
  Optional signed producer input `code_read` is closed to exact operation
  `n8n.workflows.get_code` and capability `n8n.workflows.code.read`; absent input
  changes nothing, REST transport remains port443 and inventory enrollment
  alone grants no caller capability. Native producer/consumer and projection
  tests qualify local source only; no installed policy was activated.
- Direct-FCP bounded credential mediation and other supported read routes
  still need their own installed admission and acceptance. SDK execution and
  native continuation requirements are withdrawn by the owner, not completed.
  Global runtime observation and instance-audit development are paused; no
  source-only test closes admission or authorizes their activation.

#### Useful workflow scenario — controlled evidence and installed boundary

`controlled_workflow_scenario_native_validation_process` selects an exact
EEC/Hetzner workflow from a native-shaped official search projection, reads
draft/published through controlled HTTP, and detects semantic/layout changes.
The draft contains an ordinary Set node with a dangling connection; the
published graph is empty. The fixed installed network-disabled JSON validator
reports different validation results and validates the selected draft again.
Owned process reaping/group absence is asserted. Search/HTTP responses are
synthetic; the validator process is real, using the existing dev/test factory.
This is neither a signed candidate nor installed end-to-end CLI acceptance.
The test is explicitly ignored by default and must be run with `--ignored`.

The actual task CLI regression invokes all four remote operations for both
servers and requires `bundle_unavailable`: the executing artifact is not the
signed current executable. Graph validation has the same signed-artifact
boundary. No caller executable/key/policy override is provided. Missing
published is represented as null on get and refusal on compare; no empty
validation delta is treated as success. Primary logs are in the existing
`/srv/dev-ssd/fcp/nqm81-35` review packet.

After exact source/artifact/schema admission, the four read-only commands are:

```sh
# Explicit server: use eec, then repeat with hetzner. Never infer a server.
N8N_SERVER=eec
jq -nc --arg server "$N8N_SERVER" '{server_id:$server,deadline_ms:30000,input:{query:"Synthetic",active:true,sort:"updatedAt:desc",page:{limit:20}}}' |
  /usr/local/lib/fwc-n8n/current/bin/fwc-n8n run-once n8n.workflows.search
# Select one exact id from this bound result; do not guess it or use a name as id.
# Set N8N_WORKFLOW_ID and N8N_WORKFLOW_URI to that result's exact id/resourceUri.
# Both must refer to N8N_SERVER; missing/ambiguous results stop this preparation.
jq -nc --arg server "$N8N_SERVER" --arg id "$N8N_WORKFLOW_ID" '{server_id:$server,deadline_ms:30000,input:{id:$id,version:"both",detail:"full",includeCode:false}}' |
  /usr/local/lib/fwc-n8n/current/bin/fwc-n8n run-once n8n.workflows.get
jq -nc --arg server "$N8N_SERVER" --arg id "$N8N_WORKFLOW_ID" '{server_id:$server,deadline_ms:30000,input:{id:$id,leftVersion:"draft",rightVersion:"published"}}' |
  /usr/local/lib/fwc-n8n/current/bin/fwc-n8n run-once n8n.workflows.compare
jq -nc --arg server "$N8N_SERVER" --arg uri "$N8N_WORKFLOW_URI" '{server_id:$server,deadline_ms:30000,input:{subject:"remote_workflow",target:{resourceUri:$uri},version:"draft",profile:"runtime"}}' |
  /usr/local/lib/fwc-n8n/current/bin/fwc-n8n run-once n8n.validation.run
```

These commands are preparation, not executed installed acceptance. Before
one live decision, bind the reviewed candidate commit, all normal binary and
package hashes, signed receipt/public key, native search schemas/output
presence, broker server/resource permissions, and unchanged network-disabled
local policy. Run normal root prechecks/preflight before installation; do not
substitute the diagnostic CLI for current. Search saturation, unknown schema,
missing published, version/ID drift, validator failure or incomplete teardown
must stop the dependent scenario. Expected useful results are a bounded
selected workflow, exact current version pair, semantic/layout differences,
collected safe validation delta and selected-graph validation; none is claimed
for the uninstalled full scenario yet.

`knowledge.query.action` is one of:

- `tool_documentation { toolName }`;
- `search_nodes { queries[1..20], source?, includeExamples? }`;
- `get_node { nodeType, mode, detail?, propertyQuery?, version? }`;
- `search_templates { query?, nodeTypes?, task?, metadata?, page? }`;
- `get_template { templateId, mode }`;
- `sdk_reference { section }`;
- `workflow_best_practices { technique }`.

For `search_templates`, at least one of `query`, `nodeTypes`, `task`, or
`metadata` is required. `search_nodes.source`, when present, is `community` or
`verified`. `get_node.mode` is `info`, `docs`, `search_properties`, `versions`,
`compare`, `breaking`, or `migrations`; `detail` is `minimal`, `standard`, or
`full`. `get_template.mode` is `nodes_only`, `structure`, or `full`.
`sdk_reference.section` is `patterns`, `patterns_detailed`, `expressions`,
`functions`, `rules`, `import`, `guidelines`, `design`, or `all`.

Its action-specific outputs are exactly:

| Action | `data` output |
|---|---|
| `tool_documentation` | `{toolName,documentation,digest}` |
| `search_nodes` | `{nodes:[{resourceUri,nodeType,displayName,version?,source?,discriminators?,exampleCount?}]}` |
| `get_node` | `{node:{resourceUri,nodeType,version?,detail,definition?,documentation?,examples?,migrations?}}` |
| `search_templates` | `{templates:[{resourceUri,id,name,description?,nodeTypes?,metadata?}],page?}` |
| `get_template` | `{template:{resourceUri,id,name,mode,graph?,nodes?,digest}}` |
| `sdk_reference` | `{section,reference,digest}` |
| `workflow_best_practices` | `{technique,guidance,digest}` |

`structure.search.kind` is exactly `projects`, `folders`, or `tags`.
`workflows.search.sort` is one of `updatedAt:desc`, `updatedAt:asc`,
`createdAt:desc`, `createdAt:asc`, `name:asc`, or `name:desc`.

`validation.run.subject` is one of:

- `nodes`, with `nodes[1..50]` containing `name?`, `type`, `typeVersion?`,
  `parameters?`, `subnodes?`, and `isToolNode?`;
- `graph`, with a workflow graph and optional validation profile;
- `remote_workflow`, with an exact workflow target and version selector.

`validation.run.profile` is `minimal`, `runtime`, `ai_friendly`, or `strict`.
The default is `runtime`; provider-specific extra profiles cannot become public
without a contract revision.

`workflows.lifecycle.action` is exactly `publish` or `unpublish`; archive is a
separate typed `n8n.workflows.archive` operation, and activation/deactivation
is the separate typed `n8n.workflows.activate` REST operation. Restore/unarchive,
version operations, and execution cannot be represented as aliases here; each
provider action is fixed by its typed enum and route.

Lifecycle acceptance fixtures have a stricter provider-readiness requirement
than draft creation: the graph must contain at least one activation-eligible
trigger, webhook, or polling node on the target n8n deployment. A
`manualTrigger`-only graph may be created and inspected as a draft, but it must
not be used for publish/unpublish acceptance because n8n intentionally excludes
it from activation eligibility.

The provider path currently accepts `manual` only; `.25` accepted bounded runs
on both servers. Production `.26` is rejected before dispatch and test/preparation
`.41` remains planned v1 scope. Both modes require exact current-chat workflow,
version, input and side-effect approval plus a one-use UUID. The fixed provider
is owner-policy-bound official MCP `execute_workflow`; preserve version binding
locally and through independent readback without inventing provider `versionId`
or `wait` arguments. Per-server input/output schema bindings remain mandatory;
numeric package versions cannot replace them. Return a bounded execution handle
and verify it with a separate typed `n8n.executions.get`; started is not terminal
success. Planned opt-in detail `.40` cannot change metadata-only GET or diagnostics
defaults. `inputs.headers`
rejects authorization, cookie, proxy authorization, API-key, and other
credential-bearing headers; secrets must come from the workflow's existing
credential references, not model input.

For `executions.get`, the provider request remains queryless and the public
result is metadata-only. `executions.diagnostics` is the only execution
operation that enables `includeData=true`; it decodes only typed metadata,
workflow node names/types, and bounded run errors, discarding execution items,
credentials, headers/cookies/authorization, request/response bodies, binary,
pinData, and unknown fields before serialization.

Execution status filters are limited to `canceled`, `crashed`, `error`, `new`,
`running`, `success`, `unknown`, and `waiting`. Timestamps are RFC 3339 UTC.

`workflows.update_draft.operations` is a discriminated `oneOf` list. The exact
v1 operation set is:

| Type | Required fields | Optional fields |
|---|---|---|
| `updateNodeParameters` | `nodeName`, `parameters` | `replace=false` |
| `setNodeParameter` | `nodeName`, `path`, `value` | none |
| `addNode` | `node.name`, `node.type`, `node.typeVersion` | `node.id`, `parameters`, `position`, `credentials`, `disabled`, `notes` |
| `removeNode` | `nodeName` | none |
| `renameNode` | `oldName`, `newName` | none |
| `addConnection` | `source`, `target` | `sourceIndex=0`, `targetIndex=0`, `connectionType=main` |
| `removeConnection` | `source`, `target` | `sourceIndex=0`, `targetIndex=0`, `connectionType=main` |
| `setNodeCredential` | `nodeName`, `credentialKey`, `credentialId` | `credentialName` |
| `setNodePosition` | `nodeName`, `position[x,y]` | none |
| `setNodeDisabled` | `nodeName`, `disabled` | none |
| `setNodeSettings` | `nodeName`, non-empty `settings` | none |
| `setWorkflowMetadata` | at least one of `name`, `description` | none |

`path` is an RFC 6901 JSON Pointer and cannot index into arrays. Node settings
are limited to `onError`, `retryOnFail`, `maxTries` (2-5),
`waitBetweenTries` (0-5000 ms), `alwaysOutputData`, and `executeOnce`.
Operation batches are atomic at the public contract: if the selected provider
cannot guarantee atomicity, the route is unavailable rather than emulated with
partial writes.

`setNodeCredential` binds an existing credential reference; it does not mutate
the credential object. The exact credential ID must appear in the approved
semantic diff. Provider-side automatic credential assignment is forbidden. If
an official MCP create/update tool may auto-assign a credential and offers no
way to disable or constrain that behavior, that provider route fails closed for
the proposed graph.

`workflows.versions.action` is `list`, `get`, or `rollback` in v1. `list` and
`get` are Safe/Low/None with no approval. `rollback` is Risky/High/BestEffort
with interactive approval and full workflow readback. `delete` and `prune` are
future-only and return `FCP-N8N-1401 future_only_operation`.

`data_tables.mutate.action` is `create_table`, `add_column`, `rename_column`,
`rename_table`, or `add_rows` in v1. These are Risky/Medium or High,
BestEffort, and interactive. `delete_column`, row deletion, and table deletion
are future-only because strict recovery/idempotency is not yet defined.

The exact additive data-table payloads are:

| Action | Required action payload | Constraints |
|---|---|---|
| `create_table` | `projectId`, `name`, `columns[{name,type}]` | name 1-128; at least one column |
| `add_column` | `projectId`, `dataTableId`, `name`, `type` | column name pattern `^[A-Za-z][A-Za-z0-9_]{0,62}$` |
| `rename_column` | `projectId`, `dataTableId`, `columnId`, `name` | same column-name pattern |
| `rename_table` | `projectId`, `dataTableId`, `name` | name 1-128 and unique in project |
| `add_rows` | `projectId`, `dataTableId`, `rows[1..1000]` | values are string, number, boolean, or null |

Column `type` is exactly `string`, `number`, `boolean`, or `date`. Row content
is untrusted and may contain personal data; it is never copied into telemetry,
receipts, or ClickUp.

`evaluations.manage.action` is `list_runs`, `get_run`, `list_cases`, `run`, or
`cancel`. Every action requires an exact workflow target. `get_run`,
`list_cases`, and `cancel` additionally require `runId`. `list_runs` may filter
by `status` (`new`, `running`, `completed`, `error`, or `cancelled`) and page;
`list_cases` may page. Reads are Safe/Medium/None. `run` and `cancel` are
Risky/High/BestEffort and interactive. Provider/version and key-scope support
are discovered; absence returns `capability_unavailable`, not a fallback guess.

`audit.inspect.categories` is a subset of `credentials`, `database`,
`filesystem`, `nodes`, and `instance`. Findings are summaries; raw workflow or
execution content is not part of the audit result.

The `.35` native REST adapter accepts an explicit nonempty selection of the
four categories `credentials`, `database`, `filesystem`, and `nodes`.
`instance` and default-all requests are refused before the provider call until
the instance reporter's external version-check effect is admitted. Therefore
`summary.fullAudit` is always `false`; `summary.categories` identifies the
actual requested coverage. Native `[]` means no reported risks and projects to
empty `findings`. Nonempty arrays, malformed reports, and unknown report or
section titles are refused. `affectedCount` is the bounded number of native
locations, not their contents. Codes and messages are static safe summaries;
provider descriptions, paths, names, recommendations and location values are
not exposed. This projected shape is a `.35` contract change requiring review,
not a claim of installed parity or full-audit acceptance.

The 2026-10-15 local candidate adds the separate internal operation
`n8n.audit.inspect_instance` and capability `n8n.audit.instance.read`. The public
`audit.inspect` request containing `instance` is translated before the
authoritative envelope is created; an ordinary four-category capability cannot
authorize it. Its exact optional producer policy describes the delegated native
version-service effect. It refuses old-runtime reuse and does not grant itself
through discovery or a proposed policy file. No instance audit has been run.

The native reporter may send the instance ID and version to its configured
version service using provider-controlled redirects. FCP's REST network policy
does not confine that server-side request. The proposed 45-second REST, proxy and
actor limits accommodate the reporter's 30-second request plus a hypothesized
15-second processing margin; the original shorter caller deadline still wins.
These bounds do not cancel the remote database query. The native reporter can
omit an outdated-version finding after a failed version request, so absence is
not proof that the check completed or that the instance is current. Public
output remains bounded static findings/counts with `fullAudit:false`; settings
are informational counts, never their values or names. Deployment and the exact
external-effect admission remain separate owner decisions.

`mcp_access.reconcile.scope` is exactly `workflow_ids`, `project`, `folder`, or
`all_current`; `desired` is a boolean. `all_current` is an explicit bounded
one-shot snapshot of workflows visible when the invocation starts; it is not a
future-workflow policy or daemon trigger. `dryRun=true` requires no approval and
performs no writes. `dryRun=false` requires a matching interactive approval and
the exact digest from a current dry-run with the same server, scope, selectors,
desired value, and observed workflow states. Apply sends one full required
workflow PUT per changed workflow; only `settings.availableInMCP` may change
logically. It independently reads the workflow back, preserves
graph/lifecycle invariants, and returns per-workflow exceptions for unknown
outcomes or mismatches without automatic retry. Host run-once provides the
cross-process server lock and the durable redacted reconciliation ledger at
`/var/lib/fwc-n8n/mcp-access-ledger/receipts`, owned by the runtime user with
mode `0700` and records at `0600`. Exact idempotency replay returns the prior
receipt without another provider attempt; a different binding collides, and a
pending claim remains `unknown` even after retention expiry. Committed receipts
and safe temporary outcome files are reaped under the ledger lock; malformed or
unavailable ledger state fails closed. Project/folder/all-current scopes apply
only to workflows present at that time; a newly created workflow is handled on
the next explicit bounded `all_current` invocation. No daemon, scheduler, or
implicit future-workflow policy is part of this operation.

For this operation only, a present REST `settings` object with no
`availableInMCP` key is normalized to `false`, matching n8n's public workflow
serializer for the default-off state. Missing, `null`, or non-object
`settings` remains unknown and fails closed. The ordinary workflow read
projection remains presence-aware and does not infer a value for its output.

The current host implementation keeps the generic owned connector frame and
RPC timeout at `64 KiB` and `10 seconds`. Typed
`n8n.workflows.list` and `n8n.mcp_access.reconcile` receive the bounded
`512 KiB` result frame; their per-invocation budgets are `30 seconds` and
`60 seconds` respectively. Typed `n8n.executions.diagnostics` receives a
separate `256 KiB` frame with the generic `10-second` timeout. The provider response remains subject to the
independent `10 MiB` body cap and is compacted to an allow-listed result before
it crosses the connector boundary. This exception is not a generic MCP or
caller-configurable frame expansion.

## 6. Provider routing

### 6.1 Selection policy

| Intent | Preferred | Allowed fallback | Reason |
|---|---|---|---|
| Known-ID workflow/execution metadata | Typed REST | Official MCP | Small schema, bounded response, predictable latency |
| Search workflows/executions/projects | Typed REST where parity exists | Official MCP | Native pagination and filters |
| Node/template knowledge | Host-owned local MCP run-once with API disabled | Official MCP builder tools | Local indexed knowledge and validation |
| Node/workflow validation | Host-owned local MCP run-once | Official MCP | Detailed local validation without server dependency |
| Draft/published comparison | Official MCP | REST plus local validation | Official server semantics expose both graphs |
| JSON graph/template create/update | Typed approved graph operation | No SDK-source fallback | Validate the graph with MCP; saving/testing retains separate authorization and readback |
| Publish/unpublish/archive/restore | Typed REST after parity | Official MCP | Typed preconditions and compact readback |
| Manual/production execution | Owner-gated official MCP `execute_workflow` | No REST fallback | Manual accepted by `.25`; production `.26` and test/preparation `.41` remain incomplete, with separate provider-semantic and approval gates |
| Credential metadata | Official MCP | Typed REST | Official MCP strips secret data |
| Data tables | Official MCP | Typed REST after parity | Current official typed surface is broader |
| Audit/evaluations/version history | Typed REST or local MCP by capability | No silent fallback | Feature/version dependent |

Fallback requires equivalent capability, safety classification, approval
binding, precondition, output redaction, and readback. If equivalence cannot be
proven, the operation fails closed.

### 6.2 Current provider catalog mapping

The mapping covers the catalogs observed on 2026-08-08. Catalog changes are
handled by capability discovery, not by silently extending this table.

Official instance-level MCP:

| Upstream tool | Public route |
|---|---|
| `search_workflows` | `workflows.search` |
| `get_workflow_details` | `workflows.get` / `workflows.compare` |
| `execute_workflow` | `workflows.execute` (`manual` or `production`) |
| `test_workflow`, `prepare_test_pin_data` | `workflows.execute` (`test` or `prepare_test`) |
| `publish_workflow`, `unpublish_workflow`, `archive_workflow` | `workflows.lifecycle` |
| `search_projects`, `search_folders`, `list_tags` | `structure.search` |
| `get_execution` | `executions.get` / `executions.diagnostics` (typed REST projection) |
| `search_executions` | `executions.search` |
| `list_credentials` | `credentials.list` |
| `get_sdk_reference`, `search_nodes`, `get_node_types`, `get_workflow_best_practices` | `knowledge.query` |
| `explore_node_resources` | `node_resources.explore` |
| `validate_workflow`, `validate_node_config` | `validation.run` |
| `create_workflow_from_code`, `update_workflow` | `workflows.create_draft` / `workflows.update_draft`; blocked when unconstrained credential auto-assignment is possible |
| `search_data_tables` | `data_tables.search` |
| `create_data_table`, `add_data_table_column`, `rename_data_table_column`, `rename_data_table`, `add_data_table_rows` | `data_tables.mutate` |
| `delete_data_table_column` | future-only data-table destructive gate |

The current installed fixed runtime policy records local `n8n-mcp` package
version `2.84.4`. The source update fixtures in `update_local_mcp.rs` retain
`2.69.2` as an exact historical/update-path fixture; it is not the installed
runtime policy. The earlier observed catalog count is historical evidence, not
a current tool-count claim;
catalog names and schema digests, not a human-maintained count, are
authoritative:

| Upstream tool family | Public route |
|---|---|
| `tools_documentation` | `knowledge.query.tool_documentation` |
| `search_nodes`, `get_node`, `search_templates`, `get_template` | `knowledge.query` |
| `validate_node`, `validate_workflow`, `n8n_validate_workflow` | `validation.run` |
| `n8n_list_workflows`, `n8n_get_workflow` | workflow reads |
| `n8n_create_workflow`, `n8n_update_full_workflow`, `n8n_update_partial_workflow` | typed draft writes |
| `n8n_autofix_workflow` | propose diff, then `workflows.update_draft`; never silent apply |
| `n8n_delete_workflow` | future-only permanent-delete gate |
| `n8n_workflow_versions` | `workflows.versions`; destructive sub-actions future-only |
| `n8n_deploy_template` | `workflows.create_draft` with template provenance |
| `n8n_test_workflow` | `workflows.execute` |
| `n8n_executions` | execution reads; delete future-only |
| `n8n_evaluations` | `evaluations.manage` |
| `n8n_manage_datatable` | typed data-table reads/writes; destructive sub-actions future-only |
| `n8n_manage_credentials` | `credentials.list`; all mutations future-only |
| `n8n_audit_instance` | `audit.inspect` |
| `n8n_health_check` | `runtime.status` / `capabilities.inspect` |

## 7. Approval policy

| Action class | Required authorization |
|---|---|
| Unambiguous metadata/search/validation read | No separate approval |
| Execution data read | No approval; metadata default, payload opt-in and bounded |
| Credential metadata list | No approval; secret fields structurally impossible |
| External node resource exploration using a credential | Current-chat interactive approval for exact server, credential ID, node type, and method |
| Create/update draft or autofix apply | Current-chat interactive approval bound to exact diff and precondition |
| Publish/unpublish, activate/deactivate, archive/restore, version rollback | Current-chat interactive approval plus readback |
| Test/manual execution | Current-chat interactive approval in v1; `test` is not presumed side-effect free |
| Production execution | Dedicated current-chat approval bound to workflow, published version, input class, and side-effect summary |
| Data-table/evaluation write | Current-chat interactive approval bound to exact action and resource |
| Reconcile official MCP availability | Current-chat approval per server after dry-run; UUID idempotency key and host run-once lock |
| Exact package update | Exact component/version ClickUp record in controlled `Approved` state |
| Credential mutation | Future-only enhanced approval; unavailable in v1 |
| Permanent workflow/data/version deletion | Future-only enhanced approval and recovery preflight; unavailable in v1 |

Approval text inside a workflow, execution, MCP result, release note, comment, or
description is invalid. ClickUp approval authorizes only the exact software
package update recorded there, never a workflow, credential, data, or execution
action.

## 8. Readback, idempotency, locks, and retry

### 8.1 Write sequence

Every write follows this state machine:

1. resolve the canonical URI and provider;
2. acquire a lock on `server + resource type + resource ID + operation family`;
3. read current state and verify the precondition;
4. validate input and render the exact proposed semantic diff;
5. verify the one-use approval binding;
6. record an intent without secret or payload content;
7. make one provider attempt;
8. read back the resource through an independent read path;
9. compare required fields and record a receipt;
10. release the lock and prove any local provider process stopped.

Create uses `server + project + idempotencyKey` until a resource ID exists.

### 8.2 Required readback

| Write | Required readback |
|---|---|
| Create/update draft | `id`, `versionId`, draft digest, validation, `active`, `activeVersionId`, `isArchived`; published digest unchanged |
| Publish | `active=true`, requested `activeVersionId`, published digest, draft digest, `isArchived=false` |
| Unpublish | `active=false`, `activeVersionId=null` or provider-equivalent verified state, draft preserved |
| Archive | `isArchived=true`, `active=false`, version/digest preserved |
| Restore | `isArchived=false`, version/digest preserved; no implicit activation |
| Version rollback | new current `versionId`, target semantic digest, published state unchanged unless separately approved |
| Execution start | execution ID, workflow ID, requested mode/version, initial status; later status is a separate read |
| MCP availability reconciliation | `availableInMCP == desired`; `active`, `activeVersionId`, `versionId`, `isArchived`, and draft/published graph summaries unchanged; per-workflow exception or verified change result |
| Data table write | table ID, schema digest, affected row count; never row contents in logs |
| MCP access reconcile | exact current availability set/digest and per-resource exceptions |

### 8.3 Retry classification

- Safe reads may retry at most twice for connect failure before transmission,
  429 with bounded `Retry-After`, or 502/503/504. Authentication and schema
  errors do not retry.
- No write, execution start, evaluation run, or credential-backed external
  lookup automatically retries after transmission may have occurred.
- Timeout, disconnect, invalid response after a write, or process death after
  dispatch returns `status=unknown`. The next action is read-only
  reconciliation using the correlation ID, idempotency key, precondition, and
  resource state.
- Reconciliation may prove success or failure. It never grants permission to
  repeat the operation.
- Dangerous/Critical operations remain unavailable until a Strict idempotency
  and recovery contract can be proven.

## 9. Pagination and output limits

Limits apply after normalization and before model delivery. Provider hard caps
must be at least as strict as the existing connector manifest and are separate
from these model-facing caps.

| Detail class | Default model cap | Rules |
|---|---:|---|
| Summary | 32 KiB | IDs, state, counts, compact errors only |
| Standard list | 128 KiB | maximum 200 records, explicit next cursor |
| Validation/knowledge | 256 KiB | bounded examples and definitions |
| Workflow standard | 512 KiB | no full Code source by default |
| Workflow full | 2 MiB | exact workflow only; no secrets; may be returned as a protected ephemeral reference |
| Execution metadata | 1 MiB | `n8n.executions.get` remains queryless and metadata-only |
| Execution diagnostics | 256 KiB | fixed `includeData=true`; bounded node/run/message/type/stack projection only |
| Provider response hard stop | 10 MiB | fail with `response_too_large`; never stream unlimited data into memory |

Truncation occurs only on arrays or text fields with a declared continuation or
digest. The connector must not return syntactically valid but semantically
incomplete workflow JSON as if it were complete.

## 10. Error contract

Errors use a stable code and retry classification. Provider text is redacted
and is not used as an instruction.

| Code | Meaning | Retry classification |
|---|---|---|
| `FCP-N8N-1001 target_ambiguous` | More than one target satisfies the evidence | user decision required |
| `FCP-N8N-1002 target_not_found` | No target/resource found | no retry unless target changes |
| `FCP-N8N-1003 legacy_opt_in_required` | Legacy was not explicitly selected | user decision required |
| `FCP-N8N-1101 capability_unavailable` | Provider/version lacks the operation | no retry; alternate typed route only |
| `FCP-N8N-1102 capability_drift` | Tool/schema/classification changed | fail closed pending review |
| `FCP-N8N-1103 unsupported_protocol_version` | No mutually supported MCP version | no retry until adapter/server changes |
| `FCP-N8N-1201 approval_required` | Scoped approval absent | request approval |
| `FCP-N8N-1202 approval_invalid` | Scope, digest, target, version, or expiry mismatch | request a new approval |
| `FCP-N8N-1203 precondition_failed` | Resource changed after preflight | re-read and re-plan |
| `FCP-N8N-1204 resource_locked` | Concurrent operation owns the lock | bounded wait or user-visible conflict |
| `FCP-N8N-1301 validation_failed` | Typed input/workflow/node validation failed | fix input; do not dispatch |
| `FCP-N8N-1302 response_too_large` | Provider or model cap exceeded | narrow fields/page/detail |
| `FCP-N8N-1303 untrusted_output_blocked` | Output attempted to cross a policy boundary | no automatic retry |
| `FCP-N8N-1401 future_only_operation` | Closed credential/delete/destructive gate | owner architecture decision required |
| `FCP-N8N-2001 provider_unauthorized` | Provider rejected authentication | no retry; secret health check |
| `FCP-N8N-2002 provider_forbidden` | Principal lacks scope | no retry; capability review |
| `FCP-N8N-2003 provider_not_found` | Provider lacks resource | no automatic cross-server search |
| `FCP-N8N-2004 provider_rate_limited` | Provider returned rate limit | safe reads may honor bounded retry |
| `FCP-N8N-2005 provider_unavailable` | Provider failed before known dispatch | safe reads only may retry |
| `FCP-N8N-2006 provider_result_unknown` | Mutation/run may have occurred | reconcile; never auto-repeat |
| `FCP-N8N-3001 process_start_failed` | Local provider did not start/handshake | no provider dispatch |
| `FCP-N8N-3002 process_stop_failed` | Child identity still exists after teardown | operation fails closeout and alerts |

## 11. Capability discovery and MCP compatibility

Capability discovery is per server and never copied from EEC to Hetzner or
legacy. The current wrapper emits this redacted compact result:

```json
{
  "capabilities": {
    "schema": "fwc.n8n.capabilities.v1",
    "serverId": "eec | hetzner",
    "provider": "official_mcp",
    "toolCount": 0,
    "tools": [
      {
        "name": "tool_name",
        "inputSchemaDigest": "sha256:...",
        "outputSchemaDigest": "sha256:...",
        "class": "unknown",
        "status": "unreviewed"
      }
    ]
  }
}
```

No workflow payload, Code source, execution data, tool response, credential
value, or auth header is stored in this snapshot.

### 11.1 Release-bound capability evidence (owner decision, 2026-08-25)

The canonical capability snapshot/evidence is release-bound. It is read only
from immutable `/usr/local/lib/fwc-n8n/current` or from a specifically
identified immutable release under the same `/usr/local/lib/fwc-n8n` install
root. A separate checked-in volatile catalog is not canonical. EEC and
Hetzner evidence remains separate and must not be mixed.

The release-bound files are:

- `inventory/eec.json` (EEC only);
- `inventory/hetzner.json` (Hetzner only);
- `inventory/eec-official-mcp.json` (EEC only);
- `inventory/hetzner-official-mcp.json` (Hetzner only);
- `policy/local-mcp.json`;
- `provenance.json`;
- `provision-receipt.json`.

These files are evidence inputs for the selected immutable release. The
documents retain only schema, redacted references or digests, and acceptance
status. They do not retain provider catalogs, workflow or other payloads, or
secrets.

The operator boundary is:

- the existing `status` and read-only `provision` preflight contract are for
  status and validation only; they do not install a release or switch
  `current`;
- verification must establish provenance, receipt validity, artifact digests,
  ownership/modes, and the fixed release layout before an owner-gated action;
  receipt presence or matching metadata is not proof of cryptographic
  verification, live provider acceptance, or current-release acceptance;
- rollback is owner-gated only and may target a preserved immutable release
  after the same fixed-root validation; immutable releases are not deleted;
- logs and operator receipts are redacted. No additional log path is defined
  here; the fixed runtime roots are `/usr/local/lib/fwc-n8n`,
  `/var/lib/fwc-n8n/staging`, and `/var/lib/fwc-n8n/mcp-access-ledger`.

`n8nVersion`, `mcpEra`, `protocolVersions`, `apiScopeDigest`, `capturedAt`,
`expiresAt`, `snapshotId`, and `publicRoute` are not fields emitted by the
current wrapper; they are future metadata only. The current path selects a
fixed official-MCP inventory and invokes only host-owned `mcp.tools.list`.
It has no REST fallback and accepts no caller-controlled method, URL, header,
token, or tool name.

The stateless protocol reduces connection/session state but does not itself
guarantee zero memory: a host may still keep a client process, HTTP pool, cached
catalog, or model-visible schemas resident. The host-owned local provider path
must reach zero idle provider memory through bounded process ownership and
teardown, regardless of which MCP era the remote server supports.

The connector must not assume that Codex, n8n, and the local bridge support the
same revision. Current code in `connectors/mcp-bridge` supports the reviewed
modern and legacy transport paths with bounded responses, authenticated
credential references, capability enforcement, approval enforcement, and
process teardown. It remains a provider adapter behind typed public operations,
not a generic model-visible `tools/call` surface.

Catalog policy:

- unchanged approved read tools may continue within snapshot TTL;
- a removed tool returns `capability_unavailable`;
- a new unreviewed write/execution/credential/destructive tool or semantic/security change is `blocked`; section 11.2 requires deterministic reviewed proof for harmless changes;
- a read tool whose schema changes in security-relevant fields is also blocked;
- no catalog description or annotation can downgrade risk;
- provider cache TTL is honored only within local maximums; deterministic tool
  order and schema digests are used for comparison and prompt-cache efficiency.

### 11.2 Compatible upstream updates (owner requirement, 2026-09-30)

Numeric upstream version changes alone must not disable supported operations
with compatible routes, wire protocols, inputs/outputs, permissions and readback.
Assess EEC, Hetzner, local MCP and bridge separately. Evidence versions identify
tested artifacts, rather than a permanent numeric support allowlist.

`.34` uses deterministic reviewed comparisons, never model interpretation.
Descriptive/order/additive changes cannot grant new authority. Required fields,
permissions, output/readback, unknown schema semantics and risky tools remain
fail-closed. Unaffected operations continue unless shared authentication,
transport or artifact trust is compromised. Preserve safe diagnostics without
retrying writes or adding fallback.

Exact immutable signatures, hashes, ownership, executable selection, candidate
approval and recovery remain mandatory. Ambient package changes require the
existing reviewed update path; never edit signed inventory in place. Remote n8n
is observed, not automatically upgraded or downgraded. Section 11.1 still binds
immutable evidence. Reviewed source/offline tests cover version/protocol sets,
harmless metadata, missing/changed tools, semantic/output drift, trust/expiry and
operation isolation. Offline checks cannot claim live PASS.

#### `.34` acceptance update — 2026-10-04

Primary filenames below resolve under `/srv/dev-ssd/fcp/nqm81-34/`. These
separate source, local process, installed and live evidence; they do not rewrite
the dated packets or their FAIL/UNKNOWN outcomes.

| Canonical criterion | Evidence and bounded result |
|---|---|
| Same contract with different versions; different versions on both servers | `protocol-set-matrix.log`, `final-n8n.log`; actual EEC 2.38.4 → 2.41.5 and Hetzner 2.37.10 → 2.41.5. EEC server receipt: `/var/backups/n8n-cutover-2.41.5-quiesced-fresh2/switch-public-proof.json`; Hetzner: `hetz-installed-2.41.5-final-acceptance.json`. |
| Harmless catalog metadata/order changes | `compatibility-self-test.log`, `bridge-lib.log`, `final-bridge-profile.log`: deterministic projection preserves significant fields; the self-test still reports `acceptance:false`. |
| Removed operation; renamed/changed required field; incompatible output/readback | `final-n8n.log`, `bridge-boundaries-2.log`, `resume-host-process.log`: refusal and exact readback bindings. The two new publish failure reasons were significant, separately reviewed and admitted in `20261003-publish-reason-baseline-proposal.json`; no automatic enrollment. |
| New risky tool / unknown authority | `host-official-consumer.log`: unknown profile/authority refusal is checked. This does not test permission-only drift. |
| Changed permission | `permission-only-update-tests-frozen-20261004.log`: `permission_only_change_requires_exact_review_and_owner_decision` holds all non-permission fields constant, asserts exact `ToolChange::Permissions` and `Breaking`, authorizes the positive control, and rejects both stale review and stale owner decision with `ApprovalMismatch` before ledger consumption. The earlier host/schema/process logs were not evidence for this criterion. |
| Protocol negotiation failure; local binary tamper; expired evidence | `protocol-set-matrix.log`, `final-n8n.log`, `final-preflight-self-test.log`: source/CLI trust, protocol and expiry refusals, not live tamper experiments. |
| One affected operation blocked while unrelated approved reads remain usable | `bridge-boundaries-2.log`, `final-host-local-lib.log`, `rc42-install-read-manifest.json`: operation isolation plus installed EEC/Hetzner catalogs and local knowledge read. |
| Local process and installed custom/runner behavior | `final-n8n.log`, `resume-host-process.log`; `upgrade-eec-installed-renderer-proof.json`, `hetz-installed-2.41.5-final-acceptance.json`; `installed-runner-live-20261003-{eec,hetzner}/readonly-reconciliation-flat1/public-proof.json`: EEC internal JS42, Hetzner external JS42/Python43. EEC Python/external runner is not claimed. |
| Signed package, approval canonicalization, independent readback and teardown | `rc43c-actual-unsigned-review-packet.json`, `rc43c-actual-signed-preflight-packet.json`, `rc43c-actual-installed-review-packet.json`; `rc43c-controlled-publication-final-manifest.json`: one controlled publish/unpublish per server, independent GETs, no workflow execution or webhook invocation in that cycle. |

The final missing permission-only regression passed on 2026-10-04 through real
`authorize_update` and `VerifiedOwnerDecision` bindings (19 update module tests
passed). This is test-only evidence, not a new installed runtime or provider
grant. Separate Sol final GO accepted source
`efb3e22f11c5a715a63a34296cd23eabf653aabc` and 19/19 tests; canonical `.34`
was **closed by the coordinator at `2026-10-04T03:36:40.074779411Z`**.
This records actual closure, not additional runtime or live-operation authority.

Installed RC43c runtime source is `09cebc4aaa3c968f3704611325a005a3ced7a237`;
signed receipt BLAKE3 is
`7cdcde12184f3ab3a205cd15a51653c7ad5d7519df9f8ea2a304b4fd4861fdab`.
Publication manifest SHA-256 is
`8243fc4b0eb88c32e1c889ae81fb587a590d6249b59d16c0d80f83fcb1f79eb5`.
Actual local MCP package upgrade remains **UNVERIFIED** and is not a separate
required real-upgrade claim in this acceptance. Recovery preflight passed;
recovery APPLY was not run. Owner-retired backup payloads cannot be promised as
available rollback inputs; images, small evidence and live configuration remain.

UBS remains **NON-GREEN: 100 critical / 4115 warning / 2305 informational**.
The final permission-only test passed; scoped Clippy exited 101 for eight old
test findings (four in `connector.rs`, one in `update.rs`, three in
`tests/integration.rs`), none in the added regression. This is not Clippy green.
The owner accepted the bounded residual risk only for source `09cebc4` and
`rc43c-new-source-admission-packet.json` SHA-256
`0e228bf62f1af378949489ceda39031650831168f9fd754bc3311caa212e7a5c`;
that decision is not transferable or a workspace-wide waiver. Scan timing,
excluded coverage and historical failures remain in the existing evidence.
Actual producer/consumer fixes cover closed metadata, native pins and safe
diagnostics. The protected release used verified root-owned files and direct
argv, with only secret **data** in the existing ephemeral pipe; runbook guidance
does not establish a universal launcher or change security policy.

## 12. Process lifecycle and telemetry

Each local provider call gets a new process group and a correlation ID. The host
records executable identity, PID, PGID, start time, and executable digest before
dispatch. Teardown closes the protocol, sends bounded graceful termination,
escalates only to the same verified process group, and then proves no matching
process remains. PID reuse or identity mismatch is an error, not permission to
kill a process.

Allowed telemetry fields:

- server ID, operation ID, provider, correlation ID, safe resource ID/hash;
- start/end time, startup/provider/total latency;
- request and response byte counts without content;
- result code, retry classification, provider fallback flag;
- PID/PGID identity result, final process status, and `stopped=true|false`;
- RSS, PSS, and private memory before, during, 5 seconds after, and 30 seconds
  after a benchmark call.

Prohibited telemetry includes API keys, tokens, credential values, auth
headers, workflow JSON, Code source, execution payloads, customer/patient
messages, external response bodies, and raw release notes.

### 12.1 Local `n8n-mcp` update executor boundary

The trusted local-provider update path is review-first and host-owned:

- candidate, stage plan, metadata, registry URL, and exact artifact SRI are
  bound before stage creation; a mismatch performs no stage I/O;
- archive listing is streamed with a hard output bound and absolute deadline;
  timeout handling terminates and waits for the complete dedicated process
  group, so descendants cannot retain output pipes; non-zero, oversized, or I/O
  failures are fail-closed;
- the receipt digest is checked before and after listing and again on a fresh
  descriptor immediately before extraction, so the validated artifact cannot be
  silently replaced between those phases;
- failed materialization, extraction, re-verification, and candidate-binding
  paths discard only the exact stage through bounded descriptor-relative
  cleanup. Cleanup failure is terminal and retains both error causes; cleanup
  is never run after activation starts;
- the executor accepts only fixed stage-I/O operations. It cannot receive a
  model-supplied command, environment, path, URL, registry script, or npm
  lifecycle instruction. Registry scripts and release notes remain data, not
  authority.

The executor's apply path is tested offline, but wiring registry discovery and
the owner-operated staging path is tested offline through command/stage seams;
live acceptance remains a separate gate. Registry range metadata is resolved
explicitly: npm `view` object and array results are normalized, npm-semver
prerelease/build, partial, comparator, wildcard, OR, and hyphen forms are
evaluated, and the highest matching concrete semver is selected
deterministically. The selected package/version/SRI/tarball records and every
parent-edge target are hashed into the redacted receipt. Unsupported range
syntax fails closed before content fetch. The root exact-version gate remains
mandatory. A failed exact precondition returns before the component lock is
acquired; callers must not infer lock ownership from that error.

The staging path rejects file/link/git/ssh/http(s), npm aliases, bundled
dependencies, and overrides on direct, optional, peer, and transitive edges
before any package-content fetch. It creates an initially empty cache under
the UUID-v4 stage, runs one fixed exact `npm pack` per selected registry
artifact, verifies every tarball's SHA-512 SRI, rejects published package
lockfiles, bundles, aliases, and manifest disagreement before install, writes a
root project manifest plus an immutable npm-compatible `package-lock.json`
from the frozen closure with deterministic package placement, seeds only that
stage cache, and invokes `npm ci --offline` without a package spec. Pack
consumes each frozen validated registry tarball URL; install can consume only
the stage-owned cache and placement, never a fresh registry resolution.
Environment clearing, the fixed-prefix project `.npmrc` guard, and distinct
fixed empty user/global npmrc paths prevent ambient npm configuration or cache
state from changing the closure. Optional dependencies may be omitted
only for a selected package whose `os`/`cpu` constraints exclude the current
platform; optional peers may be absent by npm semantics. Required and
non-optional peer edges must be present, and every installed lock dependency
map and edge target must match the frozen selected manifests exactly.

Dependency updates and discovery cannot expand the public FWC function set.
Any new capability requires an explicit, separately reviewed implementation
with its own contract and authorization evidence.

### 12.2 Fail-closed acceptance preflight

Every supervised provider-writing worker must run the repository checker and
obtain `verdict: "pass"` before creating an approval-request file. Approval
request creation is a subsequent step, followed by the single issuer
invocation; a failed preflight permits none of those steps, nor any credential
helper or provider operation:

```text
bash scripts/e2e/n8n_acceptance_preflight.sh <redacted-plan.json
bash scripts/e2e/n8n_acceptance_preflight.sh --self-test
```

The checker accepts exactly one bounded JSON object with schema
`fwc.n8n.acceptance-preflight.v1`. It is a read-only gate: it may inspect only
the supplied metadata projection and, when `approval_file` is explicitly
provided, `stat` the fixed `/var/lib/fwc-n8n/approval-requests` directory and
one direct child. A positional plan is read through one bounded descriptor;
stdin and file input are both capped before JSON parsing. The checker uses
fixed absolute paths for its `jq`, `wc`, and `stat` helpers rather than resolving
them through `PATH`. It never reads or prints request/response bodies, tokens,
seeds, credentials, provider output, stdout, or stderr; it never invokes
`fwc-n8n`, an issuer, KeePass, a provider, or a cleanup/write operation.

The approval projection follows the authoritative host contract in
`crates/fcp-host/src/n8n_approval.rs`: for an
`N8nApprovalIssueRequest` whose operation is `mcp_access_reconcile`,
`workflow_id` is exactly the empty string. `validate_issue_request` enforces
that shape and takes the workflow target from `input.workflowIds`; the
metadata-only checker therefore separately requires
`input_projection.workflow_ids_count == 1` and
`input_projection.workflow_ids_match_target == true`. The checker must keep
this contract at the projection boundary and must never require or expose raw
approval request bodies, tokens, or seeds.

The initial acceptance preflight is therefore ordered as
`preflight → approval-request creation → issuer → provider`. A later checker
invocation may inspect an explicitly supplied request-file projection for the
post-issuer absence assertion, but it does not replace the mandatory initial
gate or authorize another issuer attempt.

`--self-test` is a separate health-check mode: its successful output carries
`mode: "self-test"` and `acceptance: false`, so it is never an acceptance
verdict. `--help` is rejected with a non-zero argument error; only a normal
plan invocation may emit the acceptance result `verdict: "pass"` without a
mode field.

The gate rejects unknown keys and returns one redaction-safe JSON line with a
stable `abort_code`; any failure exits non-zero. Its required checks include:

- literal `/usr/local/bin/fwc-n8n run-once <allowlisted-operation>` arguments,
  one bounded document, no route/direct-host/direct-bridge/shell fallback, and
  EEC-before-Hetzner ordering;
- direct one-level `InvokeResponse` parsing with the normalized state
  projection, fresh distinct UUID correlations, and matching idempotency,
  approval, dry-run, and target metadata;
- the exact EEC inactive/unarchived/unpublished baseline, its version/graph/state
  digests, the desired MCP-access dry-run (`planned=1`, `changed=0`), matching
  apply digest, and the canonical encoded bridge URI (`%5F` for underscores);
- owner-approval envelope and parent-binding metadata, decimal 13-digit expiry
  with `now < expires_at_ms <= now+60000`, root-owned `0600` request-file
  metadata or a verified post-issuer absence assertion, and cleanup failure;
- immutable installed/source revision and artifact-digest provenance, `0700` /
  `0600` evidence modes, bounded one-attempt counters, EEC no-go stop rules,
  redaction/checksum evidence, and absence of leaked runtime/issuer processes.

A passing preflight means only that the submitted redacted metadata projection
matches this local policy. Digest fields must be correctly formatted, unlike
the synthetic self-test fixtures, and the checker verifies their cross-field
bindings; it deliberately does not recompute cryptographic digests from raw
bodies because those bodies are forbidden at this boundary. It does not
authorize a write, prove approval-file atomicity or cleanup chronology, prove
signer behavior, or prove a provider result. The live worker must still execute
the prescribed single sequence, perform typed readbacks, reconcile at most once
after uncertainty, and stop without retry on any mismatch or unknown outcome.

### 12.2.1 One-shot owner-approval issuer handoff

The approval-request-to-issuer boundary is the tracked
`scripts/n8n_approval_once.sh` entrypoint. In production it accepts only
`--request-file <one-component-basename>` and resolves that basename below the
fixed `/var/lib/fwc-n8n/approval-requests` root; it does not accept a caller-
supplied issuer, helper, path, or safe-plan override. The request must be a
root-owned `0600` regular file with one link and a size at most 64 KiB. On the
Linux deployment target, GNU `stat` reports this type as `regular file` under
`LC_ALL=C`.

Immediately before the issuer boundary, the helper retains the exact request
bytes (including a permitted final LF), validates the JSON and integer
13-digit Unix-millisecond expiry (`now < expiry <= now+60000`), reads and
validates the same final snapshot again, and computes its raw-byte SHA-256.
It passes only that digest and the basename to the fixed
`/usr/local/sbin/fcp-n8n-approval-issue` binary. The issuer performs one
bounded no-follow read into one in-memory buffer, compares its SHA-256 with the
helper's digest before JSON parsing, token construction, seed reading, or
signing, and uses that same buffer for the remainder of issuance. A replacement
or mutation between the helper and issuer therefore fails closed as
`request_changed`; the advisory inode lock is cooperative and is not the
authority for request identity.

The signing seed remains a 32-byte raw stdin stream from the fixed secret
reader. Its Base64 framing permits at most one final LF and is bounded before
decoding; raw seed bytes never enter shell variables, argv, environment, or
reports. The issued token is written only to the already-open protected FD3
pipe. The helper performs exactly one issuer attempt and has no retry path.
`bash scripts/n8n_approval_once.sh --self-test` exercises this control path
offline (24 cases, including metadata admission, exact-byte replacement,
Base64 framing, FD3 transport, missing/non-pipe FD3, and issuer failure) and
does not authorize or simulate a provider write. The helper and issuer must be
installed and hash-verified as one contract before any live run; source review
and the self-test do not establish installation or provider acceptance.

## 13. Future-only gates

### 13.1 Credential mutation

No v1 schema accepts credential secret material. Future create/update/test/
rotate/delete operations require a separate owner decision, KeePass or a
protected host channel, consumer preflight, secret-free readback, and rollback.
OAuth refresh tokens and client secrets must never cross the model boundary.

### 13.2 Disposable workflow deletion and permanent workflow deletion

The narrowly scoped `n8n.workflows.delete_disposable` operation is the only v1
provider-delete path. It is reserved for cleanup of a workflow created by the
bounded `n8n.workflows.create_draft` path. A delete request must carry the
host-issued `creationReceipt`, the exact same-server workflow target, a full
inactive/unarchived precondition, a UUID idempotency key, and current-chat
approval. The host validates the receipt against its existing create outcome
record before provider access. The connector performs one typed
`DELETE /workflows/{id}` attempt and an independent `GET`; only a 404 readback
is success. Timeout, transport failure, malformed response, conflict, or a
still-present workflow is terminal unknown and is never retried automatically.
The durable host run-once receipt remains the sole replay/unknown boundary.

General and permanent workflow deletion remain future-only. They require prior
archive, `active=false`, `isArchived=true`, an encrypted recovery export
without credentials/sensitive execution data, dependency inspection, Strict
idempotency, a separate short-lived approval, and unknown-result reconciliation.

### 13.3 Other destructive provider sub-actions

Execution deletion, workflow-version delete/prune, credential mutation, data
table/row/column deletion, and unbounded batch mutation return
`future_only_operation` until their own recovery and Strict-idempotency contracts
are accepted.

## 14. Owner decisions (accepted)

The owner accepted all six policy decisions below together on 2026-08-09.
They are normative for v1 unless changed by a later explicit owner decision:

1. credential-backed `node_resources.explore` always requires current-chat
   approval even though it is nominally a read;
2. all test/manual workflow executions require current-chat approval in v1;
3. official MCP data-table writes are available only for additive/rename actions;
   all delete actions remain future-only;
4. version rollback and evaluation run/cancel are included in v1 as approved
   writes, while version deletion/pruning is future-only;
5. the public page maximum is 200 and full execution data requires both node and
   item bounds;
6. the current official MCP and local MCP catalogs are fully reachable only
   through the typed mappings above, never through generic `tools/call`.

The owner additionally decided on 2026-08-25 that the canonical capability
snapshot/evidence is release-bound and must be read only from immutable
`/usr/local/lib/fwc-n8n/current` or a specifically identified immutable release
under that install root. The release-bound EEC and Hetzner inventory files,
`policy/local-mcp.json`, `provenance.json`, and `provision-receipt.json` must
remain server-separated. Documentation stores only schema, redacted
references/digests, and acceptance status; it does not store catalogs,
payloads, or secrets. Status/read-only preflight, provenance/receipt/digest/
ownership verification, owner-gated rollback to a preserved immutable release,
and redacted logs remain the operator boundaries. Receipt presence is not
cryptographic or live acceptance.

Acceptance of these decisions completes the policy gate for
`flywheel_connectors-nqm81.1`. Runtime work remains governed by the individual
dependent beads and their own acceptance criteria.

## 15. Primary references

- [OpenAI Codex MCP configuration](https://developers.openai.com/codex/mcp/)
- [n8n instance-level MCP setup](https://docs.n8n.io/connect/connect-to-n8n-mcp-server/)
- [n8n MCP tool reference](https://docs.n8n.io/connect/connect-to-n8n-mcp-server/mcp-server-tools-reference/)
- [n8n public API reference](https://docs.n8n.io/api/api-reference/)
- [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP 2026-07-28 key changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [`czlonkowski/n8n-mcp`](https://github.com/czlonkowski/n8n-mcp)
