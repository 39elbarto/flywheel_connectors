# Google Apps Script connector

Bounded FCP connector for Apps Script API v1 project metadata, source,
versions, deployments, metrics, process history, and optional remote execution.

## Safety boundary

- The connector exposes 15 typed operations. It does not expose raw HTTP or
  direct deletion. `script.scripts.run` is present but disabled by default.
- `script.read`, `script.source.write`, `script.deployment.write`, and
  `script.execute` are
  separate resource-bound capabilities.
- Remote execution requires `enable_script_execution=true`, a fresh capability
  token (at most five minutes old), policy approval, and a two-step preflight.
  The preflight reads the exact deployment and current manifest, displays the
  script OAuth scopes and parameter shape, and returns digests that must match
  the confirmed invocation. The deployed manifest must declare `oauthScopes`
  explicitly; inferred scopes are rejected. Development mode is always false.
- Executed code runs with its own Apps Script permissions. It can therefore
  modify or delete Drive files, send mail, or call external services despite
  this connector having no direct delete route. Static inspection cannot prove
  otherwise.
- Full source replacement is Dangerous. It requires an exact current inventory
  digest, explicit removed-file inventory, confirmation, a snapshot version,
  and post-write inventory readback.
- Deployment create/update are Dangerous and require confirmation plus
  provider readback. Project and version creation are Risky and are read back.
- Source files are validated as a complete set: 1-200 files, unique names,
  exactly one `JSON` `appsscript` manifest, and at most 5 MiB total source.
- Source reads return a compact inventory by default. One selected file can be
  read in UTF-8-safe chunks of at most 48,000 bytes with `source_offset` and
  `source_limit`.
- Production traffic is restricted to `https://script.googleapis.com/v1`.
  Loopback HTTP is accepted only for deterministic tests.
- Telemetry records only redacted auth mode and aggregate request status. It
  does not log OAuth material, source, provider bodies, or resource IDs.

## Operations

| Family | Operations |
|---|---|
| Projects | `script.projects.get`, `script.projects.get_content`, `script.projects.create`, `script.projects.update_content`, `script.projects.get_metrics` |
| Versions | `script.versions.create`, `script.versions.get`, `script.versions.list` |
| Deployments | `script.deployments.get`, `script.deployments.list`, `script.deployments.create`, `script.deployments.update` |
| Processes | `script.processes.list`, `script.processes.list_for_project` |
| Execution | `script.scripts.run` (preflight or confirmed execution) |

List operations accept `page_size` from 1 to 50 and an opaque `page_token`.
All path identifiers are validated as one path segment before provider I/O.

## Authentication

Configuration uses the shared Google authentication selector: a direct bearer
token, a host credential reference, or OAuth refresh material. The live wrapper
and OAuth consent update are intentionally outside this implementation bead.

Required Google scopes are defined by the integration contract. This crate does
not request scopes itself and never treats source content as authorization.

## Verification

Routine deterministic verification does not access a Google account:

```bash
scripts/e2e/google_apps_script_connector_verification.sh
```

The verifier checks formatting, compilation, tests, Clippy, manifest validity,
operation parity, replacement safety, provider path/auth fixtures, error
classification, source chunking, and execution enablement, preflight, digest,
parameter, token-freshness, redaction, and no-delete/raw-route gates.

Live reversible acceptance is performed separately after OAuth integration and
uses only disposable test artifacts. No live script is edited by this crate's
offline verifier.

## Recovery

Before every source replacement the connector creates an immutable Apps Script
version and returns its version number. Recovery is explicit: read that version
with `script.projects.get_content`, review its complete inventory, then submit
it through the same confirmed `script.projects.update_content` path. Deployment
deletion and source rollback shortcuts are deliberately absent.

Remote execution has no generic rollback because arbitrary script side effects
may be irreversible. Its connector rollback is to omit or set
`enable_script_execution=false`; that blocks all future `script.scripts.run`
requests before provider execution. A timed-out run has an unknown outcome and
must never be retried automatically; reconcile through process history and the
affected service before considering another invocation.

Official API references:

- <https://developers.google.com/apps-script/api/reference/rest>
- <https://developers.google.com/apps-script/api/reference/rest/v1/projects/updateContent>
- <https://developers.google.com/apps-script/api/how-tos/execute>
