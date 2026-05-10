# Windows AppContainer Capability Map

**Bead:** `flywheel_connectors-r4qcg.1.2`
**Status:** Implementation contract for the Windows AppContainer sandbox path.

Windows AppContainer profiles are deny-by-default. FCP capabilities that are
not listed here do not grant a Windows AppContainer capability until this file,
the manifest policy compiler, and the Windows evidence tests are updated in the
same change.

## Mapping

| FCP capability | Windows AppContainer capability | Notes |
|---|---|---|
| `network.egress` | `internetClient` | Current manifest spelling for outbound internet access. Granted only when the compiled network policy allows direct outbound egress. |
| `network.outbound` | `internetClient` | Basic outbound HTTP/HTTPS. |
| `network.dns` | no additional AppContainer capability | DNS is covered by the selected client network capability when egress is allowed. |
| `network.outbound_dns` | no additional AppContainer capability | Alias-level contract for DNS-capable outbound egress. |
| `network.outbound_lan` | `privateNetworkClientServer` | LAN-class egress for connectors such as Hue and Sonos. |
| `network.outbound_tailnet` | `privateNetworkClientServer` | Tailnet addresses are treated as private-network egress. |
| `network.listen` | `internetClientServer` | Required for local webhook receivers and loopback listeners. |
| `network.tls.sni` | none | Enforced by the egress proxy and TLS policy, not by an AppContainer capability SID. |
| `network.tls.mtls` | none | Enforced by TLS client configuration and credential policy, not by an AppContainer capability SID. |
| `system.exec` | none | AppContainer denies child-process spawning by default. |
| `system.privileged` | none | Privileged host operations are denied. |
| `filesystem.read` | none | Generic filesystem reads require explicit broker/path grants outside the base AppContainer capability set. |
| `filesystem.write` | none | Generic filesystem writes require explicit broker/path grants outside the base AppContainer capability set. |
| `fs.read.user_profile` | `documentsLibrary` | Read access to Documents-style user profile content. |
| `fs.write.user_profile` | none | Denied by default; per-path grants must be explicit and audited. |
| `fs.read.tmp` | AppContainer temp directory | Always available through the profile-scoped temp directory. |
| `storage.state` | profile-scoped state directory | Connector state access is limited to the per-connector AppContainer state/cache directory. It does not grant broad user-profile access. |
| `media.download` | none | Service-level transfer permission; network and filesystem effects are still controlled by the egress and path policies above. |
| `media.upload` | none | Service-level transfer permission; network and filesystem effects are still controlled by the egress and path policies above. |

Service-specific operation capabilities such as `github.read`, `gmail.send`, or
`slack.files.write` do not map directly to Windows capability SIDs. They remain
capability-token and connector-operation decisions at the host/connector
boundary. The AppContainer map only grants OS capabilities for the generic
sandbox effects that an operation needs.

## Connector Manifest Coverage

The current connector manifest scan covers 176 `connectors/*/manifest.toml`
files. Generic sandbox capabilities used by those manifests are:

| Capability | Manifest count | Mapping status |
|---|---:|---|
| `network.dns` | 169 | Covered by `network.dns`. |
| `network.egress` | 153 | Covered by `network.egress`. |
| `network.listen` | 164 | Covered by `network.listen`. |
| `network.outbound` | 23 | Covered by `network.outbound`. |
| `network.tls.mtls` | 3 | Covered by `network.tls.mtls`. |
| `network.tls.sni` | 146 | Covered by `network.tls.sni`. |
| `system.exec` | 174 | Covered by `system.exec`. |
| `system.privileged` | 46 | Covered by `system.privileged`. |
| `filesystem.read` | 1 | Covered by `filesystem.read`. |
| `filesystem.write` | 2 | Covered by `filesystem.write`. |
| `storage.state` | 85 | Covered by `storage.state`. |
| `media.download` | 73 | Covered by `media.download`. |
| `media.upload` | 61 | Covered by `media.upload`. |

The scan intentionally excludes service-specific operation capabilities from
the OS capability table. Those strings are numerous, connector-owned, and do not
authorize AppContainer SIDs by themselves.

## Current Code Surface

The runtime policy compiler normalizes explicit AppContainer capability names in
`crates/fcp-sandbox/src/sandbox.rs`. The Windows backend resolves those names to
capability SIDs when constructing `SECURITY_CAPABILITIES` for the
`STARTUPINFOEXW` launch path in `crates/fcp-sandbox/src/windows.rs`.

The current Rust surface intentionally keeps Windows at
`FilterStrength::ProcessLimit` unless a launched child process actually goes
through the AppContainer launch path. Profile creation alone must not be used as
evidence that a connector reached `ProfileLevel`.

## Update Rules

1. Add new FCP capabilities here before granting them in code.
2. Keep strict profiles fail-closed: network AppContainer capabilities must not
   be granted when the compiled sandbox policy blocks direct network access.
3. Extend the redaction-safe JSONL evidence so each new capability decision is
   visible without logging raw connector ids, local paths, credentials, or user
   data.
4. Add Windows-gated tests for allow and deny behavior before claiming the
   capability is operational.

## Evidence Fields

Windows AppContainer evidence must include these redaction-safe fields when the
profile lifecycle or process-launch path is exercised:

| Field | Purpose |
|---|---|
| `schema` | Evidence schema identifier, for example `fcp.windows_appcontainer_process_launch.v1`. |
| `connector_id_hash` | Stable hash of the connector identity. |
| `profile_name_hash` | Stable hash of the AppContainer profile name. |
| `capabilities` | Normalized Windows AppContainer capability names. |
| `capability_decision` | `mapped`, `none_required`, or a typed denial result. |
| `lifecycle_action` | Created, reused, skipped, or launch-path unsupported. |
| `sid_present` | Whether a profile SID was resolved for launch. |
| `launch_mechanism` | The process-launch mechanism selected by the Windows backend. |
| `job_object_attached` | Whether Job Object limits were attached to the child. |
| `final_filter_strength` | The readiness layer reported for this run. |
| `timestamp` | RFC 3339 UTC timestamp with millisecond precision. |
| `skip_reason` | Exact prerequisite missing when the Windows-gated lane cannot run. |

## Performance Budget

AppContainer profile creation plus child launch is part of connector activation.
The budget follows the README cold-start target: p50 under 100 ms and p99 under
500 ms. Profile destroy should stay under 50 ms p50 and 200 ms p99. Evidence
that cannot measure the Windows path must emit a structured skip artifact rather
than silently passing.
