# Windows AppContainer Runbook

**Bead:** `flywheel_connectors-r4qcg.1.2`
**Audience:** Operators and agents validating the Windows sandbox path.

Windows remains `ProcessLimit` unless a connector process is launched through
the AppContainer process-launch path and the run emits evidence showing the
profile SID, capability decision, launch mechanism, and Job Object attachment.

## Verify AppContainer Is Functioning

1. Run the Windows workflow from GitHub Actions or a Windows worker.
2. Confirm the artifact path:

```text
artifacts/e2e/windows_appcontainer/<run-id>/
```

3. Inspect `windows_appcontainer_evidence.jsonl`.
4. Treat the lane as a skip unless at least one record shows:

```json
{
  "schema_version": "1.0.0",
  "event_type": "fcp.host.windows.appcontainer.process_launched",
  "launch_mechanism": "startupinfoex_security_capabilities",
  "sid_present": true,
  "job_object_attached": true,
  "redaction_scope": "public"
}
```

Profile creation by itself is not enough to claim `ProfileLevel`.

## Rollback

Rollback means returning to the conservative Windows posture: Job Object limits
only, no live AppContainer process-launch claim.

```powershell
Remove-Item Env:FCP_SANDBOX_WINDOWS_APPCONTAINER -ErrorAction SilentlyContinue
Remove-Item Env:FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E -ErrorAction SilentlyContinue
cargo test -p fcp-sandbox --target x86_64-pc-windows-msvc --features windows-appcontainer windows_appcontainer -- --nocapture
```

The expected result after rollback is a structured skip or
`SkippedInactive` evidence. The final readiness layer must remain
`process_limit`.

## Recovery

When AppContainer launch fails in production or CI:

1. Preserve the JSONL artifact and command output.
2. Check whether `FCP_SANDBOX_WINDOWS_APPCONTAINER=1` was set for the process.
3. Check whether the profile SID was resolved.
4. Confirm Job Object attachment happened after process creation and before the
   child was resumed.
5. Confirm capability names match
   `docs/architecture/windows_appcontainer_capability_map.md`.

Do not promote Windows readiness to `ProfileLevel` after a failed launch.

## Common Failures

| Error | Cause | Fix |
|---|---|---|
| `windows_appcontainer_not_active_createprocessasuser_path_unwired` | Operator did not opt in to the AppContainer launch path. | Set `FCP_SANDBOX_WINDOWS_APPCONTAINER=1` only for the Windows validation lane. |
| `CreateAppContainerProfile failed` | Windows rejected profile creation or the profile API is unavailable. | Keep the failure artifact and check OS edition, account policy, and profile name validity. |
| `DeriveCapabilitySidsFromName(...) failed` | Capability name is invalid for Windows. | Update the capability map and policy compiler together, or deny the FCP capability. |
| `AssignProcessToJobObject(child) failed` | Child process launched but could not receive resource limits. | Treat as fail-closed; do not claim AppContainer enforcement for that run. |

## Redacted Log Examples

Successful launch:

```json
{"schema_version":"1.0.0","event_type":"fcp.host.windows.appcontainer.process_launched","bead_id":"flywheel_connectors-r4qcg.1.2","actor":"host","redaction_scope":"public","correlation_id":"windows-appcontainer-ci","timestamp":"2026-05-10T12:00:00.000Z","profile_name_hash":"8d7c...","sid_present":true,"launch_mechanism":"startupinfoex_security_capabilities","job_object_attached":true,"final_filter_strength":"process_limit"}
```

Skipped lane:

```json
{"schema_version":"1.0.0","event_type":"fcp.host.windows.appcontainer.skip","bead_id":"flywheel_connectors-r4qcg.1.2","actor":"host","redaction_scope":"public","correlation_id":"windows-appcontainer-ci","timestamp":"2026-05-10T12:00:00.000Z","skip_reason":"live_e2e_not_requested","final_filter_strength":"process_limit"}
```

Denied capability:

```json
{"schema_version":"1.0.0","event_type":"fcp.host.windows.appcontainer.capability_denied","bead_id":"flywheel_connectors-r4qcg.1.2","actor":"host","redaction_scope":"public","correlation_id":"windows-appcontainer-ci","timestamp":"2026-05-10T12:00:00.000Z","capability_decision":"denied","error_class":"capability_unsupported"}
```

## Manual Profile Cleanup

Use manual cleanup only after confirming the profile name belongs to this FCP
installation and no connector process is using it. Prefer the host crash-recovery
cleanup path when available.

```powershell
# Example only. Replace with the exact fcp-* profile name after confirming scope.
$profileName = "fcp-example-0000000000000000"
$signature = @"
using System;
using System.Runtime.InteropServices;

public static class AppContainerCleanup {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    public static extern int DeleteAppContainerProfile(string appContainerName);
}
"@
Add-Type -TypeDefinition $signature
$hr = [AppContainerCleanup]::DeleteAppContainerProfile($profileName)
if ($hr -ne 0) {
    throw ("DeleteAppContainerProfile failed: HRESULT 0x{0:x8}" -f $hr)
}
```

If manual cleanup is required, record the profile name hash, reason, operator,
and timestamp in the bead or incident record. Never run broad profile cleanup.

## Differences From Linux And macOS

| Platform | Primary sandbox proof | Readiness layer |
|---|---|---|
| Linux | seccomp/Landlock/user namespace depending on profile | `syscall_level` when active |
| macOS | SBPL profile via sandbox APIs | `profile_level` |
| Windows | Job Object limits plus AppContainer launch evidence | `process_limit` until launch proof is active |

Windows AppContainer support is an additional launch path, not evidence that
all Windows sandbox features are complete. Integrity-level and firewall egress
hardening remain separate beads.
