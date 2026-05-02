# Windows Live-Migration Research + Design Proposal (br-swfj3.1.3)

**Status:** Research / design proposal (2026-05-02). No production
implementation yet.
**Bead:** `flywheel_connectors-swfj3.1.3` [D.7.3]
**Parent:** `swfj3.1` [D.7] live process migration epic
**Siblings landed:** `swfj3.1.1` (Linux CRIU wrapper, commit
`1d8e250fa`), `swfj3.1.2` (macOS process-snapshot protocol, commit
`54b12b1cc`).
**Author:** AmberLark (Claude Opus 4.7)

## Problem

`fcp-host` already has working live-migration substrate on Linux
(`crates/fcp-host/src/migration_linux.rs` — CRIU wrapper) and macOS
(`crates/fcp-host/src/migration_macos.rs` — `dyld_info` /
`mach_task_t` snapshot). Windows has no equivalent. Without one, the
"connector follows the user" promise — a 30-minute
`whisper.transcribe_long` invocation surviving a desktop → laptop
migration with zero retry — is portable only across Linux and macOS
hosts.

The Windows ecosystem does not ship a CRIU equivalent. Process
checkpointing is achievable through a combination of platform APIs
plus careful handle/socket re-binding, but each candidate carries
distinct trade-offs.

## Hard requirements

A Windows path MUST satisfy the same contract as the Linux + macOS
paths:

1. **Capture** the connector subprocess's user-space memory, register
   state, open file/socket handles, and any connector-supplied
   "graceful checkpoint" payload.
2. **Externalize** the captured bytes as a content-addressed mesh
   object (per `swfj3.1.4` snapshot-storage protocol — pending
   breakout).
3. **Resume** the connector on a different node from the externalized
   bytes via the resume-on-target handshake (per `swfj3.1.5`).
4. **No platform privilege escalation beyond what an installer
   already requires.** The user's existing `fcp-host` install rights
   must be sufficient; we do not require a separately-signed driver.
5. **Bounded latency.** Snapshot must complete within the
   connector's `connect_timeout_ms` budget (default 10s) so a
   migration cycle is operationally invisible at human time scales.

## Candidates evaluated

### A. WSL2 + Linux CRIU (RECOMMENDED for first cut)

Run the connector subprocess inside WSL2; reuse the Linux
`migration_linux.rs` code path. The WSL2 distribution is the
runtime; CRIU snapshots the connector inside that runtime.

**Pros**
- Reuses 100% of the proven Linux CRIU work. Zero new
  cross-platform code to maintain.
- WSL2 is a first-party Microsoft technology shipped with Windows 10
  21H1+ and Windows 11. Installation is `wsl --install` for users
  who don't already have it.
- The Linux file-descriptor remap and dyld-style binary re-link
  problems are solved by CRIU; we don't need to re-derive them.
- Cross-host migration: a WSL2-hosted connector can in principle
  resume on a Linux host without bytes-format conversion (both run
  the same Linux CRIU image).

**Cons**
- WSL2 is a **dependency**, not a library — users must have it
  installed and configured. `fcp-host` cannot silently install it on
  the user's behalf.
- Adds latency to connector cold-start (WSL2 boot + connector
  process spawn).
- Introduces a Linux network namespace inside Windows, which means
  egress policies declared in `NetworkConstraints` must be re-mapped
  through the WSL2 mirrored-network mode (Windows 11 22H2+) or the
  legacy NAT mode. Mirrored-network mode is the supported posture.
- Connectors that spawn Windows-native helper processes
  (PowerShell, .NET tools, native Win32 services) cannot be fully
  contained inside WSL2.

**Implementation cost estimate:** 2–3 engineer-weeks for the
Windows-side host wiring (WSL2 lifecycle, distro provisioning,
mirrored-network configuration, propagating Windows-side egress
policy into the WSL2 instance) plus 1 week of integration testing.
Code reuse from `migration_linux.rs` is ~80%.

**Security model**
- WSL2 runs in a lightweight Hyper-V utility VM. The Windows host
  cannot directly observe connector memory; the boundary is a real
  hypervisor isolation boundary.
- CRIU snapshots inside WSL2 require `CAP_CHECKPOINT_RESTORE` (or
  `CAP_SYS_ADMIN` on older kernels). The WSL2 distro grants this to
  the WSL2 init; `fcp-host` does NOT need Windows-side admin for
  WSL2-internal CRIU.
- Snapshot bytes never traverse the Windows kernel directly — they
  flow VM-internal memory → WSL2 filesystem → Windows-side mesh
  store via the `\\wsl.localhost\` UNC bridge. Egress policy still
  applies to the Windows-side mesh store.

### B. MiniDumpWriteDump + DbgHelp + handle re-bind

Use `MiniDumpWriteDump` (DbgHelp.dll) to capture a full process
memory snapshot, then on resume use `LoadLibrary` /
`MiniDumpReadDumpStream` to re-create the address space, plus
`DuplicateHandle` / `WSADuplicateSocket` to re-bind file and socket
handles.

**Pros**
- Native Windows API; no third-party runtime dependency.
- Snapshot format (`MINIDUMP_TYPE::MiniDumpWithFullMemory`) is
  documented and stable across Windows versions.
- `DbgHelp` ships with every Windows install; no driver, no signed
  binary, no installer step.

**Cons**
- **No tested CRIU-equivalent for resume.** `MiniDumpWriteDump`
  produces a *forensic* snapshot designed for `WinDbg` post-mortem,
  not a re-executable image. Restoring a process from a minidump is
  not a supported Microsoft path — every existing tool that does
  this (e.g., `Procdump` clone forks) treats it as a research
  curiosity.
- File handles, socket handles, registry handles, GDI handles,
  module bases (ASLR), and TLS slots all need manual re-binding
  during resume. The non-trivial cases (named pipes,
  registry-watcher handles, kernel object inheritance trees)
  require significant ad-hoc engineering per handle type.
- Connectors that call into `kernel32!CreateThread` with non-portable
  TLS expectations may not survive re-bind.

**Implementation cost estimate:** 8–12 engineer-weeks for a
production-quality implementation; another 4–6 weeks of integration
testing on diverse connectors. The core risk is "every connector is
a bug" — handle-binding correctness is per-connector empirical work.

**Security model**
- `MiniDumpWriteDump` requires `PROCESS_QUERY_INFORMATION` +
  `PROCESS_VM_READ` on the target process. `fcp-host` already owns
  these on subprocesses it spawned.
- The resulting `.dmp` file contains every byte of connector
  memory, including secrets the connector held in the clear at
  snapshot time. The `swfj3.1.4` mesh-object snapshot-storage
  protocol MUST encrypt the dump at rest with the zone key (we do
  not get to keep secrets out of the snapshot — the connector's
  whole point is to hold them in memory).

### C. WerCaptureMemory (Windows Error Reporting modern API)

`Wer.dll`'s `WerCaptureMemory` and `WerLiveKernelReports` API,
introduced in newer Windows 10 / 11 builds, is the modern successor
to `MiniDumpWriteDump` for production telemetry.

**Pros**
- Designed for live capture on a running process (vs.
  `MiniDumpWriteDump` which historically expected the process to
  pause). Slightly lower latency.
- Integrates with WER infrastructure for snapshot streaming.

**Cons**
- Same restore problem as Option B — captures forensic bytes, not
  a re-executable image.
- Newer API, less ecosystem tooling for restore.
- Documentation is thin; some entry points are undocumented or
  reserved for Microsoft tooling (Watson).

**Verdict:** Strictly worse than Option B for our purposes
(same restore problem, less mature ecosystem). Skip.

### D. Job Object freeze + manual snapshot

Place the connector subprocess in a Windows Job Object with
`JOB_OBJECT_LIMIT_FREEZE`, then use `NtReadVirtualMemory` and
`NtQuerySystemInformation` to manually walk the address space and
build our own snapshot format. Resume re-creates the process and
manually restores memory + handles.

**Pros**
- Full control over snapshot format — we can design something that
  fits the FCP3 mesh-object schema directly.
- Job Object freeze is well-documented and works back to
  Windows 8 / Server 2012.

**Cons**
- We are re-implementing CRIU from scratch on Windows. Every
  edge case (signal handlers, suspended threads, kernel-mode
  callbacks, async I/O completion ports, COM/RPC contexts,
  WinSock provider state, SSL/TLS context tables) is our problem.
- `NtRead/NtQuery*` are technically NT-internal APIs; Microsoft
  reserves the right to change them. Production deployment is at
  per-Windows-version risk.

**Implementation cost estimate:** 16–24 engineer-weeks for a
correctness-first prototype; longer for production hardening.
Effectively a research project that delays connector-portability
indefinitely.

**Verdict:** Out of scope for FCP3 unless a third-party Windows
CRIU clone matures (so far, no such project has reached
production maturity).

### E. Hyper-V live VM migration

Run each connector in its own Hyper-V VM (or a shared light VM)
and use Hyper-V Live Migration to move the VM. This is the same
foundational technology that powers Azure VM live migration.

**Pros**
- A proven, production-grade Microsoft-supported live-migration
  path. Battle-tested at hyperscale.
- VM boundary is a strong isolation primitive — exceeds our
  WASI-sandbox guarantees.

**Cons**
- Hyper-V requires Windows Pro or Enterprise + virtualization
  enabled in BIOS. Significant non-trivial fraction of consumer
  machines (Windows Home users) cannot run it.
- VM-per-connector overhead is unacceptable at the "user installs
  20 connectors on a laptop" scale we target. A shared VM would
  re-introduce all the CRIU-style problems we tried to avoid by
  using Hyper-V.
- Cross-host migration only works between hosts with compatible
  Hyper-V configurations.

**Verdict:** Useful in a future Windows-Server / cloud deployment
profile, but not the right primary path for the target operator
laptop / desktop.

### F. Connector-level "graceful checkpoint" only (Windows portability tier)

Don't try to capture process memory at all on Windows. Instead,
require connectors that want migration support to implement a
`GracefulCheckpoint` trait that returns a serializable
"resume-from-here" struct, which the connector itself rebuilds
state from on the target node. This is the same primitive
`MacosGracefulCheckpoint` exposes today on macOS.

**Pros**
- Zero new platform plumbing on Windows. Implementation cost is
  per-connector, not per-platform.
- Connectors that don't want migration support simply opt out —
  graceful degradation rather than hard failure.
- Cross-platform: a graceful checkpoint emitted on Windows can be
  resumed on Linux or macOS, because the bytes are
  connector-defined and platform-agnostic.

**Cons**
- Doesn't satisfy the "30-minute transcription survives lid
  close" promise for arbitrary connectors. Only connectors that
  implement `GracefulCheckpoint` get migration; everything else
  hard-fails on lease transfer.
- Pushes correctness burden onto connector authors — every
  connector needs to express its "resume from here" state machine
  in protocol. For some connectors (a long `whisper` transcription
  job) this is natural; for others (a stateful `kubectl exec`
  shell) it's awkward.

**Verdict:** Already supported on macOS via
`MacosGracefulCheckpoint`. Should also be the **Windows Tier 1**
path until WSL2-CRIU is operational.

## Recommendation: phased rollout

### Tier 1 (immediate, ~0 weeks): Connector-level graceful checkpoint

Document and surface `GracefulCheckpoint` as the supported Windows
migration path. Connectors that opt in get cross-platform
migration. Connectors that do not opt in fail-soft on Windows: lease
transfer aborts with a structured `LeaseTransferReason::PlatformUnsupported`
denial that the operator sees clearly.

This requires NO new Windows-specific code in `fcp-host`. The
`GracefulCheckpoint` primitive is already designed for macOS and
generalizes trivially.

### Tier 2 (first cut, ~3 weeks): WSL2 + Linux CRIU bridge

Add `crates/fcp-host/src/migration_windows.rs` implementing a
WSL2 lifecycle wrapper. Connectors that run inside the
`fcp-host`-managed WSL2 distro inherit Linux CRIU behaviour
without per-connector changes. Cross-host migration to a Linux
host works directly because the snapshot format is identical.

Operator UX: `fcp-host` detects WSL2 availability at boot. If
present, connector launches inside WSL2 by default (with an
opt-out per connector for those that need Windows-native APIs).
If absent, connector launches as a Windows-native process and
falls back to Tier 1 graceful-checkpoint semantics.

### Tier 3 (long-horizon, defer): Native Windows CRIU equivalent

Track the upstream Windows CRIU community work (so far minimal —
the most active candidate is the
[https://github.com/Microsoft/cppwinrt/issues](https://github.com/Microsoft/cppwinrt)
discussions on process-state capture, which has not landed). If a
production-quality Windows CRIU equivalent materialises in the
ecosystem, integrate it analogously to how `migration_linux.rs`
wraps real CRIU today.

Until then, Tier 2 (WSL2 bridge) covers the core "lid close"
use-case; Tier 1 (graceful checkpoint) covers the "Windows-native
connector" use-case. Native Windows process-memory live migration
without a runtime dependency is **deferred indefinitely** as a
research project, not a product feature.

## Trade-off summary

| Option | Snapshot fidelity | New Win-only LoC | Latency | Platform req | Operational risk | Recommendation |
|--------|-------------------|------------------|---------|---------------|------------------|----------------|
| A: WSL2 + Linux CRIU | High (full state) | Low (~3 weeks) | ~1–2 s | WSL2 installed | Low | **Tier 2 (first cut)** |
| B: MiniDumpWriteDump | Forensic only | Very high (~12 weeks) | ~3 s capture | None | Very high (per-connector) | Defer |
| C: WerCaptureMemory | Same as B | High | ~2 s | Win 10 21H1+ | Same as B | Skip (worse than B) |
| D: Job Object + manual | Full (in theory) | Very high (~24 weeks) | ~variable | None | Highest | Defer indefinitely |
| E: Hyper-V VM | Full | Medium | ~5–30 s | Pro/Enterprise + VT-x | Medium | Future server deployment |
| F: Graceful checkpoint | Connector-defined | Zero | ~ms | None | Per-connector | **Tier 1 (immediate)** |

## Implementation sketch (Tier 1 + Tier 2)

### Tier 1: surface the existing `GracefulCheckpoint` primitive on Windows

Already shipped on macOS. The Windows path is:

1. `fcp-host` boots on Windows; detects platform via `cfg!(target_os = "windows")`.
2. If a connector subprocess is the target of a lease transfer and
   does not implement `GracefulCheckpoint`, the host returns
   `LeaseTransferReason::PlatformUnsupported` to the lease
   coordinator. Operator sees: "Connector `whisper:1.0.0` cannot
   migrate from this Windows host because it does not implement
   GracefulCheckpoint. Choose a connector that does, or move to a
   Linux/macOS host for migration support."
3. If the connector DOES implement `GracefulCheckpoint`, the host
   asks the connector for its serializable resume payload, persists
   that as a content-addressed mesh object via `swfj3.1.4`, and
   completes the lease transfer.

No new Windows-specific code required. ~50 lines of platform
detection and error wiring in `fcp-host`. Documentation update only.

### Tier 2: minimal `migration_windows.rs` skeleton (stub)

```rust
//! Windows live-migration wrapper (br-swfj3.1.3 Tier 2).
//!
//! Bridges Windows-side fcp-host to a managed WSL2 distro that
//! runs the connector subprocess and uses Linux CRIU for the
//! actual state-capture work. Reuses migration_linux.rs.

#[cfg(target_os = "windows")]
pub struct Wsl2MigrationBridge {
    distro_name: String,
    wsl_executable: PathBuf,
}

#[cfg(target_os = "windows")]
impl Wsl2MigrationBridge {
    /// Detect whether WSL2 is installed and operational. Returns
    /// `None` if WSL2 is unavailable — caller falls back to Tier 1
    /// graceful-checkpoint semantics.
    pub fn detect() -> Option<Self> { /* call `wsl --status` */ }

    /// Launch a connector subprocess inside the WSL2 distro,
    /// returning the WSL-internal PID.
    pub fn spawn_connector(&self, manifest: &ConnectorManifest)
        -> Result<u32, WindowsMigrationError> { ... }

    /// Snapshot a WSL-internal connector via Linux CRIU. Returns
    /// the snapshot bytes (same format as migration_linux.rs
    /// produces; cross-host compatible).
    pub fn snapshot(&self, wsl_pid: u32, request: ConnectorCheckpointRequest)
        -> Result<Vec<u8>, WindowsMigrationError> { ... }

    /// Resume a connector from snapshot bytes inside the WSL2
    /// distro.
    pub fn resume(&self, snapshot_bytes: &[u8], target_pid: u32)
        -> Result<u32, WindowsMigrationError> { ... }
}
```

Actual implementation of `spawn_connector`, `snapshot`, and
`resume` largely shells out to `wsl <command>`, and the snapshot
flow proxies to the existing `migration_linux::*` API once the
process is reachable inside the WSL2 namespace.

## Open questions

1. **WSL2 mirrored-network mode + `NetworkConstraints` enforcement.**
   The Windows-side `EgressGuard` evaluates `host_allow` against
   Windows-resolved DNS; the WSL2-side connector resolves DNS
   inside the WSL2 namespace. Mirrored-network mode (Windows 11
   22H2+) makes the two views consistent but introduces edge cases
   for ip-literal egress. Needs follow-up bead.

2. **WSL2 distro versioning and reproducibility.** What guarantees
   we have that "same connector binary in same WSL2 distro version"
   reconstructs identically across hosts. Probably needs a
   distro-pin in the connector manifest similar to
   `binary_artifact_id`.

3. **Cross-host snapshot compatibility.** A snapshot taken inside
   WSL2-Ubuntu-22.04 — can it resume on a Linux-host running
   Ubuntu-22.04? CRIU is sensitive to kernel version + glibc
   version. Probably YES if the kernel + libc match; needs
   empirical confirmation in `swfj3.1.6` chaos test.

4. **GracefulCheckpoint serde format.** The macOS path
   (`MacosGracefulCheckpoint`) already pins a `Vec<u8>`
   connector-defined byte payload. Reusing that on Windows is
   trivial; the question is whether we want to evolve the trait
   to be cross-platform-portable (likely yes).

## Cross-references

- Linux side: `crates/fcp-host/src/migration_linux.rs` (CRIU wrapper)
- macOS side: `crates/fcp-host/src/migration_macos.rs` (dyld_info /
  mach task ports, plus `MacosGracefulCheckpoint`)
- swfj3 epic: `flywheel_connectors-swfj3` ([REALITY-CHECK/D]
  Computation Migration: DESIGNED → IMPLEMENTED → PROVEN)
- swfj3.1 (live-migration child): `flywheel_connectors-swfj3.1` (D.7)
- Sibling: `swfj3.1.4` mesh-object snapshot-storage protocol (not
  yet broken out as a bead)
- Sibling: `swfj3.1.5` resume-on-target handshake (not yet broken
  out as a bead)
- Sibling: `swfj3.1.6` chaos test (not yet broken out as a bead)
