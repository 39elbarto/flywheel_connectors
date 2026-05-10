# Windows Cross-Compile Notes

**Bead:** `flywheel_connectors-r4qcg.1.2`

Most development for Windows AppContainer support happens from macOS or Linux,
but the final proof must run on a Windows runner because the AppContainer APIs
and process-launch behavior are OS-enforced.

## Targets

Use the GNU target for local syntax/type checks from non-Windows machines when
the toolchain is available:

```bash
rustup target add x86_64-pc-windows-gnu
```

The CI and release proof path uses MSVC on `windows-latest`:

```bash
rustup target add x86_64-pc-windows-msvc
```

Agents in this repository should offload heavy compile and test work through
`rch`, following `AGENTS.md`. The local command shape is documented here so the
same target and feature flags are visible:

```bash
rch exec -- cargo check -p fcp-sandbox --target x86_64-pc-windows-gnu --features windows-appcontainer --all-targets
```

On a Windows runner, use:

```bash
cargo test -p fcp-sandbox --target x86_64-pc-windows-msvc --features windows-appcontainer windows_appcontainer -- --nocapture
```

## Linux Host Prerequisites

For the GNU target from Linux, install a MinGW toolchain such as `mingw-w64`.
Exact package names vary by distribution. The target is useful for compile
coverage, not for proving AppContainer enforcement.

## macOS Host Prerequisites

macOS can install the Rust Windows GNU target, but linking Windows binaries may
also require a MinGW cross linker. If linking is unavailable, use the Windows
GitHub Actions lane rather than weakening the proof criteria.

## What Counts As Proof

Cross-compilation proves that Rust code and target-specific dependencies type
check for Windows. It does not prove:

- `CreateAppContainerProfile` succeeds.
- `STARTUPINFOEXW` carries a valid AppContainer SID to a child process.
- Job Object limits are attached to the launched child.
- A denied filesystem or network action fails at the OS boundary.

Those claims require the Windows-gated workflow and its JSONL evidence under
`artifacts/e2e/windows_appcontainer/<run-id>/`.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| target not installed | Rust target missing | Add the target with `rustup target add ...`. |
| linker not found | MinGW/MSVC linker missing | Use a Windows runner or install the host linker. |
| AppContainer test skipped | Live Windows prerequisites not enabled | Inspect the uploaded skip artifact for the exact reason. |
| AppContainer launch fails | OS policy or privilege issue | Keep the failure artifact; do not convert it into a passing skip. |

## CI Lane

The canonical CI lane is `.github/workflows/windows_appcontainer_e2e.yml`.
It runs on `windows-latest`, compiles `fcp-sandbox` for
`x86_64-pc-windows-msvc`, runs the Windows AppContainer tests, and uploads
redaction-safe evidence or skip artifacts.
