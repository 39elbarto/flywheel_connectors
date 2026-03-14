# WORKFLOW: Specification Refinement with APR (FCP3 docs)

> **Status**: INFORMATIONAL
> **Version**: 1.0.0
> **Last Updated**: January 2026
> **Bead Reference**: `flywheel_connectors-1n78.1.1`

---

## Purpose

This document captures the APR-based iterative specification refinement workflow so that engineers can run refinement rounds without rereading README.md.

**Goal**: Continuously harden and clarify FCP3 documentation through multi-round AI-assisted review, while using V2-era materials only as historical delta references when needed.

---

## What This Workflow Covers

The APR (Automated Plan Reviser Pro) + Oracle (browser automation) workflow reviews and refines:

| Document | Role |
|----------|------|
| `FCP_Specification_V3.md` | Canonical protocol and conformance specification |
| `FCP_Specification_V2.md` | Historical / interoperability reference only |
| `docs/fcp_model_connectors_rust.md` | Legacy connector authoring + implementation guide used for migration deltas |
| `README.md` | Overview + ops/dev UX |

---

## Scope

**In Scope:**
- Installing and running APR rounds
- Including the implementation doc periodically
- Running remotely (Oracle serve mode) when dev box has no browser
- Integrating APR feedback back into docs in a disciplined way

**Out of Scope:**
- FCP1/FCP2 compatibility shims or reviving V2 as the blessed target
- Node/npm tooling as a runtime platform requirement (APR/Oracle are dev tooling only)

---

## Why This Matters

The spec is large and security-sensitive. Iterative AI review is a force multiplier, but only if:
- We can repeat it reliably
- We can reproduce what changed and why
- We integrate feedback in a way that preserves the spec's internal consistency

---

## Prerequisites

- GPT Pro account available for Oracle/APR
- Browser access for initial APR run (can authenticate once, then use serve mode)
- Local or Tailscale network access for remote mode

---

## Setup (One-Time)

### Install APR

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/automated_plan_reviser_pro/main/install.sh" | bash
```

### Install Oracle (Browser Automation)

```bash
npm install -g @steipete/oracle
```

**Note**: Oracle is development tooling only; it is not part of the FCP runtime distribution.

---

## Workflow Configuration

**APR workflow file**: `.apr/workflows/fcp.yaml`

Expected document configuration:
```yaml
documents:
  readme: README.md
  spec: FCP_Specification_V3.md
  implementation: docs/fcp_model_connectors_rust.md
```

---

## Running Revision Rounds

### First Round (Requires Manual ChatGPT Login)

```bash
apr run 1 --login --wait
```

### Subsequent Rounds

```bash
apr run 2
apr run 3 --include-impl  # Include implementation doc every 3-4 rounds
```

### Inspect Status and Output

```bash
apr status           # Check Oracle sessions
apr show 5           # Show round 5 output
apr list             # List workflows
apr history          # Show revision history
```

---

## Remote/SSH Setup (Oracle Serve Mode)

Use this if your development machine is remote (SSH) and cannot open a local browser.

### On Your Local Machine (With Browser)

```bash
oracle serve --port 9333 --token "your-secret-token"
```

**Important**: Use port `9333` (not `9222`) to avoid clashing with Chrome DevTools.

### On the Remote Server

```bash
# Set environment variables
export ORACLE_REMOTE_HOST="100.x.x.x:9333"  # Local machine's Tailscale IP
export ORACLE_REMOTE_TOKEN="your-secret-token"

# Test connection
oracle -p "test" -e browser -m "5.2 Thinking"

# Now APR works normally
apr run 1
```

---

## Integration Discipline

When APR produces feedback for round N, follow this process:

### Step 1: Prime the Coding Agent

Don't assume partial memory. Read ALL context:
- `AGENTS.md` and `README.md`
- `FCP_Specification_V3.md`
- `docs/fcp_model_connectors_rust.md` only when reconciling legacy V2 assumptions that still appear in the repo

### Step 2: Integrate Feedback Carefully

- Treat GPT output as **suggestions**; validate each claim against the spec's goals
- Prefer "mechanical enforcement" changes over editorial prose
- Ensure changes do not introduce FCP1/FCP2 compatibility shims or re-bless V2-era execution models

### Step 3: Harmonize Documents (In Order)

1. **Update `README.md` first** — Human-facing story and operator truth
2. **Update migration / legacy-reference docs second** — Keep cleanup notes honest without reintroducing stale mental models
3. **Update `FCP_Specification_V3.md` last** — Canonical, ensure correctness

### Step 4: Commit

Commit in logical groupings with clear messages.

---

## Useful APR Commands

| Command | Description |
|---------|-------------|
| `apr status` | Check Oracle sessions |
| `apr list` | List workflows |
| `apr history` | Show revision history |
| `apr diff 4 5` | Compare rounds 4 and 5 |
| `apr stats` | Convergence analytics |
| `apr integrate 5 -c` | Copy integration prompt to clipboard |
| `apr show N` | Show round N output |

---

## Key Files

| File | Purpose |
|------|---------|
| `FCP_Specification_V3.md` | Main protocol specification |
| `FCP_Specification_V2.md` | Historical / interoperability reference only |
| `docs/fcp_model_connectors_rust.md` | Legacy Rust implementation guide |
| `.apr/workflows/fcp.yaml` | Workflow configuration |
| `.apr/rounds/fcp/round_N.md` | GPT Pro output per round |

---

## FCP3-Only Reminder

This workflow explicitly keeps the repository **FCP3-first**:
- No FCP1 compatibility work
- No FCP2 revival as the canonical execution model
- No hybrid translator layer as the blessed steady state

When reviewing suggestions, reject any that would introduce backwards compatibility shims.

---

## Acceptance Criteria

This workflow document is complete when:

- [ ] A new contributor can run APR rounds without consulting README.md
- [ ] The workflow notes explicitly maintain an FCP3-first posture without compatibility shims
- [ ] Remote mode (Oracle serve) is documented
- [ ] Integration discipline is clearly specified

---

## References

- [APR Repository](https://github.com/Dicklesworthstone/automated_plan_reviser_pro)
- [Oracle NPM Package](https://www.npmjs.com/package/@steipete/oracle)
- STANDARD_Requirements_Index.md (spec-to-bead mapping)
