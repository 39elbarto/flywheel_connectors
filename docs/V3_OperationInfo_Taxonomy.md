# FCP V3 OperationInfo Safety/Risk/Idempotency Taxonomy

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Date**: 2026-03-18
> **Bead Reference**: `flywheel_connectors-j05nu.11.3`
> **Depends On**: `V3_Connector_Acceptance_Contract.md`

---

## Purpose

This document defines the reusable classification rules for `OperationInfo` fields across all FCP connectors. It tells implementors how to assign `SafetyTier`, `RiskLevel`, and `IdempotencyClass` to any operation without re-litigating safety semantics per connector.

---

## 1. SafetyTier Decision Tree

```
Is the operation read-only with no external side effects?
├── YES → Safe
└── NO → Does it create, modify, or send data externally?
    ├── YES → Is the effect irreversible or high-consequence?
    │   ├── YES → Dangerous
    │   └── NO → Risky
    └── NO → Does it modify system-level permissions or keys?
        ├── YES → Critical
        └── NO → Re-evaluate: it should fit one of the above.
```

### SafetyTier Reference Table

| SafetyTier | Approval | Receipt Required | Idempotency Floor | When |
|------------|----------|------------------|-------------------|------|
| Safe | Never | No | None | Read-only, no cost, no PII exposure, no state change |
| Risky | Policy | OperationReceipt | BestEffort (Strict recommended) | Creates/modifies external state, has cost, exposes PII |
| Dangerous | Always | OperationIntent + OperationReceipt | Strict (mandatory) | Deletes data, modifies ACLs, financial txn, irreversible |
| Critical | Quorum | Intent + Receipt + Audit | Strict (mandatory) | Key rotation, device enrollment, zone key changes |
| Forbidden | N/A | N/A | N/A | Never allowed |

---

## 2. RiskLevel Classification

RiskLevel is independent of SafetyTier. It describes the blast radius of failure, not the operation type.

| RiskLevel | Failure Consequence | Examples |
|-----------|-------------------|----------|
| Low | No lasting consequence; trivially recoverable | Search query fails, health check fails, read cache miss |
| Medium | May need manual intervention but recoverable | Message send fails (can retry), file upload interrupted |
| High | Data loss, financial impact, or security degradation | Database write lost, payment double-charged, credential exposed |
| Critical | Irreversible damage or systemic compromise | Production data deleted, ACLs misconfigured, key material leaked |

### Common Patterns

| Operation Pattern | Typical RiskLevel |
|------------------|------------------|
| List / Get / Search / Read | Low |
| Send message / Create resource | Medium |
| Update record / Modify config | Medium to High |
| Delete resource / Revoke access | High |
| Drop table / Modify ACLs / Transfer funds | Critical |
| Key rotation / Device enrollment | Critical |

---

## 3. IdempotencyClass Rules

### Decision Matrix

| SafetyTier | IdempotencyClass: None | IdempotencyClass: BestEffort | IdempotencyClass: Strict |
|------------|----------------------|---------------------------|------------------------|
| Safe | Permitted | Permitted | Permitted |
| Risky | Discouraged | Permitted | Recommended |
| Dangerous | **FORBIDDEN** | **FORBIDDEN** | **Required** |
| Critical | **FORBIDDEN** | **FORBIDDEN** | **Required** |

**Hard constraint**: `Dangerous` + `None` or `Dangerous` + `BestEffort` is a conformance violation.

### When to Use Each Class

**None**: The operation is inherently idempotent (GET requests) or purely read-only. Retrying cannot cause harm because there are no side effects.

**BestEffort**: The operation has side effects but the provider does not support server-side idempotency keys. The connector attempts client-side deduplication (e.g., dedup window, message ID tracking) but cannot guarantee exactly-once.

**Strict**: The operation uses server-side idempotency keys, transaction IDs, or equivalent mechanisms. The connector writes an OperationIntent before execution and an OperationReceipt after. Retry with the same idempotency key returns the prior result without re-execution.

---

## 4. Operation Verb Classification Templates

### Read Operations

| Verb Pattern | SafetyTier | RiskLevel | IdempotencyClass |
|-------------|-----------|-----------|-----------------|
| `get`, `read`, `fetch`, `describe` | Safe | Low | None |
| `list`, `search`, `query` (read-only) | Safe | Low | None |
| `introspect`, `health`, `status` | Safe | Low | None |
| `export`, `download` | Safe | Low-Medium | None |

### Create Operations

| Verb Pattern | SafetyTier | RiskLevel | IdempotencyClass |
|-------------|-----------|-----------|-----------------|
| `create`, `add`, `insert` | Risky | Medium | Strict (if provider supports) |
| `send` (message, email, notification) | Risky | Medium | BestEffort or Strict |
| `upload`, `import` | Risky | Medium | Strict |
| `register`, `enroll`, `subscribe` | Risky | Medium | Strict |

### Update Operations

| Verb Pattern | SafetyTier | RiskLevel | IdempotencyClass |
|-------------|-----------|-----------|-----------------|
| `update`, `modify`, `edit`, `patch` | Risky | Medium | BestEffort or Strict |
| `rename`, `move` | Risky | Medium-High | Strict |
| `enable`, `disable`, `toggle` | Risky | Medium | Strict |
| `configure`, `set` | Risky | Medium | Strict |

### Delete Operations

| Verb Pattern | SafetyTier | RiskLevel | IdempotencyClass |
|-------------|-----------|-----------|-----------------|
| `delete`, `remove`, `destroy` | Dangerous | High | Strict |
| `purge`, `wipe`, `truncate` | Dangerous | Critical | Strict |
| `revoke`, `ban`, `block` | Dangerous | High | Strict |
| `drop` (schema/table) | Dangerous | Critical | Strict |

### Permission / Security Operations

| Verb Pattern | SafetyTier | RiskLevel | IdempotencyClass |
|-------------|-----------|-----------|-----------------|
| `grant`, `assign_role` | Dangerous | High | Strict |
| `modify_acl`, `change_permissions` | Dangerous | Critical | Strict |
| `rotate_key`, `reset_credentials` | Critical | Critical | Strict |
| `deauthorize`, `disconnect` | Dangerous | High | Strict |

### Financial Operations

| Verb Pattern | SafetyTier | RiskLevel | IdempotencyClass |
|-------------|-----------|-----------|-----------------|
| `charge`, `pay`, `transfer` | Dangerous | Critical | Strict |
| `refund`, `reverse` | Dangerous | High | Strict |
| `create_invoice`, `create_subscription` | Risky | High | Strict |
| `get_balance`, `list_transactions` | Safe | Low | None |

---

## 5. Special Case Classifications

### Webhooks (Inbound)

Webhook event processing is an internal operation (the connector receives events). Classification depends on what the connector does with the event:

| Action | SafetyTier | Notes |
|--------|-----------|-------|
| Parse and forward event to agent | Safe | No external side effect |
| Auto-acknowledge to provider | Risky | External side effect (ack changes provider state) |
| Auto-respond to event | Risky | External side effect |

### Async Jobs / Long-Running Operations

| Phase | SafetyTier | Notes |
|-------|-----------|-------|
| Start job | Risky or Dangerous (depends on job type) | External side effect begins |
| Poll job status | Safe | Read-only check |
| Cancel job | Risky | External side effect (stops processing) |
| Retrieve job result | Safe | Read-only |

### Bridge Control Operations

| Operation | SafetyTier | Notes |
|-----------|-----------|-------|
| Start/restart bridge daemon | Risky | Process management, potential service disruption |
| Stop bridge daemon | Dangerous | Service becomes unavailable |
| Update bridge configuration | Risky | May affect service behavior |
| Check bridge status | Safe | Read-only |

### Batch / Bulk Operations

Batch operations inherit the highest safety tier of any individual operation in the batch:

- Batch of reads: Safe
- Batch with at least one create/update: Risky
- Batch with at least one delete: Dangerous

IdempotencyClass for batches: always Strict (partial failure + retry must not re-execute completed items).

---

## 6. Documenting Classification Decisions

Every connector bead's V3 contract task should include an operation inventory table:

```markdown
| Operation | SafetyTier | RiskLevel | IdempotencyClass | Rationale |
|-----------|-----------|-----------|-----------------|-----------|
| service.list_items | Safe | Low | None | Read-only list, no side effects |
| service.send_message | Risky | Medium | BestEffort | External delivery, no server-side idem key |
| service.delete_item | Dangerous | High | Strict | Irreversible deletion, provider supports idem key |
```

The Rationale column is required for any non-obvious classification (e.g., why a "create" is Dangerous instead of Risky, or why a "send" is BestEffort instead of Strict).

---

## 7. Validation Rules (Machine-Checkable)

These rules can be enforced by conformance tooling:

1. Every `OperationInfo` MUST have a non-empty `safety_tier`.
2. Every `OperationInfo` MUST have a non-empty `risk_level`.
3. Every `OperationInfo` MUST have a non-empty `idempotency`.
4. If `safety_tier == Dangerous`, then `idempotency` MUST be `Strict`.
5. If `safety_tier == Critical`, then `idempotency` MUST be `Strict`.
6. Every `OperationInfo` MUST have non-empty `input_schema` and `output_schema`.
7. Every `OperationInfo` MUST have at least one example.
8. `risk_level` MUST be >= `Medium` for any `Dangerous` operation.
9. `risk_level` MUST be `Critical` for any `Critical` operation.

---

## Changelog

- **1.0.0** (2026-03-18): Initial OperationInfo taxonomy. Covers SafetyTier decision tree, RiskLevel classification, IdempotencyClass rules, verb templates, special cases (webhooks, async jobs, bridges, batches), and machine-checkable validation rules.
