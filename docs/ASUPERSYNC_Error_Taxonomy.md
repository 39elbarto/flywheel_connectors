# AsyncSuperSync Error Taxonomy & Cross-Crate Mapping

Version: 1.0.0
Status: Canonical reference for ASUPERSYNC migration error semantics

## Error Conversion Chain

```
AsyncError (fcp-async-core runtime)
    │
    ▼ ConnectorErrorMapping::from_async_error()
ConnectorError (e.g., OpenAIError, DiscordError)
    │
    ▼ ConnectorErrorMapping::to_fcp_error()
FcpError (canonical wire error)
    │
    ▼ FcpError::to_response()
FcpErrorResponse (JSON-RPC error payload with AI hints)
```

## 1. FcpError Canonical Classes

Source: `crates/fcp-core/src/error.rs`

### Protocol Errors (1xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 1001 | `InvalidRequest` | No | Fix request format/params | Caller must fix input |
| 1002 | `MalformedFrame` | No | Fix wire encoding | Caller must fix protocol |
| 1003 | `MissingField` | No | Add required field | Caller must fix input |
| 1004 | `ChecksumMismatch` | Yes | Retry (transient corruption) | Auto-retry safe |
| 1005 | `VersionMismatch` | No | Upgrade client/server | Manual intervention |

### Auth Errors (2xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 2001 | `Unauthorized` | No | Provide valid credentials | Re-authenticate |
| 2002 | `TokenExpired` | No | Refresh token, re-auth | Token refresh flow |
| 2003 | `InvalidSignature` | No | Re-sign with correct key | Cryptographic fix |

### Capability Errors (3xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 3001 | `CapabilityDenied` | No | Obtain required capability | Policy change needed |
| 3002 | `RateLimited` | Yes | Wait `retry_after_ms` | Auto-retry with backoff |
| 3003 | `OperationNotGranted` | No | Request operation grant | Policy change needed |
| 3004 | `ResourceNotAllowed` | No | Check network constraints | Policy change needed |

### Zone/Topology Errors (4xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 4001 | `ZoneViolation` | No | Check zone assignment | Architecture fix |
| 4002 | `TaintViolation` | No | Apply required taint | Policy fix |
| 4003 | `ElevationRequired` | No | Obtain elevation approval | Authorization flow |

### Connector Errors (5xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 5001 | `ConnectorUnavailable` | Yes | Wait for connector recovery | Auto-retry safe |
| 5002 | `NotConfigured` | No | Call `configure` first | Lifecycle fix |
| 5003 | `NotHandshaken` | No | Call `handshake` first | Lifecycle fix |
| 5004 | `HealthCheckFailed` | Yes | Check connector health | Diagnostic flow |
| 5005 | `StreamingNotSupported` | No | Use non-streaming API | API selection |

### Resource Errors (6xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 6001 | `ResourceNotFound` | No | Verify resource exists | Check ID/path |
| 6002 | `ResourceExhausted` | Yes | Wait for capacity | Auto-retry with backoff |
| 6003 | `BudgetExceeded` | Yes | Wait for budget refresh | Auto-retry after reset |
| 6004 | `Conflict` | Yes | Retry with fresh state | Optimistic concurrency |

### External Service Errors (7xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 7001 | `External` | Conditional | Check upstream service | Depends on status_code |
| 7002 | `UpstreamTimeout` | Yes | Retry with extended timeout | Auto-retry safe |
| 7003 | `DependencyUnavailable` | Yes | Wait for dependency | Auto-retry with backoff |

### Internal Errors (9xxx)

| Code | Variant | Retryable | Remediation | Recoverability |
|------|---------|-----------|-------------|----------------|
| 9001 | `Internal` | No | Report bug, check logs | Manual investigation |

## 2. AsyncError (Runtime Substrate)

Source: `crates/fcp-async-core/src/lib.rs`

| Variant | FcpError Mapping | Connector Mapping | Retryable |
|---------|-----------------|-------------------|-----------|
| `Timeout { timeout_ms }` | `External { status_code: 408 }` | Api(408, "deadline exceeded") | Yes |
| `Cancelled` | `External { status_code: 499 }` | Api(499, "cancelled") | No |
| `ChannelClosed` | `Internal` | Gateway("channel closed") | No |
| `ChannelFull` | `ResourceExhausted` | Gateway("channel full") | Yes |
| `ProtocolIo { message }` | `External` | Gateway(message) | Yes |
| `Join { message }` | `Internal` | Gateway(message) | No |
| `Runtime { message }` | `Internal` | Gateway(message) | No |

## 3. Connector Error Cross-Reference

### ConnectorErrorMapping Trait

Source: `crates/fcp-sdk/src/migration.rs`

Required implementors:
- `OpenAIError` (connectors/openai/src/error.rs)
- `DiscordError` (connectors/discord/src/error.rs)
- `GraphqlClientError` (crates/fcp-graphql/src/error.rs)

### OpenAI Connector Errors

| Variant | Retryable | FcpError | Retry After |
|---------|-----------|----------|-------------|
| `Http(reqwest::Error)` | Yes (timeout/connect) | `External { service: "openai" }` | None |
| `Json(serde_json::Error)` | No | `Internal` | None |
| `InvalidApiKey` | No | `Unauthorized` | None |
| `RateLimited { retry_after }` | Yes | `RateLimited { retry_after_ms }` | From header |
| `Overloaded` | Yes | `ConnectorUnavailable { code: 5001 }` | None |
| `ContextLengthExceeded` | No | `InvalidRequest` | None |
| `ContentFiltered` | No | `CapabilityDenied` | None |
| `Api { status, message }` | 5xx/429 only | `External { status_code }` | Optional |

### Discord Connector Errors

| Variant | Retryable | FcpError | Retry After |
|---------|-----------|----------|-------------|
| `Http(reqwest::Error)` | Yes | `External { service: "discord" }` | None |
| `Json(serde_json::Error)` | No | `Internal` | None |
| `WebSocket(tungstenite::Error)` | Yes | `External { service: "discord_gateway" }` | None |
| `Api { code, message, retry_after }` | 5xx/429 | `External` or `RateLimited` | From payload |
| `RateLimited { retry_after }` | Yes | `RateLimited { retry_after_ms }` | From payload |
| `Gateway(String)` | Yes | `ConnectorUnavailable { code: 5001 }` | None |

### Anthropic Connector Errors

| Variant | Retryable | FcpError | Retry After |
|---------|-----------|----------|-------------|
| `Http(reqwest::Error)` | Yes (timeout/connect) | `External { service: "anthropic" }` | None |
| `Json(serde_json::Error)` | No | `Internal` | None |
| `Api { status, message }` | 5xx/429 | `External { status_code }` | Optional |
| `RateLimited { retry_after }` | Yes | `RateLimited` | From header |
| `Overloaded` | Yes | `ConnectorUnavailable` | None |
| `InvalidApiKey` | No | `Unauthorized` | None |
| `ContextLengthExceeded` | No | `InvalidRequest` | None |

### Twitter Connector Errors

| Variant | Retryable | FcpError | Retry After |
|---------|-----------|----------|-------------|
| `Http(reqwest::Error)` | Yes | `External { service: "twitter" }` | None |
| `Json(serde_json::Error)` | No | `Internal` | None |
| `OAuth(String)` | No | `Unauthorized` | None |
| `Api { status, code, message }` | 5xx/429/503 | `External` or `RateLimited` | Optional |
| `RateLimited { retry_after }` | Yes | `RateLimited` | From header |
| `Stream(String)` | Yes | `ConnectorUnavailable` | None |
| `Config(String)` | No | `InvalidRequest` | None |
| `NotConfigured` | No | `NotConfigured` | None |

## 4. Infrastructure Error Types

### fcp-crypto Errors

Source: `crates/fcp-crypto/src/error.rs`

All crypto errors are non-retryable (deterministic failures).

| Variant | FcpError Mapping |
|---------|-----------------|
| `InvalidKeyLength` | `InvalidRequest` |
| `SignatureVerificationFailed` | `InvalidSignature` |
| `AeadEncryptFailed` / `AeadDecryptFailed` | `Internal` |
| `HpkeFailed` | `Internal` |
| `CoseFailed` | `Internal` |
| `TokenValidationError { violations }` | `CapabilityDenied` |

### fcp-streaming Errors

Source: `crates/fcp-streaming/src/error.rs`

| Variant | Retryable | FcpError Mapping |
|---------|-----------|-----------------|
| `ConnectionFailed` | Yes | `ConnectorUnavailable` |
| `ConnectionClosed` | Yes | `ConnectorUnavailable` |
| `HttpError { status }` | Conditional | `External { status_code }` |
| `Timeout` | Yes | `UpstreamTimeout` |
| `ReconnectLimitExceeded` | No | `ConnectorUnavailable` |
| `WebSocketError` | Yes | `External` |
| `SseError` | Yes | `External` |

### fcp-store Errors

Source: `crates/fcp-store/src/error.rs`

| Type | Retryable Variants | Non-Retryable Variants |
|------|-------------------|----------------------|
| `ObjectStoreError` | IoError | NotFound, QuotaExceeded, InvalidObject |
| `SymbolStoreError` | IoError | NotFound, IntegrityError |
| `QuarantineError` | - | PolicyViolation |
| `RepairError` | SourceUnavailable | InsufficientSymbols |
| `GcError` | IoError | InvalidRoot |

### fcp-raptorq Errors

Source: `crates/fcp-raptorq/src/error.rs`

| Type | Key Variants | Retryable |
|------|-------------|-----------|
| `ChunkError` | PayloadTooLarge, LengthMismatch | No |
| `EncodeError` | TooManyBlocks, MemoryLimitExceeded | No |
| `DecodeError` | InsufficientSymbols, HashMismatch, InvalidSymbol | Partial (InsufficientSymbols) |

## 5. Retryability Decision Matrix

### Always Retry (exponential backoff)
- `FcpError::RateLimited` — honor `retry_after_ms`
- `FcpError::ResourceExhausted` — wait for capacity
- `FcpError::BudgetExceeded` — wait for budget refresh
- `FcpError::UpstreamTimeout` — extend timeout or retry
- `FcpError::DependencyUnavailable` — wait for dependency
- `FcpError::ConnectorUnavailable` — wait for recovery
- `FcpError::ChecksumMismatch` — transient corruption
- `AsyncError::Timeout` — extend deadline or retry

### Conditional Retry
- `FcpError::External` — retry if `retryable: true` and `status_code >= 500`
- HTTP transport errors — retry on timeout/connect failures
- `FcpError::Conflict` — retry with fresh state (optimistic concurrency)

### Never Retry
- Auth failures (2xxx) — re-authenticate instead
- Capability denials (3xxx) — policy change needed
- Zone violations (4xxx) — architecture issue
- `NotConfigured` / `NotHandshaken` — lifecycle fix
- Crypto errors — deterministic, will always fail
- `InvalidRequest` / `MissingField` — fix input
- `AsyncError::Cancelled` — operation explicitly cancelled
- `Internal` — bug, needs investigation

## 6. Migration Behavior Deltas

### Pre-Migration (Direct Tokio)
- Each connector had hand-rolled retry loops with inconsistent behavior
- Timeout handling via `tokio::time::timeout` with varying defaults
- No shared error conversion between `AsyncError` and connector errors
- Rate limit handling was connector-specific

### Post-Migration (AsyncSuperSync)
- `RetryLoop::execute()` provides uniform retry with `AttemptOutcome` enum
- `ExecutionContext` enforces request-scoped deadlines
- `ConnectorErrorMapping` standardizes `AsyncError` → `ConnectorError` → `FcpError`
- `HttpRetryConfig` provides serializable, shared retry policy
- All connectors share identical retry/backoff/deadline semantics
