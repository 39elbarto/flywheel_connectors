# SecretFetchHook Contract

`SecretFetchHook` is the public runtime boundary for secretless connector
credentials. A connector receives a credential identifier from its manifest or
host configuration, then asks the hook for a `ZeroizingSecret` at the moment it
needs to call an external service.

The trait lives in `fcp-crypto` because it is coupled to `ZeroizingSecret`, not
to first-run provisioning. Bootstrap code may install or configure a production
backend later, but connector runtimes only need the small fetch, rotate, and
revoke contract.

## API Shape

```rust
use fcp_crypto::{SecretFetchError, SecretFetchHook, ZeroizingSecret};

pub trait SecretFetchHook: Send + Sync {
    fn fetch(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError>;

    fn rotate(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError>;

    fn revoke(&self, credential_id: &str) -> Result<(), SecretFetchError>;
}
```

Implementations must be `Send + Sync` because hosts share one hook across
worker tasks. The trait is synchronous by design: a production backend may
internally cache, block, or bridge to an async secret manager, but connector
call sites should not need a runtime-specific dependency to request a secret.

## Redaction Requirements

`credential_id` is routing metadata and may contain provider names, account
names, tenant IDs, or other sensitive operator context. Hook implementations
must not include it verbatim in `Debug`, `Display`, logs, or propagated error
messages.

For missing credentials, construct `SecretFetchError::not_found(credential_id)`.
That stores a SHA-256 digest in `CredentialIdHash`:

```rust
let error = SecretFetchError::not_found("prod/slack/bot-token");
assert!(!error.to_string().contains("prod/slack/bot-token"));
```

`SecretFetchError::backend` and `SecretFetchError::redacted` accept only
caller-redacted messages. Do not pass provider errors that echo request paths,
credential IDs, tokens, or secret-manager key names.

## Zero-On-Drop Semantics

`fetch` and `rotate` use `ZeroizingSecret`. Every returned value owns its byte
buffer, prints only a redacted length, and zeroizes that buffer on drop. Cloning
a `ZeroizingSecret` creates a second owned buffer with the same drop behavior.

The hook contract does not make static fixtures safe. Test helpers that build
secrets from static byte strings can zeroize only the copied runtime buffer, not
the static source bytes embedded in the binary.

## Test Utility Registry

Enable the `test-utils` feature, or use crate unit tests, to access
`fcp_crypto::test_utils::InMemorySecretRegistry`. It is a reference
implementation for tests:

```rust
use fcp_crypto::{SecretFetchHook, ZeroizingSecret};
use fcp_crypto::test_utils::InMemorySecretRegistry;

let registry = InMemorySecretRegistry::new();
registry.insert("local/test-token", b"secret".as_slice());

let secret = registry.fetch("local/test-token").unwrap();
assert_eq!(secret.as_bytes(), b"secret");

registry.rotate("local/test-token", ZeroizingSecret::from("rotated")).unwrap();
registry.revoke("local/test-token").unwrap();
```

`InMemorySecretRegistry` is not a production backend. It clones secret bytes into
process memory and exists so tests can exercise the exact public trait without
mocking a secret manager.
