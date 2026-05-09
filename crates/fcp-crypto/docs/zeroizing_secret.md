# ZeroizingSecret

`ZeroizingSecret` is the workspace-owned carrier for secret bytes that must be
wiped when dropped.

## Construction

Use `ZeroizingSecret::new(bytes)`, `ZeroizingSecret::from_str(text)`,
`ZeroizingSecret::with_zeroize_drop(bytes)`, or the `From<Vec<u8>>`,
`From<&[u8]>`, and `From<&str>` implementations.

`from_str` and `From<&str>` copy the string into an owned byte buffer. The
caller still owns the original string and remains responsible for its lifetime.

## Drop And Clone

The wrapper owns a `Vec<u8>` and derives `ZeroizeOnDrop`, so the owned buffer is
zeroed when the wrapper is dropped. Cloning is allowed deliberately: each clone
owns an independent buffer, and each clone is wiped independently on drop.

## Redaction

`Debug` and `Display` expose only the byte length:

```text
ZeroizingSecret(<redacted, len=N>)
```

They never print secret bytes.

## Equality

`ZeroizingSecret` does not implement `PartialEq`, `Eq`, `PartialOrd`, or `Ord`.
Use `constant_time_eq` when comparing secret values. Length still affects the
result before byte comparison; equal-length byte comparison is constant time.

## Serialization

`Serialize` and `Deserialize` are intentionally unimplemented. Secret values
must not enter logs, manifests, fixtures, or wire formats by default. Tests that
need public golden-vector secrets may use
`fcp_crypto::test_utils::unsafe_construct_from_static_test_secret` behind the
`test-utils` feature or from inside crate tests.
