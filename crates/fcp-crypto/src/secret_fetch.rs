//! Secret-fetch hook API for secretless connector runtimes.
//!
//! This module defines the public contract a connector runtime uses when it
//! needs a credential value without persisting that value in connector state.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ZeroizingSecret;

#[cfg(any(test, feature = "test-utils"))]
use std::{
    collections::HashMap,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

/// Runtime hook used to fetch, rotate, and revoke secret material.
///
/// Implementations are shared across worker tasks, so they must be safe to
/// access concurrently. Returned secrets must own their buffers and zeroize
/// those buffers on drop.
pub trait SecretFetchHook: Send + Sync {
    /// Fetch a secret for a credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot satisfy the request. Implementations must not include the
    /// credential identifier verbatim in error messages.
    fn fetch(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError>;

    /// Replace the secret for a credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot rotate the value. Implementations must not include the
    /// credential identifier verbatim in error messages.
    fn rotate(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError>;

    /// Revoke the secret for a credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot revoke the value. Implementations must not include the
    /// credential identifier verbatim in error messages.
    fn revoke(&self, credential_id: &str) -> Result<(), SecretFetchError>;
}

/// SHA-256 digest of a credential identifier for redaction-safe diagnostics.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialIdHash(String);

impl CredentialIdHash {
    /// Hash a credential identifier with SHA-256.
    #[must_use]
    pub fn from_credential_id(credential_id: &str) -> Self {
        let digest = Sha256::digest(credential_id.as_bytes());
        Self(hex::encode(digest))
    }

    /// Return the lowercase hex-encoded SHA-256 digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CredentialIdHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CredentialIdHash").field(&self.0).finish()
    }
}

impl std::fmt::Display for CredentialIdHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redaction-safe error type for secret-fetch backends.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SecretFetchError {
    /// The requested credential does not exist.
    #[error("secret credential not found: credential_id_hash={credential_id_hash}")]
    NotFound {
        /// SHA-256 digest of the credential identifier.
        credential_id_hash: CredentialIdHash,
    },

    /// Backend failure unrelated to credential existence.
    #[error("secret backend error: {message}")]
    Backend {
        /// Redacted backend message.
        message: String,
    },

    /// Generic redacted failure where the concrete cause must stay hidden.
    #[error("secret fetch failed: {message}")]
    Redacted {
        /// Redacted failure message.
        message: String,
    },
}

impl SecretFetchError {
    /// Construct a not-found error from a raw credential identifier.
    #[must_use]
    pub fn not_found(credential_id: &str) -> Self {
        Self::NotFound {
            credential_id_hash: CredentialIdHash::from_credential_id(credential_id),
        }
    }

    /// Construct a backend error from a caller-redacted message.
    #[must_use]
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend {
            message: message.into(),
        }
    }

    /// Construct a generic redacted error from a caller-redacted message.
    #[must_use]
    pub fn redacted(message: impl Into<String>) -> Self {
        Self::Redacted {
            message: message.into(),
        }
    }
}

/// In-memory reference implementation for tests and examples.
///
/// This registry clones secret bytes into and out of memory, so it is not a
/// production backend. Use it for tests that need a concrete
/// [`SecretFetchHook`] implementation without standing up a secret manager.
#[cfg(any(test, feature = "test-utils"))]
pub struct InMemorySecretRegistry {
    secrets: RwLock<HashMap<String, Vec<u8>>>,
    fetch_counts: RwLock<HashMap<String, AtomicU64>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl InMemorySecretRegistry {
    /// Construct an empty in-memory registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
            fetch_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or replace a secret for tests.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    pub fn insert(&self, credential_id: impl Into<String>, secret: impl Into<Vec<u8>>) {
        let credential_id = credential_id.into();
        let mut secrets = self.secrets.write().expect("secret registry lock poisoned");
        secrets.insert(credential_id.clone(), secret.into());
        drop(secrets);
        self.ensure_counter(&credential_id);
    }

    /// Return the number of fetch attempts for a credential identifier.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    #[must_use]
    pub fn fetch_count_for(&self, credential_id: &str) -> u64 {
        self.fetch_counts
            .read()
            .expect("secret registry lock poisoned")
            .get(credential_id)
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }

    /// Return whether the registry contains a credential identifier.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    #[must_use]
    pub fn contains(&self, credential_id: &str) -> bool {
        self.secrets
            .read()
            .expect("secret registry lock poisoned")
            .contains_key(credential_id)
    }

    /// Return the number of registered credentials.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets
            .read()
            .expect("secret registry lock poisoned")
            .len()
    }

    /// Return whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn ensure_counter(&self, credential_id: &str) {
        self.fetch_counts
            .write()
            .expect("secret registry lock poisoned")
            .entry(credential_id.to_string())
            .or_insert_with(|| AtomicU64::new(0));
    }

    fn increment_fetch_count(&self, credential_id: &str) {
        self.ensure_counter(credential_id);
        if let Some(count) = self
            .fetch_counts
            .read()
            .expect("secret registry lock poisoned")
            .get(credential_id)
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for InMemorySecretRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::fmt::Debug for InMemorySecretRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySecretRegistry")
            .field("credentials", &self.len())
            .field(
                "fetch_counters",
                &self
                    .fetch_counts
                    .read()
                    .expect("secret registry lock poisoned")
                    .len(),
            )
            .field("credential_ids", &"<redacted>")
            .field("secret_bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl SecretFetchHook for InMemorySecretRegistry {
    fn fetch(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError> {
        self.increment_fetch_count(credential_id);
        self.secrets
            .read()
            .expect("secret registry lock poisoned")
            .get(credential_id)
            .cloned()
            .map(ZeroizingSecret::new)
            .ok_or_else(|| SecretFetchError::not_found(credential_id))
    }

    fn rotate(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError> {
        let mut secrets = self.secrets.write().expect("secret registry lock poisoned");
        let secret = secrets
            .get_mut(credential_id)
            .ok_or_else(|| SecretFetchError::not_found(credential_id))?;
        *secret = new_secret.as_bytes().to_vec();
        drop(secrets);
        Ok(())
    }

    fn revoke(&self, credential_id: &str) -> Result<(), SecretFetchError> {
        self.secrets
            .write()
            .expect("secret registry lock poisoned")
            .remove(credential_id)
            .map(|_| ())
            .ok_or_else(|| SecretFetchError::not_found(credential_id))
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;

    const CREDENTIAL_ID: &str = "prod/slack/bot-token";

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn credential_id_hash_is_sha256_hex() {
        let hash = CredentialIdHash::from_credential_id("credential");
        assert_eq!(
            hash.as_str(),
            "e265b6f564601a1fe8dc42785cd18a868bd8013eb5899560e79248767a683e6b"
        );
        assert_eq!(hash.as_str().len(), 64);
    }

    #[test]
    fn credential_id_hash_debug_and_display_omit_raw_id() {
        let hash = CredentialIdHash::from_credential_id(CREDENTIAL_ID);
        assert!(!hash.to_string().contains(CREDENTIAL_ID));
        assert!(!format!("{hash:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn not_found_display_omits_raw_id_and_includes_hash() {
        let error = SecretFetchError::not_found(CREDENTIAL_ID);
        let rendered = error.to_string();
        assert!(!rendered.contains(CREDENTIAL_ID));
        assert!(rendered.contains("credential_id_hash="));
        assert!(
            rendered.contains(&CredentialIdHash::from_credential_id(CREDENTIAL_ID).to_string())
        );
    }

    #[test]
    fn not_found_debug_omits_raw_id_and_includes_hash() {
        let error = SecretFetchError::not_found(CREDENTIAL_ID);
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(CREDENTIAL_ID));
        assert!(
            rendered.contains(&CredentialIdHash::from_credential_id(CREDENTIAL_ID).to_string())
        );
    }

    #[test]
    fn backend_error_uses_redacted_message_only() {
        let error = SecretFetchError::backend("backend unavailable");
        assert_eq!(
            error.to_string(),
            "secret backend error: backend unavailable"
        );
        assert!(!format!("{error:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn redacted_error_uses_redacted_message_only() {
        let error = SecretFetchError::redacted("policy denied");
        assert_eq!(error.to_string(), "secret fetch failed: policy denied");
        assert!(!format!("{error:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn registry_starts_empty() {
        let registry = InMemorySecretRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 0);
    }

    #[test]
    fn insert_and_fetch_returns_zeroizing_secret() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());

        let secret = registry.fetch(CREDENTIAL_ID).expect("secret exists");

        assert_eq!(secret.as_bytes(), b"xoxb-test");
        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 1);
    }

    #[test]
    fn missing_fetch_returns_redacted_not_found_and_counts_attempt() {
        let registry = InMemorySecretRegistry::new();

        let error = registry.fetch(CREDENTIAL_ID).expect_err("missing secret");

        assert_eq!(error, SecretFetchError::not_found(CREDENTIAL_ID));
        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 1);
        assert!(!error.to_string().contains(CREDENTIAL_ID));
    }

    #[test]
    fn rotate_replaces_existing_secret() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"old-token".as_slice());

        registry
            .rotate(CREDENTIAL_ID, ZeroizingSecret::from("new-token"))
            .expect("rotation succeeds");

        let secret = registry.fetch(CREDENTIAL_ID).expect("secret exists");
        assert_eq!(secret.as_bytes(), b"new-token");
    }

    #[test]
    fn rotate_missing_secret_returns_redacted_not_found() {
        let registry = InMemorySecretRegistry::new();

        let error = registry
            .rotate(CREDENTIAL_ID, ZeroizingSecret::from("new-token"))
            .expect_err("missing secret");

        assert_eq!(error, SecretFetchError::not_found(CREDENTIAL_ID));
        assert!(!format!("{error:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn revoke_removes_existing_secret() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());

        registry.revoke(CREDENTIAL_ID).expect("revoke succeeds");

        assert!(!registry.contains(CREDENTIAL_ID));
        assert!(registry.fetch(CREDENTIAL_ID).is_err());
    }

    #[test]
    fn revoke_missing_secret_returns_redacted_not_found() {
        let registry = InMemorySecretRegistry::new();

        let error = registry.revoke(CREDENTIAL_ID).expect_err("missing secret");

        assert_eq!(error, SecretFetchError::not_found(CREDENTIAL_ID));
        assert!(!error.to_string().contains(CREDENTIAL_ID));
    }

    #[test]
    fn registry_debug_redacts_ids_and_secret_bytes() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"xoxb-sensitive".as_slice());

        let rendered = format!("{registry:?}");

        assert!(rendered.contains("credentials"));
        assert!(!rendered.contains(CREDENTIAL_ID));
        assert!(!rendered.contains("xoxb-sensitive"));
    }

    #[test]
    fn concurrent_fetches_are_counted_under_contention() {
        let registry = Arc::new(InMemorySecretRegistry::new());
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());

        let workers: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    for _ in 0..50 {
                        let secret = registry.fetch(CREDENTIAL_ID).expect("secret exists");
                        assert_eq!(secret.as_bytes(), b"xoxb-test");
                    }
                })
            })
            .collect();

        for worker in workers {
            worker.join().expect("worker joins cleanly");
        }

        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 400);
    }

    #[test]
    fn registry_is_usable_as_secret_fetch_hook_trait_object() {
        let registry = Arc::new(InMemorySecretRegistry::new());
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());
        let hook: Arc<dyn SecretFetchHook> = registry;

        let secret = hook.fetch(CREDENTIAL_ID).expect("secret exists");

        assert_eq!(secret.as_bytes(), b"xoxb-test");
    }

    #[test]
    fn rotate_copies_secret_bytes_from_caller_owned_wrapper() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"old-token".as_slice());
        let new_secret = ZeroizingSecret::from("new-token");

        registry
            .rotate(CREDENTIAL_ID, new_secret.clone())
            .expect("rotation succeeds");

        drop(new_secret);
        let fetched = registry.fetch(CREDENTIAL_ID).expect("secret exists");
        assert_eq!(fetched.as_bytes(), b"new-token");
    }

    #[test]
    fn trait_and_registry_are_send_sync() {
        assert_send_sync::<InMemorySecretRegistry>();
        assert_send_sync::<Arc<dyn SecretFetchHook>>();
    }
}
