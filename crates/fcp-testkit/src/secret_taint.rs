//! Secret taint tracking helpers for adversarial connector tests.
//!
//! The tracker stores registered test secrets privately, scans byte/string/JSON
//! surfaces for exact leaks, and only exposes redaction-safe fingerprints in
//! alerts.

use std::fmt;

use serde::{Deserialize, Serialize};

const DEFAULT_MIN_SECRET_LEN: usize = 8;

/// Redaction-safe alert emitted when registered secret material is observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLeakAlert {
    /// Operator-chosen label for the secret. Must not contain the secret value.
    pub label: String,
    /// BLAKE3 hex fingerprint of the leaked secret bytes.
    pub secret_fingerprint: String,
    /// Length of the registered secret in bytes.
    pub secret_len: usize,
    /// Byte offset where the secret was found in the scanned payload.
    pub offset: usize,
}

impl SecretLeakAlert {
    /// Emit a redaction-safe audit event for this leak alert.
    pub fn emit_audit_event(&self) {
        tracing::warn!(
            event = "SecretLeakAlert",
            label = %self.label,
            secret_fingerprint = %self.secret_fingerprint,
            secret_len = self.secret_len,
            offset = self.offset,
            "registered secret material detected in adversarial test surface"
        );
    }
}

#[derive(Clone)]
struct RegisteredSecret {
    label: String,
    bytes: Vec<u8>,
    fingerprint: String,
}

impl fmt::Debug for RegisteredSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredSecret")
            .field("label", &self.label)
            .field("secret_len", &self.bytes.len())
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Tracks registered test secrets and detects exact leaks without logging values.
#[derive(Clone, Debug)]
pub struct SecretTaintTracker {
    min_secret_len: usize,
    secrets: Vec<RegisteredSecret>,
}

impl Default for SecretTaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretTaintTracker {
    /// Create a tracker with the default minimum secret length.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_secret_len: DEFAULT_MIN_SECRET_LEN,
            secrets: Vec::new(),
        }
    }

    /// Create a tracker with a custom minimum secret length.
    ///
    /// Values below one byte are coerced to one so empty secrets can never be
    /// registered or detected.
    #[must_use]
    pub const fn with_min_secret_len(min_secret_len: usize) -> Self {
        Self {
            min_secret_len: if min_secret_len == 0 {
                1
            } else {
                min_secret_len
            },
            secrets: Vec::new(),
        }
    }

    /// Register a secret value for later leak scanning.
    ///
    /// Returns `false` when the candidate is shorter than the configured
    /// minimum or is already registered.
    #[must_use]
    pub fn register_secret(&mut self, label: impl Into<String>, secret: impl AsRef<[u8]>) -> bool {
        let secret = secret.as_ref();
        if secret.len() < self.min_secret_len || self.is_registered_secret(secret) {
            return false;
        }

        self.secrets.push(RegisteredSecret {
            label: label.into(),
            bytes: secret.to_vec(),
            fingerprint: Self::fingerprint(secret),
        });
        true
    }

    /// Return the minimum accepted registered secret length.
    #[must_use]
    pub const fn minimum_secret_len(&self) -> usize {
        self.min_secret_len
    }

    /// Return the number of registered secrets.
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.secrets.len()
    }

    /// Return whether the exact byte value is already registered.
    #[must_use]
    pub fn is_registered_secret(&self, secret: impl AsRef<[u8]>) -> bool {
        let secret = secret.as_ref();
        self.secrets
            .iter()
            .any(|registered| registered.bytes.as_slice() == secret)
    }

    /// Scan bytes for any registered secret and emit a redaction-safe alert.
    #[must_use]
    pub fn scan_bytes(&self, haystack: impl AsRef<[u8]>) -> Option<SecretLeakAlert> {
        let haystack = haystack.as_ref();
        for registered in &self.secrets {
            if registered.bytes.is_empty() || registered.bytes.len() > haystack.len() {
                continue;
            }
            if let Some(offset) = haystack
                .windows(registered.bytes.len())
                .position(|window| window == registered.bytes.as_slice())
            {
                let alert = SecretLeakAlert {
                    label: registered.label.clone(),
                    secret_fingerprint: registered.fingerprint.clone(),
                    secret_len: registered.bytes.len(),
                    offset,
                };
                alert.emit_audit_event();
                return Some(alert);
            }
        }
        None
    }

    /// Scan a UTF-8 string for any registered secret.
    #[must_use]
    pub fn scan_str(&self, haystack: &str) -> Option<SecretLeakAlert> {
        self.scan_bytes(haystack.as_bytes())
    }

    /// Scan a JSON value's string rendering for any registered secret.
    #[must_use]
    pub fn scan_json(&self, value: &serde_json::Value) -> Option<SecretLeakAlert> {
        self.scan_str(&value.to_string())
    }

    fn fingerprint(secret: &[u8]) -> String {
        blake3::hash(secret).to_hex().to_string()
    }
}
