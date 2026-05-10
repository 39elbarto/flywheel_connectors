//! Redaction-safe replay bundle helpers for secretless connector tests.
//!
//! The helper redacts configured secret material before serializing any replay
//! line. It is intentionally small: callers record structured event/state
//! payloads, then write one JSONL bundle that is safe to persist as evidence.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str;

use fcp_crypto::ZeroizingSecret;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REPLAY_SCHEMA_VERSION: &str = "1.0.0";
const REPLAY_FILE_NAME: &str = "secretless_replay.jsonl";

#[derive(Clone)]
struct SecretRedaction {
    material: ZeroizingSecret,
    placeholder: String,
}

/// Secret material plus its redaction label for replay evidence.
pub struct RedactedReplaySecret<'a> {
    credential_id_hash: &'a str,
    material: &'a ZeroizingSecret,
}

impl<'a> RedactedReplaySecret<'a> {
    /// Build a labeled secret redaction input.
    #[must_use]
    pub const fn new(credential_id_hash: &'a str, material: &'a ZeroizingSecret) -> Self {
        Self {
            credential_id_hash,
            material,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReplayRecord {
    Event { event_type: String, payload: Value },
    State { name: String, payload: Value },
}

/// Replay bundle builder that redacts secret material before disk writes.
pub struct RedactedReplayBundle {
    root: PathBuf,
    redactions: Vec<SecretRedaction>,
    records: Vec<ReplayRecord>,
}

impl RedactedReplayBundle {
    /// Create a replay bundle with unlabeled secret material.
    ///
    /// Prefer [`Self::new_with_credentials`] when the caller has credential-id
    /// hashes available; this fallback uses a stable hash of the secret bytes as
    /// the redaction label so the evidence remains deterministic.
    #[must_use]
    pub fn new(root: impl AsRef<Path>, secrets: &[ZeroizingSecret]) -> Self {
        let redactions = secrets
            .iter()
            .map(|secret| {
                let (fingerprint, material) = secret.with_bytes(|bytes| {
                    (sha256_first_16_hex(bytes), ZeroizingSecret::new(bytes.to_vec()))
                });
                SecretRedaction {
                    material,
                    placeholder: format!("<REDACTED:secret_sha256:{fingerprint}>"),
                }
            })
            .collect();
        Self {
            root: root.as_ref().to_path_buf(),
            redactions,
            records: Vec::new(),
        }
    }

    /// Create a replay bundle with explicit credential-id hashes.
    #[must_use]
    pub fn new_with_credentials(
        root: impl AsRef<Path>,
        secrets: &[RedactedReplaySecret<'_>],
    ) -> Self {
        let redactions = secrets
            .iter()
            .map(|secret| {
                let (fingerprint, material) = secret.material.with_bytes(|bytes| {
                    (sha256_first_16_hex(bytes), ZeroizingSecret::new(bytes.to_vec()))
                });
                SecretRedaction {
                    material,
                    placeholder: format!("<REDACTED:{}:{fingerprint}>", secret.credential_id_hash),
                }
            })
            .collect();
        Self {
            root: root.as_ref().to_path_buf(),
            redactions,
            records: Vec::new(),
        }
    }

    /// Record a replay event.
    pub fn record_event(&mut self, event_type: impl Into<String>, payload: Value) {
        self.records.push(ReplayRecord::Event {
            event_type: event_type.into(),
            payload,
        });
    }

    /// Record a replay state snapshot.
    pub fn record_state(&mut self, name: impl Into<String>, payload: Value) {
        self.records.push(ReplayRecord::State {
            name: name.into(),
            payload,
        });
    }

    /// Render redacted JSONL without writing it.
    ///
    /// This is useful for assertions that need to prove redaction occurred
    /// before persistence.
    #[must_use]
    pub fn redacted_jsonl(&self) -> String {
        self.records
            .iter()
            .map(|record| {
                let value = serde_json::to_value(record).unwrap_or_else(|error| {
                    json!({
                        "serialization_error": error.to_string(),
                    })
                });
                let value = redact_value(&value, &self.redactions);
                let line = json!({
                    "schema_version": REPLAY_SCHEMA_VERSION,
                    "record": value,
                });
                serde_json::to_string(&line).unwrap_or_else(|error| {
                    format!(
                        "{{\"schema_version\":\"{REPLAY_SCHEMA_VERSION}\",\"record\":{{\"serialization_error\":{error:?}}}}}"
                    )
                })
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Write the replay bundle to disk after applying redaction.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the bundle directory cannot be created, if the
    /// replay file already exists, or if writing the JSONL payload fails.
    pub fn commit(&self) -> io::Result<PathBuf> {
        fs::create_dir_all(&self.root)?;
        let path = self.root.join(REPLAY_FILE_NAME);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(self.redacted_jsonl().as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(path)
    }
}

fn redact_value(value: &Value, redactions: &[SecretRedaction]) -> Value {
    match value {
        Value::String(raw) => Value::String(redact_string(raw, redactions)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_value(item, redactions))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), redact_value(item, redactions)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn redact_string(raw: &str, redactions: &[SecretRedaction]) -> String {
    redactions
        .iter()
        .fold(raw.to_string(), |mut output, redaction| {
            let secret_owned: Option<String> = redaction
                .material
                .with_bytes(|bytes| str::from_utf8(bytes).map(str::to_owned).ok());
            if let Some(secret) = secret_owned
                && !secret.is_empty()
                && output.contains(&secret)
            {
                output = output.replace(&secret, &redaction.placeholder);
            }
            output
        })
}

fn sha256_first_16_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_jsonl_replaces_event_and_state_secret_strings_before_commit() {
        let secret = ZeroizingSecret::new(b"ghp_secretless_replay_fixture".to_vec());
        let redaction = RedactedReplaySecret::new("credential_id_hash:abc123", &secret);
        let mut bundle =
            RedactedReplayBundle::new_with_credentials("/tmp/fcp-unused", &[redaction]);
        bundle.record_event(
            "fcp.test.secretless_gauntlet.wire_reception.pass",
            json!({
                "authorization": "Bearer ghp_secretless_replay_fixture",
                "nested": { "debug": "token=ghp_secretless_replay_fixture" }
            }),
        );
        bundle.record_state(
            "connector_stdin",
            json!({ "transcript": "credential_id only" }),
        );

        let rendered = bundle.redacted_jsonl();

        assert!(!rendered.contains("ghp_secretless_replay_fixture"));
        assert!(rendered.contains("<REDACTED:credential_id_hash:abc123:"));
        assert!(rendered.contains("credential_id only"));
        assert!(rendered.contains(REPLAY_SCHEMA_VERSION));
    }

    #[test]
    fn default_secret_labels_are_stable_without_raw_material() {
        let secret = ZeroizingSecret::new(b"xoxb-secretless-replay-fixture".to_vec());
        let mut bundle = RedactedReplayBundle::new("/tmp/fcp-unused", &[secret]);
        bundle.record_event(
            "fcp.test.secretless_gauntlet.tracing_redaction.pass",
            json!({ "line": "xoxb-secretless-replay-fixture" }),
        );

        let rendered = bundle.redacted_jsonl();

        assert!(!rendered.contains("xoxb-secretless-replay-fixture"));
        assert!(rendered.contains("<REDACTED:secret_sha256:"));
    }
}
