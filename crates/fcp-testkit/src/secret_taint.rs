use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretTaintError {
    #[error("secret label must not be empty")]
    EmptyLabel,
    #[error("secret value must not be empty")]
    EmptySecret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandle {
    pub id: String,
    pub label_hash: String,
    pub byte_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretTaintLeak {
    pub secret_id: String,
    pub label_hash: String,
    pub context_hash: String,
    pub detector: String,
    pub byte_len: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretTaintReport {
    pub context_hash: String,
    pub leak_count: usize,
    pub leaks: Vec<SecretTaintLeak>,
}

impl SecretTaintReport {
    #[must_use]
    pub const fn has_leaks(&self) -> bool {
        self.leak_count > 0
    }
}

#[derive(Clone, Debug)]
struct RegisteredSecret {
    handle: SecretHandle,
    value: String,
}

#[derive(Clone, Debug, Default)]
pub struct SecretTaintTracker {
    secrets: Vec<RegisteredSecret>,
}

impl SecretTaintTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            secrets: Vec::new(),
        }
    }

    /// Register one secret value for exact-match leak detection.
    ///
    /// # Errors
    ///
    /// Returns [`SecretTaintError::EmptyLabel`] when `label` is blank and
    /// [`SecretTaintError::EmptySecret`] when `value` is empty.
    pub fn register_secret(
        &mut self,
        label: &str,
        value: &str,
    ) -> Result<SecretHandle, SecretTaintError> {
        let label = label.trim();
        if label.is_empty() {
            return Err(SecretTaintError::EmptyLabel);
        }
        if value.is_empty() {
            return Err(SecretTaintError::EmptySecret);
        }
        let handle = SecretHandle {
            id: format!("secret-{}", self.secrets.len()),
            label_hash: blake3_hash(label.as_bytes()),
            byte_len: value.len(),
        };
        self.secrets.push(RegisteredSecret {
            handle: handle.clone(),
            value: value.to_string(),
        });
        Ok(handle)
    }

    #[must_use]
    pub fn scan_text(&self, context: &str, text: &str) -> SecretTaintReport {
        let context_hash = blake3_hash(context.as_bytes());
        let leaks = self
            .secrets
            .iter()
            .filter(|secret| text.contains(&secret.value))
            .map(|secret| SecretTaintLeak {
                secret_id: secret.handle.id.clone(),
                label_hash: secret.handle.label_hash.clone(),
                context_hash: context_hash.clone(),
                detector: "registered_secret_exact".to_string(),
                byte_len: secret.handle.byte_len,
            })
            .collect::<Vec<_>>();
        Self::report(context_hash, leaks)
    }

    #[must_use]
    pub fn scan_json(&self, context: &str, value: &Value) -> SecretTaintReport {
        let mut material = String::new();
        append_json_strings(value, &mut material);
        self.scan_text(context, &material)
    }

    fn report(context_hash: String, leaks: Vec<SecretTaintLeak>) -> SecretTaintReport {
        let leak_count = leaks.len();
        let report = SecretTaintReport {
            context_hash,
            leak_count,
            leaks,
        };
        if report.has_leaks() {
            warn!(
                event = "SecretLeakAlert",
                leak_count = report.leak_count,
                context_hash = report.context_hash,
                "secret taint tracker detected registered secret material"
            );
        }
        report
    }
}

fn append_json_strings(value: &Value, output: &mut String) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(text) => {
            output.push('\n');
            output.push_str(text);
        }
        Value::Array(items) => {
            for item in items {
                append_json_strings(item, output);
            }
        }
        Value::Object(entries) => {
            for (key, value) in entries {
                output.push('\n');
                output.push_str(key);
                append_json_strings(value, output);
            }
        }
    }
}

fn blake3_hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}
