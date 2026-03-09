//! Secretless credential injection: agents use credential references instead of
//! raw secrets, and the egress proxy injects actual credentials at the network
//! boundary.
//!
//! The flow:
//! 1. Agent stores a `CredentialId` reference via `fwc auth add --credential-id`
//! 2. Connector sends requests with `X-FCP-Credential-ID` header
//! 3. Egress proxy intercepts, resolves the credential, injects into the request
//! 4. Connector never sees the raw secret
//!
//! This module implements the resolution, injection, and mapping logic.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Credential ID ─────────────────────────────────────────────────

/// An opaque identifier referencing a stored secret in the proxy-side vault.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CredentialId(String);

impl CredentialId {
    /// Create a new credential ID.  The ID must be non-empty and ASCII
    /// alphanumeric (plus `_`, `-`, `.`, `/`, `:`).
    pub fn new(id: impl Into<String>) -> Result<Self, SecretlessError> {
        let s: String = id.into();
        if s.is_empty() {
            return Err(SecretlessError::InvalidCredentialId(
                "credential ID must not be empty".into(),
            ));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:".contains(c))
        {
            return Err(SecretlessError::InvalidCredentialId(format!(
                "credential ID contains invalid characters: {s}"
            )));
        }
        Ok(Self(s))
    }

    /// The raw string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Injection target ──────────────────────────────────────────────

/// Where the resolved credential should be injected in the outgoing request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionTarget {
    /// `Authorization: Bearer <token>`
    BearerHeader,
    /// `Authorization: Basic <base64(user:pass)>`
    BasicHeader {
        username_field: String,
        password_field: String,
    },
    /// Custom header, e.g. `X-Api-Key: <value>`.
    CustomHeader {
        header_name: String,
        field: String,
    },
    /// Query parameter, e.g. `?api_key=<value>`.
    QueryParam {
        param_name: String,
        field: String,
    },
}

impl InjectionTarget {
    /// Bearer token injection (most common).
    pub const fn bearer() -> Self {
        Self::BearerHeader
    }

    /// Basic auth injection.
    pub fn basic() -> Self {
        Self::BasicHeader {
            username_field: "username".into(),
            password_field: "password".into(),
        }
    }

    /// Custom header injection.
    pub fn header(name: impl Into<String>, field: impl Into<String>) -> Self {
        Self::CustomHeader {
            header_name: name.into(),
            field: field.into(),
        }
    }

    /// Query parameter injection.
    pub fn query(param: impl Into<String>, field: impl Into<String>) -> Self {
        Self::QueryParam {
            param_name: param.into(),
            field: field.into(),
        }
    }
}

// ── Credential mapping ────────────────────────────────────────────

/// Maps a `CredentialId` to the actual secret fields and injection target.
/// Stored proxy-side only, never visible to connectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialMapping {
    /// The reference ID agents use.
    pub credential_id: CredentialId,
    /// Connector this mapping applies to (e.g. "github").
    pub connector_id: String,
    /// Actual secret fields (key → value).
    pub secret_fields: BTreeMap<String, String>,
    /// Where to inject into outgoing requests.
    pub injection: InjectionTarget,
    /// When this mapping was created.
    pub created_at: u64,
    /// When this mapping was last used for injection.
    pub last_used_at: Option<u64>,
    /// When this mapping expires (0 = never).
    pub expires_at: u64,
    /// Human-readable label for auditing.
    pub label: String,
}

impl CredentialMapping {
    /// Create a new credential mapping.
    pub fn new(
        credential_id: CredentialId,
        connector_id: impl Into<String>,
        secret_fields: BTreeMap<String, String>,
        injection: InjectionTarget,
    ) -> Self {
        Self {
            credential_id,
            connector_id: connector_id.into(),
            secret_fields,
            injection,
            created_at: epoch_seconds(),
            last_used_at: None,
            expires_at: 0,
            label: String::new(),
        }
    }

    /// Set expiry (seconds since epoch).
    pub const fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Set a human-readable label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Whether this mapping has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at > 0 && epoch_seconds() >= self.expires_at
    }

    /// Mark as used (updates `last_used_at`).
    pub fn touch(&mut self) {
        self.last_used_at = Some(epoch_seconds());
    }

    /// Redacted view of secret fields for display/logging.
    pub fn redacted_fields(&self) -> BTreeMap<String, String> {
        self.secret_fields
            .iter()
            .map(|(k, v)| (k.clone(), redact_secret(v)))
            .collect()
    }
}

// ── Injection result ──────────────────────────────────────────────

/// The result of resolving + injecting a credential.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InjectionResult {
    /// The credential ID that was resolved.
    pub credential_id: CredentialId,
    /// The connector this was injected for.
    pub connector_id: String,
    /// Headers to add to the outgoing request.
    pub headers: Vec<(String, String)>,
    /// Query parameters to add.
    pub query_params: Vec<(String, String)>,
    /// Timestamp of injection.
    pub injected_at: u64,
}

// ── Proxy credential vault ────────────────────────────────────────

/// In-memory credential vault for the egress proxy.
/// Maps `CredentialId → CredentialMapping`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProxyVault {
    mappings: BTreeMap<String, CredentialMapping>,
}

impl ProxyVault {
    /// Create an empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a credential mapping.
    pub fn add(&mut self, mapping: CredentialMapping) -> Result<(), SecretlessError> {
        let key = vault_key(&mapping.credential_id, &mapping.connector_id);
        if self.mappings.contains_key(&key) {
            return Err(SecretlessError::DuplicateMapping {
                credential_id: mapping.credential_id.to_string(),
                connector_id: mapping.connector_id,
            });
        }
        self.mappings.insert(key, mapping);
        Ok(())
    }

    /// Update an existing mapping's secret fields.
    pub fn update_secrets(
        &mut self,
        credential_id: &CredentialId,
        connector_id: &str,
        new_fields: BTreeMap<String, String>,
    ) -> Result<(), SecretlessError> {
        let key = vault_key(credential_id, connector_id);
        let mapping = self
            .mappings
            .get_mut(&key)
            .ok_or_else(|| SecretlessError::NotFound(credential_id.to_string()))?;
        mapping.secret_fields = new_fields;
        Ok(())
    }

    /// Remove a credential mapping.
    pub fn remove(
        &mut self,
        credential_id: &CredentialId,
        connector_id: &str,
    ) -> Result<CredentialMapping, SecretlessError> {
        let key = vault_key(credential_id, connector_id);
        self.mappings
            .remove(&key)
            .ok_or_else(|| SecretlessError::NotFound(credential_id.to_string()))
    }

    /// Resolve a credential ID to an injection result.
    pub fn resolve(
        &mut self,
        credential_id: &CredentialId,
        connector_id: &str,
    ) -> Result<InjectionResult, SecretlessError> {
        let key = vault_key(credential_id, connector_id);
        let mapping = self
            .mappings
            .get_mut(&key)
            .ok_or_else(|| SecretlessError::NotFound(credential_id.to_string()))?;

        if mapping.is_expired() {
            return Err(SecretlessError::Expired {
                credential_id: credential_id.to_string(),
                expired_at: mapping.expires_at,
            });
        }

        mapping.touch();

        let (headers, query_params) = build_injection(&mapping.injection, &mapping.secret_fields)?;

        Ok(InjectionResult {
            credential_id: credential_id.clone(),
            connector_id: connector_id.to_owned(),
            headers,
            query_params,
            injected_at: epoch_seconds(),
        })
    }

    /// List all mappings for a connector.
    pub fn list_for_connector(&self, connector_id: &str) -> Vec<&CredentialMapping> {
        self.mappings
            .values()
            .filter(|m| m.connector_id == connector_id)
            .collect()
    }

    /// List all mappings.
    pub fn list_all(&self) -> Vec<&CredentialMapping> {
        self.mappings.values().collect()
    }

    /// Total number of stored mappings.
    pub fn count(&self) -> usize {
        self.mappings.len()
    }

    /// Whether the vault is empty.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Purge all expired mappings. Returns count of removed entries.
    pub fn purge_expired(&mut self) -> usize {
        let before = self.mappings.len();
        self.mappings.retain(|_, m| !m.is_expired());
        before - self.mappings.len()
    }

    /// Serialize the vault to JSON (for persistence).
    pub fn to_json(&self) -> Result<String, SecretlessError> {
        serde_json::to_string_pretty(self).map_err(|e| SecretlessError::Serialization(e.to_string()))
    }

    /// Deserialize a vault from JSON.
    pub fn from_json(json: &str) -> Result<Self, SecretlessError> {
        serde_json::from_str(json).map_err(|e| SecretlessError::Serialization(e.to_string()))
    }
}

// ── Request interceptor ───────────────────────────────────────────

/// The canonical header connectors use to signal a secretless credential request.
pub const CREDENTIAL_ID_HEADER: &str = "x-fcp-credential-id";

/// Parsed secretless request from an intercepted connector HTTP request.
#[derive(Clone, Debug)]
pub struct SecretlessRequest {
    /// The credential ID from the `X-FCP-Credential-ID` header.
    pub credential_id: CredentialId,
    /// The connector that sent the request.
    pub connector_id: String,
}

impl SecretlessRequest {
    /// Parse from a set of request headers.
    pub fn from_headers(
        headers: &[(String, String)],
        connector_id: impl Into<String>,
    ) -> Option<Self> {
        let cred_value = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(CREDENTIAL_ID_HEADER))
            .map(|(_, v)| v.as_str())?;

        let credential_id = CredentialId::new(cred_value).ok()?;
        Some(Self {
            credential_id,
            connector_id: connector_id.into(),
        })
    }
}

// ── Audit trail ───────────────────────────────────────────────────

/// Audit event for a secretless credential operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InjectionAuditEntry {
    /// When the injection occurred.
    pub timestamp: u64,
    /// Which credential was used.
    pub credential_id: String,
    /// Which connector triggered the injection.
    pub connector_id: String,
    /// Outcome of the injection.
    pub outcome: InjectionOutcome,
}

/// Outcome of a secretless injection attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionOutcome {
    /// Successfully injected.
    Injected,
    /// Credential not found in vault.
    NotFound,
    /// Credential expired.
    Expired,
    /// Missing required secret field.
    MissingField(String),
    /// Denied by policy.
    Denied(String),
}

impl fmt::Display for InjectionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Injected => write!(f, "injected"),
            Self::NotFound => write!(f, "not_found"),
            Self::Expired => write!(f, "expired"),
            Self::MissingField(field) => write!(f, "missing_field:{field}"),
            Self::Denied(reason) => write!(f, "denied:{reason}"),
        }
    }
}

/// Append-only audit log for credential injections.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InjectionAuditLog {
    entries: Vec<InjectionAuditEntry>,
    max_entries: usize,
}

impl InjectionAuditLog {
    /// Create a new audit log with the given capacity.
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Record an injection attempt.
    pub fn record(
        &mut self,
        credential_id: &str,
        connector_id: &str,
        outcome: InjectionOutcome,
    ) {
        if self.entries.len() >= self.max_entries && self.max_entries > 0 {
            self.entries.remove(0);
        }
        self.entries.push(InjectionAuditEntry {
            timestamp: epoch_seconds(),
            credential_id: credential_id.to_owned(),
            connector_id: connector_id.to_owned(),
            outcome,
        });
    }

    /// All entries.
    pub fn entries(&self) -> &[InjectionAuditEntry] {
        &self.entries
    }

    /// Entries for a specific credential.
    pub fn entries_for(&self, credential_id: &str) -> Vec<&InjectionAuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.credential_id == credential_id)
            .collect()
    }

    /// Count of successful injections.
    pub fn success_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.outcome == InjectionOutcome::Injected)
            .count()
    }

    /// Count of failed injections.
    pub fn failure_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.outcome != InjectionOutcome::Injected)
            .count()
    }

    /// Total entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Policy ────────────────────────────────────────────────────────

/// Policy controlling which connectors can use which credential IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InjectionPolicy {
    /// Rules mapping credential ID patterns to allowed connector patterns.
    pub rules: Vec<PolicyRule>,
}

/// A single injection policy rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Credential ID pattern (supports `*` wildcard suffix).
    pub credential_pattern: String,
    /// Allowed connector IDs (supports `*` wildcard suffix).
    pub allowed_connectors: Vec<String>,
    /// Whether this rule is active.
    pub enabled: bool,
}

impl InjectionPolicy {
    /// Create a default allow-all policy.
    pub fn allow_all() -> Self {
        Self {
            rules: vec![PolicyRule {
                credential_pattern: "*".into(),
                allowed_connectors: vec!["*".into()],
                enabled: true,
            }],
        }
    }

    /// Create a deny-all policy.
    pub const fn deny_all() -> Self {
        Self { rules: Vec::new() }
    }

    /// Check whether a credential ID is allowed for a connector.
    pub fn is_allowed(&self, credential_id: &str, connector_id: &str) -> bool {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if pattern_matches(&rule.credential_pattern, credential_id) {
                for allowed in &rule.allowed_connectors {
                    if pattern_matches(allowed, connector_id) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Add a rule allowing a credential pattern for specific connectors.
    pub fn allow(
        &mut self,
        credential_pattern: impl Into<String>,
        connectors: Vec<String>,
    ) {
        self.rules.push(PolicyRule {
            credential_pattern: credential_pattern.into(),
            allowed_connectors: connectors,
            enabled: true,
        });
    }
}

impl Default for InjectionPolicy {
    fn default() -> Self {
        Self::allow_all()
    }
}

// ── Egress proxy engine ───────────────────────────────────────────

/// The main egress proxy engine: combines vault, policy, and audit log.
#[derive(Clone, Debug)]
pub struct EgressProxy {
    /// The credential vault.
    pub vault: ProxyVault,
    /// Injection policy.
    pub policy: InjectionPolicy,
    /// Audit log.
    pub audit_log: InjectionAuditLog,
}

impl EgressProxy {
    /// Create a new egress proxy with default policy (allow-all).
    pub fn new() -> Self {
        Self {
            vault: ProxyVault::new(),
            policy: InjectionPolicy::allow_all(),
            audit_log: InjectionAuditLog::new(10_000),
        }
    }

    /// Create with a specific policy.
    pub fn with_policy(policy: InjectionPolicy) -> Self {
        Self {
            vault: ProxyVault::new(),
            policy,
            audit_log: InjectionAuditLog::new(10_000),
        }
    }

    /// Process an intercepted request: resolve, check policy, inject, audit.
    pub fn process(&mut self, request: &SecretlessRequest) -> Result<InjectionResult, SecretlessError> {
        let cred_id_str = request.credential_id.as_str();
        let conn_id = &request.connector_id;

        // Policy check.
        if !self.policy.is_allowed(cred_id_str, conn_id) {
            self.audit_log.record(
                cred_id_str,
                conn_id,
                InjectionOutcome::Denied("policy".into()),
            );
            return Err(SecretlessError::PolicyDenied {
                credential_id: cred_id_str.to_owned(),
                connector_id: conn_id.clone(),
            });
        }

        // Resolve from vault.
        match self.vault.resolve(&request.credential_id, conn_id) {
            Ok(result) => {
                self.audit_log
                    .record(cred_id_str, conn_id, InjectionOutcome::Injected);
                Ok(result)
            }
            Err(SecretlessError::NotFound(id)) => {
                self.audit_log
                    .record(cred_id_str, conn_id, InjectionOutcome::NotFound);
                Err(SecretlessError::NotFound(id))
            }
            Err(SecretlessError::Expired { credential_id, expired_at }) => {
                self.audit_log
                    .record(cred_id_str, conn_id, InjectionOutcome::Expired);
                Err(SecretlessError::Expired { credential_id, expired_at })
            }
            Err(e) => Err(e),
        }
    }

    /// Register a credential mapping in the vault.
    pub fn register(
        &mut self,
        mapping: CredentialMapping,
    ) -> Result<(), SecretlessError> {
        self.vault.add(mapping)
    }
}

impl Default for EgressProxy {
    fn default() -> Self {
        Self::new()
    }
}

// ── Errors ────────────────────────────────────────────────────────

/// Errors for secretless credential operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretlessError {
    /// Invalid credential ID format.
    InvalidCredentialId(String),
    /// Credential not found in vault.
    NotFound(String),
    /// Credential has expired.
    Expired {
        credential_id: String,
        expired_at: u64,
    },
    /// Duplicate mapping for the same (`credential_id`, `connector_id`).
    DuplicateMapping {
        credential_id: String,
        connector_id: String,
    },
    /// Missing required field in `secret_fields` for injection.
    MissingField {
        credential_id: String,
        field: String,
    },
    /// Policy denied the injection.
    PolicyDenied {
        credential_id: String,
        connector_id: String,
    },
    /// Serialization error.
    Serialization(String),
}

impl fmt::Display for SecretlessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentialId(msg) => write!(f, "invalid credential ID: {msg}"),
            Self::NotFound(id) => write!(f, "credential not found: {id}"),
            Self::Expired {
                credential_id,
                expired_at,
            } => write!(f, "credential {credential_id} expired at {expired_at}"),
            Self::DuplicateMapping {
                credential_id,
                connector_id,
            } => write!(
                f,
                "duplicate mapping: {credential_id} already mapped for {connector_id}"
            ),
            Self::MissingField {
                credential_id,
                field,
            } => write!(
                f,
                "credential {credential_id} missing required field: {field}"
            ),
            Self::PolicyDenied {
                credential_id,
                connector_id,
            } => write!(
                f,
                "policy denied injection of {credential_id} for {connector_id}"
            ),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for SecretlessError {}

// ── Helpers ───────────────────────────────────────────────────────

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn vault_key(credential_id: &CredentialId, connector_id: &str) -> String {
    format!("{}@{}", credential_id.as_str(), connector_id)
}

fn redact_secret(value: &str) -> String {
    let len = value.len();
    if len <= 4 {
        "****".to_owned()
    } else {
        let visible = &value[len - 4..];
        format!("****{visible}")
    }
}

/// Simple prefix/suffix wildcard matching (supports `*` at end only).
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

/// Headers and query parameters produced by credential injection.
type InjectionParts = (Vec<(String, String)>, Vec<(String, String)>);

/// Build the actual headers and query params for injection.
fn build_injection(
    target: &InjectionTarget,
    fields: &BTreeMap<String, String>,
) -> Result<InjectionParts, SecretlessError> {
    let mut headers = Vec::new();
    let mut query_params = Vec::new();

    match target {
        InjectionTarget::BearerHeader => {
            let token = fields
                .get("token")
                .or_else(|| fields.get("api_token"))
                .or_else(|| fields.get("access_token"))
                .ok_or_else(|| SecretlessError::MissingField {
                    credential_id: String::new(),
                    field: "token".into(),
                })?;
            headers.push(("authorization".into(), format!("Bearer {token}")));
        }
        InjectionTarget::BasicHeader {
            username_field,
            password_field,
        } => {
            let user = fields
                .get(username_field.as_str())
                .ok_or_else(|| SecretlessError::MissingField {
                    credential_id: String::new(),
                    field: username_field.clone(),
                })?;
            let pass = fields
                .get(password_field.as_str())
                .ok_or_else(|| SecretlessError::MissingField {
                    credential_id: String::new(),
                    field: password_field.clone(),
                })?;
            // base64(user:pass)
            let encoded = base64_encode(&format!("{user}:{pass}"));
            headers.push(("authorization".into(), format!("Basic {encoded}")));
        }
        InjectionTarget::CustomHeader { header_name, field } => {
            let value = fields
                .get(field.as_str())
                .ok_or_else(|| SecretlessError::MissingField {
                    credential_id: String::new(),
                    field: field.clone(),
                })?;
            headers.push((header_name.clone(), value.clone()));
        }
        InjectionTarget::QueryParam { param_name, field } => {
            let value = fields
                .get(field.as_str())
                .ok_or_else(|| SecretlessError::MissingField {
                    credential_id: String::new(),
                    field: field.clone(),
                })?;
            query_params.push((param_name.clone(), value.clone()));
        }
    }

    Ok((headers, query_params))
}

/// Minimal base64 encoding (no external dependency needed for this).
#[allow(clippy::cast_lossless)]
fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fields() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("token".into(), "ghp_abc123xyz789".into());
        m
    }

    fn basic_fields() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("username".into(), "user@example.com".into());
        m.insert("password".into(), "s3cret!".into());
        m
    }

    fn api_key_fields() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("api_key".into(), "sk-proj-abc123".into());
        m
    }

    fn make_mapping(
        id: &str,
        connector: &str,
        fields: BTreeMap<String, String>,
        target: InjectionTarget,
    ) -> CredentialMapping {
        CredentialMapping::new(
            CredentialId::new(id).unwrap(),
            connector,
            fields,
            target,
        )
    }

    // ── CredentialId ──────────────────────────────────────────────

    #[test]
    fn credential_id_valid() {
        assert!(CredentialId::new("cred_github_work").is_ok());
        assert!(CredentialId::new("vault:secret/data/github").is_ok());
        assert!(CredentialId::new("my-key-123").is_ok());
        assert!(CredentialId::new("a.b.c").is_ok());
    }

    #[test]
    fn credential_id_empty_rejected() {
        let err = CredentialId::new("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn credential_id_invalid_chars() {
        assert!(CredentialId::new("has spaces").is_err());
        assert!(CredentialId::new("has@at").is_err());
        assert!(CredentialId::new("has#hash").is_err());
    }

    #[test]
    fn credential_id_display() {
        let id = CredentialId::new("cred_123").unwrap();
        assert_eq!(id.to_string(), "cred_123");
        assert_eq!(id.as_str(), "cred_123");
    }

    // ── InjectionTarget ───────────────────────────────────────────

    #[test]
    fn injection_target_bearer() {
        let t = InjectionTarget::bearer();
        assert_eq!(t, InjectionTarget::BearerHeader);
    }

    #[test]
    fn injection_target_basic() {
        let t = InjectionTarget::basic();
        match t {
            InjectionTarget::BasicHeader {
                username_field,
                password_field,
            } => {
                assert_eq!(username_field, "username");
                assert_eq!(password_field, "password");
            }
            _ => panic!("expected BasicHeader"),
        }
    }

    #[test]
    fn injection_target_custom_header() {
        let t = InjectionTarget::header("X-Api-Key", "api_key");
        match t {
            InjectionTarget::CustomHeader { header_name, field } => {
                assert_eq!(header_name, "X-Api-Key");
                assert_eq!(field, "api_key");
            }
            _ => panic!("expected CustomHeader"),
        }
    }

    #[test]
    fn injection_target_query_param() {
        let t = InjectionTarget::query("key", "api_key");
        match t {
            InjectionTarget::QueryParam { param_name, field } => {
                assert_eq!(param_name, "key");
                assert_eq!(field, "api_key");
            }
            _ => panic!("expected QueryParam"),
        }
    }

    // ── CredentialMapping ─────────────────────────────────────────

    #[test]
    fn mapping_creation() {
        let m = make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer());
        assert_eq!(m.credential_id.as_str(), "cred_gh");
        assert_eq!(m.connector_id, "github");
        assert!(!m.is_expired());
        assert!(m.last_used_at.is_none());
    }

    #[test]
    fn mapping_with_expiry() {
        let m = make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer())
            .with_expiry(1);
        assert!(m.is_expired());
    }

    #[test]
    fn mapping_with_label() {
        let m = make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer())
            .with_label("Work GitHub token");
        assert_eq!(m.label, "Work GitHub token");
    }

    #[test]
    fn mapping_touch_updates_last_used() {
        let mut m = make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer());
        assert!(m.last_used_at.is_none());
        m.touch();
        assert!(m.last_used_at.is_some());
    }

    #[test]
    fn mapping_redacted_fields() {
        let m = make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer());
        let redacted = m.redacted_fields();
        let val = redacted.get("token").unwrap();
        assert!(val.starts_with("****"));
        assert!(val.ends_with("z789"));
        assert!(!val.contains("ghp_abc123"));
    }

    #[test]
    fn mapping_serialization_roundtrip() {
        let m = make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer());
        let json = serde_json::to_string(&m).unwrap();
        let m2: CredentialMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(m.credential_id, m2.credential_id);
        assert_eq!(m.connector_id, m2.connector_id);
    }

    // ── ProxyVault ────────────────────────────────────────────────

    #[test]
    fn vault_add_and_resolve() {
        let mut vault = ProxyVault::new();
        vault
            .add(make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        assert_eq!(vault.count(), 1);

        let result = vault
            .resolve(&CredentialId::new("cred_gh").unwrap(), "github")
            .unwrap();
        assert_eq!(result.credential_id.as_str(), "cred_gh");
        assert_eq!(result.connector_id, "github");
        assert!(!result.headers.is_empty());
    }

    #[test]
    fn vault_duplicate_rejected() {
        let mut vault = ProxyVault::new();
        vault
            .add(make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        let err = vault
            .add(make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn vault_not_found() {
        let mut vault = ProxyVault::new();
        let err = vault
            .resolve(&CredentialId::new("nonexistent").unwrap(), "github")
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn vault_remove() {
        let mut vault = ProxyVault::new();
        vault
            .add(make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        let removed = vault
            .remove(&CredentialId::new("cred_gh").unwrap(), "github")
            .unwrap();
        assert_eq!(removed.credential_id.as_str(), "cred_gh");
        assert!(vault.is_empty());
    }

    #[test]
    fn vault_remove_not_found() {
        let mut vault = ProxyVault::new();
        let err = vault
            .remove(&CredentialId::new("nope").unwrap(), "github")
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn vault_update_secrets() {
        let mut vault = ProxyVault::new();
        vault
            .add(make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        let mut new_fields = BTreeMap::new();
        new_fields.insert("token".into(), "ghp_new_token_999".into());
        vault
            .update_secrets(&CredentialId::new("cred_gh").unwrap(), "github", new_fields)
            .unwrap();
        let result = vault
            .resolve(&CredentialId::new("cred_gh").unwrap(), "github")
            .unwrap();
        assert!(result.headers[0].1.contains("ghp_new_token_999"));
    }

    #[test]
    fn vault_expired_credential_rejected() {
        let mut vault = ProxyVault::new();
        vault
            .add(
                make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer())
                    .with_expiry(1),
            )
            .unwrap();
        let err = vault
            .resolve(&CredentialId::new("cred_gh").unwrap(), "github")
            .unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn vault_list_for_connector() {
        let mut vault = ProxyVault::new();
        vault
            .add(make_mapping("cred_gh1", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        vault
            .add(make_mapping("cred_gh2", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        vault
            .add(make_mapping("cred_sl", "slack", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        assert_eq!(vault.list_for_connector("github").len(), 2);
        assert_eq!(vault.list_for_connector("slack").len(), 1);
        assert_eq!(vault.list_for_connector("jira").len(), 0);
    }

    #[test]
    fn vault_list_all() {
        let mut vault = ProxyVault::new();
        vault
            .add(make_mapping("c1", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        vault
            .add(make_mapping("c2", "slack", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        assert_eq!(vault.list_all().len(), 2);
    }

    #[test]
    fn vault_purge_expired() {
        let mut vault = ProxyVault::new();
        vault
            .add(
                make_mapping("expired", "github", sample_fields(), InjectionTarget::bearer())
                    .with_expiry(1),
            )
            .unwrap();
        vault
            .add(make_mapping("valid", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        let purged = vault.purge_expired();
        assert_eq!(purged, 1);
        assert_eq!(vault.count(), 1);
    }

    #[test]
    fn vault_json_roundtrip() {
        let mut vault = ProxyVault::new();
        vault
            .add(make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer()))
            .unwrap();
        let json = vault.to_json().unwrap();
        let vault2 = ProxyVault::from_json(&json).unwrap();
        assert_eq!(vault2.count(), 1);
    }

    // ── Build injection ───────────────────────────────────────────

    #[test]
    fn inject_bearer() {
        let (headers, qp) = build_injection(&InjectionTarget::bearer(), &sample_fields()).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "authorization");
        assert!(headers[0].1.starts_with("Bearer "));
        assert!(qp.is_empty());
    }

    #[test]
    fn inject_basic() {
        let (headers, qp) = build_injection(&InjectionTarget::basic(), &basic_fields()).unwrap();
        assert_eq!(headers.len(), 1);
        assert!(headers[0].1.starts_with("Basic "));
        assert!(qp.is_empty());
    }

    #[test]
    fn inject_custom_header() {
        let target = InjectionTarget::header("X-Api-Key", "api_key");
        let (headers, qp) = build_injection(&target, &api_key_fields()).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "X-Api-Key");
        assert_eq!(headers[0].1, "sk-proj-abc123");
        assert!(qp.is_empty());
    }

    #[test]
    fn inject_query_param() {
        let target = InjectionTarget::query("key", "api_key");
        let (_, qp) = build_injection(&target, &api_key_fields()).unwrap();
        assert_eq!(qp.len(), 1);
        assert_eq!(qp[0].0, "key");
        assert_eq!(qp[0].1, "sk-proj-abc123");
    }

    #[test]
    fn inject_missing_field_error() {
        let empty = BTreeMap::new();
        let err = build_injection(&InjectionTarget::bearer(), &empty).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn inject_basic_missing_password() {
        let mut fields = BTreeMap::new();
        fields.insert("username".into(), "user".into());
        let err = build_injection(&InjectionTarget::basic(), &fields).unwrap_err();
        assert!(err.to_string().contains("password"));
    }

    // ── SecretlessRequest ─────────────────────────────────────────

    #[test]
    fn parse_secretless_request_from_headers() {
        let headers = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("x-fcp-credential-id".to_owned(), "cred_gh_work".to_owned()),
        ];
        let req = SecretlessRequest::from_headers(&headers, "github").unwrap();
        assert_eq!(req.credential_id.as_str(), "cred_gh_work");
        assert_eq!(req.connector_id, "github");
    }

    #[test]
    fn parse_secretless_request_case_insensitive() {
        let headers = vec![("X-FCP-Credential-ID".to_owned(), "cred_123".to_owned())];
        let req = SecretlessRequest::from_headers(&headers, "slack").unwrap();
        assert_eq!(req.credential_id.as_str(), "cred_123");
    }

    #[test]
    fn parse_secretless_request_absent() {
        let headers = vec![("authorization".to_owned(), "Bearer tok".to_owned())];
        assert!(SecretlessRequest::from_headers(&headers, "github").is_none());
    }

    #[test]
    fn parse_secretless_request_invalid_id() {
        let headers = vec![("x-fcp-credential-id".to_owned(), "has spaces".to_owned())];
        assert!(SecretlessRequest::from_headers(&headers, "github").is_none());
    }

    // ── Policy ────────────────────────────────────────────────────

    #[test]
    fn policy_allow_all() {
        let p = InjectionPolicy::allow_all();
        assert!(p.is_allowed("any_cred", "any_connector"));
    }

    #[test]
    fn policy_deny_all() {
        let p = InjectionPolicy::deny_all();
        assert!(!p.is_allowed("any_cred", "any_connector"));
    }

    #[test]
    fn policy_specific_credential_to_connector() {
        let mut p = InjectionPolicy::deny_all();
        p.allow("cred_gh", vec!["github".into()]);
        assert!(p.is_allowed("cred_gh", "github"));
        assert!(!p.is_allowed("cred_gh", "slack"));
        assert!(!p.is_allowed("cred_sl", "github"));
    }

    #[test]
    fn policy_wildcard_connector() {
        let mut p = InjectionPolicy::deny_all();
        p.allow("cred_admin", vec!["*".into()]);
        assert!(p.is_allowed("cred_admin", "github"));
        assert!(p.is_allowed("cred_admin", "slack"));
        assert!(!p.is_allowed("cred_other", "github"));
    }

    #[test]
    fn policy_wildcard_credential_prefix() {
        let mut p = InjectionPolicy::deny_all();
        p.allow("cred_gh*", vec!["github".into()]);
        assert!(p.is_allowed("cred_gh_work", "github"));
        assert!(p.is_allowed("cred_gh_personal", "github"));
        assert!(!p.is_allowed("cred_sl_work", "github"));
    }

    #[test]
    fn policy_disabled_rule_ignored() {
        let mut p = InjectionPolicy::deny_all();
        p.rules.push(PolicyRule {
            credential_pattern: "*".into(),
            allowed_connectors: vec!["*".into()],
            enabled: false,
        });
        assert!(!p.is_allowed("anything", "anything"));
    }

    // ── Audit log ─────────────────────────────────────────────────

    #[test]
    fn audit_log_record_and_query() {
        let mut log = InjectionAuditLog::new(100);
        log.record("cred_gh", "github", InjectionOutcome::Injected);
        log.record("cred_gh", "github", InjectionOutcome::Injected);
        log.record("cred_sl", "slack", InjectionOutcome::NotFound);
        assert_eq!(log.len(), 3);
        assert_eq!(log.success_count(), 2);
        assert_eq!(log.failure_count(), 1);
    }

    #[test]
    fn audit_log_entries_for() {
        let mut log = InjectionAuditLog::new(100);
        log.record("cred_gh", "github", InjectionOutcome::Injected);
        log.record("cred_sl", "slack", InjectionOutcome::NotFound);
        assert_eq!(log.entries_for("cred_gh").len(), 1);
        assert_eq!(log.entries_for("cred_sl").len(), 1);
        assert_eq!(log.entries_for("cred_nope").len(), 0);
    }

    #[test]
    fn audit_log_max_entries_eviction() {
        let mut log = InjectionAuditLog::new(3);
        for i in 0..5 {
            log.record(&format!("cred_{i}"), "github", InjectionOutcome::Injected);
        }
        assert_eq!(log.len(), 3);
        // Oldest entries evicted.
        assert_eq!(log.entries()[0].credential_id, "cred_2");
    }

    #[test]
    fn audit_log_empty() {
        let log = InjectionAuditLog::new(100);
        assert!(log.is_empty());
        assert_eq!(log.success_count(), 0);
        assert_eq!(log.failure_count(), 0);
    }

    // ── EgressProxy ───────────────────────────────────────────────

    #[test]
    fn proxy_end_to_end_bearer() {
        let mut proxy = EgressProxy::new();
        proxy
            .register(make_mapping(
                "cred_gh",
                "github",
                sample_fields(),
                InjectionTarget::bearer(),
            ))
            .unwrap();

        let req = SecretlessRequest {
            credential_id: CredentialId::new("cred_gh").unwrap(),
            connector_id: "github".into(),
        };
        let result = proxy.process(&req).unwrap();
        assert_eq!(result.headers[0].0, "authorization");
        assert!(result.headers[0].1.contains("ghp_abc123xyz789"));
        assert_eq!(proxy.audit_log.success_count(), 1);
    }

    #[test]
    fn proxy_end_to_end_basic() {
        let mut proxy = EgressProxy::new();
        proxy
            .register(make_mapping(
                "cred_jira",
                "jira",
                basic_fields(),
                InjectionTarget::basic(),
            ))
            .unwrap();

        let req = SecretlessRequest {
            credential_id: CredentialId::new("cred_jira").unwrap(),
            connector_id: "jira".into(),
        };
        let result = proxy.process(&req).unwrap();
        assert!(result.headers[0].1.starts_with("Basic "));
    }

    #[test]
    fn proxy_end_to_end_custom_header() {
        let mut proxy = EgressProxy::new();
        proxy
            .register(make_mapping(
                "cred_openai",
                "openai",
                api_key_fields(),
                InjectionTarget::header("X-Api-Key", "api_key"),
            ))
            .unwrap();

        let req = SecretlessRequest {
            credential_id: CredentialId::new("cred_openai").unwrap(),
            connector_id: "openai".into(),
        };
        let result = proxy.process(&req).unwrap();
        assert_eq!(result.headers[0].0, "X-Api-Key");
        assert_eq!(result.headers[0].1, "sk-proj-abc123");
    }

    #[test]
    fn proxy_not_found_audited() {
        let mut proxy = EgressProxy::new();
        let req = SecretlessRequest {
            credential_id: CredentialId::new("missing").unwrap(),
            connector_id: "github".into(),
        };
        let err = proxy.process(&req).unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert_eq!(proxy.audit_log.failure_count(), 1);
    }

    #[test]
    fn proxy_expired_audited() {
        let mut proxy = EgressProxy::new();
        proxy
            .register(
                make_mapping("cred_gh", "github", sample_fields(), InjectionTarget::bearer())
                    .with_expiry(1),
            )
            .unwrap();
        let req = SecretlessRequest {
            credential_id: CredentialId::new("cred_gh").unwrap(),
            connector_id: "github".into(),
        };
        let err = proxy.process(&req).unwrap_err();
        assert!(err.to_string().contains("expired"));
        assert_eq!(proxy.audit_log.failure_count(), 1);
    }

    #[test]
    fn proxy_policy_denied_audited() {
        let mut proxy = EgressProxy::with_policy(InjectionPolicy::deny_all());
        proxy
            .register(make_mapping(
                "cred_gh",
                "github",
                sample_fields(),
                InjectionTarget::bearer(),
            ))
            .unwrap();
        let req = SecretlessRequest {
            credential_id: CredentialId::new("cred_gh").unwrap(),
            connector_id: "github".into(),
        };
        let err = proxy.process(&req).unwrap_err();
        assert!(err.to_string().contains("denied"));
        assert_eq!(proxy.audit_log.failure_count(), 1);
    }

    #[test]
    fn proxy_policy_scoped() {
        let mut policy = InjectionPolicy::deny_all();
        policy.allow("cred_gh", vec!["github".into()]);
        let mut proxy = EgressProxy::with_policy(policy);
        proxy
            .register(make_mapping(
                "cred_gh",
                "github",
                sample_fields(),
                InjectionTarget::bearer(),
            ))
            .unwrap();
        proxy
            .register(make_mapping(
                "cred_gh",
                "slack",
                sample_fields(),
                InjectionTarget::bearer(),
            ))
            .unwrap();

        // Allowed.
        let req_gh = SecretlessRequest {
            credential_id: CredentialId::new("cred_gh").unwrap(),
            connector_id: "github".into(),
        };
        assert!(proxy.process(&req_gh).is_ok());

        // Denied.
        let req_sl = SecretlessRequest {
            credential_id: CredentialId::new("cred_gh").unwrap(),
            connector_id: "slack".into(),
        };
        assert!(proxy.process(&req_sl).is_err());
    }

    // ── Pattern matching ──────────────────────────────────────────

    #[test]
    fn pattern_exact_match() {
        assert!(pattern_matches("github", "github"));
        assert!(!pattern_matches("github", "slack"));
    }

    #[test]
    fn pattern_wildcard_all() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("*", ""));
    }

    #[test]
    fn pattern_wildcard_prefix() {
        assert!(pattern_matches("cred_*", "cred_github"));
        assert!(pattern_matches("cred_*", "cred_"));
        assert!(!pattern_matches("cred_*", "other_github"));
    }

    // ── Redaction ─────────────────────────────────────────────────

    #[test]
    fn redact_long_secret() {
        assert_eq!(redact_secret("ghp_abc123xyz789"), "****z789");
    }

    #[test]
    fn redact_short_secret() {
        assert_eq!(redact_secret("abc"), "****");
        assert_eq!(redact_secret("ab"), "****");
        assert_eq!(redact_secret("a"), "****");
    }

    #[test]
    fn redact_exactly_four() {
        assert_eq!(redact_secret("abcd"), "****");
    }

    #[test]
    fn redact_five_chars() {
        assert_eq!(redact_secret("abcde"), "****bcde");
    }

    // ── Base64 ────────────────────────────────────────────────────

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode("user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(""), "");
    }

    #[test]
    fn base64_encode_padding() {
        assert_eq!(base64_encode("a"), "YQ==");
        assert_eq!(base64_encode("ab"), "YWI=");
        assert_eq!(base64_encode("abc"), "YWJj");
    }

    // ── InjectionOutcome Display ──────────────────────────────────

    #[test]
    fn outcome_display() {
        assert_eq!(InjectionOutcome::Injected.to_string(), "injected");
        assert_eq!(InjectionOutcome::NotFound.to_string(), "not_found");
        assert_eq!(InjectionOutcome::Expired.to_string(), "expired");
        assert_eq!(
            InjectionOutcome::MissingField("token".into()).to_string(),
            "missing_field:token"
        );
        assert_eq!(
            InjectionOutcome::Denied("policy".into()).to_string(),
            "denied:policy"
        );
    }

    // ── Error Display ─────────────────────────────────────────────

    #[test]
    fn error_display_variants() {
        assert!(SecretlessError::InvalidCredentialId("bad".into())
            .to_string()
            .contains("invalid"));
        assert!(SecretlessError::NotFound("cred_123".into())
            .to_string()
            .contains("not found"));
        assert!(SecretlessError::Expired {
            credential_id: "c".into(),
            expired_at: 100,
        }
        .to_string()
        .contains("expired"));
        assert!(SecretlessError::DuplicateMapping {
            credential_id: "c".into(),
            connector_id: "g".into(),
        }
        .to_string()
        .contains("duplicate"));
        assert!(SecretlessError::MissingField {
            credential_id: "c".into(),
            field: "token".into(),
        }
        .to_string()
        .contains("missing"));
        assert!(SecretlessError::PolicyDenied {
            credential_id: "c".into(),
            connector_id: "g".into(),
        }
        .to_string()
        .contains("denied"));
        assert!(SecretlessError::Serialization("oops".into())
            .to_string()
            .contains("serialization"));
    }
}
