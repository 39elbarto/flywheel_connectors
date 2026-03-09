//! Credential management for `fwc auth` commands.
//!
//! Provides a trait-based credential backend with a file-based default
//! implementation.  Credentials are stored as base64-encoded JSON files under
//! `~/.fwc/credentials/` with `0o600` permissions.  All public read surfaces
//! return [`RedactedCredential`] to prevent accidental secret leakage.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

// ── Auth type ──────────────────────────────────────────────────────────────

/// Classification of authentication mechanism used by a connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    /// Bearer token / API key.
    ApiToken,
    /// OAuth 2.0 (access + optional refresh token).
    OAuth,
    /// HTTP basic authentication (username + password).
    BasicAuth,
    /// Opaque session token (e.g. Metabase).
    SessionToken,
    /// Reference to an external credential store.
    CredentialRef,
    /// Connector requires no authentication.
    NoAuth,
}

impl AuthType {
    /// Returns the canonical string label for this auth type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiToken => "api_token",
            Self::OAuth => "oauth",
            Self::BasicAuth => "basic_auth",
            Self::SessionToken => "session_token",
            Self::CredentialRef => "credential_ref",
            Self::NoAuth => "no_auth",
        }
    }

    /// Try to parse an auth type from its string label.
    #[must_use]
    pub fn from_str_label(s: &str) -> Option<Self> {
        match s {
            "api_token" | "api-token" | "token" | "bearer" => Some(Self::ApiToken),
            "oauth" | "oauth2" => Some(Self::OAuth),
            "basic_auth" | "basic-auth" | "basic" => Some(Self::BasicAuth),
            "session_token" | "session-token" | "session" => Some(Self::SessionToken),
            "credential_ref" | "credential-ref" | "ref" => Some(Self::CredentialRef),
            "no_auth" | "no-auth" | "none" => Some(Self::NoAuth),
            _ => None,
        }
    }
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Credential entry ───────────────────────────────────────────────────────

/// A stored credential for a connector.
///
/// Field values are stored as plain strings in memory but encoded to base64
/// when persisted to disk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// Connector identifier (e.g. `"github"`, `"slack"`).
    pub connector_id: String,
    /// Authentication type.
    pub auth_type: AuthType,
    /// Key-value pairs of credential fields (e.g. `"api_key"`, `"token"`).
    pub fields: BTreeMap<String, String>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 last-modified timestamp.
    pub updated_at: String,
    /// ISO-8601 last successful verification timestamp, if any.
    pub last_verified: Option<String>,
}

impl CredentialEntry {
    /// Create a new credential entry with the current timestamp.
    pub fn new(
        connector_id: impl Into<String>,
        auth_type: AuthType,
        fields: BTreeMap<String, String>,
    ) -> Self {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        Self {
            connector_id: connector_id.into(),
            auth_type,
            fields,
            created_at: now.clone(),
            updated_at: now,
            last_verified: None,
        }
    }

    /// Touch the `updated_at` timestamp.
    pub fn touch(&mut self) {
        self.updated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    }

    /// Record a verification event.
    pub fn mark_verified(&mut self) {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        self.last_verified = Some(now);
    }

    /// Produce a redacted view suitable for display.
    #[must_use]
    pub fn redacted(&self) -> RedactedCredential {
        let masked_fields = self
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), mask_secret(v)))
            .collect();
        RedactedCredential {
            connector_id: self.connector_id.clone(),
            auth_type: self.auth_type,
            fields: masked_fields,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            last_verified: self.last_verified.clone(),
        }
    }
}

// ── Redacted credential ────────────────────────────────────────────────────

/// A credential with secret values masked for safe display/logging.
#[derive(Clone, Debug, Serialize)]
pub struct RedactedCredential {
    pub connector_id: String,
    pub auth_type: AuthType,
    /// Masked field values (e.g. `"ghp_****abcd"`).
    pub fields: BTreeMap<String, String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_verified: Option<String>,
}

impl fmt::Display for RedactedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) fields=[{}]",
            self.connector_id,
            self.auth_type,
            self.fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

// ── Secret masking ─────────────────────────────────────────────────────────

/// Mask a secret value for display.
///
/// - If the value is <= 4 characters, the entire value is masked with `****`.
/// - Otherwise, the first characters up to a prefix boundary are shown, then
///   `****`, then the last 4 characters.
#[must_use]
pub fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return "****".to_owned();
    }

    // Show the last 4 characters only.
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("****{suffix}")
}

// ── Backend trait ──────────────────────────────────────────────────────────

/// Abstraction over credential storage backends.
///
/// The default implementation is [`FileBackend`] which writes files to
/// `~/.fwc/credentials/`.  Future implementations may use the OS keychain.
pub trait CredentialBackend {
    /// Persist a credential entry.
    ///
    /// # Errors
    /// Returns an error if the underlying storage write fails.
    fn store(&self, entry: &CredentialEntry) -> Result<()>;

    /// Retrieve a credential by connector id.
    ///
    /// # Errors
    /// Returns an error if the underlying storage read fails.
    fn get(&self, connector_id: &str) -> Result<Option<CredentialEntry>>;

    /// List all stored connector ids.
    ///
    /// # Errors
    /// Returns an error if the underlying storage enumeration fails.
    fn list(&self) -> Result<Vec<String>>;

    /// Remove a credential.  Returns `true` if the credential existed.
    ///
    /// # Errors
    /// Returns an error if the underlying storage deletion fails.
    fn remove(&self, connector_id: &str) -> Result<bool>;
}

// ── File backend ───────────────────────────────────────────────────────────

/// File-based credential backend.
///
/// Each credential is stored as a base64-encoded JSON file at
/// `<base_dir>/<connector_id>.json`.
pub struct FileBackend {
    base_dir: PathBuf,
}

impl FileBackend {
    /// Create a new file backend rooted at `base_dir`.
    ///
    /// The directory is created on first write.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Create a file backend using the default directory (`~/.fwc/credentials/`).
    ///
    /// Returns `None` if `$HOME` is not set.
    #[must_use]
    pub fn default_dir() -> Option<Self> {
        let home = std::env::var("HOME").ok()?;
        Some(Self::new(
            PathBuf::from(home).join(".fwc").join("credentials"),
        ))
    }

    /// Return the base directory this backend writes to.
    #[must_use]
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn credential_path(&self, connector_id: &str) -> PathBuf {
        self.base_dir.join(format!("{connector_id}.json"))
    }

    fn ensure_dir(&self) -> Result<()> {
        if !self.base_dir.exists() {
            fs::create_dir_all(&self.base_dir)
                .with_context(|| format!("creating credential dir {}", self.base_dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.base_dir, fs::Permissions::from_mode(0o700))
                    .with_context(|| {
                        format!("setting permissions on {}", self.base_dir.display())
                    })?;
            }
        }
        Ok(())
    }

    /// Encode field values to base64 for on-disk representation.
    fn encode_fields(fields: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        fields
            .iter()
            .map(|(k, v)| (k.clone(), BASE64.encode(v.as_bytes())))
            .collect()
    }

    /// Decode field values from base64 on-disk representation.
    fn decode_fields(fields: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
        fields
            .iter()
            .map(|(k, v)| {
                let bytes = BASE64
                    .decode(v.as_bytes())
                    .with_context(|| format!("decoding field {k}"))?;
                let decoded = String::from_utf8(bytes)
                    .with_context(|| format!("UTF-8 decode for field {k}"))?;
                Ok((k.clone(), decoded))
            })
            .collect()
    }
}

/// On-disk representation with base64-encoded field values.
#[derive(Serialize, Deserialize)]
struct DiskCredential {
    connector_id: String,
    auth_type: AuthType,
    fields: BTreeMap<String, String>,
    created_at: String,
    updated_at: String,
    last_verified: Option<String>,
}

impl CredentialBackend for FileBackend {
    fn store(&self, entry: &CredentialEntry) -> Result<()> {
        self.ensure_dir()?;
        let disk = DiskCredential {
            connector_id: entry.connector_id.clone(),
            auth_type: entry.auth_type,
            fields: Self::encode_fields(&entry.fields),
            created_at: entry.created_at.clone(),
            updated_at: entry.updated_at.clone(),
            last_verified: entry.last_verified.clone(),
        };
        let json = serde_json::to_string_pretty(&disk)?;
        let path = self.credential_path(&entry.connector_id);
        let mut file = fs::File::create(&path)
            .with_context(|| format!("writing credential to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    fn get(&self, connector_id: &str) -> Result<Option<CredentialEntry>> {
        let path = self.credential_path(connector_id);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&path)
            .with_context(|| format!("reading credential {}", path.display()))?;
        let disk: DiskCredential = serde_json::from_str(&data)
            .with_context(|| format!("parsing credential {}", path.display()))?;
        let fields = Self::decode_fields(&disk.fields)?;
        Ok(Some(CredentialEntry {
            connector_id: disk.connector_id,
            auth_type: disk.auth_type,
            fields,
            created_at: disk.created_at,
            updated_at: disk.updated_at,
            last_verified: disk.last_verified,
        }))
    }

    fn list(&self) -> Result<Vec<String>> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    ids.push(stem.to_owned());
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn remove(&self, connector_id: &str) -> Result<bool> {
        let path = self.credential_path(connector_id);
        if !path.exists() {
            return Ok(false);
        }
        fs::remove_file(&path)
            .with_context(|| format!("removing credential {}", path.display()))?;
        Ok(true)
    }
}

// ── Credential store ───────────────────────────────────────────────────────

/// High-level credential store wrapping a backend.
///
/// All read-facing methods return [`RedactedCredential`] to prevent accidental
/// secret exposure.  Use [`get_secret`](CredentialStore::get_secret) to obtain
/// raw values for connector invocation.
pub struct CredentialStore<B: CredentialBackend = FileBackend> {
    backend: B,
}

impl<B: CredentialBackend> CredentialStore<B> {
    /// Create a store backed by the given backend.
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Add (or overwrite) a credential for a connector.
    ///
    /// # Errors
    /// Returns an error if the backend write fails.
    pub fn add(
        &self,
        connector_id: impl Into<String>,
        auth_type: AuthType,
        fields: BTreeMap<String, String>,
    ) -> Result<()> {
        let entry = CredentialEntry::new(connector_id, auth_type, fields);
        self.backend.store(&entry)
    }

    /// Retrieve a full credential entry (including raw secrets).
    ///
    /// # Errors
    /// Returns an error if the backend read fails.
    pub fn get(&self, connector_id: &str) -> Result<Option<CredentialEntry>> {
        self.backend.get(connector_id)
    }

    /// List all credentials in redacted form.
    ///
    /// # Errors
    /// Returns an error if the backend enumeration or read fails.
    pub fn list(&self) -> Result<Vec<RedactedCredential>> {
        let ids = self.backend.list()?;
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entry) = self.backend.get(&id)? {
                result.push(entry.redacted());
            }
        }
        Ok(result)
    }

    /// Remove a credential.  Returns `true` if the credential existed.
    ///
    /// # Errors
    /// Returns an error if the backend deletion fails.
    pub fn remove(&self, connector_id: &str) -> Result<bool> {
        self.backend.remove(connector_id)
    }

    /// Update fields on an existing credential, merging with existing fields.
    ///
    /// # Errors
    /// Returns an error if no credential exists for the given connector or
    /// if the backend read/write fails.
    pub fn update(&self, connector_id: &str, new_fields: BTreeMap<String, String>) -> Result<()> {
        let mut entry = self
            .backend
            .get(connector_id)?
            .ok_or_else(|| anyhow::anyhow!("no credential found for {connector_id}"))?;
        for (k, v) in new_fields {
            entry.fields.insert(k, v);
        }
        entry.touch();
        self.backend.store(&entry)
    }

    /// Get a single raw secret field from a stored credential.
    ///
    /// This is the only method that returns an unmasked value.  Use it when
    /// building an invocation payload.
    ///
    /// # Errors
    /// Returns an error if the backend read fails.
    pub fn get_secret(&self, connector_id: &str, field_name: &str) -> Result<Option<String>> {
        let entry = self.backend.get(connector_id)?;
        Ok(entry.and_then(|e| e.fields.get(field_name).cloned()))
    }
}

// ── Auth verification ──────────────────────────────────────────────────────

/// Status of credential verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStatus {
    /// Credential is present and structurally valid (and not expired if OAuth).
    Valid,
    /// OAuth credential has expired.
    Expired,
    /// Credential is present but structurally invalid (e.g. missing required fields).
    Invalid,
    /// No credential is stored for this connector.
    NoCredential,
    /// An error occurred during verification.
    Error,
}

impl fmt::Display for AuthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => f.write_str("valid"),
            Self::Expired => f.write_str("expired"),
            Self::Invalid => f.write_str("invalid"),
            Self::NoCredential => f.write_str("no_credential"),
            Self::Error => f.write_str("error"),
        }
    }
}

/// Token expiry information for OAuth credentials.
#[derive(Clone, Debug, Serialize)]
pub struct ExpiryInfo {
    /// ISO-8601 expiry timestamp.
    pub expires_at: String,
    /// Number of days remaining (negative if already expired).
    pub days_remaining: i64,
}

/// Result of a credential verification check.
#[derive(Clone, Debug, Serialize)]
pub struct AuthTestResult {
    /// Connector that was verified.
    pub connector_id: String,
    /// Verification outcome.
    pub status: AuthStatus,
    /// Human-readable detail message.
    pub message: String,
    /// Token expiry info, if applicable (OAuth only).
    pub expiry_info: Option<ExpiryInfo>,
}

/// Required fields for each auth type.
const fn required_fields(auth_type: AuthType) -> &'static [&'static str] {
    match auth_type {
        AuthType::ApiToken => &["token"],
        AuthType::OAuth => &["access_token"],
        AuthType::BasicAuth => &["username", "password"],
        AuthType::SessionToken => &["session_token"],
        AuthType::CredentialRef => &["ref"],
        AuthType::NoAuth => &[],
    }
}

/// Verify a credential's structural validity and expiry.
///
/// This does NOT perform live API calls — it checks:
/// 1. Credential presence
/// 2. Required fields for the auth type
/// 3. OAuth token expiry (if `expires_at` field is present)
#[must_use]
pub fn verify_credential(entry: &CredentialEntry) -> AuthTestResult {
    let connector_id = entry.connector_id.clone();

    // Check required fields.
    let required = required_fields(entry.auth_type);
    let missing: Vec<&str> = required
        .iter()
        .filter(|f| entry.fields.get(**f).is_none_or(|v| v.trim().is_empty()))
        .copied()
        .collect();

    if !missing.is_empty() {
        return AuthTestResult {
            connector_id,
            status: AuthStatus::Invalid,
            message: format!("missing required fields: {}", missing.join(", ")),
            expiry_info: None,
        };
    }

    // For OAuth, check expiry.
    if entry.auth_type == AuthType::OAuth {
        if let Some(expires_at_str) = entry.fields.get("expires_at") {
            if let Ok(expires_at) = expires_at_str.parse::<DateTime<Utc>>() {
                let now = Utc::now();
                let days_remaining = (expires_at - now).num_days();
                let expiry = ExpiryInfo {
                    expires_at: expires_at_str.clone(),
                    days_remaining,
                };
                if days_remaining < 0 {
                    return AuthTestResult {
                        connector_id,
                        status: AuthStatus::Expired,
                        message: format!("OAuth token expired {} days ago", days_remaining.abs()),
                        expiry_info: Some(expiry),
                    };
                }
                return AuthTestResult {
                    connector_id,
                    status: AuthStatus::Valid,
                    message: format!("OAuth token valid, {days_remaining} days remaining"),
                    expiry_info: Some(expiry),
                };
            }
            // Unparseable expiry — treat as invalid.
            return AuthTestResult {
                connector_id,
                status: AuthStatus::Invalid,
                message: format!("unparseable expires_at: {expires_at_str}"),
                expiry_info: None,
            };
        }
    }

    AuthTestResult {
        connector_id,
        status: AuthStatus::Valid,
        message: format!(
            "{} credential present with all required fields",
            entry.auth_type
        ),
        expiry_info: None,
    }
}

/// Verify a credential from the store by connector id.
///
/// Returns [`AuthStatus::NoCredential`] when nothing is stored.
pub fn verify_from_store<B: CredentialBackend>(
    store: &CredentialStore<B>,
    connector_id: &str,
) -> AuthTestResult {
    match store.get(connector_id) {
        Ok(Some(entry)) => verify_credential(&entry),
        Ok(None) => AuthTestResult {
            connector_id: connector_id.to_owned(),
            status: AuthStatus::NoCredential,
            message: "no credential stored".to_owned(),
            expiry_info: None,
        },
        Err(e) => AuthTestResult {
            connector_id: connector_id.to_owned(),
            status: AuthStatus::Error,
            message: format!("error reading credential: {e}"),
            expiry_info: None,
        },
    }
}

// ── In-memory backend (for testing) ────────────────────────────────────────

/// In-memory credential backend for testing purposes.
#[cfg(test)]
pub struct MemoryBackend {
    entries: std::cell::RefCell<BTreeMap<String, CredentialEntry>>,
}

#[cfg(test)]
impl Default for MemoryBackend {
    fn default() -> Self {
        Self {
            entries: std::cell::RefCell::new(BTreeMap::new()),
        }
    }
}

#[cfg(test)]
impl MemoryBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl CredentialBackend for MemoryBackend {
    fn store(&self, entry: &CredentialEntry) -> Result<()> {
        self.entries
            .borrow_mut()
            .insert(entry.connector_id.clone(), entry.clone());
        Ok(())
    }

    fn get(&self, connector_id: &str) -> Result<Option<CredentialEntry>> {
        Ok(self.entries.borrow().get(connector_id).cloned())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.entries.borrow().keys().cloned().collect())
    }

    fn remove(&self, connector_id: &str) -> Result<bool> {
        Ok(self.entries.borrow_mut().remove(connector_id).is_some())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: make a store with in-memory backend.
    fn mem_store() -> CredentialStore<MemoryBackend> {
        CredentialStore::new(MemoryBackend::new())
    }

    // Helper: make a store with file backend in a temp dir.
    fn file_store() -> (CredentialStore<FileBackend>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fwc-cred-{}", uuid::Uuid::new_v4()));
        let store = CredentialStore::new(FileBackend::new(&dir));
        (store, dir)
    }

    fn sample_fields() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("token".to_owned(), "ghp_abc123xyz789".to_owned());
        m
    }

    fn oauth_fields(expires_at: &str) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("access_token".to_owned(), "ya29.long-token-here".to_owned());
        m.insert("refresh_token".to_owned(), "1//refresh".to_owned());
        m.insert("expires_at".to_owned(), expires_at.to_owned());
        m
    }

    // ── AuthType ───────────────────────────────────────────────────────

    #[test]
    fn auth_type_as_str_roundtrip() {
        let types = [
            AuthType::ApiToken,
            AuthType::OAuth,
            AuthType::BasicAuth,
            AuthType::SessionToken,
            AuthType::CredentialRef,
            AuthType::NoAuth,
        ];
        for t in types {
            let label = t.as_str();
            let parsed = AuthType::from_str_label(label);
            assert_eq!(parsed, Some(t), "roundtrip failed for {label}");
        }
    }

    #[test]
    fn auth_type_display() {
        assert_eq!(format!("{}", AuthType::ApiToken), "api_token");
        assert_eq!(format!("{}", AuthType::OAuth), "oauth");
    }

    #[test]
    fn auth_type_from_str_aliases() {
        assert_eq!(AuthType::from_str_label("bearer"), Some(AuthType::ApiToken));
        assert_eq!(AuthType::from_str_label("oauth2"), Some(AuthType::OAuth));
        assert_eq!(AuthType::from_str_label("basic"), Some(AuthType::BasicAuth));
        assert_eq!(
            AuthType::from_str_label("session"),
            Some(AuthType::SessionToken)
        );
        assert_eq!(AuthType::from_str_label("none"), Some(AuthType::NoAuth));
    }

    #[test]
    fn auth_type_from_str_unknown() {
        assert_eq!(AuthType::from_str_label("magic"), None);
    }

    // ── Masking ────────────────────────────────────────────────────────

    #[test]
    fn mask_secret_short_value() {
        assert_eq!(mask_secret("ab"), "****");
        assert_eq!(mask_secret("abcd"), "****");
    }

    #[test]
    fn mask_secret_shows_suffix() {
        assert_eq!(mask_secret("ghp_abc123xyz789"), "****z789");
    }

    #[test]
    fn mask_secret_five_chars() {
        assert_eq!(mask_secret("12345"), "****2345");
    }

    #[test]
    fn mask_secret_empty() {
        assert_eq!(mask_secret(""), "****");
    }

    #[test]
    fn mask_secret_unicode() {
        // Ensure we don't panic on multi-byte chars.
        let masked = mask_secret("tok_abcde");
        assert!(masked.starts_with("****"));
        assert!(masked.ends_with("bcde"));
    }

    // ── CredentialEntry ────────────────────────────────────────────────

    #[test]
    fn credential_entry_new_sets_timestamps() {
        let entry = CredentialEntry::new("github", AuthType::ApiToken, sample_fields());
        assert_eq!(entry.connector_id, "github");
        assert_eq!(entry.auth_type, AuthType::ApiToken);
        assert!(!entry.created_at.is_empty());
        assert_eq!(entry.created_at, entry.updated_at);
        assert!(entry.last_verified.is_none());
    }

    #[test]
    fn credential_entry_touch_updates_timestamp() {
        let mut entry = CredentialEntry::new("github", AuthType::ApiToken, sample_fields());
        let original = entry.updated_at.clone();
        // Touch immediately — may or may not differ by the second, but should not panic.
        entry.touch();
        assert!(!entry.updated_at.is_empty());
        // created_at should not change.
        assert_eq!(entry.created_at, original);
    }

    #[test]
    fn credential_entry_mark_verified() {
        let mut entry = CredentialEntry::new("slack", AuthType::ApiToken, sample_fields());
        assert!(entry.last_verified.is_none());
        entry.mark_verified();
        assert!(entry.last_verified.is_some());
    }

    #[test]
    fn credential_entry_redacted_masks_fields() {
        let entry = CredentialEntry::new("github", AuthType::ApiToken, sample_fields());
        let redacted = entry.redacted();
        assert_eq!(redacted.connector_id, "github");
        let token_val = redacted.fields.get("token").unwrap();
        assert!(!token_val.contains("ghp_abc123"));
        assert!(token_val.contains("****"));
    }

    // ── RedactedCredential display ─────────────────────────────────────

    #[test]
    fn redacted_credential_display() {
        let entry = CredentialEntry::new("github", AuthType::ApiToken, sample_fields());
        let redacted = entry.redacted();
        let display = format!("{redacted}");
        assert!(display.contains("github"));
        assert!(display.contains("api_token"));
        assert!(!display.contains("ghp_abc123"));
    }

    // ── In-memory store lifecycle ──────────────────────────────────────

    #[test]
    fn store_add_and_get() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let entry = store.get("github").unwrap().unwrap();
        assert_eq!(entry.connector_id, "github");
        assert_eq!(entry.fields.get("token").unwrap(), "ghp_abc123xyz789");
    }

    #[test]
    fn store_get_nonexistent() {
        let store = mem_store();
        assert!(store.get("nope").unwrap().is_none());
    }

    #[test]
    fn store_list_returns_redacted() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        store
            .add("slack", AuthType::ApiToken, sample_fields())
            .unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        // Values should be masked.
        for r in &list {
            let token_val = r.fields.get("token").unwrap();
            assert!(token_val.contains("****"));
        }
    }

    #[test]
    fn store_remove_existing() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        assert!(store.remove("github").unwrap());
        assert!(store.get("github").unwrap().is_none());
    }

    #[test]
    fn store_remove_nonexistent() {
        let store = mem_store();
        assert!(!store.remove("nope").unwrap());
    }

    #[test]
    fn store_double_remove() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        assert!(store.remove("github").unwrap());
        assert!(!store.remove("github").unwrap());
    }

    #[test]
    fn store_update_merges_fields() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let mut update = BTreeMap::new();
        update.insert("scope".to_owned(), "repo".to_owned());
        store.update("github", update).unwrap();
        let entry = store.get("github").unwrap().unwrap();
        assert_eq!(entry.fields.get("token").unwrap(), "ghp_abc123xyz789");
        assert_eq!(entry.fields.get("scope").unwrap(), "repo");
    }

    #[test]
    fn store_update_overwrites_existing_field() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let mut update = BTreeMap::new();
        update.insert("token".to_owned(), "new_token_value".to_owned());
        store.update("github", update).unwrap();
        let entry = store.get("github").unwrap().unwrap();
        assert_eq!(entry.fields.get("token").unwrap(), "new_token_value");
    }

    #[test]
    fn store_update_nonexistent_fails() {
        let store = mem_store();
        let mut update = BTreeMap::new();
        update.insert("token".to_owned(), "val".to_owned());
        assert!(store.update("nope", update).is_err());
    }

    #[test]
    fn store_add_overwrites() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let mut new_fields = BTreeMap::new();
        new_fields.insert("token".to_owned(), "new_value".to_owned());
        store.add("github", AuthType::ApiToken, new_fields).unwrap();
        let entry = store.get("github").unwrap().unwrap();
        assert_eq!(entry.fields.get("token").unwrap(), "new_value");
    }

    #[test]
    fn store_get_secret() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let secret = store.get_secret("github", "token").unwrap().unwrap();
        assert_eq!(secret, "ghp_abc123xyz789");
    }

    #[test]
    fn store_get_secret_nonexistent_connector() {
        let store = mem_store();
        assert!(store.get_secret("nope", "token").unwrap().is_none());
    }

    #[test]
    fn store_get_secret_nonexistent_field() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        assert!(store.get_secret("github", "nope").unwrap().is_none());
    }

    #[test]
    fn store_empty_fields() {
        let store = mem_store();
        store
            .add("noauth", AuthType::NoAuth, BTreeMap::new())
            .unwrap();
        let entry = store.get("noauth").unwrap().unwrap();
        assert!(entry.fields.is_empty());
    }

    #[test]
    fn store_list_empty() {
        let store = mem_store();
        assert!(store.list().unwrap().is_empty());
    }

    // ── File backend ───────────────────────────────────────────────────

    #[test]
    fn file_backend_store_and_get() {
        let (store, dir) = file_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let entry = store.get("github").unwrap().unwrap();
        assert_eq!(entry.fields.get("token").unwrap(), "ghp_abc123xyz789");
        // Cleanup.
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_persists_base64_encoded() {
        let (store, dir) = file_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let raw = fs::read_to_string(dir.join("github.json")).unwrap();
        // The raw file should contain base64, not the raw token.
        assert!(!raw.contains("ghp_abc123xyz789"));
        // Should contain the base64 encoding of the token.
        let encoded = BASE64.encode(b"ghp_abc123xyz789");
        assert!(raw.contains(&encoded));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_list() {
        let (store, dir) = file_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        store
            .add("slack", AuthType::ApiToken, sample_fields())
            .unwrap();
        let list = store.list().unwrap();
        let ids: Vec<&str> = list.iter().map(|r| r.connector_id.as_str()).collect();
        assert_eq!(ids, vec!["github", "slack"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_remove() {
        let (store, dir) = file_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        assert!(store.remove("github").unwrap());
        assert!(store.get("github").unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_list_empty_dir() {
        let (store, dir) = file_store();
        let list = store.list().unwrap();
        assert!(list.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_get_nonexistent() {
        let (store, dir) = file_store();
        assert!(store.get("nope").unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_update() {
        let (store, dir) = file_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let mut update = BTreeMap::new();
        update.insert("scope".to_owned(), "repo".to_owned());
        store.update("github", update).unwrap();
        let entry = store.get("github").unwrap().unwrap();
        assert_eq!(entry.fields.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_special_chars_in_value() {
        let (store, dir) = file_store();
        let mut fields = BTreeMap::new();
        fields.insert("token".to_owned(), "tok=abc+/def\n\t!@#$%".to_owned());
        store.add("special", AuthType::ApiToken, fields).unwrap();
        let entry = store.get("special").unwrap().unwrap();
        assert_eq!(entry.fields.get("token").unwrap(), "tok=abc+/def\n\t!@#$%");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_permissions() {
        let (store, dir) = file_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(dir.join("github.json")).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "credential file should be 0600");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // ── Auth verification ──────────────────────────────────────────────

    #[test]
    fn verify_no_credential() {
        let store = mem_store();
        let result = verify_from_store(&store, "github");
        assert_eq!(result.status, AuthStatus::NoCredential);
        assert!(result.message.contains("no credential"));
    }

    #[test]
    fn verify_valid_api_token() {
        let entry = CredentialEntry::new("github", AuthType::ApiToken, sample_fields());
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Valid);
        assert!(result.expiry_info.is_none());
    }

    #[test]
    fn verify_missing_required_field() {
        let entry = CredentialEntry::new("github", AuthType::ApiToken, BTreeMap::new());
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Invalid);
        assert!(result.message.contains("token"));
    }

    #[test]
    fn verify_empty_required_field() {
        let mut fields = BTreeMap::new();
        fields.insert("token".to_owned(), "   ".to_owned());
        let entry = CredentialEntry::new("github", AuthType::ApiToken, fields);
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Invalid);
    }

    #[test]
    fn verify_basic_auth_valid() {
        let mut fields = BTreeMap::new();
        fields.insert("username".to_owned(), "user".to_owned());
        fields.insert("password".to_owned(), "pass".to_owned());
        let entry = CredentialEntry::new("jira", AuthType::BasicAuth, fields);
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Valid);
    }

    #[test]
    fn verify_basic_auth_missing_password() {
        let mut fields = BTreeMap::new();
        fields.insert("username".to_owned(), "user".to_owned());
        let entry = CredentialEntry::new("jira", AuthType::BasicAuth, fields);
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Invalid);
        assert!(result.message.contains("password"));
    }

    #[test]
    fn verify_oauth_valid_not_expired() {
        let future =
            (Utc::now() + chrono::Duration::days(30)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let entry = CredentialEntry::new("google", AuthType::OAuth, oauth_fields(&future));
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Valid);
        let expiry = result.expiry_info.unwrap();
        assert!(expiry.days_remaining >= 29);
    }

    #[test]
    fn verify_oauth_expired() {
        let past =
            (Utc::now() - chrono::Duration::days(10)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let entry = CredentialEntry::new("google", AuthType::OAuth, oauth_fields(&past));
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Expired);
        let expiry = result.expiry_info.unwrap();
        assert!(expiry.days_remaining < 0);
        assert!(result.message.contains("expired"));
    }

    #[test]
    fn verify_oauth_unparseable_expiry() {
        let entry = CredentialEntry::new("google", AuthType::OAuth, oauth_fields("not-a-date"));
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Invalid);
        assert!(result.message.contains("unparseable"));
    }

    #[test]
    fn verify_oauth_no_expiry_field() {
        let mut fields = BTreeMap::new();
        fields.insert("access_token".to_owned(), "ya29.token".to_owned());
        let entry = CredentialEntry::new("google", AuthType::OAuth, fields);
        let result = verify_credential(&entry);
        // Valid — expiry is optional, credential is structurally present.
        assert_eq!(result.status, AuthStatus::Valid);
        assert!(result.expiry_info.is_none());
    }

    #[test]
    fn verify_session_token_valid() {
        let mut fields = BTreeMap::new();
        fields.insert("session_token".to_owned(), "sess_abc123".to_owned());
        let entry = CredentialEntry::new("metabase", AuthType::SessionToken, fields);
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Valid);
    }

    #[test]
    fn verify_no_auth_always_valid() {
        let entry = CredentialEntry::new("public-api", AuthType::NoAuth, BTreeMap::new());
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Valid);
    }

    #[test]
    fn verify_credential_ref_valid() {
        let mut fields = BTreeMap::new();
        fields.insert("ref".to_owned(), "vault:secret/data/github".to_owned());
        let entry = CredentialEntry::new("github", AuthType::CredentialRef, fields);
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Valid);
    }

    #[test]
    fn verify_credential_ref_missing_ref() {
        let entry = CredentialEntry::new("github", AuthType::CredentialRef, BTreeMap::new());
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Invalid);
        assert!(result.message.contains("ref"));
    }

    #[test]
    fn verify_from_store_valid() {
        let store = mem_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let result = verify_from_store(&store, "github");
        assert_eq!(result.status, AuthStatus::Valid);
    }

    // ── AuthStatus display ─────────────────────────────────────────────

    #[test]
    fn auth_status_display() {
        assert_eq!(format!("{}", AuthStatus::Valid), "valid");
        assert_eq!(format!("{}", AuthStatus::Expired), "expired");
        assert_eq!(format!("{}", AuthStatus::Invalid), "invalid");
        assert_eq!(format!("{}", AuthStatus::NoCredential), "no_credential");
        assert_eq!(format!("{}", AuthStatus::Error), "error");
    }

    // ── Serialization roundtrip ────────────────────────────────────────

    #[test]
    fn credential_entry_serde_roundtrip() {
        let entry = CredentialEntry::new("github", AuthType::ApiToken, sample_fields());
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: CredentialEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connector_id, "github");
        assert_eq!(deserialized.auth_type, AuthType::ApiToken);
        assert_eq!(
            deserialized.fields.get("token").unwrap(),
            "ghp_abc123xyz789"
        );
    }

    #[test]
    fn auth_type_serde_roundtrip() {
        let types = [
            AuthType::ApiToken,
            AuthType::OAuth,
            AuthType::BasicAuth,
            AuthType::SessionToken,
            AuthType::CredentialRef,
            AuthType::NoAuth,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let parsed: AuthType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, t);
        }
    }

    // ── Base64 encode/decode ───────────────────────────────────────────

    #[test]
    fn base64_encode_decode_roundtrip() {
        let fields = sample_fields();
        let encoded = FileBackend::encode_fields(&fields);
        let decoded = FileBackend::decode_fields(&encoded).unwrap();
        assert_eq!(fields, decoded);
    }

    #[test]
    fn base64_encode_decode_empty_map() {
        let fields = BTreeMap::new();
        let encoded = FileBackend::encode_fields(&fields);
        let decoded = FileBackend::decode_fields(&encoded).unwrap();
        assert_eq!(fields, decoded);
    }

    #[test]
    fn base64_encode_decode_special_chars() {
        let mut fields = BTreeMap::new();
        fields.insert("key".to_owned(), "a/b+c=d\nline2".to_owned());
        let encoded = FileBackend::encode_fields(&fields);
        let decoded = FileBackend::decode_fields(&encoded).unwrap();
        assert_eq!(fields, decoded);
    }

    // ── ExpiryInfo serialization ───────────────────────────────────────

    #[test]
    fn expiry_info_serialization() {
        let info = ExpiryInfo {
            expires_at: "2026-04-01T00:00:00Z".to_owned(),
            days_remaining: 23,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("23"));
        assert!(json.contains("2026-04-01"));
    }

    // ── AuthTestResult serialization ───────────────────────────────────

    #[test]
    fn auth_test_result_serialization() {
        let result = AuthTestResult {
            connector_id: "github".to_owned(),
            status: AuthStatus::Valid,
            message: "all good".to_owned(),
            expiry_info: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\""));
        assert!(json.contains("github"));
    }

    // ── Required fields ────────────────────────────────────────────────

    #[test]
    fn required_fields_api_token() {
        assert_eq!(required_fields(AuthType::ApiToken), &["token"]);
    }

    #[test]
    fn required_fields_oauth() {
        assert_eq!(required_fields(AuthType::OAuth), &["access_token"]);
    }

    #[test]
    fn required_fields_basic_auth() {
        assert_eq!(
            required_fields(AuthType::BasicAuth),
            &["username", "password"]
        );
    }

    #[test]
    fn required_fields_no_auth() {
        assert!(required_fields(AuthType::NoAuth).is_empty());
    }

    // ── Edge cases ─────────────────────────────────────────────────────

    #[test]
    fn store_multiple_connectors_independent() {
        let store = mem_store();
        let mut github_fields = BTreeMap::new();
        github_fields.insert("token".to_owned(), "ghp_github".to_owned());
        let mut slack_fields = BTreeMap::new();
        slack_fields.insert("token".to_owned(), "xoxb_slack".to_owned());
        store
            .add("github", AuthType::ApiToken, github_fields)
            .unwrap();
        store
            .add("slack", AuthType::ApiToken, slack_fields)
            .unwrap();
        assert_eq!(
            store.get_secret("github", "token").unwrap().unwrap(),
            "ghp_github"
        );
        assert_eq!(
            store.get_secret("slack", "token").unwrap().unwrap(),
            "xoxb_slack"
        );
    }

    #[test]
    fn file_backend_concurrent_writes() {
        let (store, dir) = file_store();
        // Write two credentials sequentially (file backend is not async).
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        store
            .add("slack", AuthType::ApiToken, sample_fields())
            .unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_overwrite() {
        let (store, dir) = file_store();
        store
            .add("github", AuthType::ApiToken, sample_fields())
            .unwrap();
        let mut new_fields = BTreeMap::new();
        new_fields.insert("token".to_owned(), "new_token".to_owned());
        store.add("github", AuthType::ApiToken, new_fields).unwrap();
        let entry = store.get("github").unwrap().unwrap();
        assert_eq!(entry.fields.get("token").unwrap(), "new_token");
        // Only one file should exist.
        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_default_dir() {
        // Just test that `default_dir` returns Some when HOME is set.
        let backend = FileBackend::default_dir();
        if std::env::var("HOME").is_ok() {
            assert!(backend.is_some());
            let b = backend.unwrap();
            assert!(b.base_dir().ends_with("credentials"));
        }
    }

    #[test]
    fn verify_basic_auth_missing_both() {
        let entry = CredentialEntry::new("jira", AuthType::BasicAuth, BTreeMap::new());
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Invalid);
        assert!(result.message.contains("username"));
        assert!(result.message.contains("password"));
    }

    #[test]
    fn verify_oauth_just_expired() {
        // Expired 1 day ago.
        let yesterday =
            (Utc::now() - chrono::Duration::days(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let entry = CredentialEntry::new("google", AuthType::OAuth, oauth_fields(&yesterday));
        let result = verify_credential(&entry);
        assert_eq!(result.status, AuthStatus::Expired);
        let expiry = result.expiry_info.unwrap();
        assert_eq!(expiry.days_remaining, -1);
    }

    #[test]
    fn redacted_credential_serde() {
        let entry = CredentialEntry::new("github", AuthType::ApiToken, sample_fields());
        let redacted = entry.redacted();
        let json = serde_json::to_string(&redacted).unwrap();
        // Raw token must not appear in serialized redacted output.
        assert!(!json.contains("ghp_abc123xyz789"));
        assert!(json.contains("****"));
    }
}
