//! Encrypted credential store for connector authentication.
//!
//! Stores connector credentials in an encrypted file at `~/.fwc/credentials.enc`
//! using ChaCha20-Poly1305 with a key derived from machine identity. Credentials
//! are never written in plaintext and are always redacted in display output.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Types ──────────────────────────────────────────────────────────

/// Authentication method used by a connector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// A single bearer/API token.
    BearerToken,
    /// Username + password (HTTP Basic).
    BasicAuth,
    /// `OAuth2` client credentials or token.
    OAuth2,
    /// Custom header-based auth (e.g. X-Api-Key).
    ApiKey,
    /// Session token acquired from a login endpoint.
    SessionToken,
    /// Secretless reference to an external credential provider.
    SecretlessRef,
    /// Custom multi-field auth.
    Custom,
}

impl AuthMethod {
    /// Detect auth method from the fields present in a credential.
    fn detect(fields: &BTreeMap<String, String>) -> Self {
        if fields.contains_key("credential_id") {
            return Self::SecretlessRef;
        }
        if fields.contains_key("client_id") && fields.contains_key("client_secret") {
            return Self::OAuth2;
        }
        if fields.contains_key("username") && fields.contains_key("password") {
            return Self::BasicAuth;
        }
        if fields.contains_key("token") || fields.contains_key("api_token") {
            return Self::BearerToken;
        }
        if fields.contains_key("api_key") {
            return Self::ApiKey;
        }
        if fields.contains_key("session_token") {
            return Self::SessionToken;
        }
        Self::Custom
    }
}

/// A stored credential for a connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    /// Connector identifier (e.g. "github", "slack").
    pub connector_id: String,
    /// Authentication method.
    pub auth_method: AuthMethod,
    /// Secret fields (key → value). Values are the actual secrets.
    pub fields: BTreeMap<String, String>,
    /// When this credential was created.
    pub created_at: DateTime<Utc>,
    /// When this credential was last updated.
    pub updated_at: DateTime<Utc>,
    /// When this credential was last used for an operation.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl Credential {
    /// Create a new credential from raw fields.
    pub fn new(
        connector_id: impl Into<String>,
        fields: BTreeMap<String, String>,
        label: Option<String>,
    ) -> Self {
        let auth_method = AuthMethod::detect(&fields);
        let now = Utc::now();
        Self {
            connector_id: connector_id.into(),
            auth_method,
            fields,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            label,
        }
    }

    /// Mark this credential as used now.
    pub fn touch(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Produce a redacted view safe for display (secrets replaced with `***`).
    pub fn redacted_view(&self) -> Value {
        let mut fields = serde_json::Map::new();
        for (key, value) in &self.fields {
            let redacted = redact_value(value);
            fields.insert(key.clone(), Value::String(redacted));
        }
        serde_json::json!({
            "connector_id": self.connector_id,
            "auth_method": self.auth_method,
            "fields": fields,
            "created_at": self.created_at.to_rfc3339(),
            "updated_at": self.updated_at.to_rfc3339(),
            "last_used_at": self.last_used_at.map(|t| t.to_rfc3339()),
            "label": self.label,
        })
    }

    /// Get a specific secret field value.
    pub fn get_field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

/// Redact a secret value for display.
///
/// Shows first and last character with `***` in between for values >= 8 chars.
/// Shorter values become `***`.
fn redact_value(value: &str) -> String {
    if value.len() < 8 {
        return "***".to_string();
    }
    let chars: Vec<char> = value.chars().collect();
    let first = chars[0];
    let last = chars[chars.len() - 1];
    format!("{first}***{last}")
}

// ── Encryption layer ───────────────────────────────────────────────

/// Encryption key length for ChaCha20-Poly1305 (256 bits).
const KEY_LEN: usize = 32;
/// Nonce length for ChaCha20-Poly1305 (96 bits).
const NONCE_LEN: usize = 12;

/// Derive an encryption key from machine identity.
///
/// Uses a combination of username and home directory path as the identity
/// source, then derives a 256-bit key via SHA-256.
fn derive_key() -> [u8; KEY_LEN] {
    use sha2::{Digest, Sha256};

    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".to_string());

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    let mut hasher = Sha256::new();
    hasher.update(b"fwc-credential-store-v1:");
    hasher.update(user.as_bytes());
    hasher.update(b":");
    hasher.update(home.as_bytes());

    let result = hasher.finalize();
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&result);
    key
}

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// Returns `nonce || ciphertext` concatenated.
fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use rand::Rng;

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("key init failed: {e}"))?;

    // Generate random nonce.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data previously encrypted with `encrypt`.
///
/// Expects `nonce || ciphertext` format.
fn decrypt(data: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    if data.len() < NONCE_LEN + 16 {
        // Minimum: nonce + poly1305 tag.
        return Err("ciphertext too short".to_string());
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("key init failed: {e}"))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed (wrong key or corrupted data): {e}"))
}

// ── Store ──────────────────────────────────────────────────────────

/// The credential store: an encrypted JSON file holding all credentials.
pub struct CredentialStore {
    path: PathBuf,
    key: [u8; KEY_LEN],
}

/// The inner data structure persisted to disk.
#[derive(Default, Serialize, Deserialize)]
struct StoreData {
    credentials: BTreeMap<String, Credential>,
}

impl CredentialStore {
    /// Create a store at the default path (`~/.fwc/credentials.enc`).
    pub fn default_path() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let path = PathBuf::from(home)
            .join(".fwc")
            .join("credentials.enc");
        Self {
            path,
            key: derive_key(),
        }
    }

    /// Create a store at a custom path with a custom key (for testing).
    pub fn new(path: impl Into<PathBuf>, key: [u8; KEY_LEN]) -> Self {
        Self {
            path: path.into(),
            key,
        }
    }

    /// Add or update a credential for a connector.
    pub fn add(&self, credential: Credential) -> Result<(), String> {
        let mut data = self.load_data()?;
        data.credentials
            .insert(credential.connector_id.clone(), credential);
        self.save_data(&data)
    }

    /// Get a credential by connector ID.
    pub fn get(&self, connector_id: &str) -> Result<Option<Credential>, String> {
        let data = self.load_data()?;
        Ok(data.credentials.get(connector_id).cloned())
    }

    /// Remove a credential by connector ID. Returns `true` if it existed.
    pub fn remove(&self, connector_id: &str) -> Result<bool, String> {
        let mut data = self.load_data()?;
        let existed = data.credentials.remove(connector_id).is_some();
        if existed {
            self.save_data(&data)?;
        }
        Ok(existed)
    }

    /// List all stored credentials (redacted).
    pub fn list(&self) -> Result<Vec<Value>, String> {
        let data = self.load_data()?;
        Ok(data
            .credentials
            .values()
            .map(Credential::redacted_view)
            .collect())
    }

    /// List all connector IDs that have stored credentials.
    pub fn list_ids(&self) -> Result<Vec<String>, String> {
        let data = self.load_data()?;
        Ok(data.credentials.keys().cloned().collect())
    }

    /// Update specific fields in an existing credential.
    pub fn update_fields(
        &self,
        connector_id: &str,
        fields: BTreeMap<String, String>,
    ) -> Result<bool, String> {
        let mut data = self.load_data()?;
        if let Some(cred) = data.credentials.get_mut(connector_id) {
            for (k, v) in fields {
                cred.fields.insert(k, v);
            }
            cred.auth_method = AuthMethod::detect(&cred.fields);
            cred.updated_at = Utc::now();
            self.save_data(&data)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Mark a credential as used.
    pub fn touch(&self, connector_id: &str) -> Result<bool, String> {
        let mut data = self.load_data()?;
        if let Some(cred) = data.credentials.get_mut(connector_id) {
            cred.touch();
            self.save_data(&data)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Number of stored credentials.
    pub fn count(&self) -> Result<usize, String> {
        let data = self.load_data()?;
        Ok(data.credentials.len())
    }

    /// Whether the store file exists on disk.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// The path to the store file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ── Internal ───────────────────────────────────────────────────

    fn load_data(&self) -> Result<StoreData, String> {
        if !self.path.exists() {
            return Ok(StoreData::default());
        }
        let encrypted = std::fs::read(&self.path)
            .map_err(|e| format!("failed to read credential store: {e}"))?;
        let plaintext = decrypt(&encrypted, &self.key)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| format!("credential store corrupted: {e}"))
    }

    fn save_data(&self, data: &StoreData) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create credential store directory: {e}"))?;
        }
        let plaintext =
            serde_json::to_vec(data).map_err(|e| format!("failed to serialize credentials: {e}"))?;
        let encrypted = encrypt(&plaintext, &self.key)?;
        std::fs::write(&self.path, encrypted)
            .map_err(|e| format!("failed to write credential store: {e}"))
    }
}

// ── CLI argument parsing helpers ────────────────────────────────────

/// Parse a `KEY=VALUE` credential field from CLI input.
pub fn parse_credential_field(input: &str) -> Option<(String, String)> {
    let (key, value) = input.split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key.to_owned(), value.to_owned()))
}

/// Parse multiple credential fields from CLI arguments.
pub fn parse_credential_fields(inputs: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for input in inputs {
        let (key, value) = parse_credential_field(input)
            .ok_or_else(|| format!("invalid credential field `{input}`; expected KEY=VALUE"))?;
        fields.insert(key, value);
    }
    if fields.is_empty() {
        return Err("at least one credential field is required".to_string());
    }
    Ok(fields)
}

/// Validate that a connector ID looks reasonable.
pub fn validate_connector_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("connector ID cannot be empty".to_string());
    }
    if id.len() > 64 {
        return Err("connector ID too long (max 64 characters)".to_string());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "connector ID `{id}` contains invalid characters; use alphanumeric, dash, underscore, or dot"
        ));
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        for (i, byte) in key.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *byte = (i as u8).wrapping_mul(7).wrapping_add(42);
            }
        }
        key
    }

    fn temp_store() -> CredentialStore {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("fwc-cred-test-{unique}"))
            .join("credentials.enc");
        CredentialStore::new(path, test_key())
    }

    fn sample_fields() -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("token".to_owned(), "ghp_abc123def456".to_owned());
        fields
    }

    fn sample_basic_fields() -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("username".to_owned(), "admin".to_owned());
        fields.insert("password".to_owned(), "s3cr3t_password".to_owned());
        fields
    }

    // ── AuthMethod detection ──────────────────────────────────────

    #[test]
    fn detect_bearer_token() {
        let fields = sample_fields();
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::BearerToken);
    }

    #[test]
    fn detect_basic_auth() {
        let fields = sample_basic_fields();
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::BasicAuth);
    }

    #[test]
    fn detect_oauth2() {
        let mut fields = BTreeMap::new();
        fields.insert("client_id".to_owned(), "id123".to_owned());
        fields.insert("client_secret".to_owned(), "secret456".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::OAuth2);
    }

    #[test]
    fn detect_api_key() {
        let mut fields = BTreeMap::new();
        fields.insert("api_key".to_owned(), "key_abc".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::ApiKey);
    }

    #[test]
    fn detect_session_token() {
        let mut fields = BTreeMap::new();
        fields.insert("session_token".to_owned(), "tok_xyz".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::SessionToken);
    }

    #[test]
    fn detect_secretless_ref() {
        let mut fields = BTreeMap::new();
        fields.insert("credential_id".to_owned(), "cred_abc".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::SecretlessRef);
    }

    #[test]
    fn detect_custom() {
        let mut fields = BTreeMap::new();
        fields.insert("x_custom_header".to_owned(), "val".to_owned());
        assert_eq!(AuthMethod::detect(&fields), AuthMethod::Custom);
    }

    // ── Credential ────────────────────────────────────────────────

    #[test]
    fn credential_new_detects_auth_method() {
        let cred = Credential::new("github", sample_fields(), None);
        assert_eq!(cred.connector_id, "github");
        assert_eq!(cred.auth_method, AuthMethod::BearerToken);
        assert!(cred.last_used_at.is_none());
    }

    #[test]
    fn credential_touch_sets_last_used() {
        let mut cred = Credential::new("github", sample_fields(), None);
        assert!(cred.last_used_at.is_none());
        cred.touch();
        assert!(cred.last_used_at.is_some());
    }

    #[test]
    fn credential_get_field() {
        let cred = Credential::new("github", sample_fields(), None);
        assert_eq!(cred.get_field("token"), Some("ghp_abc123def456"));
        assert_eq!(cred.get_field("missing"), None);
    }

    #[test]
    fn credential_with_label() {
        let cred = Credential::new("github", sample_fields(), Some("work account".to_owned()));
        assert_eq!(cred.label.as_deref(), Some("work account"));
    }

    // ── Redaction ─────────────────────────────────────────────────

    #[test]
    fn redact_short_value() {
        assert_eq!(redact_value("abc"), "***");
        assert_eq!(redact_value(""), "***");
        assert_eq!(redact_value("1234567"), "***");
    }

    #[test]
    fn redact_long_value() {
        assert_eq!(redact_value("ghp_abc123def456"), "g***6");
        assert_eq!(redact_value("12345678"), "1***8");
    }

    #[test]
    fn redacted_view_hides_secrets() {
        let cred = Credential::new("github", sample_fields(), None);
        let view = cred.redacted_view();
        let fields = view["fields"].as_object().unwrap();
        let token_display = fields["token"].as_str().unwrap();
        assert!(!token_display.contains("ghp_abc123def456"));
        assert!(token_display.contains("***"));
    }

    #[test]
    fn redacted_view_shows_metadata() {
        let cred = Credential::new("github", sample_fields(), Some("my github".to_owned()));
        let view = cred.redacted_view();
        assert_eq!(view["connector_id"], "github");
        assert_eq!(view["auth_method"], "bearer_token");
        assert_eq!(view["label"], "my github");
    }

    // ── Encryption roundtrip ──────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello, credential store!";
        let encrypted = encrypt(plaintext, &key).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key = test_key();
        let plaintext = b"secret data";
        let encrypted = encrypt(plaintext, &key).unwrap();

        let mut wrong_key = [0u8; KEY_LEN];
        wrong_key[0] = 99;
        let result = decrypt(&encrypted, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let key = test_key();
        let result = decrypt(b"short", &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let key = test_key();
        let plaintext = b"same data";
        let a = encrypt(plaintext, &key).unwrap();
        let b = encrypt(plaintext, &key).unwrap();
        // Different random nonces should produce different ciphertexts.
        assert_ne!(a, b);
    }

    // ── CredentialStore CRUD ──────────────────────────────────────

    #[test]
    fn store_add_and_get() {
        let store = temp_store();
        let cred = Credential::new("github", sample_fields(), None);
        store.add(cred).unwrap();

        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.connector_id, "github");
        assert_eq!(loaded.get_field("token"), Some("ghp_abc123def456"));
    }

    #[test]
    fn store_get_missing() {
        let store = temp_store();
        assert!(store.get("nonexistent").unwrap().is_none());
    }

    #[test]
    fn store_remove() {
        let store = temp_store();
        let cred = Credential::new("github", sample_fields(), None);
        store.add(cred).unwrap();
        assert!(store.remove("github").unwrap());
        assert!(store.get("github").unwrap().is_none());
        // Second remove returns false.
        assert!(!store.remove("github").unwrap());
    }

    #[test]
    fn store_list_all() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        // All entries should be redacted.
        for entry in &list {
            let fields = entry["fields"].as_object().unwrap();
            for (_, v) in fields {
                assert!(v.as_str().unwrap().contains("***"));
            }
        }
    }

    #[test]
    fn store_list_ids() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();

        let ids = store.list_ids().unwrap();
        assert_eq!(ids, vec!["github", "slack"]);
    }

    #[test]
    fn store_update_fields() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        let mut new_fields = BTreeMap::new();
        new_fields.insert("token".to_owned(), "ghp_new_token_value".to_owned());
        assert!(store.update_fields("github", new_fields).unwrap());

        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.get_field("token"), Some("ghp_new_token_value"));
    }

    #[test]
    fn store_update_nonexistent_returns_false() {
        let store = temp_store();
        let fields = BTreeMap::new();
        assert!(!store.update_fields("nope", fields).unwrap());
    }

    #[test]
    fn store_touch() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        let before = store.get("github").unwrap().unwrap();
        assert!(before.last_used_at.is_none());

        assert!(store.touch("github").unwrap());

        let after = store.get("github").unwrap().unwrap();
        assert!(after.last_used_at.is_some());
    }

    #[test]
    fn store_touch_nonexistent_returns_false() {
        let store = temp_store();
        assert!(!store.touch("nope").unwrap());
    }

    #[test]
    fn store_count() {
        let store = temp_store();
        assert_eq!(store.count().unwrap(), 0);
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);
        store
            .add(Credential::new("slack", sample_basic_fields(), None))
            .unwrap();
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn store_exists_false_before_first_write() {
        let store = temp_store();
        assert!(!store.exists());
    }

    #[test]
    fn store_exists_true_after_write() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();
        assert!(store.exists());
    }

    #[test]
    fn store_overwrite_credential() {
        let store = temp_store();
        store
            .add(Credential::new("github", sample_fields(), None))
            .unwrap();

        let mut new_fields = BTreeMap::new();
        new_fields.insert("api_key".to_owned(), "key_xyz".to_owned());
        store
            .add(Credential::new(
                "github",
                new_fields,
                Some("new label".to_owned()),
            ))
            .unwrap();

        let loaded = store.get("github").unwrap().unwrap();
        assert_eq!(loaded.auth_method, AuthMethod::ApiKey);
        assert_eq!(loaded.label.as_deref(), Some("new label"));
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn store_serde_roundtrip() {
        let cred = Credential::new("github", sample_fields(), Some("test".to_owned()));
        let json = serde_json::to_string(&cred).unwrap();
        let restored: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.connector_id, "github");
        assert_eq!(restored.auth_method, AuthMethod::BearerToken);
        assert_eq!(restored.label.as_deref(), Some("test"));
    }

    // ── CLI parsing helpers ───────────────────────────────────────

    #[test]
    fn parse_credential_field_valid() {
        let (key, value) = parse_credential_field("token=ghp_abc123").unwrap();
        assert_eq!(key, "token");
        assert_eq!(value, "ghp_abc123");
    }

    #[test]
    fn parse_credential_field_with_equals_in_value() {
        let (key, value) = parse_credential_field("token=abc=def=ghi").unwrap();
        assert_eq!(key, "token");
        assert_eq!(value, "abc=def=ghi");
    }

    #[test]
    fn parse_credential_field_trims_whitespace() {
        let (key, value) = parse_credential_field("  token  =  ghp_abc  ").unwrap();
        assert_eq!(key, "token");
        assert_eq!(value, "ghp_abc");
    }

    #[test]
    fn parse_credential_field_empty_key() {
        assert!(parse_credential_field("=value").is_none());
    }

    #[test]
    fn parse_credential_field_empty_value() {
        assert!(parse_credential_field("key=").is_none());
    }

    #[test]
    fn parse_credential_field_no_equals() {
        assert!(parse_credential_field("no-equals-sign").is_none());
    }

    #[test]
    fn parse_credential_fields_multiple() {
        let inputs = vec![
            "username=admin".to_owned(),
            "password=secret".to_owned(),
        ];
        let fields = parse_credential_fields(&inputs).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields["username"], "admin");
        assert_eq!(fields["password"], "secret");
    }

    #[test]
    fn parse_credential_fields_empty_is_error() {
        let result = parse_credential_fields(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_credential_fields_invalid_entry() {
        let inputs = vec!["no-equals".to_owned()];
        let result = parse_credential_fields(&inputs);
        assert!(result.is_err());
    }

    // ── Connector ID validation ───────────────────────────────────

    #[test]
    fn validate_connector_id_valid() {
        assert!(validate_connector_id("github").is_ok());
        assert!(validate_connector_id("my-connector").is_ok());
        assert!(validate_connector_id("fcp.github.v2").is_ok());
        assert!(validate_connector_id("under_score").is_ok());
    }

    #[test]
    fn validate_connector_id_empty() {
        assert!(validate_connector_id("").is_err());
    }

    #[test]
    fn validate_connector_id_too_long() {
        let long = "a".repeat(65);
        assert!(validate_connector_id(&long).is_err());
    }

    #[test]
    fn validate_connector_id_invalid_chars() {
        assert!(validate_connector_id("has space").is_err());
        assert!(validate_connector_id("has/slash").is_err());
        assert!(validate_connector_id("has@at").is_err());
    }

    #[test]
    fn validate_connector_id_max_length_ok() {
        let max = "a".repeat(64);
        assert!(validate_connector_id(&max).is_ok());
    }
}
