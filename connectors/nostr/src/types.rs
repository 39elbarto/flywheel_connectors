//! Nostr connector types, configuration, and input-parsing helpers.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bech32::{Bech32, Hrp, primitives::decode::CheckedHrpstring};
use fcp_prelude::{FcpError, FcpResult};
use secp256k1::{SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

// ─── Operation / capability constants ────────────────────────────────────
pub const OP_PUBLISH_NOTE: &str = "nostr.notes.publish";
pub const OP_SEND_DM: &str = "nostr.dm.send";
pub const OP_PROFILE_PUBLISH: &str = "nostr.profile.publish";
pub const OP_PROFILE_STATE: &str = "nostr.profile.state";
pub const OP_PROFILE_IMPORT: &str = "nostr.profile.import";
pub const OP_QUERY_EVENTS: &str = "nostr.events.query";
pub const OP_LIST_RELAYS: &str = "nostr.relays.list";
pub const OP_HEALTH: &str = "nostr.health";
pub const OP_RELAYS_HEALTH: &str = "nostr.relays.health";

pub const EVENT_INBOUND_DM: &str = "nostr.dm.inbound";

pub const CAP_NOTES_WRITE: &str = "nostr.notes.write";
pub const CAP_DM_WRITE: &str = "nostr.dm.write";
pub const CAP_PROFILE_WRITE: &str = "nostr.profile.write";
pub const CAP_PROFILE_READ: &str = "nostr.profile.read";
pub const CAP_EVENTS_READ: &str = "nostr.events.read";
pub const CAP_RELAYS_READ: &str = "nostr.relays.read";
pub const CAP_HEALTH_READ: &str = "nostr.health.read";

pub const DEFAULT_TIMEOUT_MS: u64 = 15_000;
pub const DEFAULT_QUERY_LIMIT: u64 = 25;
pub const DEFAULT_ALLOW_LOCAL_RELAYS: bool = false;
pub const DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD: u32 = 5;
pub const DEFAULT_RELAY_CIRCUIT_RESET_MS: u64 = 30_000;
pub const DEFAULT_INBOUND_DM_STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;
pub const DEFAULT_INBOUND_DM_FUTURE_SKEW_SECS: i64 = 5 * 60;
pub const DEFAULT_INBOUND_DM_MAX_CONTENT_BYTES: usize = 8 * 1024;
pub const DEFAULT_INBOUND_DM_SEEN_EVENT_CAPACITY: usize = 4096;
pub const DEFAULT_INBOUND_DM_RATE_WINDOW_SECS: i64 = 60;
pub const DEFAULT_INBOUND_DM_GLOBAL_RATE_LIMIT: u32 = 256;
pub const DEFAULT_INBOUND_DM_PER_SENDER_RATE_LIMIT: u32 = 64;
pub const NIP01_KIND_PROFILE: u64 = 0;
pub const NIP01_KIND_TEXT: u64 = 1;
pub const MAX_PROFILE_SHORT_TEXT_CHARS: usize = 256;
pub const MAX_PROFILE_ABOUT_CHARS: usize = 2000;
pub const MAX_PROFILE_ADDRESS_CHARS: usize = 320;
pub const MAX_DM_PLAINTEXT_BYTES: usize = 4096;
pub const NIP19_NSEC_HRP: &str = "nsec";
pub const NIP19_NPUB_HRP: &str = "npub";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayUrlPolicy {
    pub allow_local_relays: bool,
}

impl RelayUrlPolicy {
    #[must_use]
    pub const fn production() -> Self {
        Self {
            allow_local_relays: false,
        }
    }

    #[must_use]
    pub const fn local_harness() -> Self {
        Self {
            allow_local_relays: true,
        }
    }
}

impl Default for RelayUrlPolicy {
    fn default() -> Self {
        Self::production()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InboundDmPolicyMode {
    Disabled,
    #[default]
    Open,
    Allowlist,
    PairingEquivalent,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NostrInboundDmConfig {
    #[serde(default)]
    pub policy_mode: InboundDmPolicyMode,
    #[serde(default)]
    pub allowed_senders: Vec<String>,
    #[serde(default = "default_inbound_dm_stale_after_secs")]
    pub stale_after_secs: i64,
    #[serde(default = "default_inbound_dm_future_skew_secs")]
    pub future_skew_secs: i64,
    #[serde(default = "default_inbound_dm_max_content_bytes")]
    pub max_content_bytes: usize,
    #[serde(default = "default_inbound_dm_seen_event_capacity")]
    pub seen_event_capacity: usize,
    #[serde(default = "default_inbound_dm_rate_window_secs")]
    pub rate_window_secs: i64,
    #[serde(default = "default_inbound_dm_global_rate_limit")]
    pub global_rate_limit: u32,
    #[serde(default = "default_inbound_dm_per_sender_rate_limit")]
    pub per_sender_rate_limit: u32,
}

impl Default for NostrInboundDmConfig {
    fn default() -> Self {
        Self {
            policy_mode: InboundDmPolicyMode::Open,
            allowed_senders: Vec::new(),
            stale_after_secs: DEFAULT_INBOUND_DM_STALE_AFTER_SECS,
            future_skew_secs: DEFAULT_INBOUND_DM_FUTURE_SKEW_SECS,
            max_content_bytes: DEFAULT_INBOUND_DM_MAX_CONTENT_BYTES,
            seen_event_capacity: DEFAULT_INBOUND_DM_SEEN_EVENT_CAPACITY,
            rate_window_secs: DEFAULT_INBOUND_DM_RATE_WINDOW_SECS,
            global_rate_limit: DEFAULT_INBOUND_DM_GLOBAL_RATE_LIMIT,
            per_sender_rate_limit: DEFAULT_INBOUND_DM_PER_SENDER_RATE_LIMIT,
        }
    }
}

impl NostrInboundDmConfig {
    /// Validate inbound DM policy, replay, and rate-limit settings.
    ///
    /// # Errors
    ///
    /// Returns an error when numeric bounds are unusable or sender keys cannot
    /// be normalized.
    pub fn validate(&self) -> FcpResult<()> {
        if self.stale_after_secs <= 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.stale_after_secs must be greater than zero".into(),
            });
        }
        if self.future_skew_secs < 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.future_skew_secs must not be negative".into(),
            });
        }
        if self.max_content_bytes == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.max_content_bytes must be greater than zero".into(),
            });
        }
        if self.seen_event_capacity == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.seen_event_capacity must be greater than zero".into(),
            });
        }
        if self.rate_window_secs <= 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.rate_window_secs must be greater than zero".into(),
            });
        }
        if self.global_rate_limit == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.global_rate_limit must be greater than zero".into(),
            });
        }
        if self.per_sender_rate_limit == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.per_sender_rate_limit must be greater than zero".into(),
            });
        }
        let normalized = self.normalized_allowed_senders()?;
        if matches!(
            self.policy_mode,
            InboundDmPolicyMode::Allowlist | InboundDmPolicyMode::PairingEquivalent
        ) && normalized.is_empty()
        {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "inbound_dm.allowed_senders must not be empty for allowlist or pairing_equivalent policy".into(),
            });
        }
        Ok(())
    }

    /// Normalize configured sender keys without exposing malformed raw input in errors.
    ///
    /// # Errors
    ///
    /// Returns an error if any sender key is malformed.
    pub fn normalized_allowed_senders(&self) -> FcpResult<BTreeSet<String>> {
        self.allowed_senders
            .iter()
            .map(|sender| {
                normalize_public_key_input(sender)
                    .map(|normalized| normalized.canonical_public_key_hex().to_string())
            })
            .collect()
    }
}

// ─── NIP-01 profile metadata ────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        default,
        alias = "displayName",
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrProfilePublishInput {
    profile: NostrProfile,
    last_published_at: Option<u64>,
}

impl NostrProfilePublishInput {
    #[must_use]
    pub const fn profile(&self) -> &NostrProfile {
        &self.profile
    }

    #[must_use]
    pub const fn last_published_at(&self) -> Option<u64> {
        self.last_published_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrProfileImportInput {
    pubkey_hex: String,
    local_profile: Option<NostrProfile>,
}

impl NostrProfileImportInput {
    #[must_use]
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    #[must_use]
    pub const fn local_profile(&self) -> Option<&NostrProfile> {
        self.local_profile.as_ref()
    }
}

impl NostrProfile {
    /// Validate this NIP-01 profile shape and its display/fetch safety posture.
    ///
    /// # Errors
    ///
    /// Returns an error when text fields exceed configured bounds, profile URLs
    /// are unsafe, or NIP-05/LUD-16 address-like fields are malformed.
    pub fn validate(&self) -> FcpResult<()> {
        validate_profile_text(
            "profile.name",
            self.name.as_deref(),
            MAX_PROFILE_SHORT_TEXT_CHARS,
        )?;
        validate_profile_text(
            "profile.display_name",
            self.display_name.as_deref(),
            MAX_PROFILE_SHORT_TEXT_CHARS,
        )?;
        validate_profile_text(
            "profile.about",
            self.about.as_deref(),
            MAX_PROFILE_ABOUT_CHARS,
        )?;
        validate_profile_url("profile.picture", self.picture.as_deref())?;
        validate_profile_url("profile.banner", self.banner.as_deref())?;
        validate_profile_url("profile.website", self.website.as_deref())?;
        validate_profile_address("profile.nip05", self.nip05.as_deref())?;
        validate_profile_address("profile.lud16", self.lud16.as_deref())?;
        Ok(())
    }
}

/// Parse `nostr.profile.publish` input.
///
/// # Errors
///
/// Returns an error if `profile` is missing/malformed or if the optional
/// host-provided `last_published_at` is not an unsigned timestamp.
pub fn parse_profile_publish_input(input: &Value) -> FcpResult<NostrProfilePublishInput> {
    let Some(profile_value) = input.get("profile") else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "profile is required".into(),
        });
    };
    let profile = profile_from_value(profile_value)?;
    let last_published_at = u64_field(input, "last_published_at")?;
    Ok(NostrProfilePublishInput {
        profile,
        last_published_at,
    })
}

/// Parse `nostr.profile.import` input, defaulting the public key to the
/// connector-bound identity when omitted.
///
/// # Errors
///
/// Returns an error if `pubkey` or `local_profile` is malformed.
pub fn parse_profile_import_input(
    input: &Value,
    default_public_key_hex: &str,
) -> FcpResult<NostrProfileImportInput> {
    let pubkey_hex = match input.get("pubkey") {
        Some(value) => {
            let Some(pubkey) = value.as_str() else {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: "pubkey must be a string".into(),
                });
            };
            normalize_public_key_input(pubkey)?
                .canonical_public_key_hex()
                .to_string()
        }
        None => default_public_key_hex.to_string(),
    };
    let local_profile = input
        .get("local_profile")
        .map(profile_from_value)
        .transpose()?;
    Ok(NostrProfileImportInput {
        pubkey_hex,
        local_profile,
    })
}

/// Parse a NIP-01 profile JSON object and reject unknown fields rather than
/// silently dropping operator typos.
///
/// # Errors
///
/// Returns an error if the JSON shape or any field is invalid.
pub fn profile_from_value(value: &Value) -> FcpResult<NostrProfile> {
    let Some(object) = value.as_object() else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "profile must be an object".into(),
        });
    };
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "name"
                | "display_name"
                | "displayName"
                | "about"
                | "picture"
                | "banner"
                | "website"
                | "nip05"
                | "lud16"
        ) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("unsupported profile field `{key}`"),
            });
        }
    }
    let profile: NostrProfile =
        serde_json::from_value(value.clone()).map_err(|error| FcpError::InvalidRequest {
            code: 1005,
            message: format!("invalid profile object: {error}"),
        })?;
    profile.validate()?;
    Ok(profile)
}

#[must_use]
pub fn profile_to_content_value(profile: &NostrProfile) -> Value {
    serde_json::to_value(profile).unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

/// Convert imported NIP-01 event content into a profile. Unsafe imported URLs
/// are dropped and reported so they cannot become fetch/display hazards.
///
/// # Errors
///
/// Returns an error if non-URL profile fields are malformed.
pub fn profile_from_imported_content(
    content: &Value,
) -> FcpResult<(NostrProfile, Vec<&'static str>)> {
    let Some(object) = content.as_object() else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "profile event content must be a JSON object".into(),
        });
    };
    let mut sanitized = serde_json::Map::new();
    let mut dropped_url_fields = Vec::new();
    for (key, value) in object {
        if !matches!(
            key.as_str(),
            "name"
                | "display_name"
                | "about"
                | "picture"
                | "banner"
                | "website"
                | "nip05"
                | "lud16"
        ) {
            continue;
        }
        if matches!(key.as_str(), "picture" | "banner" | "website")
            && value
                .as_str()
                .is_none_or(|url| validate_profile_url_field(key, url).is_err())
        {
            dropped_url_fields.push(match key.as_str() {
                "picture" => "picture",
                "banner" => "banner",
                "website" => "website",
                _ => unreachable!(),
            });
            continue;
        }
        sanitized.insert(key.clone(), value.clone());
    }
    let profile = profile_from_value(&Value::Object(sanitized))?;
    Ok((profile, dropped_url_fields))
}

#[must_use]
pub fn sanitize_profile_for_display(profile: &NostrProfile) -> NostrProfile {
    NostrProfile {
        name: profile.name.as_deref().map(escape_html),
        display_name: profile.display_name.as_deref().map(escape_html),
        about: profile.about.as_deref().map(escape_html),
        picture: profile.picture.clone(),
        banner: profile.banner.clone(),
        website: profile.website.clone(),
        nip05: profile.nip05.as_deref().map(escape_html),
        lud16: profile.lud16.as_deref().map(escape_html),
    }
}

#[must_use]
pub fn merge_profiles(
    local: Option<&NostrProfile>,
    imported: Option<&NostrProfile>,
) -> NostrProfile {
    let Some(imported) = imported else {
        return local.cloned().unwrap_or_default();
    };
    let Some(local) = local else {
        return imported.clone();
    };
    NostrProfile {
        name: local.name.clone().or_else(|| imported.name.clone()),
        display_name: local
            .display_name
            .clone()
            .or_else(|| imported.display_name.clone()),
        about: local.about.clone().or_else(|| imported.about.clone()),
        picture: local.picture.clone().or_else(|| imported.picture.clone()),
        banner: local.banner.clone().or_else(|| imported.banner.clone()),
        website: local.website.clone().or_else(|| imported.website.clone()),
        nip05: local.nip05.clone().or_else(|| imported.nip05.clone()),
        lud16: local.lud16.clone().or_else(|| imported.lud16.clone()),
    }
}

fn validate_profile_text(field: &str, value: Option<&str>, max_chars: usize) -> FcpResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let char_count = value.chars().count();
    if char_count > max_chars {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must not exceed {max_chars} characters; got {char_count}"),
        });
    }
    Ok(())
}

fn validate_profile_url(field: &str, value: Option<&str>) -> FcpResult<()> {
    value.map_or(Ok(()), |value| validate_profile_url_field(field, value))
}

fn validate_profile_url_field(field: &str, value: &str) -> FcpResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must not be empty when provided"),
        });
    }
    let url = Url::parse(trimmed).map_err(|_| FcpError::InvalidRequest {
        code: 1005,
        message: format!("{field} must be a valid https:// URL"),
    })?;
    if url.scheme() != "https" {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must use https://"),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must not contain credentials"),
        });
    }
    let Some(host) = url.host_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must include a host"),
        });
    };
    if is_local_or_private_profile_host(host) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must not target private/internal hosts"),
        });
    }
    Ok(())
}

fn validate_profile_address(field: &str, value: Option<&str>) -> FcpResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.chars().count() > MAX_PROFILE_ADDRESS_CHARS
        || trimmed.matches('@').count() != 1
        || trimmed.starts_with('@')
        || trimmed.ends_with('@')
    {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "{field} must be an address-like value of the form local@domain without whitespace"
            ),
        });
    }
    Ok(())
}

#[must_use]
pub fn is_local_or_private_profile_host(host: &str) -> bool {
    let normalized = host
        .trim_matches(|c| matches!(c, '[' | ']'))
        .trim_end_matches('.')
        .to_ascii_lowercase();
    is_local_or_private_relay_host(&normalized)
        || has_hostname_suffix(&normalized, "internal")
        || has_hostname_suffix(&normalized, "local")
}

fn has_hostname_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#039;")
}

// ─── NIP-19 key/address normalization ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NostrSecretKeyFormat {
    Hex,
    Nsec,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NostrSecretKeyInput {
    canonical_secret_hex: String,
    format: NostrSecretKeyFormat,
}

impl NostrSecretKeyInput {
    #[must_use]
    pub fn canonical_secret_hex(&self) -> &str {
        &self.canonical_secret_hex
    }

    #[must_use]
    pub const fn format(&self) -> NostrSecretKeyFormat {
        self.format
    }
}

impl std::fmt::Debug for NostrSecretKeyInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrSecretKeyInput")
            .field("canonical_secret_hex", &"[REDACTED]")
            .field("format", &self.format)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NostrPublicKeyFormat {
    Hex,
    Npub,
    NostrNpub,
}

impl NostrPublicKeyFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hex => "raw_hex_pubkey",
            Self::Npub => "nip19_npub",
            Self::NostrNpub => "nostr_npub",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrPublicKeyInput {
    canonical_public_key_hex: String,
    format: NostrPublicKeyFormat,
}

impl NostrPublicKeyInput {
    #[must_use]
    pub fn canonical_public_key_hex(&self) -> &str {
        &self.canonical_public_key_hex
    }

    #[must_use]
    pub const fn format(&self) -> NostrPublicKeyFormat {
        self.format
    }
}

/// Normalize an operator-supplied secret key to canonical lowercase hex.
///
/// Accepts raw 64-character hex and NIP-19 `nsec` Bech32. Error messages never
/// include the supplied secret material.
///
/// # Errors
///
/// Returns an error if the value is empty, malformed, uses the wrong NIP-19
/// prefix, or is not a valid secp256k1 secret scalar.
pub fn normalize_secret_key_input(raw: &str) -> FcpResult<NostrSecretKeyInput> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(secret_key_input_error("secret key input must not be empty"));
    }

    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = decode_hex_32(trimmed, "secret key")?;
        validate_secret_key_bytes(&bytes)?;
        return Ok(NostrSecretKeyInput {
            canonical_secret_hex: trimmed.to_ascii_lowercase(),
            format: NostrSecretKeyFormat::Hex,
        });
    }

    if looks_like_bech32(trimmed) {
        let bytes = decode_nip19_payload(trimmed, NIP19_NSEC_HRP, "secret key")?;
        validate_secret_key_bytes(&bytes)?;
        return Ok(NostrSecretKeyInput {
            canonical_secret_hex: hex::encode(bytes),
            format: NostrSecretKeyFormat::Nsec,
        });
    }

    Err(secret_key_input_error(
        "secret key input must be a raw 64-character hex secret or NIP-19 nsec value",
    ))
}

/// Encode a canonical secret-key value as NIP-19 `nsec` Bech32.
///
/// # Errors
///
/// Returns an error if the input cannot be normalized or encoded.
pub fn encode_secret_key_nsec(raw: &str) -> FcpResult<String> {
    let normalized = normalize_secret_key_input(raw)?;
    let bytes = decode_hex_32(normalized.canonical_secret_hex(), "secret key")?;
    encode_nip19_payload(NIP19_NSEC_HRP, &bytes, "secret key")
}

/// Normalize a Nostr public key to canonical lowercase x-only hex.
///
/// Accepts raw 64-character hex, NIP-19 `npub`, and `nostr:npub` URI-style
/// forms. NIP-01 events and filters still receive canonical hex internally.
///
/// # Errors
///
/// Returns an error if the value is empty, malformed, uses the wrong NIP-19
/// prefix, or is not a valid secp256k1 x-only public key.
pub fn normalize_public_key_input(raw: &str) -> FcpResult<NostrPublicKeyInput> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(public_key_input_error("public key input must not be empty"));
    }

    let (candidate, format) = strip_nostr_prefix(trimmed);
    if candidate.len() == 64 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = decode_hex_32(candidate, "public key")?;
        validate_public_key_bytes(&bytes)?;
        return Ok(NostrPublicKeyInput {
            canonical_public_key_hex: candidate.to_ascii_lowercase(),
            format: NostrPublicKeyFormat::Hex,
        });
    }

    if looks_like_bech32(candidate) {
        let bytes = decode_nip19_payload(candidate, NIP19_NPUB_HRP, "public key")?;
        validate_public_key_bytes(&bytes)?;
        return Ok(NostrPublicKeyInput {
            canonical_public_key_hex: hex::encode(bytes),
            format,
        });
    }

    Err(public_key_input_error(
        "public key input must be a raw 64-character hex key, NIP-19 npub, or nostr:npub value",
    ))
}

/// Encode a canonical public key as NIP-19 `npub` Bech32.
///
/// # Errors
///
/// Returns an error if the input cannot be normalized or encoded.
pub fn encode_public_key_npub(raw: &str) -> FcpResult<String> {
    let normalized = normalize_public_key_input(raw)?;
    let bytes = decode_hex_32(normalized.canonical_public_key_hex(), "public key")?;
    encode_nip19_payload(NIP19_NPUB_HRP, &bytes, "public key")
}

fn strip_nostr_prefix(raw: &str) -> (&str, NostrPublicKeyFormat) {
    if raw
        .get(.."nostr:".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("nostr:"))
    {
        let candidate = raw.get("nostr:".len()..).unwrap_or_default();
        (candidate, NostrPublicKeyFormat::NostrNpub)
    } else {
        (raw, NostrPublicKeyFormat::Npub)
    }
}

fn looks_like_bech32(raw: &str) -> bool {
    raw.contains('1')
}

fn decode_nip19_payload(raw: &str, expected_hrp: &str, label: &str) -> FcpResult<[u8; 32]> {
    let decoded =
        CheckedHrpstring::new::<Bech32>(raw).map_err(|_| nip19_input_error(label, expected_hrp))?;
    let actual_hrp = decoded.hrp().to_lowercase();
    if actual_hrp != expected_hrp {
        return Err(FcpError::InvalidRequest {
            code: if label == "secret key" { 1001 } else { 1005 },
            message: format!(
                "Nostr {label} Bech32 prefix must be `{expected_hrp}`, got `{actual_hrp}`"
            ),
        });
    }
    let bytes = decoded.byte_iter().collect::<Vec<u8>>();
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| FcpError::InvalidRequest {
            code: if label == "secret key" { 1001 } else { 1005 },
            message: format!(
                "Nostr {label} Bech32 payload must decode to exactly 32 bytes, got {}",
                bytes.len()
            ),
        })
}

fn encode_nip19_payload(expected_hrp: &str, bytes: &[u8], label: &str) -> FcpResult<String> {
    let hrp = Hrp::parse(expected_hrp).map_err(|error| FcpError::Internal {
        message: format!("invalid built-in Nostr {label} HRP `{expected_hrp}`: {error}"),
    })?;
    bech32::encode::<Bech32>(hrp, bytes).map_err(|error| FcpError::Internal {
        message: format!("failed to encode Nostr {label} as Bech32: {error}"),
    })
}

fn decode_hex_32(raw: &str, label: &str) -> FcpResult<[u8; 32]> {
    let bytes = hex::decode(raw).map_err(|_| {
        if label == "secret key" {
            secret_key_input_error("secret key input must be valid hex or NIP-19 nsec")
        } else {
            public_key_input_error("public key input must be valid hex, NIP-19 npub, or nostr:npub")
        }
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        if label == "secret key" {
            secret_key_input_error(&format!(
                "secret key input must decode to exactly 32 bytes, got {}",
                bytes.len()
            ))
        } else {
            public_key_input_error(&format!(
                "public key input must decode to exactly 32 bytes, got {}",
                bytes.len()
            ))
        }
    })
}

fn validate_secret_key_bytes(bytes: &[u8; 32]) -> FcpResult<()> {
    SecretKey::from_slice(bytes).map(|_| ()).map_err(|_| {
        secret_key_input_error("secret key input is not a valid secp256k1 secret scalar")
    })
}

fn validate_public_key_bytes(bytes: &[u8; 32]) -> FcpResult<()> {
    XOnlyPublicKey::from_slice(bytes).map(|_| ()).map_err(|_| {
        public_key_input_error("public key input is not a valid secp256k1 x-only public key")
    })
}

fn secret_key_input_error(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1001,
        message: format!("Nostr {message}"),
    }
}

fn public_key_input_error(message: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: 1005,
        message: format!("Nostr {message}"),
    }
}

fn nip19_input_error(label: &str, expected_hrp: &str) -> FcpError {
    FcpError::InvalidRequest {
        code: if label == "secret key" { 1001 } else { 1005 },
        message: format!("Nostr {label} must be valid NIP-19 {expected_hrp} Bech32"),
    }
}

// ─── NIP-04 / NIP-44 DM event constants and types ───────────────────────

/// NIP-04 encrypted direct message event kind.
pub const NIP04_KIND_ENCRYPTED_DM: u64 = 4;

/// NIP-44 gift-wrapped event kind (used for newer encrypted DMs).
pub const NIP44_KIND_GIFT_WRAP: u64 = 1059;

/// NIP-44 sealed event kind (inner layer of gift wrap).
pub const NIP44_KIND_SEAL: u64 = 13;

/// Represents an encrypted DM event following the NIP-04 format.
///
/// The `content` field holds the NIP-04 encrypted payload (base64 ciphertext +
/// `?iv=` + base64 IV). Outbound operation parsing accepts plaintext, but this
/// envelope type only carries the encrypted relay event content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedDmEvent {
    /// The hex-encoded x-only public key of the DM recipient.
    pub recipient_pubkey: String,
    /// The encrypted content in NIP-04 format (base64 ciphertext + "?iv=" + base64 IV).
    pub content: String,
    /// The event kind (must be 4 for NIP-04 DMs).
    pub kind: u64,
}

impl EncryptedDmEvent {
    /// Create a new NIP-04 encrypted DM event envelope.
    #[must_use]
    pub const fn new(recipient_pubkey: String, content: String) -> Self {
        Self {
            recipient_pubkey,
            content,
            kind: NIP04_KIND_ENCRYPTED_DM,
        }
    }

    /// Create a new NIP-04 encrypted DM envelope after normalizing the recipient key.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipient key is not raw hex, `npub`, or
    /// `nostr:npub`.
    pub fn try_new(recipient_pubkey: &str, content: String) -> FcpResult<Self> {
        let normalized = normalize_public_key_input(recipient_pubkey)?;
        Ok(Self::new(
            normalized.canonical_public_key_hex().to_string(),
            content,
        ))
    }

    /// Validate the DM event fields.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipient pubkey is malformed or content is empty.
    pub fn validate(&self) -> FcpResult<()> {
        if self.recipient_pubkey.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipient_pubkey must not be empty".into(),
            });
        }
        if self.recipient_pubkey.len() != 64
            || !self.recipient_pubkey.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipient_pubkey must be a 64-character hex-encoded x-only public key"
                    .into(),
            });
        }
        if self.content.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "encrypted DM content must not be empty".into(),
            });
        }
        if self.kind != NIP04_KIND_ENCRYPTED_DM {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!(
                    "EncryptedDmEvent kind must be {} (NIP-04), got {}",
                    NIP04_KIND_ENCRYPTED_DM, self.kind
                ),
            });
        }
        Ok(())
    }

    /// Build the Nostr tags array for this DM event: `[["p", recipient_pubkey]]`.
    #[must_use]
    pub fn tags(&self) -> Value {
        serde_json::json!([["p", self.recipient_pubkey]])
    }
}

/// Parsed and normalized input for `nostr.dm.send`.
#[derive(Clone, PartialEq, Eq)]
pub struct NostrDmSendInput {
    recipient_pubkey: String,
    recipient_format: NostrPublicKeyFormat,
    plaintext: String,
    reply_to_event_id: Option<String>,
    allow_self_send: bool,
}

impl NostrDmSendInput {
    #[must_use]
    pub fn recipient_pubkey(&self) -> &str {
        &self.recipient_pubkey
    }

    #[must_use]
    pub const fn recipient_format(&self) -> NostrPublicKeyFormat {
        self.recipient_format
    }

    #[must_use]
    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }

    #[must_use]
    pub fn reply_to_event_id(&self) -> Option<&str> {
        self.reply_to_event_id.as_deref()
    }

    #[must_use]
    pub const fn allow_self_send(&self) -> bool {
        self.allow_self_send
    }
}

impl std::fmt::Debug for NostrDmSendInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrDmSendInput")
            .field("recipient_pubkey", &self.recipient_pubkey)
            .field("recipient_format", &self.recipient_format)
            .field("plaintext", &"[REDACTED]")
            .field("reply_to_event_id", &self.reply_to_event_id)
            .field("allow_self_send", &self.allow_self_send)
            .finish()
    }
}

/// Parse `nostr.dm.send` input without retaining ambiguous aliases or leaking plaintext.
///
/// Accepted recipient fields are `recipient`, `recipient_pubkey`, and `target`.
/// Accepted plaintext fields are `plaintext` and `content`. If callers provide
/// more than one alias for the same value, the values must match after trimming.
///
/// # Errors
///
/// Returns an error for missing or malformed recipient/plaintext fields,
/// oversized plaintext, invalid reply event ids, or self-send without explicit
/// opt-in.
pub fn parse_dm_send_input(
    input: &Value,
    sender_public_key_hex: &str,
) -> FcpResult<NostrDmSendInput> {
    let recipient_raw = required_alias_string(input, &["recipient", "recipient_pubkey", "target"])?;
    let recipient = normalize_public_key_input(recipient_raw)?;
    let plaintext = required_alias_string(input, &["plaintext", "content"])?;
    validate_dm_plaintext(plaintext)?;
    let reply_to_event_id = optional_event_id_alias(input, &["reply_to_event_id", "reply_to"])?;
    let allow_self_send = bool_field(input, "allow_self_send")?.unwrap_or(false);
    if recipient.canonical_public_key_hex() == sender_public_key_hex && !allow_self_send {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "Nostr DM recipient must not equal the connector signing identity unless allow_self_send is true".into(),
        });
    }
    Ok(NostrDmSendInput {
        recipient_pubkey: recipient.canonical_public_key_hex().to_string(),
        recipient_format: recipient.format(),
        plaintext: plaintext.to_string(),
        reply_to_event_id,
        allow_self_send,
    })
}

/// Build the relay tags for a NIP-04 DM event.
///
/// # Errors
///
/// Returns an error if `reply_to_event_id` is malformed.
pub fn dm_tags(recipient_pubkey: &str, reply_to_event_id: Option<&str>) -> FcpResult<Value> {
    let mut tags = vec![serde_json::json!(["p", recipient_pubkey])];
    if let Some(reply_to_event_id) = reply_to_event_id {
        validate_event_id_hex(reply_to_event_id, "reply_to_event_id")?;
        tags.push(serde_json::json!(["e", reply_to_event_id]));
    }
    Ok(Value::Array(tags))
}

fn validate_dm_plaintext(plaintext: &str) -> FcpResult<()> {
    if plaintext.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "Nostr DM plaintext must be a non-empty string".into(),
        });
    }
    let byte_len = plaintext.len();
    if byte_len > MAX_DM_PLAINTEXT_BYTES {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "Nostr DM plaintext exceeds {MAX_DM_PLAINTEXT_BYTES} byte limit; got {byte_len} bytes"
            ),
        });
    }
    Ok(())
}

fn required_alias_string<'a>(input: &'a Value, fields: &[&str]) -> FcpResult<&'a str> {
    let mut found: Vec<(&str, &str)> = Vec::new();
    for field in fields {
        if let Some(value) = input.get(*field) {
            let Some(text) = value.as_str() else {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("{field} must be a non-empty string"),
                });
            };
            if text.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("{field} must be a non-empty string"),
                });
            }
            found.push((*field, text.trim()));
        }
    }
    let Some((first_field, first_value)) = found.first().copied() else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("one of {} is required", fields.join(", ")),
        });
    };
    if found.iter().any(|(_, value)| *value != first_value) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "ambiguous {first_field} aliases must agree when more than one is provided"
            ),
        });
    }
    Ok(first_value)
}

fn bool_field(input: &Value, field: &str) -> FcpResult<Option<bool>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a boolean"),
        })
}

fn optional_event_id_alias(input: &Value, fields: &[&str]) -> FcpResult<Option<String>> {
    let mut found: Vec<(&str, &str)> = Vec::new();
    for field in fields {
        if let Some(value) = input.get(*field) {
            let Some(text) = value.as_str() else {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("{field} must be a 64-character hex event id"),
                });
            };
            if text.trim().is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("{field} must be a 64-character hex event id"),
                });
            }
            found.push((*field, text.trim()));
        }
    }
    let Some((first_field, first_value)) = found.first().copied() else {
        return Ok(None);
    };
    if found.iter().any(|(_, value)| *value != first_value) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!(
                "ambiguous {first_field} aliases must agree when more than one is provided"
            ),
        });
    }
    let normalized = first_value.to_ascii_lowercase();
    validate_event_id_hex(&normalized, first_field)?;
    Ok(Some(normalized))
}

fn validate_event_id_hex(value: &str, field: &str) -> FcpResult<()> {
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a 64-character hex event id"),
        });
    }
    Ok(())
}

// ─── Configuration ───────────────────────────────────────────────────────

#[derive(Clone, Deserialize)]
pub struct NostrConfig {
    pub relay_urls: Vec<String>,
    pub secret_key_hex: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_query_limit")]
    pub default_query_limit: u64,
    #[serde(default = "default_allow_local_relays")]
    pub allow_local_relays: bool,
    #[serde(default = "default_relay_circuit_failure_threshold")]
    pub relay_circuit_failure_threshold: u32,
    #[serde(default = "default_relay_circuit_reset_ms")]
    pub relay_circuit_reset_ms: u64,
    #[serde(default)]
    pub inbound_dm: NostrInboundDmConfig,
}

impl std::fmt::Debug for NostrConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrConfig")
            .field("relay_urls", &self.relay_urls)
            .field("secret_key_hex", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("default_query_limit", &self.default_query_limit)
            .field("allow_local_relays", &self.allow_local_relays)
            .field(
                "relay_circuit_failure_threshold",
                &self.relay_circuit_failure_threshold,
            )
            .field("relay_circuit_reset_ms", &self.relay_circuit_reset_ms)
            .field("inbound_dm", &self.inbound_dm)
            .finish()
    }
}

#[must_use]
pub const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[must_use]
pub const fn default_query_limit() -> u64 {
    DEFAULT_QUERY_LIMIT
}

#[must_use]
pub const fn default_allow_local_relays() -> bool {
    DEFAULT_ALLOW_LOCAL_RELAYS
}

#[must_use]
pub const fn default_relay_circuit_failure_threshold() -> u32 {
    DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD
}

#[must_use]
pub const fn default_relay_circuit_reset_ms() -> u64 {
    DEFAULT_RELAY_CIRCUIT_RESET_MS
}

#[must_use]
pub const fn default_inbound_dm_stale_after_secs() -> i64 {
    DEFAULT_INBOUND_DM_STALE_AFTER_SECS
}

#[must_use]
pub const fn default_inbound_dm_future_skew_secs() -> i64 {
    DEFAULT_INBOUND_DM_FUTURE_SKEW_SECS
}

#[must_use]
pub const fn default_inbound_dm_max_content_bytes() -> usize {
    DEFAULT_INBOUND_DM_MAX_CONTENT_BYTES
}

#[must_use]
pub const fn default_inbound_dm_seen_event_capacity() -> usize {
    DEFAULT_INBOUND_DM_SEEN_EVENT_CAPACITY
}

#[must_use]
pub const fn default_inbound_dm_rate_window_secs() -> i64 {
    DEFAULT_INBOUND_DM_RATE_WINDOW_SECS
}

#[must_use]
pub const fn default_inbound_dm_global_rate_limit() -> u32 {
    DEFAULT_INBOUND_DM_GLOBAL_RATE_LIMIT
}

#[must_use]
pub const fn default_inbound_dm_per_sender_rate_limit() -> u32 {
    DEFAULT_INBOUND_DM_PER_SENDER_RATE_LIMIT
}

impl NostrConfig {
    /// Validate configuration without consuming it.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing, numeric limits are
    /// zero, or any relay URL is invalid.
    pub fn validate(&self) -> FcpResult<()> {
        if self.relay_urls.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "relay_urls must not be empty".into(),
            });
        }
        if self.secret_key_hex.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "secret_key_hex must not be empty".into(),
            });
        }
        let _ = normalize_secret_key_input(&self.secret_key_hex)?;
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        if self.default_query_limit == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "default_query_limit must be greater than zero".into(),
            });
        }
        if self.default_query_limit > 1000 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "default_query_limit must not exceed 1000".into(),
            });
        }
        if self.relay_circuit_failure_threshold == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "relay_circuit_failure_threshold must be greater than zero".into(),
            });
        }
        self.inbound_dm.validate()?;
        let _ = canonicalize_relay_urls(&self.relay_urls, self.relay_policy())?;
        Ok(())
    }

    #[must_use]
    pub const fn relay_policy(&self) -> RelayUrlPolicy {
        RelayUrlPolicy {
            allow_local_relays: self.allow_local_relays,
        }
    }
}

/// Validate that a relay URL uses `ws://` or `wss://`.
///
/// # Errors
///
/// Returns an error if `raw` is empty, malformed, or uses a non-WebSocket
/// scheme.
pub fn validate_relay_url(raw: &str) -> FcpResult<Url> {
    validate_relay_url_with_policy(raw, RelayUrlPolicy::production())
}

/// Validate a relay URL under an explicit relay policy.
///
/// # Errors
///
/// Returns an error if `raw` is empty, malformed, uses a non-WebSocket scheme,
/// carries credentials or fragments, or targets a local/private host without an
/// explicit local-harness allowance.
pub fn validate_relay_url_with_policy(raw: &str, policy: RelayUrlPolicy) -> FcpResult<Url> {
    canonicalize_relay_url(raw, policy)
}

/// Canonicalize and deduplicate a relay list under an explicit relay policy.
///
/// # Errors
///
/// Returns the first validation error encountered.
pub fn canonicalize_relay_urls(
    raw_relays: &[String],
    policy: RelayUrlPolicy,
) -> FcpResult<Vec<Url>> {
    let mut seen = BTreeSet::new();
    let mut relays = Vec::with_capacity(raw_relays.len());
    for raw in raw_relays {
        let relay = canonicalize_relay_url(raw, policy)?;
        if seen.insert(relay.as_str().to_string()) {
            relays.push(relay);
        }
    }
    Ok(relays)
}

/// Canonicalize a single relay URL under an explicit relay policy.
///
/// # Errors
///
/// Returns an error if the relay does not satisfy FCP Nostr relay policy.
pub fn canonicalize_relay_url(raw: &str, policy: RelayUrlPolicy) -> FcpResult<Url> {
    let relay = raw.trim();
    if relay.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "relay URLs must not be empty strings".into(),
        });
    }
    let relay_for_error = redact_relay_url_for_error(relay);
    let url = url::Url::parse(relay).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("invalid relay URL `{relay_for_error}`: {error}"),
    })?;
    if !matches!(url.scheme(), "ws" | "wss") {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("relay URL `{relay_for_error}` must use ws:// or wss://"),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("relay URL `{relay_for_error}` must not contain credentials"),
        });
    }
    let Some(host) = url.host_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("relay URL `{relay_for_error}` must include a host"),
        });
    };
    if url.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("relay URL `{relay_for_error}` must not include a fragment"),
        });
    }
    let local_or_private = is_local_or_private_relay_host(host);
    if local_or_private && !policy.allow_local_relays {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "relay URL `{relay_for_error}` targets a local/private host; set allow_local_relays=true for local harnesses"
            ),
        });
    }
    if url.scheme() == "ws" && !local_or_private {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!(
                "relay URL `{relay_for_error}` must use wss:// outside local harnesses"
            ),
        });
    }
    Ok(url)
}

fn redact_relay_url_for_error(relay: &str) -> String {
    let Some(scheme_end) = relay.find("://") else {
        return relay.to_string();
    };
    let authority_and_path = &relay[scheme_end + 3..];
    let Some(userinfo_end) = authority_and_path.find('@') else {
        return relay.to_string();
    };
    format!(
        "{}://[redacted]@{}",
        &relay[..scheme_end],
        &authority_and_path[userinfo_end + 1..]
    )
}

#[must_use]
pub fn is_local_or_private_relay_host(host: &str) -> bool {
    let normalized = host
        .trim_matches(|c| matches!(c, '[' | ']'))
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized == "localhost" || normalized.ends_with(".localhost") {
        return true;
    }
    normalized
        .parse::<IpAddr>()
        .is_ok_and(is_local_or_private_ip)
}

#[must_use]
pub const fn is_local_or_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_local_or_private_ipv4(addr),
        IpAddr::V6(addr) => is_local_or_private_ipv6(addr),
    }
}

#[must_use]
pub const fn is_local_or_private_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.octets()[0] == 0
}

#[must_use]
pub const fn is_local_or_private_ipv6(addr: Ipv6Addr) -> bool {
    let first = addr.segments()[0];
    addr.is_loopback()
        || addr.is_unspecified()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

// ─── Input parsing helpers ───────────────────────────────────────────────

/// Read a required non-empty string field from an input object.
///
/// # Errors
///
/// Returns an error if the field is missing, not a string, or blank.
pub fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    let Some(raw) = value.get(field) else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        });
    };
    let Some(text) = raw.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-empty string"),
        });
    };
    if text.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-empty string"),
        });
    }
    Ok(text)
}

/// Read an optional array field whose entries must all be strings.
///
/// # Errors
///
/// Returns an error if the field exists but is not an array of strings.
pub fn string_array_field(input: &Value, field: &str) -> FcpResult<Option<Vec<Value>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an array of strings"),
        });
    };
    if items.iter().any(|item| !item.is_string()) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must contain only strings"),
        });
    }
    Ok(Some(items.clone()))
}

/// Read an optional array field whose entries must all be unsigned integers.
///
/// # Errors
///
/// Returns an error if the field exists but is not an array of unsigned
/// integers.
pub fn u64_array_field(input: &Value, field: &str) -> FcpResult<Option<Vec<Value>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an array of integers"),
        });
    };
    if items.iter().any(|item| item.as_u64().is_none()) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must contain only integers"),
        });
    }
    Ok(Some(items.clone()))
}

/// Read an optional signed integer field from an input object.
///
/// # Errors
///
/// Returns an error if the field exists but is not an integer.
pub fn i64_field(input: &Value, field: &str) -> FcpResult<Option<i64>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an integer"),
        })
}

/// Read an optional unsigned integer field from an input object.
///
/// # Errors
///
/// Returns an error if the field exists but is not an unsigned integer.
pub fn u64_field(input: &Value, field: &str) -> FcpResult<Option<u64>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an unsigned integer"),
        })
}

/// Parse `kind` from input, defaulting to `NIP01_KIND_TEXT`. Rejects non-1 kinds.
///
/// # Errors
///
/// Returns an error if `kind` is present but invalid, or if it requests an
/// unsupported note kind for this first slice.
pub fn note_kind(input: &Value) -> FcpResult<u64> {
    let kind = u64_field(input, "kind")?.unwrap_or(NIP01_KIND_TEXT);
    if kind != NIP01_KIND_TEXT {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "nostr.notes.publish only supports kind=1 public notes in this first slice"
                .into(),
        });
    }
    Ok(kind)
}

/// Parse `tags` from input, each tag must be an array of strings.
///
/// # Errors
///
/// Returns an error if `tags` is present but is not an array of string arrays.
pub fn note_tags(input: &Value) -> FcpResult<Value> {
    let Some(tags) = input.get("tags") else {
        return Ok(Value::Array(Vec::new()));
    };
    let Value::Array(tag_rows) = tags else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "tags must be an array of string arrays".into(),
        });
    };
    for tag in tag_rows {
        let Value::Array(parts) = tag else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "each tag must be an array of strings".into(),
            });
        };
        if parts.iter().any(|part| !part.is_string()) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "each tag entry must be a string".into(),
            });
        }
    }
    Ok(Value::Array(tag_rows.clone()))
}

/// Build a NIP-01 filter object from input, applying `default_limit`.
///
/// # Errors
///
/// Returns an error if any filter field has the wrong type or if the computed
/// limit is zero.
pub fn build_filter(input: &Value, default_limit: u64) -> FcpResult<Value> {
    const MAX_QUERY_LIMIT: u64 = 1000;
    let mut filter = serde_json::Map::new();
    if let Some(authors) = string_array_field(input, "authors")? {
        let normalized_authors = authors
            .iter()
            .map(|author| {
                let Some(raw_author) = author.as_str() else {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "authors must contain only strings".into(),
                    });
                };
                normalize_public_key_input(raw_author).map(|normalized| {
                    Value::String(normalized.canonical_public_key_hex().to_string())
                })
            })
            .collect::<FcpResult<Vec<_>>>()?;
        filter.insert("authors".into(), Value::Array(normalized_authors));
    }
    if let Some(ids) = string_array_field(input, "ids")? {
        filter.insert("ids".into(), Value::Array(ids));
    }
    if let Some(kinds) = u64_array_field(input, "kinds")? {
        filter.insert("kinds".into(), Value::Array(kinds));
    }
    if let Some(since) = i64_field(input, "since")? {
        filter.insert("since".into(), serde_json::json!(since));
    }
    if let Some(until) = i64_field(input, "until")? {
        filter.insert("until".into(), serde_json::json!(until));
    }
    let limit = u64_field(input, "limit")?
        .unwrap_or(default_limit)
        .min(MAX_QUERY_LIMIT);
    if limit == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "limit must be greater than zero".into(),
        });
    }
    filter.insert("limit".into(), serde_json::json!(limit));
    Ok(Value::Object(filter))
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_SECRET_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const NIP19_EXAMPLE_SECRET_HEX: &str =
        "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
    const NIP19_EXAMPLE_NSEC: &str =
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const NIP19_EXAMPLE_PUBLIC_HEX: &str =
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const NIP19_EXAMPLE_NPUB: &str =
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    #[test]
    fn config_deserializes_with_defaults() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "aaaa"
        }))
        .unwrap();
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.default_query_limit, DEFAULT_QUERY_LIMIT);
        assert!(!config.allow_local_relays);
        assert_eq!(
            config.relay_circuit_failure_threshold,
            DEFAULT_RELAY_CIRCUIT_FAILURE_THRESHOLD
        );
        assert_eq!(
            config.relay_circuit_reset_ms,
            DEFAULT_RELAY_CIRCUIT_RESET_MS
        );
        assert_eq!(config.inbound_dm.policy_mode, InboundDmPolicyMode::Open);
        assert_eq!(
            config.inbound_dm.seen_event_capacity,
            DEFAULT_INBOUND_DM_SEEN_EVENT_CAPACITY
        );
        assert_eq!(
            config.inbound_dm.global_rate_limit,
            DEFAULT_INBOUND_DM_GLOBAL_RATE_LIMIT
        );
        assert_eq!(
            config.inbound_dm.per_sender_rate_limit,
            DEFAULT_INBOUND_DM_PER_SENDER_RATE_LIMIT
        );
    }

    #[test]
    fn config_debug_redacts_secret_key() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "super_secret_deadbeef"
        }))
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_deadbeef"));
    }

    #[test]
    fn normalize_secret_key_accepts_valid_hex() {
        let normalized = normalize_secret_key_input(TEST_SECRET_KEY_HEX).unwrap();
        assert_eq!(normalized.canonical_secret_hex(), TEST_SECRET_KEY_HEX);
        assert_eq!(normalized.format(), NostrSecretKeyFormat::Hex);
    }

    #[test]
    fn normalize_secret_key_accepts_valid_nsec() {
        let normalized = normalize_secret_key_input(NIP19_EXAMPLE_NSEC).unwrap();
        assert_eq!(normalized.canonical_secret_hex(), NIP19_EXAMPLE_SECRET_HEX);
        assert_eq!(normalized.format(), NostrSecretKeyFormat::Nsec);
    }

    #[test]
    fn normalize_secret_key_rejects_invalid_bech32_type() {
        let err = normalize_secret_key_input(NIP19_EXAMPLE_NPUB).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("prefix must be `nsec`"));
        assert!(!message.contains(NIP19_EXAMPLE_NPUB));
        assert!(!message.contains(NIP19_EXAMPLE_PUBLIC_HEX));
    }

    #[test]
    fn normalize_secret_key_rejects_malformed_hex_without_leaking_input() {
        let raw = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let err = normalize_secret_key_input(raw).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("raw 64-character hex secret or NIP-19 nsec"));
        assert!(!message.contains(raw));
    }

    #[test]
    fn normalize_secret_key_rejects_all_zero_secret_scalar() {
        let raw = "0000000000000000000000000000000000000000000000000000000000000000";
        let err = normalize_secret_key_input(raw).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("not a valid secp256k1 secret scalar"));
        assert!(!message.contains(raw));
    }

    #[test]
    fn secret_key_input_debug_redacts_secret_material() {
        let normalized = normalize_secret_key_input(TEST_SECRET_KEY_HEX).unwrap();
        let debug = format!("{normalized:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TEST_SECRET_KEY_HEX));
    }

    #[test]
    fn encode_secret_key_nsec_roundtrips_to_canonical_hex() {
        let nsec = encode_secret_key_nsec(NIP19_EXAMPLE_SECRET_HEX).unwrap();
        let normalized = normalize_secret_key_input(&nsec).unwrap();
        assert_eq!(normalized.canonical_secret_hex(), NIP19_EXAMPLE_SECRET_HEX);
        assert_eq!(normalized.format(), NostrSecretKeyFormat::Nsec);
    }

    #[test]
    fn normalize_public_key_accepts_raw_hex_and_lowercases() {
        let normalized = normalize_public_key_input(&NIP19_EXAMPLE_PUBLIC_HEX.to_uppercase())
            .expect("uppercase raw hex public key should normalize");
        assert_eq!(
            normalized.canonical_public_key_hex(),
            NIP19_EXAMPLE_PUBLIC_HEX
        );
        assert_eq!(normalized.format(), NostrPublicKeyFormat::Hex);
    }

    #[test]
    fn normalize_public_key_accepts_npub() {
        let normalized = normalize_public_key_input(NIP19_EXAMPLE_NPUB).unwrap();
        assert_eq!(
            normalized.canonical_public_key_hex(),
            NIP19_EXAMPLE_PUBLIC_HEX
        );
        assert_eq!(normalized.format(), NostrPublicKeyFormat::Npub);
    }

    #[test]
    fn normalize_public_key_accepts_nostr_prefixed_npub() {
        let normalized =
            normalize_public_key_input(&format!("nostr:{NIP19_EXAMPLE_NPUB}")).unwrap();
        assert_eq!(
            normalized.canonical_public_key_hex(),
            NIP19_EXAMPLE_PUBLIC_HEX
        );
        assert_eq!(normalized.format(), NostrPublicKeyFormat::NostrNpub);
    }

    #[test]
    fn normalize_public_key_rejects_invalid_key() {
        let err = normalize_public_key_input("aaaa").unwrap_err();
        assert!(
            err.to_string()
                .contains("raw 64-character hex key, NIP-19 npub, or nostr:npub")
        );
    }

    #[test]
    fn normalize_public_key_rejects_wrong_bech32_type() {
        let err = normalize_public_key_input(NIP19_EXAMPLE_NSEC).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("prefix must be `npub`"));
        assert!(!message.contains(NIP19_EXAMPLE_NSEC));
        assert!(!message.contains(NIP19_EXAMPLE_SECRET_HEX));
    }

    #[test]
    fn encode_public_key_npub_roundtrips_to_canonical_hex() {
        let npub = encode_public_key_npub(NIP19_EXAMPLE_PUBLIC_HEX).unwrap();
        let normalized = normalize_public_key_input(&npub).unwrap();
        assert_eq!(
            normalized.canonical_public_key_hex(),
            NIP19_EXAMPLE_PUBLIC_HEX
        );
    }

    #[test]
    fn config_validates_empty_relay_urls() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": [],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_empty_secret_key() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": ""
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_zero_timeout() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "request_timeout_ms": 0
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_zero_query_limit() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "default_query_limit": 0
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_secret_key_input_length() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "aaaa"
        }))
        .unwrap();
        let err = config.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("64-character hex secret or NIP-19 nsec"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn config_validates_secret_key_input_non_hex_chars() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        }))
        .unwrap();
        let err = config.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("64-character hex secret or NIP-19 nsec"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn config_accepts_nsec_secret_input() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": NIP19_EXAMPLE_NSEC
        }))
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_relay_url_accepts_wss() {
        assert!(validate_relay_url("wss://relay.example.com").is_ok());
    }

    #[test]
    fn validate_relay_url_accepts_ws() {
        assert!(validate_relay_url("ws://localhost:7777").is_err());
        assert!(
            validate_relay_url_with_policy("ws://localhost:7777", RelayUrlPolicy::local_harness())
                .is_ok()
        );
    }

    #[test]
    fn validate_relay_url_rejects_https() {
        assert!(validate_relay_url("https://relay.example.com").is_err());
    }

    #[test]
    fn validate_relay_url_rejects_empty() {
        assert!(validate_relay_url("").is_err());
    }

    #[test]
    fn validate_relay_url_rejects_userinfo() {
        assert!(validate_relay_url("wss://user:pass@relay.example.com").is_err());
    }

    #[test]
    fn validate_relay_url_rejects_fragments() {
        assert!(validate_relay_url("wss://relay.example.com#frag").is_err());
    }

    #[test]
    fn validate_relay_url_rejects_public_ws() {
        let err = validate_relay_url("ws://relay.example.com").unwrap_err();
        assert!(err.to_string().contains("must use wss://"));
    }

    #[test]
    fn validate_relay_url_rejects_private_hosts_by_default() {
        assert!(validate_relay_url("wss://127.0.0.1:7777").is_err());
        assert!(validate_relay_url("wss://10.0.0.10").is_err());
        assert!(validate_relay_url("wss://[::1]:7777").is_err());
    }

    #[test]
    fn validate_relay_url_accepts_private_hosts_when_explicit() {
        let policy = RelayUrlPolicy::local_harness();
        assert!(validate_relay_url_with_policy("wss://127.0.0.1:7777", policy).is_ok());
        assert!(validate_relay_url_with_policy("ws://localhost:7777", policy).is_ok());
        assert!(validate_relay_url_with_policy("wss://[::1]:7777", policy).is_ok());
    }

    #[test]
    fn canonicalize_relay_urls_deduplicates_normalized_entries() {
        let relays = vec![
            " wss://Relay.EXAMPLE.com ".to_string(),
            "wss://relay.example.com/".to_string(),
            "wss://relay.example.com/chat".to_string(),
        ];
        let canonical = canonicalize_relay_urls(&relays, RelayUrlPolicy::production()).unwrap();
        assert_eq!(canonical.len(), 2);
        assert_eq!(canonical[0].as_str(), "wss://relay.example.com/");
        assert_eq!(canonical[1].as_str(), "wss://relay.example.com/chat");
    }

    #[test]
    fn config_validate_honors_local_relay_policy() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["ws://localhost:7777"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
        }))
        .unwrap();
        assert!(config.validate().is_err());

        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["ws://localhost:7777"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "allow_local_relays": true
        }))
        .unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_zero_relay_circuit_threshold() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "relay_circuit_failure_threshold": 0
        }))
        .unwrap();
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("relay_circuit_failure_threshold must be greater than zero")
        );
    }

    #[test]
    fn config_validate_accepts_inbound_dm_allowlist_and_rate_limits() {
        let sender_npub = encode_public_key_npub(NIP19_EXAMPLE_PUBLIC_HEX).unwrap();
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": TEST_SECRET_KEY_HEX,
            "inbound_dm": {
                "policy_mode": "allowlist",
                "allowed_senders": [format!("nostr:{sender_npub}")],
                "seen_event_capacity": 8,
                "rate_window_secs": 5,
                "global_rate_limit": 3,
                "per_sender_rate_limit": 1
            }
        }))
        .unwrap();
        assert!(config.validate().is_ok());
        let allowed = config.inbound_dm.normalized_allowed_senders().unwrap();
        assert!(allowed.contains(NIP19_EXAMPLE_PUBLIC_HEX));
    }

    #[test]
    fn config_validate_rejects_inbound_dm_bad_bounds_and_empty_allowlist() {
        let bad_limit: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": TEST_SECRET_KEY_HEX,
            "inbound_dm": {
                "rate_window_secs": 0
            }
        }))
        .unwrap();
        assert!(
            bad_limit
                .validate()
                .unwrap_err()
                .to_string()
                .contains("inbound_dm.rate_window_secs")
        );

        let empty_allowlist: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": TEST_SECRET_KEY_HEX,
            "inbound_dm": {
                "policy_mode": "allowlist"
            }
        }))
        .unwrap();
        assert!(
            empty_allowlist
                .validate()
                .unwrap_err()
                .to_string()
                .contains("allowed_senders must not be empty")
        );
    }

    #[test]
    fn validate_relay_url_rejects_missing_host() {
        let err = validate_relay_url("wss://").unwrap_err();
        assert!(err.to_string().contains("invalid relay URL"));
    }

    #[test]
    fn validate_relay_url_rejects_invalid_port() {
        let err = validate_relay_url("wss://relay.example.com:not-a-port").unwrap_err();
        assert!(err.to_string().contains("invalid relay URL"));
    }

    #[test]
    fn validate_relay_url_redacts_userinfo_in_errors() {
        let err = validate_relay_url("wss://user:pass@relay.example.com").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("[redacted]"));
        assert!(!message.contains("user:pass"));
    }

    #[test]
    fn required_string_returns_value() {
        assert_eq!(
            required_string(&json!({"content": "hello"}), "content").unwrap(),
            "hello"
        );
    }

    #[test]
    fn required_string_rejects_missing() {
        assert!(required_string(&json!({}), "content").is_err());
    }

    #[test]
    fn required_string_rejects_non_string() {
        let err = required_string(&json!({"content": 7}), "content").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert_eq!(
            err.to_string(),
            "Invalid request: content must be a non-empty string"
        );
    }

    #[test]
    fn required_string_rejects_blank() {
        assert!(required_string(&json!({"content": "  "}), "content").is_err());
    }

    #[test]
    fn note_kind_defaults_to_text() {
        assert_eq!(note_kind(&json!({})).unwrap(), NIP01_KIND_TEXT);
    }

    #[test]
    fn note_kind_rejects_non_note_kinds() {
        assert!(note_kind(&json!({"kind": 4})).is_err());
    }

    #[test]
    fn note_kind_rejects_non_integer_values() {
        assert!(note_kind(&json!({"kind": "1"})).is_err());
    }

    #[test]
    fn note_tags_defaults_to_empty() {
        assert_eq!(note_tags(&json!({})).unwrap(), json!([]));
    }

    #[test]
    fn note_tags_accepts_string_arrays() {
        let tags = json!({"tags": [["p", "abc"]]});
        assert!(note_tags(&tags).is_ok());
    }

    #[test]
    fn note_tags_rejects_non_string_entries() {
        assert!(note_tags(&json!({"tags": [["p", 3]]})).is_err());
    }

    #[test]
    fn build_filter_uses_default_limit() {
        let filter = build_filter(&json!({"kinds": [1]}), 25).unwrap();
        assert_eq!(filter["limit"], 25);
        assert_eq!(filter["kinds"], json!([1]));
    }

    #[test]
    fn build_filter_normalizes_author_public_keys() {
        let filter = build_filter(
            &json!({
                "authors": [
                    NIP19_EXAMPLE_PUBLIC_HEX.to_uppercase(),
                    NIP19_EXAMPLE_NPUB,
                    format!("nostr:{NIP19_EXAMPLE_NPUB}")
                ]
            }),
            25,
        )
        .unwrap();
        assert_eq!(
            filter["authors"],
            json!([
                NIP19_EXAMPLE_PUBLIC_HEX,
                NIP19_EXAMPLE_PUBLIC_HEX,
                NIP19_EXAMPLE_PUBLIC_HEX
            ])
        );
    }

    #[test]
    fn build_filter_respects_explicit_limit() {
        let filter = build_filter(&json!({"limit": 10}), 25).unwrap();
        assert_eq!(filter["limit"], 10);
    }

    #[test]
    fn build_filter_rejects_zero_limit() {
        assert!(build_filter(&json!({"limit": 0}), 25).is_err());
    }

    #[test]
    fn build_filter_rejects_invalid_limit_type() {
        assert!(build_filter(&json!({"limit": "10"}), 25).is_err());
    }

    #[test]
    fn build_filter_rejects_non_string_authors() {
        assert!(build_filter(&json!({"authors": ["ok", 3]}), 25).is_err());
    }

    #[test]
    fn string_array_field_none_when_absent() {
        assert!(string_array_field(&json!({}), "authors").unwrap().is_none());
    }

    #[test]
    fn u64_array_field_none_when_absent() {
        assert!(u64_array_field(&json!({}), "kinds").unwrap().is_none());
    }

    #[test]
    fn i64_field_none_when_absent() {
        assert!(i64_field(&json!({}), "since").unwrap().is_none());
    }

    #[test]
    fn u64_field_none_when_absent() {
        assert!(u64_field(&json!({}), "limit").unwrap().is_none());
    }

    #[test]
    fn i64_field_parses_negative() {
        assert_eq!(i64_field(&json!({"since": -1}), "since").unwrap(), Some(-1));
    }

    #[test]
    fn u64_field_rejects_negative() {
        assert!(u64_field(&json!({"limit": -1}), "limit").is_err());
    }

    // ── NIP-04 DM event type tests ─────────────────────────────────────

    #[test]
    fn nip04_kind_constant_is_4() {
        assert_eq!(NIP04_KIND_ENCRYPTED_DM, 4);
    }

    #[test]
    fn nip44_kind_constants() {
        assert_eq!(NIP44_KIND_GIFT_WRAP, 1059);
        assert_eq!(NIP44_KIND_SEAL, 13);
    }

    #[test]
    fn encrypted_dm_event_new_sets_kind_4() {
        let dm = EncryptedDmEvent::new("aaaa".repeat(16), "encrypted_content?iv=base64iv".into());
        assert_eq!(dm.kind, NIP04_KIND_ENCRYPTED_DM);
        assert_eq!(dm.recipient_pubkey.len(), 64);
    }

    #[test]
    fn encrypted_dm_event_try_new_normalizes_npub_recipient() {
        let dm =
            EncryptedDmEvent::try_new(NIP19_EXAMPLE_NPUB, "encrypted_content?iv=base64iv".into())
                .unwrap();
        assert_eq!(dm.kind, NIP04_KIND_ENCRYPTED_DM);
        assert_eq!(dm.recipient_pubkey, NIP19_EXAMPLE_PUBLIC_HEX);
        assert_eq!(dm.tags(), json!([["p", NIP19_EXAMPLE_PUBLIC_HEX]]));
    }

    #[test]
    fn encrypted_dm_event_serializes() {
        let dm = EncryptedDmEvent::new("bbbb".repeat(16), "ciphertext?iv=nonce".into());
        let json = serde_json::to_value(&dm).unwrap();
        assert_eq!(json["kind"], 4);
        assert_eq!(json["content"], "ciphertext?iv=nonce");
        assert_eq!(json["recipient_pubkey"], "bbbb".repeat(16));
    }

    #[test]
    fn encrypted_dm_event_deserializes() {
        let json = json!({
            "recipient_pubkey": "cccc".repeat(16),
            "content": "encrypted_payload",
            "kind": 4
        });
        let dm: EncryptedDmEvent = serde_json::from_value(json).unwrap();
        assert_eq!(dm.kind, 4);
        assert_eq!(dm.content, "encrypted_payload");
    }

    #[test]
    fn encrypted_dm_event_roundtrip() {
        let original = EncryptedDmEvent::new("dddd".repeat(16), "test_payload?iv=abc".into());
        let json = serde_json::to_value(&original).unwrap();
        let deserialized: EncryptedDmEvent = serde_json::from_value(json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn encrypted_dm_event_validate_valid() {
        let dm = EncryptedDmEvent::new("eeee".repeat(16), "valid_content".into());
        assert!(dm.validate().is_ok());
    }

    #[test]
    fn encrypted_dm_event_validate_empty_pubkey() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: String::new(),
            content: "content".into(),
            kind: 4,
        };
        let err = dm.validate().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn encrypted_dm_event_validate_short_pubkey() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "aabb".into(),
            content: "content".into(),
            kind: 4,
        };
        let err = dm.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("64-character hex"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn encrypted_dm_event_validate_non_hex_pubkey() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "zzzz".repeat(16),
            content: "content".into(),
            kind: 4,
        };
        assert!(dm.validate().is_err());
    }

    #[test]
    fn encrypted_dm_event_validate_empty_content() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "aaaa".repeat(16),
            content: "   ".into(),
            kind: 4,
        };
        assert!(dm.validate().is_err());
    }

    #[test]
    fn encrypted_dm_event_validate_wrong_kind() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "aaaa".repeat(16),
            content: "content".into(),
            kind: 1,
        };
        let err = dm.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("kind must be 4"));
            }
            other => assert!(matches!(other, FcpError::InvalidRequest { .. })),
        }
    }

    #[test]
    fn encrypted_dm_event_tags_has_p_tag() {
        let dm = EncryptedDmEvent::new("ffff".repeat(16), "payload".into());
        let tags = dm.tags();
        assert_eq!(tags, json!([["p", "ffff".repeat(16)]]));
    }

    #[test]
    fn dm_tags_include_reply_event_when_supplied() {
        let reply = "a1".repeat(32);
        let tags = dm_tags(NIP19_EXAMPLE_PUBLIC_HEX, Some(&reply)).unwrap();
        assert_eq!(tags, json!([["p", NIP19_EXAMPLE_PUBLIC_HEX], ["e", reply]]));
    }

    #[test]
    fn dm_tags_reject_invalid_reply_event_id() {
        assert!(dm_tags(NIP19_EXAMPLE_PUBLIC_HEX, Some("not-an-event-id")).is_err());
    }

    #[test]
    fn parse_dm_send_input_accepts_recipient_and_plaintext_aliases() {
        let input = json!({
            "recipient": NIP19_EXAMPLE_NPUB,
            "target": NIP19_EXAMPLE_NPUB,
            "content": "hello private relay",
            "allow_self_send": false
        });
        let parsed = parse_dm_send_input(&input, &"11".repeat(32)).unwrap();
        assert_eq!(parsed.recipient_pubkey(), NIP19_EXAMPLE_PUBLIC_HEX);
        assert_eq!(parsed.recipient_format().as_str(), "nip19_npub");
        assert_eq!(parsed.plaintext(), "hello private relay");
        assert!(!parsed.allow_self_send());
    }

    #[test]
    fn parse_dm_send_input_accepts_nostr_npub_and_reply_alias() {
        let reply = "b2".repeat(32);
        let input = json!({
            "recipient_pubkey": format!("nostr:{NIP19_EXAMPLE_NPUB}"),
            "plaintext": "with reply",
            "reply_to": reply
        });
        let parsed = parse_dm_send_input(&input, &"11".repeat(32)).unwrap();
        assert_eq!(parsed.recipient_pubkey(), NIP19_EXAMPLE_PUBLIC_HEX);
        assert_eq!(parsed.recipient_format().as_str(), "nostr_npub");
        let reply_lower = "b2".repeat(32);
        assert_eq!(parsed.reply_to_event_id(), Some(reply_lower.as_str()));
    }

    #[test]
    fn parse_dm_send_input_rejects_empty_plaintext_without_leaking_value() {
        let err = parse_dm_send_input(
            &json!({
                "recipient": NIP19_EXAMPLE_PUBLIC_HEX,
                "plaintext": "   "
            }),
            &"11".repeat(32),
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("plaintext must be a non-empty string"));
        assert!(!message.contains(NIP19_EXAMPLE_PUBLIC_HEX));
    }

    #[test]
    fn parse_dm_send_input_rejects_oversized_plaintext_without_echoing_text() {
        let oversized = "x".repeat(MAX_DM_PLAINTEXT_BYTES + 1);
        let err = parse_dm_send_input(
            &json!({
                "recipient": NIP19_EXAMPLE_PUBLIC_HEX,
                "plaintext": oversized
            }),
            &"11".repeat(32),
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("4096 byte limit"));
        assert!(!message.contains(&"x".repeat(128)));
    }

    #[test]
    fn parse_dm_send_input_rejects_invalid_recipient() {
        let err = parse_dm_send_input(
            &json!({
                "recipient": "not-a-pubkey",
                "plaintext": "hello"
            }),
            &"11".repeat(32),
        )
        .unwrap_err();
        assert!(err.to_string().contains("public key input"));
    }

    #[test]
    fn parse_dm_send_input_rejects_self_send_by_default() {
        let err = parse_dm_send_input(
            &json!({
                "recipient": NIP19_EXAMPLE_PUBLIC_HEX,
                "plaintext": "self"
            }),
            NIP19_EXAMPLE_PUBLIC_HEX,
        )
        .unwrap_err();
        assert!(err.to_string().contains("allow_self_send"));
    }

    #[test]
    fn parse_dm_send_input_allows_explicit_self_send() {
        let parsed = parse_dm_send_input(
            &json!({
                "recipient": NIP19_EXAMPLE_PUBLIC_HEX,
                "plaintext": "self",
                "allow_self_send": true
            }),
            NIP19_EXAMPLE_PUBLIC_HEX,
        )
        .unwrap();
        assert_eq!(parsed.recipient_pubkey(), NIP19_EXAMPLE_PUBLIC_HEX);
    }

    #[test]
    fn parse_dm_send_input_debug_redacts_plaintext() {
        let parsed = parse_dm_send_input(
            &json!({
                "recipient": NIP19_EXAMPLE_PUBLIC_HEX,
                "plaintext": "top secret test text"
            }),
            &"11".repeat(32),
        )
        .unwrap();
        let debug = format!("{parsed:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("top secret test text"));
    }

    #[test]
    fn profile_publish_input_accepts_empty_and_full_profile() {
        let empty = parse_profile_publish_input(&json!({"profile": {}})).unwrap();
        assert_eq!(empty.profile(), &NostrProfile::default());

        let full = parse_profile_publish_input(&json!({
            "profile": {
                "name": "testuser",
                "display_name": "Test User",
                "about": "A profile",
                "picture": "https://example.com/avatar.png",
                "banner": "https://cdn.example.com/banner.png",
                "website": "https://example.com",
                "nip05": "test@example.com",
                "lud16": "test@getalby.com"
            },
            "last_published_at": 1_700_000_000
        }))
        .unwrap();
        assert_eq!(full.profile().display_name.as_deref(), Some("Test User"));
        assert_eq!(full.last_published_at(), Some(1_700_000_000));
        assert_eq!(
            profile_to_content_value(full.profile())["display_name"],
            "Test User"
        );
    }

    #[test]
    fn profile_validation_rejects_length_and_unknown_fields() {
        let too_long = "x".repeat(MAX_PROFILE_SHORT_TEXT_CHARS + 1);
        assert!(profile_from_value(&json!({"name": too_long})).is_err());
        assert!(profile_from_value(&json!({"unexpected": "value"})).is_err());
    }

    #[test]
    fn profile_url_safety_rejects_unsafe_schemes_and_private_hosts() {
        for url in [
            "http://example.com/avatar.png",
            "javascript:alert(1)",
            "data:image/png;base64,abc",
            "file:///etc/passwd",
            "https://localhost/avatar.png",
            "https://127.0.0.1/avatar.png",
            "https://10.0.0.7/avatar.png",
            "https://[::1]/avatar.png",
            "https://printer.local/avatar.png",
            "https://metadata.internal/avatar.png",
        ] {
            assert!(
                profile_from_value(&json!({"picture": url})).is_err(),
                "{url} should be rejected"
            );
        }

        assert!(profile_from_value(&json!({"picture": "https://example.com/avatar.png"})).is_ok());
    }

    #[test]
    fn profile_address_validation_and_display_sanitization_are_explicit() {
        assert!(profile_from_value(&json!({"nip05": "not-an-address"})).is_err());
        assert!(profile_from_value(&json!({"lud16": "a b@example.com"})).is_err());
        let profile = profile_from_value(&json!({
            "name": "<alice>",
            "about": "A & B",
            "nip05": "alice@example.com",
            "lud16": "alice@getalby.com",
            "website": "https://example.com"
        }))
        .unwrap();
        let display = sanitize_profile_for_display(&profile);
        assert_eq!(display.name.as_deref(), Some("&lt;alice&gt;"));
        assert_eq!(display.about.as_deref(), Some("A &amp; B"));
        assert_eq!(display.website.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn imported_profile_drops_unsafe_urls_and_preserves_safe_fields() {
        let (profile, dropped) = profile_from_imported_content(&json!({
            "name": "imported",
            "picture": "https://127.0.0.1/avatar.png",
            "banner": "https://example.com/banner.png",
            "website": "https://metadata.internal"
        }))
        .unwrap();

        assert_eq!(profile.name.as_deref(), Some("imported"));
        assert!(profile.picture.is_none());
        assert_eq!(
            profile.banner.as_deref(),
            Some("https://example.com/banner.png")
        );
        assert!(profile.website.is_none());
        assert_eq!(dropped, vec!["picture", "website"]);
    }

    #[test]
    fn profile_import_input_normalizes_pubkey_and_merges_local_fields() {
        let input = parse_profile_import_input(
            &json!({
                "pubkey": NIP19_EXAMPLE_NPUB,
                "local_profile": {
                    "name": "local",
                    "displayName": "Local Display"
                }
            }),
            &"11".repeat(32),
        )
        .unwrap();
        assert_eq!(input.pubkey_hex(), NIP19_EXAMPLE_PUBLIC_HEX);
        let imported = profile_from_value(&json!({
            "name": "imported",
            "display_name": "Imported Display",
            "about": "imported about"
        }))
        .unwrap();
        let merged = merge_profiles(input.local_profile(), Some(&imported));
        assert_eq!(merged.name.as_deref(), Some("local"));
        assert_eq!(merged.display_name.as_deref(), Some("Local Display"));
        assert_eq!(merged.about.as_deref(), Some("imported about"));
    }

    #[test]
    fn note_publish_still_rejects_profile_kind() {
        assert!(note_kind(&json!({"kind": NIP01_KIND_PROFILE})).is_err());
    }

    #[test]
    fn op_relays_health_constant() {
        assert_eq!(OP_RELAYS_HEALTH, "nostr.relays.health");
    }

    #[test]
    fn op_send_dm_constant() {
        assert_eq!(OP_SEND_DM, "nostr.dm.send");
        assert_eq!(CAP_DM_WRITE, "nostr.dm.write");
    }

    #[test]
    fn op_profile_constants_are_separate_from_note_publish() {
        assert_eq!(OP_PROFILE_PUBLISH, "nostr.profile.publish");
        assert_eq!(OP_PROFILE_STATE, "nostr.profile.state");
        assert_eq!(OP_PROFILE_IMPORT, "nostr.profile.import");
        assert_eq!(CAP_PROFILE_WRITE, "nostr.profile.write");
        assert_eq!(CAP_PROFILE_READ, "nostr.profile.read");
    }
}
