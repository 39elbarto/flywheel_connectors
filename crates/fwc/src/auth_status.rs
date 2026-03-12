//! Token rotation tracking and expiry alerting.
//!
//! Tracks credential metadata (creation, expiry, rotation history) and
//! provides warnings when tokens are approaching expiry. Integrates with
//! the credential store for auth lifecycle management.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ── Types ──────────────────────────────────────────────────────────

/// Metadata about a stored credential's lifecycle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthMetadata {
    /// Connector identifier.
    pub connector_id: String,
    /// When the credential was first stored.
    pub created_at: DateTime<Utc>,
    /// When the credential expires (if known).
    pub expires_at: Option<DateTime<Utc>>,
    /// When the credential was last used.
    pub last_used_at: Option<DateTime<Utc>>,
    /// When the credential was last rotated.
    pub last_rotated_at: Option<DateTime<Utc>>,
    /// History of rotation events.
    pub rotation_history: Vec<RotationEvent>,
}

/// A single rotation event in the credential's history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationEvent {
    /// When the rotation happened.
    pub rotated_at: DateTime<Utc>,
    /// Why the rotation was performed.
    pub reason: RotationReason,
    /// Optional notes.
    pub notes: Option<String>,
}

/// Why a credential was rotated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    /// User manually rotated the credential.
    Manual,
    /// Credential expired and was refreshed.
    Expired,
    /// Scheduled rotation policy.
    Scheduled,
    /// Security incident required rotation.
    SecurityIncident,
    /// OAuth token refresh.
    TokenRefresh,
}

impl RotationReason {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Expired => "expired",
            Self::Scheduled => "scheduled",
            Self::SecurityIncident => "security incident",
            Self::TokenRefresh => "token refresh",
        }
    }
}

impl AuthMetadata {
    /// Create metadata for a newly stored credential.
    pub fn new(connector_id: impl Into<String>, expires_at: Option<DateTime<Utc>>) -> Self {
        let now = Utc::now();
        Self {
            connector_id: connector_id.into(),
            created_at: now,
            expires_at,
            last_used_at: None,
            last_rotated_at: None,
            rotation_history: Vec::new(),
        }
    }

    /// Record a rotation event.
    pub fn record_rotation(&mut self, reason: RotationReason, notes: Option<String>) {
        let now = Utc::now();
        self.last_rotated_at = Some(now);
        self.rotation_history.push(RotationEvent {
            rotated_at: now,
            reason,
            notes,
        });
    }

    /// Update the expiry time (e.g. after token refresh).
    pub const fn set_expiry(&mut self, expires_at: DateTime<Utc>) {
        self.expires_at = Some(expires_at);
    }

    /// Mark the credential as used.
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Whether this credential has a known expiry.
    pub const fn has_expiry(&self) -> bool {
        self.expires_at.is_some()
    }

    /// Whether the credential is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() >= exp)
    }

    /// Time remaining until expiry. `None` if no expiry set.
    pub fn time_to_expiry(&self) -> Option<Duration> {
        self.expires_at.map(|exp| {
            let now = Utc::now();
            if exp > now {
                exp - now
            } else {
                Duration::zero()
            }
        })
    }

    /// Whether the credential expires within the given duration.
    pub fn expires_within(&self, window: Duration) -> bool {
        self.time_to_expiry()
            .is_some_and(|remaining| remaining <= window)
    }

    /// Credential age (time since creation).
    pub fn age(&self) -> Duration {
        Utc::now() - self.created_at
    }

    /// Number of rotations performed.
    pub fn rotation_count(&self) -> usize {
        self.rotation_history.len()
    }
}

// ── Expiry status ──────────────────────────────────────────────────

/// Expiry status of a credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryStatus {
    /// No expiry information available.
    NoExpiry,
    /// Credential is valid with plenty of time remaining.
    Valid,
    /// Credential expires within 7 days.
    ExpiringSoon,
    /// Credential expires within 24 hours.
    ExpiringImminently,
    /// Credential has expired.
    Expired,
}

impl ExpiryStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoExpiry => "no expiry",
            Self::Valid => "valid",
            Self::ExpiringSoon => "expiring soon",
            Self::ExpiringImminently => "expiring imminently",
            Self::Expired => "expired",
        }
    }

    /// Whether this status requires attention.
    pub const fn needs_attention(self) -> bool {
        matches!(
            self,
            Self::ExpiringSoon | Self::ExpiringImminently | Self::Expired
        )
    }
}

impl std::fmt::Display for ExpiryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Classify a credential's expiry status.
pub fn classify_expiry(metadata: &AuthMetadata) -> ExpiryStatus {
    let Some(remaining) = metadata.time_to_expiry() else {
        return ExpiryStatus::NoExpiry;
    };
    if remaining.is_zero() {
        ExpiryStatus::Expired
    } else if remaining <= Duration::hours(24) {
        ExpiryStatus::ExpiringImminently
    } else if remaining <= Duration::days(7) {
        ExpiryStatus::ExpiringSoon
    } else {
        ExpiryStatus::Valid
    }
}

// ── Status report ──────────────────────────────────────────────────

/// Status report for a single credential.
#[derive(Clone, Debug, Serialize)]
pub struct AuthStatusEntry {
    pub connector_id: String,
    pub expiry_status: ExpiryStatus,
    pub expires_at: Option<String>,
    pub time_remaining: Option<String>,
    pub age_days: i64,
    pub rotation_count: usize,
    pub last_used: Option<String>,
}

impl AuthStatusEntry {
    /// Build a status entry from metadata.
    pub fn from_metadata(metadata: &AuthMetadata) -> Self {
        let expiry_status = classify_expiry(metadata);
        let time_remaining = metadata.time_to_expiry().map(format_duration);
        Self {
            connector_id: metadata.connector_id.clone(),
            expiry_status,
            expires_at: metadata.expires_at.map(|t| t.to_rfc3339()),
            time_remaining,
            age_days: metadata.age().num_days(),
            rotation_count: metadata.rotation_count(),
            last_used: metadata.last_used_at.map(|t| t.to_rfc3339()),
        }
    }

    /// Whether this entry needs attention.
    pub const fn needs_attention(&self) -> bool {
        self.expiry_status.needs_attention()
    }
}

/// Format a duration as a human-readable string.
fn format_duration(d: Duration) -> String {
    if d.is_zero() {
        return "expired".to_string();
    }
    let days = d.num_days();
    let hours = d.num_hours() % 24;
    if days > 0 {
        format!("{days}d {hours}h")
    } else {
        let mins = d.num_minutes() % 60;
        format!("{hours}h {mins}m")
    }
}

// ── Rotation guidance ──────────────────────────────────────────────

/// Rotation guidance for a specific auth type.
#[derive(Clone, Debug, Serialize)]
pub struct RotationGuidance {
    pub connector_id: String,
    pub steps: Vec<String>,
    pub automated: bool,
    pub estimated_downtime: Option<String>,
}

/// Generate rotation guidance based on auth type.
pub fn rotation_guidance(connector_id: &str, auth_type: &str) -> RotationGuidance {
    match auth_type {
        "bearer_token" | "api_key" => RotationGuidance {
            connector_id: connector_id.to_owned(),
            steps: vec![
                format!("Generate a new API token in the {connector_id} dashboard"),
                format!("fwc auth add {connector_id} --token <NEW_TOKEN>"),
                format!("fwc auth test {connector_id}"),
                "Revoke the old token in the provider dashboard".to_owned(),
            ],
            automated: false,
            estimated_downtime: Some("< 1 minute".to_owned()),
        },
        "oauth2" => RotationGuidance {
            connector_id: connector_id.to_owned(),
            steps: vec![
                format!("fwc auth refresh {connector_id}  (if refresh token available)"),
                format!("Or re-authorize: fwc auth add {connector_id} --oauth"),
                format!("fwc auth test {connector_id}"),
            ],
            automated: true,
            estimated_downtime: None,
        },
        "basic_auth" => RotationGuidance {
            connector_id: connector_id.to_owned(),
            steps: vec![
                format!("Update password in the {connector_id} dashboard"),
                format!("fwc auth add {connector_id} --username <USER> --password <NEW_PASS>"),
                format!("fwc auth test {connector_id}"),
            ],
            automated: false,
            estimated_downtime: Some("< 1 minute".to_owned()),
        },
        "session_token" => RotationGuidance {
            connector_id: connector_id.to_owned(),
            steps: vec![
                format!("Session tokens are typically auto-refreshed by the connector"),
                format!("If expired, re-authenticate: fwc auth add {connector_id} --session"),
                format!("fwc auth test {connector_id}"),
            ],
            automated: true,
            estimated_downtime: None,
        },
        _ => RotationGuidance {
            connector_id: connector_id.to_owned(),
            steps: vec![
                format!("Check {connector_id} documentation for credential rotation procedure"),
                format!("fwc auth add {connector_id} <updated credentials>"),
                format!("fwc auth test {connector_id}"),
            ],
            automated: false,
            estimated_downtime: Some("varies".to_owned()),
        },
    }
}

// ── Age-based rotation advisory ───────────────────────────────────

/// Advisory about whether a credential should be rotated based on age,
/// independent of expiry status.
#[derive(Clone, Debug, Serialize)]
pub struct RotationAdvisory {
    pub connector_id: String,
    pub age_days: i64,
    pub last_rotated_days: Option<i64>,
    pub recommendation: RotationUrgency,
    pub message: String,
}

/// How urgently a credential should be rotated based on age.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationUrgency {
    /// No rotation needed.
    None,
    /// Consider rotating soon (> 90 days old without rotation).
    Suggested,
    /// Strongly recommend rotation (> 180 days old without rotation).
    Recommended,
    /// Overdue for rotation (> 365 days old without rotation).
    Overdue,
}

impl RotationUrgency {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Suggested => "suggested",
            Self::Recommended => "recommended",
            Self::Overdue => "overdue",
        }
    }

    pub const fn needs_attention(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Produce an age-based rotation advisory for a credential.
pub fn rotation_advisory(metadata: &AuthMetadata) -> RotationAdvisory {
    let age_days = metadata.age().num_days();
    let last_rotated_days = metadata.last_rotated_at.map(|t| (Utc::now() - t).num_days());
    let days_since_rotation = last_rotated_days.unwrap_or(age_days);

    let (recommendation, message) = if days_since_rotation > 365 {
        (
            RotationUrgency::Overdue,
            format!(
                "{}: credential is {} days old without rotation — overdue for rotation",
                metadata.connector_id, days_since_rotation
            ),
        )
    } else if days_since_rotation > 180 {
        (
            RotationUrgency::Recommended,
            format!(
                "{}: credential is {} days old without rotation — rotation recommended",
                metadata.connector_id, days_since_rotation
            ),
        )
    } else if days_since_rotation > 90 {
        (
            RotationUrgency::Suggested,
            format!(
                "{}: credential is {} days old without rotation — consider rotating",
                metadata.connector_id, days_since_rotation
            ),
        )
    } else {
        (
            RotationUrgency::None,
            format!(
                "{}: credential age ({} days) within normal range",
                metadata.connector_id, days_since_rotation
            ),
        )
    };

    RotationAdvisory {
        connector_id: metadata.connector_id.clone(),
        age_days,
        last_rotated_days,
        recommendation,
        message,
    }
}

// ── Warning middleware ─────────────────────────────────────────────

/// Check all metadata entries and return warnings for credentials needing attention.
pub fn check_expiry_warnings(entries: &[AuthMetadata]) -> Vec<ExpiryWarning> {
    entries
        .iter()
        .filter_map(|meta| {
            let status = classify_expiry(meta);
            if status.needs_attention() {
                Some(ExpiryWarning {
                    connector_id: meta.connector_id.clone(),
                    status,
                    message: expiry_warning_message(meta, status),
                })
            } else {
                None
            }
        })
        .collect()
}

/// A warning about an expiring or expired credential.
#[derive(Clone, Debug, Serialize)]
pub struct ExpiryWarning {
    pub connector_id: String,
    pub status: ExpiryStatus,
    pub message: String,
}

fn expiry_warning_message(meta: &AuthMetadata, status: ExpiryStatus) -> String {
    match status {
        ExpiryStatus::Expired => format!("{}: credential has expired", meta.connector_id),
        ExpiryStatus::ExpiringImminently => {
            let remaining = meta
                .time_to_expiry()
                .map_or_else(|| "< 1h".to_owned(), format_duration);
            format!(
                "{}: credential expires in {} — rotate immediately",
                meta.connector_id, remaining
            )
        }
        ExpiryStatus::ExpiringSoon => {
            let remaining = meta
                .time_to_expiry()
                .map_or_else(|| "< 7d".to_owned(), format_duration);
            format!(
                "{}: credential expires in {} — plan rotation",
                meta.connector_id, remaining
            )
        }
        _ => String::new(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    // ── AuthMetadata ──────────────────────────────────────────────

    #[test]
    fn new_metadata_defaults() {
        let meta = AuthMetadata::new("github", None);
        assert_eq!(meta.connector_id, "github");
        assert!(!meta.has_expiry());
        assert!(meta.last_used_at.is_none());
        assert!(meta.last_rotated_at.is_none());
        assert_eq!(meta.rotation_count(), 0);
    }

    #[test]
    fn metadata_with_expiry() {
        let exp = now() + Duration::days(30);
        let meta = AuthMetadata::new("github", Some(exp));
        assert!(meta.has_expiry());
        assert!(!meta.is_expired());
    }

    #[test]
    fn metadata_expired() {
        let exp = now() - Duration::hours(1);
        let meta = AuthMetadata::new("github", Some(exp));
        assert!(meta.is_expired());
    }

    #[test]
    fn metadata_not_expired() {
        let exp = now() + Duration::hours(1);
        let meta = AuthMetadata::new("github", Some(exp));
        assert!(!meta.is_expired());
    }

    #[test]
    fn time_to_expiry_some() {
        let exp = now() + Duration::hours(5);
        let meta = AuthMetadata::new("github", Some(exp));
        let remaining = meta.time_to_expiry().unwrap();
        assert!(remaining.num_hours() >= 4);
    }

    #[test]
    fn time_to_expiry_none() {
        let meta = AuthMetadata::new("github", None);
        assert!(meta.time_to_expiry().is_none());
    }

    #[test]
    fn time_to_expiry_past() {
        let exp = now() - Duration::hours(1);
        let meta = AuthMetadata::new("github", Some(exp));
        let remaining = meta.time_to_expiry().unwrap();
        assert!(remaining.is_zero());
    }

    #[test]
    fn expires_within_true() {
        let exp = now() + Duration::hours(12);
        let meta = AuthMetadata::new("github", Some(exp));
        assert!(meta.expires_within(Duration::hours(24)));
    }

    #[test]
    fn expires_within_false() {
        let exp = now() + Duration::days(30);
        let meta = AuthMetadata::new("github", Some(exp));
        assert!(!meta.expires_within(Duration::hours(24)));
    }

    #[test]
    fn expires_within_no_expiry() {
        let meta = AuthMetadata::new("github", None);
        assert!(!meta.expires_within(Duration::hours(24)));
    }

    #[test]
    fn mark_used() {
        let mut meta = AuthMetadata::new("github", None);
        assert!(meta.last_used_at.is_none());
        meta.mark_used();
        assert!(meta.last_used_at.is_some());
    }

    #[test]
    fn record_rotation() {
        let mut meta = AuthMetadata::new("github", None);
        meta.record_rotation(RotationReason::Manual, Some("test".to_owned()));
        assert_eq!(meta.rotation_count(), 1);
        assert!(meta.last_rotated_at.is_some());
        assert_eq!(meta.rotation_history[0].reason, RotationReason::Manual);
        assert_eq!(meta.rotation_history[0].notes.as_deref(), Some("test"));
    }

    #[test]
    fn set_expiry() {
        let mut meta = AuthMetadata::new("github", None);
        assert!(!meta.has_expiry());
        let new_exp = now() + Duration::days(90);
        meta.set_expiry(new_exp);
        assert!(meta.has_expiry());
    }

    #[test]
    fn age_is_positive() {
        let meta = AuthMetadata::new("github", None);
        assert!(meta.age().num_seconds() >= 0);
    }

    #[test]
    fn metadata_serde_roundtrip() {
        let mut meta = AuthMetadata::new("github", Some(now() + Duration::days(30)));
        meta.record_rotation(RotationReason::TokenRefresh, None);
        let json = serde_json::to_string(&meta).unwrap();
        let restored: AuthMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.connector_id, "github");
        assert_eq!(restored.rotation_count(), 1);
    }

    // ── ExpiryStatus ──────────────────────────────────────────────

    #[test]
    fn expiry_status_labels() {
        assert_eq!(ExpiryStatus::NoExpiry.label(), "no expiry");
        assert_eq!(ExpiryStatus::Valid.label(), "valid");
        assert_eq!(ExpiryStatus::ExpiringSoon.label(), "expiring soon");
        assert_eq!(
            ExpiryStatus::ExpiringImminently.label(),
            "expiring imminently"
        );
        assert_eq!(ExpiryStatus::Expired.label(), "expired");
    }

    #[test]
    fn expiry_status_needs_attention() {
        assert!(!ExpiryStatus::NoExpiry.needs_attention());
        assert!(!ExpiryStatus::Valid.needs_attention());
        assert!(ExpiryStatus::ExpiringSoon.needs_attention());
        assert!(ExpiryStatus::ExpiringImminently.needs_attention());
        assert!(ExpiryStatus::Expired.needs_attention());
    }

    #[test]
    fn expiry_status_display() {
        assert_eq!(format!("{}", ExpiryStatus::Valid), "valid");
    }

    // ── classify_expiry ───────────────────────────────────────────

    #[test]
    fn classify_no_expiry() {
        let meta = AuthMetadata::new("github", None);
        assert_eq!(classify_expiry(&meta), ExpiryStatus::NoExpiry);
    }

    #[test]
    fn classify_valid() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(30)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::Valid);
    }

    #[test]
    fn classify_expiring_soon() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(3)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::ExpiringSoon);
    }

    #[test]
    fn classify_expiring_imminently() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::hours(12)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::ExpiringImminently);
    }

    #[test]
    fn classify_expired() {
        let meta = AuthMetadata::new("github", Some(now() - Duration::hours(1)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::Expired);
    }

    // ── AuthStatusEntry ───────────────────────────────────────────

    #[test]
    fn status_entry_from_metadata() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(3)));
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert_eq!(entry.connector_id, "github");
        assert_eq!(entry.expiry_status, ExpiryStatus::ExpiringSoon);
        assert!(entry.needs_attention());
        assert!(entry.time_remaining.is_some());
    }

    #[test]
    fn status_entry_no_expiry() {
        let meta = AuthMetadata::new("github", None);
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert!(!entry.needs_attention());
        assert!(entry.time_remaining.is_none());
    }

    // ── format_duration ───────────────────────────────────────────

    #[test]
    fn format_duration_days() {
        let d = Duration::days(5) + Duration::hours(3);
        let formatted = format_duration(d);
        assert!(formatted.contains("5d"));
        assert!(formatted.contains("3h"));
    }

    #[test]
    fn format_duration_hours() {
        let d = Duration::hours(3) + Duration::minutes(45);
        let formatted = format_duration(d);
        assert!(formatted.contains("3h"));
        assert!(formatted.contains("45m"));
    }

    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(Duration::zero()), "expired");
    }

    // ── RotationReason ────────────────────────────────────────────

    #[test]
    fn rotation_reason_labels() {
        assert_eq!(RotationReason::Manual.label(), "manual");
        assert_eq!(RotationReason::Expired.label(), "expired");
        assert_eq!(RotationReason::Scheduled.label(), "scheduled");
        assert_eq!(
            RotationReason::SecurityIncident.label(),
            "security incident"
        );
        assert_eq!(RotationReason::TokenRefresh.label(), "token refresh");
    }

    #[test]
    fn rotation_reason_serde() {
        let json = serde_json::to_string(&RotationReason::SecurityIncident).unwrap();
        assert_eq!(json, "\"security_incident\"");
        let restored: RotationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, RotationReason::SecurityIncident);
    }

    // ── rotation_guidance ─────────────────────────────────────────

    #[test]
    fn guidance_bearer_token() {
        let guidance = rotation_guidance("github", "bearer_token");
        assert!(!guidance.automated);
        assert!(!guidance.steps.is_empty());
        assert!(guidance.steps.iter().any(|s| s.contains("fwc auth add")));
    }

    #[test]
    fn guidance_oauth2() {
        let guidance = rotation_guidance("google", "oauth2");
        assert!(guidance.automated);
        assert!(guidance.estimated_downtime.is_none());
    }

    #[test]
    fn guidance_basic_auth() {
        let guidance = rotation_guidance("jira", "basic_auth");
        assert!(!guidance.automated);
    }

    #[test]
    fn guidance_session_token() {
        let guidance = rotation_guidance("metabase", "session_token");
        assert!(guidance.automated);
    }

    #[test]
    fn guidance_unknown() {
        let guidance = rotation_guidance("custom", "unknown_type");
        assert!(!guidance.automated);
        assert!(guidance.steps.iter().any(|s| s.contains("documentation")));
    }

    // ── check_expiry_warnings ─────────────────────────────────────

    #[test]
    fn no_warnings_for_valid_credentials() {
        let entries = vec![
            AuthMetadata::new("github", Some(now() + Duration::days(30))),
            AuthMetadata::new("slack", None),
        ];
        let warnings = check_expiry_warnings(&entries);
        assert!(warnings.is_empty());
    }

    #[test]
    fn warning_for_expiring_credential() {
        let entries = vec![
            AuthMetadata::new("github", Some(now() + Duration::days(30))),
            AuthMetadata::new("slack", Some(now() + Duration::hours(6))),
        ];
        let warnings = check_expiry_warnings(&entries);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].connector_id, "slack");
        assert_eq!(warnings[0].status, ExpiryStatus::ExpiringImminently);
    }

    #[test]
    fn warning_for_expired_credential() {
        let entries = vec![AuthMetadata::new(
            "github",
            Some(now() - Duration::hours(1)),
        )];
        let warnings = check_expiry_warnings(&entries);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].status, ExpiryStatus::Expired);
        assert!(warnings[0].message.contains("expired"));
    }

    #[test]
    fn multiple_warnings() {
        let entries = vec![
            AuthMetadata::new("github", Some(now() - Duration::hours(1))),
            AuthMetadata::new("slack", Some(now() + Duration::hours(6))),
            AuthMetadata::new("twilio", Some(now() + Duration::days(3))),
            AuthMetadata::new("jira", Some(now() + Duration::days(30))),
        ];
        let warnings = check_expiry_warnings(&entries);
        assert_eq!(warnings.len(), 3); // github, slack, twilio
    }

    // ── ExpiryWarning ─────────────────────────────────────────────

    #[test]
    fn warning_serializes() {
        let warning = ExpiryWarning {
            connector_id: "github".to_owned(),
            status: ExpiryStatus::Expired,
            message: "expired".to_owned(),
        };
        let json = serde_json::to_value(&warning).unwrap();
        assert_eq!(json["connector_id"], "github");
        assert_eq!(json["status"], "expired");
    }

    // ── RotationGuidance ──────────────────────────────────────────

    #[test]
    fn guidance_serializes() {
        let guidance = rotation_guidance("github", "bearer_token");
        let json = serde_json::to_value(&guidance).unwrap();
        assert_eq!(json["connector_id"], "github");
        assert!(!json["steps"].as_array().unwrap().is_empty());
    }

    // ── Additional AuthMetadata tests ──────────────────────────────

    #[test]
    fn metadata_multiple_rotations() {
        let mut meta = AuthMetadata::new("github", None);
        meta.record_rotation(RotationReason::Manual, Some("first".to_owned()));
        meta.record_rotation(RotationReason::Scheduled, None);
        meta.record_rotation(RotationReason::SecurityIncident, Some("breach".to_owned()));
        assert_eq!(meta.rotation_count(), 3);
        assert_eq!(meta.rotation_history[0].reason, RotationReason::Manual);
        assert_eq!(meta.rotation_history[1].reason, RotationReason::Scheduled);
        assert_eq!(
            meta.rotation_history[2].reason,
            RotationReason::SecurityIncident
        );
    }

    #[test]
    fn metadata_set_expiry_updates_field() {
        let mut meta = AuthMetadata::new("slack", None);
        assert!(!meta.has_expiry());
        assert!(!meta.is_expired());
        let future = now() + Duration::days(1);
        meta.set_expiry(future);
        assert!(meta.has_expiry());
        assert!(!meta.is_expired());
    }

    #[test]
    fn metadata_set_expiry_to_past() {
        let mut meta = AuthMetadata::new("slack", None);
        let past = now() - Duration::hours(2);
        meta.set_expiry(past);
        assert!(meta.is_expired());
    }

    #[test]
    fn metadata_mark_used_updates_timestamp() {
        let mut meta = AuthMetadata::new("github", None);
        meta.mark_used();
        let first_use = meta.last_used_at.unwrap();
        meta.mark_used();
        let second_use = meta.last_used_at.unwrap();
        assert!(second_use >= first_use);
    }

    #[test]
    fn metadata_clone() {
        let mut meta = AuthMetadata::new("github", Some(now() + Duration::days(30)));
        meta.record_rotation(RotationReason::Manual, None);
        let cloned = meta.clone();
        assert_eq!(cloned.connector_id, meta.connector_id);
        assert_eq!(cloned.rotation_count(), meta.rotation_count());
    }

    #[test]
    fn metadata_debug_format() {
        let meta = AuthMetadata::new("github", None);
        let debug = format!("{meta:?}");
        assert!(debug.contains("github"));
    }

    #[test]
    fn metadata_serde_no_expiry() {
        let meta = AuthMetadata::new("slack", None);
        let json = serde_json::to_string(&meta).unwrap();
        let restored: AuthMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.connector_id, "slack");
        assert!(!restored.has_expiry());
    }

    #[test]
    fn metadata_serde_with_rotations() {
        let mut meta = AuthMetadata::new("github", None);
        meta.record_rotation(
            RotationReason::TokenRefresh,
            Some("auto refresh".to_owned()),
        );
        meta.record_rotation(RotationReason::Expired, None);
        let json = serde_json::to_string(&meta).unwrap();
        let restored: AuthMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.rotation_count(), 2);
        assert_eq!(
            restored.rotation_history[0].notes.as_deref(),
            Some("auto refresh")
        );
        assert!(restored.rotation_history[1].notes.is_none());
    }

    #[test]
    fn metadata_serde_with_last_used() {
        let mut meta = AuthMetadata::new("jira", None);
        meta.mark_used();
        let json = serde_json::to_string(&meta).unwrap();
        let restored: AuthMetadata = serde_json::from_str(&json).unwrap();
        assert!(restored.last_used_at.is_some());
    }

    #[test]
    fn metadata_expires_within_exact_boundary() {
        // Expires in exactly 24 hours
        let exp = now() + Duration::hours(24);
        let meta = AuthMetadata::new("github", Some(exp));
        // Should expire within 24h (remaining ~= 24h, which is <= 24h)
        assert!(meta.expires_within(Duration::hours(25)));
    }

    #[test]
    fn metadata_age_non_negative() {
        let meta = AuthMetadata::new("github", None);
        assert!(meta.age().num_milliseconds() >= 0);
    }

    // ── Additional ExpiryStatus tests ──────────────────────────────

    #[test]
    fn expiry_status_serde_all_variants() {
        for (variant, expected) in [
            (ExpiryStatus::NoExpiry, "\"no_expiry\""),
            (ExpiryStatus::Valid, "\"valid\""),
            (ExpiryStatus::ExpiringSoon, "\"expiring_soon\""),
            (ExpiryStatus::ExpiringImminently, "\"expiring_imminently\""),
            (ExpiryStatus::Expired, "\"expired\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn expiry_status_display_all() {
        assert_eq!(format!("{}", ExpiryStatus::NoExpiry), "no expiry");
        assert_eq!(format!("{}", ExpiryStatus::ExpiringSoon), "expiring soon");
        assert_eq!(
            format!("{}", ExpiryStatus::ExpiringImminently),
            "expiring imminently"
        );
        assert_eq!(format!("{}", ExpiryStatus::Expired), "expired");
    }

    #[test]
    fn expiry_status_equality() {
        assert_eq!(ExpiryStatus::Valid, ExpiryStatus::Valid);
        assert_ne!(ExpiryStatus::Valid, ExpiryStatus::Expired);
    }

    #[test]
    fn expiry_status_copy() {
        let status = ExpiryStatus::ExpiringSoon;
        let copied = status;
        assert_eq!(status, copied);
    }

    // ── Additional classify_expiry tests ───────────────────────────

    #[test]
    fn classify_exactly_at_boundary_24h() {
        // Just over 24 hours is ExpiringSoon, just under is ExpiringImminently
        let meta = AuthMetadata::new("github", Some(now() + Duration::hours(23)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::ExpiringImminently);
    }

    #[test]
    fn classify_exactly_at_boundary_7d() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(6)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::ExpiringSoon);
    }

    #[test]
    fn classify_just_over_7_days() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(8)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::Valid);
    }

    #[test]
    fn classify_far_future() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(365)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::Valid);
    }

    #[test]
    fn classify_far_past() {
        let meta = AuthMetadata::new("github", Some(now() - Duration::days(365)));
        assert_eq!(classify_expiry(&meta), ExpiryStatus::Expired);
    }

    // ── Additional AuthStatusEntry tests ───────────────────────────

    #[test]
    fn status_entry_valid_no_attention() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(30)));
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert_eq!(entry.expiry_status, ExpiryStatus::Valid);
        assert!(!entry.needs_attention());
    }

    #[test]
    fn status_entry_expired_needs_attention() {
        let meta = AuthMetadata::new("github", Some(now() - Duration::hours(1)));
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert_eq!(entry.expiry_status, ExpiryStatus::Expired);
        assert!(entry.needs_attention());
        assert!(entry.time_remaining.is_some());
    }

    #[test]
    fn status_entry_expiring_imminently() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::hours(6)));
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert_eq!(entry.expiry_status, ExpiryStatus::ExpiringImminently);
        assert!(entry.needs_attention());
    }

    #[test]
    fn status_entry_serializes() {
        let meta = AuthMetadata::new("github", Some(now() + Duration::days(3)));
        let entry = AuthStatusEntry::from_metadata(&meta);
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["connector_id"], "github");
        assert_eq!(json["expiry_status"], "expiring_soon");
        assert!(json["time_remaining"].is_string());
    }

    #[test]
    fn status_entry_age_days() {
        let meta = AuthMetadata::new("github", None);
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert_eq!(entry.age_days, 0);
    }

    #[test]
    fn status_entry_with_rotations() {
        let mut meta = AuthMetadata::new("github", None);
        meta.record_rotation(RotationReason::Manual, None);
        meta.record_rotation(RotationReason::Scheduled, None);
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert_eq!(entry.rotation_count, 2);
    }

    #[test]
    fn status_entry_with_last_used() {
        let mut meta = AuthMetadata::new("github", None);
        meta.mark_used();
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert!(entry.last_used.is_some());
    }

    #[test]
    fn status_entry_expires_at_rfc3339() {
        let exp = now() + Duration::days(30);
        let meta = AuthMetadata::new("github", Some(exp));
        let entry = AuthStatusEntry::from_metadata(&meta);
        assert!(entry.expires_at.is_some());
        // Should be parseable as RFC 3339
        let parsed = DateTime::parse_from_rfc3339(entry.expires_at.as_ref().unwrap());
        assert!(parsed.is_ok());
    }

    // ── Additional format_duration tests ───────────────────────────

    #[test]
    fn format_duration_exactly_one_day() {
        let d = Duration::days(1);
        let formatted = format_duration(d);
        assert!(formatted.contains("1d"));
        assert!(formatted.contains("0h"));
    }

    #[test]
    fn format_duration_hours_and_minutes() {
        let d = Duration::hours(2) + Duration::minutes(30);
        let formatted = format_duration(d);
        assert!(formatted.contains("2h"));
        assert!(formatted.contains("30m"));
    }

    #[test]
    fn format_duration_just_minutes() {
        let d = Duration::minutes(15);
        let formatted = format_duration(d);
        assert!(formatted.contains("0h"));
        assert!(formatted.contains("15m"));
    }

    #[test]
    fn format_duration_large_value() {
        let d = Duration::days(30) + Duration::hours(12);
        let formatted = format_duration(d);
        assert!(formatted.contains("30d"));
        assert!(formatted.contains("12h"));
    }

    // ── Additional RotationReason tests ────────────────────────────

    #[test]
    fn rotation_reason_all_variants_serde_roundtrip() {
        for reason in [
            RotationReason::Manual,
            RotationReason::Expired,
            RotationReason::Scheduled,
            RotationReason::SecurityIncident,
            RotationReason::TokenRefresh,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let back: RotationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn rotation_reason_equality() {
        assert_eq!(RotationReason::Manual, RotationReason::Manual);
        assert_ne!(RotationReason::Manual, RotationReason::Expired);
    }

    #[test]
    fn rotation_reason_clone() {
        let reason = RotationReason::SecurityIncident;
        let cloned = reason.clone();
        assert_eq!(reason, cloned);
    }

    // ── Additional RotationEvent tests ─────────────────────────────

    #[test]
    fn rotation_event_serde_roundtrip() {
        let event = RotationEvent {
            rotated_at: now(),
            reason: RotationReason::Manual,
            notes: Some("test rotation".to_owned()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: RotationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.reason, RotationReason::Manual);
        assert_eq!(back.notes.as_deref(), Some("test rotation"));
    }

    #[test]
    fn rotation_event_without_notes() {
        let event = RotationEvent {
            rotated_at: now(),
            reason: RotationReason::TokenRefresh,
            notes: None,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert!(json["notes"].is_null());
    }

    #[test]
    fn rotation_event_clone() {
        let event = RotationEvent {
            rotated_at: now(),
            reason: RotationReason::Expired,
            notes: Some("auto".to_owned()),
        };
        let cloned = event.clone();
        assert_eq!(cloned.reason, event.reason);
        assert_eq!(cloned.notes, event.notes);
    }

    // ── Additional rotation_guidance tests ─────────────────────────

    #[test]
    fn guidance_bearer_token_has_four_steps() {
        let g = rotation_guidance("github", "bearer_token");
        assert_eq!(g.steps.len(), 4);
    }

    #[test]
    fn guidance_api_key_same_as_bearer() {
        let g = rotation_guidance("algolia", "api_key");
        assert!(!g.automated);
        assert!(g.estimated_downtime.is_some());
    }

    #[test]
    fn guidance_oauth2_has_three_steps() {
        let g = rotation_guidance("google", "oauth2");
        assert_eq!(g.steps.len(), 3);
    }

    #[test]
    fn guidance_basic_auth_connector_id_in_steps() {
        let g = rotation_guidance("jira", "basic_auth");
        assert!(g.steps.iter().any(|s| s.contains("jira")));
    }

    #[test]
    fn guidance_session_token_has_steps() {
        let g = rotation_guidance("metabase", "session_token");
        assert!(!g.steps.is_empty());
        assert!(g.steps.iter().any(|s| s.contains("metabase")));
    }

    #[test]
    fn guidance_unknown_mentions_documentation() {
        let g = rotation_guidance("custom", "jwt");
        assert!(g.steps.iter().any(|s| s.contains("documentation")));
    }

    // ── Additional check_expiry_warnings tests ─────────────────────

    #[test]
    fn empty_entries_no_warnings() {
        let warnings = check_expiry_warnings(&[]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn all_no_expiry_no_warnings() {
        let entries = vec![
            AuthMetadata::new("a", None),
            AuthMetadata::new("b", None),
            AuthMetadata::new("c", None),
        ];
        let warnings = check_expiry_warnings(&entries);
        assert!(warnings.is_empty());
    }

    #[test]
    fn warning_message_contains_connector_id() {
        let entries = vec![AuthMetadata::new(
            "my-connector",
            Some(now() + Duration::hours(6)),
        )];
        let warnings = check_expiry_warnings(&entries);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("my-connector"));
    }

    #[test]
    fn expiring_soon_warning_message_contains_plan() {
        let entries = vec![AuthMetadata::new("github", Some(now() + Duration::days(3)))];
        let warnings = check_expiry_warnings(&entries);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("plan rotation"));
    }

    #[test]
    fn expiring_imminently_warning_message_contains_rotate() {
        let entries = vec![AuthMetadata::new(
            "github",
            Some(now() + Duration::hours(6)),
        )];
        let warnings = check_expiry_warnings(&entries);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("rotate immediately"));
    }

    // ── ExpiryWarning tests ────────────────────────────────────────

    #[test]
    fn warning_clone() {
        let warning = ExpiryWarning {
            connector_id: "github".to_owned(),
            status: ExpiryStatus::Expired,
            message: "expired".to_owned(),
        };
        let cloned = warning.clone();
        assert_eq!(cloned.connector_id, warning.connector_id);
        assert_eq!(cloned.status, warning.status);
    }

    #[test]
    fn warning_debug_format() {
        let warning = ExpiryWarning {
            connector_id: "slack".to_owned(),
            status: ExpiryStatus::ExpiringSoon,
            message: "plan rotation".to_owned(),
        };
        let debug = format!("{warning:?}");
        assert!(debug.contains("slack"));
    }

    // ── RotationGuidance serialization ─────────────────────────────

    #[test]
    fn guidance_oauth_serializes_no_downtime() {
        let g = rotation_guidance("google", "oauth2");
        let json = serde_json::to_value(&g).unwrap();
        assert!(json["automated"].as_bool().unwrap());
        assert!(json["estimated_downtime"].is_null());
    }

    #[test]
    fn guidance_bearer_serializes_with_downtime() {
        let g = rotation_guidance("github", "bearer_token");
        let json = serde_json::to_value(&g).unwrap();
        assert!(!json["automated"].as_bool().unwrap());
        assert!(json["estimated_downtime"].is_string());
    }

    // ── RotationAdvisory ────────────────────────────────────────────

    #[test]
    fn rotation_advisory_fresh_credential() {
        let meta = AuthMetadata::new("github", None);
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::None);
        assert_eq!(advisory.age_days, 0);
        assert!(advisory.last_rotated_days.is_none());
    }

    #[test]
    fn rotation_advisory_91_days_old_suggests_rotation() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(91);
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::Suggested);
        assert!(advisory.message.contains("consider rotating"));
    }

    #[test]
    fn rotation_advisory_181_days_old_recommends_rotation() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(181);
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::Recommended);
        assert!(advisory.message.contains("rotation recommended"));
    }

    #[test]
    fn rotation_advisory_366_days_old_is_overdue() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(366);
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::Overdue);
        assert!(advisory.message.contains("overdue"));
    }

    #[test]
    fn rotation_advisory_recent_rotation_resets_clock() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(400);
        meta.last_rotated_at = Some(now() - Duration::days(10));
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::None);
        assert!(advisory.last_rotated_days.is_some());
    }

    #[test]
    fn rotation_advisory_old_rotation_still_flags() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(400);
        meta.last_rotated_at = Some(now() - Duration::days(200));
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::Recommended);
    }

    #[test]
    fn rotation_urgency_label_round_trips() {
        for u in [
            RotationUrgency::None,
            RotationUrgency::Suggested,
            RotationUrgency::Recommended,
            RotationUrgency::Overdue,
        ] {
            assert!(!u.label().is_empty());
        }
    }

    #[test]
    fn rotation_urgency_none_does_not_need_attention() {
        assert!(!RotationUrgency::None.needs_attention());
    }

    #[test]
    fn rotation_urgency_others_need_attention() {
        assert!(RotationUrgency::Suggested.needs_attention());
        assert!(RotationUrgency::Recommended.needs_attention());
        assert!(RotationUrgency::Overdue.needs_attention());
    }

    #[test]
    fn rotation_advisory_serializes() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(100);
        let advisory = rotation_advisory(&meta);
        let json = serde_json::to_value(&advisory).unwrap();
        assert_eq!(json["connector_id"], "github");
        assert_eq!(json["recommendation"], "suggested");
        assert!(json["age_days"].as_i64().unwrap() >= 100);
    }

    #[test]
    fn rotation_advisory_boundary_90_days() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(90);
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::None);
    }

    #[test]
    fn rotation_advisory_boundary_180_days() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(180);
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::Suggested);
    }

    #[test]
    fn rotation_advisory_boundary_365_days() {
        let mut meta = AuthMetadata::new("github", None);
        meta.created_at = now() - Duration::days(365);
        let advisory = rotation_advisory(&meta);
        assert_eq!(advisory.recommendation, RotationUrgency::Recommended);
    }
}
