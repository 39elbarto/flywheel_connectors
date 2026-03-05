//! Time source validation for bootstrap.
//!
//! Validates system time against NTP to detect clock drift that could
//! cause security issues with timestamps and certificates.

use chrono::{DateTime, Utc};
use std::time::Duration;

/// Result of time validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeValidationResult {
    /// Time is valid (drift < 30 seconds).
    Valid,

    /// Slight drift detected, warn user (30s - 5min).
    DriftWarning {
        /// Amount of drift detected.
        drift: Duration,
    },

    /// Significant drift, block bootstrap (> 5min).
    DriftError {
        /// Amount of drift detected.
        drift: Duration,
    },

    /// Cannot validate time (no network or NTP unreachable).
    CannotValidate,
}

impl TimeValidationResult {
    /// Check if bootstrap should proceed.
    #[must_use]
    pub const fn should_proceed(&self) -> bool {
        matches!(
            self,
            Self::Valid | Self::DriftWarning { .. } | Self::CannotValidate
        )
    }

    /// Check if this is an error that should block bootstrap.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::DriftError { .. })
    }
}

impl std::fmt::Display for TimeValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "Time validated successfully"),
            Self::DriftWarning { drift } => {
                write!(f, "Clock drift warning: {drift:?}")
            }
            Self::DriftError { drift } => {
                write!(f, "Clock drift error: {drift:?} (sync required)")
            }
            Self::CannotValidate => write!(f, "Could not validate time (no network)"),
        }
    }
}

/// Time validation state.
#[derive(Debug, Clone)]
pub struct TimeValidation {
    /// System time at validation.
    pub system_time: DateTime<Utc>,

    /// NTP time (if available).
    pub ntp_time: Option<DateTime<Utc>>,

    /// Drift detected.
    pub drift: Option<Duration>,

    /// Validation result.
    pub result: TimeValidationResult,
}

impl TimeValidation {
    /// Perform time validation against NTP.
    ///
    /// This attempts to query an NTP server to validate the system clock.
    /// If NTP is unreachable, returns `CannotValidate`.
    #[must_use]
    pub fn check() -> Self {
        let system_time = Utc::now();

        // Try NTP check with short timeout
        let ntp_result = ntp_check_with_timeout(Duration::from_secs(2));

        let (ntp_time, drift, result) =
            ntp_result.map_or((None, None, TimeValidationResult::CannotValidate), |ntp| {
                let drift = compute_drift(system_time, ntp);
                let result = classify_drift(drift);
                (Some(ntp), Some(drift), result)
            });

        Self {
            system_time,
            ntp_time,
            drift,
            result,
        }
    }

    /// Create a validation result without NTP (for testing or offline use).
    #[must_use]
    pub fn offline() -> Self {
        Self {
            system_time: Utc::now(),
            ntp_time: None,
            drift: None,
            result: TimeValidationResult::CannotValidate,
        }
    }

    /// Create a validation result with a known drift (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn with_drift(drift: Duration) -> Self {
        let system_time = Utc::now();
        let ntp_time = system_time - chrono::Duration::from_std(drift).unwrap_or_default();
        let result = classify_drift(drift);

        Self {
            system_time,
            ntp_time: Some(ntp_time),
            drift: Some(drift),
            result,
        }
    }
}

/// Compute the absolute drift between system time and NTP time.
fn compute_drift(system: DateTime<Utc>, ntp: DateTime<Utc>) -> Duration {
    let diff = (system - ntp).abs();
    diff.to_std().unwrap_or(Duration::ZERO)
}

/// Classify drift into validation result.
fn classify_drift(drift: Duration) -> TimeValidationResult {
    const WARNING_THRESHOLD: Duration = Duration::from_secs(30);
    const ERROR_THRESHOLD: Duration = Duration::from_secs(300); // 5 minutes

    if drift < WARNING_THRESHOLD {
        TimeValidationResult::Valid
    } else if drift < ERROR_THRESHOLD {
        TimeValidationResult::DriftWarning { drift }
    } else {
        TimeValidationResult::DriftError { drift }
    }
}

/// Attempt NTP check with timeout.
///
/// Returns the NTP time if successful, None otherwise.
#[cfg(unix)]
fn ntp_check_with_timeout(timeout: Duration) -> Option<DateTime<Utc>> {
    // Try well-known NTP pools
    const NTP_SERVERS: &[&str] = &[
        "pool.ntp.org:123",
        "time.google.com:123",
        "time.cloudflare.com:123",
    ];

    for server in NTP_SERVERS {
        if let Some(time) = try_ntp_server(server, timeout) {
            return Some(time);
        }
    }

    None
}

#[cfg(unix)]
fn try_ntp_server(server: &str, timeout: Duration) -> Option<DateTime<Utc>> {
    // Use rsntp crate for NTP queries
    use std::net::ToSocketAddrs;

    let addr = server.to_socket_addrs().ok()?.next()?;

    // Create a simple NTP client
    let mut client = rsntp::SntpClient::new();
    client.set_timeout(timeout);
    let result = client.synchronize(addr);

    match result {
        Ok(response) => {
            let ntp_time = response.datetime();
            // Convert to chrono DateTime via unix timestamp
            let timestamp = ntp_time.unix_timestamp().ok()?;
            let secs = i64::try_from(timestamp.as_secs()).ok()?;
            DateTime::from_timestamp(secs, 0)
        }
        Err(_) => None,
    }
}

#[cfg(windows)]
fn ntp_check_with_timeout(_timeout: Duration) -> Option<DateTime<Utc>> {
    // On Windows, use the Windows time APIs
    // This is a simplified implementation that trusts Windows time service
    // A full implementation would use NTP directly

    // For now, return None to indicate we can't validate
    // (Windows time service should keep time accurate)
    None
}

#[cfg(not(any(unix, windows)))]
fn ntp_check_with_timeout(_timeout: Duration) -> Option<DateTime<Utc>> {
    // Unsupported platform
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_drift_valid() {
        let drift = Duration::from_secs(5);
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::Valid));
    }

    #[test]
    fn test_classify_drift_warning() {
        let drift = Duration::from_secs(60);
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::DriftWarning { .. }));
    }

    #[test]
    fn test_classify_drift_error() {
        let drift = Duration::from_secs(600);
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::DriftError { .. }));
    }

    #[test]
    fn test_should_proceed() {
        assert!(TimeValidationResult::Valid.should_proceed());
        assert!(
            TimeValidationResult::DriftWarning {
                drift: Duration::from_secs(60)
            }
            .should_proceed()
        );
        assert!(TimeValidationResult::CannotValidate.should_proceed());
        assert!(
            !TimeValidationResult::DriftError {
                drift: Duration::from_secs(600)
            }
            .should_proceed()
        );
    }

    #[test]
    fn test_offline_validation() {
        let validation = TimeValidation::offline();
        assert!(matches!(
            validation.result,
            TimeValidationResult::CannotValidate
        ));
        assert!(validation.result.should_proceed());
    }

    #[test]
    fn test_with_drift() {
        let validation = TimeValidation::with_drift(Duration::from_secs(60));
        assert!(matches!(
            validation.result,
            TimeValidationResult::DriftWarning { .. }
        ));
        assert!(validation.drift.is_some());
    }

    #[test]
    fn test_is_error() {
        assert!(!TimeValidationResult::Valid.is_error());
        assert!(
            !TimeValidationResult::DriftWarning {
                drift: Duration::from_secs(60)
            }
            .is_error()
        );
        assert!(!TimeValidationResult::CannotValidate.is_error());
        assert!(
            TimeValidationResult::DriftError {
                drift: Duration::from_secs(600)
            }
            .is_error()
        );
    }

    #[test]
    fn classify_drift_boundary_warning_exactly_30s() {
        let drift = Duration::from_secs(30);
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::DriftWarning { .. }));
    }

    #[test]
    fn classify_drift_boundary_just_below_warning() {
        let drift = Duration::from_secs(29);
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::Valid));
    }

    #[test]
    fn classify_drift_boundary_error_exactly_300s() {
        let drift = Duration::from_secs(300);
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::DriftError { .. }));
    }

    #[test]
    fn classify_drift_boundary_just_below_error() {
        let drift = Duration::from_secs(299);
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::DriftWarning { .. }));
    }

    #[test]
    fn classify_drift_zero() {
        let drift = Duration::ZERO;
        let result = classify_drift(drift);
        assert!(matches!(result, TimeValidationResult::Valid));
    }

    #[test]
    fn compute_drift_zero_difference() {
        let now = Utc::now();
        let drift = compute_drift(now, now);
        assert_eq!(drift, Duration::ZERO);
    }

    #[test]
    fn compute_drift_system_ahead() {
        let now = Utc::now();
        let ntp = now - chrono::Duration::seconds(45);
        let drift = compute_drift(now, ntp);
        assert_eq!(drift.as_secs(), 45);
    }

    #[test]
    fn compute_drift_ntp_ahead() {
        let now = Utc::now();
        let ntp = now + chrono::Duration::seconds(45);
        let drift = compute_drift(now, ntp);
        assert_eq!(drift.as_secs(), 45);
    }

    #[test]
    fn display_valid() {
        let result = TimeValidationResult::Valid;
        assert_eq!(result.to_string(), "Time validated successfully");
    }

    #[test]
    fn display_drift_warning() {
        let result = TimeValidationResult::DriftWarning {
            drift: Duration::from_secs(45),
        };
        let s = result.to_string();
        assert!(s.contains("Clock drift warning"));
        assert!(s.contains("45"));
    }

    #[test]
    fn display_drift_error() {
        let result = TimeValidationResult::DriftError {
            drift: Duration::from_secs(600),
        };
        let s = result.to_string();
        assert!(s.contains("Clock drift error"));
        assert!(s.contains("sync required"));
    }

    #[test]
    fn display_cannot_validate() {
        let result = TimeValidationResult::CannotValidate;
        assert_eq!(result.to_string(), "Could not validate time (no network)");
    }

    #[test]
    fn with_drift_error_case() {
        let validation = TimeValidation::with_drift(Duration::from_secs(600));
        assert!(matches!(
            validation.result,
            TimeValidationResult::DriftError { .. }
        ));
        assert!(validation.ntp_time.is_some());
        assert_eq!(validation.drift.unwrap().as_secs(), 600);
    }

    #[test]
    fn with_drift_valid_case() {
        let validation = TimeValidation::with_drift(Duration::from_secs(1));
        assert!(matches!(validation.result, TimeValidationResult::Valid));
    }

    #[test]
    fn offline_has_no_ntp_time() {
        let validation = TimeValidation::offline();
        assert!(validation.ntp_time.is_none());
        assert!(validation.drift.is_none());
    }

    #[test]
    fn result_clone_eq() {
        let r1 = TimeValidationResult::Valid;
        let r2 = r1.clone();
        assert_eq!(r1, r2);

        let r1 = TimeValidationResult::CannotValidate;
        assert_eq!(r1, r1.clone());
    }

    #[test]
    fn result_inequality() {
        assert_ne!(
            TimeValidationResult::Valid,
            TimeValidationResult::CannotValidate
        );
        assert_ne!(
            TimeValidationResult::Valid,
            TimeValidationResult::DriftWarning {
                drift: Duration::from_secs(30)
            }
        );
    }

    #[test]
    fn debug_format_validation() {
        let validation = TimeValidation::offline();
        let debug = format!("{validation:?}");
        assert!(debug.contains("TimeValidation"));
        assert!(debug.contains("CannotValidate"));
    }
}
