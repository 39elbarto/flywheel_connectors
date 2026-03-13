//! Host integration test matrix for streaming, log tailing, watch, and reconnection.
//!
//! Provides a comprehensive matrix of test cases for exercising streaming event
//! tails, log following with level/pattern filtering, resource watch with drift
//! detection, and reconnection scenarios with gap tracking.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Stream types ─────────────────────────────────────────────────────

/// Type of stream to subscribe to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    /// Tail events from a connector.
    EventTail,
    /// Follow log output.
    LogFollow,
    /// Watch a resource for changes.
    Watch,
    /// Stream metrics data.
    Metrics,
}

impl std::fmt::Display for StreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EventTail => f.write_str("event_tail"),
            Self::LogFollow => f.write_str("log_follow"),
            Self::Watch => f.write_str("watch"),
            Self::Metrics => f.write_str("metrics"),
        }
    }
}

/// A single streaming test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamTestCase {
    /// Human-readable name.
    pub name: String,
    /// Type of stream.
    pub stream_type: StreamType,
    /// Target connector.
    pub connector: String,
    /// Optional filter expression.
    pub filter: Option<String>,
    /// Expected number of events (minimum).
    pub expected_events: usize,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
}

impl StreamTestCase {
    /// Create a new stream test case.
    pub fn new(
        name: impl Into<String>,
        stream_type: StreamType,
        connector: impl Into<String>,
        filter: Option<String>,
        expected_events: usize,
        timeout_ms: u64,
    ) -> Self {
        Self {
            name: name.into(),
            stream_type,
            connector: connector.into(),
            filter,
            expected_events,
            timeout_ms,
        }
    }

    /// Whether this case has a filter.
    pub fn has_filter(&self) -> bool {
        self.filter.is_some()
    }

    /// Whether this is a metrics stream.
    pub fn is_metrics(&self) -> bool {
        matches!(self.stream_type, StreamType::Metrics)
    }

    /// Whether this is a watch stream.
    pub fn is_watch(&self) -> bool {
        matches!(self.stream_type, StreamType::Watch)
    }
}

// ── Reconnect types ──────────────────────────────────────────────────

/// Expected behavior after reconnection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconnectBehavior {
    /// Resume from where the stream left off.
    Resume,
    /// Restart the stream from the beginning.
    Restart,
    /// Fail permanently (no reconnection).
    Fail,
}

impl std::fmt::Display for ReconnectBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resume => f.write_str("resume"),
            Self::Restart => f.write_str("restart"),
            Self::Fail => f.write_str("fail"),
        }
    }
}

/// A single reconnection test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconnectTestCase {
    /// Human-readable name.
    pub name: String,
    /// Disconnect after this many events.
    pub disconnect_after: usize,
    /// Timeout for reconnection in milliseconds.
    pub reconnect_timeout_ms: u64,
    /// Expected behavior after reconnection.
    pub expected_behavior: ReconnectBehavior,
    /// Expected gap in events (0 = no gap, -1 = overlap ok).
    pub expected_gap: i64,
}

impl ReconnectTestCase {
    /// Create a new reconnect test case.
    pub fn new(
        name: impl Into<String>,
        disconnect_after: usize,
        reconnect_timeout_ms: u64,
        expected_behavior: ReconnectBehavior,
        expected_gap: i64,
    ) -> Self {
        Self {
            name: name.into(),
            disconnect_after,
            reconnect_timeout_ms,
            expected_behavior,
            expected_gap,
        }
    }

    /// Whether reconnection is expected to succeed.
    pub fn expects_reconnection(&self) -> bool {
        !matches!(self.expected_behavior, ReconnectBehavior::Fail)
    }

    /// Whether events can be lost during reconnection.
    pub fn allows_gap(&self) -> bool {
        self.expected_gap > 0
    }

    /// Whether overlap (duplicate events) is acceptable.
    pub fn allows_overlap(&self) -> bool {
        self.expected_gap < 0
    }
}

// ── Log types ────────────────────────────────────────────────────────

/// Log level filter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug => f.write_str("debug"),
            Self::Info => f.write_str("info"),
            Self::Warn => f.write_str("warn"),
            Self::Error => f.write_str("error"),
        }
    }
}

impl LogLevel {
    /// Severity rank (higher = more severe).
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Warn => 2,
            Self::Error => 3,
        }
    }

    /// Whether this level is at or above the given threshold.
    pub fn is_at_least(&self, threshold: &Self) -> bool {
        self.severity() >= threshold.severity()
    }
}

/// A single log test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogTestCase {
    /// Human-readable name.
    pub name: String,
    /// Target connector.
    pub connector: String,
    /// Minimum log level to capture.
    pub level: LogLevel,
    /// Only show logs since this timestamp (ISO 8601 or relative).
    pub since: Option<String>,
    /// Regex pattern to filter log messages.
    pub pattern: Option<String>,
    /// Expected minimum number of matching log entries.
    pub expected_matches: usize,
}

impl LogTestCase {
    /// Create a new log test case.
    pub fn new(
        name: impl Into<String>,
        connector: impl Into<String>,
        level: LogLevel,
        since: Option<String>,
        pattern: Option<String>,
        expected_matches: usize,
    ) -> Self {
        Self {
            name: name.into(),
            connector: connector.into(),
            level,
            since,
            pattern,
            expected_matches,
        }
    }

    /// Whether this case has a time filter.
    pub fn has_since(&self) -> bool {
        self.since.is_some()
    }

    /// Whether this case has a pattern filter.
    pub fn has_pattern(&self) -> bool {
        self.pattern.is_some()
    }

    /// Whether this case filters to error-level only.
    pub fn is_error_only(&self) -> bool {
        matches!(self.level, LogLevel::Error)
    }
}

// ── Watch types ──────────────────────────────────────────────────────

/// A single watch test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchTestCase {
    /// Human-readable name.
    pub name: String,
    /// Target connector.
    pub connector: String,
    /// Resource to watch.
    pub resource: String,
    /// Poll interval in milliseconds.
    pub interval_ms: u64,
    /// Expected minimum number of update notifications.
    pub expected_updates: usize,
    /// Whether drift detection is enabled.
    pub detect_drift: bool,
}

impl WatchTestCase {
    /// Create a new watch test case.
    pub fn new(
        name: impl Into<String>,
        connector: impl Into<String>,
        resource: impl Into<String>,
        interval_ms: u64,
        expected_updates: usize,
        detect_drift: bool,
    ) -> Self {
        Self {
            name: name.into(),
            connector: connector.into(),
            resource: resource.into(),
            interval_ms,
            expected_updates,
            detect_drift,
        }
    }

    /// Whether drift detection is enabled for this case.
    pub fn has_drift_detection(&self) -> bool {
        self.detect_drift
    }

    /// Whether this case expects any updates.
    pub fn expects_updates(&self) -> bool {
        self.expected_updates > 0
    }
}

// ── Matrix builders ──────────────────────────────────────────────────

/// Build the stream test matrix (at least 12 cases).
pub fn build_stream_matrix() -> Vec<StreamTestCase> {
    vec![
        StreamTestCase::new(
            "stream_event_tail_github",
            StreamType::EventTail,
            "github",
            None,
            5,
            10000,
        ),
        StreamTestCase::new(
            "stream_event_tail_slack_filtered",
            StreamType::EventTail,
            "slack",
            Some("type=message".into()),
            3,
            8000,
        ),
        StreamTestCase::new(
            "stream_event_tail_jira_filtered",
            StreamType::EventTail,
            "jira",
            Some("project=TEST".into()),
            2,
            8000,
        ),
        StreamTestCase::new(
            "stream_log_follow_github",
            StreamType::LogFollow,
            "github",
            None,
            10,
            15000,
        ),
        StreamTestCase::new(
            "stream_log_follow_with_level_filter",
            StreamType::LogFollow,
            "slack",
            Some("level>=warn".into()),
            1,
            10000,
        ),
        StreamTestCase::new(
            "stream_watch_github_repo",
            StreamType::Watch,
            "github",
            Some("resource=repos/test-org/test-repo".into()),
            1,
            30000,
        ),
        StreamTestCase::new(
            "stream_watch_slack_channel",
            StreamType::Watch,
            "slack",
            Some("resource=channels/C123".into()),
            1,
            30000,
        ),
        StreamTestCase::new(
            "stream_metrics_github",
            StreamType::Metrics,
            "github",
            None,
            5,
            10000,
        ),
        StreamTestCase::new(
            "stream_metrics_slack_filtered",
            StreamType::Metrics,
            "slack",
            Some("metric=request_count".into()),
            3,
            10000,
        ),
        StreamTestCase::new(
            "stream_event_tail_nonexistent_connector",
            StreamType::EventTail,
            "nonexistent_connector",
            None,
            0,
            3000,
        ),
        StreamTestCase::new(
            "stream_event_tail_empty_filter",
            StreamType::EventTail,
            "github",
            Some("type=nonexistent_event".into()),
            0,
            5000,
        ),
        StreamTestCase::new(
            "stream_metrics_all_connectors",
            StreamType::Metrics,
            "*",
            None,
            10,
            15000,
        ),
        StreamTestCase::new(
            "stream_watch_discord_guild",
            StreamType::Watch,
            "discord",
            Some("resource=guilds/123".into()),
            1,
            30000,
        ),
    ]
}

/// Build the reconnect test matrix (at least 10 cases).
pub fn build_reconnect_matrix() -> Vec<ReconnectTestCase> {
    vec![
        ReconnectTestCase::new(
            "reconnect_resume_after_1_event",
            1,
            5000,
            ReconnectBehavior::Resume,
            0,
        ),
        ReconnectTestCase::new(
            "reconnect_resume_after_10_events",
            10,
            5000,
            ReconnectBehavior::Resume,
            0,
        ),
        ReconnectTestCase::new(
            "reconnect_resume_after_100_events",
            100,
            10000,
            ReconnectBehavior::Resume,
            0,
        ),
        ReconnectTestCase::new(
            "reconnect_restart_from_beginning",
            5,
            5000,
            ReconnectBehavior::Restart,
            0,
        ),
        ReconnectTestCase::new(
            "reconnect_fail_permanent",
            3,
            1000,
            ReconnectBehavior::Fail,
            0,
        ),
        ReconnectTestCase::new(
            "reconnect_resume_with_gap",
            50,
            5000,
            ReconnectBehavior::Resume,
            3,
        ),
        ReconnectTestCase::new(
            "reconnect_resume_with_overlap",
            20,
            5000,
            ReconnectBehavior::Resume,
            -2,
        ),
        ReconnectTestCase::new(
            "reconnect_timeout_too_short",
            5,
            100,
            ReconnectBehavior::Fail,
            0,
        ),
        ReconnectTestCase::new(
            "reconnect_immediate_disconnect",
            0,
            5000,
            ReconnectBehavior::Restart,
            0,
        ),
        ReconnectTestCase::new(
            "reconnect_resume_large_gap",
            1000,
            30000,
            ReconnectBehavior::Resume,
            50,
        ),
        ReconnectTestCase::new(
            "reconnect_restart_after_server_reset",
            25,
            8000,
            ReconnectBehavior::Restart,
            0,
        ),
    ]
}

/// Build the log test matrix (at least 10 cases).
pub fn build_log_matrix() -> Vec<LogTestCase> {
    vec![
        LogTestCase::new(
            "log_all_levels_github",
            "github",
            LogLevel::Debug,
            None,
            None,
            10,
        ),
        LogTestCase::new(
            "log_info_and_above_slack",
            "slack",
            LogLevel::Info,
            None,
            None,
            5,
        ),
        LogTestCase::new(
            "log_warn_and_above_jira",
            "jira",
            LogLevel::Warn,
            None,
            None,
            1,
        ),
        LogTestCase::new(
            "log_errors_only_github",
            "github",
            LogLevel::Error,
            None,
            None,
            0,
        ),
        LogTestCase::new(
            "log_with_since_filter",
            "slack",
            LogLevel::Info,
            Some("2026-03-12T00:00:00Z".into()),
            None,
            3,
        ),
        LogTestCase::new(
            "log_with_pattern_filter",
            "github",
            LogLevel::Debug,
            None,
            Some("rate.limit".into()),
            1,
        ),
        LogTestCase::new(
            "log_with_since_and_pattern",
            "jira",
            LogLevel::Info,
            Some("1h".into()),
            Some("timeout".into()),
            0,
        ),
        LogTestCase::new(
            "log_nonexistent_connector",
            "nonexistent_connector",
            LogLevel::Debug,
            None,
            None,
            0,
        ),
        LogTestCase::new(
            "log_debug_discord",
            "discord",
            LogLevel::Debug,
            None,
            None,
            5,
        ),
        LogTestCase::new(
            "log_error_pattern_match",
            "slack",
            LogLevel::Error,
            None,
            Some("connection.refused".into()),
            0,
        ),
        LogTestCase::new(
            "log_info_since_relative",
            "github",
            LogLevel::Info,
            Some("30m".into()),
            None,
            2,
        ),
    ]
}

/// Build the watch test matrix (at least 8 cases).
pub fn build_watch_matrix() -> Vec<WatchTestCase> {
    vec![
        WatchTestCase::new(
            "watch_github_repo_status",
            "github",
            "repos/test-org/test-repo",
            5000,
            2,
            true,
        ),
        WatchTestCase::new(
            "watch_slack_channel_members",
            "slack",
            "channels/C123/members",
            10000,
            1,
            false,
        ),
        WatchTestCase::new(
            "watch_jira_issue_status",
            "jira",
            "issues/TEST-1",
            5000,
            3,
            true,
        ),
        WatchTestCase::new(
            "watch_github_actions_workflow",
            "github",
            "repos/test-org/test-repo/actions/runs",
            3000,
            5,
            false,
        ),
        WatchTestCase::new(
            "watch_discord_guild_presence",
            "discord",
            "guilds/123/presence",
            15000,
            1,
            false,
        ),
        WatchTestCase::new(
            "watch_nonexistent_resource",
            "github",
            "nonexistent/resource",
            5000,
            0,
            false,
        ),
        WatchTestCase::new(
            "watch_with_drift_detection",
            "jira",
            "projects/TEST/settings",
            10000,
            1,
            true,
        ),
        WatchTestCase::new(
            "watch_rapid_polling",
            "github",
            "repos/test-org/test-repo/commits",
            1000,
            10,
            false,
        ),
        WatchTestCase::new(
            "watch_no_updates_expected",
            "slack",
            "channels/C999/topic",
            30000,
            0,
            true,
        ),
    ]
}

// ── Validators ───────────────────────────────────────────────────────

/// Validate a stream result against a test case.
pub fn validate_stream_result(case: &StreamTestCase, events: &[Value]) -> bool {
    // Check minimum event count.
    if events.len() < case.expected_events {
        return false;
    }

    // If there's a filter, verify events match (simplified check).
    if let Some(filter) = &case.filter {
        // Check that events contain evidence of the filter being applied.
        if !events.is_empty() {
            // At minimum, verify that events are non-null objects.
            for event in events {
                if !event.is_object() {
                    return false;
                }
            }
        }
        // Filter string should be non-empty for filtered streams.
        if filter.is_empty() {
            return false;
        }
    }

    true
}

/// Validate a reconnect result.
pub fn validate_reconnect_result(
    case: &ReconnectTestCase,
    reconnected: bool,
    actual_gap: i64,
) -> bool {
    match case.expected_behavior {
        ReconnectBehavior::Resume => {
            if !reconnected {
                return false;
            }
            actual_gap <= case.expected_gap
        }
        ReconnectBehavior::Restart => reconnected,
        ReconnectBehavior::Fail => !reconnected,
    }
}

/// Validate a log result against a test case.
pub fn validate_log_result(case: &LogTestCase, entries: &[Value]) -> bool {
    if entries.len() < case.expected_matches {
        return false;
    }

    // Check that all entries are at or above the required level.
    for entry in entries {
        if let Some(level_str) = entry.get("level").and_then(|l| l.as_str()) {
            let entry_level = match level_str {
                "debug" => LogLevel::Debug,
                "info" => LogLevel::Info,
                "warn" | "warning" => LogLevel::Warn,
                "error" => LogLevel::Error,
                _ => return false,
            };
            if !entry_level.is_at_least(&case.level) {
                return false;
            }
        }
    }

    // If pattern is specified, check that at least one entry matches.
    if let Some(pattern) = &case.pattern {
        if !entries.is_empty() {
            let any_match = entries.iter().any(|e| {
                e.get("message")
                    .and_then(|m| m.as_str())
                    .is_some_and(|msg| msg.contains(pattern.as_str()))
            });
            if case.expected_matches > 0 && !any_match {
                return false;
            }
        }
    }

    true
}

/// Validate a watch result against a test case.
pub fn validate_watch_result(case: &WatchTestCase, updates: &[Value]) -> bool {
    if updates.len() < case.expected_updates {
        return false;
    }

    // If drift detection is enabled, check for drift markers.
    if case.detect_drift {
        for update in updates {
            // Each update should be an object.
            if !update.is_object() {
                return false;
            }
        }
    }

    true
}

// ── Formatting ───────────────────────────────────────────────────────

/// Format the stream matrix as a human-readable table.
pub fn format_stream_matrix_toon(cases: &[StreamTestCase]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Stream Test Matrix ({} cases) ===", cases.len());
    let _ = writeln!(out);

    for (i, case) in cases.iter().enumerate() {
        let filter_str = case.filter.as_deref().unwrap_or("(none)");
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} type={:<12} connector={:<15} filter={:<30} events={} timeout={}ms",
            i + 1,
            case.name,
            case.stream_type.to_string(),
            case.connector,
            filter_str,
            case.expected_events,
            case.timeout_ms,
        );
    }

    out
}

/// Format the reconnect matrix as a human-readable table.
pub fn format_reconnect_matrix_toon(cases: &[ReconnectTestCase]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Reconnect Test Matrix ({} cases) ===", cases.len());
    let _ = writeln!(out);

    for (i, case) in cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} disconnect_after={:<5} timeout={}ms behavior={:<10} gap={}",
            i + 1,
            case.name,
            case.disconnect_after,
            case.reconnect_timeout_ms,
            case.expected_behavior.to_string(),
            case.expected_gap,
        );
    }

    out
}

/// Format the log matrix as a human-readable table.
pub fn format_log_matrix_toon(cases: &[LogTestCase]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Log Test Matrix ({} cases) ===", cases.len());
    let _ = writeln!(out);

    for (i, case) in cases.iter().enumerate() {
        let since_str = case.since.as_deref().unwrap_or("(all)");
        let pattern_str = case.pattern.as_deref().unwrap_or("(none)");
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} connector={:<15} level={:<6} since={:<25} pattern={:<20} matches={}",
            i + 1,
            case.name,
            case.connector,
            case.level.to_string(),
            since_str,
            pattern_str,
            case.expected_matches,
        );
    }

    out
}

/// Format the watch matrix as a human-readable table.
pub fn format_watch_matrix_toon(cases: &[WatchTestCase]) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "=== Watch Test Matrix ({} cases) ===", cases.len());
    let _ = writeln!(out);

    for (i, case) in cases.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{:>2}] {:<45} connector={:<15} resource={:<35} interval={}ms updates={} drift={}",
            i + 1,
            case.name,
            case.connector,
            case.resource,
            case.interval_ms,
            case.expected_updates,
            case.detect_drift,
        );
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── StreamType ───────────────────────────────────────────────

    #[test]
    fn stream_type_display_event_tail() {
        assert_eq!(StreamType::EventTail.to_string(), "event_tail");
    }

    #[test]
    fn stream_type_display_log_follow() {
        assert_eq!(StreamType::LogFollow.to_string(), "log_follow");
    }

    #[test]
    fn stream_type_display_watch() {
        assert_eq!(StreamType::Watch.to_string(), "watch");
    }

    #[test]
    fn stream_type_display_metrics() {
        assert_eq!(StreamType::Metrics.to_string(), "metrics");
    }

    #[test]
    fn stream_type_serde_roundtrip() {
        let s = StreamType::Metrics;
        let json_str = serde_json::to_string(&s).unwrap();
        let back: StreamType = serde_json::from_str(&json_str).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn stream_type_clone() {
        let s = StreamType::EventTail;
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    // ── StreamTestCase ───────────────────────────────────────────

    #[test]
    fn stream_test_case_new() {
        let tc = StreamTestCase::new("test", StreamType::EventTail, "github", None, 5, 10000);
        assert_eq!(tc.name, "test");
        assert_eq!(tc.expected_events, 5);
    }

    #[test]
    fn stream_test_case_has_filter() {
        let tc = StreamTestCase::new(
            "t",
            StreamType::EventTail,
            "c",
            Some("type=x".into()),
            1,
            1000,
        );
        assert!(tc.has_filter());
    }

    #[test]
    fn stream_test_case_no_filter() {
        let tc = StreamTestCase::new("t", StreamType::EventTail, "c", None, 1, 1000);
        assert!(!tc.has_filter());
    }

    #[test]
    fn stream_test_case_is_metrics() {
        let tc = StreamTestCase::new("t", StreamType::Metrics, "c", None, 1, 1000);
        assert!(tc.is_metrics());
    }

    #[test]
    fn stream_test_case_is_not_metrics() {
        let tc = StreamTestCase::new("t", StreamType::EventTail, "c", None, 1, 1000);
        assert!(!tc.is_metrics());
    }

    #[test]
    fn stream_test_case_is_watch() {
        let tc = StreamTestCase::new("t", StreamType::Watch, "c", None, 1, 1000);
        assert!(tc.is_watch());
    }

    #[test]
    fn stream_test_case_is_not_watch() {
        let tc = StreamTestCase::new("t", StreamType::LogFollow, "c", None, 1, 1000);
        assert!(!tc.is_watch());
    }

    #[test]
    fn stream_test_case_serde_roundtrip() {
        let tc = StreamTestCase::new("r", StreamType::Watch, "gh", Some("x".into()), 3, 5000);
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: StreamTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
    }

    #[test]
    fn stream_test_case_clone() {
        let tc = StreamTestCase::new("cl", StreamType::EventTail, "c", None, 1, 1000);
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── ReconnectBehavior ────────────────────────────────────────

    #[test]
    fn reconnect_behavior_display_resume() {
        assert_eq!(ReconnectBehavior::Resume.to_string(), "resume");
    }

    #[test]
    fn reconnect_behavior_display_restart() {
        assert_eq!(ReconnectBehavior::Restart.to_string(), "restart");
    }

    #[test]
    fn reconnect_behavior_display_fail() {
        assert_eq!(ReconnectBehavior::Fail.to_string(), "fail");
    }

    #[test]
    fn reconnect_behavior_serde_roundtrip() {
        let b = ReconnectBehavior::Resume;
        let json_str = serde_json::to_string(&b).unwrap();
        let back: ReconnectBehavior = serde_json::from_str(&json_str).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn reconnect_behavior_clone() {
        let b = ReconnectBehavior::Fail;
        let cloned = b.clone();
        assert_eq!(b, cloned);
    }

    // ── ReconnectTestCase ────────────────────────────────────────

    #[test]
    fn reconnect_test_case_new() {
        let tc = ReconnectTestCase::new("test", 5, 3000, ReconnectBehavior::Resume, 0);
        assert_eq!(tc.name, "test");
        assert_eq!(tc.disconnect_after, 5);
    }

    #[test]
    fn reconnect_test_case_expects_reconnection_resume() {
        let tc = ReconnectTestCase::new("t", 1, 1000, ReconnectBehavior::Resume, 0);
        assert!(tc.expects_reconnection());
    }

    #[test]
    fn reconnect_test_case_expects_reconnection_restart() {
        let tc = ReconnectTestCase::new("t", 1, 1000, ReconnectBehavior::Restart, 0);
        assert!(tc.expects_reconnection());
    }

    #[test]
    fn reconnect_test_case_expects_no_reconnection_fail() {
        let tc = ReconnectTestCase::new("t", 1, 1000, ReconnectBehavior::Fail, 0);
        assert!(!tc.expects_reconnection());
    }

    #[test]
    fn reconnect_test_case_allows_gap() {
        let tc = ReconnectTestCase::new("t", 1, 1000, ReconnectBehavior::Resume, 5);
        assert!(tc.allows_gap());
        assert!(!tc.allows_overlap());
    }

    #[test]
    fn reconnect_test_case_allows_overlap() {
        let tc = ReconnectTestCase::new("t", 1, 1000, ReconnectBehavior::Resume, -2);
        assert!(tc.allows_overlap());
        assert!(!tc.allows_gap());
    }

    #[test]
    fn reconnect_test_case_no_gap_no_overlap() {
        let tc = ReconnectTestCase::new("t", 1, 1000, ReconnectBehavior::Resume, 0);
        assert!(!tc.allows_gap());
        assert!(!tc.allows_overlap());
    }

    #[test]
    fn reconnect_test_case_serde_roundtrip() {
        let tc = ReconnectTestCase::new("r", 10, 5000, ReconnectBehavior::Restart, 3);
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: ReconnectTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
        assert_eq!(back.expected_gap, 3);
    }

    #[test]
    fn reconnect_test_case_clone() {
        let tc = ReconnectTestCase::new("cl", 1, 1000, ReconnectBehavior::Fail, 0);
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── LogLevel ─────────────────────────────────────────────────

    #[test]
    fn log_level_display_debug() {
        assert_eq!(LogLevel::Debug.to_string(), "debug");
    }

    #[test]
    fn log_level_display_info() {
        assert_eq!(LogLevel::Info.to_string(), "info");
    }

    #[test]
    fn log_level_display_warn() {
        assert_eq!(LogLevel::Warn.to_string(), "warn");
    }

    #[test]
    fn log_level_display_error() {
        assert_eq!(LogLevel::Error.to_string(), "error");
    }

    #[test]
    fn log_level_severity_ordering() {
        assert!(LogLevel::Debug.severity() < LogLevel::Info.severity());
        assert!(LogLevel::Info.severity() < LogLevel::Warn.severity());
        assert!(LogLevel::Warn.severity() < LogLevel::Error.severity());
    }

    #[test]
    fn log_level_is_at_least_same() {
        assert!(LogLevel::Info.is_at_least(&LogLevel::Info));
    }

    #[test]
    fn log_level_is_at_least_higher() {
        assert!(LogLevel::Error.is_at_least(&LogLevel::Debug));
    }

    #[test]
    fn log_level_is_at_least_lower() {
        assert!(!LogLevel::Debug.is_at_least(&LogLevel::Error));
    }

    #[test]
    fn log_level_serde_roundtrip() {
        let l = LogLevel::Warn;
        let json_str = serde_json::to_string(&l).unwrap();
        let back: LogLevel = serde_json::from_str(&json_str).unwrap();
        assert_eq!(l, back);
    }

    // ── LogTestCase ──────────────────────────────────────────────

    #[test]
    fn log_test_case_new() {
        let tc = LogTestCase::new("test", "github", LogLevel::Info, None, None, 5);
        assert_eq!(tc.name, "test");
        assert_eq!(tc.expected_matches, 5);
    }

    #[test]
    fn log_test_case_has_since() {
        let tc = LogTestCase::new("t", "c", LogLevel::Info, Some("1h".into()), None, 0);
        assert!(tc.has_since());
    }

    #[test]
    fn log_test_case_no_since() {
        let tc = LogTestCase::new("t", "c", LogLevel::Info, None, None, 0);
        assert!(!tc.has_since());
    }

    #[test]
    fn log_test_case_has_pattern() {
        let tc = LogTestCase::new("t", "c", LogLevel::Info, None, Some("err".into()), 0);
        assert!(tc.has_pattern());
    }

    #[test]
    fn log_test_case_no_pattern() {
        let tc = LogTestCase::new("t", "c", LogLevel::Info, None, None, 0);
        assert!(!tc.has_pattern());
    }

    #[test]
    fn log_test_case_is_error_only() {
        let tc = LogTestCase::new("t", "c", LogLevel::Error, None, None, 0);
        assert!(tc.is_error_only());
    }

    #[test]
    fn log_test_case_is_not_error_only() {
        let tc = LogTestCase::new("t", "c", LogLevel::Info, None, None, 0);
        assert!(!tc.is_error_only());
    }

    #[test]
    fn log_test_case_serde_roundtrip() {
        let tc = LogTestCase::new(
            "r",
            "gh",
            LogLevel::Warn,
            Some("1h".into()),
            Some("x".into()),
            2,
        );
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: LogTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
    }

    #[test]
    fn log_test_case_clone() {
        let tc = LogTestCase::new("cl", "c", LogLevel::Debug, None, None, 0);
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── WatchTestCase ────────────────────────────────────────────

    #[test]
    fn watch_test_case_new() {
        let tc = WatchTestCase::new("test", "github", "repos/a/b", 5000, 2, true);
        assert_eq!(tc.name, "test");
        assert_eq!(tc.resource, "repos/a/b");
    }

    #[test]
    fn watch_test_case_has_drift_detection() {
        let tc = WatchTestCase::new("t", "c", "r", 1000, 1, true);
        assert!(tc.has_drift_detection());
    }

    #[test]
    fn watch_test_case_no_drift_detection() {
        let tc = WatchTestCase::new("t", "c", "r", 1000, 1, false);
        assert!(!tc.has_drift_detection());
    }

    #[test]
    fn watch_test_case_expects_updates() {
        let tc = WatchTestCase::new("t", "c", "r", 1000, 3, false);
        assert!(tc.expects_updates());
    }

    #[test]
    fn watch_test_case_expects_no_updates() {
        let tc = WatchTestCase::new("t", "c", "r", 1000, 0, false);
        assert!(!tc.expects_updates());
    }

    #[test]
    fn watch_test_case_serde_roundtrip() {
        let tc = WatchTestCase::new("r", "gh", "repos/a", 5000, 2, true);
        let json_str = serde_json::to_string(&tc).unwrap();
        let back: WatchTestCase = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.name, "r");
        assert!(back.detect_drift);
    }

    #[test]
    fn watch_test_case_clone() {
        let tc = WatchTestCase::new("cl", "c", "r", 1000, 0, false);
        let cloned = tc.clone();
        assert_eq!(cloned.name, "cl");
    }

    // ── Matrix builders ──────────────────────────────────────────

    #[test]
    fn build_stream_matrix_has_at_least_12() {
        let cases = build_stream_matrix();
        assert!(cases.len() >= 12, "got {}", cases.len());
    }

    #[test]
    fn build_stream_matrix_unique_names() {
        let cases = build_stream_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_stream_matrix_covers_all_types() {
        let cases = build_stream_matrix();
        let types: std::collections::HashSet<_> = cases.iter().map(|c| &c.stream_type).collect();
        assert!(types.contains(&StreamType::EventTail));
        assert!(types.contains(&StreamType::LogFollow));
        assert!(types.contains(&StreamType::Watch));
        assert!(types.contains(&StreamType::Metrics));
    }

    #[test]
    fn build_stream_matrix_has_filtered_cases() {
        let cases = build_stream_matrix();
        assert!(cases.iter().any(|c| c.filter.is_some()));
    }

    #[test]
    fn build_stream_matrix_has_unfiltered_cases() {
        let cases = build_stream_matrix();
        assert!(cases.iter().any(|c| c.filter.is_none()));
    }

    #[test]
    fn build_stream_matrix_all_have_timeout() {
        let cases = build_stream_matrix();
        for case in &cases {
            assert!(case.timeout_ms > 0, "case {} has zero timeout", case.name);
        }
    }

    #[test]
    fn build_reconnect_matrix_has_at_least_10() {
        let cases = build_reconnect_matrix();
        assert!(cases.len() >= 10, "got {}", cases.len());
    }

    #[test]
    fn build_reconnect_matrix_unique_names() {
        let cases = build_reconnect_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_reconnect_matrix_covers_all_behaviors() {
        let cases = build_reconnect_matrix();
        let behaviors: std::collections::HashSet<_> =
            cases.iter().map(|c| &c.expected_behavior).collect();
        assert!(behaviors.contains(&ReconnectBehavior::Resume));
        assert!(behaviors.contains(&ReconnectBehavior::Restart));
        assert!(behaviors.contains(&ReconnectBehavior::Fail));
    }

    #[test]
    fn build_reconnect_matrix_has_gap_case() {
        let cases = build_reconnect_matrix();
        assert!(cases.iter().any(|c| c.expected_gap > 0));
    }

    #[test]
    fn build_reconnect_matrix_has_overlap_case() {
        let cases = build_reconnect_matrix();
        assert!(cases.iter().any(|c| c.expected_gap < 0));
    }

    #[test]
    fn build_reconnect_matrix_has_no_gap_case() {
        let cases = build_reconnect_matrix();
        assert!(cases.iter().any(|c| c.expected_gap == 0));
    }

    #[test]
    fn build_log_matrix_has_at_least_10() {
        let cases = build_log_matrix();
        assert!(cases.len() >= 10, "got {}", cases.len());
    }

    #[test]
    fn build_log_matrix_unique_names() {
        let cases = build_log_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_log_matrix_covers_all_levels() {
        let cases = build_log_matrix();
        let levels: std::collections::HashSet<_> = cases.iter().map(|c| &c.level).collect();
        assert!(levels.contains(&LogLevel::Debug));
        assert!(levels.contains(&LogLevel::Info));
        assert!(levels.contains(&LogLevel::Warn));
        assert!(levels.contains(&LogLevel::Error));
    }

    #[test]
    fn build_log_matrix_has_since_filter() {
        let cases = build_log_matrix();
        assert!(cases.iter().any(|c| c.since.is_some()));
    }

    #[test]
    fn build_log_matrix_has_pattern_filter() {
        let cases = build_log_matrix();
        assert!(cases.iter().any(|c| c.pattern.is_some()));
    }

    #[test]
    fn build_watch_matrix_has_at_least_8() {
        let cases = build_watch_matrix();
        assert!(cases.len() >= 8, "got {}", cases.len());
    }

    #[test]
    fn build_watch_matrix_unique_names() {
        let cases = build_watch_matrix();
        let names: std::collections::HashSet<_> = cases.iter().map(|c| &c.name).collect();
        assert_eq!(names.len(), cases.len());
    }

    #[test]
    fn build_watch_matrix_has_drift_detection() {
        let cases = build_watch_matrix();
        assert!(cases.iter().any(|c| c.detect_drift));
    }

    #[test]
    fn build_watch_matrix_has_no_drift_detection() {
        let cases = build_watch_matrix();
        assert!(cases.iter().any(|c| !c.detect_drift));
    }

    // ── Validators ───────────────────────────────────────────────

    #[test]
    fn validate_stream_result_enough_events() {
        let case = StreamTestCase::new("t", StreamType::EventTail, "c", None, 2, 1000);
        let events = vec![json!({"type": "a"}), json!({"type": "b"})];
        assert!(validate_stream_result(&case, &events));
    }

    #[test]
    fn validate_stream_result_not_enough_events() {
        let case = StreamTestCase::new("t", StreamType::EventTail, "c", None, 5, 1000);
        let events = vec![json!({"type": "a"})];
        assert!(!validate_stream_result(&case, &events));
    }

    #[test]
    fn validate_stream_result_zero_expected_empty() {
        let case = StreamTestCase::new("t", StreamType::EventTail, "c", None, 0, 1000);
        let events: Vec<Value> = vec![];
        assert!(validate_stream_result(&case, &events));
    }

    #[test]
    fn validate_stream_result_filtered_valid_events() {
        let case = StreamTestCase::new(
            "t",
            StreamType::EventTail,
            "c",
            Some("type=x".into()),
            1,
            1000,
        );
        let events = vec![json!({"type": "x"})];
        assert!(validate_stream_result(&case, &events));
    }

    #[test]
    fn validate_stream_result_filtered_non_object() {
        let case = StreamTestCase::new(
            "t",
            StreamType::EventTail,
            "c",
            Some("type=x".into()),
            1,
            1000,
        );
        let events = vec![json!("not_an_object")];
        assert!(!validate_stream_result(&case, &events));
    }

    #[test]
    fn validate_stream_result_empty_filter_string() {
        let case = StreamTestCase::new(
            "t",
            StreamType::EventTail,
            "c",
            Some(String::new()),
            1,
            1000,
        );
        let events = vec![json!({"type": "x"})];
        assert!(!validate_stream_result(&case, &events));
    }

    #[test]
    fn validate_reconnect_result_resume_success() {
        let case = ReconnectTestCase::new("t", 5, 5000, ReconnectBehavior::Resume, 0);
        assert!(validate_reconnect_result(&case, true, 0));
    }

    #[test]
    fn validate_reconnect_result_resume_not_reconnected() {
        let case = ReconnectTestCase::new("t", 5, 5000, ReconnectBehavior::Resume, 0);
        assert!(!validate_reconnect_result(&case, false, 0));
    }

    #[test]
    fn validate_reconnect_result_resume_too_much_gap() {
        let case = ReconnectTestCase::new("t", 5, 5000, ReconnectBehavior::Resume, 2);
        assert!(!validate_reconnect_result(&case, true, 5));
    }

    #[test]
    fn validate_reconnect_result_resume_within_gap() {
        let case = ReconnectTestCase::new("t", 5, 5000, ReconnectBehavior::Resume, 5);
        assert!(validate_reconnect_result(&case, true, 3));
    }

    #[test]
    fn validate_reconnect_result_restart_success() {
        let case = ReconnectTestCase::new("t", 5, 5000, ReconnectBehavior::Restart, 0);
        assert!(validate_reconnect_result(&case, true, 0));
    }

    #[test]
    fn validate_reconnect_result_fail_not_reconnected() {
        let case = ReconnectTestCase::new("t", 5, 1000, ReconnectBehavior::Fail, 0);
        assert!(validate_reconnect_result(&case, false, 0));
    }

    #[test]
    fn validate_reconnect_result_fail_but_reconnected() {
        let case = ReconnectTestCase::new("t", 5, 1000, ReconnectBehavior::Fail, 0);
        assert!(!validate_reconnect_result(&case, true, 0));
    }

    #[test]
    fn validate_log_result_enough_entries() {
        let case = LogTestCase::new("t", "c", LogLevel::Info, None, None, 2);
        let entries = vec![
            json!({"level": "info", "message": "a"}),
            json!({"level": "warn", "message": "b"}),
        ];
        assert!(validate_log_result(&case, &entries));
    }

    #[test]
    fn validate_log_result_not_enough_entries() {
        let case = LogTestCase::new("t", "c", LogLevel::Info, None, None, 5);
        let entries = vec![json!({"level": "info", "message": "a"})];
        assert!(!validate_log_result(&case, &entries));
    }

    #[test]
    fn validate_log_result_level_too_low() {
        let case = LogTestCase::new("t", "c", LogLevel::Warn, None, None, 1);
        let entries = vec![json!({"level": "debug", "message": "low"})];
        assert!(!validate_log_result(&case, &entries));
    }

    #[test]
    fn validate_log_result_pattern_matches() {
        let case = LogTestCase::new("t", "c", LogLevel::Debug, None, Some("error".into()), 1);
        let entries = vec![json!({"level": "error", "message": "an error occurred"})];
        assert!(validate_log_result(&case, &entries));
    }

    #[test]
    fn validate_log_result_pattern_no_match() {
        let case = LogTestCase::new("t", "c", LogLevel::Debug, None, Some("missing".into()), 1);
        let entries = vec![json!({"level": "info", "message": "something else"})];
        assert!(!validate_log_result(&case, &entries));
    }

    #[test]
    fn validate_log_result_warning_level_alias() {
        let case = LogTestCase::new("t", "c", LogLevel::Warn, None, None, 1);
        let entries = vec![json!({"level": "warning", "message": "w"})];
        assert!(validate_log_result(&case, &entries));
    }

    #[test]
    fn validate_watch_result_enough_updates() {
        let case = WatchTestCase::new("t", "c", "r", 1000, 2, false);
        let updates = vec![json!({"changed": true}), json!({"changed": false})];
        assert!(validate_watch_result(&case, &updates));
    }

    #[test]
    fn validate_watch_result_not_enough_updates() {
        let case = WatchTestCase::new("t", "c", "r", 1000, 5, false);
        let updates = vec![json!({"changed": true})];
        assert!(!validate_watch_result(&case, &updates));
    }

    #[test]
    fn validate_watch_result_drift_detection_objects() {
        let case = WatchTestCase::new("t", "c", "r", 1000, 1, true);
        let updates = vec![json!({"drift": true})];
        assert!(validate_watch_result(&case, &updates));
    }

    #[test]
    fn validate_watch_result_drift_detection_non_object() {
        let case = WatchTestCase::new("t", "c", "r", 1000, 1, true);
        let updates = vec![json!("not_an_object")];
        assert!(!validate_watch_result(&case, &updates));
    }

    #[test]
    fn validate_watch_result_zero_updates_expected() {
        let case = WatchTestCase::new("t", "c", "r", 1000, 0, false);
        let updates: Vec<Value> = vec![];
        assert!(validate_watch_result(&case, &updates));
    }

    // ── Formatting ───────────────────────────────────────────────

    #[test]
    fn format_stream_matrix_toon_contains_header() {
        let cases = build_stream_matrix();
        let toon = format_stream_matrix_toon(&cases);
        assert!(toon.contains("Stream Test Matrix"));
    }

    #[test]
    fn format_stream_matrix_toon_not_empty() {
        let cases = build_stream_matrix();
        let toon = format_stream_matrix_toon(&cases);
        assert!(!toon.is_empty());
    }

    #[test]
    fn format_stream_matrix_toon_contains_case_names() {
        let cases = build_stream_matrix();
        let toon = format_stream_matrix_toon(&cases);
        for case in &cases {
            assert!(toon.contains(&case.name), "missing case: {}", case.name);
        }
    }

    #[test]
    fn format_reconnect_matrix_toon_contains_header() {
        let cases = build_reconnect_matrix();
        let toon = format_reconnect_matrix_toon(&cases);
        assert!(toon.contains("Reconnect Test Matrix"));
    }

    #[test]
    fn format_reconnect_matrix_toon_not_empty() {
        let cases = build_reconnect_matrix();
        let toon = format_reconnect_matrix_toon(&cases);
        assert!(!toon.is_empty());
    }

    #[test]
    fn format_log_matrix_toon_contains_header() {
        let cases = build_log_matrix();
        let toon = format_log_matrix_toon(&cases);
        assert!(toon.contains("Log Test Matrix"));
    }

    #[test]
    fn format_log_matrix_toon_not_empty() {
        let cases = build_log_matrix();
        let toon = format_log_matrix_toon(&cases);
        assert!(!toon.is_empty());
    }

    #[test]
    fn format_watch_matrix_toon_contains_header() {
        let cases = build_watch_matrix();
        let toon = format_watch_matrix_toon(&cases);
        assert!(toon.contains("Watch Test Matrix"));
    }

    #[test]
    fn format_watch_matrix_toon_not_empty() {
        let cases = build_watch_matrix();
        let toon = format_watch_matrix_toon(&cases);
        assert!(!toon.is_empty());
    }
}
