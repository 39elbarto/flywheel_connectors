//! Zendesk Analytics and Reporting module.
//!
//! Provides reporting surfaces for ticket volume/trends, response times,
//! backlog metrics, CSAT scores, and optional agent workload aggregates.

use serde::{Deserialize, Serialize};

// ── MetricType ───────────────────────────────────────────────────────

/// The type of metric to query from Zendesk analytics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricType {
    /// Total ticket volume over the time window.
    TicketVolume,
    /// Time to first agent response.
    FirstResponseTime,
    /// Time from creation to resolution.
    ResolutionTime,
    /// Number of open/pending tickets at each point.
    BacklogDepth,
    /// Customer satisfaction score (0-100).
    Csat,
    /// Agent workload aggregates (no raw identity exposure).
    AgentWorkload,
    /// Rate at which resolved tickets are reopened.
    ReopenRate,
    /// Percentage of tickets resolved in a single reply.
    OneTouch,
}

impl MetricType {
    /// Returns the string identifier for this metric type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TicketVolume => "ticket_volume",
            Self::FirstResponseTime => "first_response_time",
            Self::ResolutionTime => "resolution_time",
            Self::BacklogDepth => "backlog_depth",
            Self::Csat => "csat",
            Self::AgentWorkload => "agent_workload",
            Self::ReopenRate => "reopen_rate",
            Self::OneTouch => "one_touch",
        }
    }

    /// Returns a human-readable description of this metric.
    pub fn description(&self) -> &'static str {
        match self {
            Self::TicketVolume => "Total ticket volume over the reporting period",
            Self::FirstResponseTime => "Average time to first agent response in hours",
            Self::ResolutionTime => "Average time from creation to resolution in hours",
            Self::BacklogDepth => "Number of open or pending tickets at each data point",
            Self::Csat => "Customer satisfaction score as a percentage (0-100)",
            Self::AgentWorkload => "Aggregate agent workload distribution metrics",
            Self::ReopenRate => "Percentage of resolved tickets that are reopened",
            Self::OneTouch => "Percentage of tickets resolved with a single reply",
        }
    }
}

impl std::fmt::Display for MetricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Granularity ──────────────────────────────────────────────────────

/// The granularity of time-series data points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Granularity {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl Granularity {
    /// Returns the string identifier for this granularity level.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }

    /// Returns the approximate number of seconds per granularity unit.
    fn seconds_per_unit(&self) -> u64 {
        match self {
            Self::Hourly => 3600,
            Self::Daily => 86400,
            Self::Weekly => 604_800,
            Self::Monthly => 2_592_000,
        }
    }
}

impl std::fmt::Display for Granularity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── TimeWindow ───────────────────────────────────────────────────────

/// A time range for analytics queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start of the window (ISO 8601 timestamp).
    pub start: String,
    /// End of the window (ISO 8601 timestamp).
    pub end: String,
    /// Granularity for data point aggregation.
    pub granularity: Granularity,
}

impl TimeWindow {
    /// Create a new time window.
    pub fn new(start: impl Into<String>, end: impl Into<String>, granularity: Granularity) -> Self {
        Self {
            start: start.into(),
            end: end.into(),
            granularity,
        }
    }

    /// Validates that the time window has non-empty start and end.
    pub fn validate(&self) -> Result<(), AnalyticsError> {
        if self.start.is_empty() {
            return Err(AnalyticsError::InvalidTimeWindow(
                "start timestamp must not be empty".to_string(),
            ));
        }
        if self.end.is_empty() {
            return Err(AnalyticsError::InvalidTimeWindow(
                "end timestamp must not be empty".to_string(),
            ));
        }
        if self.start >= self.end {
            return Err(AnalyticsError::InvalidTimeWindow(
                "start must be before end".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns a formatted label for this window.
    pub fn label(&self) -> String {
        format!("{} to {} ({})", self.start, self.end, self.granularity)
    }
}

// ── GroupBy ───────────────────────────────────────────────────────────

/// Dimensions by which metrics can be grouped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GroupBy {
    Category,
    Priority,
    Channel,
    Group,
    Brand,
    Status,
}

impl GroupBy {
    /// Returns the string identifier for this group-by dimension.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Category => "category",
            Self::Priority => "priority",
            Self::Channel => "channel",
            Self::Group => "group",
            Self::Brand => "brand",
            Self::Status => "status",
        }
    }
}

impl std::fmt::Display for GroupBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── FilterOp ─────────────────────────────────────────────────────────

/// Comparison operators for metric filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilterOp {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    In,
    NotIn,
}

impl FilterOp {
    /// Returns the string identifier for this filter operator.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equals => "eq",
            Self::NotEquals => "ne",
            Self::GreaterThan => "gt",
            Self::LessThan => "lt",
            Self::In => "in",
            Self::NotIn => "not_in",
        }
    }
}

impl std::fmt::Display for FilterOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── MetricFilter ─────────────────────────────────────────────────────

/// A filter constraint applied to an analytics query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricFilter {
    /// The field to filter on.
    pub field: String,
    /// The comparison operator.
    pub operator: FilterOp,
    /// The value to compare against.
    pub value: String,
}

impl MetricFilter {
    /// Create a new metric filter.
    pub fn new(field: impl Into<String>, operator: FilterOp, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            operator,
            value: value.into(),
        }
    }

    /// Returns a human-readable description of this filter.
    pub fn description(&self) -> String {
        format!("{} {} {}", self.field, self.operator, self.value)
    }
}

// ── MetricQuery ──────────────────────────────────────────────────────

/// A query for analytics metrics, constructed via builder pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricQuery {
    /// The metrics to retrieve.
    pub metrics: Vec<MetricType>,
    /// The time window for the query.
    pub time_window: Option<TimeWindow>,
    /// Optional grouping dimension.
    pub group_by: Option<GroupBy>,
    /// Filters to apply.
    pub filters: Vec<MetricFilter>,
}

impl MetricQuery {
    /// Create a new empty metric query builder.
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
            time_window: None,
            group_by: None,
            filters: Vec::new(),
        }
    }

    /// Add a metric type to the query.
    pub fn add_metric(mut self, metric: MetricType) -> Self {
        self.metrics.push(metric);
        self
    }

    /// Set the time window for the query.
    pub fn with_time_window(mut self, window: TimeWindow) -> Self {
        self.time_window = Some(window);
        self
    }

    /// Set the group-by dimension.
    pub fn group_by(mut self, group: GroupBy) -> Self {
        self.group_by = Some(group);
        self
    }

    /// Add a filter to the query.
    pub fn add_filter(mut self, filter: MetricFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Validate the query for completeness and correctness.
    pub fn validate(&self) -> Result<(), AnalyticsError> {
        if self.metrics.is_empty() {
            return Err(AnalyticsError::EmptyQuery(
                "at least one metric must be specified".to_string(),
            ));
        }

        // Check for duplicate metrics
        let mut seen = std::collections::HashSet::new();
        for m in &self.metrics {
            if !seen.insert(m) {
                return Err(AnalyticsError::DuplicateMetric(*m));
            }
        }

        if let Some(ref tw) = self.time_window {
            tw.validate()?;
        } else {
            return Err(AnalyticsError::InvalidTimeWindow(
                "time window is required".to_string(),
            ));
        }

        // Validate filters have non-empty fields
        for filter in &self.filters {
            if filter.field.is_empty() {
                return Err(AnalyticsError::InvalidFilter(
                    "filter field must not be empty".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Returns the number of metrics in this query.
    pub fn metric_count(&self) -> usize {
        self.metrics.len()
    }

    /// Returns whether this query requests agent workload metrics.
    pub fn includes_agent_workload(&self) -> bool {
        self.metrics.contains(&MetricType::AgentWorkload)
    }
}

impl Default for MetricQuery {
    fn default() -> Self {
        Self::new()
    }
}

// ── MetricDataPoint ──────────────────────────────────────────────────

/// A single data point in a time-series metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    /// Timestamp for this data point (ISO 8601).
    pub timestamp: String,
    /// The metric value at this point.
    pub value: f64,
    /// Optional label for grouped data points.
    pub label: Option<String>,
}

impl MetricDataPoint {
    /// Create a new data point.
    pub fn new(timestamp: impl Into<String>, value: f64) -> Self {
        Self {
            timestamp: timestamp.into(),
            value,
            label: None,
        }
    }

    /// Create a new data point with a label.
    pub fn with_label(
        timestamp: impl Into<String>,
        value: f64,
        label: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: timestamp.into(),
            value,
            label: Some(label.into()),
        }
    }
}

// ── Aggregation ──────────────────────────────────────────────────────

/// The aggregation method applied to a metric series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Aggregation {
    Sum,
    Average,
    Median,
    P95,
    Count,
}

impl Aggregation {
    /// Returns the string identifier for this aggregation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sum => "sum",
            Self::Average => "average",
            Self::Median => "median",
            Self::P95 => "p95",
            Self::Count => "count",
        }
    }
}

impl std::fmt::Display for Aggregation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Trend ────────────────────────────────────────────────────────────

/// The overall trend direction of a metric series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Trend {
    /// Values are generally increasing over time.
    Increasing,
    /// Values are generally decreasing over time.
    Decreasing,
    /// Values are relatively stable.
    Stable,
    /// Not enough data points to determine a trend.
    Insufficient,
}

impl Trend {
    /// Returns the string identifier for this trend.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Increasing => "increasing",
            Self::Decreasing => "decreasing",
            Self::Stable => "stable",
            Self::Insufficient => "insufficient",
        }
    }
}

impl std::fmt::Display for Trend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── MetricSeries ─────────────────────────────────────────────────────

/// A series of data points for a single metric type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    /// The metric this series represents.
    pub metric_type: MetricType,
    /// The ordered data points.
    pub data_points: Vec<MetricDataPoint>,
    /// The aggregation method used.
    pub aggregation: Aggregation,
    /// Precomputed total, if applicable.
    pub total: Option<f64>,
    /// Precomputed average, if applicable.
    pub average: Option<f64>,
}

impl MetricSeries {
    /// Create a new metric series.
    pub fn new(metric_type: MetricType, aggregation: Aggregation) -> Self {
        Self {
            metric_type,
            data_points: Vec::new(),
            aggregation,
            total: None,
            average: None,
        }
    }

    /// Add a data point to the series.
    pub fn add_point(&mut self, point: MetricDataPoint) {
        self.data_points.push(point);
    }

    /// Returns the minimum value in the series, or None if empty.
    pub fn min(&self) -> Option<f64> {
        self.data_points
            .iter()
            .map(|p| p.value)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Returns the maximum value in the series, or None if empty.
    pub fn max(&self) -> Option<f64> {
        self.data_points
            .iter()
            .map(|p| p.value)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Computes the trend direction based on the data points.
    ///
    /// Uses a simple linear regression slope to determine the trend.
    /// Requires at least 3 data points; otherwise returns `Insufficient`.
    pub fn trend(&self) -> Trend {
        let n = self.data_points.len();
        if n < 3 {
            return Trend::Insufficient;
        }

        // Simple linear regression: y = slope * x + intercept
        let n_f = n as f64;
        let sum_x: f64 = (0..n).map(|i| i as f64).sum();
        let sum_y: f64 = self.data_points.iter().map(|p| p.value).sum();
        let sum_xy: f64 = self
            .data_points
            .iter()
            .enumerate()
            .map(|(i, p)| i as f64 * p.value)
            .sum();
        let sum_xx: f64 = (0..n).map(|i| (i as f64) * (i as f64)).sum();

        let denominator = n_f * sum_xx - sum_x * sum_x;
        if denominator.abs() < f64::EPSILON {
            return Trend::Stable;
        }

        let slope = (n_f * sum_xy - sum_x * sum_y) / denominator;
        let mean_y = sum_y / n_f;

        // Normalize slope relative to the mean to get a relative change rate
        let threshold = if mean_y.abs() > f64::EPSILON {
            (slope / mean_y).abs()
        } else {
            slope.abs()
        };

        if threshold < 0.01 {
            Trend::Stable
        } else if slope > 0.0 {
            Trend::Increasing
        } else {
            Trend::Decreasing
        }
    }

    /// Compute running statistics over the data points.
    pub fn compute_stats(&mut self) {
        if self.data_points.is_empty() {
            self.total = None;
            self.average = None;
            return;
        }
        let sum: f64 = self.data_points.iter().map(|p| p.value).sum();
        self.total = Some(sum);
        self.average = Some(sum / self.data_points.len() as f64);
    }

    /// Returns the number of data points in this series.
    pub fn len(&self) -> usize {
        self.data_points.len()
    }

    /// Returns true if this series has no data points.
    pub fn is_empty(&self) -> bool {
        self.data_points.is_empty()
    }
}

// ── ReportSummary ────────────────────────────────────────────────────

/// A concise summary of key metrics from an analytics report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total tickets in the reporting period.
    pub total_tickets: Option<u64>,
    /// Average first response time in hours.
    pub avg_first_response_hours: Option<f64>,
    /// Average resolution time in hours.
    pub avg_resolution_hours: Option<f64>,
    /// CSAT score as a percentage.
    pub csat_score: Option<f64>,
    /// Current backlog size.
    pub backlog_size: Option<u64>,
}

impl ReportSummary {
    /// Returns true if this summary has no populated fields.
    pub fn is_empty(&self) -> bool {
        self.total_tickets.is_none()
            && self.avg_first_response_hours.is_none()
            && self.avg_resolution_hours.is_none()
            && self.csat_score.is_none()
            && self.backlog_size.is_none()
    }

    /// Returns the number of populated fields.
    pub fn populated_count(&self) -> usize {
        let mut count = 0;
        if self.total_tickets.is_some() {
            count += 1;
        }
        if self.avg_first_response_hours.is_some() {
            count += 1;
        }
        if self.avg_resolution_hours.is_some() {
            count += 1;
        }
        if self.csat_score.is_some() {
            count += 1;
        }
        if self.backlog_size.is_some() {
            count += 1;
        }
        count
    }
}

// ── AnalyticsReport ──────────────────────────────────────────────────

/// A completed analytics report containing metric series and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsReport {
    /// The metric series in this report.
    pub metrics: Vec<MetricSeries>,
    /// The time window the report covers.
    pub time_window: TimeWindow,
    /// When the report was generated (ISO 8601).
    pub generated_at: String,
    /// Human-readable descriptions of filters that were applied.
    pub filters_applied: Vec<String>,
}

impl AnalyticsReport {
    /// Create a new analytics report.
    pub fn new(time_window: TimeWindow, generated_at: impl Into<String>) -> Self {
        Self {
            metrics: Vec::new(),
            time_window,
            generated_at: generated_at.into(),
            filters_applied: Vec::new(),
        }
    }

    /// Add a metric series to the report.
    pub fn add_series(&mut self, series: MetricSeries) {
        self.metrics.push(series);
    }

    /// Record a filter that was applied.
    pub fn add_filter_description(&mut self, desc: impl Into<String>) {
        self.filters_applied.push(desc.into());
    }

    /// Generate a summary from the report's metric series.
    pub fn summary(&self) -> ReportSummary {
        let mut summary = ReportSummary::default();

        for series in &self.metrics {
            match series.metric_type {
                MetricType::TicketVolume => {
                    if let Some(total) = series.total {
                        summary.total_tickets = Some(total as u64);
                    }
                }
                MetricType::FirstResponseTime => {
                    summary.avg_first_response_hours = series.average;
                }
                MetricType::ResolutionTime => {
                    summary.avg_resolution_hours = series.average;
                }
                MetricType::Csat => {
                    summary.csat_score = series.average;
                }
                MetricType::BacklogDepth => {
                    // Use the last data point as current backlog
                    if let Some(last) = series.data_points.last() {
                        summary.backlog_size = Some(last.value as u64);
                    }
                }
                _ => {}
            }
        }

        summary
    }

    /// Returns the total number of data points across all series.
    pub fn total_data_points(&self) -> usize {
        self.metrics.iter().map(|s| s.data_points.len()).sum()
    }

    /// Returns the number of metric series in this report.
    pub fn series_count(&self) -> usize {
        self.metrics.len()
    }
}

// ── AnalyticsAuditEvent ──────────────────────────────────────────────

/// An audit event recording that an analytics query was performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsAuditEvent {
    /// When the query was executed (ISO 8601).
    pub timestamp: String,
    /// The type of query performed.
    pub query_type: String,
    /// Number of metrics requested.
    pub metric_count: usize,
    /// Human-readable time range description.
    pub time_range: String,
}

impl AnalyticsAuditEvent {
    /// Create an audit event from a metric query.
    pub fn from_query(query: &MetricQuery, timestamp: impl Into<String>) -> Self {
        let time_range = query
            .time_window
            .as_ref()
            .map_or_else(|| "unspecified".to_string(), |tw| tw.label());

        let query_type = if query.includes_agent_workload() {
            "analytics_with_workload".to_string()
        } else {
            "analytics_standard".to_string()
        };

        Self {
            timestamp: timestamp.into(),
            query_type,
            metric_count: query.metric_count(),
            time_range,
        }
    }

    /// Returns a log-friendly summary of the audit event.
    pub fn log_summary(&self) -> String {
        format!(
            "[{}] {} query: {} metrics over {}",
            self.timestamp, self.query_type, self.metric_count, self.time_range
        )
    }
}

// ── AnalyticsError ───────────────────────────────────────────────────

/// Errors that can occur during analytics operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AnalyticsError {
    #[error("invalid time window: {0}")]
    InvalidTimeWindow(String),
    #[error("empty query: {0}")]
    EmptyQuery(String),
    #[error("duplicate metric: {0}")]
    DuplicateMetric(MetricType),
    #[error("invalid filter: {0}")]
    InvalidFilter(String),
    #[error("insufficient data: {0}")]
    InsufficientData(String),
    #[error("query too broad: {0}")]
    QueryTooBroad(String),
}

// ── Helper functions ─────────────────────────────────────────────────

/// Compute the median of a slice of f64 values.
fn compute_median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        Some((values[mid - 1] + values[mid]) / 2.0)
    } else {
        Some(values[mid])
    }
}

/// Compute the p95 value of a slice of f64 values.
fn compute_p95(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((values.len() as f64) * 0.95).ceil() as usize;
    let idx = idx.min(values.len()) - 1;
    Some(values[idx])
}

/// Aggregate a set of values using the specified aggregation method.
pub fn aggregate_values(values: &[f64], method: Aggregation) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    match method {
        Aggregation::Sum => Some(values.iter().sum()),
        Aggregation::Average => {
            let sum: f64 = values.iter().sum();
            Some(sum / values.len() as f64)
        }
        Aggregation::Median => {
            let mut sorted = values.to_vec();
            compute_median(&mut sorted)
        }
        Aggregation::P95 => {
            let mut sorted = values.to_vec();
            compute_p95(&mut sorted)
        }
        Aggregation::Count => Some(values.len() as f64),
    }
}

/// Build a `MetricSeries` from raw data points and an aggregation method.
pub fn build_series(
    metric_type: MetricType,
    points: Vec<MetricDataPoint>,
    aggregation: Aggregation,
) -> MetricSeries {
    let mut series = MetricSeries::new(metric_type, aggregation);
    series.data_points = points;
    series.compute_stats();
    series
}

/// Validate that a CSAT score is within the valid range (0-100).
pub fn validate_csat_score(score: f64) -> Result<f64, AnalyticsError> {
    if score < 0.0 || score > 100.0 {
        return Err(AnalyticsError::InsufficientData(format!(
            "CSAT score {score} is outside valid range 0-100"
        )));
    }
    Ok(score)
}

/// Sanitize agent workload data by removing raw identity information.
/// Returns aggregate-only values suitable for reporting.
pub fn sanitize_agent_workload(
    agent_ticket_counts: &[u64],
) -> (f64, f64, f64, f64) {
    if agent_ticket_counts.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }
    let sum: u64 = agent_ticket_counts.iter().sum();
    let count = agent_ticket_counts.len() as f64;
    let avg = sum as f64 / count;
    let min = *agent_ticket_counts.iter().min().unwrap_or(&0) as f64;
    let max = *agent_ticket_counts.iter().max().unwrap_or(&0) as f64;
    let variance: f64 = agent_ticket_counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - avg;
            diff * diff
        })
        .sum::<f64>()
        / count;
    let std_dev = variance.sqrt();
    (avg, min, max, std_dev)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MetricType ───────────────────────────────────────────────────

    #[test]
    fn metric_type_as_str_ticket_volume() {
        assert_eq!(MetricType::TicketVolume.as_str(), "ticket_volume");
    }

    #[test]
    fn metric_type_as_str_first_response() {
        assert_eq!(
            MetricType::FirstResponseTime.as_str(),
            "first_response_time"
        );
    }

    #[test]
    fn metric_type_as_str_resolution_time() {
        assert_eq!(MetricType::ResolutionTime.as_str(), "resolution_time");
    }

    #[test]
    fn metric_type_as_str_backlog_depth() {
        assert_eq!(MetricType::BacklogDepth.as_str(), "backlog_depth");
    }

    #[test]
    fn metric_type_as_str_csat() {
        assert_eq!(MetricType::Csat.as_str(), "csat");
    }

    #[test]
    fn metric_type_as_str_agent_workload() {
        assert_eq!(MetricType::AgentWorkload.as_str(), "agent_workload");
    }

    #[test]
    fn metric_type_as_str_reopen_rate() {
        assert_eq!(MetricType::ReopenRate.as_str(), "reopen_rate");
    }

    #[test]
    fn metric_type_as_str_one_touch() {
        assert_eq!(MetricType::OneTouch.as_str(), "one_touch");
    }

    #[test]
    fn metric_type_description_not_empty() {
        let types = [
            MetricType::TicketVolume,
            MetricType::FirstResponseTime,
            MetricType::ResolutionTime,
            MetricType::BacklogDepth,
            MetricType::Csat,
            MetricType::AgentWorkload,
            MetricType::ReopenRate,
            MetricType::OneTouch,
        ];
        for mt in &types {
            assert!(!mt.description().is_empty(), "description empty for {mt:?}");
        }
    }

    #[test]
    fn metric_type_display() {
        assert_eq!(format!("{}", MetricType::TicketVolume), "ticket_volume");
        assert_eq!(format!("{}", MetricType::Csat), "csat");
    }

    #[test]
    fn metric_type_serde_roundtrip() {
        let mt = MetricType::FirstResponseTime;
        let json = serde_json::to_string(&mt).unwrap();
        let parsed: MetricType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mt);
    }

    #[test]
    fn metric_type_all_variants_unique_str() {
        let all = [
            MetricType::TicketVolume,
            MetricType::FirstResponseTime,
            MetricType::ResolutionTime,
            MetricType::BacklogDepth,
            MetricType::Csat,
            MetricType::AgentWorkload,
            MetricType::ReopenRate,
            MetricType::OneTouch,
        ];
        let mut set = std::collections::HashSet::new();
        for mt in &all {
            assert!(set.insert(mt.as_str()), "duplicate as_str for {mt:?}");
        }
    }

    #[test]
    fn metric_type_clone_eq() {
        let a = MetricType::Csat;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn metric_type_description_contains_keywords() {
        assert!(MetricType::TicketVolume.description().contains("ticket"));
        assert!(MetricType::Csat.description().contains("satisfaction"));
        assert!(MetricType::ReopenRate.description().contains("reopened"));
    }

    // ── Granularity ──────────────────────────────────────────────────

    #[test]
    fn granularity_as_str() {
        assert_eq!(Granularity::Hourly.as_str(), "hourly");
        assert_eq!(Granularity::Daily.as_str(), "daily");
        assert_eq!(Granularity::Weekly.as_str(), "weekly");
        assert_eq!(Granularity::Monthly.as_str(), "monthly");
    }

    #[test]
    fn granularity_display() {
        assert_eq!(format!("{}", Granularity::Daily), "daily");
        assert_eq!(format!("{}", Granularity::Monthly), "monthly");
    }

    #[test]
    fn granularity_serde_roundtrip() {
        let g = Granularity::Weekly;
        let json = serde_json::to_string(&g).unwrap();
        let parsed: Granularity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, g);
    }

    #[test]
    fn granularity_seconds_per_unit() {
        assert_eq!(Granularity::Hourly.seconds_per_unit(), 3600);
        assert_eq!(Granularity::Daily.seconds_per_unit(), 86400);
        assert_eq!(Granularity::Weekly.seconds_per_unit(), 604_800);
        assert_eq!(Granularity::Monthly.seconds_per_unit(), 2_592_000);
    }

    #[test]
    fn granularity_clone_eq() {
        let a = Granularity::Daily;
        let b = a;
        assert_eq!(a, b);
    }

    // ── TimeWindow ───────────────────────────────────────────────────

    #[test]
    fn time_window_new() {
        let tw = TimeWindow::new("2026-01-01T00:00:00Z", "2026-01-31T23:59:59Z", Granularity::Daily);
        assert_eq!(tw.start, "2026-01-01T00:00:00Z");
        assert_eq!(tw.end, "2026-01-31T23:59:59Z");
        assert_eq!(tw.granularity, Granularity::Daily);
    }

    #[test]
    fn time_window_validate_ok() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        assert!(tw.validate().is_ok());
    }

    #[test]
    fn time_window_validate_empty_start() {
        let tw = TimeWindow::new("", "2026-01-31", Granularity::Daily);
        assert!(tw.validate().is_err());
    }

    #[test]
    fn time_window_validate_empty_end() {
        let tw = TimeWindow::new("2026-01-01", "", Granularity::Daily);
        assert!(tw.validate().is_err());
    }

    #[test]
    fn time_window_validate_start_after_end() {
        let tw = TimeWindow::new("2026-02-01", "2026-01-01", Granularity::Daily);
        assert!(tw.validate().is_err());
    }

    #[test]
    fn time_window_validate_start_equals_end() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-01", Granularity::Daily);
        assert!(tw.validate().is_err());
    }

    #[test]
    fn time_window_label() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Weekly);
        let label = tw.label();
        assert!(label.contains("2026-01-01"));
        assert!(label.contains("2026-01-31"));
        assert!(label.contains("weekly"));
    }

    #[test]
    fn time_window_serde_roundtrip() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Monthly);
        let json = serde_json::to_string(&tw).unwrap();
        let parsed: TimeWindow = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.start, tw.start);
        assert_eq!(parsed.end, tw.end);
        assert_eq!(parsed.granularity, tw.granularity);
    }

    #[test]
    fn time_window_clone() {
        let tw = TimeWindow::new("2026-03-01", "2026-03-31", Granularity::Daily);
        let cloned = tw.clone();
        assert_eq!(tw.start, cloned.start);
        assert_eq!(tw.end, cloned.end);
    }

    // ── GroupBy ──────────────────────────────────────────────────────

    #[test]
    fn group_by_as_str() {
        assert_eq!(GroupBy::Category.as_str(), "category");
        assert_eq!(GroupBy::Priority.as_str(), "priority");
        assert_eq!(GroupBy::Channel.as_str(), "channel");
        assert_eq!(GroupBy::Group.as_str(), "group");
        assert_eq!(GroupBy::Brand.as_str(), "brand");
        assert_eq!(GroupBy::Status.as_str(), "status");
    }

    #[test]
    fn group_by_display() {
        assert_eq!(format!("{}", GroupBy::Priority), "priority");
    }

    #[test]
    fn group_by_serde_roundtrip() {
        let g = GroupBy::Channel;
        let json = serde_json::to_string(&g).unwrap();
        let parsed: GroupBy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, g);
    }

    #[test]
    fn group_by_all_unique() {
        let all = [
            GroupBy::Category,
            GroupBy::Priority,
            GroupBy::Channel,
            GroupBy::Group,
            GroupBy::Brand,
            GroupBy::Status,
        ];
        let mut set = std::collections::HashSet::new();
        for g in &all {
            assert!(set.insert(g.as_str()), "duplicate as_str for {g:?}");
        }
    }

    // ── FilterOp ─────────────────────────────────────────────────────

    #[test]
    fn filter_op_as_str() {
        assert_eq!(FilterOp::Equals.as_str(), "eq");
        assert_eq!(FilterOp::NotEquals.as_str(), "ne");
        assert_eq!(FilterOp::GreaterThan.as_str(), "gt");
        assert_eq!(FilterOp::LessThan.as_str(), "lt");
        assert_eq!(FilterOp::In.as_str(), "in");
        assert_eq!(FilterOp::NotIn.as_str(), "not_in");
    }

    #[test]
    fn filter_op_display() {
        assert_eq!(format!("{}", FilterOp::Equals), "eq");
        assert_eq!(format!("{}", FilterOp::NotIn), "not_in");
    }

    #[test]
    fn filter_op_serde_roundtrip() {
        let op = FilterOp::GreaterThan;
        let json = serde_json::to_string(&op).unwrap();
        let parsed: FilterOp = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, op);
    }

    // ── MetricFilter ─────────────────────────────────────────────────

    #[test]
    fn metric_filter_new() {
        let f = MetricFilter::new("priority", FilterOp::Equals, "high");
        assert_eq!(f.field, "priority");
        assert_eq!(f.operator, FilterOp::Equals);
        assert_eq!(f.value, "high");
    }

    #[test]
    fn metric_filter_description() {
        let f = MetricFilter::new("status", FilterOp::NotEquals, "closed");
        let desc = f.description();
        assert!(desc.contains("status"));
        assert!(desc.contains("ne"));
        assert!(desc.contains("closed"));
    }

    #[test]
    fn metric_filter_serde_roundtrip() {
        let f = MetricFilter::new("channel", FilterOp::In, "email,chat");
        let json = serde_json::to_string(&f).unwrap();
        let parsed: MetricFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.field, f.field);
        assert_eq!(parsed.operator, f.operator);
        assert_eq!(parsed.value, f.value);
    }

    #[test]
    fn metric_filter_clone() {
        let f = MetricFilter::new("group", FilterOp::Equals, "support");
        let cloned = f.clone();
        assert_eq!(f.field, cloned.field);
        assert_eq!(f.operator, cloned.operator);
    }

    // ── MetricQuery ──────────────────────────────────────────────────

    #[test]
    fn metric_query_builder_basic() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        assert_eq!(q.metrics.len(), 1);
        assert!(q.time_window.is_some());
        assert!(q.validate().is_ok());
    }

    #[test]
    fn metric_query_builder_multiple_metrics() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .add_metric(MetricType::Csat)
            .add_metric(MetricType::ResolutionTime)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        assert_eq!(q.metrics.len(), 3);
        assert_eq!(q.metric_count(), 3);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn metric_query_builder_with_group_by() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily))
            .group_by(GroupBy::Priority);
        assert_eq!(q.group_by, Some(GroupBy::Priority));
        assert!(q.validate().is_ok());
    }

    #[test]
    fn metric_query_builder_with_filter() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily))
            .add_filter(MetricFilter::new("priority", FilterOp::Equals, "high"));
        assert_eq!(q.filters.len(), 1);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn metric_query_validate_empty_metrics() {
        let q = MetricQuery::new()
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        assert!(q.validate().is_err());
    }

    #[test]
    fn metric_query_validate_no_time_window() {
        let q = MetricQuery::new().add_metric(MetricType::TicketVolume);
        assert!(q.validate().is_err());
    }

    #[test]
    fn metric_query_validate_duplicate_metrics() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        assert!(q.validate().is_err());
    }

    #[test]
    fn metric_query_validate_empty_filter_field() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily))
            .add_filter(MetricFilter::new("", FilterOp::Equals, "val"));
        assert!(q.validate().is_err());
    }

    #[test]
    fn metric_query_includes_agent_workload_false() {
        let q = MetricQuery::new().add_metric(MetricType::TicketVolume);
        assert!(!q.includes_agent_workload());
    }

    #[test]
    fn metric_query_includes_agent_workload_true() {
        let q = MetricQuery::new().add_metric(MetricType::AgentWorkload);
        assert!(q.includes_agent_workload());
    }

    #[test]
    fn metric_query_default() {
        let q = MetricQuery::default();
        assert!(q.metrics.is_empty());
        assert!(q.time_window.is_none());
        assert!(q.group_by.is_none());
        assert!(q.filters.is_empty());
    }

    #[test]
    fn metric_query_serde_roundtrip() {
        let q = MetricQuery::new()
            .add_metric(MetricType::Csat)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Weekly))
            .group_by(GroupBy::Brand);
        let json = serde_json::to_string(&q).unwrap();
        let parsed: MetricQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metrics.len(), 1);
        assert_eq!(parsed.group_by, Some(GroupBy::Brand));
    }

    #[test]
    fn metric_query_multiple_filters() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily))
            .add_filter(MetricFilter::new("priority", FilterOp::Equals, "high"))
            .add_filter(MetricFilter::new("status", FilterOp::NotEquals, "closed"));
        assert_eq!(q.filters.len(), 2);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn metric_query_validate_bad_time_window() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-02-01", "2026-01-01", Granularity::Daily));
        assert!(q.validate().is_err());
    }

    // ── MetricDataPoint ──────────────────────────────────────────────

    #[test]
    fn data_point_new() {
        let dp = MetricDataPoint::new("2026-01-15T00:00:00Z", 42.5);
        assert_eq!(dp.timestamp, "2026-01-15T00:00:00Z");
        assert!((dp.value - 42.5).abs() < f64::EPSILON);
        assert!(dp.label.is_none());
    }

    #[test]
    fn data_point_with_label() {
        let dp = MetricDataPoint::with_label("2026-01-15", 10.0, "high_priority");
        assert_eq!(dp.label, Some("high_priority".to_string()));
    }

    #[test]
    fn data_point_serde_roundtrip() {
        let dp = MetricDataPoint::new("2026-01-15", 99.9);
        let json = serde_json::to_string(&dp).unwrap();
        let parsed: MetricDataPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timestamp, dp.timestamp);
        assert!((parsed.value - dp.value).abs() < f64::EPSILON);
    }

    #[test]
    fn data_point_clone() {
        let dp = MetricDataPoint::new("2026-01-15", 50.0);
        let cloned = dp.clone();
        assert_eq!(dp.timestamp, cloned.timestamp);
        assert!((dp.value - cloned.value).abs() < f64::EPSILON);
    }

    #[test]
    fn data_point_with_label_none() {
        let dp = MetricDataPoint::new("2026-01-15", 5.0);
        assert!(dp.label.is_none());
    }

    // ── Aggregation ──────────────────────────────────────────────────

    #[test]
    fn aggregation_as_str() {
        assert_eq!(Aggregation::Sum.as_str(), "sum");
        assert_eq!(Aggregation::Average.as_str(), "average");
        assert_eq!(Aggregation::Median.as_str(), "median");
        assert_eq!(Aggregation::P95.as_str(), "p95");
        assert_eq!(Aggregation::Count.as_str(), "count");
    }

    #[test]
    fn aggregation_display() {
        assert_eq!(format!("{}", Aggregation::Sum), "sum");
        assert_eq!(format!("{}", Aggregation::P95), "p95");
    }

    #[test]
    fn aggregation_serde_roundtrip() {
        let a = Aggregation::Median;
        let json = serde_json::to_string(&a).unwrap();
        let parsed: Aggregation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, a);
    }

    // ── Trend ────────────────────────────────────────────────────────

    #[test]
    fn trend_as_str() {
        assert_eq!(Trend::Increasing.as_str(), "increasing");
        assert_eq!(Trend::Decreasing.as_str(), "decreasing");
        assert_eq!(Trend::Stable.as_str(), "stable");
        assert_eq!(Trend::Insufficient.as_str(), "insufficient");
    }

    #[test]
    fn trend_display() {
        assert_eq!(format!("{}", Trend::Increasing), "increasing");
        assert_eq!(format!("{}", Trend::Stable), "stable");
    }

    #[test]
    fn trend_serde_roundtrip() {
        let t = Trend::Decreasing;
        let json = serde_json::to_string(&t).unwrap();
        let parsed: Trend = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, t);
    }

    // ── MetricSeries ─────────────────────────────────────────────────

    #[test]
    fn metric_series_new_empty() {
        let s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.min().is_none());
        assert!(s.max().is_none());
    }

    #[test]
    fn metric_series_add_point() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 10.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 20.0));
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());
    }

    #[test]
    fn metric_series_min() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 10.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 5.0));
        s.add_point(MetricDataPoint::new("2026-01-03", 15.0));
        assert!((s.min().unwrap() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_series_max() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 10.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 5.0));
        s.add_point(MetricDataPoint::new("2026-01-03", 15.0));
        assert!((s.max().unwrap() - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_series_trend_insufficient() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 10.0));
        assert_eq!(s.trend(), Trend::Insufficient);
    }

    #[test]
    fn metric_series_trend_insufficient_two_points() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 10.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 20.0));
        assert_eq!(s.trend(), Trend::Insufficient);
    }

    #[test]
    fn metric_series_trend_increasing() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 10.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 20.0));
        s.add_point(MetricDataPoint::new("2026-01-03", 30.0));
        s.add_point(MetricDataPoint::new("2026-01-04", 40.0));
        assert_eq!(s.trend(), Trend::Increasing);
    }

    #[test]
    fn metric_series_trend_decreasing() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 100.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 80.0));
        s.add_point(MetricDataPoint::new("2026-01-03", 60.0));
        s.add_point(MetricDataPoint::new("2026-01-04", 40.0));
        assert_eq!(s.trend(), Trend::Decreasing);
    }

    #[test]
    fn metric_series_trend_stable() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 50.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 50.0));
        s.add_point(MetricDataPoint::new("2026-01-03", 50.0));
        s.add_point(MetricDataPoint::new("2026-01-04", 50.0));
        assert_eq!(s.trend(), Trend::Stable);
    }

    #[test]
    fn metric_series_compute_stats() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 10.0));
        s.add_point(MetricDataPoint::new("2026-01-02", 20.0));
        s.add_point(MetricDataPoint::new("2026-01-03", 30.0));
        s.compute_stats();
        assert!((s.total.unwrap() - 60.0).abs() < f64::EPSILON);
        assert!((s.average.unwrap() - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_series_compute_stats_empty() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.compute_stats();
        assert!(s.total.is_none());
        assert!(s.average.is_none());
    }

    #[test]
    fn metric_series_serde_roundtrip() {
        let mut s = MetricSeries::new(MetricType::Csat, Aggregation::Average);
        s.add_point(MetricDataPoint::new("2026-01-01", 85.0));
        s.compute_stats();
        let json = serde_json::to_string(&s).unwrap();
        let parsed: MetricSeries = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metric_type, MetricType::Csat);
        assert_eq!(parsed.data_points.len(), 1);
    }

    #[test]
    fn metric_series_clone() {
        let mut s = MetricSeries::new(MetricType::BacklogDepth, Aggregation::Count);
        s.add_point(MetricDataPoint::new("2026-01-01", 25.0));
        let cloned = s.clone();
        assert_eq!(s.metric_type, cloned.metric_type);
        assert_eq!(s.len(), cloned.len());
    }

    #[test]
    fn metric_series_min_max_single_point() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("2026-01-01", 42.0));
        assert!((s.min().unwrap() - 42.0).abs() < f64::EPSILON);
        assert!((s.max().unwrap() - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_series_trend_with_noise_increasing() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("d1", 10.0));
        s.add_point(MetricDataPoint::new("d2", 15.0));
        s.add_point(MetricDataPoint::new("d3", 12.0));
        s.add_point(MetricDataPoint::new("d4", 20.0));
        s.add_point(MetricDataPoint::new("d5", 25.0));
        assert_eq!(s.trend(), Trend::Increasing);
    }

    #[test]
    fn metric_series_trend_with_noise_decreasing() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("d1", 100.0));
        s.add_point(MetricDataPoint::new("d2", 95.0));
        s.add_point(MetricDataPoint::new("d3", 98.0));
        s.add_point(MetricDataPoint::new("d4", 80.0));
        s.add_point(MetricDataPoint::new("d5", 70.0));
        assert_eq!(s.trend(), Trend::Decreasing);
    }

    // ── ReportSummary ────────────────────────────────────────────────

    #[test]
    fn report_summary_default_is_empty() {
        let s = ReportSummary::default();
        assert!(s.is_empty());
        assert_eq!(s.populated_count(), 0);
    }

    #[test]
    fn report_summary_populated_count() {
        let s = ReportSummary {
            total_tickets: Some(500),
            avg_first_response_hours: Some(1.5),
            avg_resolution_hours: None,
            csat_score: Some(87.5),
            backlog_size: None,
        };
        assert!(!s.is_empty());
        assert_eq!(s.populated_count(), 3);
    }

    #[test]
    fn report_summary_all_populated() {
        let s = ReportSummary {
            total_tickets: Some(100),
            avg_first_response_hours: Some(2.0),
            avg_resolution_hours: Some(24.0),
            csat_score: Some(90.0),
            backlog_size: Some(15),
        };
        assert_eq!(s.populated_count(), 5);
    }

    #[test]
    fn report_summary_serde_roundtrip() {
        let s = ReportSummary {
            total_tickets: Some(200),
            avg_first_response_hours: Some(1.23),
            avg_resolution_hours: None,
            csat_score: Some(95.0),
            backlog_size: Some(10),
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: ReportSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_tickets, s.total_tickets);
        assert_eq!(parsed.backlog_size, s.backlog_size);
    }

    // ── AnalyticsReport ──────────────────────────────────────────────

    #[test]
    fn analytics_report_new() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let report = AnalyticsReport::new(tw, "2026-02-01T00:00:00Z");
        assert!(report.metrics.is_empty());
        assert_eq!(report.generated_at, "2026-02-01T00:00:00Z");
        assert!(report.filters_applied.is_empty());
    }

    #[test]
    fn analytics_report_add_series() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");
        let s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        report.add_series(s);
        assert_eq!(report.series_count(), 1);
    }

    #[test]
    fn analytics_report_add_filter_description() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");
        report.add_filter_description("priority = high");
        assert_eq!(report.filters_applied.len(), 1);
        assert_eq!(report.filters_applied[0], "priority = high");
    }

    #[test]
    fn analytics_report_total_data_points() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut s1 = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s1.add_point(MetricDataPoint::new("d1", 10.0));
        s1.add_point(MetricDataPoint::new("d2", 20.0));

        let mut s2 = MetricSeries::new(MetricType::Csat, Aggregation::Average);
        s2.add_point(MetricDataPoint::new("d1", 85.0));

        report.add_series(s1);
        report.add_series(s2);
        assert_eq!(report.total_data_points(), 3);
    }

    #[test]
    fn analytics_report_summary_ticket_volume() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("d1", 100.0));
        s.add_point(MetricDataPoint::new("d2", 150.0));
        s.compute_stats();
        report.add_series(s);

        let summary = report.summary();
        assert_eq!(summary.total_tickets, Some(250));
    }

    #[test]
    fn analytics_report_summary_first_response() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut s = MetricSeries::new(MetricType::FirstResponseTime, Aggregation::Average);
        s.add_point(MetricDataPoint::new("d1", 2.0));
        s.add_point(MetricDataPoint::new("d2", 4.0));
        s.compute_stats();
        report.add_series(s);

        let summary = report.summary();
        assert!((summary.avg_first_response_hours.unwrap() - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn analytics_report_summary_resolution_time() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut s = MetricSeries::new(MetricType::ResolutionTime, Aggregation::Average);
        s.add_point(MetricDataPoint::new("d1", 12.0));
        s.add_point(MetricDataPoint::new("d2", 24.0));
        s.compute_stats();
        report.add_series(s);

        let summary = report.summary();
        assert!((summary.avg_resolution_hours.unwrap() - 18.0).abs() < f64::EPSILON);
    }

    #[test]
    fn analytics_report_summary_csat() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut s = MetricSeries::new(MetricType::Csat, Aggregation::Average);
        s.add_point(MetricDataPoint::new("d1", 90.0));
        s.add_point(MetricDataPoint::new("d2", 80.0));
        s.compute_stats();
        report.add_series(s);

        let summary = report.summary();
        assert!((summary.csat_score.unwrap() - 85.0).abs() < f64::EPSILON);
    }

    #[test]
    fn analytics_report_summary_backlog() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut s = MetricSeries::new(MetricType::BacklogDepth, Aggregation::Count);
        s.add_point(MetricDataPoint::new("d1", 30.0));
        s.add_point(MetricDataPoint::new("d2", 25.0));
        report.add_series(s);

        let summary = report.summary();
        assert_eq!(summary.backlog_size, Some(25));
    }

    #[test]
    fn analytics_report_summary_full() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut vol = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        vol.add_point(MetricDataPoint::new("d1", 50.0));
        vol.compute_stats();
        report.add_series(vol);

        let mut frt = MetricSeries::new(MetricType::FirstResponseTime, Aggregation::Average);
        frt.add_point(MetricDataPoint::new("d1", 1.5));
        frt.compute_stats();
        report.add_series(frt);

        let mut res = MetricSeries::new(MetricType::ResolutionTime, Aggregation::Average);
        res.add_point(MetricDataPoint::new("d1", 8.0));
        res.compute_stats();
        report.add_series(res);

        let mut csat = MetricSeries::new(MetricType::Csat, Aggregation::Average);
        csat.add_point(MetricDataPoint::new("d1", 92.0));
        csat.compute_stats();
        report.add_series(csat);

        let mut bl = MetricSeries::new(MetricType::BacklogDepth, Aggregation::Count);
        bl.add_point(MetricDataPoint::new("d1", 12.0));
        report.add_series(bl);

        let summary = report.summary();
        assert_eq!(summary.populated_count(), 5);
    }

    #[test]
    fn analytics_report_serde_roundtrip() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");
        report.add_filter_description("status != closed");
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AnalyticsReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.filters_applied.len(), 1);
    }

    #[test]
    fn analytics_report_empty_summary() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let report = AnalyticsReport::new(tw, "2026-02-01");
        let summary = report.summary();
        assert!(summary.is_empty());
    }

    #[test]
    fn analytics_report_series_count() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");
        assert_eq!(report.series_count(), 0);
        report.add_series(MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum));
        report.add_series(MetricSeries::new(MetricType::Csat, Aggregation::Average));
        assert_eq!(report.series_count(), 2);
    }

    // ── AnalyticsAuditEvent ──────────────────────────────────────────

    #[test]
    fn audit_event_from_query_standard() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        let event = AnalyticsAuditEvent::from_query(&q, "2026-02-01T00:00:00Z");
        assert_eq!(event.query_type, "analytics_standard");
        assert_eq!(event.metric_count, 1);
        assert!(event.time_range.contains("2026-01-01"));
    }

    #[test]
    fn audit_event_from_query_with_workload() {
        let q = MetricQuery::new()
            .add_metric(MetricType::AgentWorkload)
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        let event = AnalyticsAuditEvent::from_query(&q, "2026-02-01");
        assert_eq!(event.query_type, "analytics_with_workload");
        assert_eq!(event.metric_count, 2);
    }

    #[test]
    fn audit_event_from_query_no_time_window() {
        let q = MetricQuery::new().add_metric(MetricType::Csat);
        let event = AnalyticsAuditEvent::from_query(&q, "2026-02-01");
        assert_eq!(event.time_range, "unspecified");
    }

    #[test]
    fn audit_event_log_summary() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        let event = AnalyticsAuditEvent::from_query(&q, "2026-02-01");
        let summary = event.log_summary();
        assert!(summary.contains("2026-02-01"));
        assert!(summary.contains("analytics_standard"));
        assert!(summary.contains("1 metrics"));
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let event = AnalyticsAuditEvent {
            timestamp: "2026-02-01".to_string(),
            query_type: "analytics_standard".to_string(),
            metric_count: 3,
            time_range: "2026-01-01 to 2026-01-31".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AnalyticsAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metric_count, 3);
    }

    // ── AnalyticsError ───────────────────────────────────────────────

    #[test]
    fn analytics_error_display_invalid_time_window() {
        let e = AnalyticsError::InvalidTimeWindow("start is empty".to_string());
        let msg = e.to_string();
        assert!(msg.contains("invalid time window"));
        assert!(msg.contains("start is empty"));
    }

    #[test]
    fn analytics_error_display_empty_query() {
        let e = AnalyticsError::EmptyQuery("no metrics".to_string());
        assert!(e.to_string().contains("empty query"));
    }

    #[test]
    fn analytics_error_display_duplicate_metric() {
        let e = AnalyticsError::DuplicateMetric(MetricType::Csat);
        assert!(e.to_string().contains("duplicate metric"));
    }

    #[test]
    fn analytics_error_display_invalid_filter() {
        let e = AnalyticsError::InvalidFilter("empty field".to_string());
        assert!(e.to_string().contains("invalid filter"));
    }

    #[test]
    fn analytics_error_display_insufficient_data() {
        let e = AnalyticsError::InsufficientData("need more points".to_string());
        assert!(e.to_string().contains("insufficient data"));
    }

    #[test]
    fn analytics_error_display_query_too_broad() {
        let e = AnalyticsError::QueryTooBroad("exceeds limit".to_string());
        assert!(e.to_string().contains("query too broad"));
    }

    #[test]
    fn analytics_error_clone() {
        let e = AnalyticsError::EmptyQuery("test".to_string());
        let cloned = e.clone();
        assert_eq!(e.to_string(), cloned.to_string());
    }

    // ── Helper functions ─────────────────────────────────────────────

    #[test]
    fn compute_median_empty() {
        assert!(compute_median(&mut []).is_none());
    }

    #[test]
    fn compute_median_single() {
        assert!((compute_median(&mut [5.0]).unwrap() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_median_odd() {
        let mut v = vec![3.0, 1.0, 2.0];
        assert!((compute_median(&mut v).unwrap() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_median_even() {
        let mut v = vec![4.0, 1.0, 3.0, 2.0];
        assert!((compute_median(&mut v).unwrap() - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_p95_empty() {
        assert!(compute_p95(&mut []).is_none());
    }

    #[test]
    fn compute_p95_single() {
        assert!((compute_p95(&mut [7.0]).unwrap() - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compute_p95_twenty_values() {
        let mut v: Vec<f64> = (1..=20).map(f64::from).collect();
        let p95 = compute_p95(&mut v).unwrap();
        // 20 * 0.95 = 19 → ceil = 19, idx = 18 → value = 19.0
        assert!((p95 - 19.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_sum() {
        let vals = [1.0, 2.0, 3.0, 4.0];
        let result = aggregate_values(&vals, Aggregation::Sum).unwrap();
        assert!((result - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_average() {
        let vals = [10.0, 20.0, 30.0];
        let result = aggregate_values(&vals, Aggregation::Average).unwrap();
        assert!((result - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_median() {
        let vals = [5.0, 1.0, 3.0];
        let result = aggregate_values(&vals, Aggregation::Median).unwrap();
        assert!((result - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_p95() {
        let vals: Vec<f64> = (1..=100).map(f64::from).collect();
        let result = aggregate_values(&vals, Aggregation::P95).unwrap();
        assert!((result - 95.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_count() {
        let vals = [1.0, 2.0, 3.0, 4.0, 5.0];
        let result = aggregate_values(&vals, Aggregation::Count).unwrap();
        assert!((result - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_empty() {
        assert!(aggregate_values(&[], Aggregation::Sum).is_none());
    }

    #[test]
    fn build_series_computes_stats() {
        let points = vec![
            MetricDataPoint::new("d1", 10.0),
            MetricDataPoint::new("d2", 20.0),
            MetricDataPoint::new("d3", 30.0),
        ];
        let s = build_series(MetricType::TicketVolume, points, Aggregation::Sum);
        assert_eq!(s.len(), 3);
        assert!(s.total.is_some());
        assert!((s.total.unwrap() - 60.0).abs() < f64::EPSILON);
        assert!((s.average.unwrap() - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn build_series_empty() {
        let s = build_series(MetricType::Csat, vec![], Aggregation::Average);
        assert!(s.is_empty());
        assert!(s.total.is_none());
    }

    #[test]
    fn validate_csat_score_valid() {
        assert!(validate_csat_score(0.0).is_ok());
        assert!(validate_csat_score(50.0).is_ok());
        assert!(validate_csat_score(100.0).is_ok());
    }

    #[test]
    fn validate_csat_score_negative() {
        assert!(validate_csat_score(-1.0).is_err());
    }

    #[test]
    fn validate_csat_score_over_100() {
        assert!(validate_csat_score(100.1).is_err());
    }

    #[test]
    fn sanitize_agent_workload_empty() {
        let (avg, min, max, std_dev) = sanitize_agent_workload(&[]);
        assert!((avg - 0.0).abs() < f64::EPSILON);
        assert!((min - 0.0).abs() < f64::EPSILON);
        assert!((max - 0.0).abs() < f64::EPSILON);
        assert!((std_dev - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sanitize_agent_workload_single() {
        let (avg, min, max, std_dev) = sanitize_agent_workload(&[10]);
        assert!((avg - 10.0).abs() < f64::EPSILON);
        assert!((min - 10.0).abs() < f64::EPSILON);
        assert!((max - 10.0).abs() < f64::EPSILON);
        assert!((std_dev - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sanitize_agent_workload_multiple() {
        let (avg, min, max, std_dev) = sanitize_agent_workload(&[10, 20, 30]);
        assert!((avg - 20.0).abs() < f64::EPSILON);
        assert!((min - 10.0).abs() < f64::EPSILON);
        assert!((max - 30.0).abs() < f64::EPSILON);
        // std_dev for [10,20,30]: variance = ((100+0+100)/3) = 66.67, sqrt ≈ 8.165
        assert!(std_dev > 8.0 && std_dev < 8.2);
    }

    #[test]
    fn sanitize_agent_workload_uniform() {
        let (avg, min, max, std_dev) = sanitize_agent_workload(&[5, 5, 5, 5]);
        assert!((avg - 5.0).abs() < f64::EPSILON);
        assert!((min - 5.0).abs() < f64::EPSILON);
        assert!((max - 5.0).abs() < f64::EPSILON);
        assert!((std_dev - 0.0).abs() < f64::EPSILON);
    }

    // ── Integration / end-to-end ─────────────────────────────────────

    #[test]
    fn full_query_to_report_flow() {
        // Build a query
        let query = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .add_metric(MetricType::FirstResponseTime)
            .add_metric(MetricType::Csat)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily))
            .group_by(GroupBy::Priority)
            .add_filter(MetricFilter::new("status", FilterOp::NotEquals, "closed"));
        assert!(query.validate().is_ok());

        // Create audit event
        let audit = AnalyticsAuditEvent::from_query(&query, "2026-02-01T10:00:00Z");
        assert_eq!(audit.metric_count, 3);

        // Build report with mock data
        let mut report = AnalyticsReport::new(
            query.time_window.clone().unwrap(),
            "2026-02-01T10:00:00Z",
        );
        report.add_filter_description(query.filters[0].description());

        let vol = build_series(
            MetricType::TicketVolume,
            vec![
                MetricDataPoint::new("2026-01-01", 45.0),
                MetricDataPoint::new("2026-01-02", 52.0),
                MetricDataPoint::new("2026-01-03", 48.0),
            ],
            Aggregation::Sum,
        );
        report.add_series(vol);

        let frt = build_series(
            MetricType::FirstResponseTime,
            vec![
                MetricDataPoint::new("2026-01-01", 1.5),
                MetricDataPoint::new("2026-01-02", 2.0),
                MetricDataPoint::new("2026-01-03", 1.8),
            ],
            Aggregation::Average,
        );
        report.add_series(frt);

        let csat = build_series(
            MetricType::Csat,
            vec![
                MetricDataPoint::new("2026-01-01", 88.0),
                MetricDataPoint::new("2026-01-02", 92.0),
                MetricDataPoint::new("2026-01-03", 90.0),
            ],
            Aggregation::Average,
        );
        report.add_series(csat);

        assert_eq!(report.series_count(), 3);
        assert_eq!(report.total_data_points(), 9);

        let summary = report.summary();
        assert!(summary.total_tickets.is_some());
        assert!(summary.avg_first_response_hours.is_some());
        assert!(summary.csat_score.is_some());
    }

    #[test]
    fn query_validation_catches_all_errors() {
        // No metrics
        let q1 = MetricQuery::new()
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        assert!(matches!(q1.validate(), Err(AnalyticsError::EmptyQuery(_))));

        // No time window
        let q2 = MetricQuery::new().add_metric(MetricType::TicketVolume);
        assert!(matches!(
            q2.validate(),
            Err(AnalyticsError::InvalidTimeWindow(_))
        ));

        // Duplicate metrics
        let q3 = MetricQuery::new()
            .add_metric(MetricType::Csat)
            .add_metric(MetricType::Csat)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        assert!(matches!(
            q3.validate(),
            Err(AnalyticsError::DuplicateMetric(_))
        ));

        // Empty filter field
        let q4 = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily))
            .add_filter(MetricFilter::new("", FilterOp::Equals, "x"));
        assert!(matches!(
            q4.validate(),
            Err(AnalyticsError::InvalidFilter(_))
        ));
    }

    #[test]
    fn metric_series_with_labeled_points() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::with_label("d1", 10.0, "high"));
        s.add_point(MetricDataPoint::with_label("d1", 5.0, "low"));
        s.add_point(MetricDataPoint::with_label("d1", 8.0, "normal"));
        s.compute_stats();
        assert_eq!(s.len(), 3);
        assert!((s.total.unwrap() - 23.0).abs() < f64::EPSILON);
    }

    #[test]
    fn report_with_multiple_filters() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");
        report.add_filter_description("priority = high");
        report.add_filter_description("channel = email");
        report.add_filter_description("status != closed");
        assert_eq!(report.filters_applied.len(), 3);
    }

    #[test]
    fn metric_type_hash_in_set() {
        let mut set = std::collections::HashSet::new();
        set.insert(MetricType::TicketVolume);
        set.insert(MetricType::Csat);
        set.insert(MetricType::TicketVolume); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn granularity_hash_in_set() {
        let mut set = std::collections::HashSet::new();
        set.insert(Granularity::Hourly);
        set.insert(Granularity::Daily);
        set.insert(Granularity::Hourly);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn filter_op_all_variants() {
        let ops = [
            FilterOp::Equals,
            FilterOp::NotEquals,
            FilterOp::GreaterThan,
            FilterOp::LessThan,
            FilterOp::In,
            FilterOp::NotIn,
        ];
        let mut strs = std::collections::HashSet::new();
        for op in &ops {
            assert!(strs.insert(op.as_str()));
        }
        assert_eq!(strs.len(), 6);
    }

    #[test]
    fn aggregate_values_median_even_count() {
        let vals = [1.0, 2.0, 3.0, 4.0];
        let result = aggregate_values(&vals, Aggregation::Median).unwrap();
        assert!((result - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_p95_small() {
        let vals = [1.0, 2.0, 3.0, 4.0, 5.0];
        let result = aggregate_values(&vals, Aggregation::P95).unwrap();
        // 5 * 0.95 = 4.75, ceil = 5, idx = 4, value = 5.0
        assert!((result - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn report_summary_clone() {
        let s = ReportSummary {
            total_tickets: Some(100),
            avg_first_response_hours: Some(1.23),
            avg_resolution_hours: Some(12.0),
            csat_score: Some(88.0),
            backlog_size: Some(5),
        };
        let cloned = s.clone();
        assert_eq!(s.total_tickets, cloned.total_tickets);
        assert_eq!(s.backlog_size, cloned.backlog_size);
    }

    #[test]
    fn analytics_report_clone() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");
        report.add_series(MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum));
        let cloned = report.clone();
        assert_eq!(report.series_count(), cloned.series_count());
    }

    #[test]
    fn audit_event_clone() {
        let event = AnalyticsAuditEvent {
            timestamp: "2026-02-01".to_string(),
            query_type: "standard".to_string(),
            metric_count: 2,
            time_range: "jan".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event.timestamp, cloned.timestamp);
    }

    #[test]
    fn metric_query_clone() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily));
        let cloned = q.clone();
        assert_eq!(q.metrics.len(), cloned.metrics.len());
    }

    #[test]
    fn metric_series_min_max_negative_values() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("d1", -5.0));
        s.add_point(MetricDataPoint::new("d2", -10.0));
        s.add_point(MetricDataPoint::new("d3", -1.0));
        assert!((s.min().unwrap() - (-10.0)).abs() < f64::EPSILON);
        assert!((s.max().unwrap() - (-1.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn validate_csat_score_boundary_zero() {
        assert!(validate_csat_score(0.0).is_ok());
    }

    #[test]
    fn validate_csat_score_boundary_hundred() {
        assert!(validate_csat_score(100.0).is_ok());
    }

    #[test]
    fn time_window_validate_error_message_content() {
        let tw = TimeWindow::new("", "2026-01-31", Granularity::Daily);
        let err = tw.validate().unwrap_err();
        assert!(err.to_string().contains("start timestamp"));
    }

    #[test]
    fn aggregate_values_sum_single() {
        let result = aggregate_values(&[42.0], Aggregation::Sum).unwrap();
        assert!((result - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_average_single() {
        let result = aggregate_values(&[42.0], Aggregation::Average).unwrap();
        assert!((result - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_values_count_single() {
        let result = aggregate_values(&[42.0], Aggregation::Count).unwrap();
        assert!((result - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_query_all_metrics() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .add_metric(MetricType::FirstResponseTime)
            .add_metric(MetricType::ResolutionTime)
            .add_metric(MetricType::BacklogDepth)
            .add_metric(MetricType::Csat)
            .add_metric(MetricType::AgentWorkload)
            .add_metric(MetricType::ReopenRate)
            .add_metric(MetricType::OneTouch)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-12-31", Granularity::Monthly));
        assert_eq!(q.metric_count(), 8);
        assert!(q.validate().is_ok());
        assert!(q.includes_agent_workload());
    }

    #[test]
    fn sanitize_agent_workload_large_spread() {
        let counts = vec![1, 5, 10, 50, 100];
        let (avg, min, max, std_dev) = sanitize_agent_workload(&counts);
        assert!((min - 1.0).abs() < f64::EPSILON);
        assert!((max - 100.0).abs() < f64::EPSILON);
        assert!((avg - 33.2).abs() < 0.1);
        assert!(std_dev > 35.0);
    }

    #[test]
    fn metric_series_trend_flat_with_tiny_variation() {
        let mut s = MetricSeries::new(MetricType::Csat, Aggregation::Average);
        s.add_point(MetricDataPoint::new("d1", 100.0));
        s.add_point(MetricDataPoint::new("d2", 100.1));
        s.add_point(MetricDataPoint::new("d3", 99.9));
        s.add_point(MetricDataPoint::new("d4", 100.0));
        assert_eq!(s.trend(), Trend::Stable);
    }

    #[test]
    fn report_summary_ignores_non_summary_metrics() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let mut report = AnalyticsReport::new(tw, "2026-02-01");

        let mut s = MetricSeries::new(MetricType::AgentWorkload, Aggregation::Average);
        s.add_point(MetricDataPoint::new("d1", 15.0));
        s.compute_stats();
        report.add_series(s);

        let mut s2 = MetricSeries::new(MetricType::ReopenRate, Aggregation::Average);
        s2.add_point(MetricDataPoint::new("d1", 5.0));
        s2.compute_stats();
        report.add_series(s2);

        let summary = report.summary();
        // AgentWorkload and ReopenRate don't map to summary fields
        assert!(summary.is_empty());
    }

    #[test]
    fn metric_query_serde_with_filters() {
        let q = MetricQuery::new()
            .add_metric(MetricType::TicketVolume)
            .with_time_window(TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily))
            .add_filter(MetricFilter::new("priority", FilterOp::In, "high,urgent"))
            .add_filter(MetricFilter::new("channel", FilterOp::Equals, "email"));
        let json = serde_json::to_string(&q).unwrap();
        let parsed: MetricQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.filters.len(), 2);
        assert_eq!(parsed.filters[0].operator, FilterOp::In);
    }

    #[test]
    fn group_by_serde_all_variants() {
        let variants = [
            GroupBy::Category,
            GroupBy::Priority,
            GroupBy::Channel,
            GroupBy::Group,
            GroupBy::Brand,
            GroupBy::Status,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let parsed: GroupBy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *v);
        }
    }

    #[test]
    fn aggregation_serde_all_variants() {
        let variants = [
            Aggregation::Sum,
            Aggregation::Average,
            Aggregation::Median,
            Aggregation::P95,
            Aggregation::Count,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let parsed: Aggregation = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *v);
        }
    }

    #[test]
    fn trend_serde_all_variants() {
        let variants = [
            Trend::Increasing,
            Trend::Decreasing,
            Trend::Stable,
            Trend::Insufficient,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let parsed: Trend = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *v);
        }
    }

    #[test]
    fn data_point_with_label_serde() {
        let dp = MetricDataPoint::with_label("2026-03-01", 55.5, "category_a");
        let json = serde_json::to_string(&dp).unwrap();
        let parsed: MetricDataPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label, Some("category_a".to_string()));
    }

    #[test]
    fn metric_filter_serde_all_ops() {
        let ops = [
            FilterOp::Equals,
            FilterOp::NotEquals,
            FilterOp::GreaterThan,
            FilterOp::LessThan,
            FilterOp::In,
            FilterOp::NotIn,
        ];
        for op in &ops {
            let f = MetricFilter::new("field", *op, "val");
            let json = serde_json::to_string(&f).unwrap();
            let parsed: MetricFilter = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.operator, *op);
        }
    }

    #[test]
    fn build_series_with_labeled_data() {
        let points = vec![
            MetricDataPoint::with_label("d1", 10.0, "email"),
            MetricDataPoint::with_label("d1", 20.0, "chat"),
            MetricDataPoint::with_label("d1", 30.0, "phone"),
        ];
        let s = build_series(MetricType::TicketVolume, points, Aggregation::Sum);
        assert!((s.total.unwrap() - 60.0).abs() < f64::EPSILON);
        assert_eq!(s.data_points[0].label.as_deref(), Some("email"));
    }

    #[test]
    fn compute_median_large_dataset() {
        let mut v: Vec<f64> = (1..=101).map(f64::from).collect();
        let median = compute_median(&mut v).unwrap();
        assert!((median - 51.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_series_compute_stats_single_point() {
        let mut s = MetricSeries::new(MetricType::Csat, Aggregation::Average);
        s.add_point(MetricDataPoint::new("d1", 75.0));
        s.compute_stats();
        assert!((s.total.unwrap() - 75.0).abs() < f64::EPSILON);
        assert!((s.average.unwrap() - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn analytics_report_generated_at() {
        let tw = TimeWindow::new("2026-01-01", "2026-01-31", Granularity::Daily);
        let report = AnalyticsReport::new(tw, "2026-02-01T12:00:00Z");
        assert_eq!(report.generated_at, "2026-02-01T12:00:00Z");
    }

    #[test]
    fn metric_series_trend_steep_increase() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("d1", 1.0));
        s.add_point(MetricDataPoint::new("d2", 10.0));
        s.add_point(MetricDataPoint::new("d3", 100.0));
        s.add_point(MetricDataPoint::new("d4", 1000.0));
        assert_eq!(s.trend(), Trend::Increasing);
    }

    #[test]
    fn metric_series_trend_steep_decrease() {
        let mut s = MetricSeries::new(MetricType::TicketVolume, Aggregation::Sum);
        s.add_point(MetricDataPoint::new("d1", 1000.0));
        s.add_point(MetricDataPoint::new("d2", 100.0));
        s.add_point(MetricDataPoint::new("d3", 10.0));
        s.add_point(MetricDataPoint::new("d4", 1.0));
        assert_eq!(s.trend(), Trend::Decreasing);
    }
}
