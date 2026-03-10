//! Microsoft Planner integration for Microsoft 365 connector.
//!
//! Provides types and policy enforcement for Microsoft Planner plans,
//! buckets, tasks, comments, checklists, and assignments via Microsoft Graph.
//! Write operations are capability-gated, emit audit receipts, and fail closed.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A Microsoft Planner plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub title: String,
    #[serde(
        rename = "ownerGroupId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_group_id: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(
        rename = "containerId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub container_id: Option<String>,
}

/// A bucket within a Planner plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bucket {
    pub id: String,
    pub name: String,
    #[serde(rename = "planId")]
    pub plan_id: String,
    #[serde(rename = "orderHint", default, skip_serializing_if = "Option::is_none")]
    pub order_hint: Option<String>,
}

/// Priority level for a Planner task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskPriority {
    Urgent,
    Important,
    Medium,
    Low,
    Unset,
}

impl TaskPriority {
    /// Convert to the Microsoft Graph numeric priority value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Urgent => 1,
            Self::Important => 3,
            Self::Medium => 5,
            Self::Low => 9,
            Self::Unset => 0,
        }
    }

    /// Convert from the Microsoft Graph numeric priority value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Urgent,
            2 | 3 => Self::Important,
            4..=6 => Self::Medium,
            7..=9 => Self::Low,
            _ => Self::Unset,
        }
    }
}

impl Default for TaskPriority {
    fn default() -> Self {
        Self::Unset
    }
}

impl fmt::Display for TaskPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Urgent => write!(f, "urgent"),
            Self::Important => write!(f, "important"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Unset => write!(f, "unset"),
        }
    }
}

/// A checklist item within a Planner task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistItem {
    pub id: String,
    pub title: String,
    #[serde(rename = "isChecked")]
    pub is_checked: bool,
}

/// A Planner task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerTask {
    pub id: String,
    pub title: String,
    #[serde(rename = "planId")]
    pub plan_id: String,
    #[serde(rename = "bucketId", default, skip_serializing_if = "Option::is_none")]
    pub bucket_id: Option<String>,
    #[serde(rename = "assignedTo", default)]
    pub assigned_to: Vec<String>,
    #[serde(rename = "dueDate", default, skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(rename = "startDate", default, skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    #[serde(rename = "percentComplete", default)]
    pub percent_complete: u8,
    #[serde(default)]
    pub priority: TaskPriority,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(rename = "checklistItems", default)]
    pub checklist_items: Vec<ChecklistItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl PlannerTask {
    /// Returns true when the task is 100% complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.percent_complete == 100
    }

    /// Returns true when the task has a due date that is before `now`.
    /// Both values are compared as ISO-8601 date strings (lexicographic).
    #[must_use]
    pub fn is_overdue_at(&self, now: &str) -> bool {
        match &self.due_date {
            Some(due) if !due.is_empty() => !self.is_complete() && due.as_str() < now,
            _ => false,
        }
    }
}

/// A comment on a Planner task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskComment {
    pub id: String,
    pub content: String,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Request to create a new Planner task (Dangerous operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    pub title: String,
    #[serde(rename = "planId")]
    pub plan_id: String,
    #[serde(rename = "bucketId", default, skip_serializing_if = "Option::is_none")]
    pub bucket_id: Option<String>,
    #[serde(rename = "assignedTo", default)]
    pub assigned_to: Vec<String>,
    #[serde(rename = "dueDate", default, skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(default)]
    pub priority: TaskPriority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl CreateTaskRequest {
    /// Validate the request fields. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.title.trim().is_empty() {
            return Err("title must not be empty".into());
        }
        if self.title.len() > 1024 {
            return Err("title must not exceed 1024 characters".into());
        }
        if self.plan_id.trim().is_empty() {
            return Err("plan_id must not be empty".into());
        }
        if self.assigned_to.len() > 20 {
            return Err("cannot assign to more than 20 users".into());
        }
        for assignee in &self.assigned_to {
            if assignee.trim().is_empty() {
                return Err("assignee id must not be empty".into());
            }
        }
        if let Some(desc) = &self.description {
            if desc.len() > 32_768 {
                return Err("description must not exceed 32768 characters".into());
            }
        }
        Ok(())
    }
}

/// Request to update an existing Planner task (Dangerous operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTaskRequest {
    #[serde(rename = "taskId")]
    pub task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "bucketId", default, skip_serializing_if = "Option::is_none")]
    pub bucket_id: Option<String>,
    #[serde(
        rename = "assignedTo",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assigned_to: Option<Vec<String>>,
    #[serde(rename = "dueDate", default, skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<TaskPriority>,
    #[serde(
        rename = "percentComplete",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub percent_complete: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl UpdateTaskRequest {
    /// Validate the request fields. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.task_id.trim().is_empty() {
            return Err("task_id must not be empty".into());
        }
        if let Some(title) = &self.title {
            if title.trim().is_empty() {
                return Err("title must not be empty when provided".into());
            }
            if title.len() > 1024 {
                return Err("title must not exceed 1024 characters".into());
            }
        }
        if let Some(pct) = self.percent_complete {
            if pct > 100 {
                return Err("percent_complete must be between 0 and 100".into());
            }
        }
        if let Some(assignees) = &self.assigned_to {
            if assignees.len() > 20 {
                return Err("cannot assign to more than 20 users".into());
            }
            for assignee in assignees {
                if assignee.trim().is_empty() {
                    return Err("assignee id must not be empty".into());
                }
            }
        }
        if let Some(desc) = &self.description {
            if desc.len() > 32_768 {
                return Err("description must not exceed 32768 characters".into());
            }
        }
        Ok(())
    }

    /// Returns true if at least one field would be updated.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.title.is_some()
            || self.bucket_id.is_some()
            || self.assigned_to.is_some()
            || self.due_date.is_some()
            || self.priority.is_some()
            || self.percent_complete.is_some()
            || self.description.is_some()
    }
}

// ---------------------------------------------------------------------------
// Query / filter types
// ---------------------------------------------------------------------------

/// Filter for task completion status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatusFilter {
    All,
    Active,
    Completed,
    Overdue,
}

impl Default for TaskStatusFilter {
    fn default() -> Self {
        Self::All
    }
}

impl fmt::Display for TaskStatusFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Active => write!(f, "active"),
            Self::Completed => write!(f, "completed"),
            Self::Overdue => write!(f, "overdue"),
        }
    }
}

/// Query parameters for listing Planner tasks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerQuery {
    #[serde(rename = "planId", default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    #[serde(rename = "bucketId", default, skip_serializing_if = "Option::is_none")]
    pub bucket_id: Option<String>,
    #[serde(
        rename = "assignedToFilter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assigned_to_filter: Option<String>,
    #[serde(rename = "statusFilter", default)]
    pub status_filter: Option<TaskStatusFilter>,
    #[serde(default = "PlannerQuery::default_limit")]
    pub limit: usize,
}

impl PlannerQuery {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;

    fn default_limit() -> usize {
        Self::DEFAULT_LIMIT
    }

    /// Create a new empty query.
    #[must_use]
    pub fn new() -> Self {
        Self {
            plan_id: None,
            bucket_id: None,
            assigned_to_filter: None,
            status_filter: None,
            limit: Self::DEFAULT_LIMIT,
        }
    }

    /// Filter by plan.
    #[must_use]
    pub fn for_plan(mut self, plan_id: impl Into<String>) -> Self {
        self.plan_id = Some(plan_id.into());
        self
    }

    /// Filter by bucket.
    #[must_use]
    pub fn for_bucket(mut self, bucket_id: impl Into<String>) -> Self {
        self.bucket_id = Some(bucket_id.into());
        self
    }

    /// Filter by assignee.
    #[must_use]
    pub fn assigned_to(mut self, user_id: impl Into<String>) -> Self {
        self.assigned_to_filter = Some(user_id.into());
        self
    }

    /// Filter by task status.
    #[must_use]
    pub fn with_status(mut self, status: TaskStatusFilter) -> Self {
        self.status_filter = Some(status);
        self
    }

    /// Set result limit.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Validate the query. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.limit == 0 {
            return Err("limit must be greater than 0".into());
        }
        if self.limit > Self::MAX_LIMIT {
            return Err(format!("limit must not exceed {}", Self::MAX_LIMIT));
        }
        if let Some(plan_id) = &self.plan_id {
            if plan_id.trim().is_empty() {
                return Err("plan_id filter must not be empty when provided".into());
            }
        }
        if let Some(bucket_id) = &self.bucket_id {
            if bucket_id.trim().is_empty() {
                return Err("bucket_id filter must not be empty when provided".into());
            }
        }
        if let Some(user_id) = &self.assigned_to_filter {
            if user_id.trim().is_empty() {
                return Err("assigned_to filter must not be empty when provided".into());
            }
        }
        Ok(())
    }

    /// Apply in-memory filters to a list of tasks, returning those that match.
    #[must_use]
    pub fn apply_filters(&self, tasks: &[PlannerTask], now: &str) -> Vec<PlannerTask> {
        let mut result: Vec<PlannerTask> = tasks
            .iter()
            .filter(|t| {
                if let Some(plan_id) = &self.plan_id {
                    if t.plan_id != *plan_id {
                        return false;
                    }
                }
                if let Some(bucket_id) = &self.bucket_id {
                    if t.bucket_id.as_deref() != Some(bucket_id.as_str()) {
                        return false;
                    }
                }
                if let Some(user_id) = &self.assigned_to_filter {
                    if !t.assigned_to.iter().any(|a| a == user_id) {
                        return false;
                    }
                }
                if let Some(status) = &self.status_filter {
                    match status {
                        TaskStatusFilter::All => {}
                        TaskStatusFilter::Active => {
                            if t.is_complete() {
                                return false;
                            }
                        }
                        TaskStatusFilter::Completed => {
                            if !t.is_complete() {
                                return false;
                            }
                        }
                        TaskStatusFilter::Overdue => {
                            if !t.is_overdue_at(now) {
                                return false;
                            }
                        }
                    }
                }
                true
            })
            .cloned()
            .collect();
        result.truncate(self.limit);
        result
    }
}

impl Default for PlannerQuery {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

/// Action categories for policy checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannerAction {
    Read,
    Create,
    Update,
    Delete,
    Assign,
}

impl fmt::Display for PlannerAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
            Self::Delete => write!(f, "delete"),
            Self::Assign => write!(f, "assign"),
        }
    }
}

/// Policy governing what Planner operations are allowed.
/// Default-deny: all actions are denied unless explicitly allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlannerPolicy {
    pub allow_read: bool,
    pub allow_create: bool,
    pub allow_update: bool,
    pub allow_delete: bool,
    pub allow_assign: bool,
    pub require_approval_for_create: bool,
    #[serde(
        rename = "maxTasksPerPlan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_tasks_per_plan: Option<usize>,
}

impl PlannerPolicy {
    /// Create a policy that allows all operations.
    #[must_use]
    pub const fn new_permissive() -> Self {
        Self {
            allow_read: true,
            allow_create: true,
            allow_update: true,
            allow_delete: true,
            allow_assign: true,
            require_approval_for_create: false,
            max_tasks_per_plan: None,
        }
    }

    /// Create a policy that only allows read operations (default deny for writes).
    #[must_use]
    pub const fn new_readonly() -> Self {
        Self {
            allow_read: true,
            allow_create: false,
            allow_update: false,
            allow_delete: false,
            allow_assign: false,
            require_approval_for_create: false,
            max_tasks_per_plan: None,
        }
    }

    /// Check whether the given action is allowed. Fails closed on deny.
    pub fn check_action(&self, action: PlannerAction) -> Result<(), String> {
        let allowed = match action {
            PlannerAction::Read => self.allow_read,
            PlannerAction::Create => self.allow_create,
            PlannerAction::Update => self.allow_update,
            PlannerAction::Delete => self.allow_delete,
            PlannerAction::Assign => self.allow_assign,
        };
        if allowed {
            Ok(())
        } else {
            Err(format!("policy denies {action} action"))
        }
    }

    /// Check whether creating a task would exceed the per-plan limit.
    pub fn check_task_limit(&self, current_count: usize) -> Result<(), String> {
        if let Some(max) = self.max_tasks_per_plan {
            if current_count >= max {
                return Err(format!(
                    "plan already has {current_count} tasks (max {max})"
                ));
            }
        }
        Ok(())
    }
}

impl Default for PlannerPolicy {
    /// Default is deny-all, matching the fail-closed requirement.
    fn default() -> Self {
        Self {
            allow_read: false,
            allow_create: false,
            allow_update: false,
            allow_delete: false,
            allow_assign: false,
            require_approval_for_create: false,
            max_tasks_per_plan: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// Audit event emitted for write operations (receipts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerAuditEvent {
    pub timestamp: String,
    pub action: String,
    #[serde(rename = "taskId", default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(rename = "planId")]
    pub plan_id: String,
    pub details: String,
}

impl PlannerAuditEvent {
    /// Create a new audit event.
    #[must_use]
    pub fn new(
        timestamp: impl Into<String>,
        action: impl Into<String>,
        plan_id: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: timestamp.into(),
            action: action.into(),
            task_id: None,
            plan_id: plan_id.into(),
            details: details.into(),
        }
    }

    /// Attach a task id to the audit event.
    #[must_use]
    pub fn with_task_id(mut self, task_id: impl Into<String>) -> Self {
        self.task_id = Some(task_id.into());
        self
    }
}

impl fmt::Display for PlannerAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} plan={} task={} {}",
            self.timestamp,
            self.action,
            self.plan_id,
            self.task_id.as_deref().unwrap_or("none"),
            self.details,
        )
    }
}

// ---------------------------------------------------------------------------
// Graph API URL helpers
// ---------------------------------------------------------------------------

/// Build the Microsoft Graph URL for a plan's tasks.
#[must_use]
pub fn graph_plan_tasks_url(plan_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/planner/plans/{plan_id}/tasks")
}

/// Build the Microsoft Graph URL for a plan's buckets.
#[must_use]
pub fn graph_plan_buckets_url(plan_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/planner/plans/{plan_id}/buckets")
}

/// Build the Microsoft Graph URL for a single task.
#[must_use]
pub fn graph_task_url(task_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/planner/tasks/{task_id}")
}

/// Build the Microsoft Graph URL for a single plan.
#[must_use]
pub fn graph_plan_url(plan_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/planner/plans/{plan_id}")
}

/// Build the Microsoft Graph URL for task details (description, checklist).
#[must_use]
pub fn graph_task_details_url(task_id: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/planner/tasks/{task_id}/details")
}

// ---------------------------------------------------------------------------
// Capability-gated operation wrappers
// ---------------------------------------------------------------------------

/// Execute a create-task operation with policy enforcement and audit.
/// Fails closed: if the policy denies the action, returns Err.
pub fn execute_create_task(
    policy: &PlannerPolicy,
    request: &CreateTaskRequest,
    current_task_count: usize,
    timestamp: &str,
) -> Result<PlannerAuditEvent, String> {
    policy.check_action(PlannerAction::Create)?;
    policy.check_task_limit(current_task_count)?;
    request.validate()?;

    if policy.require_approval_for_create {
        return Err("create requires approval (not yet approved)".into());
    }

    Ok(PlannerAuditEvent::new(
        timestamp,
        "create_task",
        &request.plan_id,
        format!("created task: {}", request.title),
    ))
}

/// Execute an update-task operation with policy enforcement and audit.
/// Fails closed: if the policy denies the action, returns Err.
pub fn execute_update_task(
    policy: &PlannerPolicy,
    request: &UpdateTaskRequest,
    plan_id: &str,
    timestamp: &str,
) -> Result<PlannerAuditEvent, String> {
    policy.check_action(PlannerAction::Update)?;
    request.validate()?;

    if !request.has_changes() {
        return Err("update request has no changes".into());
    }

    // If assignment is being changed, also check assign permission
    if request.assigned_to.is_some() {
        policy.check_action(PlannerAction::Assign)?;
    }

    Ok(
        PlannerAuditEvent::new(timestamp, "update_task", plan_id, "task updated")
            .with_task_id(&request.task_id),
    )
}

/// Execute a delete-task operation with policy enforcement and audit.
/// Fails closed: if the policy denies the action, returns Err.
pub fn execute_delete_task(
    policy: &PlannerPolicy,
    task_id: &str,
    plan_id: &str,
    timestamp: &str,
) -> Result<PlannerAuditEvent, String> {
    policy.check_action(PlannerAction::Delete)?;

    if task_id.trim().is_empty() {
        return Err("task_id must not be empty".into());
    }

    Ok(
        PlannerAuditEvent::new(timestamp, "delete_task", plan_id, "task deleted")
            .with_task_id(task_id),
    )
}

/// Execute an add-comment operation with policy enforcement and audit.
/// Commenting is treated as an update operation (Dangerous).
pub fn execute_add_comment(
    policy: &PlannerPolicy,
    task_id: &str,
    plan_id: &str,
    content: &str,
    timestamp: &str,
) -> Result<PlannerAuditEvent, String> {
    policy.check_action(PlannerAction::Update)?;

    if task_id.trim().is_empty() {
        return Err("task_id must not be empty".into());
    }
    if content.trim().is_empty() {
        return Err("comment content must not be empty".into());
    }
    if content.len() > 65_536 {
        return Err("comment content must not exceed 65536 characters".into());
    }

    Ok(
        PlannerAuditEvent::new(timestamp, "add_comment", plan_id, "comment added")
            .with_task_id(task_id),
    )
}

/// Execute an update-checklist operation with policy enforcement and audit.
/// Checklist mutations are treated as update operations (Dangerous).
pub fn execute_update_checklist(
    policy: &PlannerPolicy,
    task_id: &str,
    plan_id: &str,
    item_title: &str,
    timestamp: &str,
) -> Result<PlannerAuditEvent, String> {
    policy.check_action(PlannerAction::Update)?;

    if task_id.trim().is_empty() {
        return Err("task_id must not be empty".into());
    }
    if item_title.trim().is_empty() {
        return Err("checklist item title must not be empty".into());
    }

    Ok(PlannerAuditEvent::new(
        timestamp,
        "update_checklist",
        plan_id,
        format!("checklist item updated: {item_title}"),
    )
    .with_task_id(task_id))
}

/// Execute an assign-task operation with policy enforcement and audit.
pub fn execute_assign_task(
    policy: &PlannerPolicy,
    task_id: &str,
    plan_id: &str,
    assignee: &str,
    timestamp: &str,
) -> Result<PlannerAuditEvent, String> {
    policy.check_action(PlannerAction::Assign)?;

    if task_id.trim().is_empty() {
        return Err("task_id must not be empty".into());
    }
    if assignee.trim().is_empty() {
        return Err("assignee must not be empty".into());
    }

    Ok(PlannerAuditEvent::new(
        timestamp,
        "assign_task",
        plan_id,
        format!("task assigned to {assignee}"),
    )
    .with_task_id(task_id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Plan ==========

    #[test]
    fn plan_serde_roundtrip() {
        let plan = Plan {
            id: "plan-1".into(),
            title: "Sprint 42".into(),
            owner_group_id: Some("group-abc".into()),
            created_at: Some("2026-01-15T09:00:00Z".into()),
            container_id: Some("container-x".into()),
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["id"], "plan-1");
        assert_eq!(json["title"], "Sprint 42");
        assert_eq!(json["ownerGroupId"], "group-abc");
        assert_eq!(json["createdAt"], "2026-01-15T09:00:00Z");
        assert_eq!(json["containerId"], "container-x");
        let back: Plan = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "plan-1");
        assert_eq!(back.owner_group_id.as_deref(), Some("group-abc"));
    }

    #[test]
    fn plan_optional_fields_absent() {
        let json = serde_json::json!({"id": "p-1", "title": "Minimal"});
        let plan: Plan = serde_json::from_value(json).unwrap();
        assert!(plan.owner_group_id.is_none());
        assert!(plan.created_at.is_none());
        assert!(plan.container_id.is_none());
    }

    #[test]
    fn plan_clone() {
        let plan = Plan {
            id: "c-1".into(),
            title: "Cloned".into(),
            owner_group_id: None,
            created_at: None,
            container_id: None,
        };
        let cloned = plan.clone();
        assert_eq!(cloned.id, plan.id);
        assert_eq!(cloned.title, plan.title);
    }

    #[test]
    fn plan_debug() {
        let plan = Plan {
            id: "dbg-1".into(),
            title: "Debug".into(),
            owner_group_id: None,
            created_at: None,
            container_id: None,
        };
        let debug = format!("{plan:?}");
        assert!(debug.contains("Plan"), "got: {debug}");
    }

    #[test]
    fn plan_skip_serializing_none() {
        let plan = Plan {
            id: "p-2".into(),
            title: "Sparse".into(),
            owner_group_id: None,
            created_at: None,
            container_id: None,
        };
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json.get("ownerGroupId").is_none());
        assert!(json.get("createdAt").is_none());
        assert!(json.get("containerId").is_none());
    }

    // ========== Bucket ==========

    #[test]
    fn bucket_serde_roundtrip() {
        let bucket = Bucket {
            id: "bucket-1".into(),
            name: "To Do".into(),
            plan_id: "plan-1".into(),
            order_hint: Some("8585371793".into()),
        };
        let json = serde_json::to_value(&bucket).unwrap();
        assert_eq!(json["id"], "bucket-1");
        assert_eq!(json["name"], "To Do");
        assert_eq!(json["planId"], "plan-1");
        assert_eq!(json["orderHint"], "8585371793");
        let back: Bucket = serde_json::from_value(json).unwrap();
        assert_eq!(back.plan_id, "plan-1");
    }

    #[test]
    fn bucket_optional_order_hint() {
        let json = serde_json::json!({"id": "b-1", "name": "Done", "planId": "p-1"});
        let bucket: Bucket = serde_json::from_value(json).unwrap();
        assert!(bucket.order_hint.is_none());
    }

    #[test]
    fn bucket_clone() {
        let bucket = Bucket {
            id: "b-c".into(),
            name: "Clone".into(),
            plan_id: "p-c".into(),
            order_hint: None,
        };
        let cloned = bucket.clone();
        assert_eq!(cloned.id, bucket.id);
        assert_eq!(cloned.name, bucket.name);
    }

    #[test]
    fn bucket_debug() {
        let bucket = Bucket {
            id: "b-d".into(),
            name: "Debug".into(),
            plan_id: "p-d".into(),
            order_hint: None,
        };
        let debug = format!("{bucket:?}");
        assert!(debug.contains("Bucket"), "got: {debug}");
    }

    // ========== TaskPriority ==========

    #[test]
    fn task_priority_as_u8() {
        assert_eq!(TaskPriority::Urgent.as_u8(), 1);
        assert_eq!(TaskPriority::Important.as_u8(), 3);
        assert_eq!(TaskPriority::Medium.as_u8(), 5);
        assert_eq!(TaskPriority::Low.as_u8(), 9);
        assert_eq!(TaskPriority::Unset.as_u8(), 0);
    }

    #[test]
    fn task_priority_from_u8_exact() {
        assert_eq!(TaskPriority::from_u8(1), TaskPriority::Urgent);
        assert_eq!(TaskPriority::from_u8(3), TaskPriority::Important);
        assert_eq!(TaskPriority::from_u8(5), TaskPriority::Medium);
        assert_eq!(TaskPriority::from_u8(9), TaskPriority::Low);
        assert_eq!(TaskPriority::from_u8(0), TaskPriority::Unset);
    }

    #[test]
    fn task_priority_from_u8_ranges() {
        assert_eq!(TaskPriority::from_u8(2), TaskPriority::Important);
        assert_eq!(TaskPriority::from_u8(4), TaskPriority::Medium);
        assert_eq!(TaskPriority::from_u8(6), TaskPriority::Medium);
        assert_eq!(TaskPriority::from_u8(7), TaskPriority::Low);
        assert_eq!(TaskPriority::from_u8(8), TaskPriority::Low);
    }

    #[test]
    fn task_priority_from_u8_out_of_range() {
        assert_eq!(TaskPriority::from_u8(10), TaskPriority::Unset);
        assert_eq!(TaskPriority::from_u8(255), TaskPriority::Unset);
    }

    #[test]
    fn task_priority_roundtrip_via_u8() {
        for prio in [
            TaskPriority::Urgent,
            TaskPriority::Important,
            TaskPriority::Medium,
            TaskPriority::Low,
            TaskPriority::Unset,
        ] {
            assert_eq!(TaskPriority::from_u8(prio.as_u8()), prio);
        }
    }

    #[test]
    fn task_priority_default_is_unset() {
        assert_eq!(TaskPriority::default(), TaskPriority::Unset);
    }

    #[test]
    fn task_priority_display() {
        assert_eq!(TaskPriority::Urgent.to_string(), "urgent");
        assert_eq!(TaskPriority::Important.to_string(), "important");
        assert_eq!(TaskPriority::Medium.to_string(), "medium");
        assert_eq!(TaskPriority::Low.to_string(), "low");
        assert_eq!(TaskPriority::Unset.to_string(), "unset");
    }

    #[test]
    fn task_priority_serde_roundtrip() {
        let json = serde_json::to_value(TaskPriority::Urgent).unwrap();
        let back: TaskPriority = serde_json::from_value(json).unwrap();
        assert_eq!(back, TaskPriority::Urgent);
    }

    #[test]
    fn task_priority_clone_copy() {
        let prio = TaskPriority::Medium;
        let cloned = prio;
        assert_eq!(cloned, TaskPriority::Medium);
    }

    #[test]
    fn task_priority_eq() {
        assert_eq!(TaskPriority::Urgent, TaskPriority::Urgent);
        assert_ne!(TaskPriority::Urgent, TaskPriority::Low);
    }

    #[test]
    fn task_priority_debug() {
        let debug = format!("{:?}", TaskPriority::Important);
        assert!(debug.contains("Important"), "got: {debug}");
    }

    // ========== ChecklistItem ==========

    #[test]
    fn checklist_item_serde_roundtrip() {
        let item = ChecklistItem {
            id: "cl-1".into(),
            title: "Buy milk".into(),
            is_checked: false,
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["id"], "cl-1");
        assert_eq!(json["title"], "Buy milk");
        assert_eq!(json["isChecked"], false);
        let back: ChecklistItem = serde_json::from_value(json).unwrap();
        assert!(!back.is_checked);
    }

    #[test]
    fn checklist_item_checked() {
        let json = serde_json::json!({"id": "cl-2", "title": "Done", "isChecked": true});
        let item: ChecklistItem = serde_json::from_value(json).unwrap();
        assert!(item.is_checked);
    }

    #[test]
    fn checklist_item_clone() {
        let item = ChecklistItem {
            id: "cl-c".into(),
            title: "Clone".into(),
            is_checked: true,
        };
        let cloned = item.clone();
        assert_eq!(cloned.id, item.id);
        assert_eq!(cloned.is_checked, item.is_checked);
    }

    #[test]
    fn checklist_item_debug() {
        let item = ChecklistItem {
            id: "cl-d".into(),
            title: "Debug".into(),
            is_checked: false,
        };
        let debug = format!("{item:?}");
        assert!(debug.contains("ChecklistItem"), "got: {debug}");
    }

    // ========== PlannerTask ==========

    #[test]
    fn planner_task_serde_roundtrip() {
        let task = PlannerTask {
            id: "task-1".into(),
            title: "Implement feature".into(),
            plan_id: "plan-1".into(),
            bucket_id: Some("bucket-1".into()),
            assigned_to: vec!["user-a".into(), "user-b".into()],
            due_date: Some("2026-04-01".into()),
            start_date: Some("2026-03-01".into()),
            percent_complete: 50,
            priority: TaskPriority::Important,
            created_at: Some("2026-02-28T10:00:00Z".into()),
            completed_at: None,
            checklist_items: vec![ChecklistItem {
                id: "cl-1".into(),
                title: "Step 1".into(),
                is_checked: true,
            }],
            description: Some("Build the thing".into()),
        };
        let json = serde_json::to_value(&task).unwrap();
        assert_eq!(json["id"], "task-1");
        assert_eq!(json["planId"], "plan-1");
        assert_eq!(json["bucketId"], "bucket-1");
        assert_eq!(json["percentComplete"], 50);
        assert_eq!(json["assignedTo"].as_array().unwrap().len(), 2);
        assert_eq!(json["checklistItems"].as_array().unwrap().len(), 1);
        let back: PlannerTask = serde_json::from_value(json).unwrap();
        assert_eq!(back.assigned_to.len(), 2);
    }

    #[test]
    fn planner_task_minimal() {
        let json = serde_json::json!({"id": "t-m", "title": "Min", "planId": "p-m"});
        let task: PlannerTask = serde_json::from_value(json).unwrap();
        assert!(task.bucket_id.is_none());
        assert!(task.assigned_to.is_empty());
        assert_eq!(task.percent_complete, 0);
        assert_eq!(task.priority, TaskPriority::Unset);
        assert!(task.checklist_items.is_empty());
        assert!(task.description.is_none());
    }

    #[test]
    fn planner_task_is_complete_true() {
        let task = make_task("t-1", "p-1", 100);
        assert!(task.is_complete());
    }

    #[test]
    fn planner_task_is_complete_false() {
        let task = make_task("t-2", "p-1", 99);
        assert!(!task.is_complete());
    }

    #[test]
    fn planner_task_is_complete_zero() {
        let task = make_task("t-3", "p-1", 0);
        assert!(!task.is_complete());
    }

    #[test]
    fn planner_task_overdue_when_past_due() {
        let mut task = make_task("t-4", "p-1", 50);
        task.due_date = Some("2026-03-01".into());
        assert!(task.is_overdue_at("2026-03-02"));
    }

    #[test]
    fn planner_task_not_overdue_when_complete() {
        let mut task = make_task("t-5", "p-1", 100);
        task.due_date = Some("2026-03-01".into());
        assert!(!task.is_overdue_at("2026-03-02"));
    }

    #[test]
    fn planner_task_not_overdue_when_due_today() {
        let mut task = make_task("t-6", "p-1", 50);
        task.due_date = Some("2026-03-02".into());
        assert!(!task.is_overdue_at("2026-03-02"));
    }

    #[test]
    fn planner_task_not_overdue_when_due_in_future() {
        let mut task = make_task("t-7", "p-1", 30);
        task.due_date = Some("2026-04-01".into());
        assert!(!task.is_overdue_at("2026-03-15"));
    }

    #[test]
    fn planner_task_not_overdue_when_no_due_date() {
        let task = make_task("t-8", "p-1", 50);
        assert!(!task.is_overdue_at("2026-03-15"));
    }

    #[test]
    fn planner_task_not_overdue_when_empty_due_date() {
        let mut task = make_task("t-9", "p-1", 50);
        task.due_date = Some(String::new());
        assert!(!task.is_overdue_at("2026-03-15"));
    }

    #[test]
    fn planner_task_clone() {
        let task = make_task("t-clone", "p-1", 25);
        let cloned = task.clone();
        assert_eq!(cloned.id, task.id);
        assert_eq!(cloned.percent_complete, task.percent_complete);
    }

    #[test]
    fn planner_task_debug() {
        let task = make_task("t-dbg", "p-1", 0);
        let debug = format!("{task:?}");
        assert!(debug.contains("PlannerTask"), "got: {debug}");
    }

    #[test]
    fn planner_task_with_checklist() {
        let mut task = make_task("t-cl", "p-1", 0);
        task.checklist_items = vec![
            ChecklistItem {
                id: "a".into(),
                title: "A".into(),
                is_checked: false,
            },
            ChecklistItem {
                id: "b".into(),
                title: "B".into(),
                is_checked: true,
            },
        ];
        assert_eq!(task.checklist_items.len(), 2);
        assert!(task.checklist_items[1].is_checked);
    }

    #[test]
    fn planner_task_with_description() {
        let mut task = make_task("t-desc", "p-1", 0);
        task.description = Some("A long description".into());
        let json = serde_json::to_value(&task).unwrap();
        assert_eq!(json["description"], "A long description");
    }

    #[test]
    fn planner_task_skip_serializing_none_fields() {
        let task = make_task("t-skip", "p-1", 0);
        let json = serde_json::to_value(&task).unwrap();
        assert!(json.get("bucketId").is_none());
        assert!(json.get("dueDate").is_none());
        assert!(json.get("startDate").is_none());
        assert!(json.get("createdAt").is_none());
        assert!(json.get("completedAt").is_none());
        assert!(json.get("description").is_none());
    }

    // ========== TaskComment ==========

    #[test]
    fn task_comment_serde_roundtrip() {
        let comment = TaskComment {
            id: "cmt-1".into(),
            content: "Looks good to me".into(),
            created_by: Some("user-alice".into()),
            created_at: Some("2026-03-05T14:00:00Z".into()),
        };
        let json = serde_json::to_value(&comment).unwrap();
        assert_eq!(json["id"], "cmt-1");
        assert_eq!(json["content"], "Looks good to me");
        assert_eq!(json["createdBy"], "user-alice");
        let back: TaskComment = serde_json::from_value(json).unwrap();
        assert_eq!(back.created_by.as_deref(), Some("user-alice"));
    }

    #[test]
    fn task_comment_minimal() {
        let json = serde_json::json!({"id": "cmt-m", "content": "hi"});
        let comment: TaskComment = serde_json::from_value(json).unwrap();
        assert!(comment.created_by.is_none());
        assert!(comment.created_at.is_none());
    }

    #[test]
    fn task_comment_clone() {
        let comment = TaskComment {
            id: "cmt-c".into(),
            content: "Clone me".into(),
            created_by: None,
            created_at: None,
        };
        let cloned = comment.clone();
        assert_eq!(cloned.id, comment.id);
        assert_eq!(cloned.content, comment.content);
    }

    #[test]
    fn task_comment_debug() {
        let comment = TaskComment {
            id: "cmt-d".into(),
            content: "Debug".into(),
            created_by: None,
            created_at: None,
        };
        let debug = format!("{comment:?}");
        assert!(debug.contains("TaskComment"), "got: {debug}");
    }

    // ========== CreateTaskRequest ==========

    #[test]
    fn create_task_request_valid() {
        let req = CreateTaskRequest {
            title: "New task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Medium,
            description: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn create_task_request_empty_title() {
        let req = CreateTaskRequest {
            title: "   ".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("title"), "got: {err}");
    }

    #[test]
    fn create_task_request_title_too_long() {
        let req = CreateTaskRequest {
            title: "x".repeat(1025),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("1024"), "got: {err}");
    }

    #[test]
    fn create_task_request_empty_plan_id() {
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: " ".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("plan_id"), "got: {err}");
    }

    #[test]
    fn create_task_request_too_many_assignees() {
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: (0..21).map(|i| format!("user-{i}")).collect(),
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("20"), "got: {err}");
    }

    #[test]
    fn create_task_request_empty_assignee_id() {
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec!["  ".into()],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("assignee"), "got: {err}");
    }

    #[test]
    fn create_task_request_description_too_long() {
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: Some("x".repeat(32_769)),
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("32768"), "got: {err}");
    }

    #[test]
    fn create_task_request_serde_roundtrip() {
        let req = CreateTaskRequest {
            title: "Serde test".into(),
            plan_id: "p-1".into(),
            bucket_id: Some("b-1".into()),
            assigned_to: vec!["u-1".into()],
            due_date: Some("2026-04-01".into()),
            priority: TaskPriority::Urgent,
            description: Some("desc".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["title"], "Serde test");
        assert_eq!(json["planId"], "p-1");
        let back: CreateTaskRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.title, "Serde test");
    }

    #[test]
    fn create_task_request_clone() {
        let req = CreateTaskRequest {
            title: "Clone".into(),
            plan_id: "p-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Low,
            description: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.title, req.title);
        assert_eq!(cloned.priority, req.priority);
    }

    #[test]
    fn create_task_request_debug() {
        let req = CreateTaskRequest {
            title: "Debug".into(),
            plan_id: "p-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("CreateTaskRequest"), "got: {debug}");
    }

    #[test]
    fn create_task_request_max_valid_title() {
        let req = CreateTaskRequest {
            title: "x".repeat(1024),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn create_task_request_max_valid_assignees() {
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: (0..20).map(|i| format!("user-{i}")).collect(),
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn create_task_request_max_valid_description() {
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: Some("x".repeat(32_768)),
        };
        assert!(req.validate().is_ok());
    }

    // ========== UpdateTaskRequest ==========

    #[test]
    fn update_task_request_valid() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: Some("Updated".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        assert!(req.validate().is_ok());
        assert!(req.has_changes());
    }

    #[test]
    fn update_task_request_empty_task_id() {
        let req = UpdateTaskRequest {
            task_id: "  ".into(),
            title: Some("X".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("task_id"), "got: {err}");
    }

    #[test]
    fn update_task_request_empty_title_when_provided() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: Some("  ".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("title"), "got: {err}");
    }

    #[test]
    fn update_task_request_title_too_long() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: Some("x".repeat(1025)),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("1024"), "got: {err}");
    }

    #[test]
    fn update_task_request_percent_complete_over_100() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: Some(101),
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("100"), "got: {err}");
    }

    #[test]
    fn update_task_request_percent_complete_100_valid() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: Some(100),
            description: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn update_task_request_no_changes() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        assert!(!req.has_changes());
    }

    #[test]
    fn update_task_request_has_changes_each_field() {
        // title
        let mut req = empty_update("t-1");
        req.title = Some("X".into());
        assert!(req.has_changes());

        // bucket_id
        let mut req = empty_update("t-1");
        req.bucket_id = Some("b-1".into());
        assert!(req.has_changes());

        // assigned_to
        let mut req = empty_update("t-1");
        req.assigned_to = Some(vec![]);
        assert!(req.has_changes());

        // due_date
        let mut req = empty_update("t-1");
        req.due_date = Some("2026-04-01".into());
        assert!(req.has_changes());

        // priority
        let mut req = empty_update("t-1");
        req.priority = Some(TaskPriority::Urgent);
        assert!(req.has_changes());

        // percent_complete
        let mut req = empty_update("t-1");
        req.percent_complete = Some(50);
        assert!(req.has_changes());

        // description
        let mut req = empty_update("t-1");
        req.description = Some("desc".into());
        assert!(req.has_changes());
    }

    #[test]
    fn update_task_request_too_many_assignees() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: Some((0..21).map(|i| format!("u-{i}")).collect()),
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("20"), "got: {err}");
    }

    #[test]
    fn update_task_request_empty_assignee_id() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: Some(vec!["valid".into(), "  ".into()]),
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("assignee"), "got: {err}");
    }

    #[test]
    fn update_task_request_description_too_long() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: Some("x".repeat(32_769)),
        };
        let err = req.validate().unwrap_err();
        assert!(err.contains("32768"), "got: {err}");
    }

    #[test]
    fn update_task_request_serde_roundtrip() {
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: Some("Serde".into()),
            bucket_id: Some("b-1".into()),
            assigned_to: Some(vec!["u-1".into()]),
            due_date: Some("2026-05-01".into()),
            priority: Some(TaskPriority::Low),
            percent_complete: Some(75),
            description: Some("desc".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["taskId"], "task-1");
        let back: UpdateTaskRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.task_id, "task-1");
        assert_eq!(back.percent_complete, Some(75));
    }

    #[test]
    fn update_task_request_clone() {
        let req = UpdateTaskRequest {
            task_id: "t-c".into(),
            title: Some("Clone".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let cloned = req.clone();
        assert_eq!(cloned.task_id, req.task_id);
    }

    #[test]
    fn update_task_request_debug() {
        let req = empty_update("t-d");
        let debug = format!("{req:?}");
        assert!(debug.contains("UpdateTaskRequest"), "got: {debug}");
    }

    // ========== TaskStatusFilter ==========

    #[test]
    fn task_status_filter_default() {
        assert_eq!(TaskStatusFilter::default(), TaskStatusFilter::All);
    }

    #[test]
    fn task_status_filter_display() {
        assert_eq!(TaskStatusFilter::All.to_string(), "all");
        assert_eq!(TaskStatusFilter::Active.to_string(), "active");
        assert_eq!(TaskStatusFilter::Completed.to_string(), "completed");
        assert_eq!(TaskStatusFilter::Overdue.to_string(), "overdue");
    }

    #[test]
    fn task_status_filter_serde_roundtrip() {
        for filter in [
            TaskStatusFilter::All,
            TaskStatusFilter::Active,
            TaskStatusFilter::Completed,
            TaskStatusFilter::Overdue,
        ] {
            let json = serde_json::to_value(filter).unwrap();
            let back: TaskStatusFilter = serde_json::from_value(json).unwrap();
            assert_eq!(back, filter);
        }
    }

    #[test]
    fn task_status_filter_eq() {
        assert_eq!(TaskStatusFilter::Active, TaskStatusFilter::Active);
        assert_ne!(TaskStatusFilter::Active, TaskStatusFilter::Completed);
    }

    #[test]
    fn task_status_filter_debug() {
        let debug = format!("{:?}", TaskStatusFilter::Overdue);
        assert!(debug.contains("Overdue"), "got: {debug}");
    }

    // ========== PlannerQuery ==========

    #[test]
    fn planner_query_defaults() {
        let q = PlannerQuery::new();
        assert!(q.plan_id.is_none());
        assert!(q.bucket_id.is_none());
        assert!(q.assigned_to_filter.is_none());
        assert!(q.status_filter.is_none());
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn planner_query_default_trait() {
        let q = PlannerQuery::default();
        assert_eq!(q.limit, 50);
    }

    #[test]
    fn planner_query_builder_for_plan() {
        let q = PlannerQuery::new().for_plan("plan-1");
        assert_eq!(q.plan_id.as_deref(), Some("plan-1"));
    }

    #[test]
    fn planner_query_builder_for_bucket() {
        let q = PlannerQuery::new().for_bucket("bucket-1");
        assert_eq!(q.bucket_id.as_deref(), Some("bucket-1"));
    }

    #[test]
    fn planner_query_builder_assigned_to() {
        let q = PlannerQuery::new().assigned_to("user-1");
        assert_eq!(q.assigned_to_filter.as_deref(), Some("user-1"));
    }

    #[test]
    fn planner_query_builder_with_status() {
        let q = PlannerQuery::new().with_status(TaskStatusFilter::Active);
        assert_eq!(q.status_filter, Some(TaskStatusFilter::Active));
    }

    #[test]
    fn planner_query_builder_with_limit() {
        let q = PlannerQuery::new().with_limit(100);
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn planner_query_builder_chained() {
        let q = PlannerQuery::new()
            .for_plan("p-1")
            .for_bucket("b-1")
            .assigned_to("u-1")
            .with_status(TaskStatusFilter::Completed)
            .with_limit(10);
        assert_eq!(q.plan_id.as_deref(), Some("p-1"));
        assert_eq!(q.bucket_id.as_deref(), Some("b-1"));
        assert_eq!(q.assigned_to_filter.as_deref(), Some("u-1"));
        assert_eq!(q.status_filter, Some(TaskStatusFilter::Completed));
        assert_eq!(q.limit, 10);
    }

    #[test]
    fn planner_query_validate_ok() {
        let q = PlannerQuery::new().for_plan("p-1").with_limit(100);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn planner_query_validate_zero_limit() {
        let q = PlannerQuery::new().with_limit(0);
        let err = q.validate().unwrap_err();
        assert!(err.contains("greater than 0"), "got: {err}");
    }

    #[test]
    fn planner_query_validate_exceeds_max_limit() {
        let q = PlannerQuery::new().with_limit(201);
        let err = q.validate().unwrap_err();
        assert!(err.contains("200"), "got: {err}");
    }

    #[test]
    fn planner_query_validate_max_limit_ok() {
        let q = PlannerQuery::new().with_limit(200);
        assert!(q.validate().is_ok());
    }

    #[test]
    fn planner_query_validate_empty_plan_id() {
        let q = PlannerQuery::new().for_plan("  ");
        let err = q.validate().unwrap_err();
        assert!(err.contains("plan_id"), "got: {err}");
    }

    #[test]
    fn planner_query_validate_empty_bucket_id() {
        let q = PlannerQuery::new().for_bucket("  ");
        let err = q.validate().unwrap_err();
        assert!(err.contains("bucket_id"), "got: {err}");
    }

    #[test]
    fn planner_query_validate_empty_assigned_to() {
        let q = PlannerQuery::new().assigned_to("  ");
        let err = q.validate().unwrap_err();
        assert!(err.contains("assigned_to"), "got: {err}");
    }

    #[test]
    fn planner_query_serde_roundtrip() {
        let q = PlannerQuery::new().for_plan("p-1").with_limit(25);
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(json["planId"], "p-1");
        assert_eq!(json["limit"], 25);
        let back: PlannerQuery = serde_json::from_value(json).unwrap();
        assert_eq!(back.plan_id.as_deref(), Some("p-1"));
    }

    #[test]
    fn planner_query_clone() {
        let q = PlannerQuery::new().for_plan("p-1");
        let cloned = q.clone();
        assert_eq!(cloned.plan_id, q.plan_id);
    }

    #[test]
    fn planner_query_debug() {
        let q = PlannerQuery::new();
        let debug = format!("{q:?}");
        assert!(debug.contains("PlannerQuery"), "got: {debug}");
    }

    // ========== PlannerQuery::apply_filters ==========

    #[test]
    fn apply_filters_empty_tasks() {
        let q = PlannerQuery::new();
        let result = q.apply_filters(&[], "2026-03-09");
        assert!(result.is_empty());
    }

    #[test]
    fn apply_filters_no_filters() {
        let tasks = vec![make_task("t-1", "p-1", 0), make_task("t-2", "p-1", 100)];
        let q = PlannerQuery::new();
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn apply_filters_by_plan() {
        let tasks = vec![make_task("t-1", "p-1", 0), make_task("t-2", "p-2", 0)];
        let q = PlannerQuery::new().for_plan("p-1");
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "t-1");
    }

    #[test]
    fn apply_filters_by_bucket() {
        let mut t1 = make_task("t-1", "p-1", 0);
        t1.bucket_id = Some("b-1".into());
        let mut t2 = make_task("t-2", "p-1", 0);
        t2.bucket_id = Some("b-2".into());
        let t3 = make_task("t-3", "p-1", 0); // no bucket
        let tasks = vec![t1, t2, t3];
        let q = PlannerQuery::new().for_bucket("b-1");
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "t-1");
    }

    #[test]
    fn apply_filters_by_assignee() {
        let mut t1 = make_task("t-1", "p-1", 0);
        t1.assigned_to = vec!["alice".into(), "bob".into()];
        let mut t2 = make_task("t-2", "p-1", 0);
        t2.assigned_to = vec!["charlie".into()];
        let tasks = vec![t1, t2];
        let q = PlannerQuery::new().assigned_to("bob");
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "t-1");
    }

    #[test]
    fn apply_filters_status_active() {
        let tasks = vec![
            make_task("t-1", "p-1", 50),
            make_task("t-2", "p-1", 100),
            make_task("t-3", "p-1", 0),
        ];
        let q = PlannerQuery::new().with_status(TaskStatusFilter::Active);
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn apply_filters_status_completed() {
        let tasks = vec![make_task("t-1", "p-1", 50), make_task("t-2", "p-1", 100)];
        let q = PlannerQuery::new().with_status(TaskStatusFilter::Completed);
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "t-2");
    }

    #[test]
    fn apply_filters_status_overdue() {
        let mut t1 = make_task("t-1", "p-1", 50);
        t1.due_date = Some("2026-03-01".into());
        let mut t2 = make_task("t-2", "p-1", 50);
        t2.due_date = Some("2026-04-01".into());
        let tasks = vec![t1, t2];
        let q = PlannerQuery::new().with_status(TaskStatusFilter::Overdue);
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "t-1");
    }

    #[test]
    fn apply_filters_status_all() {
        let tasks = vec![make_task("t-1", "p-1", 0), make_task("t-2", "p-1", 100)];
        let q = PlannerQuery::new().with_status(TaskStatusFilter::All);
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn apply_filters_limit_truncates() {
        let tasks: Vec<PlannerTask> = (0..10)
            .map(|i| make_task(&format!("t-{i}"), "p-1", 0))
            .collect();
        let q = PlannerQuery::new().with_limit(3);
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn apply_filters_combined() {
        let mut t1 = make_task("t-1", "p-1", 50);
        t1.bucket_id = Some("b-1".into());
        t1.assigned_to = vec!["alice".into()];
        let mut t2 = make_task("t-2", "p-1", 50);
        t2.bucket_id = Some("b-1".into());
        t2.assigned_to = vec!["bob".into()];
        let mut t3 = make_task("t-3", "p-2", 50);
        t3.bucket_id = Some("b-1".into());
        t3.assigned_to = vec!["alice".into()];
        let tasks = vec![t1, t2, t3];
        let q = PlannerQuery::new()
            .for_plan("p-1")
            .for_bucket("b-1")
            .assigned_to("alice");
        let result = q.apply_filters(&tasks, "2026-03-09");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "t-1");
    }

    // ========== PlannerAction ==========

    #[test]
    fn planner_action_display() {
        assert_eq!(PlannerAction::Read.to_string(), "read");
        assert_eq!(PlannerAction::Create.to_string(), "create");
        assert_eq!(PlannerAction::Update.to_string(), "update");
        assert_eq!(PlannerAction::Delete.to_string(), "delete");
        assert_eq!(PlannerAction::Assign.to_string(), "assign");
    }

    #[test]
    fn planner_action_eq() {
        assert_eq!(PlannerAction::Read, PlannerAction::Read);
        assert_ne!(PlannerAction::Read, PlannerAction::Create);
    }

    #[test]
    fn planner_action_debug() {
        let debug = format!("{:?}", PlannerAction::Delete);
        assert!(debug.contains("Delete"), "got: {debug}");
    }

    // ========== PlannerPolicy ==========

    #[test]
    fn planner_policy_default_deny_all() {
        let policy = PlannerPolicy::default();
        assert!(!policy.allow_read);
        assert!(!policy.allow_create);
        assert!(!policy.allow_update);
        assert!(!policy.allow_delete);
        assert!(!policy.allow_assign);
    }

    #[test]
    fn planner_policy_permissive() {
        let policy = PlannerPolicy::new_permissive();
        assert!(policy.allow_read);
        assert!(policy.allow_create);
        assert!(policy.allow_update);
        assert!(policy.allow_delete);
        assert!(policy.allow_assign);
        assert!(!policy.require_approval_for_create);
        assert!(policy.max_tasks_per_plan.is_none());
    }

    #[test]
    fn planner_policy_readonly() {
        let policy = PlannerPolicy::new_readonly();
        assert!(policy.allow_read);
        assert!(!policy.allow_create);
        assert!(!policy.allow_update);
        assert!(!policy.allow_delete);
        assert!(!policy.allow_assign);
    }

    #[test]
    fn planner_policy_check_action_allowed() {
        let policy = PlannerPolicy::new_permissive();
        assert!(policy.check_action(PlannerAction::Read).is_ok());
        assert!(policy.check_action(PlannerAction::Create).is_ok());
        assert!(policy.check_action(PlannerAction::Update).is_ok());
        assert!(policy.check_action(PlannerAction::Delete).is_ok());
        assert!(policy.check_action(PlannerAction::Assign).is_ok());
    }

    #[test]
    fn planner_policy_check_action_denied() {
        let policy = PlannerPolicy::default();
        for action in [
            PlannerAction::Read,
            PlannerAction::Create,
            PlannerAction::Update,
            PlannerAction::Delete,
            PlannerAction::Assign,
        ] {
            let err = policy.check_action(action).unwrap_err();
            assert!(err.contains("denies"), "got: {err}");
        }
    }

    #[test]
    fn planner_policy_check_action_readonly_denies_write() {
        let policy = PlannerPolicy::new_readonly();
        assert!(policy.check_action(PlannerAction::Read).is_ok());
        assert!(policy.check_action(PlannerAction::Create).is_err());
        assert!(policy.check_action(PlannerAction::Update).is_err());
        assert!(policy.check_action(PlannerAction::Delete).is_err());
        assert!(policy.check_action(PlannerAction::Assign).is_err());
    }

    #[test]
    fn planner_policy_check_task_limit_none() {
        let policy = PlannerPolicy::new_permissive();
        assert!(policy.check_task_limit(1000).is_ok());
    }

    #[test]
    fn planner_policy_check_task_limit_under() {
        let mut policy = PlannerPolicy::new_permissive();
        policy.max_tasks_per_plan = Some(100);
        assert!(policy.check_task_limit(99).is_ok());
    }

    #[test]
    fn planner_policy_check_task_limit_at_max() {
        let mut policy = PlannerPolicy::new_permissive();
        policy.max_tasks_per_plan = Some(100);
        let err = policy.check_task_limit(100).unwrap_err();
        assert!(err.contains("100"), "got: {err}");
    }

    #[test]
    fn planner_policy_check_task_limit_over() {
        let mut policy = PlannerPolicy::new_permissive();
        policy.max_tasks_per_plan = Some(50);
        let err = policy.check_task_limit(60).unwrap_err();
        assert!(err.contains("60"), "got: {err}");
        assert!(err.contains("50"), "got: {err}");
    }

    #[test]
    fn planner_policy_serde_roundtrip() {
        let policy = PlannerPolicy::new_permissive();
        let json = serde_json::to_value(&policy).unwrap();
        assert_eq!(json["allow_read"], true);
        let back: PlannerPolicy = serde_json::from_value(json).unwrap();
        assert!(back.allow_read);
    }

    #[test]
    fn planner_policy_clone() {
        let policy = PlannerPolicy::new_readonly();
        let cloned = policy.clone();
        assert_eq!(cloned.allow_read, policy.allow_read);
        assert_eq!(cloned.allow_create, policy.allow_create);
    }

    #[test]
    fn planner_policy_debug() {
        let policy = PlannerPolicy::default();
        let debug = format!("{policy:?}");
        assert!(debug.contains("PlannerPolicy"), "got: {debug}");
    }

    // ========== PlannerAuditEvent ==========

    #[test]
    fn audit_event_new() {
        let evt = PlannerAuditEvent::new("2026-03-09T10:00:00Z", "create_task", "p-1", "created");
        assert_eq!(evt.timestamp, "2026-03-09T10:00:00Z");
        assert_eq!(evt.action, "create_task");
        assert_eq!(evt.plan_id, "p-1");
        assert_eq!(evt.details, "created");
        assert!(evt.task_id.is_none());
    }

    #[test]
    fn audit_event_with_task_id() {
        let evt = PlannerAuditEvent::new("ts", "update", "p-1", "updated").with_task_id("task-42");
        assert_eq!(evt.task_id.as_deref(), Some("task-42"));
    }

    #[test]
    fn audit_event_display_with_task() {
        let evt = PlannerAuditEvent::new("2026-03-09", "delete_task", "p-1", "deleted")
            .with_task_id("t-1");
        let display = evt.to_string();
        assert!(display.contains("2026-03-09"), "got: {display}");
        assert!(display.contains("delete_task"), "got: {display}");
        assert!(display.contains("p-1"), "got: {display}");
        assert!(display.contains("t-1"), "got: {display}");
    }

    #[test]
    fn audit_event_display_without_task() {
        let evt = PlannerAuditEvent::new("ts", "create", "p-1", "details");
        let display = evt.to_string();
        assert!(display.contains("none"), "got: {display}");
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let evt = PlannerAuditEvent::new("ts", "update_task", "p-1", "detail").with_task_id("t-1");
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["taskId"], "t-1");
        assert_eq!(json["planId"], "p-1");
        let back: PlannerAuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.task_id.as_deref(), Some("t-1"));
    }

    #[test]
    fn audit_event_skip_serializing_none_task_id() {
        let evt = PlannerAuditEvent::new("ts", "a", "p-1", "d");
        let json = serde_json::to_value(&evt).unwrap();
        assert!(json.get("taskId").is_none());
    }

    #[test]
    fn audit_event_clone() {
        let evt = PlannerAuditEvent::new("ts", "a", "p-1", "d");
        let cloned = evt.clone();
        assert_eq!(cloned.timestamp, evt.timestamp);
        assert_eq!(cloned.plan_id, evt.plan_id);
    }

    #[test]
    fn audit_event_debug() {
        let evt = PlannerAuditEvent::new("ts", "a", "p-1", "d");
        let debug = format!("{evt:?}");
        assert!(debug.contains("PlannerAuditEvent"), "got: {debug}");
    }

    // ========== Graph URL helpers ==========

    #[test]
    fn graph_plan_tasks_url_format() {
        let url = graph_plan_tasks_url("plan-abc");
        assert_eq!(
            url,
            "https://graph.microsoft.com/v1.0/planner/plans/plan-abc/tasks"
        );
    }

    #[test]
    fn graph_plan_buckets_url_format() {
        let url = graph_plan_buckets_url("plan-xyz");
        assert_eq!(
            url,
            "https://graph.microsoft.com/v1.0/planner/plans/plan-xyz/buckets"
        );
    }

    #[test]
    fn graph_task_url_format() {
        let url = graph_task_url("task-123");
        assert_eq!(
            url,
            "https://graph.microsoft.com/v1.0/planner/tasks/task-123"
        );
    }

    #[test]
    fn graph_plan_url_format() {
        let url = graph_plan_url("plan-42");
        assert_eq!(
            url,
            "https://graph.microsoft.com/v1.0/planner/plans/plan-42"
        );
    }

    #[test]
    fn graph_task_details_url_format() {
        let url = graph_task_details_url("task-99");
        assert_eq!(
            url,
            "https://graph.microsoft.com/v1.0/planner/tasks/task-99/details"
        );
    }

    // ========== execute_create_task ==========

    #[test]
    fn execute_create_task_success() {
        let policy = PlannerPolicy::new_permissive();
        let req = CreateTaskRequest {
            title: "New task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Medium,
            description: None,
        };
        let result = execute_create_task(&policy, &req, 0, "2026-03-09T10:00:00Z");
        assert!(result.is_ok());
        let evt = result.unwrap();
        assert_eq!(evt.action, "create_task");
        assert_eq!(evt.plan_id, "plan-1");
        assert!(evt.details.contains("New task"));
    }

    #[test]
    fn execute_create_task_denied_by_policy() {
        let policy = PlannerPolicy::new_readonly();
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = execute_create_task(&policy, &req, 0, "ts").unwrap_err();
        assert!(err.contains("denies"), "got: {err}");
    }

    #[test]
    fn execute_create_task_over_limit() {
        let mut policy = PlannerPolicy::new_permissive();
        policy.max_tasks_per_plan = Some(10);
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = execute_create_task(&policy, &req, 10, "ts").unwrap_err();
        assert!(err.contains("10"), "got: {err}");
    }

    #[test]
    fn execute_create_task_invalid_request() {
        let policy = PlannerPolicy::new_permissive();
        let req = CreateTaskRequest {
            title: "  ".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = execute_create_task(&policy, &req, 0, "ts").unwrap_err();
        assert!(err.contains("title"), "got: {err}");
    }

    #[test]
    fn execute_create_task_requires_approval() {
        let mut policy = PlannerPolicy::new_permissive();
        policy.require_approval_for_create = true;
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "plan-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        let err = execute_create_task(&policy, &req, 0, "ts").unwrap_err();
        assert!(err.contains("approval"), "got: {err}");
    }

    // ========== execute_update_task ==========

    #[test]
    fn execute_update_task_success() {
        let policy = PlannerPolicy::new_permissive();
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: Some("Updated title".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let result = execute_update_task(&policy, &req, "plan-1", "ts");
        assert!(result.is_ok());
        let evt = result.unwrap();
        assert_eq!(evt.action, "update_task");
        assert_eq!(evt.task_id.as_deref(), Some("task-1"));
    }

    #[test]
    fn execute_update_task_denied() {
        let policy = PlannerPolicy::new_readonly();
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: Some("X".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = execute_update_task(&policy, &req, "plan-1", "ts").unwrap_err();
        assert!(err.contains("denies"), "got: {err}");
    }

    #[test]
    fn execute_update_task_no_changes() {
        let policy = PlannerPolicy::new_permissive();
        let req = empty_update("task-1");
        let err = execute_update_task(&policy, &req, "plan-1", "ts").unwrap_err();
        assert!(err.contains("no changes"), "got: {err}");
    }

    #[test]
    fn execute_update_task_invalid() {
        let policy = PlannerPolicy::new_permissive();
        let req = UpdateTaskRequest {
            task_id: "  ".into(),
            title: Some("X".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = execute_update_task(&policy, &req, "plan-1", "ts").unwrap_err();
        assert!(err.contains("task_id"), "got: {err}");
    }

    #[test]
    fn execute_update_task_with_assignment_requires_assign_permission() {
        let mut policy = PlannerPolicy::new_permissive();
        policy.allow_assign = false;
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: Some(vec!["user-1".into()]),
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        let err = execute_update_task(&policy, &req, "plan-1", "ts").unwrap_err();
        assert!(err.contains("assign"), "got: {err}");
    }

    #[test]
    fn execute_update_task_with_assignment_allowed() {
        let policy = PlannerPolicy::new_permissive();
        let req = UpdateTaskRequest {
            task_id: "task-1".into(),
            title: None,
            bucket_id: None,
            assigned_to: Some(vec!["user-1".into()]),
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        assert!(execute_update_task(&policy, &req, "plan-1", "ts").is_ok());
    }

    // ========== execute_delete_task ==========

    #[test]
    fn execute_delete_task_success() {
        let policy = PlannerPolicy::new_permissive();
        let result = execute_delete_task(&policy, "task-1", "plan-1", "ts");
        assert!(result.is_ok());
        let evt = result.unwrap();
        assert_eq!(evt.action, "delete_task");
        assert_eq!(evt.task_id.as_deref(), Some("task-1"));
    }

    #[test]
    fn execute_delete_task_denied() {
        let policy = PlannerPolicy::new_readonly();
        let err = execute_delete_task(&policy, "task-1", "plan-1", "ts").unwrap_err();
        assert!(err.contains("denies"), "got: {err}");
    }

    #[test]
    fn execute_delete_task_empty_task_id() {
        let policy = PlannerPolicy::new_permissive();
        let err = execute_delete_task(&policy, "  ", "plan-1", "ts").unwrap_err();
        assert!(err.contains("task_id"), "got: {err}");
    }

    // ========== execute_add_comment ==========

    #[test]
    fn execute_add_comment_success() {
        let policy = PlannerPolicy::new_permissive();
        let result = execute_add_comment(&policy, "task-1", "plan-1", "Great work!", "ts");
        assert!(result.is_ok());
        let evt = result.unwrap();
        assert_eq!(evt.action, "add_comment");
    }

    #[test]
    fn execute_add_comment_denied() {
        let policy = PlannerPolicy::new_readonly();
        let err = execute_add_comment(&policy, "task-1", "plan-1", "nope", "ts").unwrap_err();
        assert!(err.contains("denies"), "got: {err}");
    }

    #[test]
    fn execute_add_comment_empty_task_id() {
        let policy = PlannerPolicy::new_permissive();
        let err = execute_add_comment(&policy, "  ", "plan-1", "text", "ts").unwrap_err();
        assert!(err.contains("task_id"), "got: {err}");
    }

    #[test]
    fn execute_add_comment_empty_content() {
        let policy = PlannerPolicy::new_permissive();
        let err = execute_add_comment(&policy, "task-1", "plan-1", "  ", "ts").unwrap_err();
        assert!(err.contains("content"), "got: {err}");
    }

    #[test]
    fn execute_add_comment_too_long() {
        let policy = PlannerPolicy::new_permissive();
        let long = "x".repeat(65_537);
        let err = execute_add_comment(&policy, "task-1", "plan-1", &long, "ts").unwrap_err();
        assert!(err.contains("65536"), "got: {err}");
    }

    // ========== execute_update_checklist ==========

    #[test]
    fn execute_update_checklist_success() {
        let policy = PlannerPolicy::new_permissive();
        let result = execute_update_checklist(&policy, "task-1", "plan-1", "Buy milk", "ts");
        assert!(result.is_ok());
        let evt = result.unwrap();
        assert_eq!(evt.action, "update_checklist");
        assert!(evt.details.contains("Buy milk"));
    }

    #[test]
    fn execute_update_checklist_denied() {
        let policy = PlannerPolicy::new_readonly();
        let err = execute_update_checklist(&policy, "task-1", "plan-1", "item", "ts").unwrap_err();
        assert!(err.contains("denies"), "got: {err}");
    }

    #[test]
    fn execute_update_checklist_empty_task_id() {
        let policy = PlannerPolicy::new_permissive();
        let err = execute_update_checklist(&policy, "  ", "plan-1", "item", "ts").unwrap_err();
        assert!(err.contains("task_id"), "got: {err}");
    }

    #[test]
    fn execute_update_checklist_empty_title() {
        let policy = PlannerPolicy::new_permissive();
        let err = execute_update_checklist(&policy, "task-1", "plan-1", "  ", "ts").unwrap_err();
        assert!(err.contains("title"), "got: {err}");
    }

    // ========== execute_assign_task ==========

    #[test]
    fn execute_assign_task_success() {
        let policy = PlannerPolicy::new_permissive();
        let result = execute_assign_task(&policy, "task-1", "plan-1", "alice", "ts");
        assert!(result.is_ok());
        let evt = result.unwrap();
        assert_eq!(evt.action, "assign_task");
        assert!(evt.details.contains("alice"));
    }

    #[test]
    fn execute_assign_task_denied() {
        let policy = PlannerPolicy::new_readonly();
        let err = execute_assign_task(&policy, "task-1", "plan-1", "alice", "ts").unwrap_err();
        assert!(err.contains("denies"), "got: {err}");
    }

    #[test]
    fn execute_assign_task_empty_task_id() {
        let policy = PlannerPolicy::new_permissive();
        let err = execute_assign_task(&policy, "  ", "plan-1", "alice", "ts").unwrap_err();
        assert!(err.contains("task_id"), "got: {err}");
    }

    #[test]
    fn execute_assign_task_empty_assignee() {
        let policy = PlannerPolicy::new_permissive();
        let err = execute_assign_task(&policy, "task-1", "plan-1", "  ", "ts").unwrap_err();
        assert!(err.contains("assignee"), "got: {err}");
    }

    // ========== Default-deny fail-closed integration tests ==========

    #[test]
    fn default_policy_denies_all_operations() {
        let policy = PlannerPolicy::default();
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "p-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Unset,
            description: None,
        };
        assert!(execute_create_task(&policy, &req, 0, "ts").is_err());

        let ureq = UpdateTaskRequest {
            task_id: "t-1".into(),
            title: Some("X".into()),
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        };
        assert!(execute_update_task(&policy, &ureq, "p-1", "ts").is_err());
        assert!(execute_delete_task(&policy, "t-1", "p-1", "ts").is_err());
        assert!(execute_add_comment(&policy, "t-1", "p-1", "text", "ts").is_err());
        assert!(execute_update_checklist(&policy, "t-1", "p-1", "item", "ts").is_err());
        assert!(execute_assign_task(&policy, "t-1", "p-1", "alice", "ts").is_err());
    }

    #[test]
    fn readonly_policy_allows_no_writes() {
        let policy = PlannerPolicy::new_readonly();
        assert!(policy.check_action(PlannerAction::Read).is_ok());
        assert!(policy.check_action(PlannerAction::Create).is_err());
        assert!(policy.check_action(PlannerAction::Update).is_err());
        assert!(policy.check_action(PlannerAction::Delete).is_err());
        assert!(policy.check_action(PlannerAction::Assign).is_err());
    }

    #[test]
    fn permissive_policy_allows_all() {
        let policy = PlannerPolicy::new_permissive();
        let req = CreateTaskRequest {
            title: "Task".into(),
            plan_id: "p-1".into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            priority: TaskPriority::Medium,
            description: None,
        };
        assert!(execute_create_task(&policy, &req, 0, "ts").is_ok());
        assert!(execute_delete_task(&policy, "t-1", "p-1", "ts").is_ok());
        assert!(execute_add_comment(&policy, "t-1", "p-1", "hi", "ts").is_ok());
        assert!(execute_update_checklist(&policy, "t-1", "p-1", "item", "ts").is_ok());
        assert!(execute_assign_task(&policy, "t-1", "p-1", "bob", "ts").is_ok());
    }

    // ========== Helpers ==========

    fn make_task(id: &str, plan_id: &str, percent: u8) -> PlannerTask {
        PlannerTask {
            id: id.into(),
            title: format!("Task {id}"),
            plan_id: plan_id.into(),
            bucket_id: None,
            assigned_to: vec![],
            due_date: None,
            start_date: None,
            percent_complete: percent,
            priority: TaskPriority::Unset,
            created_at: None,
            completed_at: None,
            checklist_items: vec![],
            description: None,
        }
    }

    fn empty_update(task_id: &str) -> UpdateTaskRequest {
        UpdateTaskRequest {
            task_id: task_id.into(),
            title: None,
            bucket_id: None,
            assigned_to: None,
            due_date: None,
            priority: None,
            percent_complete: None,
            description: None,
        }
    }
}
