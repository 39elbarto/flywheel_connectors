//! Cron in-memory store.
//!
//! Unlike external API connectors, the cron connector manages schedules and
//! execution history entirely in memory. The `CronStore` acts as the "client"
//! layer, analogous to an HTTP client in other connectors.

use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::{
    error::{CronError, CronResult},
    types::{Execution, Schedule, validate_cron_expression},
};

/// In-memory store for cron schedules and execution history.
#[derive(Debug, Default)]
pub struct CronStore {
    schedules: HashMap<String, Schedule>,
    executions: Vec<Execution>,
}

impl CronStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// List all schedules.
    #[must_use]
    pub fn list_schedules(&self) -> Vec<Schedule> {
        let mut schedules: Vec<Schedule> = self.schedules.values().cloned().collect();
        schedules.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        schedules
    }

    /// Create a new schedule.
    ///
    /// Returns the generated schedule ID on success. Validates the cron
    /// expression and rejects duplicate names.
    pub fn create_schedule(
        &mut self,
        name: &str,
        expression: &str,
        target_operation: &str,
        payload: Option<serde_json::Value>,
        enabled: Option<bool>,
    ) -> CronResult<String> {
        if !validate_cron_expression(expression) {
            return Err(CronError::InvalidExpression {
                expression: expression.to_string(),
            });
        }

        if self.schedules.values().any(|s| s.name == name) {
            return Err(CronError::DuplicateName {
                name: name.to_string(),
            });
        }

        let id = format!("sched_{}", Uuid::new_v4());
        let schedule = Schedule {
            id: id.clone(),
            name: name.to_string(),
            expression: expression.to_string(),
            target_operation: target_operation.to_string(),
            payload,
            enabled: enabled.unwrap_or(true),
            created_at: Utc::now().to_rfc3339(),
        };

        self.schedules.insert(id.clone(), schedule);
        Ok(id)
    }

    /// Delete a schedule by ID.
    pub fn delete_schedule(&mut self, schedule_id: &str) -> CronResult<()> {
        if self.schedules.remove(schedule_id).is_none() {
            return Err(CronError::ScheduleNotFound {
                schedule_id: schedule_id.to_string(),
            });
        }
        Ok(())
    }

    /// Get a schedule by ID.
    pub fn get_schedule(&self, schedule_id: &str) -> CronResult<&Schedule> {
        self.schedules.get(schedule_id).ok_or_else(|| CronError::ScheduleNotFound {
            schedule_id: schedule_id.to_string(),
        })
    }

    /// Trigger a schedule, recording an execution.
    ///
    /// Returns the generated execution ID.
    pub fn trigger_schedule(&mut self, schedule_id: &str) -> CronResult<String> {
        // Verify the schedule exists.
        let _schedule = self.get_schedule(schedule_id)?;

        let execution_id = format!("exec_{}", Uuid::new_v4());
        let execution = Execution {
            id: execution_id.clone(),
            schedule_id: schedule_id.to_string(),
            triggered_at: Utc::now().to_rfc3339(),
            status: "triggered".to_string(),
        };

        self.executions.push(execution);
        Ok(execution_id)
    }

    /// List executions, optionally filtered by schedule ID, with a limit.
    #[must_use]
    pub fn list_executions(
        &self,
        schedule_id: Option<&str>,
        limit: Option<usize>,
    ) -> Vec<Execution> {
        let limit = limit.unwrap_or(50).min(100);
        let mut result: Vec<Execution> = if let Some(sid) = schedule_id {
            self.executions
                .iter()
                .filter(|e| e.schedule_id == sid)
                .cloned()
                .collect()
        } else {
            self.executions.clone()
        };

        // Most recent first.
        result.reverse();
        result.truncate(limit);
        result
    }

    /// Return the number of schedules.
    #[must_use]
    pub fn schedule_count(&self) -> usize {
        self.schedules.len()
    }

    /// Return the number of executions.
    #[must_use]
    pub fn execution_count(&self) -> usize {
        self.executions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_store_is_empty() {
        let store = CronStore::new();
        assert_eq!(store.schedule_count(), 0);
        assert_eq!(store.execution_count(), 0);
    }

    #[test]
    fn default_store_is_empty() {
        let store = CronStore::default();
        assert!(store.list_schedules().is_empty());
        assert!(store.list_executions(None, None).is_empty());
    }

    #[test]
    fn create_schedule_success() {
        let mut store = CronStore::new();
        let id = store
            .create_schedule("hourly", "0 * * * *", "op.test", None, None)
            .unwrap();
        assert!(id.starts_with("sched_"));
        assert_eq!(store.schedule_count(), 1);
    }

    #[test]
    fn create_schedule_with_payload() {
        let mut store = CronStore::new();
        let id = store
            .create_schedule(
                "with-payload",
                "*/5 * * * *",
                "op.sync",
                Some(json!({"key": "value"})),
                None,
            )
            .unwrap();
        let sched = store.get_schedule(&id).unwrap();
        assert_eq!(sched.payload.as_ref().unwrap()["key"], "value");
    }

    #[test]
    fn create_schedule_with_enabled_false() {
        let mut store = CronStore::new();
        let id = store
            .create_schedule("disabled", "0 0 * * *", "op.test", None, Some(false))
            .unwrap();
        let sched = store.get_schedule(&id).unwrap();
        assert!(!sched.enabled);
    }

    #[test]
    fn create_schedule_default_enabled() {
        let mut store = CronStore::new();
        let id = store
            .create_schedule("enabled", "0 * * * *", "op.test", None, None)
            .unwrap();
        let sched = store.get_schedule(&id).unwrap();
        assert!(sched.enabled);
    }

    #[test]
    fn create_schedule_invalid_expression() {
        let mut store = CronStore::new();
        let result = store.create_schedule("bad", "not valid", "op.test", None, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CronError::InvalidExpression { expression } => {
                assert_eq!(expression, "not valid");
            }
            other => panic!("expected InvalidExpression, got {other:?}"),
        }
    }

    #[test]
    fn create_schedule_too_few_fields() {
        let mut store = CronStore::new();
        assert!(store.create_schedule("bad", "* * *", "op.test", None, None).is_err());
    }

    #[test]
    fn create_schedule_too_many_fields() {
        let mut store = CronStore::new();
        assert!(
            store
                .create_schedule("bad", "* * * * * *", "op.test", None, None)
                .is_err()
        );
    }

    #[test]
    fn create_schedule_empty_expression() {
        let mut store = CronStore::new();
        assert!(store.create_schedule("bad", "", "op.test", None, None).is_err());
    }

    #[test]
    fn create_schedule_duplicate_name() {
        let mut store = CronStore::new();
        store.create_schedule("dup", "0 * * * *", "op.a", None, None).unwrap();
        let result = store.create_schedule("dup", "*/5 * * * *", "op.b", None, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            CronError::DuplicateName { name } => assert_eq!(name, "dup"),
            other => panic!("expected DuplicateName, got {other:?}"),
        }
    }

    #[test]
    fn list_schedules_returns_all() {
        let mut store = CronStore::new();
        store.create_schedule("a", "0 * * * *", "op.a", None, None).unwrap();
        store.create_schedule("b", "*/5 * * * *", "op.b", None, None).unwrap();
        store.create_schedule("c", "0 0 * * *", "op.c", None, None).unwrap();
        assert_eq!(store.list_schedules().len(), 3);
    }

    #[test]
    fn list_schedules_sorted_by_created_at() {
        let mut store = CronStore::new();
        store.create_schedule("first", "0 * * * *", "op.a", None, None).unwrap();
        store.create_schedule("second", "*/5 * * * *", "op.b", None, None).unwrap();
        let schedules = store.list_schedules();
        assert!(schedules[0].created_at <= schedules[1].created_at);
    }

    #[test]
    fn get_schedule_found() {
        let mut store = CronStore::new();
        let id = store.create_schedule("test", "0 * * * *", "op.test", None, None).unwrap();
        let sched = store.get_schedule(&id).unwrap();
        assert_eq!(sched.name, "test");
        assert_eq!(sched.expression, "0 * * * *");
        assert_eq!(sched.target_operation, "op.test");
    }

    #[test]
    fn get_schedule_not_found() {
        let store = CronStore::new();
        let result = store.get_schedule("sched_nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            CronError::ScheduleNotFound { schedule_id } => {
                assert_eq!(schedule_id, "sched_nonexistent");
            }
            other => panic!("expected ScheduleNotFound, got {other:?}"),
        }
    }

    #[test]
    fn delete_schedule_success() {
        let mut store = CronStore::new();
        let id = store.create_schedule("del", "0 * * * *", "op.test", None, None).unwrap();
        assert_eq!(store.schedule_count(), 1);
        store.delete_schedule(&id).unwrap();
        assert_eq!(store.schedule_count(), 0);
    }

    #[test]
    fn delete_schedule_not_found() {
        let mut store = CronStore::new();
        let result = store.delete_schedule("sched_missing");
        assert!(result.is_err());
        match result.unwrap_err() {
            CronError::ScheduleNotFound { schedule_id } => {
                assert_eq!(schedule_id, "sched_missing");
            }
            other => panic!("expected ScheduleNotFound, got {other:?}"),
        }
    }

    #[test]
    fn delete_schedule_makes_it_gone() {
        let mut store = CronStore::new();
        let id = store.create_schedule("gone", "0 * * * *", "op.test", None, None).unwrap();
        store.delete_schedule(&id).unwrap();
        assert!(store.get_schedule(&id).is_err());
    }

    #[test]
    fn trigger_schedule_success() {
        let mut store = CronStore::new();
        let sched_id = store.create_schedule("trig", "0 * * * *", "op.test", None, None).unwrap();
        let exec_id = store.trigger_schedule(&sched_id).unwrap();
        assert!(exec_id.starts_with("exec_"));
        assert_eq!(store.execution_count(), 1);
    }

    #[test]
    fn trigger_schedule_not_found() {
        let mut store = CronStore::new();
        let result = store.trigger_schedule("sched_missing");
        assert!(result.is_err());
    }

    #[test]
    fn trigger_creates_execution_record() {
        let mut store = CronStore::new();
        let sched_id = store.create_schedule("exec", "0 * * * *", "op.test", None, None).unwrap();
        store.trigger_schedule(&sched_id).unwrap();
        let execs = store.list_executions(Some(&sched_id), None);
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].schedule_id, sched_id);
        assert_eq!(execs[0].status, "triggered");
    }

    #[test]
    fn trigger_multiple_creates_multiple_executions() {
        let mut store = CronStore::new();
        let sched_id = store.create_schedule("multi", "0 * * * *", "op.test", None, None).unwrap();
        store.trigger_schedule(&sched_id).unwrap();
        store.trigger_schedule(&sched_id).unwrap();
        store.trigger_schedule(&sched_id).unwrap();
        assert_eq!(store.execution_count(), 3);
    }

    #[test]
    fn list_executions_all() {
        let mut store = CronStore::new();
        let s1 = store.create_schedule("s1", "0 * * * *", "op.a", None, None).unwrap();
        let s2 = store.create_schedule("s2", "*/5 * * * *", "op.b", None, None).unwrap();
        store.trigger_schedule(&s1).unwrap();
        store.trigger_schedule(&s2).unwrap();
        store.trigger_schedule(&s1).unwrap();
        let all = store.list_executions(None, None);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn list_executions_filtered() {
        let mut store = CronStore::new();
        let s1 = store.create_schedule("s1", "0 * * * *", "op.a", None, None).unwrap();
        let s2 = store.create_schedule("s2", "*/5 * * * *", "op.b", None, None).unwrap();
        store.trigger_schedule(&s1).unwrap();
        store.trigger_schedule(&s2).unwrap();
        store.trigger_schedule(&s1).unwrap();
        let filtered = store.list_executions(Some(&s1), None);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.schedule_id == s1));
    }

    #[test]
    fn list_executions_with_limit() {
        let mut store = CronStore::new();
        let sid = store.create_schedule("lim", "0 * * * *", "op.test", None, None).unwrap();
        for _ in 0..10 {
            store.trigger_schedule(&sid).unwrap();
        }
        let limited = store.list_executions(None, Some(3));
        assert_eq!(limited.len(), 3);
    }

    #[test]
    fn list_executions_limit_capped_at_100() {
        let mut store = CronStore::new();
        let sid = store.create_schedule("cap", "0 * * * *", "op.test", None, None).unwrap();
        for _ in 0..5 {
            store.trigger_schedule(&sid).unwrap();
        }
        let result = store.list_executions(None, Some(200));
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn list_executions_default_limit() {
        let mut store = CronStore::new();
        let sid = store.create_schedule("def", "0 * * * *", "op.test", None, None).unwrap();
        for _ in 0..5 {
            store.trigger_schedule(&sid).unwrap();
        }
        let result = store.list_executions(None, None);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn list_executions_most_recent_first() {
        let mut store = CronStore::new();
        let sid = store.create_schedule("order", "0 * * * *", "op.test", None, None).unwrap();
        store.trigger_schedule(&sid).unwrap();
        store.trigger_schedule(&sid).unwrap();
        let execs = store.list_executions(None, None);
        assert!(execs[0].triggered_at >= execs[1].triggered_at);
    }

    #[test]
    fn list_executions_empty_for_unknown_schedule() {
        let mut store = CronStore::new();
        let sid = store.create_schedule("known", "0 * * * *", "op.test", None, None).unwrap();
        store.trigger_schedule(&sid).unwrap();
        let result = store.list_executions(Some("sched_unknown"), None);
        assert!(result.is_empty());
    }

    #[test]
    fn store_debug_format() {
        let store = CronStore::new();
        let debug = format!("{store:?}");
        assert!(debug.contains("CronStore"));
    }

    #[test]
    fn create_multiple_different_names() {
        let mut store = CronStore::new();
        let id1 = store.create_schedule("a", "0 * * * *", "op.a", None, None).unwrap();
        let id2 = store.create_schedule("b", "0 * * * *", "op.b", None, None).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(store.schedule_count(), 2);
    }

    #[test]
    fn schedule_has_created_at() {
        let mut store = CronStore::new();
        let id = store.create_schedule("ts", "0 * * * *", "op.test", None, None).unwrap();
        let sched = store.get_schedule(&id).unwrap();
        assert!(!sched.created_at.is_empty());
    }

    #[test]
    fn execution_has_triggered_at() {
        let mut store = CronStore::new();
        let sid = store.create_schedule("ts", "0 * * * *", "op.test", None, None).unwrap();
        store.trigger_schedule(&sid).unwrap();
        let execs = store.list_executions(None, None);
        assert!(!execs[0].triggered_at.is_empty());
    }

    #[test]
    fn delete_then_create_same_name() {
        let mut store = CronStore::new();
        let id = store.create_schedule("reuse", "0 * * * *", "op.test", None, None).unwrap();
        store.delete_schedule(&id).unwrap();
        let id2 = store.create_schedule("reuse", "*/5 * * * *", "op.test2", None, None).unwrap();
        assert_ne!(id, id2);
    }

    #[test]
    fn executions_persist_after_schedule_delete() {
        let mut store = CronStore::new();
        let sid = store.create_schedule("persist", "0 * * * *", "op.test", None, None).unwrap();
        store.trigger_schedule(&sid).unwrap();
        store.delete_schedule(&sid).unwrap();
        assert_eq!(store.execution_count(), 1);
    }

    #[test]
    fn complex_expression_accepted() {
        let mut store = CronStore::new();
        let id = store
            .create_schedule("complex", "15,45 */2 1-15 * 1-5", "op.test", None, None)
            .unwrap();
        let sched = store.get_schedule(&id).unwrap();
        assert_eq!(sched.expression, "15,45 */2 1-15 * 1-5");
    }
}
