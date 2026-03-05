//! Cron connector error types.

use fcp_core::FcpError;
use thiserror::Error;

/// Result alias for cron operations.
pub type CronResult<T> = Result<T, CronError>;

/// Cron connector errors.
#[derive(Error, Debug)]
pub enum CronError {
    /// Invalid cron expression
    #[error("Invalid cron expression: {expression}")]
    InvalidExpression { expression: String },

    /// Schedule not found
    #[error("Schedule not found: {schedule_id}")]
    ScheduleNotFound { schedule_id: String },

    /// Duplicate schedule name
    #[error("Duplicate schedule name: {name}")]
    DuplicateName { name: String },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl CronError {
    /// Convert to an `FcpError`.
    #[must_use]
    pub fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::InvalidExpression { expression } => FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid cron expression: {expression}"),
            },
            Self::ScheduleNotFound { schedule_id } => FcpError::ResourceNotFound {
                resource: format!("schedule:{schedule_id}"),
            },
            Self::DuplicateName { name } => FcpError::Conflict {
                message: format!("Schedule with name '{name}' already exists"),
            },
            Self::Internal { message } => FcpError::Internal {
                message: message.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_expression_display() {
        let err = CronError::InvalidExpression {
            expression: "bad expr".into(),
        };
        assert_eq!(err.to_string(), "Invalid cron expression: bad expr");
    }

    #[test]
    fn schedule_not_found_display() {
        let err = CronError::ScheduleNotFound {
            schedule_id: "sched_123".into(),
        };
        assert_eq!(err.to_string(), "Schedule not found: sched_123");
    }

    #[test]
    fn duplicate_name_display() {
        let err = CronError::DuplicateName {
            name: "my-job".into(),
        };
        assert_eq!(err.to_string(), "Duplicate schedule name: my-job");
    }

    #[test]
    fn internal_display() {
        let err = CronError::Internal {
            message: "something broke".into(),
        };
        assert_eq!(err.to_string(), "Internal error: something broke");
    }

    #[test]
    fn invalid_expression_to_fcp_error() {
        match (CronError::InvalidExpression {
            expression: "* *".into(),
        })
        .to_fcp_error()
        {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("* *"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn schedule_not_found_to_fcp_error() {
        match (CronError::ScheduleNotFound {
            schedule_id: "sched_abc".into(),
        })
        .to_fcp_error()
        {
            FcpError::ResourceNotFound { resource } => {
                assert!(resource.contains("sched_abc"));
            }
            other => panic!("expected ResourceNotFound, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_name_to_fcp_error() {
        match (CronError::DuplicateName {
            name: "my-job".into(),
        })
        .to_fcp_error()
        {
            FcpError::Conflict { message } => {
                assert!(message.contains("my-job"));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn internal_to_fcp_error() {
        match (CronError::Internal {
            message: "oops".into(),
        })
        .to_fcp_error()
        {
            FcpError::Internal { message } => {
                assert_eq!(message, "oops");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}
