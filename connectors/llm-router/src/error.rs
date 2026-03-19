//! LLM Router error types.

use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_core::FcpError;
use fcp_sdk::migration::ConnectorErrorMapping;

/// LLM Router errors.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("No providers configured")]
    NoProviders,

    #[error("No provider available for request: {reason}")]
    NoProviderAvailable { reason: String },

    #[error("Budget exceeded: spent {spent_usd:.4} of {budget_usd:.4} USD")]
    BudgetExceeded { spent_usd: f64, budget_usd: f64 },

    #[error("Provider {provider} error: {message}")]
    ProviderError { provider: String, message: String },

    #[error("All providers failed: {message}")]
    AllProvidersFailed { message: String },

    #[error("Invalid routing strategy: {0}")]
    InvalidStrategy(String),

    #[error("Required capability not available: {0}")]
    CapabilityNotAvailable(String),
}

impl From<RouterError> for FcpError {
    fn from(e: RouterError) -> Self {
        match e {
            RouterError::NoProviders => FcpError::InvalidRequest {
                code: 1003,
                message: e.to_string(),
            },
            RouterError::NoProviderAvailable { .. } => FcpError::InvalidRequest {
                code: 1004,
                message: e.to_string(),
            },
            RouterError::BudgetExceeded { .. } => FcpError::CapabilityDenied {
                capability: "llm-router.route".into(),
                reason: e.to_string(),
            },
            RouterError::ProviderError { .. } | RouterError::AllProvidersFailed { .. } => {
                FcpError::Internal {
                    message: e.to_string(),
                }
            }
            RouterError::InvalidStrategy(_) => FcpError::InvalidRequest {
                code: 1003,
                message: e.to_string(),
            },
            RouterError::CapabilityNotAvailable(_) => FcpError::InvalidRequest {
                code: 1004,
                message: e.to_string(),
            },
        }
    }
}

/// Convenience Result type for router operations.
pub type RouterResult<T> = Result<T, RouterError>;

impl ConnectorErrorMapping for RouterError {
    fn from_async_error(error: AsyncError) -> Self {
        match error {
            AsyncError::Timeout { timeout_ms } => Self::AllProvidersFailed {
                message: format!("deadline exceeded after {timeout_ms}ms"),
            },
            AsyncError::Cancelled => Self::AllProvidersFailed {
                message: "request cancelled".into(),
            },
            other => Self::AllProvidersFailed {
                message: other.to_string(),
            },
        }
    }

    fn to_fcp_error(&self) -> FcpError {
        match self {
            Self::NoProviders => FcpError::InvalidRequest {
                code: 1003,
                message: self.to_string(),
            },
            Self::NoProviderAvailable { .. } => FcpError::InvalidRequest {
                code: 1004,
                message: self.to_string(),
            },
            Self::BudgetExceeded { .. } => FcpError::CapabilityDenied {
                capability: "llm-router.route".into(),
                reason: self.to_string(),
            },
            Self::ProviderError { .. } | Self::AllProvidersFailed { .. } => FcpError::Internal {
                message: self.to_string(),
            },
            Self::InvalidStrategy(_) => FcpError::InvalidRequest {
                code: 1003,
                message: self.to_string(),
            },
            Self::CapabilityNotAvailable(_) => FcpError::InvalidRequest {
                code: 1004,
                message: self.to_string(),
            },
        }
    }

    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ProviderError { .. } | Self::AllProvidersFailed { .. }
        )
    }

    fn retry_after(&self) -> Option<Duration> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_providers_maps_to_invalid_request() {
        let fcp_err: FcpError = RouterError::NoProviders.into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("No providers configured"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn no_provider_available_maps_to_invalid_request() {
        let fcp_err: FcpError = RouterError::NoProviderAvailable {
            reason: "all down".into(),
        }
        .into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert!(message.contains("all down"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn budget_exceeded_maps_to_capability_denied() {
        let fcp_err: FcpError = RouterError::BudgetExceeded {
            spent_usd: 10.5,
            budget_usd: 10.0,
        }
        .into();
        match fcp_err {
            FcpError::CapabilityDenied {
                capability, reason, ..
            } => {
                assert_eq!(capability, "llm-router.route");
                assert!(reason.contains("10.5"));
                assert!(reason.contains("10.0"));
            }
            other => panic!("Expected CapabilityDenied, got {other:?}"),
        }
    }

    #[test]
    fn provider_error_maps_to_internal() {
        let fcp_err: FcpError = RouterError::ProviderError {
            provider: "openai".into(),
            message: "rate limited".into(),
        }
        .into();
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("openai"));
                assert!(message.contains("rate limited"));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn all_providers_failed_maps_to_internal() {
        let fcp_err: FcpError = RouterError::AllProvidersFailed {
            message: "timeout".into(),
        }
        .into();
        match fcp_err {
            FcpError::Internal { message } => {
                assert!(message.contains("timeout"));
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn invalid_strategy_maps_to_invalid_request() {
        let fcp_err: FcpError = RouterError::InvalidStrategy("random".into()).into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert!(message.contains("random"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn capability_not_available_maps_to_invalid_request() {
        let fcp_err: FcpError = RouterError::CapabilityNotAvailable("vision".into()).into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert!(message.contains("vision"));
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            RouterError::NoProviders.to_string(),
            "No providers configured"
        );
        assert!(
            RouterError::BudgetExceeded {
                spent_usd: 1.5,
                budget_usd: 1.0
            }
            .to_string()
            .contains("1.5")
        );
        assert!(
            RouterError::ProviderError {
                provider: "test".into(),
                message: "fail".into()
            }
            .to_string()
            .contains("test")
        );
    }

    // ---- Display messages for all variants ----

    #[test]
    fn display_no_provider_available() {
        let err = RouterError::NoProviderAvailable {
            reason: "all endpoints down".into(),
        };
        assert_eq!(
            err.to_string(),
            "No provider available for request: all endpoints down"
        );
    }

    #[test]
    fn display_all_providers_failed() {
        let err = RouterError::AllProvidersFailed {
            message: "exhausted retries".into(),
        };
        assert_eq!(err.to_string(), "All providers failed: exhausted retries");
    }

    #[test]
    fn display_invalid_strategy() {
        let err = RouterError::InvalidStrategy("round_robin".into());
        assert_eq!(err.to_string(), "Invalid routing strategy: round_robin");
    }

    #[test]
    fn display_capability_not_available() {
        let err = RouterError::CapabilityNotAvailable("streaming".into());
        assert_eq!(
            err.to_string(),
            "Required capability not available: streaming"
        );
    }

    #[test]
    fn display_provider_error_full() {
        let err = RouterError::ProviderError {
            provider: "anthropic".into(),
            message: "429 rate limited".into(),
        };
        assert_eq!(
            err.to_string(),
            "Provider anthropic error: 429 rate limited"
        );
    }

    // ---- Budget exceeded display format (4 decimal places) ----

    #[test]
    fn budget_exceeded_display_four_decimal_places() {
        let err = RouterError::BudgetExceeded {
            spent_usd: 10.123456,
            budget_usd: 5.0,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("10.1235"),
            "expected 4 decimal precision, got: {msg}"
        );
        assert!(
            msg.contains("5.0000"),
            "budget should show 4 decimals, got: {msg}"
        );
    }

    #[test]
    fn budget_exceeded_equal_values() {
        let err = RouterError::BudgetExceeded {
            spent_usd: 100.0,
            budget_usd: 100.0,
        };
        let msg = err.to_string();
        assert_eq!(msg, "Budget exceeded: spent 100.0000 of 100.0000 USD");
    }

    #[test]
    fn budget_exceeded_zero_budget() {
        let err = RouterError::BudgetExceeded {
            spent_usd: 0.0001,
            budget_usd: 0.0,
        };
        let msg = err.to_string();
        assert!(msg.contains("0.0001"));
        assert!(msg.contains("0.0000"));
    }

    #[test]
    fn budget_exceeded_large_values() {
        let err = RouterError::BudgetExceeded {
            spent_usd: 999_999.999_9,
            budget_usd: 500_000.0,
        };
        let msg = err.to_string();
        assert!(msg.contains("999999.9999"), "large spent not in msg: {msg}");
        assert!(
            msg.contains("500000.0000"),
            "large budget not in msg: {msg}"
        );
    }

    // ---- Debug formatting for each variant ----

    #[test]
    fn debug_no_providers() {
        let dbg = format!("{:?}", RouterError::NoProviders);
        assert!(dbg.contains("NoProviders"));
    }

    #[test]
    fn debug_no_provider_available() {
        let dbg = format!(
            "{:?}",
            RouterError::NoProviderAvailable {
                reason: "timeout".into()
            }
        );
        assert!(dbg.contains("NoProviderAvailable"));
        assert!(dbg.contains("timeout"));
    }

    #[test]
    fn debug_budget_exceeded() {
        let dbg = format!(
            "{:?}",
            RouterError::BudgetExceeded {
                spent_usd: std::f64::consts::PI,
                budget_usd: 2.0
            }
        );
        assert!(dbg.contains("BudgetExceeded"));
        assert!(dbg.contains("3.14"));
    }

    #[test]
    fn debug_provider_error() {
        let dbg = format!(
            "{:?}",
            RouterError::ProviderError {
                provider: "openai".into(),
                message: "500".into()
            }
        );
        assert!(dbg.contains("ProviderError"));
        assert!(dbg.contains("openai"));
    }

    #[test]
    fn debug_all_providers_failed() {
        let dbg = format!(
            "{:?}",
            RouterError::AllProvidersFailed {
                message: "circuit open".into()
            }
        );
        assert!(dbg.contains("AllProvidersFailed"));
        assert!(dbg.contains("circuit open"));
    }

    #[test]
    fn debug_invalid_strategy() {
        let dbg = format!("{:?}", RouterError::InvalidStrategy("weighted".into()));
        assert!(dbg.contains("InvalidStrategy"));
        assert!(dbg.contains("weighted"));
    }

    #[test]
    fn debug_capability_not_available() {
        let dbg = format!("{:?}", RouterError::CapabilityNotAvailable("vision".into()));
        assert!(dbg.contains("CapabilityNotAvailable"));
        assert!(dbg.contains("vision"));
    }

    // ---- RouterResult Ok and Err usage ----

    #[test]
    fn router_result_ok() {
        let result: RouterResult<u32> = Ok(42);
        let Ok(val) = result else {
            panic!("expected Ok")
        };
        assert_eq!(val, 42);
    }

    #[test]
    fn router_result_err() {
        let result: RouterResult<u32> = Err(RouterError::NoProviders);
        assert!(result.is_err());
        let Err(err) = result else {
            panic!("expected Err")
        };
        assert_eq!(err.to_string(), "No providers configured");
    }

    #[test]
    fn router_result_map() {
        let result: RouterResult<u32> = Ok(10);
        let mapped = result.map(|v| v * 2);
        assert_eq!(mapped.unwrap(), 20);
    }

    // ---- From conversion field verification ----

    #[test]
    fn from_no_providers_exact_fields() {
        let fcp_err: FcpError = RouterError::NoProviders.into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "No providers configured");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_no_provider_available_exact_fields() {
        let fcp_err: FcpError = RouterError::NoProviderAvailable {
            reason: "rate limited".into(),
        }
        .into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert_eq!(message, "No provider available for request: rate limited");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_budget_exceeded_exact_fields() {
        let fcp_err: FcpError = RouterError::BudgetExceeded {
            spent_usd: 20.0,
            budget_usd: 15.0,
        }
        .into();
        match fcp_err {
            FcpError::CapabilityDenied {
                capability, reason, ..
            } => {
                assert_eq!(capability, "llm-router.route");
                assert_eq!(reason, "Budget exceeded: spent 20.0000 of 15.0000 USD");
            }
            other => panic!("Expected CapabilityDenied, got {other:?}"),
        }
    }

    #[test]
    fn from_invalid_strategy_exact_fields() {
        let fcp_err: FcpError = RouterError::InvalidStrategy("priority".into()).into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1003);
                assert_eq!(message, "Invalid routing strategy: priority");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_capability_not_available_exact_fields() {
        let fcp_err: FcpError = RouterError::CapabilityNotAvailable("tool_use".into()).into();
        match fcp_err {
            FcpError::InvalidRequest { code, message } => {
                assert_eq!(code, 1004);
                assert_eq!(message, "Required capability not available: tool_use");
            }
            other => panic!("Expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn from_provider_error_exact_fields() {
        let fcp_err: FcpError = RouterError::ProviderError {
            provider: "google".into(),
            message: "auth failed".into(),
        }
        .into();
        match fcp_err {
            FcpError::Internal { message } => {
                assert_eq!(message, "Provider google error: auth failed");
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn from_all_providers_failed_exact_fields() {
        let fcp_err: FcpError = RouterError::AllProvidersFailed {
            message: "network partition".into(),
        }
        .into();
        match fcp_err {
            FcpError::Internal { message } => {
                assert_eq!(message, "All providers failed: network partition");
            }
            other => panic!("Expected Internal, got {other:?}"),
        }
    }

    // ---- Empty string edge cases ----

    #[test]
    fn empty_reason_no_provider_available() {
        let err = RouterError::NoProviderAvailable {
            reason: String::new(),
        };
        assert_eq!(err.to_string(), "No provider available for request: ");
    }

    #[test]
    fn empty_provider_and_message() {
        let err = RouterError::ProviderError {
            provider: String::new(),
            message: String::new(),
        };
        assert_eq!(err.to_string(), "Provider  error: ");
    }

    #[test]
    fn empty_all_providers_failed_message() {
        let err = RouterError::AllProvidersFailed {
            message: String::new(),
        };
        assert_eq!(err.to_string(), "All providers failed: ");
    }

    #[test]
    fn empty_invalid_strategy() {
        let err = RouterError::InvalidStrategy(String::new());
        assert_eq!(err.to_string(), "Invalid routing strategy: ");
    }

    #[test]
    fn empty_capability_not_available() {
        let err = RouterError::CapabilityNotAvailable(String::new());
        assert_eq!(err.to_string(), "Required capability not available: ");
    }

    // ---- Error trait (dyn std::error::Error) ----

    #[test]
    fn router_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(RouterError::NoProviders);
        assert_eq!(err.to_string(), "No providers configured");
    }

    #[test]
    fn router_error_source_is_none() {
        // RouterError variants have no source/cause
        use std::error::Error;
        let err = RouterError::NoProviders;
        assert!(err.source().is_none());
    }
}
