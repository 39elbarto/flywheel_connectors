//! LLM Router error types.

use fcp_core::FcpError;

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
}
