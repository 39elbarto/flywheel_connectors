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
