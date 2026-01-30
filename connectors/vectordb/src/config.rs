//! Configuration and provisioning for the vectordb connector.
//!
//! Supports multiple vector database providers (Pinecone, Qdrant) with
//! secretless credential handling via `CredentialId` references.

use fcp_core::{CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};

/// Supported vector database providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VectorDbProvider {
    /// Pinecone vector database (<https://pinecone.io>)
    Pinecone,
    /// Qdrant vector database (<https://qdrant.tech>)
    Qdrant,
}

impl VectorDbProvider {
    /// Get the allowed host patterns for this provider.
    #[must_use]
    pub const fn allowed_hosts(&self) -> &'static [&'static str] {
        match self {
            Self::Pinecone => &["*.pinecone.io"],
            Self::Qdrant => &["*.qdrant.io", "*.qdrant.tech"],
        }
    }

    /// Get the default port for this provider.
    #[must_use]
    pub const fn default_port(&self) -> u16 {
        match self {
            Self::Pinecone => 443,
            Self::Qdrant => 6333, // gRPC port; 6334 is REST
        }
    }

    /// Check if the provider requires TLS.
    #[must_use]
    pub const fn requires_tls(&self) -> bool {
        match self {
            Self::Pinecone => true,
            Self::Qdrant => false, // Can be local without TLS
        }
    }
}

impl std::fmt::Display for VectorDbProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pinecone => write!(f, "pinecone"),
            Self::Qdrant => write!(f, "qdrant"),
        }
    }
}

/// Configuration for the vectordb connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorDbConfig {
    /// The provider to use.
    pub provider: VectorDbProvider,

    /// Endpoint URL (without protocol).
    /// For Pinecone: index-name-project.svc.region.pinecone.io
    /// For Qdrant: host:port or qdrant.example.com
    pub endpoint: String,

    /// Credential ID for API authentication.
    /// The mesh egress proxy will inject the actual credential.
    pub credential_id: CredentialId,

    /// Whether to use TLS (HTTPS/gRPCS).
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,

    /// Optional namespace/environment for multi-tenant setups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Connection timeout in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,

    /// Request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u32,
}

const fn default_use_tls() -> bool {
    true
}

const fn default_connect_timeout_ms() -> u32 {
    10_000 // 10 seconds
}

const fn default_request_timeout_ms() -> u32 {
    60_000 // 60 seconds
}

impl VectorDbConfig {
    /// Parse configuration from JSON value.
    ///
    /// # Errors
    /// Returns `FcpError::InvalidRequest` if the configuration is invalid.
    pub fn from_params(params: &serde_json::Value) -> FcpResult<Self> {
        serde_json::from_value(params.clone()).map_err(|e| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid vectordb configuration: {e}"),
        })
    }

    /// Validate the configuration.
    ///
    /// # Errors
    /// Returns `FcpError::InvalidRequest` if validation fails.
    pub fn validate(&self) -> FcpResult<()> {
        // Check endpoint is not empty
        if self.endpoint.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Endpoint cannot be empty".into(),
            });
        }

        // Check endpoint doesn't contain protocol prefix
        if self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://") {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Endpoint should not include protocol (http:// or https://)".into(),
            });
        }

        // For Pinecone, TLS is required
        if self.provider == VectorDbProvider::Pinecone && !self.use_tls {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Pinecone requires TLS".into(),
            });
        }

        // Check timeouts are reasonable
        if self.connect_timeout_ms == 0 || self.connect_timeout_ms > 300_000 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Connect timeout must be between 1ms and 300000ms".into(),
            });
        }

        if self.request_timeout_ms == 0 || self.request_timeout_ms > 600_000 {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Request timeout must be between 1ms and 600000ms".into(),
            });
        }

        Ok(())
    }

    /// Get the full URL for the endpoint.
    #[must_use]
    pub fn url(&self) -> String {
        let protocol = if self.use_tls { "https" } else { "http" };
        format!("{protocol}://{}", self.endpoint)
    }

    /// Check if the configured endpoint matches the provider's allowed hosts.
    ///
    /// This is a basic check; the mesh egress proxy performs stricter validation.
    #[must_use]
    pub fn is_endpoint_allowed(&self) -> bool {
        let endpoint_lower = self.endpoint.to_lowercase();
        let host = endpoint_lower.split(':').next().unwrap_or(&endpoint_lower);

        self.provider.allowed_hosts().iter().any(|pattern| {
            pattern
                .strip_prefix('*')
                .map_or_else(|| host == *pattern, |suffix| host.ends_with(suffix))
        })
    }
}

/// Doctor check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorResult {
    /// Overall status.
    pub status: DoctorStatus,
    /// Individual check results.
    pub checks: Vec<DoctorCheck>,
}

/// Doctor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    /// All checks passed.
    Healthy,
    /// Some non-critical checks failed.
    Degraded,
    /// Critical checks failed.
    Unhealthy,
}

/// Individual doctor check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Check name.
    pub name: String,
    /// Check passed.
    pub passed: bool,
    /// Check message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Whether this check is critical.
    pub critical: bool,
}

impl DoctorResult {
    /// Create a new doctor result from checks.
    #[must_use]
    pub fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };

        Self { status, checks }
    }

    /// Check if the result indicates a healthy state.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == DoctorStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_provider_allowed_hosts() {
        assert!(
            VectorDbProvider::Pinecone
                .allowed_hosts()
                .contains(&"*.pinecone.io")
        );
        assert!(
            VectorDbProvider::Qdrant
                .allowed_hosts()
                .contains(&"*.qdrant.io")
        );
    }

    #[test]
    fn test_config_from_params() {
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index-abc123.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let config = VectorDbConfig::from_params(&params).unwrap();
        assert_eq!(config.provider, VectorDbProvider::Pinecone);
        assert!(config.use_tls);
    }

    #[test]
    fn test_config_validation_empty_endpoint() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: String::new(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_protocol_in_endpoint() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "https://my-index.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_pinecone_requires_tls() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_url() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        assert_eq!(config.url(), "http://localhost:6333");
    }

    #[test]
    fn test_endpoint_allowed_pinecone() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index-abc.svc.us-east-1.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        assert!(config.is_endpoint_allowed());
    }

    #[test]
    fn test_endpoint_not_allowed() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "evil.com".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        assert!(!config.is_endpoint_allowed());
    }

    #[test]
    fn test_doctor_result_healthy() {
        let checks = vec![
            DoctorCheck {
                name: "config".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "connection".into(),
                passed: true,
                message: Some("Connected".into()),
                critical: true,
            },
        ];

        let result = DoctorResult::from_checks(checks);
        assert!(result.is_healthy());
    }

    #[test]
    fn test_doctor_result_unhealthy() {
        let checks = vec![
            DoctorCheck {
                name: "config".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "connection".into(),
                passed: false,
                message: Some("Connection refused".into()),
                critical: true,
            },
        ];

        let result = DoctorResult::from_checks(checks);
        assert!(!result.is_healthy());
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn test_doctor_result_degraded() {
        let checks = vec![
            DoctorCheck {
                name: "config".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "latency".into(),
                passed: false,
                message: Some("High latency".into()),
                critical: false,
            },
        ];

        let result = DoctorResult::from_checks(checks);
        assert!(!result.is_healthy());
        assert_eq!(result.status, DoctorStatus::Degraded);
    }
}
