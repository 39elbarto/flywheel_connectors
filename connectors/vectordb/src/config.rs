//! Configuration and provisioning for the vectordb connector.
//!
//! Supports multiple vector database providers (Pinecone, Qdrant) with
//! secretless credential handling via `CredentialId` references.

use fcp_prelude::{CredentialId, FcpError, FcpResult};
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
    use chrono::{SecondsFormat, Utc};
    use fcp_testkit::LogCapture;
    use serde_json::json;
    use std::time::Instant;

    struct TestLog {
        test_name: &'static str,
        module: &'static str,
        correlation_id: String,
        start: Instant,
        assertions_passed: u32,
        assertions_failed: u32,
        capture: LogCapture,
    }

    impl TestLog {
        fn new(test_name: &'static str) -> Self {
            Self {
                test_name,
                module: "fcp-vectordb-config",
                correlation_id: uuid::Uuid::new_v4().to_string(),
                start: Instant::now(),
                assertions_passed: 0,
                assertions_failed: 0,
                capture: LogCapture::new(),
            }
        }

        fn check(&mut self, condition: bool, message: &str) -> Result<(), String> {
            if !condition {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(message.to_string());
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn check_eq<T: std::fmt::Debug + PartialEq>(
            &mut self,
            left: T,
            right: T,
            context: &str,
        ) -> Result<(), String> {
            if left != right {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                return Err(format!("{context}: left={left:?} right={right:?}"));
            }
            self.assertions_passed = self.assertions_passed.saturating_add(1);
            Ok(())
        }

        fn emit(&mut self, phase: &str, result: &str, context: serde_json::Value) {
            let duration_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let entry = serde_json::json!({
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                "log_version": "v1",
                "level": "info",
                "test_name": self.test_name,
                "module": self.module,
                "phase": phase,
                "correlation_id": self.correlation_id,
                "result": result,
                "duration_ms": duration_ms,
                "assertions": {
                    "passed": self.assertions_passed,
                    "failed": self.assertions_failed
                },
                "context": context
            });

            let serialized = serde_json::to_string(&entry).unwrap_or_else(|err| {
                self.assertions_failed = self.assertions_failed.saturating_add(1);
                format!("{{\"error\":\"log_serialization_failed\",\"detail\":\"{err}\"}}")
            });
            println!("{serialized}");
            let _ = self.capture.push_value(&entry);
            if !std::thread::panicking() {
                self.capture.assert_valid();
            }
        }
    }

    impl Drop for TestLog {
        fn drop(&mut self) {
            let result = if std::thread::panicking() {
                if self.assertions_failed == 0 {
                    self.assertions_failed = 1;
                }
                "fail"
            } else {
                "pass"
            };
            self.emit(
                "verify",
                result,
                serde_json::json!({ "connector_id": "vectordb" }),
            );
        }
    }

    #[test]
    fn test_provider_allowed_hosts() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_provider_allowed_hosts");
        log.check(
            VectorDbProvider::Pinecone
                .allowed_hosts()
                .contains(&"*.pinecone.io"),
            "pinecone host pattern missing",
        )?;
        log.check(
            VectorDbProvider::Qdrant
                .allowed_hosts()
                .contains(&"*.qdrant.io"),
            "qdrant host pattern missing",
        )?;
        Ok(())
    }

    #[test]
    fn test_config_from_params() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_config_from_params");
        let params = json!({
            "provider": "pinecone",
            "endpoint": "my-index-abc123.svc.us-east-1.pinecone.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });

        let config = VectorDbConfig::from_params(&params).map_err(|err| {
            log.assertions_failed = log.assertions_failed.saturating_add(1);
            format!("expected config to parse: {err}")
        })?;
        log.check_eq(
            config.provider,
            VectorDbProvider::Pinecone,
            "provider mismatch",
        )?;
        log.check(config.use_tls, "use_tls default should be true")?;
        Ok(())
    }

    #[test]
    fn test_config_validation_empty_endpoint() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_config_empty_endpoint");
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: String::new(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        log.check(
            config.validate().is_err(),
            "empty endpoint should be invalid",
        )?;
        Ok(())
    }

    #[test]
    fn test_config_validation_protocol_in_endpoint() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_config_protocol_endpoint");
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "https://my-index.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        log.check(
            config.validate().is_err(),
            "protocol prefix should be invalid",
        )?;
        Ok(())
    }

    #[test]
    fn test_config_validation_pinecone_requires_tls() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_config_pinecone_tls");
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        log.check(config.validate().is_err(), "pinecone must require tls")?;
        Ok(())
    }

    #[test]
    fn test_config_url() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_config_url");
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        log.check_eq(
            config.url(),
            "http://localhost:6333".to_string(),
            "url mismatch",
        )?;
        Ok(())
    }

    #[test]
    fn test_endpoint_allowed_pinecone() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_endpoint_allowed_pinecone");
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index-abc.svc.us-east-1.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        log.check(config.is_endpoint_allowed(), "endpoint should be allowed")?;
        Ok(())
    }

    #[test]
    fn test_endpoint_not_allowed() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_endpoint_not_allowed");
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "evil.com".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };

        log.check(!config.is_endpoint_allowed(), "endpoint should be rejected")?;
        Ok(())
    }

    #[test]
    fn test_doctor_result_healthy() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_doctor_result_healthy");
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
        log.check(result.is_healthy(), "doctor result should be healthy")?;
        Ok(())
    }

    #[test]
    fn test_doctor_result_unhealthy() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_doctor_result_unhealthy");
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
        log.check(!result.is_healthy(), "doctor result should be unhealthy")?;
        log.check_eq(result.status, DoctorStatus::Unhealthy, "status mismatch")?;
        Ok(())
    }

    #[test]
    fn test_doctor_result_degraded() -> Result<(), String> {
        let mut log = TestLog::new("vectordb_doctor_result_degraded");
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
        log.check(!result.is_healthy(), "doctor result should be degraded")?;
        log.check_eq(result.status, DoctorStatus::Degraded, "status mismatch")?;
        Ok(())
    }

    // ── Provider Display ─────────────────────────────────────────────────

    #[test]
    fn test_provider_display_pinecone() {
        assert_eq!(VectorDbProvider::Pinecone.to_string(), "pinecone");
    }

    #[test]
    fn test_provider_display_qdrant() {
        assert_eq!(VectorDbProvider::Qdrant.to_string(), "qdrant");
    }

    // ── Provider Debug ───────────────────────────────────────────────────

    #[test]
    fn test_provider_debug_format() {
        let debug = format!("{:?}", VectorDbProvider::Pinecone);
        assert!(
            debug.contains("Pinecone"),
            "debug should contain variant name"
        );
        let debug_q = format!("{:?}", VectorDbProvider::Qdrant);
        assert!(debug_q.contains("Qdrant"), "debug should contain Qdrant");
    }

    // ── Provider Clone / PartialEq / Eq / Copy ──────────────────────────

    #[test]
    fn test_provider_clone_eq() {
        let p = VectorDbProvider::Pinecone;
        let p2 = p;
        assert_eq!(p, p2);
        let q = VectorDbProvider::Qdrant;
        assert_ne!(p, q);
    }

    // ── Provider Serde Roundtrip ─────────────────────────────────────────

    #[test]
    fn test_provider_serde_roundtrip_pinecone() {
        let serialized = serde_json::to_string(&VectorDbProvider::Pinecone).unwrap();
        assert_eq!(serialized, "\"pinecone\"");
        let deserialized: VectorDbProvider = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, VectorDbProvider::Pinecone);
    }

    #[test]
    fn test_provider_serde_roundtrip_qdrant() {
        let serialized = serde_json::to_string(&VectorDbProvider::Qdrant).unwrap();
        assert_eq!(serialized, "\"qdrant\"");
        let deserialized: VectorDbProvider = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, VectorDbProvider::Qdrant);
    }

    #[test]
    fn test_provider_deserialize_unknown_fails() {
        let result = serde_json::from_str::<VectorDbProvider>("\"milvus\"");
        assert!(
            result.is_err(),
            "unknown provider should fail to deserialize"
        );
    }

    // ── Provider Methods ─────────────────────────────────────────────────

    #[test]
    fn test_provider_default_port_pinecone() {
        assert_eq!(VectorDbProvider::Pinecone.default_port(), 443);
    }

    #[test]
    fn test_provider_default_port_qdrant() {
        assert_eq!(VectorDbProvider::Qdrant.default_port(), 6333);
    }

    #[test]
    fn test_provider_requires_tls_pinecone() {
        assert!(VectorDbProvider::Pinecone.requires_tls());
    }

    #[test]
    fn test_provider_requires_tls_qdrant() {
        assert!(!VectorDbProvider::Qdrant.requires_tls());
    }

    #[test]
    fn test_provider_allowed_hosts_qdrant_has_both_domains() {
        let hosts = VectorDbProvider::Qdrant.allowed_hosts();
        assert!(hosts.contains(&"*.qdrant.io"));
        assert!(hosts.contains(&"*.qdrant.tech"));
    }

    // ── Config Serde Roundtrip ───────────────────────────────────────────

    #[test]
    fn test_config_serde_roundtrip_all_fields() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.svc.us-east-1.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: Some("prod".into()),
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        };
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: VectorDbConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.provider, config.provider);
        assert_eq!(deserialized.endpoint, config.endpoint);
        assert_eq!(deserialized.use_tls, config.use_tls);
        assert_eq!(deserialized.namespace, Some("prod".into()));
        assert_eq!(deserialized.connect_timeout_ms, 5_000);
        assert_eq!(deserialized.request_timeout_ms, 30_000);
    }

    #[test]
    fn test_config_serde_roundtrip_minimal() {
        let params = json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let config = VectorDbConfig::from_params(&params).unwrap();
        // Defaults should be applied
        assert!(config.use_tls, "use_tls default should be true");
        assert_eq!(config.connect_timeout_ms, 10_000);
        assert_eq!(config.request_timeout_ms, 60_000);
        assert!(config.namespace.is_none());
    }

    // ── skip_serializing_if for namespace ────────────────────────────────

    #[test]
    fn test_config_skip_serializing_if_namespace_none() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(
            !serialized.contains("namespace"),
            "namespace=None should be omitted from serialization"
        );
    }

    #[test]
    fn test_config_serializes_namespace_when_some() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: Some("my-ns".into()),
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(
            serialized.contains("\"namespace\":\"my-ns\""),
            "namespace=Some should be present in serialization"
        );
    }

    // ── Config Clone / Debug ─────────────────────────────────────────────

    #[test]
    fn test_config_clone() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: Some("ns".into()),
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        let cloned = config.clone();
        assert_eq!(cloned.provider, config.provider);
        assert_eq!(cloned.endpoint, config.endpoint);
        assert_eq!(cloned.namespace, config.namespace);
    }

    #[test]
    fn test_config_debug() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("Qdrant"), "debug should mention provider");
        assert!(
            debug.contains("localhost:6333"),
            "debug should mention endpoint"
        );
    }

    // ── Config Defaults ──────────────────────────────────────────────────

    #[test]
    fn test_config_default_use_tls_is_true() {
        let params = json!({
            "provider": "qdrant",
            "endpoint": "host.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let config = VectorDbConfig::from_params(&params).unwrap();
        assert!(config.use_tls, "default use_tls should be true");
    }

    #[test]
    fn test_config_default_connect_timeout_ms() {
        let params = json!({
            "provider": "qdrant",
            "endpoint": "host.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let config = VectorDbConfig::from_params(&params).unwrap();
        assert_eq!(config.connect_timeout_ms, 10_000);
    }

    #[test]
    fn test_config_default_request_timeout_ms() {
        let params = json!({
            "provider": "qdrant",
            "endpoint": "host.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let config = VectorDbConfig::from_params(&params).unwrap();
        assert_eq!(config.request_timeout_ms, 60_000);
    }

    #[test]
    fn test_config_override_defaults() {
        let params = json!({
            "provider": "qdrant",
            "endpoint": "host.qdrant.io",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
            "use_tls": false,
            "connect_timeout_ms": 1_000,
            "request_timeout_ms": 5_000,
            "namespace": "custom"
        });
        let config = VectorDbConfig::from_params(&params).unwrap();
        assert!(!config.use_tls);
        assert_eq!(config.connect_timeout_ms, 1_000);
        assert_eq!(config.request_timeout_ms, 5_000);
        assert_eq!(config.namespace, Some("custom".into()));
    }

    // ── Config Validation Edge Cases ─────────────────────────────────────

    #[test]
    fn test_config_validate_connect_timeout_zero() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 0,
            request_timeout_ms: 60_000,
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("Connect timeout"),
            "error should mention connect timeout: {err}"
        );
    }

    #[test]
    fn test_config_validate_connect_timeout_too_large() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 300_001,
            request_timeout_ms: 60_000,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Connect timeout"));
    }

    #[test]
    fn test_config_validate_connect_timeout_max_boundary() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 300_000,
            request_timeout_ms: 60_000,
        };
        assert!(config.validate().is_ok(), "300000ms should be valid");
    }

    #[test]
    fn test_config_validate_request_timeout_zero() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 0,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Request timeout"));
    }

    #[test]
    fn test_config_validate_request_timeout_too_large() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 600_001,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Request timeout"));
    }

    #[test]
    fn test_config_validate_request_timeout_max_boundary() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 600_000,
        };
        assert!(config.validate().is_ok(), "600000ms should be valid");
    }

    #[test]
    fn test_config_validate_http_prefix_rejected() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "http://localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("protocol"));
    }

    #[test]
    fn test_config_validate_qdrant_without_tls_ok() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "localhost:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: false,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert!(config.validate().is_ok(), "qdrant without TLS should be ok");
    }

    #[test]
    fn test_config_validate_valid_pinecone() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.svc.us-east-1.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert!(config.validate().is_ok());
    }

    // ── Config URL ───────────────────────────────────────────────────────

    #[test]
    fn test_config_url_with_tls() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "my-index.pinecone.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert_eq!(config.url(), "https://my-index.pinecone.io");
    }

    #[test]
    fn test_config_url_without_tls() {
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

    // ── Config Endpoint Allowlist Edge Cases ─────────────────────────────

    #[test]
    fn test_endpoint_allowed_qdrant_io() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "my-cluster.qdrant.io".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert!(config.is_endpoint_allowed());
    }

    #[test]
    fn test_endpoint_allowed_qdrant_tech() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "my-cluster.qdrant.tech".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert!(config.is_endpoint_allowed());
    }

    #[test]
    fn test_endpoint_not_allowed_qdrant_wrong_domain() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "qdrant.example.com".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert!(!config.is_endpoint_allowed());
    }

    #[test]
    fn test_endpoint_allowed_case_insensitive() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Pinecone,
            endpoint: "MY-INDEX.SVC.US-EAST-1.PINECONE.IO".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert!(
            config.is_endpoint_allowed(),
            "endpoint check should be case-insensitive"
        );
    }

    #[test]
    fn test_endpoint_with_port_suffix() {
        let config = VectorDbConfig {
            provider: VectorDbProvider::Qdrant,
            endpoint: "my-cluster.qdrant.io:6333".into(),
            credential_id: CredentialId::new(),
            use_tls: true,
            namespace: None,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
        };
        assert!(
            config.is_endpoint_allowed(),
            "endpoint with port should strip port for host check"
        );
    }

    // ── Config from_params Error Cases ───────────────────────────────────

    #[test]
    fn test_config_from_params_missing_provider() {
        let params = json!({
            "endpoint": "localhost:6333",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let result = VectorDbConfig::from_params(&params);
        assert!(result.is_err(), "missing provider should fail");
        if let Err(FcpError::InvalidRequest { code, .. }) = result {
            assert_eq!(code, 1003);
        } else {
            panic!("expected InvalidRequest error");
        }
    }

    #[test]
    fn test_config_from_params_missing_endpoint() {
        let params = json!({
            "provider": "pinecone",
            "credential_id": "11223344-5566-7788-99aa-bbccddeeff00"
        });
        let result = VectorDbConfig::from_params(&params);
        assert!(result.is_err(), "missing endpoint should fail");
    }

    #[test]
    fn test_config_from_params_missing_credential_id() {
        let params = json!({
            "provider": "qdrant",
            "endpoint": "localhost:6333"
        });
        let result = VectorDbConfig::from_params(&params);
        assert!(result.is_err(), "missing credential_id should fail");
    }

    #[test]
    fn test_config_from_params_invalid_json_type() {
        let params = json!("not an object");
        let result = VectorDbConfig::from_params(&params);
        assert!(result.is_err(), "string value should fail");
    }

    #[test]
    fn test_config_from_params_null() {
        let params = json!(null);
        let result = VectorDbConfig::from_params(&params);
        assert!(result.is_err(), "null should fail");
    }

    // ── DoctorStatus Serde ───────────────────────────────────────────────

    #[test]
    fn test_doctor_status_serde_roundtrip() {
        for status in [
            DoctorStatus::Healthy,
            DoctorStatus::Degraded,
            DoctorStatus::Unhealthy,
        ] {
            let serialized = serde_json::to_string(&status).unwrap();
            let deserialized: DoctorStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_doctor_status_serialized_values() {
        assert_eq!(
            serde_json::to_string(&DoctorStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&DoctorStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&DoctorStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    // ── DoctorStatus Debug / Clone / Copy / Eq ───────────────────────────

    #[test]
    fn test_doctor_status_debug() {
        let debug = format!("{:?}", DoctorStatus::Healthy);
        assert!(debug.contains("Healthy"));
    }

    #[test]
    fn test_doctor_status_clone_copy_eq() {
        let s = DoctorStatus::Degraded;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // ── DoctorCheck Serde ────────────────────────────────────────────────

    #[test]
    fn test_doctor_check_serde_with_message() {
        let check = DoctorCheck {
            name: "connectivity".into(),
            passed: true,
            message: Some("Connected in 42ms".into()),
            critical: false,
        };
        let serialized = serde_json::to_string(&check).unwrap();
        let deserialized: DoctorCheck = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, "connectivity");
        assert!(deserialized.passed);
        assert_eq!(deserialized.message, Some("Connected in 42ms".into()));
        assert!(!deserialized.critical);
    }

    #[test]
    fn test_doctor_check_skip_serializing_if_message_none() {
        let check = DoctorCheck {
            name: "config".into(),
            passed: true,
            message: None,
            critical: true,
        };
        let serialized = serde_json::to_string(&check).unwrap();
        assert!(
            !serialized.contains("message"),
            "message=None should be omitted: {serialized}"
        );
    }

    #[test]
    fn test_doctor_check_debug_clone() {
        let check = DoctorCheck {
            name: "test".into(),
            passed: false,
            message: Some("failed".into()),
            critical: true,
        };
        let cloned = check.clone();
        assert_eq!(cloned.name, check.name);
        assert_eq!(cloned.message, check.message);
        let debug = format!("{check:?}");
        assert!(debug.contains("test"));
    }

    // ── DoctorResult Edge Cases ──────────────────────────────────────────

    #[test]
    fn test_doctor_result_empty_checks_is_healthy() {
        let result = DoctorResult::from_checks(vec![]);
        assert!(result.is_healthy(), "empty checks should be healthy");
        assert_eq!(result.status, DoctorStatus::Healthy);
    }

    #[test]
    fn test_doctor_result_all_non_critical_failures_is_degraded() {
        let checks = vec![
            DoctorCheck {
                name: "latency".into(),
                passed: false,
                message: None,
                critical: false,
            },
            DoctorCheck {
                name: "optional_service".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Degraded);
        assert!(!result.is_healthy());
    }

    #[test]
    fn test_doctor_result_mixed_critical_and_noncritical() {
        let checks = vec![
            DoctorCheck {
                name: "critical_ok".into(),
                passed: true,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "noncritical_fail".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        // Critical passes, but non-critical fails -> degraded
        assert_eq!(result.status, DoctorStatus::Degraded);
    }

    #[test]
    fn test_doctor_result_critical_failure_overrides_noncritical_pass() {
        let checks = vec![
            DoctorCheck {
                name: "critical_fail".into(),
                passed: false,
                message: None,
                critical: true,
            },
            DoctorCheck {
                name: "noncritical_ok".into(),
                passed: true,
                message: None,
                critical: false,
            },
        ];
        let result = DoctorResult::from_checks(checks);
        assert_eq!(result.status, DoctorStatus::Unhealthy);
    }

    #[test]
    fn test_doctor_result_serde_roundtrip() {
        let result = DoctorResult::from_checks(vec![
            DoctorCheck {
                name: "a".into(),
                passed: true,
                message: Some("ok".into()),
                critical: true,
            },
            DoctorCheck {
                name: "b".into(),
                passed: false,
                message: None,
                critical: false,
            },
        ]);
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: DoctorResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.status, result.status);
        assert_eq!(deserialized.checks.len(), 2);
        assert_eq!(deserialized.checks[0].name, "a");
        assert_eq!(deserialized.checks[1].name, "b");
    }

    #[test]
    fn test_doctor_result_debug() {
        let result = DoctorResult::from_checks(vec![]);
        let debug = format!("{result:?}");
        assert!(debug.contains("Healthy"));
    }
}
