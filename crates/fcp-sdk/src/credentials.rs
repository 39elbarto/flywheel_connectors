//! Credential lease helpers for connector authors.
//!
//! This module keeps credential pooling host-neutral: connector code receives a
//! `Cx`, imports the SDK prelude, and calls the extension methods against a
//! host-provided lease client. The client trait is deliberately small so the
//! later host transport bridge can implement it without making `fcp-sdk`
//! depend on `fcp-host`.

use std::fmt;

use crate::async_trait;
use crate::{
    CredentialErrorReport, CredentialId, CredentialLease, CredentialLeaseRelease,
    CredentialLeaseRequest,
};

/// Error returned by a credential lease client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialLeaseClientError {
    /// The host rejected the lease request or report.
    #[error("credential lease request rejected: {reason}")]
    Rejected {
        /// Redaction-safe reason for the rejection.
        reason: String,
    },
    /// The host credential lease service is unavailable.
    #[error("credential lease service unavailable: {reason}")]
    Unavailable {
        /// Redaction-safe reason for the unavailable service.
        reason: String,
    },
    /// The connector provided an invalid lease token or request shape.
    #[error("invalid credential lease request: {reason}")]
    Invalid {
        /// Redaction-safe validation reason.
        reason: String,
    },
}

impl CredentialLeaseClientError {
    /// Build a rejected lease error.
    #[must_use]
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::Rejected {
            reason: reason.into(),
        }
    }

    /// Build an unavailable lease service error.
    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    /// Build an invalid lease request error.
    #[must_use]
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::Invalid {
            reason: reason.into(),
        }
    }
}

/// Host-facing credential lease operations used by connector SDK code.
#[async_trait]
pub trait CredentialLeaseClient: Send + Sync {
    /// Acquire a credential lease for an existing credential reference.
    async fn get_credential_lease(
        &self,
        cx: &fcp_async_core::Cx,
        request: CredentialLeaseRequest,
    ) -> Result<CredentialLease, CredentialLeaseClientError>;

    /// Release a previously granted credential lease.
    async fn release_credential_lease(
        &self,
        cx: &fcp_async_core::Cx,
        release: CredentialLeaseRelease,
    ) -> Result<(), CredentialLeaseClientError>;

    /// Report a credential-scoped failure against a lease.
    async fn report_credential_error(
        &self,
        cx: &fcp_async_core::Cx,
        report: CredentialErrorReport,
    ) -> Result<(), CredentialLeaseClientError>;
}

/// Extension methods that make credential leases feel native on `Cx`.
#[async_trait]
pub trait CredentialLeaseCxExt {
    /// Acquire a credential lease for an existing credential reference.
    async fn get_credential_lease<C>(
        &self,
        client: &C,
        credential_id: CredentialId,
    ) -> Result<CredentialLease, CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized;

    /// Acquire a credential lease using a fully specified request.
    async fn get_credential_lease_with<C>(
        &self,
        client: &C,
        request: CredentialLeaseRequest,
    ) -> Result<CredentialLease, CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized;

    /// Release a previously granted credential lease.
    async fn release_credential_lease<C>(
        &self,
        client: &C,
        release: CredentialLeaseRelease,
    ) -> Result<(), CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized;

    /// Report a typed credential error against a lease.
    async fn report_credential_error<C>(
        &self,
        client: &C,
        report: CredentialErrorReport,
    ) -> Result<(), CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized;
}

#[async_trait]
impl CredentialLeaseCxExt for fcp_async_core::Cx {
    async fn get_credential_lease<C>(
        &self,
        client: &C,
        credential_id: CredentialId,
    ) -> Result<CredentialLease, CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized,
    {
        self.get_credential_lease_with(client, CredentialLeaseRequest::new(credential_id))
            .await
    }

    async fn get_credential_lease_with<C>(
        &self,
        client: &C,
        request: CredentialLeaseRequest,
    ) -> Result<CredentialLease, CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized,
    {
        CredentialLeaseClient::get_credential_lease(client, self, request).await
    }

    async fn release_credential_lease<C>(
        &self,
        client: &C,
        release: CredentialLeaseRelease,
    ) -> Result<(), CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized,
    {
        CredentialLeaseClient::release_credential_lease(client, self, release).await
    }

    async fn report_credential_error<C>(
        &self,
        client: &C,
        report: CredentialErrorReport,
    ) -> Result<(), CredentialLeaseClientError>
    where
        C: CredentialLeaseClient + ?Sized,
    {
        CredentialLeaseClient::report_credential_error(client, self, report).await
    }
}

impl fmt::Debug for dyn CredentialLeaseClient + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialLeaseClient(..)")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use crate::{
        CredentialErrorKind, CredentialLeaseCxExt, LeaseToken,
        credentials::{CredentialLeaseClient, CredentialLeaseClientError},
    };

    use super::*;

    #[derive(Debug, Default)]
    struct RecordingCredentialLeaseClient {
        requests: Mutex<Vec<CredentialLeaseRequest>>,
        releases: Mutex<Vec<CredentialLeaseRelease>>,
        reports: Mutex<Vec<CredentialErrorReport>>,
    }

    #[async_trait]
    impl CredentialLeaseClient for RecordingCredentialLeaseClient {
        async fn get_credential_lease(
            &self,
            _cx: &fcp_async_core::Cx,
            request: CredentialLeaseRequest,
        ) -> Result<CredentialLease, CredentialLeaseClientError> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(CredentialLease::new(
                request.credential_id,
                lease_token("lease:credential:sdk-test"),
            )
            .with_provider(request.provider.unwrap_or_else(|| "default".to_string())))
        }

        async fn release_credential_lease(
            &self,
            _cx: &fcp_async_core::Cx,
            release: CredentialLeaseRelease,
        ) -> Result<(), CredentialLeaseClientError> {
            self.releases.lock().unwrap().push(release);
            Ok(())
        }

        async fn report_credential_error(
            &self,
            _cx: &fcp_async_core::Cx,
            report: CredentialErrorReport,
        ) -> Result<(), CredentialLeaseClientError> {
            self.reports.lock().unwrap().push(report);
            Ok(())
        }
    }

    fn credential_id() -> CredentialId {
        CredentialId::parse("11111111-1111-1111-1111-111111111111").unwrap()
    }

    fn lease_token(raw: &str) -> LeaseToken {
        LeaseToken::new(raw).unwrap()
    }

    #[test]
    fn cx_extension_acquires_releases_and_reports_credential_lease() {
        let cx = fcp_async_core::Cx::for_testing();
        let client = RecordingCredentialLeaseClient::default();
        let credential_id = credential_id();

        let lease = fcp_async_core::runtime::block_on_sync(
            cx.get_credential_lease_with(
                &client,
                CredentialLeaseRequest::new(credential_id)
                    .with_provider("openai")
                    .with_operation("chat.completions"),
            ),
        )
        .unwrap()
        .unwrap();

        assert_eq!(lease.credential_id, credential_id);
        assert_eq!(lease.provider.as_deref(), Some("openai"));
        {
            let requests = client.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].operation.as_deref(), Some("chat.completions"));
            drop(requests);
        }

        fcp_async_core::runtime::block_on_sync(
            cx.release_credential_lease(&client, lease.release_request()),
        )
        .unwrap()
        .unwrap();

        let report = CredentialErrorReport::new(
            lease.credential_id,
            lease.lease_token,
            CredentialErrorKind::RateLimited,
        )
        .with_retry_after_seconds(15);
        fcp_async_core::runtime::block_on_sync(cx.report_credential_error(&client, report.clone()))
            .unwrap()
            .unwrap();

        assert_eq!(client.releases.lock().unwrap().len(), 1);
        assert_eq!(client.reports.lock().unwrap().as_slice(), &[report]);
    }

    #[test]
    fn cx_extension_short_form_builds_default_request() {
        let cx = fcp_async_core::Cx::for_testing();
        let client = RecordingCredentialLeaseClient::default();

        let lease = fcp_async_core::runtime::block_on_sync(
            cx.get_credential_lease(&client, credential_id()),
        )
        .unwrap()
        .unwrap();

        assert_eq!(lease.provider.as_deref(), Some("default"));
        let requests = client.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].provider.is_none());
        assert!(requests[0].operation.is_none());
        drop(requests);
    }

    #[test]
    fn credential_lease_client_error_messages_are_redaction_safe() {
        let error = CredentialLeaseClientError::rejected("pool exhausted");

        let debug = format!("{error:?}");
        let display = error.to_string();

        assert!(debug.contains("pool exhausted"));
        assert!(display.contains("pool exhausted"));
        assert!(!debug.contains("api_key"));
        assert!(!display.contains("api_key"));
        assert!(!debug.contains("sk-"));
        assert!(!display.contains("sk-"));
    }
}
