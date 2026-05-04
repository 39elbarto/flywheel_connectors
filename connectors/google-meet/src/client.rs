//! Google Meet API client foundation.

use std::fmt;

use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};

use crate::error::{GoogleMeetError, GoogleMeetResult};

/// Default Google Meet API base URL.
pub const DEFAULT_BASE_URL: &str = "https://meet.googleapis.com/v2";

/// Render a redacted auth label suitable for logs and diagnostics.
#[must_use]
pub fn google_auth_redacted_label(auth: &GoogleMaterializedAuth) -> String {
    auth.credential_id().map_or_else(
        || "google_auth:bearer:redacted".to_string(),
        |credential_id| format!("google_auth:credential_id:{credential_id}"),
    )
}

/// Whether this auth mode requires host-side credential injection.
#[must_use]
pub const fn google_auth_is_secretless(auth: &GoogleMaterializedAuth) -> bool {
    auth.credential_id().is_some()
}

/// Minimal client state shared by later Meet API operation Beads.
pub struct GoogleMeetClient {
    auth: GoogleMaterializedAuth,
    base_url: String,
}

impl fmt::Debug for GoogleMeetClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleMeetClient")
            .field("auth", &google_auth_redacted_label(&self.auth))
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl GoogleMeetClient {
    /// Create a client with an `OAuth2` access token.
    pub fn new(token: impl Into<String>) -> GoogleMeetResult<Self> {
        Self::new_with_auth(GoogleMaterializedAuth::BearerToken {
            access_token: token.into(),
            source: GoogleAuthSourceKind::AccessToken,
            granted_scopes: Vec::new(),
            quota_project_id: None,
        })
    }

    /// Create a client with shared Google auth material.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> GoogleMeetResult<Self> {
        Ok(Self {
            auth,
            base_url: DEFAULT_BASE_URL.to_string(),
        })
    }

    /// Set the base URL for tests or approved host routing.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Base URL used by future Meet API calls.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Redacted auth label for diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        google_auth_redacted_label(&self.auth)
    }

    /// Whether this client is waiting on host credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        google_auth_is_secretless(&self.auth)
    }

    /// Placeholder shutdown hook for future supervised request/runtime state.
    pub const fn shutdown(&self) {}

    /// Foundation readiness deliberately avoids a fake network call.
    pub fn foundation_probe(&self) -> GoogleMeetResult<()> {
        if self.base_url.trim().is_empty() {
            Err(GoogleMeetError::InvalidConfig {
                message: "base_url must not be empty".to_string(),
            })
        } else {
            Ok(())
        }
    }
}
