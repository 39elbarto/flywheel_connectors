//! Host-facing policy wrapper for snapshot resume handshakes.
//!
//! `fcp-store` owns the canonical wire shapes because they are content-addressed
//! store objects. The host layer re-exports those shapes and adds the local
//! admission policy used before a source lease may be released.

pub use fcp_store::{
    CapabilityAvailability, DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS, RehydrationStatus,
    ResumeHandshakeError, ResumeHandshakeMessage, ResumeHandshakeRequest,
    ResumeHandshakeTranscript, ResumeReplayOp, ResumeRollbackPlan, ResumeRollbackReason,
    ResumeSnapshotSymbol, ResumeSourceLeaseRelease, ResumeTargetAck, ResumeTargetComplete,
    SnapshotFreshness,
};

/// Host-side bounds for accepting a resume transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostResumeHandshakePolicy {
    /// Maximum end-to-end handshake duration in milliseconds.
    pub timeout_ms: u64,
}

impl Default for HostResumeHandshakePolicy {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS,
        }
    }
}

impl HostResumeHandshakePolicy {
    /// Create a host policy with the given timeout.
    #[must_use]
    pub const fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Validate that the target completed rehydration before the source lease
    /// release was accepted by the host.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError`] if the transcript violates the
    /// canonical resume protocol or exceeds this host policy timeout.
    pub fn validate_source_release(
        &self,
        transcript: &ResumeHandshakeTranscript,
    ) -> Result<(), ResumeHandshakeError> {
        transcript.validate_success()?;
        let elapsed_ms = transcript
            .source_release
            .released_at_ms
            .saturating_sub(transcript.request.started_at_ms);
        let timeout_ms = if self.timeout_ms == 0 {
            DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS
        } else {
            self.timeout_ms
        };
        if elapsed_ms > timeout_ms {
            return Err(ResumeHandshakeError::Timeout {
                elapsed_ms,
                timeout_ms,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_policy_defaults_to_resume_timeout() {
        assert_eq!(
            HostResumeHandshakePolicy::default().timeout_ms,
            DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS
        );
    }
}
