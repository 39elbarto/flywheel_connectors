#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use thiserror::Error;

const FORBIDDEN_REPLAY_MARKERS: &[&str] = &[
    "mesh-harness-node-",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "secret",
    "token",
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RedactedReplayBundleError {
    #[error("replay artifact `{context}` contains forbidden marker `{marker}`")]
    RedactionLeak {
        context: String,
        marker: &'static str,
    },
}

pub fn assert_redaction_safe_str(
    context: &str,
    body: &str,
) -> Result<(), RedactedReplayBundleError> {
    let normalized = body.to_ascii_lowercase();
    if let Some(marker) = FORBIDDEN_REPLAY_MARKERS
        .iter()
        .copied()
        .find(|marker| normalized.contains(marker))
    {
        return Err(RedactedReplayBundleError::RedactionLeak {
            context: context.to_string(),
            marker,
        });
    }
    Ok(())
}
