use fcp_prelude::{CredentialId, FcpError, FcpResult};
use serde::{Deserialize, Serialize};

/// Auth selection provided by the connector manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EmailAuthSelection {
    #[serde(rename = "raw")]
    Raw { password: String },
    #[serde(rename = "credential_id")]
    CredentialId { credential_id: String },
}

impl EmailAuthSelection {
    pub fn materialize(&self) -> FcpResult<EmailMaterializedAuth> {
        match self {
            Self::Raw { password } => Ok(EmailMaterializedAuth::RawPassword(password.clone())),
            Self::CredentialId { credential_id } => {
                let id =
                    CredentialId::parse(credential_id).map_err(|_| FcpError::InvalidRequest {
                        code: 1003,
                        message: "credential_id must be a valid UUID".into(),
                    })?;
                Ok(EmailMaterializedAuth::CredentialId(id))
            }
        }
    }
}

/// Runtime auth output.
#[derive(Clone, Eq, PartialEq)]
pub enum EmailMaterializedAuth {
    RawPassword(String),
    CredentialId(CredentialId),
}

impl std::fmt::Debug for EmailMaterializedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawPassword(_) => f.debug_tuple("RawPassword").field(&"[REDACTED]").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}
