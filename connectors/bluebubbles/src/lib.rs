//! Dedicated `BlueBubbles` connector wrapper.
//!
//! This reuses the existing `BlueBubbles`-backed `iMessage` implementation while
//! exposing a connector identity and manifest that are explicit about the
//! bridge surface itself.

#![forbid(unsafe_code)]

use fcp_imessage::BlueBubblesConnector;

pub const CONNECTOR_ID: &str = "fcp.bluebubbles";
const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[must_use]
pub fn new_connector() -> BlueBubblesConnector {
    BlueBubblesConnector::with_connector_metadata(CONNECTOR_ID, MANIFEST_TOML)
}

pub use fcp_imessage::BlueBubblesConnector as SharedBlueBubblesConnector;

#[cfg(test)]
mod tests {
    use fcp_core::FcpConnector;

    use super::*;

    #[test]
    fn wrapper_uses_dedicated_connector_id() {
        let connector = new_connector();
        assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    }

    #[test]
    fn wrapper_exposes_existing_operation_catalog() {
        let connector = new_connector();
        let introspection = connector.introspect();
        assert!(
            introspection
                .operations
                .iter()
                .any(|operation| operation.id.as_str() == "imessage.send_message")
        );
    }
}
