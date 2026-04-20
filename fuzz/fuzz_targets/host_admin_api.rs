#![no_main]

use base64::Engine;
use fcp_host::{
    CapabilityTokenInspectRequest, CapabilityTokenVerifyRequest, ConnectorConfigApplyRequest,
    ConnectorInventoryMutationRequest, HostAdminStateStore, HostSimulateRequest,
    JournalQueryRequest, LifecycleTransitionRequest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    let _ = HostAdminStateStore::inspect_capability_token(&encoded);

    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(request) = serde_json::from_str::<CapabilityTokenInspectRequest>(json) {
        let _ = HostAdminStateStore::inspect_capability_token(&request.token_cbor_b64);
        let _ = serde_json::to_string(&request);
    }

    if let Ok(request) = serde_json::from_str::<CapabilityTokenVerifyRequest>(json) {
        let _ = HostAdminStateStore::inspect_capability_token(&request.token_cbor_b64);
        let _ = serde_json::to_string(&request);
    }

    if let Ok(request) = serde_json::from_str::<HostSimulateRequest>(json) {
        let _ = serde_json::to_string(&request);
    }

    if let Ok(request) = serde_json::from_str::<ConnectorConfigApplyRequest>(json) {
        let _ = serde_json::to_string(&request);
    }

    if let Ok(request) = serde_json::from_str::<ConnectorInventoryMutationRequest>(json) {
        let _ = serde_json::to_string(&request);
    }

    if let Ok(request) = serde_json::from_str::<LifecycleTransitionRequest>(json) {
        let _ = serde_json::to_string(&request);
    }

    if let Ok(request) = serde_json::from_str::<JournalQueryRequest>(json) {
        let _ = serde_json::to_string(&request);
    }
});
