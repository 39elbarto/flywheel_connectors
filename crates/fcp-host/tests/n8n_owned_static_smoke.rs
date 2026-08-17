#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use fcp_host::{OwnedInvocationConfig, OwnedInvocationHandle};
use fcp_sandbox::ProcessSpec;
use serde_json::json;

const BINARY_ENV: &str = "FCP_N8N_OWNED_SMOKE_BINARY";

fn run<T>(future: impl std::future::Future<Output = T>) -> T {
    fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
}

#[test]
#[ignore = "requires an explicit immutable fcp-n8n release artifact"]
fn static_n8n_connector_introspects_under_owned_network_filter() {
    let binary = PathBuf::from(
        std::env::var_os(BINARY_ENV)
            .expect("FCP_N8N_OWNED_SMOKE_BINARY must name the static fcp-n8n binary"),
    );
    let binary = std::fs::canonicalize(binary).expect("canonical fcp-n8n binary");
    let digest = blake3::hash(&std::fs::read(&binary).expect("fcp-n8n bytes"))
        .to_hex()
        .to_string();
    let fixed_env = BTreeMap::from([
        (
            OsString::from("FCP_HOST_EGRESS_TRANSPORT"),
            OsString::from("inherited-fd-v1"),
        ),
        (
            OsString::from("FCP_HOST_EGRESS_AUTH_TOKEN"),
            OsString::from("owned-static-smoke-token"),
        ),
    ]);
    let spec = ProcessSpec {
        launcher_path: binary.clone(),
        launcher_digest: digest.clone(),
        runtime_executable: binary,
        expected_runtime_executable_digest: digest,
        fixed_args: Vec::new(),
        fixed_env,
        network_disabled: true,
    };
    let (host_endpoint, child_endpoint) = UnixStream::pair().expect("host egress socketpair");
    let mut handle = run(OwnedInvocationHandle::launch(
        spec,
        child_endpoint,
        OwnedInvocationConfig::default(),
    ))
    .expect("owned fcp-n8n launch");

    let response = run(handle.request("introspect", json!({}))).expect("introspect response");
    assert!(
        response.get("error").is_none(),
        "introspect returned an error"
    );
    assert_eq!(response["result"]["connector_id"], "fcp.n8n");
    assert_eq!(
        response["result"]["operations"].as_array().map(Vec::len),
        Some(10)
    );

    drop(host_endpoint);
    let report = run(handle.terminate()).expect("owned fcp-n8n teardown");
    assert!(report.group_absent);
    assert!(report.reaped);
}
