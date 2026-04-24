//! Cross-crate conformance tests for `fcp-sandbox` WASI isolation invariants.
//!
//! These tests pin the public Preview2/WASI boundary that connector runtimes
//! must preserve:
//! - preopened directories enforce read-only vs writable permissions
//! - path traversal cannot escape a writable mount
//! - strict/mediated profiles fail closed for raw socket hostcalls
//! - deterministic hostcalls are reset per store/invocation

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use fcp_manifest::NetworkConstraints;
use fcp_sandbox::{WasiConfig, WasiHostState, WasiRuntime};
use wasmtime::{Store, component::Resource};
use wasmtime_wasi::{
    clocks::WasiClocksView,
    filesystem::WasiFilesystemView,
    p2::bindings::{
        clocks::{monotonic_clock, wall_clock},
        filesystem::{preopens, types},
        random::{insecure_seed, random},
        sockets::{instance_network, ip_name_lookup},
    },
    random::WasiRandomView,
    sockets::{SocketAddrUse, WasiSocketsView},
};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn open_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["*".to_string()],
        port_allow: vec![80, 443],
        ip_allow: vec![],
        cidr_deny: vec![],
        deny_localhost: false,
        deny_private_ranges: false,
        deny_tailnet_ranges: false,
        require_sni: false,
        spki_pins: vec![],
        deny_ip_literals: false,
        require_host_canonicalization: false,
        dns_max_ips: 16,
        max_redirects: 5,
        connect_timeout_ms: 10_000,
        total_timeout_ms: 60_000,
        max_response_bytes: 10 * 1024 * 1024,
    }
}

fn mediated_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["api.example.com".to_string()],
        port_allow: vec![443],
        ip_allow: vec![],
        cidr_deny: vec![
            "127.0.0.0/8".to_string(),
            "10.0.0.0/8".to_string(),
            "100.64.0.0/10".to_string(),
        ],
        deny_localhost: true,
        deny_private_ranges: true,
        deny_tailnet_ranges: true,
        require_sni: true,
        spki_pins: vec![],
        deny_ip_literals: true,
        require_host_canonicalization: true,
        dns_max_ips: 16,
        max_redirects: 5,
        connect_timeout_ms: 10_000,
        total_timeout_ms: 60_000,
        max_response_bytes: 10 * 1024 * 1024,
    }
}

fn preopen_descriptor(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
) -> Resource<types::Descriptor> {
    let mut filesystem = store.data_mut().filesystem();
    preopens::Host::get_directories(&mut filesystem)
        .unwrap()
        .into_iter()
        .find(|(_, path)| path == guest_path)
        .map(|(descriptor, _)| descriptor)
        .unwrap()
}

async fn read_preopened_file(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
    relative_path: &str,
) -> (Vec<u8>, bool) {
    let descriptor = preopen_descriptor(store, guest_path);
    let mut filesystem = store.data_mut().filesystem();
    let file_descriptor = types::HostDescriptor::open_at(
        &mut filesystem,
        descriptor,
        types::PathFlags::empty(),
        relative_path.to_string(),
        types::OpenFlags::empty(),
        types::DescriptorFlags::READ,
    )
    .await
    .unwrap();

    types::HostDescriptor::read(&mut filesystem, file_descriptor, 64, 0)
        .await
        .unwrap()
}

async fn open_preopened_for_write_error(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
    relative_path: &str,
) -> String {
    let descriptor = preopen_descriptor(store, guest_path);
    let mut filesystem = store.data_mut().filesystem();
    types::HostDescriptor::open_at(
        &mut filesystem,
        descriptor,
        types::PathFlags::empty(),
        relative_path.to_string(),
        types::OpenFlags::CREATE,
        types::DescriptorFlags::WRITE,
    )
    .await
    .unwrap_err()
    .to_string()
}

async fn write_preopened_file(
    store: &mut Store<WasiHostState>,
    guest_path: &str,
    relative_path: &str,
    bytes: Vec<u8>,
) -> u64 {
    let descriptor = preopen_descriptor(store, guest_path);
    let mut filesystem = store.data_mut().filesystem();
    let file_descriptor = types::HostDescriptor::open_at(
        &mut filesystem,
        descriptor,
        types::PathFlags::empty(),
        relative_path.to_string(),
        types::OpenFlags::CREATE | types::OpenFlags::TRUNCATE,
        types::DescriptorFlags::WRITE,
    )
    .await
    .unwrap();

    types::HostDescriptor::write(&mut filesystem, file_descriptor, bytes, 0)
        .await
        .unwrap()
}

async fn assert_tcp_connect_denied(
    store: &mut Store<WasiHostState>,
    addr: SocketAddr,
    context: &str,
) {
    let mut sockets = store.data_mut().sockets();
    let network = instance_network::Host::instance_network(&mut sockets).unwrap();
    let denied = sockets
        .table
        .get(&network)
        .unwrap()
        .check_socket_addr(addr, SocketAddrUse::TcpConnect)
        .await;
    assert!(
        denied.is_err(),
        "{context}: raw TCP hostcall unexpectedly allowed for {addr}"
    );
}

#[fcp_async_core::runtime::test]
async fn wasi_preopened_filesystem_conformance_blocks_writes_and_escape() {
    let readonly_dir = unique_temp_dir("fcp-conformance-sandbox-readonly");
    let writable_dir = unique_temp_dir("fcp-conformance-sandbox-writable");
    std::fs::write(readonly_dir.join("input.txt"), b"readonly-ok").unwrap();

    let runtime = WasiRuntime::new(WasiConfig {
        readonly_paths: vec![readonly_dir.clone()],
        writable_paths: vec![writable_dir.clone()],
        ..WasiConfig::default()
    })
    .unwrap();
    let mut store = runtime.create_store().unwrap();

    let readonly_guest_path = readonly_dir.display().to_string();
    let writable_guest_path = writable_dir.display().to_string();

    let (bytes, eof) = read_preopened_file(&mut store, &readonly_guest_path, "input.txt").await;
    assert_eq!(bytes, b"readonly-ok");
    assert!(!eof);

    let readonly_err =
        open_preopened_for_write_error(&mut store, &readonly_guest_path, "blocked.txt").await;
    assert!(
        readonly_err.contains("not-permitted"),
        "readonly preopen must reject writes: {readonly_err}"
    );

    let written = write_preopened_file(
        &mut store,
        &writable_guest_path,
        "output.txt",
        b"written-ok".to_vec(),
    )
    .await;
    assert_eq!(written, 10);
    assert_eq!(
        std::fs::read(writable_dir.join("output.txt")).unwrap(),
        b"written-ok"
    );

    let escape_err =
        open_preopened_for_write_error(&mut store, &writable_guest_path, "../escape.txt").await;
    assert!(
        escape_err.contains("not-permitted"),
        "path traversal must stay denied: {escape_err}"
    );
}

#[cfg(unix)]
#[test]
fn wasi_symlinked_preopens_fail_closed() {
    use std::os::unix::fs::symlink;

    let root = unique_temp_dir("fcp-conformance-sandbox-symlink-root");
    let readonly_target = unique_temp_dir("fcp-conformance-sandbox-symlink-readonly-target");
    let writable_target = unique_temp_dir("fcp-conformance-sandbox-symlink-writable-target");

    let readonly_link = root.join("readonly-link");
    let writable_link = root.join("writable-link");
    symlink(&readonly_target, &readonly_link).unwrap();
    symlink(&writable_target, &writable_link).unwrap();

    let readonly_declared = readonly_link.join("mounted-readonly");
    std::fs::create_dir_all(&readonly_target.join("mounted-readonly")).unwrap();

    let readonly_runtime = WasiRuntime::new(WasiConfig {
        readonly_paths: vec![readonly_declared.clone()],
        ..WasiConfig::default()
    })
    .unwrap();
    let readonly_err = readonly_runtime.create_store().unwrap_err().to_string();
    assert!(
        readonly_err.contains("symlinked ancestor"),
        "readonly symlinked preopen must fail closed: {readonly_err}"
    );

    let writable_declared = writable_link.join("mounted-writable");
    let writable_runtime = WasiRuntime::new(WasiConfig {
        writable_paths: vec![writable_declared.clone()],
        ..WasiConfig::default()
    })
    .unwrap();
    let writable_err = writable_runtime.create_store().unwrap_err().to_string();
    assert!(
        writable_err.contains("symlinked ancestor"),
        "writable symlinked preopen must fail closed: {writable_err}"
    );
}

#[test]
fn wasi_file_preopens_fail_closed() {
    let file_root = unique_temp_dir("fcp-conformance-sandbox-file-preopen");
    let readonly_file = file_root.join("readonly.txt");
    let writable_file = file_root.join("writable.txt");
    std::fs::write(&readonly_file, b"readonly").unwrap();
    std::fs::write(&writable_file, b"writable").unwrap();

    let readonly_runtime = WasiRuntime::new(WasiConfig {
        readonly_paths: vec![readonly_file.clone()],
        ..WasiConfig::default()
    })
    .unwrap();
    let readonly_err = readonly_runtime.create_store().unwrap_err().to_string();
    assert!(
        readonly_err.contains("must be directories"),
        "readonly file preopen must fail closed: {readonly_err}"
    );

    let writable_runtime = WasiRuntime::new(WasiConfig {
        writable_paths: vec![writable_file.clone()],
        ..WasiConfig::default()
    })
    .unwrap();
    let writable_err = writable_runtime.create_store().unwrap_err().to_string();
    assert!(
        writable_err.contains("must be directories"),
        "writable file preopen must fail closed: {writable_err}"
    );
}

#[test]
fn wasi_http_egress_invalid_urls_fail_closed() {
    let mut non_http_constraints = open_constraints();
    non_http_constraints.host_allow = vec!["*".to_string()];
    non_http_constraints.port_allow = vec![21];

    let non_http_runtime =
        WasiRuntime::new(WasiConfig::default().with_network_constraints(non_http_constraints))
            .unwrap();
    let non_http_store = non_http_runtime.create_store().unwrap();
    let non_http_err = non_http_store
        .data()
        .validate_http_access("ftp://files.example.com/data", "GET")
        .unwrap_err()
        .to_string();
    assert!(
        non_http_err.contains("http or https"),
        "non-http scheme must fail closed before port policy can allow it: {non_http_err}"
    );

    let credential_runtime =
        WasiRuntime::new(WasiConfig::default().with_network_constraints(mediated_constraints()))
            .unwrap();
    let credential_store = credential_runtime.create_store().unwrap();
    let credential_err = credential_store
        .data()
        .validate_http_access("https://user:pass@api.example.com/data", "GET")
        .unwrap_err()
        .to_string();
    assert!(
        credential_err.contains("embedded credentials"),
        "HTTP egress URLs with userinfo must fail closed: {credential_err}"
    );
}

#[fcp_async_core::runtime::test]
async fn wasi_raw_socket_hostcalls_fail_closed_when_mediation_is_required() {
    let default_runtime = WasiRuntime::new(WasiConfig::default()).unwrap();
    let mut default_store = default_runtime.create_store().unwrap();
    {
        let mut sockets = default_store.data_mut().sockets();
        let network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let err =
            ip_name_lookup::Host::resolve_addresses(&mut sockets, network, "example.com".into())
                .unwrap_err();
        assert!(err.to_string().contains("resolver-failure"));
    }

    let strict_runtime =
        WasiRuntime::new(WasiConfig::default().with_network_constraints(open_constraints()))
            .unwrap();
    let mut strict_store = strict_runtime.create_store().unwrap();
    {
        let mut sockets = strict_store.data_mut().sockets();
        let network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let err =
            ip_name_lookup::Host::resolve_addresses(&mut sockets, network, "example.com".into())
                .unwrap_err();
        assert!(err.to_string().contains("resolver-failure"));
    }
    assert_tcp_connect_denied(
        &mut strict_store,
        SocketAddr::from(([93, 184, 216, 34], 443)),
        "strict store must deny policy-shaped public TCP endpoints when mediation is required",
    )
    .await;
    assert_tcp_connect_denied(
        &mut strict_store,
        SocketAddr::from(([1, 1, 1, 1], 80)),
        "strict store must deny generic public TCP endpoints when mediation is required",
    )
    .await;

    let permissive_runtime = WasiRuntime::new(WasiConfig {
        block_direct_network: false,
        ..WasiConfig::default().with_network_constraints(open_constraints())
    })
    .unwrap();
    let mut permissive_store = permissive_runtime.create_store().unwrap();
    {
        let mut sockets = permissive_store.data_mut().sockets();
        let allowed_network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let allowed = sockets
            .table
            .get(&allowed_network)
            .unwrap()
            .check_socket_addr(
                SocketAddr::from(([93, 184, 216, 34], 443)),
                SocketAddrUse::TcpConnect,
            )
            .await;
        assert!(allowed.is_ok());

        let blocked_port_network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let blocked_port = sockets
            .table
            .get(&blocked_port_network)
            .unwrap()
            .check_socket_addr(
                SocketAddr::from(([93, 184, 216, 34], 8443)),
                SocketAddrUse::TcpConnect,
            )
            .await;
        assert!(blocked_port.is_err());
    }

    let mediated_runtime =
        WasiRuntime::new(WasiConfig::default().with_network_constraints(mediated_constraints()))
            .unwrap();
    let mut mediated_store = mediated_runtime.create_store().unwrap();
    {
        let mut sockets = mediated_store.data_mut().sockets();
        let network = instance_network::Host::instance_network(&mut sockets).unwrap();
        let err = ip_name_lookup::Host::resolve_addresses(
            &mut sockets,
            network,
            "api.example.com".into(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("resolver-failure"),
            "strict mediated profiles must still disable raw DNS hostcalls"
        );
    }
    assert_tcp_connect_denied(
        &mut mediated_store,
        SocketAddr::from(([93, 184, 216, 34], 443)),
        "mediated store must deny policy-shaped TCP endpoints until Network Guard mediation runs",
    )
    .await;
    assert_tcp_connect_denied(
        &mut mediated_store,
        SocketAddr::from(([93, 184, 216, 34], 8443)),
        "mediated store must deny generic public TCP endpoints until Network Guard mediation runs",
    )
    .await;
}

#[test]
fn wasi_deterministic_hostcalls_reset_per_store() {
    let runtime =
        WasiRuntime::new(WasiConfig::default().with_deterministic_mode(1_700_000_000, 42)).unwrap();
    let mut store_a = runtime.create_store().unwrap();
    let mut store_b = runtime.create_store().unwrap();

    let wall_a = {
        let mut clocks = store_a.data_mut().clocks();
        wall_clock::Host::now(&mut clocks).unwrap()
    };
    let wall_b = {
        let mut clocks = store_b.data_mut().clocks();
        wall_clock::Host::now(&mut clocks).unwrap()
    };
    assert_eq!(wall_a.seconds, 1_700_000_000);
    assert_eq!(wall_a.seconds, wall_b.seconds);
    assert_eq!(wall_a.nanoseconds, wall_b.nanoseconds);

    let mono_a_1 = {
        let mut clocks = store_a.data_mut().clocks();
        monotonic_clock::Host::now(&mut clocks).unwrap()
    };
    let mono_a_2 = {
        let mut clocks = store_a.data_mut().clocks();
        monotonic_clock::Host::now(&mut clocks).unwrap()
    };
    let mono_b_1 = {
        let mut clocks = store_b.data_mut().clocks();
        monotonic_clock::Host::now(&mut clocks).unwrap()
    };
    assert_eq!(mono_a_1, 0);
    assert_eq!(mono_a_2, 1_000_000);
    assert_eq!(mono_b_1, 0);

    let random_a = random::Host::get_random_bytes(store_a.data_mut().random(), 16).unwrap();
    let random_b = random::Host::get_random_bytes(store_b.data_mut().random(), 16).unwrap();
    assert_eq!(random_a, random_b);

    let seed = insecure_seed::Host::insecure_seed(store_a.data_mut().random()).unwrap();
    assert_eq!(seed, (42, 42));
}
