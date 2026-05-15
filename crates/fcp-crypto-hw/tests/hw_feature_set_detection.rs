use fcp_crypto_hw::{DispatchTier, HwFeatureSet, build_function_table, detect, function_table};

#[test]
fn test_detect_does_not_crash_on_any_isa() {
    let features = detect();
    assert!(features.detected_feature_names().len() <= 10);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_x86_64_runner_reports_known_features() {
    let features = detect();
    assert!(
        features.has_aes_ni,
        "FCP x86_64 CI runners are expected to expose AES-NI"
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn test_aarch64_runner_reports_known_features() {
    let features = detect();
    assert!(
        features.has_aarch64_aes,
        "FCP aarch64 CI runners are expected to expose AES instructions"
    );
    assert!(
        features.has_aarch64_sha2,
        "FCP aarch64 CI runners are expected to expose SHA-2 instructions"
    );
}

#[test]
fn test_dispatch_table_populated_once() {
    let first = function_table();
    let second = function_table();
    assert!(std::ptr::eq(first, second));
    assert_eq!(first.blake3 as usize, second.blake3 as usize);
    assert_eq!(first.aes_gcm as usize, second.aes_gcm as usize);
    assert_eq!(first.ntt as usize, second.ntt as usize);
}

#[test]
fn test_function_pointer_safe_to_call() {
    let table = function_table();

    let hash = (table.blake3)(b"fcp-crypto-hw");
    assert_eq!(hash.len(), 32);

    let tag = (table.aes_gcm)(b"dispatch-probe");
    assert_eq!(tag.len(), 16);

    let score = (table.ntt)(&[1, -2, 3, -4]);
    assert_ne!(score, 0);
}

#[test]
fn test_unknown_feature_falls_back_to_portable() {
    let table = build_function_table(HwFeatureSet::all_false());
    assert_eq!(table.tier, DispatchTier::Portable);
    assert_eq!(
        (table.blake3)(b"fallback"),
        *blake3::hash(b"fallback").as_bytes()
    );
}
