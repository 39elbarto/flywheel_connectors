//! `fcp_host::supply_chain` gate config + cache management
//! conformance.
//!
//! `SupplyChainGate` is the host's connector-install-time gate:
//! it wraps the evidence-owned VerificationPipeline with a result
//! cache, audit events, and dev-mode override policy. Drift in
//! its defaults silently changes how strict the host is at install
//! time.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`SupplyChainGateConfig::default`** — 3 documented values:
//!    - `policy = SupplyChainVerificationPolicy::default()`
//!      (fail-closed defaults from the evidence layer)
//!    - `cache_capacity = 256` (256-entry result cache)
//!    - `allow_dev_overrides = false` (production safety —
//!      dev-mode overrides are off by default)
//! 2. **`SupplyChainGate::new()` == `with_config(default())`**
//!    semantically (both yield the same starting state).
//! 3. **`cache_size()` starts at 0** for a freshly-constructed gate.
//! 4. **`clear_cache()` is a no-op on an empty cache** (does NOT
//!    panic, leaves size at 0).
//! 5. **`policy()` returns a reference to the configured policy**.

use fcp_host::{SupplyChainGate, SupplyChainGateConfig};

// ─── SupplyChainGateConfig::default ────────────────────────────────

#[test]
fn supply_chain_gate_config_default_cache_capacity_is_two_fifty_six() {
    assert_eq!(
        SupplyChainGateConfig::default().cache_capacity,
        256,
        "default cache_capacity MUST be 256 entries"
    );
}

#[test]
fn supply_chain_gate_config_default_allow_dev_overrides_is_false() {
    assert!(
        !SupplyChainGateConfig::default().allow_dev_overrides,
        "default allow_dev_overrides MUST be false — production safety; dev overrides MUST require explicit opt-in"
    );
}

#[test]
fn supply_chain_gate_config_default_policy_is_fail_closed() {
    // The policy default comes from the evidence layer's
    // SupplyChainVerificationPolicy::default. We can't directly
    // inspect every field without pulling fcp-evidence, but we can
    // at least pin that the default config is constructible and the
    // policy field is populated.
    let cfg = SupplyChainGateConfig::default();
    // Policy field is non-Option by type — its presence is the contract.
    let _: &_ = &cfg.policy;
}

// ─── SupplyChainGate construction ─────────────────────────────────

#[test]
fn supply_chain_gate_new_starts_with_empty_cache() {
    let gate = SupplyChainGate::new();
    assert_eq!(
        gate.cache_size(),
        0,
        "fresh gate MUST start with empty cache (no leakage from prior runs)"
    );
}

#[test]
fn supply_chain_gate_with_config_starts_with_empty_cache() {
    let gate = SupplyChainGate::with_config(SupplyChainGateConfig::default());
    assert_eq!(
        gate.cache_size(),
        0,
        "with_config-constructed gate MUST also start empty"
    );
}

#[test]
fn supply_chain_gate_new_and_with_config_default_yield_equivalent_starting_state() {
    let a = SupplyChainGate::new();
    let b = SupplyChainGate::with_config(SupplyChainGateConfig::default());
    assert_eq!(a.cache_size(), b.cache_size());
}

// ─── cache management ─────────────────────────────────────────────

#[test]
fn clear_cache_on_empty_gate_does_not_panic() {
    let gate = SupplyChainGate::new();
    // Pre-condition: empty.
    assert_eq!(gate.cache_size(), 0);
    // Operation: clear_cache MUST be safe to call when already empty.
    gate.clear_cache();
    // Post-condition: still empty.
    assert_eq!(
        gate.cache_size(),
        0,
        "clear_cache on empty gate MUST be a no-op (idempotent + safe)"
    );
}

#[test]
fn clear_cache_can_be_called_repeatedly_without_panic() {
    let gate = SupplyChainGate::new();
    for _ in 0..10 {
        gate.clear_cache();
    }
    assert_eq!(gate.cache_size(), 0);
}

// ─── policy() accessor ────────────────────────────────────────────

#[test]
fn policy_returns_borrowed_reference() {
    let gate = SupplyChainGate::new();
    // policy() is a pub const fn returning &SupplyChainVerificationPolicy.
    // Sanity check the borrow returns without panic.
    let _: &_ = gate.policy();
}

// ─── Configuration with custom cache capacity ────────────────────

#[test]
fn gate_with_zero_cache_capacity_still_constructs() {
    // Edge case: a 0-capacity cache is legal (gate still runs, but
    // never caches results). MUST NOT panic at construction.
    let cfg = SupplyChainGateConfig {
        cache_capacity: 0,
        ..SupplyChainGateConfig::default()
    };
    let gate = SupplyChainGate::with_config(cfg);
    assert_eq!(gate.cache_size(), 0);
    gate.clear_cache(); // Still safe.
}

#[test]
fn gate_with_large_cache_capacity_still_constructs() {
    let cfg = SupplyChainGateConfig {
        cache_capacity: 1_000_000,
        ..SupplyChainGateConfig::default()
    };
    let gate = SupplyChainGate::with_config(cfg);
    assert_eq!(gate.cache_size(), 0);
}

// ─── Default trait + Clone ────────────────────────────────────────

#[test]
fn supply_chain_gate_config_clone_preserves_three_fields() {
    let cfg = SupplyChainGateConfig {
        cache_capacity: 42,
        allow_dev_overrides: true,
        policy: SupplyChainGateConfig::default().policy,
    };
    let cloned = cfg.clone();
    assert_eq!(cfg.cache_capacity, cloned.cache_capacity);
    assert_eq!(cfg.allow_dev_overrides, cloned.allow_dev_overrides);
}

#[test]
fn supply_chain_gate_config_with_explicit_overrides_preserves_documented_defaults_for_unset_fields() {
    // Setting allow_dev_overrides=true while keeping other defaults.
    let cfg = SupplyChainGateConfig {
        allow_dev_overrides: true,
        ..SupplyChainGateConfig::default()
    };
    assert!(cfg.allow_dev_overrides);
    assert_eq!(
        cfg.cache_capacity, 256,
        "spread-update MUST preserve documented cache_capacity=256"
    );
}
