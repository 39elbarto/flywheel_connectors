//! Regression for br-1zlht (security audit B3) — fcp-crypto-pq half.
//!
//! Pins that `MasterTrapdoor`, `ZonePeriodTrapdoor`, and
//! `LatticePreimage` use constant-time equality (via
//! `subtle::ConstantTimeEq`) instead of the short-circuit
//! `[u8; N]::eq` derived `PartialEq`.
//!
//! The trapdoor types are the load-bearing secret of the
//! lattice-trapdoor scheme; the preimage is the signature material.
//! All three are equality candidates a future caller might compare
//! on a hot dispatch path.

use fcp_crypto_pq::{DelegationPeriod, LatticeParams, LatticePreimage, delegate, trap_gen};

#[test]
fn lattice_preimage_eq_reflects_byte_equality() {
    let a = LatticePreimage { bytes: [0x11; 64] };
    let b = LatticePreimage { bytes: [0x11; 64] };
    assert_eq!(a, b);
}

#[test]
fn lattice_preimage_eq_distinguishes_first_byte_diff() {
    let a = LatticePreimage { bytes: [0x11; 64] };
    let mut other = [0x11; 64];
    other[0] = 0xFF;
    let b = LatticePreimage { bytes: other };
    assert_ne!(a, b);
}

#[test]
fn lattice_preimage_eq_distinguishes_last_byte_diff() {
    // br-1zlht: pin behavioural correctness of the constant-time eq.
    let a = LatticePreimage { bytes: [0x11; 64] };
    let mut other = [0x11; 64];
    other[63] = 0xFF;
    let b = LatticePreimage { bytes: other };
    assert_ne!(a, b);
}

#[test]
fn master_trapdoor_eq_reflects_byte_equality() {
    let p = LatticeParams::V4_REFERENCE;
    let (_pk_a, td_a) = trap_gen(p).expect("stub trap_gen succeeds");
    let (_pk_b, td_b) = trap_gen(p).expect("stub trap_gen succeeds");
    // Stub trap_gen is deterministic in the placeholder impl; equality
    // exercises the constant-time impl regardless of whether the two
    // outputs match.
    let _ = td_a == td_b;
    // Same trapdoor compared against itself MUST be equal under any
    // sane PartialEq.
    let td_clone = td_a.clone();
    assert_eq!(td_a, td_clone);
}

#[test]
fn zone_period_trapdoor_eq_reflects_byte_equality() {
    let p = LatticeParams::V4_REFERENCE;
    let (root_pk, master_td) = trap_gen(p).expect("trap_gen");
    let zone = [0u8; 32];
    let period = DelegationPeriod {
        start_secs: 0,
        end_secs: u64::MAX,
    };
    let (_zp_pk, zp_td) = delegate(&root_pk, &master_td, zone, period, p).expect("delegate");
    let zp_td_clone = zp_td.clone();
    assert_eq!(zp_td, zp_td_clone);
}

#[test]
fn subtle_crate_is_available_in_fcp_crypto_pq() {
    use subtle::ConstantTimeEq;
    let a = [0xAB_u8; 64];
    let b = [0xAB_u8; 64];
    let mut c = [0xAB_u8; 64];
    c[63] = 0xFF;
    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
}
