//! `fcp_mesh::gossip` config + priority-gossip-policy + IBLT-decode-
//! error conformance.
//!
//! `mesh_gossip_summary_conformance.rs` already pins gossip summary
//! shape. This file pins three closely-related primitives:
//!
//! 1. **`GossipConfig` defaults + 6 documented constants** —
//!    every mesh node uses these as the gossip cadence and budget.
//! 2. **`PriorityGossipPolicy`** — `DirectPush` (default) /
//!    `PriorityInterval` / `Standard` — drives revocation push speed.
//! 3. **`IbltDecodeError`** — variant taxonomy and field carriage;
//!    operator log greps depend on the exact discriminator names.
//!
//! Properties pinned (NORMATIVE):
//!
//! - `DEFAULT_MAX_OBJECTS_PER_SUMMARY = 10_000`
//! - `DEFAULT_MAX_SYMBOLS_PER_SUMMARY = 100_000`
//! - `DEFAULT_SUMMARY_TTL_SECS = 300` (5 min)
//! - `DEFAULT_MAX_FUTURE_SKEW_SECS = 30`
//! - `DEFAULT_RECONCILIATION_BATCH_SIZE = 1000`
//! - `MAX_OBJECT_IDS_PER_REQUEST = 100`
//! - `GossipConfig::default` documented values:
//!   priority_gossip_interval_ms=100, max_revocation_push_peers=32,
//!   max_peer_states=4096
//! - `PriorityGossipPolicy::default == DirectPush` (revocations
//!   pushed immediately to all peers — drift would silently slow
//!   revocation propagation)
//! - 3 distinct PriorityGossipPolicy variants, Copy + serde
//! - `IbltDecodeError` 3 variants with documented payloads:
//!   `TooLarge { len, max }`, `InvalidEncoding`,
//!   `TooManyChanges { decoded, max }`
//! - `GossipStats` 3-field construction + Clone

use fcp_mesh::{
    DEFAULT_MAX_FUTURE_SKEW_SECS, DEFAULT_MAX_OBJECTS_PER_SUMMARY, DEFAULT_MAX_SYMBOLS_PER_SUMMARY,
    DEFAULT_RECONCILIATION_BATCH_SIZE, DEFAULT_SUMMARY_TTL_SECS, GossipConfig, GossipStats,
    IbltDecodeError, MAX_OBJECT_IDS_PER_REQUEST, PriorityGossipPolicy,
};

// ─── Documented constants ──────────────────────────────────────────

#[test]
fn default_max_objects_per_summary_is_ten_thousand() {
    assert_eq!(DEFAULT_MAX_OBJECTS_PER_SUMMARY, 10_000);
}

#[test]
fn default_max_symbols_per_summary_is_one_hundred_thousand() {
    assert_eq!(DEFAULT_MAX_SYMBOLS_PER_SUMMARY, 100_000);
}

#[test]
fn default_summary_ttl_secs_is_five_minutes() {
    assert_eq!(DEFAULT_SUMMARY_TTL_SECS, 300);
}

#[test]
fn default_max_future_skew_secs_is_thirty() {
    assert_eq!(DEFAULT_MAX_FUTURE_SKEW_SECS, 30);
}

#[test]
fn default_reconciliation_batch_size_is_one_thousand() {
    assert_eq!(DEFAULT_RECONCILIATION_BATCH_SIZE, 1000);
}

#[test]
fn max_object_ids_per_request_is_one_hundred() {
    assert_eq!(MAX_OBJECT_IDS_PER_REQUEST, 100);
}

// ─── GossipConfig::default ─────────────────────────────────────────

#[test]
fn gossip_config_default_uses_documented_summary_caps() {
    let c = GossipConfig::default();
    assert_eq!(c.max_objects_per_summary, DEFAULT_MAX_OBJECTS_PER_SUMMARY);
    assert_eq!(c.max_symbols_per_summary, DEFAULT_MAX_SYMBOLS_PER_SUMMARY);
}

#[test]
fn gossip_config_default_request_caps_match_max_object_ids_per_request() {
    let c = GossipConfig::default();
    assert_eq!(c.max_objects_per_request, MAX_OBJECT_IDS_PER_REQUEST);
    assert_eq!(c.max_symbols_per_request, MAX_OBJECT_IDS_PER_REQUEST);
}

#[test]
fn gossip_config_default_summary_ttl_matches_constant() {
    let c = GossipConfig::default();
    assert_eq!(c.summary_ttl_secs, DEFAULT_SUMMARY_TTL_SECS);
}

#[test]
fn gossip_config_default_max_future_skew_matches_constant() {
    let c = GossipConfig::default();
    assert_eq!(c.max_future_skew_secs, DEFAULT_MAX_FUTURE_SKEW_SECS);
}

#[test]
fn gossip_config_default_reconciliation_batch_size_matches_constant() {
    let c = GossipConfig::default();
    assert_eq!(
        c.reconciliation_batch_size,
        DEFAULT_RECONCILIATION_BATCH_SIZE
    );
}

#[test]
fn gossip_config_default_priority_gossip_interval_is_one_hundred_ms() {
    assert_eq!(
        GossipConfig::default().priority_gossip_interval_ms,
        100,
        "default priority_gossip_interval_ms MUST be 100ms — drift slows \
         revocation propagation"
    );
}

#[test]
fn gossip_config_default_max_revocation_push_peers_is_thirty_two() {
    assert_eq!(
        GossipConfig::default().max_revocation_push_peers,
        32,
        "default max_revocation_push_peers MUST be 32 — bounds gossip storm"
    );
}

#[test]
fn gossip_config_default_max_peer_states_is_four_thousand_ninety_six() {
    assert_eq!(
        GossipConfig::default().max_peer_states,
        4096,
        "default max_peer_states MUST be 4096 — caps peer-state memory"
    );
}

#[test]
fn gossip_config_max_iblt_bytes_is_const_fn() {
    // Sanity check the const-fn projection — pin it as a usable
    // value (proves the const fn doesn't panic / overflow at default).
    let c = GossipConfig::default();
    let max_iblt = c.max_iblt_bytes();
    assert!(
        max_iblt > 0,
        "max_iblt_bytes() MUST yield positive byte budget; got {max_iblt}"
    );
}

// ─── PriorityGossipPolicy ─────────────────────────────────────────

#[test]
fn priority_gossip_policy_default_is_direct_push() {
    assert_eq!(
        PriorityGossipPolicy::default(),
        PriorityGossipPolicy::DirectPush,
        "PriorityGossipPolicy::default MUST be DirectPush — revocations push to \
         all online peers immediately"
    );
}

#[test]
fn priority_gossip_policy_three_variants_are_distinct() {
    let a = PriorityGossipPolicy::DirectPush;
    let b = PriorityGossipPolicy::PriorityInterval;
    let c = PriorityGossipPolicy::Standard;
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

#[test]
fn priority_gossip_policy_implements_copy() {
    fn takes_value(_: PriorityGossipPolicy) {}
    let p = PriorityGossipPolicy::Standard;
    takes_value(p);
    takes_value(p);
    assert_eq!(p, PriorityGossipPolicy::Standard);
}

#[test]
fn priority_gossip_policy_serde_roundtrip_for_each_variant() {
    for variant in [
        PriorityGossipPolicy::DirectPush,
        PriorityGossipPolicy::PriorityInterval,
        PriorityGossipPolicy::Standard,
    ] {
        let json = serde_json::to_string(&variant).expect("serialize");
        let parsed: PriorityGossipPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, variant);
    }
}

// ─── IbltDecodeError ───────────────────────────────────────────────

#[test]
fn iblt_decode_error_too_large_carries_len_and_max() {
    let e = IbltDecodeError::TooLarge {
        len: 1024,
        max: 512,
    };
    match e {
        IbltDecodeError::TooLarge { len, max } => {
            assert_eq!(len, 1024);
            assert_eq!(max, 512);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn iblt_decode_error_invalid_encoding_is_unit_variant() {
    let e = IbltDecodeError::InvalidEncoding;
    match e {
        IbltDecodeError::InvalidEncoding => {}
        other => panic!("expected InvalidEncoding, got {other:?}"),
    }
}

#[test]
fn iblt_decode_error_too_many_changes_carries_decoded_and_max() {
    let e = IbltDecodeError::TooManyChanges {
        decoded: 200,
        max: 100,
    };
    match e {
        IbltDecodeError::TooManyChanges { decoded, max } => {
            assert_eq!(decoded, 200);
            assert_eq!(max, 100);
        }
        other => panic!("expected TooManyChanges, got {other:?}"),
    }
}

#[test]
fn iblt_decode_error_three_variants_are_distinct() {
    let a = IbltDecodeError::TooLarge { len: 0, max: 0 };
    let b = IbltDecodeError::InvalidEncoding;
    let c = IbltDecodeError::TooManyChanges { decoded: 0, max: 0 };
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

#[test]
fn iblt_decode_error_partial_eq_compares_payloads() {
    let a = IbltDecodeError::TooLarge { len: 100, max: 50 };
    let b = IbltDecodeError::TooLarge { len: 100, max: 50 };
    let c = IbltDecodeError::TooLarge { len: 200, max: 50 };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ─── GossipStats ──────────────────────────────────────────────────

#[test]
fn gossip_stats_three_fields_preserved_under_clone() {
    let s = GossipStats {
        object_count: 42,
        symbol_count: 1000,
        last_updated: 1_500_000_000,
    };
    let cloned = s.clone();
    assert_eq!(cloned.object_count, 42);
    assert_eq!(cloned.symbol_count, 1000);
    assert_eq!(cloned.last_updated, 1_500_000_000);
}
