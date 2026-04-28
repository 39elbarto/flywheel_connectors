use fcp_core::EvictionPolicy;

#[test]
fn eviction_policy_display_formats_are_canonical() {
    let cases = [
        (EvictionPolicy::Pinned, "pinned"),
        (
            EvictionPolicy::Lease {
                expires_at: 1_700_000_000,
            },
            "lease(expires_at=1700000000)",
        ),
        (EvictionPolicy::Ephemeral, "ephemeral"),
    ];

    for (policy, expected) in cases {
        assert_eq!(policy.to_string(), expected);
    }
}

#[test]
fn eviction_policy_variant_equality_is_structural() {
    assert_eq!(EvictionPolicy::Pinned, EvictionPolicy::Pinned);
    assert_eq!(EvictionPolicy::Ephemeral, EvictionPolicy::Ephemeral);
    assert_eq!(
        EvictionPolicy::Lease { expires_at: 42 },
        EvictionPolicy::Lease { expires_at: 42 }
    );

    assert_ne!(EvictionPolicy::Pinned, EvictionPolicy::Ephemeral);
    assert_ne!(
        EvictionPolicy::Pinned,
        EvictionPolicy::Lease { expires_at: 42 }
    );
    assert_ne!(
        EvictionPolicy::Ephemeral,
        EvictionPolicy::Lease { expires_at: 42 }
    );
    assert_ne!(
        EvictionPolicy::Lease { expires_at: 42 },
        EvictionPolicy::Lease { expires_at: 43 }
    );
}
