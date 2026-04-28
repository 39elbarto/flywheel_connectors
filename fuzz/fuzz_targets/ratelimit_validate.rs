#![no_main]

//! Fuzz target for `RateLimitDeclarations::validate`,
//! `RateLimitPool::validate`, and `RateLimitConfig::validate`
//! (ratelimit.rs:74-194).
//!
//! These validation gates protect the operator-visible rate-limit
//! declarations surface that SDKs and hosts use to plan tool
//! invocations. NOT covered as a discrete unit by any existing fuzz.
//!
//! A regression that:
//!   - dropped duplicate-pool detection would let a connector smuggle
//!     two pools with the same id, fragmenting accounting at runtime.
//!   - dropped unknown-pool detection would let a tool reference a
//!     non-existent pool, silently masking the absence of a limit.
//!   - accepted requests=0 / window=0 / burst=Some(0) would create a
//!     pool that never admits any traffic (or asserts on division).
//!
//! Properties asserted:
//!
//!   1. **`RateLimitConfig::validate` zero gates**: `requests=0` →
//!      `ZeroRequests`; `window=0` → `ZeroWindow`; `burst=Some(0)` →
//!      `ZeroBurst`.
//!   2. **`RateLimitPool::validate` empty id**: empty `id` →
//!      `EmptyPoolId`.
//!   3. **Pool validate delegates to config**: a pool with valid id
//!      and `requests=0` config returns `ZeroRequests`.
//!   4. **`RateLimitDeclarations::validate` duplicate pool**: two
//!      pools with same id → `DuplicatePoolId`.
//!   5. **`EmptyToolName`**: tool_pool_map containing key `""`.
//!   6. **`EmptyToolPools`**: tool maps to `vec![]`.
//!   7. **`EmptyToolPoolId`**: tool's pool list contains `""`.
//!   8. **`DuplicateToolPool`**: tool's pool list contains the same
//!      pool id twice.
//!   9. **`UnknownPool`**: tool references a pool id not in `limits`.
//!  10. **Empty declarations are Ok**.
//!  11. **Valid declarations pass**.
//!
//!   Once-gated anchors verify each error variant on hand-picked
//!   inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{
    RateLimitConfig, RateLimitDeclarationError, RateLimitDeclarations, RateLimitEnforcement,
    RateLimitPool, RateLimitScope, RateLimitUnit,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Once;
use std::time::Duration;

static RATELIMIT_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    pool_ids: Vec<String>,
    tool_pool_map_raw: Vec<(String, Vec<String>)>,
    requests: u32,
    window_secs: u32,
    burst: Option<u32>,
}

const MAX_POOLS: usize = 8;
const MAX_TOOLS: usize = 8;
const MAX_TOOL_POOLS: usize = 8;
const MAX_STR: usize = 64;

fn make_pool(id: String, requests: u32, window_secs: u32, burst: Option<u32>) -> RateLimitPool {
    RateLimitPool {
        id,
        description: String::new(),
        config: RateLimitConfig {
            requests,
            window: Duration::from_secs(u64::from(window_secs)),
            burst,
            unit: RateLimitUnit::Requests,
        },
        enforcement: RateLimitEnforcement::Hard,
        scope: RateLimitScope::Instance,
    }
}

fuzz_target!(|data: &[u8]| {
    RATELIMIT_ANCHOR.call_once(assert_ratelimit_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.pool_ids.len() > MAX_POOLS
        || input.tool_pool_map_raw.len() > MAX_TOOLS
        || input.pool_ids.iter().any(|s| s.len() > MAX_STR)
        || input
            .tool_pool_map_raw
            .iter()
            .any(|(t, ps)| t.len() > MAX_STR || ps.len() > MAX_TOOL_POOLS)
    {
        return;
    }

    // Build pools from input. Use config that's valid in isolation so
    // declarations-level errors dominate (we test config gates separately
    // via Property 1 below).
    let pools: Vec<RateLimitPool> = input
        .pool_ids
        .iter()
        .map(|id| make_pool(id.clone(), 1, 1, None))
        .collect();

    // Resolve tool_pool_map without dropping duplicate keys (HashMap
    // construction is destructive on dup keys; treat the LAST wins).
    let mut tool_pool_map: HashMap<String, Vec<String>> = HashMap::new();
    for (tool, ps) in &input.tool_pool_map_raw {
        tool_pool_map.insert(tool.clone(), ps.clone());
    }

    let decls = RateLimitDeclarations {
        limits: pools.clone(),
        tool_pool_map: tool_pool_map.clone(),
    };

    let result = decls.validate();

    // Compute expected outcome with a reference scan.
    let expected = expected_validate_result(&pools, &tool_pool_map);
    match (&result, &expected) {
        (Ok(()), Ok(())) => {}
        (Err(a), Err(b)) => assert_eq!(
            std::mem::discriminant(a),
            std::mem::discriminant(b),
            "validate returned {a:?} but reference expected {b:?}"
        ),
        (a, b) => panic!("validate returned {a:?} but reference expected {b:?}"),
    }

    // ── PROPERTY 1: RateLimitConfig::validate zero gates ────────────────
    let zero_req = RateLimitConfig {
        requests: 0,
        window: Duration::from_secs(1),
        burst: None,
        unit: RateLimitUnit::Requests,
    };
    assert!(matches!(
        zero_req.validate(),
        Err(RateLimitDeclarationError::ZeroRequests)
    ));
    let zero_window = RateLimitConfig {
        requests: 1,
        window: Duration::ZERO,
        burst: None,
        unit: RateLimitUnit::Requests,
    };
    assert!(matches!(
        zero_window.validate(),
        Err(RateLimitDeclarationError::ZeroWindow)
    ));
    let zero_burst = RateLimitConfig {
        requests: 1,
        window: Duration::from_secs(1),
        burst: Some(0),
        unit: RateLimitUnit::Requests,
    };
    assert!(matches!(
        zero_burst.validate(),
        Err(RateLimitDeclarationError::ZeroBurst)
    ));

    // ── PROPERTY 1 continuation: fuzzer-driven valid config ─────────────
    let cfg_input = RateLimitConfig {
        requests: input.requests,
        window: Duration::from_secs(u64::from(input.window_secs)),
        burst: input.burst,
        unit: RateLimitUnit::Requests,
    };
    let cfg_validate = cfg_input.validate();
    let cfg_expected = if input.requests == 0 {
        Err(RateLimitDeclarationError::ZeroRequests)
    } else if input.window_secs == 0 {
        Err(RateLimitDeclarationError::ZeroWindow)
    } else if matches!(input.burst, Some(0)) {
        Err(RateLimitDeclarationError::ZeroBurst)
    } else {
        Ok(())
    };
    match (&cfg_validate, &cfg_expected) {
        (Ok(()), Ok(())) => {}
        (Err(a), Err(b)) => assert_eq!(
            std::mem::discriminant(a),
            std::mem::discriminant(b),
            "RateLimitConfig::validate returned {a:?} but reference expected {b:?}"
        ),
        (a, b) => panic!("RateLimitConfig::validate returned {a:?} but reference expected {b:?}"),
    }
});

/// Reference implementation tracing the same precedence as
/// `RateLimitDeclarations::validate`.
fn expected_validate_result(
    pools: &[RateLimitPool],
    tool_pool_map: &HashMap<String, Vec<String>>,
) -> Result<(), RateLimitDeclarationError> {
    let mut seen = std::collections::HashSet::new();
    for pool in pools {
        if pool.id.is_empty() {
            return Err(RateLimitDeclarationError::EmptyPoolId);
        }
        // pool.config is hardcoded valid (1, 1s, no burst) above.
        if !seen.insert(pool.id.clone()) {
            return Err(RateLimitDeclarationError::DuplicatePoolId {
                id: pool.id.clone(),
            });
        }
    }

    for (tool, pools_for_tool) in tool_pool_map {
        if tool.is_empty() {
            return Err(RateLimitDeclarationError::EmptyToolName);
        }
        if pools_for_tool.is_empty() {
            return Err(RateLimitDeclarationError::EmptyToolPools { tool: tool.clone() });
        }
        let mut seen_pool = std::collections::HashSet::new();
        for pid in pools_for_tool {
            if pid.is_empty() {
                return Err(RateLimitDeclarationError::EmptyToolPoolId { tool: tool.clone() });
            }
            if !seen_pool.insert(pid) {
                return Err(RateLimitDeclarationError::DuplicateToolPool {
                    tool: tool.clone(),
                    pool: pid.clone(),
                });
            }
            if !seen.contains(pid) {
                return Err(RateLimitDeclarationError::UnknownPool {
                    tool: tool.clone(),
                    pool: pid.clone(),
                });
            }
        }
    }

    Ok(())
}

/// Once-gated anchors: each error variant + valid+empty cases.
fn assert_ratelimit_anchored() {
    // (a) Empty declarations → Ok.
    let empty = RateLimitDeclarations::default();
    empty.validate().expect("ANCHOR: empty declarations valid");

    // (b) Valid pool with valid tool mapping.
    let mut tpm = HashMap::new();
    tpm.insert("tool-a".to_string(), vec!["pool-1".to_string()]);
    let valid = RateLimitDeclarations {
        limits: vec![make_pool("pool-1".into(), 10, 60, Some(2))],
        tool_pool_map: tpm,
    };
    valid.validate().expect("ANCHOR: valid declarations");

    // (c) EmptyPoolId.
    let bad_pool_id = RateLimitDeclarations {
        limits: vec![make_pool(String::new(), 1, 1, None)],
        tool_pool_map: HashMap::new(),
    };
    match bad_pool_id.validate() {
        Err(RateLimitDeclarationError::EmptyPoolId) => {}
        other => panic!("ANCHOR REGRESSION: empty pool id expected EmptyPoolId, got {other:?}"),
    }

    // (d) DuplicatePoolId.
    let dup = RateLimitDeclarations {
        limits: vec![
            make_pool("pool-1".into(), 1, 1, None),
            make_pool("pool-1".into(), 2, 2, None),
        ],
        tool_pool_map: HashMap::new(),
    };
    match dup.validate() {
        Err(RateLimitDeclarationError::DuplicatePoolId { id }) => {
            assert_eq!(id, "pool-1", "ANCHOR: DuplicatePoolId.id");
        }
        other => {
            panic!("ANCHOR REGRESSION: duplicate pool expected DuplicatePoolId, got {other:?}")
        }
    }

    // (e) EmptyToolName.
    let mut tpm = HashMap::new();
    tpm.insert(String::new(), vec!["pool-1".to_string()]);
    let bad = RateLimitDeclarations {
        limits: vec![make_pool("pool-1".into(), 1, 1, None)],
        tool_pool_map: tpm,
    };
    match bad.validate() {
        Err(RateLimitDeclarationError::EmptyToolName) => {}
        other => panic!("ANCHOR REGRESSION: empty tool name expected EmptyToolName, got {other:?}"),
    }

    // (f) EmptyToolPools.
    let mut tpm = HashMap::new();
    tpm.insert("tool-a".to_string(), vec![]);
    let bad = RateLimitDeclarations {
        limits: vec![make_pool("pool-1".into(), 1, 1, None)],
        tool_pool_map: tpm,
    };
    match bad.validate() {
        Err(RateLimitDeclarationError::EmptyToolPools { tool }) => {
            assert_eq!(tool, "tool-a", "ANCHOR: EmptyToolPools.tool");
        }
        other => {
            panic!("ANCHOR REGRESSION: empty tool pools expected EmptyToolPools, got {other:?}")
        }
    }

    // (g) EmptyToolPoolId.
    let mut tpm = HashMap::new();
    tpm.insert("tool-a".to_string(), vec![String::new()]);
    let bad = RateLimitDeclarations {
        limits: vec![make_pool("pool-1".into(), 1, 1, None)],
        tool_pool_map: tpm,
    };
    match bad.validate() {
        Err(RateLimitDeclarationError::EmptyToolPoolId { tool }) => {
            assert_eq!(tool, "tool-a", "ANCHOR: EmptyToolPoolId.tool");
        }
        other => {
            panic!("ANCHOR REGRESSION: empty tool pool id expected EmptyToolPoolId, got {other:?}")
        }
    }

    // (h) DuplicateToolPool.
    let mut tpm = HashMap::new();
    tpm.insert(
        "tool-a".to_string(),
        vec!["pool-1".to_string(), "pool-1".to_string()],
    );
    let bad = RateLimitDeclarations {
        limits: vec![make_pool("pool-1".into(), 1, 1, None)],
        tool_pool_map: tpm,
    };
    match bad.validate() {
        Err(RateLimitDeclarationError::DuplicateToolPool { tool, pool }) => {
            assert_eq!(tool, "tool-a", "ANCHOR: DuplicateToolPool.tool");
            assert_eq!(pool, "pool-1", "ANCHOR: DuplicateToolPool.pool");
        }
        other => panic!(
            "ANCHOR REGRESSION: duplicate tool pool expected DuplicateToolPool, got {other:?}"
        ),
    }

    // (i) UnknownPool.
    let mut tpm = HashMap::new();
    tpm.insert("tool-a".to_string(), vec!["nonexistent".to_string()]);
    let bad = RateLimitDeclarations {
        limits: vec![make_pool("pool-1".into(), 1, 1, None)],
        tool_pool_map: tpm,
    };
    match bad.validate() {
        Err(RateLimitDeclarationError::UnknownPool { tool, pool }) => {
            assert_eq!(tool, "tool-a", "ANCHOR: UnknownPool.tool");
            assert_eq!(pool, "nonexistent", "ANCHOR: UnknownPool.pool");
        }
        other => panic!("ANCHOR REGRESSION: unknown pool expected UnknownPool, got {other:?}"),
    }

    // (j) ZeroRequests.
    let zero_req = RateLimitConfig {
        requests: 0,
        window: Duration::from_secs(1),
        burst: None,
        unit: RateLimitUnit::Requests,
    };
    match zero_req.validate() {
        Err(RateLimitDeclarationError::ZeroRequests) => {}
        other => panic!("ANCHOR REGRESSION: requests=0 expected ZeroRequests, got {other:?}"),
    }

    // (k) ZeroWindow.
    let zero_window = RateLimitConfig {
        requests: 1,
        window: Duration::ZERO,
        burst: None,
        unit: RateLimitUnit::Requests,
    };
    match zero_window.validate() {
        Err(RateLimitDeclarationError::ZeroWindow) => {}
        other => panic!("ANCHOR REGRESSION: window=0 expected ZeroWindow, got {other:?}"),
    }

    // (l) ZeroBurst.
    let zero_burst = RateLimitConfig {
        requests: 1,
        window: Duration::from_secs(1),
        burst: Some(0),
        unit: RateLimitUnit::Requests,
    };
    match zero_burst.validate() {
        Err(RateLimitDeclarationError::ZeroBurst) => {}
        other => panic!("ANCHOR REGRESSION: burst=Some(0) expected ZeroBurst, got {other:?}"),
    }

    // (m) Pool validate delegates to config.
    let bad_pool = make_pool("pool-1".into(), 0, 1, None);
    match bad_pool.validate() {
        Err(RateLimitDeclarationError::ZeroRequests) => {}
        other => {
            panic!("ANCHOR REGRESSION: pool with bad config expected ZeroRequests, got {other:?}")
        }
    }
}
