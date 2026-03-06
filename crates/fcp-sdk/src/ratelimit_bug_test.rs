use fcp_sdk::ratelimit::*;
use std::collections::HashMap;
use fcp_sdk::{RateLimitDeclarations, RateLimitPool, RateLimitConfig, RateLimitUnit, RateLimitEnforcement, RateLimitScope};
use std::time::Duration;

fn main() {
    let pool1 = RateLimitPool {
        id: "api".into(),
        description: "".into(),
        config: RateLimitConfig { requests: 10, window: Duration::from_secs(60), burst: None, unit: RateLimitUnit::Requests },
        enforcement: RateLimitEnforcement::Hard,
        scope: RateLimitScope::Instance,
    };
    let pool2 = RateLimitPool {
        id: "tokens".into(),
        description: "".into(),
        config: RateLimitConfig { requests: 2, window: Duration::from_secs(60), burst: None, unit: RateLimitUnit::Requests },
        enforcement: RateLimitEnforcement::Hard,
        scope: RateLimitScope::Instance,
    };
    let decls = RateLimitDeclarations {
        limits: vec![pool1, pool2],
        tool_pool_map: HashMap::from([("generate".to_string(), vec!["api".to_string(), "tokens".to_string()])]),
    };
    let tracker = RateLimitTracker::from_declarations(&decls);
    
    let err = tracker.try_consume("generate", 3);
    assert!(err.is_some());
    let status = tracker.pool_status("api").unwrap();
    println!("API pool remaining: {}", status.remaining);
    assert_eq!(status.remaining, 10, "Bug: api pool consumed despite operation failing!");
}
