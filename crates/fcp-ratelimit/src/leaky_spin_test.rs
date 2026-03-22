use std::time::{Duration, Instant};
use fcp_ratelimit::{RateLimiter, leaky_bucket::LeakyBucket};

#[tokio::main]
async fn main() {
    let limiter = LeakyBucket::new(1, 1.0); // 1 cap, 1/sec leak
    limiter.try_acquire().await; // Level = 1
    
    let start = Instant::now();
    let mut spins = 0;
    
    // We will simulate what `acquire` does
    loop {
        if limiter.try_acquire().await {
            break;
        }
        let wait = limiter.wait_time().await;
        if wait == Duration::ZERO {
            spins += 1;
            // sleep small to avoid locking up fully in test, but simulate spin
            tokio::time::sleep(Duration::from_millis(1)).await;
        } else {
            tokio::time::sleep(wait).await;
        }
    }
    
    println!("Elapsed: {:?}, spins: {}", start.elapsed(), spins);
}
