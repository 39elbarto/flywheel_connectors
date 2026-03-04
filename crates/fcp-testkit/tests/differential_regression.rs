//! Differential regression harness: fcp-async-core vs raw Tokio equivalents.
//!
//! ASUPERSYNC bead `flywheel_connectors-1ud0u.3.3`.
//!
//! Validates that fcp-async-core wrappers produce semantically equivalent (or
//! intentionally improved) outcomes compared to their raw Tokio counterparts.
//! Each test exercises both paths and compares observable behavior:
//!
//! - Timeout semantics and error normalization
//! - Channel send/recv parity
//! - Bounded channel instrumentation hooks
//! - Watch channel shutdown propagation
//! - Cancellation token vs ad-hoc watch patterns
//! - `Select!` macro passthrough fidelity
//! - `ExecutionContext` vs manual `tokio::select!` composition
//! - `TaskGroup` shutdown vs manual `join_all`

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::channel::{broadcast, mpsc, oneshot, watch};
use fcp_async_core::{AsyncError, CancellationToken, ExecutionContext, Instrumentation, TaskGroup};
use fcp_async_core::{task, time};

// ============================================================================
// 1. Timeout error normalization
// ============================================================================

/// Both paths produce a timeout — fcp-async-core normalizes to `AsyncError::Timeout`.
#[fcp_async_core::runtime::test]
async fn timeout_error_normalized_vs_tokio_elapsed() {
    // fcp-async-core path
    let fcp_result = time::timeout(
        Duration::from_millis(10),
        time::sleep(Duration::from_secs(5)),
    )
    .await;
    assert!(
        matches!(fcp_result, Err(AsyncError::Timeout { timeout_ms: 10 })),
        "fcp timeout should produce Timeout{{timeout_ms:10}}: {fcp_result:?}"
    );

    // Raw tokio path (same underlying operation)
    let tokio_result = tokio::time::timeout(
        Duration::from_millis(10),
        tokio::time::sleep(Duration::from_secs(5)),
    )
    .await;
    assert!(
        tokio_result.is_err(),
        "tokio timeout should produce Elapsed"
    );

    // Behavioral parity: both timed out
    assert!(fcp_result.is_err());
    assert!(tokio_result.is_err());
}

/// Fast work completes identically under both timeout wrappers.
#[fcp_async_core::runtime::test]
async fn timeout_fast_work_succeeds_in_both() {
    let fcp_val = time::timeout(Duration::from_millis(500), async { 42 })
        .await
        .unwrap();

    let tokio_val = tokio::time::timeout(Duration::from_millis(500), async { 42 })
        .await
        .unwrap();

    assert_eq!(fcp_val, tokio_val);
}

/// Zero-duration timeout: both poll once and let sync work succeed.
#[fcp_async_core::runtime::test]
async fn zero_timeout_sync_parity() {
    let fcp = time::timeout(Duration::ZERO, async { 42 }).await;
    let tokio_r = tokio::time::timeout(Duration::ZERO, async { 42 }).await;

    assert_eq!(fcp.unwrap(), 42);
    assert_eq!(tokio_r.unwrap(), 42);
}

/// Zero-duration timeout: both reject async work that yields.
#[fcp_async_core::runtime::test]
async fn zero_timeout_async_rejection_parity() {
    let fcp = time::timeout(Duration::ZERO, time::sleep(Duration::from_millis(10))).await;
    let tokio_r = tokio::time::timeout(
        Duration::ZERO,
        tokio::time::sleep(Duration::from_millis(10)),
    )
    .await;

    assert!(fcp.is_err(), "fcp should timeout: {fcp:?}");
    assert!(tokio_r.is_err(), "tokio should timeout: {tokio_r:?}");
}

// ============================================================================
// 2. Sleep timing parity
// ============================================================================

/// Sleep durations are equivalent within jitter bounds.
#[fcp_async_core::runtime::test]
async fn sleep_duration_parity() {
    let dur = Duration::from_millis(50);

    let start_fcp = Instant::now();
    time::sleep(dur).await;
    let elapsed_fcp = start_fcp.elapsed();

    let start_tokio = Instant::now();
    tokio::time::sleep(dur).await;
    let elapsed_tokio = start_tokio.elapsed();

    // Both should be >= requested (may be slightly more due to scheduling)
    assert!(elapsed_fcp >= dur, "fcp slept too short: {elapsed_fcp:?}");
    assert!(
        elapsed_tokio >= dur,
        "tokio slept too short: {elapsed_tokio:?}"
    );

    // Jitter within 50ms is acceptable
    let diff = elapsed_fcp.abs_diff(elapsed_tokio);
    assert!(
        diff < Duration::from_millis(50),
        "timing jitter too large: {diff:?}"
    );
}

// ============================================================================
// 3. MPSC channel behavioral parity
// ============================================================================

/// Bounded mpsc send/recv semantics are identical.
#[fcp_async_core::runtime::test]
async fn mpsc_send_recv_parity() {
    // fcp-async-core mpsc (re-export)
    let (fcp_tx, mut fcp_rx) = mpsc::channel::<u32>(8);
    fcp_tx.send(42).await.unwrap();
    let fcp_val = fcp_rx.recv().await.unwrap();

    // raw tokio mpsc
    let (tok_tx, mut tok_rx) = tokio::sync::mpsc::channel::<u32>(8);
    tok_tx.send(42).await.unwrap();
    let tok_val = tok_rx.recv().await.unwrap();

    assert_eq!(fcp_val, tok_val);
}

/// Dropping sender causes `recv()` to return `None` in both.
#[fcp_async_core::runtime::test]
async fn mpsc_closed_channel_parity() {
    let (fcp_tx, mut fcp_rx) = mpsc::channel::<u32>(8);
    drop(fcp_tx);
    let fcp_result = fcp_rx.recv().await;

    let (tok_tx, mut tok_rx) = tokio::sync::mpsc::channel::<u32>(8);
    drop(tok_tx);
    let tok_result = tok_rx.recv().await;

    assert!(fcp_result.is_none());
    assert!(tok_result.is_none());
}

// ============================================================================
// 4. Bounded channel with instrumentation (behavioral improvement)
// ============================================================================

/// `BoundedSender`/`BoundedReceiver` fires instrumentation hooks — an intentional improvement.
#[fcp_async_core::runtime::test]
async fn bounded_channel_fires_instrumentation_hooks() {
    let sends = Arc::new(AtomicUsize::new(0));
    let recvs = Arc::new(AtomicUsize::new(0));

    let instrumentation: Arc<dyn Instrumentation> = Arc::new(CountingInstrumentation {
        sends: Arc::clone(&sends),
        recvs: Arc::clone(&recvs),
    });

    let (tx, mut rx) =
        fcp_async_core::channel::bounded_with_instrumentation("test-q", 8, instrumentation);

    tx.send(1).await.unwrap();
    tx.send(2).await.unwrap();
    tx.try_send(3).unwrap();

    assert_eq!(sends.load(Ordering::SeqCst), 3);

    let _ = rx.recv().await;
    let _ = rx.recv().await;
    assert_eq!(recvs.load(Ordering::SeqCst), 2);
}

struct CountingInstrumentation {
    sends: Arc<AtomicUsize>,
    recvs: Arc<AtomicUsize>,
}

impl Instrumentation for CountingInstrumentation {
    fn on_queue_send(&self, _name: &str, _depth: usize, _capacity: usize) {
        self.sends.fetch_add(1, Ordering::SeqCst);
    }

    fn on_queue_receive(&self, _name: &str, _depth: usize, _capacity: usize) {
        self.recvs.fetch_add(1, Ordering::SeqCst);
    }
}

/// Bounded channel normalizes errors to `AsyncError` variants.
#[fcp_async_core::runtime::test]
async fn bounded_channel_error_normalization() {
    let (tx, rx) = fcp_async_core::channel::bounded::<u32>("err-q", 1);

    // Fill channel
    tx.send(1).await.unwrap();

    // try_send on full → ChannelFull
    let full_err = tx.try_send(2).unwrap_err();
    assert!(
        matches!(full_err, AsyncError::ChannelFull),
        "expected ChannelFull: {full_err:?}"
    );

    // Drop receiver, send → ChannelClosed
    drop(rx);
    let closed_err = tx.send(3).await.unwrap_err();
    assert!(
        matches!(closed_err, AsyncError::ChannelClosed),
        "expected ChannelClosed: {closed_err:?}"
    );
}

// ============================================================================
// 5. Broadcast channel parity
// ============================================================================

/// Broadcast channel semantics match raw tokio.
#[fcp_async_core::runtime::test]
async fn broadcast_channel_parity() {
    let (fcp_tx, mut fcp_rx) = broadcast::channel::<u32>(16);
    fcp_tx.send(42).unwrap();
    let fcp_val = fcp_rx.recv().await.unwrap();

    let (tok_tx, mut tok_rx) = tokio::sync::broadcast::channel::<u32>(16);
    tok_tx.send(42).unwrap();
    let tok_val = tok_rx.recv().await.unwrap();

    assert_eq!(fcp_val, tok_val);
}

// ============================================================================
// 6. Oneshot channel parity
// ============================================================================

/// Oneshot send/recv semantics match raw tokio.
#[fcp_async_core::runtime::test]
async fn oneshot_channel_parity() {
    let (fcp_tx, fcp_rx) = oneshot::channel::<u32>();
    fcp_tx.send(42).unwrap();
    let fcp_val = fcp_rx.await.unwrap();

    let (tok_tx, tok_rx) = tokio::sync::oneshot::channel::<u32>();
    tok_tx.send(42).unwrap();
    let tok_val = tok_rx.await.unwrap();

    assert_eq!(fcp_val, tok_val);
}

/// Dropped oneshot sender produces `RecvError` in both.
#[fcp_async_core::runtime::test]
async fn oneshot_dropped_sender_parity() {
    let (fcp_tx, fcp_rx) = oneshot::channel::<u32>();
    drop(fcp_tx);
    assert!(fcp_rx.await.is_err());

    let (tok_tx, tok_rx) = tokio::sync::oneshot::channel::<u32>();
    drop(tok_tx);
    assert!(tok_rx.await.is_err());
}

// ============================================================================
// 7. Watch channel parity
// ============================================================================

/// Watch channel semantics match raw tokio.
#[fcp_async_core::runtime::test]
async fn watch_channel_value_propagation_parity() {
    let (fcp_tx, mut fcp_rx) = watch::channel(0u32);
    fcp_tx.send(42).unwrap();
    fcp_rx.changed().await.unwrap();
    let fcp_val = *fcp_rx.borrow();

    let (tok_tx, mut tok_rx) = tokio::sync::watch::channel(0u32);
    tok_tx.send(42).unwrap();
    tok_rx.changed().await.unwrap();
    let tok_val = *tok_rx.borrow();

    assert_eq!(fcp_val, tok_val);
}

// ============================================================================
// 8. CancellationToken vs ad-hoc watch (intentional improvement)
// ============================================================================

/// `CancellationToken` provides cleaner semantics than manual watch patterns.
#[fcp_async_core::runtime::test]
async fn cancellation_token_vs_manual_watch() {
    // fcp-async-core: CancellationToken (purpose-built)
    let token = CancellationToken::new();
    let mut listener = token.subscribe();
    assert!(!listener.is_cancelled());
    token.cancel();
    assert!(listener.is_cancelled());
    // cancelled() resolves immediately after cancel
    let fcp_result = time::timeout(Duration::from_millis(100), listener.cancelled()).await;
    assert!(fcp_result.is_ok());

    // Raw tokio equivalent: manual watch channel
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    assert!(!*rx.borrow());
    tx.send(true).unwrap();
    assert!(*rx.borrow());
    // Must manually loop on changed()
    let tokio_result = tokio::time::timeout(Duration::from_millis(100), async {
        while !*rx.borrow_and_update() {
            rx.changed().await.unwrap();
        }
    })
    .await;
    assert!(tokio_result.is_ok());
}

/// Pre-cancelled token resolves immediately — same as pre-signaled watch.
#[fcp_async_core::runtime::test]
async fn pre_cancelled_resolution_parity() {
    // fcp-async-core
    let token = CancellationToken::new();
    token.cancel();
    let mut listener = token.subscribe();
    let fcp_start = Instant::now();
    let _ = listener.cancelled().await;
    let fcp_elapsed = fcp_start.elapsed();

    // Raw tokio
    let (_tx, rx) = tokio::sync::watch::channel(true);
    let tok_start = Instant::now();
    // Manual check — already true
    if *rx.borrow() {
        // done
    }
    let tok_elapsed = tok_start.elapsed();

    // Both should be near-instant (< 10ms)
    assert!(
        fcp_elapsed < Duration::from_millis(10),
        "fcp pre-cancel slow: {fcp_elapsed:?}"
    );
    assert!(
        tok_elapsed < Duration::from_millis(10),
        "tokio pre-signal slow: {tok_elapsed:?}"
    );
}

// ============================================================================
// 9. ExecutionContext::run() vs manual select! composition
// ============================================================================

/// `ExecutionContext::run()` matches manual `tokio::select!` for timeout.
#[fcp_async_core::runtime::test]
async fn execution_context_timeout_vs_manual_select() {
    // fcp-async-core path
    let ctx = ExecutionContext::request_scoped(Duration::from_millis(50));
    let fcp_result = ctx
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await;
    assert!(matches!(fcp_result, Err(AsyncError::Timeout { .. })));

    // Manual tokio equivalent
    let manual_result = tokio::time::timeout(
        Duration::from_millis(50),
        tokio::time::sleep(Duration::from_secs(5)),
    )
    .await;
    assert!(manual_result.is_err());
}

/// `ExecutionContext::run()` — cancellation preempts deadline (intentional improvement).
#[fcp_async_core::runtime::test]
async fn cancellation_preempts_deadline_no_raw_equivalent() {
    let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
    ctx.cancel();

    let result = ctx
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await;

    // Cancellation takes priority (biased select!) — this is an intentional
    // improvement over raw tokio where you'd need manual biased select!.
    assert_eq!(
        result.unwrap_err(),
        AsyncError::Cancelled,
        "cancellation should preempt deadline"
    );
}

// ============================================================================
// 10. TaskGroup::shutdown() vs manual join_all
// ============================================================================

/// `TaskGroup` provides structured shutdown — manual equivalent needs explicit join.
#[fcp_async_core::runtime::test]
async fn task_group_shutdown_vs_manual_join() {
    let counter = Arc::new(AtomicUsize::new(0));

    // fcp-async-core: TaskGroup
    {
        let counter = Arc::clone(&counter);
        let mut group = TaskGroup::new();
        for i in 0..4 {
            let c = Arc::clone(&counter);
            let mut listener = group.subscribe_cancellation();
            group.spawn(format!("worker-{i}"), async move {
                listener.cancelled().await?;
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
        }
        task::yield_now().await;
        time::sleep(Duration::from_millis(10)).await;
        let result = group.shutdown(Duration::from_secs(2)).await;
        assert!(result.is_ok());
    }
    let fcp_count = counter.load(Ordering::SeqCst);
    assert_eq!(fcp_count, 4, "all 4 tasks should complete via TaskGroup");

    // Manual tokio equivalent
    counter.store(0, Ordering::SeqCst);
    {
        let (tx, _) = tokio::sync::watch::channel(false);
        let mut handles = Vec::new();
        for _ in 0..4 {
            let c = Arc::clone(&counter);
            let mut rx = tx.subscribe();
            handles.push(tokio::task::spawn(async move {
                // Wait for shutdown signal
                while !*rx.borrow_and_update() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
                c.fetch_add(1, Ordering::SeqCst);
            }));
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send(true).unwrap();
        for h in handles {
            let _ = tokio::time::timeout(Duration::from_secs(2), h).await;
        }
    }
    let manual_count = counter.load(Ordering::SeqCst);
    assert_eq!(manual_count, 4, "all 4 tasks should complete manually");

    // Both achieved the same outcome
    assert_eq!(fcp_count, manual_count);
}

/// `TaskGroup` aborts stuck tasks on timeout — manual equivalent must do this explicitly.
#[fcp_async_core::runtime::test]
async fn task_group_abort_stuck_vs_manual() {
    // fcp-async-core: TaskGroup handles abort on timeout
    let mut group = TaskGroup::new();
    group.spawn("stuck", async move {
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        Ok(())
    });
    let fcp_result = group.shutdown(Duration::from_millis(50)).await;
    assert!(
        matches!(fcp_result, Err(AsyncError::Timeout { .. })),
        "TaskGroup should timeout on stuck task: {fcp_result:?}"
    );

    // Manual tokio: must explicitly abort
    let handle = tokio::task::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    let manual_result = tokio::time::timeout(Duration::from_millis(50), handle).await;
    assert!(manual_result.is_err(), "manual should timeout too");
}

// ============================================================================
// 11. Spawn parity
// ============================================================================

/// `task::spawn` matches `tokio::task::spawn`.
#[fcp_async_core::runtime::test]
async fn spawn_parity() {
    let fcp_handle = task::spawn(async { 42 });
    let tokio_handle = tokio::task::spawn(async { 42 });

    let fcp_val = fcp_handle.await.unwrap();
    let tokio_val = tokio_handle.await.unwrap();

    assert_eq!(fcp_val, tokio_val);
}

// ============================================================================
// 12. Select! macro passthrough
// ============================================================================

/// The `fcp_async_core::select!` macro produces identical outcomes to `tokio::select!`.
#[fcp_async_core::runtime::test]
async fn select_macro_parity() {
    // fcp-async-core select!
    let fcp_winner = fcp_async_core::select! {
        () = time::sleep(Duration::from_millis(10)) => "sleep",
        () = time::sleep(Duration::from_secs(60)) => "long",
    };
    assert_eq!(fcp_winner, "sleep");

    // raw tokio select!
    let tokio_winner = tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(10)) => "sleep",
        () = tokio::time::sleep(Duration::from_secs(60)) => "long",
    };
    assert_eq!(tokio_winner, "sleep");
}

// ============================================================================
// 13. Shutdown propagation: sleep_or_shutdown parity
// ============================================================================

/// `sleep_or_shutdown` achieves the same result as manual `select!` over sleep+watch.
#[fcp_async_core::runtime::test]
async fn sleep_or_shutdown_vs_manual_select() {
    // fcp-async-core: sleep_or_shutdown
    let (tx, mut rx) = watch::channel(false);
    let fcp_handle = task::spawn(async move {
        fcp_async_core::shutdown::sleep_or_shutdown(Duration::from_secs(60), &mut rx).await
    });
    time::sleep(Duration::from_millis(10)).await;
    tx.send(true).unwrap();
    let fcp_result = time::timeout(Duration::from_millis(500), fcp_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(fcp_result, Err(AsyncError::Cancelled)));

    // Manual tokio equivalent
    let (manual_tx, mut manual_rx) = tokio::sync::watch::channel(false);
    let manual_handle = tokio::task::spawn(async move {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(60)) => Ok(()),
            () = async {
                while !*manual_rx.borrow_and_update() {
                    if manual_rx.changed().await.is_err() { break; }
                }
            } => Err("shutdown"),
        }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    manual_tx.send(true).unwrap();
    let manual_result = tokio::time::timeout(Duration::from_millis(500), manual_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(manual_result, Err("shutdown")),
        "manual should get shutdown: {manual_result:?}"
    );
}

// ============================================================================
// 14. Sync primitives parity
// ============================================================================

/// `Mutex` from fcp-async-core is the same `tokio::sync::Mutex`.
#[fcp_async_core::runtime::test]
async fn mutex_parity() {
    let fcp_mutex = fcp_async_core::sync::Mutex::new(0u32);
    *fcp_mutex.lock().await = 42;
    assert_eq!(*fcp_mutex.lock().await, 42);

    let tokio_mutex = tokio::sync::Mutex::new(0u32);
    *tokio_mutex.lock().await = 42;
    assert_eq!(*tokio_mutex.lock().await, 42);
}

// ============================================================================
// 15. Streaming / interval parity
// ============================================================================

/// Interval ticks produce values at equivalent cadence.
#[fcp_async_core::runtime::test]
async fn interval_tick_parity() {
    let mut fcp_interval = time::interval(Duration::from_millis(20));
    let mut fcp_ticks = Vec::new();
    let start = Instant::now();
    for _ in 0..3 {
        fcp_interval.tick().await;
        fcp_ticks.push(start.elapsed());
    }

    let mut tokio_interval = tokio::time::interval(Duration::from_millis(20));
    let mut tokio_ticks = Vec::new();
    let start = Instant::now();
    for _ in 0..3 {
        tokio_interval.tick().await;
        tokio_ticks.push(start.elapsed());
    }

    // First tick is immediate for both
    assert!(fcp_ticks[0] < Duration::from_millis(10));
    assert!(tokio_ticks[0] < Duration::from_millis(10));

    // Subsequent ticks ~20ms apart (within 30ms tolerance)
    assert!(fcp_ticks[2] > Duration::from_millis(30));
    assert!(tokio_ticks[2] > Duration::from_millis(30));
}

// ============================================================================
// 16. Retries under deadline: pattern equivalence
// ============================================================================

/// Retry-under-deadline pattern produces similar attempt counts.
#[fcp_async_core::runtime::test]
async fn retry_under_deadline_equivalence() {
    // fcp-async-core path: ExecutionContext retry
    let ctx = ExecutionContext::request_scoped(Duration::from_millis(100));
    let fcp_attempts = Arc::new(AtomicUsize::new(0));
    let fcp_attempts_clone = Arc::clone(&fcp_attempts);

    for _ in 0..100 {
        fcp_attempts_clone.fetch_add(1, Ordering::SeqCst);
        if ctx
            .run(async { time::sleep(Duration::from_millis(20)).await })
            .await
            .is_err()
        {
            break;
        }
    }
    let fcp_count = fcp_attempts.load(Ordering::SeqCst);

    // Manual tokio path: timeout + retry
    let deadline = Instant::now() + Duration::from_millis(100);
    let tokio_attempts = Arc::new(AtomicUsize::new(0));
    let tokio_attempts_clone = Arc::clone(&tokio_attempts);

    for _ in 0..100 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        tokio_attempts_clone.fetch_add(1, Ordering::SeqCst);
        if tokio::time::timeout(remaining, tokio::time::sleep(Duration::from_millis(20)))
            .await
            .is_err()
        {
            break;
        }
    }
    let tokio_count = tokio_attempts.load(Ordering::SeqCst);

    // Both should exhaust in roughly 3-7 attempts (100ms / 20ms = ~5)
    assert!(
        (3..=7).contains(&fcp_count),
        "fcp attempts out of range: {fcp_count}"
    );
    assert!(
        (3..=7).contains(&tokio_count),
        "tokio attempts out of range: {tokio_count}"
    );

    // Difference should be at most 2 (scheduling jitter)
    let diff = fcp_count.abs_diff(tokio_count);
    assert!(
        diff <= 2,
        "attempt count difference too large: fcp={fcp_count} tokio={tokio_count}"
    );
}
