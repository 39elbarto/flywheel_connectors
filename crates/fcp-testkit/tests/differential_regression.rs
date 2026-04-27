//! Differential regression harness for `fcp-async-core`.
//!
//! ASUPERSYNC bead `flywheel_connectors-1ud0u.3.3`.
//!
//! Validates that the async-core surface preserves its intended semantics after
//! the ASUPERSYNC migration. Where useful, tests compare a high-level helper to
//! a lower-level composition built from the same substrate.
//!
//! Coverage areas:
//! - Timeout semantics and error normalization
//! - Channel send/recv behavior
//! - Bounded channel instrumentation hooks
//! - Watch-based shutdown propagation
//! - Cancellation token behavior
//! - `ExecutionContext` vs direct timeout/manual select composition
//! - `TaskGroup` shutdown vs manual watch + join patterns
//! - `select!` helper behavior
//! - Sync primitives and timer cadence

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::channel::{broadcast, mpsc, oneshot, watch};
use fcp_async_core::{
    AsyncError, CancellationToken, Deadline, ExecutionContext, Instrumentation, TaskGroup,
};
use fcp_async_core::{task, time};

// ============================================================================
// 1. Timeout error normalization
// ============================================================================

#[fcp_async_core::runtime::test]
async fn timeout_error_normalized() {
    let result = time::timeout(
        Duration::from_millis(10),
        time::sleep(Duration::from_secs(5)),
    )
    .await;

    assert!(
        matches!(result, Err(AsyncError::Timeout { timeout_ms: 10 })),
        "timeout should normalize to AsyncError::Timeout: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn deadline_run_matches_timeout_wrapper() {
    let timeout_value = time::timeout(Duration::from_millis(500), async { 42 })
        .await
        .unwrap();

    let deadline_value = Deadline::after(Duration::from_millis(500))
        .run(async { 42 })
        .await
        .unwrap();

    assert_eq!(timeout_value, deadline_value);
}

#[fcp_async_core::runtime::test]
async fn zero_timeout_sync_work_succeeds() {
    let timeout_value = time::timeout(Duration::ZERO, async { 42 }).await.unwrap();
    let deadline_value = Deadline::after(Duration::ZERO)
        .run(async { 42 })
        .await
        .unwrap();

    assert_eq!(timeout_value, 42);
    assert_eq!(deadline_value, 42);
}

#[fcp_async_core::runtime::test]
async fn zero_timeout_async_work_times_out() {
    let timeout_result =
        time::timeout(Duration::ZERO, time::sleep(Duration::from_millis(10))).await;
    let deadline_result = Deadline::after(Duration::ZERO)
        .run(time::sleep(Duration::from_millis(10)))
        .await;

    assert!(
        timeout_result.is_err(),
        "timeout path should fail: {timeout_result:?}"
    );
    assert!(
        deadline_result.is_err(),
        "deadline path should fail: {deadline_result:?}"
    );
}

// ============================================================================
// 2. Sleep timing behavior
// ============================================================================

#[fcp_async_core::runtime::test]
async fn execution_context_sleep_matches_direct_sleep() {
    let dur = Duration::from_millis(50);

    let direct_start = Instant::now();
    time::sleep(dur).await;
    let direct_elapsed = direct_start.elapsed();

    let ctx = ExecutionContext::background();
    let ctx_start = Instant::now();
    ctx.sleep(dur).await.unwrap();
    let ctx_elapsed = ctx_start.elapsed();

    assert!(
        direct_elapsed >= dur,
        "direct sleep too short: {direct_elapsed:?}"
    );
    assert!(
        ctx_elapsed >= dur,
        "context sleep too short: {ctx_elapsed:?}"
    );
    assert!(
        direct_elapsed.abs_diff(ctx_elapsed) < Duration::from_millis(50),
        "sleep jitter too large: direct={direct_elapsed:?} ctx={ctx_elapsed:?}"
    );
}

// ============================================================================
// 3. MPSC channel behavior
// ============================================================================

#[fcp_async_core::runtime::test]
async fn mpsc_send_recv_round_trip() {
    let (tx, mut rx) = mpsc::channel::<u32>(8);
    tx.send(42).await.unwrap();
    assert_eq!(rx.recv().await, Some(42));
}

#[fcp_async_core::runtime::test]
async fn mpsc_closed_channel_returns_none() {
    let (tx, mut rx) = mpsc::channel::<u32>(8);
    drop(tx);
    assert!(rx.recv().await.is_none());
}

// ============================================================================
// 4. Bounded channel instrumentation and normalization
// ============================================================================

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

#[fcp_async_core::runtime::test]
async fn bounded_channel_error_normalization() {
    let (tx, rx) = fcp_async_core::channel::bounded::<u32>("err-q", 1);

    tx.send(1).await.unwrap();

    let full_err = tx.try_send(2).unwrap_err();
    assert!(
        matches!(full_err, AsyncError::ChannelFull),
        "expected ChannelFull: {full_err:?}"
    );

    drop(rx);
    let closed_err = tx.send(3).await.unwrap_err();
    assert!(
        matches!(closed_err, AsyncError::ChannelClosed),
        "expected ChannelClosed: {closed_err:?}"
    );
}

// ============================================================================
// 5. Broadcast / oneshot / watch behavior
// ============================================================================

#[fcp_async_core::runtime::test]
async fn broadcast_channel_fans_out() {
    let (tx, mut rx_a) = broadcast::channel::<u32>(16);
    let mut rx_b = tx.subscribe();

    tx.send(42).unwrap();

    assert_eq!(rx_a.recv().await.unwrap(), 42);
    assert_eq!(rx_b.recv().await.unwrap(), 42);
}

#[fcp_async_core::runtime::test]
async fn oneshot_send_recv_round_trip() {
    let (tx, rx) = oneshot::channel::<u32>();
    tx.send(42).unwrap();
    assert_eq!(rx.await.unwrap(), 42);
}

#[fcp_async_core::runtime::test]
async fn oneshot_dropped_sender_errors() {
    let (tx, rx) = oneshot::channel::<u32>();
    drop(tx);
    assert!(rx.await.is_err());
}

#[fcp_async_core::runtime::test]
async fn watch_channel_value_propagates() {
    let (tx, mut rx) = watch::channel(0u32);
    tx.send(42).unwrap();
    rx.changed().await.unwrap();
    assert_eq!(*rx.borrow(), 42);
}

// ============================================================================
// 6. CancellationToken vs manual watch composition
// ============================================================================

#[fcp_async_core::runtime::test]
async fn cancellation_token_vs_manual_watch() {
    let token = CancellationToken::new();
    let mut listener = token.subscribe();
    assert!(!listener.is_cancelled());
    token.cancel();
    assert!(listener.is_cancelled());

    let token_result = time::timeout(Duration::from_millis(100), listener.cancelled()).await;
    assert!(token_result.is_ok());

    let (manual_tx, mut manual_rx) = watch::channel(false);
    assert!(!*manual_rx.borrow());
    manual_tx.send(true).unwrap();
    assert!(*manual_rx.borrow());

    let manual_result = time::timeout(Duration::from_millis(100), async {
        while !*manual_rx.borrow_and_update() {
            manual_rx.changed().await.unwrap();
        }
    })
    .await;
    assert!(manual_result.is_ok());
}

#[fcp_async_core::runtime::test]
async fn pre_cancelled_listener_resolves_immediately() {
    let token = CancellationToken::new();
    token.cancel();
    let mut listener = token.subscribe();

    let token_start = Instant::now();
    let _ = listener.cancelled().await;
    let token_elapsed = token_start.elapsed();

    let (_manual_tx, manual_rx) = watch::channel(true);
    let manual_start = Instant::now();
    if *manual_rx.borrow() {
        // already complete
    }
    let manual_elapsed = manual_start.elapsed();

    assert!(
        token_elapsed < Duration::from_millis(10),
        "token resolution too slow: {token_elapsed:?}"
    );
    assert!(
        manual_elapsed < Duration::from_millis(10),
        "manual watch resolution too slow: {manual_elapsed:?}"
    );
}

// ============================================================================
// 7. ExecutionContext helper behavior
// ============================================================================

#[fcp_async_core::runtime::test]
async fn execution_context_timeout_matches_direct_timeout() {
    let ctx = ExecutionContext::request_scoped(Duration::from_millis(50));
    let ctx_result = ctx
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await;
    assert!(matches!(ctx_result, Err(AsyncError::Timeout { .. })));

    let direct_result = time::timeout(
        Duration::from_millis(50),
        time::sleep(Duration::from_secs(5)),
    )
    .await;
    assert!(matches!(direct_result, Err(AsyncError::Timeout { .. })));
}

#[fcp_async_core::runtime::test]
async fn execution_context_cancellation_preempts_deadline() {
    let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
    ctx.cancel();

    let result = ctx
        .run(async { time::sleep(Duration::from_secs(5)).await })
        .await;

    assert_eq!(result.unwrap_err(), AsyncError::Cancelled);
}

// ============================================================================
// 8. TaskGroup vs manual watch + join patterns
// ============================================================================

#[fcp_async_core::runtime::test]
async fn task_group_shutdown_matches_manual_join_pattern() {
    let counter = Arc::new(AtomicUsize::new(0));

    let group_count = {
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
        group.shutdown(Duration::from_secs(2)).await.unwrap();
        counter.load(Ordering::SeqCst)
    };

    counter.store(0, Ordering::SeqCst);

    let manual_count = {
        let (shutdown_tx, _) = watch::channel(false);
        let mut handles = Vec::new();
        for _ in 0..4 {
            let c = Arc::clone(&counter);
            let mut shutdown_rx = shutdown_tx.subscribe();
            handles.push(task::spawn(async move {
                while !*shutdown_rx.borrow_and_update() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
                c.fetch_add(1, Ordering::SeqCst);
            }));
        }
        task::yield_now().await;
        time::sleep(Duration::from_millis(10)).await;
        shutdown_tx.send(true).unwrap();
        for handle in handles {
            let _ = time::timeout(Duration::from_secs(2), handle).await;
        }
        counter.load(Ordering::SeqCst)
    };

    assert_eq!(group_count, 4);
    assert_eq!(manual_count, 4);
    assert_eq!(group_count, manual_count);
}

#[fcp_async_core::runtime::test]
async fn task_group_times_out_stuck_tasks() {
    let mut group = TaskGroup::new();
    group.spawn("stuck", async move {
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        Ok(())
    });

    let result = group.shutdown(Duration::from_millis(50)).await;
    assert!(
        matches!(result, Err(AsyncError::Timeout { .. })),
        "TaskGroup should timeout on stuck task: {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn manual_timeout_then_abort_stuck_task() {
    let mut handle = task::spawn(async {
        loop {
            time::sleep(Duration::from_secs(60)).await;
        }
        #[allow(unreachable_code)]
        0_u32
    });

    let timed = time::timeout(Duration::from_millis(50), &mut handle).await;
    assert!(timed.is_err(), "manual timeout should fire: {timed:?}");

    handle.abort();
    let join = handle.await;
    assert!(join.is_err(), "aborted task should report join error");
}

// ============================================================================
// 9. Spawn / select / shutdown helpers
// ============================================================================

#[fcp_async_core::runtime::test]
async fn spawn_returns_output() {
    let handle = task::spawn(async { 42 });
    assert_eq!(handle.await.unwrap(), 42);
}

#[fcp_async_core::runtime::test]
async fn select_macro_picks_ready_branch() {
    let winner = fcp_async_core::select! {
        () = time::sleep(Duration::from_millis(10)) => "sleep",
        () = time::sleep(Duration::from_secs(60)) => "long",
    };

    assert_eq!(winner, "sleep");
}

#[fcp_async_core::runtime::test]
async fn sleep_or_shutdown_matches_manual_select() {
    let (tx, mut rx) = watch::channel(false);
    let helper_handle = task::spawn(async move {
        fcp_async_core::shutdown::sleep_or_shutdown(Duration::from_secs(60), &mut rx).await
    });

    time::sleep(Duration::from_millis(10)).await;
    tx.send(true).unwrap();

    let helper_result = time::timeout(Duration::from_millis(500), helper_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(helper_result, Err(AsyncError::Cancelled)));

    let (manual_tx, mut manual_rx) = watch::channel(false);
    let manual_handle = task::spawn(async move {
        fcp_async_core::select! {
            () = time::sleep(Duration::from_secs(60)) => Ok(()),
            () = async {
                while !*manual_rx.borrow_and_update() {
                    if manual_rx.changed().await.is_err() {
                        break;
                    }
                }
            } => Err(AsyncError::Cancelled),
        }
    });

    time::sleep(Duration::from_millis(10)).await;
    manual_tx.send(true).unwrap();

    let manual_result = time::timeout(Duration::from_millis(500), manual_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(manual_result, Err(AsyncError::Cancelled)));
}

// ============================================================================
// 10. Sync primitives and timer cadence
// ============================================================================

#[fcp_async_core::runtime::test]
async fn mutex_supports_mutation() {
    let mutex = fcp_async_core::sync::Mutex::new(0u32);
    *mutex.lock().await = 42;
    assert_eq!(*mutex.lock().await, 42);
}

#[fcp_async_core::runtime::test]
async fn interval_tick_cadence_reasonable() {
    let mut interval = time::interval(Duration::from_millis(20));
    let mut ticks = Vec::new();
    let start = Instant::now();

    for _ in 0..3 {
        interval.tick().await;
        ticks.push(start.elapsed());
    }

    assert!(ticks[0] < Duration::from_millis(10));
    assert!(ticks[2] > Duration::from_millis(30));
}

// ============================================================================
// 11. Retry-under-deadline pattern
// ============================================================================

#[fcp_async_core::runtime::test]
async fn retry_under_deadline_stops_on_timeout() {
    let ctx = ExecutionContext::request_scoped(Duration::from_millis(50));
    let mut ctx_count = 0;
    let ctx_err = loop {
        ctx_count += 1;
        match ctx.run(std::future::pending::<()>()).await {
            Ok(()) => continue,
            Err(err) => break err,
        }
    };

    let deadline = Instant::now() + Duration::from_millis(50);
    let mut timeout_count = 0;
    let timeout_err = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break AsyncError::Timeout { timeout_ms: 0 };
        }
        timeout_count += 1;
        match time::timeout(remaining, std::future::pending::<()>()).await {
            Ok(()) => continue,
            Err(err) => break err,
        }
    };

    assert_eq!(ctx_count, 1, "ctx retry should stop after first timeout");
    assert_eq!(timeout_count, 1, "manual retry should stop after first timeout");
    assert!(matches!(ctx_err, AsyncError::Timeout { .. }));
    assert!(matches!(timeout_err, AsyncError::Timeout { .. }));
}
