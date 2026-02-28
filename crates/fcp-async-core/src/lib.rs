//! Shared async runtime substrate for FCP crates.
//!
//! Provides unified entrypoints, task group APIs, timers, channels,
//! and cancellation helpers so all FCP components use a single
//! consistent async concurrency model.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

pub use tokio::select;
pub use tokio::task_local;

/// Unified async failure taxonomy for substrate consumers.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AsyncError {
    /// Operation timed out.
    #[error("operation timed out after {timeout_ms}ms")]
    Timeout {
        /// Timeout budget in milliseconds.
        timeout_ms: u64,
    },

    /// Operation cancelled.
    #[error("operation cancelled")]
    Cancelled,

    /// Channel was closed.
    #[error("channel closed")]
    ChannelClosed,

    /// Channel was full for non-blocking send.
    #[error("channel full")]
    ChannelFull,

    /// Protocol I/O failure.
    #[error("protocol io fault: {message}")]
    ProtocolIo {
        /// Human-readable detail.
        message: String,
    },

    /// Task join failure.
    #[error("task join failed: {message}")]
    Join {
        /// Human-readable detail.
        message: String,
    },

    /// Runtime infrastructure failure.
    #[error("runtime failure: {message}")]
    Runtime {
        /// Human-readable detail.
        message: String,
    },
}

/// Hooks for task and queue instrumentation.
pub trait Instrumentation: Send + Sync {
    /// Called on task spawn.
    fn on_task_spawn(&self, _task_name: &str) {}

    /// Called on task exit.
    fn on_task_exit(&self, _task_name: &str, _result: &Result<(), AsyncError>) {}

    /// Called after queue send.
    fn on_queue_send(&self, _queue_name: &str, _depth: usize, _capacity: usize) {}

    /// Called after queue receive.
    fn on_queue_receive(&self, _queue_name: &str, _depth: usize, _capacity: usize) {}
}

/// No-op hook implementation.
#[derive(Debug, Default)]
pub struct NoopInstrumentation;

impl Instrumentation for NoopInstrumentation {}

/// Runtime bridging helpers.
pub mod runtime {
    use super::{AsyncError, Future};

    pub use tokio::main;
    pub use tokio::runtime::{Builder, Runtime};
    pub use tokio::test;

    /// Execute a future from sync context.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Runtime`] when runtime setup is unavailable.
    pub fn block_on_sync<F>(future: F) -> Result<F::Output, AsyncError>
    where
        F: Future,
    {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return Ok(tokio::task::block_in_place(|| handle.block_on(future)));
            }

            return Err(AsyncError::Runtime {
                message: "cannot block_on_sync inside a current-thread runtime".to_string(),
            });
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| AsyncError::Runtime {
                message: err.to_string(),
            })?;
        Ok(runtime.block_on(future))
    }
}

/// Time/timer helpers.
pub mod time {
    use std::future::Future;
    use std::time::Duration;

    use super::AsyncError;

    pub use tokio::time::{Interval, Sleep};

    /// Sleep for a duration.
    pub fn sleep(duration: Duration) -> Sleep {
        tokio::time::sleep(duration)
    }

    /// Create interval ticker.
    #[must_use]
    pub fn interval(period: Duration) -> Interval {
        tokio::time::interval(period)
    }

    /// Timeout wrapper with normalized error mapping.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Timeout`] when elapsed.
    pub async fn timeout<T, F>(duration: Duration, future: F) -> Result<T, AsyncError>
    where
        F: Future<Output = T>,
    {
        tokio::time::timeout(duration, future)
            .await
            .map_err(|_| AsyncError::Timeout {
                timeout_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            })
    }
}

/// Absolute deadline wrapper used for deterministic timeout budgeting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    deadline_at: Instant,
}

impl Deadline {
    /// Create a deadline relative to now.
    #[must_use]
    pub fn after(timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            deadline_at: now.checked_add(timeout).unwrap_or(now),
        }
    }

    /// Create a deadline from an absolute instant.
    #[must_use]
    pub const fn at(deadline_at: Instant) -> Self {
        Self { deadline_at }
    }

    /// Return the remaining budget before timeout.
    #[must_use]
    pub fn remaining(self) -> Duration {
        self.deadline_at.saturating_duration_since(Instant::now())
    }

    /// Return true if deadline is already expired.
    #[must_use]
    pub fn is_expired(self) -> bool {
        self.remaining().is_zero()
    }

    /// Run a future under the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Timeout`] when deadline budget is exhausted.
    pub async fn run<T, F>(self, future: F) -> Result<T, AsyncError>
    where
        F: Future<Output = T>,
    {
        time::timeout(self.remaining(), future).await
    }
}

/// Scope classification for execution contexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextScope {
    /// Request-scoped foreground work with explicit deadline budget.
    Request,
    /// Background work that may be cancellation-bound without deadline.
    Background,
}

/// Propagated async context (cancellation + optional deadline + scope).
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    scope: ContextScope,
    cancellation: CancellationToken,
    deadline: Option<Deadline>,
}

impl ExecutionContext {
    /// Create a request-scoped context with fixed timeout budget.
    #[must_use]
    pub fn request_scoped(timeout: Duration) -> Self {
        Self {
            scope: ContextScope::Request,
            cancellation: CancellationToken::new(),
            deadline: Some(Deadline::after(timeout)),
        }
    }

    /// Create a background context (no deadline by default).
    #[must_use]
    pub fn background() -> Self {
        Self {
            scope: ContextScope::Background,
            cancellation: CancellationToken::new(),
            deadline: None,
        }
    }

    /// Create a child context inheriting cancellation and deadline.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            scope: self.scope,
            cancellation: self.cancellation.clone(),
            deadline: self.deadline,
        }
    }

    /// Set or replace the context deadline.
    #[must_use]
    pub fn with_deadline(mut self, timeout: Duration) -> Self {
        self.deadline = Some(Deadline::after(timeout));
        self
    }

    /// Context scope.
    #[must_use]
    pub const fn scope(&self) -> ContextScope {
        self.scope
    }

    /// Deadline, if present.
    #[must_use]
    pub const fn deadline(&self) -> Option<Deadline> {
        self.deadline
    }

    /// Remaining timeout budget, if deadline exists.
    #[must_use]
    pub fn remaining_budget(&self) -> Option<Duration> {
        self.deadline.map(Deadline::remaining)
    }

    /// Trigger cancellation on this context (and its descendants).
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Whether the context is already cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Subscribe to context cancellation.
    #[must_use]
    pub fn subscribe(&self) -> CancellationListener {
        self.cancellation.subscribe()
    }

    /// Run a future under this context.
    ///
    /// Cancellation is deterministic and takes precedence over deadline timeout.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] when cancellation is observed first, or
    /// [`AsyncError::Timeout`] when deadline expires first.
    pub async fn run<T, F>(&self, future: F) -> Result<T, AsyncError>
    where
        F: Future<Output = T>,
    {
        let mut listener = self.subscribe();
        if listener.is_cancelled() {
            return Err(AsyncError::Cancelled);
        }

        tokio::select! {
            biased;
            _ = listener.cancelled() => Err(AsyncError::Cancelled),
            output = async {
                match self.deadline {
                    Some(deadline) => deadline.run(future).await,
                    None => Ok(future.await),
                }
            } => output,
        }
    }

    /// Sleep for a duration under this context.
    ///
    /// # Errors
    ///
    /// Returns timeout/cancellation failures according to context semantics.
    pub async fn sleep(&self, duration: Duration) -> Result<(), AsyncError> {
        self.run(tokio::time::sleep(duration)).await
    }
}

/// Channel helpers and re-exports.
pub mod channel {
    use std::sync::Arc;

    use tokio::sync::mpsc::{self as tokio_mpsc, error::TrySendError};

    use super::{AsyncError, Instrumentation, NoopInstrumentation};

    pub use tokio::sync::{broadcast, mpsc, watch};

    /// Bounded sender with queue instrumentation hooks.
    #[derive(Clone)]
    pub struct BoundedSender<T> {
        name: String,
        capacity: usize,
        inner: tokio_mpsc::Sender<T>,
        instrumentation: Arc<dyn Instrumentation>,
    }

    impl<T> BoundedSender<T> {
        fn current_depth(&self) -> usize {
            self.capacity.saturating_sub(self.inner.capacity())
        }

        /// Send with backpressure.
        ///
        /// # Errors
        ///
        /// Returns [`AsyncError::ChannelClosed`] if receiver dropped.
        pub async fn send(&self, value: T) -> Result<(), AsyncError> {
            self.inner
                .send(value)
                .await
                .map_err(|_| AsyncError::ChannelClosed)?;

            self.instrumentation
                .on_queue_send(&self.name, self.current_depth(), self.capacity);
            Ok(())
        }

        /// Try send without waiting.
        ///
        /// # Errors
        ///
        /// Returns [`AsyncError::ChannelFull`] or [`AsyncError::ChannelClosed`].
        pub fn try_send(&self, value: T) -> Result<(), AsyncError> {
            match self.inner.try_send(value) {
                Ok(()) => {
                    self.instrumentation.on_queue_send(
                        &self.name,
                        self.current_depth(),
                        self.capacity,
                    );
                    Ok(())
                }
                Err(TrySendError::Closed(_)) => Err(AsyncError::ChannelClosed),
                Err(TrySendError::Full(_)) => Err(AsyncError::ChannelFull),
            }
        }
    }

    /// Bounded receiver with queue instrumentation hooks.
    pub struct BoundedReceiver<T> {
        name: String,
        capacity: usize,
        inner: tokio_mpsc::Receiver<T>,
        instrumentation: Arc<dyn Instrumentation>,
    }

    impl<T> BoundedReceiver<T> {
        fn current_depth(&self) -> usize {
            self.capacity.saturating_sub(self.inner.capacity())
        }

        /// Receive next queued item.
        pub async fn recv(&mut self) -> Option<T> {
            let item = self.inner.recv().await;
            self.instrumentation
                .on_queue_receive(&self.name, self.current_depth(), self.capacity);
            item
        }

        /// Close receiver side.
        pub fn close(&mut self) {
            self.inner.close();
        }
    }

    /// Create a bounded channel with no-op instrumentation.
    #[must_use]
    pub fn bounded<T>(
        name: impl Into<String>,
        capacity: usize,
    ) -> (BoundedSender<T>, BoundedReceiver<T>) {
        bounded_with_instrumentation(name, capacity, Arc::new(NoopInstrumentation))
    }

    /// Create a bounded channel with explicit instrumentation.
    #[must_use]
    pub fn bounded_with_instrumentation<T>(
        name: impl Into<String>,
        capacity: usize,
        instrumentation: Arc<dyn Instrumentation>,
    ) -> (BoundedSender<T>, BoundedReceiver<T>) {
        let name = name.into();
        let (sender, receiver) = tokio_mpsc::channel(capacity);
        (
            BoundedSender {
                name: name.clone(),
                capacity,
                inner: sender,
                instrumentation: Arc::clone(&instrumentation),
            },
            BoundedReceiver {
                name,
                capacity,
                inner: receiver,
                instrumentation,
            },
        )
    }
}

/// Helpers for watch-based shutdown propagation.
pub mod shutdown {
    use std::time::Duration;

    use super::{AsyncError, channel::watch};

    /// Wait until shutdown is signaled (`true`).
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] when shutdown is observed or sender drops.
    pub async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) -> Result<(), AsyncError> {
        if *shutdown.borrow() {
            return Err(AsyncError::Cancelled);
        }

        loop {
            shutdown
                .changed()
                .await
                .map_err(|_| AsyncError::Cancelled)?;
            if *shutdown.borrow() {
                return Err(AsyncError::Cancelled);
            }
        }
    }

    /// Sleep until duration elapses unless shutdown arrives first.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] when shutdown is observed before sleep completes.
    pub async fn sleep_or_shutdown(
        duration: Duration,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<(), AsyncError> {
        if *shutdown.borrow() {
            return Err(AsyncError::Cancelled);
        }

        tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => Err(AsyncError::Cancelled),
            () = tokio::time::sleep(duration) => Ok(()),
        }
    }
}

/// Synchronization re-exports.
pub mod sync {
    pub use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore};
}

/// Task re-exports.
pub mod task {
    pub use tokio::task::{JoinHandle, spawn, yield_now};
}

/// Tokio IO re-exports.
pub mod io {
    pub use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
}

/// Tokio process re-exports.
pub mod process {
    pub use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
}

/// Tokio net re-exports.
pub mod net {
    pub use tokio::net::{TcpListener, TcpStream};
}

/// Cooperative cancellation token.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    sender: channel::watch::Sender<bool>,
}

impl CancellationToken {
    /// Create token.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _receiver) = channel::watch::channel(false);
        Self { sender }
    }

    /// Trigger cancellation.
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    /// Current cancellation state.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    /// Subscribe cancellation updates.
    #[must_use]
    pub fn subscribe(&self) -> CancellationListener {
        CancellationListener {
            receiver: self.sender.subscribe(),
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Cancellation listener for a [`CancellationToken`].
#[derive(Debug)]
pub struct CancellationListener {
    receiver: channel::watch::Receiver<bool>,
}

impl CancellationListener {
    /// Current cancellation state.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Await cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError::Cancelled`] if sender side drops.
    pub async fn cancelled(&mut self) -> Result<(), AsyncError> {
        if *self.receiver.borrow() {
            return Ok(());
        }

        loop {
            self.receiver
                .changed()
                .await
                .map_err(|_| AsyncError::Cancelled)?;
            if *self.receiver.borrow() {
                return Ok(());
            }
        }
    }
}

/// Structured task group with cooperative shutdown.
pub struct TaskGroup {
    cancellation: CancellationToken,
    tasks: Vec<(String, tokio::task::JoinHandle<Result<(), AsyncError>>)>,
    instrumentation: Arc<dyn Instrumentation>,
}

impl TaskGroup {
    /// Create group with no-op hooks.
    #[must_use]
    pub fn new() -> Self {
        Self::with_instrumentation(Arc::new(NoopInstrumentation))
    }

    /// Create group with custom hooks.
    #[must_use]
    pub fn with_instrumentation(instrumentation: Arc<dyn Instrumentation>) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            tasks: Vec::new(),
            instrumentation,
        }
    }

    /// Get cancellation token.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Subscribe cancellation.
    #[must_use]
    pub fn subscribe_cancellation(&self) -> CancellationListener {
        self.cancellation.subscribe()
    }

    /// Spawn named task.
    pub fn spawn<F>(&mut self, name: impl Into<String>, future: F)
    where
        F: Future<Output = Result<(), AsyncError>> + Send + 'static,
    {
        let task_name = name.into();
        self.instrumentation.on_task_spawn(&task_name);

        let instrumentation = Arc::clone(&self.instrumentation);
        let hook_name = task_name.clone();
        let handle = tokio::task::spawn(async move {
            let result = future.await;
            instrumentation.on_task_exit(&hook_name, &result);
            result
        });

        self.tasks.push((task_name, handle));
    }

    /// Cancel and await tasks with timeout bound.
    ///
    /// # Errors
    ///
    /// Returns first error from task exit/join/timeout.
    pub async fn shutdown(mut self, timeout: Duration) -> Result<(), AsyncError> {
        self.cancellation.cancel();

        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let mut first_error: Option<AsyncError> = None;

        for (task_name, mut handle) in self.tasks.drain(..) {
            match tokio::time::timeout(timeout, &mut handle).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(err))) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
                Ok(Err(err)) => {
                    if first_error.is_none() {
                        first_error = Some(AsyncError::Join {
                            message: format!("{task_name}: {err}"),
                        });
                    }
                }
                Err(_) => {
                    handle.abort();
                    if first_error.is_none() {
                        first_error = Some(AsyncError::Timeout { timeout_ms });
                    }
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

impl Default for TaskGroup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::{
        sync::Arc,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::{
        AsyncError, CancellationToken, ContextScope, ExecutionContext, TaskGroup, channel, runtime,
        task, time,
    };

    #[runtime::test]
    async fn cancellation_propagates_to_all_listeners() {
        let token = CancellationToken::new();
        let mut listener_a = token.subscribe();
        let mut listener_b = token.subscribe();

        let task_a = task::spawn(async move { listener_a.cancelled().await });
        let task_b = task::spawn(async move { listener_b.cancelled().await });

        token.cancel();

        assert!(task_a.await.expect("join task_a").is_ok());
        assert!(task_b.await.expect("join task_b").is_ok());
    }

    #[runtime::test]
    async fn bounded_queue_enforces_capacity() {
        let (sender, mut receiver) = channel::bounded::<u8>("test-queue", 1);

        sender.try_send(1).expect("first send");
        let err = sender.try_send(2).expect_err("full queue should reject");
        assert!(matches!(err, AsyncError::ChannelFull));

        assert_eq!(receiver.recv().await, Some(1));
        sender.send(3).await.expect("send after drain");
        assert_eq!(receiver.recv().await, Some(3));
    }

    #[runtime::test]
    async fn task_group_structured_shutdown() {
        let mut group = TaskGroup::new();
        let mut shutdown = group.subscribe_cancellation();

        group.spawn("worker", async move {
            shutdown.cancelled().await?;
            Ok(())
        });

        let result = group.shutdown(Duration::from_millis(250)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn cancellation_storm_drains_task_group_without_orphans() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut group = TaskGroup::new();

        for index in 0..64 {
            let active = Arc::clone(&active);
            let mut listener = group.subscribe_cancellation();
            group.spawn(format!("worker-{index}"), async move {
                active.fetch_add(1, Ordering::SeqCst);
                let result = listener.cancelled().await;
                active.fetch_sub(1, Ordering::SeqCst);
                result
            });
        }

        task::yield_now().await;

        let shutdown = group.shutdown(Duration::from_secs(1)).await;
        assert!(shutdown.is_ok());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[runtime::test]
    async fn request_context_deadline_times_out() {
        let context = ExecutionContext::request_scoped(Duration::from_millis(10));
        let err = context
            .run(async {
                time::sleep(Duration::from_millis(50)).await;
            })
            .await
            .expect_err("deadline should timeout");
        assert!(matches!(err, AsyncError::Timeout { .. }));
        assert_eq!(context.scope(), ContextScope::Request);
    }

    #[runtime::test]
    async fn request_context_cancellation_precedes_deadline() {
        let context = ExecutionContext::request_scoped(Duration::from_secs(1));
        context.cancel();

        let err = context
            .run(async {
                time::sleep(Duration::from_secs(5)).await;
            })
            .await
            .expect_err("cancelled context should fail");

        assert_eq!(err, AsyncError::Cancelled);
    }
}
