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

#[doc(hidden)]
pub mod __private {
    pub use tokio;
}

/// `select!` macro routed through the async-core substrate.
#[macro_export]
macro_rules! select {
    ($($tokens:tt)*) => {
        $crate::__private::tokio::select! { $($tokens)* }
    };
}

/// `task_local!` macro routed through the async-core substrate.
#[macro_export]
macro_rules! task_local {
    ($($tokens:tt)*) => {
        $crate::__private::tokio::task_local! { $($tokens)* }
    };
}

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
    use std::io;

    use super::{AsyncError, Future};

    pub use tokio::main;
    pub use tokio::test;

    /// Runtime builder abstraction owned by async-core.
    pub struct Builder {
        inner: tokio::runtime::Builder,
    }

    impl Builder {
        /// Create a single-threaded runtime builder.
        #[must_use]
        pub fn new_current_thread() -> Self {
            Self {
                inner: tokio::runtime::Builder::new_current_thread(),
            }
        }

        /// Create a multi-threaded runtime builder.
        #[must_use]
        pub fn new_multi_thread() -> Self {
            Self {
                inner: tokio::runtime::Builder::new_multi_thread(),
            }
        }

        /// Enable all Tokio drivers.
        #[must_use]
        pub fn enable_all(mut self) -> Self {
            self.inner.enable_all();
            self
        }

        /// Enable Tokio time driver.
        #[must_use]
        pub fn enable_time(mut self) -> Self {
            self.inner.enable_time();
            self
        }

        /// Enable Tokio I/O driver.
        #[must_use]
        pub fn enable_io(mut self) -> Self {
            self.inner.enable_io();
            self
        }

        /// Build runtime.
        ///
        /// # Errors
        ///
        /// Returns I/O errors from runtime initialization.
        pub fn build(mut self) -> io::Result<Runtime> {
            self.inner.build().map(|inner| Runtime { inner })
        }
    }

    /// Runtime abstraction owned by async-core.
    #[derive(Debug)]
    pub struct Runtime {
        inner: tokio::runtime::Runtime,
    }

    impl Runtime {
        /// Create a default multi-thread runtime with all drivers enabled.
        ///
        /// # Errors
        ///
        /// Returns I/O errors from runtime initialization.
        pub fn new() -> io::Result<Self> {
            Builder::new_multi_thread().enable_all().build()
        }

        /// Block on a future.
        pub fn block_on<F>(&self, future: F) -> F::Output
        where
            F: Future,
        {
            self.inner.block_on(future)
        }
    }

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

        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| AsyncError::Runtime {
                message: format!("failed to build runtime: {err}"),
            })?;
        Ok(runtime.block_on(future))
    }
}

/// Time/timer helpers.
pub mod time {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use super::AsyncError;

    /// Sleep future abstraction owned by async-core.
    pub struct Sleep {
        inner: Pin<Box<tokio::time::Sleep>>,
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.inner.as_mut().poll(cx)
        }
    }

    /// Interval abstraction owned by async-core.
    pub struct Interval {
        inner: tokio::time::Interval,
    }

    impl Interval {
        /// Wait for the next interval tick.
        pub async fn tick(&mut self) -> std::time::Instant {
            self.inner.tick().await.into()
        }
    }

    /// Sleep for a duration.
    #[must_use]
    pub fn sleep(duration: Duration) -> Sleep {
        Sleep {
            inner: Box::pin(tokio::time::sleep(duration)),
        }
    }

    /// Create interval ticker.
    #[must_use]
    pub fn interval(period: Duration) -> Interval {
        Interval {
            inner: tokio::time::interval(period),
        }
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
        asupersync::time::timeout(asupersync::time::wall_now(), duration, future)
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

        crate::select! {
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
        self.run(time::sleep(duration)).await
    }
}

/// Channel helpers and re-exports.
pub mod channel {
    use std::sync::Arc;

    use tokio::sync::mpsc::{self as tokio_mpsc, error::TrySendError};

    use super::{AsyncError, Instrumentation, NoopInstrumentation};

    /// Tokio broadcast compatibility surface owned by async-core.
    pub mod broadcast {
        pub type Sender<T> = tokio::sync::broadcast::Sender<T>;
        pub type Receiver<T> = tokio::sync::broadcast::Receiver<T>;

        pub mod error {
            pub type RecvError = tokio::sync::broadcast::error::RecvError;
            pub type SendError<T> = tokio::sync::broadcast::error::SendError<T>;
        }

        /// Create a bounded broadcast channel.
        #[must_use]
        pub fn channel<T: Clone>(capacity: usize) -> (Sender<T>, Receiver<T>) {
            tokio::sync::broadcast::channel(capacity)
        }
    }

    /// Tokio mpsc compatibility surface owned by async-core.
    pub mod mpsc {
        pub type Sender<T> = tokio::sync::mpsc::Sender<T>;
        pub type Receiver<T> = tokio::sync::mpsc::Receiver<T>;
        pub type UnboundedSender<T> = tokio::sync::mpsc::UnboundedSender<T>;
        pub type UnboundedReceiver<T> = tokio::sync::mpsc::UnboundedReceiver<T>;

        pub mod error {
            pub type SendError<T> = tokio::sync::mpsc::error::SendError<T>;
            pub type TrySendError<T> = tokio::sync::mpsc::error::TrySendError<T>;
            pub type TryRecvError = tokio::sync::mpsc::error::TryRecvError;
        }

        /// Create a bounded mpsc channel.
        #[must_use]
        pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
            tokio::sync::mpsc::channel(capacity)
        }

        /// Create an unbounded mpsc channel.
        #[must_use]
        pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
            tokio::sync::mpsc::unbounded_channel()
        }
    }

    /// Tokio oneshot compatibility surface owned by async-core.
    pub mod oneshot {
        pub type Sender<T> = tokio::sync::oneshot::Sender<T>;
        pub type Receiver<T> = tokio::sync::oneshot::Receiver<T>;

        pub mod error {
            pub type RecvError = tokio::sync::oneshot::error::RecvError;
        }

        /// Create a one-shot channel.
        #[must_use]
        pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
            tokio::sync::oneshot::channel()
        }
    }

    /// Tokio watch compatibility surface owned by async-core.
    pub mod watch {
        pub type Sender<T> = tokio::sync::watch::Sender<T>;
        pub type Receiver<T> = tokio::sync::watch::Receiver<T>;
        pub type Ref<'a, T> = tokio::sync::watch::Ref<'a, T>;

        pub mod error {
            pub type RecvError = tokio::sync::watch::error::RecvError;
            pub type SendError<T> = tokio::sync::watch::error::SendError<T>;
        }

        /// Create a watch channel.
        #[must_use]
        pub fn channel<T>(value: T) -> (Sender<T>, Receiver<T>) {
            tokio::sync::watch::channel(value)
        }
    }

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

    use super::{AsyncError, channel::watch, time};

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

        crate::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => Err(AsyncError::Cancelled),
            () = time::sleep(duration) => Ok(()),
        }
    }
}

/// Synchronization compatibility surface owned by async-core.
pub mod sync {
    pub type Mutex<T> = tokio::sync::Mutex<T>;
    pub type OwnedSemaphorePermit = tokio::sync::OwnedSemaphorePermit;
    pub type RwLock<T> = tokio::sync::RwLock<T>;
    pub type Semaphore = tokio::sync::Semaphore;
}

/// Task compatibility surface owned by async-core.
pub mod task {
    use std::future::Future;

    pub type JoinHandle<T> = tokio::task::JoinHandle<T>;

    /// Spawn an asynchronous task.
    pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::task::spawn(future)
    }

    /// Cooperatively yield execution.
    pub async fn yield_now() {
        tokio::task::yield_now().await;
    }
}

/// Tokio IO re-exports.
pub mod io {
    pub use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    pub type BufReader<R> = tokio::io::BufReader<R>;
}

/// Tokio process re-exports.
pub mod process {
    pub type Child = tokio::process::Child;
    pub type ChildStderr = tokio::process::ChildStderr;
    pub type ChildStdin = tokio::process::ChildStdin;
    pub type ChildStdout = tokio::process::ChildStdout;
    pub type Command = tokio::process::Command;
}

/// Tokio net re-exports.
pub mod net {
    pub type TcpListener = tokio::net::TcpListener;
    pub type TcpStream = tokio::net::TcpStream;
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
    tasks: Vec<(String, task::JoinHandle<Result<(), AsyncError>>)>,
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
        let handle = task::spawn(async move {
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
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(std::time::Instant::now);
        let mut first_error: Option<AsyncError> = None;

        for (task_name, mut handle) in self.tasks.drain(..) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match time::timeout(remaining, &mut handle).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Err(err)) => {
                    if first_error.is_none() {
                        first_error = Some(AsyncError::Join {
                            message: format!("{task_name}: {err}"),
                        });
                    }
                }
                Err(AsyncError::Timeout { .. }) => {
                    handle.abort();
                    if first_error.is_none() {
                        first_error = Some(AsyncError::Timeout { timeout_ms });
                    }
                }
                Ok(Ok(Err(err))) | Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
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
    use std::future;
    use std::time::Duration;
    use std::{
        sync::Arc,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::{
        AsyncError, CancellationToken, ContextScope, ExecutionContext, TaskGroup, channel, runtime,
        task, time,
    };

    #[test]
    fn block_on_sync_executes_outside_tokio_runtime() {
        let output = runtime::block_on_sync(async { 7_u8 }).expect("block_on_sync should succeed");
        assert_eq!(output, 7);
    }

    #[test]
    fn block_on_sync_supports_io_driver() {
        let result = runtime::block_on_sync(async {
            let listener = super::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind local listener");
            drop(listener);
        });
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn timeout_maps_elapsed_to_async_error() {
        let timeout_result = time::timeout(Duration::from_millis(5), future::pending::<()>()).await;
        assert!(matches!(timeout_result, Err(AsyncError::Timeout { .. })));
    }

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
