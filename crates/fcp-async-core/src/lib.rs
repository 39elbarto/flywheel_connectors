//! Shared async runtime substrate for FCP crates.
//!
//! Provides unified entrypoints, task group APIs, timers, channels,
//! and cancellation helpers so all FCP components use a single
//! consistent async concurrency model.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

extern crate self as fcp_async_core;

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
    use std::cell::RefCell;
    use std::io;

    use asupersync::runtime::{
        Runtime as AsupersyncRuntime, RuntimeBuilder as AsupersyncRuntimeBuilder,
        RuntimeHandle as AsupersyncRuntimeHandle,
    };

    use super::{AsyncError, Future};

    pub use fcp_async_core_macros::{main, test};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RuntimeFlavor {
        CurrentThread,
        MultiThread,
    }

    #[derive(Clone)]
    struct RuntimeContext {
        handle: AsupersyncRuntimeHandle,
        flavor: RuntimeFlavor,
    }

    std::thread_local! {
        static CURRENT_RUNTIME: RefCell<Vec<RuntimeContext>> = const { RefCell::new(Vec::new()) };
    }

    struct RuntimeGuard;

    impl RuntimeGuard {
        fn enter(context: RuntimeContext) -> Self {
            CURRENT_RUNTIME.with(|slot| {
                slot.borrow_mut().push(context);
            });
            Self
        }
    }

    impl Drop for RuntimeGuard {
        fn drop(&mut self) {
            CURRENT_RUNTIME.with(|slot| {
                let _ = slot.borrow_mut().pop();
            });
        }
    }

    pub(crate) fn current_runtime_handle() -> Option<AsupersyncRuntimeHandle> {
        CURRENT_RUNTIME.with(|slot| slot.borrow().last().map(|context| context.handle.clone()))
    }

    /// Runtime builder abstraction owned by async-core.
    pub struct Builder {
        inner: AsupersyncRuntimeBuilder,
        flavor: RuntimeFlavor,
    }

    impl Builder {
        /// Create a single-threaded runtime builder.
        #[must_use]
        pub fn new_current_thread() -> Self {
            Self {
                inner: AsupersyncRuntimeBuilder::current_thread(),
                flavor: RuntimeFlavor::CurrentThread,
            }
        }

        /// Create a multi-threaded runtime builder.
        #[must_use]
        pub fn new_multi_thread() -> Self {
            Self {
                inner: AsupersyncRuntimeBuilder::multi_thread(),
                flavor: RuntimeFlavor::MultiThread,
            }
        }

        /// Enable all runtime services.
        #[must_use]
        pub const fn enable_all(self) -> Self {
            self
        }

        /// Enable time services.
        #[must_use]
        pub const fn enable_time(self) -> Self {
            self
        }

        /// Enable I/O services.
        #[must_use]
        pub const fn enable_io(self) -> Self {
            self
        }

        /// Build runtime.
        ///
        /// # Errors
        ///
        /// Returns I/O errors from runtime initialization.
        pub fn build(self) -> io::Result<Runtime> {
            self.inner
                .build()
                .map(|inner| Runtime {
                    inner,
                    flavor: self.flavor,
                })
                .map_err(|err| io::Error::other(err.to_string()))
        }
    }

    /// Runtime abstraction owned by async-core.
    pub struct Runtime {
        inner: AsupersyncRuntime,
        flavor: RuntimeFlavor,
    }

    impl std::fmt::Debug for Runtime {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Runtime")
                .field("flavor", &self.flavor)
                .finish_non_exhaustive()
        }
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
            let _guard = RuntimeGuard::enter(RuntimeContext {
                handle: self.inner.handle(),
                flavor: self.flavor,
            });
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
        if let Some(flavor) = CURRENT_RUNTIME.with(|slot| slot.borrow().last().map(|ctx| ctx.flavor))
        {
            let flavor_name = match flavor {
                RuntimeFlavor::CurrentThread => "current-thread",
                RuntimeFlavor::MultiThread => "multi-thread",
            };
            return Err(AsyncError::Runtime {
                message: format!("cannot block_on_sync inside an active {flavor_name} runtime"),
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
    use std::sync::OnceLock;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use asupersync::types::Time;

    use super::AsyncError;

    static TIMER_EPOCH: OnceLock<std::time::Instant> = OnceLock::new();

    fn wall_now() -> Time {
        let now = asupersync::time::wall_now();
        let _ = TIMER_EPOCH.get_or_init(std::time::Instant::now);
        now
    }

    fn instant_from_time(time: Time) -> std::time::Instant {
        let epoch = *TIMER_EPOCH.get_or_init(std::time::Instant::now);
        epoch
            .checked_add(Duration::from_nanos(time.as_nanos()))
            .unwrap_or(epoch)
    }

    /// Sleep future abstraction owned by async-core.
    pub struct Sleep {
        inner: Pin<Box<asupersync::time::Sleep>>,
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.inner.as_mut().poll(cx)
        }
    }

    /// Interval abstraction owned by async-core.
    pub struct Interval {
        inner: asupersync::time::Interval,
    }

    impl Interval {
        /// Wait for the next interval tick.
        pub async fn tick(&mut self) -> std::time::Instant {
            loop {
                let now = wall_now();
                if self.inner.is_ready(now) {
                    return instant_from_time(self.inner.tick(now));
                }

                asupersync::time::sleep_until(self.inner.deadline()).await;
            }
        }
    }

    /// Sleep for a duration.
    #[must_use]
    pub fn sleep(duration: Duration) -> Sleep {
        Sleep {
            inner: Box::pin(asupersync::time::sleep(wall_now(), duration)),
        }
    }

    /// Create interval ticker.
    #[must_use]
    pub fn interval(period: Duration) -> Interval {
        Interval {
            inner: asupersync::time::interval(wall_now(), period),
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
        AsyncError, CancellationToken, ContextScope, ExecutionContext, Instrumentation, TaskGroup,
        channel, runtime, task, time,
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

    // ─────────────────────────────────────────────────────────────────────
    // AsyncError enum coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn async_error_display_messages() {
        let timeout = AsyncError::Timeout { timeout_ms: 5000 };
        assert_eq!(timeout.to_string(), "operation timed out after 5000ms");

        let cancelled = AsyncError::Cancelled;
        assert_eq!(cancelled.to_string(), "operation cancelled");

        let closed = AsyncError::ChannelClosed;
        assert_eq!(closed.to_string(), "channel closed");

        let full = AsyncError::ChannelFull;
        assert_eq!(full.to_string(), "channel full");

        let io = AsyncError::ProtocolIo {
            message: "connection reset".into(),
        };
        assert_eq!(io.to_string(), "protocol io fault: connection reset");

        let join = AsyncError::Join {
            message: "task panicked".into(),
        };
        assert_eq!(join.to_string(), "task join failed: task panicked");

        let rt = AsyncError::Runtime {
            message: "no runtime".into(),
        };
        assert_eq!(rt.to_string(), "runtime failure: no runtime");
    }

    #[test]
    fn async_error_clone_and_eq() {
        let a = AsyncError::Timeout { timeout_ms: 100 };
        let b = a.clone();
        assert_eq!(a, b);

        assert_ne!(AsyncError::Cancelled, AsyncError::ChannelClosed);
        assert_ne!(AsyncError::ChannelFull, AsyncError::ChannelClosed);
    }

    #[test]
    fn async_error_debug_format() {
        let err = AsyncError::Timeout { timeout_ms: 42 };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Timeout"));
        assert!(dbg.contains("42"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Deadline coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn deadline_after_not_immediately_expired() {
        let d = super::Deadline::after(Duration::from_secs(10));
        assert!(!d.is_expired());
        assert!(d.remaining() > Duration::ZERO);
    }

    #[test]
    fn deadline_at_with_past_instant_is_expired() {
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let d = super::Deadline::at(past);
        assert!(d.is_expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn deadline_clone_and_eq() {
        let d1 = super::Deadline::after(Duration::from_secs(5));
        let d2 = d1;
        assert_eq!(d1, d2);
    }

    #[runtime::test]
    async fn deadline_run_succeeds_within_budget() {
        let d = super::Deadline::after(Duration::from_secs(5));
        let result = d.run(async { 42_u32 }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[runtime::test]
    async fn deadline_run_times_out_on_expired() {
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let d = super::Deadline::at(past);
        let err = d
            .run(async {
                time::sleep(Duration::from_secs(10)).await;
            })
            .await
            .expect_err("expired deadline should timeout");
        assert!(matches!(err, AsyncError::Timeout { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────
    // ContextScope coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn context_scope_eq_and_debug() {
        assert_eq!(ContextScope::Request, ContextScope::Request);
        assert_eq!(ContextScope::Background, ContextScope::Background);
        assert_ne!(ContextScope::Request, ContextScope::Background);
        let dbg = format!("{:?}", ContextScope::Request);
        assert!(dbg.contains("Request"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // ExecutionContext coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn background_context_no_deadline() {
        let ctx = ExecutionContext::background();
        assert_eq!(ctx.scope(), ContextScope::Background);
        assert!(ctx.deadline().is_none());
        assert!(ctx.remaining_budget().is_none());
    }

    #[runtime::test]
    async fn background_context_run_completes() {
        let ctx = ExecutionContext::background();
        let result = ctx.run(async { 99_u64 }).await;
        assert_eq!(result.unwrap(), 99);
    }

    #[runtime::test]
    async fn context_child_inherits_scope_and_cancellation() {
        let parent = ExecutionContext::request_scoped(Duration::from_secs(10));
        let child = parent.child();

        assert_eq!(child.scope(), ContextScope::Request);
        assert!(!child.is_cancelled());

        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[runtime::test]
    async fn context_with_deadline_replaces_existing() {
        let ctx = ExecutionContext::background().with_deadline(Duration::from_secs(30));
        assert!(ctx.deadline().is_some());
        assert!(ctx.remaining_budget().is_some());
    }

    #[runtime::test]
    async fn context_remaining_budget_decreases() {
        let ctx = ExecutionContext::request_scoped(Duration::from_millis(500));
        let budget_before = ctx.remaining_budget().unwrap();
        time::sleep(Duration::from_millis(50)).await;
        let budget_after = ctx.remaining_budget().unwrap();
        assert!(budget_after < budget_before);
    }

    #[runtime::test]
    async fn context_sleep_completes_within_budget() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        let result = ctx.sleep(Duration::from_millis(10)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn context_sleep_cancelled_returns_error() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(5));
        ctx.cancel();
        let err = ctx
            .sleep(Duration::from_secs(10))
            .await
            .expect_err("cancelled context sleep should fail");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn context_is_cancelled_reflects_state() {
        let ctx = ExecutionContext::request_scoped(Duration::from_secs(10));
        assert!(!ctx.is_cancelled());
        ctx.cancel();
        assert!(ctx.is_cancelled());
    }

    // ─────────────────────────────────────────────────────────────────────
    // CancellationToken & CancellationListener coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn cancellation_token_default() {
        let token = CancellationToken::default();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancellation_token_cancel_is_observable() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancellation_token_clone_shares_state() {
        let token = CancellationToken::new();
        let cloned = token.clone();
        token.cancel();
        assert!(cloned.is_cancelled());
    }

    #[runtime::test]
    async fn cancellation_listener_already_cancelled_returns_immediately() {
        let token = CancellationToken::new();
        token.cancel();

        let mut listener = token.subscribe();
        assert!(listener.is_cancelled());

        // cancelled() should return immediately
        let result = time::timeout(Duration::from_millis(100), listener.cancelled()).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn cancellation_listener_waits_for_cancel() {
        let token = CancellationToken::new();
        let mut listener = token.subscribe();
        assert!(!listener.is_cancelled());

        let token_clone = token.clone();
        task::spawn(async move {
            time::sleep(Duration::from_millis(20)).await;
            token_clone.cancel();
        });

        let result = time::timeout(Duration::from_secs(1), listener.cancelled()).await;
        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────
    // TaskGroup coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn task_group_default() {
        let group = TaskGroup::default();
        let result = group.shutdown(Duration::from_millis(100)).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn task_group_spawn_error_propagated() {
        let mut group = TaskGroup::new();

        group.spawn("failing-task", async {
            Err(AsyncError::Runtime {
                message: "deliberate failure".into(),
            })
        });

        let err = group
            .shutdown(Duration::from_secs(1))
            .await
            .expect_err("task error should propagate");
        assert!(matches!(err, AsyncError::Runtime { .. }));
    }

    #[runtime::test]
    async fn task_group_shutdown_timeout_aborts_hung_tasks() {
        let mut group = TaskGroup::new();

        group.spawn("hung-task", async {
            // Never completes
            future::pending::<Result<(), AsyncError>>().await
        });

        let err = group
            .shutdown(Duration::from_millis(50))
            .await
            .expect_err("hung task should cause timeout");
        assert!(matches!(err, AsyncError::Timeout { .. }));
    }

    #[runtime::test]
    async fn task_group_cancellation_token_shared() {
        let mut group = TaskGroup::new();
        let token = group.cancellation_token();
        let mut listener = group.subscribe_cancellation();

        group.spawn("watcher", async move {
            listener.cancelled().await?;
            Ok(())
        });

        assert!(!token.is_cancelled());
        let result = group.shutdown(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert!(token.is_cancelled());
    }

    #[runtime::test]
    async fn task_group_with_instrumentation_fires_hooks() {
        use std::sync::atomic::AtomicU32;

        struct CountingHooks {
            spawns: AtomicU32,
            exits: AtomicU32,
        }

        impl super::Instrumentation for CountingHooks {
            fn on_task_spawn(&self, _name: &str) {
                self.spawns.fetch_add(1, Ordering::SeqCst);
            }
            fn on_task_exit(&self, _name: &str, _result: &Result<(), AsyncError>) {
                self.exits.fetch_add(1, Ordering::SeqCst);
            }
        }

        let hooks = Arc::new(CountingHooks {
            spawns: AtomicU32::new(0),
            exits: AtomicU32::new(0),
        });
        let hooks_ref = Arc::clone(&hooks);

        let mut group = TaskGroup::with_instrumentation(hooks);
        group.spawn("task-a", async { Ok(()) });
        group.spawn("task-b", async { Ok(()) });

        group.shutdown(Duration::from_secs(1)).await.unwrap();

        assert_eq!(hooks_ref.spawns.load(Ordering::SeqCst), 2);
        assert_eq!(hooks_ref.exits.load(Ordering::SeqCst), 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Instrumentation trait coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn noop_instrumentation_default() {
        let noop = super::NoopInstrumentation;
        // All methods should be callable without panic
        noop.on_task_spawn("test");
        noop.on_task_exit("test", &Ok(()));
        noop.on_queue_send("q", 5, 10);
        noop.on_queue_receive("q", 4, 10);
    }

    // ─────────────────────────────────────────────────────────────────────
    // BoundedSender/BoundedReceiver coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn bounded_sender_closed_channel_error() {
        let (sender, receiver) = channel::bounded::<u32>("test", 4);
        drop(receiver);

        let err = sender
            .send(1)
            .await
            .expect_err("closed channel should fail");
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    #[runtime::test]
    async fn bounded_try_send_closed_channel() {
        let (sender, receiver) = channel::bounded::<u32>("test", 4);
        drop(receiver);

        let err = sender.try_send(1).expect_err("closed channel should fail");
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    #[runtime::test]
    async fn bounded_receiver_close_signals_sender() {
        let (sender, mut receiver) = channel::bounded::<u32>("test", 4);
        receiver.close();

        // Sender should eventually fail
        let err = sender
            .send(1)
            .await
            .expect_err("closed receiver should fail");
        assert_eq!(err, AsyncError::ChannelClosed);
    }

    #[runtime::test]
    async fn bounded_receiver_returns_none_when_sender_dropped() {
        let (sender, mut receiver) = channel::bounded::<u32>("test", 4);
        sender.send(1).await.unwrap();
        drop(sender);

        assert_eq!(receiver.recv().await, Some(1));
        assert_eq!(receiver.recv().await, None);
    }

    #[runtime::test]
    async fn bounded_with_instrumentation_fires_hooks() {
        use std::sync::atomic::AtomicU32;

        struct QueueHooks {
            sends: AtomicU32,
            recvs: AtomicU32,
        }

        impl super::Instrumentation for QueueHooks {
            fn on_queue_send(&self, _name: &str, _depth: usize, _capacity: usize) {
                self.sends.fetch_add(1, Ordering::SeqCst);
            }
            fn on_queue_receive(&self, _name: &str, _depth: usize, _capacity: usize) {
                self.recvs.fetch_add(1, Ordering::SeqCst);
            }
        }

        let hooks = Arc::new(QueueHooks {
            sends: AtomicU32::new(0),
            recvs: AtomicU32::new(0),
        });
        let hooks_ref = Arc::clone(&hooks);

        let (sender, mut receiver) =
            channel::bounded_with_instrumentation("instrumented", 4, hooks);

        sender.send(1).await.unwrap();
        sender.try_send(2).unwrap();
        receiver.recv().await;
        receiver.recv().await;

        assert_eq!(hooks_ref.sends.load(Ordering::SeqCst), 2);
        assert_eq!(hooks_ref.recvs.load(Ordering::SeqCst), 2);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Shutdown module coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn wait_for_shutdown_returns_immediately_if_already_set() {
        let (tx, mut rx) = channel::watch::channel(true);
        let _ = tx; // keep sender alive
        let err = super::shutdown::wait_for_shutdown(&mut rx)
            .await
            .expect_err("already-shutdown should return Cancelled");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn wait_for_shutdown_signals_on_true() {
        let (tx, mut rx) = channel::watch::channel(false);

        task::spawn(async move {
            time::sleep(Duration::from_millis(20)).await;
            tx.send_replace(true);
        });

        let err = super::shutdown::wait_for_shutdown(&mut rx)
            .await
            .expect_err("shutdown signal should return Cancelled");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn sleep_or_shutdown_completes_sleep() {
        let (_tx, mut rx) = channel::watch::channel(false);
        let result = super::shutdown::sleep_or_shutdown(Duration::from_millis(10), &mut rx).await;
        assert!(result.is_ok());
    }

    #[runtime::test]
    async fn sleep_or_shutdown_cancelled_by_shutdown() {
        let (tx, mut rx) = channel::watch::channel(false);

        task::spawn(async move {
            time::sleep(Duration::from_millis(10)).await;
            tx.send_replace(true);
        });

        let err = super::shutdown::sleep_or_shutdown(Duration::from_secs(60), &mut rx)
            .await
            .expect_err("shutdown should cancel sleep");
        assert_eq!(err, AsyncError::Cancelled);
    }

    #[runtime::test]
    async fn sleep_or_shutdown_already_shutdown() {
        let (_tx, mut rx) = channel::watch::channel(true);
        let err = super::shutdown::sleep_or_shutdown(Duration::from_secs(60), &mut rx)
            .await
            .expect_err("already-shutdown should return immediately");
        assert_eq!(err, AsyncError::Cancelled);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Runtime builder coverage
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn runtime_builder_current_thread() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current thread runtime");
        rt.block_on(async { 1 + 1 });
    }

    #[test]
    fn runtime_builder_multi_thread() {
        let rt = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("multi thread runtime");
        rt.block_on(async { 2 + 2 });
    }

    #[test]
    fn runtime_builder_enable_time_and_io() {
        let rt = runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .expect("runtime with time+io");
        rt.block_on(async { 3 + 3 });
    }

    #[test]
    fn runtime_new_default() {
        let rt = runtime::Runtime::new().expect("default runtime");
        let result = rt.block_on(async { 42 });
        assert_eq!(result, 42);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Channel sub-module factory coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn broadcast_channel_basic() {
        let (tx, mut rx1) = channel::broadcast::channel::<u32>(16);
        let mut rx2 = tx.subscribe();

        tx.send(42).unwrap();
        assert_eq!(rx1.recv().await.unwrap(), 42);
        assert_eq!(rx2.recv().await.unwrap(), 42);
    }

    #[runtime::test]
    async fn mpsc_channel_basic() {
        let (tx, mut rx) = channel::mpsc::channel::<u32>(8);
        tx.send(7).await.unwrap();
        assert_eq!(rx.recv().await, Some(7));
    }

    #[runtime::test]
    async fn mpsc_unbounded_channel_basic() {
        let (tx, mut rx) = channel::mpsc::unbounded_channel::<u32>();
        tx.send(99).unwrap();
        assert_eq!(rx.recv().await, Some(99));
    }

    #[runtime::test]
    async fn oneshot_channel_basic() {
        let (tx, rx) = channel::oneshot::channel::<String>();
        tx.send("hello".into()).unwrap();
        assert_eq!(rx.await.unwrap(), "hello");
    }

    #[runtime::test]
    async fn watch_channel_basic() {
        let (tx, mut rx) = channel::watch::channel(0_u32);
        assert_eq!(*rx.borrow(), 0);

        tx.send_replace(42);
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow(), 42);
    }

    // ─────────────────────────────────────────────────────────────────────
    // block_on_sync edge case: current-thread rejection
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn block_on_sync_rejects_current_thread_runtime() {
        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let err = runtime::block_on_sync(async { 1 })
                .expect_err("block_on_sync in current-thread should fail");
            assert!(matches!(err, AsyncError::Runtime { .. }));
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Time module coverage
    // ─────────────────────────────────────────────────────────────────────

    #[runtime::test]
    async fn sleep_zero_completes_immediately() {
        time::sleep(Duration::ZERO).await;
    }

    #[runtime::test]
    async fn interval_ticks_repeatedly() {
        let mut interval = time::interval(Duration::from_millis(10));
        interval.tick().await; // first tick is immediate
        interval.tick().await; // second tick after delay
    }

    #[runtime::test]
    async fn timeout_succeeds_when_future_completes_fast() {
        let result = time::timeout(Duration::from_secs(5), async { 42_u32 }).await;
        assert_eq!(result.unwrap(), 42);
    }
}
