//! Stream processing utilities.
//!
//! Provides common stream operations and transformations.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use fcp_async_core::time::{Sleep, sleep};
use futures_util::stream::Stream;
use pin_project_lite::pin_project;

use crate::{StreamError, StreamResult};

/// Extension trait for streams.
pub trait StreamExt: Stream {
    /// Add timeout to stream items.
    fn with_timeout(self, timeout: Duration) -> TimeoutStream<Self>
    where
        Self: Sized,
    {
        TimeoutStream::new(self, timeout)
    }

    /// Buffer stream items.
    fn buffered_batches(self, max_size: usize, max_wait: Duration) -> BatchStream<Self>
    where
        Self: Sized,
        Self::Item: Clone,
    {
        BatchStream::new(self, max_size, max_wait)
    }
}

impl<S: Stream> StreamExt for S {}

pin_project! {
    /// Stream with per-item timeout.
    pub struct TimeoutStream<S> {
        #[pin]
        inner: S,
        timeout: Duration,
        #[pin]
        deadline: Option<Sleep>,
    }
}

impl<S> TimeoutStream<S> {
    /// Create a new timeout stream.
    pub const fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            deadline: None,
        }
    }
}

impl<S: Stream> Stream for TimeoutStream<S> {
    type Item = StreamResult<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Initialize deadline if not set
        if this.deadline.is_none() {
            this.deadline.set(Some(sleep(*this.timeout)));
        }

        // Check timeout
        if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
            if deadline.poll(cx).is_ready() {
                return Poll::Ready(Some(Err(StreamError::Timeout(*this.timeout))));
            }
        }

        // Poll inner stream
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                // Reset deadline
                this.deadline.set(Some(sleep(*this.timeout)));
                Poll::Ready(Some(Ok(item)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pin_project! {
    /// Stream that batches items.
    pub struct BatchStream<S: Stream> {
        #[pin]
        inner: S,
        max_size: usize,
        max_wait: Duration,
        batch: Vec<S::Item>,
        #[pin]
        deadline: Option<Sleep>,
    }
}

impl<S: Stream> BatchStream<S>
where
    S::Item: Clone,
{
    /// Create a new batch stream.
    pub fn new(inner: S, max_size: usize, max_wait: Duration) -> Self {
        Self {
            inner,
            max_size,
            max_wait,
            batch: Vec::with_capacity(max_size),
            deadline: None,
        }
    }
}

impl<S: Stream> Stream for BatchStream<S>
where
    S::Item: Clone,
{
    type Item = Vec<S::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            // Check if batch is full
            if this.batch.len() >= *this.max_size {
                let batch = std::mem::take(this.batch);
                *this.batch = Vec::with_capacity(*this.max_size);
                this.deadline.set(None);
                return Poll::Ready(Some(batch));
            }

            // Check timeout
            if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
                if deadline.poll(cx).is_ready() {
                    if !this.batch.is_empty() {
                        let batch = std::mem::take(this.batch);
                        *this.batch = Vec::with_capacity(*this.max_size);
                        this.deadline.set(None);
                        return Poll::Ready(Some(batch));
                    }
                    this.deadline.set(None);
                }
            }

            // Poll inner stream
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    // Start deadline on first item
                    if this.batch.is_empty() && this.deadline.is_none() {
                        this.deadline.set(Some(sleep(*this.max_wait)));
                    }
                    this.batch.push(item);
                }
                Poll::Ready(None) => {
                    // Stream ended, return remaining items
                    if this.batch.is_empty() {
                        return Poll::Ready(None);
                    }
                    let batch = std::mem::take(this.batch);
                    return Poll::Ready(Some(batch));
                }
                Poll::Pending => {
                    // If we have items and deadline passed, return them
                    if !this.batch.is_empty() {
                        if let Some(deadline) = this.deadline.as_mut().as_pin_mut() {
                            if deadline.poll(cx).is_ready() {
                                let batch = std::mem::take(this.batch);
                                *this.batch = Vec::with_capacity(*this.max_size);
                                this.deadline.set(None);
                                return Poll::Ready(Some(batch));
                            }
                        }
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

/// Counting stream that tracks items processed.
#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    items_count: usize,
}

impl<S> CountingStream<S> {
    /// Create a new counting stream.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            items_count: 0,
        }
    }

    /// Get the current count of processed items.
    #[must_use]
    pub const fn items_count(&self) -> usize {
        self.items_count
    }
}

impl<S: Stream + Unpin> Stream for CountingStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                self.items_count += 1;
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

pin_project! {
    /// Rate-limited stream.
    ///
    /// Ensures minimum interval between stream items.
    pub struct RateLimitedStream<S> {
        #[pin]
        inner: S,
        interval: Duration,
        #[pin]
        delay: Option<Sleep>,
    }
}

impl<S> RateLimitedStream<S> {
    /// Create a new rate-limited stream.
    pub const fn new(inner: S, interval: Duration) -> Self {
        Self {
            inner,
            interval,
            delay: None,
        }
    }
}

impl<S: Stream> Stream for RateLimitedStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // If there's a pending delay, wait for it
        if let Some(delay) = this.delay.as_mut().as_pin_mut() {
            match delay.poll(cx) {
                Poll::Ready(()) => {
                    this.delay.set(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        match this.inner.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                // Schedule delay for next item
                this.delay.set(Some(sleep(*this.interval)));
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::pin_mut;
    use futures_util::stream::{self, StreamExt as _};

    #[fcp_async_core::runtime::test]
    async fn test_counting_stream() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5]);
        let mut counting = CountingStream::new(stream);

        assert_eq!(counting.items_count(), 0);

        while counting.next().await.is_some() {}

        assert_eq!(counting.items_count(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn test_timeout_stream_success() {
        let stream = stream::iter(vec![1, 2, 3]);
        let timeout_stream = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(timeout_stream);

        let mut results = Vec::new();
        while let Some(result) = timeout_stream.next().await {
            results.push(result.unwrap());
        }

        assert_eq!(results, vec![1, 2, 3]);
    }

    // ── New tests ──

    #[fcp_async_core::runtime::test]
    async fn test_counting_stream_empty() {
        let stream = stream::empty::<i32>();
        let mut counting = CountingStream::new(stream);
        assert!(counting.next().await.is_none());
        assert_eq!(counting.items_count(), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn test_counting_stream_increments() {
        let stream = stream::iter(vec![10, 20]);
        let mut counting = CountingStream::new(stream);

        assert_eq!(counting.items_count(), 0);
        let _ = counting.next().await;
        assert_eq!(counting.items_count(), 1);
        let _ = counting.next().await;
        assert_eq!(counting.items_count(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited_stream() {
        let stream = stream::iter(vec![1, 2, 3]);
        let rate_limited = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rate_limited);

        let mut results = Vec::new();
        while let Some(item) = rate_limited.next().await {
            results.push(item);
        }
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_stream_ext_with_timeout() {
        let stream = stream::iter(vec![1, 2, 3]);
        let timeout_stream = super::StreamExt::with_timeout(stream, Duration::from_secs(1));
        pin_mut!(timeout_stream);

        let mut results = Vec::new();
        while let Some(result) = timeout_stream.next().await {
            results.push(result.unwrap());
        }
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[fcp_async_core::runtime::test]
    async fn test_timeout_stream_empty() {
        let stream = stream::empty::<i32>();
        let timeout_stream = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(timeout_stream);

        let result = timeout_stream.next().await;
        assert!(result.is_none());
    }

    // ── RateLimitedStream tests ──

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_empty() {
        let stream = stream::empty::<i32>();
        let rl = RateLimitedStream::new(stream, Duration::from_millis(10));
        pin_mut!(rl);

        assert!(rl.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_single_item() {
        let stream = stream::iter(vec![42]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        assert_eq!(rl.next().await, Some(42));
        assert!(rl.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_preserves_order() {
        let stream = stream::iter(vec![10, 20, 30, 40, 50]);
        let rl = RateLimitedStream::new(stream, Duration::from_millis(1));
        pin_mut!(rl);

        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        assert_eq!(items, vec![10, 20, 30, 40, 50]);
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_enforces_interval() {
        let stream = stream::iter(vec![1, 2, 3]);
        let interval = Duration::from_millis(50);
        let rl = RateLimitedStream::new(stream, interval);
        pin_mut!(rl);

        let start = std::time::Instant::now();
        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        let elapsed = start.elapsed();

        assert_eq!(items, vec![1, 2, 3]);
        // With 3 items and 50ms interval, after item 1 and 2 we wait 50ms each = ~100ms minimum
        assert!(
            elapsed >= Duration::from_millis(80),
            "expected >=80ms, got {elapsed:?}"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn rate_limited_stream_zero_interval() {
        let stream = stream::iter(vec![1, 2, 3]);
        let rl = RateLimitedStream::new(stream, Duration::ZERO);
        pin_mut!(rl);

        let mut items = Vec::new();
        while let Some(item) = rl.next().await {
            items.push(item);
        }
        assert_eq!(items, vec![1, 2, 3]);
    }

    // ── BatchStream tests ──

    #[fcp_async_core::runtime::test]
    async fn batch_stream_full_batch() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5, 6]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        let batch1 = batched.next().await.unwrap();
        assert_eq!(batch1, vec![1, 2, 3]);

        let batch2 = batched.next().await.unwrap();
        assert_eq!(batch2, vec![4, 5, 6]);

        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_partial_at_end() {
        let stream = stream::iter(vec![1, 2, 3, 4, 5]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        let batch1 = batched.next().await.unwrap();
        assert_eq!(batch1, vec![1, 2, 3]);

        // Remaining items at stream end
        let batch2 = batched.next().await.unwrap();
        assert_eq!(batch2, vec![4, 5]);

        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_empty() {
        let stream = stream::empty::<i32>();
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_single_item_end() {
        let stream = stream::iter(vec![42]);
        let batched = BatchStream::new(stream, 5, Duration::from_secs(10));
        pin_mut!(batched);

        let batch = batched.next().await.unwrap();
        assert_eq!(batch, vec![42]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_exact_batch_size() {
        let stream = stream::iter(vec![1, 2, 3]);
        let batched = BatchStream::new(stream, 3, Duration::from_secs(10));
        pin_mut!(batched);

        let batch = batched.next().await.unwrap();
        assert_eq!(batch, vec![1, 2, 3]);
        assert!(batched.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn batch_stream_max_size_one() {
        let stream = stream::iter(vec![1, 2, 3]);
        let batched = BatchStream::new(stream, 1, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![1]);
        assert_eq!(batched.next().await.unwrap(), vec![2]);
        assert_eq!(batched.next().await.unwrap(), vec![3]);
        assert!(batched.next().await.is_none());
    }

    // ── CountingStream additional tests ──

    #[fcp_async_core::runtime::test]
    async fn counting_stream_single_item() {
        let stream = stream::iter(vec![99]);
        let mut counting = CountingStream::new(stream);

        assert_eq!(counting.items_count(), 0);
        assert_eq!(counting.next().await, Some(99));
        assert_eq!(counting.items_count(), 1);
        assert!(counting.next().await.is_none());
        // Count doesn't change after stream ends
        assert_eq!(counting.items_count(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn counting_stream_count_persists_after_exhaustion() {
        let stream = stream::iter(vec![1, 2, 3]);
        let mut counting = CountingStream::new(stream);

        while counting.next().await.is_some() {}
        assert_eq!(counting.items_count(), 3);

        // Additional polls don't change count
        assert!(counting.next().await.is_none());
        assert_eq!(counting.items_count(), 3);
    }

    // ── StreamExt trait tests ──

    #[fcp_async_core::runtime::test]
    async fn stream_ext_buffered_batches() {
        let stream = stream::iter(vec![1, 2, 3, 4]);
        let batched = super::StreamExt::buffered_batches(stream, 2, Duration::from_secs(10));
        pin_mut!(batched);

        assert_eq!(batched.next().await.unwrap(), vec![1, 2]);
        assert_eq!(batched.next().await.unwrap(), vec![3, 4]);
        assert!(batched.next().await.is_none());
    }

    // ── TimeoutStream additional tests ──

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_single_item() {
        let stream = stream::iter(vec![42]);
        let ts = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(ts);

        assert_eq!(ts.next().await.unwrap().unwrap(), 42);
        assert!(ts.next().await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn timeout_stream_wraps_items_in_ok() {
        let stream = stream::iter(vec![1, 2]);
        let ts = TimeoutStream::new(stream, Duration::from_secs(1));
        pin_mut!(ts);

        // Each item should be Ok-wrapped
        let r1 = ts.next().await.unwrap();
        assert!(r1.is_ok());
        let r2 = ts.next().await.unwrap();
        assert!(r2.is_ok());
    }
}
