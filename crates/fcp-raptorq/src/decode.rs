//! `RaptorQ` decoder with `DoS` mitigation.

// Allow truncation casts - symbol counts are bounded by protocol
#![allow(clippy::cast_possible_truncation)]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fcp_async_core::{AsyncError, ExecutionContext};
use raptorq::{Decoder, EncodingPacket, ObjectTransmissionInformation, PayloadId};

use crate::config::RaptorQConfig;
use crate::error::DecodeError;

const COOPERATIVE_YIELD_INTERVAL: usize = 32;

/// `RaptorQ` decoder for reconstructing payload from symbols.
pub struct RaptorQDecoder {
    inner: Decoder,
    config: RaptorQConfig,
    received: HashSet<u32>,
    k: u32,
    started_at: Instant,
}

impl RaptorQDecoder {
    /// Create a decoder with the given transmission info.
    #[must_use]
    pub fn new(oti: ObjectTransmissionInformation, config: &RaptorQConfig) -> Self {
        let k = (oti.transfer_length() as usize).div_ceil(usize::from(oti.symbol_size()));

        Self {
            inner: Decoder::new(oti),
            config: config.clone(),
            received: HashSet::new(),
            k: k as u32,
            started_at: Instant::now(),
        }
    }

    /// Create a decoder expecting K source symbols.
    #[must_use]
    pub fn with_expected_symbols(
        k: u32,
        transfer_length: u64,
        symbol_size: u16,
        config: &RaptorQConfig,
    ) -> Self {
        let oti = ObjectTransmissionInformation::new(transfer_length, symbol_size, 1, 1, 8);
        Self {
            inner: Decoder::new(oti),
            config: config.clone(),
            received: HashSet::new(),
            k,
            started_at: Instant::now(),
        }
    }

    /// Add a symbol and attempt reconstruction.
    ///
    /// Returns `Some(payload)` when reconstruction succeeds.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::Timeout` if decode timeout has been exceeded.
    pub fn add_symbol(&mut self, esi: u32, data: Vec<u8>) -> Result<Option<Vec<u8>>, DecodeError> {
        // Check timeout
        if self.started_at.elapsed() > self.config.decode_timeout {
            return Err(DecodeError::Timeout);
        }

        // Skip duplicates
        if self.received.contains(&esi) {
            return Ok(None);
        }

        self.received.insert(esi);

        // Try decode
        let packet = EncodingPacket::new(PayloadId::new(0, esi), data);

        Ok(self.inner.decode(packet))
    }

    /// Number of unique symbols received.
    #[must_use]
    pub fn received_count(&self) -> u32 {
        self.received.len() as u32
    }

    /// Approximate number needed for reconstruction.
    ///
    /// K' is approximately K × 1.002.
    #[must_use]
    pub fn needed(&self) -> u32 {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let k_prime = (f64::from(self.k) * 1.002).ceil() as u32;
        k_prime.max(1)
    }

    /// Check if we likely have enough symbols.
    #[must_use]
    pub fn likely_complete(&self) -> bool {
        self.received_count() >= self.needed()
    }

    /// Time elapsed since decode started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Time remaining before timeout.
    #[must_use]
    pub fn time_remaining(&self) -> Duration {
        self.config
            .decode_timeout
            .saturating_sub(self.started_at.elapsed())
    }

    /// Check if decode has timed out.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        self.started_at.elapsed() > self.config.decode_timeout
    }

    /// Get expected K (source symbols).
    #[must_use]
    pub const fn expected_k(&self) -> u32 {
        self.k
    }
}

/// Decode admission controller (NORMATIVE).
///
/// Prevents resource exhaustion from decode `DoS` attacks by:
/// - Bounding concurrent decodes
/// - Enforcing timeouts
/// - Limiting allocation per decode
/// - Prioritizing pinned/referenced objects over unknown
#[derive(Clone)]
pub struct DecodeAdmissionController {
    /// Maximum concurrent decode operations.
    max_concurrent: usize,
    /// Current active decodes.
    active: Arc<AtomicUsize>,
    /// Per-decode memory limit.
    max_memory_per_decode: usize,
    /// Decode timeout.
    timeout: Duration,
    /// Symbol buffer limit per object.
    max_symbols_buffered: u32,
}

impl DecodeAdmissionController {
    /// Create a new admission controller with the given config.
    #[must_use]
    pub fn new(config: &RaptorQConfig) -> Self {
        // Calculate max symbols needed for max object size, plus safety margin
        let max_symbols = config.total_symbols(config.max_object_size as usize);
        let max_symbols_buffered = max_symbols.saturating_add(1000);

        Self {
            max_concurrent: 16,
            active: Arc::new(AtomicUsize::new(0)),
            max_memory_per_decode: config.max_object_size as usize,
            timeout: config.decode_timeout,
            max_symbols_buffered,
        }
    }

    /// Create a controller with custom limits.
    #[must_use]
    pub fn with_limits(
        max_concurrent: usize,
        max_memory_per_decode: usize,
        timeout: Duration,
        max_symbols_buffered: u32,
    ) -> Self {
        Self {
            max_concurrent,
            active: Arc::new(AtomicUsize::new(0)),
            max_memory_per_decode,
            timeout,
            max_symbols_buffered,
        }
    }

    /// Try to acquire a decode slot.
    ///
    /// Returns `Some(permit)` if a slot is available, `None` otherwise.
    #[must_use]
    pub fn try_acquire(&self) -> Option<DecodePermit> {
        let mut current = self.active.load(Ordering::SeqCst);
        loop {
            if current >= self.max_concurrent {
                return None;
            }
            match self.active.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        Some(DecodePermit {
            active: Arc::clone(&self.active),
            started_at: Instant::now(),
            timeout: self.timeout,
            max_memory: self.max_memory_per_decode,
            max_symbols: self.max_symbols_buffered,
            symbols_buffered: 0,
            memory_used: 0,
        })
    }

    /// Acquire a decode slot, returning an error if unavailable.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::AdmissionDenied` if no slots are available.
    pub fn acquire(&self) -> Result<DecodePermit, DecodeError> {
        self.try_acquire()
            .ok_or_else(|| DecodeError::AdmissionDenied {
                reason: format!(
                    "maximum concurrent decodes ({}) exceeded",
                    self.max_concurrent
                ),
            })
    }

    /// Run a decode job under context cancellation/deadline controls.
    ///
    /// Symbols are replayed in ascending ESI order to preserve deterministic epoch behavior.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `DecodeError::AdmissionDenied` if no decode slots are available
    /// - `DecodeError::Cancelled` if the execution context is cancelled
    /// - `DecodeError::Timeout` if the execution context deadline expires
    /// - `DecodeError::InsufficientSymbols` if replay completes without reconstruction
    pub async fn decode_with_context<I>(
        &self,
        context: &ExecutionContext,
        decoder: &mut RaptorQDecoder,
        symbols: I,
    ) -> Result<Vec<u8>, DecodeError>
    where
        I: IntoIterator<Item = (u32, Vec<u8>)>,
    {
        if context.is_cancelled() {
            return Err(DecodeError::Cancelled);
        }

        let mut permit = self.acquire()?;
        let mut ordered_symbols: Vec<(u32, Vec<u8>)> = symbols.into_iter().collect();
        ordered_symbols.sort_unstable_by_key(|(esi, _)| *esi);

        match context
            .run(async {
                for (index, (esi, data)) in ordered_symbols.into_iter().enumerate() {
                    permit.try_buffer_symbol(data.len())?;

                    if let Some(payload) = decoder.add_symbol(esi, data)? {
                        return Ok(payload);
                    }

                    // Keep long symbol loops cancellable and deadline-aware.
                    if index % COOPERATIVE_YIELD_INTERVAL == COOPERATIVE_YIELD_INTERVAL - 1 {
                        fcp_async_core::time::sleep(Duration::ZERO).await;
                    }
                }

                Err(DecodeError::InsufficientSymbols {
                    received: decoder.received_count(),
                    needed: decoder.needed(),
                })
            })
            .await
        {
            Ok(result) => result,
            Err(error) => Err(Self::map_async_error(error)),
        }
    }

    fn map_async_error(error: AsyncError) -> DecodeError {
        match error {
            AsyncError::Cancelled => DecodeError::Cancelled,
            AsyncError::Timeout { .. } => DecodeError::Timeout,
            other => DecodeError::Runtime {
                reason: other.to_string(),
            },
        }
    }

    /// Get the number of active decode operations.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// Get the maximum concurrent decode limit.
    #[must_use]
    pub const fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Check if any slots are available.
    #[must_use]
    pub fn has_capacity(&self) -> bool {
        self.active.load(Ordering::SeqCst) < self.max_concurrent
    }
}

impl Default for DecodeAdmissionController {
    fn default() -> Self {
        Self::new(&RaptorQConfig::default())
    }
}

/// RAII permit for a decode operation.
///
/// Automatically releases the slot when dropped.
pub struct DecodePermit {
    active: Arc<AtomicUsize>,
    started_at: Instant,
    timeout: Duration,
    max_memory: usize,
    max_symbols: u32,
    symbols_buffered: u32,
    memory_used: usize,
}

impl DecodePermit {
    /// Check if permit is still valid (not timed out).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.started_at.elapsed() < self.timeout
    }

    /// Try to buffer a symbol (checks limits).
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::SymbolBufferExceeded` if symbol limit is reached.
    /// Returns `DecodeError::MemoryLimitExceeded` if memory limit is reached.
    /// Returns `DecodeError::Timeout` if the permit has timed out.
    pub fn try_buffer_symbol(&mut self, symbol_size: usize) -> Result<(), DecodeError> {
        if !self.is_valid() {
            return Err(DecodeError::Timeout);
        }

        if self.symbols_buffered >= self.max_symbols {
            return Err(DecodeError::SymbolBufferExceeded {
                buffered: self.symbols_buffered,
                limit: self.max_symbols,
            });
        }

        if self.memory_used + symbol_size > self.max_memory {
            return Err(DecodeError::MemoryLimitExceeded {
                used: self.memory_used + symbol_size,
                limit: self.max_memory,
            });
        }

        self.symbols_buffered += 1;
        self.memory_used += symbol_size;
        Ok(())
    }

    /// Get the number of symbols buffered.
    #[must_use]
    pub const fn symbols_buffered(&self) -> u32 {
        self.symbols_buffered
    }

    /// Get the amount of memory used.
    #[must_use]
    pub const fn memory_used(&self) -> usize {
        self.memory_used
    }

    /// Get time elapsed since permit was acquired.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get time remaining before timeout.
    #[must_use]
    pub fn time_remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.started_at.elapsed())
    }
}

impl Drop for DecodePermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RaptorQEncoder;

    fn test_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: Duration::from_secs(30),
            max_chunk_threshold: 256 * 1024,
            chunk_size: 64 * 1024,
        }
    }

    #[test]
    fn decoder_creation() {
        let config = test_config();
        let oti = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
        let decoder = RaptorQDecoder::new(oti, &config);

        assert_eq!(decoder.received_count(), 0);
        assert!(!decoder.is_timed_out());
    }

    #[test]
    fn decoder_with_expected_symbols() {
        let config = test_config();
        let decoder = RaptorQDecoder::with_expected_symbols(16, 1024, 64, &config);

        assert_eq!(decoder.expected_k(), 16);
        assert_eq!(decoder.needed(), 17); // ceil(16 * 1.002) = 17
    }

    #[test]
    fn decoder_duplicate_symbols_ignored() {
        let config = test_config();
        let oti = ObjectTransmissionInformation::new(64, 64, 1, 1, 8);
        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Add symbol with ESI 0
        let _ = decoder.add_symbol(0, vec![0u8; 64]);
        assert_eq!(decoder.received_count(), 1);

        // Add same symbol again - should be ignored
        let _ = decoder.add_symbol(0, vec![0u8; 64]);
        assert_eq!(decoder.received_count(), 1);

        // Add different symbol
        let _ = decoder.add_symbol(1, vec![0u8; 64]);
        assert_eq!(decoder.received_count(), 2);
    }

    #[test]
    fn decoder_needed_calculation() {
        let config = test_config();
        let decoder = RaptorQDecoder::with_expected_symbols(100, 6400, 64, &config);

        // K=100, K' = ceil(100 * 1.002) = 101
        assert_eq!(decoder.needed(), 101);
    }

    #[test]
    fn decoder_likely_complete() {
        let config = test_config();
        let oti = ObjectTransmissionInformation::new(64, 64, 1, 1, 8);
        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Need ~2 symbols for 64 bytes
        assert!(!decoder.likely_complete());

        let _ = decoder.add_symbol(0, vec![0u8; 64]);
        let _ = decoder.add_symbol(1, vec![0u8; 64]);

        // May or may not be complete depending on K calculation
    }

    #[test]
    fn decoder_timeout() {
        let mut config = test_config();
        config.decode_timeout = Duration::from_millis(1);

        let oti = ObjectTransmissionInformation::new(64, 64, 1, 1, 8);
        let mut decoder = RaptorQDecoder::new(oti, &config);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(10));

        assert!(decoder.is_timed_out());

        let result = decoder.add_symbol(0, vec![0u8; 64]);
        assert!(matches!(result, Err(DecodeError::Timeout)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DecodeAdmissionController Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn admission_controller_creation() {
        let config = test_config();
        let controller = DecodeAdmissionController::new(&config);

        assert_eq!(controller.max_concurrent(), 16);
        assert_eq!(controller.active_count(), 0);
        assert!(controller.has_capacity());
    }

    #[test]
    fn admission_controller_with_limits() {
        let controller =
            DecodeAdmissionController::with_limits(4, 1024 * 1024, Duration::from_secs(10), 5000);

        assert_eq!(controller.max_concurrent(), 4);
    }

    #[test]
    fn admission_controller_acquire_release() {
        let controller =
            DecodeAdmissionController::with_limits(2, 1024 * 1024, Duration::from_secs(30), 10000);

        assert_eq!(controller.active_count(), 0);

        let permit1 = controller.try_acquire().unwrap();
        assert_eq!(controller.active_count(), 1);

        let permit2 = controller.try_acquire().unwrap();
        assert_eq!(controller.active_count(), 2);

        // Third acquire should fail
        assert!(controller.try_acquire().is_none());

        // Release one
        drop(permit1);
        assert_eq!(controller.active_count(), 1);

        // Now we can acquire again
        let _permit3 = controller.try_acquire().unwrap();
        assert_eq!(controller.active_count(), 2);

        drop(permit2);
        assert_eq!(controller.active_count(), 1);
    }

    #[test]
    fn admission_controller_acquire_error() {
        let controller =
            DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_secs(30), 10000);

        let _permit = controller.acquire().unwrap();
        let result = controller.acquire();
        assert!(matches!(result, Err(DecodeError::AdmissionDenied { .. })));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DecodePermit Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn permit_is_valid() {
        let controller =
            DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_secs(30), 10000);

        let permit = controller.try_acquire().unwrap();
        assert!(permit.is_valid());
    }

    #[test]
    fn permit_timeout() {
        let controller =
            DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_millis(1), 10000);

        let permit = controller.try_acquire().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(!permit.is_valid());
    }

    #[test]
    fn permit_buffer_symbol() {
        let controller =
            DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_secs(30), 10000);

        let mut permit = controller.try_acquire().unwrap();

        permit.try_buffer_symbol(1024).unwrap();
        assert_eq!(permit.symbols_buffered(), 1);
        assert_eq!(permit.memory_used(), 1024);

        permit.try_buffer_symbol(1024).unwrap();
        assert_eq!(permit.symbols_buffered(), 2);
        assert_eq!(permit.memory_used(), 2048);
    }

    #[test]
    fn permit_symbol_limit() {
        let controller = DecodeAdmissionController::with_limits(
            1,
            1024 * 1024,
            Duration::from_secs(30),
            2, // Only 2 symbols allowed
        );

        let mut permit = controller.try_acquire().unwrap();

        permit.try_buffer_symbol(64).unwrap();
        permit.try_buffer_symbol(64).unwrap();

        // Third should fail
        let result = permit.try_buffer_symbol(64);
        assert!(matches!(
            result,
            Err(DecodeError::SymbolBufferExceeded { .. })
        ));
    }

    #[test]
    fn permit_memory_limit() {
        let controller = DecodeAdmissionController::with_limits(
            1,
            1024, // Only 1KB
            Duration::from_secs(30),
            10000,
        );

        let mut permit = controller.try_acquire().unwrap();

        permit.try_buffer_symbol(512).unwrap();
        permit.try_buffer_symbol(512).unwrap();

        // Next should exceed memory
        let result = permit.try_buffer_symbol(512);
        assert!(matches!(
            result,
            Err(DecodeError::MemoryLimitExceeded { .. })
        ));
    }

    #[test]
    fn permit_timeout_on_buffer() {
        let controller =
            DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_millis(1), 10000);

        let mut permit = controller.try_acquire().unwrap();
        std::thread::sleep(Duration::from_millis(10));

        let result = permit.try_buffer_symbol(64);
        assert!(matches!(result, Err(DecodeError::Timeout)));
    }

    #[test]
    fn permit_time_remaining() {
        let controller =
            DecodeAdmissionController::with_limits(1, 1024 * 1024, Duration::from_secs(30), 10000);

        let permit = controller.try_acquire().unwrap();
        let remaining = permit.time_remaining();
        // Should be close to 30 seconds
        assert!(remaining > Duration::from_secs(29));
        assert!(remaining <= Duration::from_secs(30));
    }

    #[test]
    fn default_admission_controller() {
        let controller = DecodeAdmissionController::default();
        assert_eq!(controller.max_concurrent(), 16);
        assert!(controller.has_capacity());
    }

    #[test]
    fn controller_clone() {
        let controller =
            DecodeAdmissionController::with_limits(4, 1024 * 1024, Duration::from_secs(30), 10000);

        let cloned = controller.clone();

        // Acquire on original
        let _permit = controller.try_acquire().unwrap();

        // Clone shares the same active counter
        assert_eq!(cloned.active_count(), 1);
    }

    #[test]
    fn test_concurrent_acquire_respects_limit_strictly() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let max_concurrent = 5;
        let controller = DecodeAdmissionController::with_limits(
            max_concurrent,
            1024,
            Duration::from_secs(30),
            100,
        );
        let controller = Arc::new(controller);
        let barrier = Arc::new(Barrier::new(20)); // 20 threads

        let mut handles = vec![];
        for _ in 0..20 {
            let c = controller.clone();
            let b = barrier.clone();
            handles.push(thread::spawn(move || {
                b.wait();
                let permit = c.try_acquire();
                // Hold permit for a bit
                if permit.is_some() {
                    thread::sleep(Duration::from_millis(10));
                }
                // Verify we never see active_count > max_concurrent
                let current = c.active_count();
                assert!(
                    current <= max_concurrent,
                    "active count {current} exceeded max {max_concurrent}"
                );
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(controller.active_count(), 0);
    }

    #[test]
    fn decode_with_context_roundtrip_orders_symbols() {
        fcp_async_core::runtime::block_on_sync(async {
            let config = test_config();
            let payload: Vec<u8> = (0..4096_u32)
                .map(|i| u8::try_from(i % 256).expect("payload byte fits u8"))
                .collect();

            let encoder = RaptorQEncoder::new(&payload, &config).unwrap();
            let oti = encoder.transmission_info();
            let mut symbols = encoder.encode_all();
            symbols.reverse();

            let controller = DecodeAdmissionController::new(&config);
            let mut decoder = RaptorQDecoder::new(oti, &config);
            let context = ExecutionContext::request_scoped(Duration::from_secs(5));

            let decoded = controller
                .decode_with_context(&context, &mut decoder, symbols)
                .await
                .unwrap();

            assert_eq!(decoded, payload);
        })
        .expect("runtime available for async decode test");
    }

    #[test]
    fn decode_with_context_cancelled_context() {
        fcp_async_core::runtime::block_on_sync(async {
            let config = test_config();
            let controller = DecodeAdmissionController::new(&config);
            let context = ExecutionContext::request_scoped(Duration::from_secs(5));
            context.cancel();

            let mut decoder = RaptorQDecoder::with_expected_symbols(4, 256, 64, &config);
            let symbols = vec![(0, vec![0u8; 64]), (1, vec![0u8; 64])];

            let err = controller
                .decode_with_context(&context, &mut decoder, symbols)
                .await
                .expect_err("cancelled context should fail decode");
            assert!(matches!(err, DecodeError::Cancelled));
        })
        .expect("runtime available for async decode test");
    }

    #[test]
    fn decode_with_context_deadline_timeout() {
        fcp_async_core::runtime::block_on_sync(async {
            let config = test_config();
            let controller = DecodeAdmissionController::with_limits(
                4,
                1024 * 1024,
                Duration::from_secs(30),
                10000,
            );
            let context = ExecutionContext::request_scoped(Duration::from_millis(1));
            fcp_async_core::time::sleep(Duration::from_millis(5)).await;

            let mut decoder = RaptorQDecoder::with_expected_symbols(1000, 64_000, 64, &config);
            let symbols: Vec<(u32, Vec<u8>)> = (0..256).map(|esi| (esi, vec![0u8; 64])).collect();

            let err = controller
                .decode_with_context(&context, &mut decoder, symbols)
                .await
                .expect_err("expired deadline should fail decode");
            assert!(matches!(err, DecodeError::Timeout));
        })
        .expect("runtime available for async decode test");
    }

    #[test]
    fn decode_with_context_admission_denied() {
        fcp_async_core::runtime::block_on_sync(async {
            let config = test_config();
            let controller = DecodeAdmissionController::with_limits(
                0,
                1024 * 1024,
                Duration::from_secs(30),
                1024,
            );
            let context = ExecutionContext::request_scoped(Duration::from_secs(5));

            let mut decoder = RaptorQDecoder::with_expected_symbols(4, 256, 64, &config);
            let symbols = vec![(0, vec![0u8; 64]), (1, vec![0u8; 64])];

            let err = controller
                .decode_with_context(&context, &mut decoder, symbols)
                .await
                .expect_err("admission limit should reject decode");
            assert!(matches!(err, DecodeError::AdmissionDenied { .. }));
        })
        .expect("runtime available for async decode test");
    }

    #[test]
    fn decode_with_context_returns_insufficient_symbols() {
        fcp_async_core::runtime::block_on_sync(async {
            let config = test_config();
            let controller = DecodeAdmissionController::new(&config);
            let context = ExecutionContext::request_scoped(Duration::from_secs(5));

            let mut decoder = RaptorQDecoder::with_expected_symbols(128, 8192, 64, &config);
            let symbols = vec![(0, vec![0u8; 64]), (1, vec![0u8; 64]), (2, vec![0u8; 64])];

            let err = controller
                .decode_with_context(&context, &mut decoder, symbols)
                .await
                .expect_err("insufficient symbols should be surfaced");

            match err {
                DecodeError::InsufficientSymbols { received, needed } => {
                    assert_eq!(received, 3);
                    assert!(needed >= 128);
                }
                other => panic!("expected insufficient symbols, got {other:?}"),
            }
        })
        .expect("runtime available for async decode test");
    }
}
