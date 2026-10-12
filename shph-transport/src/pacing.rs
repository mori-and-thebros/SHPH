//! Deadline-aware, bounded QUIC datagram pacing. No background worker is spawned.
use bytes::Bytes;
use shph_core::{Result, ShphError};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Semaphore};

#[derive(Debug, Default)]
pub struct PacingMetrics {
    pub sent: AtomicU64,
    pub expired: AtomicU64,
    pub rejected_full: AtomicU64,
    pub cancelled: AtomicU64,
    pub locally_dropped: AtomicU64,
    pub shaping_micros: AtomicU64,
    pub queue_micros: AtomicU64,
    pub overshoot_micros: AtomicU64,
}

fn add(counter: &AtomicU64, amount: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(amount);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn queue_deadline(enqueued_at: Instant, budget: Duration) -> Instant {
    enqueued_at + budget
}

fn release_at(enqueued_at: Instant, shaping_delay: Duration, budget: Duration) -> Instant {
    enqueued_at + shaping_delay.min(budget)
}

fn effective_deadline(enqueued_at: Instant, caller_deadline: Instant, budget: Duration) -> Instant {
    caller_deadline.min(queue_deadline(enqueued_at, budget))
}

fn validate_carrier_limit(payload_len: usize, max_datagram_size: Option<usize>) -> Result<()> {
    if max_datagram_size.is_none_or(|limit| payload_len > limit) {
        return Err(ShphError::Protocol(
            "paced datagram exceeds current carrier limit".into(),
        ));
    }
    Ok(())
}

async fn wait_for_release(release: Instant, deadline: Instant) -> Result<()> {
    tokio::time::sleep_until(release.into()).await;
    if Instant::now() >= deadline {
        return Err(ShphError::Timeout);
    }
    Ok(())
}

async fn race_cancel<F>(
    deadline: Instant,
    mut cancel: watch::Receiver<bool>,
    sending: F,
) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    if *cancel.borrow() || cancel.has_changed().is_err() {
        return Err(ShphError::ConnectionClosed);
    }
    tokio::select! {
        biased;
        _ = async { loop {
            if *cancel.borrow_and_update() || cancel.changed().await.is_err() { break; }
        }} => Err(ShphError::ConnectionClosed),
        result = tokio::time::timeout_at(deadline.into(), sending) => result.unwrap_or(Err(ShphError::Timeout)),
    }
}

pub struct DatagramPacer {
    slots: Semaphore,
    budget: Duration,
    metrics: PacingMetrics,
}

impl DatagramPacer {
    pub fn new(capacity: usize, maximum_queue_age: Duration) -> Result<Self> {
        if !(1..=1024).contains(&capacity)
            || maximum_queue_age.is_zero()
            || maximum_queue_age > Duration::from_secs(60)
        {
            return Err(ShphError::Config(
                "invalid pacing capacity or deadline".into(),
            ));
        }
        Ok(Self {
            slots: Semaphore::new(capacity),
            budget: maximum_queue_age,
            metrics: PacingMetrics::default(),
        })
    }

    pub fn metrics(&self) -> &PacingMetrics {
        &self.metrics
    }

    fn reserve_slot(&self) -> Result<tokio::sync::SemaphorePermit<'_>> {
        self.slots.try_acquire().map_err(|_| {
            add(&self.metrics.rejected_full, 1);
            ShphError::ResourceExhausted("pacing queue is full".into())
        })
    }

    fn record_result(&self, result: &Result<()>) {
        match result {
            Ok(()) => add(&self.metrics.sent, 1),
            Err(ShphError::Timeout) => add(&self.metrics.expired, 1),
            Err(ShphError::ConnectionClosed) => add(&self.metrics.cancelled, 1),
            _ => {}
        }
        if result.is_err() {
            add(&self.metrics.locally_dropped, 1);
        }
    }

    /// Overflow and deadline expiry are explicit errors. Payloads are copied
    /// only after a queue slot has been reserved. The future is cancellation safe
    /// before handoff to Quinn; successful handoff is not delivery evidence.
    pub async fn send(
        &self,
        connection: &quinn::Connection,
        payload: &[u8],
        enqueued_at: Instant,
        shaping_delay: Duration,
        cancel: watch::Receiver<bool>,
    ) -> Result<()> {
        self.send_until(
            connection,
            payload,
            enqueued_at,
            queue_deadline(enqueued_at, self.budget),
            shaping_delay,
            cancel,
        )
        .await
    }

    pub async fn send_until(
        &self,
        connection: &quinn::Connection,
        payload: &[u8],
        enqueued_at: Instant,
        caller_deadline: Instant,
        shaping_delay: Duration,
        cancel: watch::Receiver<bool>,
    ) -> Result<()> {
        if payload.len() > 65_535
            || shaping_delay > Duration::from_secs(1)
            || enqueued_at > Instant::now()
        {
            return Err(ShphError::InvalidArgument(
                "invalid paced datagram or timestamp".into(),
            ));
        }
        let _slot = match self.reserve_slot() {
            Ok(slot) => slot,
            Err(error) => {
                add(&self.metrics.locally_dropped, 1);
                return Err(error);
            }
        };
        let deadline = effective_deadline(enqueued_at, caller_deadline, self.budget);
        let release = release_at(enqueued_at, shaping_delay, self.budget);
        add(
            &self.metrics.shaping_micros,
            shaping_delay.as_micros().min(u64::MAX as u128) as u64,
        );
        let sending = async {
            wait_for_release(release, deadline).await?;
            validate_carrier_limit(payload.len(), connection.max_datagram_size())?;
            let actual = Instant::now();
            add(
                &self.metrics.queue_micros,
                actual
                    .saturating_duration_since(enqueued_at)
                    .as_micros()
                    .min(u64::MAX as u128) as u64,
            );
            add(
                &self.metrics.overshoot_micros,
                actual
                    .saturating_duration_since(release)
                    .as_micros()
                    .min(u64::MAX as u128) as u64,
            );
            connection
                .send_datagram_wait(Bytes::copy_from_slice(payload))
                .await
                .map_err(|error| ShphError::Transport(error.to_string()))
        };
        let result = race_cancel(deadline, cancel, sending).await;
        self.record_result(&result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_counter_saturates_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);
        add(&counter, 4);
        add(&counter, 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn pacing_limits_and_overflow_are_bounded() {
        assert!(DatagramPacer::new(0, Duration::from_secs(1)).is_err());
        assert!(DatagramPacer::new(1025, Duration::from_secs(1)).is_err());
        assert!(DatagramPacer::new(1, Duration::ZERO).is_err());
        let pacer = DatagramPacer::new(1, Duration::from_millis(20)).unwrap();
        let slot = pacer.slots.try_acquire().unwrap();
        assert!(pacer.slots.try_acquire().is_err());
        drop(slot);
        assert!(pacer.slots.try_acquire().is_ok());
    }

    #[test]
    fn queue_capacity_rejects_overflow_and_recovers() {
        let pacer = DatagramPacer::new(1, Duration::from_secs(1)).unwrap();
        let slot = pacer.reserve_slot().unwrap();

        assert!(matches!(
            pacer.reserve_slot(),
            Err(ShphError::ResourceExhausted(_))
        ));
        assert_eq!(pacer.metrics().rejected_full.load(Ordering::Relaxed), 1);

        drop(slot);
        assert!(pacer.reserve_slot().is_ok());
    }

    #[test]
    fn caller_deadline_cannot_exceed_or_replace_queue_age_budget() {
        let enqueued_at = Instant::now();
        let budget = Duration::from_secs(2);
        assert_eq!(
            effective_deadline(enqueued_at, enqueued_at + Duration::from_secs(5), budget),
            enqueued_at + budget
        );
        assert_eq!(
            effective_deadline(enqueued_at, enqueued_at + Duration::from_secs(1), budget),
            enqueued_at + Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn queue_deadline_includes_time_since_enqueue() {
        let pacer = DatagramPacer::new(1, Duration::from_secs(2)).unwrap();
        let enqueued_at = Instant::now() - Duration::from_secs(3);
        let deadline = queue_deadline(enqueued_at, pacer.budget);
        let release = release_at(enqueued_at, Duration::ZERO, pacer.budget);
        let (_cancel_tx, cancel_rx) = watch::channel(false);

        let result = race_cancel(deadline, cancel_rx, wait_for_release(release, deadline)).await;
        pacer.record_result(&result);

        assert!(matches!(result, Err(ShphError::Timeout)));
        assert_eq!(pacer.metrics().expired.load(Ordering::Relaxed), 1);
        assert_eq!(pacer.metrics().locally_dropped.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn datagram_expiring_at_release_is_not_sent() {
        let pacer = DatagramPacer::new(1, Duration::from_millis(20)).unwrap();
        let enqueued_at = Instant::now();
        let deadline = queue_deadline(enqueued_at, pacer.budget);
        let release = release_at(enqueued_at, pacer.budget, pacer.budget);
        let (_cancel_tx, cancel_rx) = watch::channel(false);

        let result = race_cancel(deadline, cancel_rx, wait_for_release(release, deadline)).await;
        pacer.record_result(&result);

        assert!(matches!(result, Err(ShphError::Timeout)));
        assert_eq!(pacer.metrics().expired.load(Ordering::Relaxed), 1);
        assert_eq!(pacer.metrics().sent.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_waiting_datagram() {
        let pacer = DatagramPacer::new(1, Duration::from_secs(10)).unwrap();
        let enqueued_at = Instant::now();
        let deadline = queue_deadline(enqueued_at, pacer.budget);
        let release = release_at(enqueued_at, Duration::from_secs(5), pacer.budget);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            race_cancel(deadline, cancel_rx, wait_for_release(release, deadline)).await
        });

        tokio::task::yield_now().await;
        cancel_tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        pacer.record_result(&result);

        assert!(matches!(result, Err(ShphError::ConnectionClosed)));
        assert_eq!(pacer.metrics().cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(pacer.metrics().locally_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn carrier_size_check_uses_the_current_limit() {
        assert!(validate_carrier_limit(1200, Some(1200)).is_ok());
        assert!(validate_carrier_limit(1201, Some(1200)).is_err());
        assert!(validate_carrier_limit(1, None).is_err());
    }
}
