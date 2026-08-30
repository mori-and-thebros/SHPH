//! Metrics collection for observability.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default, Clone)]
pub struct MetricsCollector {
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_recv: Arc<AtomicU64>,
    pub packets_sent: Arc<AtomicU64>,
    pub packets_recv: Arc<AtomicU64>,
    pub errors: Arc<AtomicU64>,
    pub malformed_packets: Arc<AtomicU64>,
    pub replay_drops: Arc<AtomicU64>,
    pub timeouts: Arc<AtomicU64>,
    pub oversized_packets: Arc<AtomicU64>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_bytes_sent(&self, bytes: usize) {
        saturating_add(&self.bytes_sent, bytes as u64);
        saturating_add(&self.packets_sent, 1);
    }

    pub fn inc_bytes_recv(&self, bytes: usize) {
        saturating_add(&self.bytes_recv, bytes as u64);
        saturating_add(&self.packets_recv, 1);
    }

    pub fn inc_error(&self) {
        saturating_add(&self.errors, 1);
    }

    pub fn inc_malformed_packet(&self) {
        saturating_add(&self.malformed_packets, 1);
    }

    pub fn inc_replay_drop(&self) {
        saturating_add(&self.replay_drops, 1);
    }

    pub fn inc_timeout(&self) {
        saturating_add(&self.timeouts, 1);
    }

    pub fn inc_oversized_packet(&self) {
        saturating_add(&self.oversized_packets, 1);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            replay_drops: self.replay_drops.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            oversized_packets: self.oversized_packets.load(Ordering::Relaxed),
        }
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub errors: u64,
    pub malformed_packets: u64,
    pub replay_drops: u64,
    pub timeouts: u64,
    pub oversized_packets: u64,
}

impl MetricsSnapshot {
    pub const fn zero() -> Self {
        Self {
            bytes_sent: 0,
            bytes_recv: 0,
            packets_sent: 0,
            packets_recv: 0,
            errors: 0,
            malformed_packets: 0,
            replay_drops: 0,
            timeouts: 0,
            oversized_packets: 0,
        }
    }

    /// Return the non-negative counter delta from an earlier snapshot.
    ///
    /// Saturating subtraction makes this safe to use across a counter reset
    /// or an externally supplied snapshot without turning a reset into a
    /// misleading large rate.
    pub const fn delta_since(self, earlier: Self) -> Self {
        Self {
            bytes_sent: self.bytes_sent.saturating_sub(earlier.bytes_sent),
            bytes_recv: self.bytes_recv.saturating_sub(earlier.bytes_recv),
            packets_sent: self.packets_sent.saturating_sub(earlier.packets_sent),
            packets_recv: self.packets_recv.saturating_sub(earlier.packets_recv),
            errors: self.errors.saturating_sub(earlier.errors),
            malformed_packets: self
                .malformed_packets
                .saturating_sub(earlier.malformed_packets),
            replay_drops: self.replay_drops.saturating_sub(earlier.replay_drops),
            timeouts: self.timeouts.saturating_sub(earlier.timeouts),
            oversized_packets: self
                .oversized_packets
                .saturating_sub(earlier.oversized_packets),
        }
    }

    pub const fn total_bytes(self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_recv)
    }

    pub const fn total_packets(self) -> u64 {
        self.packets_sent.saturating_add(self.packets_recv)
    }

    pub const fn error_count(self) -> u64 {
        self.errors
            .saturating_add(self.malformed_packets)
            .saturating_add(self.replay_drops)
            .saturating_add(self.timeouts)
            .saturating_add(self.oversized_packets)
    }

    pub const fn has_errors(self) -> bool {
        self.error_count() != 0
    }
}

#[cfg(test)]
mod tests {
    use super::{MetricsCollector, MetricsSnapshot};
    use std::sync::atomic::Ordering;

    #[test]
    fn collector_counters_saturate_instead_of_wrapping() {
        let metrics = MetricsCollector::new();
        metrics.bytes_sent.store(u64::MAX, Ordering::Relaxed);
        metrics.packets_sent.store(u64::MAX, Ordering::Relaxed);

        metrics.inc_bytes_sent(1);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.bytes_sent, u64::MAX);
        assert_eq!(snapshot.packets_sent, u64::MAX);
    }

    #[test]
    fn snapshot_delta_and_totals_are_bounded() {
        let earlier = MetricsSnapshot {
            bytes_sent: 100,
            packets_sent: 5,
            ..MetricsSnapshot::zero()
        };
        let current = MetricsSnapshot {
            bytes_sent: 40,
            bytes_recv: u64::MAX,
            packets_sent: 7,
            packets_recv: 3,
            replay_drops: 1,
            ..MetricsSnapshot::zero()
        };
        let delta = current.delta_since(earlier);

        assert_eq!(delta.bytes_sent, 0);
        assert_eq!(delta.packets_sent, 2);
        assert_eq!(delta.total_bytes(), u64::MAX);
        assert_eq!(delta.total_packets(), 5);
        assert_eq!(delta.error_count(), 1);
        assert!(delta.has_errors());
    }

    #[test]
    fn snapshot_serializes_with_stable_field_names() {
        let json = serde_json::to_value(MetricsSnapshot::default()).expect("serialize metrics");
        assert_eq!(json["bytes_sent"], 0);
        assert_eq!(json["oversized_packets"], 0);
    }
}
