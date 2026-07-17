//! Metrics collection for observability.

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
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_bytes_recv(&self, bytes: usize) {
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_malformed_packet(&self) {
        self.malformed_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_replay_drop(&self) {
        self.replay_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_oversized_packet(&self) {
        self.oversized_packets.fetch_add(1, Ordering::Relaxed);
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

#[derive(Debug, Clone)]
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
