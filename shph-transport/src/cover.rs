//! Explicit cover-traffic budget. Callers drive time, congestion and cancellation.
use shph_core::{Result, ShphError};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverPolicy {
    pub interval_ms: u32,
    pub idle_timeout_ms: u32,
    pub maximum_bytes: u64,
    pub overhead_percent: u16,
}

impl CoverPolicy {
    pub fn validate(self) -> Result<()> {
        if !(100..=60_000).contains(&self.interval_ms)
            || self.idle_timeout_ms < self.interval_ms
            || self.idle_timeout_ms > 300_000
            || self.maximum_bytes == 0
            || self.maximum_bytes > 64 * 1024 * 1024
            || !(1..=100).contains(&self.overhead_percent)
        {
            return Err(ShphError::Config("invalid cover traffic budget".into()));
        }
        Ok(())
    }
}

pub struct CoverScheduler {
    policy: Option<CoverPolicy>,
    last_observed: Duration,
    last_data: Option<Duration>,
    last_cover: Option<Duration>,
    payload_bytes: u64,
    cover_bytes: u64,
    stopped: bool,
}

impl CoverScheduler {
    pub fn new(policy: Option<CoverPolicy>) -> Result<Self> {
        if let Some(policy) = policy {
            policy.validate()?;
        }
        Ok(Self {
            policy,
            last_observed: Duration::ZERO,
            last_data: None,
            last_cover: None,
            payload_bytes: 0,
            cover_bytes: 0,
            stopped: false,
        })
    }
    fn observe(&mut self, now: Duration) -> Result<()> {
        if now < self.last_observed {
            return Err(ShphError::InvalidArgument(
                "cover clock moved backwards".into(),
            ));
        }
        self.last_observed = now;
        Ok(())
    }
    pub fn record_payload(&mut self, now: Duration, bytes: usize) -> Result<()> {
        self.observe(now)?;
        self.last_data = Some(now);
        self.payload_bytes = self.payload_bytes.saturating_add(bytes as u64);
        Ok(())
    }
    /// Reserve complete envelope+AEAD+framing bytes, not just the dummy payload.
    /// Reservation is deliberately retained on I/O failure to prevent retry overspend.
    pub fn reserve(
        &mut self,
        now: Duration,
        bytes: usize,
        payload_pending: bool,
        congested: bool,
        cancelled: bool,
    ) -> Result<bool> {
        self.observe(now)?;
        self.stopped |= cancelled;
        let Some(policy) = self.policy else {
            return Ok(false);
        };
        let Some(last_data) = self.last_data else {
            return Ok(false);
        };
        if self.stopped
            || payload_pending
            || congested
            || bytes == 0
            || bytes > 4096
            || now - last_data >= Duration::from_millis(u64::from(policy.idle_timeout_ms))
            || now - self.last_cover.unwrap_or(last_data)
                < Duration::from_millis(u64::from(policy.interval_ms))
        {
            return Ok(false);
        }
        let allowance = (u128::from(self.payload_bytes) * u128::from(policy.overhead_percent) / 100)
            .min(u128::from(policy.maximum_bytes)) as u64;
        if bytes as u64 > allowance.saturating_sub(self.cover_bytes) {
            return Ok(false);
        }
        self.cover_bytes = self.cover_bytes.saturating_add(bytes as u64);
        self.last_cover = Some(now);
        Ok(true)
    }
    pub fn cover_bytes(&self) -> u64 {
        self.cover_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cover_is_bounded_idle_suppressed_and_permanently_cancelled() {
        let policy = CoverPolicy {
            interval_ms: 100,
            idle_timeout_ms: 500,
            maximum_bytes: 500,
            overhead_percent: 10,
        };
        let mut cover = CoverScheduler::new(Some(policy)).unwrap();
        assert!(!cover
            .reserve(Duration::ZERO, 128, false, false, false)
            .unwrap());
        cover.record_payload(Duration::ZERO, 2560).unwrap();
        assert!(cover
            .reserve(Duration::from_millis(100), 128, false, false, false)
            .unwrap());
        assert!(!cover
            .reserve(Duration::from_millis(101), 128, false, false, false)
            .unwrap());
        assert!(!cover
            .reserve(Duration::from_millis(200), 128, true, false, false)
            .unwrap());
        assert!(!cover
            .reserve(Duration::from_millis(200), 128, false, true, false)
            .unwrap());
        assert!(cover
            .reserve(Duration::from_millis(200), 128, false, false, false)
            .unwrap());
        assert!(!cover
            .reserve(Duration::from_millis(300), 1, false, false, false)
            .unwrap());
        cover
            .record_payload(Duration::from_millis(300), 10000)
            .unwrap();
        assert!(!cover
            .reserve(Duration::from_millis(800), 128, false, false, false)
            .unwrap());
        assert!(!cover
            .reserve(Duration::from_millis(800), 128, false, false, true)
            .unwrap());
        cover
            .record_payload(Duration::from_millis(900), 10000)
            .unwrap();
        assert!(!cover
            .reserve(Duration::from_millis(1000), 128, false, false, false)
            .unwrap());
        assert_eq!(cover.cover_bytes(), 256);
        assert!(cover.record_payload(Duration::ZERO, 1).is_err());
        assert!(!CoverScheduler::new(None)
            .unwrap()
            .reserve(Duration::ZERO, 128, false, false, false)
            .unwrap());
    }
}
