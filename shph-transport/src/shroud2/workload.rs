//! Caller-driven workload observations; no hidden timer or application inspection.
use super::{
    validate_payload_for_path, AdaptiveMorphologyConfig, MorphologyEngine, MorphologyProfile,
};
use shph_core::{Result, ShphError};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct WorkloadConfig {
    pub minimum_dwell: Duration,
    pub burst_gap: Duration,
    pub burst_threshold: u32,
    pub queue_age_limit: Duration,
    pub use_arrivals: bool,
    pub use_queue_age: bool,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self {
            minimum_dwell: Duration::from_millis(100),
            burst_gap: Duration::from_millis(5),
            burst_threshold: 8,
            queue_age_limit: Duration::from_millis(10),
            use_arrivals: true,
            use_queue_age: true,
        }
    }
}

impl WorkloadConfig {
    fn validate(self) -> Result<()> {
        if self.minimum_dwell > Duration::from_secs(60)
            || self.burst_gap.is_zero()
            || self.burst_gap > Duration::from_secs(1)
            || !(2..=1024).contains(&self.burst_threshold)
            || self.queue_age_limit.is_zero()
            || self.queue_age_limit > Duration::from_secs(1)
        {
            return Err(ShphError::Config(
                "invalid workload adaptation bounds".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionReason {
    Payload,
    Burst,
    QueueAge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadObservation {
    pub observed_at: Duration,
    pub queue_age: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkloadMetrics {
    pub observations: u64,
    pub switches: u64,
    pub payload_transitions: u64,
    pub burst_transitions: u64,
    pub queue_age_transitions: u64,
    pub dwell_suppressed: u64,
    pub burst_length: u32,
    pub last_reason: Option<TransitionReason>,
}

pub struct WorkloadMorphology {
    engine: MorphologyEngine,
    config: WorkloadConfig,
    thresholds: AdaptiveMorphologyConfig,
    last_observation: Option<Duration>,
    last_switch: Option<Duration>,
    ewma: usize,
    metrics: WorkloadMetrics,
}

impl WorkloadMorphology {
    /// Create a production engine with operating-system seeded randomness.
    ///
    /// `from_seed` is retained for deterministic lab tests. Applications that
    /// emit wire padding should use this constructor rather than a public or
    /// otherwise predictable seed.
    pub fn new(config: WorkloadConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            engine: MorphologyEngine::new(MorphologyProfile::TunedLowLatency),
            config,
            thresholds: AdaptiveMorphologyConfig::default(),
            last_observation: None,
            last_switch: None,
            ewma: 0,
            metrics: WorkloadMetrics::default(),
        })
    }

    pub fn from_seed(config: WorkloadConfig, seed: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            engine: MorphologyEngine::from_seed(MorphologyProfile::TunedLowLatency, seed),
            config,
            thresholds: AdaptiveMorphologyConfig::default(),
            last_observation: None,
            last_switch: None,
            ewma: 0,
            metrics: WorkloadMetrics::default(),
        })
    }

    pub fn profile(&self) -> MorphologyProfile {
        self.engine.profile()
    }
    pub fn metrics(&self) -> WorkloadMetrics {
        self.metrics
    }

    pub fn next_delay(&mut self) -> Duration {
        self.engine.next_delay()
    }

    /// `observed_at` is elapsed monotonic time from one session origin.
    /// Queue age must include all time since application enqueue.
    pub fn encode(
        &mut self,
        payload: &[u8],
        path_mtu: usize,
        observed_at: Duration,
        queue_age: Duration,
    ) -> Result<Vec<u8>> {
        validate_payload_for_path(payload.len(), path_mtu)?;
        if self.last_observation.is_some_and(|last| observed_at < last) || queue_age > observed_at {
            return Err(ShphError::InvalidArgument(
                "nonmonotonic or impossible workload observation".into(),
            ));
        }
        let burst = if self
            .last_observation
            .is_some_and(|last| observed_at - last <= self.config.burst_gap)
        {
            self.metrics.burst_length.saturating_add(1).min(1024)
        } else {
            1
        };
        let delta = payload.len().abs_diff(self.ewma).div_ceil(4);
        let ewma = if payload.len() >= self.ewma {
            self.ewma.saturating_add(delta)
        } else {
            self.ewma.saturating_sub(delta)
        };
        let current = self.profile();
        let mut next = match current {
            MorphologyProfile::TunedLowLatency if ewma >= self.thresholds.interactive_enter() => {
                MorphologyProfile::TunedWebBrowsingLab
            }
            MorphologyProfile::TunedWebBrowsingLab
                if ewma <= self.thresholds.interactive_exit() =>
            {
                MorphologyProfile::TunedLowLatency
            }
            MorphologyProfile::TunedWebBrowsingLab if ewma >= self.thresholds.video_enter() => {
                MorphologyProfile::TunedVideoStreamingLab
            }
            MorphologyProfile::TunedVideoStreamingLab if ewma <= self.thresholds.video_exit() => {
                MorphologyProfile::TunedWebBrowsingLab
            }
            MorphologyProfile::TunedVideoStreamingLab if ewma >= self.thresholds.bulk_enter() => {
                MorphologyProfile::TunedBulkLab
            }
            MorphologyProfile::TunedBulkLab if ewma <= self.thresholds.bulk_exit() => {
                MorphologyProfile::TunedVideoStreamingLab
            }
            _ => current,
        };
        let mut reason = TransitionReason::Payload;
        if self.config.use_arrivals
            && burst >= self.config.burst_threshold
            && ewma >= self.thresholds.video_enter()
        {
            next = MorphologyProfile::TunedBulkLab;
            reason = TransitionReason::Burst;
        }
        if self.config.use_queue_age && queue_age >= self.config.queue_age_limit {
            next = MorphologyProfile::TunedLowLatency;
            reason = TransitionReason::QueueAge;
        }
        let origin = self
            .last_switch
            .or(self.last_observation)
            .unwrap_or(observed_at);
        let suppressed = next != current && observed_at - origin < self.config.minimum_dwell;
        if suppressed {
            next = current;
        }
        self.engine.set_profile(next);
        let encoded = match self.engine.encode_datagram(payload, path_mtu) {
            Ok(value) => value,
            Err(error) => {
                self.engine.set_profile(current);
                return Err(error);
            }
        };
        if self.last_switch.is_none() {
            self.last_switch = Some(observed_at);
        }
        if next != current {
            self.last_switch = Some(observed_at);
            self.metrics.switches = self.metrics.switches.saturating_add(1);
            match reason {
                TransitionReason::Payload => {
                    self.metrics.payload_transitions =
                        self.metrics.payload_transitions.saturating_add(1);
                }
                TransitionReason::Burst => {
                    self.metrics.burst_transitions =
                        self.metrics.burst_transitions.saturating_add(1);
                }
                TransitionReason::QueueAge => {
                    self.metrics.queue_age_transitions =
                        self.metrics.queue_age_transitions.saturating_add(1);
                }
            }
            self.metrics.last_reason = Some(reason);
        }
        self.ewma = ewma;
        self.last_observation = Some(observed_at);
        self.metrics.burst_length = burst;
        self.metrics.observations = self.metrics.observations.saturating_add(1);
        self.metrics.dwell_suppressed = self
            .metrics
            .dwell_suppressed
            .saturating_add(u64::from(suppressed));
        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_and_payload_transitions_are_counted_across_idle_gaps() {
        let config = WorkloadConfig {
            minimum_dwell: Duration::ZERO,
            use_queue_age: false,
            ..WorkloadConfig::default()
        };
        let mut engine = WorkloadMorphology::from_seed(config, 1).unwrap();

        for millis in 0..100 {
            engine
                .encode(
                    &[0; 1300],
                    1472,
                    Duration::from_millis(millis),
                    Duration::ZERO,
                )
                .unwrap();
            if millis < 7 {
                assert_ne!(engine.profile(), MorphologyProfile::TunedBulkLab);
            }
        }
        assert_eq!(engine.profile(), MorphologyProfile::TunedBulkLab);
        assert_eq!(engine.metrics().burst_transitions, 1);

        engine
            .encode(&[0; 1300], 1472, Duration::from_millis(120), Duration::ZERO)
            .unwrap();
        assert_eq!(
            engine.metrics().burst_length,
            1,
            "idle gap resets the burst"
        );

        for index in 1..=100 {
            engine
                .encode(
                    b"x",
                    1472,
                    Duration::from_millis(120 + index * 6),
                    Duration::ZERO,
                )
                .unwrap();
        }
        assert_eq!(engine.profile(), MorphologyProfile::TunedLowLatency);
        assert!(engine.metrics().payload_transitions >= 3);
        assert_eq!(
            engine.metrics().switches,
            engine.metrics().payload_transitions + engine.metrics().burst_transitions
        );
        assert_eq!(engine.metrics().queue_age_transitions, 0);
    }

    #[test]
    fn queue_age_transition_is_counted() {
        let config = WorkloadConfig {
            minimum_dwell: Duration::ZERO,
            use_arrivals: false,
            ..WorkloadConfig::default()
        };
        let mut engine = WorkloadMorphology::from_seed(config, 2).unwrap();
        for millis in 0..100 {
            engine
                .encode(
                    &[0; 1400],
                    1472,
                    Duration::from_millis(millis),
                    Duration::ZERO,
                )
                .unwrap();
        }
        assert_eq!(engine.profile(), MorphologyProfile::TunedBulkLab);
        engine
            .encode(
                &[0; 1400],
                1472,
                Duration::from_millis(100),
                Duration::from_millis(10),
            )
            .unwrap();
        assert_eq!(engine.profile(), MorphologyProfile::TunedLowLatency);
        assert_eq!(
            engine.metrics().last_reason,
            Some(TransitionReason::QueueAge)
        );
        assert_eq!(engine.metrics().queue_age_transitions, 1);
        assert_eq!(
            engine.metrics().switches,
            engine.metrics().payload_transitions
                + engine.metrics().burst_transitions
                + engine.metrics().queue_age_transitions
        );
    }

    #[test]
    fn dwell_prevents_oscillation_and_invalid_observations_preserve_state() {
        let mut engine = WorkloadMorphology::from_seed(WorkloadConfig::default(), 3).unwrap();
        for millis in 0..100 {
            engine
                .encode(
                    &[0; 1300],
                    1472,
                    Duration::from_millis(millis),
                    Duration::ZERO,
                )
                .unwrap();
            assert_eq!(engine.profile(), MorphologyProfile::TunedLowLatency);
        }
        engine
            .encode(&[0; 1300], 1472, Duration::from_millis(100), Duration::ZERO)
            .unwrap();
        assert_eq!(engine.profile(), MorphologyProfile::TunedBulkLab);
        assert_eq!(engine.metrics().burst_transitions, 1);
        engine
            .encode(
                &[0; 1300],
                1472,
                Duration::from_millis(101),
                Duration::from_millis(20),
            )
            .unwrap();
        assert_eq!(engine.profile(), MorphologyProfile::TunedBulkLab);
        assert_eq!(engine.metrics().queue_age_transitions, 0);
        assert!(engine.metrics().dwell_suppressed > 0);

        let state = (
            engine.profile(),
            engine.last_observation,
            engine.last_switch,
            engine.ewma,
            engine.metrics(),
        );
        assert!(engine
            .encode(&[0; 1300], 1472, Duration::from_millis(99), Duration::ZERO)
            .is_err());
        assert_eq!(
            (
                engine.profile(),
                engine.last_observation,
                engine.last_switch,
                engine.ewma,
                engine.metrics(),
            ),
            state
        );
        assert!(engine
            .encode(&[0; 2000], 1472, Duration::from_millis(101), Duration::ZERO)
            .is_err());
        assert_eq!(
            (
                engine.profile(),
                engine.last_observation,
                engine.last_switch,
                engine.ewma,
                engine.metrics(),
            ),
            state
        );
    }

    #[test]
    fn workload_configuration_and_burst_counters_are_bounded() {
        let mut invalid = WorkloadConfig {
            minimum_dwell: Duration::from_secs(61),
            ..WorkloadConfig::default()
        };
        assert!(WorkloadMorphology::from_seed(invalid, 4).is_err());
        invalid = WorkloadConfig {
            burst_gap: Duration::ZERO,
            ..WorkloadConfig::default()
        };
        assert!(WorkloadMorphology::from_seed(invalid, 4).is_err());
        invalid = WorkloadConfig {
            burst_threshold: 1,
            ..WorkloadConfig::default()
        };
        assert!(WorkloadMorphology::from_seed(invalid, 4).is_err());
        invalid = WorkloadConfig {
            queue_age_limit: Duration::from_secs(2),
            ..WorkloadConfig::default()
        };
        assert!(WorkloadMorphology::from_seed(invalid, 4).is_err());

        let mut engine = WorkloadMorphology::from_seed(WorkloadConfig::default(), 5).unwrap();
        for _ in 0..1_025 {
            engine
                .encode(b"x", 1472, Duration::ZERO, Duration::ZERO)
                .unwrap();
        }
        assert_eq!(engine.metrics().burst_length, 1_024);
        assert_eq!(engine.metrics().observations, 1_025);
    }

    #[test]
    fn aggregate_transition_counters_saturate() {
        let config = WorkloadConfig {
            minimum_dwell: Duration::ZERO,
            use_arrivals: false,
            use_queue_age: false,
            ..WorkloadConfig::default()
        };
        let mut engine = WorkloadMorphology::from_seed(config, 6).unwrap();
        engine.ewma = 191;
        engine.metrics.observations = u64::MAX;
        engine.metrics.switches = u64::MAX;
        engine.metrics.payload_transitions = u64::MAX;

        engine
            .encode(&[0; 1000], 1472, Duration::ZERO, Duration::ZERO)
            .unwrap();

        assert_eq!(engine.profile(), MorphologyProfile::TunedWebBrowsingLab);
        assert_eq!(engine.metrics().observations, u64::MAX);
        assert_eq!(engine.metrics().switches, u64::MAX);
        assert_eq!(engine.metrics().payload_transitions, u64::MAX);
    }
}
