//! Independent, opt-in Shroud 3 morphology for authenticated QUIC datagrams.
//!
//! Shroud 3 owns its workload state machine and joint size/delay sampler. It
//! does not call the Shroud 2 encoder or reuse its morphology classes. The
//! seven-byte S3 v1 envelope remains a framing format; it is not evidence that
//! the resulting traffic is harder to classify.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use shph_core::{Result, ShphError};
use std::time::Duration;
use zeroize::Zeroize;

pub const SHROUD3_MAGIC: [u8; 2] = *b"S3";
pub const SHROUD3_VERSION: u8 = 1;
pub const SHROUD3_HEADER_BYTES: usize = 7;
pub const MAX_SHROUD3_DATAGRAM_BYTES: usize = u16::MAX as usize;
pub const MAX_SHROUD3_PADDING_BYTES: usize = 4_096;
pub const MAX_SHROUD3_PROFILE_BINS: usize = 64;
pub const MAX_SHROUD3_DELAY: Duration = Duration::from_millis(100);

const WORKLOAD_WINDOW_CAPACITY: usize = 16;
const MAX_MINIMUM_DWELL: Duration = Duration::from_secs(60);
const MAX_BURST_GAP: Duration = Duration::from_secs(1);
const MAX_SUSTAINED_GAP: Duration = Duration::from_secs(1);
const MAX_QUEUE_AGE: Duration = Duration::from_secs(1);
const MAX_BURST_LENGTH: u32 = 1_024;
const MAX_TRANSITION_CONFIRMATIONS: u8 = 16;

/// Workload state selected from the caller's size, arrival, and queue signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shroud3WorkloadMode {
    Interactive,
    Bursty,
    Sustained,
    QueuePressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shroud3TransitionReason {
    WindowTrend,
    BurstDensity,
    QueuePressure,
}

/// Session-relative monotonic time and time already spent queued by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shroud3Observation {
    pub observed_at: Duration,
    pub queue_age: Duration,
}

/// One point in a bounded joint distribution over extra padding and send delay.
///
/// Padding is expressed in multiples of the profile's size quantum. Keeping
/// size and delay in one weighted choice preserves their configured
/// relationship. Profile values are operator-supplied lab parameters; the
/// defaults are not fitted to browser or background traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shroud3JointBin {
    pub extra_padding_quanta: u16,
    pub shaping_delay: Duration,
    pub weight: u32,
}

/// Bounded parametric joint profile for one workload mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shroud3JointProfile {
    pub size_quantum: usize,
    pub bins: Vec<Shroud3JointBin>,
}

impl Shroud3JointProfile {
    pub fn new(size_quantum: usize, bins: Vec<Shroud3JointBin>) -> Self {
        Self { size_quantum, bins }
    }

    fn validate(&self, max_delay: Duration) -> Result<()> {
        if !(1..=256).contains(&self.size_quantum) || !self.size_quantum.is_power_of_two() {
            return Err(ShphError::Config(
                "Shroud 3 size quantum must be a power of two from 1 through 256".into(),
            ));
        }
        if self.bins.is_empty() || self.bins.len() > MAX_SHROUD3_PROFILE_BINS {
            return Err(ShphError::Config(format!(
                "Shroud 3 profile must contain 1 through {MAX_SHROUD3_PROFILE_BINS} bins"
            )));
        }
        let mut total_weight = 0u64;
        let mut has_zero_fallback = false;
        for bin in &self.bins {
            if bin.weight == 0 {
                return Err(ShphError::Config(
                    "Shroud 3 profile weights must be nonzero".into(),
                ));
            }
            if bin.shaping_delay > max_delay {
                return Err(ShphError::Config(
                    "Shroud 3 profile delay exceeds its configured maximum".into(),
                ));
            }
            total_weight = total_weight
                .checked_add(u64::from(bin.weight))
                .ok_or_else(|| ShphError::Config("Shroud 3 profile weight overflow".into()))?;
            has_zero_fallback |= bin.extra_padding_quanta == 0 && bin.shaping_delay.is_zero();
        }
        if total_weight == 0 || !has_zero_fallback {
            return Err(ShphError::Config(
                "each Shroud 3 profile needs a zero-padding, zero-delay choice".into(),
            ));
        }
        Ok(())
    }
}

/// Four independently configurable parametric workload profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shroud3Profiles {
    pub interactive: Shroud3JointProfile,
    pub bursty: Shroud3JointProfile,
    pub sustained: Shroud3JointProfile,
    pub queue_pressure: Shroud3JointProfile,
}

impl Default for Shroud3Profiles {
    fn default() -> Self {
        let profile = |size_quantum, bins: &[(u16, u64, u32)]| {
            Shroud3JointProfile::new(
                size_quantum,
                bins.iter()
                    .map(
                        |(extra_padding_quanta, delay_micros, weight)| Shroud3JointBin {
                            extra_padding_quanta: *extra_padding_quanta,
                            shaping_delay: Duration::from_micros(*delay_micros),
                            weight: *weight,
                        },
                    )
                    .collect(),
            )
        };

        Self {
            interactive: profile(
                16,
                &[(0, 0, 50), (0, 250, 20), (1, 500, 20), (4, 1_000, 10)],
            ),
            bursty: profile(32, &[(0, 0, 35), (1, 100, 20), (2, 250, 30), (4, 500, 15)]),
            sustained: profile(64, &[(0, 0, 20), (1, 100, 20), (2, 250, 30), (4, 500, 30)]),
            queue_pressure: profile(16, &[(0, 0, 90), (1, 0, 10)]),
        }
    }
}

/// Configuration for the independent Shroud 3 workload and joint shape engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shroud3Config {
    pub minimum_dwell: Duration,
    pub burst_gap: Duration,
    pub sustained_activity_gap: Duration,
    pub burst_length_threshold: u32,
    pub burst_density_threshold_percent: u8,
    pub queue_age_limit: Duration,
    pub sustained_payload_threshold: usize,
    pub transition_confirmations: u8,
    pub max_padding_bytes: usize,
    pub max_shaping_delay: Duration,
    pub profiles: Shroud3Profiles,
}

impl Default for Shroud3Config {
    fn default() -> Self {
        Self {
            minimum_dwell: Duration::from_millis(100),
            burst_gap: Duration::from_millis(5),
            sustained_activity_gap: Duration::from_millis(250),
            burst_length_threshold: 4,
            burst_density_threshold_percent: 60,
            queue_age_limit: Duration::from_millis(10),
            sustained_payload_threshold: 1_024,
            transition_confirmations: 2,
            max_padding_bytes: 1_024,
            max_shaping_delay: Duration::from_millis(10),
            profiles: Shroud3Profiles::default(),
        }
    }
}

impl Shroud3Config {
    fn validate(&self) -> Result<()> {
        if self.minimum_dwell > MAX_MINIMUM_DWELL
            || self.burst_gap.is_zero()
            || self.burst_gap > MAX_BURST_GAP
            || self.sustained_activity_gap.is_zero()
            || self.sustained_activity_gap > MAX_SUSTAINED_GAP
            || !(2..=MAX_BURST_LENGTH).contains(&self.burst_length_threshold)
            || !(1..=100).contains(&self.burst_density_threshold_percent)
            || self.queue_age_limit.is_zero()
            || self.queue_age_limit > MAX_QUEUE_AGE
            || self.sustained_payload_threshold == 0
            || self.sustained_payload_threshold > u16::MAX as usize
            || !(1..=MAX_TRANSITION_CONFIRMATIONS).contains(&self.transition_confirmations)
            || self.max_padding_bytes > MAX_SHROUD3_PADDING_BYTES
            || self.max_shaping_delay > MAX_SHROUD3_DELAY
        {
            return Err(ShphError::Config(
                "invalid Shroud 3 workload or resource bounds".into(),
            ));
        }
        self.profiles.interactive.validate(self.max_shaping_delay)?;
        self.profiles.bursty.validate(self.max_shaping_delay)?;
        self.profiles.sustained.validate(self.max_shaping_delay)?;
        self.profiles
            .queue_pressure
            .validate(self.max_shaping_delay)?;
        Ok(())
    }

    fn profile(&self, mode: Shroud3WorkloadMode) -> &Shroud3JointProfile {
        match mode {
            Shroud3WorkloadMode::Interactive => &self.profiles.interactive,
            Shroud3WorkloadMode::Bursty => &self.profiles.bursty,
            Shroud3WorkloadMode::Sustained => &self.profiles.sustained,
            Shroud3WorkloadMode::QueuePressure => &self.profiles.queue_pressure,
        }
    }
}

/// Counters for one independent Shroud 3 engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Shroud3Metrics {
    pub observations: u64,
    pub switches: u64,
    pub burst_transitions: u64,
    pub window_trend_transitions: u64,
    pub queue_pressure_transitions: u64,
    pub transition_deferred: u64,
    pub profile_fallback_frames: u64,
    pub burst_length: u32,
    pub payload_bytes: u64,
    pub wire_bytes: u64,
    pub padding_bytes: u64,
    pub total_shaping_delay_nanos: u128,
    pub min_wire_bytes: Option<usize>,
    pub max_wire_bytes: Option<usize>,
    pub last_reason: Option<Shroud3TransitionReason>,
}

impl Shroud3Metrics {
    pub fn average_wire_bytes(self) -> Option<f64> {
        (self.observations > 0).then(|| self.wire_bytes as f64 / self.observations as f64)
    }

    pub fn overhead_pct(self) -> Option<f64> {
        (self.payload_bytes > 0).then(|| {
            self.wire_bytes.saturating_sub(self.payload_bytes) as f64 / self.payload_bytes as f64
                * 100.0
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct WindowSample {
    payload_bytes: usize,
    inter_arrival: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
struct TransitionPlan {
    mode: Shroud3WorkloadMode,
    pending_mode: Option<Shroud3WorkloadMode>,
    pending_count: u8,
    reason: Option<Shroud3TransitionReason>,
    deferred: bool,
}

/// Adaptive Shroud 3 state, scoped to one authenticated connection direction.
pub struct AdaptiveShroud3 {
    config: Shroud3Config,
    rng: StdRng,
    mode: Shroud3WorkloadMode,
    history: [WindowSample; WORKLOAD_WINDOW_CAPACITY],
    history_len: usize,
    history_next: usize,
    pending_mode: Option<Shroud3WorkloadMode>,
    pending_count: u8,
    last_observation: Option<Duration>,
    last_transition: Option<Duration>,
    burst_length: u32,
    pending_delay: Duration,
    metrics: Shroud3Metrics,
}

impl AdaptiveShroud3 {
    /// Create an engine with operating-system seeded randomness.
    pub fn new(config: Shroud3Config) -> Result<Self> {
        Self::with_rng(config, StdRng::from_entropy())
    }

    /// Deterministic constructor for unit tests.
    /// Do not use it for production or benchmark wire padding.
    #[cfg(test)]
    pub fn from_seed(config: Shroud3Config, seed: u64) -> Result<Self> {
        Self::with_rng(config, StdRng::seed_from_u64(seed))
    }

    fn with_rng(config: Shroud3Config, rng: StdRng) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            rng,
            mode: Shroud3WorkloadMode::Interactive,
            history: [WindowSample::default(); WORKLOAD_WINDOW_CAPACITY],
            history_len: 0,
            history_next: 0,
            pending_mode: None,
            pending_count: 0,
            last_observation: None,
            last_transition: None,
            burst_length: 0,
            pending_delay: Duration::ZERO,
            metrics: Shroud3Metrics::default(),
        })
    }

    pub fn mode(&self) -> Shroud3WorkloadMode {
        self.mode
    }

    pub fn metrics(&self) -> Shroud3Metrics {
        self.metrics
    }

    /// Return the delay selected jointly with the most recently encoded frame.
    pub fn next_delay(&self) -> Duration {
        self.pending_delay
    }

    /// Encode one payload using caller-supplied monotonic time and queue age.
    pub fn encode(
        &mut self,
        payload: &[u8],
        path_mtu: usize,
        observation: Shroud3Observation,
    ) -> Result<Vec<u8>> {
        let minimum = validate_payload_for_path(payload.len(), path_mtu)?;
        if self
            .last_observation
            .is_some_and(|last| observation.observed_at < last)
        {
            return Err(ShphError::InvalidArgument(
                "nonmonotonic Shroud 3 observation".into(),
            ));
        }

        let inter_arrival = self
            .last_observation
            .map(|last| observation.observed_at - last);
        let burst_length = if inter_arrival.is_some_and(|gap| gap <= self.config.burst_gap) {
            self.burst_length.saturating_add(1).min(MAX_BURST_LENGTH)
        } else {
            1
        };
        let mut history = self.history;
        let history_len = (self.history_len + 1).min(WORKLOAD_WINDOW_CAPACITY);
        let history_next = (self.history_next + 1) % WORKLOAD_WINDOW_CAPACITY;
        history[self.history_next] = WindowSample {
            payload_bytes: payload.len(),
            inter_arrival,
        };

        let observed_mode =
            self.classify_workload(&history[..history_len], burst_length, observation.queue_age);
        let transition = self.plan_transition(observed_mode, observation.observed_at);
        let mut rng = self.rng.clone();
        let (target_size, shaping_delay, used_profile_fallback) =
            self.select_joint_shape(transition.mode, minimum, path_mtu, &mut rng);

        let payload_len = u16::try_from(payload.len())
            .map_err(|_| ShphError::Protocol("Shroud 3 payload length overflow".into()))?;
        let target_len = u16::try_from(target_size)
            .map_err(|_| ShphError::Protocol("Shroud 3 datagram length overflow".into()))?;
        let mut datagram = vec![0u8; target_size];
        datagram[..2].copy_from_slice(&SHROUD3_MAGIC);
        datagram[2] = SHROUD3_VERSION;
        datagram[3..5].copy_from_slice(&payload_len.to_be_bytes());
        datagram[5..7].copy_from_slice(&target_len.to_be_bytes());
        datagram[SHROUD3_HEADER_BYTES..minimum].copy_from_slice(payload);
        if rng.try_fill_bytes(&mut datagram[minimum..]).is_err() {
            datagram.zeroize();
            return Err(ShphError::Crypto(
                "Shroud 3 padding randomness failed".into(),
            ));
        }

        self.rng = rng;
        self.history = history;
        self.history_len = history_len;
        self.history_next = history_next;
        self.mode = transition.mode;
        self.pending_mode = transition.pending_mode;
        self.pending_count = transition.pending_count;
        self.last_observation = Some(observation.observed_at);
        self.last_transition = if transition.reason.is_some() {
            Some(observation.observed_at)
        } else {
            self.last_transition
        };
        self.burst_length = burst_length;
        self.pending_delay = shaping_delay;
        self.record(
            payload.len(),
            target_size,
            shaping_delay,
            transition,
            used_profile_fallback,
        );
        Ok(datagram)
    }

    fn classify_workload(
        &self,
        history: &[WindowSample],
        burst_length: u32,
        queue_age: Duration,
    ) -> Shroud3WorkloadMode {
        if queue_age >= self.config.queue_age_limit {
            return Shroud3WorkloadMode::QueuePressure;
        }
        if burst_length >= self.config.burst_length_threshold
            && burst_density_percent(history, self.config.burst_gap)
                >= self.config.burst_density_threshold_percent
        {
            return Shroud3WorkloadMode::Bursty;
        }
        if history.len() >= 4
            && median_payload_bytes(history) >= self.config.sustained_payload_threshold
            && median_inter_arrival(history)
                .is_some_and(|gap| gap <= self.config.sustained_activity_gap)
        {
            return Shroud3WorkloadMode::Sustained;
        }
        Shroud3WorkloadMode::Interactive
    }

    fn plan_transition(
        &self,
        observed_mode: Shroud3WorkloadMode,
        observed_at: Duration,
    ) -> TransitionPlan {
        if observed_mode == self.mode {
            return TransitionPlan {
                mode: self.mode,
                pending_mode: None,
                pending_count: 0,
                reason: None,
                deferred: false,
            };
        }
        if observed_mode == Shroud3WorkloadMode::QueuePressure {
            return TransitionPlan {
                mode: observed_mode,
                pending_mode: None,
                pending_count: 0,
                reason: Some(Shroud3TransitionReason::QueuePressure),
                deferred: false,
            };
        }

        let pending_count = if self.pending_mode == Some(observed_mode) {
            self.pending_count.saturating_add(1)
        } else {
            1
        };
        let dwell_elapsed = self
            .last_transition
            .is_none_or(|last| observed_at.saturating_sub(last) >= self.config.minimum_dwell);
        if pending_count >= self.config.transition_confirmations && dwell_elapsed {
            TransitionPlan {
                mode: observed_mode,
                pending_mode: None,
                pending_count: 0,
                reason: Some(transition_reason(observed_mode)),
                deferred: false,
            }
        } else {
            TransitionPlan {
                mode: self.mode,
                pending_mode: Some(observed_mode),
                pending_count,
                reason: None,
                deferred: true,
            }
        }
    }

    fn select_joint_shape(
        &self,
        mode: Shroud3WorkloadMode,
        minimum: usize,
        path_mtu: usize,
        rng: &mut StdRng,
    ) -> (usize, Duration, bool) {
        let profile = self.config.profile(mode);
        let base = align_up(minimum, profile.size_quantum);
        let max_wire_size = path_mtu.min(minimum.saturating_add(self.config.max_padding_bytes));
        let mut total_weight = 0u64;
        for bin in &profile.bins {
            if let Some(target) = shape_target(base, profile.size_quantum, bin) {
                if target >= minimum && target <= max_wire_size {
                    total_weight = total_weight.saturating_add(u64::from(bin.weight));
                }
            }
        }
        if total_weight == 0 {
            return (minimum, Duration::ZERO, true);
        }

        let mut sample = rng.gen_range(0..total_weight);
        for bin in &profile.bins {
            let Some(target) = shape_target(base, profile.size_quantum, bin) else {
                continue;
            };
            if target < minimum || target > max_wire_size {
                continue;
            }
            let weight = u64::from(bin.weight);
            if sample < weight {
                return (target, bin.shaping_delay, false);
            }
            sample -= weight;
        }
        // The total is calculated from the same bounded choices above. Keep a
        // fail-closed exact-size result for defensive handling of arithmetic
        // edge cases rather than indexing beyond the profile.
        (minimum, Duration::ZERO, true)
    }

    fn record(
        &mut self,
        payload_bytes: usize,
        wire_bytes: usize,
        shaping_delay: Duration,
        transition: TransitionPlan,
        used_profile_fallback: bool,
    ) {
        self.metrics.observations = self.metrics.observations.saturating_add(1);
        self.metrics.payload_bytes = self
            .metrics
            .payload_bytes
            .saturating_add(payload_bytes as u64);
        self.metrics.wire_bytes = self.metrics.wire_bytes.saturating_add(wire_bytes as u64);
        self.metrics.padding_bytes = self.metrics.padding_bytes.saturating_add(
            wire_bytes
                .saturating_sub(payload_bytes)
                .saturating_sub(SHROUD3_HEADER_BYTES) as u64,
        );
        self.metrics.total_shaping_delay_nanos = self
            .metrics
            .total_shaping_delay_nanos
            .saturating_add(shaping_delay.as_nanos());
        self.metrics.min_wire_bytes = Some(
            self.metrics
                .min_wire_bytes
                .map_or(wire_bytes, |current| current.min(wire_bytes)),
        );
        self.metrics.max_wire_bytes = Some(
            self.metrics
                .max_wire_bytes
                .map_or(wire_bytes, |current| current.max(wire_bytes)),
        );
        self.metrics.burst_length = self.burst_length;
        self.metrics.transition_deferred = self
            .metrics
            .transition_deferred
            .saturating_add(u64::from(transition.deferred));
        if used_profile_fallback {
            self.metrics.profile_fallback_frames =
                self.metrics.profile_fallback_frames.saturating_add(1);
        }
        if let Some(reason) = transition.reason {
            self.metrics.switches = self.metrics.switches.saturating_add(1);
            self.metrics.last_reason = Some(reason);
            match reason {
                Shroud3TransitionReason::WindowTrend => {
                    self.metrics.window_trend_transitions =
                        self.metrics.window_trend_transitions.saturating_add(1);
                }
                Shroud3TransitionReason::BurstDensity => {
                    self.metrics.burst_transitions =
                        self.metrics.burst_transitions.saturating_add(1);
                }
                Shroud3TransitionReason::QueuePressure => {
                    self.metrics.queue_pressure_transitions =
                        self.metrics.queue_pressure_transitions.saturating_add(1);
                }
            }
        }
    }
}

fn transition_reason(mode: Shroud3WorkloadMode) -> Shroud3TransitionReason {
    match mode {
        Shroud3WorkloadMode::Bursty => Shroud3TransitionReason::BurstDensity,
        Shroud3WorkloadMode::QueuePressure => Shroud3TransitionReason::QueuePressure,
        Shroud3WorkloadMode::Interactive | Shroud3WorkloadMode::Sustained => {
            Shroud3TransitionReason::WindowTrend
        }
    }
}

fn align_up(value: usize, quantum: usize) -> usize {
    let remainder = value % quantum;
    if remainder == 0 {
        value
    } else {
        value.saturating_add(quantum - remainder)
    }
}

fn shape_target(base: usize, quantum: usize, bin: &Shroud3JointBin) -> Option<usize> {
    base.checked_add(usize::from(bin.extra_padding_quanta).checked_mul(quantum)?)
}

fn burst_density_percent(history: &[WindowSample], burst_gap: Duration) -> u8 {
    let mut intervals = 0usize;
    let mut close_intervals = 0usize;
    for sample in history {
        if let Some(inter_arrival) = sample.inter_arrival {
            intervals += 1;
            if inter_arrival <= burst_gap {
                close_intervals += 1;
            }
        }
    }
    if intervals < 3 {
        return 0;
    }
    ((close_intervals * 100) / intervals) as u8
}

fn median_payload_bytes(history: &[WindowSample]) -> usize {
    if history.is_empty() {
        return 0;
    }
    let mut payloads = [0usize; WORKLOAD_WINDOW_CAPACITY];
    for (index, sample) in history.iter().enumerate() {
        payloads[index] = sample.payload_bytes;
    }
    payloads[..history.len()].sort_unstable();
    payloads[history.len() / 2]
}

fn median_inter_arrival(history: &[WindowSample]) -> Option<Duration> {
    let mut intervals = [Duration::ZERO; WORKLOAD_WINDOW_CAPACITY];
    let mut count = 0usize;
    for interval in history.iter().filter_map(|sample| sample.inter_arrival) {
        intervals[count] = interval;
        count += 1;
    }
    if count == 0 {
        return None;
    }
    intervals[..count].sort_unstable();
    Some(intervals[count / 2])
}

fn validate_payload_for_path(payload_len: usize, path_mtu: usize) -> Result<usize> {
    if !(SHROUD3_HEADER_BYTES..=MAX_SHROUD3_DATAGRAM_BYTES).contains(&path_mtu) {
        return Err(ShphError::Protocol(
            "Shroud 3 path MTU is outside its supported range".into(),
        ));
    }
    if payload_len == 0 {
        return Err(ShphError::Protocol(
            "Shroud 3 payload must not be empty".into(),
        ));
    }
    if payload_len > u16::MAX as usize {
        return Err(ShphError::Protocol(
            "Shroud 3 payload exceeds its length field".into(),
        ));
    }
    let minimum = payload_len
        .checked_add(SHROUD3_HEADER_BYTES)
        .ok_or_else(|| ShphError::Protocol("Shroud 3 payload length overflow".into()))?;
    if minimum > path_mtu {
        return Err(ShphError::Protocol(
            "Shroud 3 payload exceeds the negotiated datagram limit".into(),
        ));
    }
    Ok(minimum)
}

/// Decode one Shroud 3 envelope into its application payload.
pub fn decode(datagram: &[u8], path_mtu: usize) -> Result<Vec<u8>> {
    let mut decoded = datagram.to_vec();
    match decode_in_place(&mut decoded, path_mtu) {
        Ok(()) => Ok(decoded),
        Err(error) => {
            decoded.zeroize();
            Err(error)
        }
    }
}

/// Validate and remove one Shroud 3 envelope in a caller-owned buffer.
pub fn decode_in_place(datagram: &mut Vec<u8>, path_mtu: usize) -> Result<()> {
    let result = decode_inner(datagram, path_mtu);
    if result.is_err() {
        datagram.zeroize();
        datagram.clear();
    }
    result
}

fn decode_inner(datagram: &mut Vec<u8>, path_mtu: usize) -> Result<()> {
    if !(SHROUD3_HEADER_BYTES..=MAX_SHROUD3_DATAGRAM_BYTES).contains(&path_mtu)
        || datagram.len() < SHROUD3_HEADER_BYTES
        || datagram.len() > path_mtu
    {
        return Err(ShphError::Protocol(
            "Shroud 3 datagram length is outside the negotiated limit".into(),
        ));
    }
    if datagram[..2] != SHROUD3_MAGIC || datagram[2] != SHROUD3_VERSION {
        return Err(ShphError::Protocol(
            "Shroud 3 envelope version mismatch".into(),
        ));
    }
    let payload_len = u16::from_be_bytes([datagram[3], datagram[4]]) as usize;
    let declared_size = u16::from_be_bytes([datagram[5], datagram[6]]) as usize;
    if declared_size != datagram.len() {
        return Err(ShphError::Protocol(
            "Shroud 3 datagram size does not match its envelope".into(),
        ));
    }
    let payload_end = SHROUD3_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| ShphError::Protocol("Shroud 3 payload length overflow".into()))?;
    if payload_len == 0
        || payload_end > datagram.len()
        || datagram.len().saturating_sub(payload_end) > MAX_SHROUD3_PADDING_BYTES
    {
        return Err(ShphError::Protocol(
            "Shroud 3 payload or padding length is invalid".into(),
        ));
    }
    datagram.copy_within(SHROUD3_HEADER_BYTES..payload_end, 0);
    datagram[payload_len..].zeroize();
    datagram.truncate(payload_len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(millis: u64) -> Shroud3Observation {
        Shroud3Observation {
            observed_at: Duration::from_millis(millis),
            queue_age: Duration::ZERO,
        }
    }

    fn immediate_config() -> Shroud3Config {
        Shroud3Config {
            minimum_dwell: Duration::ZERO,
            transition_confirmations: 1,
            ..Shroud3Config::default()
        }
    }

    #[test]
    fn independent_engine_round_trips_with_s3_v1_and_rejects_s2() {
        let mut engine = AdaptiveShroud3::from_seed(immediate_config(), 73).unwrap();
        let payload = b"independent adaptive frame";
        let encoded = engine.encode(payload, 1_472, observation(1)).unwrap();

        assert_eq!(&encoded[..2], &SHROUD3_MAGIC);
        assert_eq!(encoded[2], SHROUD3_VERSION);
        assert_eq!(
            u16::from_be_bytes([encoded[5], encoded[6]]) as usize,
            encoded.len()
        );
        assert_eq!(decode(&encoded, 1_472).unwrap(), payload);
        assert!(crate::shroud2::decode_datagram(&encoded, 1_472).is_err());
    }

    #[test]
    fn shroud3_rejects_s2_and_wipes_rejected_input() {
        let mut old_format = crate::shroud2::encode_datagram(b"old", 32, 1_472).unwrap();
        let error = decode_in_place(&mut old_format, 1_472).unwrap_err();
        assert!(matches!(error, ShphError::Protocol(_)));
        assert!(old_format.is_empty());
    }

    #[test]
    fn invalid_observation_does_not_advance_engine_state() {
        let mut engine = AdaptiveShroud3::from_seed(Shroud3Config::default(), 74).unwrap();
        let mut control = AdaptiveShroud3::from_seed(Shroud3Config::default(), 74).unwrap();
        engine.encode(b"a", 1_472, observation(10)).unwrap();
        control.encode(b"a", 1_472, observation(10)).unwrap();
        let state = (engine.mode(), engine.metrics(), engine.next_delay());
        let error = engine
            .encode(
                b"b",
                1_472,
                Shroud3Observation {
                    observed_at: Duration::from_millis(9),
                    queue_age: Duration::ZERO,
                },
            )
            .unwrap_err();
        assert!(matches!(error, ShphError::InvalidArgument(_)));
        assert_eq!(
            (engine.mode(), engine.metrics(), engine.next_delay()),
            state
        );
        assert_eq!(
            engine.encode(b"next", 1_472, observation(11)).unwrap(),
            control.encode(b"next", 1_472, observation(11)).unwrap()
        );
    }

    #[test]
    fn queue_pressure_overrides_dwell_and_selects_zero_delay_profile() {
        let mut config = Shroud3Config {
            minimum_dwell: Duration::from_secs(1),
            ..Shroud3Config::default()
        };
        config.profiles.queue_pressure = Shroud3JointProfile::new(
            16,
            vec![Shroud3JointBin {
                extra_padding_quanta: 0,
                shaping_delay: Duration::ZERO,
                weight: 1,
            }],
        );
        let mut engine = AdaptiveShroud3::from_seed(config, 75).unwrap();
        engine.encode(b"a", 1_472, observation(1)).unwrap();
        let mut delayed = observation(2);
        delayed.queue_age = Duration::from_millis(10);
        engine.encode(b"b", 1_472, delayed).unwrap();
        assert_eq!(engine.mode(), Shroud3WorkloadMode::QueuePressure);
        assert_eq!(engine.next_delay(), Duration::ZERO);
        assert_eq!(engine.metrics().queue_pressure_transitions, 1);
    }

    #[test]
    fn rolling_window_selects_bursty_and_sustained_modes() {
        let mut config = immediate_config();
        config.burst_length_threshold = 4;
        config.burst_density_threshold_percent = 60;
        let mut burst = AdaptiveShroud3::from_seed(config.clone(), 76).unwrap();
        for millis in 0..4 {
            burst.encode(b"x", 1_472, observation(millis * 2)).unwrap();
        }
        assert_eq!(burst.mode(), Shroud3WorkloadMode::Bursty);

        let mut sustained = AdaptiveShroud3::from_seed(config, 77).unwrap();
        for index in 0..WORKLOAD_WINDOW_CAPACITY {
            sustained
                .encode(&[0; 1_200], 1_472, observation(index as u64 * 100))
                .unwrap();
        }
        assert_eq!(sustained.mode(), Shroud3WorkloadMode::Sustained);
    }

    #[test]
    fn configured_arrival_gaps_drive_burst_and_sustained_modes() {
        let config = Shroud3Config {
            burst_gap: Duration::from_millis(20),
            sustained_activity_gap: Duration::from_millis(250),
            ..immediate_config()
        };
        let mut burst = AdaptiveShroud3::from_seed(config.clone(), 771).unwrap();
        for index in 0..4 {
            burst
                .encode(b"small", 1_472, observation(index * 10))
                .unwrap();
        }
        assert_eq!(burst.mode(), Shroud3WorkloadMode::Bursty);

        let mut inactive_large = AdaptiveShroud3::from_seed(config.clone(), 772).unwrap();
        for index in 0..4 {
            inactive_large
                .encode(&[0; 1_200], 1_472, observation(index * 300))
                .unwrap();
        }
        assert_eq!(inactive_large.mode(), Shroud3WorkloadMode::Interactive);

        let mut sustained = AdaptiveShroud3::from_seed(config, 773).unwrap();
        for index in 0..4 {
            sustained
                .encode(&[0; 1_200], 1_472, observation(index * 200))
                .unwrap();
        }
        assert_eq!(sustained.mode(), Shroud3WorkloadMode::Sustained);
    }

    #[test]
    fn joint_profile_preserves_size_and_delay_pairing() {
        let mut config = immediate_config();
        config.profiles.interactive = Shroud3JointProfile::new(
            16,
            vec![
                Shroud3JointBin {
                    extra_padding_quanta: 0,
                    shaping_delay: Duration::ZERO,
                    weight: 1,
                },
                Shroud3JointBin {
                    extra_padding_quanta: 2,
                    shaping_delay: Duration::from_millis(2),
                    weight: 1,
                },
            ],
        );
        let mut engine = AdaptiveShroud3::from_seed(config, 78).unwrap();
        for index in 0..128 {
            let encoded = engine
                .encode(b"pairing", 1_472, observation(index * 10))
                .unwrap();
            let padding = encoded.len() - SHROUD3_HEADER_BYTES - b"pairing".len();
            match engine.next_delay() {
                Duration::ZERO => assert!(padding < 16),
                delay if delay == Duration::from_millis(2) => assert!(padding >= 32),
                other => panic!("unexpected joint delay sample: {other:?}"),
            }
        }
    }

    #[test]
    fn path_mtu_and_padding_budgets_bound_every_sample() {
        let mut config = immediate_config();
        config.max_padding_bytes = 32;
        let mut engine = AdaptiveShroud3::from_seed(config, 79).unwrap();
        for index in 0..128 {
            let encoded = engine
                .encode(&[0x5a; 100], 112, observation(index))
                .unwrap();
            assert!(encoded.len() <= 112);
            assert!(encoded.len() - 100 - SHROUD3_HEADER_BYTES <= 32);
            assert_eq!(decode(&encoded, 112).unwrap(), vec![0x5a; 100]);
        }
        let shrunk = engine
            .encode(&[0x5a; 100], 107, observation(128))
            .expect("encode after path-MTU shrink");
        assert_eq!(shrunk.len(), 107);
        assert_eq!(decode(&shrunk, 107).unwrap(), vec![0x5a; 100]);
    }

    #[test]
    fn exact_fit_fallback_counts_padding_separately_from_framing() {
        let config = Shroud3Config {
            max_padding_bytes: 0,
            ..immediate_config()
        };
        let mut engine = AdaptiveShroud3::from_seed(config, 791).unwrap();
        let payload = b"x".repeat(100);
        let encoded = engine.encode(&payload, 107, observation(1)).unwrap();
        let metrics = engine.metrics();

        assert_eq!(encoded.len(), 107);
        assert_eq!(metrics.padding_bytes, 0);
        assert_eq!(metrics.profile_fallback_frames, 1);
        assert!((metrics.overhead_pct().unwrap() - 7.0).abs() < 1e-12);
    }

    #[test]
    fn profile_configuration_rejects_unbounded_or_invalid_joint_tables() {
        let config = Shroud3Config {
            max_padding_bytes: MAX_SHROUD3_PADDING_BYTES + 1,
            ..Shroud3Config::default()
        };
        assert!(AdaptiveShroud3::new(config).is_err());

        let config = Shroud3Config {
            max_shaping_delay: MAX_SHROUD3_DELAY + Duration::from_nanos(1),
            ..Shroud3Config::default()
        };
        assert!(AdaptiveShroud3::new(config).is_err());

        let mut config = Shroud3Config::default();
        config.profiles.bursty = Shroud3JointProfile::new(
            16,
            vec![Shroud3JointBin {
                extra_padding_quanta: 1,
                shaping_delay: Duration::ZERO,
                weight: 1,
            }],
        );
        assert!(AdaptiveShroud3::new(config).is_err());
    }

    #[test]
    fn seeded_joint_sampling_is_reproducible() {
        let config = immediate_config();
        let mut left = AdaptiveShroud3::from_seed(config.clone(), 80).unwrap();
        let mut right = AdaptiveShroud3::from_seed(config, 80).unwrap();
        for index in 0..64 {
            let observation = observation(index);
            let left_datagram = left.encode(b"same", 1_472, observation).unwrap();
            let right_datagram = right.encode(b"same", 1_472, observation).unwrap();
            assert_eq!(left_datagram, right_datagram);
            assert_eq!(left.next_delay(), right.next_delay());
        }
    }

    #[test]
    fn malformed_and_oversized_frames_are_wiped() {
        let mut engine = AdaptiveShroud3::from_seed(immediate_config(), 81).unwrap();
        let mut frame = engine.encode(b"payload", 1_472, observation(1)).unwrap();
        frame[5..7].copy_from_slice(&1u16.to_be_bytes());
        assert!(decode_in_place(&mut frame, 1_472).is_err());
        assert!(frame.is_empty());

        let mut excessive_padding =
            vec![0u8; SHROUD3_HEADER_BYTES + 1 + MAX_SHROUD3_PADDING_BYTES + 1];
        excessive_padding[..2].copy_from_slice(&SHROUD3_MAGIC);
        excessive_padding[2] = SHROUD3_VERSION;
        excessive_padding[3..5].copy_from_slice(&1u16.to_be_bytes());
        let declared_len = excessive_padding.len() as u16;
        excessive_padding[5..7].copy_from_slice(&declared_len.to_be_bytes());
        assert!(decode_in_place(&mut excessive_padding, 8_192).is_err());
        assert!(excessive_padding.is_empty());
    }
}
