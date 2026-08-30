//! Bounded Shroud 2.0 lab morphology for authenticated QUIC datagrams.
//!
//! This module deliberately does not implement browser fingerprint forgery,
//! active-probe deception, or a replacement for QUIC's congestion control and
//! loss recovery. It provides an explicit, measurable envelope for experiments
//! with payload-size classes and bounded inter-frame delay.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use shph_core::{Result, ShphError};
use std::collections::{btree_map::Entry, BTreeMap};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub const MORPHOLOGY_MAGIC: [u8; 2] = *b"S2";
pub const MORPHOLOGY_VERSION: u8 = 1;
pub const MORPHOLOGY_HEADER_BYTES: usize = 7;
pub const MAX_MORPHOLOGY_DATAGRAM_BYTES: usize = 65_535;
pub const BATCH_MESSAGE_LENGTH_BYTES: usize = 2;
pub const MAX_BATCH_MESSAGES: usize = 32;
pub const MAX_BATCH_WAIT: Duration = Duration::from_secs(1);
/// Maximum number of bins retained by the optional empirical sampler.
///
/// Sampling uses a precomputed CDF, so this bound also limits configuration
/// validation and the amount of distribution state held by one engine.
pub const MAX_HISTOGRAM_BINS: usize = 4_096;
/// Maximum number of samples accepted by the offline histogram builder.
pub const MAX_HISTOGRAM_SAMPLES: usize = 1_000_000;
const MAX_BATCH_PAYLOAD_BYTES: usize = MAX_MORPHOLOGY_DATAGRAM_BYTES - MORPHOLOGY_HEADER_BYTES;
const MAX_PROFILE_SIZE_CLASSES: usize = 8;

struct WipeBufferOnError<'a> {
    buffer: &'a mut Vec<u8>,
    committed: bool,
}

impl<'a> WipeBufferOnError<'a> {
    fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self {
            buffer,
            committed: false,
        }
    }

    fn prepare(&mut self, target_len: usize) {
        if self.buffer.len() > target_len {
            self.buffer[target_len..].zeroize();
        }
        self.buffer.clear();
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for WipeBufferOnError<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.buffer.zeroize();
            self.buffer.clear();
        }
    }
}

/// A normalized one-dimensional empirical distribution.
///
/// Bins are ordered sample values such as packet sizes or measured
/// inter-arrival times. This type is intentionally an offline/lab primitive:
/// it does not parse PCAP files and it does not claim that a sampled
/// distribution matches browser traffic.
#[derive(Debug, Clone, PartialEq)]
pub struct EmpiricalHistogram {
    bins: Vec<u64>,
    weights: Vec<f64>,
    cdf: Vec<f64>,
}

impl EmpiricalHistogram {
    /// Construct and normalize a finite, strictly ordered distribution.
    pub fn new(bins: Vec<u64>, weights: Vec<f64>) -> Result<Self> {
        if bins.is_empty() || bins.len() != weights.len() {
            return Err(ShphError::InvalidArgument(
                "histogram bins and weights must be non-empty and have equal length".into(),
            ));
        }
        if bins.len() > MAX_HISTOGRAM_BINS {
            return Err(ShphError::ResourceExhausted(format!(
                "histogram exceeds the {MAX_HISTOGRAM_BINS}-bin limit"
            )));
        }
        if bins.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ShphError::InvalidArgument(
                "histogram bins must be strictly increasing".into(),
            ));
        }
        if weights
            .iter()
            .any(|weight| !weight.is_finite() || *weight < 0.0)
        {
            return Err(ShphError::InvalidArgument(
                "histogram weights must be finite and non-negative".into(),
            ));
        }
        let total = weights.iter().sum::<f64>();
        if !total.is_finite() || total <= 0.0 {
            return Err(ShphError::InvalidArgument(
                "histogram weights must have a positive finite sum".into(),
            ));
        }
        let weights = weights
            .into_iter()
            .map(|weight| weight / total)
            .collect::<Vec<_>>();
        let mut cdf = Vec::with_capacity(weights.len());
        let mut cumulative = 0.0;
        for weight in &weights {
            cumulative += *weight;
            cdf.push(cumulative);
        }
        // Make the final interval closed against accumulated floating-point
        // rounding without changing the normalized public weights.
        *cdf.last_mut().expect("histogram is non-empty") = 1.0;
        Ok(Self { bins, weights, cdf })
    }

    /// Build a normalized histogram from observed integer samples.
    pub fn from_samples(samples: &[u64]) -> Result<Self> {
        if samples.is_empty() {
            return Err(ShphError::InvalidArgument(
                "histogram samples must not be empty".into(),
            ));
        }
        if samples.len() > MAX_HISTOGRAM_SAMPLES {
            return Err(ShphError::ResourceExhausted(format!(
                "histogram exceeds the {MAX_HISTOGRAM_SAMPLES}-sample limit"
            )));
        }
        let mut counts = BTreeMap::<u64, u64>::new();
        for sample in samples {
            let at_bin_limit = counts.len() >= MAX_HISTOGRAM_BINS;
            match counts.entry(*sample) {
                Entry::Occupied(entry) => {
                    let count = entry.into_mut();
                    *count = count.checked_add(1).ok_or_else(|| {
                        ShphError::ResourceExhausted("histogram sample count overflow".into())
                    })?;
                }
                Entry::Vacant(_entry) if at_bin_limit => {
                    return Err(ShphError::ResourceExhausted(format!(
                        "histogram exceeds the {MAX_HISTOGRAM_BINS}-bin limit"
                    )));
                }
                Entry::Vacant(entry) => {
                    entry.insert(1);
                }
            }
        }
        let (bins, counts): (Vec<_>, Vec<_>) = counts.into_iter().unzip();
        Self::new(bins, counts.into_iter().map(|count| count as f64).collect())
    }

    pub fn bins(&self) -> &[u64] {
        &self.bins
    }

    pub fn weights(&self) -> &[f64] {
        &self.weights
    }

    /// Sample one bin according to its normalized weight.
    pub fn sample_bin(&self, rng: &mut impl Rng) -> u64 {
        let target = rng.gen::<f64>();
        let index = self.cdf.partition_point(|bound| *bound <= target);
        self.bins
            .get(index)
            .copied()
            .unwrap_or_else(|| *self.bins.last().expect("histogram is non-empty"))
    }
}

/// Calculate the exact one-dimensional Wasserstein-1 distance between two
/// normalized discrete histograms.
pub fn wasserstein_distance(current: &EmpiricalHistogram, target: &EmpiricalHistogram) -> f64 {
    let mut current_index = 0usize;
    let mut target_index = 0usize;
    let mut current_mass: f64 = 0.0;
    let mut target_mass: f64 = 0.0;
    let mut previous_position = current.bins[0].min(target.bins[0]);
    let mut distance = 0.0;

    while current_index < current.bins.len() || target_index < target.bins.len() {
        let current_position = current.bins.get(current_index).copied().unwrap_or(u64::MAX);
        let target_position = target.bins.get(target_index).copied().unwrap_or(u64::MAX);
        let position = current_position.min(target_position);
        distance +=
            (current_mass - target_mass).abs() * position.saturating_sub(previous_position) as f64;

        while current.bins.get(current_index).copied() == Some(position) {
            current_mass += current.weights[current_index];
            current_index += 1;
        }
        while target.bins.get(target_index).copied() == Some(position) {
            target_mass += target.weights[target_index];
            target_index += 1;
        }
        previous_position = position;
    }

    distance
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MorphologyProfile {
    LowLatency,
    WebBrowsingLab,
    VideoStreamingLab,
    /// Large-payload video/application-stream profile.
    ///
    /// This profile is intentionally scoped to already-aggregated payloads
    /// near a 1,472-byte UDP payload budget. It is not a claim that arbitrary
    /// small video/control messages have low overhead.
    VideoStreamingLargePayloadLab,
    /// High-entropy, near-MTU video/application stream profile.
    ///
    /// This profile is intentionally scoped to already-aggregated payloads
    /// near a 1,472-byte UDP payload budget. Its tighter classes increase
    /// shape diversity without introducing a large padding step.
    VideoStreamingBalancedPayloadLab,
    BulkLab,
    /// Tuned interactive profile with small fitting classes.
    TunedLowLatency,
    /// Tuned general-purpose profile with intermediate classes.
    TunedWebBrowsingLab,
    /// Tuned video profile favoring path-aware near-MTU classes.
    TunedVideoStreamingLab,
    /// Tuned bulk profile that avoids classes which collapse above the path MTU.
    TunedBulkLab,
}

impl MorphologyProfile {
    fn size_classes(self) -> &'static [usize] {
        match self {
            Self::LowLatency => &[128, 256, 512, 1_024],
            Self::WebBrowsingLab => &[384, 768, 1_024, 1_280, 1_536],
            Self::VideoStreamingLab => &[1_024, 1_280, 1_536, 2_048, 4_096],
            Self::VideoStreamingLargePayloadLab => &[1_408, 1_440, 1_465],
            Self::VideoStreamingBalancedPayloadLab => &[1_415, 1_430, 1_445, 1_460, 1_472],
            Self::BulkLab => &[1_280, 2_048, 4_096, 8_192, 16_384],
            Self::TunedLowLatency => &[64, 96, 128, 192, 256, 512, 768],
            Self::TunedWebBrowsingLab => &[256, 384, 512, 768, 1_024, 1_280, 1_360],
            Self::TunedVideoStreamingLab => &[1_024, 1_152, 1_280, 1_360, 1_408, 1_440, 1_472],
            Self::TunedBulkLab => &[1_024, 1_152, 1_280, 1_360, 1_408, 1_440, 1_472],
        }
    }

    /// Weighted selection among eligible classes keeps larger buckets available
    /// for shape diversity without making them the common case. The weights
    /// are intentionally integer-valued so seeded lab runs remain reproducible.
    fn size_class_weights(self) -> Option<&'static [u32]> {
        match self {
            Self::LowLatency => Some(&[65, 25, 8, 2]),
            Self::WebBrowsingLab => Some(&[45, 30, 15, 8, 2]),
            Self::VideoStreamingLab => Some(&[45, 30, 15, 8, 2]),
            Self::VideoStreamingLargePayloadLab => Some(&[60, 30, 10]),
            Self::VideoStreamingBalancedPayloadLab => Some(&[35, 30, 20, 12, 3]),
            Self::BulkLab => None,
            Self::TunedLowLatency => Some(&[65, 20, 6, 4, 3, 1, 1]),
            Self::TunedWebBrowsingLab => Some(&[35, 25, 18, 12, 7, 2, 1]),
            Self::TunedVideoStreamingLab => Some(&[26, 24, 20, 14, 8, 5, 3]),
            Self::TunedBulkLab => Some(&[5, 10, 15, 20, 20, 15, 15]),
        }
    }

    fn jitter_bounds(self) -> (Duration, Duration) {
        match self {
            Self::LowLatency => (Duration::ZERO, Duration::from_micros(500)),
            Self::WebBrowsingLab => (Duration::from_micros(100), Duration::from_millis(8)),
            Self::VideoStreamingLab => (Duration::from_micros(50), Duration::from_millis(3)),
            Self::VideoStreamingLargePayloadLab => {
                (Duration::from_micros(50), Duration::from_millis(3))
            }
            Self::VideoStreamingBalancedPayloadLab => {
                (Duration::from_micros(50), Duration::from_millis(3))
            }
            Self::BulkLab => (Duration::ZERO, Duration::from_micros(750)),
            Self::TunedLowLatency => (Duration::ZERO, Duration::from_micros(250)),
            Self::TunedWebBrowsingLab => (Duration::from_micros(50), Duration::from_millis(5)),
            Self::TunedVideoStreamingLab => (Duration::from_micros(50), Duration::from_millis(3)),
            Self::TunedBulkLab => (Duration::ZERO, Duration::from_micros(500)),
        }
    }
}

#[derive(Debug)]
pub struct MorphologyEngine {
    profile: MorphologyProfile,
    rng: StdRng,
    size_histogram: Option<EmpiricalHistogram>,
    metrics: MorphologyMetrics,
    metrics_enabled: bool,
}

impl Clone for MorphologyEngine {
    /// Clone the configuration and counters, but never duplicate the live
    /// morphology RNG stream. A cloned engine starts with fresh entropy.
    fn clone(&self) -> Self {
        Self {
            profile: self.profile,
            rng: StdRng::from_entropy(),
            size_histogram: self.size_histogram.clone(),
            metrics: self.metrics,
            metrics_enabled: self.metrics_enabled,
        }
    }
}

/// Counters for one morphology engine's encoded frames.
///
/// These counters are local instrumentation only. They do not infer
/// classifier success, browser similarity, or censorship resistance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MorphologyMetrics {
    frames: u64,
    payload_bytes: u64,
    wire_bytes: u64,
    padding_bytes: u64,
    min_wire_bytes: Option<usize>,
    max_wire_bytes: Option<usize>,
}

impl MorphologyMetrics {
    pub const fn frames(self) -> u64 {
        self.frames
    }

    pub const fn payload_bytes(self) -> u64 {
        self.payload_bytes
    }

    pub const fn wire_bytes(self) -> u64 {
        self.wire_bytes
    }

    pub const fn padding_bytes(self) -> u64 {
        self.padding_bytes
    }

    pub const fn min_wire_bytes(self) -> Option<usize> {
        self.min_wire_bytes
    }

    pub const fn max_wire_bytes(self) -> Option<usize> {
        self.max_wire_bytes
    }

    pub fn average_wire_bytes(self) -> Option<f64> {
        (self.frames > 0).then(|| self.wire_bytes as f64 / self.frames as f64)
    }

    pub fn overhead_pct(self) -> Option<f64> {
        (self.payload_bytes > 0)
            .then(|| self.padding_bytes as f64 / self.payload_bytes as f64 * 100.0)
    }

    fn record(&mut self, payload_bytes: usize, wire_bytes: usize) {
        self.frames = self.frames.saturating_add(1);
        self.payload_bytes = self.payload_bytes.saturating_add(payload_bytes as u64);
        self.wire_bytes = self.wire_bytes.saturating_add(wire_bytes as u64);
        self.padding_bytes = self
            .padding_bytes
            .saturating_add(wire_bytes.saturating_sub(payload_bytes) as u64);
        self.min_wire_bytes = Some(
            self.min_wire_bytes
                .map_or(wire_bytes, |current| current.min(wire_bytes)),
        );
        self.max_wire_bytes = Some(
            self.max_wire_bytes
                .map_or(wire_bytes, |current| current.max(wire_bytes)),
        );
    }
}

/// Bounded thresholds for the session-local adaptive morphology experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveMorphologyConfig {
    interactive_enter: usize,
    interactive_exit: usize,
    video_enter: usize,
    video_exit: usize,
    bulk_enter: usize,
    bulk_exit: usize,
}

impl AdaptiveMorphologyConfig {
    pub fn new(
        interactive_enter: usize,
        interactive_exit: usize,
        video_enter: usize,
        video_exit: usize,
        bulk_enter: usize,
        bulk_exit: usize,
    ) -> Result<Self> {
        let config = Self {
            interactive_enter,
            interactive_exit,
            video_enter,
            video_exit,
            bulk_enter,
            bulk_exit,
        };
        config.validate()?;
        Ok(config)
    }

    pub const fn interactive_enter(self) -> usize {
        self.interactive_enter
    }

    pub const fn interactive_exit(self) -> usize {
        self.interactive_exit
    }

    pub const fn video_enter(self) -> usize {
        self.video_enter
    }

    pub const fn video_exit(self) -> usize {
        self.video_exit
    }

    pub const fn bulk_enter(self) -> usize {
        self.bulk_enter
    }

    pub const fn bulk_exit(self) -> usize {
        self.bulk_exit
    }

    fn validate(self) -> Result<()> {
        if self.interactive_exit >= self.interactive_enter
            || self.interactive_enter >= self.video_exit
            || self.video_exit >= self.video_enter
            || self.video_enter >= self.bulk_exit
            || self.bulk_exit >= self.bulk_enter
        {
            return Err(ShphError::Config(
                "adaptive morphology thresholds must be ordered with hysteresis".into(),
            ));
        }
        Ok(())
    }
}

impl Default for AdaptiveMorphologyConfig {
    fn default() -> Self {
        Self {
            interactive_enter: 192,
            interactive_exit: 128,
            video_enter: 900,
            video_exit: 640,
            bulk_enter: 1_350,
            bulk_exit: 1_100,
        }
    }
}

/// Session-scoped adaptive morphology over the existing tuned profiles.
///
/// The classifier is intentionally simple and bounded: it uses an integer
/// EWMA of payload sizes and hysteresis, not browser classification or hidden
/// background work.
#[derive(Debug)]
pub struct AdaptiveMorphologyEngine {
    engine: MorphologyEngine,
    config: AdaptiveMorphologyConfig,
    ewma_payload: usize,
    switches: u64,
}

/// Result of adding one application message to a bounded morphology batch.
///
/// When adding a message would exceed the negotiated datagram budget or the
/// message-count bound, the existing batch is returned and the new message is
/// buffered for the next batch. Callers should send the returned batch
/// immediately and flush the remaining batch at their normal latency boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum MorphologyBatchPushResult {
    Buffered,
    Flush(Vec<Vec<u8>>),
}

/// Caller-selected batching limits for small application messages.
///
/// The wait bound is a flush deadline, not a promise that a message will be
/// delivered within that duration. The caller must call
/// [`MorphologyBatcher::flush_if_due`] from its event loop or timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MorphologyBatchPolicy {
    max_messages: usize,
    max_wait: Duration,
}

impl MorphologyBatchPolicy {
    pub fn new(max_messages: usize, max_wait: Duration) -> Result<Self> {
        if !(1..=MAX_BATCH_MESSAGES).contains(&max_messages) {
            return Err(ShphError::Config(format!(
                "morphology batch message limit must be between 1 and {MAX_BATCH_MESSAGES}"
            )));
        }
        if max_wait > MAX_BATCH_WAIT {
            return Err(ShphError::Config(format!(
                "morphology batch wait must not exceed {} milliseconds",
                MAX_BATCH_WAIT.as_millis()
            )));
        }
        Ok(Self {
            max_messages,
            max_wait,
        })
    }

    /// Conservative lab defaults that trade a bounded latency budget for
    /// lower small-message overhead while preserving the discrete envelope.
    pub fn recommended(profile: MorphologyProfile) -> Self {
        match profile {
            MorphologyProfile::LowLatency => Self {
                max_messages: 4,
                max_wait: Duration::from_millis(2),
            },
            MorphologyProfile::WebBrowsingLab => Self {
                max_messages: 8,
                max_wait: Duration::from_millis(10),
            },
            MorphologyProfile::VideoStreamingLab => Self {
                max_messages: 8,
                max_wait: Duration::from_millis(20),
            },
            MorphologyProfile::VideoStreamingLargePayloadLab => Self {
                max_messages: 8,
                max_wait: Duration::from_millis(20),
            },
            MorphologyProfile::VideoStreamingBalancedPayloadLab => Self {
                max_messages: 8,
                max_wait: Duration::from_millis(20),
            },
            MorphologyProfile::BulkLab => Self {
                max_messages: MAX_BATCH_MESSAGES,
                max_wait: Duration::from_millis(50),
            },
            MorphologyProfile::TunedLowLatency => Self {
                max_messages: 6,
                max_wait: Duration::from_millis(2),
            },
            MorphologyProfile::TunedWebBrowsingLab => Self {
                max_messages: 10,
                max_wait: Duration::from_millis(8),
            },
            MorphologyProfile::TunedVideoStreamingLab => Self {
                max_messages: 8,
                max_wait: Duration::from_millis(16),
            },
            MorphologyProfile::TunedBulkLab => Self {
                max_messages: MAX_BATCH_MESSAGES,
                max_wait: Duration::from_millis(40),
            },
        }
    }

    pub const fn max_messages(self) -> usize {
        self.max_messages
    }

    pub const fn max_wait(self) -> Duration {
        self.max_wait
    }
}

impl Default for MorphologyBatchPolicy {
    fn default() -> Self {
        Self {
            max_messages: MAX_BATCH_MESSAGES,
            max_wait: MAX_BATCH_WAIT,
        }
    }
}

/// MTU-aware application-message coalescer for the authenticated morphology
/// envelope.
///
/// This is intentionally not used by the native-TUN bridge: an unreliable
/// batch would amplify loss across otherwise independent IP packets. It is
/// intended for small application messages carried through the opt-in
/// standards-QUIC morphology API.
#[derive(Debug, Default)]
pub struct MorphologyBatcher {
    messages: Vec<Vec<u8>>,
    encoded_payload_bytes: usize,
    policy: MorphologyBatchPolicy,
    first_message_at: Option<Instant>,
}

impl Drop for MorphologyBatcher {
    fn drop(&mut self) {
        for message in &mut self.messages {
            message.zeroize();
        }
    }
}

impl MorphologyBatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_policy(policy: MorphologyBatchPolicy) -> Self {
        Self {
            messages: Vec::new(),
            encoded_payload_bytes: 0,
            policy,
            first_message_at: None,
        }
    }

    pub fn for_profile(profile: MorphologyProfile) -> Self {
        Self::with_policy(MorphologyBatchPolicy::recommended(profile))
    }

    pub const fn policy(&self) -> MorphologyBatchPolicy {
        self.policy
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn is_due(&self) -> bool {
        self.first_message_at
            .is_some_and(|started_at| self.is_due_at(Instant::now(), started_at))
    }

    pub fn time_until_due(&self) -> Option<Duration> {
        self.first_message_at
            .map(|started_at| self.policy.max_wait.saturating_sub(started_at.elapsed()))
    }

    pub fn flush_if_due(&mut self) -> Option<Vec<Vec<u8>>> {
        if self.is_due() {
            self.flush()
        } else {
            None
        }
    }

    /// Add one message, returning a full previous batch when the new message
    /// should start the next datagram. A due batch is flushed before the new
    /// message is buffered.
    pub fn push(&mut self, message: &[u8], path_mtu: usize) -> Result<MorphologyBatchPushResult> {
        self.push_at(message, path_mtu, Instant::now())
    }

    fn push_at(
        &mut self,
        message: &[u8],
        path_mtu: usize,
        now: Instant,
    ) -> Result<MorphologyBatchPushResult> {
        validate_path_mtu(path_mtu)?;
        validate_batch_message(message)?;
        let maximum_payload_bytes = path_mtu - MORPHOLOGY_HEADER_BYTES;
        let message_bytes = BATCH_MESSAGE_LENGTH_BYTES
            .checked_add(message.len())
            .ok_or_else(|| ShphError::Protocol("batch message length overflow".into()))?;
        if message_bytes > maximum_payload_bytes {
            return Err(ShphError::Protocol(
                "batch message exceeds the negotiated datagram limit".into(),
            ));
        }

        let batch_is_due = self
            .first_message_at
            .is_some_and(|started_at| self.is_due_at(now, started_at));
        let next_payload_bytes = self
            .encoded_payload_bytes
            .checked_add(message_bytes)
            .ok_or_else(|| ShphError::Protocol("morphology batch length overflow".into()))?;
        if !self.messages.is_empty()
            && (batch_is_due
                || self.messages.len() >= self.policy.max_messages
                || next_payload_bytes > maximum_payload_bytes)
        {
            let flushed = self.flush().ok_or_else(|| {
                ShphError::Protocol("morphology batch state became inconsistent".into())
            })?;
            self.push_without_flush(message, now)?;
            return Ok(MorphologyBatchPushResult::Flush(flushed));
        }

        self.push_without_flush(message, now)?;
        Ok(MorphologyBatchPushResult::Buffered)
    }

    pub fn flush(&mut self) -> Option<Vec<Vec<u8>>> {
        if self.messages.is_empty() {
            return None;
        }
        self.encoded_payload_bytes = 0;
        self.first_message_at = None;
        Some(std::mem::take(&mut self.messages))
    }

    fn push_without_flush(&mut self, message: &[u8], now: Instant) -> Result<()> {
        if self.messages.is_empty() {
            self.first_message_at = Some(now);
        }
        self.encoded_payload_bytes = self
            .encoded_payload_bytes
            .checked_add(
                BATCH_MESSAGE_LENGTH_BYTES
                    .checked_add(message.len())
                    .ok_or_else(|| ShphError::Protocol("batch message length overflow".into()))?,
            )
            .ok_or_else(|| ShphError::Protocol("morphology batch length overflow".into()))?;
        self.messages.push(message.to_vec());
        Ok(())
    }

    fn is_due_at(&self, now: Instant, started_at: Instant) -> bool {
        now.saturating_duration_since(started_at) >= self.policy.max_wait
    }
}

impl MorphologyEngine {
    pub fn new(profile: MorphologyProfile) -> Self {
        Self {
            profile,
            rng: StdRng::from_entropy(),
            size_histogram: None,
            metrics: MorphologyMetrics::default(),
            metrics_enabled: false,
        }
    }

    pub fn from_seed(profile: MorphologyProfile, seed: u64) -> Self {
        Self {
            profile,
            rng: StdRng::seed_from_u64(seed),
            size_histogram: None,
            metrics: MorphologyMetrics::default(),
            metrics_enabled: false,
        }
    }

    /// Construct an engine using an explicit empirical CDF for outer sizes.
    ///
    /// The histogram is sampled with inverse-CDF selection and every result is
    /// still clamped to the negotiated path MTU and the current payload's
    /// minimum envelope size. This is a lab primitive, not a claim of traffic
    /// fingerprint equivalence.
    pub fn from_histogram(
        profile: MorphologyProfile,
        histogram: EmpiricalHistogram,
        seed: u64,
    ) -> Self {
        Self {
            profile,
            rng: StdRng::seed_from_u64(seed),
            size_histogram: Some(histogram),
            metrics: MorphologyMetrics::default(),
            metrics_enabled: false,
        }
    }

    pub fn profile(&self) -> MorphologyProfile {
        self.profile
    }

    pub fn metrics(&self) -> MorphologyMetrics {
        self.metrics
    }

    /// Enable local morphology counters for a measurement or diagnostic run.
    ///
    /// Counters are disabled by default so steady-state transport does not pay
    /// for instrumentation it does not consume.
    pub fn enable_metrics(&mut self) {
        self.metrics_enabled = true;
    }

    /// Enable local morphology counters and return the engine.
    pub fn with_metrics(mut self) -> Self {
        self.enable_metrics();
        self
    }

    pub fn metrics_enabled(&self) -> bool {
        self.metrics_enabled
    }

    pub fn set_metrics_enabled(&mut self, enabled: bool) {
        self.metrics_enabled = enabled;
    }

    pub fn reset_metrics(&mut self) {
        self.metrics = MorphologyMetrics::default();
    }

    fn set_profile(&mut self, profile: MorphologyProfile) {
        self.profile = profile;
        self.size_histogram = None;
    }

    /// Select an outer datagram size without exceeding the negotiated path MTU.
    ///
    /// The returned size includes the Shroud 2.0 envelope header and padding.
    /// A caller must still use the negotiated QUIC datagram limit, not a guessed
    /// Ethernet MTU, as the `path_mtu` argument.
    pub fn target_size(&mut self, payload_len: usize, path_mtu: usize) -> Result<usize> {
        let minimum = validate_payload_for_path(payload_len, path_mtu)?;

        let sampled = if let Some(histogram) = &self.size_histogram {
            usize::try_from(histogram.sample_bin(&mut self.rng)).unwrap_or(usize::MAX)
        } else {
            let classes = self.profile.size_classes();
            if let Some(weights) = self.profile.size_class_weights() {
                self.sample_weighted_size_class(classes, weights, minimum, path_mtu)
            } else {
                self.sample_uniform_size_class(classes, minimum, path_mtu)
            }
        };
        Ok(sampled.max(minimum).min(path_mtu))
    }

    /// Encode one morphology datagram using this engine's session-scoped RNG.
    ///
    /// Keeping tail generation on the same stateful CSPRNG as class selection
    /// avoids an OS-randomness request for every datagram while preserving
    /// unpredictable wire padding for engines created with [`Self::new`].
    pub fn encode_datagram(&mut self, payload: &[u8], path_mtu: usize) -> Result<Vec<u8>> {
        let mut datagram = Vec::new();
        self.encode_datagram_into(payload, path_mtu, &mut datagram)?;
        Ok(datagram)
    }

    /// Encode one morphology datagram into a caller-owned buffer.
    ///
    /// The buffer is cleared and reused. This is the preferred steady-state
    /// API for transport loops that already own a reusable frame buffer.
    pub fn encode_datagram_into(
        &mut self,
        payload: &[u8],
        path_mtu: usize,
        datagram: &mut Vec<u8>,
    ) -> Result<()> {
        let target_size = match self.target_size(payload.len(), path_mtu) {
            Ok(target_size) => target_size,
            Err(error) => {
                datagram.zeroize();
                datagram.clear();
                return Err(error);
            }
        };
        encode_datagram_with_rng_into(payload, target_size, path_mtu, &mut self.rng, datagram)?;
        if self.metrics_enabled {
            self.metrics.record(payload.len(), target_size);
        }
        Ok(())
    }

    fn sample_weighted_size_class(
        &mut self,
        classes: &[usize],
        weights: &[u32],
        minimum: usize,
        path_mtu: usize,
    ) -> usize {
        let mut eligible = [(0usize, 0u32); MAX_PROFILE_SIZE_CLASSES];
        let mut eligible_len = 0usize;
        for (class, weight) in classes.iter().copied().zip(weights) {
            if *weight == 0 {
                continue;
            }
            let effective_class = class.min(path_mtu);
            if effective_class < minimum {
                continue;
            }
            if eligible_len > 0 && eligible[eligible_len - 1].0 == effective_class {
                eligible[eligible_len - 1].1 = eligible[eligible_len - 1].1.saturating_add(*weight);
            } else {
                if eligible_len == MAX_PROFILE_SIZE_CLASSES {
                    break;
                }
                eligible[eligible_len] = (effective_class, *weight);
                eligible_len += 1;
            }
        }
        let total_weight = eligible[..eligible_len]
            .iter()
            .fold(0u64, |total, (_, weight)| {
                total.saturating_add(u64::from(*weight))
            });

        if total_weight == 0 {
            return minimum;
        }

        let mut selection = self.rng.gen_range(0..total_weight);
        for (class, weight) in eligible[..eligible_len].iter().copied() {
            if selection < u64::from(weight) {
                return class;
            }
            selection -= u64::from(weight);
        }
        // Keep this path total even if a future profile changes its static
        // weights without keeping the sum and ranges perfectly aligned.
        eligible[eligible_len.saturating_sub(1)].0
    }

    fn sample_uniform_size_class(
        &mut self,
        classes: &[usize],
        minimum: usize,
        path_mtu: usize,
    ) -> usize {
        let mut eligible = [0usize; MAX_PROFILE_SIZE_CLASSES];
        let mut eligible_len = 0usize;
        for class in classes.iter().copied() {
            if (minimum..=path_mtu).contains(&class) {
                if eligible_len == MAX_PROFILE_SIZE_CLASSES {
                    break;
                }
                eligible[eligible_len] = class;
                eligible_len += 1;
            }
        }
        if eligible_len == 0 {
            return minimum;
        }
        eligible[self.rng.gen_range(0..eligible_len)]
    }

    pub fn next_delay(&mut self) -> Duration {
        let (minimum, maximum) = self.profile.jitter_bounds();
        if minimum >= maximum {
            return minimum;
        }
        let min_nanos = minimum.as_nanos() as u64;
        let max_nanos = maximum.as_nanos() as u64;
        Duration::from_nanos(self.rng.gen_range(min_nanos..=max_nanos))
    }
}

impl AdaptiveMorphologyEngine {
    pub fn new(config: AdaptiveMorphologyConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            engine: MorphologyEngine::new(MorphologyProfile::TunedLowLatency),
            config,
            ewma_payload: 0,
            switches: 0,
        })
    }

    pub fn from_seed(config: AdaptiveMorphologyConfig, seed: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            engine: MorphologyEngine::from_seed(MorphologyProfile::TunedLowLatency, seed),
            config,
            ewma_payload: 0,
            switches: 0,
        })
    }

    pub fn config(&self) -> AdaptiveMorphologyConfig {
        self.config
    }

    pub fn profile(&self) -> MorphologyProfile {
        self.engine.profile()
    }

    pub fn ewma_payload_bytes(&self) -> usize {
        self.ewma_payload
    }

    pub fn profile_switches(&self) -> u64 {
        self.switches
    }

    pub fn metrics(&self) -> MorphologyMetrics {
        self.engine.metrics()
    }

    pub fn enable_metrics(&mut self) {
        self.engine.enable_metrics();
    }

    pub fn with_metrics(mut self) -> Self {
        self.enable_metrics();
        self
    }

    pub fn metrics_enabled(&self) -> bool {
        self.engine.metrics_enabled()
    }

    pub fn set_metrics_enabled(&mut self, enabled: bool) {
        self.engine.set_metrics_enabled(enabled);
    }

    pub fn encode_datagram(&mut self, payload: &[u8], path_mtu: usize) -> Result<Vec<u8>> {
        let mut datagram = Vec::new();
        self.encode_datagram_into(payload, path_mtu, &mut datagram)?;
        Ok(datagram)
    }

    pub fn encode_datagram_into(
        &mut self,
        payload: &[u8],
        path_mtu: usize,
        datagram: &mut Vec<u8>,
    ) -> Result<()> {
        if let Err(error) = validate_payload_for_path(payload.len(), path_mtu) {
            datagram.zeroize();
            datagram.clear();
            return Err(error);
        }
        self.observe_payload(payload.len());
        self.engine
            .encode_datagram_into(payload, path_mtu, datagram)
    }

    fn observe_payload(&mut self, payload_len: usize) {
        const EWMA_DIVISOR: usize = 4;
        let delta = payload_len.abs_diff(self.ewma_payload);
        let adjustment = delta.div_ceil(EWMA_DIVISOR);
        if payload_len >= self.ewma_payload {
            self.ewma_payload = self.ewma_payload.saturating_add(adjustment);
        } else {
            self.ewma_payload = self.ewma_payload.saturating_sub(adjustment);
        }

        let next = match self.profile() {
            MorphologyProfile::TunedLowLatency
                if self.ewma_payload >= self.config.interactive_enter =>
            {
                Some(MorphologyProfile::TunedWebBrowsingLab)
            }
            MorphologyProfile::TunedWebBrowsingLab
                if self.ewma_payload <= self.config.interactive_exit =>
            {
                Some(MorphologyProfile::TunedLowLatency)
            }
            MorphologyProfile::TunedWebBrowsingLab
                if self.ewma_payload >= self.config.video_enter =>
            {
                Some(MorphologyProfile::TunedVideoStreamingLab)
            }
            MorphologyProfile::TunedVideoStreamingLab
                if self.ewma_payload <= self.config.video_exit =>
            {
                Some(MorphologyProfile::TunedWebBrowsingLab)
            }
            MorphologyProfile::TunedVideoStreamingLab
                if self.ewma_payload >= self.config.bulk_enter =>
            {
                Some(MorphologyProfile::TunedBulkLab)
            }
            MorphologyProfile::TunedBulkLab if self.ewma_payload <= self.config.bulk_exit => {
                Some(MorphologyProfile::TunedVideoStreamingLab)
            }
            _ => None,
        };
        if let Some(profile) = next {
            self.engine.set_profile(profile);
            self.switches = self.switches.saturating_add(1);
        }
    }
}

pub fn validate_path_mtu(path_mtu: usize) -> Result<()> {
    if !(MORPHOLOGY_HEADER_BYTES..=MAX_MORPHOLOGY_DATAGRAM_BYTES).contains(&path_mtu) {
        return Err(ShphError::Config(format!(
            "morphology path MTU must be between {MORPHOLOGY_HEADER_BYTES} and {MAX_MORPHOLOGY_DATAGRAM_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Encode an authenticated-transport payload with bounded outer padding.
///
/// The QUIC implementation encrypts the complete DATAGRAM after this function
/// returns. Padding bytes therefore do not carry unauthenticated control data;
/// the fixed envelope header is only interpreted after QUIC authentication.
pub fn encode_datagram(payload: &[u8], target_size: usize, path_mtu: usize) -> Result<Vec<u8>> {
    let mut datagram = Vec::new();
    encode_datagram_with_rng_into(
        payload,
        target_size,
        path_mtu,
        &mut rand::rngs::OsRng,
        &mut datagram,
    )?;
    Ok(datagram)
}

fn encode_datagram_with_rng_into(
    payload: &[u8],
    target_size: usize,
    path_mtu: usize,
    rng: &mut impl RngCore,
    datagram: &mut Vec<u8>,
) -> Result<()> {
    // Rejected requests wipe the previous payload through the guard.
    // Successful requests overwrite every byte in the new envelope and only
    // wipe bytes retired by a shrink, keeping steady-state reuse bounded.
    let mut cleanup = WipeBufferOnError::new(datagram);
    let minimum = validate_payload_for_path(payload.len(), path_mtu)?;
    if target_size > path_mtu || target_size > MAX_MORPHOLOGY_DATAGRAM_BYTES {
        return Err(ShphError::Protocol(
            "morphology target exceeds negotiated datagram limit".into(),
        ));
    }
    if target_size < minimum {
        return Err(ShphError::Protocol(
            "morphology target is smaller than the payload".into(),
        ));
    }

    let target_size_u16 = u16::try_from(target_size)
        .map_err(|_| ShphError::Protocol("morphology target length overflow".into()))?;
    cleanup.prepare(target_size);
    cleanup.buffer.resize(target_size, 0);
    cleanup.buffer[..2].copy_from_slice(&MORPHOLOGY_MAGIC);
    cleanup.buffer[2] = MORPHOLOGY_VERSION;
    cleanup.buffer[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    cleanup.buffer[5..7].copy_from_slice(&target_size_u16.to_be_bytes());
    cleanup.buffer[7..minimum].copy_from_slice(payload);
    if rng.try_fill_bytes(&mut cleanup.buffer[minimum..]).is_err() {
        return Err(ShphError::Crypto(
            "morphology padding randomness failed".into(),
        ));
    }
    cleanup.commit();
    Ok(())
}

fn validate_payload_for_path(payload_len: usize, path_mtu: usize) -> Result<usize> {
    validate_path_mtu(path_mtu)?;
    if payload_len == 0 {
        return Err(ShphError::Protocol(
            "morphology payload must not be empty".into(),
        ));
    }
    if payload_len > u16::MAX as usize {
        return Err(ShphError::Protocol(
            "morphology payload exceeds the length field".into(),
        ));
    }
    let minimum = payload_len
        .checked_add(MORPHOLOGY_HEADER_BYTES)
        .ok_or_else(|| ShphError::Protocol("morphology payload length overflow".into()))?;
    if minimum > path_mtu {
        return Err(ShphError::Protocol(
            "morphology payload exceeds negotiated datagram limit".into(),
        ));
    }
    Ok(minimum)
}

fn validate_batch_message(message: &[u8]) -> Result<()> {
    if message.is_empty() {
        return Err(ShphError::Protocol(
            "morphology batch messages must not be empty".into(),
        ));
    }
    if message.len() > u16::MAX as usize {
        return Err(ShphError::Protocol(
            "morphology batch message exceeds the length field".into(),
        ));
    }
    Ok(())
}

/// Encode length-prefixed application messages for one morphology datagram.
///
/// The resulting payload is authenticated by the surrounding QUIC
/// connection, and the length prefixes are still bounded by the negotiated
/// path MTU and `MAX_BATCH_MESSAGES`.
pub fn encode_batch_payload<M: AsRef<[u8]>>(messages: &[M], path_mtu: usize) -> Result<Vec<u8>> {
    validate_path_mtu(path_mtu)?;
    if messages.is_empty() {
        return Err(ShphError::Protocol(
            "morphology batch must contain at least one message".into(),
        ));
    }
    if messages.len() > MAX_BATCH_MESSAGES {
        return Err(ShphError::Protocol(format!(
            "morphology batch exceeds the {MAX_BATCH_MESSAGES}-message limit"
        )));
    }

    let maximum_payload_bytes = path_mtu - MORPHOLOGY_HEADER_BYTES;
    let expected_payload_bytes = messages.iter().try_fold(0usize, |total, message| {
        let message = message.as_ref();
        validate_batch_message(message)?;
        total
            .checked_add(BATCH_MESSAGE_LENGTH_BYTES)
            .and_then(|length| length.checked_add(message.len()))
            .ok_or_else(|| ShphError::Protocol("morphology batch length overflow".into()))
    })?;
    if expected_payload_bytes > maximum_payload_bytes {
        return Err(ShphError::Protocol(
            "morphology batch exceeds the negotiated datagram limit".into(),
        ));
    }
    let mut payload = Vec::with_capacity(expected_payload_bytes);
    for message in messages {
        let message = message.as_ref();
        payload.extend_from_slice(&(message.len() as u16).to_be_bytes());
        payload.extend_from_slice(message);
    }
    Ok(payload)
}

/// Decode length-prefixed application messages from an authenticated
/// morphology payload.
pub fn decode_batch_payload(payload: &[u8]) -> Result<Vec<Vec<u8>>> {
    if payload.is_empty() {
        return Err(ShphError::Protocol(
            "morphology batch payload must not be empty".into(),
        ));
    }
    if payload.len() > MAX_BATCH_PAYLOAD_BYTES {
        return Err(ShphError::Protocol(
            "morphology batch payload exceeds the global envelope limit".into(),
        ));
    }

    let mut messages = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        if messages.len() >= MAX_BATCH_MESSAGES {
            return Err(ShphError::Protocol(format!(
                "morphology batch exceeds the {MAX_BATCH_MESSAGES}-message limit"
            )));
        }
        let length_end = offset
            .checked_add(BATCH_MESSAGE_LENGTH_BYTES)
            .ok_or_else(|| ShphError::Protocol("morphology batch offset overflow".into()))?;
        let length_bytes = payload.get(offset..length_end).ok_or_else(|| {
            ShphError::Protocol("morphology batch has a truncated length prefix".into())
        })?;
        let message_len = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
        if message_len == 0 {
            return Err(ShphError::Protocol(
                "morphology batch contains an empty message".into(),
            ));
        }
        let message_start = length_end;
        let message_end = message_start
            .checked_add(message_len)
            .ok_or_else(|| ShphError::Protocol("morphology batch message overflow".into()))?;
        let message = payload.get(message_start..message_end).ok_or_else(|| {
            ShphError::Protocol("morphology batch has a truncated message".into())
        })?;
        messages.push(message.to_vec());
        offset = message_end;
    }
    Ok(messages)
}

/// Encode a bounded batch using the real Shroud2 morphology envelope.
pub fn encode_batched_datagram<M: AsRef<[u8]>>(
    morphology: &mut MorphologyEngine,
    messages: &[M],
    path_mtu: usize,
) -> Result<Vec<u8>> {
    let payload = encode_batch_payload(messages, path_mtu)?;
    morphology.encode_datagram(&payload, path_mtu)
}

/// Decode and split one authenticated Shroud2 batch datagram.
pub fn decode_batched_datagram(datagram: &[u8], path_mtu: usize) -> Result<Vec<Vec<u8>>> {
    let payload = decode_datagram(datagram, path_mtu)?;
    decode_batch_payload(&payload)
}

pub fn decode_datagram(datagram: &[u8], path_mtu: usize) -> Result<Vec<u8>> {
    let mut decoded = datagram.to_vec();
    match decode_datagram_in_place(&mut decoded, path_mtu) {
        Ok(()) => Ok(decoded),
        Err(error) => {
            decoded.zeroize();
            Err(error)
        }
    }
}

/// Validate and remove one morphology envelope in a caller-owned buffer.
///
/// The payload is moved to the front and all retired envelope bytes are
/// cleared before truncation. This is useful for receive loops that already
/// own a mutable datagram buffer and avoids a second payload allocation.
pub fn decode_datagram_in_place(datagram: &mut Vec<u8>, path_mtu: usize) -> Result<()> {
    validate_path_mtu(path_mtu)?;
    if datagram.len() < MORPHOLOGY_HEADER_BYTES || datagram.len() > path_mtu {
        return Err(ShphError::Protocol(
            "morphology datagram length is outside the negotiated limit".into(),
        ));
    }
    if datagram[..2] != MORPHOLOGY_MAGIC || datagram[2] != MORPHOLOGY_VERSION {
        return Err(ShphError::Protocol(
            "morphology envelope version mismatch".into(),
        ));
    }
    let payload_len = u16::from_be_bytes([datagram[3], datagram[4]]) as usize;
    let declared_size = u16::from_be_bytes([datagram[5], datagram[6]]) as usize;
    if declared_size != datagram.len() {
        return Err(ShphError::Protocol(
            "morphology datagram size does not match its envelope".into(),
        ));
    }
    let payload_end = MORPHOLOGY_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| ShphError::Protocol("morphology payload length overflow".into()))?;
    if payload_len == 0 || payload_end > datagram.len() {
        return Err(ShphError::Protocol(
            "morphology payload length is invalid".into(),
        ));
    }
    datagram.copy_within(MORPHOLOGY_HEADER_BYTES..payload_end, 0);
    datagram[payload_len..].zeroize();
    datagram.truncate(payload_len);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_batch_payload, decode_batched_datagram, decode_datagram, encode_batch_payload,
        encode_batched_datagram, encode_datagram, wasserstein_distance, AdaptiveMorphologyConfig,
        AdaptiveMorphologyEngine, EmpiricalHistogram, MorphologyBatchPolicy,
        MorphologyBatchPushResult, MorphologyBatcher, MorphologyEngine, MorphologyProfile,
        MAX_BATCH_MESSAGES, MAX_BATCH_WAIT, MAX_HISTOGRAM_BINS, MAX_HISTOGRAM_SAMPLES,
        MORPHOLOGY_HEADER_BYTES,
    };
    use rand::SeedableRng;
    use std::time::{Duration, Instant};

    #[test]
    fn seeded_engine_stays_within_mtu_and_preserves_capacity() {
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::WebBrowsingLab, 7);
        for payload_len in [1, 128, 1_000, 1_500] {
            let target = engine.target_size(payload_len, 2_000).expect("target");
            assert!(target >= payload_len + MORPHOLOGY_HEADER_BYTES);
            assert!(target <= 2_000);
        }
    }

    #[test]
    fn reusable_encode_buffer_records_bounded_metrics() {
        let mut engine =
            MorphologyEngine::from_seed(MorphologyProfile::TunedWebBrowsingLab, 7).with_metrics();
        let mut buffer = Vec::with_capacity(2_000);
        engine
            .encode_datagram_into(b"payload", 1_472, &mut buffer)
            .expect("encode into buffer");
        let first_capacity = buffer.capacity();
        let first_len = buffer.len();
        engine
            .encode_datagram_into(b"second", 1_472, &mut buffer)
            .expect("reuse buffer");
        assert!(buffer.capacity() >= first_capacity);
        assert_ne!(buffer.len(), 0);
        assert_ne!(first_len, 0);
        assert_eq!(engine.metrics().frames(), 2);
        assert_eq!(engine.metrics().payload_bytes(), 13);
        assert!(engine.metrics().wire_bytes() >= engine.metrics().payload_bytes());
        assert!(engine.metrics().overhead_pct().is_some());
    }

    #[test]
    fn reusable_encode_buffer_is_cleared_when_validation_rejects_input() {
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::LowLatency, 7);
        let mut buffer = vec![0xa5; 128];
        assert!(engine
            .encode_datagram_into(&[0u8; 512], 128, &mut buffer)
            .is_err());
        assert!(buffer.is_empty());
    }

    #[test]
    fn in_place_decode_reuses_storage_and_preserves_payload() {
        let payload = b"in-place morphology payload";
        let encoded = encode_datagram(payload, 256, 512).expect("encode");
        let capacity = encoded.capacity();
        let mut reusable = encoded;
        super::decode_datagram_in_place(&mut reusable, 512).expect("decode in place");
        assert_eq!(reusable, payload);
        assert!(reusable.capacity() >= capacity);
    }

    #[test]
    fn bulk_profile_does_not_collapse_ineligible_classes_to_the_mtu() {
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::BulkLab, 7);
        for _ in 0..128 {
            assert_eq!(engine.target_size(1, 1_472).expect("target"), 1_280);
        }
    }

    #[test]
    fn weighted_sampler_bounds_future_profile_shape_changes() {
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::BulkLab, 7);
        let classes = [128, 256, 384, 512, 640, 768, 896, 1_024, 1_152, 1_280];
        let weights = [1u32; 10];
        let target = engine.sample_weighted_size_class(&classes, &weights, 7, 1_472);
        assert!((128..=1_024).contains(&target));
    }

    #[test]
    fn adaptive_morphology_switches_with_hysteresis() {
        let mut adaptive =
            AdaptiveMorphologyEngine::from_seed(AdaptiveMorphologyConfig::default(), 11)
                .expect("adaptive engine");
        assert_eq!(adaptive.profile(), MorphologyProfile::TunedLowLatency);
        adaptive
            .encode_datagram(&[0u8; 1_024], 1_472)
            .expect("interactive-to-web transition");
        assert_eq!(adaptive.profile(), MorphologyProfile::TunedWebBrowsingLab);

        for _ in 0..8 {
            adaptive
                .encode_datagram(&[0u8; 1_400], 1_472)
                .expect("web-to-video transition");
        }
        assert_eq!(
            adaptive.profile(),
            MorphologyProfile::TunedVideoStreamingLab
        );
        assert!(adaptive.profile_switches() >= 2);
    }

    #[test]
    fn adaptive_rejection_does_not_advance_classifier_state() {
        let mut adaptive =
            AdaptiveMorphologyEngine::from_seed(AdaptiveMorphologyConfig::default(), 11)
                .expect("adaptive engine");
        let before = (
            adaptive.profile(),
            adaptive.ewma_payload_bytes(),
            adaptive.profile_switches(),
        );
        let mut buffer = Vec::new();

        assert!(adaptive
            .encode_datagram_into(&[0u8; 1_024], 512, &mut buffer)
            .is_err());
        assert_eq!(
            (
                adaptive.profile(),
                adaptive.ewma_payload_bytes(),
                adaptive.profile_switches()
            ),
            before
        );
    }

    #[test]
    fn adaptive_thresholds_require_ordered_hysteresis() {
        assert!(AdaptiveMorphologyConfig::new(128, 192, 900, 640, 1_350, 1_100).is_err());
    }

    #[test]
    fn histogram_targets_are_safely_clamped() {
        let histogram =
            EmpiricalHistogram::new(vec![u64::MAX], vec![1.0]).expect("large histogram bin");
        let mut engine =
            MorphologyEngine::from_histogram(MorphologyProfile::WebBrowsingLab, histogram, 3);
        assert_eq!(engine.target_size(1, 1_400).expect("clamped target"), 1_400);
    }

    #[test]
    fn low_latency_prefers_small_classes_without_losing_shape_diversity() {
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::LowLatency, 7);
        let mut counts = [0usize; 4];
        for _ in 0..10_000 {
            match engine.target_size(1, 2_000).expect("target") {
                128 => counts[0] += 1,
                256 => counts[1] += 1,
                512 => counts[2] += 1,
                1_024 => counts[3] += 1,
                target => panic!("unexpected low-latency target size: {target}"),
            }
        }
        assert!(counts[0] > counts[1]);
        assert!(counts[1] > counts[2]);
        assert!(counts[2] > counts[3]);
        assert!(counts[3] > 0);
    }

    #[test]
    fn low_latency_weighting_only_uses_classes_that_fit() {
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::LowLatency, 7);
        for _ in 0..100 {
            let target = engine.target_size(300, 2_000).expect("target");
            assert!(matches!(target, 512 | 1_024));
        }
    }

    #[test]
    fn web_and_video_profiles_keep_discrete_shape_diversity() {
        for (profile, classes) in [
            (
                MorphologyProfile::WebBrowsingLab,
                &[384, 768, 1_024, 1_280, 1_536][..],
            ),
            (
                MorphologyProfile::VideoStreamingLab,
                &[1_024, 1_280, 1_536, 2_048, 4_096][..],
            ),
            (
                MorphologyProfile::VideoStreamingLargePayloadLab,
                &[1_408, 1_440, 1_465][..],
            ),
            (
                MorphologyProfile::VideoStreamingBalancedPayloadLab,
                &[1_415, 1_430, 1_445, 1_460, 1_472][..],
            ),
        ] {
            let mut engine = MorphologyEngine::from_seed(profile, 7);
            let mut counts = vec![0usize; classes.len()];
            for _ in 0..10_000 {
                let target = engine.target_size(1, 8_192).expect("target");
                let index = classes
                    .iter()
                    .position(|class| *class == target)
                    .expect("target must remain in the profile's discrete classes");
                counts[index] += 1;
            }
            assert!(counts.iter().all(|count| *count > 0));
            assert!(counts[0] > counts[classes.len() - 1]);
        }
    }

    #[test]
    fn tuned_profiles_keep_path_bounded_discrete_shape_diversity() {
        for (profile, classes) in [
            (
                MorphologyProfile::TunedLowLatency,
                &[64, 96, 128, 192, 256, 512, 768][..],
            ),
            (
                MorphologyProfile::TunedWebBrowsingLab,
                &[256, 384, 512, 768, 1_024, 1_280, 1_360][..],
            ),
            (
                MorphologyProfile::TunedVideoStreamingLab,
                &[1_024, 1_152, 1_280, 1_360, 1_408, 1_440, 1_472][..],
            ),
            (
                MorphologyProfile::TunedBulkLab,
                &[1_024, 1_152, 1_280, 1_360, 1_408, 1_440, 1_472][..],
            ),
        ] {
            let mut engine = MorphologyEngine::from_seed(profile, 7);
            let mut counts = vec![0usize; classes.len()];
            for _ in 0..20_000 {
                let target = engine.target_size(1, 1_472).expect("target");
                let index = classes
                    .iter()
                    .position(|class| *class == target)
                    .expect("target must remain in the tuned profile classes");
                counts[index] += 1;
            }
            assert!(counts.iter().all(|count| *count > 0));
        }
    }

    #[test]
    fn weighted_profiles_fold_large_classes_into_the_mtu_bucket() {
        for (profile, classes) in [
            (
                MorphologyProfile::WebBrowsingLab,
                &[384, 768, 1_024, 1_280, 1_472][..],
            ),
            (
                MorphologyProfile::VideoStreamingLab,
                &[1_024, 1_280, 1_472][..],
            ),
            (
                MorphologyProfile::VideoStreamingLargePayloadLab,
                &[1_408, 1_440, 1_465][..],
            ),
            (
                MorphologyProfile::VideoStreamingBalancedPayloadLab,
                &[1_415, 1_430, 1_445, 1_460, 1_472][..],
            ),
        ] {
            let mut engine = MorphologyEngine::from_seed(profile, 11);
            for _ in 0..1_000 {
                let target = engine.target_size(1, 1_472).expect("target");
                assert!(classes.contains(&target));
            }
        }
    }

    #[test]
    fn envelope_round_trip_preserves_payload() {
        let payload = b"authenticated lab payload";
        let encoded = encode_datagram(payload, 256, 512).expect("encode");
        assert_eq!(decode_datagram(&encoded, 512).expect("decode"), payload);
    }

    #[test]
    fn batch_envelope_round_trip_preserves_message_boundaries() {
        let messages = vec![
            b"one".to_vec(),
            b"two".to_vec(),
            b"interactive-message".to_vec(),
        ];
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::LowLatency, 19);
        let encoded = encode_batched_datagram(&mut engine, &messages, 512).expect("batch encode");
        assert_eq!(
            decode_batched_datagram(&encoded, 512).expect("batch decode"),
            messages
        );
        let payload = encode_batch_payload(&messages, 512).expect("payload encode");
        assert_eq!(
            decode_batch_payload(&payload).expect("payload decode"),
            messages
        );
    }

    #[test]
    fn batcher_flushes_at_count_and_mtu_boundaries() {
        let mut batcher = MorphologyBatcher::new();
        for _ in 0..MAX_BATCH_MESSAGES {
            assert_eq!(
                batcher.push(b"message", 512).expect("batch push"),
                MorphologyBatchPushResult::Buffered
            );
        }
        let flushed = match batcher.push(b"message", 512).expect("count boundary") {
            MorphologyBatchPushResult::Flush(messages) => messages,
            MorphologyBatchPushResult::Buffered => panic!("count boundary did not flush"),
        };
        assert_eq!(flushed.len(), MAX_BATCH_MESSAGES);
        assert_eq!(batcher.len(), 1);

        let mut mtu_batcher = MorphologyBatcher::new();
        assert_eq!(
            mtu_batcher.push(&[0u8; 200], 256).expect("first MTU push"),
            MorphologyBatchPushResult::Buffered
        );
        let flushed = match mtu_batcher.push(&[1u8; 50], 256).expect("MTU boundary") {
            MorphologyBatchPushResult::Flush(messages) => messages,
            MorphologyBatchPushResult::Buffered => panic!("MTU boundary did not flush"),
        };
        assert_eq!(flushed, vec![vec![0u8; 200]]);
        assert_eq!(mtu_batcher.len(), 1);
    }

    #[test]
    fn recommended_batch_policies_bound_interactive_latency() {
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::LowLatency),
            MorphologyBatchPolicy::new(4, Duration::from_millis(2)).expect("low-latency policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::WebBrowsingLab),
            MorphologyBatchPolicy::new(8, Duration::from_millis(10)).expect("web policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::VideoStreamingLab),
            MorphologyBatchPolicy::new(8, Duration::from_millis(20)).expect("video policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::VideoStreamingLargePayloadLab),
            MorphologyBatchPolicy::new(8, Duration::from_millis(20))
                .expect("large-payload video policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::VideoStreamingBalancedPayloadLab),
            MorphologyBatchPolicy::new(8, Duration::from_millis(20))
                .expect("balanced-payload video policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::TunedLowLatency),
            MorphologyBatchPolicy::new(6, Duration::from_millis(2))
                .expect("tuned low-latency policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::TunedWebBrowsingLab),
            MorphologyBatchPolicy::new(10, Duration::from_millis(8)).expect("tuned web policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::TunedVideoStreamingLab),
            MorphologyBatchPolicy::new(8, Duration::from_millis(16)).expect("tuned video policy")
        );
        assert_eq!(
            MorphologyBatchPolicy::recommended(MorphologyProfile::TunedBulkLab),
            MorphologyBatchPolicy::new(MAX_BATCH_MESSAGES, Duration::from_millis(40))
                .expect("tuned bulk policy")
        );
        assert!(MorphologyBatchPolicy::new(0, Duration::ZERO).is_err());
        assert!(MorphologyBatchPolicy::new(MAX_BATCH_MESSAGES + 1, Duration::ZERO).is_err());
        assert!(MorphologyBatchPolicy::new(1, MAX_BATCH_WAIT + Duration::from_nanos(1)).is_err());
    }

    #[test]
    fn batcher_flushes_when_the_latency_budget_expires() {
        let policy =
            MorphologyBatchPolicy::new(8, Duration::from_millis(10)).expect("batch policy");
        let mut batcher = MorphologyBatcher::with_policy(policy);
        let started_at = Instant::now();
        assert_eq!(
            batcher
                .push_at(b"first", 512, started_at)
                .expect("first push"),
            MorphologyBatchPushResult::Buffered
        );
        assert!(!batcher.is_due_at(started_at + Duration::from_millis(9), started_at));
        let flushed = match batcher
            .push_at(b"second", 512, started_at + Duration::from_millis(10))
            .expect("deadline push")
        {
            MorphologyBatchPushResult::Flush(messages) => messages,
            MorphologyBatchPushResult::Buffered => panic!("deadline did not flush"),
        };
        assert_eq!(flushed, vec![b"first".to_vec()]);
        assert_eq!(batcher.flush(), Some(vec![b"second".to_vec()]));
    }

    #[test]
    fn batch_decoder_rejects_malformed_or_oversized_batches() {
        assert!(decode_batch_payload(&[0, 1]).is_err());
        assert!(decode_batch_payload(&[0, 0]).is_err());
        assert!(decode_batch_payload(&vec![1u8; 65_529]).is_err());
        let messages = vec![b"message".to_vec(); MAX_BATCH_MESSAGES + 1];
        assert!(encode_batch_payload(&messages, 4_096).is_err());
    }

    #[test]
    fn envelope_rejects_truncation_and_bad_version() {
        let payload = b"payload";
        let encoded = encode_datagram(payload, 64, 128).expect("encode");
        assert!(decode_datagram(&encoded[..encoded.len() - 1], 128).is_err());
        let mut bad = encoded;
        bad[2] = 2;
        assert!(decode_datagram(&bad, 128).is_err());
    }

    #[test]
    fn envelope_rejects_target_below_payload() {
        assert!(encode_datagram(b"payload", 5, 128).is_err());
        assert!(encode_datagram(b"", 64, 128).is_err());
    }

    #[test]
    fn envelope_rejects_declared_size_and_payload_length_mismatch() {
        let mut encoded = encode_datagram(b"payload", 64, 128).expect("encode");
        encoded[5..7].copy_from_slice(&63u16.to_be_bytes());
        assert!(decode_datagram(&encoded, 128).is_err());

        let mut encoded = encode_datagram(b"payload", 64, 128).expect("encode");
        encoded[3..5].copy_from_slice(&58u16.to_be_bytes());
        assert!(decode_datagram(&encoded, 128).is_err());
    }

    #[test]
    fn envelope_rejects_payloads_that_cannot_fit_length_field() {
        let payload = vec![0u8; u16::MAX as usize + 1];
        assert!(encode_datagram(&payload, 65_535, 65_535).is_err());
    }

    #[test]
    fn path_mtu_bounds_are_fail_closed() {
        assert!(super::validate_path_mtu(0).is_err());
        assert!(super::validate_path_mtu(6).is_err());
        assert!(super::validate_path_mtu(65_536).is_err());
        assert!(super::validate_path_mtu(7).is_ok());
    }

    #[test]
    fn delay_is_bounded_for_each_profile() {
        for profile in [
            MorphologyProfile::LowLatency,
            MorphologyProfile::WebBrowsingLab,
            MorphologyProfile::VideoStreamingLab,
            MorphologyProfile::VideoStreamingLargePayloadLab,
            MorphologyProfile::VideoStreamingBalancedPayloadLab,
            MorphologyProfile::BulkLab,
        ] {
            let mut engine = MorphologyEngine::from_seed(profile, 9);
            for _ in 0..100 {
                let delay = engine.next_delay();
                assert!(delay <= std::time::Duration::from_millis(8));
            }
        }
    }

    #[test]
    fn empirical_histogram_normalizes_and_samples_known_bins() {
        let histogram = EmpiricalHistogram::new(vec![100, 200], vec![1.0, 3.0]).expect("histogram");
        let total = histogram.weights().iter().sum::<f64>();
        assert!((total - 1.0).abs() < f64::EPSILON);
        assert_eq!(histogram.bins(), &[100, 200]);

        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for _ in 0..32 {
            assert!(matches!(histogram.sample_bin(&mut rng), 100 | 200));
        }
    }

    #[test]
    fn empirical_histogram_rejects_invalid_shapes_and_weights() {
        assert!(EmpiricalHistogram::new(vec![], vec![]).is_err());
        assert!(EmpiricalHistogram::new(vec![1, 1], vec![1.0, 1.0]).is_err());
        assert!(EmpiricalHistogram::new(vec![1], vec![f64::NAN]).is_err());
        assert!(EmpiricalHistogram::new(vec![1], vec![0.0]).is_err());
        assert!(EmpiricalHistogram::from_samples(&[]).is_err());
    }

    #[test]
    fn empirical_histogram_bounds_bins_and_skips_zero_weight_intervals() {
        let oversized_bins = (0..=MAX_HISTOGRAM_BINS)
            .map(|bin| bin as u64)
            .collect::<Vec<_>>();
        let oversized_weights = vec![1.0; oversized_bins.len()];
        assert!(EmpiricalHistogram::new(oversized_bins, oversized_weights).is_err());
        let oversized_samples = vec![0u64; MAX_HISTOGRAM_SAMPLES + 1];
        assert!(EmpiricalHistogram::from_samples(&oversized_samples).is_err());

        let histogram =
            EmpiricalHistogram::new(vec![10, 20, 30], vec![0.0, 1.0, 0.0]).expect("histogram");
        let mut rng = rand::rngs::StdRng::seed_from_u64(91);
        for _ in 0..64 {
            assert_eq!(histogram.sample_bin(&mut rng), 20);
        }
    }

    #[test]
    fn wasserstein_distance_matches_discrete_shift() {
        let current = EmpiricalHistogram::from_samples(&[0, 0, 10, 10]).expect("current");
        let target = EmpiricalHistogram::from_samples(&[0, 0, 20, 20]).expect("target");
        assert!((wasserstein_distance(&current, &target) - 5.0).abs() < f64::EPSILON);
        assert_eq!(wasserstein_distance(&current, &current), 0.0);
    }

    #[test]
    fn explicit_empirical_cdf_is_sampled_and_still_respects_bounds() {
        let histogram =
            EmpiricalHistogram::new(vec![64, 512, 1_280], vec![1.0, 2.0, 1.0]).expect("histogram");
        let mut engine =
            MorphologyEngine::from_histogram(MorphologyProfile::WebBrowsingLab, histogram, 42);
        for payload_len in [1, 100, 600] {
            let target = engine.target_size(payload_len, 1_400).expect("target");
            assert!(target >= payload_len + MORPHOLOGY_HEADER_BYTES);
            assert!(target <= 1_400);
        }
    }
}
