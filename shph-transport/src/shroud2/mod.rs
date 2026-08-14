//! Bounded Shroud 2.0 lab morphology for authenticated QUIC datagrams.
//!
//! This module deliberately does not implement browser fingerprint forgery,
//! active-probe deception, or a replacement for QUIC's congestion control and
//! loss recovery. It provides an explicit, measurable envelope for experiments
//! with payload-size classes and bounded inter-frame delay.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use shph_core::{Result, ShphError};
use std::collections::BTreeMap;
use std::time::Duration;

pub const MORPHOLOGY_MAGIC: [u8; 2] = *b"S2";
pub const MORPHOLOGY_VERSION: u8 = 1;
pub const MORPHOLOGY_HEADER_BYTES: usize = 7;
pub const MAX_MORPHOLOGY_DATAGRAM_BYTES: usize = 65_535;
const MAX_PROFILE_SIZE_CLASSES: usize = 8;

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
}

impl EmpiricalHistogram {
    /// Construct and normalize a finite, strictly ordered distribution.
    pub fn new(bins: Vec<u64>, weights: Vec<f64>) -> Result<Self> {
        if bins.is_empty() || bins.len() != weights.len() {
            return Err(ShphError::InvalidArgument(
                "histogram bins and weights must be non-empty and have equal length".into(),
            ));
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
        Ok(Self {
            bins,
            weights: weights.into_iter().map(|weight| weight / total).collect(),
        })
    }

    /// Build a normalized histogram from observed integer samples.
    pub fn from_samples(samples: &[u64]) -> Result<Self> {
        if samples.is_empty() {
            return Err(ShphError::InvalidArgument(
                "histogram samples must not be empty".into(),
            ));
        }
        let mut counts = BTreeMap::<u64, u64>::new();
        for sample in samples {
            let count = counts.entry(*sample).or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                ShphError::ResourceExhausted("histogram sample count overflow".into())
            })?;
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
        let mut cumulative = 0.0;
        for (bin, weight) in self.bins.iter().zip(&self.weights) {
            cumulative += weight;
            if target < cumulative {
                return *bin;
            }
        }
        *self.bins.last().expect("histogram is non-empty")
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
    BulkLab,
}

impl MorphologyProfile {
    fn size_classes(self) -> &'static [usize] {
        match self {
            Self::LowLatency => &[256, 512, 768, 1_024],
            Self::WebBrowsingLab => &[384, 768, 1_024, 1_280, 1_536],
            Self::VideoStreamingLab => &[1_024, 1_280, 1_536, 2_048, 4_096],
            Self::BulkLab => &[1_280, 2_048, 4_096, 8_192, 16_384],
        }
    }

    fn jitter_bounds(self) -> (Duration, Duration) {
        match self {
            Self::LowLatency => (Duration::ZERO, Duration::from_micros(500)),
            Self::WebBrowsingLab => (Duration::from_micros(100), Duration::from_millis(8)),
            Self::VideoStreamingLab => (Duration::from_micros(50), Duration::from_millis(3)),
            Self::BulkLab => (Duration::ZERO, Duration::from_micros(750)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MorphologyEngine {
    profile: MorphologyProfile,
    rng: StdRng,
    size_histogram: Option<EmpiricalHistogram>,
}

impl MorphologyEngine {
    pub fn new(profile: MorphologyProfile) -> Self {
        Self::from_seed(profile, rand::random())
    }

    pub fn from_seed(profile: MorphologyProfile, seed: u64) -> Self {
        Self {
            profile,
            rng: StdRng::seed_from_u64(seed),
            size_histogram: None,
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
        }
    }

    pub fn profile(&self) -> MorphologyProfile {
        self.profile
    }

    /// Select an outer datagram size without exceeding the negotiated path MTU.
    ///
    /// The returned size includes the Shroud 2.0 envelope header and padding.
    /// A caller must still use the negotiated QUIC datagram limit, not a guessed
    /// Ethernet MTU, as the `path_mtu` argument.
    pub fn target_size(&mut self, payload_len: usize, path_mtu: usize) -> Result<usize> {
        validate_path_mtu(path_mtu)?;
        let minimum = payload_len
            .checked_add(MORPHOLOGY_HEADER_BYTES)
            .ok_or_else(|| ShphError::Protocol("morphology payload length overflow".into()))?;
        if minimum > path_mtu {
            return Err(ShphError::Protocol(
                "morphology payload exceeds negotiated datagram limit".into(),
            ));
        }

        let sampled = if let Some(histogram) = &self.size_histogram {
            histogram.sample_bin(&mut self.rng) as usize
        } else {
            let classes = self.profile.size_classes();
            debug_assert!(classes.len() <= MAX_PROFILE_SIZE_CLASSES);
            classes[self.rng.gen_range(0..classes.len())]
        };
        Ok(sampled.max(minimum).min(path_mtu))
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
    validate_path_mtu(path_mtu)?;
    if payload.is_empty() {
        return Err(ShphError::Protocol(
            "morphology payload must not be empty".into(),
        ));
    }
    if target_size > path_mtu || target_size > MAX_MORPHOLOGY_DATAGRAM_BYTES {
        return Err(ShphError::Protocol(
            "morphology target exceeds negotiated datagram limit".into(),
        ));
    }
    let minimum = payload
        .len()
        .checked_add(MORPHOLOGY_HEADER_BYTES)
        .ok_or_else(|| ShphError::Protocol("morphology payload length overflow".into()))?;
    if target_size < minimum || payload.len() > u16::MAX as usize {
        return Err(ShphError::Protocol(
            "morphology target is smaller than the payload".into(),
        ));
    }

    let target_size_u16 = u16::try_from(target_size)
        .map_err(|_| ShphError::Protocol("morphology target length overflow".into()))?;
    let mut datagram = vec![0u8; target_size];
    datagram[..2].copy_from_slice(&MORPHOLOGY_MAGIC);
    datagram[2] = MORPHOLOGY_VERSION;
    datagram[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    datagram[5..7].copy_from_slice(&target_size_u16.to_be_bytes());
    datagram[7..minimum].copy_from_slice(payload);
    rand::rngs::OsRng
        .try_fill_bytes(&mut datagram[minimum..])
        .map_err(|_| ShphError::Crypto("OS randomness unavailable".into()))?;
    Ok(datagram)
}

pub fn decode_datagram(datagram: &[u8], path_mtu: usize) -> Result<Vec<u8>> {
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
    Ok(datagram[MORPHOLOGY_HEADER_BYTES..payload_end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_datagram, encode_datagram, wasserstein_distance, EmpiricalHistogram,
        MorphologyEngine, MorphologyProfile, MORPHOLOGY_HEADER_BYTES,
    };
    use rand::SeedableRng;

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
    fn envelope_round_trip_preserves_payload() {
        let payload = b"authenticated lab payload";
        let encoded = encode_datagram(payload, 256, 512).expect("encode");
        assert_eq!(decode_datagram(&encoded, 512).expect("decode"), payload);
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
