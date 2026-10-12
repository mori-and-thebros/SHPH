//! Versioned, opt-in Phantom One inner morphology and framing.
//!
//! Phantom One is an authenticated-transport inner envelope. It supplies explicit
//! framing, bounded session-scoped padding, path-MTU checks, and replay
//! tracking; it does not provide encryption, browser impersonation, DPI
//! resistance, or QUIC fragmentation.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use shph_core::{Result, ShphError};
use shph_obfuscation::ProfileTier;
use zeroize::Zeroize;

/// Four-byte Phantom One envelope marker.
pub const PHANTOM_ONE_MAGIC: [u8; 4] = *b"PH1\0";
/// Phantom One envelope format version.
pub const PHANTOM_ONE_VERSION: u8 = 1;
/// Fixed Phantom One header size in bytes.
pub const PHANTOM_ONE_HEADER_BYTES: usize = 24;
/// Largest representable Phantom One envelope and path MTU.
pub const PHANTOM_ONE_MAX_ENVELOPE_BYTES: usize = u16::MAX as usize;
/// Largest payload representable by the Phantom One payload-length field.
pub const PHANTOM_ONE_MAX_PAYLOAD_BYTES: usize =
    PHANTOM_ONE_MAX_ENVELOPE_BYTES - PHANTOM_ONE_HEADER_BYTES;
/// Maximum configured padding bound.
pub const PHANTOM_ONE_MAX_PADDING_BYTES: usize = 4096;
/// Default replay window size.
pub const PHANTOM_ONE_DEFAULT_REPLAY_WINDOW: usize = 64;

const MAGIC_END: usize = 4;
const VERSION_OFFSET: usize = 4;
const PROFILE_OFFSET: usize = 5;
const GENERATION_OFFSET: usize = 6;
const FRAME_TYPE_OFFSET: usize = 10;
const SEQUENCE_OFFSET: usize = 11;
const PAYLOAD_LENGTH_OFFSET: usize = 19;
const TARGET_LENGTH_OFFSET: usize = 21;
const RESERVED_OFFSET: usize = 23;

/// The frame types understood by Phantom One.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PhantomOneFrameType {
    Data = 1,
    Control = 2,
    Keepalive = 3,
}

impl TryFrom<u8> for PhantomOneFrameType {
    type Error = ShphError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            value if value == Self::Data as u8 => Ok(Self::Data),
            value if value == Self::Control as u8 => Ok(Self::Control),
            value if value == Self::Keepalive as u8 => Ok(Self::Keepalive),
            _ => Err(protocol("unsupported Phantom One frame type")),
        }
    }
}

/// Bounds for Phantom One tail padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhantomOneConfig {
    /// Profile identifier carried in every Phantom One header.
    profile: ProfileTier,
    /// Minimum number of random tail-padding bytes.
    min_padding: usize,
    /// Maximum number of random tail-padding bytes.
    max_padding: usize,
    /// Enforce this profile's canonical wire-size classes when possible.
    profile_bound: bool,
    selection: SizeSelection,
    padding_budget: Option<u64>,
}

/// Weights correspond to `ProfileTier::base_tiers()`; unused entries must be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SizeSelection {
    #[default]
    FirstFit,
    Weighted([u16; 7]),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnvelopeMetrics {
    pub frames: u64,
    pub payload_bytes: u64,
    pub header_bytes: u64,
    pub padding_bytes: u64,
}

impl PhantomOneConfig {
    pub fn new(min_padding: usize, max_padding: usize) -> Result<Self> {
        let config = Self {
            profile: ProfileTier::Medium,
            min_padding,
            max_padding,
            profile_bound: false,
            selection: SizeSelection::FirstFit,
            padding_budget: None,
        };
        config.validate()?;
        Ok(config)
    }

    /// Create a profile-bound configuration using the full bounded padding
    /// range needed by the profile's canonical size tiers.
    pub fn for_profile(profile: ProfileTier) -> Self {
        Self {
            profile,
            min_padding: 0,
            max_padding: PHANTOM_ONE_MAX_PADDING_BYTES,
            profile_bound: true,
            selection: SizeSelection::FirstFit,
            padding_budget: None,
        }
    }

    pub const fn profile(self) -> ProfileTier {
        self.profile
    }

    pub const fn with_profile(mut self, profile: ProfileTier) -> Self {
        self.profile = profile;
        self.profile_bound = true;
        self
    }

    pub fn min_padding(self) -> usize {
        self.min_padding
    }

    pub fn max_padding(self) -> usize {
        self.max_padding
    }

    pub fn with_selection(mut self, selection: SizeSelection) -> Result<Self> {
        self.selection = selection;
        self.validate()?;
        Ok(self)
    }

    /// Lifetime tail-padding allowance. Exhaustion returns an error; it never
    /// silently changes profile or resets at a time-window boundary.
    pub fn with_padding_budget(mut self, bytes: u64) -> Self {
        self.padding_budget = Some(bytes);
        self
    }

    pub fn selection(self) -> SizeSelection {
        self.selection
    }

    pub fn padding_budget(self) -> Option<u64> {
        self.padding_budget
    }

    pub fn is_profile_bound(self) -> bool {
        self.profile_bound
    }

    fn validate(self) -> Result<()> {
        if let SizeSelection::Weighted(weights) = self.selection {
            let count = self.profile.base_tiers().len();
            if !self.profile_bound
                || weights[..count].iter().all(|weight| *weight == 0)
                || weights[count..].iter().any(|weight| *weight != 0)
            {
                return Err(ShphError::Config(
                    "invalid Phantom One class weights".into(),
                ));
            }
        }
        if self.min_padding > self.max_padding {
            return Err(ShphError::Config(
                "Phantom One minimum padding must not exceed maximum padding".into(),
            ));
        }
        if self.max_padding > PHANTOM_ONE_MAX_PADDING_BYTES {
            return Err(ShphError::Config(format!(
                "Phantom One maximum padding must not exceed {PHANTOM_ONE_MAX_PADDING_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

impl Default for PhantomOneConfig {
    fn default() -> Self {
        Self {
            profile: ProfileTier::Medium,
            min_padding: 0,
            max_padding: 64,
            profile_bound: false,
            selection: SizeSelection::FirstFit,
            padding_budget: None,
        }
    }
}

/// One decoded Phantom One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhantomOneFrame {
    pub profile: ProfileTier,
    pub generation: u32,
    pub frame_type: PhantomOneFrameType,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub target_len: usize,
    pub padding_len: usize,
}

impl Drop for PhantomOneFrame {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

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

/// Session-scoped Phantom One encoder.
///
/// The RNG is retained for the lifetime of the encoder. It is used for both
/// target-size selection and tail-padding generation.
#[derive(Debug)]
pub struct PhantomOneEncoder {
    generation: u32,
    next_sequence: Option<u64>,
    config: PhantomOneConfig,
    rng: StdRng,
    metrics: EnvelopeMetrics,
}

impl PhantomOneEncoder {
    pub fn new(generation: u32) -> Self {
        Self {
            generation,
            next_sequence: Some(0),
            config: PhantomOneConfig::default(),
            rng: StdRng::from_entropy(),
            metrics: EnvelopeMetrics::default(),
        }
    }

    pub fn from_seed(generation: u32, seed: u64) -> Self {
        Self::from_validated_config(generation, seed, PhantomOneConfig::default())
    }

    pub fn with_profile(generation: u32, profile: ProfileTier) -> Self {
        Self::from_validated_config(
            generation,
            rand::random(),
            PhantomOneConfig::for_profile(profile),
        )
    }

    pub fn from_seed_with_profile(generation: u32, seed: u64, profile: ProfileTier) -> Self {
        Self::from_validated_config(generation, seed, PhantomOneConfig::for_profile(profile))
    }

    pub fn with_config(generation: u32, config: PhantomOneConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            generation,
            next_sequence: Some(0),
            config,
            rng: StdRng::from_entropy(),
            metrics: EnvelopeMetrics::default(),
        })
    }

    pub fn from_seed_with_config(
        generation: u32,
        seed: u64,
        config: PhantomOneConfig,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self::from_validated_config(generation, seed, config))
    }

    fn from_validated_config(generation: u32, seed: u64, config: PhantomOneConfig) -> Self {
        Self {
            generation,
            next_sequence: Some(0),
            config,
            rng: StdRng::seed_from_u64(seed),
            metrics: EnvelopeMetrics::default(),
        }
    }

    pub fn from_seed_at(generation: u32, sequence: u64, seed: u64) -> Self {
        let mut encoder =
            Self::from_validated_config(generation, seed, PhantomOneConfig::default());
        encoder.next_sequence = Some(sequence);
        encoder
    }

    pub fn from_seed_at_with_profile(
        generation: u32,
        sequence: u64,
        seed: u64,
        profile: ProfileTier,
    ) -> Self {
        let mut encoder =
            Self::from_validated_config(generation, seed, PhantomOneConfig::for_profile(profile));
        encoder.next_sequence = Some(sequence);
        encoder
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn config(&self) -> PhantomOneConfig {
        self.config
    }

    pub fn next_sequence(&self) -> Option<u64> {
        self.next_sequence
    }

    pub fn metrics(&self) -> EnvelopeMetrics {
        self.metrics
    }

    fn remaining_padding(&self) -> usize {
        self.config.padding_budget.map_or(usize::MAX, |budget| {
            usize::try_from(budget.saturating_sub(self.metrics.padding_bytes)).unwrap_or(usize::MAX)
        })
    }

    /// Select a canonical target size for a payload on the supplied path MTU.
    pub fn target_size(&mut self, payload_len: usize, path_mtu: usize) -> Result<usize> {
        self.config.validate()?;
        validate_path_mtu(path_mtu)?;
        validate_payload_length(payload_len)?;
        if self.next_sequence.is_none() {
            return Err(ShphError::ResourceExhausted(
                "Phantom One sequence space exhausted".into(),
            ));
        }

        let minimum = PHANTOM_ONE_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or_else(|| protocol("Phantom One payload length overflow"))?;
        let minimum_target = minimum
            .checked_add(self.config.min_padding)
            .ok_or_else(|| protocol("Phantom One target length overflow"))?;
        if minimum_target > path_mtu {
            return Err(protocol("Phantom One minimum target exceeds path MTU"));
        }

        let maximum_target = minimum
            .checked_add(self.config.max_padding.min(self.remaining_padding()))
            .ok_or_else(|| protocol("Phantom One target length overflow"))?
            .min(path_mtu);

        if minimum_target > maximum_target {
            return Err(ShphError::ResourceExhausted(
                "Phantom One padding budget exhausted".into(),
            ));
        }

        if let SizeSelection::Weighted(weights) = self.config.selection {
            let tiers = self.config.profile.base_tiers();
            let total: u32 = tiers
                .iter()
                .zip(weights)
                .filter_map(|(tier, weight)| {
                    (minimum_target..=maximum_target)
                        .contains(tier)
                        .then_some(u32::from(weight))
                })
                .sum();
            if total == 0 {
                return Err(protocol(
                    "no weighted Phantom One class fits the remaining budget",
                ));
            }
            let mut sample = self.rng.gen_range(0..total);
            for (&tier, weight) in tiers.iter().zip(weights) {
                if !(minimum_target..=maximum_target).contains(&tier) {
                    continue;
                }
                if sample < u32::from(weight) {
                    return Ok(tier);
                }
                sample -= u32::from(weight);
            }
            unreachable!("positive eligible weight must select a tier");
        }

        for &base_target in self.config.profile.base_tiers() {
            if base_target < minimum_target || base_target > maximum_target {
                continue;
            }
            let jitter_bound = match self.config.profile {
                ProfileTier::Low => 7,
                ProfileTier::TunedLow => 3,
                _ => 0,
            };
            let available_jitter = jitter_bound.min(maximum_target - base_target);
            let jitter = if available_jitter == 0 {
                0
            } else {
                self.rng.gen_range(0..=available_jitter)
            };
            return Ok(base_target + jitter);
        }

        if self.config.profile_bound {
            return Err(protocol(
                "Phantom One payload does not fit the selected profile's canonical size classes",
            ));
        }

        Ok(self.rng.gen_range(minimum_target..=maximum_target))
    }

    /// Encode one frame using a session-selected target size.
    pub fn encode(
        &mut self,
        frame_type: PhantomOneFrameType,
        payload: &[u8],
        path_mtu: usize,
    ) -> Result<Vec<u8>> {
        let mut envelope = Vec::new();
        self.encode_into(frame_type, payload, path_mtu, &mut envelope)?;
        Ok(envelope)
    }

    /// Encode one frame into a caller-owned buffer.
    ///
    /// The buffer is cleared and reused, avoiding an allocation in a
    /// steady-state transport loop.
    pub fn encode_into(
        &mut self,
        frame_type: PhantomOneFrameType,
        payload: &[u8],
        path_mtu: usize,
        envelope: &mut Vec<u8>,
    ) -> Result<()> {
        let target_len = match self.target_size(payload.len(), path_mtu) {
            Ok(target_len) => target_len,
            Err(error) => {
                envelope.zeroize();
                envelope.clear();
                return Err(error);
            }
        };
        self.encode_with_target_into(frame_type, payload, target_len, path_mtu, envelope)
    }

    /// Encode one frame at an explicit, validated target size.
    pub fn encode_with_target(
        &mut self,
        frame_type: PhantomOneFrameType,
        payload: &[u8],
        target_len: usize,
        path_mtu: usize,
    ) -> Result<Vec<u8>> {
        let mut envelope = Vec::new();
        self.encode_with_target_into(frame_type, payload, target_len, path_mtu, &mut envelope)?;
        Ok(envelope)
    }

    /// Encode one frame at an explicit target into a caller-owned buffer.
    pub fn encode_with_target_into(
        &mut self,
        frame_type: PhantomOneFrameType,
        payload: &[u8],
        target_len: usize,
        path_mtu: usize,
        envelope: &mut Vec<u8>,
    ) -> Result<()> {
        // A caller-owned buffer may contain the previous plaintext envelope.
        // Rejected requests wipe it through the guard. Successful requests
        // overwrite every byte in the new envelope and only wipe retired tail
        // bytes, keeping the steady-state path allocation- and copy-bounded.
        let mut cleanup = WipeBufferOnError::new(envelope);
        self.config.validate()?;
        validate_path_mtu(path_mtu)?;
        validate_payload_length(payload.len())?;
        let sequence = self.next_sequence.ok_or_else(|| {
            ShphError::ResourceExhausted("Phantom One sequence space exhausted".into())
        })?;

        let minimum = PHANTOM_ONE_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or_else(|| protocol("Phantom One payload length overflow"))?;
        let padding_len = target_len.checked_sub(minimum).ok_or_else(|| {
            protocol("Phantom One target is smaller than the Phantom One header and payload")
        })?;
        if target_len > path_mtu
            || target_len > PHANTOM_ONE_MAX_ENVELOPE_BYTES
            || padding_len < self.config.min_padding
            || padding_len > self.config.max_padding
            || padding_len > self.remaining_padding()
        {
            return Err(protocol(
                "Phantom One target is outside configured path-MTU bounds",
            ));
        }
        if self.config.profile_bound && !self.config.profile.accepts_frame_len(target_len) {
            return Err(protocol(
                "Phantom One target is outside the selected profile's canonical size classes",
            ));
        }

        let target_u16 = u16::try_from(target_len)
            .map_err(|_| protocol("Phantom One target length overflow"))?;
        let payload_u16 = u16::try_from(payload.len())
            .map_err(|_| protocol("Phantom One payload length overflow"))?;
        cleanup.prepare(target_len);
        cleanup.buffer.resize(target_len, 0);
        cleanup.buffer[..MAGIC_END].copy_from_slice(&PHANTOM_ONE_MAGIC);
        cleanup.buffer[VERSION_OFFSET] = PHANTOM_ONE_VERSION;
        cleanup.buffer[PROFILE_OFFSET] = self.config.profile.id();
        cleanup.buffer[GENERATION_OFFSET..FRAME_TYPE_OFFSET]
            .copy_from_slice(&self.generation.to_be_bytes());
        cleanup.buffer[FRAME_TYPE_OFFSET] = frame_type as u8;
        cleanup.buffer[SEQUENCE_OFFSET..PAYLOAD_LENGTH_OFFSET]
            .copy_from_slice(&sequence.to_be_bytes());
        cleanup.buffer[PAYLOAD_LENGTH_OFFSET..TARGET_LENGTH_OFFSET]
            .copy_from_slice(&payload_u16.to_be_bytes());
        cleanup.buffer[TARGET_LENGTH_OFFSET..RESERVED_OFFSET]
            .copy_from_slice(&target_u16.to_be_bytes());
        cleanup.buffer[RESERVED_OFFSET..PHANTOM_ONE_HEADER_BYTES].fill(0);
        cleanup.buffer[PHANTOM_ONE_HEADER_BYTES..minimum].copy_from_slice(payload);
        if self
            .rng
            .try_fill_bytes(&mut cleanup.buffer[minimum..])
            .is_err()
        {
            return Err(ShphError::Crypto(
                "Phantom One padding randomness failed".into(),
            ));
        }

        self.next_sequence = sequence.checked_add(1);
        self.metrics.frames = self.metrics.frames.saturating_add(1);
        self.metrics.payload_bytes = self
            .metrics
            .payload_bytes
            .saturating_add(payload.len() as u64);
        self.metrics.header_bytes = self
            .metrics
            .header_bytes
            .saturating_add(PHANTOM_ONE_HEADER_BYTES as u64);
        self.metrics.padding_bytes = self
            .metrics
            .padding_bytes
            .saturating_add(padding_len as u64);
        cleanup.commit();
        Ok(())
    }
}

/// Stateful Phantom One decoder with a bounded replay window.
#[derive(Debug)]
pub struct PhantomOneDecoder {
    generation: u32,
    window_size: usize,
    config: PhantomOneConfig,
    highest_sequence: Option<u64>,
    seen_bitmap: u64,
    padding_bytes_used: u64,
}

impl PhantomOneDecoder {
    pub fn new(generation: u32) -> Self {
        Self {
            generation,
            window_size: PHANTOM_ONE_DEFAULT_REPLAY_WINDOW,
            config: PhantomOneConfig::default(),
            highest_sequence: None,
            seen_bitmap: 0,
            padding_bytes_used: 0,
        }
    }

    pub fn with_window(generation: u32, window_size: usize) -> Result<Self> {
        Self::with_config_and_window(generation, PhantomOneConfig::default(), window_size)
    }

    pub fn with_config(generation: u32, config: PhantomOneConfig) -> Result<Self> {
        Self::with_config_and_window(generation, config, PHANTOM_ONE_DEFAULT_REPLAY_WINDOW)
    }

    pub fn with_config_and_window(
        generation: u32,
        config: PhantomOneConfig,
        window_size: usize,
    ) -> Result<Self> {
        config.validate()?;
        if !(1..=PHANTOM_ONE_DEFAULT_REPLAY_WINDOW).contains(&window_size) {
            return Err(ShphError::Config(format!(
                "Phantom One replay window must be between 1 and {PHANTOM_ONE_DEFAULT_REPLAY_WINDOW}"
            )));
        }
        Ok(Self {
            generation,
            window_size,
            config,
            highest_sequence: None,
            seen_bitmap: 0,
            padding_bytes_used: 0,
        })
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn window_size(&self) -> usize {
        self.window_size
    }

    pub fn config(&self) -> PhantomOneConfig {
        self.config
    }

    pub fn highest_sequence(&self) -> Option<u64> {
        self.highest_sequence
    }

    pub fn reset(&mut self) {
        self.highest_sequence = None;
        self.seen_bitmap = 0;
    }

    /// Decode and accept one frame, rejecting duplicate or stale sequences.
    pub fn decode(&mut self, datagram: &[u8], path_mtu: usize) -> Result<PhantomOneFrame> {
        let parts = decode_parts(datagram, self.generation, path_mtu, self.config)?;
        let next_padding_bytes = self.next_padding_bytes(parts.padding_len)?;
        self.accept_sequence(parts.sequence)?;
        self.padding_bytes_used = next_padding_bytes;
        Ok(parts.to_frame(datagram))
    }

    /// Decode and remove the Phantom One envelope in the caller-owned buffer.
    ///
    /// The authenticated payload is moved to the front and the vector is
    /// truncated after replay acceptance, avoiding a second allocation in the
    /// transport receive loop.
    pub fn decode_in_place(&mut self, datagram: &mut Vec<u8>, path_mtu: usize) -> Result<()> {
        let parts = decode_parts(datagram, self.generation, path_mtu, self.config)?;
        let next_padding_bytes = self.next_padding_bytes(parts.padding_len)?;
        self.accept_sequence(parts.sequence)?;
        self.padding_bytes_used = next_padding_bytes;
        datagram.copy_within(PHANTOM_ONE_HEADER_BYTES..parts.payload_end, 0);
        datagram[parts.payload_len..].zeroize();
        datagram.truncate(parts.payload_len);
        Ok(())
    }

    fn next_padding_bytes(&self, padding_len: usize) -> Result<u64> {
        let next = self
            .padding_bytes_used
            .checked_add(padding_len as u64)
            .ok_or_else(|| protocol("Phantom One session padding counter overflow"))?;
        if self
            .config
            .padding_budget
            .is_some_and(|budget| next > budget)
        {
            return Err(protocol("Phantom One session padding budget exceeded"));
        }
        Ok(next)
    }

    fn accept_sequence(&mut self, sequence: u64) -> Result<()> {
        let Some(highest) = self.highest_sequence else {
            self.highest_sequence = Some(sequence);
            self.seen_bitmap = 1;
            return Ok(());
        };

        if sequence > highest {
            let shift = sequence - highest;
            if shift >= self.window_size as u64 {
                // A forward jump is a fresh authenticated frame. Resetting
                // the bitmap makes all skipped sequence numbers stale once
                // the receive window advances past them.
                self.seen_bitmap = 1;
            } else {
                self.seen_bitmap = ((self.seen_bitmap << shift) | 1) & self.window_mask();
            }
            self.highest_sequence = Some(sequence);
            return Ok(());
        }

        let distance = highest - sequence;
        if distance >= self.window_size as u64 {
            return Err(protocol("Phantom One sequence is outside replay window"));
        }
        let bit = 1u64 << distance;
        if self.seen_bitmap & bit != 0 {
            return Err(protocol("Phantom One replay detected"));
        }
        self.seen_bitmap |= bit;
        Ok(())
    }

    fn window_mask(&self) -> u64 {
        if self.window_size == 64 {
            u64::MAX
        } else {
            (1u64 << self.window_size) - 1
        }
    }
}

/// Validate a path MTU representable by the Phantom One target-length field.
pub fn validate_path_mtu(path_mtu: usize) -> Result<()> {
    if !(PHANTOM_ONE_HEADER_BYTES..=PHANTOM_ONE_MAX_ENVELOPE_BYTES).contains(&path_mtu) {
        return Err(ShphError::Config(format!(
            "Phantom One path MTU must be between {PHANTOM_ONE_HEADER_BYTES} and {PHANTOM_ONE_MAX_ENVELOPE_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Decode one Phantom One frame without replay tracking.
///
/// The caller must use [`PhantomOneDecoder`] when sequence/replay protection is
/// required.
pub fn decode(
    datagram: &[u8],
    expected_generation: u32,
    path_mtu: usize,
) -> Result<PhantomOneFrame> {
    let profile = datagram
        .get(PROFILE_OFFSET)
        .and_then(|profile| ProfileTier::from_id(*profile))
        .ok_or_else(|| protocol("Phantom One profile identifier is unsupported"))?;
    let parts = decode_parts(
        datagram,
        expected_generation,
        path_mtu,
        PhantomOneConfig {
            profile,
            min_padding: 0,
            max_padding: PHANTOM_ONE_MAX_PADDING_BYTES,
            profile_bound: false,
            selection: SizeSelection::FirstFit,
            padding_budget: None,
        },
    )?;
    Ok(parts.to_frame(datagram))
}

#[derive(Debug, Clone, Copy)]
struct DecodedPhantomOneParts {
    profile: ProfileTier,
    generation: u32,
    frame_type: PhantomOneFrameType,
    sequence: u64,
    payload_len: usize,
    target_len: usize,
    padding_len: usize,
    payload_end: usize,
}

impl DecodedPhantomOneParts {
    fn to_frame(self, datagram: &[u8]) -> PhantomOneFrame {
        PhantomOneFrame {
            profile: self.profile,
            generation: self.generation,
            frame_type: self.frame_type,
            sequence: self.sequence,
            payload: datagram[PHANTOM_ONE_HEADER_BYTES..self.payload_end].to_vec(),
            target_len: self.target_len,
            padding_len: self.padding_len,
        }
    }
}

fn decode_parts(
    datagram: &[u8],
    expected_generation: u32,
    path_mtu: usize,
    config: PhantomOneConfig,
) -> Result<DecodedPhantomOneParts> {
    config.validate()?;
    validate_path_mtu(path_mtu)?;
    if datagram.len() < PHANTOM_ONE_HEADER_BYTES || datagram.len() > path_mtu {
        return Err(protocol(
            "Phantom One datagram length is outside path-MTU bounds",
        ));
    }
    if datagram[..MAGIC_END] != PHANTOM_ONE_MAGIC {
        return Err(protocol("Phantom One magic mismatch"));
    }
    if datagram[VERSION_OFFSET] != PHANTOM_ONE_VERSION {
        return Err(protocol("Phantom One version mismatch"));
    }

    let profile = ProfileTier::from_id(datagram[PROFILE_OFFSET])
        .ok_or_else(|| protocol("Phantom One profile identifier is unsupported"))?;
    if profile != config.profile() {
        return Err(protocol(
            "Phantom One profile does not match session policy",
        ));
    }
    let generation = u32::from_be_bytes([
        datagram[GENERATION_OFFSET],
        datagram[GENERATION_OFFSET + 1],
        datagram[GENERATION_OFFSET + 2],
        datagram[GENERATION_OFFSET + 3],
    ]);
    if generation != expected_generation {
        return Err(protocol("Phantom One generation mismatch"));
    }
    let frame_type = PhantomOneFrameType::try_from(datagram[FRAME_TYPE_OFFSET])?;
    let sequence = u64::from_be_bytes([
        datagram[SEQUENCE_OFFSET],
        datagram[SEQUENCE_OFFSET + 1],
        datagram[SEQUENCE_OFFSET + 2],
        datagram[SEQUENCE_OFFSET + 3],
        datagram[SEQUENCE_OFFSET + 4],
        datagram[SEQUENCE_OFFSET + 5],
        datagram[SEQUENCE_OFFSET + 6],
        datagram[SEQUENCE_OFFSET + 7],
    ]);
    let payload_len = u16::from_be_bytes([
        datagram[PAYLOAD_LENGTH_OFFSET],
        datagram[PAYLOAD_LENGTH_OFFSET + 1],
    ]) as usize;
    let target_len = u16::from_be_bytes([
        datagram[TARGET_LENGTH_OFFSET],
        datagram[TARGET_LENGTH_OFFSET + 1],
    ]) as usize;
    if datagram[RESERVED_OFFSET..PHANTOM_ONE_HEADER_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(protocol(
            "Phantom One reserved header bytes are non-canonical",
        ));
    }
    if target_len != datagram.len() {
        return Err(protocol(
            "Phantom One target length does not match datagram length",
        ));
    }
    if target_len > path_mtu {
        return Err(protocol("Phantom One target length exceeds path MTU"));
    }
    validate_payload_length(payload_len)?;
    let payload_end = PHANTOM_ONE_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| protocol("Phantom One payload length overflow"))?;
    if payload_end > target_len {
        return Err(protocol(
            "Phantom One payload is truncated by target length",
        ));
    }
    let padding_len = target_len - payload_end;
    if padding_len < config.min_padding() || padding_len > config.max_padding() {
        return Err(protocol(
            "Phantom One padding is outside the configured bounds",
        ));
    }
    if config.profile_bound && !profile.accepts_frame_len(target_len) {
        return Err(protocol(
            "Phantom One target is outside the selected profile's canonical size classes",
        ));
    }

    Ok(DecodedPhantomOneParts {
        profile,
        generation,
        frame_type,
        sequence,
        payload_len,
        target_len,
        padding_len,
        payload_end,
    })
}

fn validate_payload_length(payload_len: usize) -> Result<()> {
    if payload_len > PHANTOM_ONE_MAX_PAYLOAD_BYTES || payload_len > u16::MAX as usize {
        return Err(protocol(
            "Phantom One payload exceeds the Phantom One length bound",
        ));
    }
    Ok(())
}

fn protocol(message: &str) -> ShphError {
    ShphError::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::{
        decode, validate_path_mtu, PhantomOneConfig, PhantomOneDecoder, PhantomOneEncoder,
        PhantomOneFrameType, SizeSelection, PHANTOM_ONE_HEADER_BYTES, PHANTOM_ONE_MAGIC,
        PHANTOM_ONE_MAX_ENVELOPE_BYTES, PHANTOM_ONE_MAX_PADDING_BYTES, PHANTOM_ONE_VERSION,
        PROFILE_OFFSET, TARGET_LENGTH_OFFSET,
    };
    use shph_core::ShphError;
    use shph_obfuscation::ProfileTier;

    fn assert_protocol_error(result: shph_core::Result<impl Sized>) {
        assert!(matches!(result, Err(ShphError::Protocol(_))));
    }

    #[test]
    fn round_trip_preserves_explicit_phantom_one_fields() {
        let mut encoder = PhantomOneEncoder::from_seed(0x0102_0304, 7);
        let encoded = encoder
            .encode(PhantomOneFrameType::Data, b"payload", 256)
            .expect("encode");
        let frame = decode(&encoded, 0x0102_0304, 256).expect("decode");

        assert_eq!(frame.generation, 0x0102_0304);
        assert_eq!(frame.frame_type, PhantomOneFrameType::Data);
        assert_eq!(frame.sequence, 0);
        assert_eq!(frame.payload, b"payload");
        assert_eq!(frame.target_len, encoded.len());
        assert_eq!(
            frame.padding_len,
            encoded.len() - PHANTOM_ONE_HEADER_BYTES - 7
        );
    }

    #[test]
    fn reusable_encode_buffer_matches_allocating_api() {
        let mut allocating = PhantomOneEncoder::from_seed(9, 42);
        let mut reusable = PhantomOneEncoder::from_seed(9, 42);
        let expected = allocating
            .encode(PhantomOneFrameType::Data, b"payload", 256)
            .expect("allocating encode");
        let mut buffer = Vec::with_capacity(256);
        reusable
            .encode_into(PhantomOneFrameType::Data, b"payload", 256, &mut buffer)
            .expect("reusable encode");
        assert_eq!(buffer, expected);
        assert_eq!(reusable.next_sequence(), allocating.next_sequence());
    }

    #[test]
    fn session_rng_is_reused_but_seeded_sessions_are_reproducible() {
        let mut first = PhantomOneEncoder::from_seed(9, 42);
        let mut second = PhantomOneEncoder::from_seed(9, 42);
        let first_frame = first
            .encode(PhantomOneFrameType::Data, b"one", 256)
            .expect("first frame");
        let second_frame = second
            .encode(PhantomOneFrameType::Data, b"one", 256)
            .expect("second frame");
        assert_eq!(first_frame, second_frame);

        let next_first = first
            .encode(PhantomOneFrameType::Data, b"two", 256)
            .expect("next frame");
        assert_ne!(first_frame, next_first);
        assert_eq!(first.next_sequence(), Some(2));
    }

    #[test]
    fn explicit_target_and_path_mtu_bounds_are_enforced() {
        let config = PhantomOneConfig::new(4, 8).expect("config");
        let mut encoder =
            PhantomOneEncoder::from_seed_with_config(1, 4, config).expect("encoder config");
        let minimum = PHANTOM_ONE_HEADER_BYTES + 3 + 4;
        let encoded = encoder
            .encode_with_target(PhantomOneFrameType::Control, b"abc", minimum, 128)
            .expect("minimum configured target");
        assert_eq!(encoded.len(), minimum);

        assert_protocol_error(encoder.encode_with_target(
            PhantomOneFrameType::Control,
            b"abc",
            minimum - 1,
            128,
        ));
        assert_protocol_error(encoder.encode_with_target(
            PhantomOneFrameType::Control,
            b"abc",
            minimum + 9,
            128,
        ));
        assert_eq!(
            encoder.next_sequence(),
            Some(1),
            "rejected encodes must not consume sequence numbers"
        );
        assert_protocol_error(encoder.encode(PhantomOneFrameType::Data, &[0u8; 105], 128));
        assert!(validate_path_mtu(PHANTOM_ONE_HEADER_BYTES - 1).is_err());
        assert!(validate_path_mtu(PHANTOM_ONE_MAX_ENVELOPE_BYTES + 1).is_err());
    }

    #[test]
    fn reusable_explicit_encode_clears_buffer_on_rejection() {
        let mut encoder = PhantomOneEncoder::from_seed(25, 17);
        let mut buffer = encoder
            .encode(PhantomOneFrameType::Data, b"previous", 128)
            .expect("initial encode");
        assert!(!buffer.is_empty());

        assert_protocol_error(encoder.encode_with_target_into(
            PhantomOneFrameType::Data,
            b"next",
            PHANTOM_ONE_HEADER_BYTES,
            128,
            &mut buffer,
        ));
        assert!(buffer.is_empty());
    }

    #[test]
    fn malformed_truncated_oversized_and_noncanonical_inputs_fail_closed() {
        let mut encoder = PhantomOneEncoder::from_seed(3, 5);
        let encoded = encoder
            .encode(PhantomOneFrameType::Data, b"valid", 128)
            .expect("encode");

        assert_protocol_error(decode(&[], 3, 128));
        assert_protocol_error(decode(&encoded[..PHANTOM_ONE_HEADER_BYTES - 1], 3, 128));
        assert_protocol_error(decode(&encoded, 3, PHANTOM_ONE_HEADER_BYTES));

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_protocol_error(decode(&bad_magic, 3, 128));

        let mut bad_version = encoded.clone();
        bad_version[4] = PHANTOM_ONE_VERSION + 1;
        assert_protocol_error(decode(&bad_version, 3, 128));

        let mut bad_generation = encoded.clone();
        bad_generation[6] ^= 1;
        assert_protocol_error(decode(&bad_generation, 3, 128));

        let mut bad_type = encoded.clone();
        bad_type[10] = 0xff;
        assert_protocol_error(decode(&bad_type, 3, 128));

        let mut bad_profile = encoded.clone();
        bad_profile[5] = u8::MAX;
        assert_protocol_error(decode(&bad_profile, 3, 128));

        let mut bad_reserved = encoded.clone();
        bad_reserved[PHANTOM_ONE_HEADER_BYTES - 1] = 1;
        assert_protocol_error(decode(&bad_reserved, 3, 128));

        let mut bad_target = encoded.clone();
        bad_target[21..23].copy_from_slice(&(encoded.len() as u16 - 1).to_be_bytes());
        assert_protocol_error(decode(&bad_target, 3, 128));

        let mut bad_payload_length = encoded.clone();
        bad_payload_length[19..21].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_protocol_error(decode(&bad_payload_length, 3, 128));

        let mut empty_payload = encoded;
        empty_payload[19..21].copy_from_slice(&0u16.to_be_bytes());
        assert!(decode(&empty_payload, 3, 128)
            .expect("empty Phantom One payload is valid")
            .payload
            .is_empty());
    }

    #[test]
    fn decoder_rejects_padding_beyond_the_safety_bound() {
        let mut encoder = PhantomOneEncoder::from_seed_with_config(
            3,
            5,
            PhantomOneConfig::new(0, PHANTOM_ONE_MAX_PADDING_BYTES).expect("bounded config"),
        )
        .expect("encoder config");
        let target = PHANTOM_ONE_HEADER_BYTES + 1 + PHANTOM_ONE_MAX_PADDING_BYTES;
        let mut encoded = encoder
            .encode_with_target(
                PhantomOneFrameType::Data,
                b"x",
                target,
                PHANTOM_ONE_MAX_ENVELOPE_BYTES,
            )
            .expect("encode");
        encoded.push(0);
        let encoded_len = encoded.len() as u16;
        encoded[TARGET_LENGTH_OFFSET..TARGET_LENGTH_OFFSET + 2]
            .copy_from_slice(&encoded_len.to_be_bytes());

        assert_protocol_error(decode(&encoded, 3, PHANTOM_ONE_MAX_ENVELOPE_BYTES));
    }

    #[test]
    fn decoder_pins_generation_and_rejects_replays_and_stale_sequences() {
        let mut encoder = PhantomOneEncoder::from_seed(12, 8);
        let first = encoder
            .encode(PhantomOneFrameType::Data, b"first", 128)
            .expect("first");
        let second = encoder
            .encode(PhantomOneFrameType::Data, b"second", 128)
            .expect("second");
        let mut decoder = PhantomOneDecoder::with_window(12, 2).expect("decoder");

        assert_eq!(
            decoder.decode(&second, 128).expect("second first").sequence,
            1
        );
        assert_eq!(
            decoder
                .decode(&first, 128)
                .expect("reordered first")
                .sequence,
            0
        );
        assert_protocol_error(decoder.decode(&first, 128));
        assert_protocol_error(decode(&second, 13, 128));

        let mut far_encoder = PhantomOneEncoder::from_seed_at(12, 10, 9);
        let far = far_encoder
            .encode(PhantomOneFrameType::Data, b"far", 128)
            .expect("far");
        assert_eq!(
            decoder.decode(&far, 128).expect("forward jump").sequence,
            10
        );
        assert_protocol_error(decoder.decode(&first, 128));
    }

    #[test]
    fn decoder_in_place_reuses_storage_and_enforces_padding_config() {
        let config = PhantomOneConfig::new(4, 8).expect("config");
        let mut encoder =
            PhantomOneEncoder::from_seed_with_config(21, 13, config).expect("encoder");
        let mut encoded = encoder
            .encode_with_target(
                PhantomOneFrameType::Data,
                b"payload",
                PHANTOM_ONE_HEADER_BYTES + 7 + 6,
                128,
            )
            .expect("encoded");
        let capacity = encoded.capacity();
        let mut decoder = PhantomOneDecoder::with_config(21, config).expect("decoder");

        decoder
            .decode_in_place(&mut encoded, 128)
            .expect("in-place decode");
        assert_eq!(encoded, b"payload");
        assert!(encoded.capacity() >= capacity);
        assert_eq!(decoder.highest_sequence(), Some(0));
    }

    #[test]
    fn decoder_in_place_replay_rejection_preserves_input_and_state() {
        let mut encoder = PhantomOneEncoder::from_seed(23, 15);
        let encoded = encoder
            .encode(PhantomOneFrameType::Data, b"payload", 128)
            .expect("encoded");
        let mut decoder = PhantomOneDecoder::new(23);
        let mut first = encoded.clone();
        decoder
            .decode_in_place(&mut first, 128)
            .expect("first decode");
        assert_eq!(first, b"payload");

        let mut replay = encoded.clone();
        assert_protocol_error(decoder.decode_in_place(&mut replay, 128));
        assert_eq!(replay, encoded);
        assert_eq!(decoder.highest_sequence(), Some(0));
    }

    #[test]
    fn decoder_in_place_rejects_malformed_input_without_mutation() {
        let mut encoder = PhantomOneEncoder::from_seed(24, 16);
        let encoded = encoder
            .encode(PhantomOneFrameType::Data, b"payload", 128)
            .expect("encoded");
        let mut malformed = encoded.clone();
        malformed[0] ^= 1;
        let expected = malformed.clone();
        let mut decoder = PhantomOneDecoder::new(24);

        assert_protocol_error(decoder.decode_in_place(&mut malformed, 128));
        assert_eq!(malformed, expected);
        assert_eq!(decoder.highest_sequence(), None);
    }

    #[test]
    fn decoder_rejects_padding_outside_its_session_policy_without_advancing_replay() {
        let mut encoder = PhantomOneEncoder::from_seed(22, 14);
        let encoded = encoder
            .encode_with_target(
                PhantomOneFrameType::Data,
                b"payload",
                PHANTOM_ONE_HEADER_BYTES + 7,
                128,
            )
            .expect("encoded");
        let config = PhantomOneConfig::new(4, 8).expect("config");
        let mut decoder = PhantomOneDecoder::with_config(22, config).expect("decoder");

        assert_protocol_error(decoder.decode(&encoded, 128));
        assert_eq!(decoder.highest_sequence(), None);
    }

    #[test]
    fn low_profile_selection_clamps_jitter_at_exact_carrier_and_budget_limits() {
        let profile = ProfileTier::Low;
        let target = profile.base_tiers()[0];
        let padding_budget = target - PHANTOM_ONE_HEADER_BYTES - 1;
        let config =
            PhantomOneConfig::for_profile(profile).with_padding_budget(padding_budget as u64);

        for seed in 0..64 {
            let mut encoder = PhantomOneEncoder::from_seed_with_config(31, seed, config)
                .expect("budgeted low-profile encoder");
            assert_eq!(
                encoder
                    .target_size(1, target)
                    .expect("exact canonical limit is usable"),
                target
            );
        }
    }

    #[test]
    fn decoder_enforces_cumulative_session_padding_budget_before_acceptance() {
        let raw_config = PhantomOneConfig::new(0, 16).expect("raw frame config");
        let budget_config = raw_config.with_padding_budget(8);
        let mut encoder =
            PhantomOneEncoder::from_seed_with_config(32, 17, raw_config).expect("encoder");
        let first = encoder
            .encode_with_target(
                PhantomOneFrameType::Data,
                b"a",
                PHANTOM_ONE_HEADER_BYTES + 1 + 5,
                128,
            )
            .expect("first frame");
        let over_budget = encoder
            .encode_with_target(
                PhantomOneFrameType::Data,
                b"b",
                PHANTOM_ONE_HEADER_BYTES + 1 + 4,
                128,
            )
            .expect("second frame");

        let mut decoder = PhantomOneDecoder::with_config(32, budget_config).expect("decoder");
        assert_eq!(
            decoder.decode(&first, 128).expect("first decode").payload,
            b"a"
        );
        assert_eq!(decoder.padding_bytes_used, 5);
        assert_protocol_error(decoder.decode(&over_budget, 128));
        assert_eq!(decoder.highest_sequence(), Some(0));
        assert_eq!(decoder.padding_bytes_used, 5);

        let mut in_place_decoder =
            PhantomOneDecoder::with_config(32, budget_config).expect("in-place decoder");
        let mut first_in_place = first.clone();
        in_place_decoder
            .decode_in_place(&mut first_in_place, 128)
            .expect("first in-place decode");
        assert_eq!(first_in_place, b"a");
        let mut over_budget_in_place = over_budget.clone();
        assert_protocol_error(in_place_decoder.decode_in_place(&mut over_budget_in_place, 128));
        assert_eq!(over_budget_in_place, over_budget);
        assert_eq!(in_place_decoder.highest_sequence(), Some(0));
        assert_eq!(in_place_decoder.padding_bytes_used, 5);
    }

    #[test]
    fn replay_free_decode_accepts_every_assigned_profile() {
        let profiles = [
            ProfileTier::Low,
            ProfileTier::Medium,
            ProfileTier::High,
            ProfileTier::TunedLow,
            ProfileTier::TunedMedium,
            ProfileTier::TunedHigh,
        ];

        for (generation, profile) in profiles.into_iter().enumerate() {
            let mut encoder =
                PhantomOneEncoder::from_seed_with_profile(generation as u32, 31, profile);
            let encoded = encoder
                .encode(PhantomOneFrameType::Data, b"profile", 1360)
                .expect("profile encode");
            let frame = decode(&encoded, generation as u32, 1360).expect("profile decode");
            assert_eq!(frame.profile, profile);
        }
    }

    #[test]
    fn profile_bound_mode_rejects_noncanonical_large_payloads_and_targets() {
        let mut encoder = PhantomOneEncoder::from_seed_with_profile(27, 41, ProfileTier::High);
        assert_protocol_error(encoder.encode(
            PhantomOneFrameType::Data,
            &[0u8; 1337],
            PHANTOM_ONE_MAX_ENVELOPE_BYTES,
        ));
        assert_eq!(encoder.next_sequence(), Some(0));
        assert_protocol_error(encoder.encode_with_target(
            PhantomOneFrameType::Data,
            b"x",
            ProfileTier::High.max_canonical_frame_len() + 1,
            PHANTOM_ONE_MAX_ENVELOPE_BYTES,
        ));
        assert_eq!(encoder.next_sequence(), Some(0));

        let unbound_config =
            PhantomOneConfig::new(0, PHANTOM_ONE_MAX_PADDING_BYTES).expect("unbound config");
        let mut unbound = PhantomOneEncoder::from_seed_with_config(27, 41, unbound_config)
            .expect("unbound encoder");
        let mut noncanonical = unbound
            .encode_with_target(
                PhantomOneFrameType::Data,
                b"x",
                ProfileTier::Medium.max_canonical_frame_len() + 1,
                PHANTOM_ONE_MAX_ENVELOPE_BYTES,
            )
            .expect("unbound encode");
        let target_len = noncanonical.len();
        noncanonical[PROFILE_OFFSET] = ProfileTier::Medium.id();
        assert_protocol_error(
            PhantomOneDecoder::with_config(27, PhantomOneConfig::for_profile(ProfileTier::Medium))
                .expect("strict decoder")
                .decode(&noncanonical, PHANTOM_ONE_MAX_ENVELOPE_BYTES),
        );
        assert_eq!(
            target_len,
            ProfileTier::Medium.max_canonical_frame_len() + 1
        );
    }

    #[test]
    fn sequence_space_exhaustion_fails_closed_without_wraparound() {
        let mut encoder = PhantomOneEncoder::from_seed_at(4, u64::MAX, 10);
        let last = encoder
            .encode(PhantomOneFrameType::Keepalive, b"x", 128)
            .expect("last sequence is usable");
        assert_eq!(decode(&last, 4, 128).expect("decode").sequence, u64::MAX);
        assert_eq!(encoder.next_sequence(), None);
        assert!(matches!(
            encoder.encode(PhantomOneFrameType::Keepalive, b"x", 128),
            Err(ShphError::ResourceExhausted(_))
        ));
    }

    #[test]
    fn decoder_handles_max_sequence_without_wraparound() {
        let mut encoder = PhantomOneEncoder::from_seed_at(5, u64::MAX - 1, 12);
        let penultimate = encoder
            .encode(PhantomOneFrameType::Keepalive, b"a", 128)
            .expect("penultimate sequence is usable");
        let last = encoder
            .encode(PhantomOneFrameType::Keepalive, b"b", 128)
            .expect("last sequence is usable");
        let mut decoder = PhantomOneDecoder::new(5);

        assert_eq!(
            decoder
                .decode(&last, 128)
                .expect("maximum sequence")
                .sequence,
            u64::MAX
        );
        assert_eq!(
            decoder
                .decode(&penultimate, 128)
                .expect("reordered penultimate")
                .sequence,
            u64::MAX - 1
        );
        assert_protocol_error(decoder.decode(&last, 128));
    }

    #[test]
    fn config_and_replay_window_bounds_are_explicit() {
        assert!(PhantomOneConfig::new(9, 8).is_err());
        assert!(PhantomOneConfig::new(0, super::PHANTOM_ONE_MAX_PADDING_BYTES + 1).is_err());
        let config = PhantomOneConfig::new(4, 8).expect("valid config");
        assert_eq!(config.min_padding(), 4);
        assert_eq!(config.max_padding(), 8);
        assert!(PhantomOneDecoder::with_window(1, 0).is_err());
        assert!(PhantomOneDecoder::with_window(1, 65).is_err());
        assert!(PhantomOneDecoder::with_window(1, 64).is_ok());
    }

    #[test]
    fn seeded_config_constructor_rejects_invalid_config() {
        let invalid = PhantomOneConfig::new(8, 4).expect_err("invalid padding range");
        assert!(matches!(invalid, ShphError::Config(_)));
        assert!(
            PhantomOneEncoder::from_seed_with_config(1, 2, PhantomOneConfig::default()).is_ok()
        );
    }

    #[test]
    fn large_but_representable_envelopes_remain_mtu_bounded() {
        let payload = vec![0x5a; super::PHANTOM_ONE_MAX_PAYLOAD_BYTES];
        let mut encoder = PhantomOneEncoder::from_seed_with_config(
            6,
            11,
            PhantomOneConfig::new(0, 0).expect("zero padding"),
        )
        .expect("encoder config");
        let encoded = encoder
            .encode(
                PhantomOneFrameType::Data,
                &payload,
                PHANTOM_ONE_MAX_ENVELOPE_BYTES,
            )
            .expect("maximum envelope");
        assert_eq!(encoded.len(), PHANTOM_ONE_MAX_ENVELOPE_BYTES);
        assert_eq!(
            decode(&encoded, 6, PHANTOM_ONE_MAX_ENVELOPE_BYTES)
                .expect("maximum decode")
                .payload,
            payload
        );
    }

    #[test]
    fn magic_is_version_specific() {
        assert_eq!(&PHANTOM_ONE_MAGIC, b"PH1\0");
        assert_eq!(PHANTOM_ONE_VERSION, 1);
    }

    #[test]
    fn weighted_selection_is_seeded_and_matches_configured_frequency() {
        let config = PhantomOneConfig::for_profile(ProfileTier::Medium)
            .with_selection(SizeSelection::Weighted([1, 3, 0, 0, 0, 0, 0]))
            .expect("weighted profile config");
        let mut first =
            PhantomOneEncoder::from_seed_with_config(31, 42, config).expect("first encoder");
        let mut second =
            PhantomOneEncoder::from_seed_with_config(31, 42, config).expect("second encoder");
        let mut first_class_count = 0usize;
        const SAMPLES: usize = 10_000;

        for _ in 0..SAMPLES {
            let first_size = first.target_size(1, 256).expect("select first target");
            let second_size = second.target_size(1, 256).expect("select second target");
            assert_eq!(first_size, second_size, "seeded selection must reproduce");
            assert!(matches!(first_size, 128 | 256));
            first_class_count += usize::from(first_size == 128);
        }

        assert!(
            (2_200..=2_800).contains(&first_class_count),
            "first class frequency {first_class_count}/{SAMPLES} must be within 3% of the configured 25%"
        );
    }

    #[test]
    fn weighted_selection_validates_weights_and_requires_profile_binding() {
        let weighted = SizeSelection::Weighted([1, 0, 0, 0, 0, 0, 0]);
        assert!(PhantomOneConfig::new(0, 0)
            .expect("unbound config")
            .with_selection(weighted)
            .is_err());

        let profile_config = PhantomOneConfig::for_profile(ProfileTier::Medium);
        assert!(profile_config
            .with_selection(SizeSelection::Weighted([0; 7]))
            .is_err());
        assert!(profile_config
            .with_selection(SizeSelection::Weighted([1, 1, 1, 1, 1, 1, 0]))
            .is_err());
    }

    #[test]
    fn weighted_class_and_session_padding_budgets_hold_at_boundaries() {
        let config = PhantomOneConfig::for_profile(ProfileTier::Medium)
            .with_selection(SizeSelection::Weighted([1, 0, 0, 0, 0, 0, 0]))
            .expect("single-class config")
            .with_padding_budget((128 - PHANTOM_ONE_HEADER_BYTES - 1) as u64);
        let mut encoder =
            PhantomOneEncoder::from_seed_with_config(32, 77, config).expect("budgeted encoder");
        let mut control =
            PhantomOneEncoder::from_seed_with_config(32, 77, config).expect("control encoder");

        assert!(encoder.target_size(1, 127).is_err());
        assert_eq!(encoder.next_sequence(), Some(0));
        assert_eq!(encoder.metrics().frames, 0);

        let encoded = encoder
            .encode(PhantomOneFrameType::Data, b"x", 128)
            .expect("canonical class exactly meets carrier limit");
        let control_encoded = control
            .encode(PhantomOneFrameType::Data, b"x", 128)
            .expect("control encoding");
        assert_eq!(
            encoded, control_encoded,
            "rejected selection must not advance RNG"
        );
        assert_eq!(encoded.len(), 128);
        assert_eq!(
            encoder.metrics().padding_bytes,
            config.padding_budget().unwrap()
        );

        let metrics = encoder.metrics();
        assert!(encoder
            .encode(PhantomOneFrameType::Data, b"x", 128)
            .is_err());
        assert_eq!(encoder.next_sequence(), Some(1));
        assert_eq!(
            encoder.metrics(),
            metrics,
            "budget rejection must not mutate metrics"
        );
        assert!(encoder
            .encode(
                PhantomOneFrameType::Data,
                &[0; 128 - PHANTOM_ONE_HEADER_BYTES + 1],
                128
            )
            .is_err());
        assert_eq!(encoder.next_sequence(), Some(1));
        assert_eq!(encoder.metrics(), metrics);
    }
}
