//! Shared traffic-shaping profiles for SHPH transports.
//!
//! Profile padding is applied before transport AEAD encryption. That keeps the
//! original payload length and the randomized tail inside the authenticated
//! envelope, while allowing TCP and QUIC to use the same discrete size policy.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use shph_core::{Result, ShphError, ShroudProfile, StealthProfile};
use std::str::FromStr;
use zeroize::Zeroize;

const PROFILE_MAGIC: &[u8; 4] = b"SPAD";
pub const PROFILE_HEADER_BYTES: usize = 7;
const LOW_JITTER_BYTES: usize = 7;

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

#[derive(Debug, Clone, Copy)]
pub struct ObfuscationPreset {
    pub shroud: ShroudProfile,
    pub stealth: StealthProfile,
}

/// Discrete application-frame padding tiers shared by stream and datagram
/// transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileTier {
    /// Small interactive traffic: 128-byte and 256-byte buckets with up to
    /// seven bytes of bounded jitter.
    Low,
    /// General traffic: 128, 256, 512, 1024, and 1360-byte buckets.
    Medium,
    /// Bulk/video traffic: 512, 1024, and 1360-byte buckets.
    High,
    /// Tuned low-latency buckets for small interactive messages.
    TunedLow,
    /// Tuned mixed-traffic buckets with an intermediate 768-byte class.
    TunedMedium,
    /// Tuned bulk buckets aligned with the default 1,360-byte TUN path.
    TunedHigh,
}

impl ProfileTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::TunedLow => "tuned-low",
            Self::TunedMedium => "tuned-medium",
            Self::TunedHigh => "tuned-high",
        }
    }

    pub const fn id(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::TunedLow => 3,
            Self::TunedMedium => 4,
            Self::TunedHigh => 5,
        }
    }

    /// Decode the stable wire identifier used by Phantom One.
    ///
    /// Values outside the six assigned tiers are deliberately rejected rather
    /// than mapped to a default profile.
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Low),
            1 => Some(Self::Medium),
            2 => Some(Self::High),
            3 => Some(Self::TunedLow),
            4 => Some(Self::TunedMedium),
            5 => Some(Self::TunedHigh),
            _ => None,
        }
    }

    pub const fn base_tiers(self) -> &'static [usize] {
        match self {
            Self::Low => &[128, 256],
            Self::Medium => &[128, 256, 512, 1024, 1360],
            Self::High => &[512, 1024, 1360],
            Self::TunedLow => &[64, 96, 128, 192, 256, 512, 768],
            Self::TunedMedium => &[128, 256, 512, 768, 1024, 1360],
            Self::TunedHigh => &[512, 768, 1024, 1280, 1360],
        }
    }

    /// Map the existing Shroud lab selection onto the shared transport tier.
    pub fn from_shroud_profile(profile: ShroudProfile) -> Self {
        match profile.name {
            "tuned-low" => Self::TunedLow,
            "tuned-medium" => Self::TunedMedium,
            "tuned-high" => Self::TunedHigh,
            "low-latency" => Self::Low,
            "bulk" | "extreme-lab" => Self::High,
            _ => Self::Medium,
        }
    }

    #[cfg(test)]
    fn max_frame_len(self) -> usize {
        let max = self.base_tiers()[self.base_tiers().len() - 1];
        max + match self {
            Self::Low => LOW_JITTER_BYTES,
            Self::TunedLow => 3,
            _ => 0,
        }
    }

    /// Return whether a frame length belongs to this profile's canonical
    /// discrete-size set, including the intentionally bounded low-profile
    /// jitter.
    pub fn accepts_frame_len(self, len: usize) -> bool {
        match self {
            Self::Low => {
                (128..=128 + LOW_JITTER_BYTES).contains(&len)
                    || (256..=256 + LOW_JITTER_BYTES).contains(&len)
            }
            Self::TunedLow => self
                .base_tiers()
                .iter()
                .any(|base| (*base..=*base + 3).contains(&len)),
            Self::Medium | Self::High | Self::TunedMedium | Self::TunedHigh => {
                self.base_tiers().contains(&len)
            }
        }
    }

    /// Largest canonical frame length for this profile.
    pub const fn max_canonical_frame_len(self) -> usize {
        let base = self.base_tiers()[self.base_tiers().len() - 1];
        base + match self {
            Self::Low => LOW_JITTER_BYTES,
            Self::TunedLow => 3,
            _ => 0,
        }
    }

    /// Maximum application payload that fits in this profile's largest
    /// canonical frame after the profile envelope header.
    pub const fn max_payload_bytes(self) -> usize {
        self.base_tiers()[self.base_tiers().len() - 1].saturating_sub(PROFILE_HEADER_BYTES)
    }
}

impl FromStr for ProfileTier {
    type Err = ShphError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" | "low-latency" => Ok(Self::Low),
            "medium" | "balanced" => Ok(Self::Medium),
            "high" | "bulk" | "extreme" | "extreme-lab" => Ok(Self::High),
            "tuned" | "optimized" | "tuned-medium" | "optimized-medium" => Ok(Self::TunedMedium),
            "tuned-low" | "optimized-low" => Ok(Self::TunedLow),
            "tuned-high" | "optimized-high" => Ok(Self::TunedHigh),
            _ => Err(ShphError::Obfuscation(format!(
                "unsupported padding profile: {value}"
            ))),
        }
    }
}

/// Session-scoped padding generator.
///
/// The generator is seeded once from the process RNG and then reused for the
/// lifetime of a transport session. This avoids an OS-randomness syscall for
/// every frame while retaining unpredictable padding on the wire. The
/// `from_seed` constructor is intended for deterministic lab and benchmark
/// runs only.
#[derive(Debug)]
pub struct ProfilePadder {
    profile: ProfileTier,
    rng: StdRng,
}

impl ProfilePadder {
    pub fn new(profile: ProfileTier) -> Self {
        Self::from_seed(profile, rand::random())
    }

    pub fn from_seed(profile: ProfileTier, seed: [u8; 32]) -> Self {
        Self {
            profile,
            rng: StdRng::from_seed(seed),
        }
    }

    pub const fn profile(&self) -> ProfileTier {
        self.profile
    }

    /// Fill a caller-owned buffer with one authenticated profile envelope.
    ///
    /// Reusing `framed` across calls avoids a second allocation in the
    /// transport send loop; the subsequent AEAD operation still owns its
    /// ciphertext allocation.
    pub fn apply_into(&mut self, payload: &[u8], framed: &mut Vec<u8>) -> Result<()> {
        apply_profile_into_with_rng(self.profile, payload, framed, &mut self.rng)
    }

    pub fn apply(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut framed = Vec::new();
        self.apply_into(payload, &mut framed)?;
        Ok(framed)
    }
}

fn apply_profile_into_with_rng(
    profile: ProfileTier,
    payload: &[u8],
    framed: &mut Vec<u8>,
    rng: &mut impl RngCore,
) -> Result<()> {
    let mut cleanup = WipeBufferOnError::new(framed);
    let minimum = PROFILE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| ShphError::Obfuscation("profile payload length overflow".into()))?;
    let base = profile
        .base_tiers()
        .iter()
        .copied()
        .find(|size| *size >= minimum)
        .ok_or_else(|| {
            ShphError::Obfuscation(format!(
                "{} profile cannot carry a {}-byte payload",
                profile.as_str(),
                payload.len()
            ))
        })?;
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| ShphError::Obfuscation("profile payload exceeds u16".into()))?;
    let jitter = if matches!(profile, ProfileTier::Low | ProfileTier::TunedLow) {
        let jitter_bound = if matches!(profile, ProfileTier::TunedLow) {
            3
        } else {
            LOW_JITTER_BYTES
        };
        sample_uniform_below(rng, (jitter_bound + 1) as u32)
    } else {
        0
    };
    let frame_len = base
        .checked_add(jitter)
        .ok_or_else(|| ShphError::Obfuscation("profile frame length overflow".into()))?;
    if frame_len > u16::MAX as usize {
        return Err(ShphError::Obfuscation(
            "profile frame length exceeds u16".into(),
        ));
    }

    cleanup.prepare(frame_len);
    cleanup.buffer.resize(frame_len, 0);
    cleanup.buffer[..PROFILE_MAGIC.len()].copy_from_slice(PROFILE_MAGIC);
    cleanup.buffer[PROFILE_MAGIC.len()] = profile.id();
    cleanup.buffer[5..7].copy_from_slice(&payload_len.to_be_bytes());
    cleanup.buffer[PROFILE_HEADER_BYTES..PROFILE_HEADER_BYTES + payload.len()]
        .copy_from_slice(payload);
    if PROFILE_HEADER_BYTES + payload.len() < cleanup.buffer.len()
        && rng
            .try_fill_bytes(&mut cleanup.buffer[PROFILE_HEADER_BYTES + payload.len()..])
            .is_err()
    {
        return Err(ShphError::Crypto("OS randomness unavailable".into()));
    }
    cleanup.commit();
    Ok(())
}

fn sample_uniform_below(rng: &mut impl RngCore, upper: u32) -> usize {
    debug_assert!(upper > 0);
    if upper <= 1 {
        return 0;
    }

    let range = u64::from(u32::MAX) + 1;
    let limit = range - range % u64::from(upper);
    loop {
        let sample = u64::from(rng.next_u32());
        if sample < limit {
            return (sample % u64::from(upper)) as usize;
        }
    }
}

/// Apply a bounded, authenticated profile envelope to an application payload.
///
/// The returned bytes contain a small marker, the original payload length, the
/// payload, and randomized tail bytes. Call [`remove_profile`] after AEAD
/// decryption. A caller should treat the returned bytes as opaque transport
/// plaintext rather than application data.
pub fn apply_profile(profile: ProfileTier, payload: &[u8]) -> Result<Vec<u8>> {
    let mut framed = Vec::new();
    apply_profile_into(profile, payload, &mut framed)?;
    Ok(framed)
}

/// Apply a profile envelope into a caller-owned reusable buffer.
///
/// Rejected requests clear the buffer. Successful reuse overwrites the new
/// envelope and wipes bytes retired by a shrink.
pub fn apply_profile_into(
    profile: ProfileTier,
    payload: &[u8],
    framed: &mut Vec<u8>,
) -> Result<()> {
    let mut rng = rand::rngs::OsRng;
    apply_profile_into_with_rng(profile, payload, framed, &mut rng)
}

/// Remove a profile envelope after transport AEAD decryption.
///
/// If the marker is absent, the payload is returned unchanged to keep newer
/// receivers tolerant of legacy unprofiled peers. A present but malformed
/// marker fails closed.
pub fn remove_profile(profile: ProfileTier, framed: &[u8]) -> Result<Vec<u8>> {
    let mut reusable = framed.to_vec();
    remove_profile_in_place(profile, &mut reusable)?;
    Ok(reusable)
}

/// Remove a profile envelope in the caller-owned decrypted buffer.
///
/// The payload is moved to the front and the vector is truncated, so callers
/// that already own the decrypted transport buffer avoid a second allocation.
pub fn remove_profile_in_place(profile: ProfileTier, framed: &mut Vec<u8>) -> Result<()> {
    let cleanup = WipeBufferOnError::new(framed);
    if cleanup.buffer.len() < PROFILE_MAGIC.len()
        || &cleanup.buffer[..PROFILE_MAGIC.len()] != PROFILE_MAGIC
    {
        cleanup.commit();
        return Ok(());
    }
    if cleanup.buffer.len() < PROFILE_HEADER_BYTES {
        return Err(ShphError::Obfuscation(
            "profile envelope is truncated".into(),
        ));
    }
    if cleanup.buffer[PROFILE_MAGIC.len()] != profile.id() {
        return Err(ShphError::Obfuscation(
            "profile envelope tier mismatch".into(),
        ));
    }
    if !profile.accepts_frame_len(cleanup.buffer.len()) {
        return Err(ShphError::Obfuscation(
            "profile envelope size is not a canonical tier".into(),
        ));
    }
    let payload_len = u16::from_be_bytes([cleanup.buffer[5], cleanup.buffer[6]]) as usize;
    if payload_len > cleanup.buffer.len() - PROFILE_HEADER_BYTES {
        return Err(ShphError::Obfuscation(
            "profile envelope payload length exceeds frame".into(),
        ));
    }
    let payload_end = PROFILE_HEADER_BYTES + payload_len;
    cleanup
        .buffer
        .copy_within(PROFILE_HEADER_BYTES..payload_end, 0);
    cleanup.buffer[payload_len..].zeroize();
    cleanup.buffer.truncate(payload_len);
    cleanup.commit();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_profile, remove_profile, remove_profile_in_place, ProfilePadder, ProfileTier,
        PROFILE_HEADER_BYTES,
    };

    #[test]
    fn profile_tiers_match_the_declared_discrete_mapping() {
        assert_eq!(ProfileTier::Low.base_tiers(), &[128, 256]);
        assert_eq!(
            ProfileTier::Medium.base_tiers(),
            &[128, 256, 512, 1024, 1360]
        );
        assert_eq!(ProfileTier::High.base_tiers(), &[512, 1024, 1360]);
        assert_eq!(
            ProfileTier::TunedLow.base_tiers(),
            &[64, 96, 128, 192, 256, 512, 768]
        );
        assert_eq!(
            ProfileTier::TunedMedium.base_tiers(),
            &[128, 256, 512, 768, 1024, 1360]
        );
        assert_eq!(
            ProfileTier::TunedHigh.base_tiers(),
            &[512, 768, 1024, 1280, 1360]
        );
    }

    #[test]
    fn profile_payload_capacity_accounts_for_the_envelope_header() {
        assert_eq!(ProfileTier::Low.max_payload_bytes(), 249);
        assert_eq!(ProfileTier::Medium.max_payload_bytes(), 1353);
        assert_eq!(ProfileTier::High.max_payload_bytes(), 1353);
        assert_eq!(ProfileTier::TunedLow.max_payload_bytes(), 761);
        assert_eq!(ProfileTier::TunedMedium.max_payload_bytes(), 1353);
        assert_eq!(ProfileTier::TunedHigh.max_payload_bytes(), 1353);
    }

    #[test]
    fn shroud_profiles_map_to_the_shared_transport_tiers() {
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::LOW_LATENCY),
            ProfileTier::Low
        );
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::BALANCED),
            ProfileTier::Medium
        );
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::RANDOMIZED_LAB),
            ProfileTier::Medium
        );
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::BULK),
            ProfileTier::High
        );
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::EXTREME_LAB),
            ProfileTier::High
        );
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::TUNED_LOW),
            ProfileTier::TunedLow
        );
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::TUNED_MEDIUM),
            ProfileTier::TunedMedium
        );
        assert_eq!(
            ProfileTier::from_shroud_profile(shph_core::TUNED_HIGH),
            ProfileTier::TunedHigh
        );
    }

    #[test]
    fn profile_ids_are_strict_and_stable() {
        let profiles = [
            ProfileTier::Low,
            ProfileTier::Medium,
            ProfileTier::High,
            ProfileTier::TunedLow,
            ProfileTier::TunedMedium,
            ProfileTier::TunedHigh,
        ];

        for (id, profile) in profiles.into_iter().enumerate() {
            assert_eq!(profile.id(), id as u8);
            assert_eq!(ProfileTier::from_id(id as u8), Some(profile));
        }
        assert_eq!(ProfileTier::from_id(6), None);
        assert_eq!(ProfileTier::from_id(u8::MAX), None);
    }

    #[test]
    fn every_profile_round_trips_and_stays_bounded() {
        for profile in [
            ProfileTier::Low,
            ProfileTier::Medium,
            ProfileTier::High,
            ProfileTier::TunedLow,
            ProfileTier::TunedMedium,
            ProfileTier::TunedHigh,
        ] {
            let payload = vec![0x5a; 73];
            let framed = apply_profile(profile, &payload).expect("apply profile");
            assert!(framed.len() <= profile.max_frame_len());
            assert_eq!(
                remove_profile(profile, &framed).expect("remove profile"),
                payload
            );
        }
    }

    #[test]
    fn low_profile_jitter_stays_inside_the_small_bound() {
        for _ in 0..128 {
            let framed = apply_profile(ProfileTier::Low, b"ssh").expect("apply low profile");
            assert!((128..=263).contains(&framed.len()));
        }
    }

    #[test]
    fn tuned_profile_jitter_stays_inside_its_declared_bounds() {
        for _ in 0..128 {
            let framed =
                apply_profile(ProfileTier::TunedLow, b"ssh").expect("apply tuned low profile");
            assert!((64..=67).contains(&framed.len()));
        }
    }

    #[test]
    fn stateful_padder_reuses_rng_without_changing_the_envelope_contract() {
        let mut padder = ProfilePadder::from_seed(ProfileTier::TunedLow, [7; 32]);
        let mut framed = Vec::new();
        padder
            .apply_into(b"ssh", &mut framed)
            .expect("first envelope");
        assert_eq!(
            remove_profile(ProfileTier::TunedLow, &framed).expect("first decode"),
            b"ssh"
        );
        let first = framed.clone();
        padder
            .apply_into(b"ssh", &mut framed)
            .expect("second envelope");
        assert_eq!(
            remove_profile(ProfileTier::TunedLow, &framed).expect("second decode"),
            b"ssh"
        );
        assert_ne!(first, framed);
    }

    #[test]
    fn reusable_profile_encode_clears_buffer_on_rejection() {
        let mut padder = ProfilePadder::from_seed(ProfileTier::Low, [8; 32]);
        let mut framed = Vec::new();
        padder
            .apply_into(b"previous", &mut framed)
            .expect("initial envelope");
        assert!(padder.apply_into(&[0u8; 2_000], &mut framed).is_err());
        assert!(framed.is_empty());
    }

    #[test]
    fn malformed_profile_marker_fails_closed() {
        let mut framed = apply_profile(ProfileTier::Medium, b"payload").expect("apply profile");
        framed[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(remove_profile(ProfileTier::Medium, &framed).is_err());
    }

    #[test]
    fn malformed_profile_removal_clears_reusable_buffer() {
        let mut framed = apply_profile(ProfileTier::Medium, b"payload").expect("apply profile");
        framed[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(remove_profile_in_place(ProfileTier::Medium, &mut framed).is_err());
        assert!(framed.is_empty());
    }

    #[test]
    fn truncated_profile_marker_fails_closed() {
        for length in 4..PROFILE_HEADER_BYTES {
            let mut framed = b"SPAD".to_vec();
            framed.resize(length, 0);
            assert!(remove_profile(ProfileTier::Medium, &framed).is_err());
        }
    }

    #[test]
    fn profile_removal_can_reuse_the_decrypted_buffer() {
        let framed = apply_profile(ProfileTier::Medium, b"payload").expect("apply profile");
        let expected = remove_profile(ProfileTier::Medium, &framed).expect("remove profile");
        let mut reusable = framed;
        remove_profile_in_place(ProfileTier::Medium, &mut reusable).expect("remove in place");
        assert_eq!(reusable, expected);
    }

    #[test]
    fn unprofiled_payload_remains_compatible() {
        assert_eq!(
            remove_profile(ProfileTier::Medium, b"legacy").expect("legacy payload"),
            b"legacy"
        );
    }
}
