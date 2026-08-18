//! Shared traffic-shaping profiles for SHPH transports.
//!
//! Profile padding is applied before transport AEAD encryption. That keeps the
//! original payload length and the randomized tail inside the authenticated
//! envelope, while allowing TCP and QUIC to use the same discrete size policy.

use rand::RngCore;
use shph_core::{Result, ShphError, ShroudProfile, StealthProfile};
use std::str::FromStr;

const PROFILE_MAGIC: &[u8; 4] = b"SPAD";
const PROFILE_HEADER_BYTES: usize = 7;
const LOW_JITTER_BYTES: usize = 7;

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
}

impl ProfileTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub const fn id(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }

    pub const fn base_tiers(self) -> &'static [usize] {
        match self {
            Self::Low => &[128, 256],
            Self::Medium => &[128, 256, 512, 1024, 1360],
            Self::High => &[512, 1024, 1360],
        }
    }

    /// Map the existing Shroud lab selection onto the shared transport tier.
    pub fn from_shroud_profile(profile: ShroudProfile) -> Self {
        match profile.name {
            "low-latency" => Self::Low,
            "bulk" | "extreme-lab" => Self::High,
            _ => Self::Medium,
        }
    }

    #[cfg(test)]
    fn max_frame_len(self) -> usize {
        let max = self.base_tiers()[self.base_tiers().len() - 1];
        max + if matches!(self, Self::Low) {
            LOW_JITTER_BYTES
        } else {
            0
        }
    }

    fn accepts_frame_len(self, len: usize) -> bool {
        match self {
            Self::Low => {
                (128..=128 + LOW_JITTER_BYTES).contains(&len)
                    || (256..=256 + LOW_JITTER_BYTES).contains(&len)
            }
            Self::Medium | Self::High => self.base_tiers().contains(&len),
        }
    }
}

impl FromStr for ProfileTier {
    type Err = ShphError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" | "low-latency" => Ok(Self::Low),
            "medium" | "balanced" => Ok(Self::Medium),
            "high" | "bulk" | "extreme" | "extreme-lab" => Ok(Self::High),
            _ => Err(ShphError::Obfuscation(format!(
                "unsupported padding profile: {value}"
            ))),
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
    let jitter = if matches!(profile, ProfileTier::Low) {
        let mut random = [0u8; 1];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| ShphError::Crypto("OS randomness unavailable".into()))?;
        usize::from(random[0]) % (LOW_JITTER_BYTES + 1)
    } else {
        0
    };
    let frame_len = base
        .checked_add(jitter)
        .ok_or_else(|| ShphError::Obfuscation("profile frame length overflow".into()))?;

    let mut framed = vec![0u8; frame_len];
    framed[..PROFILE_MAGIC.len()].copy_from_slice(PROFILE_MAGIC);
    framed[PROFILE_MAGIC.len()] = profile.id();
    framed[5..7].copy_from_slice(
        &u16::try_from(payload.len())
            .map_err(|_| ShphError::Obfuscation("profile payload exceeds u16".into()))?
            .to_be_bytes(),
    );
    framed[PROFILE_HEADER_BYTES..PROFILE_HEADER_BYTES + payload.len()].copy_from_slice(payload);
    if PROFILE_HEADER_BYTES + payload.len() < framed.len() {
        rand::rngs::OsRng
            .try_fill_bytes(&mut framed[PROFILE_HEADER_BYTES + payload.len()..])
            .map_err(|_| ShphError::Crypto("OS randomness unavailable".into()))?;
    }
    Ok(framed)
}

/// Remove a profile envelope after transport AEAD decryption.
///
/// If the marker is absent, the payload is returned unchanged to keep newer
/// receivers tolerant of legacy unprofiled peers. A present but malformed
/// marker fails closed.
pub fn remove_profile(profile: ProfileTier, framed: &[u8]) -> Result<Vec<u8>> {
    if framed.len() < PROFILE_HEADER_BYTES || &framed[..PROFILE_MAGIC.len()] != PROFILE_MAGIC {
        return Ok(framed.to_vec());
    }
    if framed[PROFILE_MAGIC.len()] != profile.id() {
        return Err(ShphError::Obfuscation(
            "profile envelope tier mismatch".into(),
        ));
    }
    if !profile.accepts_frame_len(framed.len()) {
        return Err(ShphError::Obfuscation(
            "profile envelope size is not a canonical tier".into(),
        ));
    }
    let payload_len = u16::from_be_bytes([framed[5], framed[6]]) as usize;
    if payload_len > framed.len() - PROFILE_HEADER_BYTES {
        return Err(ShphError::Obfuscation(
            "profile envelope payload length exceeds frame".into(),
        ));
    }
    Ok(framed[PROFILE_HEADER_BYTES..PROFILE_HEADER_BYTES + payload_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::{apply_profile, remove_profile, ProfileTier};

    #[test]
    fn profile_tiers_match_the_declared_discrete_mapping() {
        assert_eq!(ProfileTier::Low.base_tiers(), &[128, 256]);
        assert_eq!(
            ProfileTier::Medium.base_tiers(),
            &[128, 256, 512, 1024, 1360]
        );
        assert_eq!(ProfileTier::High.base_tiers(), &[512, 1024, 1360]);
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
    }

    #[test]
    fn every_profile_round_trips_and_stays_bounded() {
        for profile in [ProfileTier::Low, ProfileTier::Medium, ProfileTier::High] {
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
    fn malformed_profile_marker_fails_closed() {
        let mut framed = apply_profile(ProfileTier::Medium, b"payload").expect("apply profile");
        framed[5..7].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(remove_profile(ProfileTier::Medium, &framed).is_err());
    }

    #[test]
    fn unprofiled_payload_remains_compatible() {
        assert_eq!(
            remove_profile(ProfileTier::Medium, b"legacy").expect("legacy payload"),
            b"legacy"
        );
    }
}
