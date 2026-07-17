//! Stealth and traffic-shaping profiles for SHPH.
//!
//! These profiles define how traffic is padded, shaped, and obfuscated
//! to evade DPI and blend with normal traffic.

use std::time::Duration;

/// Shroud profile for fixed-size cell framing
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShroudProfile {
    pub name: &'static str,
    pub cell_size: usize,
    pub send_interval: Duration,
    pub chaff_interval: Duration,
    pub max_payload_chunk: usize,
    pub deterministic_padding: bool,
    pub adaptive_chunking: bool,
}

impl ShroudProfile {
    pub const fn payload_capacity(&self) -> usize {
        self.cell_size.saturating_sub(5)
    }

    pub const fn is_valid(&self) -> bool {
        self.cell_size >= 64
            && self.cell_size <= 16 * 1024
            && self.max_payload_chunk > 0
            && self.max_payload_chunk <= self.payload_capacity()
            && !self.send_interval.is_zero()
            && !self.chaff_interval.is_zero()
    }
}

pub const BALANCED: ShroudProfile = ShroudProfile {
    name: "balanced",
    cell_size: 1024,
    send_interval: Duration::from_millis(25),
    chaff_interval: Duration::from_millis(250),
    max_payload_chunk: 768,
    deterministic_padding: true,
    adaptive_chunking: true,
};

pub const LOW_LATENCY: ShroudProfile = ShroudProfile {
    name: "low-latency",
    cell_size: 512,
    send_interval: Duration::from_millis(5),
    chaff_interval: Duration::from_millis(100),
    max_payload_chunk: 384,
    deterministic_padding: true,
    adaptive_chunking: true,
};

pub const BULK: ShroudProfile = ShroudProfile {
    name: "bulk",
    cell_size: 4096,
    send_interval: Duration::from_millis(10),
    chaff_interval: Duration::from_millis(500),
    max_payload_chunk: 3072,
    deterministic_padding: true,
    adaptive_chunking: true,
};

pub const RANDOMIZED_LAB: ShroudProfile = ShroudProfile {
    name: "randomized-lab",
    cell_size: 1024,
    send_interval: Duration::from_millis(25),
    chaff_interval: Duration::from_millis(250),
    max_payload_chunk: 768,
    deterministic_padding: false,
    adaptive_chunking: true,
};

/// Stealth profile for DPI evasion
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StealthProfile {
    pub name: &'static str,
    pub tls_camouflage: TlsCamouflage,
    pub handshake_jitter_floor: Duration,
    pub handshake_jitter_ceil: Duration,
    pub morph: MorphProfile,
    pub quic_candidate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsCamouflage {
    Balanced,
    BrowserBlend,
    Http11Favor,
    BrowserStrict,
    H3Camouflage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkDistribution {
    Uniform,
    FrontLoaded,
    TailLoaded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MorphProfile {
    pub chunk_distribution: ChunkDistribution,
    pub padding_probability_pct: u8,
    pub burst_probability_pct: u8,
    pub idle_chaff_probability_pct: u8,
    pub cell_size_classes: &'static [usize],
}

pub const STEADY: StealthProfile = StealthProfile {
    name: "steady",
    tls_camouflage: TlsCamouflage::Balanced,
    handshake_jitter_floor: Duration::from_millis(5),
    handshake_jitter_ceil: Duration::from_millis(40),
    morph: MorphProfile {
        chunk_distribution: ChunkDistribution::Uniform,
        padding_probability_pct: 18,
        burst_probability_pct: 22,
        idle_chaff_probability_pct: 35,
        cell_size_classes: &[1024, 1280],
    },
    quic_candidate: false,
};

pub const CAMOUFLAGE: StealthProfile = StealthProfile {
    name: "camouflage",
    tls_camouflage: TlsCamouflage::BrowserBlend,
    handshake_jitter_floor: Duration::from_millis(12),
    handshake_jitter_ceil: Duration::from_millis(90),
    morph: MorphProfile {
        chunk_distribution: ChunkDistribution::FrontLoaded,
        padding_probability_pct: 30,
        burst_probability_pct: 38,
        idle_chaff_probability_pct: 45,
        cell_size_classes: &[768, 1024, 1280],
    },
    quic_candidate: true,
};

pub const MIMICRY_LAB: StealthProfile = StealthProfile {
    name: "mimicry-lab",
    tls_camouflage: TlsCamouflage::Http11Favor,
    handshake_jitter_floor: Duration::from_millis(20),
    handshake_jitter_ceil: Duration::from_millis(140),
    morph: MorphProfile {
        chunk_distribution: ChunkDistribution::TailLoaded,
        padding_probability_pct: 44,
        burst_probability_pct: 53,
        idle_chaff_probability_pct: 58,
        cell_size_classes: &[512, 768, 1024, 1536],
    },
    quic_candidate: true,
};

pub fn profiles() -> &'static [ShroudProfile] {
    &[BALANCED, LOW_LATENCY, BULK, RANDOMIZED_LAB]
}

pub fn stealth_profiles() -> &'static [StealthProfile] {
    &[STEADY, CAMOUFLAGE, MIMICRY_LAB]
}

pub fn shroud_profile_by_name(name: &str) -> Option<ShroudProfile> {
    profiles()
        .iter()
        .copied()
        .find(|profile| profile.name == name)
}

pub fn stealth_profile_by_name(name: &str) -> Option<StealthProfile> {
    stealth_profiles()
        .iter()
        .copied()
        .find(|profile| profile.name == name)
}

#[cfg(test)]
mod tests {
    use super::{shroud_profile_by_name, ShroudProfile, BALANCED};

    #[test]
    fn randomized_lab_profile_is_available_and_valid() {
        let profile = shroud_profile_by_name("randomized-lab").expect("profile");
        assert!(profile.is_valid());
        assert!(!profile.deterministic_padding);
    }

    #[test]
    fn profile_validation_rejects_invalid_payload_chunk() {
        let invalid = ShroudProfile {
            max_payload_chunk: 0,
            ..BALANCED
        };
        assert!(!invalid.is_valid());
    }
}
