//! Minimal obfuscation profile surface for SHPH Phase 0.

use shph_core::{ShroudProfile, StealthProfile};

#[derive(Debug, Clone, Copy)]
pub struct ObfuscationPreset {
    pub shroud: ShroudProfile,
    pub stealth: StealthProfile,
}
