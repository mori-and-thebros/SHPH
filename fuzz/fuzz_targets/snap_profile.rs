#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_snap::{ProfileFormat, SnapProfile, MAX_PROFILE_BYTES};

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_PROFILE_BYTES {
        return;
    }

    let _ = SnapProfile::parse(input, ProfileFormat::Json);
    let _ = SnapProfile::parse(input, ProfileFormat::Toml);
});
