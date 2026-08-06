#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_transport::shroud2::{decode_datagram, MorphologyProfile, MorphologyEngine};

fuzz_target!(|input: &[u8]| {
    if input.len() > 65_535 {
        return;
    }
    let _ = decode_datagram(input, 65_535);

    if let Some(payload) = input.get(..input.len().min(4_096)) {
        let seed = input
            .get(..8)
            .map(|bytes| {
                let mut seed = [0u8; 8];
                seed[..bytes.len()].copy_from_slice(bytes);
                u64::from_be_bytes(seed)
            })
            .unwrap_or_default();
        let mut engine = MorphologyEngine::from_seed(MorphologyProfile::WebBrowsingLab, seed);
        if let Ok(target) = engine.target_size(payload.len(), 65_535) {
            if let Ok(encoded) = shph_transport::shroud2::encode_datagram(
                payload,
                target,
                65_535,
            ) {
                let _ = decode_datagram(&encoded, 65_535);
            }
        }
    }
});
