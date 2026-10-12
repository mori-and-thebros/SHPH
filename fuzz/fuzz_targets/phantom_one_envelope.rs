#![no_main]
//! Phantom One envelope fuzz target.
//!
//! Exercises the real `shph_transport::phantom_one` decode/validation, encoder,
//! and stateful-decoder paths with arbitrary bytes and bounded path MTU.
//! Covers malformed, truncated, noncanonical, oversized, replay, and
//! policy-offer inputs. Never panics, never allocates unboundedly.

use libfuzzer_sys::fuzz_target;
use shph_obfuscation::ProfileTier;
use shph_transport::envelope_policy::EnvelopeOffer;
use shph_transport::phantom_one::{
    decode, validate_path_mtu, PhantomOneConfig, PhantomOneDecoder, PhantomOneEncoder,
    PhantomOneFrameType, PHANTOM_ONE_HEADER_BYTES, PHANTOM_ONE_MAGIC,
    PHANTOM_ONE_MAX_ENVELOPE_BYTES, PHANTOM_ONE_MAX_PADDING_BYTES, PHANTOM_ONE_VERSION,
};

const FRAME_TYPE_OFFSET: usize = 10;
const TARGET_LENGTH_OFFSET: usize = 21;

fuzz_target!(|input: &[u8]| {
    if input.len() > PHANTOM_ONE_MAX_ENVELOPE_BYTES {
        return;
    }

    let _ = EnvelopeOffer::decode(input);
    if let Ok(offer) = EnvelopeOffer::new(
        &"00".repeat(32),
        PhantomOneConfig::for_profile(ProfileTier::Medium),
        1_360,
    ) {
        let mut mutated_offer = offer.encode();
        for (target, value) in mutated_offer[9..].iter_mut().zip(input) {
            *target = *value;
        }
        let _ = EnvelopeOffer::decode(&mutated_offer);
    }

    // ---- Derive fuzz-controlled parameters from input bytes ----
    let generation = u32_from_bytes(input, 0);
    let alt_generation = generation.wrapping_add(1).max(1);
    let seed = u64_from_bytes(input, 4);
    let path_mtus = derive_path_mtus(input);

    // ---- 1. Raw stateless decode: arbitrary bytes ----
    for &mtu in &path_mtus {
        let _ = decode(input, generation, mtu);
        let _ = decode(input, alt_generation, mtu);
    }

    // ---- 2. Structural fuzzing: encode then corrupt ----
    let payload_len = input.len().clamp(
        1,
        PHANTOM_ONE_MAX_ENVELOPE_BYTES - PHANTOM_ONE_HEADER_BYTES - 1,
    );
    let payload = &input[..input.len().min(payload_len)];

    // Pick a path MTU large enough for the payload.
    let envelope_mtu = (PHANTOM_ONE_HEADER_BYTES + payload.len() + PHANTOM_ONE_MAX_PADDING_BYTES)
        .min(PHANTOM_ONE_MAX_ENVELOPE_BYTES);

    let mut encoder = PhantomOneEncoder::from_seed_with_config(
        generation,
        seed,
        PhantomOneConfig::new(0, 0).expect("valid zero-padding config"),
    )
    .expect("valid seeded encoder");

    if let Ok(valid) = encoder.encode(PhantomOneFrameType::Data, payload, envelope_mtu) {
        // 2a. Round-trip stateless decode
        if let Ok(frame) = decode(&valid, generation, envelope_mtu) {
            assert_eq!(frame.payload, payload, "Phantom One round-trip mismatch");
            assert_eq!(frame.generation, generation);
            assert_eq!(frame.frame_type, PhantomOneFrameType::Data);
            assert_eq!(frame.target_len, valid.len());
        }

        // 2b. Round-trip stateful decode
        let mut decoder =
            PhantomOneDecoder::with_window(generation, 64).expect("default window is valid");
        if let Ok(frame) = decoder.decode(&valid, envelope_mtu) {
            assert_eq!(frame.payload, payload);
        }
        let mut reusable = valid.clone();
        let mut in_place_decoder =
            PhantomOneDecoder::with_window(generation, 64).expect("default window is valid");
        if in_place_decoder
            .decode_in_place(&mut reusable, envelope_mtu)
            .is_ok()
        {
            assert_eq!(reusable, payload);
        }

        // 2c. Truncation: strip 1..header bytes from the tail
        for trim in 1..=valid.len().min(PHANTOM_ONE_HEADER_BYTES) {
            let truncated = &valid[..valid.len() - trim];
            let result = decode(truncated, generation, envelope_mtu);
            assert!(result.is_err(), "truncated (trim={trim}) should fail");
        }

        // 2d. Magic corruption: flip each byte
        for i in 0..4 {
            let mut bad = valid.clone();
            bad[i] ^= 0xFF;
            assert!(
                decode(&bad, generation, envelope_mtu).is_err(),
                "bad magic at offset {i} should fail"
            );
        }

        // 2e. Version corruption
        if valid.len() > 4 {
            let mut bad = valid.clone();
            bad[4] = PHANTOM_ONE_VERSION.wrapping_add(1).max(2);
            assert!(
                decode(&bad, generation, envelope_mtu).is_err(),
                "bad version should fail"
            );
        }

        // 2f. Generation mismatch
        assert!(
            decode(&valid, alt_generation, envelope_mtu).is_err(),
            "generation mismatch should fail"
        );

        // 2g. The stateless decoder treats the profile identifier as
        // self-describing. Unknown identifiers must fail, while known
        // identifiers may be structurally valid until a session policy is
        // applied. A policy-bound decoder must reject every profile other
        // than the negotiated medium profile.
        if valid.len() > 5 {
            for profile_id in [0u8, 2, 3, 4, 5] {
                let mut bad = valid.clone();
                bad[5] = profile_id;
                let stateless = decode(&bad, generation, envelope_mtu);
                if let Ok(frame) = stateless {
                    assert_eq!(frame.profile, ProfileTier::from_id(profile_id).unwrap());
                }
                let mut policy_decoder = PhantomOneDecoder::with_config(
                    generation,
                    PhantomOneConfig::for_profile(ProfileTier::Medium),
                )
                .expect("valid medium profile policy");
                assert!(
                    policy_decoder.decode(&bad, envelope_mtu).is_err(),
                    "profile {profile_id} should fail under a medium policy"
                );
            }
            for profile_id in [6u8, u8::MAX] {
                let mut bad = valid.clone();
                bad[5] = profile_id;
                assert!(
                    decode(&bad, generation, envelope_mtu).is_err(),
                    "unknown profile {profile_id} should fail closed"
                );
            }
        }

        // 2h. Frame type corruption
        if valid.len() > FRAME_TYPE_OFFSET {
            let mut bad = valid.clone();
            bad[FRAME_TYPE_OFFSET] = 0xFF;
            assert!(
                decode(&bad, generation, envelope_mtu).is_err(),
                "bad frame type should fail"
            );
        }

        // 2i. Reserved bytes noncanonical
        if valid.len() >= PHANTOM_ONE_HEADER_BYTES {
            let mut bad = valid.clone();
            bad[PHANTOM_ONE_HEADER_BYTES - 1] = 1;
            assert!(
                decode(&bad, generation, envelope_mtu).is_err(),
                "noncanonical reserved bytes should fail"
            );
        }

        // 2j. Target length mismatch
        if valid.len() >= PHANTOM_ONE_HEADER_BYTES && valid.len() > 1 {
            let mut bad = valid.clone();
            let fake_target = (valid.len() - 1) as u16;
            bad[TARGET_LENGTH_OFFSET..TARGET_LENGTH_OFFSET + 2]
                .copy_from_slice(&fake_target.to_be_bytes());
            assert!(
                decode(&bad, generation, envelope_mtu).is_err(),
                "target length mismatch should fail"
            );
        }

        // 2k. Path MTU too small for the envelope
        if valid.len() > PHANTOM_ONE_HEADER_BYTES {
            let small_mtu = valid.len() - 1;
            if small_mtu >= PHANTOM_ONE_HEADER_BYTES {
                let result = decode(&valid, generation, small_mtu);
                assert!(
                    result.is_err(),
                    "MTU {small_mtu} < envelope {} should fail",
                    valid.len()
                );
            }
        }

        // 2l. Payload length zero is valid; an oversized declared length is
        // rejected by the envelope bounds.
        if valid.len() >= PHANTOM_ONE_HEADER_BYTES {
            let mut bad = valid.clone();
            bad[19..21].copy_from_slice(&0u16.to_be_bytes());
            let zero_payload = decode(&bad, generation, envelope_mtu)
                .expect("zero payload length is valid for control/keepalive framing");
            assert!(zero_payload.payload.is_empty());
            let mut bad2 = valid.clone();
            bad2[19..21].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(
                decode(&bad2, generation, envelope_mtu).is_err(),
                "max payload length should fail"
            );
        }
    }

    // ---- 3. Stateful decoder: replay and sequence fuzzing ----
    let mut decoder = PhantomOneDecoder::with_window(generation, 64).expect("window");
    let mut enc = PhantomOneEncoder::from_seed_with_config(
        generation,
        seed,
        PhantomOneConfig::new(0, 0).expect("valid zero-padding config"),
    )
    .expect("valid seeded encoder");
    // Encode up to 4 frames and feed them to the decoder in various orders.
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for _ in 0..4 {
        if let Ok(env) = enc.encode(PhantomOneFrameType::Data, payload, envelope_mtu) {
            frames.push(env);
        }
    }
    for frame in &frames {
        let _ = decoder.decode(frame, envelope_mtu);
    }
    // Replay the first frame: must fail.
    if let Some(first) = frames.first() {
        let result = decoder.decode(first, envelope_mtu);
        assert!(result.is_err(), "replay should fail");
    }
    // Reset and retry: must succeed.
    decoder.reset();
    if let Some(first) = frames.first() {
        let result = decoder.decode(first, envelope_mtu);
        assert!(result.is_ok(), "after reset, first frame should decode");
    }

    // ---- 4. Boundary cases ----

    // 4a. Empty input
    let _ = decode(b"", generation, PHANTOM_ONE_HEADER_BYTES);
    let _ = decode(b"", generation, PHANTOM_ONE_MAX_ENVELOPE_BYTES);

    // 4b. Path MTU validation boundaries
    let _ = validate_path_mtu(0);
    let _ = validate_path_mtu(PHANTOM_ONE_HEADER_BYTES - 1);
    let _ = validate_path_mtu(PHANTOM_ONE_HEADER_BYTES);
    let _ = validate_path_mtu(PHANTOM_ONE_MAX_ENVELOPE_BYTES);
    let _ = validate_path_mtu(PHANTOM_ONE_MAX_ENVELOPE_BYTES + 1);
    let _ = validate_path_mtu(usize::MAX);

    // 4c. A valid encoded frame always carries the canonical marker.
    if let Ok(encoded) = enc.encode(PhantomOneFrameType::Keepalive, b"x", envelope_mtu) {
        assert_eq!(&encoded[..PHANTOM_ONE_MAGIC.len()], &PHANTOM_ONE_MAGIC);
    }

    // 4d. Encoder with various configs
    for (min_pad, max_pad) in [(0, 0), (0, 64), (8, 64), (0, PHANTOM_ONE_MAX_PADDING_BYTES)] {
        let mut enc2 = PhantomOneEncoder::from_seed_with_config(
            generation,
            seed,
            PhantomOneConfig::new(min_pad, max_pad).expect("valid padding config"),
        )
        .expect("valid seeded encoder");
        if let Ok(env) = enc2.encode(PhantomOneFrameType::Keepalive, b"x", envelope_mtu) {
            let _ = decode(&env, generation, envelope_mtu);
            // Decode with a new stateful decoder
            let mut dec2 = PhantomOneDecoder::with_window(generation, 64).expect("window");
            let _ = dec2.decode(&env, envelope_mtu);
        }
    }

    // 4e. All frame types
    for ft in [
        PhantomOneFrameType::Data,
        PhantomOneFrameType::Control,
        PhantomOneFrameType::Keepalive,
    ] {
        let mut enc3 = PhantomOneEncoder::from_seed_with_config(
            generation,
            seed,
            PhantomOneConfig::new(0, 0).expect("valid zero-padding config"),
        )
        .expect("valid seeded encoder");
        if let Ok(env) = enc3.encode(ft, b"x", envelope_mtu) {
            let _ = decode(&env, generation, envelope_mtu);
        }
    }

    // 4g. Payload at max representable size
    let max_payload_len = PHANTOM_ONE_MAX_ENVELOPE_BYTES - PHANTOM_ONE_HEADER_BYTES; // 65511
    let big_payload = vec![0xAAu8; max_payload_len.min(1024)]; // cap at 1024 for fuzz speed
    let mut enc4 = PhantomOneEncoder::from_seed_with_config(
        generation,
        seed,
        PhantomOneConfig::new(0, 0).expect("valid zero-padding config"),
    )
    .expect("valid seeded encoder");
    let _ = enc4.encode(
        PhantomOneFrameType::Data,
        &big_payload,
        PHANTOM_ONE_MAX_ENVELOPE_BYTES,
    );
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn u32_from_bytes(input: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    let end = (offset + 4).min(input.len());
    let len = end.saturating_sub(offset);
    buf[..len].copy_from_slice(input.get(offset..end).unwrap_or(&[]));
    u32::from_be_bytes(buf)
}

fn u64_from_bytes(input: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    let end = (offset + 8).min(input.len());
    let len = end.saturating_sub(offset);
    buf[..len].copy_from_slice(input.get(offset..end).unwrap_or(&[]));
    u64::from_be_bytes(buf)
}

/// Derive 4 path MTU values from input bytes, spanning the full MTU range.
fn derive_path_mtus(input: &[u8]) -> [usize; 4] {
    let b0 = input.first().copied().unwrap_or(0) as usize;
    let b1 = input.get(1).copied().unwrap_or(0) as usize;
    let b2 = input.get(2).copied().unwrap_or(0) as usize;
    let b3 = input.get(3).copied().unwrap_or(0) as usize;

    [
        b0 % PHANTOM_ONE_HEADER_BYTES,         // 0..23 (invalid, below min)
        PHANTOM_ONE_HEADER_BYTES + (b1 % 128), // 24..151 (valid, small)
        PHANTOM_ONE_HEADER_BYTES + 128 + (b2 % 1024), // 152..1303 (valid, medium)
        (PHANTOM_ONE_MAX_ENVELOPE_BYTES.saturating_sub(2048) + (b3 * 257) % 2048)
            .min(PHANTOM_ONE_MAX_ENVELOPE_BYTES + 1), // near max + overflow
    ]
}
