#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_core::{
    decode_cell, ShroudProfile, BALANCED, BULK, EXTREME_LAB, LOW_LATENCY, RANDOMIZED_LAB,
    TUNED_HIGH, TUNED_LOW, TUNED_MEDIUM,
};

fn profile_for(selector: u8) -> ShroudProfile {
    match selector % 8 {
        0 => BALANCED,
        1 => LOW_LATENCY,
        2 => BULK,
        3 => RANDOMIZED_LAB,
        4 => EXTREME_LAB,
        5 => TUNED_LOW,
        6 => TUNED_MEDIUM,
        7 => TUNED_HIGH,
        _ => unreachable!(),
    }
}

fuzz_target!(|input: &[u8]| {
    if input.is_empty() {
        return;
    }
    let profile = profile_for(input[0]);
    let mut cell = input[1..]
        .iter()
        .copied()
        .take(profile.cell_size)
        .collect::<Vec<_>>();
    cell.resize(profile.cell_size, 0);
    let _ = decode_cell(profile, &cell);
});
