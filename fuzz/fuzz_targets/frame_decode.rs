#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_core::{decode_cell, ShroudProfile, BALANCED, BULK, LOW_LATENCY};

fn profile_for(selector: u8) -> ShroudProfile {
    match selector % 3 {
        0 => BALANCED,
        1 => LOW_LATENCY,
        _ => BULK,
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
