#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_core::ReplayWindow;

fuzz_target!(|input: &[u8]| {
    let mut window = ReplayWindow::new(128);
    for chunk in input.chunks_exact(8).take(2048) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        let _ = window.check_and_insert(u64::from_be_bytes(bytes));
    }
});
