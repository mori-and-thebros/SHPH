#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_core::ReplayWindow;

fuzz_target!(|input: &[u8]| {
    let mut window = ReplayWindow::new(128);
    let (chunks, _) = input.as_chunks::<8>();
    for chunk in chunks.iter().take(2048) {
        let _ = window.check_and_insert(u64::from_be_bytes(*chunk));
    }
});
