#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_core::RatchetAuditRecord;

fuzz_target!(|input: &[u8]| {
    if input.len() > 16 * 1024 {
        return;
    }
    let _ = serde_json::from_slice::<RatchetAuditRecord>(input);
});
