#![no_main]

use libfuzzer_sys::fuzz_target;
use shph_config::Config;

fuzz_target!(|input: &[u8]| {
    if input.len() > 64 * 1024 {
        return;
    }
    let text = String::from_utf8_lossy(input);
    let _ = Config::parse(&text);
});
