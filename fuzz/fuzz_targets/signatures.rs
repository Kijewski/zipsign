#![no_main]

use libfuzzer_sys::fuzz_target;
use zipsign_api::verify::read_signatures;

fuzz_target!(|data: &[u8]| {
    let _ = read_signatures(&mut &data[..]);
});
