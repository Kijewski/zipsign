#![no_main]

mod common;

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zipsign_api::unsign::copy_and_unsign_zip;
use zipsign_api::verify::verify_zip;

fuzz_target!(|data: &[u8]| {
    let _ = verify_zip(
        &mut Cursor::new(data),
        &common::verifying_keys(),
        Some(common::CONTEXT),
    );
    let _ = copy_and_unsign_zip(&mut Cursor::new(data), &mut Cursor::new(Vec::new()));
});
