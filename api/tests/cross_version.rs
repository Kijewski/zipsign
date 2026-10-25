//! Signatures must stay compatible across zipsign versions.
//!
//! The files in `fixtures/cross-version/` were generated with the zipsign 0.2.2 CLI
//! (ed25519-dalek 2.x), using the throwaway key pair `test-only.{priv,pub}`:
//!
//! ```sh
//! C=zipsign-cross-version
//! zipsign gen-key test-only.priv test-only.pub
//! zipsign sign zip      unsigned.zip    test-only.priv -c $C -o signed-v0.2.2.zip    -f
//! zipsign sign tar      unsigned.tar.gz test-only.priv -c $C -o signed-v0.2.2.tar.gz -f
//! zipsign sign separate message.txt     test-only.priv -c $C -o message-v0.2.2.sig  -f
//! ```
//!
//! `unsigned.zip` was created by Info-ZIP 3.0 and carries the 0x7875 (Unix UID/GID) extra
//! field, which zip < 9.1 refused to copy without the `unreserved` feature.
//!
//! Ed25519 signing is deterministic, so producing byte-identical signatures also proves that
//! files signed by this version verify with 0.2.2.

#![cfg(all(feature = "zip", feature = "tar"))]

use std::io::Cursor;

use zipsign_api::sign::{
    copy_and_sign_tar, copy_and_sign_zip, gather_signature_data, read_signing_keys,
};
use zipsign_api::unsign::copy_and_unsign_zip;
use zipsign_api::verify::{collect_keys, verify_tar, verify_zip};
use zipsign_api::{PUBLIC_KEY_LENGTH, Prehash, SigningKey, VerifyingKey};

type Result<T = (), E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

const CONTEXT: &[u8] = b"zipsign-cross-version";

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cross-version/",
            $name
        ))
    };
}

fn signing_keys() -> Result<Vec<SigningKey>> {
    Ok(read_signing_keys([Ok(&fixture!("test-only.priv")[..])])?)
}

fn verifying_keys() -> Result<Vec<VerifyingKey>> {
    let key: [u8; PUBLIC_KEY_LENGTH] = *fixture!("test-only.pub");
    Ok(collect_keys([Ok(key)])?)
}

#[test]
fn verifies_zip_signed_by_v0_2_2() -> Result {
    let mut signed = Cursor::new(fixture!("signed-v0.2.2.zip"));
    assert_eq!(
        verify_zip(&mut signed, &verifying_keys()?, Some(CONTEXT))?,
        0
    );
    Ok(())
}

#[test]
fn verifies_tar_signed_by_v0_2_2() -> Result {
    let mut signed = Cursor::new(fixture!("signed-v0.2.2.tar.gz"));
    assert_eq!(
        verify_tar(&mut signed, &verifying_keys()?, Some(CONTEXT))?,
        0
    );
    Ok(())
}

#[test]
fn detached_signature_matches_v0_2_2() -> Result {
    let prehash = Prehash::calculate(&mut &fixture!("message.txt")[..])?;
    let signature = gather_signature_data(&signing_keys()?, &prehash, Some(CONTEXT))?;
    assert_eq!(signature, fixture!("message-v0.2.2.sig"));
    Ok(())
}

#[test]
fn signed_tar_matches_v0_2_2() -> Result {
    let mut output = Cursor::new(Vec::new());
    copy_and_sign_tar(
        &mut Cursor::new(fixture!("unsigned.tar.gz")),
        &mut output,
        &signing_keys()?,
        Some(CONTEXT),
    )?;
    assert_eq!(output.into_inner(), fixture!("signed-v0.2.2.tar.gz"));
    Ok(())
}

// The signed `.zip` bytes also depend on the `zip` crate's writer, so this test checks
// a sign/verify/unsign round trip instead of comparing bytes against the fixture.
#[test]
fn zip_with_info_zip_extra_field_round_trips() -> Result {
    let mut signed = Cursor::new(Vec::new());
    copy_and_sign_zip(
        &mut Cursor::new(fixture!("unsigned.zip")),
        &mut signed,
        &signing_keys()?,
        Some(CONTEXT),
    )?;
    signed.set_position(0);
    assert_eq!(
        verify_zip(&mut signed, &verifying_keys()?, Some(CONTEXT))?,
        0
    );

    let mut unsigned = Cursor::new(Vec::new());
    signed.set_position(0);
    copy_and_unsign_zip(&mut signed, &mut unsigned)?;
    unsigned.set_position(0);
    assert!(
        verify_zip(&mut unsigned, &verifying_keys()?, Some(CONTEXT)).is_err(),
        "unsigned output must not verify",
    );
    Ok(())
}
