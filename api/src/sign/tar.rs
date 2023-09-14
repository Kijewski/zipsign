#![cfg_attr(docsrs, doc(cfg(feature = "sign-tar")))]

use std::io::{copy, Read, Seek, Write};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::SIGNATURE_LENGTH;

use super::{gather_signature_data, prehashed_message, GatherSignatureDataError};
use crate::{
    SignatureCountLeInt, SigningKey, BUF_LIMIT, GZIP_END, GZIP_EXTRA, GZIP_START, HEADER_SIZE,
};

/// An error returned by [`copy_and_sign_tar()`]
#[derive(Debug, thiserror::Error)]
pub enum SignTarError {
    /// Could not copy input to output
    #[error("could not copy input to output")]
    Copy(#[source] std::io::Error),
    /// Could not read input
    #[error("could not read input")]
    InputRead(#[source] std::io::Error),
    /// Could not seek in input
    #[error("could not seek in input")]
    InputSeek(#[source] std::io::Error),
    /// Could not seek in output
    #[error("could not seek in output")]
    OutputSeek(#[source] std::io::Error),
    /// Could not write output
    #[error("could not write output")]
    OutputWrite(#[source] std::io::Error),
    /// Could not sign pre-hashed message
    #[error("could not sign pre-hashed message")]
    Sign(#[source] GatherSignatureDataError),
    /// Too many keys
    #[error("too many keys")]
    TooManyKeys,
}

/// Copy a `.tar.gz` file and sign its content
pub fn copy_and_sign_tar<I, O>(
    input: &mut I,
    output: &mut O,
    keys: &[SigningKey],
    context: Option<&[u8]>,
) -> Result<(), SignTarError>
where
    I: ?Sized + Read + Seek,
    O: ?Sized + Read + Seek + Write,
{
    if keys.len() > SignatureCountLeInt::MAX as usize {
        return Err(SignTarError::TooManyKeys);
    }
    let signature_bytes = SIGNATURE_LENGTH * keys.len() + HEADER_SIZE;
    if (signature_bytes.saturating_add(2) / 3).saturating_mul(4) > BUF_LIMIT {
        return Err(SignTarError::TooManyKeys);
    }

    // gather signature
    let prehashed_message = prehashed_message(input).map_err(SignTarError::InputRead)?;
    let buf =
        gather_signature_data(keys, &prehashed_message, context).map_err(SignTarError::Sign)?;
    let buf = BASE64_STANDARD.encode(buf);
    if buf.len() > BUF_LIMIT {
        return Err(SignTarError::TooManyKeys);
    }

    // copy input
    input.rewind().map_err(SignTarError::InputSeek)?;
    let _: u64 = copy(input, output).map_err(SignTarError::Copy)?;

    // write signature
    let start = output.stream_position().map_err(SignTarError::OutputSeek)?;
    let mut start_buf = [0u8; 16];
    write!(&mut start_buf[..], "{start:016x}").unwrap();

    let mut tail = Vec::with_capacity(GZIP_EXTRA + buf.len());
    tail.extend(GZIP_START);
    tail.extend(buf.into_bytes()); // GZIP comment
    tail.extend(start_buf); // GZIP comment
    tail.extend(GZIP_END);
    output.write_all(&tail).map_err(SignTarError::OutputWrite)?;

    Ok(())
}
