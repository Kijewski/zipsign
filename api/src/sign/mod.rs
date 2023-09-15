#![cfg_attr(docsrs, doc(cfg(feature = "sign")))]

//! Common functions to sign a file

#[cfg(feature = "sign-tar")]
mod tar;
#[cfg(feature = "sign-zip")]
mod zip;

use std::io::Read;

#[cfg(feature = "sign-tar")]
pub use self::tar::{copy_and_sign_tar, SignTarError};
#[cfg(feature = "sign-zip")]
pub use self::zip::{copy_and_sign_zip, SignZipError};
use crate::{
    Sha512, SignatureCountLeInt, SignatureError, SigningKey, BUF_LIMIT, HEADER_SIZE,
    KEYPAIR_LENGTH, MAGIC_HEADER, SIGNATURE_LENGTH,
};

/// An error returned by [`read_signing_keys()`]
#[derive(Debug, thiserror::Error)]
pub enum ReadSigningKeysError {
    /// Input did not contain a valid key
    #[error("input #{1} did not contain a valid key")]
    Construct(#[source] ed25519_dalek::ed25519::Error, usize),
    /// No signing keys provided
    #[error("no signing keys provided")]
    Empty,
    /// Could not read keys
    #[error("could not read key in file #{1}")]
    Read(#[source] std::io::Error, usize),
}

/// Read signing keys from an [`Iterator`] of [readable][Read] inputs
pub fn read_signing_keys<I, R>(inputs: I) -> Result<Vec<SigningKey>, ReadSigningKeysError>
where
    I: IntoIterator<Item = std::io::Result<R>>,
    R: Read,
{
    // read signing keys
    let mut keys = inputs
        .into_iter()
        .enumerate()
        .map(|(key_index, input)| {
            let mut key = [0; KEYPAIR_LENGTH];
            input
                .and_then(|mut input| input.read_exact(&mut key))
                .map_err(|err| ReadSigningKeysError::Read(err, key_index))?;
            SigningKey::from_keypair_bytes(&key)
                .map_err(|err| ReadSigningKeysError::Construct(err, key_index))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err(ReadSigningKeysError::Empty);
    }
    keys.sort_by(|l, r| {
        l.verifying_key()
            .as_bytes()
            .cmp(r.verifying_key().as_bytes())
    });
    Ok(keys)
}

/// An error returned by [`gather_signature_data()`]
#[derive(Debug, thiserror::Error)]
pub enum GatherSignatureDataError {
    /// No signing keys provided
    #[error("no signing keys provided")]
    Empty,
    /// could not sign data
    #[error("could not sign data with key #{1}")]
    Signature(#[source] SignatureError, usize),
    /// Too many signing keys provided
    #[error("too many signing keys provided")]
    TooManyKeys,
}

/// Sign a pre-hashed message with all provided signing keys, and return a signature block incl.
/// a header
pub fn gather_signature_data(
    keys: &[SigningKey],
    prehashed_message: &Sha512,
    context: Option<&[u8]>,
) -> Result<Vec<u8>, GatherSignatureDataError> {
    if keys.is_empty() {
        return Err(GatherSignatureDataError::Empty);
    }

    let signature_bytes = HEADER_SIZE + keys.len() * SIGNATURE_LENGTH;
    if signature_bytes > BUF_LIMIT {
        return Err(GatherSignatureDataError::TooManyKeys);
    }

    let mut header = [0; HEADER_SIZE];
    header[..MAGIC_HEADER.len()].copy_from_slice(MAGIC_HEADER);
    header[MAGIC_HEADER.len()..]
        .copy_from_slice(&(keys.len() as SignatureCountLeInt).to_le_bytes());

    let mut buf = Vec::with_capacity(signature_bytes);
    buf.extend(header);
    for (idx, key) in keys.iter().enumerate() {
        let signature = key
            .sign_prehashed(prehashed_message.clone(), context)
            .map_err(|err| GatherSignatureDataError::Signature(err, idx))?;
        buf.extend(signature.to_bytes());
    }
    Ok(buf)
}
