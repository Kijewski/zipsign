#![cfg_attr(docsrs, doc(cfg(feature = "verify")))]

//! Common functions to verify a signed file

#[cfg(feature = "verify-tar")]
mod tar;
#[cfg(feature = "verify-zip")]
mod zip;

use std::io::Read;

#[cfg(feature = "verify-tar")]
pub use self::tar::{verify_tar, VerifyTarError};
#[cfg(feature = "verify-zip")]
pub use self::zip::{verify_zip, VerifyZipError};
use crate::{
    Sha512, Signature, SignatureCountLeInt, SignatureError, VerifyingKey, BUF_LIMIT, HEADER_SIZE,
    MAGIC_HEADER, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

/// An error returned by [`collect_keys()`]
#[derive(Debug, thiserror::Error)]
pub enum CollectKeysError {
    /// The input was empty
    #[error("the input was empty")]
    Empty,
    /// Could not read a key
    #[error("could not read key #{1}")]
    Io(#[source] std::io::Error, usize),
    /// Input contained an illegal key
    #[error("input contained an illegal key at #{1}")]
    Signature(#[source] SignatureError, usize),
}

/// Convert a slice of key bytes into a [`Vec`] of [`VerifyingKey`]s.
pub fn collect_keys<K>(keys: K) -> Result<Vec<VerifyingKey>, CollectKeysError>
where
    K: IntoIterator<Item = std::io::Result<[u8; PUBLIC_KEY_LENGTH]>>,
{
    let keys = keys
        .into_iter()
        .enumerate()
        .map(|(idx, key)| {
            let key = key.map_err(|err| CollectKeysError::Io(err, idx))?;
            VerifyingKey::from_bytes(&key).map_err(|err| CollectKeysError::Signature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err(CollectKeysError::Empty);
    }
    Ok(keys)
}

/// No matching key/signature pair found
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("no matching key/signature pair found")]
pub struct NoMatch;

/// Iterate [signatures][Signature] and [keys][VerifyingKey] and return the indices of the first
/// match
pub fn find_match(
    keys: &[VerifyingKey],
    signatures: &[Signature],
    prehashed_message: &Sha512,
    context: Option<&[u8]>,
) -> Result<(usize, usize), NoMatch> {
    for (key_idx, key) in keys.iter().enumerate() {
        for (sig_idx, signature) in signatures.iter().enumerate() {
            let is_ok = key
                .verify_prehashed_strict(prehashed_message.clone(), context, signature)
                .is_ok();
            if is_ok {
                return Ok((key_idx, sig_idx));
            }
        }
    }
    Err(NoMatch)
}

/// An error returned by [`read_signatures()`]
#[derive(Debug, thiserror::Error)]
pub enum ReadSignaturesError {
    /// The input contained no signatures
    #[error("the input contained no signatures")]
    Empty,
    /// Could not read signatures
    #[error("could not read signatures")]
    Read(#[source] std::io::Error),
    /// The expected magic header was missing or corrupted
    #[error("the expected magic header was missing or corrupted")]
    MagicHeader,
    /// Input contained an illegal signature
    #[error("input contained an illegal signature at #{1}")]
    Signature(#[source] SignatureError, usize),
}

/// Collect all signatures in a file
pub fn read_signatures<I>(input: &mut I) -> Result<Vec<Signature>, ReadSignaturesError>
where
    I: ?Sized + Read,
{
    let mut header = [0; HEADER_SIZE];
    input
        .read_exact(&mut header)
        .map_err(ReadSignaturesError::Read)?;
    if header[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(ReadSignaturesError::MagicHeader);
    }

    let signature_count = header[MAGIC_HEADER.len()..].try_into().unwrap();
    let signature_count = SignatureCountLeInt::from_le_bytes(signature_count) as usize;
    if signature_count == 0 {
        return Err(ReadSignaturesError::Empty);
    }
    let signature_bytes = signature_count * SIGNATURE_LENGTH;
    if signature_bytes > BUF_LIMIT {
        return Err(ReadSignaturesError::MagicHeader);
    }

    let mut signatures = vec![0; signature_bytes];
    input
        .read_exact(&mut signatures)
        .map_err(ReadSignaturesError::Read)?;

    let signatures = signatures
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| ReadSignaturesError::Signature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(signatures)
}
