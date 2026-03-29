//! Functions to verify a signed file

#[cfg(feature = "verify-tar")]
mod tar;
#[cfg(feature = "verify-zip")]
mod zip;

use std::io::Read;

#[cfg(feature = "verify-tar")]
pub use self::tar::{VerifyTarError, verify_tar};
#[cfg(feature = "verify-zip")]
pub use self::zip::{VerifyZipError, verify_zip};
use crate::constants::{BUF_LIMIT, HEADER_SIZE, MAGIC_HEADER, SignatureCountLeInt};
use crate::{
    PUBLIC_KEY_LENGTH, Prehash, SIGNATURE_LENGTH, Signature, SignatureError, VerifyingKey,
};

crate::Error! {
    /// An error returned by [`read_verifying_keys()`]
    pub struct ReadVerifyingKeysError(VerifyKeysError) {
        #[error("no verifying keys provided")]
        Empty,
        #[error("input #{1} did not contain a valid key")]
        Parse(#[source] crate::keys::ParseKeyError, usize),
        #[error("could not read key in file #{1}")]
        Read(#[source] std::io::Error, usize),
    }
}

/// Read verifying keys from an [`Iterator`] of [readable][Read] inputs.
/// Each input may contain either a raw 32-byte key or a PEM-encoded key.
pub fn read_verifying_keys<I, R>(inputs: I) -> Result<Vec<VerifyingKey>, ReadVerifyingKeysError>
where
    I: IntoIterator<Item = std::io::Result<R>>,
    R: Read,
{
    let keys = inputs
        .into_iter()
        .enumerate()
        .map(|(key_index, input)| {
            let mut buf = Vec::new();
            let _: usize = input
                .and_then(|mut input| input.read_to_end(&mut buf))
                .map_err(|err| VerifyKeysError::Read(err, key_index))?;
            crate::keys::parse_verifying_key(&buf)
                .map_err(|err| VerifyKeysError::Parse(err, key_index))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err(VerifyKeysError::Empty.into());
    }
    Ok(keys)
}

crate::Error! {
    /// An error returned by [`collect_keys()`]
    pub struct CollectKeysError(KeysError) {
        #[error("the input was empty")]
        Empty,
        #[error("could not read key #{1}")]
        Io(#[source] std::io::Error, usize),
        #[error("input contained an illegal key at #{1}")]
        Signature(#[source] SignatureError, usize),
    }
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
            let key = key.map_err(|err| KeysError::Io(err, idx))?;
            VerifyingKey::from_bytes(&key).map_err(|err| KeysError::Signature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err(KeysError::Empty.into());
    }
    Ok(keys)
}

/// No matching key/signature pair found
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("no matching key/signature pair found")]
pub struct NoMatch;

/// Iterate signatures and keys, and return the indices of the first match
/// match
pub fn find_match(
    keys: &[VerifyingKey],
    signatures: &[Signature],
    prehashed_message: &Prehash,
    context: Option<&[u8]>,
) -> Result<(usize, usize), NoMatch> {
    for (key_idx, key) in keys.iter().enumerate() {
        for (sig_idx, signature) in signatures.iter().enumerate() {
            let is_ok = key
                .verify_prehashed_strict(prehashed_message.0.clone(), context, signature)
                .is_ok();
            if is_ok {
                return Ok((key_idx, sig_idx));
            }
        }
    }
    Err(NoMatch)
}

crate::Error! {
    /// An error returned by [`read_signatures()`]
    pub struct ReadSignaturesError(SignaturesError) {
        #[error("the input contained no signatures")]
        Empty,
        #[error("could not read signatures")]
        Read(#[source] std::io::Error),
        #[error("the expected magic header was missing or corrupted")]
        MagicHeader,
        #[error("input contained an illegal signature at #{1}")]
        Signature(#[source] SignatureError, usize),
    }
}

/// Collect all signatures in a file
pub fn read_signatures<I>(input: &mut I) -> Result<Vec<Signature>, ReadSignaturesError>
where
    I: ?Sized + Read,
{
    let mut header = [0; HEADER_SIZE];
    input
        .read_exact(&mut header)
        .map_err(SignaturesError::Read)?;
    if header[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(SignaturesError::MagicHeader.into());
    }

    let signature_count = header[MAGIC_HEADER.len()..].try_into().unwrap();
    let signature_count = SignatureCountLeInt::from_le_bytes(signature_count) as usize;
    if signature_count == 0 {
        return Err(SignaturesError::Empty.into());
    }
    let signature_bytes = signature_count
        .checked_mul(SIGNATURE_LENGTH)
        .ok_or(SignaturesError::MagicHeader)?;
    if signature_bytes > BUF_LIMIT {
        return Err(SignaturesError::MagicHeader.into());
    }

    let mut signatures = vec![0; signature_bytes];
    input
        .read_exact(&mut signatures)
        .map_err(SignaturesError::Read)?;

    let signatures = signatures
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| SignaturesError::Signature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(signatures)
}
