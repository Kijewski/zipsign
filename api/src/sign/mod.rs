//! Functions to sign a file

#[cfg(feature = "sign-tar")]
mod tar;
#[cfg(feature = "sign-zip")]
mod zip;

use std::io::Read;

#[cfg(feature = "sign-tar")]
pub use self::tar::{SignTarError, copy_and_sign_tar};
#[cfg(feature = "sign-zip")]
pub use self::zip::{SignZipError, copy_and_sign_zip};
use crate::constants::{BUF_LIMIT, HEADER_SIZE, MAGIC_HEADER, SignatureCountLeInt};
use crate::{Prehash, SIGNATURE_LENGTH, SignatureError, SigningKey};

crate::Error! {
    /// An error returned by [`read_signing_keys()`]
    pub struct ReadSigningKeysError(KeysError) {
        #[error("no signing keys provided")]
        Empty,
        #[error("input #{1} did not contain a valid key")]
        Parse(#[source] crate::keys::ParseKeyError, usize),
        #[error("could not read key in file #{1}")]
        Read(#[source] std::io::Error, usize),
    }
}

/// Read signing keys from an [`Iterator`] of [readable][Read] inputs.
/// Each input may contain either a raw 64-byte keypair or a PEM-encoded key.
pub fn read_signing_keys<I, R>(inputs: I) -> Result<Vec<SigningKey>, ReadSigningKeysError>
where
    I: IntoIterator<Item = std::io::Result<R>>,
    R: Read,
{
    let mut keys = inputs
        .into_iter()
        .enumerate()
        .map(|(key_index, input)| {
            let mut buf = Vec::new();
            let _: usize = input
                .and_then(|mut input| input.read_to_end(&mut buf))
                .map_err(|err| KeysError::Read(err, key_index))?;
            crate::keys::parse_signing_key(&buf).map_err(|err| KeysError::Parse(err, key_index))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err(KeysError::Empty.into());
    }
    keys.sort_by(|l, r| {
        l.verifying_key()
            .as_bytes()
            .cmp(r.verifying_key().as_bytes())
    });
    Ok(keys)
}

crate::Error! {
    /// An error returned by [`gather_signature_data()`]
    pub struct GatherSignatureDataError(SignaturesError) {
        #[error("no signing keys provided")]
        Empty,
        #[error("could not sign data with key #{1}")]
        Signature(#[source] SignatureError, usize),
        #[error("too many signing keys provided")]
        TooManyKeys,
    }
}

/// Sign a pre-hashed message with all provided signing keys, and return a signature block incl.
/// a header
pub fn gather_signature_data(
    keys: &[SigningKey],
    prehashed_message: &Prehash,
    context: Option<&[u8]>,
) -> Result<Vec<u8>, GatherSignatureDataError> {
    if keys.is_empty() {
        return Err(SignaturesError::Empty.into());
    }

    let signature_bytes = HEADER_SIZE + keys.len() * SIGNATURE_LENGTH;
    if signature_bytes > BUF_LIMIT {
        return Err(SignaturesError::TooManyKeys.into());
    }

    let mut header = [0; HEADER_SIZE];
    header[..MAGIC_HEADER.len()].copy_from_slice(MAGIC_HEADER);
    header[MAGIC_HEADER.len()..]
        .copy_from_slice(&(keys.len() as SignatureCountLeInt).to_le_bytes());

    let mut buf = Vec::with_capacity(signature_bytes);
    buf.extend(header);
    for (idx, key) in keys.iter().enumerate() {
        let signature = key
            .sign_prehashed(prehashed_message.0.clone(), context)
            .map_err(|err| SignaturesError::Signature(err, idx))?;
        buf.extend(signature.to_bytes());
    }
    Ok(buf)
}
