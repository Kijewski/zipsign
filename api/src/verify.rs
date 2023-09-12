//! Common functions to verify a signed file

use std::io::{copy, Read, Seek, SeekFrom};

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Digest, Signature, SIGNATURE_LENGTH};
#[doc(no_inline)]
pub use ed25519_dalek::{Sha512, SignatureError, VerifyingKey, PUBLIC_KEY_LENGTH};

use crate::{SignatureCountLeInt, GZIP_END, GZIP_START, HEADER_SIZE, MAGIC_HEADER};

const BUF_LIMIT: usize = 1 << 17; // 128 kiB

/// The result of a verification function
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error that can occur while verifying files
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No matching (signature, verifying_key) pair was found
    #[error("no matching (signature, verifying_key) pair was found")]
    NoMatch,
    /// Illegal, unknown or missing header
    #[error("illegal, unknown or missing header")]
    MagicHeader,
    /// An I/O error occured reading the signed file
    #[error("an I/O error occured reading the signed file")]
    Read(#[source] std::io::Error),
    /// An I/O error occured seeking inside the signed file
    #[error("an I/O error occured seeking inside the signed file")]
    Seek(#[source] std::io::Error),
    /// A supplied key verifying key was invalid
    #[error("a supplied key verifying key was invalid (#{0})")]
    IllegalKey(#[source] SignatureError, usize),
    /// The input contained an illegal signature
    #[error("the input contained an illegal signature (#{0})")]
    IllegalSignature(#[source] SignatureError, usize),
}

/// Find the index of the first [`VerifyingKey`] that matches the a signature in a signed .tar.gz
/// file
pub fn verify_tar<R: ?Sized + Read + Seek>(
    signed_file: &mut R,
    keys: &[[u8; PUBLIC_KEY_LENGTH]],
    context: Option<&[u8]>,
) -> Result<usize> {
    let keys = collect_keys(keys)?;
    let (prehashed_message, signatures) = read_tar(signed_file)?;
    find_match(&keys, &signatures, &prehashed_message, context)
}

/// Find the index of the first [`VerifyingKey`] that matches the a signature in a signed .zip file
pub fn verify_zip<R: ?Sized + Read + Seek>(
    signed_file: &mut R,
    keys: &[[u8; PUBLIC_KEY_LENGTH]],
    context: Option<&[u8]>,
) -> Result<usize> {
    let keys = collect_keys(keys)?;
    let (prehashed_message, signatures) = read_zip(signed_file)?;
    find_match(&keys, &signatures, &prehashed_message, context)
}

/// Convert a slice of key bytes into a [`Vec`] of [`VerifyingKey`]s.
pub fn collect_keys(keys: &[[u8; 32]]) -> Result<Vec<VerifyingKey>, Error> {
    keys.iter()
        .enumerate()
        .map(|(idx, key)| VerifyingKey::from_bytes(key).map_err(|err| Error::IllegalKey(err, idx)))
        .collect::<Result<Vec<_>, _>>()
}

/// Iterate [`signatures`][Signature] and find the index of the first matching [`VerifyingKey`]
pub fn find_match(
    keys: &[VerifyingKey],
    signatures: &[Signature],
    prehashed_message: &Sha512,
    context: Option<&[u8]>,
) -> Result<usize> {
    for (idx, key) in keys.iter().enumerate() {
        for signature in signatures {
            let is_ok = key
                .verify_prehashed_strict(prehashed_message.clone(), context, signature)
                .is_ok();
            if is_ok {
                return Ok(idx);
            }
        }
    }
    Err(Error::NoMatch)
}

/// Hash the content of a signed .tar.gz file, and collect all contained signatures
pub fn read_tar<R: ?Sized + Read + Seek>(signed_file: &mut R) -> Result<(Sha512, Vec<Signature>)> {
    // seek to start of base64 encoded signatures
    let mut tail = [0; u64::BITS as usize / 4 + GZIP_END.len()];
    let data_end = signed_file
        .seek(SeekFrom::End(-(tail.len() as i64)))
        .map_err(Error::Seek)?;
    signed_file.read_exact(&mut tail).map_err(Error::Read)?;
    if tail[u64::BITS as usize / 4..] != *GZIP_END {
        return Err(Error::MagicHeader);
    }

    let Ok(gzip_start) = std::str::from_utf8(&tail[..16]) else {
        return Err(Error::MagicHeader);
    };
    let Ok(gzip_start) = u64::from_str_radix(gzip_start, 16) else {
        return Err(Error::MagicHeader);
    };
    let Some(data_start) = gzip_start.checked_add(10) else {
        return Err(Error::MagicHeader);
    };
    let Some(data_len) = data_end.checked_sub(data_start) else {
        return Err(Error::MagicHeader);
    };
    let Ok(data_len) = usize::try_from(data_len) else {
        return Err(Error::MagicHeader);
    };
    if data_len > BUF_LIMIT {
        return Err(Error::MagicHeader);
    }

    let _: u64 = signed_file
        .seek(SeekFrom::Start(gzip_start))
        .map_err(Error::Seek)?;

    // read base64 encoded signatures
    let mut data = vec![0; data_len + 10];
    signed_file.read_exact(&mut data).map_err(Error::Read)?;

    if data[..GZIP_START.len()] != *GZIP_START {
        return Err(Error::MagicHeader);
    }

    let Ok(data) = BASE64_STANDARD.decode(&data[GZIP_START.len()..]) else {
        return Err(Error::MagicHeader);
    };
    if data.len() < HEADER_SIZE {
        return Err(Error::MagicHeader);
    }
    if data[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(Error::MagicHeader);
    }
    let signatures = data[HEADER_SIZE..]
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| Error::IllegalSignature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // pre-hash file
    signed_file.rewind().map_err(Error::Seek)?;
    let prehashed_message = prehash(&mut signed_file.take(gzip_start))?;

    Ok((prehashed_message, signatures))
}

/// Hash the content of a signed .zip file, and collect all contained signatures
pub fn read_zip<R: ?Sized + Read + Seek>(signed_file: &mut R) -> Result<(Sha512, Vec<Signature>)> {
    let signatures = read_signatures(signed_file)?;
    let prehashed_message = prehash(signed_file)?;
    Ok((prehashed_message, signatures))
}

/// Collect all signatures in a file
pub fn read_signatures<R: ?Sized + Read + Seek>(signed_file: &mut R) -> Result<Vec<Signature>> {
    let mut header = [0; HEADER_SIZE];
    signed_file.read_exact(&mut header).map_err(Error::Read)?;
    if header[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(Error::MagicHeader);
    }

    let signature_count = header[MAGIC_HEADER.len()..].try_into().unwrap();
    let signature_count = SignatureCountLeInt::from_le_bytes(signature_count) as usize;
    let signature_bytes = signature_count * SIGNATURE_LENGTH;
    if signature_bytes > BUF_LIMIT {
        return Err(Error::MagicHeader);
    }

    let mut signatures = vec![0; signature_bytes];
    signed_file
        .read_exact(&mut signatures)
        .map_err(Error::Read)?;

    let signatures = signatures
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| Error::IllegalSignature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(signatures)
}

/// Calculate the hash of an input file
pub fn prehash<R: ?Sized + Read>(file: &mut R) -> Result<Sha512> {
    let mut prehashed_message = Sha512::new();
    let _: u64 = copy(file, &mut prehashed_message).map_err(Error::Read)?;
    Ok(prehashed_message)
}
