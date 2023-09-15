#![cfg_attr(docsrs, doc(cfg(feature = "verify-tar")))]

use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;

use super::{find_match, NoMatch};
use crate::constants::{
    SignatureCountLeInt, BUF_LIMIT, GZIP_END, GZIP_START, HEADER_SIZE, MAGIC_HEADER,
};
use crate::{prehash, Sha512, Signature, SignatureError, VerifyingKey, SIGNATURE_LENGTH};

/// An error returned by [`verify_tar()`]
#[derive(Debug, thiserror::Error)]
pub enum VerifyTarError {
    /// The input contained invalid base64 encoded data
    #[error("the input contained invalid base64 encoded data")]
    Base64,
    /// The input contained no signatures
    #[error("the input contained no signatures")]
    Empty,
    /// The expected last GZIP block was missing or corrupted
    #[error("the expected last GZIP block was missing or corrupted")]
    Gzip,
    /// The encoded length did not fit the expected length
    #[error("the encoded length did not fit the expected length")]
    LengthMismatch,
    /// The expected magic header was missing or corrupted
    #[error("the expected magic header was missing or corrupted")]
    MagicHeader,
    /// No matching key/signature pair found
    #[error(transparent)]
    NoMatch(NoMatch),
    /// Could not read input
    #[error("could not read input")]
    Read(#[source] std::io::Error),
    /// Could not seek inside the input
    #[error("could not seek inside the input")]
    Seek(#[source] std::io::Error),
    /// The input contained an illegal signature
    #[error("the input contained an illegal signature at index #{1}")]
    Signature(#[source] SignatureError, usize),
    /// Too many signatures in input
    #[error("too many signatures in input")]
    TooManySignatures,
}

/// Find the index of the first [`VerifyingKey`] that matches the a signature in a signed `.tar.gz`
/// file
pub fn verify_tar<I>(
    input: &mut I,
    keys: &[VerifyingKey],
    context: Option<&[u8]>,
) -> Result<usize, VerifyTarError>
where
    I: ?Sized + Read + Seek,
{
    let (prehashed_message, signatures) = read_tar(input)?;
    let (key_idx, _) = find_match(keys, &signatures, &prehashed_message, context)
        .map_err(VerifyTarError::NoMatch)?;
    Ok(key_idx)
}

fn read_tar<I: ?Sized + Read + Seek>(
    input: &mut I,
) -> Result<(Sha512, Vec<Signature>), VerifyTarError> {
    // seek to start of base64 encoded signatures
    let (data_start, data_len) = find_data_start_and_len(input)?;

    // read base64 encoded signatures
    let signatures = read_signatures(data_start, data_len, input)?;

    // pre-hash file
    input.rewind().map_err(VerifyTarError::Seek)?;
    let prehashed_message = prehash(&mut input.take(data_start)).map_err(VerifyTarError::Read)?;

    Ok((prehashed_message, signatures))
}

fn find_data_start_and_len<I>(input: &mut I) -> Result<(u64, usize), VerifyTarError>
where
    I: ?Sized + Read + Seek,
{
    let mut tail = [0; u64::BITS as usize / 4 + GZIP_END.len()];
    let data_end = input
        .seek(SeekFrom::End(-(tail.len() as i64)))
        .map_err(VerifyTarError::Seek)?;

    input.read_exact(&mut tail).map_err(VerifyTarError::Read)?;
    if tail[u64::BITS as usize / 4..] != *GZIP_END {
        return Err(VerifyTarError::Gzip);
    }
    let Ok(gzip_start) = std::str::from_utf8(&tail[..16]) else {
        return Err(VerifyTarError::Gzip);
    };
    let Ok(gzip_start) = u64::from_str_radix(gzip_start, 16) else {
        return Err(VerifyTarError::Gzip);
    };
    let Some(data_start) = gzip_start.checked_add(10) else {
        return Err(VerifyTarError::Gzip);
    };
    let Some(data_len) = data_end.checked_sub(data_start) else {
        return Err(VerifyTarError::Gzip);
    };
    let Ok(data_len) = usize::try_from(data_len) else {
        return Err(VerifyTarError::Gzip);
    };
    if data_len > BUF_LIMIT {
        return Err(VerifyTarError::TooManySignatures);
    }

    Ok((gzip_start, data_len + GZIP_START.len()))
}

fn read_signatures<I>(
    data_start: u64,
    data_len: usize,
    input: &mut I,
) -> Result<Vec<Signature>, VerifyTarError>
where
    I: ?Sized + Read + Seek,
{
    let _: u64 = input
        .seek(SeekFrom::Start(data_start))
        .map_err(VerifyTarError::Read)?;

    let mut data = vec![0; data_len];
    input.read_exact(&mut data).map_err(VerifyTarError::Read)?;

    if data[..GZIP_START.len()] != *GZIP_START {
        return Err(VerifyTarError::Gzip);
    }
    let Ok(data) = BASE64_STANDARD.decode(&data[GZIP_START.len()..]) else {
        return Err(VerifyTarError::Base64);
    };
    if data.len() < HEADER_SIZE {
        return Err(VerifyTarError::MagicHeader);
    }
    if data[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(VerifyTarError::MagicHeader);
    }

    let signature_count = data[MAGIC_HEADER.len()..][..size_of::<SignatureCountLeInt>()]
        .try_into()
        .unwrap();
    let signature_count = SignatureCountLeInt::from_le_bytes(signature_count) as usize;
    if signature_count == 0 {
        return Err(VerifyTarError::Empty);
    }
    if data.len() != HEADER_SIZE + signature_count * SIGNATURE_LENGTH {
        return Err(VerifyTarError::LengthMismatch);
    }

    data[HEADER_SIZE..]
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| VerifyTarError::Signature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()
}
