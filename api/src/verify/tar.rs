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

crate::Error! {
    /// An error returned by [`verify_tar()`]
    pub struct VerifyTarError(Error) {
        #[error("the input contained invalid base64 encoded data")]
        Base64,
        #[error("the input contained no signatures")]
        Empty,
        #[error("the expected last GZIP block was missing or corrupted")]
        Gzip,
        #[error("the encoded length did not fit the expected length")]
        LengthMismatch,
        #[error("the expected magic header was missing or corrupted")]
        MagicHeader,
        #[error(transparent)]
        NoMatch(NoMatch),
        #[error("could not read input")]
        Read(#[source] std::io::Error),
        #[error("could not seek inside the input")]
        Seek(#[source] std::io::Error),
        #[error("the input contained an illegal signature at index #{1}")]
        Signature(#[source] SignatureError, usize),
        #[error("too many signatures in input")]
        TooManySignatures,
    }
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
    let (key_idx, _) =
        find_match(keys, &signatures, &prehashed_message, context).map_err(Error::NoMatch)?;
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
    input.rewind().map_err(Error::Seek)?;
    let prehashed_message = prehash(&mut input.take(data_start)).map_err(Error::Read)?;

    Ok((prehashed_message, signatures))
}

fn find_data_start_and_len<I>(input: &mut I) -> Result<(u64, usize), VerifyTarError>
where
    I: ?Sized + Read + Seek,
{
    let mut tail = [0; u64::BITS as usize / 4 + GZIP_END.len()];
    let data_end = input
        .seek(SeekFrom::End(-(tail.len() as i64)))
        .map_err(Error::Seek)?;

    input.read_exact(&mut tail).map_err(Error::Read)?;
    if tail[u64::BITS as usize / 4..] != *GZIP_END {
        return Err(Error::Gzip.into());
    }
    let Ok(gzip_start) = std::str::from_utf8(&tail[..16]) else {
        return Err(Error::Gzip.into());
    };
    let Ok(gzip_start) = u64::from_str_radix(gzip_start, 16) else {
        return Err(Error::Gzip.into());
    };
    let Some(data_start) = gzip_start.checked_add(10) else {
        return Err(Error::Gzip.into());
    };
    let Some(data_len) = data_end.checked_sub(data_start) else {
        return Err(Error::Gzip.into());
    };
    let Ok(data_len) = usize::try_from(data_len) else {
        return Err(Error::Gzip.into());
    };
    if data_len > BUF_LIMIT {
        return Err(Error::TooManySignatures.into());
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
        .map_err(Error::Read)?;

    let mut data = vec![0; data_len];
    input.read_exact(&mut data).map_err(Error::Read)?;

    if data[..GZIP_START.len()] != *GZIP_START {
        return Err(Error::Gzip.into());
    }
    let Ok(data) = BASE64_STANDARD.decode(&data[GZIP_START.len()..]) else {
        return Err(Error::Base64.into());
    };
    if data.len() < HEADER_SIZE {
        return Err(Error::MagicHeader.into());
    }
    if data[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(Error::MagicHeader.into());
    }

    let signature_count = data[MAGIC_HEADER.len()..][..size_of::<SignatureCountLeInt>()]
        .try_into()
        .unwrap();
    let signature_count = SignatureCountLeInt::from_le_bytes(signature_count) as usize;
    if signature_count == 0 {
        return Err(Error::Empty.into());
    }
    if data.len() != HEADER_SIZE + signature_count * SIGNATURE_LENGTH {
        return Err(Error::LengthMismatch.into());
    }

    let signatures = data[HEADER_SIZE..]
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| Signature::from_slice(bytes).map_err(|err| Error::Signature(err, idx)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(signatures)
}
