#![cfg_attr(docsrs, doc(cfg(feature = "verify-zip")))]

use std::io::{Read, Seek};

use super::{find_match, read_signatures, NoMatch, ReadSignaturesError, VerifyingKey};
use crate::{prehash, Sha512, Signature};

crate::Error! {
    /// An error retuned by [`verify_zip()`]
    pub struct VerifyZipError(Error) {
        #[error("could not read input")]
        InputRead(#[source] std::io::Error),
        #[error(transparent)]
        NoMatch(NoMatch),
        #[error("could not read signatures from input")]
        ReadSignaturesError(#[source] ReadSignaturesError),
    }
}

/// Find the index of the first [`VerifyingKey`] that matches the a signature in a signed `.zip`
/// file
pub fn verify_zip<R>(
    signed_file: &mut R,
    keys: &[VerifyingKey],
    context: Option<&[u8]>,
) -> Result<usize, VerifyZipError>
where
    R: ?Sized + Read + Seek,
{
    let (prehashed_message, signatures) = read_zip(signed_file)?;
    let (key_idx, _) =
        find_match(keys, &signatures, &prehashed_message, context).map_err(Error::NoMatch)?;
    Ok(key_idx)
}

fn read_zip<R>(signed_file: &mut R) -> Result<(Sha512, Vec<Signature>), VerifyZipError>
where
    R: ?Sized + Read + Seek,
{
    let signatures = read_signatures(signed_file).map_err(Error::ReadSignaturesError)?;
    let prehashed_message = prehash(signed_file).map_err(Error::InputRead)?;
    Ok((prehashed_message, signatures))
}
