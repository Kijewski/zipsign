#![cfg_attr(docsrs, doc(cfg(feature = "sign-zip")))]

use std::io::{BufReader, BufWriter, IoSlice, Read, Seek, SeekFrom, Write};

use zip::result::ZipError;
use zip::{ZipArchive, ZipWriter};

use super::{gather_signature_data, GatherSignatureDataError};
use crate::constants::{SignatureCountLeInt, BUF_LIMIT, HEADER_SIZE};
use crate::{prehash, SigningKey, SIGNATURE_LENGTH};

crate::Error! {
    /// An error returned by [`copy_and_sign_zip()`]
    pub struct SignZipError(Error) {
        #[error("could not read input ZIP")]
        InputZip(#[source] ZipError),
        #[error("could not read file #{1} inside input ZIP")]
        InputZipIndex(#[source] ZipError, usize),
        #[error("could not write to output, device full?")]
        OutputFull,
        #[error("could not read output")]
        OutputRead(#[source] std::io::Error),
        #[error("could not seek in output")]
        OutputSeek(#[source] std::io::Error),
        #[error("could not write to output")]
        OutputWrite(#[source] std::io::Error),
        #[error("could not write ZIP file #{1} to output")]
        OutputZip(#[source] ZipError, usize),
        #[error("could not finish writing output ZIP")]
        OutputZipFinish(#[source] ZipError),
        #[error("could not gather signature data")]
        Sign(#[source] GatherSignatureDataError),
        #[error("too many keys")]
        TooManyKeys,
    }
}

/// Copy a `.zip` file and sign its content
pub fn copy_and_sign_zip<I, O>(
    input: &mut I,
    output: &mut O,
    keys: &[SigningKey],
    context: Option<&[u8]>,
) -> Result<(), SignZipError>
where
    I: ?Sized + Read + Seek,
    O: ?Sized + Read + Seek + Write,
{
    if keys.len() > SignatureCountLeInt::MAX as usize {
        return Err(Error::TooManyKeys.into());
    }
    let signature_bytes = SIGNATURE_LENGTH * keys.len() + HEADER_SIZE;
    if signature_bytes > BUF_LIMIT {
        return Err(Error::TooManyKeys.into());
    }

    // copy ZIP
    write_padding(signature_bytes, output)?;
    copy_zip(input, output)?;

    // gather signature
    let _ = output
        .seek(SeekFrom::Start(signature_bytes.try_into().unwrap()))
        .map_err(Error::OutputSeek)?;
    let prehashed_message = prehash(output).map_err(Error::OutputRead)?;
    let buf = gather_signature_data(keys, &prehashed_message, context).map_err(Error::Sign)?;

    // write signature
    output.rewind().map_err(Error::OutputSeek)?;
    output
        .write_all(&buf)
        .map_err(|err| SignZipError(Error::OutputWrite(err)))
}

fn write_padding<O>(mut padding_to_write: usize, output: &mut O) -> Result<(), Error>
where
    O: ?Sized + Write,
{
    while padding_to_write > 0 {
        const PADDING: &[u8; 512] = &[0; 512];
        let result = if padding_to_write > PADDING.len() {
            let num_slices = ((padding_to_write + PADDING.len() - 1) / PADDING.len()).min(128);
            let mut slices = vec![IoSlice::new(PADDING); num_slices];
            slices[num_slices - 1] = IoSlice::new(&PADDING[..padding_to_write % PADDING.len()]);
            output.write_vectored(&slices)
        } else {
            output.write(&PADDING[..padding_to_write])
        };
        let written = result.map_err(Error::OutputWrite)?;

        if written == 0 {
            return Err(Error::OutputFull);
        }
        padding_to_write -= written;
    }
    Ok(())
}

fn copy_zip<I, O>(input: &mut I, output: &mut O) -> Result<(), Error>
where
    I: ?Sized + Read + Seek,
    O: ?Sized + Write + Seek,
{
    let mut input = ZipArchive::new(BufReader::new(input)).map_err(Error::InputZip)?;
    let mut output = ZipWriter::new(BufWriter::new(output));

    output.set_raw_comment(input.comment().to_owned());
    for idx in 0..input.len() {
        let file = input
            .by_index_raw(idx)
            .map_err(|err| Error::InputZipIndex(err, idx))?;
        output
            .raw_copy_file(file)
            .map_err(|err| Error::OutputZip(err, idx))?;
    }
    output
        .finish()
        .map_err(Error::OutputZipFinish)?
        .flush()
        .map_err(Error::OutputWrite)?;

    Ok(())
}
