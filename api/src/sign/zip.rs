#![cfg_attr(docsrs, doc(cfg(feature = "sign-zip")))]

use std::io::{BufReader, BufWriter, IoSlice, Read, Seek, SeekFrom, Write};

use zip::result::ZipError;
use zip::{ZipArchive, ZipWriter};

use super::{gather_signature_data, prehashed_message, GatherSignatureDataError};
use crate::{SignatureCountLeInt, SigningKey, BUF_LIMIT, HEADER_SIZE, SIGNATURE_LENGTH};

/// An error returned by [`copy_and_sign_zip()`]
#[derive(Debug, thiserror::Error)]
pub enum SignZipError {
    /// Could not read input ZIP
    #[error("could not read input ZIP")]
    InputZip(#[source] ZipError),
    /// Could not read a file inside input ZIP
    #[error("could not read file #{1} inside input ZIP")]
    InputZipIndex(#[source] ZipError, usize),
    /// Could not write to output, device full?
    #[error("could not write to output, device full?")]
    OutputFull,
    /// Could not read output
    #[error("could not read output")]
    OutputRead(#[source] std::io::Error),
    /// Could not seek in output
    #[error("could not seek in output")]
    OutputSeek(#[source] std::io::Error),
    /// Could not write to output
    #[error("could not write to output")]
    OutputWrite(#[source] std::io::Error),
    /// Could not write ZIP file to output
    #[error("could not write ZIP file #{1} to output")]
    OutputZip(#[source] ZipError, usize),
    /// Could not finish writing output ZIP
    #[error("could not finish writing output ZIP")]
    OutputZipFinish(#[source] ZipError),
    /// Could not gather signature data
    #[error("could not gather signature data")]
    Sign(#[source] GatherSignatureDataError),
    /// Too many keys
    #[error("too many keys")]
    TooManyKeys,
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
    O: ?Sized + Read + Write + Seek,
{
    if keys.len() > SignatureCountLeInt::MAX as usize {
        return Err(SignZipError::TooManyKeys);
    }
    let signature_bytes = SIGNATURE_LENGTH * keys.len() + HEADER_SIZE;
    if signature_bytes > BUF_LIMIT {
        return Err(SignZipError::TooManyKeys);
    }

    // copy ZIP
    write_padding(signature_bytes, output)?;
    copy_zip(input, output)?;

    // gather signature
    let _ = output
        .seek(SeekFrom::Start(signature_bytes.try_into().unwrap()))
        .map_err(SignZipError::OutputSeek)?;
    let prehashed_message = prehashed_message(output).map_err(SignZipError::OutputRead)?;
    let buf =
        gather_signature_data(keys, &prehashed_message, context).map_err(SignZipError::Sign)?;

    // write signature
    output.rewind().map_err(SignZipError::OutputSeek)?;
    output.write_all(&buf).map_err(SignZipError::OutputWrite)
}

fn write_padding<O>(mut padding_to_write: usize, output: &mut O) -> Result<(), SignZipError>
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
        let written = result.map_err(SignZipError::OutputWrite)?;

        if written == 0 {
            return Err(SignZipError::OutputFull);
        }
        padding_to_write -= written;
    }
    Ok(())
}

fn copy_zip<I, O>(input: &mut I, output: &mut O) -> Result<(), SignZipError>
where
    I: ?Sized + Read + Seek,
    O: ?Sized + Write + Seek,
{
    let mut input = ZipArchive::new(BufReader::new(input)).map_err(SignZipError::InputZip)?;
    let mut output = ZipWriter::new(BufWriter::new(output));

    output.set_raw_comment(input.comment().to_owned());
    for idx in 0..input.len() {
        let file = input
            .by_index_raw(idx)
            .map_err(|err| SignZipError::InputZipIndex(err, idx))?;
        output
            .raw_copy_file(file)
            .map_err(|err| SignZipError::OutputZip(err, idx))?;
    }
    output
        .finish()
        .map_err(SignZipError::OutputZipFinish)?
        .flush()
        .map_err(SignZipError::OutputWrite)?;

    Ok(())
}
