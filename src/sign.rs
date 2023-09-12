use std::fs::OpenOptions;
use std::io::{copy, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{Digest, Sha512, SignatureError, SigningKey, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
use zip::result::ZipError;
use zip::{ZipArchive, ZipWriter};

use crate::{SignatureCountLeInt, HEADER_SIZE, MAGIC_HEADER};

pub fn main(args: Cli) -> Result<(), Error> {
    if args.private_key.len() > SignatureCountLeInt::MAX as usize {
        return Err(Error::TooManyKeys);
    }
    let signature_bytes = SIGNATURE_LENGTH * args.private_key.len() + HEADER_SIZE;
    let context = args.context.as_deref().map(str::as_bytes);

    // read signing keys
    let mut keys = args
        .private_key
        .into_iter()
        .map(|key_file| {
            let mut key = [0; KEYPAIR_LENGTH];
            let mut f = match OpenOptions::new().read(true).open(&key_file) {
                Ok(f) => f,
                Err(err) => return Err(Error::OpenRead(err, key_file)),
            };
            if let Err(err) = f.read_exact(&mut key) {
                return Err(Error::Read(err, key_file));
            }
            SigningKey::from_keypair_bytes(&key).map_err(|err| Error::KeyInvalid(err, key_file))
        })
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort_by(|l, r| {
        l.verifying_key()
            .as_bytes()
            .cmp(r.verifying_key().as_bytes())
    });

    // open input file
    let mut input = match OpenOptions::new().read(true).open(&args.input) {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenRead(err, args.input)),
    };

    // open output file
    // TODO: FIXME: O_TMPFILE?
    // TODO: FIXME: tempdir?
    let mut output = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.signature)
    {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenWrite(err, args.signature)),
    };

    // Copy ZIP file.
    // The file headers inside a ZIP file contain references to the absolute position in the file,
    // so the checksum of the copy will be different from its original.
    if args.zip {
        let signature_bytes = signature_bytes.try_into().unwrap();
        if let Err(err) = output.set_len(signature_bytes) {
            return Err(Error::Write(err, args.signature));
        }
        if let Err(err) = output.seek(SeekFrom::Start(signature_bytes)) {
            return Err(Error::Seek(err, args.signature));
        }

        let mut input = match ZipArchive::new(BufReader::new(&mut input)) {
            Ok(input) => input,
            Err(err) => return Err(Error::Zip(err, args.input)),
        };

        let mut output = ZipWriter::new(BufWriter::new(&mut output));
        output.set_raw_comment(input.comment().to_owned());
        for idx in 0..input.len() {
            let file = match input.by_index_raw(idx) {
                Ok(entry) => entry,
                Err(err) => return Err(Error::ZipRead(err, args.input, idx)),
            };
            if let Err(err) = output.raw_copy_file(file) {
                return Err(Error::ZipWrite(err, args.signature, idx));
            }
        }
        if let Err(err) = output.finish() {
            return Err(Error::ZipFinish(err, args.signature));
        }
    }

    // the header is hashed, too, to the set of keys cannot be easily changed after the fact
    let mut header = [0; HEADER_SIZE];
    header[..MAGIC_HEADER.len()].copy_from_slice(MAGIC_HEADER);
    header[MAGIC_HEADER.len()..]
        .copy_from_slice(&(keys.len() as SignatureCountLeInt).to_le_bytes());

    // pre-hash input
    let mut prehashed_message = Sha512::new();
    if args.zip {
        let signature_bytes = signature_bytes.try_into().unwrap();
        if let Err(err) = output.seek(SeekFrom::Start(signature_bytes)) {
            return Err(Error::Seek(err, args.input));
        }
        if let Err(err) = copy(&mut output, &mut prehashed_message) {
            return Err(Error::Read(err, args.signature));
        }
    } else if let Err(err) = copy(&mut input, &mut prehashed_message) {
        return Err(Error::Read(err, args.input));
    }
    prehashed_message.update(header);

    // write signatures
    let mut signatures_buf = Vec::with_capacity(signature_bytes);
    if !args.end_of_file {
        signatures_buf.extend(header);
    }
    for key in keys {
        let signature = key
            .sign_prehashed(prehashed_message.clone(), context)
            .map_err(Error::FileSign)?;
        signatures_buf.extend(signature.to_bytes());
    }
    if args.end_of_file {
        signatures_buf.extend(header);
    }
    if args.zip {
        if let Err(err) = output.seek(SeekFrom::Start(0)) {
            return Err(Error::Seek(err, args.signature));
        }
    }
    if let Err(err) = output.write_all(&signatures_buf) {
        return Err(Error::Write(err, args.signature));
    }
    Ok(())
}

/// Generate signature for a file
#[derive(Debug, Parser)]
pub struct Cli {
    /// File to verify
    #[arg(long, short = 'i')]
    input: PathBuf,
    /// Signature to (over)write
    #[arg(long, short = 'o')]
    signature: PathBuf,
    /// One or more files containing private keys
    #[arg(long, short = 'k', num_args = 1..)]
    private_key: Vec<PathBuf>,
    /// Context (an arbitrary string used to salt the input, e.g. the basename of `<INPUT>`)
    #[arg(long, short = 'c')]
    context: Option<String>,
    /// `<INPUT>` is a ZIP file. Copy its data into the output.
    #[arg(long, short = 'z')]
    zip: bool,
    /// Signatures at end of file (.tar files)
    #[arg(long, short = 'e')]
    end_of_file: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not open {1:?} for reading")]
    OpenRead(#[source] std::io::Error, PathBuf),
    #[error("could not open {1:?} for writing")]
    OpenWrite(#[source] std::io::Error, PathBuf),
    #[error("could not read from {1:?}")]
    Read(#[source] std::io::Error, PathBuf),
    #[error("could not write to {1:?}")]
    Write(#[source] std::io::Error, PathBuf),
    #[error("could not not seek in file {1:?}")]
    Seek(#[source] std::io::Error, PathBuf),
    #[error("private key {1:?} was invalid")]
    KeyInvalid(#[source] SignatureError, PathBuf),
    #[error("could not sign file")]
    FileSign(#[source] SignatureError),
    #[error("could not read ZIP file {1:?}")]
    Zip(#[source] ZipError, PathBuf),
    #[error("could not read entry #{2:?} of ZIP file {1:?}")]
    ZipRead(#[source] ZipError, PathBuf, usize),
    #[error("could not write entry #{2:?} input output file {1:?}")]
    ZipWrite(#[source] ZipError, PathBuf, usize),
    #[error("could not finalize output file {1:?}")]
    ZipFinish(ZipError, PathBuf),
    #[error("cannot have more than 65535 keys")]
    TooManyKeys,
}
