use std::fs::OpenOptions;
use std::io::{copy, Read, Seek, SeekFrom};
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{
    Digest, Sha512, Signature, SignatureError, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

use crate::{SignatureCountLeInt, HEADER_SIZE, MAGIC_HEADER};

pub fn main(args: Cli) -> Result<(), Error> {
    let context = args.context.as_deref().map(str::as_bytes);

    // open signatures
    let signature_file = args.signature.as_deref().unwrap_or(&args.input);
    let mut f = match OpenOptions::new().read(true).open(signature_file) {
        Ok(f) => f,
        Err(err) => {
            return Err(Error::OpenRead(err, args.signature.unwrap_or(args.input)));
        },
    };

    // read header
    if args.end_of_file {
        if let Err(err) = f.seek(SeekFrom::End(-(HEADER_SIZE as i64))) {
            return Err(Error::Seek(err, args.signature.unwrap_or(args.input)));
        }
    }

    let mut header = [0; HEADER_SIZE];
    if let Err(err) = f.read_exact(&mut header) {
        return Err(Error::Read(err, args.signature.unwrap_or(args.input)));
    }
    if header[..MAGIC_HEADER.len()] != MAGIC_HEADER[..] {
        return Err(Error::MagicHeader(args.signature.unwrap_or(args.input)));
    }
    let signature_count = header[MAGIC_HEADER.len()..].try_into().unwrap();
    let signature_count = SignatureCountLeInt::from_le_bytes(signature_count) as usize;

    if args.end_of_file {
        let signature_bytes = signature_count * SIGNATURE_LENGTH + HEADER_SIZE;
        if let Err(err) = f.seek(SeekFrom::End(-(signature_bytes as i64))) {
            return Err(Error::Seek(err, args.signature.unwrap_or(args.input)));
        }
    }

    let signature_bytes = signature_count * SIGNATURE_LENGTH + HEADER_SIZE;
    let mut signatures = vec![0; signature_bytes - HEADER_SIZE];
    if let Err(err) = f.read_exact(&mut signatures) {
        return Err(Error::Read(err, args.signature.unwrap_or(args.input)));
    };
    let signatures = signatures
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| Error::IllegalSignature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // pre-hash input
    let prehashed_message = {
        let mut f = match OpenOptions::new().read(true).open(&args.input) {
            Ok(f) => f,
            Err(err) => return Err(Error::OpenRead(err, args.input)),
        };

        let mut prehashed_message = Sha512::new();
        let result = match (args.signature.is_none(), args.end_of_file) {
            (false, _) => {
                // signature is stored in extra file: read entire <INPUT>
                copy(&mut f, &mut prehashed_message)
            },
            (true, false) => {
                // signature is stored in <INPUT>, skip start of file
                if let Err(err) = f.seek(SeekFrom::Start(signature_bytes as u64)) {
                    return Err(Error::Seek(err, args.signature.unwrap_or(args.input)));
                }
                copy(&mut f, &mut prehashed_message)
            },
            (true, true) => {
                // signature is stored in <INPUT>, omit end of file
                let len = match f.metadata() {
                    Ok(m) => m.len(),
                    Err(err) => return Err(Error::Read(err, args.input)),
                };
                let mut f = f.take(len - signature_bytes as u64);
                copy(&mut f, &mut prehashed_message)
            },
        };
        if let Err(err) = result {
            return Err(Error::Read(err, args.input));
        }
        prehashed_message.update(header);
        prehashed_message
    };

    // read verifying keys
    let keys = args
        .verifying_key
        .into_iter()
        .map(|key_file| {
            let mut key = [0; PUBLIC_KEY_LENGTH];
            let mut f = match OpenOptions::new().read(true).open(&key_file) {
                Ok(f) => f,
                Err(err) => return Err(Error::OpenRead(err, key_file)),
            };
            if let Err(err) = f.read_exact(&mut key) {
                return Err(Error::Read(err, key_file));
            }
            VerifyingKey::from_bytes(&key).map_err(|err| Error::KeyInvalid(err, key_file))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // try to find `(signature, verifying key)` match
    for key in &keys {
        for signature in &signatures {
            if key
                .verify_prehashed_strict(prehashed_message.clone(), context, signature)
                .is_ok()
            {
                println!("OK");
                return Ok(());
            }
        }
    }
    Err(Error::NoMatch)
}

/// Verify a signature
#[derive(Debug, Parser)]
pub struct Cli {
    /// File to verify
    #[arg(long, short = 'i')]
    input: PathBuf,
    /// Signature file. If absent the signature it is read from `<INPUT>`
    #[arg(long, short = 'o')]
    signature: Option<PathBuf>,
    /// One or more files containing verifying keys
    #[arg(long, short = 'k', num_args = 1..)]
    verifying_key: Vec<PathBuf>,
    /// Context (an arbitrary string used to salt the input, e.g. the basename of `<INPUT>`)
    #[arg(long, short = 'c')]
    context: Option<String>,
    /// Signatures at end of file (.tar files)
    #[arg(long, short = 'e')]
    end_of_file: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no matching (signature, verifying_key) pair was found")]
    NoMatch,
    #[error("could not open {1:?} for reading")]
    OpenRead(#[source] std::io::Error, PathBuf),
    #[error("could not read from {1:?}")]
    Read(#[source] std::io::Error, PathBuf),
    #[error("could not not seek in file {1:?}")]
    Seek(#[source] std::io::Error, PathBuf),
    #[error("verify key {1:?} invalid")]
    KeyInvalid(#[source] SignatureError, PathBuf),
    #[error("illegal signature #{1}")]
    IllegalSignature(#[source] SignatureError, usize),
    #[error("illegal, unknown or missing header in {0:?}")]
    MagicHeader(PathBuf),
}
