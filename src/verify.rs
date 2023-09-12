use std::fs::{File, OpenOptions};
use std::io::{copy, Read, Seek, SeekFrom};
use std::path::PathBuf;

use base64::engine::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{
    Digest, Sha512, Signature, SignatureError, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

use crate::{SignatureCountLeInt, GZIP_END, GZIP_START, HEADER_SIZE, MAGIC_HEADER};

pub fn main(args: Cli) -> Result<(), Error> {
    let (kind, input, args) = args.subcommand.split();

    // prehash input and read signatures
    let (input, prehashed_message, signatures) = match kind {
        ArchiveKind::Separate { signature } => prehash_separate(input, signature)?,
        ArchiveKind::Zip => prehash_zip(input)?,
        ArchiveKind::Tar => prehash_tar(input)?,
    };

    // read verifying keys
    let keys = args
        .keys
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
    let context = match &args.context {
        Some(context) => context.as_bytes(),
        None => {
            // TODO: FIXME: windows
            std::os::unix::prelude::OsStrExt::as_bytes(input.as_os_str())
        },
    };
    for key in &keys {
        for signature in &signatures {
            if key
                .verify_prehashed_strict(prehashed_message.clone(), Some(context), signature)
                .is_ok()
            {
                if !args.quiet {
                    println!("OK");
                }
                return Ok(());
            }
        }
    }
    Err(Error::NoMatch)
}

fn prehash_separate(
    input: PathBuf,
    signatures: PathBuf,
) -> Result<(PathBuf, Sha512, Vec<Signature>), Error> {
    // read signatures
    let mut f = match OpenOptions::new().read(true).open(&signatures) {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenRead(err, signatures)),
    };
    let (_, signatures) = read_signatures(&mut f, signatures)?;
    drop(f);

    // pre-hash file
    let mut f = match OpenOptions::new().read(true).open(&input) {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenRead(err, input)),
    };
    let mut prehashed_message = Sha512::new();
    if let Err(err) = copy(&mut f, &mut prehashed_message) {
        return Err(Error::Read(err, input));
    }

    Ok((input, prehashed_message, signatures))
}

fn prehash_zip(input: PathBuf) -> Result<(PathBuf, Sha512, Vec<Signature>), Error> {
    let mut f = match OpenOptions::new().read(true).open(&input) {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenRead(err, input)),
    };

    // read signatures
    let (input, signatures) = read_signatures(&mut f, input)?;

    // pre-hash file
    let mut prehashed_message = Sha512::new();
    if let Err(err) = copy(&mut f, &mut prehashed_message) {
        return Err(Error::Read(err, input));
    }

    Ok((input, prehashed_message, signatures))
}

fn read_signatures(f: &mut File, input: PathBuf) -> Result<(PathBuf, Vec<Signature>), Error> {
    let mut header = [0; HEADER_SIZE];
    if let Err(err) = f.read_exact(&mut header) {
        return Err(Error::Read(err, input));
    }
    if header[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(Error::MagicHeader(input));
    }

    let signature_count = header[MAGIC_HEADER.len()..].try_into().unwrap();
    let signature_count = SignatureCountLeInt::from_le_bytes(signature_count) as usize;
    let signature_bytes = signature_count * SIGNATURE_LENGTH;
    if signature_bytes > (8 << 20) {
        return Err(Error::MagicHeader(input));
    }

    let mut signatures = vec![0; signature_bytes];
    if let Err(err) = f.read_exact(&mut signatures) {
        return Err(Error::Read(err, input));
    };

    let signatures = signatures
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| Error::IllegalSignature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((input, signatures))
}

fn prehash_tar(input: PathBuf) -> Result<(PathBuf, Sha512, Vec<Signature>), Error> {
    let mut f = match OpenOptions::new().read(true).open(&input) {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenRead(err, input)),
    };

    // seek to start of base64 encoded signatures
    let mut tail = [0; u64::BITS as usize / 4 + GZIP_END.len()];
    let data_end = match f.seek(SeekFrom::End(-(tail.len() as i64))) {
        Ok(tail_start) => tail_start,
        Err(err) => return Err(Error::Seek(err, input)),
    };
    if let Err(err) = f.read_exact(&mut tail) {
        return Err(Error::Read(err, input));
    }
    if tail[u64::BITS as usize / 4..] != *GZIP_END {
        return Err(Error::MagicHeader(input));
    }

    let Ok(gzip_start) = std::str::from_utf8(&tail[..16]) else {
        return Err(Error::MagicHeader(input));
    };
    let Ok(gzip_start) = u64::from_str_radix(gzip_start, 16) else {
        return Err(Error::MagicHeader(input));
    };
    let Some(data_start) = gzip_start.checked_add(10) else {
        return Err(Error::MagicHeader(input));
    };
    let Some(data_len) = data_end.checked_sub(data_start) else {
        return Err(Error::MagicHeader(input));
    };
    let Ok(data_len) = usize::try_from(data_len) else {
        return Err(Error::MagicHeader(input));
    };
    if data_len > (8 << 20) {
        return Err(Error::MagicHeader(input));
    }

    if let Err(err) = f.seek(SeekFrom::Start(gzip_start)) {
        return Err(Error::Seek(err, input));
    }

    // read base64 encoded signatures
    let mut data = vec![0; data_len + 10];
    if let Err(err) = f.read_exact(&mut data) {
        return Err(Error::Read(err, input));
    }

    if data[..GZIP_START.len()] != *GZIP_START {
        return Err(Error::MagicHeader(input));
    }

    let Ok(data) = BASE64_STANDARD.decode(&data[GZIP_START.len()..]) else {
        return Err(Error::MagicHeader(input));
    };
    if data.len() < HEADER_SIZE {
        return Err(Error::MagicHeader(input));
    }
    if data[..MAGIC_HEADER.len()] != *MAGIC_HEADER {
        return Err(Error::MagicHeader(input));
    }
    let signatures = data[HEADER_SIZE..]
        .chunks_exact(SIGNATURE_LENGTH)
        .enumerate()
        .map(|(idx, bytes)| {
            Signature::from_slice(bytes).map_err(|err| Error::IllegalSignature(err, idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // pre-hash file
    if let Err(err) = f.rewind() {
        return Err(Error::Seek(err, input));
    }
    let mut prehashed_message = Sha512::new();
    if let Err(err) = copy(&mut f.take(gzip_start), &mut prehashed_message) {
        return Err(Error::Read(err, input));
    }

    Ok((input, prehashed_message, signatures))
}

/// Verify a signature
#[derive(Debug, Parser, Clone)]
pub struct Cli {
    #[command(subcommand)]
    subcommand: CliKind,
}

impl CliKind {
    fn split(self) -> (ArchiveKind, PathBuf, CommonArgs) {
        match self {
            CliKind::Separate {
                common,
                input,
                signature,
            } => (ArchiveKind::Separate { signature }, input, common),
            CliKind::Zip { common, input } => (ArchiveKind::Zip, input, common),
            CliKind::Tar { common, input } => (ArchiveKind::Tar, input, common),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
enum CliKind {
    /// Store generated signature in a separate file
    Separate {
        /// File to verify
        input: PathBuf,
        /// Signature file
        signature: PathBuf,
        #[command(flatten)]
        common: CommonArgs,
    },
    /// `<INPUT>` is a .zip file.
    /// Its data is copied and the signatures are stored next to the data.
    Zip {
        /// Signed .zip file
        input: PathBuf,
        #[command(flatten)]
        common: CommonArgs,
    },
    /// `<INPUT>` is an uncompressed or gzipped .tar file.
    /// Its data is copied and the signatures are stored next to the data.
    Tar {
        /// Signed .tar file
        input: PathBuf,
        #[command(flatten)]
        common: CommonArgs,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ArchiveKind {
    Separate { signature: PathBuf },
    Zip,
    Tar,
}

#[derive(Debug, Args, Clone)]
struct CommonArgs {
    /// One or more files containing verifying keys
    #[arg(required = true)]
    keys: Vec<PathBuf>,
    /// An arbitrary string used to salt the input, defaults to file name of `<INPUT>`
    #[arg(long, short = 'c')]
    context: Option<String>,
    /// Don't write "OK" if the verification succeeded
    #[arg(long, short = 'q')]
    quiet: bool,
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
