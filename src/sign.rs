use std::fs::OpenOptions;
use std::io::{copy, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use base64::engine::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Digest, Sha512, SignatureError, SigningKey, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
use zip::result::ZipError;
use zip::{ZipArchive, ZipWriter};
use zipsign_api::{
    SignatureCountLeInt, GZIP_END, GZIP_EXTRA, GZIP_START, HEADER_SIZE, MAGIC_HEADER,
};

/// Generate signature for a file
#[derive(Debug, Parser, Clone)]
pub(crate) struct Cli {
    #[command(subcommand)]
    subcommand: CliKind,
}

impl CliKind {
    fn split(self) -> (ArchiveKind, CommonArgs) {
        match self {
            CliKind::Separate(common) => (ArchiveKind::Separate, common),
            CliKind::Zip(common) => (ArchiveKind::Zip, common),
            CliKind::Tar(common) => (ArchiveKind::Tar, common),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
enum CliKind {
    /// Store generated signature in a separate file
    Separate(#[command(flatten)] CommonArgs),
    /// `<INPUT>` is a .zip file.
    /// Its data is copied and the signatures are stored next to the data.
    Zip(#[command(flatten)] CommonArgs),
    /// `<INPUT>` is a gzipped .tar file.
    /// Its data is copied and the signatures are stored next to the data.
    Tar(#[command(flatten)] CommonArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Separate,
    Zip,
    Tar,
}

#[derive(Debug, Args, Clone)]
struct CommonArgs {
    /// Input file to sign
    input: PathBuf,
    /// Signed file to generate
    #[arg(long, short = 'o')]
    output: PathBuf,
    /// One or more files containing private keys
    #[arg(required = true)]
    keys: Vec<PathBuf>,
    /// Arbitrary string used to salt the input, defaults to file name of `<OUTPUT>`
    #[arg(long, short = 'c')]
    context: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
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

pub(crate) fn main(args: Cli) -> Result<(), Error> {
    let (kind, args) = args.subcommand.split();

    if args.keys.len() > SignatureCountLeInt::MAX as usize {
        return Err(Error::TooManyKeys);
    }
    let signature_bytes = SIGNATURE_LENGTH * args.keys.len() + HEADER_SIZE;

    // read signing keys
    let mut keys = args
        .keys
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
        .open(&args.output)
    {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenWrite(err, args.output)),
    };

    // Copy ZIP file.
    // The file headers inside a ZIP file contain references to the absolute position in the file,
    // so the checksum of the copy will be different from its original.
    if kind == ArchiveKind::Zip {
        let signature_bytes = signature_bytes.try_into().unwrap();
        if let Err(err) = output.set_len(signature_bytes) {
            return Err(Error::Write(err, args.output));
        }
        if let Err(err) = output.seek(SeekFrom::Start(signature_bytes)) {
            return Err(Error::Seek(err, args.output));
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
                return Err(Error::ZipWrite(err, args.output, idx));
            }
        }
        if let Err(err) = output.finish() {
            return Err(Error::ZipFinish(err, args.output));
        }
    }

    // pre-hash input
    let mut prehashed_message = Sha512::new();
    match kind {
        ArchiveKind::Separate => {
            if let Err(err) = copy(&mut input, &mut prehashed_message) {
                return Err(Error::Read(err, args.input));
            }
        },
        ArchiveKind::Zip => {
            let signature_bytes = signature_bytes.try_into().unwrap();
            if let Err(err) = output.seek(SeekFrom::Start(signature_bytes)) {
                return Err(Error::Seek(err, args.input));
            }
            if let Err(err) = copy(&mut output, &mut prehashed_message) {
                return Err(Error::Read(err, args.output));
            }
        },
        ArchiveKind::Tar => {
            if let Err(err) = copy(&mut input, &mut output) {
                return Err(Error::Read(err, args.output));
            }
            if let Err(err) = input.seek(SeekFrom::Start(0)) {
                return Err(Error::Seek(err, args.output));
            }
            if let Err(err) = copy(&mut input, &mut prehashed_message) {
                return Err(Error::Read(err, args.output));
            }
        },
    }

    // gather signature data
    let mut header = [0; HEADER_SIZE];
    header[..MAGIC_HEADER.len()].copy_from_slice(MAGIC_HEADER);
    header[MAGIC_HEADER.len()..]
        .copy_from_slice(&(keys.len() as SignatureCountLeInt).to_le_bytes());

    let mut signatures_buf = Vec::with_capacity(signature_bytes);
    signatures_buf.extend(header);

    let context = match &args.context {
        Some(context) => context.as_bytes(),
        None => {
            // TODO: FIXME: windows
            std::os::unix::prelude::OsStrExt::as_bytes(args.output.as_os_str())
        },
    };
    for key in keys {
        let signature = key
            .sign_prehashed(prehashed_message.clone(), Some(context))
            .map_err(Error::FileSign)?;
        signatures_buf.extend(signature.to_bytes());
    }

    // write signatures
    match kind {
        ArchiveKind::Separate => {
            if let Err(err) = output.write_all(&signatures_buf) {
                return Err(Error::Write(err, args.output));
            }
        },
        ArchiveKind::Zip => {
            if let Err(err) = output.seek(SeekFrom::Start(0)) {
                return Err(Error::Seek(err, args.output));
            }
            if let Err(err) = output.write_all(&signatures_buf) {
                return Err(Error::Write(err, args.output));
            }
        },
        ArchiveKind::Tar => {
            let signatures = BASE64_STANDARD.encode(signatures_buf);
            let start = match output.stream_position() {
                Ok(start) => format!("{start:016x}"),
                Err(err) => return Err(Error::Seek(err, args.output)),
            };

            let mut tail = Vec::with_capacity(GZIP_EXTRA + signatures.len());
            tail.extend(GZIP_START);
            tail.extend(signatures.into_bytes()); // GZIP comment
            tail.extend(start.into_bytes()); // GZIP comment
            tail.extend(GZIP_END);
            if let Err(err) = output.write_all(&tail) {
                return Err(Error::Write(err, args.output));
            }
        },
    }
    Ok(())
}
