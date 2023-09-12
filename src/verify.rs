use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use zipsign_api::verify::{
    collect_keys, find_match, prehash, read_signatures, read_tar, read_zip, Error as ApiError,
    SignatureError, PUBLIC_KEY_LENGTH,
};

pub(crate) fn main(args: Cli) -> Result<(), Error> {
    let (kind, input, mut args) = args.subcommand.split();

    let mut input_file = match File::open(&input) {
        Ok(f) => f,
        Err(err) => return Err(Error::Open(err, input)),
    };

    let context = match &args.context {
        Some(context) => context.as_bytes(),
        None => {
            // TODO: FIXME: windows
            std::os::unix::prelude::OsStrExt::as_bytes(input.as_os_str())
        },
    };

    let keys: Result<Vec<_>, _> = args
        .keys
        .iter()
        .map(|k| k.as_path())
        .enumerate()
        .map(|(idx, key_file)| {
            let mut key = [0; PUBLIC_KEY_LENGTH];
            File::open(key_file)
                .map_err(|err| (false, err, idx))?
                .read_exact(&mut key)
                .map_err(|err| (true, err, idx))?;
            Ok(key)
        })
        .collect();
    let keys = match keys {
        Ok(keys) => keys,
        Err((is_read, err, idx)) => {
            let path = args.keys.swap_remove(idx);
            return Err(match is_read {
                false => Error::Open(err, path),
                true => Error::Read(err, path),
            });
        },
    };
    let keys = match collect_keys(&keys) {
        Ok(keys) => keys,
        Err(err) => return Err(convert_error(err, input, args)),
    };

    let (prehashed_message, signatures) = match kind {
        ArchiveKind::Separate { signature } => {
            let prehashed_message = match prehash(&mut input_file) {
                Ok(signatures) => signatures,
                Err(err) => return Err(convert_error(err, input, args)),
            };
            let signatures = match File::open(&signature) {
                Ok(mut file) => read_signatures(&mut file),
                Err(err) => return Err(Error::Open(err, signature)),
            };
            let signatures = match signatures {
                Ok(signatures) => signatures,
                Err(err) => return Err(convert_error(err, signature, args)),
            };
            (prehashed_message, signatures)
        },
        ArchiveKind::Zip => match read_zip(&mut input_file) {
            Ok(data) => data,
            Err(err) => return Err(convert_error(err, input, args)),
        },
        ArchiveKind::Tar => match read_tar(&mut input_file) {
            Ok(data) => data,
            Err(err) => return Err(convert_error(err, input, args)),
        },
    };
    if let Err(err) = find_match(&keys, &signatures, &prehashed_message, Some(context)) {
        return Err(convert_error(err, input, args));
    }

    if !args.quiet {
        println!("OK");
    }
    Ok(())
}

/// Verify a signature
#[derive(Debug, Parser, Clone)]
pub(crate) struct Cli {
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
pub(crate) enum Error {
    #[error("no matching (signature, verifying_key) pair was found")]
    NoMatch,
    #[error("could not open {1:?} for reading")]
    Open(#[source] std::io::Error, PathBuf),
    #[error("could not read from {1:?}")]
    Read(#[source] std::io::Error, PathBuf),
    #[error("could not not seek in file {1:?}")]
    Seek(#[source] std::io::Error, PathBuf),
    #[error("verify key {1:?} invalid")]
    IllegalKey(#[source] SignatureError, PathBuf),
    #[error("illegal signature #{1}")]
    IllegalSignature(#[source] SignatureError, usize),
    #[error("illegal, unknown or missing header in {0:?}")]
    MagicHeader(PathBuf),
}

fn convert_error(err: ApiError, input: PathBuf, mut args: CommonArgs) -> Error {
    match err {
        ApiError::NoMatch => Error::NoMatch,
        ApiError::MagicHeader => Error::MagicHeader(input),
        ApiError::Read(err) => Error::Read(err, input),
        ApiError::Seek(err) => Error::Seek(err, input),
        ApiError::IllegalKey(err, idx) => {
            let path = args.keys.swap_remove(idx);
            Error::IllegalKey(err, path)
        },
        ApiError::IllegalSignature(err, idx) => Error::IllegalSignature(err, idx),
    }
}
