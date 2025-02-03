use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use zipsign_api::verify::{
    CollectKeysError, NoMatch, ReadSignaturesError, VerifyTarError, VerifyZipError, collect_keys,
    find_match, read_signatures, verify_tar, verify_zip,
};
use zipsign_api::{PUBLIC_KEY_LENGTH, Prehash};

use crate::{ImplicitContextError, get_context};

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
    #[error("could not collect keys")]
    CollectKeys(#[from] CollectKeysError),
    #[error("could not determine `context` string by the input name")]
    Context(#[from] ImplicitContextError),
    #[error("could not open input")]
    InputOpen(#[source] std::io::Error),
    #[error("could not read input")]
    InputRead(#[source] std::io::Error),
    #[error(transparent)]
    NoMatch(#[from] NoMatch),
    #[error("could not open signatures")]
    SignaturesOpen(#[source] std::io::Error),
    #[error("could not read signatures")]
    SignaturesRead(#[from] ReadSignaturesError),
    #[error("could not verify `.tar.gz` file")]
    Tar(#[from] VerifyTarError),
    #[error("could not verify `.zip` file")]
    Zip(#[from] VerifyZipError),
}

pub(crate) fn main(args: Cli) -> Result<(), Error> {
    let (kind, input, args) = args.subcommand.split();

    let context = get_context(args.context.as_deref(), &input)?;

    let keys = args.keys.into_iter().map(|path| {
        let mut buf = [0; PUBLIC_KEY_LENGTH];
        File::open(path)?.read_exact(&mut buf)?;
        Ok(buf)
    });
    let keys = collect_keys(keys)?;

    let mut input = File::open(&input).map_err(Error::InputOpen)?;

    let _idx = match kind {
        ArchiveKind::Separate { signature } => {
            let signatures =
                read_signatures(&mut File::open(signature).map_err(Error::SignaturesOpen)?)?;
            let prehashed_message = Prehash::calculate(&mut input).map_err(Error::InputRead)?;
            let (key_idx, _) = find_match(&keys, &signatures, &prehashed_message, Some(context))
                .map_err(Error::NoMatch)?;
            key_idx
        },
        ArchiveKind::Zip => verify_zip(&mut input, &keys, Some(context))?,
        ArchiveKind::Tar => verify_tar(&mut input, &keys, Some(context))?,
    };
    if !args.quiet {
        println!("OK")
    }
    Ok(())
}
