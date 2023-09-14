use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use zipsign_api::prehash;
use zipsign_api::sign::{
    copy_and_sign_tar, copy_and_sign_zip, gather_signature_data, read_signing_keys,
    GatherSignatureDataError, ReadSigningKeysError, SignTarError, SignZipError,
};

use crate::{get_context, ImplicitContextError};

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
    /// Arbitrary string used to salt the input, defaults to file name of `<INPUT>`
    #[arg(long, short = 'c')]
    context: Option<String>,
    /// Overwrite output file if it exists
    #[arg(long, short = 'f')]
    force: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("could not determine `context` string by the input name")]
    Context(#[from] ImplicitContextError),
    #[error("could not gather signature data")]
    GatherSignatureData(#[from] GatherSignatureDataError),
    #[error("could not open input file")]
    InputOpen(#[source] std::io::Error),
    #[error("could not read input")]
    InputRead(#[source] std::io::Error),
    #[error("could not open or create output file")]
    OutputOpen(#[source] std::io::Error),
    #[error("could not write to output")]
    OutputWrite(#[source] std::io::Error),
    #[error("could not read signing keys")]
    ReadSigningKeys(#[from] ReadSigningKeysError),
    #[error("could not copy and sign the input")]
    Tar(#[from] SignTarError),
    #[error("could not copy and sign the input")]
    Zip(#[from] SignZipError),
}

pub(crate) fn main(args: Cli) -> Result<(), Error> {
    let (kind, args) = args.subcommand.split();

    let context = get_context(args.context.as_deref(), &args.input)?;

    let keys = args.keys.into_iter().map(File::open);
    let keys = read_signing_keys(keys)?;

    let mut input = File::open(&args.input).map_err(Error::InputOpen)?;
    let mut output = OpenOptions::new()
        .create(true)
        .create_new(!args.force)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&args.output)
        .map_err(Error::OutputOpen)?;

    match kind {
        ArchiveKind::Separate => {
            let prehashed_message = prehash(&mut input).map_err(Error::InputRead)?;
            let data = gather_signature_data(&keys, &prehashed_message, Some(context))?;
            output.write_all(&data).map_err(Error::OutputWrite)?;
        },
        ArchiveKind::Zip => {
            copy_and_sign_zip(&mut input, &mut output, &keys, Some(context))?;
        },
        ArchiveKind::Tar => {
            copy_and_sign_tar(&mut input, &mut output, &keys, Some(context))?;
        },
    }
    Ok(())
}
