use std::fs::{File, rename};
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use normalize_path::NormalizePath;
use zipsign_api::unsign::{
    UnsignTarError, UnsignZipError, copy_and_unsign_tar, copy_and_unsign_zip,
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
            CliKind::Zip(common) => (ArchiveKind::Zip, common),
            CliKind::Tar(common) => (ArchiveKind::Tar, common),
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
enum CliKind {
    /// `<INPUT>` is a .zip file.
    /// Its data is copied and the signatures are stored next to the data.
    Zip(#[command(flatten)] CommonArgs),
    /// `<INPUT>` is a gzipped .tar file.
    /// Its data is copied and the signatures are stored next to the data.
    Tar(#[command(flatten)] CommonArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    Zip,
    Tar,
}

#[derive(Debug, Args, Clone)]
struct CommonArgs {
    /// Input file to sign
    input: PathBuf,
    /// Signed file to generate (if omitted, the input is overwritten)
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,
    /// Overwrite output file if it exists
    #[arg(long, short = 'f')]
    force: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("output exists, use `--force` allow replacing a file")]
    Exists,
    #[error("could not open input file")]
    InputOpen(#[source] std::io::Error),
    #[error("could not rename output file")]
    OutputRename(#[source] std::io::Error),
    #[error(transparent)]
    Tar(#[from] UnsignTarError),
    #[error("could not create temporary file in output directory")]
    Tempfile(#[source] std::io::Error),
    #[error(transparent)]
    Zip(#[from] UnsignZipError),
}

pub(crate) fn main(args: Cli) -> Result<(), Error> {
    let (kind, args) = args.subcommand.split();

    let output_path = args.output.as_deref().unwrap_or(&args.input).normalize();
    if args.output.is_some() && !args.force {
        return Err(Error::Exists);
    }
    let output_dir = output_path.parent().unwrap_or(Path::new("."));
    let tempdir = tempfile::Builder::new()
        .prefix(".zipsign.")
        .suffix(".tmp")
        .tempdir_in(output_dir)
        .map_err(Error::Tempfile)?;
    let mut temp_file = tempfile::Builder::new()
        .tempfile_in(&tempdir)
        .map_err(Error::Tempfile)?;
    let output_file = temp_file.as_file_mut();

    let mut input = File::open(&args.input).map_err(Error::InputOpen)?;
    match kind {
        ArchiveKind::Zip => copy_and_unsign_zip(&mut input, output_file)?,
        ArchiveKind::Tar => copy_and_unsign_tar(&mut input, output_file)?,
    }
    // drop input so it can be overwritten if input=output
    drop(input);

    rename(temp_file.into_temp_path(), output_path).map_err(Error::OutputRename)?;
    Ok(())
}
