#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![forbid(unsafe_code)]
#![allow(unknown_lints)]
#![doc = include_str!("../README.md")]

mod generate;
mod sign;
mod unsign;
mod verify;

use std::path::Path;

use clap::{Parser, Subcommand};

/// Sign a file with an ed25519 signing key.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    subcommand: CliSubcommand,
}

#[derive(Debug, Subcommand, Clone)]
enum CliSubcommand {
    GenKey(generate::Cli),
    Verify(verify::Cli),
    Sign(sign::Cli),
    Unsign(unsign::Cli),
}

#[derive(pretty_error_debug::Debug, thiserror::Error)]
enum MainError {
    #[error("could not generate key")]
    GenKey(#[from] generate::Error),
    #[error("could not verify file")]
    Verify(#[from] verify::Error),
    #[error("could not sign file")]
    Sign(#[from] sign::Error),
    #[error("could not remove sign from file")]
    Unsign(#[from] unsign::Error),
}

fn main() -> Result<(), MainError> {
    let args = Cli::parse();
    match args.subcommand {
        CliSubcommand::GenKey(args) => generate::main(args)?,
        CliSubcommand::Verify(args) => verify::main(args)?,
        CliSubcommand::Sign(args) => sign::main(args)?,
        CliSubcommand::Unsign(args) => unsign::main(args)?,
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
enum ImplicitContextError {
    #[error("could not determine basename")]
    Basename,
    #[error("path could not be interpreted as UTF-8 string")]
    Utf8,
}

fn get_context<'a>(
    explicit: Option<&'a str>,
    implicit: &'a Path,
) -> Result<&'a [u8], ImplicitContextError> {
    if let Some(context) = explicit {
        Ok(context.as_bytes())
    } else {
        // This function does not use `std::os::unix::prelude::OsStrExt` so that the windows and
        // linux implementation work the same for non-ASCII filenames. Otherwise a file signed on
        // linux might not successfully verify on windows, and vice versa.
        implicit
            .file_name()
            .ok_or(ImplicitContextError::Basename)?
            .to_str()
            .ok_or(ImplicitContextError::Utf8)
            .map(str::as_bytes)
    }
}
