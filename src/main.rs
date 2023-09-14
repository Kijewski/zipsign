#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![allow(unknown_lints)]
#![warn(absolute_paths_not_starting_with_crate)]
#![warn(elided_lifetimes_in_paths)]
#![warn(explicit_outlives_requirements)]
#![warn(meta_variable_misuse)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(non_ascii_idents)]
#![warn(noop_method_call)]
#![warn(rust_2018_idioms)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(unreachable_pub)]
#![warn(unused_crate_dependencies)]
#![warn(unused_extern_crates)]
#![warn(unused_lifetimes)]
#![warn(unused_results)]
#![doc = include_str!("../README.md")]

mod generate;
mod sign;
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
}

#[derive(pretty_error_debug::Debug, thiserror::Error)]
enum MainError {
    #[error("could not generate key")]
    GenKey(#[from] generate::Error),
    #[error("could not verify file")]
    Verify(#[from] verify::Error),
    #[error("could not sign file")]
    Sign(#[from] sign::Error),
}

fn main() -> Result<(), MainError> {
    let args = Cli::parse();
    match args.subcommand {
        CliSubcommand::GenKey(args) => generate::main(args)?,
        CliSubcommand::Verify(args) => verify::main(args)?,
        CliSubcommand::Sign(args) => sign::main(args)?,
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
