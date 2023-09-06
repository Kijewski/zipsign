mod generate;
mod sign;
mod verify;
mod zip;

use clap::{Parser, Subcommand};

fn main() -> Result<(), MainError> {
    let args = Cli::parse();
    match args.subcommand {
        CliSubcommand::GenKey(args) => generate::main(args)?,
        CliSubcommand::Verify(args) => verify::main(args)?,
        CliSubcommand::Sign(args) => sign::main(args)?,
        CliSubcommand::Zip(args) => zip::main(args)?,
    }
    Ok(())
}

/// Sign a file with an ed25519 signing key.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    subcommand: CliSubcommand,
}

#[derive(Debug, Subcommand)]
enum CliSubcommand {
    GenKey(generate::Cli),
    Verify(verify::Cli),
    Sign(sign::Cli),
    Zip(zip::Cli),
}

#[derive(pretty_error_debug::Debug, thiserror::Error)]
enum MainError {
    #[error("could not generate key")]
    GenKey(#[from] generate::Error),
    #[error("could not verify file")]
    Verify(#[from] verify::Error),
    #[error("could not sign file")]
    Sign(#[from] sign::Error),
    #[error("could not zip file")]
    Zip(#[from] zip::Error),
}
