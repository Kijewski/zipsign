use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

pub fn main(args: Cli) -> Result<(), Error> {
    let key: SigningKey = SigningKey::generate(&mut OsRng);

    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.private_key)
        .map_err(Error::PrivOpen)?
        .write_all(&key.to_keypair_bytes())
        .map_err(Error::PrivWrite)?;

    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.verifying_key)
        .map_err(Error::VerifyingOpen)?
        .write_all(key.verifying_key().as_bytes())
        .map_err(Error::VerifyingWrite)?;

    Ok(())
}

/// Generate a signing key
#[derive(Debug, Parser)]
pub struct Cli {
    /// Private key file to create
    private_key: PathBuf,
    /// Verifying key (public key) file to create
    verifying_key: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not open private key file for writing")]
    PrivOpen(#[source] std::io::Error),
    #[error("could not write to private key file")]
    PrivWrite(#[source] std::io::Error),
    #[error("could not open verifying key file for writing")]
    VerifyingOpen(#[source] std::io::Error),
    #[error("could not write to verifying key file")]
    VerifyingWrite(#[source] std::io::Error),
}
