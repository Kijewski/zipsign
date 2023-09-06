use std::fs::OpenOptions;
use std::io::Read;
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{Signature, SignatureError, VerifyingKey};
use mmarinus::{perms, Map, Private};

pub fn main(args: Cli) -> Result<(), Error> {
    let mut key = [0; 32];
    OpenOptions::new()
        .read(true)
        .open(&args.verifying_key)
        .map_err(Error::KeyOpen)?
        .read_exact(&mut key)
        .map_err(Error::KeyRead)?;
    let key = VerifyingKey::from_bytes(&key).map_err(Error::KeyValidate)?;

    let mut sign = [0; 64];
    OpenOptions::new()
        .read(true)
        .open(&args.signature)
        .map_err(Error::SignOpen)?
        .read_exact(&mut sign)
        .map_err(Error::SignRead)?;
    let sign = Signature::from_bytes(&sign);

    let result = key.verify_strict(&Map::load(&args.file, Private, perms::Read)?, &sign);
    result.map_err(Error::Signature)?;

    Ok(())
}

/// Verify a signature
#[derive(Debug, Parser)]
pub struct Cli {
    /// Verifying key
    verifying_key: PathBuf,
    /// Signed file
    file: PathBuf,
    /// Signature file or .zip file generated with "zip-file"
    signature: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not open verifying key file for reading")]
    KeyOpen(#[source] std::io::Error),
    #[error("could not read verifying key file")]
    KeyRead(#[source] std::io::Error),
    #[error("verifying key was invalid")]
    KeyValidate(#[source] SignatureError),
    #[error("could not open signature file for reading")]
    SignOpen(#[source] std::io::Error),
    #[error("could not read signature file")]
    SignRead(#[source] std::io::Error),
    #[error("could not map file")]
    FileMap(#[from] mmarinus::Error<()>),
    #[error("wrong signature")]
    Signature(#[from] SignatureError),
}
