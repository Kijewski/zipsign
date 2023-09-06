use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{SignatureError, Signer, SigningKey};
use mmarinus::{perms, Map, Private};

pub fn main(args: Cli) -> Result<(), Error> {
    let mut key = [0; 64];
    OpenOptions::new()
        .read(true)
        .open(&args.private_key)
        .map_err(Error::KeyOpen)?
        .read_exact(&mut key)
        .map_err(Error::KeyRead)?;
    let key = SigningKey::from_keypair_bytes(&key)?;

    let result = key.try_sign(&Map::load(&args.file, Private, perms::Read)?);
    let signature = result.map_err(Error::FileSign)?;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(args.signature)
        .map_err(Error::SignOpen)?
        .write_all(&signature.to_bytes())
        .map_err(Error::SignWrite)?;

    Ok(())
}

/// Generate signature for a file
#[derive(Debug, Parser)]
pub struct Cli {
    /// Private key
    private_key: PathBuf,
    /// File to sign
    file: PathBuf,
    /// Signature to (over)write
    signature: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not open private key file for reading")]
    KeyOpen(#[source] std::io::Error),
    #[error("could not read private key file")]
    KeyRead(#[source] std::io::Error),
    #[error("private key was invalid")]
    KeyValidate(#[from] SignatureError),
    #[error("could not map file")]
    FileMap(#[from] mmarinus::Error<()>),
    #[error("could not sign file")]
    FileSign(#[source] SignatureError),
    #[error("could not open signature for writing")]
    SignOpen(#[source] std::io::Error),
    #[error("could not write to signature file")]
    SignWrite(#[source] std::io::Error),
}
