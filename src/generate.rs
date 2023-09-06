use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

pub fn main(args: Cli) -> Result<(), Error> {
    let key: SigningKey = SigningKey::generate(&mut OsRng);

    let result = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.private_key);
    let mut f = match result {
        Ok(f) => f,
        Err(err) => return Err(Error::Open(err, args.private_key)),
    };
    f.write_all(&key.to_keypair_bytes())
        .map_err(|err| Error::Write(err, args.private_key))?;
    drop(f);

    let result = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.verifying_key);
    let mut f = match result {
        Ok(f) => f,
        Err(err) => return Err(Error::Open(err, args.verifying_key)),
    };
    f.write_all(key.verifying_key().as_bytes())
        .map_err(|err| Error::Write(err, args.verifying_key))
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
    #[error("could not open {1:?} for writing")]
    Open(#[source] std::io::Error, PathBuf),
    #[error("could not write to {1:?}")]
    Write(#[source] std::io::Error, PathBuf),
}
