use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{SignatureError, Signer, SigningKey};
use memmap2::Mmap;

pub fn main(args: Cli) -> Result<(), Error> {
    // read signing key
    let mut key = [0; 64];
    let mut f = match OpenOptions::new().read(true).open(&args.private_key) {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenRead(err, args.private_key)),
    };
    if let Err(err) = f.read_exact(&mut key) {
        return Err(Error::Read(err, args.private_key));
    }
    let key = SigningKey::from_keypair_bytes(&key)
        .map_err(|err| Error::KeyValidate(err, args.private_key))?;
    drop(f);

    // map "file"
    let f = match OpenOptions::new().read(true).open(&args.file) {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenRead(err, args.file)),
    };
    let file = match unsafe { Mmap::map(&f) } {
        Ok(file) => file,
        Err(err) => return Err(Error::Mmap(err, args.file)),
    };
    drop(f);

    // write signature
    let signature = key.try_sign(&file).map_err(Error::FileSign)?;
    let result = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.signature);
    let mut f = match result {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenWrite(err, args.signature)),
    };
    f.write_all(&signature.to_bytes())
        .map_err(|err| Error::Write(err, args.signature))
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
    #[error("could not open {1:?} for reading")]
    OpenRead(#[source] std::io::Error, PathBuf),
    #[error("could not open {1:?} for writing")]
    OpenWrite(#[source] std::io::Error, PathBuf),
    #[error("could not read from {1:?}")]
    Read(#[source] std::io::Error, PathBuf),
    #[error("could not write to {1:?}")]
    Write(#[source] std::io::Error, PathBuf),
    #[error("could not mmap {1:?} for reading")]
    Mmap(#[source] std::io::Error, PathBuf),
    #[error("private key {1:?} was invalid")]
    KeyValidate(#[source] SignatureError, PathBuf),
    #[error("could not sign file")]
    FileSign(#[source] SignatureError),
}
