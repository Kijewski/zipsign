use std::fs::OpenOptions;
use std::io::Read;
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{Signature, SignatureError, VerifyingKey};
use memmap2::Mmap;

pub fn main(args: Cli) -> Result<(), Error> {
    // read key
    let mut key = [0; 32];
    let mut f = match OpenOptions::new().read(true).open(&args.verifying_key) {
        Ok(f) => f,
        Err(err) => return Err(Error::Open(err, args.verifying_key)),
    };
    if let Err(err) = f.read_exact(&mut key) {
        return Err(Error::Read(err, args.verifying_key));
    }
    let key = match VerifyingKey::from_bytes(&key) {
        Ok(key) => key,
        Err(err) => return Err(Error::VerifyingKeyInvalid(err, args.verifying_key)),
    };
    drop(f);

    // read signature
    let mut sign = [0; 64];
    let mut f = match OpenOptions::new().read(true).open(&args.signature) {
        Ok(f) => f,
        Err(err) => return Err(Error::Open(err, args.signature)),
    };
    if let Err(err) = f.read_exact(&mut sign) {
        return Err(Error::Read(err, args.signature));
    }
    let sign = Signature::from_bytes(&sign);
    drop(f);

    // map "file"
    let f = match OpenOptions::new().read(true).open(&args.file) {
        Ok(f) => f,
        Err(err) => return Err(Error::Open(err, args.file)),
    };
    let file = match unsafe { Mmap::map(&f) } {
        Ok(file) => file,
        Err(err) => return Err(Error::Mmap(err, args.file)),
    };
    drop(f);

    // verify signature
    key.verify_strict(&file, &sign).map_err(Error::Signature)?;
    println!("OK");
    Ok(())
}

/// Verify a signature
#[derive(Debug, Parser)]
pub struct Cli {
    /// Verifying key
    verifying_key: PathBuf,
    /// Signed file
    file: PathBuf,
    /// Signature file or .zip file generated with "zip" command
    signature: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not open {1:?} for reading")]
    Open(#[source] std::io::Error, PathBuf),
    #[error("could not read from {1:?}")]
    Read(#[source] std::io::Error, PathBuf),
    #[error("could not mmap {1:?} for reading")]
    Mmap(#[source] std::io::Error, PathBuf),
    #[error("verify key {1:?} invalid")]
    VerifyingKeyInvalid(#[source] SignatureError, PathBuf),
    #[error("wrong signature")]
    Signature(#[source] SignatureError),
}
