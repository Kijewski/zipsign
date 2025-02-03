use std::fs::OpenOptions;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::prelude::OpenOptionsExt;
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{KEYPAIR_LENGTH, SigningKey};
use rand_core::OsRng;

/// Generate a signing key
#[derive(Debug, Parser, Clone)]
pub(crate) struct Cli {
    /// Private key file to create
    private_key: PathBuf,
    /// Verifying key (public key) file to create
    verifying_key: PathBuf,
    /// Don't create new key pair, but extract public key from private key
    #[arg(long, short = 'e')]
    extract: bool,
    /// Overwrite output files if they exists
    #[arg(long, short = 'f')]
    force: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("could not open {1:?} for writing")]
    OpenWrite(#[source] std::io::Error, PathBuf),
    #[error("could not open {1:?} for reading")]
    OpenRead(#[source] std::io::Error, PathBuf),
    #[error("could not write to {1:?}")]
    Write(#[source] std::io::Error, PathBuf),
    #[error("could not read from {1:?}")]
    Read(#[source] std::io::Error, PathBuf),
    #[error("no valid key found in from {1:?}")]
    IllegalKey(#[source] ed25519_dalek::SignatureError, PathBuf),
}

pub(crate) fn main(args: Cli) -> Result<(), Error> {
    let key = if args.extract {
        let result = OpenOptions::new().read(true).open(&args.private_key);
        let mut f = match result {
            Ok(f) => f,
            Err(err) => return Err(Error::OpenRead(err, args.private_key)),
        };
        let mut key = [0; KEYPAIR_LENGTH];
        if let Err(err) = f.read_exact(&mut key) {
            return Err(Error::Read(err, args.private_key));
        }
        match SigningKey::from_keypair_bytes(&key) {
            Ok(key) => key,
            Err(err) => return Err(Error::IllegalKey(err, args.private_key)),
        }
    } else {
        let key: SigningKey = SigningKey::generate(&mut OsRng);
        let result = OpenOptions::new()
            .write(true)
            .create(true)
            .create_new(!args.force)
            .truncate(true)
            .mode(0o600)
            .open(&args.private_key);
        let mut f = match result {
            Ok(f) => f,
            Err(err) => return Err(Error::OpenWrite(err, args.private_key)),
        };
        f.write_all(&key.to_keypair_bytes())
            .map_err(|err| Error::Write(err, args.private_key))?;
        key
    };

    let result = OpenOptions::new()
        .write(true)
        .create(true)
        .create_new(!args.force)
        .truncate(true)
        .open(&args.verifying_key);
    let mut f = match result {
        Ok(f) => f,
        Err(err) => return Err(Error::OpenWrite(err, args.verifying_key)),
    };
    f.write_all(key.verifying_key().as_bytes())
        .map_err(|err| Error::Write(err, args.verifying_key))
}

#[allow(dead_code)]
trait NotUnixOpenOptionsExt {
    #[inline(always)]
    fn mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}

#[cfg(not(unix))]
impl NotUnixOpenOptionsExt for OpenOptions {}
