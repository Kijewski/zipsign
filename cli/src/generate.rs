use std::fs::OpenOptions;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::prelude::OpenOptionsExt;
use std::path::PathBuf;

use clap::Parser;
use ed25519_dalek::{SecretKey, SigningKey};
use zipsign_api::keys::{
    ParseKeyError, encode_signing_key, encode_verifying_key, parse_signing_key,
};

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
    /// Write keys in PEM format instead of raw binary
    #[arg(long, short = 'p')]
    pem: bool,
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
    #[error("no valid key found in {1:?}")]
    ParseKey(#[source] ParseKeyError, PathBuf),
    #[error("could not get random data")]
    Random(#[source] getrandom::Error),
}

pub(crate) fn main(args: Cli) -> Result<(), Error> {
    let key = if args.extract {
        let result = OpenOptions::new().read(true).open(&args.private_key);
        let mut f = match result {
            Ok(f) => f,
            Err(err) => return Err(Error::OpenRead(err, args.private_key)),
        };
        let mut buf = Vec::new();
        if let Err(err) = f.read_to_end(&mut buf) {
            return Err(Error::Read(err, args.private_key.clone()));
        }
        match parse_signing_key(&buf) {
            Ok(key) => key,
            Err(err) => return Err(Error::ParseKey(err, args.private_key)),
        }
    } else {
        let mut secret = SecretKey::default();
        getrandom::fill(secret.as_mut_slice()).map_err(Error::Random)?;
        let key = SigningKey::from_bytes(&{ secret });

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
        if args.pem {
            f.write_all(encode_signing_key(&key).as_bytes())
        } else {
            f.write_all(&key.to_keypair_bytes())
        }
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
    if args.pem {
        f.write_all(encode_verifying_key(&key.verifying_key()).as_bytes())
    } else {
        f.write_all(key.verifying_key().as_bytes())
    }
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
