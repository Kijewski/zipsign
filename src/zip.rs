use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use ed25519_dalek::{SignatureError, Signer, SigningKey};
use memmap2::Mmap;
use zip::result::ZipError;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

pub fn main(args: Cli) -> Result<(), Error> {
    let name = args
        .file
        .file_name()
        .ok_or(Error::NoFileName)?
        .to_str()
        .ok_or(Error::NoFileName)?;

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
        .open(&args.zip);
    let mut zip_file = match result {
        Ok(zip_file) => zip_file,
        Err(err) => return Err(Error::OpenWrite(err, args.zip)),
    };
    if let Err(err) = zip_file.write_all(&signature.to_bytes()) {
        return Err(Error::Write(err, args.zip));
    }

    // get permissions
    let permissions = match args.permissions {
        Some(permissions) => permissions.0 as u32,
        None => match is_executable::is_executable(&args.file) {
            true => 0o755,
            false => 0o644,
        },
    };

    // write ZIP content
    let mut zip_file = ZipWriter::new(zip_file);
    let method = match args.method.unwrap_or_default() {
        NamedCompressionMethod::Stored => CompressionMethod::Stored,
        NamedCompressionMethod::Deflated => CompressionMethod::Deflated,
        NamedCompressionMethod::Bzip2 => CompressionMethod::Bzip2,
        NamedCompressionMethod::Zstd => CompressionMethod::Zstd,
    };
    let options = FileOptions::default()
        .compression_method(method)
        .compression_level(args.level)
        .unix_permissions(permissions);
    if let Err(err) = zip_file.start_file(name, options) {
        return Err(Error::Zip(err, args.zip));
    }
    if let Err(err) = zip_file.write_all(&file) {
        return Err(Error::Write(err, args.zip));
    }
    if let Err(err) = zip_file.finish() {
        return Err(Error::Zip(err, args.zip));
    }

    Ok(())
}

/// ZIP a file and store the signature
#[derive(Debug, Parser)]
pub struct Cli {
    /// Private key
    private_key: PathBuf,
    /// File to sign
    file: PathBuf,
    /// ZIP file to (over)write
    zip: PathBuf,
    /// Compression method (stored | *deflated | bzip2 | zstd, *=default)
    #[arg(short, long)]
    method: Option<NamedCompressionMethod>,
    /// Compression level
    #[arg(short, long)]
    level: Option<i32>,
    /// Unix-style permissions, default: 0o755 if "FILE" is executable, otherwise 0o644
    #[arg(short, long)]
    permissions: Option<Permissions>,
}

#[derive(Debug, Clone, Copy, Default, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
enum NamedCompressionMethod {
    Stored,
    #[default]
    Deflated,
    Bzip2,
    Zstd,
}

#[derive(Debug, Clone, Copy)]
struct Permissions(u16);

impl FromStr for Permissions {
    type Err = <u16 as num_traits::Num>::FromStrRadixErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_int::parse(s)?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("input file has no UTF-8 name")]
    NoFileName,
    #[error("could not sign file")]
    FileSign(#[source] SignatureError),
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
    #[error("could not write to ZIP file {1:?}")]
    Zip(#[source] ZipError, PathBuf),
}
