use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use ed25519_dalek::{SignatureError, Signer, SigningKey};
use mmarinus::{perms, Map, Private};
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

    let mut key = [0; 64];
    OpenOptions::new()
        .read(true)
        .open(&args.private_key)
        .map_err(Error::KeyOpen)?
        .read_exact(&mut key)
        .map_err(Error::KeyRead)?;
    let key = SigningKey::from_keypair_bytes(&key)?;

    let file = Map::load(&args.file, Private, perms::Read)?;
    let signature = key.try_sign(&file).map_err(Error::FileSign)?;

    let mut zip_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(args.zip)
        .map_err(Error::ZipOpen)?;
    zip_file
        .write_all(&signature.to_bytes())
        .map_err(Error::ZipWrite)?;
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
        .unix_permissions(args.permissions.unwrap_or_default().0 as u32);
    zip_file
        .start_file(name, options)
        .map_err(Error::ZipAppend)?;
    zip_file.write_all(&file).map_err(Error::ZipWrite)?;
    drop(file);
    zip_file.finish().map_err(Error::ZipFinish)?;

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
    /// Unix-style permissions (default=0o644)
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

impl Default for Permissions {
    fn default() -> Self {
        Self(0o644)
    }
}

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
    #[error("could not open ZIP file for writing")]
    ZipOpen(#[source] std::io::Error),
    #[error("could not write to ZIP file")]
    ZipWrite(#[source] std::io::Error),
    #[error("could not append new file into ZIP file")]
    ZipAppend(#[source] ZipError),
    #[error("could not finish wriging ZIP file")]
    ZipFinish(#[source] ZipError),
}
