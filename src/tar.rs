use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use bzip2::write::BzEncoder;
use clap::Parser;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey};
use flate2::write::GzEncoder;
use memmap2::Mmap;
use xz2::write::XzEncoder;

pub fn main(args: Cli) -> Result<(), Error> {
    let name = args
        .file
        .file_name()
        .ok_or(Error::NoFileName)?
        .to_str()
        .ok_or(Error::NoFileName)?;
    if name.len() >= 100 {
        return Err(Error::NoFileName);
    }

    let level = match args.level.unwrap_or(9) {
        level @ 0..=9 => level as u32,
        level => return Err(Error::CompressionLevel(level)),
    };

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
    let src = match unsafe { Mmap::map(&f) } {
        Ok(src) => src,
        Err(err) => return Err(Error::Mmap(err, args.file)),
    };
    drop(f);
    let signature = key.try_sign(&src).map_err(Error::FileSign)?;

    // get permissions
    let permissions = match args.permissions {
        Some(permissions) => permissions.0 as u32,
        None => match is_executable::is_executable(&args.file) {
            true => 0o755,
            false => 0o644,
        },
    };

    // write .tar file
    let dest: Result<File, std::io::Error> = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.tar);
    let dest = match dest {
        Ok(dest) => dest,
        Err(err) => return Err(Error::OpenWrite(err, args.tar)),
    };
    let dest = match args.method.unwrap_or_default() {
        CompressionMethod::Uncompressed => CompressionStream::Uncompressed(BufWriter::new(dest)),
        CompressionMethod::Bzip2 => {
            let level = bzip2::Compression::new(level);
            CompressionStream::Bzip2(BzEncoder::new(dest, level))
        },
        CompressionMethod::Gzip => {
            let level = flate2::Compression::new(level);
            CompressionStream::Gzip(GzEncoder::new(dest, level))
        },
        CompressionMethod::Xz => CompressionStream::Xz(XzEncoder::new(dest, level)),
    };
    write_tar(dest, src, name, permissions, signature)
        .map_err(|err| Error::Write(err, args.tar))?;

    Ok(())
}

fn write_tar(
    mut dest: impl Write,
    src: Mmap,
    name: &str,
    permissions: u32,
    signature: Signature,
) -> std::io::Result<()> {
    // #[repr(C, packed(1))]
    // struct Header {
    //     name: [u8; 100],
    //     mode: [u8; 8],
    //     uid: [u8; 8],
    //     gid: [u8; 8],
    //     size: [u8; 12],
    //     mtime: [u8; 12],
    //     chksum: [u8; 8],
    //     typeflag: [u8; 1],
    //     linkname: [u8; 100],
    //     magic: [u8; 6],
    //     version: [u8; 2],
    //     uname: [u8; 32],
    //     gname: [u8; 32],
    //     devmajor: [u8; 8],
    //     devminor: [u8; 8],
    //     prefix: [u8; 155],
    //     _padding: [u8; 12],
    // }

    let mut header = [0u8; 512];
    write!(&mut header[0x0..][..100], "{}", name)?; // name
    write!(&mut header[0x64..][..8], "{:07o}", permissions & 0o777)?; // mode
    write!(&mut header[0x6c..][..8], "{:07o}", 0)?; // uid
    write!(&mut header[0x74..][..8], "{:07o}", 0)?; // gid
    write!(&mut header[0x7c..][..12], "{:011o}", src.len())?; // size
    write!(&mut header[0x88..][..12], "{:011o}", 978303600)?; // mtime (2001-01-01 00:00:00 Z)
    write!(&mut header[0x94..][..8], "{:<8}", "")?; // chksum
    // typeflag ('\0')
    // linkname ("")
    write!(&mut header[0x101..][..6], "ustar")?; // magic
    write!(&mut header[0x107..][..2], "00")?; // version
    write!(&mut header[0x109..][..32], "root")?; // uname
    write!(&mut header[0x129..][..32], "root")?; // gname
    write!(&mut header[0x149..][..8], "{:07o}", 0)?; // devmajor
    write!(&mut header[0x151..][..8], "{:07o}", 0)?; // devminor
    // prefix ("")
    let cksum: u32 = header.iter().map(|&v| v as u32).sum();
    write!(&mut header[0x94..][..8], "{cksum:06o}\0")?; // chksum

    dest.write_all(&header)?;
    dest.write_all(&src)?;

    const BLOCKSIZE: usize = 512;
    const EXTRA: usize = Signature::BYTE_SIZE;

    let pos = BLOCKSIZE + src.len();
    // rounded up to next multiple of 512
    let new_pos = if pos & (BLOCKSIZE - 1) != 0 {
        (pos | (BLOCKSIZE - 1)) + 1
    } else {
        pos
    };
    // is there enough room to put the signature at the end of the block?
    let new_pos = if new_pos - pos < EXTRA {
        new_pos
    } else {
        new_pos - EXTRA
    };
    // pad with zeroes
    match new_pos - pos {
        0 => {},
        bytes => {
            const PAD: &[u8; BLOCKSIZE - EXTRA] = &[0; BLOCKSIZE - EXTRA];
            dest.write_all(&PAD[..bytes])?;
        },
    }
    // write signature
    dest.write_all(&signature.to_bytes())
}

/// .tar a file and store the signature
#[derive(Debug, Parser)]
pub struct Cli {
    /// Private key
    private_key: PathBuf,
    /// File to sign
    file: PathBuf,
    /// .tar file to (over)write
    tar: PathBuf,
    /// Compression method (*uncompressed | bzip2 | gzip | xz, *=default)
    #[arg(short, long)]
    method: Option<CompressionMethod>,
    /// Compression level (0 - *9, *=default)
    #[arg(short, long)]
    level: Option<u8>,
    /// Unix-style permissions, default: 0o755 if "FILE" is executable, otherwise 0o644
    #[arg(short, long)]
    permissions: Option<Permissions>,
}

enum CompressionStream {
    Uncompressed(BufWriter<File>),
    Bzip2(BzEncoder<File>),
    Gzip(GzEncoder<File>),
    Xz(XzEncoder<File>),
}

impl Write for CompressionStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            CompressionStream::Uncompressed(s) => s.write(buf),
            CompressionStream::Bzip2(s) => s.write(buf),
            CompressionStream::Gzip(s) => s.write(buf),
            CompressionStream::Xz(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            CompressionStream::Uncompressed(s) => s.flush(),
            CompressionStream::Bzip2(s) => s.flush(),
            CompressionStream::Gzip(s) => s.flush(),
            CompressionStream::Xz(s) => s.flush(),
        }
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        match self {
            CompressionStream::Uncompressed(s) => s.write_vectored(bufs),
            CompressionStream::Bzip2(s) => s.write_vectored(bufs),
            CompressionStream::Gzip(s) => s.write_vectored(bufs),
            CompressionStream::Xz(s) => s.write_vectored(bufs),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            CompressionStream::Uncompressed(s) => s.write_all(buf),
            CompressionStream::Bzip2(s) => s.write_all(buf),
            CompressionStream::Gzip(s) => s.write_all(buf),
            CompressionStream::Xz(s) => s.write_all(buf),
        }
    }

    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        match self {
            CompressionStream::Uncompressed(s) => s.write_fmt(fmt),
            CompressionStream::Bzip2(s) => s.write_fmt(fmt),
            CompressionStream::Gzip(s) => s.write_fmt(fmt),
            CompressionStream::Xz(s) => s.write_fmt(fmt),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
enum CompressionMethod {
    #[default]
    Uncompressed,
    Bzip2,
    Gzip,
    Xz,
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
    #[error("input file has no UTF-8 name or name is longer than 99 bytes")]
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
    #[error("illgal compression level {0:?} not in 0..=9")]
    CompressionLevel(u8),
}
