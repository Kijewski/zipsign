mod generate;
mod sign;
mod verify;

use clap::{Parser, Subcommand};

// "\x0c\x04\x01" -- form feed, end of text, start of header
// "ed25519ph" -- used algorithm
// "\x00\x00" -- version number in network byte order
const MAGIC_HEADER: &[u8; 14] = b"\x0c\x04\x01ed25519ph\x00\x00";
const HEADER_SIZE: usize = 16;
type SignatureCountLeInt = u16;

fn main() -> Result<(), MainError> {
    let args = Cli::parse();
    match args.subcommand {
        CliSubcommand::GenKey(args) => generate::main(args)?,
        CliSubcommand::Verify(args) => verify::main(args)?,
        CliSubcommand::Sign(args) => sign::main(args)?,
    }
    Ok(())
}

/// Sign a file with an ed25519 signing key.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    subcommand: CliSubcommand,
}

#[derive(Debug, Subcommand, Clone)]
enum CliSubcommand {
    GenKey(generate::Cli),
    Verify(verify::Cli),
    Sign(sign::Cli),
}

#[derive(pretty_error_debug::Debug, thiserror::Error)]
enum MainError {
    #[error("could not generate key")]
    GenKey(#[from] generate::Error),
    #[error("could not verify file")]
    Verify(#[from] verify::Error),
    #[error("could not sign file")]
    Sign(#[from] sign::Error),
}

const EPOCH: u32 = 978307200; // 2001-01-01 00:00:00 Z

const GZIP_START: &[u8; 10] = {
    let [m1, m2, m3, m4] = EPOCH.to_le_bytes();
    &[
        0x1f, 0x8b, // gzip: magic number
        0x08, // gzip: compression method (deflate)
        0x10, // gzip: flags (binary, no checksum, no extra fields, no name, has comment)
        m1, m2, m3, m4,   // gzip: modification time
        0x00, // gzip: extra flags (unset)
        0xff, // gzip: Operating system ID: unknown
    ]
};

const GZIP_END: &[u8; 14] = &[
    0x00, // NUL terminator
    0x01, // deflate: block header (final block, uncompressed)
    0x00, 0x00, // deflate: length
    0xff, 0xff, // deflate: negated length
    0, 0, 0, 0, // gzip: crc32 of uncompressed data
    0, 0, 0, 0, // total uncompressed size
];

const GZIP_EXTRA: usize = GZIP_START.len() + GZIP_END.len() + u64::BITS as usize / 4;
