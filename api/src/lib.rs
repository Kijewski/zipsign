#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![allow(unknown_lints)]
#![warn(absolute_paths_not_starting_with_crate)]
#![warn(elided_lifetimes_in_paths)]
#![warn(explicit_outlives_requirements)]
#![warn(meta_variable_misuse)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(non_ascii_idents)]
#![warn(noop_method_call)]
#![warn(rust_2018_idioms)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(unreachable_pub)]
#![warn(unused_crate_dependencies)]
#![warn(unused_extern_crates)]
#![warn(unused_lifetimes)]
#![warn(unused_results)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "sign")]
pub mod sign;
#[cfg(feature = "verify")]
pub mod verify;

use std::io::{copy, Read};

#[doc(no_inline)]
pub use ed25519_dalek::{
    Digest, Sha512, Signature, SignatureError, SigningKey, VerifyingKey, KEYPAIR_LENGTH,
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

// "\x0c\x04\x01" -- form feed, end of text, start of header
// "ed25519ph" -- used algorithm
// "\x00\x00" -- version number in network byte order
/// Bytes preceeding signatures
pub const MAGIC_HEADER: &[u8; 14] = b"\x0c\x04\x01ed25519ph\x00\x00";

/// Total number of bytes in a [`MAGIC_HEADER`] + [`SignatureCountLeInt`]
pub const HEADER_SIZE: usize = 16;

/// Integer type to tell the number of signatures in a signed file, stored in little endian
pub type SignatureCountLeInt = u16;

const EPOCH: u32 = 978_307_200; // 2001-01-01 00:00:00 Z

/// Prefix of the signature block in a signed .tar.gz file
///
/// Followed by base64 encoded signatures string, the current stream position before this block
/// encoded as zero-padded 16 bytes hexadecimal string, and [`GZIP_END`]
/// [`GZIP_END`]
pub const GZIP_START: &[u8; 10] = {
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

/// Suffix of the signature block in a signed .tar.gz file
pub const GZIP_END: &[u8; 14] = &[
    0x00, // deflate: NUL terminator, end of comments
    0x01, // deflate: block header (final block, uncompressed)
    0x00, 0x00, // deflate: length
    0xff, 0xff, // deflate: negated length
    0, 0, 0, 0, // gzip: crc32 of uncompressed data
    0, 0, 0, 0, // gzip: total uncompressed size
];

/// Total overhead the signature block in a signed .tar.gz file excluding signature data
pub const GZIP_EXTRA: usize = GZIP_START.len() + GZIP_END.len() + u64::BITS as usize / 4;

/// Maximum number of bytes the encoded signatures may have
///
/// This number equates to 1022 signatures in a `.zip` file, and 767 signatures in `.tar.gz` file.
pub const BUF_LIMIT: usize = 1 << 16; // 64 kiB

/// Calculate the hash of an input file
pub fn prehash<I>(input: &mut I) -> std::io::Result<Sha512>
where
    I: ?Sized + Read,
{
    let mut prehashed_message = Sha512::new();
    let _: u64 = copy(input, &mut prehashed_message)?;
    Ok(prehashed_message)
}

/// A collection of all error this library can return
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub enum ZipsignError {
    /// An error returned by [`gather_signature_data()`][self::sign::gather_signature_data]
    #[cfg(feature = "sign")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
    GatherSignatureData(#[from] self::sign::GatherSignatureDataError),
    /// An error returned by [`read_signing_keys()`][self::sign::read_signing_keys]
    #[cfg(feature = "sign")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
    ReadSigningKeys(#[from] self::sign::ReadSigningKeysError),
    /// An error returned by [`copy_and_sign_tar()`][self::sign::copy_and_sign_tar]
    #[cfg(feature = "sign-tar")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sign-tar")))]
    SignTar(#[from] self::sign::SignTarError),
    /// An error returned by [`copy_and_sign_zip()`][self::sign::copy_and_sign_zip]
    #[cfg(feature = "sign-zip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sign-zip")))]
    SignZip(#[from] self::sign::SignZipError),

    /// No matching key/signature pair found
    #[cfg(feature = "verify")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
    NoMatch(#[from] self::verify::NoMatch),
    /// An error returned by [`collect_keys()`][self::verify::collect_keys]
    #[cfg(feature = "verify")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
    CollectKeys(#[from] self::verify::CollectKeysError),
    /// An error returned by [`read_signatures()`][self::verify::read_signatures]
    #[cfg(feature = "verify")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
    ReadSignatures(#[from] self::verify::ReadSignaturesError),
    /// An error returned by [`verify_tar()`][self::verify::verify_tar]
    #[cfg(feature = "verify-tar")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify-tar")))]
    VerifyTar(#[from] self::verify::VerifyTarError),
    /// An error retuned by [`verify_zip()`][self::verify::verify_zip]
    #[cfg(feature = "verify-zip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify-zip")))]
    VerifyZip(#[from] self::verify::VerifyZipError),

    /// An I/O occurred
    Io(#[from] std::io::Error),
}
