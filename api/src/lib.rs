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
#![allow(clippy::enum_variant_names)]
#![doc = include_str!("../README.md")]

mod constants;
pub mod sign;
pub mod verify;

use std::io::{copy, Read};

#[doc(no_inline)]
pub use ed25519_dalek::{
    Digest, Sha512, Signature, SignatureError, SigningKey, VerifyingKey, KEYPAIR_LENGTH,
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

/// Calculate the hash of an input file
pub fn prehash<I>(input: &mut I) -> std::io::Result<Sha512>
where
    I: ?Sized + Read,
{
    let mut prehashed_message = Sha512::new();
    let _: u64 = copy(input, &mut prehashed_message)?;
    Ok(prehashed_message)
}

/// A collection of all errors this library can return
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub enum ZipsignError {
    /// An error returned by [`gather_signature_data()`][self::sign::gather_signature_data]
    GatherSignatureData(#[from] self::sign::GatherSignatureDataError),
    /// An error returned by [`read_signing_keys()`][self::sign::read_signing_keys]
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
    NoMatch(#[from] self::verify::NoMatch),
    /// An error returned by [`collect_keys()`][self::verify::collect_keys]
    CollectKeys(#[from] self::verify::CollectKeysError),
    /// An error returned by [`read_signatures()`][self::verify::read_signatures]
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

macro_rules! Error {
    (
        $(#[$meta:meta])+
        $vis:vis struct $outer:ident($inner:ident) { $(
            $(#[$field_meta:meta])+
            $field:ident $(( $(
                $(#[$ty_meta:meta])*
                $field_type:ty
            ),+ $(,)? ))?
        ),+ $(,)? }
    ) => {
        $(#[$meta])+
        $vis struct $outer($inner);

        #[derive(Debug, thiserror::Error)]
        enum $inner { $(
            $(#[$field_meta])+
            $field $(( $(
                $(#[$ty_meta])* $field_type,
            )+ ))?,
        )+ }

        const _: () = {
            impl std::fmt::Debug for $outer {
                #[inline]
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    std::fmt::Debug::fmt(&self.0, f)
                }
            }

            impl std::fmt::Display for $outer {
                #[inline]
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    std::fmt::Display::fmt(&self.0, f)
                }
            }

            impl From<$inner> for $outer {
                #[inline]
                fn from(value: $inner) -> Self {
                    Self(value)
                }
            }

            impl std::error::Error for $outer {
                #[inline]
                fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                    self.0.source()
                }
            }
        };
    };
}

pub(crate) use Error;
