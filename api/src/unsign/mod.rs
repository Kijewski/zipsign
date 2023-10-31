//! Functions to remove signatures from a file

#[cfg(feature = "unsign-tar")]
mod tar;
#[cfg(feature = "unsign-zip")]
mod zip;

#[cfg(feature = "unsign-tar")]
pub use self::tar::{copy_and_unsign_tar, UnsignTarError};
#[cfg(feature = "unsign-zip")]
pub use self::zip::{copy_and_unsign_zip, UnsignZipError};
