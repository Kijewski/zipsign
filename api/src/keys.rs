//! Key encoding and decoding utilities

use crate::{KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SigningKey, VerifyingKey};

/// PEM tag used for public (verifying) keys
pub const PUBLIC_KEY_PEM_TAG: &str = "ZIPSIGN PUBLIC KEY";

/// PEM tag used for private (signing) keys
pub const PRIVATE_KEY_PEM_TAG: &str = "ZIPSIGN PRIVATE KEY";

crate::Error! {
    /// An error returned by [`parse_signing_key`] and [`parse_verifying_key`]
    pub struct ParseKeyError(ParseKey) {
        #[error("expected key length {0}, got {1}")]
        Length(usize, usize),
        #[error("the PEM data could not be parsed")]
        Pem(#[source] pem::PemError),
        #[error("expected PEM tag {0:?}, got {1:?}")]
        Tag(&'static str, String),
        #[error("the key data was invalid")]
        Key(#[source] ed25519_dalek::SignatureError),
    }
}

/// Encode a signing (private) key as a PEM string
pub fn encode_signing_key(key: &SigningKey) -> String {
    pem::encode(&pem::Pem::new(PRIVATE_KEY_PEM_TAG, key.to_keypair_bytes()))
}

/// Encode a verifying (public) key as a PEM string
pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    pem::encode(&pem::Pem::new(PUBLIC_KEY_PEM_TAG, key.as_bytes()))
}

/// Parse a signing key from either raw bytes (64-byte keypair) or PEM format
pub fn parse_signing_key(input: &[u8]) -> Result<SigningKey, ParseKeyError> {
    let bytes = decode_key(input, PRIVATE_KEY_PEM_TAG, KEYPAIR_LENGTH)?;
    let mut arr = [0u8; KEYPAIR_LENGTH];
    arr.copy_from_slice(&bytes);
    SigningKey::from_keypair_bytes(&arr).map_err(|e| ParseKey::Key(e).into())
}

/// Parse a verifying key from either raw bytes (32-byte key) or PEM format
pub fn parse_verifying_key(input: &[u8]) -> Result<VerifyingKey, ParseKeyError> {
    let bytes = decode_key(input, PUBLIC_KEY_PEM_TAG, PUBLIC_KEY_LENGTH)?;
    let mut arr = [0u8; PUBLIC_KEY_LENGTH];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| ParseKey::Key(e).into())
}

/// Extract raw key bytes from either PEM or raw-byte input, validating length
fn decode_key(
    input: &[u8],
    expected_tag: &'static str,
    expected_len: usize,
) -> Result<Vec<u8>, ParseKeyError> {
    let begin = format!("-----BEGIN {}-----", expected_tag);
    if input.starts_with(begin.as_bytes()) {
        let p = pem::parse(input).map_err(ParseKey::Pem)?;
        if p.tag() != expected_tag {
            return Err(ParseKey::Tag(expected_tag, p.tag().to_owned()).into());
        }
        let contents = p.contents();
        if contents.len() != expected_len {
            return Err(ParseKey::Length(expected_len, contents.len()).into());
        }
        Ok(contents.to_owned())
    } else {
        if input.len() != expected_len {
            return Err(ParseKey::Length(expected_len, input.len()).into());
        }
        Ok(input.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SecretKey;

    use super::*;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&SecretKey::default())
    }

    #[test]
    fn encode_signing_key_has_correct_pem_header() {
        let pem = encode_signing_key(&test_signing_key());
        assert!(
            pem.starts_with(&format!("-----BEGIN {}-----", PRIVATE_KEY_PEM_TAG)),
            "unexpected header: {pem}",
        );
    }

    #[test]
    fn encode_verifying_key_has_correct_pem_header() {
        let pem = encode_verifying_key(&test_signing_key().verifying_key());
        assert!(
            pem.starts_with(&format!("-----BEGIN {}-----", PUBLIC_KEY_PEM_TAG)),
            "unexpected header: {pem}",
        );
    }

    #[test]
    fn pem_signing_key_round_trip() {
        let key = test_signing_key();
        let pem = encode_signing_key(&key);
        let parsed = parse_signing_key(pem.as_bytes()).expect("parse failed");
        assert_eq!(key.to_keypair_bytes(), parsed.to_keypair_bytes());
    }

    #[test]
    fn pem_verifying_key_round_trip() {
        let key = test_signing_key().verifying_key();
        let pem = encode_verifying_key(&key);
        let parsed = parse_verifying_key(pem.as_bytes()).expect("parse failed");
        assert_eq!(key.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn parse_signing_key_from_raw_bytes() {
        let key = test_signing_key();
        let parsed = parse_signing_key(&key.to_keypair_bytes()).expect("parse failed");
        assert_eq!(key.to_keypair_bytes(), parsed.to_keypair_bytes());
    }

    #[test]
    fn parse_verifying_key_from_raw_bytes() {
        let key = test_signing_key().verifying_key();
        let parsed = parse_verifying_key(key.as_bytes()).expect("parse failed");
        assert_eq!(key.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn parse_signing_key_wrong_tag() {
        let pem = encode_verifying_key(&test_signing_key().verifying_key());
        let err = parse_signing_key(pem.as_bytes()).expect_err("should fail");
        assert!(
            format!("{err}").contains("expected key length 64"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_verifying_key_wrong_tag() {
        let pem = encode_signing_key(&test_signing_key());
        let err = parse_verifying_key(pem.as_bytes()).expect_err("should fail");
        assert!(
            format!("{err}").contains("expected key length 32"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_signing_key_wrong_length_raw() {
        let err = parse_signing_key(&[0u8; 16]).expect_err("should fail");
        assert!(
            format!("{err}").contains("expected key length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_verifying_key_wrong_length_raw() {
        let err = parse_verifying_key(&[0u8; 16]).expect_err("should fail");
        assert!(
            format!("{err}").contains("expected key length"),
            "unexpected error: {err}"
        );
    }
}
