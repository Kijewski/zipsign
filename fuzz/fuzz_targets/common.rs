use zipsign_api::{SigningKey, VerifyingKey};

pub const CONTEXT: &[u8] = b"zipsign-fuzz";

/// Fixed key, so the seeds in `fuzz/seeds/` can be signed with the matching private key and
/// the fuzzer reaches the signature-matching code, not only the parsers in front of it.
pub fn verifying_keys() -> [VerifyingKey; 1] {
    [SigningKey::from_bytes(&[0x5a; 32]).verifying_key()]
}
