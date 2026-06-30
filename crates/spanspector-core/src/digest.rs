//! Deterministic content digests used for correlation without storing raw data.

use sha2::{Digest, Sha256};

/// Return a stable `sha256:<hex>` digest of `value`.
///
/// The digest lets diagnostics correlate identical inputs (for example, the same
/// request body across two failures) without ever serializing the original
/// bytes. It is deterministic for the same input, which keeps trace output and
/// snapshots reproducible.
///
/// ```
/// let digest = spanspector_core::sha256_digest("hello");
/// assert_eq!(
///     digest,
///     "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
/// );
/// ```
pub fn sha256_digest(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        encoded.push(hex_nibble(byte >> 4));
        encoded.push(hex_nibble(byte & 0x0f));
    }
    encoded
}

fn hex_nibble(nibble: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[nibble as usize] as char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_prefixed_and_lowercase_hex() {
        let digest = sha256_digest("");
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
        assert!(
            digest
                .trim_start_matches("sha256:")
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn digest_is_stable_for_same_input() {
        assert_eq!(sha256_digest("same"), sha256_digest("same"));
        assert_ne!(sha256_digest("a"), sha256_digest("b"));
    }
}
