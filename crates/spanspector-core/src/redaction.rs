//! Sensitive-value classification and redaction primitives.
//!
//! Redaction is a core feature, not an optional layer. The functions here decide
//! whether a field key names a secret and, if so, produce a [`RedactedValue`]
//! that retains only safe shape metadata (class, size, digest) — never the raw
//! value.

use serde::{Deserialize, Serialize};

use crate::digest::sha256_digest;

/// Substrings that, when present in a normalized field key, mark it sensitive.
///
/// Matching is substring-based against a normalized key, so `auth.token`,
/// `Authorization`, and `refresh-token` all match. When unsure, prefer adding a
/// term here: over-redaction is safe, under-redaction is not.
const SENSITIVE_KEY_PARTS: &[&str] = &[
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "db_url",
    "jwt",
    "passphrase",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session",
    "token",
];

/// Classification for values that must never be emitted raw.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveClass {
    /// Password or passphrase.
    Password,
    /// Access token, refresh token, JWT, API key, or bearer credential.
    Token,
    /// Session identifier or cookie value.
    Cookie,
    /// Private key material.
    PrivateKey,
    /// Database or infrastructure connection string.
    ConnectionString,
    /// Sensitive value without a more specific classification.
    Secret,
}

/// A redacted stand-in for a sensitive field value.
///
/// It keeps only what is safe to share: the inferred class, whether a value was
/// present, the byte length (useful for spotting truncation or empties), and a
/// stable digest for correlation. The raw value is never stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedValue {
    /// Sensitive-data classification inferred from the field key.
    pub class: SensitiveClass,
    /// Whether a value was present before redaction.
    pub present: bool,
    /// Whether the raw value was removed (always `true` for this type).
    pub redacted: bool,
    /// UTF-8 byte length of the original value.
    pub size_bytes: usize,
    /// Stable `sha256:` digest for correlation without storing the original.
    pub digest: String,
}

impl RedactedValue {
    /// Build a redacted representation from a field key and raw string value.
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            class: classify_sensitive_key(key),
            present: true,
            redacted: true,
            size_bytes: value.len(),
            digest: sha256_digest(value),
        }
    }
}

/// Return true when a field key must not be serialized with a raw value.
pub fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|part| normalized.contains(part))
}

/// Infer a [`SensitiveClass`] from a field key.
///
/// The order of checks matters: more specific classes (password, cookie, private
/// key, connection string) are tested before the broad token class so a key like
/// `session_token` classifies as a cookie/session rather than a generic token.
pub fn classify_sensitive_key(key: &str) -> SensitiveClass {
    let normalized = normalize_key(key);

    if normalized.contains("password") || normalized.contains("passphrase") {
        SensitiveClass::Password
    } else if normalized.contains("private_key") {
        SensitiveClass::PrivateKey
    } else if normalized.contains("cookie") || normalized.contains("session") {
        SensitiveClass::Cookie
    } else if normalized.contains("db_url") || normalized.contains("connection") {
        SensitiveClass::ConnectionString
    } else if normalized.contains("token")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("authorization")
        || normalized.contains("jwt")
    {
        SensitiveClass::Token
    } else {
        SensitiveClass::Secret
    }
}

/// Normalize a key for matching: lowercase ASCII alphanumerics, every other byte
/// becomes `_`. This collapses `auth.token`, `auth-token`, and `AuthToken` to the
/// same shape so separators cannot be used to smuggle a secret past the filter.
fn normalize_key(key: &str) -> String {
    key.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_key_matching_handles_common_secret_names() {
        for key in [
            "password",
            "api.key",
            "Authorization",
            "session_cookie",
            "refresh-token",
            "database.db_url",
            "private-key",
            "user.passphrase",
        ] {
            assert!(is_sensitive_key(key), "{key} should be sensitive");
        }
    }

    #[test]
    fn non_sensitive_keys_are_not_flagged() {
        for key in ["ai.kind", "input.class", "order.id", "perf.duration_ms"] {
            assert!(!is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn classification_prefers_specific_classes() {
        assert_eq!(classify_sensitive_key("password"), SensitiveClass::Password);
        assert_eq!(
            classify_sensitive_key("session_token"),
            SensitiveClass::Cookie
        );
        assert_eq!(
            classify_sensitive_key("db_url"),
            SensitiveClass::ConnectionString
        );
        assert_eq!(classify_sensitive_key("api_key"), SensitiveClass::Token);
        assert_eq!(classify_sensitive_key("secret"), SensitiveClass::Secret);
    }

    #[test]
    fn redacted_value_never_contains_raw_secret() {
        let value = RedactedValue::new("auth.token", "raw-secret-token");
        let json = serde_json::to_string(&value).unwrap();
        assert!(!json.contains("raw-secret-token"));
        assert!(json.contains("sha256:"));
        assert_eq!(value.size_bytes, "raw-secret-token".len());
    }

    #[test]
    fn redacted_digest_is_stable_for_same_value() {
        let first = RedactedValue::new("password", "same-secret");
        let second = RedactedValue::new("password", "same-secret");
        assert_eq!(first.digest, second.digest);
    }
}
