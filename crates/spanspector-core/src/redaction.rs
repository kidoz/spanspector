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
    ///
    /// The class is inferred from `key` with the built-in classifier. To honor a
    /// caller-supplied [`RedactionPolicy`] (with extra keys), prefer
    /// [`RedactionPolicy::redacted_value`].
    pub fn new(key: &str, value: &str) -> Self {
        Self::with_class(classify_sensitive_key(key), value)
    }

    /// Build a redacted representation with an explicit [`SensitiveClass`].
    ///
    /// Used when the class is decided by a [`RedactionPolicy`] rather than the
    /// built-in key classifier. The raw `value` is still never stored — only its
    /// length and digest.
    pub fn with_class(class: SensitiveClass, value: &str) -> Self {
        Self {
            class,
            present: true,
            redacted: true,
            size_bytes: value.len(),
            digest: sha256_digest(value),
        }
    }
}

/// An extensible classifier for sensitive field keys.
///
/// The built-in sensitive key parts are always active; a policy layers
/// **additional** key substrings on top so a downstream service can redact
/// domain-specific fields the core list does not know about — for example a
/// database server adding `sql.literal`, `connection_string`, `admin_token`, or
/// `encryption_key_alias`. Extra keys are matched against the same normalized key
/// form as the defaults, so separators (`.`, `-`, camelCase) cannot smuggle a
/// value past them.
///
/// A policy never *removes* a built-in sensitive key: extensions can only widen
/// what is redacted, never narrow it.
///
/// ```
/// use spanspector_core::{RedactionPolicy, SensitiveClass};
///
/// let policy = RedactionPolicy::new()
///     .with_key("sql.literal", SensitiveClass::Secret)
///     .with_key("connection_string", SensitiveClass::ConnectionString);
///
/// assert!(policy.is_sensitive_key("query.sql.literal"));
/// assert_eq!(
///     policy.classify_sensitive_key("db.connection-string"),
///     SensitiveClass::ConnectionString,
/// );
/// // Built-in keys still redact under any policy.
/// assert!(policy.is_sensitive_key("auth.token"));
/// ```
#[derive(Clone, Debug, Default)]
pub struct RedactionPolicy {
    /// `(normalized substring, class)` pairs added on top of the defaults.
    extra: Vec<(String, SensitiveClass)>,
}

impl RedactionPolicy {
    /// Create a policy with only the built-in sensitive keys active.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one extra sensitive key substring with the class to report for it.
    ///
    /// The substring is normalized the same way keys are, so `"SQL.Literal"` and
    /// `"sql_literal"` register the same matcher.
    #[must_use]
    pub fn with_key(mut self, substring: impl AsRef<str>, class: SensitiveClass) -> Self {
        let normalized = normalize_key(substring.as_ref());
        if !normalized.is_empty() {
            self.extra.push((normalized, class));
        }
        self
    }

    /// Add many extra `(substring, class)` sensitive keys at once.
    #[must_use]
    pub fn with_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = (S, SensitiveClass)>,
        S: AsRef<str>,
    {
        for (substring, class) in keys {
            self = self.with_key(substring, class);
        }
        self
    }

    /// Return true when `key` is sensitive under the defaults or any extra key.
    #[must_use]
    pub fn is_sensitive_key(&self, key: &str) -> bool {
        let normalized = normalize_key(key);
        default_is_sensitive(&normalized) || self.matches_extra(&normalized).is_some()
    }

    /// Classify `key`, preferring an extra-key class over the built-in inference.
    ///
    /// Extra keys win so a downstream caller can label, say, `sql.literal` as
    /// [`SensitiveClass::Secret`] even though the built-in classifier would never
    /// have flagged it.
    #[must_use]
    pub fn classify_sensitive_key(&self, key: &str) -> SensitiveClass {
        let normalized = normalize_key(key);
        if let Some(class) = self.matches_extra(&normalized) {
            return class;
        }
        classify_normalized(&normalized)
    }

    /// Build a [`RedactedValue`] for `key`/`value` using this policy's class.
    #[must_use]
    pub fn redacted_value(&self, key: &str, value: &str) -> RedactedValue {
        RedactedValue::with_class(self.classify_sensitive_key(key), value)
    }

    fn matches_extra(&self, normalized: &str) -> Option<SensitiveClass> {
        self.extra
            .iter()
            .find(|(part, _)| normalized.contains(part.as_str()))
            .map(|(_, class)| *class)
    }
}

/// Return true when a field key must not be serialized with a raw value.
///
/// Uses the built-in key list only. For extensible classification, build a
/// [`RedactionPolicy`].
pub fn is_sensitive_key(key: &str) -> bool {
    default_is_sensitive(&normalize_key(key))
}

fn default_is_sensitive(normalized: &str) -> bool {
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
    classify_normalized(&normalize_key(key))
}

fn classify_normalized(normalized: &str) -> SensitiveClass {
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

    #[test]
    fn policy_adds_extra_keys_without_dropping_builtins() {
        let policy = RedactionPolicy::new()
            .with_key("sql.literal", SensitiveClass::Secret)
            .with_key("admin_token", SensitiveClass::Token);

        // Extra keys redact, with separator normalization.
        assert!(policy.is_sensitive_key("query.sql-literal"));
        assert_eq!(
            policy.classify_sensitive_key("request.admin.token"),
            SensitiveClass::Token
        );
        // Built-in keys still redact under any policy.
        assert!(policy.is_sensitive_key("auth.token"));
        // An unrelated key remains non-sensitive.
        assert!(!policy.is_sensitive_key("order.id"));
    }

    #[test]
    fn policy_extra_class_wins_over_builtin_inference() {
        // `connection_string` is not a built-in part, so the default classifier
        // would call it a generic secret; the policy pins it precisely.
        let policy =
            RedactionPolicy::new().with_key("connection_string", SensitiveClass::ConnectionString);
        assert_eq!(
            policy.classify_sensitive_key("db.connection-string"),
            SensitiveClass::ConnectionString
        );
        assert!(
            policy
                .redacted_value("db.connection-string", "postgres://u:p@h/db")
                .redacted
        );
    }

    #[test]
    fn default_policy_matches_free_functions() {
        let policy = RedactionPolicy::new();
        for key in ["password", "auth.token", "order.id", "input.class"] {
            assert_eq!(policy.is_sensitive_key(key), is_sensitive_key(key));
        }
    }
}
