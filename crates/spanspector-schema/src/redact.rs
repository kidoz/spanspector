//! Redaction helpers that produce schema [`FieldValue`]s.
//!
//! These wrap the core redaction primitives ([`spanspector_core::is_sensitive_key`]
//! and [`RedactedValue`]) so callers can turn a raw `(key, value)` pair into a
//! schema-ready [`FieldValue`] that is redacted whenever the key is sensitive.

use std::collections::BTreeMap;

use spanspector_core::{RedactedValue, is_sensitive_key};

use crate::event::FieldValue;

/// Redact a single string field value when its key is classified sensitive.
///
/// ```
/// use spanspector_schema::{FieldValue, redact_field_value};
///
/// let safe = redact_field_value("input.class", "json.order.v1");
/// assert!(matches!(safe, FieldValue::Text(_)));
///
/// let secret = redact_field_value("auth.token", "super-secret");
/// assert!(matches!(secret, FieldValue::Redacted(_)));
/// ```
pub fn redact_field_value(key: &str, value: &str) -> FieldValue {
    if is_sensitive_key(key) {
        FieldValue::Redacted(RedactedValue::new(key, value))
    } else {
        FieldValue::Text(value.to_owned())
    }
}

/// Redact an iterator of `(key, value)` string pairs into a field map.
///
/// Keys are preserved; values are redacted per [`redact_field_value`]. The result
/// is a [`BTreeMap`], so field order is deterministic.
pub fn redact_fields<I, K, V>(fields: I) -> BTreeMap<String, FieldValue>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    fields
        .into_iter()
        .map(|(key, value)| {
            let key = key.into();
            let value = value.into();
            let field_value = redact_field_value(&key, &value);
            (key, field_value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_sensitive_values_stay_textual() {
        assert_eq!(
            redact_field_value("input.class", "json.order.v1"),
            FieldValue::Text("json.order.v1".to_owned())
        );
    }

    #[test]
    fn sensitive_values_are_redacted_without_raw_data() {
        let value = redact_field_value("password", "hunter2");
        let json = serde_json::to_string(&value).unwrap();
        assert!(!json.contains("hunter2"));
        assert!(json.contains("sha256:"));
    }

    #[test]
    fn redact_fields_redacts_only_sensitive_keys() {
        let map = redact_fields([("ai.kind", "command"), ("api_key", "abc123")]);
        assert!(matches!(map["ai.kind"], FieldValue::Text(_)));
        assert!(matches!(map["api_key"], FieldValue::Redacted(_)));
    }
}
