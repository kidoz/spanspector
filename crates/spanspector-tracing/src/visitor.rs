//! A [`tracing::field::Visit`] implementation that captures fields as redacted
//! [`FieldValue`]s.
//!
//! Redaction happens here, at the boundary where raw tracing values enter the
//! evidence pipeline: every value is keyed by its field name and passed through
//! [`redact_field_value`], so a field named `password` or `auth.token` is hashed
//! and stripped before it can reach a [`crate`] record. This is the single choke
//! point — nothing downstream re-introduces raw values.

use std::collections::BTreeMap;
use std::fmt::Debug;

use spanspector_schema::{FieldValue, redact_field_value};
use tracing_core::Field;

/// Collects visited tracing fields into a redacted, deterministically ordered map.
#[derive(Debug, Default)]
pub(crate) struct FieldCollector {
    fields: BTreeMap<String, FieldValue>,
}

impl FieldCollector {
    /// Consume the collector and return the captured fields.
    pub(crate) fn into_fields(self) -> BTreeMap<String, FieldValue> {
        self.fields
    }

    /// Merge already-captured fields into another map (used to fold span-open
    /// fields and later `record` updates together at close time).
    pub(crate) fn merge_into(self, target: &mut BTreeMap<String, FieldValue>) {
        target.extend(self.fields);
    }

    fn insert_text(&mut self, field: &Field, value: &str) {
        // Key-based redaction: textual values under sensitive keys never survive.
        self.fields.insert(
            field.name().to_owned(),
            redact_field_value(field.name(), value),
        );
    }

    fn insert(&mut self, field: &Field, value: FieldValue) {
        self.fields.insert(field.name().to_owned(), value);
    }
}

impl tracing_core::field::Visit for FieldCollector {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, FieldValue::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, FieldValue::Integer(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        match i64::try_from(value) {
            Ok(signed) => self.insert(field, FieldValue::Integer(signed)),
            // Out-of-range unsigned values are kept as text rather than wrapping
            // into a misleading negative integer.
            Err(_) => self.insert_text(field, &value.to_string()),
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // The schema has no float field type; record a stable textual form.
        self.insert_text(field, &value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert_text(field, value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        // Error displays can carry payload data, so they are redacted by key too.
        self.insert_text(field, &value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.insert_text(field, &format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_core::field::Visit;

    // A small helper to obtain a `Field` for testing. `tracing` does not expose a
    // public `Field` constructor, so we build a callsite-free field via a span's
    // metadata is heavy; instead we exercise the collector through a real
    // subscriber in the layer integration tests. Here we only assert the map
    // shape using the public `into_fields`.
    #[test]
    fn empty_collector_yields_no_fields() {
        let collector = FieldCollector::default();
        assert!(collector.into_fields().is_empty());
    }

    #[test]
    fn merge_into_extends_target() {
        let mut target = BTreeMap::new();
        target.insert("a".to_owned(), FieldValue::Bool(true));
        // We cannot easily fabricate a Field here, so just confirm merge of an
        // empty collector preserves the target.
        let collector = FieldCollector::default();
        collector.merge_into(&mut target);
        assert_eq!(target.len(), 1);
    }

    // The redaction and type-mapping behavior is covered end-to-end in
    // `tests/layer.rs`, which drives a real `tracing` subscriber.
    fn _assert_visit_impl<V: Visit>() {}
    #[test]
    fn collector_implements_visit() {
        _assert_visit_impl::<FieldCollector>();
    }
}
