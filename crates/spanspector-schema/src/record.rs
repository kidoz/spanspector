//! The top-level `spanspector-trace/v1` record: schema tag, run metadata, event.

use serde::{Deserialize, Serialize};
use spanspector_core::RunMetadata;

use crate::error::{Result, SchemaError};
use crate::event::TraceEvent;

/// Current SpanSpector trace schema identifier.
///
/// Versioning policy: additive field changes keep `v1`; any change that would
/// break a `v1` reader (renamed/removed required fields, changed semantics) bumps
/// to `v2`. Readers reject unknown schema strings rather than guessing.
pub const SCHEMA_VERSION: &str = "spanspector-trace/v1";

/// One complete SpanSpector JSONL trace record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceRecord {
    /// Versioned schema identifier. Must equal [`SCHEMA_VERSION`].
    #[serde(default = "default_schema_version")]
    pub schema: String,
    /// Metadata for the run that emitted the event.
    pub run: RunMetadata,
    /// The recorded tracing event or span lifecycle transition.
    pub event: TraceEvent,
}

impl TraceRecord {
    /// Build a trace record stamped with the current schema version.
    pub fn new(run: RunMetadata, event: TraceEvent) -> Self {
        Self {
            schema: SCHEMA_VERSION.to_owned(),
            run,
            event,
        }
    }

    /// Validate the schema version, required fields, and redaction invariant.
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA_VERSION {
            return Err(SchemaError::UnsupportedSchema {
                expected: SCHEMA_VERSION,
                actual: self.schema.clone(),
            });
        }
        if self.run.id.trim().is_empty() {
            return Err(SchemaError::EmptyRequiredField { field: "run.id" });
        }
        self.event.validate()
    }
}

fn default_schema_version() -> String {
    SCHEMA_VERSION.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, EventStatus, FieldValue, Level, SourceLocation, TestHint};
    use crate::jsonl::{from_jsonl_line, to_jsonl_line};
    use crate::redact::redact_field_value;

    #[test]
    fn serializes_with_schema_and_crate_name() {
        let line = to_jsonl_line(&sample_record()).unwrap();
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"schema\":\"spanspector-trace/v1\""));
        assert!(line.contains("\"crate\":\"example-app\""));
    }

    #[test]
    fn jsonl_round_trip_preserves_record() {
        let record = sample_record();
        let line = to_jsonl_line(&record).unwrap();
        assert_eq!(from_jsonl_line(&line).unwrap(), record);
    }

    #[test]
    fn field_order_is_deterministic() {
        let mut record = sample_record();
        record
            .event
            .fields
            .insert("z.last".to_owned(), FieldValue::Bool(true));
        record
            .event
            .fields
            .insert("a.first".to_owned(), FieldValue::Bool(true));
        let line = to_jsonl_line(&record).unwrap();
        assert!(line.find("\"a.first\"").unwrap() < line.find("\"z.last\"").unwrap());
    }

    #[test]
    fn validation_rejects_raw_sensitive_fields() {
        let mut record = sample_record();
        record
            .event
            .fields
            .insert("auth.token".to_owned(), FieldValue::Text("raw".to_owned()));
        let error = record.validate().unwrap_err().to_string();
        assert!(error.contains("auth.token"));
        assert!(!error.contains("raw"));
    }

    #[test]
    fn missing_schema_defaults_to_current_version() {
        let json = r#"{"run":{"id":"run-1"},"event":{"kind":"event","trace_id":"t","span_id":"s","name":"n","target":"tg","level":"INFO","status":"unknown"}}"#;
        let record = from_jsonl_line(json).unwrap();
        assert_eq!(record.schema, SCHEMA_VERSION);
    }

    pub(super) fn sample_record() -> TraceRecord {
        let run = RunMetadata::new("run-1")
            .with_git_sha("abc1234")
            .with_profile("test")
            .with_crate("example-app");

        let mut event = TraceEvent::new(
            EventKind::SpanClosed,
            "trace-1",
            "span-1",
            "order.create",
            "example_app::orders",
            Level::Info,
        );
        event.duration_ms = Some(312);
        event.status = EventStatus::Error;
        event.source = Some(SourceLocation {
            file: "src/orders.rs".to_owned(),
            line: 42,
            function: Some("example_app::orders::create_order".to_owned()),
        });
        event
            .fields
            .insert("ai.kind".to_owned(), FieldValue::Text("command".to_owned()));
        event.fields.insert(
            "auth.token".to_owned(),
            redact_field_value("auth.token", "raw-token"),
        );
        event.test_hints.push(TestHint {
            kind: "regression".to_owned(),
            suggested_name: "rejects_order_with_invalid_total".to_owned(),
            fixture: Some("tests/fixtures/orders/invalid-total.json".to_owned()),
            assertion: "returns validation error".to_owned(),
        });

        TraceRecord::new(run, event)
    }
}
