//! Trace event types: the body of every `spanspector-trace/v1` record.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use spanspector_core::{RedactedValue, is_sensitive_key};

use crate::error::{Result, SchemaError};

/// A tracing span lifecycle transition or a point-in-time tracing event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceEvent {
    /// Event kind.
    pub kind: EventKind,
    /// Stable trace identifier (shared by every span in one logical operation).
    pub trace_id: String,
    /// Stable span identifier.
    pub span_id: String,
    /// Parent span identifier when this event is nested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    /// Span or event name.
    pub name: String,
    /// Rust tracing target (module path).
    pub target: String,
    /// Tracing level.
    pub level: Level,
    /// Duration for completed spans, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Outcome status.
    pub status: EventStatus,
    /// Source location when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    /// Stable semantic fields. Sensitive keys must hold redacted values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, FieldValue>,
    /// Deterministic hints for focused test generation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_hints: Vec<TestHint>,
    /// Reproduction command metadata when safe to emit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repro: Option<Repro>,
}

impl TraceEvent {
    /// Build a trace event with the required identifiers and descriptive metadata.
    pub fn new(
        kind: EventKind,
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
        name: impl Into<String>,
        target: impl Into<String>,
        level: Level,
    ) -> Self {
        Self {
            kind,
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            parent_span_id: None,
            name: name.into(),
            target: target.into(),
            level,
            duration_ms: None,
            status: EventStatus::Unknown,
            source: None,
            fields: BTreeMap::new(),
            test_hints: Vec::new(),
            repro: None,
        }
    }

    /// Validate required identifiers and the redaction invariant.
    ///
    /// The redaction check is the security-critical one: any field whose key is
    /// classified sensitive must carry a [`FieldValue::Redacted`] value, never a
    /// raw string. This makes "a secret reached the trace" a hard validation
    /// failure rather than a silent leak.
    pub(crate) fn validate(&self) -> Result<()> {
        require_non_empty("event.trace_id", &self.trace_id)?;
        require_non_empty("event.span_id", &self.span_id)?;
        require_non_empty("event.name", &self.name)?;
        require_non_empty("event.target", &self.target)?;

        for (key, value) in &self.fields {
            require_non_empty("event.fields.key", key)?;
            if is_sensitive_key(key) && !matches!(value, FieldValue::Redacted(_)) {
                return Err(SchemaError::UnredactedSensitiveField { field: key.clone() });
            }
        }

        Ok(())
    }

    /// The value of `error.kind` when present and textual.
    pub(crate) fn error_kind(&self) -> Option<&str> {
        match self.fields.get("error.kind") {
            Some(FieldValue::Text(kind)) => Some(kind.as_str()),
            _ => None,
        }
    }

    /// Whether this event is flagged as a performance suspect.
    pub(crate) fn is_perf_suspect(&self) -> bool {
        matches!(
            self.fields.get("perf.suspect"),
            Some(FieldValue::Bool(true))
        )
    }

    /// The `security.boundary`/`security.decision` pair when both are textual.
    pub(crate) fn security_decision(&self) -> Option<(&str, &str)> {
        match (
            self.fields.get("security.boundary"),
            self.fields.get("security.decision"),
        ) {
            (Some(FieldValue::Text(boundary)), Some(FieldValue::Text(decision))) => {
                Some((boundary.as_str(), decision.as_str()))
            }
            _ => None,
        }
    }
}

/// Trace event kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A span was opened.
    SpanStarted,
    /// A span was closed; may carry duration and status.
    SpanClosed,
    /// A point-in-time tracing event was recorded.
    Event,
}

/// Tracing level.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Level {
    /// Trace-level diagnostic.
    Trace,
    /// Debug-level diagnostic.
    Debug,
    /// Informational diagnostic.
    Info,
    /// Warning diagnostic.
    Warn,
    /// Error diagnostic.
    Error,
}

/// Outcome status of a span or event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    /// Operation succeeded.
    Ok,
    /// Operation failed.
    Error,
    /// Status was not known at capture time.
    Unknown,
}

/// Source location attached to a trace event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceLocation {
    /// Source file path as emitted by tracing metadata.
    pub file: String,
    /// One-based source line.
    pub line: u32,
    /// Function path when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

/// A value stored under a semantic field key.
///
/// `serde(untagged)` keeps the on-wire form natural (`"command"`, `312`, `true`,
/// or a redacted object) while [`FieldValue::Redacted`] makes "this was a secret"
/// explicit and machine-checkable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    /// Boolean value.
    Bool(bool),
    /// Signed integer value.
    Integer(i64),
    /// Redacted sensitive value.
    Redacted(RedactedValue),
    /// String value safe to emit.
    Text(String),
}

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for FieldValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<RedactedValue> for FieldValue {
    fn from(value: RedactedValue) -> Self {
        Self::Redacted(value)
    }
}

/// A hint that helps an agent generate a focused test from observed evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestHint {
    /// Test strategy, such as `regression`, `property`, or `snapshot`.
    pub kind: String,
    /// Stable suggested test name.
    pub suggested_name: String,
    /// Redacted fixture path or identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixture: Option<String>,
    /// Assertion intent in concise text.
    #[serde(rename = "assert")]
    pub assertion: String,
}

/// Safe reproduction metadata for an observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Repro {
    /// Exact focused command to reproduce the observation.
    pub command: String,
    /// Environment variables required for reproduction.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

fn require_non_empty(field: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(SchemaError::EmptyRequiredField { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untagged_field_value_round_trips_each_variant() {
        for value in [
            FieldValue::Bool(true),
            FieldValue::Integer(-7),
            FieldValue::Text("command".to_owned()),
            FieldValue::Redacted(RedactedValue::new("password", "x")),
        ] {
            let json = serde_json::to_string(&value).unwrap();
            let back: FieldValue = serde_json::from_str(&json).unwrap();
            assert_eq!(value, back);
        }
    }

    #[test]
    fn validation_rejects_raw_sensitive_field() {
        let mut event = sample_event();
        event
            .fields
            .insert("auth.token".to_owned(), FieldValue::Text("raw".to_owned()));
        let error = event.validate().unwrap_err().to_string();
        assert!(error.contains("auth.token"));
        assert!(!error.contains("raw"));
    }

    fn sample_event() -> TraceEvent {
        TraceEvent::new(EventKind::Event, "trace-1", "span-1", "n", "t", Level::Info)
    }
}
