//! The `spanspector-trace/v1` schema.
//!
//! This crate defines the JSONL evidence format SpanSpector emits and consumes:
//! the [`TraceRecord`] type, deterministic serialization, error-tolerant parsing
//! ([`read_jsonl`]), validation, and incremental [`RunSummary`] aggregation.
//!
//! ```
//! use spanspector_schema::{
//!     EventKind, Level, RunMetadata, TraceEvent, TraceRecord, to_jsonl_line,
//! };
//!
//! let record = TraceRecord::new(
//!     RunMetadata::new("run-1"),
//!     TraceEvent::new(
//!         EventKind::Event,
//!         "trace-1",
//!         "span-1",
//!         "order.create",
//!         "example_app::orders",
//!         Level::Info,
//!     ),
//! );
//! let line = to_jsonl_line(&record).unwrap();
//! assert!(line.ends_with('\n'));
//! assert!(line.contains("\"schema\":\"spanspector-trace/v1\""));
//! ```

mod error;
mod event;
mod jsonl;
mod record;
mod redact;
mod summary;

pub use error::{Result, SchemaError};
pub use event::{
    EventKind, EventStatus, FieldValue, Level, Repro, SourceLocation, TestHint, TraceEvent,
};
pub use jsonl::{JsonlLine, from_jsonl_line, read_jsonl, to_jsonl_line};
pub use record::{SCHEMA_VERSION, TraceRecord};
pub use redact::{redact_field_value, redact_field_value_with, redact_fields};
pub use summary::{DEFAULT_SLOWEST_SPANS, RunSummary, SpanTiming};

// Re-export the core types that appear in this crate's public API so downstream
// crates can use the schema without naming `spanspector-core` directly.
pub use spanspector_core::{RedactedValue, RedactionPolicy, RunMetadata, SensitiveClass};
