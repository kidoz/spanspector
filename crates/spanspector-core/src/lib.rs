//! Shared SpanSpector domain primitives.
//!
//! This crate holds the low-level types that other SpanSpector crates depend on
//! without depending on each other: deterministic hashing, sensitive-value
//! redaction, and run metadata. It has no knowledge of the trace schema, the
//! tracing integration, or the MCP server, so it sits at the bottom of the
//! dependency graph.

mod digest;
mod redaction;
mod run;

pub use digest::sha256_digest;
pub use redaction::{
    RedactedValue, RedactionPolicy, SensitiveClass, classify_sensitive_key, is_sensitive_key,
};
pub use run::RunMetadata;
