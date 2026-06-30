//! `tracing` integration for SpanSpector.
//!
//! This crate provides [`SpanSpectorLayer`], a [`tracing_subscriber::Layer`] that
//! turns spans and events into `spanspector-trace/v1` JSONL records. It captures
//! span open/close lifecycles, source locations, durations, and semantic fields,
//! redacting sensitive field values at the capture boundary.
//!
//! See [`SpanSpectorLayer`] for a runnable example.

mod layer;
mod visitor;

pub use layer::SpanSpectorLayer;
