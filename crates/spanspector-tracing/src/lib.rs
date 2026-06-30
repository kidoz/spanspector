//! `tracing` integration for SpanSpector.
//!
//! This crate provides [`SpanSpectorLayer`], a [`tracing_subscriber::Layer`] that
//! turns spans and events into `spanspector-trace/v1` JSONL records. It captures
//! span open/close lifecycles, source locations, durations, and semantic fields,
//! redacting sensitive field values at the capture boundary.
//!
//! ## Choosing a writer
//!
//! The layer writes serialized lines to any [`RecordWriter`] sink:
//!
//! - An `Arc<Mutex<W>>` over a [`std::io::Write`] is a simple, ordered,
//!   **synchronous** sink — good for tests, CLIs, and low-volume use. It writes
//!   inline and can block the calling thread.
//! - [`NonBlockingWriter`] offloads writes to a background thread over a bounded
//!   channel, with an explicit [`Overflow`] policy and dropped/error counters —
//!   use it on server request, consensus, recovery, and backup paths where a
//!   blocking filesystem write is unacceptable.
//!
//! ## Configuring evidence output
//!
//! [`EvidenceBuilder`] is the one-call path: it picks a trace-file path, creates
//! parent directories, builds [`RunMetadata`], wires a [`NonBlockingWriter`], and
//! hands back a ready [`SpanSpectorLayer`] plus its [`SpanSpectorGuard`].
//!
//! ## Bounding evidence volume
//!
//! The layer is a plain [`tracing_subscriber::Layer`], so attach a per-layer
//! filter to capture only the targets that matter — without affecting the `fmt`
//! or OTLP layers in the same registry:
//!
//! ```
//! use spanspector_schema::RunMetadata;
//! use spanspector_tracing::SpanSpectorLayer;
//! use std::sync::{Arc, Mutex};
//! use tracing_subscriber::filter::{LevelFilter, Targets};
//! use tracing_subscriber::layer::SubscriberExt;
//! use tracing_subscriber::Layer;
//!
//! let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
//! // Capture pgwire and raft at info+, everything else only at error.
//! let filter = Targets::new()
//!     .with_target("nodus_pgwire", LevelFilter::INFO)
//!     .with_target("nodus_server::raft", LevelFilter::INFO)
//!     .with_default(LevelFilter::ERROR);
//! let layer = SpanSpectorLayer::new(RunMetadata::new("run-1"), buffer).with_filter(filter);
//! let _subscriber = tracing_subscriber::registry().with(layer);
//! ```
//!
//! See [`SpanSpectorLayer`] for a runnable end-to-end example.

mod builder;
mod layer;
mod nonblocking;
mod visitor;
mod writer;

pub use builder::{Evidence, EvidenceBuilder};
pub use layer::SpanSpectorLayer;
pub use nonblocking::{
    DEFAULT_CAPACITY, ErrorCallback, NonBlockingOptions, NonBlockingWriter, Overflow,
    SpanSpectorGuard, non_blocking_jsonl,
};
pub use writer::RecordWriter;

// Re-export the run/redaction types that appear in this crate's public API so a
// downstream consumer can configure evidence without naming the lower crates.
pub use spanspector_core::{RedactionPolicy, RunMetadata, SensitiveClass};
