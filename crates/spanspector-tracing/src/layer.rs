//! The [`SpanSpectorLayer`] tracing-subscriber layer.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use spanspector_core::{RedactionPolicy, RunMetadata};
use spanspector_schema::{
    EventKind, EventStatus, FieldValue, Level, SourceLocation, TraceEvent, TraceRecord,
    to_jsonl_line,
};
use tracing_core::span::{Attributes, Id, Record};
use tracing_core::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::visitor::FieldCollector;
use crate::writer::RecordWriter;

/// Per-span state cached in the registry between open and close.
struct SpanState {
    name: String,
    target: String,
    level: Level,
    source: Option<SourceLocation>,
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
    fields: BTreeMap<String, FieldValue>,
    started: Instant,
}

/// A `tracing` layer that converts spans and events into `spanspector-trace/v1`
/// JSONL records written to a [`RecordWriter`] sink.
///
/// Construct it with a [`RunMetadata`] and a sink, then compose it onto a
/// [`tracing_subscriber::Registry`]. Any `Arc<Mutex<W>>` over a [`Write`] is a
/// valid sink (synchronous, ordered); for server paths that must never block on
/// I/O, use [`crate::non_blocking_jsonl`] or [`crate::NonBlockingWriter`].
///
/// [`Write`]: std::io::Write
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use spanspector_schema::RunMetadata;
/// use spanspector_tracing::SpanSpectorLayer;
/// use tracing_subscriber::layer::SubscriberExt;
/// use tracing_subscriber::util::SubscriberInitExt;
///
/// let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
/// let layer = SpanSpectorLayer::new(RunMetadata::new("run-1"), buffer.clone());
/// let subscriber = tracing_subscriber::registry().with(layer);
///
/// tracing::subscriber::with_default(subscriber, || {
///     let span = tracing::info_span!("work", input.class = "json.order.v1");
///     let _guard = span.enter();
///     tracing::info!(error.kind = "validation_error", "rejected");
/// });
///
/// let written = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
/// assert!(written.contains("\"name\":\"work\""));
/// assert!(written.contains("validation_error"));
/// ```
///
/// ## Overhead
///
/// Each record is serialized and handed to the sink's [`RecordWriter::write_line`].
/// Field maps are captured once per span (plus any `record` updates) and the run
/// metadata is shared behind an [`Arc`]; the per-event cost is one clone of the
/// small run metadata and one JSON serialization. Writes are best-effort: a
/// failing sink drops the record rather than panicking inside the tracing
/// callback. Whether emission blocks the calling thread is a property of the
/// sink — an `Arc<Mutex<W>>` writes inline; [`NonBlockingWriter`] hands the line
/// to a background thread.
///
/// [`NonBlockingWriter`]: crate::NonBlockingWriter
pub struct SpanSpectorLayer<W> {
    run: Arc<RunMetadata>,
    writer: W,
    emit_span_started: bool,
    redaction: Arc<RedactionPolicy>,
    next_synthetic_id: AtomicU64,
}

impl<W: RecordWriter> SpanSpectorLayer<W> {
    /// Create a layer that writes records for one run to `writer`.
    pub fn new(run: RunMetadata, writer: W) -> Self {
        Self {
            run: Arc::new(run),
            writer,
            emit_span_started: false,
            redaction: Arc::new(RedactionPolicy::new()),
            next_synthetic_id: AtomicU64::new(1),
        }
    }

    /// Also emit a `span_started` record when each span opens.
    ///
    /// Off by default: closed spans already carry duration and final fields, so
    /// most consumers only need open records when correlating long-lived spans.
    #[must_use]
    pub fn with_span_started(mut self, enabled: bool) -> Self {
        self.emit_span_started = enabled;
        self
    }

    /// Use a custom [`RedactionPolicy`] for field redaction.
    ///
    /// The built-in sensitive keys always stay active; the policy only adds
    /// domain-specific keys on top (for example a database service redacting
    /// `sql.literal` or `connection_string`).
    #[must_use]
    pub fn with_redaction(mut self, policy: RedactionPolicy) -> Self {
        self.redaction = Arc::new(policy);
        self
    }

    fn collector(&self) -> FieldCollector {
        FieldCollector::new(Arc::clone(&self.redaction))
    }

    /// Serialize and write one record, best-effort.
    fn write_record(&self, event: TraceEvent) {
        let record = TraceRecord::new((*self.run).clone(), event);
        // `to_jsonl_line` also validates, so an unredacted sensitive field is
        // dropped here rather than written — defense in depth behind the visitor.
        let Ok(line) = to_jsonl_line(&record) else {
            return;
        };
        self.writer.write_line(&line);
    }

    fn synthetic_id(&self) -> String {
        let id = self.next_synthetic_id.fetch_add(1, Ordering::Relaxed);
        format!("event-{id}")
    }
}

impl<S, W> Layer<S> for SpanSpectorLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: RecordWriter,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let metadata = attrs.metadata();

        let span_id = id.into_u64().to_string();
        let parent_span_id = span
            .parent()
            .map(|parent| parent.id().into_u64().to_string());
        // The trace id is the id of the outermost span in this scope, so every
        // span and event in one logical operation shares it.
        let trace_id = span
            .scope()
            .from_root()
            .next()
            .map_or_else(|| span_id.clone(), |root| root.id().into_u64().to_string());

        let mut collector = self.collector();
        attrs.record(&mut collector);

        let state = SpanState {
            name: metadata.name().to_owned(),
            target: metadata.target().to_owned(),
            level: level_of(metadata),
            source: source_location(metadata),
            trace_id,
            span_id,
            parent_span_id,
            fields: collector.into_fields(),
            started: Instant::now(),
        };

        if self.emit_span_started {
            self.write_record(build_event(
                &state,
                EventKind::SpanStarted,
                None,
                EventStatus::Unknown,
            ));
        }

        span.extensions_mut().insert(state);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        let Some(state) = extensions.get_mut::<SpanState>() else {
            return;
        };
        let mut collector = self.collector();
        values.record(&mut collector);
        collector.merge_into(&mut state.fields);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut collector = self.collector();
        event.record(&mut collector);
        let fields = collector.into_fields();

        let status = if fields.contains_key("error.kind") || level_of(metadata) == Level::Error {
            EventStatus::Error
        } else {
            EventStatus::Unknown
        };

        // Anchor the event to the span it occurred in, when there is one.
        let (trace_id, span_id, parent_span_id) = match ctx.event_span(event) {
            Some(span) => {
                let span_id = span.id().into_u64().to_string();
                let parent_span_id = span
                    .parent()
                    .map(|parent| parent.id().into_u64().to_string());
                let trace_id = span
                    .scope()
                    .from_root()
                    .next()
                    .map_or_else(|| span_id.clone(), |root| root.id().into_u64().to_string());
                (trace_id, span_id, parent_span_id)
            }
            None => {
                let synthetic = self.synthetic_id();
                (synthetic.clone(), synthetic, None)
            }
        };

        let mut trace_event = TraceEvent::new(
            EventKind::Event,
            trace_id,
            span_id,
            metadata.name(),
            metadata.target(),
            level_of(metadata),
        );
        trace_event.parent_span_id = parent_span_id;
        trace_event.status = status;
        trace_event.source = source_location(metadata);
        trace_event.fields = fields;
        self.write_record(trace_event);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        let Some(state) = extensions.remove::<SpanState>() else {
            return;
        };

        let duration_ms = u64::try_from(state.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let status = if state.fields.contains_key("error.kind") || state.level == Level::Error {
            EventStatus::Error
        } else {
            EventStatus::Ok
        };
        self.write_record(build_event(
            &state,
            EventKind::SpanClosed,
            Some(duration_ms),
            status,
        ));
    }
}

/// Build a span lifecycle record from cached span state.
fn build_event(
    state: &SpanState,
    kind: EventKind,
    duration_ms: Option<u64>,
    status: EventStatus,
) -> TraceEvent {
    let mut event = TraceEvent::new(
        kind,
        state.trace_id.clone(),
        state.span_id.clone(),
        state.name.clone(),
        state.target.clone(),
        state.level,
    );
    event.parent_span_id = state.parent_span_id.clone();
    event.duration_ms = duration_ms;
    event.status = status;
    event.source = state.source.clone();
    event.fields = state.fields.clone();
    event
}

fn level_of(metadata: &tracing_core::Metadata<'_>) -> Level {
    match *metadata.level() {
        tracing_core::Level::TRACE => Level::Trace,
        tracing_core::Level::DEBUG => Level::Debug,
        tracing_core::Level::INFO => Level::Info,
        tracing_core::Level::WARN => Level::Warn,
        tracing_core::Level::ERROR => Level::Error,
    }
}

fn source_location(metadata: &tracing_core::Metadata<'_>) -> Option<SourceLocation> {
    let file = metadata.file()?;
    let line = metadata.line()?;
    Some(SourceLocation {
        file: file.to_owned(),
        line,
        function: Some(metadata.target().to_owned()),
    })
}
