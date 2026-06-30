//! End-to-end tests that drive the layer through a real `tracing` subscriber.

use std::sync::{Arc, Mutex};

use spanspector_schema::{JsonlLine, RunMetadata, read_jsonl};
use spanspector_tracing::SpanSpectorLayer;
use tracing_subscriber::layer::SubscriberExt;

fn capture<F: FnOnce()>(body: F) -> Vec<spanspector_schema::TraceRecord> {
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let layer = SpanSpectorLayer::new(
        RunMetadata::new("run-1").with_crate("example-app"),
        buffer.clone(),
    )
    .with_span_started(true);
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, body);

    let bytes = match buffer.lock() {
        Ok(buffer) => buffer.clone(),
        Err(poisoned) => panic!("buffer mutex was poisoned: {poisoned}"),
    };
    read_jsonl(std::io::Cursor::new(bytes))
        .into_iter()
        .map(|line| match line {
            JsonlLine::Record(record) => *record,
            JsonlLine::Fault { error, .. } => panic!("emitted invalid JSONL: {error}"),
        })
        .collect()
}

#[test]
fn span_close_emits_redacted_record_with_duration() {
    let records = capture(|| {
        let span = tracing::info_span!(
            "order.create",
            input.class = "json.order.v1",
            auth.token = "super-secret-token"
        );
        let _guard = span.enter();
    });

    let closed = records
        .iter()
        .find(|r| matches!(r.event.kind, spanspector_schema::EventKind::SpanClosed))
        .expect("a span_closed record");

    assert_eq!(closed.event.name, "order.create");
    assert!(closed.event.duration_ms.is_some());

    // The non-sensitive field is preserved verbatim.
    assert_eq!(
        closed.event.fields.get("input.class"),
        Some(&spanspector_schema::FieldValue::Text(
            "json.order.v1".to_owned()
        ))
    );
    // The sensitive field is redacted, and the raw token never appears anywhere.
    assert!(matches!(
        closed.event.fields.get("auth.token"),
        Some(spanspector_schema::FieldValue::Redacted(_))
    ));
    let line = serde_json::to_string(closed).unwrap();
    assert!(!line.contains("super-secret-token"));
}

#[test]
fn event_inherits_trace_and_span_ids_from_enclosing_span() {
    let records = capture(|| {
        let span = tracing::info_span!("work");
        let _guard = span.enter();
        tracing::error!(error.kind = "boom", "failed");
    });

    let span_started = records
        .iter()
        .find(|r| matches!(r.event.kind, spanspector_schema::EventKind::SpanStarted))
        .expect("a span_started record");
    let event = records
        .iter()
        .find(|r| matches!(r.event.kind, spanspector_schema::EventKind::Event))
        .expect("an event record");

    // The event is anchored to the enclosing span and shares its trace id.
    assert_eq!(event.event.span_id, span_started.event.span_id);
    assert_eq!(event.event.trace_id, span_started.event.trace_id);
    // `error.kind` drives error status without a raw message field being required.
    assert_eq!(event.event.status, spanspector_schema::EventStatus::Error);
    assert_eq!(
        event.event.fields.get("error.kind"),
        Some(&spanspector_schema::FieldValue::Text("boom".to_owned()))
    );
}
