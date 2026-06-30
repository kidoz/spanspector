//! Integration tests for the non-blocking writer, the guard lifecycle, drop
//! accounting, and composition with a `fmt` layer.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use spanspector_schema::{EventKind, JsonlLine, RunMetadata, read_jsonl};
use spanspector_tracing::{
    EvidenceBuilder, NonBlockingOptions, NonBlockingWriter, Overflow, SpanSpectorLayer,
};
use tracing_subscriber::layer::SubscriberExt;

/// A unique temp path under the OS temp dir for one test.
fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("spanspector-test-{}-{name}", std::process::id()));
    path
}

/// A `Write` that appends into a shared buffer the test can inspect afterwards.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.0.lock().map_err(|_| io::Error::other("poisoned"))?;
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn records_from(bytes: Vec<u8>) -> Vec<spanspector_schema::TraceRecord> {
    read_jsonl(io::Cursor::new(bytes))
        .into_iter()
        .map(|line| match line {
            JsonlLine::Record(record) => *record,
            JsonlLine::Fault { error, .. } => panic!("emitted invalid JSONL: {error}"),
        })
        .collect()
}

#[test]
fn non_blocking_writer_emits_valid_redacted_jsonl_to_file() {
    let dir = temp_path("runs");
    let _ = std::fs::remove_dir_all(&dir);

    let evidence = EvidenceBuilder::new()
        .runs_dir(&dir)
        .run_id("run-fixed")
        .crate_name("nodus_server")
        .build()
        .expect("evidence builds");
    let trace_path = evidence.path.clone();
    assert_eq!(trace_path, dir.join("run-fixed").join("trace.jsonl"));

    let subscriber = tracing_subscriber::registry().with(evidence.layer);
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!(
            "order.create",
            input.class = "json.order.v1",
            auth.token = "super-secret-token"
        );
        let _entered = span.enter();
    });

    // Flush and join the writer thread before reading the file.
    evidence.guard.shutdown().expect("clean shutdown");

    let bytes = std::fs::read(&trace_path).expect("trace file exists");
    assert!(!bytes.is_empty(), "evidence should have been written");
    assert!(
        !String::from_utf8_lossy(&bytes).contains("super-secret-token"),
        "raw secret must never reach the file"
    );
    let records = records_from(bytes);
    let closed = records
        .iter()
        .find(|r| matches!(r.event.kind, EventKind::SpanClosed))
        .expect("a span_closed record");
    assert_eq!(closed.event.name, "order.create");
    assert!(matches!(
        closed.event.fields.get("auth.token"),
        Some(spanspector_schema::FieldValue::Redacted(_))
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn block_overflow_loses_no_records() {
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (writer, guard) = NonBlockingWriter::new(
        SharedBuf(buffer.clone()),
        NonBlockingOptions::new()
            .capacity(4)
            .overflow(Overflow::Block),
    )
    .expect("writer starts");

    let layer = SpanSpectorLayer::new(RunMetadata::new("run-1"), writer);
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        for i in 0..200 {
            let span = tracing::info_span!("work", iteration = i as i64);
            let _entered = span.enter();
        }
    });

    guard.flush().expect("flush succeeds");
    assert_eq!(guard.dropped(), 0, "Block overflow must not drop records");

    let bytes = buffer.lock().expect("lock").clone();
    let closed = records_from(bytes)
        .into_iter()
        .filter(|r| matches!(r.event.kind, EventKind::SpanClosed))
        .count();
    assert_eq!(closed, 200, "every span should have been written");
}

#[test]
fn composes_with_fmt_layer_without_disturbing_evidence() {
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let spanspector = SpanSpectorLayer::new(RunMetadata::new("run-1"), buffer.clone());
    // A real fmt layer in the same registry, silenced to a sink so the test stays
    // quiet; it proves SpanSpector composes alongside formatted logging.
    let fmt = tracing_subscriber::fmt::layer().with_writer(io::sink);
    let subscriber = tracing_subscriber::registry().with(fmt).with(spanspector);

    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("order.create", input.class = "json.order.v1");
        let _entered = span.enter();
        tracing::error!(error.kind = "validation_error", "rejected");
    });

    let bytes = buffer.lock().expect("lock").clone();
    let records = records_from(bytes);
    assert!(
        records
            .iter()
            .any(|r| matches!(r.event.kind, EventKind::SpanClosed)),
        "SpanSpector still emits its span_closed record next to fmt"
    );
    assert!(
        records
            .iter()
            .any(|r| r.event.status == spanspector_schema::EventStatus::Error),
        "the error event is captured"
    );
}

/// A sink whose writes block while the test holds `gate`, so the writer thread
/// stalls and the bounded channel fills — forcing `DropNewest` to drop.
struct BlockingSink {
    gate: Arc<Mutex<()>>,
    inner: Arc<Mutex<Vec<u8>>>,
}

impl Write for BlockingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _held = self.gate.lock().map_err(|_| io::Error::other("poisoned"))?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?;
        inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?;
        inner.flush()
    }
}

#[test]
fn drop_newest_counts_dropped_records_when_sink_stalls() {
    let gate = Arc::new(Mutex::new(()));
    let inner = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = BlockingSink {
        gate: gate.clone(),
        inner: inner.clone(),
    };

    let (writer, guard) = NonBlockingWriter::new(
        sink,
        NonBlockingOptions::new()
            .capacity(1)
            .overflow(Overflow::DropNewest),
    )
    .expect("writer starts");

    // Hold the gate so the writer thread blocks on its first write; with capacity
    // 1, at most two lines are accepted and the rest are dropped.
    let held = gate.lock().expect("gate");
    let layer = SpanSpectorLayer::new(RunMetadata::new("run-1"), writer);
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..1000 {
            let span = tracing::info_span!("work");
            let _entered = span.enter();
        }
    });

    assert!(
        guard.dropped() > 0,
        "a stalled sink with capacity 1 must drop records"
    );

    // Release the sink and drain cleanly.
    drop(held);
    guard.shutdown().expect("clean shutdown");
}
